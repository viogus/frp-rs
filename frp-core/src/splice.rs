//! Linux splice(2) zero-copy relay for raw TCP connections.
//!
//! Uses `tokio::io::unix::AsyncFd` for epoll-driven readiness notification,
//! avoiding the busy-loop that the original `spawn_blocking` implementation
//! suffered from under backpressure.
//!
//! Only compiled on Linux — the module is gated with `#[cfg(target_os = "linux")]`
//! in `lib.rs`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::unix::AsyncFd;

/// Default pipe capacity (Linux kernel pipe max, 64 KiB).
const PIPE_CAPACITY: usize = 65536;

/// Create a non-blocking pipe pair, returning `(read_end, write_end)`.
///
/// Uses `pipe2()` with `O_NONBLOCK` so spliced I/O returns `EAGAIN`
/// instead of blocking the task — readiness is managed exclusively
/// through `AsyncFd`.
fn create_pipe_pair() -> io::Result<(AsyncFd<OwnedFd>, AsyncFd<OwnedFd>)> {
    let mut fds: [i32; 2] = [0; 2];
    // SAFETY: pipe2 writes two valid file descriptors into `fds` on success.
    // We check the return value before wrapping them in OwnedFd.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned 0, so fds[0] and fds[1] are valid open fds.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let read_async = AsyncFd::new(read)?;
    let write_async = AsyncFd::new(write)?;
    Ok((read_async, write_async))
}

/// Relay data from `src` through a pipe to `dst`.
///
/// Phase A: `splice(src → pipe_wr)` to move data into the kernel pipe.
/// Phase B: `splice(pipe_rd → dst)` to drain the pipe to the destination.
///
/// Returns when either side signals EOF (splice returns 0).
async fn splice_direction(
    src: &AsyncFd<OwnedFd>,
    pipe_rd: &AsyncFd<OwnedFd>,
    pipe_wr: &AsyncFd<OwnedFd>,
    dst: &AsyncFd<OwnedFd>,
    counter: &AtomicU64,
) -> io::Result<()> {
    let flags = (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;

    let src_fd = src.get_ref().as_raw_fd();
    let pipe_wr_fd = pipe_wr.get_ref().as_raw_fd();
    let pipe_rd_fd = pipe_rd.get_ref().as_raw_fd();
    let dst_fd = dst.get_ref().as_raw_fd();

    loop {
        // ---- Phase A: src → pipe ----
        let n_read = 'read_block: loop {
            let mut guard = src.readable().await?;
            // SAFETY: src_fd and pipe_wr_fd are valid. null offset pointers.
            // splice is a standard Linux syscall.
            let ret = unsafe {
                libc::splice(
                    src_fd,
                    std::ptr::null_mut(),
                    pipe_wr_fd,
                    std::ptr::null_mut(),
                    PIPE_CAPACITY,
                    flags,
                )
            };
            if ret > 0 {
                guard.retain_ready();
                break ret as usize;
            }
            if ret == 0 {
                // Real EOF: splice returns 0 when the source has no more
                // data (FIN received on socket). Return immediately —
                // don't conflate with the EAGAIN sentinel.
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) => {
                    // Stale epoll notification (edge-triggered). Re-arm
                    // and re-await readable().
                    guard.retain_ready();
                    break 'read_block 0;
                }
                Some(libc::EINTR) => continue,
                _ => return Err(err),
            }
        };

        // EAGAIN sentinel — re-await readable.
        if n_read == 0 {
            continue;
        }

        // ---- Phase B: pipe → dst ----
        let mut remaining = n_read;
        while remaining > 0 {
            let mut guard = dst.writable().await?;
            let ret = unsafe {
                libc::splice(
                    pipe_rd_fd,
                    std::ptr::null_mut(),
                    dst_fd,
                    std::ptr::null_mut(),
                    remaining,
                    flags,
                )
            };
            if ret >= 0 {
                guard.retain_ready();
                let n = ret as usize;
                counter.fetch_add(n as u64, Ordering::Relaxed);
                if n == 0 {
                    return Ok(()); // EOF on dst
                }
                remaining -= n;
            } else {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) => {
                        guard.retain_ready();
                        // Break inner loop to re-await writable().
                        break;
                    }
                    Some(libc::EINTR) => continue,
                    _ => return Err(err),
                }
            }
        }
    }
}

/// Relay traffic between two raw TCP sockets using splice(2) zero-copy transfer.
///
/// Returns `(bytes_user_to_work, bytes_work_to_user)`.
///
/// Both TCP streams are consumed. Two kernel pipe pairs are created (one per
/// direction). The two direction futures run concurrently via `tokio::join!`.
pub async fn bridge_splice(
    user: tokio::net::TcpStream,
    work: tokio::net::TcpStream,
) -> io::Result<(u64, u64)> {
    // Step 1: Deregister from tokio's reactor and transfer fd ownership.
    // `into_std()` returns a std TcpStream which implements `Into<OwnedFd>`,
    // so the fd has exactly one owner — no double-close risk.
    let user_owned: OwnedFd = user.into_std()?.into();
    let work_owned: OwnedFd = work.into_std()?.into();

    // Step 2: Wrap in AsyncFd for epoll-driven readiness.
    let user_async = AsyncFd::new(user_owned)?;
    let work_async = AsyncFd::new(work_owned)?;

    // Step 3: Create two pipe pairs (one per direction).
    let (u2w_r, u2w_w) = create_pipe_pair()?;
    let (w2u_r, w2u_w) = create_pipe_pair()?;

    // Step 4: Shared byte counters.
    let u2w_count = AtomicU64::new(0);
    let w2u_count = AtomicU64::new(0);

    // Step 5: Run both directions concurrently.
    // tokio::join! runs both futures on the same task — no extra spawn.
    let (res1, res2) = tokio::join!(
        splice_direction(&user_async, &u2w_r, &u2w_w, &work_async, &u2w_count),
        splice_direction(&work_async, &w2u_r, &w2u_w, &user_async, &w2u_count),
    );

    // Step 6: Propagate first error; return byte counts.
    // Drop order: pipe AsyncFds → pipe OwnedFds (pipe fds closed) →
    // socket AsyncFds → socket OwnedFds (socket fds closed). Single owner each.
    res1?;
    res2?;

    Ok((u2w_count.into_inner(), w2u_count.into_inner()))
}
