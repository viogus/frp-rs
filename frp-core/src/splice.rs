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

/// Pipe capacity. 1 MiB = the default `/proc/sys/fs/pipe-max-size`; a larger
/// pipe lets each `splice(src → pipe)` move up to 16x more bytes per syscall,
/// cutting epoll round-trips on bulk transfers. The actual capacity is set
/// via `F_SETPIPE_SZ` in `create_pipe_pair`; this constant must match it so
/// the `splice` length argument never under-requests.
const PIPE_CAPACITY: usize = 1024 * 1024;

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
    // Grow both ends to PIPE_CAPACITY. F_SETPIPE_SZ fails with EPERM when the
    // requested size exceeds the kernel's pipe-max-size (or the process's
    // soft limit); on failure the kernel default stays and splice simply
    // moves up to the smaller pipe, so the fallback is safe (never EAGAIN
    // early — a full pipe still reports partial progress, not an error).
    for fd in [fds[0], fds[1]] {
        // SAFETY: fds[0]/fds[1] are valid fds from pipe2 above; fcntl does
        // not take ownership. The return value is intentionally ignored —
        // the size is a throughput hint, not a correctness requirement.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_CAPACITY as libc::c_int) };
    }
    let read_async = AsyncFd::new(read)?;
    let write_async = AsyncFd::new(write)?;
    Ok((read_async, write_async))
}

/// Propagate a source FIN after its buffered bytes have reached `dst`.
///
/// `shutdown(SHUT_WR)` is idempotent for a connected TCP socket. A peer may
/// have already closed the connection by the time the FIN is propagated, in
/// which case Linux reports `ENOTCONN` or `EPIPE`; both mean there is no write
/// half left to close and can be treated as successful completion.
fn shutdown_write(dst_fd: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: `dst_fd` is borrowed from a live AsyncFd for the duration of
        // this call. shutdown does not take ownership of the descriptor.
        if unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) } == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ENOTCONN | libc::EPIPE) => return Ok(()),
            _ => return Err(err),
        }
    }
}

/// Run one splice direction, propagating the FIN to `dst` when the
/// direction fails.
///
/// The loop below returns `Err` without telling `dst` that no more bytes
/// will follow (e.g. the source errored with `ECONNRESET`). That leaves a
/// peer waiting for our EOF — a half-duplex exchange where the response
/// direction is parked on a live-but-silent connection — hanging. Shutting
/// down the write half of `dst` on the error path lets that peer terminate
/// instead. A shutdown error is secondary to the direction's own error, so
/// it is dropped with a comment (matching the `let _ =` discipline
/// elsewhere).
async fn splice_direction(
    src: &AsyncFd<OwnedFd>,
    pipe_rd: &AsyncFd<OwnedFd>,
    pipe_wr: &AsyncFd<OwnedFd>,
    dst: &AsyncFd<OwnedFd>,
    counter: &AtomicU64,
) -> io::Result<()> {
    let result = splice_direction_loop(src, pipe_rd, pipe_wr, dst, counter).await;
    if result.is_err() {
        // Tell dst that no more bytes will follow so a peer waiting for our
        // EOF terminates instead of hanging on a live-but-silent conn.
        let _ = shutdown_write(dst.get_ref().as_raw_fd());
    }
    result
}

/// Relay data from `src` through a pipe to `dst`.
///
/// Phase A: `splice(src → pipe_wr)` to move data into the kernel pipe.
/// Phase B: `splice(pipe_rd → dst)` to drain the pipe to the destination.
///
/// When `src` signals EOF, drains already-completed pipe data and propagates
/// that half-close to `dst` before returning. The opposite direction remains
/// available to carry its response.
///
/// # Readiness model (tokio `AsyncFd`)
///
/// tokio's `AsyncFd` tracks readiness in an atomic bitmask inside
/// `ScheduledIo`. When `readable().await` returns, the READABLE bit is
/// **still set** — it is only cleared by an explicit `clear_ready()` call
/// (see `AsyncFdReadyGuard::clear_ready`). `retain_ready()` is a no-op
/// that merely satisfies the `#[must_use]` lint.
///
/// This means:
/// - On **success** (splice returns >0): skip `clear_ready()` so the
///   readiness bit stays for the next poll — this avoids an epoll
///   round-trip when there is likely more data.
/// - On **EAGAIN**: call `guard.clear_ready()` to clear the readiness
///   bit. Without this, the next `readable().await` / `writable().await`
///   returns immediately (the bit is still set), creating a tight loop
///   that never yields to the runtime. The cleared bit forces
///   re-registration with epoll, which parks the task until the fd
///   truly becomes ready again.
async fn splice_direction_loop(
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
                // Success: don't clear readiness — the bit stays set so the
                // next readable().await returns immediately. Fast path for
                // when more data is already buffered.
                guard.retain_ready(); // no-op, satisfies #[must_use]
                break ret as usize;
            }
            if ret == 0 {
                // Real EOF: splice returns 0 when the source has no more
                // data (FIN received on socket). Phase B has fully drained
                // all earlier reads before we reach Phase A again, so it is
                // now safe to propagate the FIN to dst.
                shutdown_write(dst_fd)?;
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) => {
                    // Clear the READABLE bit. Without this, readable().await
                    // on the next loop iteration returns immediately (bit
                    // was never cleared), creating a tight polling loop.
                    guard.clear_ready();
                    break 'read_block 0;
                }
                Some(libc::EINTR) => continue,
                _ => return Err(err),
            }
        };

        // EAGAIN sentinel — src ran dry or the pipe is full (dst slow).
        if n_read == 0 {
            // A full pipe is the only way a readable src can still EAGAIN,
            // and nothing else drains it (Phase B only runs after a
            // successful Phase A), so move whatever it holds to dst before
            // waiting — otherwise the wait below could never be satisfied.
            // Parking on dst.writable() mirrors Phase B's backpressure
            // handling.
            let mut pending: libc::c_int = 0;
            // SAFETY: pipe_rd_fd is a live fd borrowed from the pipe_rd
            // AsyncFd for the duration of this call; FIONREAD writes the
            // number of queued bytes into `pending`. The pointer is not
            // retained after the call returns.
            let drained = unsafe { libc::ioctl(pipe_rd_fd, libc::FIONREAD, &mut pending) };
            if drained != 0 {
                // FIONREAD failing is practically impossible on a live fd,
                // but without the byte count the drain loop below cannot
                // run — and with the pipe full nothing else ever drains it,
                // so the park after this block would wait forever, deadlocking
                // the bridge. Return the error instead.
                return Err(io::Error::last_os_error());
            }
            if pending > 0 {
                loop {
                    let mut guard = dst.writable().await?;
                    // SAFETY: pipe_rd_fd and dst_fd are live fds borrowed
                    // from their AsyncFd wrappers for the duration of this
                    // call; splice does not take ownership of either
                    // descriptor, and the null offset pointers keep the
                    // kernel-managed pipe/socket positions.
                    let ret = unsafe {
                        libc::splice(
                            pipe_rd_fd,
                            std::ptr::null_mut(),
                            dst_fd,
                            std::ptr::null_mut(),
                            PIPE_CAPACITY,
                            flags,
                        )
                    };
                    if ret > 0 {
                        counter.fetch_add(ret as u64, Ordering::Relaxed);
                        // Keep the WRITABLE bit for the next chunk.
                        guard.retain_ready(); // no-op, satisfies #[must_use]
                        continue;
                    }
                    if ret == 0 {
                        break; // pipe fully drained
                    }
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EAGAIN) => {
                            // dst send buffer full — clear WRITABLE and
                            // park until the peer reads.
                            guard.clear_ready();
                        }
                        Some(libc::EINTR) => continue,
                        _ => return Err(err),
                    }
                }
            }
            // The pipe now has room. Park until it is writable again or src
            // receives fresh data, then retry Phase A. Do NOT re-await
            // src.readable() directly here: AsyncFd readiness is
            // level-triggered, so while src still has buffered data the
            // reactor re-arms the READABLE bit immediately and the retry
            // spins on epoll + splice without making progress. Clearing the
            // pipe's WRITABLE bit after the wake forces a fresh epoll
            // report instead of an immediate re-poll on the stale bit.
            tokio::select! {
                guard = pipe_wr.writable() => {
                    // The pipe has room again. Clear its WRITABLE bit so the
                    // next writable() await re-registers with epoll instead
                    // of returning immediately on the stale bit. writable()
                    // only errors if the pipe fd is closed — nothing to
                    // clear then.
                    if let Ok(mut guard) = guard {
                        guard.clear_ready();
                    }
                }
                _ = src.readable() => {}
            }
            continue;
        }

        // ---- Phase B: pipe → dst ----
        let mut remaining = n_read;
        while remaining > 0 {
            let mut guard = dst.writable().await?;
            // SAFETY: pipe_rd_fd and dst_fd are live fds borrowed from their
            // AsyncFd wrappers for the duration of this call; splice does not
            // take ownership of either descriptor, and the null offset
            // pointers keep the kernel-managed pipe/socket positions.
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
                // Success: don't clear readiness so next writable().await
                // returns immediately if the kernel buffer still has room.
                guard.retain_ready(); // no-op, satisfies #[must_use]
                let n = ret as usize;
                counter.fetch_add(n as u64, Ordering::Relaxed);
                if n == 0 {
                    // splice(pipe → dst) returning 0 while `remaining > 0`
                    // means the pipe drained unexpectedly — NOT a clean EOF
                    // on dst. Treating it as success would silently drop the
                    // tail of the stream (the write side may have closed).
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "splice: pipe drained with data still pending",
                    ));
                }
                remaining -= n;
            } else {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) => {
                        // Clear the WRITABLE bit. Continue the inner loop
                        // to finish draining the pipe before reading more
                        // data from src (avoids pipe overflow).
                        guard.clear_ready();
                        continue;
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
/// direction). The two direction futures run concurrently; the first
/// completion wins:
/// - a **clean EOF** (half-close) in one direction keeps the opposite
///   direction running so it can carry the response — matching
///   `tokio::io::copy_bidirectional` and the half-close semantics of
///   `splice_direction`;
/// - an **error** in one direction immediately cancels the sibling (its
///   future is dropped) and propagates — previously the sibling was left
///   running on a live-but-silent connection, hanging the bridge forever
///   (`tokio::join!` waits for both).
enum Side {
    UserToWork,
    WorkToUser,
}

pub async fn bridge_splice(
    user: tokio::net::TcpStream,
    work: tokio::net::TcpStream,
) -> io::Result<(u64, u64)> {
    // Step 1: Deregister from tokio's reactor and transfer fd ownership.
    // `into_std()` may reset the fd to blocking mode; AsyncFd requires
    // non-blocking fds for correct epoll edge-triggered behavior.
    let user_std = user.into_std()?;
    user_std.set_nonblocking(true)?;
    let user_owned: OwnedFd = user_std.into();
    let work_std = work.into_std()?;
    work_std.set_nonblocking(true)?;
    let work_owned: OwnedFd = work_std.into();

    // Step 2: Wrap in AsyncFd for epoll-driven readiness.
    let user_async = AsyncFd::new(user_owned)?;
    let work_async = AsyncFd::new(work_owned)?;

    // Step 3: Create two pipe pairs (one per direction).
    let (u2w_r, u2w_w) = create_pipe_pair()?;
    let (w2u_r, w2u_w) = create_pipe_pair()?;

    // Step 4: Shared byte counters.
    let u2w_count = AtomicU64::new(0);
    let w2u_count = AtomicU64::new(0);

    // Step 5: Run both directions concurrently on the same task. First
    // completion wins; the loser is dropped when the select completes.
    let u2w_fut = splice_direction(&user_async, &u2w_r, &u2w_w, &work_async, &u2w_count);
    let w2u_fut = splice_direction(&work_async, &w2u_r, &w2u_w, &user_async, &w2u_count);
    // The pinned futures borrow the counters below; the block scopes them so
    // the pins (and their borrows) are dropped before the counts are read.
    {
        let mut u2w = std::pin::pin!(u2w_fut);
        let mut w2u = std::pin::pin!(w2u_fut);
        let first: io::Result<Side> = tokio::select! {
            r = u2w.as_mut() => r.map(|()| Side::UserToWork),
            r = w2u.as_mut() => r.map(|()| Side::WorkToUser),
        };

        match first {
            // Error: cancel the sibling by dropping its future and return
            // immediately — the caller closes both connections.
            Err(e) => return Err(e),
            // Clean half-close: splice_direction already propagated the FIN
            // to the peer. Keep the response direction alive until it
            // finishes.
            Ok(Side::UserToWork) => {
                w2u.await?;
            }
            Ok(Side::WorkToUser) => {
                u2w.await?;
            }
        }
    }

    // Step 6: Return byte counts.
    // Drop order: pipe AsyncFds → pipe OwnedFds (pipe fds closed) →
    // socket AsyncFds → socket OwnedFds (socket fds closed). Single owner each.
    Ok((u2w_count.into_inner(), w2u_count.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Helper: create two connected TCP socket pairs.
    /// Returns ((bridge_user, test_user), (bridge_work, test_work)).
    async fn socket_pairs() -> io::Result<(
        (tokio::net::TcpStream, tokio::net::TcpStream),
        (tokio::net::TcpStream, tokio::net::TcpStream),
    )> {
        let user_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let user_addr = user_listener.local_addr()?;
        let work_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let work_addr = work_listener.local_addr()?;

        let (test_user_res, accept_user_res) = tokio::join!(
            tokio::net::TcpStream::connect(user_addr),
            user_listener.accept(),
        );
        let test_user = test_user_res?;
        let (bridge_user, _) = accept_user_res?;

        let (test_work_res, accept_work_res) = tokio::join!(
            tokio::net::TcpStream::connect(work_addr),
            work_listener.accept(),
        );
        let test_work = test_work_res?;
        let (bridge_work, _) = accept_work_res?;

        Ok(((bridge_user, test_user), (bridge_work, test_work)))
    }

    /// One-direction: send data user→work, verify it arrives, then close both
    /// ends so bridge_splice returns.
    #[tokio::test]
    async fn test_bridge_splice_one_direction() {
        let ((bridge_user, mut test_user), (bridge_work, mut test_work)) =
            socket_pairs().await.expect("socket pairs");

        // Spawn bridge in background.
        let handle = tokio::spawn(async move { bridge_splice(bridge_user, bridge_work).await });

        // Send data user → work direction.
        let msg = b"hello from user to work";
        test_user.write_all(msg).await.expect("write to user");
        test_user.shutdown().await.expect("shutdown user write");

        // Read data on work side.
        let mut buf = vec![0u8; msg.len()];
        test_work
            .read_exact(&mut buf)
            .await
            .expect("read from work");
        assert_eq!(&buf, msg);

        // Close work side so bridge can complete.
        drop(test_work); // close work fd → Direction 2 sees EOF
        drop(test_user); // close user fd → Direction 1 sees EOF

        // Bridge should complete.
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(Ok((_u2w, _w2u)))) => {
                // success
            }
            Ok(Ok(Err(e))) => {
                panic!("bridge_splice error: {}", e);
            }
            Ok(Err(join_err)) => {
                panic!("join error: {}", join_err);
            }
            Err(_timeout) => {
                panic!("bridge_splice timed out after 5s — likely hung");
            }
        }
    }

    /// Bidirectional: send data both ways simultaneously.
    #[tokio::test]
    async fn test_bridge_splice_bidirectional() {
        let ((bridge_user, mut test_user), (bridge_work, mut test_work)) =
            socket_pairs().await.expect("socket pairs");

        // Spawn bridge in background.
        let handle = tokio::spawn(async move { bridge_splice(bridge_user, bridge_work).await });

        // Send data in both directions concurrently.
        let ((), ()) = tokio::join!(
            async {
                test_user.write_all(b"ping").await.expect("write ping");
                let mut buf = [0u8; 4];
                test_user.read_exact(&mut buf).await.expect("read pong");
                assert_eq!(&buf, b"pong");
                test_user.shutdown().await.expect("shutdown user");
            },
            async {
                let mut buf = [0u8; 4];
                test_work.read_exact(&mut buf).await.expect("read ping");
                assert_eq!(&buf, b"ping");
                test_work.write_all(b"pong").await.expect("write pong");
                test_work.shutdown().await.expect("shutdown work");
            },
        );

        // Bridge should complete.
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(Ok((u2w, w2u)))) => {
                assert!(u2w > 0, "should have transferred data user→work");
                assert!(w2u > 0, "should have transferred data work→user");
            }
            Ok(Ok(Err(e))) => {
                panic!("bridge_splice error: {}", e);
            }
            Ok(Err(join_err)) => {
                panic!("join error: {}", join_err);
            }
            Err(_timeout) => {
                panic!("bridge_splice timed out after 5s — likely hung");
            }
        }
    }

    /// Backpressure: a slow reader must not deadlock or busy-spin the relay.
    /// The pipe fills (dst send buffer full), Phase B parks on dst writable,
    /// and the transfer completes once the peer starts reading.
    #[tokio::test]
    async fn test_bridge_splice_backpressure_slow_reader() {
        let ((bridge_user, mut test_user), (bridge_work, mut test_work)) =
            socket_pairs().await.expect("socket pairs");

        let handle = tokio::spawn(async move { bridge_splice(bridge_user, bridge_work).await });

        // 4 MiB burst against a deliberately slow peer: the kernel send
        // buffer and the relay pipe stay full for the tail of the transfer.
        let payload = vec![0xabu8; 4 * 1024 * 1024];
        let payload_len = payload.len();
        let write = tokio::spawn(async move {
            test_user.write_all(&payload).await.expect("write burst");
            test_user.shutdown().await.expect("shutdown user write");
        });

        let mut received = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                test_work.read(&mut chunk),
            )
            .await
            .expect("slow reader stalled — backpressure must make progress")
            .expect("read");
            if n == 0 {
                break; // EOF after full drain
            }
            received += n;
            // Slow the reader down so backpressure actually builds.
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        write.await.expect("writer");
        assert_eq!(received, payload_len);

        drop(test_work);
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(Ok((u2w, _w2u)))) => assert_eq!(u2w, payload_len as u64),
            Ok(Ok(Err(e))) => panic!("bridge_splice error: {}", e),
            Ok(Err(join_err)) => panic!("join error: {}", join_err),
            Err(_timeout) => panic!("bridge_splice timed out under backpressure"),
        }
    }

    /// An error in one direction must terminate the whole bridge promptly:
    /// the sibling direction is parked on a live-but-silent peer and would
    /// otherwise hang forever (the join!-based implementation waited for
    /// both directions — audit fix: select + drop loser on first error).
    #[tokio::test]
    async fn test_bridge_splice_error_cancels_sibling() {
        let ((bridge_user, test_user), (bridge_work, mut test_work)) =
            socket_pairs().await.expect("socket pairs");

        let handle = tokio::spawn(async move { bridge_splice(bridge_user, bridge_work).await });

        // Prove the user→work direction is live before killing the user side.
        let mut t_user = test_user;
        t_user.write_all(b"hello").await.expect("write to user");
        let mut buf = [0u8; 5];
        test_work
            .read_exact(&mut buf)
            .await
            .expect("work should receive user data");
        assert_eq!(&buf, b"hello");

        // Hard-reset the user side while the work side stays open and
        // silent: the work→user direction is parked on it and must be
        // cancelled by the u2w error instead of waiting forever. Pump a
        // 64 KiB burst to the user side and wait (FIONREAD) until ALL of it
        // is queued in test_user's receive buffer — closing with unread
        // data deterministically produces an RST (not a FIN), regardless of
        // kernel buffer timing.
        use std::os::fd::AsRawFd;
        let payload = vec![0x42u8; 64 * 1024];
        test_work
            .write_all(&payload)
            .await
            .expect("write burst to user");
        let user_fd = t_user.as_raw_fd();
        let mut pending: libc::c_int = 0;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                // SAFETY: user_fd is a live fd owned by t_user for the
                // duration of this call; FIONREAD writes the number of
                // queued bytes into `pending`. The pointer is not retained
                // after the call returns.
                unsafe { libc::ioctl(user_fd, libc::FIONREAD, &mut pending) };
                if pending as usize >= payload.len() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all bytes must be queued at the user side");
        drop(t_user); // close with unread data in the receive buffer → RST

        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(Err(_e))) => {
                // Error propagated; sibling cancelled. Success.
            }
            Ok(Ok(Ok(_))) => panic!("bridge_splice should report the reset as an error"),
            Ok(Err(join_err)) => panic!("join error: {}", join_err),
            Err(_timeout) => panic!("bridge_splice hung on dead sibling"),
        }
        drop(test_work);
    }

    /// A client half-close must become a FIN at the backend only after all
    /// request bytes have drained, while leaving the reverse direction open.
    #[tokio::test]
    async fn test_bridge_splice_propagates_half_close_after_drain() {
        let ((bridge_user, mut test_user), (bridge_work, mut test_work)) =
            socket_pairs().await.expect("socket pairs");

        let handle = tokio::spawn(async move { bridge_splice(bridge_user, bridge_work).await });

        let request = b"request body";
        test_user.write_all(request).await.expect("write request");
        test_user.shutdown().await.expect("shutdown client write");

        let mut received_request = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            test_work.read_to_end(&mut received_request),
        )
        .await
        .expect("backend should receive EOF after client half-close")
        .expect("read request");
        assert_eq!(received_request, request);

        let response = b"response body";
        test_work.write_all(response).await.expect("write response");
        test_work.shutdown().await.expect("shutdown backend write");

        let mut received_response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            test_user.read_to_end(&mut received_response),
        )
        .await
        .expect("client should receive backend response and EOF")
        .expect("read response");
        assert_eq!(received_response, response);

        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(Ok((u2w, w2u)))) => {
                assert_eq!(u2w, request.len() as u64);
                assert_eq!(w2u, response.len() as u64);
            }
            Ok(Ok(Err(e))) => {
                panic!("bridge_splice error: {}", e);
            }
            Ok(Err(join_err)) => {
                panic!("join error: {}", join_err);
            }
            Err(_timeout) => {
                panic!("bridge_splice timed out after 5s — likely hung");
            }
        }
    }
}
