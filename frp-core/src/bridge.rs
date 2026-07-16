use std::sync::atomic::Ordering;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bandwidth::BandwidthLimiter;
use crate::buffer_pool::PoolGuard;
use crate::cipher_stream::{CipherReader, CipherWriter};
use crate::encryption;
use crate::transport::IoStream;
use tracing::instrument;

/// Emit a TRACE-level event with a hex-encoded field.
///
/// In release builds (`debug_assertions` off), the entire call is compiled
/// away so `hex::encode` is never evaluated.  In debug builds the standard
/// `tracing::trace!` static-filter guard still applies.
macro_rules! trace_hex {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            if tracing::level_enabled!(tracing::Level::TRACE) {
                tracing::trace!($($arg)*);
            }
        }
    };
}

/// Compress a plaintext chunk into a reusable buffer, or return a reference
/// to the original data when compression is disabled.
///
/// Returns `None` on compression failure — the caller should break its loop.
/// On success returns `Some(true)` (compressed into buf) or `Some(false)` (passthrough).
#[inline]
fn compress_chunk_into(payload: &[u8], use_compression: bool, buf: &mut Vec<u8>) -> Option<bool> {
    if use_compression {
        encryption::compress_into(payload, buf).ok()?;
        Some(true)
    } else {
        Some(false)
    }
}

/// Build a streaming Snappy decompressor when compression is enabled and the
/// `compression` feature is present; otherwise `None` (plaintext passthrough).
#[inline]
fn make_decompressor(use_compression: bool) -> Option<encryption::SnappyDecompressor> {
    #[cfg(feature = "compression")]
    {
        if use_compression {
            Some(encryption::SnappyDecompressor::new())
        } else {
            None
        }
    }
    #[cfg(not(feature = "compression"))]
    {
        let _ = use_compression;
        None
    }
}

/// Feed a chunk through the decompressor into a reusable buffer.
/// Returns `None` on decompress error — the caller should break its loop.
#[inline]
fn decompress_chunk_into<'a>(
    dec: &mut Option<encryption::SnappyDecompressor>,
    data: &'a [u8],
    buf: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    match dec {
        Some(d) => {
            d.feed_into(data, buf)
                .inspect_err(|_e| {
                    #[cfg(feature = "compression")]
                    tracing::warn!(error = %_e, "snappy decompress error in bridge: {}", _e);
                })
                .ok()?;
            Some(buf.as_slice())
        }
        None => Some(data),
    }
}

/// Unified bridge writer — Plain delegates to AsyncWrite, Encrypted wraps
/// CipherWriter and calls write_encrypted (in-place CFB encrypt + write).
enum WorkWriter<W: AsyncWrite + Unpin> {
    Plain(W),
    Encrypted(CipherWriter<W>),
}

impl<W: AsyncWrite + Unpin> WorkWriter<W> {
    /// Write data (encrypts in-place for Encrypted variant).
    async fn write_bridge_all(&mut self, data: &mut [u8]) -> io::Result<()> {
        match self {
            Self::Plain(w) => w.write_all(data).await,
            Self::Encrypted(w) => w.write_encrypted(data).await.map(|_| ()),
        }
    }

    /// Flush buffered data.
    async fn flush_bridge(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(w) => w.flush().await,
            Self::Encrypted(w) => AsyncWriteExt::flush(w).await,
        }
    }

    /// Shutdown the write half.
    async fn shutdown_bridge(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(w) => {
                let _ = AsyncWriteExt::flush(w).await;
                w.shutdown().await
            }
            Self::Encrypted(w) => AsyncWriteExt::shutdown(w).await,
        }
    }
}

/// Bridge user→work direction: read from user, optionally compress,
/// apply write bandwidth limit, write through WorkWriter.
///
/// When `pre_read` is non-empty (VHost HTTP parsing), the bytes are written
/// first. If `had_pre_read` is true, the writer is NOT shut down at the end
/// so the work→user direction can still receive the backend response.
async fn bridge_user_to_work<W: AsyncWrite + Unpin>(
    mut user_r: impl AsyncReadExt + Unpin,
    mut writer: WorkWriter<W>,
    use_compression: bool,
    pre_read: Vec<u8>,
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let had_pre_read = !pre_read.is_empty();

    if had_pre_read {
        // Pre-read bytes (VHost HTTP parsing): write through WorkWriter.
        // CipherWriter variant encrypts automatically.
        let mut pre_read_buf = pre_read;
        if writer.write_bridge_all(&mut pre_read_buf).await.is_err() {
            return;
        }
    }

    let mut buf = PoolGuard::acquire();
    let cap = buf.as_mut_slice().len();
    let mut comp_buf = Vec::new();
    loop {
        let n = match user_r.read(buf.as_mut_slice()).await {
            Ok(0) => break,
            Ok(n) => {
                trace_hex!(n, first_hex = %hex::encode(&buf.raw_buf()[..n.min(32)]), "bridge user_to_work: read {} bytes", n);
                if let Some(ref m) = metrics {
                    m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                }
                n
            }
            Err(_) => break,
        };

        if use_compression {
            if compress_chunk_into(&buf.raw_buf()[..n], true, &mut comp_buf).is_none() {
                break;
            }
            if let Some(ref mut lim) = write_limiter {
                lim.consume(comp_buf.len()).await;
            }
            if writer.write_bridge_all(&mut comp_buf).await.is_err() {
                break;
            }
            // comp_buf is cleared on next compress_chunk_into call
        } else {
            let slice = &mut buf.as_mut_slice()[..n];
            if let Some(ref mut lim) = write_limiter {
                lim.consume(slice.len()).await;
            }
            if writer.write_bridge_all(slice).await.is_err() {
                break;
            }
        }

        // Conditional flush: batch on full reads unless compressing
        if (use_compression || n < cap) && writer.flush_bridge().await.is_err() {
            break;
        }
    }

    // Symmetric shutdown: signal EOF to work side.
    // When pre_read bytes were forwarded (e.g. VHost), leave writer open
    // so work_to_user can receive the backend response.
    if !had_pre_read {
        let _ = writer.shutdown_bridge().await;
    }
}

/// Bridge work→user direction: read from work (plain or via CipherReader),
/// decompress, apply read bandwidth limit, write to user.
async fn bridge_work_to_user(
    mut work_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    mut read_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let mut buf = PoolGuard::acquire();
    let cap = buf.as_mut_slice().len();
    let mut decomp_buf = Vec::new();
    let mut decompressor = make_decompressor(use_compression);
    loop {
        let n = match work_r.read(buf.as_mut_slice()).await {
            Ok(0) => break,
            Ok(n) => {
                trace_hex!(n, first_hex = %hex::encode(&buf.raw_buf()[..n.min(32)]), "bridge work_to_user: read {} bytes", n);
                n
            }
            Err(_) => break,
        };

        let plaintext =
            match decompress_chunk_into(&mut decompressor, &buf.raw_buf()[..n], &mut decomp_buf) {
                Some(p) => p,
                None => break,
            };

        if !plaintext.is_empty() {
            // Apply read bandwidth limit before writing to user
            if let Some(ref mut lim) = read_limiter {
                lim.consume(plaintext.len()).await;
            }

            if user_w.write_all(plaintext).await.is_err() {
                break;
            }
            if let Some(ref m) = metrics {
                m.bytes_out
                    .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
            }
            // Conditional flush: batch on full reads unless compressing
            if (use_compression || n < cap) && user_w.flush().await.is_err() {
                break;
            }
        }
    }

    // Flush remaining buffered compressed data
    if let Some(ref mut dec) = decompressor {
        match dec.flush() {
            Ok(plaintext) if !plaintext.is_empty() => {
                if let Err(e) = user_w.write_all(&plaintext).await {
                    tracing::debug!(error = %e, "bridge flush: user_w.write_all failed");
                }
                if let Some(ref m) = metrics {
                    m.bytes_out
                        .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                }
                if let Err(e) = user_w.flush().await {
                    tracing::debug!(error = %e, "bridge flush: user_w.flush failed");
                }
            }
            #[cfg(feature = "compression")]
            Err(e) => {
                tracing::warn!(error = %e, "snappy flush error in bridge: {}", e);
            }
            _ => {}
        }
    }

    // Symmetric shutdown: signal EOF to user side
    let _ = user_w.flush().await;
    if let Err(e) = user_w.shutdown().await {
        tracing::debug!(error = %e, "bridge shutdown: user_w.shutdown failed");
    }
}

/// Bridge encrypted data between two IoStreams, splitting them internally.
#[allow(clippy::too_many_arguments)]
#[instrument(
    skip(user, work, key, pre_read, read_limiter, write_limiter, metrics),
    fields(use_compression)
)]
pub async fn bridge_encrypted_io(
    user: IoStream,
    work: IoStream,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    read_limiter: Option<&mut BandwidthLimiter>,
    write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let (u_r, u_w) = user.into_split();
    let (w_r, w_w) = work.into_split();
    bridge_encrypted(
        u_r,
        u_w,
        w_r,
        w_w,
        key,
        use_compression,
        pre_read,
        read_limiter,
        write_limiter,
        metrics,
    )
    .await;
}

/// Bridge data between user and work connections over an encrypted+compressed channel.
/// Matches Go frp v0.69.1: compress (Snappy) → encrypt (AES-128-CFB streaming).
///
/// Encryption uses streaming CFB: work_r / work_w are wrapped in
/// `CipherReader` / `CipherWriter` internally. A single random IV is sent
/// per direction on the first write/read, then all subsequent data is
/// encrypted/decrypted with continuous cipher state.
///
/// `pre_read` bytes (e.g., VHost HTTP body) are written through the encrypting
/// writer before the main bridge loop, ensuring they share the same IV and
/// CFB state.
///
/// `read_limiter` limits work→user (download). `write_limiter` limits user→work (upload).
#[allow(clippy::too_many_arguments)]
#[instrument(
    skip(
        user_r,
        user_w,
        work_r,
        work_w,
        key,
        pre_read,
        read_limiter,
        write_limiter,
        metrics
    ),
    fields(use_compression)
)]
pub async fn bridge_encrypted(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    mut read_limiter: Option<&mut BandwidthLimiter>,
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let mut enc_work_w = CipherWriter::new(work_w, *key);

    // Eagerly flush the IV to unblock the peer's CipherReader.
    // Without this, when both sides use CipherWriter/CipherReader pairs,
    // each side's work_to_user task blocks on CipherReader::read() waiting
    // for the other side's IV, while the other side's user_to_work task
    // blocks waiting for user data — deadlock. Flushing here sends our
    // random IV immediately so the peer's CipherReader can make progress.
    if enc_work_w.flush().await.is_err() {
        return;
    }

    let enc_work_r = CipherReader::new(work_r, *key);

    let user_to_work = bridge_user_to_work(
        user_r,
        WorkWriter::Encrypted(enc_work_w),
        use_compression,
        pre_read,
        write_limiter,
        metrics.clone(),
    );
    let work_to_user = bridge_work_to_user(enc_work_r, user_w, use_compression, read_limiter, metrics);

    let _ = tokio::join!(user_to_work, work_to_user);
}

/// Plain (unencrypted) bidirectional bridge with optional compression.
#[instrument(
    skip(user_r, user_w, work_r, work_w, pre_read, metrics),
    fields(use_compression)
)]
pub async fn bridge_plain(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let had_pre_read = !pre_read.is_empty();
    tracing::debug!(
        had_pre_read,
        "bridge_plain: starting, had_pre_read={}",
        had_pre_read
    );

    let user_to_work = bridge_user_to_work(
        user_r,
        WorkWriter::Plain(work_w),
        use_compression,
        pre_read,
        None,
        metrics.clone(),
    );
    let work_to_user = bridge_work_to_user(work_r, user_w, use_compression, None, metrics);

    let _ = tokio::join!(user_to_work, work_to_user);
}

/// Plain (unencrypted) bidirectional bridge with optional bandwidth limiting
/// and compression.
///
/// Uses the same `join!`-of-two-halves pattern as `bridge_encrypted` so that
/// both directions run to completion independently. Supports compression
/// (Snappy) with reusable buffers, matching `bridge_plain`.
///
/// `read_limiter` throttles work→user (download).
/// `write_limiter` throttles user→work (upload).
#[allow(clippy::too_many_arguments)]
pub async fn bridge_plain_rate_limited(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    mut read_limiter: Option<&mut BandwidthLimiter>,
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let user_to_work = bridge_user_to_work(
        user_r,
        WorkWriter::Plain(work_w),
        use_compression,
        pre_read,
        write_limiter,
        metrics.clone(),
    );
    let work_to_user = bridge_work_to_user(work_r, user_w, use_compression, read_limiter, metrics);

    let _ = tokio::join!(user_to_work, work_to_user);
}

// ── Zero-copy Linux splice bridge ──────────────────────────────────────────

/// Pipe capacity used for splice relay (Linux default pipe size).
#[cfg(target_os = "linux")]
const PIPE_CAPACITY: usize = 65536;

/// SPLICE_F_MOVE flag — hint that pages can be moved (not copied).
#[cfg(target_os = "linux")]
const SPLICE_F_MOVE: libc::c_uint = 1;

/// Zero-copy bridge between two TcpStreams using `splice(2)`.
///
/// **DISABLED for v0.7.0**: the non-blocking EAGAIN loop can busy-wait
/// under backpressure, saturating CPU with 2 spawn_blocking tasks per
/// connection. Re-enable with AsyncFd/epoll-driven readiness waiting.
///
/// Data is relayed kernel-space via two pipe pairs (one per direction),
/// avoiding userspace copies entirely. Only available on Linux.
///
/// Returns `(bytes_user_to_work, bytes_work_to_user)` on success.
/// On failure, the TcpStreams are consumed (their fds are invalid after
/// `into_std()`).
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub async fn bridge_plain_zero_copy(
    user: tokio::net::TcpStream,
    work: tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let user_fd = user.as_raw_fd();
    let work_fd = work.as_raw_fd();

    // Convert to std to prevent tokio from closing fds on drop.
    let _user = user.into_std()?;
    let _work = work.into_std()?;

    // Create two pipe pairs — one per direction.
    let (u2w_r, u2w_w) = create_pipe()?;
    let (w2u_r, w2u_w) = create_pipe()?;

    let u2w_bytes = Arc::new(AtomicU64::new(0));
    let w2u_bytes = Arc::new(AtomicU64::new(0));

    let u2w = {
        let b = u2w_bytes.clone();
        tokio::task::spawn_blocking(move || splice_relay(user_fd, u2w_w, u2w_r, work_fd, &b))
    };

    let w2u = {
        let b = w2u_bytes.clone();
        tokio::task::spawn_blocking(move || splice_relay(work_fd, w2u_w, w2u_r, user_fd, &b))
    };

    // Wait for both directions.
    let (r1, r2) = tokio::join!(u2w, w2u);

    // SAFETY: pipe fds were created by create_pipe() above and are valid.
    // close() is safe to call on valid file descriptors; errors are ignored
    // since these are cleanup fds and we cannot recover anyway.
    unsafe {
        libc::close(u2w_r);
        libc::close(u2w_w);
        libc::close(w2u_r);
        libc::close(w2u_w);
    }

    // If both directions panicked, propagate error.
    match (r1, r2) {
        (Err(e), _) | (_, Err(e)) if e.is_panic() => {
            Err(std::io::Error::other(format!("splice panic: {e}")))
        }
        _ => Ok((
            u2w_bytes.load(Ordering::Relaxed),
            w2u_bytes.load(Ordering::Relaxed),
        )),
    }
}

/// Relay loop: splice(fd_in → pipe_wr), then splice(pipe_rd → fd_out).
/// Runs in spawn_blocking since splice may block.
#[cfg(target_os = "linux")]
fn splice_relay(
    fd_in: i32,
    pipe_wr: i32,
    pipe_rd: i32,
    fd_out: i32,
    total: &std::sync::atomic::AtomicU64,
) -> std::io::Result<()> {
    use std::sync::atomic::Ordering;
    loop {
        // SAFETY: fd_in and pipe_wr are valid file descriptors (fd_in is
        // a kernel socket fd, pipe_wr was created by create_pipe). null
        // off_out/off_in pointers tell the kernel to use the current file
        // offset. PIPE_CAPACITY is a safe upper bound.
        let n = unsafe {
            libc::splice(
                fd_in,
                std::ptr::null_mut::<libc::loff_t>(),
                pipe_wr,
                std::ptr::null_mut::<libc::loff_t>(),
                PIPE_CAPACITY,
                SPLICE_F_MOVE,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => return Err(err),
            }
        }
        if n == 0 {
            return Ok(());
        }

        // Move same bytes from pipe to destination socket (may need multiple
        // calls if pipe write was shorter than the splice into it).
        let mut remaining = n as usize;
        // SAFETY: pipe_rd and fd_out are valid file descriptors (pipe_rd
        // was created by create_pipe; fd_out is a kernel socket fd).
        // Same null-offset contract as the fd_in→pipe splice above.
        while remaining > 0 {
            let m = unsafe {
                libc::splice(
                    pipe_rd,
                    std::ptr::null_mut::<libc::loff_t>(),
                    fd_out,
                    std::ptr::null_mut::<libc::loff_t>(),
                    remaining,
                    SPLICE_F_MOVE,
                )
            };
            if m < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                    _ => return Err(err),
                }
            }
            if m == 0 {
                return Ok(());
            }
            remaining -= m as usize;
            total.fetch_add(m as u64, Ordering::Relaxed);
        }
    }
}

/// Create a pipe pair with O_NONBLOCK.
#[cfg(target_os = "linux")]
fn create_pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [-1i32; 2];
    // SAFETY: pipe2 writes two file descriptors into `fds`, which is a
    // valid 2-element i32 array on the stack. O_NONBLOCK is the only flag.
    // Errors are checked by the return value below.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Plain bridge: basic bidirectional data flow.
    #[tokio::test]
    async fn test_bridge_plain_bidirectional() {
        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
        let (mut w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

        tokio::spawn(async move {
            bridge_plain(
                u_r_bridge,
                u_w_bridge,
                w_r_bridge,
                w_w_bridge,
                false,
                vec![],
                None,
            )
            .await;
        });

        // User → Work
        u_w_test.write_all(b"user->work").await.unwrap();
        u_w_test.flush().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"user->work");

        // Work → User
        w_w_test.write_all(b"work->user").await.unwrap();
        w_w_test.flush().await.unwrap();
        let n2 = u_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"work->user");
    }

    /// Plain bridge with pre_read: bytes forwarded before main loop.
    #[tokio::test]
    async fn test_bridge_plain_pre_read() {
        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
        let (_w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        let pre_read = b"pre-read body".to_vec();

        tokio::spawn(async move {
            bridge_plain(
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge, false, pre_read, None,
            )
            .await;
        });

        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pre-read body");

        u_w_test.write_all(b"after").await.unwrap();
        u_w_test.flush().await.unwrap();
        let n2 = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"after");
    }

    /// Encrypted bridge: smoke test — starts, processes data, completes without panic.
    /// Content verification is done in cipher_stream tests.
    /// Note: bridge uses tokio::join! — both directions must complete. We drop
    /// both write sides to signal EOF on both read sides.
    #[tokio::test]
    async fn test_encrypted_bridge_smoke() {
        let key = crate::encryption::derive_key("smoke_test_key_42");

        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, _w_r_test) = tokio::io::duplex(65536);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        let handle = tokio::spawn(async move {
            bridge_encrypted(
                u_r_bridge,
                u_w_bridge,
                w_r_bridge,
                w_w_bridge,
                &key,
                false,
                vec![],
                None,
                None,
                None,
            )
            .await;
        });

        u_w_test.write_all(b"hello encrypted world").await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test); // EOF on user_r
        drop(w_w_test); // EOF on work_r (so enc_work_r.read() returns 0)

        handle.await.unwrap();
    }

    /// Encrypted bridge with compression: smoke test.
    #[tokio::test]
    async fn test_encrypted_bridge_compression_smoke() {
        let key = crate::encryption::derive_key("comp_smoke_key_99");

        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, _w_r_test) = tokio::io::duplex(65536);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        let handle = tokio::spawn(async move {
            bridge_encrypted(
                u_r_bridge,
                u_w_bridge,
                w_r_bridge,
                w_w_bridge,
                &key,
                true,
                vec![],
                None,
                None,
                None,
            )
            .await;
        });

        let msg = b"AAAA".repeat(256);
        u_w_test.write_all(&msg).await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test);
        drop(w_w_test);

        handle.await.unwrap();
    }

    /// Encrypted bridge: large data smoke test.
    #[tokio::test]
    async fn test_encrypted_bridge_large_smoke() {
        let key = crate::encryption::derive_key("large_smoke_12345");

        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
        let (w_w_bridge, _w_r_test) = tokio::io::duplex(256 * 1024);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(256 * 1024);

        let handle = tokio::spawn(async move {
            bridge_encrypted(
                u_r_bridge,
                u_w_bridge,
                w_r_bridge,
                w_w_bridge,
                &key,
                false,
                vec![],
                None,
                None,
                None,
            )
            .await;
        });

        let large_msg = vec![0x42u8; 100_000];
        u_w_test.write_all(&large_msg).await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test);
        drop(w_w_test);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn bridge_plain_batches_flushes_on_full_reads() {
        use std::pin::Pin;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        // Writer that counts flush() calls and discards data.
        struct CountingWriter(Arc<AtomicUsize>);
        impl AsyncWrite for CountingWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                b: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        // Reader that yields two full-capacity chunks then EOF.
        struct TwoFullChunks(usize);
        impl AsyncRead for TwoFullChunks {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.0 == 0 {
                    return Poll::Ready(Ok(()));
                } // EOF
                self.0 -= 1;
                let n = buf.remaining();
                buf.initialize_unfilled_to(n);
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }

        let flushes = Arc::new(AtomicUsize::new(0));
        let user_r = TwoFullChunks(2);
        let work_w = CountingWriter(flushes.clone());
        // work_r EOFs immediately; user_w sinks.
        let work_r = TwoFullChunks(0);
        let user_w = CountingWriter(Arc::new(AtomicUsize::new(0)));

        bridge_plain(user_r, user_w, work_r, work_w, false, Vec::new(), None).await;

        // Two full-capacity reads => no per-chunk flush; exactly one final flush.
        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "expected batched flush, got per-chunk"
        );
    }

    #[test]
    fn test_compress_chunk_identity_when_disabled() {
        let mut buf = Vec::new();
        let compressed = compress_chunk_into(b"hello", false, &mut buf).unwrap();
        assert!(!compressed); // false = passthrough (no compression)
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let original = b"AAAA".repeat(64);
        let mut comp_buf = Vec::new();
        compress_chunk_into(&original, true, &mut comp_buf).expect("compress ok");
        let mut dec = make_decompressor(true);
        let mut decomp_buf = Vec::new();
        let out =
            decompress_chunk_into(&mut dec, &comp_buf, &mut decomp_buf).expect("decompress ok");
        assert_eq!(out, original);
    }

    #[test]
    fn test_decompress_chunk_identity_when_none() {
        let mut dec: Option<encryption::SnappyDecompressor> = None;
        let mut buf = Vec::new();
        let out = decompress_chunk_into(&mut dec, b"raw", &mut buf).unwrap();
        assert_eq!(out, b"raw");
    }

    /// Rate-limited plain bridge: bidirectional data flow with high limit.
    #[tokio::test]
    async fn test_bridge_plain_rate_limited_smoke() {
        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
        let (mut w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

        // 1 GB/s — effectively unlimited for small data
        let mut wlim = BandwidthLimiter::new(1_000_000_000);
        let mut rlim = BandwidthLimiter::new(1_000_000_000);

        tokio::spawn(async move {
            bridge_plain_rate_limited(
                u_r_bridge,
                u_w_bridge,
                w_r_bridge,
                w_w_bridge,
                false,
                vec![],
                Some(&mut rlim),
                Some(&mut wlim),
                None,
            )
            .await;
        });

        // User → Work
        u_w_test.write_all(b"user->work").await.unwrap();
        u_w_test.flush().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"user->work");

        // Work → User
        w_w_test.write_all(b"work->user").await.unwrap();
        w_w_test.flush().await.unwrap();
        let n2 = u_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"work->user");
    }

    /// Rate-limited plain bridge: low bandwidth caps transfer speed.
    #[tokio::test]
    async fn test_bridge_plain_rate_limited_bandwidth() {
        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        // 1 KB/s — very slow. Burst = 1 KB so first KB instant, rest throttled.
        let mut wlim = BandwidthLimiter::new(1024);

        let start = std::time::Instant::now();

        let handle = tokio::spawn(async move {
            bridge_plain_rate_limited(
                u_r_bridge,
                u_w_bridge,
                w_r_bridge,
                w_w_bridge,
                false,
                vec![],
                None,
                Some(&mut wlim),
                None,
            )
            .await;
        });

        // Send 2 KB. 1 KB burst + 1 KB deficit → ~1 s wait.
        let data = vec![0x41u8; 2 * 1024];
        u_w_test.write_all(&data).await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test); // EOF on user_r
        drop(w_w_test); // EOF on work_r

        // Drain work side
        let mut buf = vec![0u8; 4 * 1024];
        let mut total = 0;
        loop {
            match w_r_test.read(&mut buf[total..]).await {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }

        handle.await.unwrap();
        let elapsed = start.elapsed().as_millis();

        assert_eq!(total, 2 * 1024, "all 2 KB should be transferred");
        assert!(
            elapsed >= 500,
            "expected >= 500 ms with 1 KB/s limit, got {elapsed} ms"
        );
        assert!(elapsed <= 3000, "expected <= 3000 ms, got {elapsed} ms");
    }
}
