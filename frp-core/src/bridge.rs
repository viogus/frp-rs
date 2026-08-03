use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bandwidth::BandwidthLimiter;
use crate::buffer_pool::PoolGuard;
use crate::cipher_stream::{CipherReader, CipherWriter};
use crate::encryption;
use crate::transport::IoStream;

/// Upper bound for the reusable work→user batch buffer. Frames returned by
/// the decompressor are accumulated up to this cap, then written/flushed once,
/// so a transport read containing many small frames costs one write instead of
/// one write per frame.
const MAX_WORK_TO_USER_BATCH: usize = 256 * 1024;

/// Body-less HTTP 504 response written to the user when the backend (work
/// conn) produces no response bytes within `header_timeout`. Matches Go frp's
/// `httputil.ReverseProxy` + `ResponseHeaderTimeoutS` (VhostHTTPTimeout)
/// semantics: the response head never arrived in time, so the client gets a
/// bare `504 Gateway Timeout` with `Content-Length: 0` and no body.
const GATEWAY_TIMEOUT_504: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n";

/// Emit a TRACE-level event with a hex-encoded field.
///
/// In release builds (`debug_assertions` off), the entire call is compiled
/// away so `crate::hex_encode` is never evaluated.  In debug builds the standard
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
/// Uses a connection-lifetime [`encryption::SnappyCompressor`] so the
/// ~128 KiB `FrameEncoder` allocation is paid once instead of once per chunk.
///
/// Returns `None` on compression failure — the caller should break its loop.
/// On success returns `Some(true)` (compressed into buf) or `Some(false)` (passthrough).
#[inline]
fn compress_chunk_into(
    compressor: &mut Option<encryption::SnappyCompressor>,
    payload: &[u8],
    use_compression: bool,
    buf: &mut Vec<u8>,
) -> Option<bool> {
    if use_compression {
        compressor.as_mut()?.compress(payload, buf).ok()?;
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

/// Build a reusable Snappy compressor when compression is enabled and the
/// `compression` feature is present; otherwise `None` (plaintext passthrough).
#[inline]
fn make_compressor(use_compression: bool) -> Option<encryption::SnappyCompressor> {
    #[cfg(feature = "compression")]
    {
        if use_compression {
            Some(encryption::SnappyCompressor::new())
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

/// Feed a chunk through the decompressor, appending decoded output to `buf`.
/// Returns the number of bytes appended, or `None` on decompress error.
///
/// Unlike a slice-returning variant, this does not borrow `buf`, so callers
/// can keep feeding frames into the same accumulation buffer and avoid a
/// per-frame memcpy through a scratch buffer. When no decompressor is
/// configured, `data` is appended unchanged (plaintext passthrough).
#[inline]
fn decompress_chunk_append_into(
    dec: &mut Option<encryption::SnappyDecompressor>,
    data: &[u8],
    buf: &mut Vec<u8>,
) -> Option<usize> {
    match dec {
        Some(d) => {
            let before = buf.len();
            d.feed_into_append_progress(data, buf)
                .inspect_err(|_e| {
                    #[cfg(feature = "compression")]
                    tracing::warn!(error = %_e, "snappy decompress error in bridge: {}", _e);
                })
                .ok()?;
            Some(buf.len() - before)
        }
        None => {
            buf.extend_from_slice(data);
            Some(data.len())
        }
    }
}

/// Unified bridge writer — Plain delegates to AsyncWrite, Encrypted wraps
/// CipherWriter and calls write_encrypted (in-place CFB encrypt + write).
///
/// `CipherWriter` stores a multi-KiB scratch buffer, making it much larger
/// than `Plain(W)`. Boxing it would add a heap allocation per bridge call,
/// so we accept the enum size difference here.
#[allow(clippy::large_enum_variant)]
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
        if let Err(e) = writer.write_bridge_all(&mut pre_read_buf).await {
            tracing::warn!(error = %e, "bridge user_to_work: pre_read write failed");
            return;
        }
    }

    let mut buf = PoolGuard::acquire();
    let cap = buf.as_mut_slice().len();
    let mut comp_buf = Vec::new();
    let mut compressor = make_compressor(use_compression);
    loop {
        let n = match user_r.read(buf.as_mut_slice()).await {
            Ok(0) => break,
            Ok(n) => {
                trace_hex!(n, first_hex = %crate::hex_encode(&buf.raw_buf()[..n.min(32)]), "bridge user_to_work: read {} bytes", n);
                if let Some(ref m) = metrics {
                    m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                }
                n
            }
            Err(e) => {
                tracing::debug!(error = %e, "bridge user_to_work: read error");
                break;
            }
        };

        if use_compression {
            if compress_chunk_into(&mut compressor, &buf.raw_buf()[..n], true, &mut comp_buf)
                .is_none()
            {
                tracing::warn!("bridge user_to_work: compression failed");
                break;
            }
            if let Some(ref mut lim) = write_limiter {
                lim.consume(comp_buf.len()).await;
            }
            if let Err(e) = writer.write_bridge_all(&mut comp_buf).await {
                tracing::debug!(error = %e, "bridge user_to_work: write error (compressed)");
                break;
            }
            // comp_buf is swapped with the compressor's internal sink on the
            // next compress call, so its capacity is retained across chunks.
        } else {
            let slice = &mut buf.as_mut_slice()[..n];
            if let Some(ref mut lim) = write_limiter {
                lim.consume(slice.len()).await;
            }
            if let Err(e) = writer.write_bridge_all(slice).await {
                tracing::debug!(error = %e, "bridge user_to_work: write error");
                break;
            }
        }

        // Conditional flush: batch on full reads unless compressing
        if use_compression || n < cap {
            if let Err(e) = writer.flush_bridge().await {
                tracing::debug!(error = %e, "bridge user_to_work: flush error");
                break;
            }
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
///
/// When `header_timeout` is `Some`, only the FIRST read on this direction is
/// wrapped in `tokio::time::timeout` — if the backend produces no response
/// bytes before the deadline (Go frp VhostHTTPTimeout / ResponseHeaderTimeoutS
/// semantics), a body-less `504 Gateway Timeout` is written to the user and
/// the direction ends. First byte arrival is taken as the (approximate) start
/// of the response head; subsequent reads are never timed out.
async fn bridge_work_to_user(
    mut work_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    mut read_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    header_timeout: Option<Duration>,
) {
    let mut buf = PoolGuard::acquire();
    let cap = buf.as_mut_slice().len();
    let mut batch_buf = Vec::new();
    let mut decompressor = make_decompressor(use_compression);
    let mut header_timeout = header_timeout;
    'read_loop: loop {
        let read_res = match header_timeout.take() {
            Some(timeout) => {
                match tokio::time::timeout(timeout, work_r.read(buf.as_mut_slice())).await {
                    Ok(r) => r,
                    Err(_elapsed) => {
                        tracing::debug!(
                            "bridge work_to_user: backend response header timeout, writing 504"
                        );
                        let _ = user_w.write_all(GATEWAY_TIMEOUT_504).await;
                        let _ = user_w.flush().await;
                        break 'read_loop;
                    }
                }
            }
            None => work_r.read(buf.as_mut_slice()).await,
        };
        let n = match read_res {
            Ok(0) => break,
            Ok(n) => {
                trace_hex!(n, first_hex = %crate::hex_encode(&buf.raw_buf()[..n.min(32)]), "bridge work_to_user: read {} bytes", n);
                n
            }
            Err(e) => {
                tracing::debug!(error = %e, "bridge work_to_user: read error");
                break;
            }
        };

        let mut compressed_input = &buf.raw_buf()[..n];
        loop {
            if decompressor.is_some() {
                // Compressed path: decode directly into the batch buffer,
                // eliminating the per-frame scratch memcpy. `added` counts
                // the bytes produced by this feed for limiter/metrics.
                let added = match decompress_chunk_append_into(
                    &mut decompressor,
                    compressed_input,
                    &mut batch_buf,
                ) {
                    Some(a) => a,
                    None => {
                        tracing::warn!("bridge work_to_user: decompression failed");
                        break 'read_loop;
                    }
                };
                compressed_input = &[];
                if added == 0 {
                    if decompressor
                        .as_ref()
                        .is_some_and(encryption::SnappyDecompressor::has_complete_frame)
                    {
                        // Metadata-only batches are deliberately bounded inside
                        // feed_into_progress; yield before draining the next batch.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    break;
                }

                // Apply read bandwidth limit before writing to user
                if let Some(ref mut lim) = read_limiter {
                    lim.consume(added).await;
                }
                if let Some(ref m) = metrics {
                    m.bytes_out.fetch_add(added as u64, Ordering::Relaxed);
                }
                if batch_buf.len() >= MAX_WORK_TO_USER_BATCH {
                    if let Err(e) = user_w.write_all(&batch_buf).await {
                        tracing::debug!(error = %e, "bridge work_to_user: write error (batch)");
                        break 'read_loop;
                    }
                    if let Err(e) = user_w.flush().await {
                        tracing::debug!(error = %e, "bridge work_to_user: flush error (batch)");
                        break 'read_loop;
                    }
                    batch_buf.clear();
                }
            } else {
                // Plaintext passthrough: write immediately, flushing on short
                // reads for interactive latency.
                let plaintext = compressed_input;
                if let Some(ref mut lim) = read_limiter {
                    lim.consume(plaintext.len()).await;
                }
                if let Some(ref m) = metrics {
                    m.bytes_out
                        .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                }
                if let Err(e) = user_w.write_all(plaintext).await {
                    tracing::debug!(error = %e, "bridge work_to_user: write error");
                    break 'read_loop;
                }
                if n < cap {
                    if let Err(e) = user_w.flush().await {
                        tracing::debug!(error = %e, "bridge work_to_user: flush error");
                        break 'read_loop;
                    }
                }
                break;
            }
        }
        if !batch_buf.is_empty() {
            if let Err(e) = user_w.write_all(&batch_buf).await {
                tracing::debug!(error = %e, "bridge work_to_user: write error (batch)");
                break 'read_loop;
            }
            if let Err(e) = user_w.flush().await {
                tracing::debug!(error = %e, "bridge work_to_user: flush error (batch)");
                break 'read_loop;
            }
            batch_buf.clear();
        }
    }

    // Every complete frame is drained before the next transport read. At EOF,
    // only validate that no partial frame remains; never invoke the synchronous
    // legacy flush path, whose compatibility semantics may scan metadata.
    if let Some(ref mut dec) = decompressor {
        if let Err(e) = dec.validate_partial_eof() {
            #[cfg(feature = "compression")]
            tracing::warn!(error = %e, "snappy EOF validation failed in bridge: {}", e);
            #[cfg(not(feature = "compression"))]
            let _ = e;
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
pub async fn bridge_encrypted_io(
    user: IoStream,
    work: IoStream,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    read_limiter: Option<&mut BandwidthLimiter>,
    write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    header_timeout: Option<Duration>,
) {
    tracing::debug!(use_compression, "bridge_encrypted_io: starting");
    let (u_r, u_w) = user.into_split().unwrap();
    let (w_r, w_w) = work.into_split().unwrap();
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
        header_timeout,
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
pub async fn bridge_encrypted(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    read_limiter: Option<&mut BandwidthLimiter>,
    write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    header_timeout: Option<Duration>,
) {
    tracing::debug!(use_compression, "bridge_encrypted: starting");
    let mut enc_work_w = CipherWriter::new(work_w, *key);

    // Eagerly flush the IV to unblock the peer's CipherReader.
    // Without this, when both sides use CipherWriter/CipherReader pairs,
    // each side's work_to_user task blocks on CipherReader::read() waiting
    // for the other side's IV, while the other side's user_to_work task
    // blocks waiting for user data — deadlock. Flushing here sends our
    // random IV immediately so the peer's CipherReader can make progress.
    if let Err(e) = enc_work_w.flush().await {
        tracing::warn!(error = %e, "bridge_encrypted: IV flush failed (guaranteed deadlock)");
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
    let work_to_user = bridge_work_to_user(
        enc_work_r,
        user_w,
        use_compression,
        read_limiter,
        metrics,
        header_timeout,
    );

    let _ = tokio::join!(user_to_work, work_to_user);
}

/// Plain (unencrypted) bidirectional bridge with optional compression.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_plain(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    header_timeout: Option<Duration>,
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
    let work_to_user = bridge_work_to_user(
        work_r,
        user_w,
        use_compression,
        None,
        metrics,
        header_timeout,
    );

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
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    read_limiter: Option<&mut BandwidthLimiter>,
    write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    header_timeout: Option<Duration>,
) {
    let user_to_work = bridge_user_to_work(
        user_r,
        WorkWriter::Plain(work_w),
        use_compression,
        pre_read,
        write_limiter,
        metrics.clone(),
    );
    let work_to_user = bridge_work_to_user(
        work_r,
        user_w,
        use_compression,
        read_limiter,
        metrics,
        header_timeout,
    );

    let _ = tokio::join!(user_to_work, work_to_user);
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
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge, false, pre_read, None, None,
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

        bridge_plain(
            user_r,
            user_w,
            work_r,
            work_w,
            false,
            Vec::new(),
            None,
            None,
        )
        .await;

        // Two full-capacity reads => no per-chunk flush; exactly one final flush.
        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "expected batched flush, got per-chunk"
        );
    }

    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn bridge_work_to_user_batches_compressed_frames() {
        use std::pin::Pin;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct CountingWriter {
            writes: Arc<AtomicUsize>,
            flushes: Arc<AtomicUsize>,
        }
        impl AsyncWrite for CountingWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                b: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.writes.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                self.flushes.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Reader that yields one transport chunk containing three snappy
        // frames (each decompresses to 64 KiB), then EOF.
        struct OneShot(Option<Vec<u8>>);
        impl AsyncRead for OneShot {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                let Some(data) = self.0.take() else {
                    return Poll::Ready(Ok(()));
                };
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.0 = Some(data[n..].to_vec());
                }
                Poll::Ready(Ok(()))
            }
        }

        let mut frames = Vec::new();
        let payload = vec![0x42u8; 64 * 1024];
        for _ in 0..3 {
            frames.extend_from_slice(&crate::encryption::compress(&payload).unwrap());
        }

        let writes = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(AtomicUsize::new(0));
        bridge_work_to_user(
            OneShot(Some(frames)),
            CountingWriter {
                writes: writes.clone(),
                flushes: flushes.clone(),
            },
            true,
            None,
            None,
            None,
        )
        .await;

        // Three 64 KiB frames in one read => one batched write, plus the
        // final EOF flush. The old path wrote and flushed once per frame.
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(flushes.load(Ordering::SeqCst), 2);
    }

    // ── Extracted helper unit tests (bridge_user_to_work, bridge_work_to_user) ──

    /// bridge_user_to_work: plain basic forwarding.
    #[tokio::test]
    async fn test_bridge_user_to_work_plain_basic() {
        let (mut u_w_test, u_r) = tokio::io::duplex(65536);
        let (w_w, mut w_r_test) = tokio::io::duplex(65536);

        tokio::spawn(async move {
            bridge_user_to_work(u_r, WorkWriter::Plain(w_w), false, vec![], None, None).await;
        });

        u_w_test.write_all(b"hello").await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test); // EOF

        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    /// bridge_user_to_work: pre_read bytes arrive before main loop data.
    #[tokio::test]
    async fn test_bridge_user_to_work_pre_read() {
        let (mut u_w_test, u_r) = tokio::io::duplex(65536);
        let (w_w, mut w_r_test) = tokio::io::duplex(65536);

        let pre_read = b"pre-read body".to_vec();

        tokio::spawn(async move {
            bridge_user_to_work(u_r, WorkWriter::Plain(w_w), false, pre_read, None, None).await;
        });

        // pre_read should arrive first
        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pre-read body");

        u_w_test.write_all(b"after").await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test);

        let n2 = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"after");
    }

    /// bridge_work_to_user: basic forwarding.
    #[tokio::test]
    async fn test_bridge_work_to_user_basic() {
        let (mut w_w_test, w_r) = tokio::io::duplex(65536);
        let (u_w, mut u_r_test) = tokio::io::duplex(65536);

        tokio::spawn(async move {
            bridge_work_to_user(w_r, u_w, false, None, None, None).await;
        });

        w_w_test.write_all(b"work->user").await.unwrap();
        w_w_test.flush().await.unwrap();
        drop(w_w_test); // EOF

        let mut buf = vec![0u8; 1024];
        let n = u_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"work->user");
    }

    /// bridge_work_to_user: decompressor flush residual data.
    #[tokio::test]
    async fn test_bridge_work_to_user_decompressor_flush() {
        use crate::encryption;

        let (mut w_w_test, w_r) = tokio::io::duplex(65536);
        let (u_w, mut u_r_test) = tokio::io::duplex(65536);

        tokio::spawn(async move {
            bridge_work_to_user(w_r, u_w, true, None, None, None).await;
        });

        // Write compressed data that needs flush to produce final bytes
        let original = b"AAAA".repeat(64);
        let mut comp_buf = Vec::new();
        encryption::compress_into(&original, &mut comp_buf).unwrap();
        w_w_test.write_all(&comp_buf).await.unwrap();
        w_w_test.flush().await.unwrap();
        drop(w_w_test); // EOF triggers flush in bridge_work_to_user

        let mut out = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            match u_r_test.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        assert_eq!(out, original);
    }

    /// Encrypted round-trip: user_to_work (Encrypted) + work_to_user (CipherReader)
    /// verifies byte-identical data after encrypt/decrypt cycle.
    #[tokio::test]
    async fn test_bridge_helpers_encrypted_roundtrip() {
        let key = crate::encryption::derive_key("roundtrip_key_42");

        // Create two duplex pairs:
        //   user_duplex: connects user_r (read by u2w) to test writer
        //   work_duplex: connects work_w (written by u2w, Encrypted) to work_r (read by w2u, CipherReader)
        let (mut u_w_test, u_r) = tokio::io::duplex(65536);
        let (work_duplex_w, work_duplex_r) = tokio::io::duplex(65536);
        let (u_w_sink, mut u_r_test) = tokio::io::duplex(65536);

        let enc_writer = CipherWriter::new(work_duplex_w, key);
        let enc_reader = CipherReader::new(work_duplex_r, key);

        let u2w = tokio::spawn(async move {
            bridge_user_to_work(
                u_r,
                WorkWriter::Encrypted(enc_writer),
                false,
                vec![],
                None,
                None,
            )
            .await;
        });

        let w2u = tokio::spawn(async move {
            bridge_work_to_user(enc_reader, u_w_sink, false, None, None, None).await;
        });

        // Write plaintext, read decrypted output
        let msg = b"hello encrypted roundtrip";
        u_w_test.write_all(msg).await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test); // EOF on user_r → u2w sends data then exits

        // w2u reads from work_duplex_r (same duplex pair as work_duplex_w)
        // u2w encrypts and writes to work_duplex_w → w2u reads and decrypts

        let mut out = vec![0u8; 1024];
        let out_n = u_r_test.read(&mut out).await.unwrap();
        assert_eq!(&out[..out_n], msg);

        let _ = tokio::join!(u2w, w2u);
    }

    #[test]
    fn test_compress_chunk_identity_when_disabled() {
        let mut buf = Vec::new();
        let mut compressor = make_compressor(false);
        let compressed = compress_chunk_into(&mut compressor, b"hello", false, &mut buf).unwrap();
        assert!(!compressed); // false = passthrough (no compression)
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_compress_decompress_roundtrip() {
        let original = b"AAAA".repeat(64);
        let mut comp_buf = Vec::new();
        let mut compressor = make_compressor(true);
        compress_chunk_into(&mut compressor, &original, true, &mut comp_buf).expect("compress ok");
        let mut dec = make_decompressor(true);
        let mut decomp_buf = Vec::new();
        let added = decompress_chunk_append_into(&mut dec, &comp_buf, &mut decomp_buf)
            .expect("decompress ok");
        assert_eq!(&decomp_buf[..added], original);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn decompress_chunk_accepts_legal_one_megabyte_multi_chunk_read() {
        let original = vec![0x42; 1024 * 1024];
        let mut comp_buf = Vec::new();
        let mut compressor = make_compressor(true);
        compress_chunk_into(&mut compressor, &original, true, &mut comp_buf).expect("compress ok");
        let mut dec = make_decompressor(true);
        let mut decomp_buf = Vec::new();

        let mut output = Vec::new();
        let mut input = comp_buf.as_slice();
        loop {
            let before = decomp_buf.len();
            let added = decompress_chunk_append_into(&mut dec, input, &mut decomp_buf)
                .expect("legal multi-chunk read must decompress");
            input = &[];
            if added == 0 {
                break;
            }
            assert!(added <= 128 * 1024);
            output.extend_from_slice(&decomp_buf[before..before + added]);
        }
        assert_eq!(output, original);
    }

    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn work_to_user_drains_all_compressed_chunks_after_peer_eof() {
        let original = vec![0x42; 3 * 1024 * 1024];
        let compressed = encryption::compress(&original).unwrap();
        let (mut work_tx, work_rx) = tokio::io::duplex(64 * 1024);
        let (user_tx, mut user_rx) = tokio::io::duplex(64 * 1024);

        let bridge = tokio::spawn(async move {
            bridge_work_to_user(work_rx, user_tx, true, None, None, None).await;
        });
        let writer = tokio::spawn(async move {
            work_tx.write_all(&compressed).await.unwrap();
            work_tx.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        user_rx.read_to_end(&mut received).await.unwrap();
        writer.await.unwrap();
        bridge.await.unwrap();
        assert_eq!(received, original);
    }

    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn metadata_storm_drain_yields_to_runtime_timers() {
        let storm = [0xfe, 0, 0, 0].repeat(300_000);
        let (mut work_tx, work_rx) = tokio::io::duplex(64 * 1024);
        let (user_tx, mut user_rx) = tokio::io::duplex(64 * 1024);
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let timer_ticks = ticks.clone();

        let bridge = tokio::spawn(async move {
            bridge_work_to_user(work_rx, user_tx, true, None, None, None).await;
        });
        let timer = tokio::spawn(async move {
            for _ in 0..5 {
                tokio::task::yield_now().await;
                timer_ticks.fetch_add(1, Ordering::Relaxed);
            }
        });
        work_tx.write_all(&storm).await.unwrap();
        work_tx.shutdown().await.unwrap();
        let mut received = Vec::new();
        user_rx.read_to_end(&mut received).await.unwrap();
        timer.await.unwrap();
        bridge.await.unwrap();

        assert!(received.is_empty());
        assert_eq!(ticks.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_decompress_chunk_identity_when_none() {
        let mut dec: Option<encryption::SnappyDecompressor> = None;
        let mut buf = Vec::new();
        let added = decompress_chunk_append_into(&mut dec, b"raw", &mut buf).unwrap();
        assert_eq!(&buf[..added], b"raw");
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
