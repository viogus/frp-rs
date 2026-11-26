use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bandwidth::{BandwidthLimiter, SharedBandwidthLimiter};
use crate::buffer_pool::PoolGuard;
use crate::cipher_stream::{CipherReader, CipherWriter};
use crate::encryption;
use crate::transport::IoStream;

/// Upper bound for the reusable work→user batch buffer. Frames returned by
/// the decompressor are accumulated up to this cap, then written/flushed once,
/// so a transport read containing many small frames costs one write instead of
/// one write per frame.
const MAX_WORK_TO_USER_BATCH: usize = 256 * 1024;

/// Body-less HTTP 504 response written to the user when the work→user read
/// errors with `TimedOut` — the caller-owned response-head deadline (the
/// frp-server ResponseHeaderInjector's absolute deadline, Go
/// `httputil.ReverseProxy` + `ResponseHeaderTimeoutS` / VhostHTTPTimeout
/// semantics) fired, so the client gets a bare `504 Gateway Timeout` with
/// `Content-Length: 0` and no body.
const GATEWAY_TIMEOUT_504: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n";

/// Emit a TRACE-level event with a hex-encoded field.
///
/// Compiled away entirely unless the `debug-logs` feature is enabled, so
/// `crate::hex_encode` is never evaluated in shipped builds. When enabled,
/// the standard `tracing::trace!` static-filter guard still applies.
macro_rules! trace_hex {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logs")]
        if tracing::level_enabled!(tracing::Level::TRACE) {
            tracing::trace!($($arg)*);
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
                if let Err(e) = AsyncWriteExt::flush(w).await {
                    tracing::debug!(error = %e, "bridge flush failed (peer disconnected)");
                }
                w.shutdown().await
            }
            Self::Encrypted(w) => AsyncWriteExt::shutdown(w).await,
        }
    }
}

/// Bridge user→work direction: read from user, optionally compress,
/// apply the shared per-proxy bandwidth limit, write through WorkWriter.
///
/// When `pre_read` is non-empty (VHost HTTP parsing), the bytes are written
/// first. If `had_pre_read` is true, the writer is NOT shut down at the end
/// so the work→user direction can still receive the backend response.
async fn bridge_user_to_work<W: AsyncWrite + Unpin>(
    mut user_r: impl AsyncReadExt + Unpin,
    mut writer: WorkWriter<W>,
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let had_pre_read = !pre_read.is_empty();

    let mut buf = PoolGuard::acquire();
    let cap = buf.as_mut_slice().len();
    // Pre-size the compression buffer to the bridge chunk size only when
    // compression is on — the plaintext path never touches it, so a
    // pre-sized Vec there is one buffer's worth of dead allocation per bridge.
    // Snappy worst-case expansion is ~1.06× + tag overhead (max ~cap + cap/6 +
    // 32), so pre-sizing to `cap` alone reallocs + copies once on the first
    // incompressible chunk (round-3 core F6).
    let mut comp_buf = if use_compression {
        Vec::with_capacity(cap + cap / 6 + 32)
    } else {
        Vec::new()
    };
    // The compressor must exist before the pre-read block: with compression
    // enabled the pre-read bytes are part of the same Snappy stream as the
    // main loop body, and the work side (bridge_work_to_user) decompresses
    // the stream from byte 0. Writing them RAW would hand the peer a garbage
    // Snappy header and kill the proxy (compressed vhost proxies).
    let mut compressor = make_compressor(use_compression);

    if had_pre_read {
        // Pre-read bytes (VHost HTTP parsing): write through WorkWriter.
        // CipherWriter variant encrypts automatically.
        if use_compression {
            if compress_chunk_into(&mut compressor, &pre_read, true, &mut comp_buf).is_none() {
                tracing::warn!("bridge user_to_work: pre_read compression failed");
                return;
            }
            // Pre-read bytes must count against the same bandwidth limit as
            // the main loop, or a rate-limited HTTP proxy flooded with small
            // GETs (headers+body entirely in the pre-read) would sidestep the
            // cap entirely (every connection's first ~4–8 KiB un-throttled).
            // Count the compressed size — that is what actually crosses the
            // tunnel and what the main loop charges.
            if let Some(lim) = limiter {
                BandwidthLimiter::consume_shared(lim, comp_buf.len()).await;
            }
            if let Err(e) = writer.write_bridge_all(&mut comp_buf).await {
                tracing::warn!(error = %e, "bridge user_to_work: pre_read write failed");
                return;
            }
            // Request head is interactive traffic: flush it out now. A GET
            // whose entire request lives in the pre-read may never produce
            // another user read, so the main loop's flush-on-read would leave
            // the head sitting in a buffered transport (TLS/WS/yamux) forever.
            if let Err(e) = writer.flush_bridge().await {
                tracing::debug!(error = %e, "bridge user_to_work: pre_read flush error");
                return;
            }
        } else {
            let mut pre_read_buf = pre_read;
            // Pre-read bytes must count against the same bandwidth limit as
            // the main loop, or a rate-limited HTTP proxy flooded with small
            // GETs (headers+body entirely in the pre-read) would sidestep the
            // cap entirely (every connection's first ~4–8 KiB un-throttled).
            if let Some(lim) = limiter {
                BandwidthLimiter::consume_shared(lim, pre_read_buf.len()).await;
            }
            if let Err(e) = writer.write_bridge_all(&mut pre_read_buf).await {
                tracing::warn!(error = %e, "bridge user_to_work: pre_read write failed");
                return;
            }
            // Same as the compressed arm: flush now. A GET whose entire
            // request lives in the pre-read may never produce another user
            // read, and with had_pre_read the shutdown flush is skipped —
            // without this the head would sit in a buffered transport
            // (TLS/WS/yamux) forever.
            if let Err(e) = writer.flush_bridge().await {
                tracing::debug!(error = %e, "bridge user_to_work: pre_read flush error");
                return;
            }
        }
    }

    // Flush every read, in both the compressed and plaintext paths (mirroring
    // bridge_work_to_user's unconditional tail flush). Raw TCP under
    // TCP_NODELAY sees no change (flush is a no-op there), but on a buffered
    // transport (TLS/WS/yamux) a flush gated on `n < cap` stranded an
    // exact-size burst (n == cap): the bytes sat in the buffered writer until
    // more data or EOF happened to arrive — a deadlock for a request whose
    // size lands exactly on the read buffer boundary.
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
            if let Some(lim) = limiter {
                BandwidthLimiter::consume_shared(lim, comp_buf.len()).await;
            }
            if let Err(e) = writer.write_bridge_all(&mut comp_buf).await {
                tracing::debug!(error = %e, "bridge user_to_work: write error (compressed)");
                break;
            }
            // comp_buf is cleared and refilled on each compress call, so its
            // capacity is retained across chunks.
            // Flush unconditionally — see the note above the loop.
            if let Err(e) = writer.flush_bridge().await {
                tracing::debug!(error = %e, "bridge user_to_work: flush error");
                break;
            }
        } else {
            let slice = &mut buf.as_mut_slice()[..n];
            if let Some(lim) = limiter {
                BandwidthLimiter::consume_shared(lim, slice.len()).await;
            }
            if let Err(e) = writer.write_bridge_all(slice).await {
                tracing::debug!(error = %e, "bridge user_to_work: write error");
                break;
            }
            // Flush unconditionally — see the note above the loop.
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
        if let Err(e) = writer.shutdown_bridge().await {
            tracing::debug!(error = %e, "bridge shutdown failed (peer disconnected)");
        }
    }
}

/// Write the Go-shaped 504 head (`GATEWAY_TIMEOUT_504`) to the user side
/// when the response head never arrived in time, then flush.
async fn write_gateway_timeout_504(user_w: &mut (impl tokio::io::AsyncWriteExt + Unpin)) {
    if let Err(e) = user_w.write_all(GATEWAY_TIMEOUT_504).await {
        tracing::debug!(error = %e, "bridge 504 write failed (peer disconnected)");
    }
    if let Err(e) = user_w.flush().await {
        tracing::debug!(error = %e, "bridge flush failed (peer disconnected)");
    }
}

/// Go frp v0.71.0 `NotFoundResponse` builtin body (pkg/util/http/http.go)
/// — served when no `custom_404_page` is configured. 489 bytes; with the
/// 92-byte head written by [`write_not_found_response`] the full answer is
/// 581 bytes (probe vs Go v0.71.0).
///
/// Shared crate-wide: frp-server's vhost/tcpmux route-miss writers and this
/// crate's work→user bridge Err arm (Go `httputil.ReverseProxy`
/// ErrorHandler parity — every non-timeout backend failure answers this
/// same 404, pkg/util/vhost/http.go:128-138) all write one byte template.
pub const GO_404_NOT_FOUND_BODY: &str = concat!(
    "<!DOCTYPE html>\n",
    "<html>\n",
    "<head>\n",
    "<title>Not Found</title>\n",
    "<style>\n",
    "    body {\n",
    "        width: 35em;\n",
    "        margin: 0 auto;\n",
    "        font-family: Tahoma, Verdana, Arial, sans-serif;\n",
    "    }\n",
    "</style>\n",
    "</head>\n",
    "<body>\n",
    "<h1>The page you requested was not found.</h1>\n",
    "<p>Sorry, the page you are looking for is currently unavailable.<br/>\n",
    "Please try again later.</p>\n",
    "<p>The server is powered by <a href=\"https://github.com/fatedier/frp\">frp</a>.</p>\n",
    "<p><em>Faithfully yours, frp.</em></p>\n",
    "</body>\n",
    "</html>\n",
);

/// Write Go frp's `NotFoundResponse` (pkg/util/http/http.go) — the 404
/// answer on a vhost/tcpmux route miss, on a control-gone (Go
/// connectHandler's CreateConnection error path answers the same 404, not
/// a 502), and on a malformed/oversize backend response head in the
/// work→user bridge (Go ErrorHandler parity). Head order is fixed
/// (Content-Length, Content-Type, Server) and matches the Go literal
/// byte-for-byte; `custom_body` (custom_404_page) replaces the builtin
/// HTML when non-empty, with Content-Length tracking the custom body. Go's
/// stdlib http.Server-layer additions (Date, Connection: close, charset)
/// that http.Error-based handlers would emit are absent from frp's own
/// pre-built response — the raw write sites emit NotFoundResponse
/// verbatim, like the Go CONNECT path. Write failures mean the client
/// disconnected; logged at debug so a hung client stays observable.
pub async fn write_not_found_response(
    stream: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    custom_body: &str,
) {
    let body: &[u8] = if custom_body.is_empty() {
        GO_404_NOT_FOUND_BODY.as_bytes()
    } else {
        custom_body.as_bytes()
    };
    let head = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nContent-Type: text/html\r\nServer: frp/{}\r\n\r\n",
        body.len(),
        crate::VERSION
    );
    if let Err(e) = stream.write_all(head.as_bytes()).await {
        tracing::debug!(error = %e, "failed to write HTTP error response header");
        return;
    }
    if let Err(e) = stream.write_all(body).await {
        tracing::debug!(error = %e, "failed to write HTTP error response body");
    }
}

/// Bridge work→user direction: read from work (plain or via CipherReader),
/// decompress, apply the shared per-proxy bandwidth limit, write to user.
///
/// The response-head deadline is NEVER armed here (round-15: the one-shot
/// first-read `header_timeout` arm was dead — frp-server's
/// ResponseHeaderInjector runs on every plain-HTTP non-CONNECT leg and arms
/// its own ABSOLUTE deadline, so no production call site passed `Some`).
/// Callers that need Go's ResponseHeaderTimeout / VhostHTTPTimeout semantics
/// wrap `work_r` in a deadline-owning reader (the injector) whose expiry
/// surfaces as an `io::ErrorKind::TimedOut` read error handled below.
///
/// Read errors end the direction with a Go-shaped answer, mirroring Go
/// frp v0.71.0's vhost ErrorHandler (pkg/util/vhost/http.go:128-138):
/// `TimedOut` (an upstream absolute head deadline that fired after interim
/// bytes were served) writes the bare 504; `InvalidData` (an upstream head
/// parser rejected the backend head — no status line, or over its size
/// cap) writes Go's NotFoundResponse 404 page
/// ([`write_not_found_response`]). Other error kinds are logged and the
/// direction ends silently (Go would also 404 them — scope-limited
/// follow-up, none are produced on this read path today).
///
/// `decompress_read` controls whether bytes read from `work_r` are decoded as
/// a Snappy stream. It is independent of the opposite direction's compression
/// (see `bridge_user_to_work`): callers that supply an ALREADY-decompressed
/// read stream (e.g. frp-server's response-header injector over a
/// [`SnappyStreamReader`](crate::snappy_stream::SnappyStreamReader)) pass
/// false while the user→work direction keeps compressing.
async fn bridge_work_to_user(
    mut work_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    decompress_read: bool,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let mut buf = PoolGuard::acquire();
    let cap = buf.as_mut_slice().len();
    // Pre-size the decompression batch buffer to the bridge chunk size only
    // when decompression is on — the plaintext path never touches it, so a
    // pre-sized Vec there is one buffer's worth of dead allocation per bridge.
    let mut batch_buf = if decompress_read {
        Vec::with_capacity(cap)
    } else {
        Vec::new()
    };
    let mut decompressor = make_decompressor(decompress_read);
    // Gateway error heads (404/504 below) are safe to write only while no
    // FINAL response head has reached the user — Go's vhost ErrorHandler
    // runs solely on a RoundTrip failure and a mid-body error merely aborts
    // the transport copy (reverseproxy.go). That phase is owned by the
    // caller's reader, not by this function: on http legs frp-server wraps
    // work_r in ResponseHeaderInjector, which (a) never emits error kinds
    // once an injectable final head has been served — a mid-body decode
    // failure after the head is swallowed there and surfaced as clean EOF —
    // and (b) converts a pre-head inner EOF into Err(UnexpectedEof) so the
    // 404 arm below answers it. Interim 1xx relays are a legal prefix to a
    // late 404/504 (an Expect:100 backend that answers 100 and then stalls
    // or dies still gets the gateway head Go would have sent). Non-http
    // legs (no injector) produce none of the three error kinds below — raw
    // sockets error ConnectionReset-class and their clean close is Ok(0).
    'read_loop: loop {
        let read_res = work_r.read(buf.as_mut_slice()).await;
        let n = match read_res {
            // Clean EOF. After a complete head — or on any leg without an
            // injector — this is normal end-of-stream (backend closed) and
            // stays silent. A pre-head EOF on an http leg never reaches
            // this arm: the ResponseHeaderInjector converts it to
            // Err(UnexpectedEof) so the 404 arm below answers it (Go
            // readResponse errors on an unterminated head → ErrorHandler
            // 404; nothing is relayed).
            Ok(0) => break,
            Ok(n) => {
                trace_hex!(n, first_hex = %crate::hex_encode(&buf.raw_buf()[..n.min(32)]), "bridge work_to_user: read {} bytes", n);
                n
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    // The response-head deadline fired AFTER interim 1xx
                    // bytes were already served (frp-server
                    // ResponseHeaderInjector's absolute deadline, A2) —
                    // Go's transport errors the whole response and the
                    // vhost ErrorHandler answers 504 (vhost http.go:128,
                    // net.Error Timeout gate); write the same final head
                    // here. A 100 already relayed is a legal interim
                    // prefix to it.
                    tracing::debug!(
                        error = %e,
                        "bridge work_to_user: response-head deadline hit, writing 504"
                    );
                    write_gateway_timeout_504(&mut user_w).await;
                } else if e.kind() == std::io::ErrorKind::InvalidData
                    || e.kind() == std::io::ErrorKind::UnexpectedEof
                {
                    // The backend never produced a usable response head —
                    // both kinds are emitted only by the injector's
                    // head-gather phase, which ends the moment a final head
                    // is served (after that the injector passes reads
                    // through raw and swallows a mid-body decode failure as
                    // clean EOF — the contract note above), so no final
                    // head can be in flight here. InvalidData = the head was rejected as
                    // malformed (no status line, or past the 64 KiB injector
                    // cap); UnexpectedEof = the backend closed before
                    // completing a head (the injector converts its pre-head
                    // Ok(0); a partial unterminated head is dropped, never
                    // relayed raw). Go frp v0.71.0: every non-timeout
                    // reverse-proxy failure answers the 404 NotFoundResponse
                    // page (vhost ErrorHandler http.go:128-138 — undecodable
                    // and oversize heads land here; Go's cap is the 10 MiB
                    // `maxHeaderResponseSize` default, transport.go:2106-2112 —
                    // frp-rs's 64 KiB injector cap is a documented Rust
                    // hardening divergence). Write the 404, then end this
                    // direction.
                    tracing::debug!(
                        error = %e,
                        "bridge work_to_user: no usable response head, writing 404"
                    );
                    write_not_found_response(&mut user_w, "").await;
                } else {
                    // Any other read failure (conn reset, EOF race, ...).
                    // Go's ErrorHandler answers the same 404
                    // NotFoundResponse for every non-timeout error;
                    // frp-rs only logs and ends the direction here — a
                    // scope-limited follow-up, since these error kinds are
                    // not currently produced on the work->user read path
                    // (TimedOut, InvalidData and UnexpectedEof above are
                    // the three the injector can surface).
                    tracing::debug!(error = %e, "bridge work_to_user: read error");
                }
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

                // Apply the shared per-proxy bandwidth limit before writing
                // to user (same bucket as the user→work direction — Go
                // single-limiter parity)
                if let Some(lim) = limiter {
                    BandwidthLimiter::consume_shared(lim, added).await;
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
                // Plaintext passthrough: write immediately and ALWAYS flush.
                // The flush is a no-op on a raw TcpStream; on a buffered
                // transport (yamux/WS-wrapped user side) it is what pushes the
                // bytes out — a flush gated on `n < cap` stranded an exact-size
                // burst (n == cap) until more data happened to arrive.
                let plaintext = compressed_input;
                if let Some(lim) = limiter {
                    BandwidthLimiter::consume_shared(lim, plaintext.len()).await;
                }
                if let Some(ref m) = metrics {
                    m.bytes_out
                        .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                }
                if let Err(e) = user_w.write_all(plaintext).await {
                    tracing::debug!(error = %e, "bridge work_to_user: write error");
                    break 'read_loop;
                }
                if let Err(e) = user_w.flush().await {
                    tracing::debug!(error = %e, "bridge work_to_user: flush error");
                    break 'read_loop;
                }
                break;
            }
        }
        if !batch_buf.is_empty() {
            if let Err(e) = user_w.write_all(&batch_buf).await {
                tracing::debug!(error = %e, "bridge work_to_user: write error (batch)");
                break 'read_loop;
            }
            // Always flush, as in the plaintext arm: the mid-batch write
            // above (>= MAX_WORK_TO_USER_BATCH) flushed itself, but the tail
            // must not wait for more data — a flush gated on `n < cap`
            // stranded an exact-size final batch in a buffered transport
            // until the next burst (or EOF) happened to arrive.
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
            // Without the compression feature the decompressor is a passthrough
            // that cannot fail meaningfully; discard its (unreachable) error.
            #[cfg(not(feature = "compression"))]
            let _ = e;
        }
    }

    // Symmetric shutdown: signal EOF to user side
    if let Err(e) = user_w.flush().await {
        tracing::debug!(error = %e, "bridge flush failed (peer disconnected)");
    }
    if let Err(e) = user_w.shutdown().await {
        tracing::debug!(error = %e, "bridge shutdown: user_w.shutdown failed");
    }
}

/// The transform applied to the work connection's bytes.
#[derive(Clone, Copy, Debug)]
pub enum Crypto<'a> {
    /// No encryption on the work connection.
    Plain,
    /// AES-128-CFB streaming encryption with this key.
    Encrypted { key: &'a [u8; 16] },
}

/// Everything that distinguishes the bridge entry points, as data.
///
/// The eight public entry points below are combinations of five independent
/// axes — crypto, whether user→work compresses, whether work→user still needs
/// decompressing, whether the caller already decrypted the read side, the bytes
/// read before the handshake finished, and the shared bandwidth limiter — plus
/// one shape axis (whole `IoStream`s versus already-split halves). Naming the
/// axes once keeps the combinations from drifting apart, and lets the two
/// dispatchers (`frp-server/src/control/bridge.rs`, `frp-client/src/proxy.rs`)
/// build a value instead of re-deriving the case analysis.
///
/// Decompression and decryption are deliberately **separate** axes: a caller can
/// hand over an already-decrypted reader whose bytes are still snappy-compressed
/// (that is exactly `bridge_encrypted` with `read_is_decrypted = true` and
/// compression on), and conflating the two would silently stop decompressing.
pub struct BridgePlan<'a> {
    /// Wire transform on the work connection.
    pub crypto: Crypto<'a>,
    /// Compress user→work. `false` means the connection is plain both ways.
    pub compress: bool,
    /// Wrap the work→user reader in a snappy decompressor.
    pub decompress_read: bool,
    /// The caller already wrapped the work→user reader (e.g. an injector above a
    /// `CipherReader`), so the encrypted core must not wrap it again.
    pub read_is_plaintext: bool,
    /// Bytes already read from the work connection (VHost HTTP body).
    pub pre_read: Vec<u8>,
    /// The proxy's shared limiter: one bucket covers both directions.
    pub limiter: Option<&'a SharedBandwidthLimiter>,
    /// Per-proxy counters for the duration of the bridge.
    pub metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
}

/// What a dispatcher should do with a plan — see [`BridgePlan::choice`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeChoice {
    /// AES-128-CFB work connection: run the encrypted core, which splits the
    /// pair itself.
    EncryptedWhole,
    /// Plain connection with compression or a bandwidth limit: split both sides
    /// and run the plain core.
    PlainSplit,
    /// Plain connection with neither: the fast relay (`splice(2)` where the
    /// platform allows it, pooled copy otherwise).
    PlainFastRelay,
}

impl<'a> BridgePlan<'a> {
    /// Unencrypted work connection; `compress` turns on bidirectional snappy.
    pub fn plain(compress: bool) -> Self {
        Self {
            crypto: Crypto::Plain,
            compress,
            decompress_read: compress,
            read_is_plaintext: false,
            pre_read: Vec::new(),
            limiter: None,
            metrics: None,
        }
    }

    /// Encrypted work connection (AES-128-CFB); `compress` as above.
    pub fn encrypted(key: &'a [u8; 16], compress: bool) -> Self {
        Self {
            crypto: Crypto::Encrypted { key },
            ..Self::plain(compress)
        }
    }

    /// The caller already decrypted the read side (round-14 A1 injector path).
    pub fn read_is_plaintext(mut self, already: bool) -> Self {
        self.read_is_plaintext = already;
        self
    }

    /// Turn work→user decompression off while user→work keeps compressing.
    pub fn without_read_decompression(mut self) -> Self {
        self.decompress_read = false;
        self
    }

    pub fn pre_read(mut self, pre_read: Vec<u8>) -> Self {
        self.pre_read = pre_read;
        self
    }

    pub fn limiter(mut self, limiter: Option<&'a SharedBandwidthLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    pub fn metrics(mut self, metrics: Option<Arc<crate::metrics::ProxyMetrics>>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Which shape this configuration calls for, so a dispatcher does not have
    /// to re-derive the case analysis itself.
    ///
    /// The three answers are the three things a caller can actually do with a
    /// plan: run the encrypted core whole (it splits internally), split the
    /// plain connection and hand it to the compress/limit core, or hand a plain
    /// pair to the fast relay (`splice(2)` / pooled copy) which owns its own
    /// buffer strategy.
    pub fn choice(&self) -> BridgeChoice {
        match self.crypto {
            Crypto::Encrypted { .. } => BridgeChoice::EncryptedWhole,
            // Pre-read bytes only exist on the split path: the fast relay has
            // nowhere to put them, so a plain plan carrying them must not be
            // answered with `PlainFastRelay`.
            Crypto::Plain
                if self.compress || self.limiter.is_some() || !self.pre_read.is_empty() =>
            {
                BridgeChoice::PlainSplit
            }
            Crypto::Plain => BridgeChoice::PlainFastRelay,
        }
    }

    /// The three booleans the cores take, read off the axes. No axis is derived
    /// from another: the pairs the entry points use are fixed in their bodies.
    fn core_flags(&self) -> (bool, bool, bool) {
        (self.compress, self.decompress_read, self.read_is_plaintext)
    }

    /// Bridge already-split halves on an unencrypted work connection.
    pub async fn run_plain<UR, UW, WR, WW>(self, user_r: UR, user_w: UW, work_r: WR, work_w: WW)
    where
        UR: AsyncReadExt + Unpin,
        UW: AsyncWriteExt + Unpin,
        WR: AsyncReadExt + Unpin,
        WW: AsyncWriteExt + Unpin,
    {
        if !matches!(self.crypto, Crypto::Plain) {
            unreachable!("BridgePlan::run_plain is only reached from the plain entry points")
        }
        let (compress, decompress_read, _) = self.core_flags();
        bridge_plain_core(
            user_r,
            user_w,
            work_r,
            work_w,
            compress,
            self.pre_read,
            self.limiter,
            self.metrics,
            decompress_read,
        )
        .await
    }

    /// Bridge already-split halves on an encrypted work connection. `work_r` must
    /// be `Send`: the core boxes it together with the cipher reader and drives
    /// both directions with `tokio::join!`, which needs the futures to be `Send`
    /// for the bridge to be usable from a spawned connection task.
    pub async fn run_encrypted<UR, UW, WR, WW>(self, user_r: UR, user_w: UW, work_r: WR, work_w: WW)
    where
        UR: AsyncReadExt + Unpin,
        UW: AsyncWriteExt + Unpin,
        WR: tokio::io::AsyncRead + Unpin + Send,
        WW: AsyncWriteExt + Unpin,
    {
        let Crypto::Encrypted { key } = self.crypto else {
            unreachable!("run_encrypted is only used by the encrypted entry points")
        };
        let (compress, decompress_read, read_is_plaintext) = self.core_flags();
        bridge_encrypted_core(
            user_r,
            user_w,
            work_r,
            work_w,
            key,
            compress,
            self.pre_read,
            self.limiter,
            self.metrics,
            read_is_plaintext,
            decompress_read,
        )
        .await
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
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) -> std::io::Result<()> {
    tracing::debug!(use_compression, "bridge_encrypted_io: starting");
    let (u_r, u_w) = user.into_split()?;
    let (w_r, w_w) = work.into_split()?;
    BridgePlan::encrypted(key, use_compression)
        .pre_read(pre_read)
        .limiter(limiter)
        .metrics(metrics)
        .run_encrypted(u_r, u_w, w_r, w_w)
        .await;
    Ok(())
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
/// `limiter` is the proxy's SHARED bandwidth limiter: one bucket covers both
/// directions (work→user and user→work) and all concurrent connections of
/// the proxy (Go frp v0.71.0 single-`rate.Limiter` parity).
///
/// `read_is_decrypted`: when true, `work_r` is assumed to already be a
/// plaintext stream (e.g. an injector wrapping a `CipherReader`) and is used
/// as-is — `bridge_encrypted` does NOT wrap it in a second `CipherReader`.
/// Used by frp-server's response-header-injector path so the injector sees
/// decrypted (true) response bytes rather than ciphertext. All other callers
/// pass false and keep the internal wrapping.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_encrypted(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl tokio::io::AsyncRead + Unpin + Send,
    work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    read_is_decrypted: bool,
) {
    // `read_is_decrypted` and decompression are independent: the base passed
    // `decompress_read = use_compression` for both values of the flag.
    BridgePlan::encrypted(key, use_compression)
        .read_is_plaintext(read_is_decrypted)
        .pre_read(pre_read)
        .limiter(limiter)
        .metrics(metrics)
        .run_encrypted(user_r, user_w, work_r, work_w)
        .await;
}

/// Like [`bridge_encrypted`], but the work→user read stream is assumed to be
/// ALREADY decompressed by the caller (in addition to being decrypted).
/// `decompress_read` is therefore forced off while the user→work write
/// direction still compresses per `use_compression`.
///
/// Audit round-14 A1: frp-server's response-header injector must observe
/// DECOMPRESSED plaintext — Go frp's vhost ReverseProxy/ModifyResponse sits
/// above the transport's snappy layer, so it always injects into plaintext.
/// When a compressed http proxy carries `response_headers`, frp-server wraps
/// the decrypted stream in a
/// [`SnappyStreamReader`](crate::snappy_stream::SnappyStreamReader) before
/// the injector and calls this variant; without it the injector would parse
/// Snappy bytes (corrupt splices / silent injection loss).
#[allow(clippy::too_many_arguments)]
pub async fn bridge_encrypted_decompressed_read(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl tokio::io::AsyncRead + Unpin + Send,
    work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    BridgePlan::encrypted(key, use_compression)
        .read_is_plaintext(true)
        .without_read_decompression()
        .pre_read(pre_read)
        .limiter(limiter)
        .metrics(metrics)
        .run_encrypted(user_r, user_w, work_r, work_w)
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn bridge_encrypted_core(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl tokio::io::AsyncRead + Unpin + Send,
    work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    read_is_decrypted: bool,
    decompress_read: bool,
) {
    tracing::debug!(use_compression, "bridge_encrypted: starting");
    // Audit B2: OS-RNG failure surfaces as an error, not a process abort.
    let mut enc_work_w = match CipherWriter::new(work_w, *key) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "bridge_encrypted: IV generation failed");
            return;
        }
    };

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

    // When the caller already supplies a decrypted (plaintext) work_r —
    // e.g. the header injector wrapping its own CipherReader — do not wrap
    // it again, or the stream would be doubly-decrypted (corrupt). Boxed as
    // AsyncRead (not AsyncReadExt, which isn't dyn-compatible); the boxed
    // reader still implements AsyncReadExt via the blanket impl.
    let work_r: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if read_is_decrypted {
        Box::new(work_r)
    } else {
        Box::new(CipherReader::new(work_r, *key))
    };

    let user_to_work = bridge_user_to_work(
        user_r,
        WorkWriter::Encrypted(enc_work_w),
        use_compression,
        pre_read,
        limiter,
        metrics.clone(),
    );
    let work_to_user = bridge_work_to_user(work_r, user_w, decompress_read, limiter, metrics);

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
) {
    BridgePlan::plain(use_compression)
        .pre_read(pre_read)
        .metrics(metrics)
        .run_plain(user_r, user_w, work_r, work_w)
        .await;
}

/// Like [`bridge_plain`], but the work→user read stream is assumed to be
/// ALREADY decompressed by the caller (frp-server's response-header injector
/// over a
/// [`SnappyStreamReader`](crate::snappy_stream::SnappyStreamReader)); only the
/// user→work write direction compresses. See
/// [`bridge_encrypted_decompressed_read`] for the audit round-14 A1
/// rationale.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_plain_decompressed_read(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    BridgePlan::plain(use_compression)
        .without_read_decompression()
        .pre_read(pre_read)
        .metrics(metrics)
        .run_plain(user_r, user_w, work_r, work_w)
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn bridge_plain_core(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
    decompress_read: bool,
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
        limiter,
        metrics.clone(),
    );
    let work_to_user = bridge_work_to_user(work_r, user_w, decompress_read, limiter, metrics);

    let _ = tokio::join!(user_to_work, work_to_user);
}

/// How long one relay direction may sit with NO progress (no bytes read)
/// after the OPPOSITE direction has already hit EOF, before the relay
/// abandons it and drops both transports.
///
/// Half-close (FIN propagation) exists so that a peer which shut down its
/// write half can still receive the rest of a response. It has to be
/// bounded, because a peer that never sends its own FIN leaves the opposite
/// read parked on a future that can never complete — pinning two sockets and
/// two pooled bridge buffers for the lifetime of the process. Measured on a
/// live frpc (OpenWrt router, socks5 plugin proxy, ordinary browser
/// traffic): 2137 permanently half-closed sockets (1490 `FIN_WAIT2` + 647
/// `CLOSE_WAIT`) and ~224 MB RSS+swap after 23 h, growing at ~2 fds and
/// ~120 kB per minute, all of it unreclaimable without restarting the
/// process.
///
/// Go frp's `golib/io.Join` closes BOTH connections as soon as either
/// `io.Copy` returns, so it cannot park this way; any bound is strictly more
/// permissive than the compatibility target.
///
/// This is an IDLE bound, not a deadline measured from the moment of
/// half-close: the window restarts on every byte read, so a peer that keeps
/// making progress (e.g. a client that half-closes its request and then
/// receives a long response) is never cut mid-transfer. What IS cut, after one
/// full idle window, is a direction whose next byte never arrives — a peer
/// that has gone away, or a server that needs longer than the window to start
/// responding. That direction ends cleanly (`Ok` with the bytes copied so
/// far), so the give-up itself is not reported as an error; the counts simply
/// stop short.
///
/// Scope: used by [`relay_plain_pooled`] and, on Linux, `bridge_splice`
/// (`frp-core/src/splice.rs`). The compressed / encrypted / rate-limited
/// variants (`bridge_plain_core`, `bridge_plain_rate_limited_core`,
/// `bridge_encrypted_core`) and the SUDP message bridge still join their two
/// directions unbounded and carry the same leak.
///
/// No config key exposes this deliberately: Go frp has no equivalent knob (it
/// closes both connections on the first `io.Copy` return), so adding one would
/// extend the config surface past the compatibility target for a bound that is
/// already strictly more permissive than it.
pub const HALF_CLOSE_LINGER_TIMEOUT: Duration = Duration::from_secs(30);

/// Bidirectional plain relay between two full-duplex transports using
/// POOLED buffers (one `PoolGuard` per direction, returned to the pool on
/// exit). Replaces `tokio::io::copy_bidirectional_with_sizes`, which
/// allocates two fresh buffers on EVERY bridge call — under connection
/// churn that is two allocs + two frees per connection on every non-splice
/// path.
///
/// Each direction copies independently, and when one side's read hits EOF the
/// peer's write half is shut down (TCP FIN / yamux half-close / QUIC stream
/// finish) so the opposite copy observes EOF too. The call ends when BOTH
/// directions have completed, or — if the opposite direction stops making
/// progress after a half-close — one [`HALF_CLOSE_LINGER_TIMEOUT`] window
/// after its last byte. It does NOT return an error in that case: the bytes
/// copied in each direction are reported as usual. (Go frp closes both
/// connections the moment either direction finishes; the linger keeps the
/// half-close behaviour for the normal case — the peer's FIN follows within
/// an RTT — while making the pathological case bounded.)
///
/// The generic `tokio::io::split` (BiLock) is used rather than
/// `Transport::into_split`: shutdown forwards to the inner transport's
/// AsyncWrite identically, and the helper then works for any
/// AsyncRead+AsyncWrite pair (e.g. the client's local `TcpStream`), not
/// just `IoStream`.
pub async fn relay_plain_pooled<A, B>(a: A, b: B) -> io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    relay_plain_pooled_with_linger(a, b, HALF_CLOSE_LINGER_TIMEOUT).await
}

/// Bidirectional relay between two raw `TcpStream`s.
///
/// - On Linux: uses kernel-space zero-copy `crate::splice::bridge_splice`
///   with identical half-close linger semantics (note: allocates two kernel
///   pipe pairs per active connection, matching plain `tcp` proxies in
///   `frp-client`/`frp-server`).
/// - On non-Linux (macOS / Windows): uses lock-free `TcpStream::into_split()`
///   with pooled 64 KiB buffers, avoiding `tokio::io::split`'s per-socket
///   `BiLock` contention on full-duplex traffic.
pub async fn relay_tcp_fast(
    a: tokio::net::TcpStream,
    b: tokio::net::TcpStream,
) -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        crate::splice::bridge_splice(a, b).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        relay_tcp_pooled_with_linger(a, b, HALF_CLOSE_LINGER_TIMEOUT).await
    }
}

#[cfg(any(not(target_os = "linux"), test))]
async fn relay_tcp_pooled_with_linger(
    a: tokio::net::TcpStream,
    b: tokio::net::TcpStream,
    linger: Duration,
) -> io::Result<(u64, u64)> {
    let (mut a_r, mut a_w) = a.into_split();
    let (mut b_r, mut b_w) = b.into_split();
    let (half_closed_tx, half_closed_rx) = tokio::sync::watch::channel(false);
    let a_to_b = {
        let rx = half_closed_rx.clone();
        let tx = half_closed_tx.clone();
        async move {
            let n = copy_pooled(&mut a_r, &mut b_w, rx, linger).await?;
            let _ = tx.send(true);
            b_w.shutdown().await?;
            Ok::<u64, io::Error>(n)
        }
    };
    let b_to_a = {
        let tx = half_closed_tx;
        async move {
            let n = copy_pooled(&mut b_r, &mut a_w, half_closed_rx, linger).await?;
            let _ = tx.send(true);
            a_w.shutdown().await?;
            Ok::<u64, io::Error>(n)
        }
    };
    let (x, y) = tokio::try_join!(a_to_b, b_to_a)?;
    Ok((x, y))
}

/// [`relay_plain_pooled`] with an injectable half-close linger, so tests can
/// pin both the abandon-a-stalled-peer and the do-not-truncate-a-slow-peer
/// behaviours without depending on the wall clock.
async fn relay_plain_pooled_with_linger<A, B>(
    a: A,
    b: B,
    linger: Duration,
) -> io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);
    // Flipped by whichever direction reaches EOF first. The opposite
    // direction then keeps running for as long as it reads bytes, and is
    // abandoned after `linger` with no progress.
    let (half_closed_tx, half_closed_rx) = tokio::sync::watch::channel(false);
    let a_to_b = {
        let rx = half_closed_rx.clone();
        let tx = half_closed_tx.clone();
        async move {
            let n = copy_pooled(&mut a_r, &mut b_w, rx, linger).await?;
            // Signal before awaiting the shutdown: the peer's write half is
            // already closed (EOF was read), so the sibling may start its
            // linger window immediately.
            let _ = tx.send(true);
            b_w.shutdown().await?;
            Ok::<u64, io::Error>(n)
        }
    };
    let b_to_a = {
        let tx = half_closed_tx;
        async move {
            let n = copy_pooled(&mut b_r, &mut a_w, half_closed_rx, linger).await?;
            let _ = tx.send(true);
            a_w.shutdown().await?;
            Ok::<u64, io::Error>(n)
        }
    };
    let (x, y) = tokio::try_join!(a_to_b, b_to_a)?;
    Ok((x, y))
}

/// One-direction copy through a pooled `PoolGuard` buffer (length ==
/// BUFFER_SIZE, so `read` always has a full slice to fill).
///
/// Once `half_closed_rx` reports that the sibling direction has finished, a
/// read that makes no progress for `linger` ends this copy early and returns
/// the bytes copied so far. That releases the socket and the pooled buffer
/// instead of parking them forever on a half-close the peer never completes.
/// Reads before the half-close, and reads that keep producing bytes after it,
/// stay unbounded.
async fn copy_pooled<R, W>(
    src: &mut R,
    dst: &mut W,
    mut half_closed_rx: tokio::sync::watch::Receiver<bool>,
    linger: Duration,
) -> io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = PoolGuard::acquire();
    let mut total = 0u64;
    loop {
        // Scoped so the read future's borrow of `buf` ends before the write
        // below needs it.
        let n = {
            // Cancel-safe: `AsyncReadExt::read` only ever reports bytes that
            // are already in `buf`, so dropping the future loses nothing.
            let read = src.read(buf.as_mut_slice());
            tokio::pin!(read);
            if *half_closed_rx.borrow() {
                match tokio::time::timeout(linger, &mut read).await {
                    Ok(n) => n?,
                    Err(_) => {
                        tracing::debug!(
                            "half-close linger expired: releasing an idle bridge direction \
                             ({} bytes copied; the peer never sent its FIN)",
                            total
                        );
                        return Ok(total);
                    }
                }
            } else {
                tokio::select! {
                    n = &mut read => n?,
                    // The sibling hit EOF while this read was pending: stop
                    // waiting without a bound and re-issue the read under the
                    // linger.
                    //
                    // The `Ok(())` pattern is load-bearing: if the sender were
                    // ever dropped before sending, this arm is merely disabled
                    // and the read stays unbounded. The sender lives in the
                    // sibling direction (see `relay_plain_pooled_with_linger`),
                    // which cannot finish without sending, so the arm is
                    // always live here.
                    Ok(()) = half_closed_rx.changed() => continue,
                }
            }
        };
        if n == 0 {
            return Ok(total);
        }
        dst.write_all(&buf.raw_buf()[..n]).await?;
        total += n as u64;
    }
}

/// Plain (unencrypted) bidirectional bridge with optional bandwidth limiting
/// and compression.
///
/// Uses the same `join!`-of-two-halves pattern as `bridge_encrypted` so that
/// both directions run to completion independently. Supports compression
/// (Snappy) with reusable buffers, matching `bridge_plain`.
///
/// `limiter` is the proxy's SHARED bandwidth limiter: one bucket covers both
/// directions (work→user and user→work) and all concurrent connections of
/// the proxy (Go frp v0.71.0 single-`rate.Limiter` parity).
#[allow(clippy::too_many_arguments)]
pub async fn bridge_plain_rate_limited(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    BridgePlan::plain(use_compression)
        .pre_read(pre_read)
        .limiter(limiter)
        .metrics(metrics)
        .run_plain(user_r, user_w, work_r, work_w)
        .await;
}

/// Like [`bridge_plain_rate_limited`], but the work→user read stream is
/// assumed to be ALREADY decompressed by the caller (frp-server's
/// response-header injector over a
/// [`SnappyStreamReader`](crate::snappy_stream::SnappyStreamReader)); only
/// the user→work write direction compresses. See
/// [`bridge_encrypted_decompressed_read`] for the audit round-14 A1
/// rationale.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_plain_rate_limited_decompressed_read(
    user_r: impl AsyncReadExt + Unpin,
    user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    limiter: Option<&SharedBandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    BridgePlan::plain(use_compression)
        .without_read_decompression()
        .pre_read(pre_read)
        .limiter(limiter)
        .metrics(metrics)
        .run_plain(user_r, user_w, work_r, work_w)
        .await;
}

#[cfg(test)]
mod tests;
