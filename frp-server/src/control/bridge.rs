use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use futures_util::FutureExt;

use frp_core::cipher_stream::{CipherReader, CipherWriter};
use frp_core::encryption::derive_key;
use frp_core::metrics::ConnGuard;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{
    read_msg_v1, read_msg_v2_udp_binary_socket, read_msg_v2_with_udp_codec, write_msg_v1,
    write_msg_v2_with_udp_codec, write_v2_frame_raw, UdpBinaryRead, V2_FRAME_TYPE_MESSAGE,
};
use frp_core::snappy_stream::{SnappyStreamReader, SnappyStreamWriter};
use frp_core::transport::{split_work_conn_halves, IoStream};

use crate::service::AppState;

use super::pool::PendingRequest;

/// Build a StartWorkConn message from request and address info.
/// Pure data construction — no `.await` calls. Extracted from the
/// async state machine in `assign_work_to_proxy`.
#[inline(never)]
fn build_start_work_conn(
    req: &PendingRequest,
    src_addr: &str,
    src_port: u16,
    dst_addr: &str,
    dst_port: u16,
) -> FrpMessage {
    FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        src_addr: if !src_addr.is_empty() {
            Some(src_addr.to_string())
        } else {
            None
        },
        src_port: if src_port != 0 { Some(src_port) } else { None },
        dst_addr: if !dst_addr.is_empty() {
            Some(dst_addr.to_string())
        } else {
            None
        },
        dst_port: if dst_port != 0 { Some(dst_port) } else { None },
        error: None,
        // use_encryption/use_compression: propagate proxy config settings.
        // Go frpc v0.69.1 ignores these fields (not in its StartWorkConn struct)
        // and uses its own proxy config. The server must match whatever the
        // provider does, so the bridge type (plain vs encrypted) is determined
        // below based on req.use_encryption/compression, NOT forced to false.
        // Rust frpc (work_conn.rs) respects swc.use_encryption over its own config.
        // CipherWriter now eagerly flushes IV on first poll_flush, preventing the
        // dual-CipherWriter deadlock that previously forced plain bridge for XTCP.
        use_encryption: if req.use_encryption { Some(true) } else { None },
        use_compression: if req.use_compression {
            Some(true)
        } else {
            None
        },
        // For XTCP STCP fallback: set empty nat_hole_sid marker so Rust frpc
        // knows this work conn is for STCP bridging, not XTCP notification.
        // When `proxy_info` is None the proxy was already unregistered in the
        // enqueue→bridge window, so this path is already broken (the bridge
        // fails or the peer rejects the StartWorkConn); omitting the marker
        // there is acceptable because the proxy type is unknown anyway.
        nat_hole_sid: if req
            .proxy_info
            .as_ref()
            .is_some_and(|p| p.proxy_type == "xtcp")
        {
            Some(String::new())
        } else {
            None
        },
        nat_hole_visitor_addr: None,
        sk: None,
    }))
}

/// RAII guard that tracks an active bridge connection for graceful shutdown drain.
struct ActiveGuard(std::sync::Arc<AppState>);
impl ActiveGuard {
    fn new(state: &std::sync::Arc<AppState>) -> Self {
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(state.clone())
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Wraps an AsyncRead, buffering HTTP response headers on first read
/// and injecting configured headers before passing through.
struct ResponseHeaderInjector<R> {
    inner: R,
    headers: std::collections::HashMap<String, String>,
    buffer: Vec<u8>,
    buffer_offset: usize,
    /// True once the response head ended — the first blank line under Go
    /// `textproto.ReadLine` rules (CRLF, bare-LF, or mixed line endings)
    /// was seen — and the configured headers were injected. Until this is
    /// true (or the inner stream hit EOF), `poll_read` never emits bytes
    /// to the caller: emission before the head end is known would corrupt
    /// the stream for headers spanning multiple internal reads.
    injected: bool,
    /// True once the inner stream hit EOF before the head ended — the
    /// buffered partial header is served (no injection), then EOF.
    eof: bool,
    /// True once every buffered byte is served and no further buffering is
    /// possible — the rest of the response passes through raw.
    complete: bool,
    /// Persistent read buffer to avoid per-poll_read allocation.
    read_buf: [u8; 4096],
}

// SAFETY: All fields of ResponseHeaderInjector are Unpin when R: Unpin.
// HashMap, Vec, usize, bool, and [u8; 4096] are all Unpin types.
impl<R: Unpin> Unpin for ResponseHeaderInjector<R> {}

impl<R: AsyncRead + Unpin> ResponseHeaderInjector<R> {
    fn new(inner: R, headers: std::collections::HashMap<String, String>) -> Self {
        Self {
            inner,
            headers,
            buffer: Vec::new(),
            buffer_offset: 0,
            injected: false,
            eof: false,
            complete: false,
            read_buf: [0u8; 4096],
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ResponseHeaderInjector<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        // Everything buffered has been served and injection is settled
        // (headers injected, or EOF cut the response short) — the rest of
        // the response passes through untouched.
        if this.complete {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        // Serve buffered bytes — only ever POST-injection (the head with
        // the injected headers appended) or post-EOF (a truncated response:
        // emit the partial header bytes, inject nothing). M3: the old code
        // served pre-boundary fragments to the caller, so a header spanning
        // several internal reads (e.g. a big Set-Cookie set over 4 KiB)
        // leaked out fragment-first and the configured headers were never
        // injected — the drain path even raised `complete` before the
        // boundary existed, silently disabling injection for the rest of
        // the response.
        if this.buffer_offset < this.buffer.len() {
            debug_assert!(this.injected || this.eof);
            let remaining = this.buffer.len() - this.buffer_offset;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
            this.buffer_offset += to_copy;
            if this.buffer_offset >= this.buffer.len() {
                // The injected head (or truncated tail) is fully out; the
                // remainder of the response is raw pass-through.
                this.complete = true;
            }
            return Poll::Ready(Ok(()));
        }

        // No buffered bytes left. If EOF already cut the header short,
        // signal EOF now (the buffer was drained above).
        if this.eof {
            this.complete = true;
            return Poll::Ready(Ok(()));
        }

        // Buffer empty and the head has not ended yet — gather more of the
        // response header from the backend. Bytes are held (never served)
        // until the first blank line ends the head (Go `textproto.ReadLine`
        // semantics: CRLF, bare-LF, or mixed line endings all legal) or the
        // backend closes.
        loop {
            let mut temp_buf = ReadBuf::new(&mut this.read_buf);
            match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = temp_buf.filled().len();
                    if n == 0 {
                        // EOF before the terminator: no configured headers
                        // are injected; the partial bytes (if any) are
                        // served below (returning Ready-with-0 here would
                        // read as EOF and drop them — callers treat a
                        // zero-byte Ready as end-of-stream). Empty buffer →
                        // real EOF right away.
                        this.eof = true;
                        if this.buffer.is_empty() {
                            this.complete = true;
                            return Poll::Ready(Ok(()));
                        }
                        break;
                    }
                    // Guard against memory exhaustion from backends that
                    // never terminate the head with a blank line (the cap
                    // still bounds a backend that sends no blank line at
                    // all, whatever EOL convention it uses).
                    if this.buffer.len() + n > 65536 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "response header exceeds 64KB limit",
                        )));
                    }
                    this.buffer.extend_from_slice(&this.read_buf[..n]);
                    // The head end may span internal reads — the search
                    // covers the whole buffer.
                    if let Some(end) = frp_core::textproto::head_end(&this.buffer) {
                        // `end` is past the terminating blank line. The
                        // blank line itself is exactly "\n" or "\r\n" (a
                        // line textproto deemed empty keeps at most one
                        // trailing "\r") and stays attached to the head:
                        // the configured headers must go out BEFORE it —
                        // bytes after the blank line are the backend's
                        // entity body and pass verbatim.
                        let blank_start = if end >= 2 && this.buffer[end - 2] == b'\r' {
                            end - 2
                        } else {
                            end - 1
                        };
                        // Go http.ReadResponse rejects a head whose FIRST
                        // line is empty (the head starting with its own
                        // blank line means no status line exists) — such a
                        // backend answer is malformed, and splicing
                        // configured headers in front of it would
                        // manufacture a plausible response out of garbage.
                        // Fail the read like Go's reverse proxy would
                        // (round-3 review finding).
                        if blank_start == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "backend response head has no status line",
                            )));
                        }
                        let mut injected = Vec::with_capacity(this.buffer.len() + 512);
                        injected.extend_from_slice(&this.buffer[..blank_start]);
                        for (k, v) in &this.headers {
                            // Sanitize header names/values to prevent HTTP
                            // header injection.
                            let safe_k: String =
                                k.chars().filter(|&c| c != '\r' && c != '\n').collect();
                            let safe_v: String =
                                v.chars().filter(|&c| c != '\r' && c != '\n').collect();
                            // Configured headers always go out CRLF (Go
                            // net/http renders every response header CRLF,
                            // whatever the backend wrote) — a backend
                            // LF-only head intentionally ends up mixed-EOL;
                            // the injected lines remain parseable and the
                            // trailing blank keeps the backend's own EOL.
                            injected.extend_from_slice(
                                format!("{}: {}\r\n", safe_k, safe_v).as_bytes(),
                            );
                        }
                        injected.extend_from_slice(&this.buffer[blank_start..]);
                        this.buffer = injected;
                        this.injected = true;
                        break;
                    }
                    // Still a partial header — withhold it from the caller
                    // (injection happens at the boundary) and keep pulling
                    // while the inner stream is ready. Returning Pending
                    // straight after a Ready inner read would park the
                    // caller with no registered waker (a Ready poll does
                    // not register one) — deadlock; the loop below only
                    // returns Pending once the inner poll itself went
                    // Pending, so its waker is set.
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Data will arrive later; that inner poll registered
                    // the waker — park until then.
                    return Poll::Pending;
                }
            }
        }

        // Boundary found (and headers injected) in this poll: serve what
        // fits; the tail goes out on subsequent polls and `complete` is
        // raised only once the buffer is fully drained.
        let remaining = this.buffer.len() - this.buffer_offset;
        let to_copy = remaining.min(buf.remaining());
        buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
        this.buffer_offset += to_copy;
        if this.buffer_offset >= this.buffer.len() {
            this.complete = true;
        }

        Poll::Ready(Ok(()))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_work_conn(
    work_conn: IoStream,
    sock: Arc<tokio::net::UdpSocket>,
    proxy_name: String,
    local_addr: Option<msg::UdpAddr>,
    use_enc: bool,
    enc_key: [u8; 16],
    v2: bool,
    udp_packet_size: usize,
    bw_limiter: Option<frp_core::bandwidth::SharedBandwidthLimiter>,
    cancel: tokio_util::sync::CancellationToken,
    // Negotiated UDPPacket codec (`"binary-v1"` or empty). When set, UDP
    // packets on this V2 work conn use the binary codec (Go frp v0.71.0).
    udp_packet_codec: String,
    // M1 (audit round 3): read deadline for this work conn, mirroring Go
    // server/proxy/udp.go `workConnReaderFn` SetReadDeadline(60s). The
    // client pings at a FIXED 30s (audit F1 — Go client/proxy/udp.go
    // heartbeatFn hardcodes 30s; frp-rs used to wire dial_server_keepalive
    // here, whose 7200s default let this 60s deadline kill idle conns), so
    // 60s of frame silence means the peer is dead or the conn is
    // half-open — the bridge must end so the assign supervisor re-requests
    // a replacement (Go udpWorker loop parity). Without it a silent
    // half-open peer parked the reader forever, leaving the UDP proxy dead
    // until control reconnect. The deadline applies per read (each
    // completed frame — a Ping included — starts a fresh 60s), so an
    // active conn is never reaped.
    read_timeout: std::time::Duration,
) {
    // write_msg_v2_nof skips the flush syscall. That is only safe for a raw
    // TcpStream: TLS/mux/WS-wrapped streams buffer internally and would leave
    // frames in flight without flush — and a CipherWriter must flush to emit
    // its IV.
    let no_flush = work_conn.try_tcp().is_some() && !use_enc;
    let udp_codec_opt = if udp_packet_codec.is_empty() {
        None
    } else {
        Some(udp_packet_codec.as_str())
    };
    let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
        return;
    };
    // Provider-segment encryption (Go parity): when the UDP proxy configures
    // use_encryption, the work conn carries a CipherStream (AES-128-CFB,
    // derive_key(token)) with the V1/V2 frame protocol inside it — matching
    // the client side (frp-client work_conn.rs) and Go's
    // libio.WithEncryption(rwc, token) on the UDP proxy work conn.
    let w_r: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if use_enc {
        Box::new(CipherReader::new(w_r, enc_key))
    } else {
        w_r
    };
    let mut w_w: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = if use_enc {
        // Audit B2: OS-RNG failure (IV generation) ends this work conn
        // instead of aborting the process.
        match CipherWriter::new(w_w, enc_key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::warn!(error = %e, "udp work conn: IV generation failed");
                return;
            }
        }
    } else {
        w_w
    };
    // Buffer the frame reads: read_msg_v1/v2 issue two read_exact calls per
    // packet (header + payload), so BufReader amortizes them into one
    // syscall per packet — and one syscall for several small packets. The
    // write half is untouched (separate object), so no flush semantics
    // change.
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    let sock_reader = sock.clone();
    let reader_name = proxy_name.clone();
    let mut reader_cancel = cancel_rx.clone();
    let cancel_reader = cancel.clone();
    // UDP bandwidth limiting (frp-rs extension; Go frp v0.70.1 has no UDP
    // limiter). Go v0.71.0 parity for the model: ONE per-proxy shared
    // limiter created at registration (mode == "server"/"both"), wrapping
    // BOTH directions with the same bucket (proxy.go single-`rate.Limiter`
    // semantics). Both bridge tasks clone the Arc; empty/unset rate (0)
    // stays unlimited (limiter is None).
    let reader_lim = bw_limiter.clone();
    let reader = async move {
        debug!(proxy_name = %reader_name, "UDP work conn reader task started for '{}'", reader_name);
        // Reusable payload buffer for the V2 UDP read path (avoids a heap
        // alloc per UDP packet).
        let mut scratch: Vec<u8> = Vec::new();
        loop {
            let result = tokio::select! {
                biased;
                _ = cancel_reader.cancelled() => break,
                changed = reader_cancel.changed() => {
                    if changed.is_err() || *reader_cancel.borrow() { break; }
                    continue;
                }
                result = async {
                    match tokio::time::timeout(read_timeout, async {
                        if v2 {
                            if udp_codec_opt.is_some() {
                                // Binary UDP codec negotiated (Go v0.71.0):
                                // type-19 frames decode to native SocketAddr
                                // form, skipping the per-packet String alloc +
                                // reparse that the message path performs
                                // (audit LOW: decode formats then re-parses).
                                read_msg_v2_udp_binary_socket(&mut w_r, &mut scratch).await
                            } else {
                                read_msg_v2_with_udp_codec(&mut w_r, udp_codec_opt, &mut scratch)
                                    .await
                                    .map(UdpBinaryRead::Message)
                            }
                        } else {
                            read_msg_v1(&mut w_r).await.map(UdpBinaryRead::Message)
                        }
                    })
                    .await
                    {
                        Ok(r) => r,
                        // M1: 60s of frame silence (Go udp.go read-deadline
                        // parity) = dead/half-open peer. Folds into the Err
                        // arm below: log + break, and the supervisor
                        // re-requests a replacement work conn.
                        Err(_) => Err(frp_core::Error::Protocol(
                            format!(
                                "UDP work conn read deadline ({read_timeout:?}) expired with no frame from the client"
                            )
                            .into(),
                        )),
                    }
                } => result,
            };
            match result {
                // Native-address form (binary codec): the destination is
                // already a SocketAddr — send directly, no text round trip.
                Ok(UdpBinaryRead::Socket(pkt)) => {
                    if let Some(lim) = reader_lim.as_ref() {
                        frp_core::bandwidth::BandwidthLimiter::consume_shared(
                            lim,
                            pkt.content.len(),
                        )
                        .await;
                    }
                    if let Err(e) = sock_reader.send_to(&pkt.content, pkt.remote_addr).await {
                        debug!(proxy_name = %reader_name, error = %e,
                            "UDP send_to failed for '{}': {}", reader_name, e);
                    }
                }
                Ok(UdpBinaryRead::Message(FrpMessage::UDPPacket(up))) => {
                    // Rate-limit only bytes actually forwarded. Counting a
                    // dropped (malformed, no remote_addr) packet against the
                    // budget without delivering it would silently bill the
                    // user for nothing — refund=true by consuming only here,
                    // and log the drop for diagnosability.
                    if let Some(ref remote) = up.remote_addr {
                        if let Some(lim) = reader_lim.as_ref() {
                            frp_core::bandwidth::BandwidthLimiter::consume_shared(
                                lim,
                                up.content.len(),
                            )
                            .await;
                        }
                        // Prefer a direct `SocketAddr` (no per-packet String
                        // alloc + reparse of the destination, audit #14a); fall
                        // back to the string form when the address carries an
                        // IPv6 zone that `SocketAddr` cannot express.
                        if let Some(dest) = udp_dest_socket_addr(remote) {
                            if let Err(e) = sock_reader.send_to(&up.content, dest).await {
                                debug!(proxy_name = %reader_name, error = %e,
                                    "UDP send_to failed for '{}': {}", reader_name, e);
                            }
                        } else if let Err(e) =
                            sock_reader.send_to(&up.content, remote.to_string()).await
                        {
                            debug!(proxy_name = %reader_name, error = %e,
                                "UDP send_to failed for '{}': {}", reader_name, e);
                        }
                    } else {
                        debug!(
                            proxy_name = %reader_name,
                            bytes = up.content.len(),
                            "UDP work conn for '{}': dropped datagram with no remote_addr (malformed)",
                            reader_name
                        );
                    }
                }
                Ok(UdpBinaryRead::Message(FrpMessage::Ping(_)))
                | Ok(UdpBinaryRead::Message(FrpMessage::Pong(_))) => continue,
                Ok(UdpBinaryRead::Message(other)) => {
                    debug!(proxy_name = %reader_name, msg_type = %other.v1_type_byte(),
                        "UDP work conn for '{}': unexpected msg 0x{:02x}", reader_name, other.v1_type_byte());
                }
                Err(e) => {
                    debug!(proxy_name = %reader_name, error = %e,
                        "UDP work conn for '{}' read closed: {}", reader_name, e);
                    break;
                }
            }
        }
    };

    let writer_name = proxy_name.clone();
    let mut writer_cancel = cancel_rx;
    let cancel_writer = cancel;
    let writer_lim = bw_limiter.clone();
    let writer = async move {
        debug!(proxy_name = %writer_name, "UDP work conn writer task started for '{}'", writer_name);
        let mut buf = vec![0u8; udp_packet_size];
        // local_addr is loop-invariant (comes from proxy config). Move the
        // owned value into each packet and back out afterwards, so the
        // Option<UdpAddr> String heap allocs happen once per bridge instead
        // of once per packet. Single-task writer: no concurrency risk.
        let mut local_addr = local_addr;
        // Spare Vec for the packet content: the wire format base64-encodes
        // UDPPacket.content, and the memcpy of `buf[..n]` is inherent — but
        // the per-packet Vec *allocation* is not. take/return keeps the
        // capacity across packets (audit D1-4).
        let mut spare: Vec<u8> = Vec::with_capacity(udp_packet_size);
        // Reused binary-codec wire buffer: type ID + encoded packet.
        let mut wire_scratch: Vec<u8> = Vec::with_capacity(udp_packet_size + 48);
        loop {
            let received = tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => break,
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                    continue;
                }
                result = sock.recv_from(&mut buf) => result,
            };
            match received {
                Ok((n, src)) => {
                    spare.clear();
                    spare.extend_from_slice(&buf[..n]);
                    let content = std::mem::take(&mut spare);
                    if let Some(lim) = writer_lim.as_ref() {
                        frp_core::bandwidth::BandwidthLimiter::consume_shared(lim, n).await;
                    }
                    let result = if v2 && udp_codec_opt.is_some() {
                        // V2 binary codec path: encode the remote `SocketAddr`
                        // straight into the wire body — the per-packet
                        // `ip.to_string()` String alloc + reparse is only
                        // needed for the V1 JSON path, where the address is
                        // serialized as text (audit: LOW). Output bytes are
                        // identical to the string round trip
                        // (`encode_udp_packet_binary_socket_addr`). `content`
                        // is borrowed here and returned to `spare` below;
                        // `local_addr` is loop-invariant and only borrowed.
                        let encode = async {
                            wire_scratch.clear();
                            wire_scratch
                                .extend_from_slice(&msg::V2_TYPE_UDP_PACKET_BINARY.to_be_bytes());
                            frp_core::udp_binary::encode_udp_packet_binary_socket_addr(
                                &content,
                                local_addr.as_ref(),
                                &src,
                                &mut wire_scratch,
                            )
                            .map_err(|e| {
                                frp_core::Error::Protocol(
                                    format!("encode binary UDP packet: {e}").into(),
                                )
                            })?;
                            write_v2_frame_raw(&mut w_w, V2_FRAME_TYPE_MESSAGE, 0, &wire_scratch)
                                .await?;
                            if !no_flush {
                                w_w.flush().await.map_err(|e| {
                                    frp_core::Error::Protocol(
                                        format!("flush after binary UDP packet: {e}").into(),
                                    )
                                })?;
                            }
                            Ok(())
                        };
                        let r = encode.await;
                        spare = content;
                        r
                    } else {
                        let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                            content,
                            local_addr: local_addr.take(),
                            remote_addr: Some(msg::UdpAddr {
                                // Go net.IP.String() collapses IPv4-mapped
                                // IPv6 to the dotted-quad form; mirror that
                                // on the V1 JSON path too (same normalization
                                // as the V2 binary codec, review finding C1).
                                ip: match src.ip() {
                                    std::net::IpAddr::V6(v6) => v6
                                        .to_ipv4_mapped()
                                        .map(|v4| v4.to_string())
                                        .unwrap_or_else(|| src.ip().to_string()),
                                    _ => src.ip().to_string(),
                                },
                                port: src.port(),
                                zone: String::new(),
                            }),
                        });
                        let r = if v2 {
                            write_msg_v2_with_udp_codec(
                                &mut w_w,
                                &pkt,
                                udp_codec_opt,
                                no_flush,
                                &mut wire_scratch,
                            )
                            .await
                        } else {
                            write_msg_v1(&mut w_w, &pkt).await
                        };
                        // Return the invariant values to their locals for the
                        // next packet before checking the write result.
                        if let FrpMessage::UDPPacket(p) = pkt {
                            local_addr = p.local_addr;
                            spare = p.content;
                        }
                        r
                    };
                    if let Err(e) = result {
                        debug!(proxy_name = %writer_name, error = %e,
                            "UDP work conn write failed for '{}': {}", writer_name, e);
                        break;
                    }
                }
                Err(e) => {
                    debug!(proxy_name = %writer_name, error = %e,
                        "UDP recv_from error for '{}': {}", writer_name, e);
                    break;
                }
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            debug!(proxy_name = %proxy_name, "UDP reader exited; draining then cancelling writer");
            // Best-effort signal to the writer; a closed watch channel is fine.
            let _ = cancel_tx.send(true);
            // Give the writer a bounded window to drain before we drop it.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut writer,
            )
            .await;
        }
        _ = &mut writer => {
            debug!(proxy_name = %proxy_name, "UDP writer exited; draining then cancelling reader");
            // Best-effort signal to the reader; a closed watch channel is fine.
            let _ = cancel_tx.send(true);
            // Give the reader a bounded window to drain before we drop it.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut reader,
            )
            .await;
        }
    }
}

/// Log a bridge-task panic. Bridge tasks are spawned fire-and-forget and
/// their JoinHandles deliberately dropped, so a panic used to be silently
/// swallowed by Tokio (audit round 5, MEDIUM). The RAII `ConnGuard` still
/// releases the connection slot during unwind, but the panic cause was lost
/// — `catch_unwind` at the spawn sites preserves the diagnostic.
fn log_bridge_panic(proxy_name: &str, what: &str, p: Box<dyn std::any::Any + Send>) {
    let msg = p
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("(unknown)");
    tracing::error!(
        proxy_name = %proxy_name,
        panic = %msg,
        "Bridge task panicked: {what} (proxy '{}', panic: {})",
        proxy_name,
        msg
    );
}

/// Server-side UDP work-conn read deadline (Go server/proxy/udp.go
/// `workConnReaderFn` SetReadDeadline(60s) parity, M1 audit round 3). The
/// client pings at a FIXED 30s (audit F1 — Go client/proxy/udp.go
/// heartbeatFn hardcodes 30s, no config knob; frp-rs matches), so 60s
/// without ANY frame — a Ping included — means the peer is gone or the
/// conn is half-open.
const UDP_WORK_CONN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Re-request a UDP work conn after the previous one died (M1, audit
/// round 3). Mirrors Go's udpWorker replacement loop
/// (server/proxy/udp.go:184-243): a UDP proxy needs one live work conn
/// for its lifetime, and work-conn death must not strand it until control
/// reconnect. The cancel guard lives at the call site — a proxy close or
/// control teardown must not re-request. The existence guard in
/// `handle_udp_work_conn` closes the remaining cancel-vs-send race (a
/// close that lands between the guard check here and the internal send).
async fn request_udp_work_conn_replacement(
    internal_tx: &tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
    proxy_name: &str,
    reason: &str,
) {
    if let Err(e) = internal_tx
        .send(crate::state::InternalMsg::UdpNeedsWorkConn {
            proxy_name: proxy_name.to_string(),
        })
        .await
    {
        debug!(
            proxy_name = %proxy_name,
            error = %e,
            "UDP work-conn re-request after {reason} failed for '{}': {}",
            proxy_name,
            e
        );
    }
}

/// Assign a work connection to a UDP proxy for bidirectional data forwarding.
/// Matches Go frp v0.69.1 behavior: sends StartWorkConn, then bridges
/// UDP socket ↔ work connection via UDPPacket messages.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn assign_udp_work_conn(
    work_conn: IoStream,
    proxy_name: &str,
    udp_sockets: &std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    local_addr: Option<msg::UdpAddr>,
    use_enc: bool,
    enc_key: [u8; 16],
    v2: bool,
    udp_packet_size: usize,
    bw_limiter: Option<frp_core::bandwidth::SharedBandwidthLimiter>,
    cancel: tokio_util::sync::CancellationToken,
    udp_packet_codec: String,
    // M1 (audit round 3): internal channel back to the control loop — used
    // to re-request a replacement work conn when this one dies.
    internal_tx: tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
) {
    let mut work_conn = work_conn;
    let sock = match udp_sockets.get(proxy_name) {
        Some(s) => s.clone(),
        None => {
            // Proxy closed between the pending_udp enqueue and this work
            // conn's arrival (CloseProxy removed the socket) — nothing to
            // assign to, and no re-request: the proxy is gone.
            warn!(proxy_name = %proxy_name, "UDP socket not found for proxy '{}'", proxy_name);
            return;
        }
    };
    let proxy_name = proxy_name.to_string();

    // Control is shutting down (supersession / disconnect) — do not start a
    // bridge that would immediately be cancelled anyway.
    if cancel.is_cancelled() {
        debug!(proxy_name = %proxy_name, "Control is shutting down, not starting UDP bridge for '{}'", proxy_name);
        return;
    }

    // Send StartWorkConn to tell the client which proxy to associate
    let swc = FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: proxy_name.clone(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        error: None,
        use_encryption: if use_enc { Some(true) } else { None },
        use_compression: None,
        nat_hole_sid: None,
        nat_hole_visitor_addr: None,
        sk: None,
    }));
    if v2 {
        if let Err(e) = work_conn.write_v2_frame(&swc).await {
            warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn (V2) for UDP '{}': {}", proxy_name, e);
            // M1: the fresh work conn died before the bridge could start
            // and the pending_udp entry was already consumed — re-request
            // so the proxy is not stranded.
            request_udp_work_conn_replacement(
                &internal_tx,
                &proxy_name,
                "StartWorkConn (V2) write failure",
            )
            .await;
            return;
        }
    } else if let Err(e) = work_conn.write_v1_frame(&swc).await {
        warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn for UDP '{}': {}", proxy_name, e);
        // M1: same as the V2 branch above.
        request_udp_work_conn_replacement(&internal_tx, &proxy_name, "StartWorkConn write failure")
            .await;
        return;
    }
    debug!(proxy_name = %proxy_name, "UDP work conn assigned to '{}', starting bridge supervisor", proxy_name);

    let log_proxy_name = proxy_name.clone();
    let bridge_cancel = cancel.clone();
    let req_tx = internal_tx;
    tokio::spawn(async move {
        // Await the bridge's JoinHandle instead of dropping it: if the task
        // panics, JoinError carries the panic payload (audit round 5, MEDIUM).
        // The RAII ConnGuard still releases the slot during unwind; this just
        // preserves the panic cause in the logs.
        let handle = tokio::spawn(run_udp_work_conn(
            work_conn,
            sock,
            proxy_name,
            local_addr,
            use_enc,
            enc_key,
            v2,
            udp_packet_size,
            bw_limiter,
            bridge_cancel,
            udp_packet_codec,
            UDP_WORK_CONN_READ_TIMEOUT,
        ));
        if let Err(e) = handle.await {
            if e.is_panic() {
                log_bridge_panic(&log_proxy_name, "UDP bridge", e.into_panic());
            }
        }
        // M1 (audit round 3): work-conn death (EOF / read error / 60s
        // frame silence) must not strand the UDP proxy until control
        // reconnect — Go's udpWorker loop replaces the conn
        // (server/proxy/udp.go:184-243). Re-request a replacement unless
        // the exit was a cancellation (proxy closed or control teardown:
        // the socket entry is gone, and a ReqWorkConn would dial a work
        // conn into nothing). The existence guard in handle_udp_work_conn
        // closes the remaining cancel-vs-send race.
        if !cancel.is_cancelled() {
            request_udp_work_conn_replacement(&req_tx, &log_proxy_name, "work-conn death").await;
        }
    });
}

/// Relay plain traffic between two IoStreams, preferring zero-copy splice
/// on Linux when both sides are raw TCP.
async fn relay_plain_fast(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    relay_plain_fast_inner(user_conn, work_conn, metrics).await
}

/// Linux: try splice(2) zero-copy relay when both sides are raw TCP.
#[cfg(target_os = "linux")]
async fn relay_plain_fast_inner(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    // Two-arm dispatch so the Tcp arm consumes the streams while the other
    // arm binds new mutable variables for the copy_bidirectional fallthrough.
    // try_tcp() (borrow check) then into_tcp() (owned) — no await between,
    // so the transport cannot change.
    if user_conn.try_tcp().is_some() && work_conn.try_tcp().is_some() {
        let user = user_conn
            .into_tcp()
            .expect("try_tcp confirmed raw TCP above");
        let work = work_conn
            .into_tcp()
            .expect("try_tcp confirmed raw TCP above");
        match frp_core::splice::bridge_splice(user, work).await {
            Ok((a, b)) => {
                metrics.record_traffic(a, b);
            }
            Err(e) => {
                tracing::warn!(error = %e, "splice bridge closed with error: {}", e);
            }
        }
    } else {
        // Pooled-buffer relay (P3): copy_bidirectional_with_sizes allocated
        // two fresh 32 KiB buffers per bridge call; PoolGuard recycles them
        // across connections (FRP_BRIDGE_BUF_KB still governs the size).
        match frp_core::bridge::relay_plain_pooled(user_conn, work_conn).await {
            Ok((a, b)) => {
                metrics.record_traffic(a, b);
            }
            Err(e) => {
                tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
            }
        }
    }
}

/// Non-Linux: pooled-buffer bidirectional relay (splice(2) unavailable).
#[cfg(not(target_os = "linux"))]
async fn relay_plain_fast_inner(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    match frp_core::bridge::relay_plain_pooled(user_conn, work_conn).await {
        Ok((a, b)) => {
            metrics.record_traffic(a, b);
        }
        Err(e) => {
            tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
        }
    }
}

/// Type-erased user-side bridge halves: erasing the per-transport types lets
/// `bridge_encrypted` & friends share one monomorphization, and lets the
/// visitor-segment Cipher wrapper (`CipherReader`/`CipherWriter`) and the
/// plain boxed halves be handled uniformly.
type UserBridgeHalves = (
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
);

/// Split the visitor (user) conn into bridge halves, wrapping them in
/// `CipherReader`/`CipherWriter` with `derive_key(sk)` when visitor-segment
/// encryption is enabled (`visitor_enc_key = Some(key)`) and in
/// `SnappyStreamReader`/`SnappyStreamWriter` when visitor-segment compression
/// is enabled (`visitor_comp`).
///
/// Wire order matches Go frp's `VisitorManager.NewConn` (`WithEncryption`
/// outer, `WithCompression` inner): write plaintext → snappy → CFB → socket,
/// so the enc+comp wrapper is `SnappyStreamReader::new(CipherReader::new(...))`
/// / `SnappyStreamWriter::new(CipherWriter::new(...))`. A compression-only
/// visitor wraps the raw halves in Snappy directly.
///
/// When the `compression` feature is disabled, `SnappyStream*` degrades to a
/// transparent passthrough, so a compression-only visitor bridges plaintext
/// (same behavior as the provider-segment `compress_chunk_into` passthrough).
///
/// Returns `Err` (with a warn-worthy message) only when the underlying
/// transport cannot be split (same guard as `split_work_conn_halves`).
fn split_user_side(
    visitor_enc_key: Option<[u8; 16]>,
    visitor_comp: bool,
    user_conn: IoStream,
) -> Result<UserBridgeHalves, &'static str> {
    let (u_r, u_w) = split_work_conn_halves(user_conn)?;
    let (u_r, u_w): UserBridgeHalves = if let Some(key) = visitor_enc_key {
        (
            Box::new(CipherReader::new(u_r, key)),
            // Audit B2: IV-generation failure is an error, not an abort.
            Box::new(CipherWriter::new(u_w, key).map_err(|_| "OS random generator failed")?),
        )
    } else {
        (u_r, u_w)
    };
    if visitor_comp {
        Ok((
            Box::new(SnappyStreamReader::new(u_r)),
            Box::new(SnappyStreamWriter::new(u_w)),
        ))
    } else {
        Ok((u_r, u_w))
    }
}

/// Compute the visitor-segment encryption key from the proxy's `sk`
/// (`derive_key(sk)`), when the visitor declared `use_encryption`. Empty sk is
/// treated as "no key": we warn and bridge plaintext (robustness over exact
/// Go parity — Go would PBKDF2 an empty string into a weak key). Shared by the
/// byte-stream and SUDP message bridges so the logic (and its warn) cannot
/// drift apart (audit #12).
fn visitor_encryption_key(
    proxy_info: Option<&std::sync::Arc<crate::proxy::ProxyInfo>>,
    proxy_name: &str,
    use_encryption: bool,
) -> Option<[u8; 16]> {
    if !use_encryption {
        return None;
    }
    match proxy_info
        .and_then(|p| p.sk.as_deref())
        .filter(|s| !s.is_empty())
    {
        Some(sk) => Some(derive_key(sk)),
        None => {
            warn!(
                proxy_name = %proxy_name,
                "visitor declared use_encryption but proxy '{}' has no secret_key; \
                 bridging visitor segment in plaintext",
                proxy_name
            );
            None
        }
    }
}

/// Build a `SocketAddr` for `remote` without allocating, when the address is a
/// plain IPv4/IPv6 (no zone). Returns `None` when the ip does not parse or the
/// address carries an IPv6 scope zone — the caller falls back to the string
/// form in that case. Hot-path helper for the UDP reader (audit #14a): avoids
/// a `String` alloc + reparse per datagram in the common case.
fn udp_dest_socket_addr(remote: &msg::UdpAddr) -> Option<std::net::SocketAddr> {
    if !remote.zone.is_empty() {
        return None;
    }
    let ip: std::net::IpAddr = remote.ip.parse().ok()?;
    Some(std::net::SocketAddr::new(ip, remote.port))
}

/// Checked split of the user-side (visitor-segment) conn: calls `split_user_side`
/// and turns the `Err(&'static str)` into a `warn!`-and-None, so call sites use
/// `let Some((u_r, u_w)) = try_split_user_side(...) else { return };` instead of
/// repeating the five-line warn-return match (audit #12 — the pattern drifted
/// across SUDP and byte-stream bridges).
fn try_split_user_side(
    visitor_enc_key: Option<[u8; 16]>,
    visitor_comp: bool,
    user_conn: IoStream,
) -> Option<UserBridgeHalves> {
    match split_user_side(visitor_enc_key, visitor_comp, user_conn) {
        Ok(pair) => Some(pair),
        Err(msg) => {
            warn!("{msg}");
            None
        }
    }
}

/// Checked split of the work-conn halves: turns the `Err(&'static str)` into a
/// `warn!`-and-None (audit #12, dedup of the repeated warn-return match).
fn try_split_work_halves(
    work_conn: IoStream,
) -> Option<(
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
)> {
    match split_work_conn_halves(work_conn) {
        Ok(pair) => Some(pair),
        Err(msg) => {
            warn!("{msg}");
            None
        }
    }
}

/// Holds split user-side halves as one `AsyncRead`+`AsyncWrite` object so the
/// XTCP STCP fallback can keep its `copy_bidirectional` semantics via the
/// pooled relay `relay_plain_pooled` (both directions run to completion; the
/// work side is only shut down after the full bidirectional copy — avoids
/// the premature-FIN race that a join-of-two-halves bridge would
/// reintroduce).
struct UserSide<R, W> {
    r: R,
    w: W,
}

impl<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> AsyncRead for UserSide<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for UserSide<R, W>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.w).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

/// Bridge a user connection to a work connection for one proxy.
///
/// Runs inside the spawned bridge task. Extracted from `assign_work_to_proxy`
/// so the spawn site is a plain call and the bridge logic lives in its own
/// state machine instead of a 54 KiB inline closure.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
async fn run_work_bridge(
    work_conn: IoStream,
    req: PendingRequest,
    proxy_info: Option<Arc<crate::proxy::ProxyInfo>>,
    encryption_key: [u8; 16],
    metrics: Arc<frp_core::metrics::ProxyMetrics>,
    header_timeout: Option<std::time::Duration>,
    state: Arc<AppState>,
    v2: bool,
) {
    let _guard = ConnGuard::new(metrics.clone());
    let _drain = ActiveGuard::new(&state);

    // --- Encryption decisions (Go frp three-stage model) ---
    // Provider segment (work conn): token-based encryption from the proxy
    // config (`req.use_encryption`). SUDP previously forced plaintext here —
    // the per-packet transform model is now aligned with Go's stream
    // encryption, so SUDP honors the provider-segment encryption too.
    // (SUDP compression stays off — see `comp_key` below.)
    let is_sudp = proxy_info.as_ref().is_some_and(|p| p.proxy_type == "sudp");
    let use_enc = req.use_encryption;

    // SUDP data plane: when the visitor and provider segments use the same
    // wire protocol + packet codec, the byte-stream bridge below is
    // correct (Go `libio.Join`); when they differ, Go frp v0.71.0 routes
    // the pair through `joinSUDPMessageBridge`, which decodes and re-encodes
    // every packet on each side. The mismatch happens during upgrades —
    // e.g. a V1/JSON visitor talking to a V2/binary provider — and a plain
    // byte-stream relay would make the provider misparse the visitor's
    // frames ("unexpected V2 frame type"). Route mismatches to the
    // message-level bridge; identical encodings keep the zero-copy path.
    if is_sudp {
        let provider_codec = proxy_info
            .as_ref()
            .map(|p| p.udp_packet_codec.clone())
            .unwrap_or_default();
        let visitor_codec = req.visitor_udp_packet_codec.as_str();
        let mixed = normalize_wire_protocol(v2) != normalize_wire_protocol(req.visitor_v2)
            || provider_codec != visitor_codec;
        if mixed {
            tracing::info!(
                proxy_name = %req.proxy_name,
                provider_wire = %normalize_wire_protocol(v2),
                provider_codec = %provider_codec,
                visitor_wire = %normalize_wire_protocol(req.visitor_v2),
                visitor_codec = %visitor_codec,
                "bridging mixed SUDP packet encodings (message-level bridge)"
            );
            return run_sudp_message_bridge(
                work_conn,
                req,
                proxy_info,
                encryption_key,
                metrics,
                state,
                v2,
                &provider_codec,
            )
            .await;
        }
    }

    // Visitor segment (user conn): sk-based encryption when the visitor
    // declared `use_encryption` in NewVisitorConn (Go three-stage model,
    // stage 1). The visitor conn is wrapped in CipherReader/CipherWriter with
    // `derive_key(sk)` and only then joined to the provider segment
    // (token encryption or plaintext) — two nested layers, mirroring Go's
    // three-stage model.
    //
    // Empty sk: Go frp would still PBKDF2 an empty string and encrypt (the
    // key is just weak); we warn and bridge plaintext to keep the tunnel
    // usable (robustness over exact parity).
    let visitor_enc_key = visitor_encryption_key(
        proxy_info.as_ref(),
        &req.proxy_name,
        req.visitor_use_encryption,
    );

    // Whether visitor-segment encryption/compression is on. The user conn is
    // NOT split here — each bridge branch below calls
    // `split_user_side(visitor_enc_key, visitor_comp, req.user_conn)`, which
    // wraps the halves in CipherReader/CipherWriter (when the key is present)
    // and SnappyStreamReader/SnappyStreamWriter (when compression is on),
    // keeping the plain IoStream available for the relay_plain_fast splice
    // path (only taken when neither wrapping applies). CipherWriter::poll_flush
    // already sends the IV eagerly, and the first write to the user side
    // carries it, so no manual IV flush is needed.
    let visitor_encrypted = visitor_enc_key.is_some();
    if visitor_encrypted {
        debug!(
            proxy_name = %req.proxy_name,
            "Visitor-segment encryption on for proxy '{}' (derive_key(sk))", req.proxy_name
        );
    }

    // Visitor-segment compression: from the visitor's NewVisitorConn
    // use_compression declaration (`[[visitors]] transport.useCompression`),
    // Go 三段式第 1 段. Applied in `split_user_side` below — Snappy stream
    // inside the CFB layer when visitor-segment encryption is also on.
    let visitor_comp = req.visitor_use_compression;
    if visitor_comp {
        debug!(
            proxy_name = %req.proxy_name,
            "Visitor-segment compression on for proxy '{}'", req.proxy_name
        );
    }

    // The per-proxy SHARED bandwidth limiter (F1/F2): created once at proxy
    // registration (build_proxy_info) when mode == "server"/"both" and a
    // rate is set; one bucket covers BOTH directions and all concurrent
    // connections (Go frp v0.71.0 single-`rate.Limiter` parity — the mode
    // gate lives at registration, not per bridge call). "client"/empty mode
    // is the client's responsibility (Go: server creates a limiter only in
    // "server" mode).
    let bw_limiter = proxy_info
        .as_ref()
        .and_then(|p| p.bandwidth_limiter.clone());

    // The response-header injector only fires for HTTP-family proxies
    // with configured headers; clone the HashMap at bridge time instead
    // of deep-cloning it into every pending request at enqueue time.
    // Uses the resolved metadata (bridge-time re-fetch when the
    // enqueue-time snapshot was None).
    let injector_headers = proxy_info
        .as_ref()
        .filter(|p| p.proxy_type.starts_with("http"))
        .map(|p| p.response_headers.clone())
        .filter(|h| !h.is_empty());

    // For encrypted bridges, pre_read bytes are passed into bridge_encrypted
    // which writes them through the CipherWriter (matching Go frp streaming CFB).
    if use_enc {
        let key = encryption_key;
        let Some((u_r, u_w)) = try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
        else {
            return;
        };
        // One boxed split for every IoStream variant — a single
        // monomorphization of bridge_encrypted instead of one per variant.
        let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
            return;
        };
        // SUDP provider-segment compression stays off in BOTH bridge modes:
        // bridge_encrypted's Snappy stream would be misread by the provider's
        // frame reader as a V1 header (sNaPpY magic → "invalid V1 msg length").
        // Go's streaming compression model for the per-packet SUDP plane is
        // not unified here yet — this change is encryption-focused.
        let comp_key = req.use_compression && !is_sudp;
        if let Some(headers) = injector_headers {
            // Response-header injection MUST observe plaintext (#2): the
            // work conn carries AES-128-CFB ciphertext, so decrypt FIRST via
            // CipherReader, THEN wrap in the injector. Passing this to
            // bridge_encrypted with `read_is_decrypted=true` stops the bridge
            // from re-wrapping (which would double-decrypt/corrupt).
            let decrypted = CipherReader::new(w_r, key);
            let injector = ResponseHeaderInjector::new(decrypted, headers);
            frp_core::bridge::bridge_encrypted(
                u_r,
                u_w,
                injector,
                w_w,
                &key,
                comp_key,
                req.pre_read,
                bw_limiter.as_ref(),
                Some(metrics.clone()),
                header_timeout,
                true,
            )
            .await;
            // Matches the original inline closure: the injector path skips
            // the "bridge completed" debug below.
            return;
        }
        frp_core::bridge::bridge_encrypted(
            u_r,
            u_w,
            w_r,
            w_w,
            &key,
            comp_key,
            req.pre_read,
            bw_limiter.as_ref(),
            Some(metrics.clone()),
            header_timeout,
            false,
        )
        .await;
    } else {
        // Pass VHost pre-read bytes through bridge_plain so the bridge
        // can coordinate: write pre_read first, then skip work_w shutdown
        // to let the backend response flow back to the user.
        let bridge_pre_read = req.pre_read;
        // SUDP: compression stays forced off — bridge_plain wraps the stream
        // in Snappy when comp_key is set, which the provider's plaintext
        // read_msg_v1 would misread as a V1 frame header (sNaPpY magic →
        // "invalid V1 msg length"). Go's streaming compression model for the
        // per-packet SUDP plane is not unified here yet; this change is
        // encryption-focused, so SUDP compression remains off (only the
        // provider-segment encryption restriction was lifted above).
        let comp_key = req.use_compression && !is_sudp;

        // XTCP STCP fallback: keep copy_bidirectional semantics for both
        // directions — bridge_plain's join! pattern drops the work writer
        // (sending FIN) as soon as the user reader reaches EOF. For STCP
        // fallback the visitor's test client half-closes after sending data,
        // so the server sees EOF on the user side ~60ms before the provider
        // starts its bridge. The premature FIN on the work connection races
        // with the provider's copy_bidirectional startup and produces
        // ECONNRESET on VPS. relay_plain_pooled avoids this exactly like
        // copy_bidirectional: both directions run to completion within the
        // same function, and the work side is only shut down after the full
        // bidirectional copy finishes (pooled buffers — audit round-8 P1).
        //
        // Visitor-segment encryption/compression (if on) split the user conn
        // into wrapped halves (via `split_user_side`), re-combined via
        // `UserSide` for the same relay call.
        if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            // Pooled-buffer relay (audit round-8 P1): relay_plain_pooled has
            // EXACTLY the copy_bidirectional semantics this arm's comment
            // above requires — both directions run to completion and the
            // work side is only shut down after the full bidirectional copy
            // (FIN-propagation, no premature-FIN race), without the
            // per-conn buffer pair. Buffer size stays FRP_BRIDGE_BUF_KB
            // (the pool's BUFFER_SIZE governs the XTCP STCP fallback path).
            let user_side = UserSide { r: u_r, w: u_w };
            match frp_core::bridge::relay_plain_pooled(user_side, work_conn).await {
                Ok((a, b)) => {
                    metrics.record_traffic(a, b);
                }
                Err(e) => {
                    debug!(error = %e, "XTCP STCP fallback bridge closed: {}", e);
                }
            }
        } else if bw_limiter.is_some() {
            // Bandwidth limiting active: use rate-limited plain bridge.
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
                return;
            };
            if let Some(headers) = injector_headers {
                let injector = ResponseHeaderInjector::new(w_r, headers);
                frp_core::bridge::bridge_plain_rate_limited(
                    u_r,
                    u_w,
                    injector,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    bw_limiter.as_ref(),
                    Some(metrics.clone()),
                    header_timeout,
                )
                .await;
            } else {
                frp_core::bridge::bridge_plain_rate_limited(
                    u_r,
                    u_w,
                    w_r,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    bw_limiter.as_ref(),
                    Some(metrics.clone()),
                    header_timeout,
                )
                .await;
            }
        } else if !comp_key
            && bridge_pre_read.is_empty()
            && injector_headers.is_none()
            && !visitor_encrypted
            && !visitor_comp
        {
            // Fast path: pure plain relay with no compression, no VHost
            // pre-read, no header injection, and no visitor-segment
            // encryption/compression (splice needs the raw IoStream; visitor
            // wrapping already split it into wrapped halves). On Linux, try
            // zero-copy splice for Tcp-to-Tcp; otherwise use
            // copy_bidirectional.
            relay_plain_fast(req.user_conn, work_conn, &metrics).await;
        } else {
            // Slow path: compression, VHost pre-read, header injection, or
            // visitor-segment encryption.
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
                return;
            };
            if let Some(headers) = injector_headers {
                let injector = ResponseHeaderInjector::new(w_r, headers);
                frp_core::bridge::bridge_plain(
                    u_r,
                    u_w,
                    injector,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    Some(metrics.clone()),
                    header_timeout,
                )
                .await;
            } else {
                frp_core::bridge::bridge_plain(
                    u_r,
                    u_w,
                    w_r,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    Some(metrics.clone()),
                    header_timeout,
                )
                .await;
            }
        }
    }
    debug!(proxy_name = %req.proxy_name, "Proxy '{}' bridge completed", req.proxy_name);
}

/// Go frp v0.71.0 `normalizeWireProtocol`: "" and "v1" both normalize to
/// "v1"; only "v2" stays "v2".
fn normalize_wire_protocol(v2: bool) -> &'static str {
    if v2 {
        "v2"
    } else {
        "v1"
    }
}

/// Message-level SUDP bridge (Go frp v0.71.0 `joinSUDPMessageBridge`).
///
/// Used when the visitor segment and the provider segment negotiate
/// different packet encodings (e.g. a V1/JSON visitor talking to a
/// V2/binary provider during an upgrade). A plain byte-stream relay would
/// make the provider misparse the visitor's frames as its own protocol
/// ("unexpected V2 frame type"), so every `UDPPacket` is decoded on the
/// source side and re-encoded on the destination side.
///
/// Direction semantics match Go:
/// - visitor → provider: `UDPPacket` forwarded, `Ping` dropped
///   (`bridgeSUDPVisitorToProxy`);
/// - provider → visitor: `UDPPacket` forwarded, `Ping` forwarded
///   (`bridgeSUDPProxyToVisitor`).
///
/// `Pong` is ignored on both sides (frp-rs UDP data planes treat
/// Ping/Pong as keepalive and never forward them); any other message type
/// is a protocol violation and closes the pair.
#[allow(clippy::too_many_arguments)]
async fn run_sudp_message_bridge(
    work_conn: IoStream,
    req: PendingRequest,
    proxy_info: Option<Arc<crate::proxy::ProxyInfo>>,
    encryption_key: [u8; 16],
    metrics: Arc<frp_core::metrics::ProxyMetrics>,
    state: Arc<AppState>,
    provider_v2: bool,
    provider_codec: &str,
) {
    let _guard = ConnGuard::new(metrics.clone());
    let _drain = ActiveGuard::new(&state);
    let visitor_v2 = req.visitor_v2;
    let visitor_codec = req.visitor_udp_packet_codec.as_str();

    // Visitor-segment encryption/compression (Go 三段式第 1 段): identical
    // decision to the byte-stream bridge — sk-derived key when the visitor
    let visitor_enc_key = visitor_encryption_key(
        proxy_info.as_ref(),
        &req.proxy_name,
        req.visitor_use_encryption,
    );
    let Some((v_r, mut v_w)) =
        try_split_user_side(visitor_enc_key, req.visitor_use_compression, req.user_conn)
    else {
        return;
    };
    // Provider-segment encryption (token-derived key) wraps the work halves
    // before the message loop, matching the byte-stream bridge.
    let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
        return;
    };
    let w_r: frp_core::transport::BoxedReadHalf = if req.use_encryption {
        Box::new(CipherReader::new(w_r, encryption_key))
    } else {
        w_r
    };
    let mut w_w: frp_core::transport::BoxedWriteHalf = if req.use_encryption {
        // Audit B2: OS-RNG failure (IV generation) ends this bridge instead
        // of aborting the process.
        match CipherWriter::new(w_w, encryption_key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::warn!(error = %e, "udp bridge: IV generation failed");
                return;
            }
        }
    } else {
        w_w
    };
    // Frame reads issue two read_exact calls per message; buffer them.
    let mut v_r = tokio::io::BufReader::with_capacity(16 * 1024, v_r);
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);

    let visitor_codec_opt = if visitor_codec.is_empty() {
        None
    } else {
        Some(visitor_codec)
    };
    let provider_codec_opt = if provider_codec.is_empty() {
        None
    } else {
        Some(provider_codec)
    };
    let proxy_name = req.proxy_name.clone();

    // Direction 1: visitor → provider. Ping is dropped (Go
    // bridgeSUDPVisitorToProxy). Traffic is accumulated locally and flushed
    // to metrics periodically so the live dashboard/otel counters are not
    // frozen at 0 for the whole (possibly long-lived) bridge — and so an
    // aborted/joined-interrupted task does not lose the session's bytes or
    // dump them wholesale into the teardown day's bucket (#4).
    const SUDP_TRAFFIC_REPORT_EVERY: u32 = 64;
    let visitor_to_provider = async {
        // Reusable payload buffer for the V2 UDP read path.
        let mut scratch: Vec<u8> = Vec::new();
        // Reusable binary-codec wire buffer (write side; `scratch` above is
        // the read side).
        let mut wire_scratch: Vec<u8> = Vec::new();
        let mut fwd_in: u64 = 0;
        let mut report = 0u32;
        loop {
            let read = if visitor_v2 {
                read_msg_v2_with_udp_codec(&mut v_r, visitor_codec_opt, &mut scratch).await
            } else {
                read_msg_v1(&mut v_r).await
            };
            let msg = match read {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        proxy_name = %proxy_name,
                        error = %e,
                        "SUDP message bridge: visitor read closed: {}",
                        e
                    );
                    break;
                }
            };
            match &msg {
                FrpMessage::UDPPacket(pkt) => {
                    fwd_in += pkt.content.len() as u64;
                }
                FrpMessage::Ping(_) | FrpMessage::Pong(_) => {
                    // Go drops SUDP pings on the visitor→proxy leg.
                    continue;
                }
                other => {
                    warn!(
                        proxy_name = %proxy_name,
                        type_byte = %other.v1_type_byte(),
                        "SUDP message bridge: unexpected visitor message 0x{:02x}",
                        other.v1_type_byte()
                    );
                    break;
                }
            }
            let write = if provider_v2 {
                write_msg_v2_with_udp_codec(
                    &mut w_w,
                    &msg,
                    provider_codec_opt,
                    false,
                    &mut wire_scratch,
                )
                .await
            } else {
                write_msg_v1(&mut w_w, &msg).await
            };
            if let Err(e) = write {
                debug!(
                    proxy_name = %proxy_name,
                    error = %e,
                    "SUDP message bridge: provider write failed: {}",
                    e
                );
                break;
            }
            report += 1;
            if report >= SUDP_TRAFFIC_REPORT_EVERY {
                metrics.record_traffic(fwd_in, 0);
                fwd_in = 0;
                report = 0;
            }
        }
        metrics.record_traffic(fwd_in, 0);
    };

    // Direction 2: provider → visitor. Ping is forwarded (Go
    // bridgeSUDPProxyToVisitor). Traffic is accumulated locally and flushed
    // periodically (see direction 1's rationale: live counters, no loss on
    // abort, no single-day dump).
    let provider_to_visitor = async {
        // Reusable payload buffer for the V2 UDP read path (own buffer; the
        // two directions run concurrently via tokio::join!).
        let mut scratch: Vec<u8> = Vec::new();
        // Reusable binary-codec wire buffer (write side; `scratch` above is
        // the read side).
        let mut wire_scratch: Vec<u8> = Vec::new();
        let mut fwd_out: u64 = 0;
        let mut report = 0u32;
        loop {
            let read = if provider_v2 {
                read_msg_v2_with_udp_codec(&mut w_r, provider_codec_opt, &mut scratch).await
            } else {
                read_msg_v1(&mut w_r).await
            };
            let msg = match read {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        proxy_name = %proxy_name,
                        error = %e,
                        "SUDP message bridge: provider read closed: {}",
                        e
                    );
                    break;
                }
            };
            match &msg {
                FrpMessage::UDPPacket(pkt) => {
                    fwd_out += pkt.content.len() as u64;
                }
                FrpMessage::Ping(_) => {
                    // Go forwards SUDP pings provider→visitor
                    // (bridgeSUDPProxyToVisitor).
                }
                FrpMessage::Pong(_) => {
                    // Pong is never forwarded (Go has no Pong in this
                    // direction; frp-rs data planes treat Ping/Pong as
                    // keepalive and ignore them).
                    continue;
                }
                other => {
                    warn!(
                        proxy_name = %proxy_name,
                        type_byte = %other.v1_type_byte(),
                        "SUDP message bridge: unexpected provider message 0x{:02x}",
                        other.v1_type_byte()
                    );
                    break;
                }
            }
            let write = if visitor_v2 {
                write_msg_v2_with_udp_codec(
                    &mut v_w,
                    &msg,
                    visitor_codec_opt,
                    false,
                    &mut wire_scratch,
                )
                .await
            } else {
                write_msg_v1(&mut v_w, &msg).await
            };
            if let Err(e) = write {
                debug!(
                    proxy_name = %proxy_name,
                    error = %e,
                    "SUDP message bridge: visitor write failed: {}",
                    e
                );
                break;
            }
            report += 1;
            if report >= SUDP_TRAFFIC_REPORT_EVERY {
                metrics.record_traffic(0, fwd_out);
                fwd_out = 0;
                report = 0;
            }
        }
        metrics.record_traffic(0, fwd_out);
    };

    tokio::join!(visitor_to_provider, provider_to_visitor);
    debug!(proxy_name = %proxy_name, "SUDP message bridge completed");
}

/// Assign `req` to `work_conn`, starting the bridge.
///
/// Returns `Ok(())` once the bridge task is spawned (work_conn and req are
/// consumed), or `Err(req)` if the StartWorkConn write failed — the work
/// conn is dead and the request (with its user conn) is returned so the
/// caller can retry it against a fresh work conn instead of dropping the
/// user connection (audit fix: dead pooled work conns used to fail the user
/// conn with no retry). Boxed: the request is large and this error is cold
/// (one alloc on the retry path; keeps `result_large_err` quiet).
pub(crate) async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
    state: Arc<AppState>,
    v2: bool,
    bridge_cancel: tokio_util::sync::CancellationToken,
) -> Result<(), Box<PendingRequest>> {
    // Extract peer address from user connection for PROXY protocol support
    let (src_addr, src_port) = req
        .user_conn
        .try_tcp()
        .and_then(|s| s.peer_addr().ok())
        .map(|a| (a.ip().to_string(), a.port()))
        .unwrap_or_default();

    // Proxy metadata is carried in the request (fetched once by the
    // dispatcher). When the snapshot is None — the STCP/XTCP
    // visitor-before-provider-registration race, where the request was
    // enqueued before the proxy was visible to the dispatcher — re-fetch
    // from the proxy map at bridge time (the old behavior), so the bridge
    // uses the now-registered proxy's metadata instead of empty
    // local_addr/dst_port. Clone the Arc (cheap refcount bump) so the
    // borrow does not block moving `req` into the spawned bridge task
    // below.
    let proxy_info = match req.proxy_info.clone() {
        Some(info) => Some(info),
        None => state.proxy_manager.get(&req.proxy_name).await,
    };
    let dst_addr = proxy_info
        .as_ref()
        .and_then(|p| p.local_addr.clone())
        .unwrap_or_default();
    let dst_port = proxy_info.as_ref().and_then(|p| p.remote_port).unwrap_or(0);

    let swc = build_start_work_conn(&req, &src_addr, src_port, &dst_addr, dst_port);

    let write_result = if v2 {
        work_conn.write_v2_frame(&swc).await
    } else {
        work_conn.write_v1_frame(&swc).await
    };

    if let Err(e) = write_result {
        warn!(error = %e, "Failed to send StartWorkConn: {}", e);
        // The work conn is dead (e.g. the client closed it while pooled).
        // Return the request so the caller can re-enqueue it against a
        // fresh work conn instead of failing the user connection.
        return Err(Box::new(req));
    }

    // Flush StartWorkConn to wire before bridge data. KcpStream::poll_flush
    // now triggers immediate force_flush (update + drain + FEC encode + UDP send)
    // in the KCP driver, so Go frpc receives StartWorkConn as a separate KCP
    // output before bridge data arrives.
    if let Err(e) = work_conn.flush().await {
        warn!(error = %e, "Failed to flush StartWorkConn: {}", e);
    }

    // For XTCP STCP fallback: send a dummy NatHoleSid frame with
    // empty sid after StartWorkConn for Go frpc compatibility.
    // Go frpc's InWorkConn expects either an embedded nat_hole_sid in
    // StartWorkConn JSON (newer frp) or a separate NatHoleSid frame
    // immediately after StartWorkConn (Go frp v0.69.1). Our Rust frpc
    // provider's byte-peek (V1) / V2 frame read handles both formats.
    // The copy_bidirectional-semantics relay (used for XTCP STCP fallback
    // below) doesn't send a premature FIN, so the provider can safely
    // consume this frame without the old ECONNRESET race.
    // V2-aware: use V2 or V1 framing based on protocol version.
    if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
        let dummy = FrpMessage::NatHoleSid(msg::NatHoleSid::default());
        let write_result = if v2 {
            work_conn.write_v2_frame(&dummy).await
        } else {
            work_conn.write_v1_frame(&dummy).await
        };
        // A failure to deliver the empty NatHoleSid marker means the Go frpc
        // provider may not start its XTCP STCP fallback bridge; log it (unlike
        // the StartWorkConn write above, this one didn't name the failing frame).
        if let Err(e) = write_result {
            debug!(
                proxy_name = %req.proxy_name,
                error = %e,
                "failed to write dummy NatHoleSid frame to work conn: {e}"
            );
        }
    }

    debug!(proxy_name = %req.proxy_name, proxy_type = %proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""), "Bridging user conn to work conn for proxy '{}' (type={})", req.proxy_name, proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""));

    let proxy_name = req.proxy_name.clone();
    let metrics = state.proxy_metrics.get_or_create(&proxy_name).await;

    // HTTP vhost backend response-header timeout (Go frp compat:
    // VhostHTTPTimeout drives httputil.ReverseProxy.ResponseHeaderTimeoutS).
    // Only HTTP-family proxies get the timeout; TCP/STCP/XTCP bridges have no
    // such semantic. 0 (unset) disables the timeout, matching Go where the
    // ReverseProxy transport never arms a header deadline.
    let header_timeout = if proxy_info
        .as_ref()
        .is_some_and(|p| p.proxy_type.starts_with("http"))
        && state.vhost_http_timeout > 0
    {
        Some(std::time::Duration::from_secs(state.vhost_http_timeout))
    } else {
        None
    };

    // Spawn the bridge; select against the server shutdown token so a
    // graceful shutdown can interrupt half-open idle bridges instead of
    // waiting on TCP keepalive (2h) or yamux keepalive (90s) — audit D2-4 —
    // AND against the per-control `bridge_cancel` token so control teardown
    // (disconnect / supersession) stops the bridge: the work conn is owned
    // by this control, and a half-open client-side conn would otherwise
    // copy forever, leaking 1 task + 2 fds per reconnect with active
    // tunnels (HIGH finding). ONE task per bridged connection instead of
    // the old nested spawn whose JoinHandle was awaited only to extract the
    // panic payload (audit round 5, MEDIUM): the select is polled in-place
    // and panics are surfaced via catch_unwind, halving the task
    // allocations and wakeup registrations. The task is fire-and-forget
    // (bridges are connection-bounded and self-terminate; shutdown just
    // accelerates teardown). Note: in the release panic=abort profile the
    // panic aborts before catch_unwind fires — exactly as the old
    // JoinHandle-await also never fired there; in unwinding builds (tests)
    // the payload still reaches log_bridge_panic and the RAII ConnGuard
    // still releases the slot during unwind.
    let shutdown = state.shutdown_token.clone();
    let state_for_bridge = state.clone();
    let log_proxy_name = req.proxy_name.clone();
    tokio::spawn(async move {
        let fut = async {
            tokio::select! {
                _ = run_work_bridge(
                    work_conn,
                    req,
                    proxy_info,
                    encryption_key,
                    metrics,
                    header_timeout,
                    state_for_bridge,
                    v2,
                ) => {}
                _ = shutdown.cancelled() => {}
                _ = bridge_cancel.cancelled() => {}
            }
        };
        if let Err(p) = AssertUnwindSafe(fut).catch_unwind().await {
            log_bridge_panic(&log_proxy_name, "bridge", p);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Work stream whose reads block forever and whose writes fail
    /// deterministically, independent of platform TCP shutdown/RST timing.
    struct FailingWorkStream;

    impl AsyncRead for FailingWorkStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for FailingWorkStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected writer failure",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn udp_work_reader_eof_cancels_blocked_socket_writer() {
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_addr = socket.local_addr().unwrap();
        let retained_socket = socket.clone();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            // M1: keep the 60s production read deadline; these tests end
            // the bridge via EOF/cancel, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));
        drop(peer);

        tokio::time::timeout(std::time::Duration::from_millis(200), bridge)
            .await
            .expect("reader EOF must cancel the sibling blocked on UDP recv_from")
            .unwrap();

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"after-stop", socket_addr).await.unwrap();
        let mut buf = [0; 32];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            retained_socket.recv_from(&mut buf),
        )
        .await
        .expect("stopped writer must not consume a later datagram")
        .unwrap();
        assert_eq!(&buf[..n], b"after-stop");
    }

    #[tokio::test]
    async fn udp_work_writer_error_cancels_blocked_work_reader() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_addr = socket.local_addr().unwrap();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::SshChannel(Box::new(FailingWorkStream)),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            // M1: keep the 60s production read deadline; these tests end
            // the bridge via EOF/cancel, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));
        sender.send_to(b"force-write", socket_addr).await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
            .await
            .expect("writer error must cancel the sibling blocked on work read")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_forwards_packets_and_addresses_bidirectionally() {
        let (work, peer) = tcp_pair().await;
        let mut peer = IoStream::Tcp(peer);
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();
        let local_addr = msg::UdpAddr {
            ip: "192.0.2.8".to_string(),
            port: 7000,
            zone: String::new(),
        };
        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket.clone(),
            "udp-test".to_string(),
            Some(local_addr.clone()),
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            // M1: keep the 60s production read deadline; these tests end
            // the bridge via EOF/cancel, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));

        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"request".to_vec(),
            local_addr: None,
            remote_addr: Some(msg::UdpAddr {
                ip: remote_addr.ip().to_string(),
                port: remote_addr.port(),
                zone: String::new(),
            }),
        }))
        .await
        .unwrap();
        let mut buf = [0u8; 32];
        let (n, _) = remote.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        remote
            .send_to(b"response", socket.local_addr().unwrap())
            .await
            .unwrap();
        let response = peer.read_v1_frame().await.unwrap();
        match response {
            FrpMessage::UDPPacket(packet) => {
                assert_eq!(packet.content, b"response");
                assert_eq!(
                    packet.local_addr.unwrap().to_string(),
                    local_addr.to_string()
                );
                assert_eq!(
                    packet.remote_addr.unwrap().to_string(),
                    remote_addr.to_string()
                );
            }
            other => panic!("expected UDPPacket, got type {}", other.v1_type_byte()),
        }

        drop(peer);
        tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn udp_bridge_cancel_terminates_half_open_work_conn() {
        // Half-open work conn: keep the peer side open but never send, so the
        // reader blocks on read_msg_v1 (no EOF) and the writer blocks on
        // recv_from. Before the cancellation fix this bridge task hung
        // forever, leaking the work conn fd + socket + task memory after
        // control supersession/disconnect (Go frp v0.70.1 fix parity).
        let (work, _peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cancel = tokio_util::sync::CancellationToken::new();
        let bridge_cancel = cancel.clone();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            bridge_cancel,
            String::new(),
            // M1: keep the 60s production read deadline; the cancel arm
            // below ends this bridge, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));

        // Let both bridge tasks reach their blocking points.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
            .await
            .expect("cancel must terminate the half-open UDP bridge task")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_reader_silence_reaps_half_open_conn() {
        // M1: Go server/proxy/udp.go read-deadline parity. A peer that
        // stays open but silent (no frames at all — a Ping included) must
        // be reaped after the read deadline; before the fix the reader was
        // parked on read_msg forever (dead UDP proxy until control
        // reconnect). Short deadline (150ms) pins the reap path without a
        // 60s test.
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let retained_socket = socket.clone();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            std::time::Duration::from_millis(150),
        ));
        // Keep `peer` alive and silent: no EOF, no frames.
        std::mem::forget(peer);

        tokio::time::timeout(std::time::Duration::from_secs(2), bridge)
            .await
            .expect("frame silence must end the UDP bridge after the read deadline")
            .unwrap();

        // The reaped bridge must not consume a later datagram (writer was
        // cancelled, not left draining).
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"after-stop", retained_socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0; 32];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            retained_socket.recv_from(&mut buf),
        )
        .await
        .expect("stopped writer must not consume a later datagram")
        .unwrap();
        assert_eq!(&buf[..n], b"after-stop");
    }

    #[tokio::test]
    async fn udp_work_conn_death_requests_replacement() {
        // M1: a UDP work-conn death (EOF here; read error / 60s silence
        // follow the same break path) must re-request a replacement
        // through the control loop — Go udpWorker replacement-loop parity.
        // Before the fix UdpNeedsWorkConn was sent exactly once at
        // registration and a dead work conn stranded the UDP proxy until
        // control reconnect.
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut udp_sockets = std::collections::HashMap::new();
        udp_sockets.insert("udp-test".to_string(), socket.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::InternalMsg>(16);

        let assign = tokio::spawn(async move {
            assign_udp_work_conn(
                IoStream::Tcp(work),
                "udp-test",
                &udp_sockets,
                None,
                false,
                [0u8; 16],
                false,
                1500,
                None,
                tokio_util::sync::CancellationToken::new(),
                String::new(),
                tx,
            )
            .await
        });
        // Let assign write StartWorkConn and spawn the bridge, then kill the
        // peer so the bridge read sees EOF.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(peer);
        assign.await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("work-conn death must re-request a replacement")
            .expect("channel closed");
        match msg {
            crate::state::InternalMsg::UdpNeedsWorkConn { proxy_name } => {
                assert_eq!(proxy_name, "udp-test");
            }
            other => panic!("expected UdpNeedsWorkConn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_work_conn_cancel_suppresses_replacement_request() {
        // M1: an exit caused by cancellation (proxy closed / control
        // teardown) must NOT re-request — the udp_sockets entry is gone and
        // a ReqWorkConn would dial a work conn into nothing. Half-open
        // bridge cancelled mid-flight; the channel must stay empty.
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut udp_sockets = std::collections::HashMap::new();
        udp_sockets.insert("udp-test".to_string(), socket.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::InternalMsg>(16);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_in = cancel.clone();

        let assign = tokio::spawn(async move {
            assign_udp_work_conn(
                IoStream::Tcp(work),
                "udp-test",
                &udp_sockets,
                None,
                false,
                [0u8; 16],
                false,
                1500,
                None,
                cancel_in,
                String::new(),
                tx,
            )
            .await
        });
        // Let the bridge park on the half-open read, then cancel it (the
        // 60s production read deadline keeps the natural-death path out of
        // this test's window). Keep `peer` alive so no EOF races the cancel.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        assign.await.unwrap();
        std::mem::forget(peer);

        match tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await {
            // Supervisors finished (tx dropped) without sending — correct.
            Ok(None) => {}
            Ok(Some(other)) => {
                panic!("cancel-based bridge exit must not re-request a replacement, got {other:?}")
            }
            Err(_elapsed) => panic!("supervisor still alive 300ms after cancel"),
        }
    }

    #[tokio::test]
    async fn bridge_cancel_terminates_half_open_tcp_bridge() {
        // Half-open TCP bridge: work conn + user conn both open, neither
        // side sending, so the copy blocks forever. Before the fix the
        // bridge task selected only on the server-global shutdown token, so
        // control teardown (disconnect / supersession) left it copying — the
        // half-open work conn (client side gone) + user conn + task leaked
        // per reconnect with active tunnels (HIGH finding). The bridge must
        // exit when the per-control token is cancelled, which is exactly
        // what control cleanup does with `bridge_cancel`.
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        let (work, mut work_peer) = tcp_pair().await;
        let (user, _user_peer) = tcp_pair().await;
        let cancel = tokio_util::sync::CancellationToken::new();

        let req = PendingRequest {
            proxy_name: "t1".to_string(),
            user_conn: IoStream::Tcp(user),
            pre_read: Vec::new(),
            use_encryption: false,
            use_compression: false,
            visitor_use_encryption: false,
            visitor_use_compression: false,
            visitor_v2: false,
            visitor_udp_packet_codec: String::new(),
            created_at: tokio::time::Instant::now(),
            user_conn_permit: None,
            proxy_info: Some(Arc::new(
                crate::control::proxy_ops::unregister_generation_tests::proxy_info(
                    "t1",
                    "tcp",
                    "run-1",
                    Some(24000),
                    1,
                ),
            )),
        };
        let spawn_res = assign_work_to_proxy(
            IoStream::Tcp(work),
            req,
            [0u8; 16],
            state,
            false,
            cancel.clone(),
        )
        .await;
        assert!(spawn_res.is_ok(), "bridge spawn must succeed");

        // Let the bridge reach its blocking copy point on the half-open pair.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Control teardown: cancel the per-control bridge token.
        cancel.cancel();

        // The bridge task must exit, dropping the work conn (and user conn).
        // The work-conn peer observes EOF — but first drains the
        // StartWorkConn frame written on spawn. Without the fix the final
        // read hangs forever and the timeout fires.
        let mut out = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                work_peer.read(&mut chunk),
            )
            .await
            .expect("cancel must terminate the half-open TCP bridge (work conn peer must see EOF)")
            .expect("read from work conn peer must succeed");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        assert!(
            !out.is_empty(),
            "StartWorkConn frame must have been delivered before EOF"
        );
    }

    // ---------------------------------------------------------------------
    // ResponseHeaderInjector unit tests (regressions for #3a / #3b).
    // ---------------------------------------------------------------------

    async fn injector_read_all(
        injector: &mut ResponseHeaderInjector<tokio::io::DuplexStream>,
    ) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        let mut chunk = [0u8; 7];
        loop {
            let n = injector.read(&mut chunk).await.expect("injector read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            // A deliberately small caller buffer exercises the "injected tail
            // must survive a partial serve" path (#3b).
        }
        out
    }

    /// #3a: a response header longer than one internal 4 KiB buffer, whose
    /// `\r\n\r\n` terminator spans two inner reads, must still be injected.
    #[tokio::test]
    async fn injector_headers_hspanning_reads_are_injected() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers);

        // Build a response whose header block is larger than the injector's
        // 4096-byte read buffer, so the boundary lands in the second read.
        let mut big_cookie = String::from("Set-Cookie: a=");
        for _ in 0..900 {
            big_cookie.push('x');
        }
        big_cookie.push_str(";\r\n");
        let response = format!("HTTP/1.1 200 OK\r\n{big_cookie}\r\nbody-data");
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("X-Injected: yes"),
            "injected header must be present, got: {s:?}"
        );
        assert!(s.ends_with("body-data"), "body must survive, got: {s:?}");
        assert!(
            s.starts_with("HTTP/1.1 200 OK\r\n"),
            "leading status line must be preserved"
        );
    }

    /// #3b: the injected buffer is larger than the caller's `ReadBuf`, so the
    /// injected header tail spans multiple polls — none of it may be dropped.
    #[tokio::test]
    async fn injector_injected_tail_not_dropped_across_small_reads() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        for i in 0..20 {
            headers.insert(format!("X-{i}"), String::from("value-value-value-value"));
        }
        let mut injector = ResponseHeaderInjector::new(inner_r, headers);

        let response = "HTTP/1.1 200 OK\r\n\r\nhello-body";
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        for i in 0..20 {
            assert!(
                s.contains(&format!("X-{i}: value-value-value-value\r\n")),
                "injected header {i} missing (tail dropped?): {s:?}"
            );
        }
        assert!(s.ends_with("hello-body"), "body must be intact");
    }

    /// No `\r\n\r\n` and EOF before it: bytes pass through unmodified.
    #[tokio::test]
    async fn injector_non_http_passthrough_on_eof() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers);

        inner_w
            .write_all(b"no-header-terminator-here")
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        assert_eq!(&out, b"no-header-terminator-here");
    }

    /// Audit round 7 (S1 family): a backend response head with bare-LF line
    /// endings is legal under Go textproto.ReadLine semantics (each line
    /// ends at the next `\n`, ONE trailing `\r` is stripped, the head ends
    /// at the first empty line) but contains no `\r\n\r\n` window. The old
    /// strict-CRLF scan never found a boundary: injection was skipped and
    /// the head read on until EOF. RED on the old scan — the fix must
    /// terminate the gather at the LF blank line, emit the configured
    /// header as a REAL header line BEFORE the head/body blank line (bytes
    /// past it are the backend's body and pass verbatim), and keep the
    /// body intact after it.
    #[tokio::test]
    async fn injector_lf_only_head_injects_at_blank_line() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers);

        let response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhello";
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        // Byte-exact pin: head lines verbatim (LF kept), the injected
        // header line CRLF-terminated BEFORE the backend's blank line, the
        // blank line itself and the body verbatim after it.
        let expected = b"HTTP/1.1 200 OK\nContent-Type: text/plain\nX-Injected: yes\r\n\nhello";
        assert_eq!(
            &out[..],
            expected,
            "LF-only head must terminate at the blank line with the header injected"
        );
    }

    #[tokio::test]
    async fn injector_empty_first_line_is_rejected_not_prepended() {
        // Go http.ReadResponse rejects a head with no status line (the head
        // starting with its own blank line) — the old splice prepended the
        // configured headers to the garbage and forwarded it as a plausible
        // 200-ish response (round-3 review finding).
        use tokio::io::AsyncWriteExt;
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));

        for garbage in [
            "\r\nHTTP/1.1 200 OK\r\n\r\nbody",
            "\nHTTP/1.1 200 OK\n\nbody",
        ] {
            let (mut w, r) = tokio::io::duplex(64 * 1024);
            let mut injector = ResponseHeaderInjector::new(r, headers.clone());
            w.write_all(garbage.as_bytes()).await.expect("write");
            w.shutdown().await.expect("shutdown");
            drop(w);
            let mut buf = Vec::new();
            let res = tokio::io::AsyncReadExt::read_to_end(&mut injector, &mut buf).await;
            assert!(
                res.is_err(),
                "an empty first line must error, not forward: {garbage:?}"
            );
        }
    }
}
