use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use frp_core::metrics::ConnGuard;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1, read_msg_v2, write_msg_v2};
use frp_core::transport::IoStream;

use crate::service::AppState;

use super::PendingRequest;

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
        if self.complete {
            let this = self.as_mut().get_mut();
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        let this = self.as_mut().get_mut();

        // Read from inner into our buffer
        let mut temp_buf = ReadBuf::new(&mut this.read_buf);
        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
            Poll::Ready(Ok(())) => {
                let n = temp_buf.filled().len();
                if n == 0 {
                    this.complete = true;
                    return Poll::Ready(Ok(()));
                }
                // Guard against memory exhaustion from backends that never send \r\n\r\n
                if this.buffer.len() + n > 65536 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response header exceeds 64KB limit",
                    )));
                }
                this.buffer.extend_from_slice(&this.read_buf[..n]);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.buffer.is_empty() {
                    return Poll::Pending;
                }
            }
        }

        // Check for end of HTTP headers
        let header_end = this.buffer.windows(4).position(|w| w == b"\r\n\r\n");
        if let Some(pos) = header_end {
            let mut injected = Vec::with_capacity(this.buffer.len() + 512);
            injected.extend_from_slice(&this.buffer[..pos]);
            for (k, v) in &this.headers {
                injected.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
            }
            injected.extend_from_slice(&this.buffer[pos..]);
            this.buffer = injected;
            this.complete = true;
        }

        // Serve from buffer
        if this.buffer_offset < this.buffer.len() {
            let remaining = this.buffer.len() - this.buffer_offset;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
            this.buffer_offset += to_copy;
        }

        if this.buffer_offset >= this.buffer.len() {
            this.complete = true;
        }

        Poll::Ready(Ok(()))
    }
}

/// Assign a work connection to a UDP proxy for bidirectional data forwarding.
/// Matches Go frp v0.69.1 behavior: sends StartWorkConn, then bridges
/// UDP socket ↔ work connection via UDPPacket messages.
pub(crate) async fn assign_udp_work_conn(
    work_conn: IoStream,
    proxy_name: &str,
    udp_sockets: &std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    local_addr: Option<msg::UdpAddr>,
    v2: bool,
    udp_packet_size: usize,
) {
    let mut work_conn = work_conn;
    let sock = match udp_sockets.get(proxy_name) {
        Some(s) => s.clone(),
        None => {
            warn!(proxy_name = %proxy_name, "UDP socket not found for proxy '{}'", proxy_name);
            return;
        }
    };
    let proxy_name = proxy_name.to_string();

    // Send StartWorkConn to tell the client which proxy to associate
    let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
        proxy_name: proxy_name.clone(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        error: None,
        use_encryption: None,
        use_compression: None,
        nat_hole_sid: None,
        nat_hole_visitor_addr: None,
    });
    if v2 {
        if let Err(e) = work_conn.write_v2_frame(&swc).await {
            warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn (V2) for UDP '{}': {}", proxy_name, e);
            return;
        }
    } else if let Err(e) = work_conn.write_v1_frame(&swc).await {
        warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn for UDP '{}': {}", proxy_name, e);
        return;
    }
    debug!(proxy_name = %proxy_name, "UDP work conn assigned to '{}', starting bridge tasks", proxy_name);

    let (mut w_r, mut w_w) = work_conn.into_split();

    // Task: read UDPPacket from work conn → send to UDP socket
    let sock_w = sock.clone();
    let pn_w = proxy_name.clone();
    tokio::spawn(async move {
        debug!(proxy_name = %pn_w, "UDP work conn reader task started for '{}'", pn_w);
        loop {
            let result = if v2 {
                read_msg_v2(&mut w_r).await
            } else {
                read_msg_v1(&mut w_r).await
            };
            match result {
                Ok(FrpMessage::UDPPacket(up)) => {
                    if let Some(ref remote) = up.remote_addr {
                        let remote_str = remote.to_string();
                        if let Err(e) = sock_w.send_to(&up.content, &remote_str).await {
                            debug!(proxy_name = %pn_w, error = %e, "UDP send_to failed for '{}': {}", pn_w, e);
                        }
                    }
                }
                Ok(FrpMessage::Ping(_)) | Ok(FrpMessage::Pong(_)) => {
                    // Heartbeat on work conn (Go frp compat) — ignore
                    continue;
                }
                Ok(other) => {
                    debug!(proxy_name = %pn_w, msg_type = %other.v1_type_byte(), "UDP work conn for '{}': unexpected msg 0x{:02x}", pn_w, other.v1_type_byte());
                }
                Err(e) => {
                    debug!(proxy_name = %pn_w, error = %e, "UDP work conn for '{}' read closed: {}", pn_w, e);
                    break;
                }
            }
        }
    });

    // Task: read from UDP socket → write UDPPacket to work conn
    let pn_w2 = proxy_name.clone();
    tokio::spawn(async move {
        debug!(proxy_name = %pn_w2, "UDP work conn writer task started for '{}'", pn_w2);
        let mut buf = vec![0u8; udp_packet_size];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    debug!(proxy_name = %pn_w2, bytes = %n, source = %src, "UDP writer '{}' recv'd {} bytes from {}", pn_w2, n, src);
                    let remote = msg::UdpAddr {
                        ip: src.ip().to_string(),
                        port: src.port(),
                        zone: String::new(),
                    };
                    let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                        content: buf[..n].to_vec(),
                        local_addr: local_addr.clone(),
                        remote_addr: Some(remote),
                    });
                    debug!(proxy_name = %pn_w2, "UDP writer '{}' sending UDPPacket to work conn...", pn_w2);
                    let write_result = if v2 {
                        write_msg_v2(&mut w_w, &pkt).await
                    } else {
                        write_msg_v1(&mut w_w, &pkt).await
                    };
                    if let Err(e) = write_result {
                        debug!(proxy_name = %pn_w2, error = %e, "UDP work conn write failed for '{}': {}", pn_w2, e);
                        break;
                    }
                    debug!(bytes = %n, proxy_name = %pn_w2, "UDP work conn wrote {} bytes for '{}'", n, pn_w2);
                }
                Err(e) => {
                    debug!(proxy_name = %pn_w2, error = %e, "UDP recv_from error for '{}': {}", pn_w2, e);
                    break;
                }
            }
        }
        debug!(proxy_name = %pn_w2, "UDP writer '{}' task exiting", pn_w2);
    });
}

/// Relay plain traffic between two IoStreams, preferring zero-copy splice
/// on Linux when both sides are raw TCP.
async fn relay_plain_fast(
    mut user_conn: IoStream,
    mut work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    use std::sync::atomic::Ordering;

    // On Linux, try zero-copy splice for Tcp-to-Tcp.
    // Check with references first to avoid consuming streams on mismatch.
    #[cfg(target_os = "linux")]
    if let (IoStream::Tcp(_), IoStream::Tcp(_)) = (&user_conn, &work_conn) {
        let (IoStream::Tcp(user), IoStream::Tcp(work)) = (user_conn, work_conn) else {
            unreachable!()
        };
        match frp_core::bridge::bridge_plain_zero_copy(user, work).await {
            Ok((a, b)) => {
                metrics.bytes_in.fetch_add(a, Ordering::Relaxed);
                metrics.bytes_out.fetch_add(b, Ordering::Relaxed);
                return;
            }
            Err(e) => {
                tracing::debug!(error = %e, "zero-copy bridge failed: {}", e);
                return;
            }
        }
    }

    // Fallback: standard copy_bidirectional.
    match tokio::io::copy_bidirectional(&mut user_conn, &mut work_conn).await {
        Ok((a, b)) => {
            metrics.bytes_in.fetch_add(a, Ordering::Relaxed);
            metrics.bytes_out.fetch_add(b, Ordering::Relaxed);
        }
        Err(e) => {
            tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
        }
    }
}

pub(crate) async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
    state: Arc<AppState>,
    v2: bool,
) {
    // Extract peer address from user connection for PROXY protocol support
    let (src_addr, src_port) = match &req.user_conn {
        IoStream::Tcp(s) => {
            s.peer_addr().map(|a| (a.ip().to_string(), a.port() as i32)).ok()
        }
        _ => None,
    }.map_or((String::new(), 0), |(ip, port)| (ip, port));

    // Look up proxy info for dst address and proxy protocol version
    let proxy_info = state.proxy_manager.get(&req.proxy_name).await;
    let proxy_protocol_version = proxy_info.as_ref()
        .map(|p| p.proxy_protocol_version.clone()).unwrap_or_default();
    let dst_addr = proxy_info.as_ref()
        .and_then(|p| p.local_addr.clone()).unwrap_or_default();
    let dst_port = proxy_info.as_ref()
        .and_then(|p| p.remote_port).map(|p| p as i32).unwrap_or(0);

    let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        src_addr: if !proxy_protocol_version.is_empty() && !src_addr.is_empty() { Some(src_addr) } else { None },
        src_port: if !proxy_protocol_version.is_empty() && src_port != 0 { Some(src_port) } else { None },
        dst_addr: if !proxy_protocol_version.is_empty() && !dst_addr.is_empty() { Some(dst_addr) } else { None },
        dst_port: if !proxy_protocol_version.is_empty() && dst_port != 0 { Some(dst_port) } else { None },
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
        use_compression: if req.use_compression { Some(true) } else { None },
        // For XTCP STCP fallback: set empty nat_hole_sid marker so Rust frpc
        // knows this work conn is for STCP bridging, not XTCP notification.
        nat_hole_sid: if req.proxy_type == "xtcp" { Some(String::new()) } else { None },
        nat_hole_visitor_addr: None,
    });

    let write_result = if v2 {
        work_conn.write_v2_frame(&swc).await
    } else {
        work_conn.write_v1_frame(&swc).await
    };

    if let Err(e) = write_result {
        warn!(error = %e, "Failed to send StartWorkConn: {}", e);
        return;
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
    // The copy_bidirectional bridge (used for XTCP STCP fallback below)
    // doesn't send a premature FIN, so the provider can safely consume
    // this frame without the old ECONNRESET race.
    // V2-aware: use V2 or V1 framing based on protocol version.
    if req.proxy_type == "xtcp" {
        let dummy = FrpMessage::NatHoleSid(msg::NatHoleSid {
            sid: None,
            provider_addr: None,
        });
        if v2 {
            let _ = work_conn.write_v2_frame(&dummy).await;
        } else {
            let _ = work_conn.write_v1_frame(&dummy).await;
        }
    }

    debug!(proxy_name = %req.proxy_name, proxy_type = %req.proxy_type, "Bridging user conn to work conn for proxy '{}' (type={})", req.proxy_name, req.proxy_type);

    let proxy_name = req.proxy_name.clone();
    let metrics = state.proxy_metrics.get_or_create(&proxy_name).await;
    let guard = ConnGuard::new(metrics.clone());
    let drain_guard = ActiveGuard::new(&state);

    let pre_read = req.pre_read;
    let enc_key = req.use_encryption;
    let comp_key = req.use_compression;
    let proxy_type = req.proxy_type.clone();

    tokio::spawn(async move {
        let _guard = guard;
        let _drain = drain_guard;
        // Use encryption if the proxy config requests it (req.use_encryption
        // comes from proxy_manager). For XTCP STCP fallback, we previously
        // forced plain bridge to avoid a dual-CipherWriter deadlock — that
        // deadlock is now fixed by eager IV flush in CipherWriter::poll_flush.
        // Go frpc v0.69.1 ignores swc.use_encryption (not in its struct) and
        // uses its own proxy config, so the server MUST match.
        let use_enc = enc_key;
        // For encrypted bridges, pre_read bytes are passed into bridge_encrypted
        // which writes them through the CipherWriter (matching Go frp streaming CFB).
        if use_enc {
            let key = encryption_key;
            match work_conn {
                IoStream::Tcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                #[cfg(feature = "tls")]
                IoStream::Tls(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                #[cfg(feature = "kcp")]
                IoStream::Kcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                #[cfg(feature = "websocket")]
                IoStream::WebSocket(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                #[cfg(feature = "quic")]
                IoStream::Quic(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = work.into_split();
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                IoStream::Yamux(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                IoStream::Cipher(_) => {
                    warn!("Cipher stream unexpected in server bridge");
                    return;
                }
                IoStream::Aead(_) => {
                    warn!("Aead stream unexpected in server bridge");
                    return;
                }
                IoStream::SshChannel(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                IoStream::PreRead(_, work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                IoStream::BufferedRead(_, _, inner) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = inner.into_split();
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
            }
        } else {
            // Pass VHost pre-read bytes through bridge_plain so the bridge
            // can coordinate: write pre_read first, then skip work_w shutdown
            // to let the backend response flow back to the user.
            let bridge_pre_read = pre_read;

            // XTCP STCP fallback (plain, no encryption): use copy_bidirectional
            // directly instead of bridge_plain. bridge_plain's join! pattern
            // drops the work writer (sending FIN) as soon as the user reader
            // reaches EOF. For STCP fallback the visitor's test client
            // half-closes after sending data, so the server sees EOF on the
            // user side ~60ms before the provider starts its bridge. The
            // premature FIN on the work connection races with the provider's
            // copy_bidirectional startup and produces ECONNRESET on VPS.
            // copy_bidirectional avoids this: both directions run to completion
            // within the same function, and the work side is only shut down
            // after the full bidirectional copy finishes.
            if proxy_type == "xtcp" {
                let mut user_conn = req.user_conn;
                match tokio::io::copy_bidirectional(&mut user_conn, &mut work_conn).await {
                    Ok((a, b)) => {
                        metrics.bytes_in.fetch_add(a, Ordering::Relaxed);
                        metrics.bytes_out.fetch_add(b, Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!(error = %e, "XTCP STCP fallback bridge closed: {}", e);
                    }
                }
            } else if !comp_key
                && bridge_pre_read.is_empty()
                && req.response_headers.is_empty()
            {
                // Fast path: pure plain relay with no compression, no VHost
                // pre-read, and no header injection. On Linux, try zero-copy
                // splice for Tcp-to-Tcp; otherwise use copy_bidirectional.
                relay_plain_fast(req.user_conn, work_conn, &metrics).await;
            } else {
                // Slow path: compression, VHost pre-read, or header injection.
                let (u_r, u_w) = req.user_conn.into_split();
                let (w_r, w_w) = work_conn.into_split();
                if !req.response_headers.is_empty() && req.proxy_type.starts_with("http") {
                    let injector = ResponseHeaderInjector::new(w_r, req.response_headers);
                    frp_core::bridge::bridge_plain(u_r, u_w, injector, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
                } else {
                    frp_core::bridge::bridge_plain(u_r, u_w, w_r, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
                }
            }
        }
        debug!(proxy_name = %req.proxy_name, "Proxy '{}' bridge completed", req.proxy_name);
    });
}
