use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tracing::{debug, info, warn};

use frp_core::metrics::ConnGuard;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1, read_msg_v2, write_msg_v2};
use frp_core::transport::IoStream;

use crate::service::AppState;

use super::PendingRequest;

/// Wraps an AsyncRead, buffering HTTP response headers on first read
/// and injecting configured headers before passing through.
struct ResponseHeaderInjector<R> {
    inner: R,
    headers: std::collections::HashMap<String, String>,
    buffer: Vec<u8>,
    buffer_offset: usize,
    complete: bool,
}

impl<R: AsyncRead + Unpin> ResponseHeaderInjector<R> {
    fn new(inner: R, headers: std::collections::HashMap<String, String>) -> Self {
        Self {
            inner,
            headers,
            buffer: Vec::new(),
            buffer_offset: 0,
            complete: false,
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
            let this = unsafe { self.as_mut().get_unchecked_mut() };
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        let this = unsafe { self.as_mut().get_unchecked_mut() };

        // Read from inner into our buffer
        let mut temp = vec![0u8; 4096];
        let mut temp_buf = ReadBuf::new(&mut temp);
        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
            Poll::Ready(Ok(())) => {
                let n = temp_buf.filled().len();
                if n == 0 {
                    this.complete = true;
                    return Poll::Ready(Ok(()));
                }
                this.buffer.extend_from_slice(&temp[..n]);
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
            warn!("UDP socket not found for proxy '{}'", proxy_name);
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
    });
    if v2 {
        if let Err(e) = work_conn.write_v2_frame(&swc).await {
            warn!("Failed to send StartWorkConn (V2) for UDP '{}': {}", proxy_name, e);
            return;
        }
    } else if let Err(e) = work_conn.write_v1_frame(&swc).await {
        warn!("Failed to send StartWorkConn for UDP '{}': {}", proxy_name, e);
        return;
    }
    debug!("UDP work conn assigned to '{}', starting bridge tasks", proxy_name);

    let (mut w_r, mut w_w) = work_conn.into_split();

    // Task: read UDPPacket from work conn → send to UDP socket
    let sock_w = sock.clone();
    let pn_w = proxy_name.clone();
    tokio::spawn(async move {
        debug!("UDP work conn reader task started for '{}'", pn_w);
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
                            debug!("UDP send_to failed for '{}': {}", pn_w, e);
                        }
                    }
                }
                Ok(FrpMessage::Ping(_)) | Ok(FrpMessage::Pong(_)) => {
                    // Heartbeat on work conn (Go frp compat) — ignore
                    continue;
                }
                Ok(other) => {
                    debug!("UDP work conn for '{}': unexpected msg 0x{:02x}", pn_w, other.v1_type_byte());
                }
                Err(e) => {
                    debug!("UDP work conn for '{}' read closed: {}", pn_w, e);
                    break;
                }
            }
        }
    });

    // Task: read from UDP socket → write UDPPacket to work conn
    let pn_w2 = proxy_name.clone();
    tokio::spawn(async move {
        debug!("UDP work conn writer task started for '{}'", pn_w2);
        let mut buf = vec![0u8; udp_packet_size];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    debug!("UDP writer '{}' recv'd {} bytes from {}", pn_w2, n, src);
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
                    debug!("UDP writer '{}' sending UDPPacket to work conn...", pn_w2);
                    let write_result = if v2 {
                        write_msg_v2(&mut w_w, &pkt).await
                    } else {
                        write_msg_v1(&mut w_w, &pkt).await
                    };
                    if let Err(e) = write_result {
                        debug!("UDP work conn write failed for '{}': {}", pn_w2, e);
                        break;
                    }
                    debug!("UDP work conn wrote {} bytes for '{}'", n, pn_w2);
                }
                Err(e) => {
                    debug!("UDP recv_from error for '{}': {}", pn_w2, e);
                    break;
                }
            }
        }
        debug!("UDP writer '{}' task exiting", pn_w2);
    });
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
    });

    let write_result = if v2 {
        work_conn.write_v2_frame(&swc).await
    } else {
        work_conn.write_v1_frame(&swc).await
    };

    if let Err(e) = write_result {
        warn!("Failed to send StartWorkConn: {}", e);
        return;
    }

    info!("Bridging user conn to work conn for proxy '{}'", req.proxy_name);

    let proxy_name = req.proxy_name.clone();
    let metrics = state.proxy_metrics.get_or_create(&proxy_name).await;
    let guard = ConnGuard::new(metrics.clone());

    let pre_read = req.pre_read;
    let enc_key = req.use_encryption;
    let comp_key = req.use_compression;

    tokio::spawn(async move {
        let _guard = guard;
        // For encrypted bridges, pre_read bytes are passed into bridge_encrypted
        // which writes them through the CipherWriter (matching Go frp streaming CFB).
        if enc_key {
            let key = encryption_key;
            match work_conn {
                IoStream::Tcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
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
                #[cfg(not(feature = "kcp"))]
                IoStream::Kcp(_work) => {
                    warn!("KCP work bridge but kcp feature disabled");
                }
                #[cfg(feature = "websocket")]
                IoStream::WebSocket(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                #[cfg(not(feature = "websocket"))]
                IoStream::WebSocket(_work) => {
                    warn!("WebSocket work bridge but websocket feature disabled");
                }
                #[cfg(feature = "quic")]
                IoStream::Quic(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = work.into_split();
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None, Some(metrics.clone())).await;
                }
                #[cfg(not(feature = "quic"))]
                IoStream::Quic(_work) => {
                    warn!("QUIC work bridge but quic feature disabled");
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
            // Plain bridge with optional compression.
            let (u_r, u_w) = req.user_conn.into_split();
            let (w_r, w_w) = work_conn.into_split();
            if !req.response_headers.is_empty() && req.proxy_type.starts_with("http") {
                let injector = ResponseHeaderInjector::new(w_r, req.response_headers);
                frp_core::bridge::bridge_plain(u_r, u_w, injector, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
            } else {
                frp_core::bridge::bridge_plain(u_r, u_w, w_r, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
            }
        }
        info!("Proxy '{}' bridge completed", req.proxy_name);
    });
}
