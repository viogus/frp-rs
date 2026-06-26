use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use crate::service::{AppState, InternalMsg};

use super::{PENDING_REQUEST_TIMEOUT, PendingRequest};

/// Assign a work connection to a pending proxy request.
/// Assign a work connection to a UDP proxy for bidirectional data forwarding.
/// Matches Go frp v0.69.1 behavior: sends StartWorkConn, then bridges
/// UDP socket ↔ work connection via UDPPacket messages.
pub(crate) async fn assign_udp_work_conn(
    work_conn: IoStream,
    proxy_name: &str,
    udp_sockets: &std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    local_addr: Option<msg::UdpAddr>,
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
    if let Err(e) = write_msg_v1(&mut work_conn, &swc).await {
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
            match read_msg_v1(&mut w_r).await {
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
        let mut buf = vec![0u8; 65535];
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
                    if let Err(e) = write_msg_v1(&mut w_w, &pkt).await {
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
) {
    let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        src_addr: None,
        src_port: None,
        dst_addr: None,
        dst_port: None,
        error: None,
    });

    let write_result = match &mut work_conn {
        IoStream::Tcp(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Tls(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::WebSocket(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Yamux(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Kcp(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Quic(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Cipher(_) => {
            warn!("Cipher stream unexpected in server StartWorkConn write");
            return;
        }
    };

    if let Err(e) = write_result {
        warn!("Failed to send StartWorkConn: {}", e);
        return;
    }

    info!("Bridging user conn to work conn for proxy '{}'", req.proxy_name);

    let pre_read = req.pre_read;
    let enc_key = req.use_encryption;
    let comp_key = req.use_compression;

    tokio::spawn(async move {
        // For encrypted bridges, pre_read bytes are passed into bridge_encrypted
        // which writes them through the CipherWriter (matching Go frp streaming CFB).
        if enc_key {
            let key = encryption_key;
            match work_conn {
                IoStream::Tcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None).await;
                }
                IoStream::Tls(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None).await;
                }
                IoStream::Kcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None).await;
                }
                IoStream::WebSocket(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None).await;
                }
                IoStream::Quic(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = work.into_split();
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None).await;
                }
                IoStream::Yamux(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, pre_read, None, None).await;
                }
                IoStream::Cipher(_) => {
                    warn!("Cipher stream unexpected in server bridge");
                    return;
                }
            }
        } else {
            // Write VHost pre-read bytes to work connection first (plain).
            if !pre_read.is_empty() {
                let write_result = match &mut work_conn {
                    IoStream::Tcp(ref mut s) => s.write_all(&pre_read).await,
                    IoStream::Tls(ref mut s) => s.write_all(&pre_read).await,
                    IoStream::WebSocket(ref mut s) => s.write_all(&pre_read).await,
                    IoStream::Yamux(ref mut s) => s.write_all(&pre_read).await,
                    IoStream::Kcp(ref mut s) => s.write_all(&pre_read).await,
                    IoStream::Quic(ref mut s) => s.write_all(&pre_read).await,
                    _ => Ok(()),
                };
                if let Err(e) = write_result {
                    warn!("Failed to write VHost pre-read bytes: {}", e);
                    return;
                }
            }
            // Plain bridge with optional compression.
            let (u_r, u_w) = req.user_conn.into_split();
            let (w_r, w_w) = work_conn.into_split();
            frp_core::bridge::bridge_plain(u_r, u_w, w_r, w_w, comp_key, pre_read).await;
        }
        info!("Proxy '{}' bridge completed", req.proxy_name);
    });
}
