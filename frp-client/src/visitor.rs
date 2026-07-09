use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;
use tracing::{info, warn, debug};

use frp_core::transport::{TransportProtocol, DialOptions, dial_server};
use frp_core::msg::{self, FrpMessage};


/// Attempt TCP simultaneous open to `peer_addr`.
///
/// Binds a local port with SO_REUSEADDR (required for simultaneous open),
/// then dials the peer. When both sides do this at roughly the same time,
/// the kernel's TCP stack matches the SYN packets and establishes a P2P
/// connection through most NAT types.
///
/// Returns the connected TcpStream on success, or an error on timeout (5s)
/// or other failures.
pub(crate) async fn tcp_simultaneous_open(peer_addr: &str, timeout_ms: u64) -> Result<TcpStream, String> {
    let peer: SocketAddr = peer_addr
        .parse()
        .map_err(|e| format!("invalid peer address '{}': {}", peer_addr, e))?;

    // Use socket family matching peer address (IPv4 or IPv6)
    let local = if peer.is_ipv4() {
        TcpSocket::new_v4().map_err(|e| format!("TcpSocket::new_v4: {}", e))?
    } else {
        TcpSocket::new_v6().map_err(|e| format!("TcpSocket::new_v6: {}", e))?
    };

    // SO_REUSEADDR is required for TCP simultaneous open:
    // both sides bind to the same port they use to connect.
    local
        .set_reuseaddr(true)
        .map_err(|e| format!("set_reuseaddr: {}", e))?;
    #[cfg(unix)]
    local.set_reuseport(true).ok();

    // Bind to any available port
    let wildcard: &str = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    local
        .bind(wildcard.parse().unwrap())
        .map_err(|e| format!("bind: {}", e))?;

    debug!(peer = %peer, "TCP simultaneous open: bound to local, dialing {}", peer);

    // Dial with configured timeout
    match tokio::time::timeout(Duration::from_millis(timeout_ms), local.connect(peer)).await {
        Ok(Ok(stream)) => {
            debug!(peer = %peer, "TCP simultaneous open to {} succeeded", peer);
            Ok(stream)
        }
        Ok(Err(e)) => {
            debug!(peer = %peer, error = %e, "TCP simultaneous open to {} failed: {}", peer, e);
            Err(format!("connect failed: {}", e))
        }
        Err(_) => {
            debug!(peer = %peer, timeout_ms = %timeout_ms, "TCP simultaneous open to {} timed out after {}ms", peer, timeout_ms);
            Err("hole punch timeout".into())
        }
    }
}

/// Run an STCP/XTCP visitor listener.
/// Binds a local port, accepts connections, and tunnels them
/// through the frps server to the remote STCP proxy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_visitor_listener(
    server_addr: String,
    server_port: u16,
    protocol: TransportProtocol,
    server_name: String,
    secret_key: String,
    bind_addr: String,
    use_encryption: bool,
    use_compression: bool,
    name: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    visitor_type: String,
    fallback_timeout_ms: u64,
    keep_tunnel_open: bool,
    max_retries_an_hour: i32,
    min_retry_interval: i64,
    stun_server: String,
    visitor_tx: mpsc::UnboundedSender<crate::service::VisitorRequest>,
    fallback_to: String,
) {
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(name = %name, bind_addr = %bind_addr, error = %e, "Visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    info!(name = %name, bind_addr = %bind_addr, "Visitor '{}' listening on {}", name, bind_addr);

    loop {
        match listener.accept().await {
            Ok((user_conn, peer)) => {
                debug!(name = %name, peer = %peer, "Visitor '{}': user connection from {}", name, peer);

                let sa = server_addr.clone();
                let sp = server_port;
                let pt = protocol.clone();
                let sn = server_name.clone();
                let sk = secret_key.clone();
                let visitor_name = name.clone();
                let tls_sn = tls_server_name.clone();
                let tls_ca = tls_ca_file.clone();
                let vt = visitor_type.clone();
                let stun_server = stun_server.clone();
                let vtx = visitor_tx.clone();
                let fb_to = fallback_to.clone();

                tokio::spawn(async move {
                    // Dial options for STCP fallback (fresh connections only).
                    let opts = DialOptions {
                        server_addr: sa.clone(),
                        server_port: sp,
                        protocol: pt.clone(),
                        tls_enable,
                        tls_server_name: tls_sn,
                        tls_ca_file: tls_ca,
                        ..Default::default()
                    };

                    if vt == "xtcp" {
                        // --- XTCP NAT hole punch via control connection ---
                        // Go frps v0.69.1 only handles NatHoleVisitor on the existing
                        // control connection path, not on fresh TCP connections.
                        // We send the message through the control loop and receive the
                        // NatHoleResp via a oneshot channel.
                        // When keep_tunnel_open is false, still retry once (2 total attempts).
                        // TCP simultaneous open timing is finicky — a second attempt with fresh
                        // STUN addresses often succeeds even when the first times out.
                        // When keep_tunnel_open is true, use the configured retry count/delay.
                        let max_retries = if keep_tunnel_open {
                            max_retries_an_hour.max(0) as usize
                        } else {
                            1 // 2 total attempts
                        };
                        let retry_delay = if keep_tunnel_open {
                            Duration::from_secs(min_retry_interval.max(1) as u64)
                        } else {
                            Duration::from_secs(2) // Quick retry for one-shot mode
                        };
                        let mut hole_punch_ok = false;
                        // Wrap in Option — P2P success arm moves it out via take().
                        let mut user_conn = Some(user_conn);

                        for attempt in 0..=max_retries {
                            if attempt > 0 {
                                debug!(
                                    visitor_name = %visitor_name, attempt = %attempt, max_retries = %max_retries, retry_delay = ?retry_delay,
                                    "Visitor '{}': XTCP retry {}/{} after {:?}",
                                    visitor_name, attempt, max_retries, retry_delay
                                );
                                tokio::time::sleep(retry_delay).await;
                            }

                            // --- STUN Discovery ---
                            // Run STUN twice — Go frps v0.69.1 NAT classifier needs ≥2
                            // mapped addresses to determine NAT type and behavior.
                            let mut mapped_addrs = Vec::new();
                            for _ in 0..2 {
                                match frp_core::stun::stun_binding(&stun_server).await {
                                    Ok(addr) => {
                                        debug!(visitor_name = %visitor_name, addr = %addr, "Visitor '{}': STUN mapped address: {}", visitor_name, addr);
                                        if !mapped_addrs.contains(&addr) {
                                            mapped_addrs.push(addr);
                                        }
                                    }
                                    Err(e) => {
                                        warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STUN failed: {}", visitor_name, e);
                                    }
                                }
                            }
                            if mapped_addrs.is_empty() {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': all STUN attempts failed", visitor_name);
                            }

                            // --- Send NatHoleVisitor on control connection ---
                            let txn_id = uuid::Uuid::new_v4().to_string();
                            // Generate auth credentials (Go frps v0.69.1 requires sign_key+timestamp)
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64;
                            let sign_key = if sk.is_empty() {
                                None
                            } else {
                                Some(frp_core::auth::generate_token(&sk, ts))
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let nhv = crate::service::VisitorRequest {
                                nhv: msg::NatHoleVisitor {
                                    transaction_id: txn_id.clone(),
                                    proxy_name: sn.clone(),
                                    pre_check: false,
                                    protocol: Some("tcp".to_string()),
                                    sign_key,
                                    timestamp: Some(ts),
                                    mapped_addrs: if mapped_addrs.is_empty() { None } else { Some(mapped_addrs) },
                                    ..Default::default()
                                },
                                reply: reply_tx,
                            };
                            if vtx.send(nhv).is_err() {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': failed to send NatHoleVisitor to control loop (channel closed)", visitor_name);
                                return;
                            }
                            debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NatHoleVisitor on control connection for '{}'", visitor_name, sn);

                            // --- Wait for NatHoleResp from control loop ---
                            // Timeout after 15s (server NAT_HOLE_TIMEOUT is 10s)
                            let resp = match tokio::time::timeout(
                                Duration::from_secs(15),
                                reply_rx,
                            ).await {
                                Ok(Ok(Ok(resp))) => resp,
                                Ok(Ok(Err(e))) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': NatHoleResp error from server: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                                Ok(Err(_)) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': NatHoleResp channel closed (control loop dropped)", visitor_name);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                                Err(_elapsed) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': NatHoleResp timed out after 15s", visitor_name);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            };
                            debug!(visitor_name = %visitor_name, "Visitor '{}': received NatHoleResp from server", visitor_name);

                            let candidates = resp.candidate_addrs.unwrap_or_default();
                            debug!(visitor_name = %visitor_name, candidate_count = %candidates.len(), "Visitor '{}': got {} candidate addresses from server", visitor_name, candidates.len());

                            // TCP simultaneous open to each candidate
                            for addr in &candidates {
                                debug!(visitor_name = %visitor_name, addr = %addr, "Visitor '{}': trying simultaneous open to {}", visitor_name, addr);
                                match tcp_simultaneous_open(addr, fallback_timeout_ms).await {
                                    Ok(p2p_stream) => {
                                        info!(visitor_name = %visitor_name, addr = %addr, "Visitor '{}': XTCP P2P connected to {}", visitor_name, addr);
                                        // Encrypt P2P channel if configured (matches Go frp wrapVisitorConn).
                                        let use_enc = use_encryption && !sk.is_empty();
                                        let (user_r, user_w) = user_conn.take().unwrap().into_split();
                                        let (p2p_r, p2p_w) = p2p_stream.into_split();
                                        if use_enc {
                                            let key = frp_core::encryption::derive_key(&sk);
                                            frp_core::bridge::bridge_encrypted(
                                                user_r, user_w, p2p_r, p2p_w,
                                                &key, use_compression, vec![], None, None, None,
                                            ).await;
                                            debug!(visitor_name = %visitor_name, "Visitor '{}' XTCP encrypted P2P closed", visitor_name);
                                        } else {
                                            frp_core::bridge::bridge_plain(
                                                user_r, user_w, p2p_r, p2p_w,
                                                use_compression, vec![], None,
                                            ).await;
                                            debug!(visitor_name = %visitor_name, "Visitor '{}' XTCP closed", visitor_name);
                                        }
                                        hole_punch_ok = true;
                                        break; // P2P succeeded
                                    }
                                    Err(e) => {
                                        debug!(visitor_name = %visitor_name, addr = %addr, error = %e, "Visitor '{}': hole punch to {} failed: {}", visitor_name, addr, e);
                                    }
                                }
                            }
                            if hole_punch_ok {
                                break; // Exit retry loop
                            }
                        }

                        if hole_punch_ok {
                            return; // XTCP P2P succeeded
                        }

                        // Unwrap user_conn for STCP fallback (hole punch failed, so not moved).
                        let user_conn = user_conn.expect("user_conn not consumed when hole_punch_ok=false");

                        // --- STCP fallback (hole punch failed) ---
                        // STCP relay via NewVisitorConn on a fresh connection works against
                        // Rust frps (which looks up the proxy in proxy_manager regardless of type).
                        // Against Go frps v0.69.1, XTCP proxies do NOT create a custom listener
                        // (only NatHoleController listener), so NewVisitorConn fails with
                        // "custom listener for [X] doesn't exist". This is expected — Go frp's
                        // XTCP fallback uses a separate STCP proxy+visitor, not the same proxy.
                        // Open a NEW connection for STCP relay
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STCP fallback dial failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let stcp_proxy_name = if fb_to.is_empty() { sn.clone() } else { fb_to.clone() };
                        // STCP fallback is always plain relay. Go frp semantics:
                        // `fallbackTo` routes to a SEPARATE STCP visitor with its own
                        // encryption config; the XTCP visitor's use_encryption applies
                        // to the P2P channel ONLY and does not carry into the fallback.
                        // Sending use_encryption=true here would make the server↔provider
                        // work-conn bridge encrypted while this side stays plain → mismatch.
                        let nvc = crate::proxy::create_visitor_conn_msg(&stcp_proxy_name, &sk, false, false);
                        debug!(visitor_name = %visitor_name, json = %serde_json::to_string(&nvc).unwrap_or_default(), "Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STCP fallback send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        info!(visitor_name = %visitor_name, stcp_proxy_name = %stcp_proxy_name, "Visitor '{}': fell back to STCP relay for '{}'", visitor_name, stcp_proxy_name);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!(visitor_name = %visitor_name, error = %err, "Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!(visitor_name = %visitor_name, proxy_name = %resp.proxy_name, "Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!(visitor_name = %visitor_name, type_byte = %other.v1_type_byte(), msg = ?other, "Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let user = user_conn;
                        let (user_r, user_w) = user.into_split();
                        let (srv_r, srv_w) = server_conn.into_split();
                        frp_core::bridge::bridge_plain(
                            user_r, user_w, srv_r, srv_w,
                            false, vec![], None,
                        ).await;
                        debug!(visitor_name = %visitor_name, "Visitor '{}' STCP relay closed", visitor_name);
                    } else {
                        // --- STCP relay path (existing) ---
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': dial server failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!(visitor_name = %visitor_name, json = %serde_json::to_string(&nvc).unwrap_or_default(), "Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!(visitor_name = %visitor_name, error = %err, "Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!(visitor_name = %visitor_name, proxy_name = %resp.proxy_name, "Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!(visitor_name = %visitor_name, type_byte = %other.v1_type_byte(), msg = ?other, "Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let user = user_conn;
                        let (user_r, user_w) = user.into_split();
                        let (srv_r, srv_w) = server_conn.into_split();
                        let use_enc_relay = use_encryption && !sk.is_empty();
                        if use_enc_relay {
                            let key = frp_core::encryption::derive_key(&sk);
                            frp_core::bridge::bridge_encrypted(
                                user_r, user_w, srv_r, srv_w,
                                &key, use_compression, vec![], None, None, None,
                            ).await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP encrypted relay closed", visitor_name);
                        } else {
                            frp_core::bridge::bridge_plain(
                                user_r, user_w, srv_r, srv_w,
                                use_compression, vec![], None,
                            ).await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP relay closed", visitor_name);
                        }
                    }
                });
            }
            Err(e) => {
                warn!(name = %name, error = %e, "Visitor '{}': accept error: {}", name, e);
                break;
            }
        }
    }
}
