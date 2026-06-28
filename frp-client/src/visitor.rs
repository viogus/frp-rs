use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, TcpSocket};
use tokio::time::Duration;
use tracing::{info, warn, debug};

use frp_core::transport::{TransportProtocol, DialOptions, dial_server};
use frp_core::msg::{self, FrpMessage};

use crate::proxy;

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

    debug!("TCP simultaneous open: bound to local, dialing {}", peer);

    // Dial with configured timeout
    match tokio::time::timeout(Duration::from_millis(timeout_ms), local.connect(peer)).await {
        Ok(Ok(stream)) => {
            debug!("TCP simultaneous open to {} succeeded", peer);
            Ok(stream)
        }
        Ok(Err(e)) => {
            debug!("TCP simultaneous open to {} failed: {}", peer, e);
            Err(format!("connect failed: {}", e))
        }
        Err(_) => {
            debug!("TCP simultaneous open to {} timed out after {}ms", peer, timeout_ms);
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
) {
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    info!("Visitor '{}' listening on {}", name, bind_addr);

    loop {
        match listener.accept().await {
            Ok((mut user_conn, peer)) => {
                debug!("Visitor '{}': user connection from {}", name, peer);

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

                tokio::spawn(async move {
                    // Connect to the server
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
                        // --- XTCP NAT hole punch path (Go frp v0.69.1 two-phase compat) ---
                        let max_retries = if keep_tunnel_open { max_retries_an_hour.max(0) as usize } else { 0 };
                        let retry_delay = Duration::from_secs(min_retry_interval.max(1) as u64);
                        let mut hole_punch_ok = false;

                        for attempt in 0..=max_retries {
                            if attempt > 0 {
                                debug!(
                                    "Visitor '{}': XTCP retry {}/{} after {:?}",
                                    visitor_name, attempt, max_retries, retry_delay
                                );
                                tokio::time::sleep(retry_delay).await;
                            }

                            // --- Phase 1: PreCheck ---
                            let mut precheck_conn = match dial_server(&opts).await {
                                Ok(io) => io,
                                Err(e) => {
                                    warn!("Visitor '{}': precheck dial failed: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            };
                            let precheck_txn = uuid::Uuid::new_v4().to_string();
                            let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
                                transaction_id: precheck_txn,
                                proxy_name: sn.clone(),
                                pre_check: true,
                                ..Default::default()
                            });
                            if let Err(e) = precheck_conn.write_v1_frame(&nhv).await {
                                warn!("Visitor '{}': precheck send failed: {}", visitor_name, e);
                                if keep_tunnel_open && attempt < max_retries { continue; }
                                return;
                            }
                            debug!("Visitor '{}': sent NatHoleVisitor pre_check for '{}'", visitor_name, sn);

                            match precheck_conn.read_v1_frame().await {
                                Ok(FrpMessage::NatHoleResp(resp)) => {
                                    if let Some(err) = resp.error {
                                        warn!("Visitor '{}': precheck error: {}", visitor_name, err);
                                        if keep_tunnel_open && attempt < max_retries { continue; }
                                        return;
                                    }
                                    debug!("Visitor '{}': precheck OK", visitor_name);
                                }
                                Ok(other) => {
                                    warn!("Visitor '{}': unexpected precheck response 0x{:02x}", visitor_name, other.v1_type_byte());
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                                Err(e) => {
                                    warn!("Visitor '{}': precheck read failed: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            }
                            drop(precheck_conn);

                            // --- STUN Discovery ---
                            let mapped_addrs = match frp_core::stun::stun_binding(&stun_server.clone()).await {
                                Ok(addr) => {
                                    debug!("Visitor '{}': STUN mapped address: {}", visitor_name, addr);
                                    vec![addr]
                                }
                                Err(e) => {
                                    warn!("Visitor '{}': STUN failed: {}", visitor_name, e);
                                    vec![]
                                }
                            };

                            // --- Phase 2: Full NatHoleVisitor ---
                            let mut full_conn = match dial_server(&opts).await {
                                Ok(io) => io,
                                Err(e) => {
                                    warn!("Visitor '{}': full phase dial failed: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            };
                            let txn_id = uuid::Uuid::new_v4().to_string();
                            let nhv2 = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
                                transaction_id: txn_id,
                                proxy_name: sn.clone(),
                                pre_check: false,
                                protocol: Some("tcp".to_string()),
                                mapped_addrs: if mapped_addrs.is_empty() { None } else { Some(mapped_addrs) },
                                ..Default::default()
                            });
                            if let Err(e) = full_conn.write_v1_frame(&nhv2).await {
                                warn!("Visitor '{}': full NatHoleVisitor send failed: {}", visitor_name, e);
                                if keep_tunnel_open && attempt < max_retries { continue; }
                                return;
                            }
                            debug!("Visitor '{}': sent full NatHoleVisitor for '{}'", visitor_name, sn);

                            // Read NatHoleResp with provider's candidate addresses
                            match full_conn.read_v1_frame().await {
                                Ok(FrpMessage::NatHoleResp(resp)) => {
                                    if let Some(err) = resp.error {
                                        warn!("Visitor '{}': NatHoleResp error: {}", visitor_name, err);
                                        if keep_tunnel_open && attempt < max_retries { continue; }
                                        return;
                                    }
                                    let candidates = resp.candidate_addrs.unwrap_or_default();
                                    debug!("Visitor '{}': got {} candidate addresses from server", visitor_name, candidates.len());

                                    // TCP simultaneous open to each candidate
                                    for addr in &candidates {
                                        debug!("Visitor '{}': trying simultaneous open to {}", visitor_name, addr);
                                        match tcp_simultaneous_open(addr, fallback_timeout_ms).await {
                                            Ok(p2p_stream) => {
                                                info!("Visitor '{}': XTCP P2P connected to {}", visitor_name, addr);
                                                let mut p2p = p2p_stream;
                                                match tokio::io::copy_bidirectional(&mut user_conn, &mut p2p).await {
                                                    Ok((to_p2p, to_user)) => {
                                                        debug!("Visitor '{}' XTCP closed: {}B to P2P, {}B to user",
                                                            visitor_name, to_p2p, to_user);
                                                    }
                                                    Err(e) => {
                                                        debug!("Visitor '{}' XTCP bridge error: {}", visitor_name, e);
                                                    }
                                                }
                                                hole_punch_ok = true;
                                                break; // P2P succeeded
                                            }
                                            Err(e) => {
                                                debug!("Visitor '{}': hole punch to {} failed: {}", visitor_name, addr, e);
                                            }
                                        }
                                    }
                                    if hole_punch_ok {
                                        break; // Exit retry loop
                                    }
                                }
                                Ok(other) => {
                                    warn!("Visitor '{}': unexpected NatHole response 0x{:02x}", visitor_name, other.v1_type_byte());
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                                Err(e) => {
                                    warn!("Visitor '{}': read NatHoleResp failed: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            }
                        }

                        if hole_punch_ok {
                            return; // XTCP P2P succeeded
                        }

                        // --- STCP fallback (hole punch failed) ---
                        // Open a NEW connection for STCP relay
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                debug!("Visitor '{}': STCP fallback dial failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!("Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!("Visitor '{}': STCP fallback send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        info!("Visitor '{}': fell back to STCP relay for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!("Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!("Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!("Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let mut user = user_conn;
                        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                            Ok((to_server, to_user)) => {
                                debug!("Visitor '{}' STCP relay closed: {}B to server, {}B to user",
                                    visitor_name, to_server, to_user);
                            }
                            Err(e) => {
                                debug!("Visitor '{}' STCP relay bridge error: {}", visitor_name, e);
                            }
                        }
                    } else {
                        // --- STCP relay path (existing) ---
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!("Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!("Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        debug!("Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!("Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!("Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!("Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let mut user = user_conn;
                        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                            Ok((to_server, to_user)) => {
                                debug!("Visitor '{}' closed: {}B to server, {}B to user", visitor_name, to_server, to_user);
                            }
                            Err(e) => {
                                debug!("Visitor '{}' bridge error: {}", visitor_name, e);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                warn!("Visitor '{}': accept error: {}", name, e);
                break;
            }
        }
    }
}
