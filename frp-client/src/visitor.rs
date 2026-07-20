use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;
use tracing::{debug, info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::transport::{dial_server, DialOptions, TransportProtocol};

/// Configuration for an STCP/XTCP visitor listener.
pub(crate) struct VisitorListenerConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: TransportProtocol,
    pub server_name: String,
    pub secret_key: String,
    pub bind_addr: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub name: String,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub visitor_type: String,
    pub fallback_timeout_ms: u64,
    pub keep_tunnel_open: bool,
    pub max_retries_an_hour: i32,
    pub min_retry_interval: i64,
    pub stun_server: String,
    pub visitor_tx: mpsc::Sender<crate::service::VisitorRequest>,
    pub fallback_to: String,
    pub disable_assisted_addrs: bool,
}
/// Run an STCP/XTCP visitor listener.
/// Binds a local port, accepts connections, and tunnels them
/// through the frps server to the remote STCP proxy.
pub(crate) async fn run_visitor_listener(config: VisitorListenerConfig) {
    let VisitorListenerConfig {
        server_addr,
        server_port,
        protocol,
        server_name,
        secret_key,
        bind_addr,
        use_encryption,
        use_compression,
        name,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        visitor_type,
        fallback_timeout_ms,
        keep_tunnel_open,
        max_retries_an_hour,
        min_retry_interval,
        stun_server,
        visitor_tx,
        fallback_to,
        disable_assisted_addrs,
    } = config;
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
                frp_core::transport::set_nodelay(&user_conn);
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
                let daa = disable_assisted_addrs;

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

                        // --- PreCheck: validate proxy existence/permissions before STUN ---
                        // Go frp two-phase approach: first send pre_check=true to validate
                        // auth/permissions, THEN do STUN + full request. Skipping this
                        // wastes STUN calls on auth/proxy-not-found failures.
                        {
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64;
                            let sign_key = if sk.is_empty() {
                                None
                            } else {
                                Some(frp_core::auth::generate_token(&sk, ts))
                            };
                            let pre_check_req = crate::service::VisitorRequest {
                                nhv: msg::NatHoleVisitor {
                                    transaction_id: uuid::Uuid::new_v4().to_string(),
                                    proxy_name: sn.clone(),
                                    pre_check: true,
                                    protocol: Some("kcp".to_string()),
                                    sign_key,
                                    timestamp: Some(ts),
                                    mapped_addrs: None,
                                    assisted_addrs: None,
                                },
                                reply: reply_tx,
                            };
                            if vtx.try_send(pre_check_req).is_err() {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': failed to send pre_check to control loop (channel closed)", visitor_name);
                                return;
                            }
                            debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NatHoleVisitor pre_check for '{}'", visitor_name, sn);

                            match tokio::time::timeout(Duration::from_secs(15), reply_rx).await {
                                Ok(Ok(Ok(resp))) => {
                                    if let Some(err) = resp.error {
                                        warn!(visitor_name = %visitor_name, error = %err, "Visitor '{}': pre_check failed: {}", visitor_name, err);
                                        return;
                                    }
                                    debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': pre_check OK for '{}'", visitor_name, sn);
                                }
                                Ok(Ok(Err(e))) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': pre_check error: {}", visitor_name, e);
                                    return;
                                }
                                Ok(Err(_)) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': pre_check channel closed (control loop dropped)", visitor_name);
                                    return;
                                }
                                Err(_elapsed) => {
                                    // Timeout on pre_check: server may not support
                                    // pre_check on control channel. Proceed with full
                                    // request anyway (graceful degradation).
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': pre_check timed out after 15s, proceeding with full request", visitor_name);
                                }
                            }
                        }

                        for attempt in 0..=max_retries {
                            if attempt > 0 {
                                debug!(
                                    visitor_name = %visitor_name, attempt = %attempt, max_retries = %max_retries, retry_delay = ?retry_delay,
                                    "Visitor '{}': XTCP retry {}/{} after {:?}",
                                    visitor_name, attempt, max_retries, retry_delay
                                );
                                tokio::time::sleep(retry_delay).await;
                            }

                            // --- STUN Discovery (UDP socket for XTCP P2P) ---
                            // Go frps v0.69.1 NAT classifier needs ≥2 mapped
                            // addresses. Reuse the same UDP socket for both
                            // STUN calls and subsequent KCP data plane.
                            let (stun_socket, mapped_addrs) =
                                match frp_core::stun::stun_binding_with_socket(&stun_server).await {
                                    Ok((sock, addr1)) => {
                                        debug!(visitor_name = %visitor_name, addr = %addr1, "Visitor '{}': STUN #1: {}", visitor_name, addr1);
                                        let mut addrs = vec![addr1];
                                        match frp_core::stun::stun_binding_on_socket(
                                            &sock,
                                            &stun_server,
                                        )
                                        .await
                                        {
                                            Ok(addr2) => {
                                                debug!(visitor_name = %visitor_name, addr = %addr2, "Visitor '{}': STUN #2: {}", visitor_name, addr2);
                                                if !addrs.contains(&addr2) {
                                                    addrs.push(addr2);
                                                }
                                            }
                                            Err(e) => {
                                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STUN #2 failed: {}", visitor_name, e);
                                            }
                                        }
                                        (Some(sock), addrs)
                                    }
                                    Err(e) => {
                                        warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STUN failed: {}", visitor_name, e);
                                        (None, vec![])
                                    }
                                };

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
                            // Go v0.70 compat: XTCP P2P uses KCP over UDP.
                            let nhv = crate::service::VisitorRequest {
                                nhv: msg::NatHoleVisitor {
                                    transaction_id: txn_id.clone(),
                                    proxy_name: sn.clone(),
                                    pre_check: false,
                                    protocol: Some("kcp".to_string()),
                                    sign_key,
                                    timestamp: Some(ts),
                                    mapped_addrs: if mapped_addrs.is_empty() {
                                        None
                                    } else {
                                        Some(mapped_addrs.clone())
                                    },
                                    assisted_addrs: if daa || mapped_addrs.is_empty() {
                                        None
                                    } else {
                                        Some(mapped_addrs)
                                    },
                                },
                                reply: reply_tx,
                            };
                            if vtx.try_send(nhv).is_err() {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': failed to send NatHoleVisitor to control loop (channel closed)", visitor_name);
                                return;
                            }
                            debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NatHoleVisitor on control connection for '{}'", visitor_name, sn);

                            // --- Wait for NatHoleResp from control loop ---
                            // Timeout after 15s (server NAT_HOLE_TIMEOUT is 10s)
                            let resp = match tokio::time::timeout(Duration::from_secs(15), reply_rx)
                                .await
                            {
                                Ok(Ok(Ok(resp))) => resp,
                                Ok(Ok(Err(e))) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': NatHoleResp error from server: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries {
                                        continue;
                                    }
                                    return;
                                }
                                Ok(Err(_)) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': NatHoleResp channel closed (control loop dropped)", visitor_name);
                                    if keep_tunnel_open && attempt < max_retries {
                                        continue;
                                    }
                                    return;
                                }
                                Err(_elapsed) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': NatHoleResp timed out after 15s", visitor_name);
                                    if keep_tunnel_open && attempt < max_retries {
                                        continue;
                                    }
                                    return;
                                }
                            };
                            debug!(visitor_name = %visitor_name, "Visitor '{}': received NatHoleResp from server", visitor_name);

                            let candidates = resp.candidate_addrs.unwrap_or_default();
                            debug!(visitor_name = %visitor_name, candidate_count = %candidates.len(), "Visitor '{}': got {} candidate addresses from server", visitor_name, candidates.len());

                            // UDP hole punch + KCP data plane (Go v0.70 compat).
                            // Uses the STUN socket to punch a hole and create
                            // a KCP stream over UDP.
                            if let Some(socket) = stun_socket {
                                // Derive shared KCP conv from the NAT session ID
                                // (both sides get the same sid from the server).
                                let sid = resp.sid.clone().unwrap_or_default();
                                let conv = frp_core::xtcp_p2p::conv_from_sid(&sid);
                                #[allow(clippy::default_constructed_unit_structs)]
                                let kcp_cfg = frp_core::kcp::KcpConfig::default();
                                // Go v0.70 compat: NatHoleSid detect + yamux client.
                                let p2p_key = if !sk.is_empty() {
                                    Some(frp_core::xtcp_p2p::derive_detect_key(&sk))
                                } else {
                                    None
                                };
                                let p2p_sid = if sid.is_empty() {
                                    None
                                } else {
                                    Some(sid.as_str())
                                };
                                match frp_core::xtcp_p2p::xtcp_p2p_connect_yamux(
                                    socket,
                                    &candidates,
                                    conv,
                                    kcp_cfg,
                                    fallback_timeout_ms,
                                    true, // yamux_client = visitor
                                    p2p_sid,
                                    p2p_key.as_ref(),
                                )
                                .await
                                {
                                    Ok(mut p2p_stream) => {
                                        info!(visitor_name = %visitor_name, "Visitor '{}': XTCP P2P connected via KCP", visitor_name);
                                        let use_enc = use_encryption && !sk.is_empty();
                                        let (user_r, user_w) =
                                            user_conn.take().unwrap().into_split();
                                        let (p2p_r, p2p_w) = tokio::io::split(&mut p2p_stream);
                                        if use_enc {
                                            let key = frp_core::encryption::derive_key(&sk);
                                            frp_core::bridge::bridge_encrypted(
                                                user_r,
                                                user_w,
                                                p2p_r,
                                                p2p_w,
                                                &key,
                                                use_compression,
                                                vec![],
                                                None,
                                                None,
                                                None,
                                            )
                                            .await;
                                            debug!(visitor_name = %visitor_name, "Visitor '{}' XTCP encrypted P2P closed", visitor_name);
                                        } else {
                                            frp_core::bridge::bridge_plain(
                                                user_r,
                                                user_w,
                                                p2p_r,
                                                p2p_w,
                                                use_compression,
                                                vec![],
                                                None,
                                            )
                                            .await;
                                            debug!(visitor_name = %visitor_name, "Visitor '{}' XTCP closed", visitor_name);
                                        }
                                        hole_punch_ok = true;
                                    }
                                    Err(e) => {
                                        debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': UDP+KCP hole punch failed: {}", visitor_name, e);
                                    }
                                }
                            } else {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': no STUN socket for XTCP P2P", visitor_name);
                            }
                            if hole_punch_ok {
                                break; // Exit retry loop
                            }
                        }

                        if hole_punch_ok {
                            return; // XTCP P2P succeeded
                        }

                        // Unwrap user_conn for STCP fallback (hole punch failed, so not moved).
                        let user_conn =
                            user_conn.expect("user_conn not consumed when hole_punch_ok=false");

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

                        let stcp_proxy_name = if fb_to.is_empty() {
                            sn.clone()
                        } else {
                            fb_to.clone()
                        };
                        // STCP fallback is always plain relay. Go frp semantics:
                        // `fallbackTo` routes to a SEPARATE STCP visitor with its own
                        // encryption config; the XTCP visitor's use_encryption applies
                        // to the P2P channel ONLY and does not carry into the fallback.
                        // Sending use_encryption=true here would make the server↔provider
                        // work-conn bridge encrypted while this side stays plain → mismatch.
                        let nvc = crate::proxy::create_visitor_conn_msg(
                            &stcp_proxy_name,
                            &sk,
                            false,
                            false,
                        );
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
                        let (srv_r, srv_w) = server_conn.into_split().unwrap();
                        frp_core::bridge::bridge_plain(
                            user_r,
                            user_w,
                            srv_r,
                            srv_w,
                            false,
                            vec![],
                            None,
                        )
                        .await;
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

                        let nvc = crate::proxy::create_visitor_conn_msg(
                            &sn,
                            &sk,
                            use_encryption,
                            use_compression,
                        );
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
                        let (srv_r, srv_w) = server_conn.into_split().unwrap();
                        let use_enc_relay = use_encryption && !sk.is_empty();
                        if use_enc_relay {
                            let key = frp_core::encryption::derive_key(&sk);
                            frp_core::bridge::bridge_encrypted(
                                user_r,
                                user_w,
                                srv_r,
                                srv_w,
                                &key,
                                use_compression,
                                vec![],
                                None,
                                None,
                                None,
                            )
                            .await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP encrypted relay closed", visitor_name);
                        } else {
                            frp_core::bridge::bridge_plain(
                                user_r,
                                user_w,
                                srv_r,
                                srv_w,
                                use_compression,
                                vec![],
                                None,
                            )
                            .await;
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
