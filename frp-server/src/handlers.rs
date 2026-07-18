use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::{debug, info, instrument, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg;
use frp_core::transport::IoStream;

use crate::control;
use crate::lock::RwLockExt;
use crate::nathole::controller as nathole_ctrl;
use crate::nathole::{classify, NAT_HOLE_TIMEOUT};
use crate::state::{AppState, InternalMsg};

// ---------------------------------------------------------------
// STCP visitor connection handler
// ---------------------------------------------------------------

/// Handle an incoming STCP NewVisitorConn on the main accept port.
///
/// Supports two auth modes:
/// 1. Go-compatible: sign_key = MD5(proxy.sk + timestamp), lookup by proxy_name
///    then validate the hash against the registered sk.
/// 2. Legacy Rust: sign_key = raw sk value, looked up directly in sk_index.
pub(crate) async fn handle_visitor_conn_inner(
    mut stream: IoStream,
    msg: msg::NewVisitorConn,
    state: Arc<AppState>,
    v2: bool,
) {
    let sign_key = msg.sign_key.unwrap_or_default();
    let timestamp = msg.timestamp.unwrap_or(0);

    // Validate timestamp freshness to prevent replay attacks.
    // Uses the same authentication_timeout as control-channel Login
    // (Go frp compat: authentication_timeout config).
    let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
    let ts_valid = frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout);

    // --- Mode 1: Go-compatible — lookup by proxy_name, validate MD5(sk + timestamp) ---
    // Look up proxy BEFORE rejecting empty sign_key: a proxy with no sk
    // allows unauthenticated access (Rust↔Rust STCP with useEncryption=false).
    let proxy_name = if let Some(proxy_info) = state.proxy_manager.get(&msg.proxy_name).await {
        if let Some(ref sk) = proxy_info.sk {
            if !sk.is_empty() {
                if sign_key.is_empty() {
                    warn!(proxy_name = %msg.proxy_name, "STCP visitor: missing sign_key for protected proxy '{}'", msg.proxy_name);
                    None
                } else if let Err(e) = &ts_valid {
                    warn!(proxy_name = %msg.proxy_name, error = %e, "STCP visitor: timestamp rejected for proxy '{}'", msg.proxy_name);
                    None
                } else if frp_core::auth::verify_token(sk, timestamp, &sign_key) {
                    debug!(proxy_name = %msg.proxy_name, "STCP visitor auth OK (Go-compat MD5, constant-time) for proxy '{}'", msg.proxy_name);
                    Some(msg.proxy_name.clone())
                } else {
                    warn!(proxy_name = %msg.proxy_name, "STCP visitor MD5 auth mismatch for proxy '{}'", msg.proxy_name);
                    None
                }
            } else {
                // Proxy has no sk — no auth required (allow)
                debug!(proxy_name = %msg.proxy_name, "STCP visitor: proxy '{}' has no sk, allowing", msg.proxy_name);
                Some(msg.proxy_name.clone())
            }
        } else {
            // Proxy has no sk — no auth required (allow)
            debug!(proxy_name = %msg.proxy_name, "STCP visitor: proxy '{}' has no sk, allowing", msg.proxy_name);
            Some(msg.proxy_name.clone())
        }
    } else {
        None
    };

    // --- Mode 2: Legacy Rust — raw sk_index lookup (backward compat) ---
    let proxy_name = match proxy_name {
        Some(pn) => pn,
        None => {
            // Fall back to raw sk lookup for old Rust clients that send raw sk as sign_key.
            // Look up by msg.proxy_name directly — do NOT iterate the whole map:
            // multiple proxies sharing the same sk would route to the wrong one.
            let sk_map = state.xtcp.sk_index.read().await;
            let pn = match sk_map.get(&msg.proxy_name) {
                Some(stored_sk) if *stored_sk == sign_key => {
                    debug!(proxy_name = %msg.proxy_name, "STCP visitor auth OK (raw sk_index lookup) for proxy '{}'", msg.proxy_name);
                    Some(msg.proxy_name.clone())
                }
                _ => None,
            };
            match pn {
                Some(pn) => pn,
                None => {
                    // SAFETY: chars().take(8) is safe on any UTF-8 input, including
                    // multi-byte characters. Byte-index slicing (&s[..8]) would
                    // panic if byte 8 falls inside a multi-byte char boundary.
                    let sign_key_prefix: String = sign_key.chars().take(8).collect();
                    warn!(proxy_name = %msg.proxy_name, sign_key_prefix = %sign_key_prefix, "NewVisitorConn: no STCP proxy found for proxy_name='{}', sign_key='{}...'",
                        msg.proxy_name, sign_key_prefix);
                    // Send error response to visitor (Go frp expects NewVisitorConnResp)
                    let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                        proxy_name: msg.proxy_name.clone(),
                        error: Some("proxy not found".into()),
                    });
                    let _ = write_msg(&mut stream, &resp, v2).await;
                    return;
                }
            }
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!(proxy_name = %proxy_name, "NewVisitorConn: no run_id found for proxy '{}'", proxy_name);
            // Send error response to visitor
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: Some("provider not found".into()),
            });
            let _ = write_msg(&mut stream, &resp, v2).await;
            return;
        }
    };

    // --- allow_users check (Go frp compat: XTCP/STCP access control) ---
    if let Some(proxy_info) = state.proxy_manager.get(&proxy_name).await {
        if !proxy_info.allow_users.is_empty() {
            let visitor_run_id = msg.run_id.as_deref().unwrap_or("");
            if !proxy_info.allow_users.iter().any(|u| u == visitor_run_id) {
                warn!(visitor_run_id = %visitor_run_id, proxy_name = %proxy_name, "STCP visitor '{}' not in allow_users for proxy '{}'", visitor_run_id, proxy_name);
                let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                    proxy_name: proxy_name.clone(),
                    error: Some("visitor not allowed".into()),
                });
                let _ = write_msg(&mut stream, &resp, v2).await;
                return;
            }
        }
    }

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            info!(proxy_name = %proxy_name, run_id = %run_id, "STCP visitor for proxy '{}' routed to provider {}", proxy_name, run_id);
            // Send success response to visitor BEFORE forwarding the stream
            // (Go frp visitor expects NewVisitorConnResp on the same connection)
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: None,
            });
            if let Err(e) = write_msg(&mut stream, &resp, v2).await {
                warn!(proxy_name = %proxy_name, error = %e, "Failed to send NewVisitorConnResp for proxy '{}': {}", proxy_name, e);
                return;
            }
            // Use send().await, not try_send: we already sent success to the
            // visitor, so this connection MUST be delivered. Backpressure is
            // correct here — the visitor is waiting anyway.
            if ctl
                .tx
                .send(InternalMsg::VisitorConn {
                    proxy_name,
                    visitor_conn: stream,
                })
                .await
                .is_err()
            {
                // Channel closed: provider disconnected between auth check
                // and delivery. Visitor will time out and retry.
                warn!(run_id = %run_id, "Provider for run_id {} disconnected during visitor delivery", run_id);
            }
        }
        None => {
            warn!(run_id = %run_id, "No provider found for run_id {}", run_id);
            // Send error response to visitor
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: Some("provider disconnected".into()),
            });
            let _ = write_msg(&mut stream, &resp, v2).await;
        }
    }
}

// ---------------------------------------------------------------
// XTCP NAT hole visitor handler
// ---------------------------------------------------------------

/// Handle an incoming XTCP NatHoleVisitor connection.
///
/// Uses transaction_id and proxy_name from the message directly.
/// Validates proxy exists, looks up the provider, creates a NAT session,
/// forwards NatHoleClient to the provider via InternalMsg,
/// writes NatHoleResp (OK or error) to the visitor via the accept-loop writer,
/// and waits for the provider's report signal.
#[instrument(skip(stream, state), fields(proxy_name = %msg.proxy_name, transaction_id = %msg.transaction_id))]
pub(crate) async fn handle_nat_hole_visitor(
    stream: IoStream,
    msg: msg::NatHoleVisitor,
    state: Arc<AppState>,
    _visitor_addr: Option<String>, // not used in Go compat path; kept for callers
    v2: bool,
) {
    let transaction_id = msg.transaction_id.clone();
    let proxy_name = msg.proxy_name.clone();

    if proxy_name.is_empty() {
        warn!("NatHoleVisitor without proxy_name, ignoring");
        return;
    }

    // Validate proxy exists and capture its info for auth.
    let proxy_info = match state.proxy_manager.get(&proxy_name).await {
        Some(info) => info,
        None => {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: proxy '{}' not found", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("proxy not found".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: no run_id found for proxy '{}'", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider offline".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    let ctl_tx = match ctl_tx {
        Some(ctl) => ctl,
        None => {
            warn!(run_id = %run_id, "No provider control handler for run_id {}", run_id);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider disconnected".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    };

    // --- Go frp v0.69.1 compat: pre_check validates proxy and permissions
    // without creating a session. Visitor proceeds to STUN after receiving OK.
    // Check mapped_addrs.is_none() to distinguish from clients that send
    // pre_check=true with full data (treating it as a full request).
    if msg.pre_check && msg.mapped_addrs.is_none() {
        debug!(
            proxy_name = %proxy_name,
            "NatHoleVisitor pre_check for proxy '{}': OK",
            proxy_name
        );
        let (_, mut writer) = stream.into_split();
        let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            ..Default::default()
        }));
        let _ = write_msg(&mut writer, &resp, v2).await;
        return;
    }

    // --- Auth: verify visitor knows the shared secret ---
    // NatHoleVisitor on a fresh TCP connection must prove knowledge of the
    // proxy's secret key, just like NewVisitorConn. Without this check, an
    // attacker can trigger NAT traversal and provider simultaneous-open for
    // any proxy they can name.
    {
        let sign_key = msg.sign_key.as_deref().unwrap_or("");
        let timestamp = msg.timestamp.unwrap_or(0);

        // Require sign_key for non-pre_check requests on fresh connections.
        // The sign_key must equal MD5(proxy_sk + timestamp), verified with
        // constant-time comparison and timestamp freshness check to prevent
        // replay attacks.
        if sign_key.is_empty() {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: missing sign_key, rejecting");
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("auth required".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }

        let proxy_sk = proxy_info.sk.as_deref().unwrap_or("");
        if proxy_sk.is_empty() {
            // XTCP proxy without a shared secret: no way to authenticate
            // visitors on fresh connections. Reject.
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: proxy has no sk configured — rejecting fresh connection");
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("proxy has no shared secret".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }

        // Validate timestamp freshness (replay attack prevention).
        let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
        if let Err(freshness_err) =
            frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout)
        {
            warn!(proxy_name = %proxy_name, error = %freshness_err, "NatHoleVisitor: timestamp rejected for proxy '{}'", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some(freshness_err),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }

        if !frp_core::auth::verify_token(proxy_sk, timestamp, sign_key) {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor auth failed for proxy '{}'", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("auth failed".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
        debug!(proxy_name = %proxy_name, "NatHoleVisitor auth OK (constant-time) for proxy '{}'", proxy_name);

        // --- allow_users check on fresh connections ---
        // Fresh TCP connections carry no user identity — only sign_key.
        // If the proxy restricts visitors via allow_users, reject fresh
        // connections outright; authorized visitors must use the control
        // channel path (control/mod.rs NatHoleVisitor handler).
        if !proxy_info.allow_users.is_empty() {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: proxy has allow_users configured — rejecting fresh connection (use control channel)");
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("access denied: use control channel for user-based auth".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    }

    let (reader, writer) = stream.into_split();
    let sid = transaction_id.clone();

    // --- Step 1: Create session and notify provider ---
    let (session, report_rx) = match state
        .xtcp
        .nat_hole
        .create_session_with_writer(sid.clone(), proxy_name.clone(), msg.clone(), writer.into())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "NatHole session creation failed: {}", e);
            return;
        }
    };

    // --- Step 2: Set up notify channel BEFORE sending to provider ---
    // Must happen before the provider notification to avoid a race:
    // if the provider responds with NatHoleClient before we set up
    // notify_rx, the signal is lost and we timeout spuriously.
    let notify_rx = {
        let mut guard = session.notify_ch.lock().await;
        let (tx, rx) = oneshot::channel();
        *guard = Some(tx);
        rx
    };

    // Send NatHoleSid to provider ON A WORK CONNECTION (Go frp v0.69.1 compat).
    // The provider reads NatHoleSid from the work connection, does its own STUN,
    // and sends NatHoleClient back on its control connection with its mapped addresses.
    // handle_client() signals notify_ch when the provider's response arrives.
    if ctl_tx
        .tx
        .try_send(InternalMsg::NatHoleSidOnWorkConn {
            sid: sid.clone(),
            proxy_name: proxy_name.clone(),
        })
        .is_err()
    {
        warn!(run_id = %run_id, "Provider for run_id {} has gone away", run_id);
        state.xtcp.nat_hole.remove(&transaction_id).await;
        return;
    }

    info!(
        proxy_name = %proxy_name, sid = %sid,
        "NatHoleVisitor for proxy '{}': created session {}, waiting for provider",
        proxy_name, sid
    );

    // Wait for provider's NatHoleClient with STUN addresses.
    // The provider does its own STUN discovery and sends
    // NatHoleClient back with mapped_addrs/assisted_addrs.
    // Go frp v0.69.1 compat: server is a pure relay.
    // handle_client() signals notify_ch when the message arrives.

    let client_msg_received =
        tokio::time::timeout(Duration::from_secs(NAT_HOLE_TIMEOUT), notify_rx).await;

    if client_msg_received.is_err() {
        warn!(
            sid = %sid,
            "NatHole session {}: timeout waiting for provider NatHoleClient",
            sid
        );
        // Take the writer out of the option so we can perform async I/O
        // without holding the tokio::sync::Mutex guard.
        let mut taken_writer = session.visitor_writer.lock().await.take();
        if let Some(ref mut w) = taken_writer {
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider NAT detection timeout".into()),
                sid: None,
                protocol: None,
                candidate_addrs: None,
                assisted_addrs: None,
                detect_behavior: None,
            }));
            let _ = write_msg(w, &resp, v2).await;
            // Return the writer to the session
            *session.visitor_writer.lock().await = taken_writer;
        }
        state.xtcp.nat_hole.remove(&sid).await;
        drop(reader);
        return;
    }

    // --- Step 3: Get provider's addresses from session ---
    let client_msg_opt = session.client_msg.lock().await.take();
    let client_msg = match client_msg_opt {
        Some(m) => m,
        None => {
            warn!(sid = %sid, "NatHole session {}: no client message after notify", sid);
            state.xtcp.nat_hole.remove(&sid).await;
            drop(reader);
            return;
        }
    };

    let client_mapped = client_msg.mapped_addrs.unwrap_or_default();
    let client_assisted = client_msg.assisted_addrs.unwrap_or_default();
    let visitor_mapped = msg.mapped_addrs.unwrap_or_default();
    let visitor_assisted = msg.assisted_addrs.unwrap_or_default();

    // --- Step 4: Classify both NAT features ---
    let v_feature = classify::classify_nat_feature(&visitor_mapped, &[]).ok();
    let c_feature = classify::classify_nat_feature(&client_mapped, &[]).ok();

    // Store features on session
    if let Some(ref vf) = v_feature {
        *session.v_nat_feature.lock().await = Some(vf.clone());
    }
    if let Some(ref cf) = c_feature {
        *session.c_nat_feature.lock().await = Some(cf.clone());
    }

    // --- Step 5: Run analysis and build responses ---
    let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
        let key = nathole_ctrl::gen_analysis_key(cf, vf);
        let (mode, index, c_behavior, v_behavior) = state
            .xtcp
            .nat_hole
            .analyzer
            .get_recommend_behaviors(&key, cf, vf);
        *session.selected_index.lock().await = Some(index);

        let timeout_ms = c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000;
        let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
        let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;
        let c_ports_diff = cf.ports_difference;
        let v_ports_diff = vf.ports_difference;

        let v_resp = nathole_ctrl::build_nat_hole_response(
            nathole_ctrl::NatHoleResponseParams {
                transaction_id: transaction_id.clone(),
                sid: sid.clone(),
                protocol: msg.protocol.clone(),
                mode,
                candidate_addrs: client_mapped.clone(), // visitor gets PROVIDER's addresses
                assisted_addrs: client_assisted.clone(),
                behavior: v_behavior,
                read_timeout_ms: v_read_timeout,
                ports_difference: c_ports_diff,
            },
        );

        // Use visitor's protocol for provider's response too —
        // Go frp provider reads NatHoleResp.protocol to decide
        // KCP vs TCP transport. If empty, Go falls back to TCP
        // which is incompatible with visitor's KCP.
        let protocol_for_provider = msg.protocol.clone().or_else(|| client_msg.protocol.clone());
        let c_resp = nathole_ctrl::build_nat_hole_response(
            nathole_ctrl::NatHoleResponseParams {
                transaction_id: client_msg.transaction_id.clone(),
                sid: sid.clone(),
                protocol: protocol_for_provider,
                mode,
                candidate_addrs: visitor_mapped.clone(), // provider gets VISITOR's addresses
                assisted_addrs: visitor_assisted.clone(),
                behavior: c_behavior,
                read_timeout_ms: c_read_timeout,
                ports_difference: v_ports_diff,
            },
        );

        (v_resp, Some(c_resp))
    } else {
        // Fallback: simple exchange without analysis
        let v_resp = msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: msg.protocol.clone(),
            candidate_addrs: if client_mapped.is_empty() {
                None
            } else {
                Some(client_mapped)
            },
            assisted_addrs: if client_assisted.is_empty() {
                None
            } else {
                Some(client_assisted)
            },
            ..Default::default()
        };
        let protocol_for_provider = msg.protocol.clone().or_else(|| client_msg.protocol.clone());
        let c_resp = msg::NatHoleResp {
            transaction_id: client_msg.transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: protocol_for_provider,
            candidate_addrs: if visitor_mapped.is_empty() {
                None
            } else {
                Some(visitor_mapped)
            },
            assisted_addrs: if visitor_assisted.is_empty() {
                None
            } else {
                Some(visitor_assisted)
            },
            ..Default::default()
        };
        (v_resp, Some(c_resp))
    };

    // Store v_resp for reporting
    *session.v_resp.lock().await = Some(v_resp.clone());

    // --- Step 6: Send NatHoleResp to both sides ---
    // Send to visitor via writer
    {
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut w) = *writer_guard {
            if let Err(e) = write_msg(w, &FrpMessage::NatHoleResp(Box::new(v_resp)), v2).await {
                warn!(error = %e, "failed to write NatHoleResp to visitor");
            }
        }
    }

    // Send to provider via control channel.
    // send().await: backpressure is correct — if the provider's
    // control handler cannot drain messages, the XTCP session
    // should wait rather than silently drop the NatHoleResp
    // (which would cause a permanent visitor hang).
    if let Some(ref cr) = c_resp {
        let _ = ctl_tx
            .tx
            .send(InternalMsg::WriteNatHoleResp {
                transaction_id: cr.transaction_id.clone(),
                error: cr.error.clone(),
                sid: cr.sid.clone(),
                protocol: cr.protocol.clone(),
                candidate_addrs: cr.candidate_addrs.clone(),
                assisted_addrs: cr.assisted_addrs.clone(),
            })
            .await;
    }

    info!(sid = %sid, "NatHole session {}: NatHoleResp sent to both sides", sid);

    // --- Step 7: Wait for report ---
    match tokio::time::timeout(Duration::from_secs(30), report_rx).await {
        Ok(Ok(_report)) => {
            debug!(sid = %sid, "NatHole session {}: provider completed", sid);
        }
        Ok(Err(_)) => {
            debug!(sid = %sid, "NatHole session {}: provider dropped without report", sid);
            state.xtcp.nat_hole.remove(&sid).await;
        }
        Err(_) => {
            warn!(sid = %sid, "NatHole session {}: timed out waiting for provider report", sid);
            state.xtcp.nat_hole.remove(&sid).await;
            drop(reader);
        }
    }
    // reader dropped → connection closes
}

// ---------------------------------------------------------------
// V2 message dispatch
// ---------------------------------------------------------------

/// Decode a V2 message from raw frame payload and dispatch to the appropriate handler.
/// `payload` is the frame payload: [type_id: u16 BE][JSON bytes].
pub(crate) async fn dispatch_v2_message(
    io: IoStream,
    payload: Vec<u8>,
    state: std::sync::Arc<AppState>,
    addr: std::net::SocketAddr,
    incoming: Option<frp_core::mux::IncomingStreams>,
    visitor_addr: Option<String>,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
) {
    if payload.len() < 2 {
        warn!(addr = %addr, "V2 message payload too short from {}", addr);
        return;
    }
    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
    let msg = match frp_core::protocol::deserialize_v2(type_id, &payload[2..]) {
        Ok(m) => m,
        Err(e) => {
            warn!(addr = %addr, error = %e, "Failed to decode V2 message from {}: {}", addr, e);
            return;
        }
    };
    match msg {
        FrpMessage::Login(login) => {
            control::handle_control(io, *login, state, Some(addr), incoming, true, crypto_ctx)
                .await;
        }
        FrpMessage::NewWorkConn(nwc) => {
            handle_work_conn_inner(io, nwc, state).await;
        }
        FrpMessage::NewVisitorConn(vc) => {
            handle_visitor_conn_inner(io, vc, state, true).await;
        }
        FrpMessage::NatHoleVisitor(nhv) => {
            handle_nat_hole_visitor(io, nhv, state, visitor_addr, true).await;
        }
        other => {
            warn!(addr = %addr, type_id = ?other.v2_type_id(), "Unexpected V2 first message from {}: {:?}", addr, other.v2_type_id());
        }
    }
}

/// V1 mirror of `dispatch_v2_message`: read one V1 message off `io` and route
/// it to the matching handler. `addr`/`incoming`/`visitor_addr` vary per call
/// site; everything else is uniform (V1 => v2=false, no crypto context).
pub(crate) async fn dispatch_v1_message(
    mut io: IoStream,
    state: std::sync::Arc<AppState>,
    addr: Option<std::net::SocketAddr>,
    incoming: Option<frp_core::mux::IncomingStreams>,
    visitor_addr: Option<String>,
) {
    match frp_core::protocol::read_msg_v1(&mut io).await {
        Ok(FrpMessage::Login(login)) => {
            control::handle_control(io, *login, state, addr, incoming, false, None).await;
        }
        Ok(FrpMessage::NewWorkConn(nwc)) => {
            handle_work_conn_inner(io, nwc, state).await;
        }
        Ok(FrpMessage::NewVisitorConn(nvc)) => {
            handle_visitor_conn_inner(io, nvc, state, false).await;
        }
        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
            handle_nat_hole_visitor(io, nhv, state, visitor_addr, false).await;
        }
        Ok(other) => {
            warn!(other = ?other.v1_type_byte(), "Unexpected V1 first message: {:?}", other.v1_type_byte());
        }
        Err(e) => {
            warn!(error = %e, "V1 read error: {}", e);
        }
    }
}

// ---------------------------------------------------------------
// Work connection handler
// ---------------------------------------------------------------

/// Handle an incoming work connection. Verifies auth, then routes the
/// IoStream to the appropriate control handler via InternalMsg.
#[instrument(skip(stream, state), fields(run_id = %msg.run_id.clone().unwrap_or_default()))]
pub(crate) async fn handle_work_conn_inner(
    stream: IoStream,
    msg: msg::NewWorkConn,
    state: Arc<AppState>,
) {
    let run_id = match msg.run_id {
        Some(id) => id,
        None => {
            warn!("NewWorkConn without run_id, ignoring");
            return;
        }
    };

    // Verify work connection auth (Go frp v0.69.1 compat).
    // Only validate when "NewWorkConns" is in additional_auth_scopes.
    let requires_nwc_auth = state
        .reloadable
        .read_ok()
        .additional_auth_scopes
        .iter()
        .any(|s| s == "NewWorkConns");
    let nwc_auth_result = if !requires_nwc_auth {
        Ok(())
    } else if let Some(ref verifier) = state.oidc.verifier {
        let expected_sub = state
            .oidc
            .subjects
            .read()
            .await
            .get(&run_id)
            .cloned()
            .unwrap_or_default();
        verifier
            .verify_new_work_conn(msg.privilege_key.as_deref().unwrap_or(""), &expected_sub)
            .await
    } else {
        state
            .reloadable
            .read_ok()
            .auth_cfg
            .validate_login(msg.privilege_key.as_deref(), msg.timestamp)
            .map(|_| ())
    };
    if let Err(e) = nwc_auth_result {
        warn!(run_id = %run_id, error = %e, "Work conn auth failed for run_id {}: {}", run_id, e);
        return;
    }

    // NewWorkConn plugin hook — control-enabled plugins can reject
    let nwc_content = serde_json::json!({
        "run_id": run_id,
    });
    if let Err(reason) = state
        .plugin_manager
        .notify("new_work_conn", nwc_content)
        .await
    {
        warn!(run_id = %run_id, reason = %reason, "NewWorkConn plugin hook rejected: {}", reason);
        return;
    }

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            // Use send().await: a dropped NewWorkConn leaves the proxy
            // without a work connection until the control handler times out
            // and requests a new one. Backpressure is correct.
            if ctl.tx.send(InternalMsg::NewWorkConn(stream)).await.is_err() {
                warn!(run_id = %run_id, "Control handler for {} has gone away", run_id);
            }
        }
        None => {
            warn!(run_id = %run_id, "No control handler found for run_id {}", run_id);
        }
    }
}
