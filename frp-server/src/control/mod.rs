mod bridge;
mod proxy_ops;

use proxy_ops::err_msg;
use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::VecDeque;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug, instrument};
use crate::nathole::NAT_HOLE_TIMEOUT;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;
use frp_core::protocol::{read_msg_v1, write_msg_v1, read_msg_v2, write_msg_v2};

/// Protocol-aware read: dispatches to V1 or V2 framing based on the `v2` flag.
async fn read_ctl_msg<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    v2: bool,
) -> Result<FrpMessage, frp_core::Error> {
    if v2 {
        read_msg_v2(reader).await
    } else {
        read_msg_v1(reader).await
    }
}

/// Protocol-aware write: dispatches to V1 or V2 framing based on the `v2` flag.
async fn write_ctl_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    v2: bool,
) -> Result<(), frp_core::Error> {
    if v2 {
        write_msg_v2(writer, msg).await
    } else {
        write_msg_v1(writer, msg).await
    }
}
use frp_core::transport::IoStream;

use crate::service::{AppState, InternalMsg, ControlTx};

/// Max age of a pending request before it is dropped (Go frp: 10s default).
pub(super) const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Max work connections to pool beyond what the client requested (Go frp: poolCount + 10).
const WORK_POOL_EXTRA: usize = 10;

/// A pending request from a proxy listener waiting for a work connection.
pub(super) struct PendingRequest {
    proxy_name: String,
    user_conn: IoStream,
    pre_read: Vec<u8>,
    use_encryption: bool,
    use_compression: bool,
    created_at: Instant,
    response_headers: std::collections::HashMap<String, String>,
    proxy_type: String,
}

/// Handle a control connection from a frpc client.
/// The login message has already been consumed from the stream.
/// `peer` is passed separately because generic stream types don't have peer_addr().
#[instrument(skip(stream, state, incoming, crypto_ctx), fields(run_id = %login.run_id.clone().unwrap_or_default(), peer = ?peer))]
pub async fn handle_control<S>(
    mut stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    mut incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(peer = ?peer, "New control connection from {:?}", peer);

    // --- Authenticate ---
    let oidc_subject: Option<String> = if let Some(ref verifier) = state.oidc_verifier {
        let token = login.privilege_key.as_deref().unwrap_or("");
        match verifier.verify_login(token).await {
            Ok(oidc_token) => {
                info!(subject = %oidc_token.subject, "OIDC login verified: subject={}", oidc_token.subject);
                Some(oidc_token.subject)
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "OIDC auth failed for {:?}: {}", peer, e);
                let (_, mut writer) = tokio::io::split(stream);
                let resp = FrpMessage::LoginResp(msg::LoginResp {
                    version: Some(frp_core::VERSION.into()),
                    run_id: None,
                    error: Some(err_msg(state.detailed_errors_to_client, format!("OIDC authentication failed: {e}"), "OIDC authentication failed")),
                    server_additional_auth_scopes: None,
                });
                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                return;
            }
        }
    } else {
        let auth_cfg = state.reloadable.read().unwrap().auth_cfg.clone();
        if let Err(e) = auth_cfg.validate_login(
            login.privilege_key.as_deref(),
            login.timestamp,
        ) {
            warn!(peer = ?peer, error = %e, "Authentication failed for {:?}: {}", peer, e);
            // Emit WebSocket event for dashboard subscribers
            #[cfg(feature = "dashboard")]
            {
                let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                    message: format!("Authentication failed for {:?}", peer),
                    context: Some("login".into()),
                });
            }
            let (_, mut writer) = tokio::io::split(stream);
            let resp = FrpMessage::LoginResp(msg::LoginResp {
                version: Some(frp_core::VERSION.into()),
                run_id: None,
                error: Some(err_msg(state.detailed_errors_to_client, e, "token authentication failed")),
                server_additional_auth_scopes: None,
            });
            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
            return;
        }
        None
    };

    let reloadable = state.reloadable.read().unwrap().clone();

    let run_id = login.run_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!(peer = ?peer, run_id = %run_id, "Client {:?} logged in with run_id: {}", peer, run_id);

    // Store OIDC subject for ping/NWC verification
    if let Some(ref sub) = oidc_subject {
        state.oidc_subjects.write().await.insert(run_id.clone(), sub.clone());
    }

    // --- Server plugin: login hook ---
    let login_content = serde_json::json!({
        "version": login.version,
        "hostname": login.hostname,
        "os": login.os,
        "user": login.user,
        "run_id": run_id,
        "remote_addr": peer.map(|a| a.to_string()),
        "metas": login.metas,
    });
    if let Err(reason) = state.plugin_manager.notify("login", login_content).await {
        warn!(run_id = %run_id, reason = %reason, "Login for run_id {} rejected by server plugin: {}", run_id, reason);
        let (_, mut writer) = tokio::io::split(stream);
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: None,
            error: Some(reason),
            server_additional_auth_scopes: None,
        });
        let _ = write_ctl_msg(&mut writer, &resp, v2).await;
        return;
    }

    // --- Set up internal channel ---
    let (internal_tx, mut internal_rx) = mpsc::unbounded_channel::<InternalMsg>();

    // Register control channel. If a previous handler exists for this run_id,
    // send Shutdown to it so it stops listening (Go frp v0.69.1 compat).
    {
        let mut map = state.run_id_to_ctl_tx.write().await;
        if let Some(old_ctl) = map.get(&run_id) {
            warn!(run_id = %run_id, "Duplicate run_id {}: shutting down old control handler", run_id);
            let _ = old_ctl.tx.send(InternalMsg::Shutdown);
        }
        map.insert(run_id.clone(), ControlTx {
            tx: internal_tx.clone(),
            client_addr: peer,
            login_time: std::time::Instant::now(),
        });
    }

    // --- Send login response (plain, before encryption) ---
    {
        let additional_auth_scopes = reloadable.additional_auth_scopes.clone();
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some(run_id.clone()),
            error: None,
            server_additional_auth_scopes: if additional_auth_scopes.is_empty() { None } else { Some(additional_auth_scopes) },
        });
        // Hex-dump the raw LoginResp V1 frame for Go compat debugging
        let type_byte = resp.v1_type_byte();
        let payload = serde_json::to_vec(&resp).unwrap_or_default();
        let frame_len = 9 + payload.len();
        info!(
            peer = ?peer, run_id = %run_id,
            type_byte = format_args!("{:#04x}", type_byte),
            payload_len = payload.len(),
            payload_text = %String::from_utf8_lossy(&payload),
            "LoginResp V1 frame: type={:#04x} len={} frame_total={} json={}",
            type_byte, payload.len(), frame_len,
            String::from_utf8_lossy(&payload),
        );
        if let Err(e) = write_ctl_msg(&mut stream, &resp, v2).await {
            warn!(peer = ?peer, error = %e, "Failed to send login response to {:?}: {}", peer, e);
            proxy_ops::unregister_control(&state, &run_id).await;
            return;
        }
        // Flush TLS stream to ensure LoginResp reaches KCP before we wrap in CipherStream
        if let Err(e) = stream.flush().await {
            warn!(peer = ?peer, error = %e, "Failed to flush after LoginResp: {}", e);
        }
        info!(peer = ?peer, run_id = %run_id, "LoginResp sent to {:?}, flushed", peer);

        // Emit WebSocket event for dashboard subscribers
        #[cfg(feature = "dashboard")]
        {
            let _ = state.event_tx.send(crate::event::ServerEvent::ClientConnected {
                run_id: run_id.clone(),
                client_addr: peer.map(|a| a.to_string()),
            });
        }
    }

    // --- Wrap in encryption (matches client after login) ---
    // V2 with AEAD crypto: wrap stream in AEAD here, AFTER LoginResp sent
    // (matching Go frp flow: ClientHello/ServerHello + Login/LoginResp in
    // plaintext, then AEAD for all subsequent messages).
    // V1 or V2 without AEAD: wrap in AES-128-CFB (CipherStream) for backward compat.
    let (mut reader, mut writer): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) = if let (true, Some(ctx)) = (v2, crypto_ctx.as_ref()) {
        let token = reloadable.auth_cfg.token.clone();
        match frp_core::crypto::derive_aead_control_keys(
            token.as_bytes(), ctx.algorithm, &ctx.transcript_hash,
        ) {
            Ok((read_key, write_key)) => {
                // derive_aead_control_keys returns (client_to_server, server_to_client).
                // Server reads from client → client_to_server (= read_key).
                // Server writes to client → server_to_client (= write_key).
                match frp_core::crypto::AeadStream::new(
                    Box::new(stream), ctx.algorithm, &read_key, &write_key,
                ) {
                    Ok(aead) => {
                        let (r, w) = tokio::io::split(aead);
                        (Box::new(r), Box::new(w))
                    }
                    Err(e) => {
                        warn!(peer = ?peer, error = %e, "Failed to create AEAD stream for {:?}: {}", peer, e);
                        proxy_ops::unregister_control(&state, &run_id).await;
                        return;
                    }
                }
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to derive AEAD keys for {:?}: {}", peer, e);
                proxy_ops::unregister_control(&state, &run_id).await;
                return;
            }
        }
    } else {
        // V1 or plain V2: ALWAYS wrap in AES-128-CFB after LoginResp.
        // Go frp v0.69.1 always encrypts the control connection after login
        // (both frps service.go:460 and frpc control_session.go:219 call
        // NewCryptoReadWriter unconditionally — no config flag gates it).
        // The use_encryption config flag controls proxy bridge (data plane)
        // encryption, not control plane encryption.
        info!(peer = ?peer, run_id = %run_id, "Wrapping control stream in CipherStream (AES-128-CFB)");
        let enc_key = encryption::derive_key(&reloadable.auth_cfg.token);
        let mut cipher = frp_core::cipher_stream::CipherStream::new(Box::new(stream), enc_key);

        // --- Send ReqWorkConn BEFORE tokio::io::split ---
        // Matching Go frps service.go:496 ctl.Start() which sends ReqWorkConn
        // immediately after LoginResp. This triggers our first encrypted write
        // (IV + ReqWorkConn), unblocking Go frpc's crypto.Reader.Read().
        {
            let pool_count = login.pool_count.unwrap_or(1).max(1) as usize;
            info!(peer = ?peer, pool_count = pool_count, "Sending ReqWorkConn x{} through cipher (before split)", pool_count);
            for i in 0..pool_count {
                if let Err(e) = write_ctl_msg(&mut cipher, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                    warn!(peer = ?peer, error = %e, i = i, "Failed to send ReqWorkConn #{}/{}: {}", i, pool_count, e);
                    proxy_ops::unregister_control(&state, &run_id).await;
                    return;
                }
            }
            if let Err(e) = cipher.flush().await {
                warn!(peer = ?peer, error = %e, "Failed to flush after ReqWorkConn: {}", e);
            }
            info!(peer = ?peer, pool_count = pool_count, "ReqWorkConn x{} sent (pre-split)", pool_count);
        }

        let (r, w) = tokio::io::split(cipher);
        (Box::new(r), Box::new(w))
    };

    info!(peer = ?peer, run_id = %run_id, "Control stream encrypted, entering message loop");

    // --- Per-client state ---
    let pool_cap = login.pool_count.unwrap_or(1).max(0) as usize + WORK_POOL_EXTRA;
    let mut work_pool: VecDeque<IoStream> = VecDeque::new();
    let mut pending_requests: VecDeque<PendingRequest> = VecDeque::new();
    let mut pending_udp: VecDeque<(String, Instant)> = VecDeque::new();
    let mut pending_nat_hole_sids: VecDeque<(String, String, Instant)> = VecDeque::new();
    // TCP/HTTP/STCP listener handles. UDP listeners are managed via the work-connection
    // mechanism (UdpNeedsWorkConn → ReqWorkConn → assign_udp_work_conn).
    let mut listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> = std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> = std::collections::HashMap::new();
    // Reverse mapping: local_addr → proxy_name for routing UDPPacket responses
    let mut udp_local_to_proxy: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut last_ping = Instant::now();
    // Ping interval: max 10s to stay well within Go frpc's heartbeat timeout
    let ping_interval = Duration::from_secs(10);
    let mut ping_tick = tokio::time::interval(ping_interval);
    // First tick fires immediately to unblock Go frpc's read loop
    ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // --- Main select loop ---
    loop {
        // Expire stale pending requests
        while let Some(req) = pending_requests.front() {
            if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                let expired = pending_requests.pop_front().unwrap();
                debug!(proxy_name = %expired.proxy_name, timeout = ?PENDING_REQUEST_TIMEOUT, "Pending request for proxy '{}' timed out after {:?}", expired.proxy_name, PENDING_REQUEST_TIMEOUT);
            } else {
                break;
            }
        }

        // Heartbeat check: if no ping in heartbeat_timeout, disconnect
        let hb_timeout = Duration::from_secs(state.heartbeat_timeout.max(1) as u64);
        if last_ping.elapsed() > hb_timeout {
            warn!(peer = ?peer, hb_timeout = ?hb_timeout, "Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, hb_timeout);
            break;
        }

        tokio::select! {
            biased;

            // Prefer internal messages to reduce latency for proxy connections
            internal = internal_rx.recv() => {
                match internal {
                    Some(InternalMsg::NewWorkConn(mut stream)) => {
                        debug!(run_id = %run_id, "Got work conn for run_id {}", run_id);
                        // Expire stale pending NatHoleSid entries first.
                        while let Some((_, _, ts)) = pending_nat_hole_sids.front() {
                            if ts.elapsed() > PENDING_REQUEST_TIMEOUT {
                                let (sid, _pn, _) = pending_nat_hole_sids.pop_front().unwrap();
                                debug!(sid = %sid, "Pending NatHoleSid {} timed out", sid);
                            } else {
                                break;
                            }
                        }
                        // Check NatHoleSid delivery first (Go frp XTCP compat).
                        // Pending sids take priority — they unblock waiting visitors.
                        if let Some((sid, proxy_name, _ts)) = pending_nat_hole_sids.pop_front() {
                            debug!(sid = %sid, proxy_name = %proxy_name, "Delivering pending NatHoleSid {} for {} to provider", sid, proxy_name);
                            // Look up proxy flags for StartWorkConn (encryption/compression propagation)
                            let (use_enc, use_comp) = state.proxy_manager.get(&proxy_name).await
                                .map(|p| (p.use_encryption, p.use_compression))
                                .unwrap_or((false, false));
                            // Embed NatHoleSid info directly in StartWorkConn JSON.
                            // This avoids a separate NatHoleSid frame after StartWorkConn
                            // which Go frpc would misinterpret as bridge data.
                            let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
                                proxy_name: proxy_name.clone(),
                                src_addr: None, src_port: None,
                                dst_addr: None, dst_port: None, error: None,
                                use_encryption: if use_enc { Some(true) } else { None },
                                use_compression: if use_comp { Some(true) } else { None },
                                nat_hole_sid: Some(sid.clone()),
                                nat_hole_visitor_addr: None,
                            });
                            if let Err(e) = write_ctl_msg(&mut stream, &swc, v2).await {
                                warn!(error = %e, "Failed to send pending StartWorkConn with NatHoleSid: {}", e);
                            } else {
                                // Also send a separate NatHoleSid V1 frame for Go frpc compat.
                                // Go frp ignores unknown JSON fields (embedded nat_hole_sid),
                                // so it needs the standalone frame to recognize the XTCP notification.
                                let nhs = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                    sid: Some(sid.clone()),
                                    provider_addr: None,
                                });
                                if let Err(e) = write_ctl_msg(&mut stream, &nhs, v2).await {
                                    debug!(error = %e, "Failed to send separate NatHoleSid frame (non-fatal): {}", e);
                                }
                            }
                            // Work conn consumed for XTCP notification — drop it.
                        } else {
                            // Expire stale pending UDP requests first
                            while let Some((_, ts)) = pending_udp.front() {
                                if ts.elapsed() > PENDING_REQUEST_TIMEOUT {
                                    let (pn, _) = pending_udp.pop_front().unwrap();
                                    debug!(proxy_name = %pn, "Pending UDP work conn for '{}' timed out", pn);
                                } else {
                                    break;
                                }
                            }
                            // Check if a UDP proxy needs this work connection
                            if let Some((proxy_name, _)) = pending_udp.pop_front() {
                                info!(proxy_name = %proxy_name, "Assigning work conn to UDP proxy '{}'", proxy_name);
                                let local_addr = state.proxy_manager.get(&proxy_name).await
                                    .and_then(|info| info.local_addr)
                                    .and_then(|s| msg::UdpAddr::from_string(&s));
                                bridge::assign_udp_work_conn(stream, &proxy_name, &udp_sockets, local_addr, v2, state.udp_packet_size).await;
                            } else {
                                // Drain expired TCP requests
                                while let Some(req) = pending_requests.front() {
                                    if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                                        pending_requests.pop_front();
                                    } else {
                                        break;
                                    }
                                }
                                if let Some(req) = pending_requests.pop_front() {
                                    let enc_key = reloadable.encryption_key;
                                    bridge::assign_work_to_proxy(stream, req, enc_key, state.clone(), v2).await;
                                } else if work_pool.len() < pool_cap {
                                    work_pool.push_back(stream);
                                    debug!(run_id = %run_id, pool_size = %work_pool.len(), pool_cap = %pool_cap, "Work conn pooled for {} (pool size: {}/{})", run_id, work_pool.len(), pool_cap);
                                } else {
                                    debug!(run_id = %run_id, pool_size = %work_pool.len(), pool_cap = %pool_cap, "Work pool full for {} ({}/{}), dropping work conn", run_id, work_pool.len(), pool_cap);
                                }
                            }
                        }
                    }
                    Some(InternalMsg::VisitorConn { proxy_name, visitor_conn }) => {
                        // NewUserConn plugin hook — control-enabled plugins can reject
                        let user_content = serde_json::json!({
                            "proxy_name": proxy_name,
                            "run_id": run_id,
                        });
                        if let Err(reason) = state.plugin_manager.notify("new_user_conn", user_content).await {
                            debug!(proxy_name = %proxy_name, reason = %reason, "NewUserConn plugin hook rejected (VisitorConn): {}", reason);
                            continue;
                        }
                        debug!(proxy_name = %proxy_name, run_id = %run_id, "STCP visitor conn for proxy {} on run_id {}", proxy_name, run_id);
                        let (enc, comp, response_headers, proxy_type) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let e = p.as_ref().map(|p| p.use_encryption).unwrap_or(false);
                            let c = p.as_ref().map(|p| p.use_compression).unwrap_or(false);
                            let rh = p.as_ref().map(|p| p.response_headers.clone()).unwrap_or_default();
                            let pt = p.as_ref().map(|p| p.proxy_type.clone()).unwrap_or_default();
                            (e, c, rh, pt)
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            let enc_key = reloadable.encryption_key;
                            bridge::assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn: visitor_conn, pre_read: Vec::new(), use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type }, enc_key, state.clone(), v2).await;
                        } else {
                            debug!("No pooled work conn for STCP, sending ReqWorkConn");
                            if let Err(e) = write_ctl_msg(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!(error = %e, "Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn: visitor_conn, pre_read: Vec::new(), use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type });
                        }
                    }
                    Some(InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }) => {
                        // NewUserConn plugin hook — control-enabled plugins can reject
                        let user_content = serde_json::json!({
                            "proxy_name": proxy_name,
                            "run_id": run_id,
                        });
                        if let Err(reason) = state.plugin_manager.notify("new_user_conn", user_content).await {
                            debug!(proxy_name = %proxy_name, reason = %reason, "NewUserConn plugin hook rejected (ProxyUserConn): {}", reason);
                            continue;
                        }
                        debug!(proxy_name = %proxy_name, run_id = %run_id, "User conn for proxy {} on run_id {}", proxy_name, run_id);
                        // Group load balancing: if proxy belongs to a group,
                        // select a backend (possibly on a different run_id).
                        let (target_proxy, target_run_id) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let group = p.as_ref().and_then(|p| p.group.clone()).filter(|g| !g.is_empty());
                            let group_key = p.as_ref().and_then(|p| p.group_key.clone()).unwrap_or_default();
                            if let Some(ref group_name) = group {
                                if let Some(backend) = state.proxy_manager.select_group_backend(group_name, &group_key).await {
                                    let backend_run_id = state.proxy_manager.get_run_id(&backend).await.unwrap_or_default();
                                    info!(proxy_name = %proxy_name, backend = %backend, backend_run_id = %backend_run_id, "Group LB: {} -> backend {} (run_id {})", proxy_name, backend, backend_run_id);
                                    (backend, backend_run_id)
                                } else {
                                    (proxy_name.clone(), run_id.clone())
                                }
                            } else {
                                (proxy_name.clone(), run_id.clone())
                            }
                        };
                        // If backend is on a different run_id, forward to that handler
                        if target_run_id != run_id {
                            let ctl_tx = {
                                let map = state.run_id_to_ctl_tx.read().await;
                                map.get(&target_run_id).cloned()
                            };
                            if let Some(ctl) = ctl_tx {
                                let _ = ctl.tx.send(InternalMsg::ProxyUserConn {
                                    proxy_name: target_proxy,
                                    user_conn,
                                    pre_read,
                                });
                                continue;
                            }
                            warn!(target_run_id = %target_run_id, target_proxy = %target_proxy, "Group backend run_id {} not found for proxy {}", target_run_id, target_proxy);
                            continue;
                        }
                        let (enc, comp, response_headers, proxy_type) = {
                            let p = state.proxy_manager.get(&target_proxy).await;
                            let e = p.as_ref().map(|p| p.use_encryption).unwrap_or(false);
                            let c = p.as_ref().map(|p| p.use_compression).unwrap_or(false);
                            let rh = p.as_ref().map(|p| p.response_headers.clone()).unwrap_or_default();
                            let pt = p.as_ref().map(|p| p.proxy_type.clone()).unwrap_or_default();
                            (e, c, rh, pt)
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            let enc_key = reloadable.encryption_key;
                            bridge::assign_work_to_proxy(work_conn, PendingRequest { proxy_name: target_proxy, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type }, enc_key, state.clone(), v2).await;
                        } else {
                            debug!(target_proxy = %target_proxy, "No pooled work conn, sending ReqWorkConn for {}", target_proxy);
                            if let Err(e) = write_ctl_msg(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!(error = %e, "Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name: target_proxy, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type });
                        }
                    }
                    Some(InternalMsg::UdpNeedsWorkConn { proxy_name }) => {
                        debug!(proxy_name = %proxy_name, "UDP proxy '{}' needs work connection", proxy_name);
                        if let Err(e) = write_ctl_msg(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                            warn!(error = %e, "Failed to send ReqWorkConn for UDP: {}", e);
                            break;
                        }
                        pending_udp.push_back((proxy_name, Instant::now()));
                    }
                    Some(InternalMsg::WriteNatHoleSid { sid, provider_addr }) => {
                        debug!(sid = %sid, "Writing NatHoleSid to visitor via control channel for {}", sid);
                        let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                            sid: Some(sid),
                            provider_addr,
                        });
                        if let Err(e) = write_ctl_msg(&mut writer, &forward, v2).await {
                            warn!(error = %e, "Failed to write NatHoleSid to visitor: {}", e);
                        }
                    }
                    Some(InternalMsg::WriteNatHoleResp { transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs }) => {
                        debug!(transaction_id = %transaction_id, "Writing NatHoleResp to visitor via control channel for {}", transaction_id);
                        let forward = FrpMessage::NatHoleResp(msg::NatHoleResp {
                            transaction_id,
                            error,
                            sid,
                            protocol,
                            candidate_addrs,
                            assisted_addrs,
                            ..Default::default()
                        });
                        if let Err(e) = write_ctl_msg(&mut writer, &forward, v2).await {
                            warn!(error = %e, "Failed to write NatHoleResp to visitor: {}", e);
                        }
                    }
                    Some(InternalMsg::WriteNatHoleReport { sid }) => {
                        debug!(sid = %sid, "Writing NatHoleReport to visitor via control channel for {}", sid);
                        let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
                            sid: Some(sid),
                        });
                        if let Err(e) = write_ctl_msg(&mut writer, &forward, v2).await {
                            warn!(error = %e, "Failed to write NatHoleReport to visitor: {}", e);
                        }
                    }
                    Some(InternalMsg::NatHoleSidOnWorkConn { sid, proxy_name }) => {
                        debug!(sid = %sid, proxy_name = %proxy_name, "Sending NatHoleSid {} for proxy {} to provider on work conn", sid, proxy_name);
                        if let Some(mut work_conn) = work_pool.pop_front() {
                            // Look up proxy flags for StartWorkConn (encryption/compression propagation)
                            let (use_enc, use_comp) = state.proxy_manager.get(&proxy_name).await
                                .map(|p| (p.use_encryption, p.use_compression))
                                .unwrap_or((false, false));
                            // Embed NatHoleSid info directly in StartWorkConn JSON.
                            // This avoids a separate NatHoleSid frame after StartWorkConn
                            // which Go frpc would misinterpret as bridge data.
                            // Go frp ignores unknown JSON fields, so the embedded fields
                            // are backward-compatible.
                            let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
                                proxy_name: proxy_name.clone(),
                                src_addr: None, src_port: None,
                                dst_addr: None, dst_port: None, error: None,
                                use_encryption: if use_enc { Some(true) } else { None },
                                use_compression: if use_comp { Some(true) } else { None },
                                nat_hole_sid: Some(sid.clone()),
                                nat_hole_visitor_addr: None,
                            });
                            if let Err(e) = write_ctl_msg(&mut work_conn, &swc, v2).await {
                                warn!(error = %e, "Failed to send StartWorkConn with NatHoleSid on work conn: {}", e);
                            } else {
                                debug!(sid = %sid, "Sent StartWorkConn with embedded NatHoleSid {} to provider on work conn", sid);
                                // Also send a separate NatHoleSid V1 frame for Go frpc compat.
                                // Go frp ignores unknown JSON fields (embedded nat_hole_sid),
                                // so it needs the standalone frame to recognize the XTCP notification.
                                // Rust frpc checks the embedded field first and returns early,
                                // so the separate frame is harmlessly dropped with the connection.
                                let nhs = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                    sid: Some(sid.clone()),
                                    provider_addr: None,
                                });
                                if let Err(e) = write_ctl_msg(&mut work_conn, &nhs, v2).await {
                                    debug!(error = %e, "Failed to send separate NatHoleSid frame (non-fatal): {}", e);
                                }
                            }
                            // Connection consumed — Go frp doesn't reuse after NatHoleSid.
                            drop(work_conn);
                        } else {
                            // No pooled work conn — request one, queue sid.
                            debug!(sid = %sid, "No pooled work conn for NatHoleSid {}, requesting via ReqWorkConn", sid);
                            if let Err(e) = write_ctl_msg(&mut writer,
                                &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!(error = %e, "Failed to send ReqWorkConn for NatHoleSid: {}", e);
                            }
                            pending_nat_hole_sids.push_back((sid, proxy_name, Instant::now()));
                        }
                    }
                    Some(InternalMsg::Shutdown) => {
                        warn!(run_id = %run_id, "Shutdown received for run_id {} (replaced by new control connection)", run_id);
                        break;
                    }
                    #[cfg(feature = "vnet")]
                    Some(InternalMsg::VnetPacketForward { proxy_name, data }) => {
                        let pkt = FrpMessage::VnetPacket(msg::VnetPacket {
                            proxy_name,
                            data,
                        });
                        if let Err(e) = write_ctl_msg(&mut writer, &pkt, v2).await {
                            warn!(error = %e, "Failed to forward VnetPacket: {}", e);
                        }
                    }
                    None => {
                        info!(peer = ?peer, "Control channel closed for {:?}", peer);
                        break;
                    }
                }
            }

            // Accept yamux streams (TcpMux work connections).
            // Go frp compat: client sends NewWorkConn on each yamux stream.
            // Read it to validate, then pool or assign.
            incoming_msg = async {
                match &mut incoming {
                    Some(inc) => inc.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(stream) = incoming_msg {
                    let mut io = IoStream::Yamux(stream);
                    if v2 {
                        match frp_core::protocol::read_v2_magic_or_replay(&mut io).await {
                            Ok(None) => {} // magic consumed
                            Ok(Some(bytes)) => {
                                // Older V2 client without per-stream magic —
                                // replay bytes as start of next frame.
                                io = IoStream::BufferedRead(bytes, 0, Box::new(io));
                            }
                            Err(e) => {
                                warn!(run_id = %run_id, error = %e, "Failed to read V2 magic from yamux stream for {run_id}: {e}");
                                continue;
                            }
                        }
                    }
                    match read_ctl_msg(&mut io, v2).await {
                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                            let stream_run_id = nwc.run_id.as_deref().unwrap_or("");
                            if stream_run_id != run_id {
                                debug!(expected_run_id = %run_id, got_run_id = %stream_run_id, "Yamux work conn run_id mismatch: expected {run_id}, got {stream_run_id}");
                                continue;
                            }
                        }
                        Ok(other) => {
                            debug!(run_id = %run_id, msg_type = ?other.v1_type_byte(), "Unexpected yamux stream message for {run_id}: {:?}", other.v1_type_byte());
                            continue;
                        }
                        Err(e) => {
                            warn!(run_id = %run_id, error = %e, "Failed to read from yamux stream for {run_id}: {e}");
                            continue;
                        }
                    }
                    debug!(run_id = %run_id, "Yamux work conn for run_id {}", run_id);
                    while let Some(req) = pending_requests.front() {
                        if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                            pending_requests.pop_front();
                        } else {
                            break;
                        }
                    }
                    if let Some(req) = pending_requests.pop_front() {
                        let enc_key = reloadable.encryption_key;
                        bridge::assign_work_to_proxy(io, req, enc_key, state.clone(), v2).await;
                    } else if work_pool.len() < pool_cap {
                        work_pool.push_back(io);
                        debug!(run_id = %run_id, pool_size = %work_pool.len(), pool_cap = %pool_cap, "Yamux work conn pooled for {} (pool size: {}/{})", run_id, work_pool.len(), pool_cap);
                    } else {
                        debug!(run_id = %run_id, pool_size = %work_pool.len(), pool_cap = %pool_cap, "Work pool full for {} ({}/{}), dropping yamux work conn", run_id, work_pool.len(), pool_cap);
                    }
                }
            }

            msg = read_ctl_msg(&mut reader, v2) => {
                match msg {
                    Ok(FrpMessage::UDPPacket(up)) => {
                        debug!(byte_count = %up.content.len(), remote_addr = ?up.remote_addr, "UDPPacket from client: {} bytes to {:?}", up.content.len(), up.remote_addr);
                        // Forward via the proxy's UDP socket (bidirectional NAT, Go frp compat).
                        let local_addr_str = up.local_addr.as_ref().map(|a| a.to_string()).unwrap_or_default();
                        let proxy_name = udp_local_to_proxy.get(&local_addr_str).cloned();
                        // Cache local_addr → proxy_name mapping from incoming packets
                        if !local_addr_str.is_empty() && !udp_local_to_proxy.contains_key(&local_addr_str) {
                            let fallback_pn = proxy_name
                                .clone()
                                .or_else(|| {
                                    let first = udp_sockets.keys().next().cloned();
                                    if first.is_some() {
                                        tracing::debug!(
                                            local_addr = %local_addr_str,
                                            "UDP packet local_addr→proxy_name not cached, falling back to first available socket"
                                        );
                                    }
                                    first
                                });
                            if let Some(ref pn) = fallback_pn {
                                udp_local_to_proxy.insert(local_addr_str.clone(), pn.clone());
                            }
                        }
                        // Decrypt/decompress if the proxy requires it
                        let mut payload = up.content.clone();
                        if let Some(ref pn) = proxy_name {
                            if let Some(proxy_info) = state.proxy_manager.get(pn.as_str()).await {
                                if proxy_info.use_encryption {
                                    if let Ok(decrypted) = encryption::decrypt(&payload, &reloadable.encryption_key) {
                                        payload = decrypted;
                                    }
                                }
                                if proxy_info.use_compression {
                                    if let Ok(decompressed) = encryption::decompress(&payload) {
                                        payload = decompressed;
                                    }
                                }
                            }
                        }
                        let sock_opt = proxy_name
                            .as_ref()
                            .and_then(|pn| udp_sockets.get(pn.as_str()))
                            .or_else(|| udp_sockets.iter().next().map(|(_, s)| s));
                        if let Some(sock) = sock_opt {
                            let sock = sock.clone();
                            let content = payload;
                            if let Some(ref remote) = up.remote_addr {
                                let remote_str = remote.to_string();
                                tokio::spawn(async move {
                                    let _ = sock.send_to(&content, &remote_str).await;
                                });
                            }
                        } else {
                            warn!(byte_count = %up.content.len(), "No UDP socket for proxy, dropping {} bytes", up.content.len());
                        }
                    }
                    Ok(FrpMessage::NewProxy(np)) => {
                        info!(proxy_name = %np.proxy_name, "KCP TLS: received NewProxy for {}", np.proxy_name);
                        proxy_ops::handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx, &mut listener_handles, &mut udp_sockets, &mut udp_local_to_proxy, v2).await;
                    }
                    #[cfg(feature = "vnet")]
                    Ok(FrpMessage::VnetRouteAdvertise(ref adv)) => {
                        let vn = adv.virtual_net.clone().unwrap_or_default();
                        let key = (vn.clone(), adv.subnet.clone());
                        state.vnet_routes.write().await.insert(
                            key,
                            (run_id.clone(), adv.proxy_name.clone()),
                        );
                        info!(
                            proxy_name = %adv.proxy_name,
                            subnet = %adv.subnet,
                            "vnet route advertised: {} → {}",
                            adv.subnet, adv.proxy_name
                        );
                    }
                    #[cfg(feature = "vnet")]
                    Ok(FrpMessage::VnetPacket(ref pkt)) => {
                        // Look up target proxy and forward packet via internal message
                        if let Some(target_info) = state.proxy_manager.get(&pkt.proxy_name).await {
                            let target_run_id = target_info.run_id.clone();
                            if target_run_id == run_id {
                                // Same client — no forwarding needed (client handles locally)
                                debug!(proxy_name = %pkt.proxy_name, "vnet packet target is self, skipping forward");
                            } else if let Some(ctl_tx) = state.run_id_to_ctl_tx.read().await.get(&target_run_id) {
                                let _ = ctl_tx.tx.send(crate::state::InternalMsg::VnetPacketForward {
                                    proxy_name: pkt.proxy_name.clone(),
                                    data: pkt.data.clone(),
                                });
                            }
                        }
                    }
                    #[cfg(feature = "vnet")]
                    Ok(FrpMessage::VnetRouteRemove(ref rem)) => {
                        let vn = rem.virtual_net.clone().unwrap_or_default();
                        let mut routes = state.vnet_routes.write().await;
                        routes.retain(|(vn_k, _), (_, name)| !(vn_k == &vn && name == &rem.proxy_name));
                        info!(proxy_name = %rem.proxy_name, "vnet route removed: {}", rem.proxy_name);
                    }
                    Ok(FrpMessage::CloseProxy(cp)) => {
                        if let Some(info) = state.proxy_manager.get(&cp.proxy_name).await {
                            if let Some(port) = info.remote_port {
                                state.used_ports.write().await.remove(&port);
                            }
                            // Clean up STCP sk_index
                            if let Some(ref sk) = info.sk {
                                if !sk.is_empty() {
                                    state.sk_index.write().await.remove(sk);
                                }
                            }
                            // Clean up VHost routes
                            state.vhost_manager.unregister(&cp.proxy_name).await;
                            state.proxy_metrics.remove(&cp.proxy_name).await;
                            #[cfg(feature = "vnet")]
                            {
                                let mut routes = state.vnet_routes.write().await;
                                routes.retain(|_, (_, name)| name != &cp.proxy_name);
                            }
                        }
                        // Stop the listener task
                        if let Some(handle) = listener_handles.remove(&cp.proxy_name) {
                            handle.abort();
                        }
                        state.proxy_manager.remove(&cp.proxy_name).await;
                        info!(proxy_name = %cp.proxy_name, "Proxy closed: {}", cp.proxy_name);
                        // Emit WebSocket event for dashboard subscribers
                        #[cfg(feature = "dashboard")]
                        {
                            let _ = state.event_tx.send(crate::event::ServerEvent::ProxyDown {
                                proxy_name: cp.proxy_name.clone(),
                                run_id: run_id.clone(),
                            });
                        }
                        // Server plugin: close_proxy hook (fire-and-forget)
                        let plugin_state = state.clone();
                        let pn = cp.proxy_name.clone();
                        let rid = run_id.clone();
                        tokio::spawn(async move {
                            let _ = plugin_state.plugin_manager.notify(
                                "close_proxy",
                                serde_json::json!({ "proxy_name": pn, "run_id": rid }),
                            ).await;
                        });
                        // Send CloseProxyResp back to client (Go frp compat)
                        let cpr = FrpMessage::CloseProxyResp(msg::CloseProxyResp {
                            proxy_name: cp.proxy_name.clone(),
                        });
                        let _ = write_ctl_msg(&mut writer, &cpr, v2).await;
                    }
                    Ok(FrpMessage::NatHoleClient(ref client_msg)) => {
                        debug!(
                            transaction_id = %client_msg.transaction_id,
                            mapped_addrs = ?client_msg.mapped_addrs,
                            "Received NatHoleClient from provider: txn={}, addrs={:?}",
                            client_msg.transaction_id, client_msg.mapped_addrs
                        );
                        state.nat_hole.handle_client(client_msg.clone()).await;
                    }
                    Ok(FrpMessage::NatHoleSid(ref sid_msg)) => {
                        debug!(sid = ?sid_msg.sid, "Received NatHoleSid from provider: {:?}", sid_msg.sid);
                        if let Some(ref sid) = sid_msg.sid {
                            let provider_addr = peer.as_ref().map(|a| a.to_string());
                            // Try control-channel path first (Go frp compat).
                            if state.nat_hole.forward_sid_via_ctl(sid, provider_addr.clone()).await {
                                debug!(sid = %sid, "Forwarded NatHoleSid via control channel for {}", sid);
                            } else if let Some(mut writer) = state.nat_hole.take_writer(sid).await {
                                // Fallback: accept-loop writer path
                                let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                    sid: Some(sid.clone()),
                                    provider_addr,
                                });
                                if write_ctl_msg(&mut writer, &forward, v2).await.is_ok() {
                                    debug!(sid = %sid, "Forwarded NatHoleSid to visitor for session {}", sid);
                                } else {
                                    warn!(sid = %sid, "Failed to write NatHoleSid to visitor for session {}", sid);
                                }
                                state.nat_hole.return_writer(sid, writer).await;
                            } else {
                                warn!(sid = %sid, "NatHoleSid for unknown session {}", sid);
                            }
                        }
                    }
                    Ok(FrpMessage::NatHoleResp(ref resp_msg)) => {
                        debug!(transaction_id = %resp_msg.transaction_id, error = ?resp_msg.error, candidate_addrs = ?resp_msg.candidate_addrs, "Received NatHoleResp from provider: txn={}, error={:?}, candidates={:?}",
                            resp_msg.transaction_id, resp_msg.error, resp_msg.candidate_addrs);
                        // Relay provider's NAT hole response to visitor.
                        // Go frp XTCP compat: visitor needs provider's candidate addresses
                        // for TCP simultaneous open.
                        let tid = &resp_msg.transaction_id;
                        // Try control-channel path first.
                        if state.nat_hole.forward_nat_hole_resp_via_ctl(
                            tid,
                            resp_msg.error.clone(),
                            resp_msg.sid.clone(),
                            resp_msg.protocol.clone(),
                            resp_msg.candidate_addrs.clone(),
                            resp_msg.assisted_addrs.clone(),
                        ).await {
                            debug!(tid = %tid, "Forwarded NatHoleResp via control channel for {}", tid);
                        } else if let Some(mut writer) = state.nat_hole.take_writer(tid).await {
                            let forward = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                transaction_id: tid.clone(),
                                error: resp_msg.error.clone(),
                                sid: resp_msg.sid.clone(),
                                protocol: resp_msg.protocol.clone(),
                                candidate_addrs: resp_msg.candidate_addrs.clone(),
                                assisted_addrs: resp_msg.assisted_addrs.clone(),
                                ..Default::default()
                            });
                            let _ = write_ctl_msg(&mut writer, &forward, v2).await;
                            state.nat_hole.return_writer(tid, writer).await;
                        } else {
                            warn!(tid = %tid, "NatHoleResp for unknown session {}", tid);
                        }
                        // Signal the session so handle_nat_hole_visitor wakes up.
                        // Go frp v0.69.1 sends NatHoleResp (type 'm') from provider
                        // with its discovered addresses. We store them as if they
                        // arrived via NatHoleClient so the accept-loop path can
                        // build the combined NatHoleResp for both sides.
                        state.nat_hole.handle_client(msg::NatHoleClient {
                            sid: resp_msg.sid.clone().or_else(|| Some(tid.clone())),
                            transaction_id: tid.clone(),
                            proxy_name: String::new(),
                            protocol: resp_msg.protocol.clone(),
                            mapped_addrs: resp_msg.candidate_addrs.clone(),
                            assisted_addrs: resp_msg.assisted_addrs.clone(),
                            visitor_addr: None,
                        }).await;
                    }
                    Ok(FrpMessage::NatHoleReport(ref report_msg)) => {
                        debug!(sid = ?report_msg.sid, "Received NatHoleReport from provider: {:?}", report_msg.sid);
                        if let Some(ref sid) = report_msg.sid {
                            // Try control-channel path first (Go frp compat).
                            if !state.nat_hole.forward_report_via_ctl(sid).await {
                                // Fallback: accept-loop writer path
                                if let Some(mut writer) = state.nat_hole.take_writer(sid).await {
                                    let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                        sid: Some(sid.clone()),
                                    });
                                    let _ = write_ctl_msg(&mut writer, &forward, v2).await;
                                }
                            }
                            state.nat_hole.complete(sid).await;
                        }
                    }
                    Ok(FrpMessage::Ping(ref ping_msg)) => {
                        // Validate ping auth (Go frp v0.69.1 compat).
                        // Only validate when "HeartBeats" is in additional_auth_scopes.
                        let requires_ping_auth = reloadable
                            .additional_auth_scopes.iter().any(|s| s == "HeartBeats");
                        let ping_auth_result = if !requires_ping_auth {
                            Ok(())
                        } else if let Some(ref verifier) = state.oidc_verifier {
                            let expected_sub = state.oidc_subjects.read().await
                                .get(&run_id).cloned().unwrap_or_default();
                            verifier.verify_ping(
                                ping_msg.privilege_key.as_deref().unwrap_or(""),
                                &expected_sub,
                            ).await
                        } else {
                            reloadable.auth_cfg.validate_login(
                                ping_msg.privilege_key.as_deref(),
                                ping_msg.timestamp,
                            ).map(|_| ())
                        };
                        if let Err(e) = ping_auth_result {
                            warn!(peer = ?peer, error = %e, "Ping auth failed from {:?}: {}", peer, e);
                            let pong = FrpMessage::Pong(msg::Pong { error: Some(err_msg(state.detailed_errors_to_client, e, "ping authentication failed")) });
                            let _ = write_ctl_msg(&mut writer, &pong, v2).await;
                            break;
                        }
                        last_ping = Instant::now();
                        // Fire ping plugin hook (fire-and-forget — don't block control loop)
                        let ping_content = serde_json::json!({
                            "run_id": run_id,
                            "remote_addr": peer.map(|a| a.to_string()).unwrap_or_default(),
                            "timestamp": ping_msg.timestamp,
                        });
                        let plugin_mgr = state.plugin_manager.clone();
                        tokio::spawn(async move {
                            if let Err(e) = plugin_mgr.notify("ping", ping_content).await {
                                debug!("Ping plugin hook: {}", e);
                            }
                        });
                        let pong = FrpMessage::Pong(msg::Pong { error: None });
                        if let Err(e) = write_ctl_msg(&mut writer, &pong, v2).await {
                            warn!(error = %e, "Failed to send pong: {}", e);
                            break;
                        }
                        debug!(peer = ?peer, "Ping from {:?}", peer);
                    }
                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                        debug!(proxy_name = %nvc.proxy_name, "NewVisitorConn on control channel: proxy='{}'", nvc.proxy_name);
                        // Visitor registration on the control connection.
                        // Rust frpc sends NewVisitorConn on control before sending
                        // NatHoleVisitor for XTCP hole punching. Go frps v0.69.1
                        // responds with ReqWorkConn but we send NewVisitorConnResp
                        // with no error — the visitor just needs acknowledgment.
                        let sign_key = nvc.sign_key.unwrap_or_default();
                        let timestamp = nvc.timestamp.unwrap_or(0);

                        // Validate proxy exists and sign_key matches
                        let ok = if let Some(proxy_info) = state.proxy_manager.get(&nvc.proxy_name).await {
                            if let Some(ref sk) = proxy_info.sk {
                                if sk.is_empty() {
                                    true // No sk — allow without auth
                                } else {
                                    let expected = frp_core::auth::generate_token(sk, timestamp);
                                    expected == sign_key
                                }
                            } else {
                                true // No sk configured
                            }
                        } else {
                            false // Proxy not found
                        };

                        if ok {
                            info!(proxy_name = %nvc.proxy_name, "Visitor '{}' registered on control channel for proxy '{}'",
                                nvc.proxy_name, nvc.proxy_name);
                            // Go frps v0.69.1 compat: respond with ReqWorkConn.
                            // Rust frpc control.rs register_visitor() treats
                            // ReqWorkConn as success (just like Go frps does).
                            let rwc = FrpMessage::ReqWorkConn(msg::ReqWorkConn {});
                            let _ = write_ctl_msg(&mut writer, &rwc, v2).await;
                        } else {
                            warn!(proxy_name = %nvc.proxy_name, "NewVisitorConn auth failed on control channel for proxy '{}'",
                                nvc.proxy_name);
                            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                                proxy_name: nvc.proxy_name.clone(),
                                error: Some("auth failed".into()),
                            });
                            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                        }
                    }
                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                        debug!(proxy_name = %nhv.proxy_name, transaction_id = %nhv.transaction_id, "NatHoleVisitor on control channel: proxy='{}', txn='{}'",
                            nhv.proxy_name, nhv.transaction_id);
                        let transaction_id = nhv.transaction_id.clone();
                        let proxy_name = nhv.proxy_name.clone();

                        // Validate proxy exists
                        if state.proxy_manager.get(&proxy_name).await.is_none() {
                            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                transaction_id: transaction_id.clone(),
                                error: Some("proxy not found".into()),
                                ..Default::default()
                            });
                            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                            continue;
                        }

                        // Look up provider run_id and control channel
                        let provider_run_id = match state.proxy_manager.get_run_id(&proxy_name).await {
                            Some(id) => id,
                            None => {
                                let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                    transaction_id: transaction_id.clone(),
                                    error: Some("provider offline".into()),
                                    ..Default::default()
                                });
                                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                continue;
                            }
                        };

                        // Go frp v0.69.1 pre_check compat: validate and return OK,
                        // no session created, no provider notified.
                        if nhv.pre_check && nhv.mapped_addrs.is_none() {
                            debug!(proxy_name = %proxy_name, "NatHoleVisitor pre_check on ctl channel: proxy='{}' OK", proxy_name);
                            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                transaction_id: transaction_id.clone(),
                                error: None,
                                ..Default::default()
                            });
                            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                            continue;
                        }

                        let provider_ctl = {
                            let map = state.run_id_to_ctl_tx.read().await;
                            map.get(&provider_run_id).cloned()
                        };
                        let provider_ctl = match provider_ctl {
                            Some(ctl) => ctl,
                            None => {
                                let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                    transaction_id: transaction_id.clone(),
                                    error: Some("provider disconnected".into()),
                                    ..Default::default()
                                });
                                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                continue;
                            }
                        };

                        // Create session via control-channel path
                        let (session, report_rx) = match state.nat_hole
                            .create_session_with_ctl(
                                transaction_id.clone(),
                                proxy_name.clone(),
                                nhv.clone(),
                                internal_tx.clone(),
                            ).await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(error = %e, "NatHole session creation failed: {}", e);
                                continue;
                            }
                        };

                        // Set up notify channel BEFORE sending to provider
                        let notify_rx = {
                            let mut guard = session.notify_ch.lock().await;
                            let (tx, rx) = oneshot::channel();
                            *guard = Some(tx);
                            rx
                        };

                        // Send NatHoleSid to provider ON A WORK CONNECTION (Go frp compat).
                        if provider_ctl.tx.send(InternalMsg::NatHoleSidOnWorkConn {
                            sid: transaction_id.clone(),
                            proxy_name: proxy_name.clone(),
                        }).is_err() {
                            warn!(provider_run_id = %provider_run_id, "Provider for run_id {} has gone away", provider_run_id);
                            state.nat_hole.remove(&transaction_id).await;
                            continue;
                        }

                        // Spawn task for full Go-compat analysis flow.
                        // Waits for provider's NatHoleClient on control, runs NAT analysis,
                        // and sends NatHoleResp to both sides.
                        let nat_hole = state.nat_hole.clone();
                        let visitor_tx = internal_tx.clone();
                        let provider_tx = provider_ctl.tx.clone();
                        let tid = transaction_id.clone();
                        let visitor_msg = nhv.clone();
                        let _proxy = proxy_name.clone();
                        tokio::spawn(async move {
                            // Wait for provider's NatHoleClient with STUN addresses
                            let client_received = tokio::time::timeout(
                                Duration::from_secs(NAT_HOLE_TIMEOUT),
                                notify_rx,
                            ).await;

                            if client_received.is_err() {
                                warn!(tid = %tid, "NatHole ctl session {}: timeout waiting for provider", tid);
                                nat_hole.remove(&tid).await;
                                return;
                            }

                            let client_msg_opt = {
                                let session_ref = nat_hole.sessions.read().await;
                                if let Some(s) = session_ref.get(&tid) {
                                    s.client_msg.lock().await.take()
                                } else {
                                    None
                                }
                            };
                            let client_msg = match client_msg_opt {
                                Some(m) => m,
                                None => {
                                    warn!(tid = %tid, "NatHole ctl session {}: no client msg", tid);
                                    nat_hole.remove(&tid).await;
                                    return;
                                }
                            };

                            let client_mapped = client_msg.mapped_addrs.unwrap_or_default();
                            let client_assisted = client_msg.assisted_addrs.unwrap_or_default();
                            let visitor_mapped = visitor_msg.mapped_addrs.unwrap_or_default();
                            let visitor_assisted = visitor_msg.assisted_addrs.unwrap_or_default();

                            // Classify NAT features
                            use crate::nathole::classify;
                            use crate::nathole::controller as nathole_ctrl;
                            let v_feature = classify::classify_nat_feature(&visitor_mapped, &[]).ok();
                            let c_feature = classify::classify_nat_feature(&client_mapped, &[]).ok();

                            // Run analysis and build responses
                            let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
                                let key = nathole_ctrl::gen_analysis_key(cf, vf);
                                let (mode, _index, c_behavior, v_behavior) =
                                    nat_hole.analyzer.get_recommend_behaviors(&key, cf, vf);

                                let timeout_ms = c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000;
                                let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
                                let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;

                                let v_resp = nathole_ctrl::build_nat_hole_response(
                                    &tid, &tid, visitor_msg.protocol.clone(), mode,
                                    client_mapped.clone(), client_assisted.clone(),
                                    v_behavior, v_read_timeout, cf.ports_difference,
                                );
                                let c_resp = nathole_ctrl::build_nat_hole_response(
                                    &client_msg.transaction_id, &tid, client_msg.protocol.clone(), mode,
                                    visitor_mapped.clone(), visitor_assisted.clone(),
                                    c_behavior, c_read_timeout, vf.ports_difference,
                                );
                                (v_resp, Some(c_resp))
                            } else {
                                let v_resp = msg::NatHoleResp {
                                    transaction_id: tid.clone(),
                                    error: None,
                                    sid: Some(tid.clone()),
                                    protocol: visitor_msg.protocol.clone(),
                                    candidate_addrs: if client_mapped.is_empty() { None } else { Some(client_mapped) },
                                    assisted_addrs: if client_assisted.is_empty() { None } else { Some(client_assisted) },
                                    ..Default::default()
                                };
                                let c_resp = msg::NatHoleResp {
                                    transaction_id: client_msg.transaction_id.clone(),
                                    error: None,
                                    sid: Some(tid.clone()),
                                    protocol: client_msg.protocol.clone(),
                                    candidate_addrs: if visitor_mapped.is_empty() { None } else { Some(visitor_mapped) },
                                    assisted_addrs: if visitor_assisted.is_empty() { None } else { Some(visitor_assisted) },
                                    ..Default::default()
                                };
                                (v_resp, Some(c_resp))
                            };

                            // Send NatHoleResp to visitor via control channel
                            let _ = visitor_tx.send(InternalMsg::WriteNatHoleResp {
                                transaction_id: v_resp.transaction_id.clone(),
                                error: v_resp.error.clone(),
                                sid: v_resp.sid.clone(),
                                protocol: v_resp.protocol.clone(),
                                candidate_addrs: v_resp.candidate_addrs.clone(),
                                assisted_addrs: v_resp.assisted_addrs.clone(),
                            });

                            // Send NatHoleResp to provider via control channel
                            if let Some(ref cr) = c_resp {
                                let _ = provider_tx.send(InternalMsg::WriteNatHoleResp {
                                    transaction_id: cr.transaction_id.clone(),
                                    error: cr.error.clone(),
                                    sid: cr.sid.clone(),
                                    protocol: cr.protocol.clone(),
                                    candidate_addrs: cr.candidate_addrs.clone(),
                                    assisted_addrs: cr.assisted_addrs.clone(),
                                });
                            }

                            // Wait for report
                            match tokio::time::timeout(Duration::from_secs(30), report_rx).await {
                                Ok(Ok(_)) => debug!(tid = %tid, "NatHole ctl session {}: completed", tid),
                                Ok(Err(_)) | Err(_) => {
                                    debug!(tid = %tid, "NatHole ctl session {}: cleanup", tid);
                                    nat_hole.remove(&tid).await;
                                }
                            }
                        });
                    }
                    Ok(_) => {
                        debug!(peer = ?peer, "Unhandled message from {:?}", peer);
                    }
                    Err(e) => {
                        info!(peer = ?peer, error = %e, run_id = %run_id, "Control connection {:?} closed: {} (run_id={})", peer, e, run_id);
                        break;
                    }
                }
            }
            _ = ping_tick.tick() => {
                // Send periodic Ping to keep the control connection alive.
                // Go frpc expects server Pings; without them it times out and reconnects.
                let ping = FrpMessage::Ping(msg::Ping {
                    timestamp: Some(std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64),
                    privilege_key: Some(reloadable.auth_cfg.token.clone()),
                });
                if let Err(e) = write_ctl_msg(&mut writer, &ping, v2).await {
                    warn!(peer = ?peer, error = %e, "Failed to send Ping: {}", e);
                    break;
                }
                debug!(peer = ?peer, "Sent Ping to {:?}", peer);
                last_ping = Instant::now();
            }
            _ = state.shutdown_token.cancelled() => {
                info!(run_id = %run_id, "Graceful shutdown: draining control handler for {}", run_id);
                break;
            }
        }
    }

    // Cleanup
    for (_, handle) in listener_handles.drain() {
        handle.abort();
    }
    // Emit ProxyDown for all proxies owned by this client (before removing them)
    #[cfg(feature = "dashboard")]
    {
        let proxies = state.proxy_manager.list_client(&run_id).await;
        for p in &proxies {
            let _ = state.event_tx.send(crate::event::ServerEvent::ProxyDown {
                proxy_name: p.name.clone(),
                run_id: run_id.clone(),
            });
        }
    }
    // Emit ClientDisconnected
    #[cfg(feature = "dashboard")]
    {
        let _ = state.event_tx.send(crate::event::ServerEvent::ClientDisconnected {
            run_id: run_id.clone(),
        });
    }
    proxy_ops::unregister_control(&state, &run_id).await;
    state.proxy_manager.remove_client(&run_id).await;
    info!(run_id = %run_id, "Control connection {} removed", run_id);
}
