mod bridge;
mod proxy_ops;

use proxy_ops::err_msg;
use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::VecDeque;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};
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
    info!("New control connection from {:?}", peer);

    // --- Authenticate ---
    let oidc_subject: Option<String> = if let Some(ref verifier) = state.oidc_verifier {
        let token = login.privilege_key.as_deref().unwrap_or("");
        match verifier.verify_login(token).await {
            Ok(oidc_token) => {
                info!("OIDC login verified: subject={}", oidc_token.subject);
                Some(oidc_token.subject)
            }
            Err(e) => {
                warn!("OIDC auth failed for {:?}: {}", peer, e);
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
            warn!("Authentication failed for {:?}: {}", peer, e);
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

    let run_id = login.run_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!("Client {:?} logged in with run_id: {}", peer, run_id);

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
        warn!("Login for run_id {} rejected by server plugin: {}", run_id, reason);
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
            warn!("Duplicate run_id {}: shutting down old control handler", run_id);
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
        let additional_auth_scopes = state.reloadable.read().unwrap().additional_auth_scopes.clone();
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some(run_id.clone()),
            error: None,
            server_additional_auth_scopes: if additional_auth_scopes.is_empty() { None } else { Some(additional_auth_scopes) },
        });
        if let Err(e) = write_ctl_msg(&mut stream, &resp, v2).await {
            warn!("Failed to send login response to {:?}: {}", peer, e);
            proxy_ops::unregister_control(&state, &run_id).await;
            return;
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
        let token = state.reloadable.read().unwrap().auth_cfg.token.clone();
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
                        warn!("Failed to create AEAD stream for {:?}: {}", peer, e);
                        proxy_ops::unregister_control(&state, &run_id).await;
                        return;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to derive AEAD keys for {:?}: {}", peer, e);
                proxy_ops::unregister_control(&state, &run_id).await;
                return;
            }
        }
    } else {
        // V1 or plain V2: wrap in AES-128-CFB
        let enc_key = encryption::derive_key(&state.reloadable.read().unwrap().auth_cfg.token);
        let cipher = frp_core::cipher_stream::CipherStream::new(Box::new(stream), enc_key);
        let (r, w) = tokio::io::split(cipher);
        (Box::new(r), Box::new(w))
    };

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

    // --- Main select loop ---
    loop {
        // Expire stale pending requests
        while let Some(req) = pending_requests.front() {
            if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                let expired = pending_requests.pop_front().unwrap();
                debug!("Pending request for proxy '{}' timed out after {:?}", expired.proxy_name, PENDING_REQUEST_TIMEOUT);
            } else {
                break;
            }
        }

        // Heartbeat check: if no ping in heartbeat_timeout, disconnect
        let hb_timeout = Duration::from_secs(state.heartbeat_timeout.max(1) as u64);
        if last_ping.elapsed() > hb_timeout {
            warn!("Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, hb_timeout);
            break;
        }

        tokio::select! {
            biased;

            // Prefer internal messages to reduce latency for proxy connections
            internal = internal_rx.recv() => {
                match internal {
                    Some(InternalMsg::NewWorkConn(mut stream)) => {
                        debug!("Got work conn for run_id {}", run_id);
                        // Expire stale pending NatHoleSid entries first.
                        while let Some((_, _, ts)) = pending_nat_hole_sids.front() {
                            if ts.elapsed() > PENDING_REQUEST_TIMEOUT {
                                let (sid, _pn, _) = pending_nat_hole_sids.pop_front().unwrap();
                                debug!("Pending NatHoleSid {} timed out", sid);
                            } else {
                                break;
                            }
                        }
                        // Check NatHoleSid delivery first (Go frp XTCP compat).
                        // Pending sids take priority — they unblock waiting visitors.
                        if let Some((sid, proxy_name, _ts)) = pending_nat_hole_sids.pop_front() {
                            debug!("Delivering pending NatHoleSid {} for {} to provider", sid, proxy_name);
                            // Look up proxy flags for StartWorkConn (encryption/compression propagation)
                            let (use_enc, use_comp) = state.proxy_manager.get(&proxy_name).await
                                .map(|p| (p.use_encryption, p.use_compression))
                                .unwrap_or((false, false));
                            // Go frp v0.69.1 compat: StartWorkConn first to route the
                            // work connection to the XTCP proxy handler.
                            let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
                                proxy_name: proxy_name.clone(),
                                src_addr: None, src_port: None,
                                dst_addr: None, dst_port: None, error: None,
                                use_encryption: if use_enc { Some(true) } else { None },
                                use_compression: if use_comp { Some(true) } else { None },
                            });
                            let _ = write_ctl_msg(&mut stream, &swc, v2).await;
                            let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                sid: Some(sid.clone()),
                                provider_addr: None,
                            });
                            if let Err(e) = write_ctl_msg(&mut stream, &forward, v2).await {
                                warn!("Failed to send pending NatHoleSid: {}", e);
                            }
                            // Work conn consumed for XTCP notification — drop it.
                        } else {
                            // Expire stale pending UDP requests first
                            while let Some((_, ts)) = pending_udp.front() {
                                if ts.elapsed() > PENDING_REQUEST_TIMEOUT {
                                    let (pn, _) = pending_udp.pop_front().unwrap();
                                    debug!("Pending UDP work conn for '{}' timed out", pn);
                                } else {
                                    break;
                                }
                            }
                            // Check if a UDP proxy needs this work connection
                            if let Some((proxy_name, _)) = pending_udp.pop_front() {
                                info!("Assigning work conn to UDP proxy '{}'", proxy_name);
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
                                    let enc_key = state.reloadable.read().unwrap().encryption_key;
                                    bridge::assign_work_to_proxy(stream, req, enc_key, state.clone(), v2).await;
                                } else if work_pool.len() < pool_cap {
                                    work_pool.push_back(stream);
                                    debug!("Work conn pooled for {} (pool size: {}/{})", run_id, work_pool.len(), pool_cap);
                                } else {
                                    debug!("Work pool full for {} ({}/{}), dropping work conn", run_id, work_pool.len(), pool_cap);
                                }
                            }
                        }
                    }
                    Some(InternalMsg::VisitorConn { proxy_name, visitor_conn }) => {
                        debug!("STCP visitor conn for proxy {} on run_id {}", proxy_name, run_id);
                        let (enc, comp, response_headers, proxy_type) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let e = p.as_ref().map(|p| p.use_encryption).unwrap_or(false);
                            let c = p.as_ref().map(|p| p.use_compression).unwrap_or(false);
                            let rh = p.as_ref().map(|p| p.response_headers.clone()).unwrap_or_default();
                            let pt = p.as_ref().map(|p| p.proxy_type.clone()).unwrap_or_default();
                            (e, c, rh, pt)
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            let enc_key = state.reloadable.read().unwrap().encryption_key;
                            bridge::assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn: visitor_conn, pre_read: Vec::new(), use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type }, enc_key, state.clone(), v2).await;
                        } else {
                            debug!("No pooled work conn for STCP, sending ReqWorkConn");
                            if let Err(e) = write_ctl_msg(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn: visitor_conn, pre_read: Vec::new(), use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type });
                        }
                    }
                    Some(InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }) => {
                        debug!("User conn for proxy {} on run_id {}", proxy_name, run_id);
                        // Group load balancing: if proxy belongs to a group,
                        // select a backend (possibly on a different run_id).
                        let (target_proxy, target_run_id) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let group = p.as_ref().and_then(|p| p.group.clone()).filter(|g| !g.is_empty());
                            let group_key = p.as_ref().and_then(|p| p.group_key.clone()).unwrap_or_default();
                            if let Some(ref group_name) = group {
                                if let Some(backend) = state.proxy_manager.select_group_backend(group_name, &group_key).await {
                                    let backend_run_id = state.proxy_manager.get_run_id(&backend).await.unwrap_or_default();
                                    info!("Group LB: {} -> backend {} (run_id {})", proxy_name, backend, backend_run_id);
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
                            warn!("Group backend run_id {} not found for proxy {}", target_run_id, target_proxy);
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
                            let enc_key = state.reloadable.read().unwrap().encryption_key;
                            bridge::assign_work_to_proxy(work_conn, PendingRequest { proxy_name: target_proxy, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type }, enc_key, state.clone(), v2).await;
                        } else {
                            debug!("No pooled work conn, sending ReqWorkConn for {}", target_proxy);
                            if let Err(e) = write_ctl_msg(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name: target_proxy, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now(), response_headers, proxy_type });
                        }
                    }
                    Some(InternalMsg::UdpNeedsWorkConn { proxy_name }) => {
                        debug!("UDP proxy '{}' needs work connection", proxy_name);
                        if let Err(e) = write_ctl_msg(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                            warn!("Failed to send ReqWorkConn for UDP: {}", e);
                            break;
                        }
                        pending_udp.push_back((proxy_name, Instant::now()));
                    }
                    Some(InternalMsg::WriteNatHoleSid { sid, provider_addr }) => {
                        debug!("Writing NatHoleSid to visitor via control channel for {}", sid);
                        let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                            sid: Some(sid),
                            provider_addr,
                        });
                        if let Err(e) = write_ctl_msg(&mut writer, &forward, v2).await {
                            warn!("Failed to write NatHoleSid to visitor: {}", e);
                        }
                    }
                    Some(InternalMsg::WriteNatHoleResp { transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs }) => {
                        debug!("Writing NatHoleResp to visitor via control channel for {}", transaction_id);
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
                            warn!("Failed to write NatHoleResp to visitor: {}", e);
                        }
                    }
                    Some(InternalMsg::WriteNatHoleReport { sid }) => {
                        debug!("Writing NatHoleReport to visitor via control channel for {}", sid);
                        let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
                            sid: Some(sid),
                        });
                        if let Err(e) = write_ctl_msg(&mut writer, &forward, v2).await {
                            warn!("Failed to write NatHoleReport to visitor: {}", e);
                        }
                    }
                    Some(InternalMsg::NatHoleSidOnWorkConn { sid, proxy_name }) => {
                        debug!("Sending NatHoleSid {} for proxy {} to provider on work conn", sid, proxy_name);
                        if let Some(mut work_conn) = work_pool.pop_front() {
                            // Look up proxy flags for StartWorkConn (encryption/compression propagation)
                            let (use_enc, use_comp) = state.proxy_manager.get(&proxy_name).await
                                .map(|p| (p.use_encryption, p.use_compression))
                                .unwrap_or((false, false));
                            // Go frp v0.69.1 compat: write StartWorkConn FIRST to route
                            // the work connection to the XTCP proxy handler.
                            let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
                                proxy_name: proxy_name.clone(),
                                src_addr: None, src_port: None,
                                dst_addr: None, dst_port: None, error: None,
                                use_encryption: if use_enc { Some(true) } else { None },
                                use_compression: if use_comp { Some(true) } else { None },
                            });
                            let _ = write_ctl_msg(&mut work_conn, &swc, v2).await;
                            let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                sid: Some(sid.clone()),
                                provider_addr: None,
                            });
                            if let Err(e) = write_ctl_msg(&mut work_conn, &forward, v2).await {
                                warn!("Failed to send NatHoleSid on work conn: {}", e);
                            } else {
                                debug!("Sent StartWorkConn+NatHoleSid {} to provider on work conn", sid);
                            }
                            // Connection consumed — Go frp doesn't reuse after NatHoleSid.
                            drop(work_conn);
                        } else {
                            // No pooled work conn — request one, queue sid.
                            debug!("No pooled work conn for NatHoleSid {}, requesting via ReqWorkConn", sid);
                            if let Err(e) = write_ctl_msg(&mut writer,
                                &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!("Failed to send ReqWorkConn for NatHoleSid: {}", e);
                            }
                            pending_nat_hole_sids.push_back((sid, proxy_name, Instant::now()));
                        }
                    }
                    Some(InternalMsg::Shutdown) => {
                        warn!("Shutdown received for run_id {} (replaced by new control connection)", run_id);
                        break;
                    }
                    None => {
                        info!("Control channel closed for {:?}", peer);
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
                    match read_ctl_msg(&mut io, v2).await {
                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                            let stream_run_id = nwc.run_id.as_deref().unwrap_or("");
                            if stream_run_id != run_id {
                                debug!("Yamux work conn run_id mismatch: expected {run_id}, got {stream_run_id}");
                                continue;
                            }
                        }
                        Ok(other) => {
                            debug!("Unexpected yamux stream message for {run_id}: {:?}", other.v1_type_byte());
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to read from yamux stream for {run_id}: {e}");
                            continue;
                        }
                    }
                    debug!("Yamux work conn for run_id {}", run_id);
                    while let Some(req) = pending_requests.front() {
                        if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                            pending_requests.pop_front();
                        } else {
                            break;
                        }
                    }
                    if let Some(req) = pending_requests.pop_front() {
                        let enc_key = state.reloadable.read().unwrap().encryption_key;
                        bridge::assign_work_to_proxy(io, req, enc_key, state.clone(), v2).await;
                    } else if work_pool.len() < pool_cap {
                        work_pool.push_back(io);
                        debug!("Yamux work conn pooled for {} (pool size: {}/{})", run_id, work_pool.len(), pool_cap);
                    } else {
                        debug!("Work pool full for {} ({}/{}), dropping yamux work conn", run_id, work_pool.len(), pool_cap);
                    }
                }
            }

            msg = read_ctl_msg(&mut reader, v2) => {
                match msg {
                    Ok(FrpMessage::UDPPacket(up)) => {
                        debug!("UDPPacket from client: {} bytes to {:?}", up.content.len(), up.remote_addr);
                        // Forward via the proxy's UDP socket (bidirectional NAT, Go frp compat).
                        let local_addr_str = up.local_addr.as_ref().map(|a| a.to_string()).unwrap_or_default();
                        let proxy_name = udp_local_to_proxy.get(&local_addr_str).cloned();
                        // Cache local_addr → proxy_name mapping from incoming packets
                        if !local_addr_str.is_empty() && !udp_local_to_proxy.contains_key(&local_addr_str) {
                            let fallback_pn = proxy_name
                                .clone()
                                .or_else(|| udp_sockets.keys().next().cloned());
                            if let Some(ref pn) = fallback_pn {
                                udp_local_to_proxy.insert(local_addr_str.clone(), pn.clone());
                            }
                        }
                        // Decrypt/decompress if the proxy requires it
                        let mut payload = up.content.clone();
                        if let Some(ref pn) = proxy_name {
                            if let Some(proxy_info) = state.proxy_manager.get(pn.as_str()).await {
                                if proxy_info.use_encryption {
                                    if let Ok(decrypted) = encryption::decrypt(&payload, &state.reloadable.read().unwrap().encryption_key) {
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
                            warn!("No UDP socket for proxy, dropping {} bytes", up.content.len());
                        }
                    }
                    Ok(FrpMessage::NewProxy(np)) => {
                        proxy_ops::handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx, &mut listener_handles, &mut udp_sockets, &mut udp_local_to_proxy, v2).await;
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
                        }
                        // Stop the listener task
                        if let Some(handle) = listener_handles.remove(&cp.proxy_name) {
                            handle.abort();
                        }
                        state.proxy_manager.remove(&cp.proxy_name).await;
                        info!("Proxy closed: {}", cp.proxy_name);
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
                            "Received NatHoleClient from provider: txn={}, addrs={:?}",
                            client_msg.transaction_id, client_msg.mapped_addrs
                        );
                        state.nat_hole.handle_client(client_msg.clone()).await;
                    }
                    Ok(FrpMessage::NatHoleSid(ref sid_msg)) => {
                        debug!("Received NatHoleSid from provider: {:?}", sid_msg.sid);
                        if let Some(ref sid) = sid_msg.sid {
                            let provider_addr = peer.as_ref().map(|a| a.to_string());
                            // Try control-channel path first (Go frp compat).
                            if state.nat_hole.forward_sid_via_ctl(sid, provider_addr.clone()).await {
                                debug!("Forwarded NatHoleSid via control channel for {}", sid);
                            } else if let Some(mut writer) = state.nat_hole.take_writer(sid).await {
                                // Fallback: accept-loop writer path
                                let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                    sid: Some(sid.clone()),
                                    provider_addr,
                                });
                                if write_ctl_msg(&mut writer, &forward, v2).await.is_ok() {
                                    debug!("Forwarded NatHoleSid to visitor for session {}", sid);
                                } else {
                                    warn!("Failed to write NatHoleSid to visitor for session {}", sid);
                                }
                                state.nat_hole.return_writer(sid, writer).await;
                            } else {
                                warn!("NatHoleSid for unknown session {}", sid);
                            }
                        }
                    }
                    Ok(FrpMessage::NatHoleResp(ref resp_msg)) => {
                        debug!("Received NatHoleResp from provider: txn={}, error={:?}, candidates={:?}",
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
                            debug!("Forwarded NatHoleResp via control channel for {}", tid);
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
                            warn!("NatHoleResp for unknown session {}", tid);
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
                        debug!("Received NatHoleReport from provider: {:?}", report_msg.sid);
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
                        let requires_ping_auth = state.reloadable.read().unwrap()
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
                            state.reloadable.read().unwrap().auth_cfg.validate_login(
                                ping_msg.privilege_key.as_deref(),
                                ping_msg.timestamp,
                            ).map(|_| ())
                        };
                        if let Err(e) = ping_auth_result {
                            warn!("Ping auth failed from {:?}: {}", peer, e);
                            let pong = FrpMessage::Pong(msg::Pong { error: Some(err_msg(state.detailed_errors_to_client, e, "ping authentication failed")) });
                            let _ = write_ctl_msg(&mut writer, &pong, v2).await;
                            break;
                        }
                        last_ping = Instant::now();
                        let pong = FrpMessage::Pong(msg::Pong { error: None });
                        if let Err(e) = write_ctl_msg(&mut writer, &pong, v2).await {
                            warn!("Failed to send pong: {}", e);
                            break;
                        }
                        debug!("Ping from {:?}", peer);
                    }
                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                        debug!("NewVisitorConn on control channel: proxy='{}'", nvc.proxy_name);
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
                            info!("Visitor '{}' registered on control channel for proxy '{}'",
                                nvc.proxy_name, nvc.proxy_name);
                            // Go frps v0.69.1 compat: respond with ReqWorkConn.
                            // Rust frpc control.rs register_visitor() treats
                            // ReqWorkConn as success (just like Go frps does).
                            let rwc = FrpMessage::ReqWorkConn(msg::ReqWorkConn {});
                            let _ = write_ctl_msg(&mut writer, &rwc, v2).await;
                        } else {
                            warn!("NewVisitorConn auth failed on control channel for proxy '{}'",
                                nvc.proxy_name);
                            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                                proxy_name: nvc.proxy_name.clone(),
                                error: Some("auth failed".into()),
                            });
                            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                        }
                    }
                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                        debug!("NatHoleVisitor on control channel: proxy='{}', txn='{}'",
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
                            debug!("NatHoleVisitor pre_check on ctl channel: proxy='{}' OK", proxy_name);
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
                                warn!("NatHole session creation failed: {}", e);
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
                            warn!("Provider for run_id {} has gone away", provider_run_id);
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
                                warn!("NatHole ctl session {}: timeout waiting for provider", tid);
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
                                    warn!("NatHole ctl session {}: no client msg", tid);
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
                                    nat_hole.analyzer.get_recommand_behaviors(&key, cf, vf);

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
                                Ok(Ok(_)) => debug!("NatHole ctl session {}: completed", tid),
                                Ok(Err(_)) | Err(_) => {
                                    debug!("NatHole ctl session {}: cleanup", tid);
                                    nat_hole.remove(&tid).await;
                                }
                            }
                        });
                    }
                    Ok(_) => {
                        debug!("Unhandled message from {:?}", peer);
                    }
                    Err(e) => {
                        info!("Control connection {:?} closed: {}", peer, e);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    for (_, handle) in listener_handles.drain() {
        handle.abort();
    }
    proxy_ops::unregister_control(&state, &run_id).await;
    state.proxy_manager.remove_client(&run_id).await;
    info!("Control connection {} removed", run_id);
}
