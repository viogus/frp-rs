mod bridge;
mod login;
mod nathole;
mod pool;
mod proxy_ops;

use proxy_ops::err_msg;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, instrument, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;
use frp_core::protocol::{read_msg_v1, read_msg_v2, write_msg_v1, write_msg_v2};

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

use crate::service::{AppState, InternalMsg};

// ---- State containers for handle_control ----

/// Mutable local state owned by the control session. Passed by `&mut` to
/// all handler functions. Single-task — no synchronisation needed.
pub(crate) struct ControlState {
    pub shutting_down: bool,
    pub work_pool: VecDeque<pool::PoolEntry>,
    pub pending_requests: VecDeque<pool::PendingRequest>,
    pub pending_udp: VecDeque<(String, Instant)>,
    /// (sid, proxy_name, created_at) triples queued while waiting for a work connection.
    pub pending_nat_hole_sids: VecDeque<(String, String, Instant)>,
    pub listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    pub udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    pub udp_local_to_proxy: std::collections::HashMap<String, String>,
    pub last_ping: Instant,
}

/// Immutable/shared context passed to every handler. Owns its data —
/// no lifetimes needed. Writer/reader are passed separately as generic
/// params to handlers that need them.
pub(crate) struct ControlContext {
    pub state: std::sync::Arc<crate::state::AppState>,
    pub pool_stats: std::sync::Arc<crate::state::PoolStats>,
    pub reloadable: crate::state::ReloadableState,
    pub v2: bool,
    pub run_id: String,
    pub pool_cap: usize,
    #[allow(dead_code)]
    pub internal_tx: tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
    pub peer: Option<std::net::SocketAddr>,
}

/// Handle a control connection from a frpc client.
/// The login message has already been consumed from the stream.
/// `peer` is passed separately because generic stream types don't have peer_addr().
#[instrument(skip(stream, state, incoming, crypto_ctx, login), fields(run_id = %login.run_id.clone().unwrap_or_default(), peer = ?peer))]
pub async fn handle_control<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(peer = ?peer, "New control connection from {:?}", peer);
    // 1. Authenticate and set up per-client state (login.rs)
    let (
        mut ctx,
        ctl,
        internal_tx,
        mut internal_rx,
        mut reader,
        mut writer,
        mut incoming,
        mut ping_tick,
    ) = match login::authenticate(stream, &login, state, peer, incoming, v2, crypto_ctx).await {
        Ok(tuple) => tuple,
        Err(()) => return,
    };

    // Convenience bindings for the main loop
    let state = ctx.state.clone();
    let run_id = ctx.run_id.clone();
    let pool_cap = ctx.pool_cap;
    let pool_stats = ctx.pool_stats.clone();
    let v2 = ctx.v2;
    let reloadable = ctx.reloadable.clone();
    let peer = ctx.peer;
    let login_user = login.user.clone().unwrap_or_default();

    let mut ctl = ctl;

    // --- Main select loop ---
    loop {
        // Expire stale pending requests
        while let Some(req) = ctl.pending_requests.front() {
            if req.created_at.elapsed() > pool::PENDING_REQUEST_TIMEOUT {
                let expired = ctl.pending_requests.pop_front().unwrap();
                pool_stats
                    .pending_requests
                    .store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                debug!(proxy_name = %expired.proxy_name, timeout = ?pool::PENDING_REQUEST_TIMEOUT, "Pending request for proxy '{}' timed out after {:?}", expired.proxy_name, pool::PENDING_REQUEST_TIMEOUT);
            } else {
                break;
            }
        }

        // Expire idle pooled connections (if timeout configured)
        let pool_idle_timeout = state.pool.idle_timeout;
        if pool_idle_timeout > Duration::ZERO {
            while let Some(entry) = ctl.work_pool.front() {
                if entry.pooled_at.elapsed() >= pool_idle_timeout {
                    ctl.work_pool.pop_front();
                    pool_stats
                        .pool_size
                        .store(ctl.work_pool.len() as i64, Ordering::Relaxed);
                    debug!(run_id = %run_id, idle_timeout = ?pool_idle_timeout, "Idle work conn expired after {:?}", pool_idle_timeout);
                } else {
                    break;
                }
            }
        }

        // Heartbeat check: if no ping in heartbeat_timeout, disconnect.
        // When heartbeat_timeout <= 0, heartbeat checking is disabled
        // (matching Go frp v0.70.0 behaviour when tcpMux is enabled).
        if state.heartbeat_timeout > 0 {
            let hb_timeout = Duration::from_secs(state.heartbeat_timeout as u64);
            if ctl.last_ping.elapsed() > hb_timeout {
                warn!(peer = ?peer, hb_timeout = ?hb_timeout, "Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, hb_timeout);
                break;
            }
        }

        tokio::select! {
            biased;

            // Prefer internal messages to reduce latency for proxy connections
            internal = internal_rx.recv() => {
                match internal {
                    Some(InternalMsg::NewWorkConn(stream)) => {
                        if pool::handle_new_work_conn(&mut ctx, &mut ctl, &mut writer, stream).await.is_err() {
                            break;
                        }
                    }
                    Some(InternalMsg::VisitorConn { proxy_name, visitor_conn }) => {
                        if pool::handle_visitor_conn(&mut ctx, &mut ctl, &mut writer, proxy_name, visitor_conn).await.is_err() {
                            break;
                        }
                    }
                    Some(InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }) => {
                        if pool::handle_proxy_user_conn(&mut ctx, &mut ctl, &mut writer, proxy_name, user_conn, pre_read).await.is_err() {
                            break;
                        }
                    }
                    Some(InternalMsg::UdpNeedsWorkConn { proxy_name }) => {
                        if pool::handle_udp_work_conn(&mut ctx, &mut ctl, &mut writer, proxy_name).await.is_err() {
                            break;
                        }
                    }
                    Some(InternalMsg::WriteNatHoleSid { sid, provider_addr }) => {
                        nathole::handle_write_sid(&ctx, &mut ctl, &mut writer, sid, provider_addr).await;
                    }
                    Some(InternalMsg::WriteNatHoleResp { transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs }) => {
                        nathole::handle_write_resp(&ctx, &mut ctl, &mut writer, transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs).await;
                    }
                    Some(InternalMsg::WriteNatHoleReport { sid }) => {
                        nathole::handle_write_report(&ctx, &mut ctl, &mut writer, sid).await;
                    }
                    Some(InternalMsg::NatHoleSidOnWorkConn { sid, proxy_name }) => {
                        if nathole::handle_sid_on_work_conn(&mut ctx, &mut ctl, &mut writer, sid, proxy_name).await.is_err() {
                            break;
                        }
                    }
                    Some(InternalMsg::Shutdown) => {
                        warn!(run_id = %run_id, "Shutdown received for run_id {} (replaced by new control connection)", run_id);
                        ctl.shutting_down = true;
                        break;
                    }
                    #[cfg(feature = "vnet")]
                    Some(InternalMsg::VnetPacketForward { proxy_name, data }) => {
                        nathole::handle_vnet_packet_forward(&ctx, &mut ctl, &mut writer, proxy_name, data).await;
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
                    while let Some(req) = ctl.pending_requests.front() {
                        if req.created_at.elapsed() > pool::PENDING_REQUEST_TIMEOUT {
                            ctl.pending_requests.pop_front();
                            pool_stats.pending_requests.store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                        } else {
                            break;
                        }
                    }
                    if let Some(req) = ctl.pending_requests.pop_front() {
                        state.pool.hits.fetch_add(1, Ordering::Relaxed);
                        pool_stats.pending_requests.store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                        pool_stats.pool_size.store(ctl.work_pool.len() as i64, Ordering::Relaxed);
                        let enc_key = reloadable.encryption_key;
                        bridge::assign_work_to_proxy(io, req, enc_key, state.clone(), v2).await;
                    } else if ctl.work_pool.len() < pool_cap {
                        ctl.work_pool.push_back(pool::PoolEntry { conn: io, pooled_at: Instant::now() });
                        pool_stats.pool_size.store(ctl.work_pool.len() as i64, Ordering::Relaxed);
                        debug!(run_id = %run_id, pool_size = %ctl.work_pool.len(), pool_cap = %pool_cap, "Yamux work conn pooled for {} (pool size: {}/{})", run_id, ctl.work_pool.len(), pool_cap);
                    } else {
                        state.pool.drops.fetch_add(1, Ordering::Relaxed);
                        debug!(run_id = %run_id, pool_size = %ctl.work_pool.len(), pool_cap = %pool_cap, "Work pool full for {} ({}/{}), dropping yamux work conn", run_id, ctl.work_pool.len(), pool_cap);
                    }
                }
            }

            msg = read_ctl_msg(&mut reader, v2) => {
                match msg {
                    Ok(FrpMessage::UDPPacket(up)) => {
                        debug!(byte_count = %up.content.len(), remote_addr = ?up.remote_addr, "UDPPacket from client: {} bytes to {:?}", up.content.len(), up.remote_addr);
                        // Forward via the proxy's UDP socket (bidirectional NAT, Go frp compat).
                        let local_addr_str = up.local_addr.as_ref().map(|a| a.to_string()).unwrap_or_default();
                        let proxy_name = ctl.udp_local_to_proxy.get(&local_addr_str).cloned();
                        // Cache local_addr → proxy_name mapping from incoming packets
                        if !local_addr_str.is_empty() && !ctl.udp_local_to_proxy.contains_key(&local_addr_str) {
                            let fallback_pn = proxy_name
                                .clone()
                                .or_else(|| {
                                    let first = ctl.udp_sockets.keys().next().cloned();
                                    if first.is_some() {
                                        tracing::debug!(
                                            local_addr = %local_addr_str,
                                            "UDP packet local_addr→proxy_name not cached, falling back to first available socket"
                                        );
                                    }
                                    first
                                });
                            if let Some(ref pn) = fallback_pn {
                                ctl.udp_local_to_proxy.insert(local_addr_str.clone(), pn.clone());
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
                            .and_then(|pn| ctl.udp_sockets.get(pn.as_str()))
                            .or_else(|| ctl.udp_sockets.iter().next().map(|(_, s)| s));
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
                        proxy_ops::handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx, &mut ctl.listener_handles, &mut ctl.udp_sockets, &mut ctl.udp_local_to_proxy, v2).await;
                    }
                    #[cfg(feature = "vnet")]
                    Ok(FrpMessage::VnetRouteAdvertise(adv)) => {
                        nathole::handle_vnet_route_advertise(&ctx, &mut ctl, &mut writer, adv).await;
                    }
                    #[cfg(feature = "vnet")]
                    Ok(FrpMessage::VnetPacket(pkt)) => {
                        nathole::handle_vnet_packet(&ctx, &mut ctl, &mut writer, pkt).await;
                    }
                    #[cfg(feature = "vnet")]
                    Ok(FrpMessage::VnetRouteRemove(rem)) => {
                        nathole::handle_vnet_route_remove(&ctx, &mut ctl, &mut writer, rem).await;
                    }
                    Ok(FrpMessage::CloseProxy(cp)) => {
                        // Verify the proxy belongs to this client
                        let owner_run_id = state.proxy_manager.get_run_id(&cp.proxy_name).await;
                        if owner_run_id.as_ref() != Some(&run_id) {
                            warn!(
                                proxy_name = %cp.proxy_name,
                                run_id = %run_id,
                                owner = ?owner_run_id,
                                "CloseProxy rejected: proxy belongs to different client"
                            );
                            continue;
                        }
                        if let Some(info) = state.proxy_manager.get(&cp.proxy_name).await {
                            if let Some(port) = info.remote_port {
                                state.used_ports.write().await.remove(&port);
                            }
                            // Clean up STCP sk_index (indexed by proxy_name)
                            if let Some(key) = info.sk_index_key() {
                                state.xtcp.sk_index.write().await.remove(key);
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
                        if let Some(handle) = ctl.listener_handles.remove(&cp.proxy_name) {
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
                        // Note: Go frp does not send CloseProxyResp (type 7/19 is
                        // Rust-only). frp-rs client handles both CloseProxy
                        // and CloseProxyResp identically and already cleans up
                        // health_cancels immediately after sending CloseProxy,
                        // so no response is needed here.
                    }
                    Ok(FrpMessage::NatHoleClient(client_msg)) => {
                        nathole::handle_nat_hole_client(&ctx, &mut ctl, &mut writer, client_msg).await;
                    }
                    Ok(FrpMessage::NatHoleSid(sid_msg)) => {
                        nathole::handle_nat_hole_sid(&ctx, &mut ctl, &mut writer, sid_msg).await;
                    }
                    Ok(FrpMessage::NatHoleResp(resp_msg)) => {
                        nathole::handle_nat_hole_resp(&ctx, &mut ctl, &mut writer, resp_msg).await;
                    }
                    Ok(FrpMessage::NatHoleReport(report_msg)) => {
                        nathole::handle_nat_hole_report(&ctx, &mut ctl, &mut writer, report_msg).await;
                    }
                    Ok(FrpMessage::Ping(ref ping_msg)) => {
                        // Validate ping auth (Go frp v0.69.1 compat).
                        // Only validate when "HeartBeats" is in additional_auth_scopes.
                        let requires_ping_auth = reloadable
                            .additional_auth_scopes.iter().any(|s| s == "HeartBeats");
                        let ping_auth_result = if !requires_ping_auth {
                            Ok(())
                        } else if let Some(ref verifier) = state.oidc.verifier {
                            let expected_sub = state.oidc.subjects.read().await
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
                        ctl.last_ping = Instant::now();
                        // Fire ping plugin hook (fire-and-forget — don't block control loop)
                        let ping_content = serde_json::json!({
                            "run_id": run_id,
                            "remote_addr": peer.map(|a| a.to_string()).unwrap_or_default(),
                            "timestamp": ping_msg.timestamp,
                        });
                        let plugin_mgr = state.plugin_manager.clone();
                        tokio::spawn(async move {
                            if let Err(e) = plugin_mgr.notify("ping", ping_content).await {
                                debug!(error = %e, "Ping plugin hook failed");
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
                        nathole::handle_new_visitor_conn(&ctx, &mut ctl, &mut writer, nvc, &login_user).await;
                    }
                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                        if nathole::handle_nat_hole_visitor_on_ctl(&mut ctx, &mut ctl, &mut writer, nhv, &login_user).await.is_err() {
                            break;
                        }
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
                // Do NOT update last_ping here — only update when Pong is
                // received from client. Updating on server-initiated Pings
                // would prevent the heartbeat timeout from ever triggering.
            }
            _ = state.shutdown_token.cancelled() => {
                info!(run_id = %run_id, "Graceful shutdown: draining control handler for {}", run_id);
                break;
            }
        }
    }

    // Cleanup
    for (_, handle) in ctl.listener_handles.drain() {
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
        let _ = state
            .event_tx
            .send(crate::event::ServerEvent::ClientDisconnected {
                run_id: run_id.clone(),
            });
    }
    proxy_ops::unregister_control(&state, &run_id, ctl.shutting_down).await;
    state.proxy_manager.remove_client(&run_id).await;
    info!(run_id = %run_id, "Control connection {} removed", run_id);
}
