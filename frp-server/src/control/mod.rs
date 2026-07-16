mod bridge;
mod login;
mod pool;
mod proxy_ops;

use crate::lock::RwLockExt;
use crate::nathole::NAT_HOLE_TIMEOUT;

use proxy_ops::err_msg;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
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
                        if let Some(entry) = ctl.work_pool.pop_front() {
                            let mut work_conn = entry.conn;
                            state.pool.hits.fetch_add(1, Ordering::Relaxed);
                            pool_stats.pool_size.store(ctl.work_pool.len() as i64, Ordering::Relaxed);
                            // Look up proxy flags for StartWorkConn (encryption/compression propagation)
                            let (use_enc, use_comp, sk) = state.proxy_manager.get(&proxy_name).await
                                .map(|p| (p.use_encryption, p.use_compression, p.sk.clone()))
                                .unwrap_or((false, false, None));
                            pool::write_start_work_conn_with_nat_hole_sid(&mut work_conn, &proxy_name, use_enc, use_comp, sk.as_deref(), &sid, v2, " on work conn").await;
                            // Connection consumed — Go frp doesn't reuse after NatHoleSid.
                            drop(work_conn);
                        } else {
                            state.pool.misses.fetch_add(1, Ordering::Relaxed);
                            // No pooled work conn — request one, queue sid.
                            debug!(sid = %sid, "No pooled work conn for NatHoleSid {}, requesting via ReqWorkConn", sid);
                            if let Err(e) = write_ctl_msg(&mut writer,
                                &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
                                warn!(error = %e, "Failed to send ReqWorkConn for NatHoleSid: {}", e);
                            }
                            ctl.pending_nat_hole_sids.push_back((sid, proxy_name, Instant::now()));
                        }
                    }
                    Some(InternalMsg::Shutdown) => {
                        warn!(run_id = %run_id, "Shutdown received for run_id {} (replaced by new control connection)", run_id);
                        ctl.shutting_down = true;
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
                                let _ = ctl_tx.tx.try_send(crate::state::InternalMsg::VnetPacketForward {
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
                    Ok(FrpMessage::NatHoleClient(ref client_msg)) => {
                        debug!(
                            transaction_id = %client_msg.transaction_id,
                            mapped_addrs = ?client_msg.mapped_addrs,
                            "Received NatHoleClient from provider: txn={}, addrs={:?}",
                            client_msg.transaction_id, client_msg.mapped_addrs
                        );
                        state.xtcp.nat_hole.handle_client(client_msg.clone()).await;
                    }
                    Ok(FrpMessage::NatHoleSid(ref sid_msg)) => {
                        debug!(sid = ?sid_msg.sid, "Received NatHoleSid from provider: {:?}", sid_msg.sid);
                        if let Some(ref sid) = sid_msg.sid {
                            let provider_addr = peer.as_ref().map(|a| a.to_string());
                            // Try control-channel path first (Go frp compat).
                            if state.xtcp.nat_hole.forward_sid_via_ctl(sid, provider_addr.clone()).await {
                                debug!(sid = %sid, "Forwarded NatHoleSid via control channel for {}", sid);
                            } else if let Some(mut writer) = state.xtcp.nat_hole.take_writer(sid).await {
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
                                state.xtcp.nat_hole.return_writer(sid, writer).await;
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
                        if state.xtcp.nat_hole.forward_nat_hole_resp_via_ctl(
                            tid,
                            resp_msg.error.clone(),
                            resp_msg.sid.clone(),
                            resp_msg.protocol.clone(),
                            resp_msg.candidate_addrs.clone(),
                            resp_msg.assisted_addrs.clone(),
                        ).await {
                            debug!(tid = %tid, "Forwarded NatHoleResp via control channel for {}", tid);
                        } else if let Some(mut writer) = state.xtcp.nat_hole.take_writer(tid).await {
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
                            state.xtcp.nat_hole.return_writer(tid, writer).await;
                        } else {
                            warn!(tid = %tid, "NatHoleResp for unknown session {}", tid);
                        }
                        // Signal the session so handle_nat_hole_visitor wakes up.
                        // Go frp v0.69.1 sends NatHoleResp (type 'm') from provider
                        // with its discovered addresses. We store them as if they
                        // arrived via NatHoleClient so the accept-loop path can
                        // build the combined NatHoleResp for both sides.
                        state.xtcp.nat_hole.handle_client(msg::NatHoleClient {
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
                            if !state.xtcp.nat_hole.forward_report_via_ctl(sid).await {
                                // Fallback: accept-loop writer path
                                if let Some(mut writer) = state.xtcp.nat_hole.take_writer(sid).await {
                                    let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                        sid: Some(sid.clone()),
                                    });
                                    let _ = write_ctl_msg(&mut writer, &forward, v2).await;
                                }
                            }
                            state.xtcp.nat_hole.complete(sid).await;
                        }
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
                        debug!(proxy_name = %nvc.proxy_name, "NewVisitorConn on control channel: proxy='{}'", nvc.proxy_name);
                        // Visitor registration on the control connection.
                        // Rust frpc sends NewVisitorConn on control before sending
                        // NatHoleVisitor for XTCP hole punching. Go frps v0.69.1
                        // responds with ReqWorkConn but we send NewVisitorConnResp
                        // with no error — the visitor just needs acknowledgment.
                        let sign_key = nvc.sign_key.unwrap_or_default();
                        let timestamp = nvc.timestamp.unwrap_or(0);

                        // Validate timestamp freshness (replay attack prevention).
                        let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
                        let ts_fresh = frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout);

                        // Validate proxy exists and sign_key matches.
                        // Uses constant-time comparison (verify_token) instead of
                        // plain string == to prevent timing side-channel attacks.
                        let ok = if let Some(proxy_info) = state.proxy_manager.get(&nvc.proxy_name).await {
                            // allow_users check on control channel: match Path A
                            // (accept loop) semantics. Empty = owner-only (Go frp compat);
                            // if both owner and visitor have no user (empty string),
                            // they are the same identity and access is allowed.
                            let visitor_user = login.user.clone().unwrap_or_default();
                            let user_ok = if proxy_info.allow_users.is_empty() {
                                visitor_user == proxy_info.user
                            } else if proxy_info.allow_users.iter().any(|u| u == "*") {
                                true
                            } else {
                                proxy_info.allow_users.contains(&visitor_user)
                            };
                            if !user_ok {
                                warn!(proxy_name = %nvc.proxy_name, "NewVisitorConn on ctl: user denied for proxy '{}'", nvc.proxy_name);
                                false
                            } else if let Some(ref sk) = proxy_info.sk {
                                if sk.is_empty() {
                                    true // No sk — allow without auth
                                } else if ts_fresh.is_err() {
                                    warn!(proxy_name = %nvc.proxy_name, "NewVisitorConn on ctl: timestamp stale for proxy '{}'", nvc.proxy_name);
                                    false
                                } else {
                                    frp_core::auth::verify_token(sk, timestamp, &sign_key)
                                }
                            } else {
                                true // No sk configured
                            }
                        } else {
                            // Race: NewVisitorConn may arrive before proxy_manager
                            // registration completes. Fall back to sk_index
                            // (populated after successful registration).
                            if ts_fresh.is_err() {
                                false
                            } else {
                                let sk_map = state.xtcp.sk_index.read().await;
                                sk_map
                                    .get(&nvc.proxy_name)
                                    .is_some_and(|sk_raw| {
                                        frp_core::auth::verify_token(sk_raw, timestamp, &sign_key)
                                    })
                            }
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

                        // Validate proxy exists and capture info for auth
                        let proxy_info = match state.proxy_manager.get(&proxy_name).await {
                            Some(info) => info,
                            None => {
                                let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                    transaction_id: transaction_id.clone(),
                                    error: Some("proxy not found".into()),
                                    ..Default::default()
                                });
                                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                continue;
                            }
                        };

                        // --- Auth: verify visitor is authorized to access this proxy ---
                        // Go frp v0.70 allowUsers semantics:
                        //   - Empty: only the proxy owner can be a visitor
                        //   - ["*"]: all authenticated users
                        //   - Specific list: only those users
                        // Auth is enforced BEFORE pre_check response so Go frp's
                        // pre_check permission model is preserved.
                        let visitor_user = login.user.clone().unwrap_or_default();

                        if proxy_info.allow_users.is_empty() {
                            // Empty = proxy owner only (Go frp compat).
                            // When both owner and visitor have no user set
                            // (default empty string), they are the same
                            // identity and access is allowed.
                            let owner = &proxy_info.user;
                            if visitor_user != *owner {
                                warn!(proxy_name = %proxy_name, user = %visitor_user, owner = %owner, "NatHoleVisitor: user '{}' not proxy owner '{}' for proxy '{}'", visitor_user, owner, proxy_name);
                                let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                    transaction_id: transaction_id.clone(),
                                    error: Some("access denied: owner only".into()),
                                    ..Default::default()
                                });
                                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                continue;
                            }
                        } else if proxy_info.allow_users.iter().any(|u| u == "*") {
                            // Wildcard — any authenticated user
                        } else if !proxy_info.allow_users.contains(&visitor_user) {
                            warn!(proxy_name = %proxy_name, user = %visitor_user, "NatHoleVisitor: user '{}' not in allow_users for proxy '{}'", visitor_user, proxy_name);
                            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                transaction_id: transaction_id.clone(),
                                error: Some("access denied".into()),
                                ..Default::default()
                            });
                            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                            continue;
                        }

                        // Verify sign_key if the proxy has a shared secret.
                        // Uses constant-time comparison (verify_token) and timestamp
                        // freshness check to prevent timing side-channel and replay attacks.
                        let sign_key = nhv.sign_key.as_deref().unwrap_or("");
                        let timestamp = nhv.timestamp.unwrap_or(0);
                        if let Some(ref sk) = proxy_info.sk {
                            if !sk.is_empty() {
                                if sign_key.is_empty() {
                                    warn!(proxy_name = %proxy_name, "NatHoleVisitor: missing sign_key for protected proxy '{}'", proxy_name);
                                    let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                        transaction_id: transaction_id.clone(),
                                        error: Some("auth required".into()),
                                        ..Default::default()
                                    });
                                    let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                    continue;
                                }
                                // Validate timestamp freshness (replay attack prevention).
                                let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
                                if let Err(freshness_err) = frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout) {
                                    warn!(proxy_name = %proxy_name, error = %freshness_err, "NatHoleVisitor on ctl: timestamp stale for proxy '{}'", proxy_name);
                                    let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                        transaction_id: transaction_id.clone(),
                                        error: Some(freshness_err),
                                        ..Default::default()
                                    });
                                    let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                    continue;
                                }
                                if !frp_core::auth::verify_token(sk, timestamp, sign_key) {
                                    warn!(proxy_name = %proxy_name, "NatHoleVisitor auth failed on ctl for proxy '{}'", proxy_name);
                                    let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                        transaction_id: transaction_id.clone(),
                                        error: Some("auth failed".into()),
                                        ..Default::default()
                                    });
                                    let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                                    continue;
                                }
                                debug!(proxy_name = %proxy_name, "NatHoleVisitor auth OK (constant-time) on ctl for proxy '{}'", proxy_name);
                            }
                        }

                        // Go frp v0.70 pre_check compat: after auth, return OK without
                        // creating a session or notifying the provider.
                        if nhv.pre_check && nhv.mapped_addrs.is_none() {
                            debug!(proxy_name = %proxy_name, user = %visitor_user, "NatHoleVisitor pre_check on ctl channel: proxy='{}' OK", proxy_name);
                            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                                transaction_id: transaction_id.clone(),
                                error: None,
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
                        let (session, report_rx) = match state.xtcp.nat_hole
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
                        if provider_ctl.tx.try_send(InternalMsg::NatHoleSidOnWorkConn {
                            sid: transaction_id.clone(),
                            proxy_name: proxy_name.clone(),
                        }).is_err() {
                            warn!(provider_run_id = %provider_run_id, "Provider for run_id {} has gone away", provider_run_id);
                            state.xtcp.nat_hole.remove(&transaction_id).await;
                            continue;
                        }

                        // Spawn task for full Go-compat analysis flow.
                        // Waits for provider's NatHoleClient on control, runs NAT analysis,
                        // and sends NatHoleResp to both sides.
                        let nat_hole = state.xtcp.nat_hole.clone();
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
                            let analysis_index;
                            let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
                                let key = nathole_ctrl::gen_analysis_key(cf, vf);
                                let (mode, index, c_behavior, v_behavior) =
                                    nat_hole.analyzer.get_recommend_behaviors(&key, cf, vf);
                                analysis_index = Some(index);

                                let timeout_ms = c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000;
                                let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
                                let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;

                                let v_resp = nathole_ctrl::build_nat_hole_response(
                                    &tid, &tid, visitor_msg.protocol.clone(), mode,
                                    client_mapped.clone(), client_assisted.clone(),
                                    v_behavior, v_read_timeout, cf.ports_difference,
                                );
                                // Use visitor's protocol in c_resp so the provider
                                // knows which transport to use (Go frp compat:
                                // provider reads NatHoleResp.protocol to decide
                                // KCP vs TCP). If empty, Go falls back to TCP
                                // which is incompatible with visitor's KCP.
                                let protocol_for_provider = visitor_msg
                                    .protocol
                                    .clone()
                                    .or_else(|| client_msg.protocol.clone());
                                let c_resp = nathole_ctrl::build_nat_hole_response(
                                    &client_msg.transaction_id, &tid, protocol_for_provider, mode,
                                    visitor_mapped.clone(), visitor_assisted.clone(),
                                    c_behavior, c_read_timeout, vf.ports_difference,
                                );
                                (v_resp, Some(c_resp))
                            } else {
                                analysis_index = None;
                                let v_resp = msg::NatHoleResp {
                                    transaction_id: tid.clone(),
                                    error: None,
                                    sid: Some(tid.clone()),
                                    protocol: visitor_msg.protocol.clone(),
                                    candidate_addrs: if client_mapped.is_empty() { None } else { Some(client_mapped) },
                                    assisted_addrs: if client_assisted.is_empty() { None } else { Some(client_assisted) },
                                    ..Default::default()
                                };
                                let protocol_for_provider2 = visitor_msg
                                    .protocol
                                    .clone()
                                    .or_else(|| client_msg.protocol.clone());
                                let c_resp = msg::NatHoleResp {
                                    transaction_id: client_msg.transaction_id.clone(),
                                    error: None,
                                    sid: Some(tid.clone()),
                                    protocol: protocol_for_provider2,
                                    candidate_addrs: if visitor_mapped.is_empty() { None } else { Some(visitor_mapped) },
                                    assisted_addrs: if visitor_assisted.is_empty() { None } else { Some(visitor_assisted) },
                                    ..Default::default()
                                };
                                (v_resp, Some(c_resp))
                            };

                            // Store v_resp, NAT features, and selected_index on
                            // session for analyzer feedback in handle_report
                            // (C15, C16). The accept-loop path stores these in
                            // handlers.rs; the Go frp compat control-path did not,
                            // so report_success always used index=0 with no features.
                            {
                                let sessions = nat_hole.sessions.read().await;
                                if let Some(s) = sessions.get(&tid) {
                                    *s.v_resp.lock().await = Some(v_resp.clone());
                                    *s.selected_index.lock().await = analysis_index;
                                    if let Some(ref vf) = v_feature {
                                        *s.v_nat_feature.lock().await = Some(vf.clone());
                                    }
                                    if let Some(ref cf) = c_feature {
                                        *s.c_nat_feature.lock().await = Some(cf.clone());
                                    }
                                }
                            }

                            // Send NatHoleResp to visitor via control channel.
                            // send().await: backpressure is correct — silently
                            // dropping NatHoleResp would permanently hang the
                            // visitor (protocol-critical message).
                            let _ = visitor_tx.send(InternalMsg::WriteNatHoleResp {
                                transaction_id: v_resp.transaction_id.clone(),
                                error: v_resp.error.clone(),
                                sid: v_resp.sid.clone(),
                                protocol: v_resp.protocol.clone(),
                                candidate_addrs: v_resp.candidate_addrs.clone(),
                                assisted_addrs: v_resp.assisted_addrs.clone(),
                            }).await;

                            // Send NatHoleResp to provider via control channel
                            if let Some(ref cr) = c_resp {
                                let _ = provider_tx.send(InternalMsg::WriteNatHoleResp {
                                    transaction_id: cr.transaction_id.clone(),
                                    error: cr.error.clone(),
                                    sid: cr.sid.clone(),
                                    protocol: cr.protocol.clone(),
                                    candidate_addrs: cr.candidate_addrs.clone(),
                                    assisted_addrs: cr.assisted_addrs.clone(),
                                }).await;
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
