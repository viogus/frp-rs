mod bridge;
mod dispatch;
mod login;
mod nathole;
mod pool;
mod proxy;
mod proxy_ops;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, instrument, warn};

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

use crate::service::AppState;

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
        mut ctl,
        _internal_tx,
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

    // --- Main select loop ---
    loop {
        // Expire stale pending requests
        while let Some(req) = ctl.pending_requests.pop_front() {
            if req.created_at.elapsed() > pool::PENDING_REQUEST_TIMEOUT {
                pool_stats
                    .pending_requests
                    .store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                debug!(proxy_name = %req.proxy_name, timeout = ?pool::PENDING_REQUEST_TIMEOUT, "Pending request for proxy '{}' timed out after {:?}", req.proxy_name, pool::PENDING_REQUEST_TIMEOUT);
            } else {
                ctl.pending_requests.push_front(req);
                break;
            }
        }

        // Expire stale pending_udp entries
        while let Some((proxy_name, ts)) = ctl.pending_udp.pop_front() {
            if ts.elapsed() > pool::PENDING_REQUEST_TIMEOUT {
                debug!(%proxy_name, timeout = ?pool::PENDING_REQUEST_TIMEOUT, "Pending UDP request for proxy '{}' timed out after {:?}", proxy_name, pool::PENDING_REQUEST_TIMEOUT);
            } else {
                ctl.pending_udp.push_front((proxy_name, ts));
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
                    Some(msg) => {
                        if dispatch::dispatch_internal(&mut ctx, &mut ctl, &mut writer, msg).await.is_err() {
                            break;
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
                    Ok(msg) => {
                        if dispatch::dispatch_frp_message(&mut ctx, &mut ctl, &mut writer, msg, &login_user).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        info!(peer = ?peer, error = %e, run_id = %run_id, "Control connection closed");
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
    proxy::cleanup(&mut ctx, &mut ctl, &mut writer).await;
}
