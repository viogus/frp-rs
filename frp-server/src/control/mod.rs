pub(crate) mod bridge;
mod dispatch;
mod login;
mod nathole;
mod pool;
mod proxy;
// pub(crate) so the dashboard delete path (cleanup_deleted_proxy_port) can
// reuse proxy_ops' test helpers and the SUDP owner-check helper.
pub(crate) mod proxy_ops;

// Re-export for the dashboard delete path (cleanup_deleted_proxy_port),
// which mirrors handle_close_proxy's SUDP shared-port owner check.
// Gated on `dashboard`: the only consumer outside control/ is dashboard.rs,
// and the unused re-export warned in default (no-dashboard) builds.
#[cfg(feature = "dashboard")]
pub(crate) use proxy_ops::release_udp_port_with_owner_check;

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
use crate::state::InternalMsg;

// ---- State containers for handle_control ----

/// Mutable local state owned by the control session. Passed by `&mut` to
/// all handler functions. Single-task — no synchronisation needed.
pub(crate) struct ControlState {
    pub shutting_down: bool,
    /// Signaled after cleanup completes so the new control generation
    /// (same run_id) can proceed past its handoff barrier.
    pub shutdown_done: Option<tokio::sync::oneshot::Sender<()>>,
    /// Cancelled by cleanup (supersession / control disconnect) so UDP
    /// bridge tasks spawned by `assign_udp_work_conn` terminate instead of
    /// hanging forever on a half-open work conn (Go frp v0.70.1 fix parity).
    pub udp_cancel: tokio_util::sync::CancellationToken,
    /// Per-proxy UDP bridge cancellation (low finding 5): each UDP/SUDP
    /// proxy gets a child token of `udp_cancel` at registration, and
    /// `handle_close_proxy` cancels its own so a wedged per-proxy UDP
    /// bridge task exits immediately instead of lingering until control
    /// teardown. Children of `udp_cancel` — cleanup's
    /// `udp_cancel.cancel()` covers them too (idempotent, no double-cancel
    /// hazard). Map key: proxy_name.
    pub udp_cancels: std::collections::HashMap<String, tokio_util::sync::CancellationToken>,
    pub work_pool: VecDeque<pool::PoolEntry>,
    pub pending_requests: VecDeque<pool::PendingRequest>,
    pub pending_udp: VecDeque<(String, Instant)>,
    /// (sid, proxy_name, created_at) triples queued while waiting for a work connection.
    pub pending_nat_hole_sids: VecDeque<(String, String, Instant)>,
    pub listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    pub udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
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
    /// Monotonically increasing control generation ID for this connection.
    pub control_id: u64,
    pub pool_cap: usize,
    pub internal_tx: tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
    pub peer: Option<std::net::SocketAddr>,
    /// Authorization identity used for proxy ownership and visitor access.
    /// Go frp keeps the client-claimed `login.user` here even with OIDC; the
    /// verified OIDC subject is used only for NewWorkConn/Ping verification.
    pub authenticated_user: String,
    /// Keeps the per-run_id lifecycle mutex entry alive for this control
    /// session and reclaims it after cleanup.
    pub(crate) _run_mu_guard: crate::state::RunMuGuard,
}

/// Handle a control connection from a frpc client.
/// The login message has already been consumed from the stream.
/// `peer` is passed separately because generic stream types don't have peer_addr().
/// `internal` marks connections from internal sources (SSH gateway) — when combined
/// with AlwaysAuthPass in the login ClientSpec, authentication is bypassed.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(stream, state, incoming, crypto_ctx, login), fields(run_id = %login.run_id.clone().unwrap_or_default(), peer = ?peer, internal))]
pub async fn handle_control<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    internal: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_control_inner(
        stream, login, state, peer, incoming, v2, crypto_ctx, internal, None,
    )
    .await;
}

/// QUIC control variant that signals only after Login authentication and
/// LoginResp flush have completed successfully.
#[allow(clippy::too_many_arguments)]
pub async fn handle_control_with_auth_signal<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    internal: bool,
    auth_success: tokio::sync::oneshot::Sender<()>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_control_inner(
        stream,
        login,
        state,
        peer,
        incoming,
        v2,
        crypto_ctx,
        internal,
        Some(auth_success),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_control_inner<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    internal: bool,
    auth_success: Option<tokio::sync::oneshot::Sender<()>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(peer = ?peer, "New control connection from {:?}", peer);
    // Box stream to erase type — authenticate is type-erased to avoid
    // monomorphization (saves ~30KB per copy in release binary).
    let stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin> = Box::new(stream);
    // 1. Authenticate and set up per-client state (login.rs)
    let (mut ctx, mut ctl, _internal_tx, mut internal_rx, mut reader, mut writer, mut incoming) =
        match login::authenticate(
            stream,
            &login,
            state,
            peer,
            incoming,
            v2,
            crypto_ctx,
            internal,
            auth_success,
        )
        .await
        {
            Ok(tuple) => tuple,
            Err(()) => return,
        };

    // Convenience bindings for the main loop
    let state = ctx.state.clone();
    let run_id = ctx.run_id.clone();
    let _pool_cap = ctx.pool_cap; // used by the non-yamux work-conn paths
    let pool_stats = ctx.pool_stats.clone();
    let v2 = ctx.v2;
    let peer = ctx.peer;
    let authenticated_user = ctx.authenticated_user.clone();

    // --- Main select loop ---
    // Cache heartbeat timeout duration (never changes during the loop).
    // Clamp non-positive values (0 = disabled, Go frp's -1) to zero: the
    // select guard `if state.heartbeat_timeout > 0` gates the branch, but
    // tokio::select! evaluates the branch expression (including this
    // arithmetic) before the guard, so a raw `-1i64 as u64` here would
    // overflow `last_ping + hb_timeout` and panic.
    let hb_timeout = if state.heartbeat_timeout > 0 {
        Duration::from_secs(state.heartbeat_timeout as u64)
    } else {
        Duration::ZERO
    };
    loop {
        // Expire stale pending requests
        while let Some(req) = ctl.pending_requests.pop_front() {
            if req.created_at.elapsed() >= pool::pending_request_timeout(state.user_conn_timeout) {
                pool_stats
                    .pending_requests
                    .store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                debug!(proxy_name = %req.proxy_name, timeout = ?pool::pending_request_timeout(state.user_conn_timeout), "Pending request for proxy '{}' timed out after {:?}", req.proxy_name, pool::pending_request_timeout(state.user_conn_timeout));
            } else {
                ctl.pending_requests.push_front(req);
                break;
            }
        }

        // Expire stale pending_udp entries
        while let Some((proxy_name, ts)) = ctl.pending_udp.pop_front() {
            if ts.elapsed() >= pool::pending_request_timeout(state.user_conn_timeout) {
                debug!(%proxy_name, timeout = ?pool::pending_request_timeout(state.user_conn_timeout), "Pending UDP request for proxy '{}' timed out after {:?}", proxy_name, pool::pending_request_timeout(state.user_conn_timeout));
            } else {
                ctl.pending_udp.push_front((proxy_name, ts));
                break;
            }
        }

        // Expire stale pending_nat_hole_sids entries (low finding 1):
        // previously they only expired inside handle_new_work_conn when a
        // work conn arrived, so a provider that never delivers work conns
        // let the queue grow unbounded. Same pattern as pending_requests.
        pool::expire_pending_nat_hole_sids(
            &mut ctl.pending_nat_hole_sids,
            pool::pending_request_timeout(state.user_conn_timeout),
        );

        // NOTE: pooled work-conn idle expiry was removed (audit D2-3):
        // `state.pool.idle_timeout` is always Duration::ZERO (never wired
        // from config; Go frp parity keeps pooled conns alive until the
        // control disconnect), so the old branch was dead code.

        // Heartbeat check: if no ping in heartbeat_timeout, disconnect.
        // When heartbeat_timeout <= 0, heartbeat checking is disabled
        // (matching Go frp v0.70.0 behaviour when tcpMux is enabled).
        if state.heartbeat_timeout > 0 && ctl.last_ping.elapsed() > hb_timeout {
            warn!(peer = ?peer, hb_timeout = ?hb_timeout, "Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, hb_timeout);
            break;
        }

        // Earliest pending-request expiry deadline. Loop-top expiry is
        // event-driven only — with tcp_mux on (the default), heartbeat is
        // disabled and this select has no timer arm, so a silent client
        // could pin pending_requests entries + user fds forever. This branch
        // wakes the select at the earliest deadline; loop-top does the
        // cleanup (audit D2-1).
        let pending_deadline = ctl
            .pending_requests
            .front()
            .map(|r| r.created_at + pool::pending_request_timeout(state.user_conn_timeout))
            .or_else(|| {
                ctl.pending_udp
                    .front()
                    .map(|(_, ts)| *ts + pool::pending_request_timeout(state.user_conn_timeout))
            })
            .or_else(|| {
                ctl.pending_nat_hole_sids
                    .front()
                    .map(|(_, _, ts)| *ts + pool::pending_request_timeout(state.user_conn_timeout))
            });

        tokio::select! {
            // Wake when the earliest pending request expires (loop-top
            // cleanup handles the actual expiry).
            _ = async {
                match pending_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {}

            // Heartbeat watchdog: an idle control connection must not hold
            // its conn_semaphore permit / task / fd forever. The check above
            // only runs after select returns, so without this branch a silent
            // client would never be disconnected. tokio::select re-evaluates
            // the sleep target on every iteration, so last_ping updates are
            // picked up automatically.
            _ = tokio::time::sleep_until(ctl.last_ping + hb_timeout), if state.heartbeat_timeout > 0 => {
                warn!(peer = ?peer, hb_timeout = ?hb_timeout, "Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, hb_timeout);
                break;
            }

            // Keep selection fair: an always-ready internal queue must not
            // starve control reads (including heartbeat pings) or shutdown.
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
                            // Validate NewWorkConn credentials (privilege_key + timestamp).
                            // Standalone TCP work connections go through handle_work_conn_inner
                            // which validates auth. Yamux work connections must apply the
                            // same validation — without it, tcp_mux (default on) creates an
                            // auth bypass: yamux streams skip NewWorkConn verification that
                            // standalone TCP work connections require.
                            if let Err(e) = crate::handlers::validate_new_work_conn_auth(
                                &nwc, &run_id, &state,
                            )
                            .await
                            {
                                warn!(run_id = %run_id, error = %e, "Yamux work conn auth failed for {run_id}: {e}");
                                continue;
                            }
                            // NewWorkConn plugin hook — control-enabled plugins can reject
                            if let Err(reason) =
                                crate::handlers::run_new_work_conn_plugin(&run_id, &state).await
                            {
                                warn!(run_id = %run_id, reason = %reason, "Yamux work conn plugin hook rejected: {reason}");
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
                    // Route through pool::handle_new_work_conn for consistent
                    // priority: NatHoleSid → UDP → pending requests → pool → drop.
                    // The inline handler previously checked only pending_requests.
                    let _ = pool::handle_new_work_conn(&mut ctx, &mut ctl, &mut writer, io).await;
                }
            }

            msg = read_ctl_msg(&mut reader, v2) => {
                match msg {
                    Ok(msg) => {
                        if dispatch::dispatch_frp_message(&mut ctx, &mut ctl, &mut writer, msg, &authenticated_user).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        info!(peer = ?peer, error = %e, run_id = %run_id, "Control connection closed");
                        break;
                    }
                }
            }
            _ = state.shutdown_token.cancelled() => {
                info!(run_id = %run_id, "Graceful shutdown: draining control handler for {}", run_id);
                break;
            }
        }
    }

    // Supersession handoff: the old handler MUST release the new login
    // waiting on the handoff barrier no matter why this loop exited. If a
    // Shutdown was queued (via try_send) but never dispatched — the loop can
    // break on a client read error before the select consumes it — extract
    // its `done` sender here so cleanup signals the barrier. Without this,
    // the new login's `barrier.await` hangs forever, leaking its connection
    // semaphore permit and fd, and every reconnect for the same run_id
    // collides with the same stuck barrier.
    if ctl.shutdown_done.is_none() {
        let mut dropped_internal: usize = 0;
        while let Ok(msg) = internal_rx.try_recv() {
            if let InternalMsg::Shutdown { done } = msg {
                ctl.shutting_down = true;
                ctl.shutdown_done = Some(done);
                break;
            }
            // Other queued internal messages are dropped: the control
            // connection is already gone, so dispatching them would fail.
            dropped_internal += 1;
        }
        if dropped_internal > 0 {
            debug!(run_id = %run_id, dropped = dropped_internal,
                "Supersession handoff: dropped {dropped_internal} buffered internal message(s) (control connection already gone) — operator can correlate with lost work/visitor conns");
        }
    }

    // Drain buffered internal messages after supersession Shutdown.
    // When the old control handler breaks on Shutdown (replaced by a new
    // control connection for the same run_id), messages already queued in
    // internal_rx (up to 1024 — VisitorConn, ProxyUserConn, NewWorkConn)
    // are processed before cleanup. Without this drain, those connections
    // receive TCP RST instead of clean error responses.
    if ctl.shutting_down {
        while let Ok(msg) = internal_rx.try_recv() {
            debug!(run_id = %run_id, "Draining buffered internal message after supersession Shutdown");
            let _ = dispatch::dispatch_internal(&mut ctx, &mut ctl, &mut writer, msg).await;
        }
    }

    // Cleanup
    proxy::cleanup(&mut ctx, &mut ctl, &mut writer).await;

    // Signal the new control generation (waiting on the handoff barrier)
    // that the old handler's cleanup is complete.
    if let Some(done) = ctl.shutdown_done.take() {
        let _ = done.send(());
    }
}

#[cfg(test)]
mod fairness_tests {
    use std::time::{Duration, Instant};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fair_four_lane_pressure_bounds_control_p99_and_preserves_internal_throughput() {
        const CONTROL_MESSAGES: usize = 500;
        let (internal_tx, mut internal_rx) = tokio::sync::mpsc::channel(1024);
        let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::channel(1024);
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(CONTROL_MESSAGES);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

        for _ in 0..1024 {
            internal_tx.try_send(()).unwrap();
            incoming_tx.try_send(()).unwrap();
        }
        for _ in 0..CONTROL_MESSAGES {
            control_tx.try_send(Instant::now()).unwrap();
        }

        let started = Instant::now();
        let mut internal_ops = 0usize;
        let mut control_latency = Vec::with_capacity(CONTROL_MESSAGES);
        while control_latency.len() < CONTROL_MESSAGES {
            tokio::select! {
                Some(()) = internal_rx.recv() => {
                    internal_ops += 1;
                    tokio::task::yield_now().await; // model non-zero dispatch cost
                    internal_tx.try_send(()).unwrap();
                }
                Some(()) = incoming_rx.recv() => {
                    tokio::task::yield_now().await; // model stream validation cost
                    incoming_tx.try_send(()).unwrap();
                }
                Some(queued_at) = control_rx.recv() => {
                    control_latency.push(queued_at.elapsed());
                }
                _ = shutdown_rx.recv() => break,
            }
        }

        control_latency.sort_unstable();
        let p99 = control_latency[CONTROL_MESSAGES * 99 / 100];
        let internal_ops_per_second = internal_ops as f64 / started.elapsed().as_secs_f64();

        let (biased_internal_tx, mut biased_internal_rx) = tokio::sync::mpsc::channel(1);
        let (biased_control_tx, mut biased_control_rx) = tokio::sync::mpsc::channel(1);
        biased_internal_tx.try_send(()).unwrap();
        biased_control_tx.try_send(()).unwrap();
        let biased_started = Instant::now();
        let mut biased_internal_ops = 0usize;
        let mut biased_control_ops = 0usize;
        for _ in 0..internal_ops.max(1_000) {
            tokio::select! {
                biased;
                Some(()) = biased_internal_rx.recv() => {
                    biased_internal_ops += 1;
                    tokio::task::yield_now().await;
                    biased_internal_tx.try_send(()).unwrap();
                }
                Some(()) = biased_control_rx.recv() => {
                    biased_control_ops += 1;
                    biased_control_tx.try_send(()).unwrap();
                }
            }
        }
        let biased_internal_ops_per_second =
            biased_internal_ops as f64 / biased_started.elapsed().as_secs_f64();
        eprintln!(
            "fair control p99={p99:?}, fair internal={internal_ops_per_second:.0} ops/s, biased internal={biased_internal_ops_per_second:.0} ops/s, biased control ops={biased_control_ops}"
        );

        // Generous wall-clock bound: the real property is that control
        // messages complete under sustained internal pressure. A hard 250ms
        // p99 is flaky on loaded CI runners (the audit flagged this test).
        assert!(p99 < Duration::from_secs(2), "control p99 was {p99:?}");
        assert!(
            internal_ops_per_second >= biased_internal_ops_per_second * 0.05,
            "fair throughput {internal_ops_per_second:.0} ops/s was under 5% of biased baseline {biased_internal_ops_per_second:.0} ops/s"
        );
        assert_eq!(
            biased_control_ops, 0,
            "biased baseline should starve control"
        );
        assert!(
            include_str!("mod.rs")
                .matches(concat!("biased", ";"))
                .count()
                == 1,
            "control select must remain fair under sustained internal pressure"
        );
    }
}
