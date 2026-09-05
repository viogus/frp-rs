pub(crate) mod bridge;
mod dispatch;
// pub(crate) so the stale-control reaper (service.rs) can clear the OIDC
// subject mapping for a swept run_id (round-7 audit LOW — the generation-
// guarded helper lives in login.rs).
pub(crate) mod login;
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

// Re-export for the dashboard delete paths (single + bulk), which perform
// their own registry removal: the helper releases the counters the entry
// owned (https SNI-sniff gate count, per-client port-budget slot) only when
// THIS call actually removed the proxy, so a delete racing the client
// CloseProxy handler cannot double-decrement (S4). Gated on `dashboard`
// like the SUDP re-export above.
#[cfg(feature = "dashboard")]
pub(crate) use proxy_ops::remove_proxy_and_release_client_counts;

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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

/// Shared per-control stall state, written by the persisted read future
/// (via [`ProgressRead::poll_read`]) and read by the self-arming reap arm to
/// compute its deadline LIVE. The arm cannot snapshot loop-top state: when a
/// mid-frame poll consumes bytes and returns Pending, the select parks with no
/// Ready arm — loop-top only runs after a select returns — so a loop-top
/// snapshot of the stall start would arm a never-firing timer exactly when the
/// stall begins mid-iteration (the round-17 reaper silently never fired for
/// the exact HIGH it was meant to close).
struct StallState {
    /// Fixed at construction; `now_ms()`/`stall_start()` are relative to it so
    /// the whole state is readable from sync `poll_read` without a mutex.
    anchor: Instant,
    /// Millis (relative to `anchor`) at which the current mid-frame stall
    /// began, or `u64::MAX` when the read is fresh / no frame in flight.
    stall_start_ms: AtomicU64,
    /// Wakes the reap arm when a stall begins or extends so it can arm a live
    /// deadline (see the reap arm).
    notify: tokio::sync::Notify,
}

impl StallState {
    fn new() -> Self {
        Self {
            anchor: Instant::now(),
            stall_start_ms: AtomicU64::new(u64::MAX),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn now_ms(&self) -> u64 {
        (Instant::now() - self.anchor).as_millis() as u64
    }

    /// The moment the current stall began, or None for a fresh read.
    fn stall_start(&self) -> Option<Instant> {
        let ms = self.stall_start_ms.load(Ordering::Acquire);
        (ms != u64::MAX).then(|| self.anchor + Duration::from_millis(ms))
    }

    /// Called from [`ProgressRead::poll_read`] when a poll consumed bytes:
    /// mark the stall in progress, record its start (first consumption of the
    /// frame), and wake the reap arm so it arms a live deadline.
    fn mark_progress(&self) {
        let _ = self.stall_start_ms.compare_exchange(
            u64::MAX,
            self.now_ms(),
            Ordering::Release,
            Ordering::Relaxed,
        );
        self.notify.notify_one();
    }

    /// A fresh read (loop-top recreation) or a completed frame (read arm)
    /// clears the stall: the reaper goes back to never-firing until the NEXT
    /// partial frame.
    fn reset(&self) {
        self.stall_start_ms.store(u64::MAX, Ordering::Release);
    }
}

/// Wraps the control read so the half-frame-stall reaper can see whether the
/// in-flight frame has consumed any bytes. A read that returns Pending after
/// consuming bytes is mid-frame (trickle/stalled body); a read that never
/// consumes anything is indistinguishable from a heartbeat-disabled client.
///
/// Progress counts BOTH decrypted bytes delivered to the caller AND raw
/// wire bytes consumed below the cipher (via `raw`, the `CountingIoStream`
/// counter from `login::authenticate`): a peer that sends exactly the
/// 16-byte CFB IV (or an AEAD frame header) then goes silent has started a
/// frame — the stall reaper must see it (S1).
struct ProgressRead<'a, R> {
    inner: &'a mut R,
    stall: &'a StallState,
    /// Raw wire-byte counter (below the cipher): IV / AEAD frame headers /
    /// ciphertext bytes consumed from the underlying stream.
    raw: &'a AtomicU64,
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressRead<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let raw_before = self.raw.load(Ordering::Relaxed);
        let filled_before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > filled_before || self.raw.load(Ordering::Relaxed) > raw_before {
            self.stall.mark_progress();
        }
        res
    }
}

/// Deadline for control-plane writes (audit H2). A wedged-but-alive peer
/// must not pin the control task + fd + semaphore permit forever: the
/// heartbeat timeout can never fire while the select loop is blocked inside
/// a write, so every control write gets this bound. Longer than the 5s
/// login reject/success deadlines — those keep their tighter budget.
const CTL_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Mid-frame stall deadline for the main control connection when the
/// heartbeat watchdog is DISABLED (`heartbeat_timeout <= 0` — tcp_mux enabled
/// by default forces `heartbeat_timeout = -1`, see
/// `frp-core/src/config/server.rs`, and under tcp_mux frpc also normalizes
/// its `heartbeat_interval` to -1, so a HEALTHY default client completes no
/// control frames while idle).
///
/// Without a fallback here, an authenticated client that pins its
/// conn_semaphore permit + task + fd forever (512 such connections exhaust
/// every permit → the whole server rejects all new login / work / visitor /
/// vhost / tcpmux connections with "Max connections reached" — HIGH: auth'd
/// silent-control DoS) would never be reclaimed. But the anchor CANNOT be
/// "last completed frame": a healthy idle default client also completes no
/// frames, and reaping it every 90s was a BLOCKER (round-17 review,
/// reproduced live — an idle frpc behind tcp_mux was disconnected exactly
/// every 90s).
///
/// So the reaper targets only a MID-FRAME stall: the in-flight control read
/// has consumed bytes (progress flag set by [`ProgressRead`]) but has not
/// completed a frame within `CONTROL_IDLE_TIMEOUT`. A fresh read that has
/// consumed nothing is indistinguishable from a heartbeat-disabled client and
/// is deliberately left alone — Go frp parity, since Go under tcpMux performs
/// no app-level reap at all (audit B3 scope note: `MAX_IDLE_KEEPALIVE_TICKS`
/// bounds only peers whose yamux driver stops answering session pings; a peer
/// whose driver keeps ponging — automatic at the mux layer, no app data
/// needed — while its control stream never sends a byte is NOT reaped here
/// or in Go. This arm closes the subset it can: a peer that started a frame
/// and stalled mid-body, where the consumed bytes prove liveness). Only
/// active when the heartbeat watchdog is off (`heartbeat_timeout <= 0`), so
/// the normal `heartbeat_timeout > 0` path is untouched.
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Deadline for yamux-stream reads in the control select loop (round 10
/// HIGH). Unlike the main control-read branch (the persisted
/// `pending_read` future — which yields back to the select when the peer
/// trickles, so the heartbeat and shutdown arms stay live), the yamux
/// arm's reads run inside the arm body, where no other arm can fire. A
/// post-auth client trickling partial frame bytes on a yamux stream would
/// pin the task + fd + semaphore permit + run_id registration forever (Go
/// bounds this via its independent heartbeatWorker goroutine calling
/// `ctl.Close()`).
///
/// A read timeout behaves like the Err branch: drop the stream, keep the
/// control loop alive.
const CTL_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Protocol-aware write: dispatches to V1 or V2 framing based on the `v2`
/// flag. Bounded by `CTL_WRITE_TIMEOUT` (30s): on timeout the write is
/// abandoned and a Protocol error is returned, which control-loop callers
/// treat as fatal — the connection closes and its resources release.
async fn write_ctl_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    v2: bool,
) -> Result<(), frp_core::Error> {
    let write = async {
        if v2 {
            write_msg_v2(writer, msg).await
        } else {
            write_msg_v1(writer, msg).await
        }
    };
    match tokio::time::timeout(CTL_WRITE_TIMEOUT, write).await {
        Ok(result) => result,
        Err(_elapsed) => Err(frp_core::Error::Protocol("control write timed out".into())),
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
    /// Cancelled by cleanup (supersession / control disconnect) so TCP/WS/KCP
    /// work-conn bridge tasks spawned by `assign_work_to_proxy` terminate
    /// instead of copying forever over a half-open work conn whose control
    /// connection is gone (HIGH finding: 1 task + 2 fds leak per reconnect
    /// with active tunnels). The server-global `AppState::shutdown_token`
    /// still interrupts bridges on graceful shutdown; this is the
    /// per-control teardown signal, mirroring `udp_cancel` for the TCP path.
    pub bridge_cancel: tokio_util::sync::CancellationToken,
    pub work_pool: VecDeque<pool::PoolEntry>,
    pub pending_requests: VecDeque<pool::PendingRequest>,
    pub pending_udp: VecDeque<(String, Instant)>,
    /// (sid, proxy_name, created_at) triples queued while waiting for a work connection.
    pub pending_nat_hole_sids: VecDeque<(String, String, Instant)>,
    pub listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    pub udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    pub last_ping: Instant,
    /// Set by a superseding login (same run_id) whose Shutdown message could
    /// not be delivered through a full channel; checked at loop top so the
    /// handler exits as soon as it is free (see `ControlTx::superseded`).
    pub superseded: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
    /// Negotiated UDPPacket codec for this session's V2 data plane:
    /// `"binary-v1"` or empty (JSON fallback). Go frp v0.71.0
    /// `udpPacketCodec` from the ServerHello handshake.
    pub udp_packet_codec: String,
    /// Keeps the per-run_id lifecycle mutex entry alive for this control
    /// session and reclaims it after cleanup.
    pub(crate) _run_mu_guard: crate::state::RunMuGuard,
}

/// Handle a control connection from a frpc client.
/// The login message has already been consumed from the stream.
/// `peer` is passed separately because generic stream types don't have peer_addr().
/// `internal` marks connections from internal sources (SSH gateway) — when combined
/// with AlwaysAuthPass in the login ClientSpec, authentication is bypassed.
///
/// Logins over TCP/TLS/WS/QUIC key the per-IP login throttle on the peer IP
/// (real, non-spoofable source). KCP-sourced logins pass through
/// `handle_control_inner` with `throttle_keyed=false` (spoofable UDP source —
/// audit E1/S1, see `AppState::login_throttle` docs in state.rs).
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
        stream, login, state, peer, incoming, v2, crypto_ctx, internal, None, true,
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
        true,
    )
    .await;
}

/// `throttle_keyed`: whether the login's peer source IP may key the per-IP
/// login throttle. True for TCP/TLS/WS/QUIC (real source); false for
/// KCP-sourced logins (spoofable UDP source — audit E1/S1; see
/// `AppState::login_throttle` docs). Forwarded into `login::authenticate`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_control_inner<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    internal: bool,
    auth_success: Option<tokio::sync::oneshot::Sender<()>>,
    throttle_keyed: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(peer = ?peer, "New control connection from {:?}", peer);
    // Box stream to erase type — authenticate is type-erased to avoid
    // monomorphization (saves ~30KB per copy in release binary).
    let stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin> = Box::new(stream);
    // 1. Authenticate and set up per-client state (login.rs)
    let (mut ctx, mut ctl, _internal_tx, mut internal_rx, reader, mut writer, mut incoming, raw) =
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
            throttle_keyed,
        )
        .await
        {
            Ok(tuple) => tuple,
            Err(()) => return,
        };

    // The control read half is shared with the persisted read future via an
    // async Mutex: the future holds the guard only while a frame is being
    // read (control-plane rate), and no other loop arm touches `reader`.
    let reader = std::sync::Arc::new(tokio::sync::Mutex::new(reader));

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

    // Persist a partial control-frame read across select iterations (audit
    // finding 4 — MEDIUM): the select drops every branch future when
    // another arm wins, and `read_exact`-based framing keeps its partial
    // state only in the branch future's locals. A client that splits a
    // frame across two writes and forces an internal/accept arm to win
    // mid-frame would lose the consumed bytes; the next iteration would
    // parse the frame tail as a fresh header — a garbage type/length →
    // protocol error → control drop + reconnect. The boxed future
    // survives the select, so consumed bytes are retained until the frame
    // completes. The loop shape stays fair (no biased branch ordering —
    // the fairness regression test below asserts this): the read still
    // progresses only at loop top, exactly like a fresh future would. Note
    // the read does NOT "always win its own round": tokio::select! returns
    // the FIRST Ready branch in declaration order, and internal_rx is
    // declared above the read arm, so an internal message can win a round
    // in which the read is also complete. Correctness never relies on the
    // read winning — the future lives in the loop-outer Option, so a lost
    // round drops the branch's reference, not the future: a completed read
    // stays Ready and wins the first round in which no earlier arm is also
    // Ready (a Ready future needs no waker to make progress), and a
    // partial read keeps its consumed bytes until completion. The arm
    // body's reset below therefore can never strand a completed future.
    //
    // The future owns an Arc<tokio::sync::Mutex<ReadHalf>> clone and locks
    // inside its own poll, so it borrows nothing from the loop — a
    // loop-local borrow could not be stored across select iterations (the
    // Option's type region would keep the borrow alive for the whole loop,
    // conflicting with the loop-top recreation below).
    type PendingRead = Pin<Box<dyn Future<Output = Result<FrpMessage, frp_core::Error>> + Send>>;
    let mut pending_read: Option<PendingRead> = None;

    // Half-frame-stall reaper state for when the heartbeat watchdog is
    // disabled (tcp_mux default → heartbeat_timeout = -1). Shared between the
    // persisted read future (writes via `ProgressRead`) and the self-arming
    // reap arm (reads for its live deadline). See `CONTROL_IDLE_TIMEOUT` for
    // why a completed-frame anchor would falsely reap healthy idle tcp_mux
    // clients.
    let stall = Arc::new(StallState::new());

    loop {
        // Superseded by a newer login (same run_id) whose Shutdown message
        // could not be delivered through a full channel (round-7 review
        // finding): exit as soon as the loop is free so cleanup — proxy
        // registrations, bridges, conn_semaphore permit — runs at wedge-end
        // instead of lingering until the socket dies or the heartbeat fires.
        if ctl.superseded.load(std::sync::atomic::Ordering::Acquire) {
            warn!(peer = ?peer, run_id = %run_id, "Control superseded (Shutdown could not be delivered); closing");
            break;
        }

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

        // Recreate the control-read future when the previous frame
        // completed (the arm body detached it). Starts a fresh read at the
        // next frame boundary. The async block owns an Arc clone and takes
        // the lock only while the frame is in flight.
        if pending_read.is_none() {
            // Fresh frame: clear the stall state from any previous read
            // (belt-and-suspenders — the completed-read arm resets it too).
            stall.reset();
            let reader = reader.clone();
            let stall_clone = stall.clone();
            let raw_clone = raw.clone();
            pending_read = Some(Box::pin(async move {
                let mut guard = reader.lock().await;
                let mut progress = ProgressRead {
                    inner: &mut *guard,
                    stall: &stall_clone,
                    raw: &raw_clone,
                };
                read_ctl_msg(&mut progress, v2).await
            }));
        }

        // Earliest pending-request expiry deadline. Loop-top expiry is
        // event-driven only — with tcp_mux on (the default), heartbeat is
        // disabled and this select has no timer arm, so a silent client
        // could pin pending_requests entries + user fds forever. This branch
        // wakes the select at the earliest deadline; loop-top does the
        // cleanup (audit D2-1).
        let pending_timeout = pool::pending_request_timeout(state.user_conn_timeout);
        let pending_deadline = ctl
            .pending_requests
            .front()
            // checked_add (review finding): a hostile/legacy user_conn_timeout
            // must never panic the process — degrade to never firing this
            // wake arm instead (the loop-top expiry above still applies).
            .and_then(|r| r.created_at.checked_add(pending_timeout))
            .or_else(|| {
                ctl.pending_udp
                    .front()
                    .and_then(|(_, ts)| ts.checked_add(pending_timeout))
            })
            .or_else(|| {
                ctl.pending_nat_hole_sids
                    .front()
                    .and_then(|(_, _, ts)| ts.checked_add(pending_timeout))
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
            _ = async {
                // checked_add (round-8): config no longer clamps heartbeat
                // values (Go has none — Go frpc uses 7200), so any positive
                // i64 can reach here. checked_add must never panic the
                // process — an overflowing value degrades to never firing
                // this arm (the loop-top check above still applies).
                match ctl.last_ping.checked_add(hb_timeout) {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            }, if state.heartbeat_timeout > 0 => {
                warn!(peer = ?peer, hb_timeout = ?hb_timeout, "Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, hb_timeout);
                break;
            }

            // Round-17-review BLOCKER fix: reap only a MID-FRAME stall, not
            // an idle connection. Under tcp_mux both the server heartbeat
            // watchdog and the client's own heartbeats are disabled, so an
            // idle-but-healthy default client completes no control frames — a
            // completed-frame anchor disconnected it every 90s. `stall_since`
            // is only set while a read has consumed bytes without completing
            // a frame; a fresh read keeps it None and is never reaped (Go
            // frp parity: under tcpMux Go performs no app-level reap at all,
            // and yamux keepalive bounds fully-silent peers via
            // `MAX_IDLE_KEEPALIVE_TICKS`). Mutually exclusive with the
            // heartbeat arm above, so only one idle ramp can ever fire.
            _ = async {
                // Self-arming stall reap. This arm CANNOT snapshot loop-top
                // state: when a mid-frame read consumes bytes and returns
                // Pending, the select parks with no Ready arm — loop-top only
                // re-runs after a select returns, so a snapshot would arm a
                // `pending()` timer exactly when the stall starts (the
                // round-17 reaper never fired for the HIGH it was built to
                // close). Instead the arm parks on `stall.notify` (fired by
                // `ProgressRead` on byte consumption) and, once in a stall,
                // sleeps until the stall START + CONTROL_IDLE_TIMEOUT,
                // re-checking on wake (the frame may have completed meanwhile).
                let stall = stall.clone();
                loop {
                    // Only park on the notify when no stall is live: once a
                    // mid-frame stall exists, the deadline is recomputed from
                    // the FIXED stall start on every re-poll, so a competing
                    // arm winning a select round (internal msg, yamux stream)
                    // can no longer strand the reaper by consuming the
                    // one-shot notify permit.
                    if stall.stall_start().is_none() {
                        stall.notify.notified().await;
                    }
                    while let Some(start) = stall.stall_start() {
                        // Live deadline from the stall START — not from this
                        // notification (a multi-byte trickle would otherwise
                        // keep pushing the deadline out forever).
                        let deadline = start.checked_add(CONTROL_IDLE_TIMEOUT);
                        if let Some(deadline) = deadline {
                            tokio::time::sleep_until(deadline).await;
                            // Re-check after the sleep: if the frame completed
                            // while sleeping, the stall is cleared and we go
                            // back to parking on notify. Still stalled → reap.
                            if stall.stall_start().is_some() {
                                return;
                            }
                        } else {
                            // `Instant` overflow — degrade to reaping rather
                            // than never firing.
                            return;
                        }
                    }
                }
            }, if state.heartbeat_timeout <= 0 => {
                warn!(peer = ?peer, idle = ?CONTROL_IDLE_TIMEOUT, "Control connection for {:?} stalled mid-frame (partial control frame not completed in {:?}, heartbeat watchdog disabled), disconnecting", peer, CONTROL_IDLE_TIMEOUT);
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
                    // Bounded by CTL_READ_TIMEOUT: see the const doc — these
                    // arm-body reads must not outlive the select's other arms.
                    // The block owns the stream and hands back the (possibly
                    // re-wrapped) IoStream with the message; a timeout drops
                    // the stream.
                    let run_id_log = run_id.clone();
                    let stream_read = tokio::time::timeout(CTL_READ_TIMEOUT, async move {
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
                                    return Err(format!(
                                        "Failed to read V2 magic from yamux stream for {run_id_log}: {e}"
                                    ));
                                }
                            }
                        }
                        let msg = read_ctl_msg(&mut io, v2)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok((msg, io))
                    });
                    let (nwc, io) = match stream_read.await {
                        Ok(Ok((FrpMessage::NewWorkConn(nwc), io))) => (nwc, io),
                        Ok(Ok((other, _io))) => {
                            debug!(run_id = %run_id, msg_type = ?other.v1_type_byte(), "Unexpected yamux stream message for {run_id}: {:?}", other.v1_type_byte());
                            continue;
                        }
                        Ok(Err(e)) => {
                            warn!(run_id = %run_id, error = %e, "Failed to read from yamux stream for {run_id}: {e}");
                            continue;
                        }
                        Err(_elapsed) => {
                            warn!(run_id = %run_id, "Yamux stream read timed out after {CTL_READ_TIMEOUT:?} for {run_id}");
                            continue;
                        }
                    };
                    let stream_run_id = nwc.run_id.as_deref().unwrap_or("");
                    if stream_run_id != run_id {
                        debug!(expected_run_id = %run_id, got_run_id = %stream_run_id, "Yamux work conn run_id mismatch: expected {run_id}, got {stream_run_id}");
                        continue;
                    }
                    // NewWorkConn plugin hook — Go frp v0.71.0 RegisterWorkConn
                    // ordering (server/service.go:852-888): the hook runs BEFORE
                    // auth and may REPLACE the message (`newMsg =
                    // &retContent.NewWorkConn`), so a plugin that rewrites
                    // privilege_key/timestamp changes what auth validates.
                    // Control-enabled plugins can also reject.
                    let nwc = match crate::handlers::run_new_work_conn_plugin_with_msg(
                        &nwc, &run_id, &state,
                    )
                    .await
                    {
                        Ok(Some(mutated)) => mutated,
                        Ok(None) => nwc,
                        Err(reason) => {
                            warn!(run_id = %run_id, reason = %reason, "Yamux work conn plugin hook rejected: {reason}");
                            continue;
                        }
                    };
                    // Validate NewWorkConn credentials (privilege_key + timestamp)
                    // on the possibly plugin-mutated message. Standalone TCP work
                    // connections go through handle_work_conn_inner which
                    // validates auth. Yamux work connections must apply the same
                    // validation — without it, tcp_mux (default on) creates an
                    // auth bypass: yamux streams skip NewWorkConn verification
                    // that standalone TCP work connections require.
                    if let Err(e) = crate::handlers::validate_new_work_conn_auth(
                        &nwc, &run_id, &state,
                    )
                    .await
                    {
                        warn!(run_id = %run_id, error = %e, "Yamux work conn auth failed for {run_id}: {e}");
                        continue;
                    }
                    // Route through pool::handle_new_work_conn for consistent
                    // priority: NatHoleSid → UDP → pending requests → pool → drop.
                    // The inline handler previously checked only pending_requests.
                    let _ = pool::handle_new_work_conn(&mut ctx, &mut ctl, &mut writer, io).await;
                }
            }

            msg = pending_read.as_mut().unwrap() => {
                // Detach the completed future before handling the message:
                // the select has dropped the branch future, and the
                // loop-top `if pending_read.is_none()` recreates a fresh
                // one for the next frame.
                pending_read = None;
                // A completed frame (Ok or Err) ends the mid-frame stall:
                // clear the progress flag + stall clock so the reaper arm
                // goes back to never-firing until the NEXT partial frame.
                stall.reset();
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

#[cfg(test)]
mod ctl_write_timeout_tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// AsyncWrite whose poll_write never completes — simulates a
    /// wedged-but-alive peer whose TCP window is exhausted.
    struct StalledWriter;

    impl tokio::io::AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    /// Audit H2 regression: write_ctl_msg must be bounded by
    /// CTL_WRITE_TIMEOUT — a wedged peer must not pin the control task
    /// forever (the heartbeat timeout cannot fire while the select loop is
    /// blocked inside the write), and the timeout must surface as a
    /// Protocol error so the control loop tears the connection down.
    /// Paused time keeps the test instant.
    #[tokio::test(start_paused = true)]
    async fn write_ctl_msg_bounded_by_ctl_write_timeout() {
        let mut stalled = StalledWriter;
        let msg = FrpMessage::ReqWorkConn(msg::ReqWorkConn {});
        // Outer +1s guard: without the fix (bare unbounded write) the outer
        // timeout would fire and the match below would hit the Elapsed arm.
        let result = tokio::time::timeout(
            CTL_WRITE_TIMEOUT + Duration::from_secs(1),
            write_ctl_msg(&mut stalled, &msg, false),
        )
        .await;
        match result {
            Ok(Err(frp_core::Error::Protocol(_))) => {}
            other => panic!("expected Protocol error at CTL_WRITE_TIMEOUT, got {other:?}"),
        }
        // Same for the V2 path.
        let result = tokio::time::timeout(
            CTL_WRITE_TIMEOUT + Duration::from_secs(1),
            write_ctl_msg(&mut stalled, &msg, true),
        )
        .await;
        match result {
            Ok(Err(frp_core::Error::Protocol(_))) => {}
            other => panic!("expected Protocol error on V2 write, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod partial_read_tests {
    use super::*;

    /// Read one V1 LoginResp frame from the client side of the duplex and
    /// return its error field (empty when the login succeeded).
    async fn read_login_resp_error(client: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 9];
        client
            .read_exact(&mut header)
            .await
            .expect("read frame header");
        let len = u64::from_be_bytes(header[1..9].try_into().unwrap()) as usize;
        assert!(len < 4096, "implausible frame length {len}");
        let mut payload = vec![0u8; len];
        client
            .read_exact(&mut payload)
            .await
            .expect("read frame payload");
        let resp: frp_core::msg::LoginResp =
            serde_json::from_slice(&payload).expect("parse LoginResp");
        resp.error.unwrap_or_default()
    }

    /// Audit finding 4 (MEDIUM) regression: a control frame delivered in
    /// two chunks with an internal message landing mid-frame must not lose
    /// the consumed bytes. The old select arm created a fresh
    /// `read_ctl_msg` future every iteration, so a competing arm winning
    /// mid-frame dropped the partial read — the next iteration parsed the
    /// frame tail as a fresh header (garbage type/length → protocol error
    /// → control drop + reconnect). The persisted boxed future retains the
    /// consumed bytes and completes the frame.
    ///
    /// Determinism: the duplex (1024) capacity makes chunk 1's write_all
    /// block until the loop's read branch has consumed it (the only
    /// consumer), so the read is provably mid-frame when the injected
    /// `NewWorkConn` internal message wins the select — the test observes
    /// the win via `pool_stats.pool_size >= 1` (the pooled work conn).
    /// Registration of the frame's stcp proxy is the observable end state:
    /// old code breaks on a garbage header before registering anything;
    /// new code completes the frame and registers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_frame_survives_competing_internal_message() {
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        let (server, mut client) = tokio::io::duplex(1024);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("test-run-id".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("test-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let peer: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let control_task = tokio::spawn(handle_control(
            server,
            login,
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
        ));

        // Login handshake. The server's prewarm ReqWorkConn stays in the
        // client buffer — never read, small enough to fit.
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login failed: {error}");

        // The V1 control channel is ALWAYS AES-128-CFB wrapped after
        // LoginResp (Go parity — no config flag gates it), so the frame
        // must go out encrypted: wrap the client half and write through it.
        let client_key = frp_core::encryption::derive_key("test-token");
        let mut client =
            frp_core::cipher_stream::CipherStream::new(client, client_key).expect("rng");

        // NewProxy frame with a large headers map so the frame exceeds the
        // duplex capacity. stcp needs no listener — registration alone is
        // the observable end state.
        let np = msg::NewProxy {
            proxy_name: "t".into(),
            proxy_type: "stcp".into(),
            use_encryption: None,
            use_compression: None,
            group: None,
            group_key: None,
            local_str: None,
            remote_port: Some(0),
            sk: Some("sk".into()),
            custom_domains: None,
            subdomain: None,
            locations: None,
            http_user: None,
            http_pwd: None,
            host_header_rewrite: None,
            headers: Some(std::collections::HashMap::from([(
                "x-pad".into(),
                "x".repeat(5000),
            )])),
            response_headers: None,
            route_by_http_user: None,
            allow_users: None,
            bandwidth_limit: None,
            bandwidth_limit_mode: None,
            annotations: None,
            metas: None,
            multiplexer: None,
            virtual_net: None,
            proxy_protocol_version: None,
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        };
        let new_proxy_msg = FrpMessage::NewProxy(Box::new(np));
        let type_byte = new_proxy_msg.v1_type_byte();
        let payload = serde_json::to_vec(&new_proxy_msg).expect("encode NewProxy");
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(type_byte);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        frame.extend_from_slice(&payload);
        assert!(
            frame.len() > 1024,
            "frame must exceed the duplex capacity: {} bytes",
            frame.len()
        );
        let chunk1 = 1500.min(frame.len());

        // Chunk 1 write: blocks until the loop's read branch has consumed
        // the first 1024 bytes (it is the only consumer), so the read is
        // provably mid-frame afterwards. (The CipherStream adds a 16-byte
        // IV on the first write; the blocking math still holds.)
        client
            .write_all(&frame[..chunk1])
            .await
            .expect("write chunk 1");

        // Inject an internal NewWorkConn: it must win the select while the
        // read is mid-frame, dropping the branch future (the bug).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let accept = tokio::spawn(async move {
            let (s, _) = listener.accept().await.expect("accept");
            s
        });
        let client_keepalive = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let work_conn = accept.await.expect("accepted socket");
        // Keep the peer end alive so the server-side socket stays open.
        let _client_keepalive = client_keepalive;

        let ctl_tx = state
            .run_id_to_ctl_tx
            .get("test-run-id")
            .expect("control registered at login");
        ctl_tx
            .tx
            .send(InternalMsg::NewWorkConn(IoStream::Tcp(work_conn)))
            .await
            .expect("internal send");
        // The message being processed proves the select returned with the
        // read mid-frame (pooling sets pool_size >= 1).
        let pool_stats = ctl_tx.pool_stats.clone();
        drop(ctl_tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while pool_stats.pool_size.load(Ordering::Relaxed) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("internal NewWorkConn must be processed");

        // Chunk 2: the rest of the frame.
        client
            .write_all(&frame[chunk1..])
            .await
            .expect("write chunk 2");

        // The stcp proxy must register. Old code: the frame tail parsed as
        // a fresh header → garbage length → protocol error → control drop,
        // nothing registered.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state.proxy_manager.get("t").await.is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stcp proxy 't' must register after the interrupted frame");

        // Teardown: closing the client side ends the control (read EOF).
        drop(client);
        control_task.await.expect("control task must exit");
    }
}

#[cfg(test)]
mod idle_reap_tests {
    use super::*;
    use std::time::Duration;

    /// Read one V1 LoginResp frame (shared local copy — the sibling module's
    /// helper is private).
    async fn read_login_resp_error(client: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 9];
        client
            .read_exact(&mut header)
            .await
            .expect("read frame header");
        let len = u64::from_be_bytes(header[1..9].try_into().unwrap()) as usize;
        assert!(len < 4096, "implausible frame length {len}");
        let mut payload = vec![0u8; len];
        client
            .read_exact(&mut payload)
            .await
            .expect("read frame payload");
        let resp: frp_core::msg::LoginResp =
            serde_json::from_slice(&payload).expect("parse LoginResp");
        resp.error.unwrap_or_default()
    }

    /// Round-17-review BLOCKER regression: a silent (healthy, heartbeat-
    /// disabled) control connection must NOT be reaped. Under tcp_mux the
    /// client's heartbeats are normalized off too, so an idle default client
    /// completes no control frames; the old completed-frame anchor
    /// disconnected it every 90s (reproduced live). A fresh read (zero bytes
    /// consumed) is indistinguishable from a heartbeat-disabled client and is
    /// deliberately left alone — Go frp parity (Go under tcpMux performs no
    /// app-level reap at all).
    ///
    /// Paused time advances `CONTROL_IDLE_TIMEOUT` instantly while the duplex
    /// login handshake still runs (real socket I/O — frame delivery isn't
    /// time-driven). After login we send nothing and assert the control
    /// survives past the deadline, then close the duplex for a clean exit.
    #[tokio::test(start_paused = true)]
    async fn silent_control_not_reaped_when_heartbeat_disabled() {
        let mut state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        Arc::get_mut(&mut state)
            .expect("sole state ref")
            .heartbeat_timeout = 0; // disabled; exercises the idle arm (<=0 guard)

        let (server, mut client) = tokio::io::duplex(1024);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("idle-test-run".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("test-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let peer: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let state_clone = state.clone();
        let control_task = tokio::spawn(handle_control(
            server,
            login,
            state_clone,
            Some(peer),
            None,
            false,
            None,
            false,
        ));

        // Login handshake completes (real duplex I/O).
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login failed: {error}");

        // Send NOTHING — the connection is idle with a fresh (zero-byte)
        // read. Advance past the old idle deadline: the reaper must NOT fire
        // (a healthy heartbeat-disabled client is indistinguishable from this
        // silent conn and is left alone).
        tokio::time::advance(CONTROL_IDLE_TIMEOUT + Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert!(
            !control_task.is_finished(),
            "silent conn must NOT be reaped (healthy heartbeat-disabled client)"
        );
        // Close the duplex → the server read sees EOF → control exits cleanly.
        drop(client);
        control_task.await.expect("control task exits on EOF");
    }

    /// Retained security property: a conn that sends a PARTIAL control frame
    /// (half-frame trickle — consumes bytes but never completes a frame,
    /// while ponging yamux keepalive so the session stays up) MUST still be
    /// reaped. This is the only case the `CONTROL_IDLE_TIMEOUT` arm closes.
    #[tokio::test(start_paused = true)]
    async fn stalled_control_reaped_when_heartbeat_disabled() {
        let mut state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        Arc::get_mut(&mut state)
            .expect("sole state ref")
            .heartbeat_timeout = 0; // disabled; exercises the stall arm (<=0 guard)

        let (server, mut client) = tokio::io::duplex(1024);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("idle-test-run".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("test-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let peer: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let state_clone = state.clone();
        let control_task = tokio::spawn(handle_control(
            server,
            login,
            state_clone,
            Some(peer),
            None,
            false,
            None,
            false,
        ));

        // Login handshake completes (real duplex I/O).
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login failed: {error}");

        // Send a partial frame and stall. The control stream is always
        // AES-128-CFB-wrapped after LoginResp (Go frp encrypts the control
        // plane unconditionally), so the peer's first 16 bytes are consumed as
        // the CFB IV into `CipherReader.iv_buf` — invisible to `ProgressRead`
        // (its filled-buffer check sees only decrypted bytes). Only bytes past
        // the IV reach the user read buffer. So: write a 16-byte IV followed by
        // the first 4 bytes of a V1 frame header (type 0x01 + 3 of 8 length
        // bytes). The read consumes those 4 decrypted bytes →
        // `stall.mark_progress()` records the stall start and notifies → the
        // self-arming reap arm fires at CONTROL_IDLE_TIMEOUT. The 4 bytes are
        // any 4 decrypted bytes: `read_exact(9)` can never complete on 4, so
        // the read stays mid-header regardless of what the CFB decrypts them
        // to.
        use tokio::io::AsyncWriteExt;
        client
            .write_all(&[0u8; 20]) // 16-byte CFB IV + 4-byte partial frame
            .await
            .expect("write partial frame");
        // Two scheduler passes: the first lets the control task consume the
        // 4 bytes (notifying the reap arm), the second lets the reap arm
        // re-poll, complete its `notified()`, and reach `sleep_until` with
        // its live deadline armed — only then can `advance` fire it.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(CONTROL_IDLE_TIMEOUT + Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert!(
            control_task.is_finished(),
            "mid-frame stall must be reaped at CONTROL_IDLE_TIMEOUT"
        );
        control_task.await.expect("control task exits");
    }

    /// Round-17-review residual (S1, MEDIUM, security review round 3): an
    /// authenticated client that sends EXACTLY the 16-byte CFB IV and then
    /// goes silent (ponging yamux keepalive so the session survives) delivers
    /// ZERO decrypted bytes — a `ProgressRead` counting only decrypted bytes
    /// never fires `mark_progress`, the reap arm parks on `notified()` with no
    /// stall recorded, and task + fd + conn_semaphore permit + run_id
    /// registration stay pinned forever. ~512 such connections exhaust every
    /// permit ("Max connections reached") — the exact HIGH this arm was built
    /// to close, bypassed by the 16-byte IV. RED on the decrypted-bytes-only
    /// progress site: the raw-wire counter (CountingIoStream, below the
    /// cipher) must count the IV as progress.
    #[tokio::test(start_paused = true)]
    async fn iv_only_stall_is_reaped_when_heartbeat_disabled() {
        let mut state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        Arc::get_mut(&mut state)
            .expect("sole state ref")
            .heartbeat_timeout = 0; // disabled; exercises the stall arm (<=0 guard)

        let (server, mut client) = tokio::io::duplex(1024);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("iv-test-run".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("test-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let peer: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let state_clone = state.clone();
        let control_task = tokio::spawn(handle_control(
            server,
            login,
            state_clone,
            Some(peer),
            None,
            false,
            None,
            false,
        ));

        // Login handshake completes (real duplex I/O).
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login failed: {error}");

        // The peer's first post-login write is exactly the 16-byte CFB IV —
        // consumed into `CipherStream.iv_buf`, never visible as decrypted
        // bytes. Then silence. A decrypted-bytes-only progress counter never
        // marks the stall; the raw-wire counter must.
        use tokio::io::AsyncWriteExt;
        client.write_all(&[0u8; 16]).await.expect("write IV only");
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(CONTROL_IDLE_TIMEOUT + Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert!(
            control_task.is_finished(),
            "IV-only stall must be reaped at CONTROL_IDLE_TIMEOUT"
        );
        control_task.await.expect("control task exits");
    }

    /// Round-18-review C-2 regression pin (green): a mid-frame completion
    /// must reset the stall timer. Sequence: partial frame (stall recorded,
    /// reap arm armed at the FIRST stall start) → frame completed (the read
    /// arm calls `stall.reset()` — a stale deadline surviving the reset
    /// would reap this connection at the first stall's deadline despite the
    /// healthy completion: a false positive disconnecting any client that
    /// ever trickled a frame slowly). The conn must survive past that
    /// deadline. Then a SECOND partial frame re-arms the stall from a fresh
    /// start and IS reaped at the new deadline — both halves of the arm's
    /// contract in one test.
    ///
    /// The client writes through a real `CipherWriter` (same
    /// `derive_key("test-token")` as the server's `authenticate` wrap), so
    /// the completed frame is legitimate ciphertext the server can parse:
    /// an unauthenticated `Ping` (no `HeartBeats` scope in test_state) is
    /// answered with a Pong and the control stays up — the 4 partial
    /// plaintext bytes before it are decrypted as the start of the frame
    /// header and never complete a `read_exact(9)`.
    #[tokio::test(start_paused = true)]
    async fn mid_frame_completion_resets_stall_and_second_stall_is_reaped() {
        use frp_core::cipher_stream::CipherWriter;
        use frp_core::encryption::derive_key;
        use tokio::io::AsyncWriteExt;

        let mut state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        Arc::get_mut(&mut state)
            .expect("sole state ref")
            .heartbeat_timeout = 0; // disabled; exercises the stall arm (<=0 guard)

        let (server, mut client) = tokio::io::duplex(1024);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("mid-stall-test-run".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("test-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let peer: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let state_clone = state.clone();
        let control_task = tokio::spawn(handle_control(
            server,
            login,
            state_clone,
            Some(peer),
            None,
            false,
            None,
            false,
        ));

        // Login handshake completes (real duplex I/O).
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login failed: {error}");

        // Client-side cipher: the server wraps the control stream in
        // CipherStream with derive_key("test-token") after LoginResp; the
        // peer must encrypt with the same key so the decrypted bytes parse.
        let mut cw = CipherWriter::new(client, derive_key("test-token")).expect("rng");

        // Build one valid V1 Ping frame (type byte + 8-byte BE length +
        // JSON payload) by hand. Writing it through the cipher in TWO
        // pieces — the first 4 bytes as the "partial frame", the rest as
        // the completion — must reassemble into exactly the same byte
        // stream `write_v1_frame` would emit: the server's `read_exact(9)`
        // consumes 4 (partial) + 5 (frame head) bytes = the full correct
        // header, then reads the payload. (Writing a garbage partial frame
        // and THEN a complete frame would corrupt the header with garbage
        // type/length bytes — the frame would fail to parse.)
        let ping = frp_core::msg::FrpMessage::Ping(msg::Ping {
            privilege_key: None,
            timestamp: None,
        });
        let payload = serde_json::to_vec(&ping).expect("serialize ping");
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(ping.v1_type_byte());
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        frame.extend_from_slice(&payload);

        // Frame 1 begins: the first 4 bytes of the header as a partial
        // frame → CipherWriter emits IV(16) + 4 ciphertext bytes. The
        // server consumes the IV into `CipherStream.iv_buf` (raw-wire
        // progress) and decrypts 4 bytes → `stall.mark_progress()` records
        // the FIRST stall start and notifies the reap arm.
        cw.write_all(&frame[..4])
            .await
            .expect("write partial frame");
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Frame 1 completes: the remaining header + payload. The server
        // finishes `read_exact(9)`, parses the Ping, answers a Pong into
        // the duplex (harmless — it is never read), and the read arm
        // resets the stall timer.
        cw.write_all(&frame[4..]).await.expect("write ping frame");
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Past the FIRST stall's deadline: the reset must have re-based the
        // timer — the reap arm's re-check (`stall_start().is_some()`) finds
        // no stall and must NOT reap a healthy connection.
        tokio::time::advance(CONTROL_IDLE_TIMEOUT + Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(
            !control_task.is_finished(),
            "completed frame must reset the stall: conn must NOT be reaped \
             at the first stall's deadline"
        );

        // Frame 2: another partial frame → fresh stall start → the reap arm
        // re-arms at the NEW deadline and must fire.
        cw.write_all(&[0u8; 4])
            .await
            .expect("write second partial frame");
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(CONTROL_IDLE_TIMEOUT + Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert!(
            control_task.is_finished(),
            "second stall must be reaped at its own deadline"
        );
        control_task.await.expect("control task exits");
    }

    /// Round-17-review residual (MEDIUM): the self-arming reap arm parks on
    /// `stall.notify.notified()` and only re-arms its deadline after a
    /// subsequent notification. A competing select arm winning a round (an
    /// internal message here; a yamux stream — or any server-side internal
    /// event — in production) drops the arm's in-flight `sleep_until`; the
    /// re-created arm then parks on `notified()` with the one-shot notify
    /// permit already consumed by the stall-start wake, and a staller that
    /// sends no further bytes never wakes it — the stall is never reaped. A
    /// partial-frame staller that ALSO opens one yamux stream (any time
    /// within the 90s window) pins its permit / task / fd forever, defeating
    /// exactly the DoS this arm was built to close.
    #[tokio::test(start_paused = true)]
    async fn stalled_control_reaped_despite_competing_select_arm() {
        let mut state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        Arc::get_mut(&mut state)
            .expect("sole state ref")
            .heartbeat_timeout = 0; // disabled; exercises the stall arm (<=0 guard)

        let (server, mut client) = tokio::io::duplex(1024);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("idle-test-run".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("test-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let peer: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
        let state_clone = state.clone();
        let control_task = tokio::spawn(handle_control(
            server,
            login,
            state_clone,
            Some(peer),
            None,
            false,
            None,
            false,
        ));

        // Login handshake completes (real duplex I/O).
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login failed: {error}");

        // Send a partial frame and stall (same shape as the sibling test:
        // 16-byte CFB IV + 4-byte partial V1 header).
        use tokio::io::AsyncWriteExt;
        client
            .write_all(&[0u8; 20])
            .await
            .expect("write partial frame");
        // Let the control task consume the 4 bytes and arm the reap arm.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Competing arm: an internal message delivered mid-stall (production
        // equivalent: the attacker opens a yamux stream). The select picks it
        // over the reap arm's sleep, dropping the sleep; the re-created arm
        // parks on `notified()` — the one-shot permit from the stall-start
        // wake is already consumed, and no further bytes ever arrive.
        let ctl_tx = state
            .run_id_to_ctl_tx
            .get("idle-test-run")
            .expect("control registered at login")
            .tx
            .clone();
        ctl_tx
            .send(crate::state::InternalMsg::WriteNatHoleSid {
                sid: "no-such-session".into(),
            })
            .await
            .expect("send internal msg");
        tokio::task::yield_now().await;

        tokio::time::advance(CONTROL_IDLE_TIMEOUT + Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert!(
            control_task.is_finished(),
            "mid-frame stall must still be reaped at CONTROL_IDLE_TIMEOUT even after a competing select arm wins a round"
        );
        control_task.await.expect("control task exits");
    }
}
