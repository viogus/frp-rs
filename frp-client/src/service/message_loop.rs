//! The control-channel message loop — `run_message_loop` (Phase 6 of one
//! connection attempt) and the session-agnostic plumbing it is driven by:
//! [`SessionChannels`], the [`LoopExit`] result, the [`StunResult`] hand-off,
//! and the retry cadence/tolerance knobs its retry arm reads.
//!
//! Split out of `frp-client/src/service.rs` by the P2 S3 seam as a pure move
//! (every moved line byte-identical except eleven `pub(super)` tokens, which
//! are the minimum that lets the parent name these items from `run()`). This
//! module is a *child* of `service`, which is what lets the `impl Service`
//! block below reach the parent's private fields and methods; it is deployed
//! as a child module rather than a flat sibling for exactly that reason (see
//! the P2 layout note in `docs/refactor-large-modules.md`).
//!
//! The loop *skeleton* is the specification and travels verbatim: the
//! persisted partial-frame read (`pending_read`, an `Option` outside the
//! `select!` so a competing arm cannot discard bytes already consumed from a
//! split frame), the persistent heartbeat-watchdog `Sleep` (created once for
//! the whole loop, re-armed at the loop top only when its deadline moved or it
//! fired), and deliberately no `biased;` — `tokio::select!` randomizes
//! Ready-branch order each round. The test that pins exactly that shape is
//! `frp-client/tests/partial_frame_survives_competing_ping_tick.rs`.
//!
//! `run_message_loop` itself is `pub(super)` because its only caller is the
//! parent's `run()`; `LoopExit`, `SessionChannels` and `StunResult` are
//! `pub(super)` because the parent names each of them (the `match` on the loop
//! exit, the `SessionChannels` literal at the call site, and `SessionCtx`'s
//! STUN sender/receiver field types). `SessionChannels`' seven fields are
//! `pub(super)` too, because that literal is built by field name in the parent
//! (a struct visible to a module does not by itself expose its private
//! fields). `PROXY_RETRY_INTERVAL` and `WAIT_START_RETRY_TIMEOUT` keep their
//! original `pub(crate)` token and `PROXY_RETRY_GRACE` stays private — all
//! three are referenced only from inside this module.

use super::*;

/// StartErr retry cadence for the message-loop retry arm: re-register
/// proxies stuck in StartErr (anchored on the last StartErr time — Go frp's
/// `lastStartErr.Add(startErrTimeout)`, so a proxy that errors right after a
/// tick is not re-sent until a full interval has elapsed since ITS error).
/// Matches Go frp's proxy_wrapper.checkWorker (default startErrTimeout 30s).
/// The WaitStart-stuck re-send uses its own cadence,
/// [`WAIT_START_RETRY_TIMEOUT`] (Go's waitResponseTimeout, 20s) — see the
/// retry arm.
pub(crate) static PROXY_RETRY_INTERVAL: LazyLock<Duration> =
    LazyLock::new(|| env_duration_ms("FRP_PROXY_RETRY_INTERVAL_MS", Duration::from_secs(30)));

/// WaitStart-stuck re-send timeout for the message-loop retry arm: how long
/// a proxy may sit in WaitStart (a NewProxy that is never answered — a
/// silent server that still Pongs) before its NewProxy is re-sent. Go frp
/// parity: client/proxy/proxy_wrapper.go `waitResponseTimeout` (20s) —
/// distinct from `startErrTimeout` (30s, [`PROXY_RETRY_INTERVAL`]) used for
/// StartErr retries.
pub(crate) static WAIT_START_RETRY_TIMEOUT: LazyLock<Duration> =
    LazyLock::new(|| env_duration_ms("FRP_WAIT_START_RETRY_TIMEOUT_MS", Duration::from_secs(20)));

/// Tolerance for the WaitStart-stuck check in the retry arm. The stuck
/// elapsed time compares two wall-clock `Instant`s (first-seen vs tick), so
/// it can measure a hair under one full interval and a retry would slip to
/// the next tick. The grace only ever advances a retry by at most one tick.
const PROXY_RETRY_GRACE: Duration = Duration::from_millis(100);

/// Finished STUN discovery result, handed from the off-loop STUN task back
/// to the control loop so the NatHoleClient write + pending_xtcp bookkeeping
/// stay on the loop (preserving the write-before-NatHoleResp ordering).
pub(super) struct StunResult {
    sid: String,
    proxy_name: String,
    msg: FrpMessage,
}

/// How the message loop exited. `Shutdown` when a stop was requested (admin
/// API or signal — the session must not reconnect); `Reconnect` when the
/// session died and run() should tear down and reconnect.
pub(super) enum LoopExit {
    Shutdown,
    Reconnect,
}

/// The session-agnostic inputs to the message loop, created once in run()
/// and outliving sessions. Held by `&mut` borrow (not owned) because run()
/// needs `stop_rx` and `health_cancels` again after the loop returns — the
/// reconnect-backoff race and teardown both use them.
pub(super) struct SessionChannels<'a> {
    /// Health-check results from the spawned health check tasks.
    pub(super) health_rx: &'a mut mpsc::Receiver<HealthEvent>,
    /// Reload requests from the admin API (config hot-reload).
    pub(super) reload_rx: &'a mut mpsc::Receiver<ReloadRequest>,
    /// XTCP STUN results from the off-loop STUN discovery tasks.
    pub(super) xtcp_rx: &'a mut mpsc::Receiver<XtcpNotification>,
    /// New-visitor requests from spawned visitor listeners (STCP/XTCP).
    pub(super) visitor_rx: &'a mut mpsc::Receiver<VisitorRequest>,
    /// Stop request from the admin API / signal handler.
    pub(super) stop_rx: &'a mut mpsc::Receiver<()>,
    /// Cancellation flags for health check tasks, shared with teardown.
    pub(super) health_cancels: &'a Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    /// STUN server address used for XTCP hole punching.
    pub(super) nat_hole_stun_server: &'a str,
}

impl Service {
    /// Phase 6 of one connection attempt: the message loop. Reads control
    /// frames, ticks the heartbeat ping, retries StartErr proxies every 30s,
    /// and handles health / reload / XTCP / visitor / stop events until the
    /// session ends. Returns how it ended: `Shutdown` when a stop was
    /// requested (run() must not reconnect), `Reconnect` when the session
    /// died (run() tears down and reconnects).
    ///
    /// The session-agnostic receivers and handles are bundled in `channels`:
    /// they are created once in run() and outlive sessions.
    pub(super) async fn run_message_loop(
        &self,
        ctx: &mut SessionCtx,
        channels: &mut SessionChannels<'_>,
    ) -> LoopExit {
        // The message loop owns the split reader half. It is shared with
        // the persisted read future below via an async Mutex: the future
        // holds the guard only while a frame is being read (control-plane
        // rate), and no other loop arm touches `reader`.
        let reader = Arc::new(Mutex::new(
            ctx.reader
                .take()
                .expect("reader available before message loop"),
        ));

        // Control writes are funneled through the writer handle
        // (always set by phase 5 before the loop starts).
        let writer = ctx
            .writer
            .as_ref()
            .expect("writer available before message loop")
            .clone();

        // --- Message loop ---
        // Map sid -> proxy_name for XTCP NatHoleResp routing (provider side).
        // Map sid -> STUN UDP socket for XTCP P2P hole punching.
        // Map sid -> oneshot sender for visitor NatHoleResp routing (Go frps compat).
        // (All three maps live on SessionCtx, as do waitstart_seen and
        // cfg_user — see the field docs.)
        // STUN discovery runs off the control loop (two STUN round-trips can
        // stall up to ~10s). The finished NatHoleClient is sent back here so
        // the write + pending_xtcp bookkeeping stay on the loop, preserving
        // the write-before-NatHoleResp ordering. A separate cleanup channel
        // lets a timeout task reclaim stale xtcp_sockets/pending_xtcp entries
        // when the server never sends NatHoleResp.
        let (stun_result_tx, stun_result_rx) = mpsc::channel::<StunResult>(64);
        ctx.stun_result_tx = Some(stun_result_tx);
        ctx.stun_result_rx = Some(stun_result_rx);
        let (xtcp_cleanup_tx, xtcp_cleanup_rx) = mpsc::channel::<String>(64);
        ctx.xtcp_cleanup_rx = Some(xtcp_cleanup_rx);

        // Proxy retry cadence: Go's proxy_wrapper.checkWorker ticks every
        // statusCheckInterval (3s) and gates each condition on its own
        // timeout (startErrTimeout 30s / waitResponseTimeout 20s). frp-rs
        // folds both into one tick — the smaller of the two timeouts — and
        // gates each retry class on its own anchor below (last_start_err /
        // waitstart_seen). At defaults a StartErr retry fires 30–40s after
        // its last error and a WaitStart re-send 20–40s after it was
        // observed (anchor set at the first tick where the proxy is seen in
        // WaitStart, so up to one tick late vs Go's 3s-tick 20–23s), staying
        // consistent under env overrides.
        let mut proxy_retry_interval =
            tokio::time::interval(PROXY_RETRY_INTERVAL.min(*WAIT_START_RETRY_TIMEOUT));
        proxy_retry_interval.tick().await; // Skip first immediate tick
        ctx.proxy_retry_interval = Some(proxy_retry_interval);

        // When each proxy last entered StartErr (message-loop
        // NewProxyResp error). Go frp's proxy_wrapper anchors the
        // StartErr retry on the error time (`lastStartErr.Add(
        // startErrTimeout)`), so a proxy that errors right before a
        // tick must NOT be re-sent at the tick — that would re-arm
        // the error immediately and, for a permanently-rejected
        // proxy (e.g. remote_port in use), hammer the server with a
        // NewProxy every tick while staying in StartErr. The retry
        // arm gates StartErr proxies on
        // `now - last_start_err >= PROXY_RETRY_INTERVAL`, mirroring
        // Go's `startErrTimeout` anchored on the error. Proxies that
        // entered StartErr during the REGISTRATION phase (before the
        // message loop) have no entry here — treated as eligible at
        // the first tick, preserving the pre-loop behavior. Pruned
        // when the proxy leaves StartErr.
        let mut last_start_err: HashMap<String, Instant> = HashMap::new();

        // Persist a partial control-frame read across select iterations
        // (audit finding S3 — HIGH; exact mirror of the server round-14 fix
        // in frp-server/src/control/mod.rs, whose fairness regression test
        // this comment chain mirrors too): the select drops every branch
        // future when another arm wins, and `read_msg`'s two-phase framing
        // (read_exact header, then read_exact payload) keeps its partial
        // state only in the branch future's locals. A peer that splits a
        // frame across two writes while a competing arm wins mid-frame
        // (heartbeat ping tick, proxy-retry tick, health/reload/xtcp/
        // visitor/stop event, heartbeat watchdog, writer failure) would
        // lose the consumed bytes; the next iteration would parse the frame
        // tail as a fresh header — a garbage type/length → protocol error →
        // LoopExit::Reconnect → infinite reconnect churn under a
        // slow-dribbling peer. The boxed future survives the select, so
        // consumed bytes are retained until the frame completes. The loop
        // shape stays fair (no biased branch ordering — tokio::select!
        // without `biased;` randomizes Ready-branch order each round): the
        // read still progresses only at loop top, exactly like a fresh
        // future would, and a mid-frame read is NOT polled again until the
        // select round that follows the competing arm's body. Correctness
        // never relies on the read winning — the future lives in the
        // loop-outer Option, so a lost round drops the branch's reference,
        // not the future: a completed read stays Ready and wins the first
        // round in which no earlier arm is also Ready (a Ready future needs
        // no waker to make progress), and a partial read keeps its consumed
        // bytes until completion. The arm body's reset below therefore can
        // never strand a completed future.
        //
        // The future owns an Arc<Mutex<BoxedReadHalf>> clone and locks
        // inside its own poll, so it borrows nothing from the loop — a
        // loop-local borrow could not be stored across select iterations
        // (the Option's type region would keep the borrow alive for the
        // whole loop, conflicting with the loop-top recreation below).
        type PendingRead =
            Pin<Box<dyn Future<Output = Result<FrpMessage, frp_core::Error>> + Send>>;
        let mut pending_read: Option<PendingRead> = None;

        // Persistent heartbeat-watchdog timer (perf audit LOW): one `Sleep`
        // lives for the whole message loop instead of a fresh
        // `sleep(hb_timeout_dur - last_pong.elapsed())` built on every select
        // iteration — the per-iteration form paid an `Instant::now()` plus a
        // timer construction on every control frame, while the deadline is
        // fully determined by `last_pong` + `hb_timeout_dur`. The deadline is
        // absolute, so the timer is re-armed at the loop top only when a Pong
        // moved `last_pong` or after it has fired (an elapsed `Sleep` polls
        // Ready immediately — the same guard shape as the Wave-1
        // xtcp_session ticker). Cadence is unchanged: the first fire is one
        // full `hb_timeout` after login, and no tick is ever replayed or
        // coalesced, because the reset target is the absolute deadline
        // `last_pong + hb_timeout_dur`, never `now + interval`.
        let mut hb_armed_pong = ctx.last_pong;
        // A hostile heartbeat_timeout (the config preserves i64::MAX raw)
        // makes `last_pong + hb_timeout_dur` overflow `Instant` — a panic
        // that aborts the process under panic=abort. Degrade to never-fire:
        // an absurd interval means "no watchdog", and the deadline is
        // unreachable (round-13 dropped the 3600s clamp on both sides).
        let mut hb_deadline: Option<std::time::Instant> =
            ctx.last_pong.checked_add(ctx.hb_timeout_dur);
        // The timer holds a placeholder deadline while `hb_deadline` is None
        // (overflow); the select arm below is gated off in that state, so
        // the placeholder is never polled and never fires.
        let mut hb_sleep = Box::pin(tokio::time::sleep_until(
            hb_deadline
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(tokio::time::Instant::now),
        ));

        loop {
            // Re-arm the watchdog only when its deadline moved or the timer
            // already fired. A disabled watchdog (heartbeat interval <= 0,
            // hb_watchdog_active false) is never armed at all — its select
            // arm below is gated off, so the timer would never be polled.
            if ctx.hb_watchdog_active && (ctx.last_pong != hb_armed_pong || hb_sleep.is_elapsed()) {
                hb_armed_pong = ctx.last_pong;
                hb_deadline = ctx.last_pong.checked_add(ctx.hb_timeout_dur);
                // Overflow degrades to never-fire (see the initial arm); the
                // placeholder timer is left alone — the gated select arm
                // never polls it.
                if let Some(deadline) = hb_deadline {
                    hb_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::from_std(deadline));
                }
            }
            // Recreate the control-read future when the previous frame
            // completed (the arm body detached it). Starts a fresh read at
            // the next frame boundary. The async block owns an Arc clone
            // and takes the lock only while the frame is in flight.
            if pending_read.is_none() {
                let reader = reader.clone();
                let v2 = ctx.v2;
                pending_read = Some(Box::pin(async move {
                    let mut guard = reader.lock().await;
                    read_msg(&mut *guard, v2).await
                }));
            }
            tokio::select! {
                msg = pending_read.as_mut().expect("pending read armed at loop top") => {
                    // Detach the completed future before handling the
                    // message: the select has dropped the branch future,
                    // and the loop-top `if pending_read.is_none()` above
                    // recreates a fresh one for the next frame. A
                    // `continue` inside the message match below therefore
                    // also restarts the read at the next frame boundary.
                    pending_read = None;
                    match msg {
                        Ok(FrpMessage::ReqWorkConn(_)) => {
                            // Shared with the registration read loop above.
                            self.handle_req_work_conn(ctx);
                        }
                        Ok(FrpMessage::Pong(pong)) => {
                            if let Some(ref err) = pong.error {
                                if !err.is_empty() {
                                    warn!(error = %err, "Pong contains error: {}", err);
                                    return LoopExit::Reconnect;
                                }
                            }
                            debug!("Pong received");
                            ctx.last_pong = Instant::now();
                        }
                        Ok(FrpMessage::Ping(_)) => {
                            // Answer an unsolicited server Ping with Pong
                            // (Go frp client parity). Previously inbound
                            // Ping fell into the ignored-messages bucket, so
                            // a server that probes liveness with Ping would
                            // have its watchdog kill a healthy connection.
                            let pong = FrpMessage::Pong(msg::Pong { error: None });
                            if let Err(e) = writer.send(pong, ctx.v2) {
                                debug!(error = %e, "Pong reply to server Ping failed: {}", e);
                            }
                        }
                        Ok(FrpMessage::CloseProxy(cp)) => {
                            self.handle_close_proxy(cp, ctx, &writer, channels).await;
                        }
                        Ok(FrpMessage::CloseProxyResp(cpr)) => {
                            info!(proxy_name = %cpr.proxy_name, "Server confirmed proxy close: {}", cpr.proxy_name);
                            // Do NOT cancel/remove health check here. This response comes from
                            // our CloseProxy (health check failure → CloseProxy → server → CloseProxyResp).
                            // The health check monitor keeps running for recovery detection (Go frp compat).
                        }
                        Ok(FrpMessage::Error(err)) => {
                            warn!(error = %err.error, "Server error: {}", err.error);
                        }
                        Ok(FrpMessage::NatHoleClient(nhc)) => {
                            // F2 cancel-before-reinsert guard: a reload removal
                            // or health Close at an earlier iteration cancelled
                            // this proxy's P2P token; a NatHoleClient the server
                            // already queued must not re-arm a fresh uncancelled
                            // token here (the punch/bridge would then run until
                            // the peer closes). Bail before the insert — the same
                            // guard therefore covers the spawn in
                            // handle_nat_hole_client (no token, no punch).
                            if !self.punch_proxy_still_live(&nhc.proxy_name).await {
                                debug!(proxy_name = %nhc.proxy_name, "Ignoring NatHoleClient for dead proxy '{}'", nhc.proxy_name);
                                continue;
                            }
                            let proxy_token = self
                                .p2p_bridge_tokens
                                .lock()
                                .await
                                .entry(nhc.proxy_name.clone())
                                .or_insert_with(CancellationToken::new)
                                .clone();
                            self.handle_nat_hole_client(*nhc, &writer, ctx.v2, ctx.session_alive.clone(), proxy_token).await;
                        }
                        Ok(FrpMessage::NatHoleResp(resp)) => {
                            // Lazily resolve the provider's cancel token from the
                            // sid → proxy_name map. A visitor-routed resp (or an
                            // unknown sid) has no pending provider proxy; the
                            // fresh inert token it gets is never inserted into
                            // the map and simply stays uncancelled.
                            let sid = resp.sid.clone().unwrap_or_default();
                            let proxy_name = if sid.is_empty() {
                                None
                            } else {
                                ctx.pending_xtcp.get(&sid).cloned()
                            };
                            // F2 cancel-before-reinsert guard, same race as the
                            // NatHoleClient arm: a reload removal or health Close
                            // cancelled this proxy's P2P token at an earlier
                            // iteration; a NatHoleResp the server already queued
                            // must not re-arm a fresh uncancelled token. Reclaim
                            // the sid's socket + pending_xtcp entries so the
                            // bailed resp cannot leak the STUN UDP socket.
                            let proxy_token = match proxy_name {
                                Some(name) if !name.is_empty() => {
                                    if !self.punch_proxy_still_live(&name).await {
                                        debug!(proxy_name = %name, "Ignoring NatHoleResp for dead proxy '{}'", name);
                                        ctx.pending_xtcp.remove(&sid);
                                        ctx.xtcp_sockets.lock().await.remove(&sid);
                                        continue;
                                    }
                                    self
                                        .p2p_bridge_tokens
                                        .lock()
                                        .await
                                        .entry(name)
                                        .or_insert_with(CancellationToken::new)
                                        .clone()
                                }
                                _ => CancellationToken::new(),
                            };
                            self.handle_nat_hole_resp(*resp, &mut ctx.pending_xtcp, &mut ctx.visitor_pending, &ctx.xtcp_sockets, &writer, ctx.session_alive.clone(), proxy_token).await;
                        }
                        Ok(FrpMessage::NewProxyResp(resp)) => {
                            if let Some(err) = resp.error.as_ref().filter(|e| !e.is_empty()) {
                                warn!(proxy_name = %resp.proxy_name, error = %err, "Proxy '{}' registration error: {}", resp.proxy_name, err);
                                // Update phase if proxy was being retried (WaitStart -> StartErr).
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&resp.proxy_name) {
                                    if info.phase == ProxyPhase::WaitStart {
                                        info.err = err.clone();
                                        info.phase = ProxyPhase::StartErr(err.clone());
                                        // Anchor the StartErr retry on the error
                                        // time (Go frp: lastStartErr.Add(
                                        // startErrTimeout)) so the next tick
                                        // does not immediately re-send.
                                        last_start_err.insert(
                                            resp.proxy_name.clone(),
                                            Instant::now(),
                                        );
                                    }
                                }
                            } else {
                                // Successful registration from retry path.
                                // Accept it from WaitStart (normal) or
                                // StartErr (a healthy response that just
                                // missed the 30s retry deadline must not
                                // be thrown away — Go frp keeps
                                // re-registering until the response
                                // lands).
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&resp.proxy_name) {
                                    if info.phase == ProxyPhase::WaitStart
                                        || matches!(info.phase, ProxyPhase::StartErr(_))
                                    {
                                        if let Some(ref remote) = resp.remote_addr {
                                            info.remote_addr.clone_from(remote);
                                        }
                                        info.err.clear();
                                        info.phase = ProxyPhase::Running;
                                        info!(proxy_name = %resp.proxy_name, "Proxy '{}' re-registered", resp.proxy_name);
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetRouteAdvertise(adv)) => {
                            // Isolation: only accept routes for virtual nets
                            // this client participates in. Advertisements for
                            // other vnets are ignored (design spec: different
                            // virtual nets have isolated routing tables).
                            let vnet = adv.virtual_net.clone().unwrap_or_default();
                            if !local_vnet_set(&*self.cfg.read().await).contains(&vnet) {
                                debug!(
                                    vnet,
                                    proxy_name = %adv.proxy_name,
                                    "ignoring vnet route advertisement for unknown virtual net"
                                );
                            } else {
                                info!(vnet, subnet = %adv.subnet, proxy_name = %adv.proxy_name, "peer vnet route advertisement received");
                                // Update the shared route table (TX direction lookup).
                                {
                                    let route_table = self.vnet_controller.route_table();
                                    let mut routes = route_table.write().await;
                                    if let Err(e) =
                                        routes.insert(&vnet, &adv.proxy_name, &adv.subnet)
                                    {
                                        warn!(%e, "failed to add vnet route");
                                    }
                                }
                                // Inject OS route so the kernel sends matching packets
                                // through the TUN device instead of the default gateway.
                                // vnet_tun_names is keyed by *local* proxy name, while
                                // adv.proxy_name is the *remote* peer's name — so match
                                // by virtual_net (the route's isolation domain, already
                                // validated above) instead of by name. The local vnet
                                // proxy owning that virtual net is the one whose TUN must
                                // carry this route; with no local TUN for the net (e.g.
                                // this client is only a visitor) there is nothing to
                                // inject, which is correct — the old code grabbed an
                                // arbitrary TUN and silently misrouted.
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                {
                                    let local_tun_proxy: Option<String> = {
                                        let cfg = self.cfg.read().await;
                                        cfg.proxies
                                            .iter()
                                            .find(|p| {
                                                p.proxy_type == "vnet" && p.virtual_net == vnet
                                            })
                                            .map(|p| p.name.clone())
                                    };
                                    let names = self.vnet_tun_names.lock().await;
                                    if let Some(tun_name) =
                                        local_tun_proxy.as_deref().and_then(|n| names.get(n))
                                    {
                                        add_os_route(&adv.subnet, tun_name);
                                        self.vnet_peer_routes.lock().await.insert(
                                            adv.proxy_name.clone(),
                                            (
                                                adv.subnet.clone(),
                                                tun_name.clone(),
                                                vnet.clone(),
                                            ),
                                        );
                                    } else {
                                        debug!(
                                            vnet,
                                            proxy_name = %adv.proxy_name,
                                            "vnet route advertise: no local TUN for virtual net '{}' — skipping OS route",
                                            vnet
                                        );
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetPacket(vpkt)) => {
                            match frp_core::base64::decode(&vpkt.data) {
                                Ok(packet) => {
                                    // Virtual_net visitors first: deliver into
                                    // the visitor's STCP/XTCP tunnel. TUN-backed
                                    // vnet proxies fall back to their TUN channel
                                    // only when no visitor consumed the packet
                                    // (Err returns the packet untouched).
                                    match self
                                        .vnet_controller
                                        .deliver_visitor_packet(&vpkt.proxy_name, packet)
                                    {
                                        Ok(()) => {}
                                        Err(packet) => {
                                            let txs = self
                                                .vnet_tun_tx
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            if let Some(tx) = txs.get(&vpkt.proxy_name) {
                                                // Single destination: the Vec
                                                // moves into the Arc (no copy).
                                                if tx.try_send(Arc::from(packet)).is_err() {
                                                    warn!(proxy_name = %vpkt.proxy_name, "vnet TUN channel closed");
                                                }
                                            } else {
                                                debug!(proxy_name = %vpkt.proxy_name, "vnet packet dropped: no visitor or TUN target");
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(%e, "VnetPacket base64 decode error");
                                }
                            }
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetRouteRemove(adv)) => {
                            // Isolation: mirror the advertise handler — only
                            // accept removals for virtual nets this client
                            // participates in. Removals for other vnets are
                            // ignored (defensive symmetry; in practice there
                            // is no matching route to clean up anyway).
                            let vnet = adv.virtual_net.clone().unwrap_or_default();
                            if !local_vnet_set(&*self.cfg.read().await).contains(&vnet) {
                                debug!(
                                    vnet,
                                    proxy_name = %adv.proxy_name,
                                    "ignoring vnet route removal for unknown virtual net"
                                );
                            } else {
                                info!(vnet, proxy_name = %adv.proxy_name, "peer vnet route removed");
                                if let Some((subnet, tun_name, _)) = self
                                    .vnet_peer_routes
                                    .lock()
                                    .await
                                    .remove(&adv.proxy_name)
                                {
                                    remove_os_route(&subnet, &tun_name);
                                }
                                self.vnet_controller
                                    .route_table()
                                    .write()
                                    .await
                                    .remove(&vnet, &adv.proxy_name);
                                self.vnet_controller
                                    .unregister_visitor_route(&adv.proxy_name)
                                    .await;
                            }
                        }
                        Ok(_) => {
                            // Other messages are ignored
                        }
                        Err(e) => {
                            warn!(error = %e, "Control read error: {}. Reconnecting...", e);
                            return LoopExit::Reconnect;
                        }
                    }
                }

                _ = async {
                    if let Some(ref mut interval) = ctx.ping_interval {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    let mut ping_msg = msg::Ping {
                        privilege_key: None,
                        timestamp: None,
                    };
                    // Go frp v0.71.0: ping auth failures skip this heartbeat
                    // instead of tearing the session down.
                    let mut skip_ping = false;
                    // Auth scopes: unioning the client's own scopes with the
                    // server-advertised scopes is a Rust-to-Rust extension.
                    // Go v0.70.1's TokenAuthSetterVerifier.SetPing checks only
                    // the client's own additionalAuthScopes
                    // (pkg/auth/token.go:44-51); Go has no
                    // serverAdditionalAuthScopes field in LoginResp, so the
                    // server side of this union is ignored by Go peers.
                    let send_auth = crate::backoff::heartbeat_requires_auth(
                        &ctx.client_scopes,
                        &ctx.server_scopes,
                    );
                    if send_auth {
                        if let Some(ref oidc) = self.oidc_client {
                            if let Err(e) = oidc.set_ping(&mut ping_msg).await {
                                // Go frp v0.71.0: ping auth failure only
                                // SKIPS this heartbeat — the session stays
                                // up and the next heartbeat retries
                                // (client/control.go "skip sending ping
                                // message"). A full reconnect is wasted when
                                // the control link is healthy.
                                warn!(error = %e, "OIDC ping token failed, skipping this ping");
                                skip_ping = true;
                            }
                        } else {
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;
                            match self.auth_cfg.try_generate_login_key(ts) {
                                Ok(key) => {
                                    ping_msg.privilege_key = Some(key);
                                    ping_msg.timestamp = Some(ts);
                                }
                                Err(e) => {
                                    warn!(error = %e, "Ping token source failed, skipping this ping");
                                    skip_ping = true;
                                }
                            }
                        }
                    }
                    if skip_ping {
                        // Go parity (client/control.go:253-265): a ping whose
                        // auth setup failed is retried on a fast exponential
                        // backoff instead of at the next interval tick — a
                        // token outage is probed within ~2s, not after a full
                        // heartbeat_interval (+watchdog). Go's
                        // wait.BackoffUntil re-arms the ticker itself, so the
                        // retry REPLACES the next interval tick: reset_after
                        // points the existing interval at now + backoff. The
                        // session stays up (skip, not teardown — a reconnect
                        // is wasted when the control link is healthy).
                        if let Some(interval) = ctx.ping_interval.as_mut() {
                            let delay = next_ping_backoff(ctx.ping_retry_backoff, interval.period());
                            ctx.ping_retry_backoff = Some(delay);
                            interval.reset_after(delay);
                        }
                        continue;
                    }
                    let ping = FrpMessage::Ping(ping_msg);
                    if let Err(e) = writer.send(ping, ctx.v2) {
                        warn!(error = %e, "Ping write failed: {}", e);
                        // Non-fatal: heartbeat timeout will detect actual dead connection.
                    } else {
                        debug!("Ping sent");
                    }
                    // A non-skipped attempt ends the failure streak (Go's
                    // sendHeartBeat returns no error here — even a failed
                    // Send is swallowed with `_ =`, so only auth failures
                    // engage the backoff). The next attempt runs on the
                    // interval cadence again.
                    ctx.ping_retry_backoff = None;
                }

                _ = ctx
                    .proxy_retry_interval
                    .as_mut()
                    .expect("proxy retry interval available")
                    .tick() => {
                    let now = Instant::now();
                    let mut to_retry: Vec<(String, String)> = {
                        let map = self.proxy_info_map.read().await;
                        map.iter()
                            .filter(|(_, info)| matches!(info.phase, ProxyPhase::StartErr(_)))
                            // Go frp parity: a StartErr proxy is retried only
                            // once a full interval has elapsed since ITS last
                            // error (lastStartErr.Add(startErrTimeout)) — not
                            // on the tick boundary. A permanently-rejected
                            // proxy therefore gets at most one NewProxy per
                            // interval instead of one per tick (which, when
                            // an error lands just before a tick, re-arms the
                            // error and re-sends immediately — hammering the
                            // server). Proxies that entered StartErr during
                            // registration have no entry here; they are
                            // eligible at the first tick (pre-loop behavior).
                            .filter(|(name, _)| {
                                last_start_err
                                    .get(*name)
                                    .is_none_or(|t| now.duration_since(*t) >= *PROXY_RETRY_INTERVAL)
                            })
                            .map(|(name, info)| (name.clone(), info.local_addr.clone()))
                            .collect()
                    };
                    // Fold proxies stuck in WaitStart past the
                    // WaitStart response timeout into the retry set. A NewProxy that is never
                    // answered (a silent server that still Pongs) keeps the
                    // proxy in WaitStart — the StartErr transition happens
                    // only on a NewProxyResp error, so without this check a
                    // single unanswered retry would stop the retries
                    // forever. Go frp parity: proxy_wrapper re-arms
                    // waitResponseTimeout while in waitStart and retries
                    // indefinitely. `waitstart_seen` records when each
                    // proxy last entered WaitStart (initial registration or
                    // a retry send) and is pruned once it leaves WaitStart
                    // (registered, errored, or closed).
                    {
                        let map = self.proxy_info_map.read().await;
                        ctx.waitstart_seen.retain(|name, _| {
                            map.get(name).is_some_and(|info| {
                                info.phase == ProxyPhase::WaitStart
                            })
                        });
                        // Prune StartErr anchors for proxies that left
                        // StartErr (registered, closed, or re-entered
                        // WaitStart via a retry send below).
                        last_start_err.retain(|name, _| {
                            map.get(name).is_some_and(|info| {
                                matches!(info.phase, ProxyPhase::StartErr(_))
                            })
                        });
                        for (name, info) in map.iter() {
                            if info.phase == ProxyPhase::WaitStart
                                && !ctx.waitstart_seen.contains_key(name)
                            {
                                // First observed in WaitStart at this tick
                                // (e.g. the initial registration left it
                                // pending past retry setup): start its
                                // clock now.
                                ctx.waitstart_seen.insert(name.clone(), now);
                            }
                        }
                        to_retry.extend(map.iter().filter_map(|(name, info)| {
                            if info.phase == ProxyPhase::WaitStart
                                && ctx.waitstart_seen.get(name).is_some_and(|first_seen| {
                                    // saturating_sub: an env-shrunk
                                    // interval below the 100ms grace must
                                    // not underflow (panic).
                                    now.duration_since(*first_seen)
                                        >= (*WAIT_START_RETRY_TIMEOUT)
                                            .saturating_sub(PROXY_RETRY_GRACE)
                                })
                            {
                                Some((name.clone(), info.local_addr.clone()))
                            } else {
                                None
                            }
                        }));
                    }
                    if !to_retry.is_empty() {
                        // Retry candidates come from the LIVE proxy set:
                        // try_reload refreshes self.proxies, so a proxy
                        // ADDED by a reload that failed to register
                        // (StartErr) is retried too — the session-start
                        // `proxies` snapshot (still used by the
                        // registration loop above) would miss it.
                        // Lock order: proxies read then cfg read (the
                        // session loop takes them in the opposite order).
                        // Not a deadlock: both locks' writers (try_reload)
                        // run only in this message-loop task, so these read
                        // guards never contend with a writer across tasks.
                        let all_proxies = Arc::clone(&*self.proxies.read().await);
                        let retry_candidates =
                            filter_active_proxies(&*self.cfg.read().await, &all_proxies);
                        // Hoist the wire-name prefix (format! allocates); it is
                        // loop-invariant within this tick.
                        let cfg_user_prefix = if ctx.cfg_user.is_empty() {
                            None
                        } else {
                            Some(format!("{}.", ctx.cfg_user))
                        };
                        for (name, local_addr) in to_retry {
                            let bare_name = match &cfg_user_prefix {
                                Some(prefix) => name.strip_prefix(prefix).unwrap_or(&name),
                                None => name.as_str(),
                            };
                            if let Some(p) = retry_candidates.iter().find(|p| p.name == bare_name) {
                                let new_proxy = crate::proxy::create_new_proxy_msg(p, &local_addr, &ctx.cfg_user);
                                if let Err(e) = writer.send(new_proxy, ctx.v2) {
                                    warn!(proxy_name = %name, error = %e, "Proxy '{}' retry: write NewProxy failed: {}", name, e);
                                } else {
                                    info!(proxy_name = %name, "Proxy '{}' retry: sent NewProxy", name);
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&name) {
                                        info.phase = ProxyPhase::WaitStart;
                                    }
                                    // Re-arm the WaitStart clock at the send
                                    // (Go frp's proxy_wrapper re-arms
                                    // startErrTimeout per NewProxy send).
                                    ctx.waitstart_seen.insert(name.clone(), Instant::now());
                                }
                            }
                        }
                    }
                }

                Some(event) = channels.health_rx.recv() => {
                    match event {
                        HealthEvent::Close(proxy_name) => {
                            info!(proxy_name = %proxy_name, "Health check sending CloseProxy for unhealthy proxy: {}", proxy_name);
                            // Cancel + drop the XTCP P2P bridge token for this
                            // proxy, mirroring the CloseProxy handler: a
                            // health-closed XTCP provider must not leave its
                            // in-flight P2P bridge + UDP socket running.
                            let mut tokens = self.p2p_bridge_tokens.lock().await;
                            if let Some(token) = tokens.remove(&proxy_name) {
                                token.cancel();
                            }
                            // Set phase to CheckFailed before sending CloseProxy
                            // (Go frp compat: PhaseCheckFailed is an explicit state in proxy lifecycle).
                            {
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&proxy_name) {
                                    info.phase = ProxyPhase::CheckFailed;
                                }
                            }
                            let close = FrpMessage::CloseProxy(msg::CloseProxy {
                                proxy_name: proxy_name.clone(),
                            });
                            if let Err(e) = writer.send(close, ctx.v2) {
                                warn!(proxy_name = %proxy_name, error = %e, "Failed to send CloseProxy for {}: {}", proxy_name, e);
                            }
                            // Keep health check running -- monitor for recovery (Go frp compat).
                        }
                        HealthEvent::Recover(proxy_name) => {
                            info!(proxy_name = %proxy_name, "Health check recovered for '{}', re-registering", proxy_name);
                            // Look up proxy config and send NewProxy to re-register.
                            let need_send = {
                                let configs = self.health_proxy_configs.lock().await;
                                configs.get(&proxy_name).cloned()
                            };
                            if let Some(cfg) = need_send {
                                let local_addr = self.proxy_info_map.read().await
                                    .get(&proxy_name)
                                    .map(|info| info.local_addr.clone())
                                    .unwrap_or_else(|| format!("{}:{}", cfg.local_ip, cfg.local_port));
                                // Set phase to WaitStart so NewProxyResp handler
                                // transitions it to Running on success (Go frp compat:
                                // CheckFailed -> re-register -> Running).
                                {
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&proxy_name) {
                                        info.phase = ProxyPhase::WaitStart;
                                    }
                                }
                                let new_proxy = crate::proxy::create_new_proxy_msg(&cfg, &local_addr, &ctx.cfg_user);
                                if let Err(e) = writer.send(new_proxy, ctx.v2) {
                                    warn!(proxy_name = %proxy_name, error = %e, "Failed to re-register proxy on health recovery: {}", e);
                                } else {
                                    info!(proxy_name = %proxy_name, "Health recovery: re-registered proxy '{}'", proxy_name);
                                }
                            } else {
                                warn!(proxy_name = %proxy_name, "Health check recovered but no config found for '{}'", proxy_name);
                            }
                        }
                    }
                }

                Some(req) = channels.reload_rx.recv() => {
                    let result = match &self.config_file {
                        Some(path) => self.try_reload(path, req.strict, &writer).await,
                        None => Err("no config file path stored".into()),
                    };
                    if result.is_ok()
                        && self.visitor_reload_needed.swap(false, Ordering::AcqRel)
                    {
                        // Visitor changes require a clean session restart.
                        tracing::info!("Visitor config changed — restarting session");
                        let _ = req.reply.send(Ok("reload success: visitor changes applied on session restart".into()));
                        return LoopExit::Reconnect;
                    }
                    let _ = req.reply.send(result);
                }

                Some(xtcp_notif) = channels.xtcp_rx.recv() => {
                    let XtcpNotification { sid, proxy_name } = xtcp_notif;
                    info!(proxy_name = %proxy_name, "XTCP provider: received NatHoleSid for '{}'", proxy_name);
                    // STUN discovery runs off the control loop: two STUN
                    // round-trips can stall up to ~10s and would block the
                    // message loop (heartbeats, work conns, reloads). The
                    // spawned task does the STUN, persists the socket, and
                    // hands the finished NatHoleClient back for the loop to
                    // write + bookkeep, preserving the write-before-NatHoleResp
                    // ordering.
                    let stun_server = channels.nat_hole_stun_server.to_string();
                    let stun_sockets = Arc::clone(&ctx.xtcp_sockets);
                    let stun_tx = ctx
                        .stun_result_tx
                        .as_ref()
                        .expect("stun_result_tx available before STUN spawn")
                        .clone();
                    tokio::spawn(async move {
                        // 1. Do STUN discovery on a persistent UDP socket.
                        //    Go frps needs ≥2 mapped addresses for NAT classification.
                        let mut mapped_addrs = Vec::new();
                        let stun_socket = match frp_core::stun::stun_binding_with_details(&stun_server).await {
                            Ok((sock, result1)) => {
                                let addr1 = result1.mapped_addr;
                                debug!(addr = %addr1, "XTCP STUN #1: {}", addr1);
                                mapped_addrs.push(addr1);
                                // Use OTHER-ADDRESS as second STUN target if available
                                // (Go frp v0.70 discovery.go:137 dual-server probing).
                                // This gives the server a second mapped address for NAT
                                // classification (RFC 5780, detects endpoint-independent
                                // vs address-dependent mapping).
                                let second_target =
                                    result1.other_addr.as_deref().unwrap_or(&stun_server);
                                match frp_core::stun::stun_binding_on_socket(&sock, second_target).await {
                                    Ok(addr2) => {
                                        debug!(addr = %addr2, "XTCP STUN #2 from '{}': {}", second_target, addr2);
                                        // Go frps NAT classifier needs ≥2 addresses.
                                        // Always push — Go frp doesn't dedup.
                                        mapped_addrs.push(addr2);
                                    }
                                    Err(e) => warn!(error = %e, "XTCP STUN #2 failed: {}", e),
                                }
                                Some(sock)
                            }
                            Err(e) => {
                                warn!(error = %e, "XTCP STUN failed: {}", e);
                                None
                            }
                        };
                        // Get the local port from the STUN socket for assisted_addrs.
                        // Go frp compat: assisted_addrs = local IPs + STUN port, NOT STUN
                        // mapped addresses. The server uses assisted_addrs as localIPs
                        // parameter to ClassifyNATFeature — STUN addresses would never
                        // match local interfaces, causing misclassification.
                        let local_port = stun_socket
                            .as_ref()
                            .and_then(|sock| sock.local_addr().ok())
                            .map(|addr| addr.port());
                        // Save socket for later UDP+KCP hole punch.
                        if let Some(sock) = stun_socket {
                            stun_sockets
                                .lock()
                                .await
                                .insert(sid.clone(), std::sync::Arc::new(sock));
                        }
                        // Build assisted_addrs from local IPs + STUN port.
                        // Go frp v0.69.1: ListLocalIPsForNatHole returns non-loopback
                        // IPv4 addresses filtered from all network interfaces.
                        let assisted_addrs: Option<Vec<String>> = local_port.and_then(|port| {
                            let local_ips = crate::nat_hole::list_local_ips_for_nat_hole(10);
                            if local_ips.is_empty() {
                                None
                            } else {
                                Some(
                                    local_ips
                                        .iter()
                                        .map(|ip| format!("{}:{}", ip, port))
                                        .collect(),
                                )
                            }
                        });
                        // 2. Send NatHoleClient on control (Go v0.70 compat: protocol "kcp").
                        // Use a unique transaction_id per request (Go frp compat: UUID).
                        let txn_id = uuid::Uuid::new_v4().to_string();
                        let client_msg = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
                            transaction_id: txn_id.clone(),
                            proxy_name: proxy_name.clone(),
                            sid: Some(sid.clone()),
                            protocol: Some("kcp".to_string()),
                            mapped_addrs: if mapped_addrs.is_empty() { None } else { Some(mapped_addrs) },
                            assisted_addrs,
                            visitor_addr: None,
                        }));
                        // Hand the finished message back to the control loop.
                        if stun_tx
                            .send(StunResult { sid, proxy_name, msg: client_msg })
                            .await
                            .is_err()
                        {
                            warn!("XTCP: control loop dropped STUN result channel");
                        }
                    });
                }

                // STUN finished off-loop: write NatHoleClient on the control
                // connection and track sid→proxy_name for NatHoleResp routing.
                Some(stun_result) = ctx
                    .stun_result_rx
                    .as_mut()
                    .expect("stun_result_rx available before STUN result recv")
                    .recv() => {
                    let StunResult { sid, proxy_name, msg } = stun_result;
                    if let Err(e) = writer.send(msg, ctx.v2) {
                        warn!(error = %e, "XTCP: failed to send NatHoleClient: {}", e);
                        // The STUN socket was stored in xtcp_sockets but no
                        // pending_xtcp entry was created; reclaim it now so it
                        // does not sit until control-loop teardown.
                        ctx.xtcp_sockets.lock().await.remove(&sid);
                    } else {
                        ctx.pending_xtcp.insert(sid.clone(), proxy_name);
                        // Defensive cleanup: if the server never sends
                        // NatHoleResp for this sid, the socket + pending_xtcp
                        // entry would leak until the control loop tears down.
                        // Reclaim them after the server's NAT session window
                        // (NAT_HOLE_TIMEOUT = 10s) plus margin. If NatHoleResp
                        // arrives in time, handle_nat_hole_resp already removed
                        // both entries and these removes are no-ops.
                        let cleanup_sockets = Arc::clone(&ctx.xtcp_sockets);
                        let cleanup_tx = xtcp_cleanup_tx.clone();
                        let cleanup_sid = sid.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(15)).await;
                            cleanup_sockets.lock().await.remove(&cleanup_sid);
                            let _ = cleanup_tx.send(cleanup_sid).await;
                        });
                    }
                }

                // A NatHoleResp never arrived within the timeout window:
                // reclaim the pending provider-side entry (socket already
                // removed) and any residual visitor-side sender. `cleanup_sid`
                // carries either a provider sid or a visitor txn_id; the two
                // namespaces are independent, so reclaiming from both is
                // always safe (see reclaim_stale_xtcp_entry).
                Some(cleanup_sid) = ctx
                    .xtcp_cleanup_rx
                    .as_mut()
                    .expect("xtcp_cleanup_rx available before cleanup recv")
                    .recv() => {
                    if reclaim_stale_xtcp_entry(
                        &mut ctx.pending_xtcp,
                        &mut ctx.visitor_pending,
                        &cleanup_sid,
                    ) {
                        debug!(sid = %cleanup_sid, "XTCP: reclaimed stale entry for '{}'", cleanup_sid);
                    }
                }

                // Visitor requests: send NatHoleVisitor on control connection.
                // Go frps v0.69.1 only handles NatHoleVisitor on the control
                // connection path, not on fresh TCP connections.
                Some(vreq) = channels.visitor_rx.recv() => {
                    let txn_id = vreq.nhv.transaction_id.clone();
                    let nhv = FrpMessage::NatHoleVisitor(vreq.nhv);
                    match writer.send(nhv, ctx.v2) {
                        Ok(()) => {
                            debug!(sid = %txn_id, "Visitor: sent NatHoleVisitor on control, sid={}", txn_id);
                            ctx.visitor_pending.insert(txn_id.clone(), vreq.reply);
                            // Defensive cleanup: if the server never sends a
                            // NatHoleResp for this txn, the visitor_pending
                            // entry would otherwise sit until control-loop
                            // teardown. Reclaim it after 20s. Why 20s: the
                            // visitor side gives up after its own 15s timeout
                            // (visitor.rs), so by the time we run the
                            // receiver is already dropped and the entry is
                            // only reclaimed after the visitor stopped
                            // waiting — we never preempt a slow-but-valid
                            // response. The server's NAT session window is
                            // 10s plus network latency, well under 20s. If
                            // NatHoleResp arrives in time,
                            // handle_nat_hole_resp already removed the entry
                            // and this is a no-op.
                            let cleanup_tx = xtcp_cleanup_tx.clone();
                            let cleanup_key = txn_id.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(20)).await;
                                // Channel closed (control loop exited) — ignore.
                                let _ = cleanup_tx.send(cleanup_key).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Visitor: failed to send NatHoleVisitor on control: {}", e);
                            let _ = vreq.reply.send(Err(format!("send failed: {e}")));
                        }
                    }
                }

                Some(()) = channels.stop_rx.recv() => {
                    info!("Stop requested, shutting down");
                    ctx.shutdown_flag.store(true, Ordering::SeqCst);
                    return LoopExit::Shutdown;
                }

                // Heartbeat timeout watchdog: triggers reconnect if no Pong
                // received within heartbeat_timeout seconds (Go frp compat).
                // Event-driven: the persistent timer armed at the loop top
                // (hb_sleep) waits until the absolute deadline (last_pong +
                // hb_timeout_dur), so each Pong arrival re-arms it there
                // instead of rebuilding a `Sleep` per iteration. Uses sleep
                // so the timer is only active when hb_timeout > 0. Explicit
                // negative values disable it independently of tcp_mux.
                // Gated on the ping loop being active (hb_watchdog_active):
                // with heartbeat_interval <= 0 no Pong can ever arrive. Also
                // gated on hb_deadline (Some): an overflowing timeout
                // degrades the watchdog to never-fire, so its placeholder
                // timer must never be polled here.
                _ = &mut hb_sleep, if ctx.hb_watchdog_active && hb_deadline.is_some() => {
                    warn!("Heartbeat timeout ({}s), reconnecting...", ctx.hb_timeout);
                    return LoopExit::Reconnect;
                }
                // The dedicated writer task hit a write failure (peer
                // dead / connection reset on the control path). Tear down
                // and reconnect, mirroring the read-error branch.
                _ = writer.wait_failed() => {
                    warn!("Control writer failed, reconnecting...");
                    return LoopExit::Reconnect;
                }
            }
        }
    }

    /// Handle a server-initiated `CloseProxy` for one proxy: mark it
    /// `Closed` (unless a same-name registration is in flight), stop its
    /// health monitor and its XTCP P2P bridge token, and release its local
    /// resources — the plugin listener handle and the vnet TUN controller —
    /// mirroring the reload-removal commit phase. A proxy in `New`/
    /// `WaitStart` is skipped: the `CloseProxy` belongs to an OLD registration
    /// whose authoritative phase arrives with its own `NewProxyResp`.
    ///
    /// Extracted from the `run_message_loop` `CloseProxy` arm by the P2 S3b
    /// seam. The arm was terminal — nothing follows the `select!` inside the
    /// loop, so its `continue` resumed at the loop top, which is exactly where
    /// falling off the branch body lands — and that `continue` is the `return`
    /// here. Every other statement, its order and all five `.await`s are
    /// unchanged; the one further delta is the vnet teardown's writer argument
    /// (`writer`, not the original `&writer`: this parameter is already a
    /// `&Arc<ControlWriter>`, so the re-borrow is a clippy `needless_borrow` —
    /// the same reference reaches `remove_vnet_tun`). Called inline from the
    /// loop, never spawned: the retry arm's lock-order note ("both locks'
    /// writers run only in this message-loop task") holds only while that stays
    /// true.
    async fn handle_close_proxy(
        &self,
        cp: msg::CloseProxy,
        // `&mut`, not `&`: `SessionCtx` holds the boxed reader half, so it is
        // `Send` but NOT `Sync` — a shared `&SessionCtx` held across this fn's
        // awaits makes `run_message_loop`'s future non-`Send`, which the
        // spawned `client_service.run()` call sites in the client integration
        // tests require. The body only reads `ctx.cfg_user` and `ctx.v2`, so
        // the exclusive borrow is a type-level requirement, not a mutation.
        ctx: &mut SessionCtx,
        // Read only by the vnet teardown below (same reason
        // `spawn_session_tasks` allows its `proxies` binding unused).
        #[cfg_attr(not(feature = "vnet"), allow(unused_variables))] writer: &Arc<ControlWriter>,
        channels: &SessionChannels<'_>,
    ) {
        info!(proxy_name = %cp.proxy_name, "Server closed proxy: {}", cp.proxy_name);
        // Registration race: a server CloseProxy for an
        // OLD registration can land while a same-name
        // reload re-registration (phase New/WaitStart) is
        // in flight. Marking it Closed would kill the NEW
        // proxy — Closed is excluded from the retry loop
        // and the health-monitor kill below is not re-armed
        // — so skip the teardown when a registration is
        // pending; the authoritative phase comes from its
        // NewProxyResp. (Go deletes the entry by name —
        // same-keyed semantics — so this is client-side
        // robustness beyond parity.)
        let kill = {
            let mut map = self.proxy_info_map.write().await;
            match map.get_mut(&cp.proxy_name) {
                Some(info) if matches!(info.phase, ProxyPhase::New | ProxyPhase::WaitStart) => {
                    false
                }
                Some(info) => {
                    info.phase = ProxyPhase::Closed;
                    true
                }
                None => true, // absent: still reap stale handles
            }
        };
        if !kill {
            return;
        }
        // Cancel health check task and remove map entry.
        let mut cancels = channels.health_cancels.lock().await;
        if let Some(cancel) = cancels.get(&cp.proxy_name) {
            cancel.store(true, Ordering::Relaxed);
        }
        cancels.remove(&cp.proxy_name);
        // Cancel any XTCP P2P bridge tasks for this proxy
        // and drop the token (a re-registered proxy gets a
        // fresh token via lazy get_or_insert_with).
        let mut tokens = self.p2p_bridge_tokens.lock().await;
        if let Some(token) = tokens.remove(&cp.proxy_name) {
            token.cancel();
        }
        // Mirror the reload-removal path (try_reload
        // commit phase): drop the local plugin listener
        // handle — PluginHandle::Drop fires the shutdown
        // oneshot, so the plugin task exits and its bind
        // port is released — and tear down the vnet TUN
        // controller. Without this, a server-initiated
        // CloseProxy (dashboard delete) leaves the plugin
        // listener and TUN running even though the proxy
        // is gone (finding 2).
        //
        // plugin_handles and the vnet maps are keyed by
        // the BARE proxy name (start_plugin /
        // register_vnet_tun), while the wire CloseProxy
        // name carries the {user.} prefix — strip it.
        let bare_name = if ctx.cfg_user.is_empty() {
            cp.proxy_name.clone()
        } else {
            let prefix = format!("{}.", ctx.cfg_user);
            cp.proxy_name
                .strip_prefix(&prefix)
                .unwrap_or(&cp.proxy_name)
                .to_string()
        };
        // Teardown order mirrors try_reload: vnet TUN
        // removal first, then the plugin handle drop.
        #[cfg(feature = "vnet")]
        {
            let vnet = self
                .cfg
                .read()
                .await
                .proxies
                .iter()
                .find(|p| p.name == bare_name)
                .map(|p| p.virtual_net.clone())
                .unwrap_or_default();
            remove_vnet_tun(
                &self.vnet_tuns,
                &self.vnet_tun_tx,
                &self.vnet_tun_cancels,
                &self.vnet_tun_names,
                &self.vnet_tun_subnets,
                &self.vnet_controller.route_table(),
                &self.vnet_peer_routes,
                writer,
                ctx.v2,
                &bare_name,
                &vnet,
            )
            .await;
        }
        {
            let mut handles = self
                .plugin_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if handles.remove(&bare_name).is_some() {
                debug!(proxy_name = %bare_name, "CloseProxy: dropped plugin handle for '{}'", bare_name);
            }
        }
        // The Closed phase (set above, outside the lock
        // order used by HealthEvent): the server's nathole
        // session outlives the close (NAT_HOLE_TIMEOUT =
        // 10s), so a late NatHoleClient/NatHoleResp would
        // otherwise punch/bridge for a proxy the server
        // just deleted — punch_proxy_still_live must reject
        // it (matches the health-Close CheckFailed marking
        // in HealthEvent).
    }
}
