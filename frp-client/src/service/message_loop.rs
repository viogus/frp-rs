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
                    // recreates a fresh one for the next frame. Every
                    // non-terminal path in the match below falls off this arm
                    // body, which restarts the read at the next boundary.
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
                            self.handle_nat_hole_client_arm(nhc, ctx, &writer).await;
                        }
                        Ok(FrpMessage::NatHoleResp(resp)) => {
                            self.handle_nat_hole_resp_arm(resp, ctx, &writer).await;
                        }
                        Ok(FrpMessage::NewProxyResp(resp)) => {
                            self.handle_new_proxy_resp_arm(resp, &mut last_start_err).await;
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetRouteAdvertise(adv)) => {
                            self.handle_vnet_route_advertise_arm(adv).await;
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetPacket(vpkt)) => {
                            self.handle_vnet_packet_arm(vpkt).await;
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetRouteRemove(adv)) => {
                            self.handle_vnet_route_remove_arm(adv).await;
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
                    self.handle_ping_tick_arm(ctx, &writer).await;
                }

                _ = ctx
                    .proxy_retry_interval
                    .as_mut()
                    .expect("proxy retry interval available")
                    .tick() => {
                    self.handle_proxy_retry_tick_arm(ctx, &writer, &mut last_start_err).await;
                }

                Some(event) = channels.health_rx.recv() => {
                    self.handle_health_event_arm(event, ctx, &writer).await;
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
                    self.handle_xtcp_notify_arm(xtcp_notif, ctx, channels).await;
                }

                // STUN finished off-loop: write NatHoleClient on the control
                // connection and track sid→proxy_name for NatHoleResp routing.
                Some(stun_result) = ctx
                    .stun_result_rx
                    .as_mut()
                    .expect("stun_result_rx available before STUN result recv")
                    .recv() => {
                    self.handle_stun_result_arm(stun_result, ctx, &writer, &xtcp_cleanup_tx).await;
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
                    self.handle_xtcp_cleanup_arm(cleanup_sid, ctx).await;
                }

                // Visitor requests: send NatHoleVisitor on control connection.
                // Go frps v0.69.1 only handles NatHoleVisitor on the control
                // connection path, not on fresh TCP connections.
                Some(vreq) = channels.visitor_rx.recv() => {
                    self.handle_visitor_request_arm(vreq, ctx, &writer, &xtcp_cleanup_tx).await;
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

    /// Handle a server-sent `NatHoleClient` (XTCP provider side): drop the
    /// frame if the proxy's P2P bridge token was already cancelled (a reload
    /// removal or a health Close), otherwise arm the token and delegate the
    /// punch to `Self::handle_nat_hole_client`.
    ///
    /// Extracted from the `run_message_loop` `NatHoleClient` arm by the P2 S3b
    /// seam (group A). The arm was terminal — nothing follows the `select!`
    /// inside the loop, so its `continue` resumed at the loop top, which is
    /// exactly where falling off this body lands — and that `continue` is the
    /// `return` here. It bound to the message loop, not to an inner one: the
    /// arm contains no `for`/`while`/`loop` (the only textual match is the
    /// English word "for" inside a log string). Called inline from the loop,
    /// never spawned: the retry arm's lock-order note ("both locks' writers
    /// run only in this message-loop task") holds only while that stays true.
    async fn handle_nat_hole_client_arm(
        &self,
        nhc: Box<msg::NatHoleClient>,
        // `&mut`, not `&`: `SessionCtx` holds the boxed reader half, so it is
        // `Send` but NOT `Sync` — a shared `&SessionCtx` held across this fn's
        // awaits makes `run_message_loop`'s future non-`Send`, which the
        // spawned `client_service.run()` call sites require. The body only
        // reads `ctx.v2` and `ctx.session_alive`, so the exclusive borrow is a
        // type-level requirement, not a mutation.
        ctx: &mut SessionCtx,
        #[cfg_attr(not(feature = "vnet"), allow(unused_variables))] writer: &Arc<ControlWriter>,
    ) {
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
            return;
        }
        let proxy_token = self
            .p2p_bridge_tokens
            .lock()
            .await
            .entry(nhc.proxy_name.clone())
            .or_insert_with(CancellationToken::new)
            .clone();
        self.handle_nat_hole_client(*nhc, writer, ctx.v2, ctx.session_alive.clone(), proxy_token)
            .await;
    }

    /// Handle a server-sent `NatHoleResp`: resolve the sid's provider proxy,
    /// refuse one whose P2P bridge token was already cancelled (reclaiming its
    /// sid's socket and `pending_xtcp` slot), otherwise arm the token and
    /// delegate to `Self::handle_nat_hole_resp`.
    ///
    /// Extracted from the `run_message_loop` `NatHoleResp` arm by the P2 S3b
    /// seam (group A). The arm was terminal — nothing follows the `select!`
    /// inside the loop, so its `continue` resumed at the loop top, which is
    /// exactly where falling off this body lands — and that `continue` is the
    /// `return` here. It sat inside the `match proxy_name` (a match, not a
    /// loop) and bound to the message loop; the arm contains no
    /// `for`/`while`/`loop` (the only textual match is the English word "for"
    /// inside a log string). Called inline from the loop, never spawned, for
    /// the reason the previous handler records.
    async fn handle_nat_hole_resp_arm(
        &self,
        resp: Box<msg::NatHoleResp>,
        // `&mut` for the same type-level reason as `handle_nat_hole_client_arm`;
        // this body additionally takes disjoint `&mut`/`&` borrows of three of
        // `ctx`'s own fields in the delegate call.
        ctx: &mut SessionCtx,
        #[cfg_attr(not(feature = "vnet"), allow(unused_variables))] writer: &Arc<ControlWriter>,
    ) {
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
                    return;
                }
                self.p2p_bridge_tokens
                    .lock()
                    .await
                    .entry(name)
                    .or_insert_with(CancellationToken::new)
                    .clone()
            }
            _ => CancellationToken::new(),
        };
        self.handle_nat_hole_resp(
            *resp,
            &mut ctx.pending_xtcp,
            &mut ctx.visitor_pending,
            &ctx.xtcp_sockets,
            writer,
            ctx.session_alive.clone(),
            proxy_token,
        )
        .await;
    }

    /// Apply one server `NewProxyResp` to `proxy_info_map`: a non-empty error
    /// moves a `WaitStart` proxy to `StartErr` and anchors its retry clock in
    /// `last_start_err`; success accepts `WaitStart` or `StartErr` as
    /// `Running`.
    ///
    /// Extracted from the `run_message_loop` `NewProxyResp` arm by the P2 S3b
    /// seam (group A). The arm is terminal and carries no `continue`, so its
    /// body is the de-indented original apart from rustfmt reflow. It takes no
    /// ctx at all: the arm reads only `self.proxy_info_map` and the loop-local
    /// `last_start_err` (never a `SessionCtx` field). Directly exercised by
    /// this module's `#[cfg(test)] mod tests`.
    async fn handle_new_proxy_resp_arm(
        &self,
        resp: msg::NewProxyResp,
        last_start_err: &mut HashMap<String, Instant>,
    ) {
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
                    last_start_err.insert(resp.proxy_name.clone(), Instant::now());
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

    /// Handle a server-sent `VnetRouteAdvertise`: accept it only for a virtual
    /// net this client participates in, insert the route into the shared route
    /// table (TX lookup), and inject the matching OS route through the local
    /// TUN device that owns that net.
    ///
    /// Extracted from the `run_message_loop` `VnetRouteAdvertise` arm by the
    /// P2 S3b seam (group B). The arm was terminal — nothing follows the
    /// `select!` inside the loop, so falling off this body lands at the loop
    /// top exactly where falling off the arm did — and it carried no
    /// `continue` and no inner loop, so there is no control-flow delta. It
    /// carries **two** gates, both preserved: the `vnet` feature gate on this
    /// fn and on the call site (the body reads vnet-only `Service` fields and
    /// the vnet-feature-gated `vnet` module's helpers, so the arm cannot
    /// compile without the feature), and the original `linux`/`macos`
    /// `target_os` gate on the OS-route block inside the body. It takes no
    /// `SessionCtx` and no writer: the arm body reads only `&self`. Called
    /// inline from the loop, never spawned —
    /// the retry arm's lock-order note ("both locks' writers run only in this
    /// message-loop task") holds only while that stays true.
    #[cfg(feature = "vnet")]
    async fn handle_vnet_route_advertise_arm(&self, adv: msg::VnetRouteAdvertise) {
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
                if let Err(e) = routes.insert(&vnet, &adv.proxy_name, &adv.subnet) {
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
                        .find(|p| p.proxy_type == "vnet" && p.virtual_net == vnet)
                        .map(|p| p.name.clone())
                };
                let names = self.vnet_tun_names.lock().await;
                if let Some(tun_name) = local_tun_proxy.as_deref().and_then(|n| names.get(n)) {
                    add_os_route(&adv.subnet, tun_name);
                    self.vnet_peer_routes.lock().await.insert(
                        adv.proxy_name.clone(),
                        (adv.subnet.clone(), tun_name.clone(), vnet.clone()),
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

    /// Handle a server-sent `VnetPacket`: base64-decode the payload and hand
    /// it to the virtual-net visitor tunnel first; if no visitor consumes it,
    /// forward it to the TUN channel registered for that proxy.
    ///
    /// Extracted from the `run_message_loop` `VnetPacket` arm by the P2 S3b
    /// seam (group B). The arm was terminal — nothing follows the `select!`
    /// inside the loop, so falling off this body lands at the loop top exactly
    /// where falling off the arm did — and it carried no `continue` and no
    /// inner loop (the nested `match`es are not loops), so there is no
    /// control-flow delta. It carries **one** gate, preserved: the `vnet`
    /// feature gate on this fn and on the call site (the body reaches the
    /// vnet-only `Service` fields). It takes no `SessionCtx` and no writer:
    /// the arm body reads only `&self`. Called inline from the loop,
    /// never spawned — the retry arm's lock-order note ("both locks' writers
    /// run only in this message-loop task") holds only while that stays true.
    #[cfg(feature = "vnet")]
    async fn handle_vnet_packet_arm(&self, vpkt: msg::VnetPacket) {
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
                        let txs = self.vnet_tun_tx.lock().unwrap_or_else(|e| e.into_inner());
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

    /// Handle a server-sent `VnetRouteRemove`: accept it only for a virtual net
    /// this client participates in, then drop the peer's OS route, route-table
    /// entry and visitor route.
    ///
    /// Extracted from the `run_message_loop` `VnetRouteRemove` arm by the P2
    /// S3b seam (group B). The arm was terminal — nothing follows the `select!`
    /// inside the loop, so falling off this body lands at the loop top exactly
    /// where falling off the arm did — and it carried no `continue` and no
    /// inner loop, so there is no control-flow delta. It carries **one** gate,
    /// preserved: the `vnet` feature gate on this fn and on the call site (the
    /// body reads vnet-only `Service` fields and the vnet module's helper). It
    /// takes no `SessionCtx` and no writer: the arm body reads only `&self`.
    /// Called inline from the loop, never spawned — the retry arm's lock-order
    /// note ("both locks' writers run only in this message-loop task") holds
    /// only while that stays true.
    #[cfg(feature = "vnet")]
    async fn handle_vnet_route_remove_arm(&self, adv: msg::VnetRouteRemove) {
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
            if let Some((subnet, tun_name, _)) =
                self.vnet_peer_routes.lock().await.remove(&adv.proxy_name)
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

    /// Handle one heartbeat ping tick: build the `Ping` (with the auth scope
    /// union and the Go v0.71.0 auth-failure policy — a failed OIDC token or
    /// token-source setup SKIPS this heartbeat rather than tearing the session
    /// down, re-arming `ping_interval` on the exponential backoff), send it,
    /// and clear the failure streak.
    ///
    /// Extracted from the `run_message_loop` ping-tick arm by the P2 S3b seam
    /// (group C). The arm was terminal — nothing follows the `select!` inside
    /// the loop, and the `continue` was not inside an inner loop (the arm
    /// carries zero real `for`/`while`/`loop` tokens), so it bound the message
    /// `loop` and resumed at the loop top, which is exactly where falling off
    /// this body lands; it is the `return` here. That was the program's last
    /// `continue;`. No statement is otherwise added, removed or reordered.
    ///
    /// The timer future the arm polls (`_ = async { … }`, the
    /// `pending::<()>()` disabled-heartbeat shape) stays at the call site
    /// verbatim: this handler is the arm *body*, not the arm.
    ///
    /// `writer` is used unconditionally (the `Ping` send), not behind the
    /// `vnet` gate, so this handler carries no
    /// `cfg_attr(not(feature = "vnet"), allow(unused_variables))` — proved by
    /// a no-vnet removal probe, not inherited.
    ///
    /// Called inline from the loop, never spawned: the retry arm's lock-order
    /// note ("both locks' writers run only in this message-loop task") holds
    /// only while that stays true.
    async fn handle_ping_tick_arm(&self, ctx: &mut SessionCtx, writer: &Arc<ControlWriter>) {
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
        let send_auth =
            crate::backoff::heartbeat_requires_auth(&ctx.client_scopes, &ctx.server_scopes);
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
            return;
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

    /// Handle one proxy-retry tick: re-send `NewProxy` for proxies stuck in
    /// `StartErr` past their own retry anchor and for proxies stuck in
    /// `WaitStart` past the response timeout, pruning the two bookkeeping maps
    /// first.
    ///
    /// Extracted from the `run_message_loop` proxy-retry-tick arm by the P2
    /// S3b seam (group C). The arm was terminal — nothing follows the `select!`
    /// inside the loop — and it carried no `continue` and no inner loop, so
    /// there is no control-flow delta: the body is the de-indented original. It
    /// carries no `#[cfg]`, matching the original.
    ///
    /// The lock-order note inside the body is the reason this extraction must
    /// keep calling it inline: `self.proxies` is read before `self.cfg` here
    /// while the session loop takes them in the opposite order, which is sound
    /// **only** because both locks' writers (`try_reload`) run in this same
    /// message-loop task. `.await`ing this handler from the loop preserves that
    /// task affinity; `tokio::spawn`ing it would break the ordering argument
    /// and is a defect, not a style choice.
    ///
    /// The timer future the arm polls (`_ = ctx.proxy_retry_interval…tick()`)
    /// stays at the call site verbatim: this handler is the arm *body*, not the
    /// arm.
    ///
    /// `writer` is used unconditionally (each retry's `NewProxy` send), not
    /// behind the `vnet` gate, so this handler carries no
    /// `cfg_attr(not(feature = "vnet"), allow(unused_variables))` — proved by a
    /// no-vnet removal probe.
    async fn handle_proxy_retry_tick_arm(
        &self,
        ctx: &mut SessionCtx,
        writer: &Arc<ControlWriter>,
        last_start_err: &mut HashMap<String, Instant>,
    ) {
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
                map.get(name)
                    .is_some_and(|info| info.phase == ProxyPhase::WaitStart)
            });
            // Prune StartErr anchors for proxies that left
            // StartErr (registered, closed, or re-entered
            // WaitStart via a retry send below).
            last_start_err.retain(|name, _| {
                map.get(name)
                    .is_some_and(|info| matches!(info.phase, ProxyPhase::StartErr(_)))
            });
            for (name, info) in map.iter() {
                if info.phase == ProxyPhase::WaitStart && !ctx.waitstart_seen.contains_key(name) {
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
                            >= (*WAIT_START_RETRY_TIMEOUT).saturating_sub(PROXY_RETRY_GRACE)
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
            let retry_candidates = filter_active_proxies(&*self.cfg.read().await, &all_proxies);
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
                    let new_proxy =
                        crate::proxy::create_new_proxy_msg(p, &local_addr, &ctx.cfg_user);
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

    /// Handle one XTCP provider notification (`NatHoleSid`): spawn the STUN
    /// discovery whose finished `NatHoleClient` this session must send.
    ///
    /// Extracted from the `run_message_loop` XTCP-notify arm by the P2 S3b
    /// seam (group D1) as a de-indented pure move — no statement is added,
    /// removed or reordered. The arm carried no `continue` (the program's last
    /// one left with group C) and no `LoopExit::`, so its terminality is the
    /// shared "nothing follows the `select!` inside the loop" fact.
    ///
    /// This handler **spawns**, and the spawn is the arm's own, deliberately:
    /// two STUN round-trips can stall up to ~10s and would block the message
    /// loop (heartbeats, work conns, reloads). The spawned task does the STUN,
    /// persists the socket in `ctx.xtcp_sockets`, and hands the finished
    /// `NatHoleClient` back on `ctx.stun_result_tx` so the write and the
    /// `pending_xtcp` bookkeeping stay on the loop, preserving the
    /// write-before-`NatHoleResp` ordering. The handler is itself called
    /// inline from the loop and is never spawned; it is the thing that spawns.
    ///
    /// It reaches no `Service` state: measured (this arm's own census), the
    /// base span has **zero** `self.` occurrences, so `&self` is unused. It
    /// takes no `writer` — the arm writes nothing on the control connection
    /// (that send is the `stun_result` arm's) — so the
    /// `cfg_attr(not(feature = "vnet"), allow(unused_variables))` rule cannot
    /// obtain here, and a handler that takes no `writer` never needs it. It
    /// carries no `#[cfg]`, matching the original arm.
    async fn handle_xtcp_notify_arm(
        &self,
        xtcp_notif: XtcpNotification,
        ctx: &mut SessionCtx,
        channels: &SessionChannels<'_>,
    ) {
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
                    let second_target = result1.other_addr.as_deref().unwrap_or(&stun_server);
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
                mapped_addrs: if mapped_addrs.is_empty() {
                    None
                } else {
                    Some(mapped_addrs)
                },
                assisted_addrs,
                visitor_addr: None,
            }));
            // Hand the finished message back to the control loop.
            if stun_tx
                .send(StunResult {
                    sid,
                    proxy_name,
                    msg: client_msg,
                })
                .await
                .is_err()
            {
                warn!("XTCP: control loop dropped STUN result channel");
            }
        });
    }

    /// Handle one `StunResult` handed back by the off-loop STUN task: write
    /// the `NatHoleClient` on the control connection and track
    /// `sid -> proxy_name` in `ctx.pending_xtcp` for `NatHoleResp` routing.
    ///
    /// Extracted from the `run_message_loop` STUN-result arm by the P2 S3b
    /// seam (group D1) as a de-indented pure move — no statement is added,
    /// removed or reordered. The arm carries no `continue` and no
    /// `LoopExit::`, so the shared script-level terminality fact ("nothing
    /// follows the `select!` inside the loop") is all this arm needs.
    ///
    /// This handler **spawns** the arm's own defensive cleanup task: on the
    /// success path the socket in `ctx.xtcp_sockets` and the `pending_xtcp`
    /// entry are reclaimed after 15s (the server's 10s NAT session window plus
    /// margin) and the sid is handed to the `xtcp_cleanup` arm through
    /// `xtcp_cleanup_tx`. The handler is called inline from the loop, never
    /// spawned.
    ///
    /// Coupling, derived from this arm: `&mut SessionCtx` (`ctx.v2`,
    /// `ctx.xtcp_sockets`, `ctx.pending_xtcp` are used here; the
    /// `ctx.stun_result_rx` receive stays at the call site as the arm's future),
    /// `writer`, and the loop-local `xtcp_cleanup_tx` sender. No `Service`
    /// state is reached: measured, the base span has zero `self.`
    /// occurrences. The `&mut pending_xtcp` / `xtcp_sockets` /
    /// `stun_result_rx` of the plan's row are not three parameters — they are
    /// fields of the one `&mut SessionCtx` parameter, and `xtcp_cleanup_tx`
    /// (a caller-owned local) was missing from that row.
    ///
    /// `writer` is used unconditionally (the `NatHoleClient` send), not behind
    /// the `vnet` gate, so this handler carries no
    /// `cfg_attr(not(feature = "vnet"), allow(unused_variables))` — proved by
    /// a no-vnet removal probe, not inherited. It carries no `#[cfg]`.
    async fn handle_stun_result_arm(
        &self,
        stun_result: StunResult,
        ctx: &mut SessionCtx,
        writer: &Arc<ControlWriter>,
        xtcp_cleanup_tx: &mpsc::Sender<String>,
    ) {
        let StunResult {
            sid,
            proxy_name,
            msg,
        } = stun_result;
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

    /// Handle one stale XTCP entry from the cleanup channel: reclaim the
    /// provider `sid` or the visitor txn_id from both NAT-hole maps.
    ///
    /// Extracted from the `run_message_loop` `xtcp_cleanup` arm by the P2 S3b
    /// seam (group D1) as a de-indented pure move — no statement is added,
    /// removed or reordered. The arm carries no `continue` and no
    /// `LoopExit::`, so falling off this body lands at the loop top exactly
    /// where the arm's end did.
    ///
    /// Coupling, derived from this arm: `&mut SessionCtx` only —
    /// `ctx.pending_xtcp` and `ctx.visitor_pending`, reached through the one
    /// parameter rather than passed as two. The arm reaches no `Service`
    /// state (measured: zero `self.` occurrences in the base span), takes no
    /// `writer`, and does not name `xtcp_cleanup_tx` (its sender side is the
    /// `stun_result` / visitor arms'). It carries no `#[cfg]`.
    async fn handle_xtcp_cleanup_arm(&self, cleanup_sid: String, ctx: &mut SessionCtx) {
        if reclaim_stale_xtcp_entry(
            &mut ctx.pending_xtcp,
            &mut ctx.visitor_pending,
            &cleanup_sid,
        ) {
            debug!(sid = %cleanup_sid, "XTCP: reclaimed stale entry for '{}'", cleanup_sid);
        }
    }

    /// Handle one `HealthEvent` from a proxy's health-check task: `Close` tears
    /// the proxy down on the server, `Recover` re-registers it.
    ///
    /// `Close` mirrors the `CloseProxy` handler's teardown for the parts a
    /// health failure owns — cancel and drop the proxy's XTCP P2P bridge token,
    /// mark the proxy `CheckFailed` (Go frp compat: `PhaseCheckFailed` is an
    /// explicit lifecycle state), then send `CloseProxy` — while deliberately
    /// leaving the monitor running so a later `Recover` can re-register (Go frp
    /// compat). `Recover` looks the proxy's config up by name, marks it
    /// `WaitStart` so the `NewProxyResp` handler completes the transition to
    /// `Running`, and re-sends `NewProxy` carrying the registration's auth user.
    ///
    /// Extracted from the `run_message_loop` health-event arm by the P2 S3b
    /// seam (group D2) as a de-indented move: the token stream is identical
    /// (633 = 633) and the whitespace-collapsed stream is identical
    /// (1998 = 1998), so 0 statements are added, removed or reordered and no
    /// `&` was dropped; the raw stream grows 3366 -> 3465 characters because
    /// rustfmt reflows two expressions the arm's macro body had left alone
    /// (the `proxy_info_map.read()` chain, 1 -> 4 lines, and the
    /// `create_new_proxy_msg` call, 1 -> 2 lines). The arm carries no
    /// `continue` and no `LoopExit::`, so its terminality is the shared
    /// "nothing follows the `select!` inside the loop" fact.
    ///
    /// **Ordering**: this is the arm the `CloseProxy` handler's own comment
    /// names — this body keeps the `p2p_bridge_tokens` guard alive while it
    /// writes `proxy_info_map`, the opposite of `handle_close_proxy`'s order
    /// (`proxy_info_map`, then `health_cancels`, then `p2p_bridge_tokens`; base
    /// `:690-697` calls the phase write there "outside the lock order used by
    /// HealthEvent"). That is sound only because both run in this same
    /// message-loop task, so the handler must stay `.await`ed inline and must
    /// never be spawned.
    ///
    /// Coupling, derived from this arm: `&mut SessionCtx` for `ctx.v2` and
    /// `ctx.cfg_user` (3 uses, 2 distinct fields), `&Arc<ControlWriter>`, and
    /// `&self` for `p2p_bridge_tokens` / `proxy_info_map` /
    /// `health_proxy_configs` (5 uses, 3 distinct fields — measured on the base
    /// span; the landed body's reflow splits `self` from `.proxy_info_map`
    /// once, so a one-line `self.` grep counts 4 here while the uses are
    /// unchanged). It takes no `channels`: the `health_rx` receive stays at the
    /// call site. It carries no `#[cfg]`, matching the original arm.
    ///
    /// `writer` is used unconditionally (both branches send), not behind the
    /// `vnet` gate, so this handler carries no
    /// `cfg_attr(not(feature = "vnet"), allow(unused_variables))` — settled by
    /// a no-vnet removal probe, not inherited: removing both sends gives
    /// rc 101 `unused variable: writer`, and adding the attribute on top gives
    /// rc 0.
    ///
    /// Called inline from the loop, never spawned: the retry arm's lock-order
    /// note ("both locks' writers run only in this message-loop task") holds
    /// only while that stays true.
    async fn handle_health_event_arm(
        &self,
        event: HealthEvent,
        ctx: &mut SessionCtx,
        writer: &Arc<ControlWriter>,
    ) {
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
                    let local_addr = self
                        .proxy_info_map
                        .read()
                        .await
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
                    let new_proxy =
                        crate::proxy::create_new_proxy_msg(&cfg, &local_addr, &ctx.cfg_user);
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

    /// Handle one visitor request: send its `NatHoleVisitor` on the control
    /// connection and hand the server's `NatHoleResp` back through the
    /// request's oneshot.
    ///
    /// Go frps v0.69.1 handles `NatHoleVisitor` only on the control connection
    /// path, not on fresh TCP connections, which is why the visitor task hands
    /// the request to this loop. On a successful write the txn is recorded in
    /// `ctx.visitor_pending` (the `NatHoleResp` arm completes it) and a 20 s
    /// defensive cleanup is armed so an unanswered txn cannot sit until control
    /// teardown; the 20 s figure is chosen to outlast the visitor's own 15 s
    /// timeout and the server's 10 s NAT session window. On a write failure the
    /// reply is completed with the error and nothing is recorded.
    ///
    /// Extracted from the `run_message_loop` visitor-request arm by the P2 S3b
    /// seam (group D2) as a de-indented move: the raw stream is identical
    /// (1805 = 1805 characters), the whitespace-collapsed stream is identical
    /// (1129 = 1129) and the token stream is identical (374 = 374), so this
    /// arm's delta list is empty — 0 statements added, removed or reordered,
    /// no `&` dropped, no `continue` and no `LoopExit::`. Its terminality is
    /// the shared "nothing follows the `select!` inside the loop" fact.
    ///
    /// This handler **spawns** (1), and the spawn is the arm's own: the 20 s
    /// wait must not hold the message loop, and the task hands the txn id back
    /// on the loop-owned `xtcp_cleanup_tx` so the reclaim still runs on the
    /// loop (`handle_xtcp_cleanup_arm`), never off it. The statement order the
    /// spawn depends on is preserved: write, record, then arm. The handler is
    /// itself called inline from the loop and is never spawned; 0 spawns at the
    /// call site.
    ///
    /// Coupling, derived from this arm: `&mut SessionCtx` for `ctx.v2` and
    /// `ctx.visitor_pending` (2 uses, 2 distinct fields), `&Arc<ControlWriter>`,
    /// the loop-local `xtcp_cleanup_tx` as `&mpsc::Sender<String>` (it is
    /// loop-owned at `run_message_loop:148` and shared with the STUN-result
    /// arm, so it must not be taken by value) and the request by value. It
    /// reaches no `Service` state — measured, the base span has 0 `self.`
    /// occurrences — so `&self` is unused. It carries no `#[cfg]`, matching the
    /// original arm.
    ///
    /// `writer` is used unconditionally (the `NatHoleVisitor` send), not behind
    /// the `vnet` gate, so this handler carries no
    /// `cfg_attr(not(feature = "vnet"), allow(unused_variables))` — settled by
    /// a no-vnet removal probe, not inherited: removing the send gives rc 101
    /// `unused variable: writer`, and adding the attribute on top gives rc 0.
    async fn handle_visitor_request_arm(
        &self,
        vreq: VisitorRequest,
        ctx: &mut SessionCtx,
        writer: &Arc<ControlWriter>,
        xtcp_cleanup_tx: &mpsc::Sender<String>,
    ) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_info(phase: ProxyPhase) -> ProxyRuntimeInfo {
        ProxyRuntimeInfo {
            local_addr: "127.0.0.1:8080".to_string(),
            proxy_type: "tcp".to_string(),
            use_encryption: false,
            use_compression: false,
            sk: String::new(),
            bandwidth_limit: 0,
            bandwidth_limit_mode: String::new(),
            bandwidth_limiter: None,
            proxy_protocol_version: String::new(),
            plugin: String::new(),
            remote_addr: String::new(),
            err: String::new(),
            config_snapshot: String::new(),
            phase,
        }
    }

    /// A `ControlWriter` whose receiver the caller keeps, so a test can assert
    /// on what the handler under test enqueued on the control channel.
    fn test_control_writer_rx() -> (
        Arc<ControlWriter>,
        tokio::sync::mpsc::Receiver<(FrpMessage, bool)>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel::<(FrpMessage, bool)>(16);
        (
            Arc::new(ControlWriter {
                tx,
                failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                notify: Arc::new(tokio::sync::Notify::new()),
            }),
            rx,
        )
    }

    /// A minimal `SessionCtx` for tests that drive an extracted arm handler
    /// directly. The extracted arms reach only a handful of `SessionCtx`
    /// fields between them, but the struct has no `Default` and is private to
    /// `service` (this module is its child, so it can name it), so the literal
    /// is spelled out. `reader` stays `None`: no arm touches it.
    fn test_session_ctx() -> SessionCtx {
        SessionCtx {
            control_stream: None,
            run_id: "test-run-id".to_string(),
            yamux: None,
            v2: false,
            #[cfg(feature = "quic")]
            quic_conn: None,
            ping_interval: None,
            ping_retry_backoff: None,
            last_pong: Instant::now(),
            hb_timeout: 30,
            hb_timeout_dur: Duration::from_secs(30),
            hb_watchdog_active: false,
            session_alive: Arc::new(AtomicBool::new(true)),
            wc_server_addr: "127.0.0.1".to_string(),
            wc_server_port: 7000,
            wc_tls_enable: false,
            wc_tls_server_name: String::new(),
            wc_tls_ca_file: None,
            wc_tls_cert_file: None,
            wc_tls_key_file: None,
            wc_dns_server: None,
            wc_udp_packet_size: 1500,
            wc_udp_packet_codec: String::new(),
            wc_disable_custom_tls_first_byte: false,
            wc_keepalive_secs: 7200,
            wc_bind_addr: None,
            wc_proxy_url: String::new(),
            wc_dial_timeout_secs: 10,
            protocol: TransportProtocol::Tcp,
            client_scopes: Vec::new(),
            server_scopes: Vec::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            session_started_at: Instant::now(),
            pending_proxies: Vec::new(),
            pending_visitors: Vec::new(),
            write_failed: false,
            seen_registration_response: false,
            req_work_conns_seen: 0,
            writer: None,
            control_rx: None,
            control_failed: None,
            control_notify: None,
            reader: None,
            visitor_shutdown: None,
            visitor_handles: Vec::new(),
            work_conn_handles: Vec::new(),
            control_writer_handle: None,
            pending_xtcp: HashMap::new(),
            xtcp_sockets: Default::default(),
            visitor_pending: HashMap::new(),
            stun_result_tx: None,
            stun_result_rx: None,
            xtcp_cleanup_rx: None,
            proxy_retry_interval: None,
            waitstart_seen: HashMap::new(),
            cfg_user: String::new(),
        }
    }

    async fn test_service() -> Service {
        let cfg = ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 7000,
            token: "test-token".to_string(),
            ..Default::default()
        };
        Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
            .await
            .expect("service init must succeed")
    }

    /// The extracted `NewProxyResp` arm, driven directly. That arm has no
    /// wire-level lane (no test puts a `NewProxyResp` on the wire to a client
    /// `Service`), so this is the direct test for the phase and
    /// `last_start_err` transitions it owns: an error moves
    /// `WaitStart` -> `StartErr`, records the message and anchors the retry
    /// clock; success accepts `WaitStart` and `StartErr` as `Running`
    /// (clearing the error and copying `remote_addr`); a `Running` proxy and
    /// an unknown proxy are left untouched by both branches.
    #[tokio::test]
    async fn new_proxy_resp_arm_moves_phase_and_anchors_retry() {
        let service = test_service().await;
        {
            let mut map = service.proxy_info_map.write().await;
            map.insert("user.p1".to_string(), proxy_info(ProxyPhase::WaitStart));
            map.insert("user.p2".to_string(), proxy_info(ProxyPhase::WaitStart));
            map.insert("user.p3".to_string(), proxy_info(ProxyPhase::Running));
        }
        let mut last_start_err: HashMap<String, Instant> = HashMap::new();

        // Non-empty error on a WaitStart proxy -> StartErr + retry anchor.
        service
            .handle_new_proxy_resp_arm(
                msg::NewProxyResp {
                    proxy_name: "user.p1".to_string(),
                    remote_addr: None,
                    error: Some("port already used".to_string()),
                },
                &mut last_start_err,
            )
            .await;
        // Unknown proxy: neither branch may panic or anchor a clock.
        service
            .handle_new_proxy_resp_arm(
                msg::NewProxyResp {
                    proxy_name: "user.unknown".to_string(),
                    remote_addr: None,
                    error: Some("boom".to_string()),
                },
                &mut last_start_err,
            )
            .await;

        {
            let map = service.proxy_info_map.read().await;
            let p1 = map.get("user.p1").expect("p1 present");
            match &p1.phase {
                ProxyPhase::StartErr(e) => assert_eq!(e, "port already used"),
                other => panic!("expected StartErr, got {}", other.as_str()),
            }
            assert_eq!(p1.err, "port already used");
            let p3 = map.get("user.p3").expect("p3 present");
            assert_eq!(
                p3.phase.as_str(),
                "running",
                "the error branch must not touch a Running proxy"
            );
        }
        assert!(
            last_start_err.contains_key("user.p1"),
            "the StartErr retry clock must be anchored on the error"
        );
        assert!(
            !last_start_err.contains_key("user.unknown"),
            "an unknown proxy must not anchor a retry clock"
        );

        // Success from WaitStart -> Running.
        service
            .handle_new_proxy_resp_arm(
                msg::NewProxyResp {
                    proxy_name: "user.p2".to_string(),
                    remote_addr: Some("1.2.3.4:7001".to_string()),
                    error: None,
                },
                &mut last_start_err,
            )
            .await;
        // Empty (not absent) error is success, and StartErr may still recover.
        service
            .handle_new_proxy_resp_arm(
                msg::NewProxyResp {
                    proxy_name: "user.p1".to_string(),
                    remote_addr: Some("1.2.3.4:7002".to_string()),
                    error: Some(String::new()),
                },
                &mut last_start_err,
            )
            .await;

        {
            let map = service.proxy_info_map.read().await;
            let p2 = map.get("user.p2").expect("p2 present");
            assert_eq!(p2.phase.as_str(), "running");
            assert_eq!(p2.remote_addr, "1.2.3.4:7001");
            assert!(p2.err.is_empty());
            let p1 = map.get("user.p1").expect("p1 present");
            assert_eq!(p1.phase.as_str(), "running");
            assert_eq!(p1.remote_addr, "1.2.3.4:7002");
            assert!(p1.err.is_empty());
            let p3 = map.get("user.p3").expect("p3 present");
            assert_eq!(p3.phase.as_str(), "running");
            assert!(
                p3.remote_addr.is_empty(),
                "the success branch must not touch a Running proxy"
            );
        }
    }

    /// A `Service` whose config participates in the `corp-net` virtual net: one
    /// `virtual_net` proxy with a TUN address. That is the precondition
    /// `local_vnet_set` applies before a vnet route frame is accepted, so it is
    /// what the three vnet handlers below need to reach their accept branch.
    #[cfg(feature = "vnet")]
    async fn vnet_service() -> Service {
        let mut cfg = ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 7000,
            token: "test-token".to_string(),
            ..Default::default()
        };
        cfg.virtual_net.address = "10.0.0.1".to_string();
        cfg.proxies.push(frp_core::config::ProxyConfig {
            name: "vnet-a".to_string(),
            proxy_type: "vnet".to_string(),
            vnet_ip: "10.0.0.2".to_string(),
            vnet_netmask: "255.255.255.0".to_string(),
            virtual_net: "corp-net".to_string(),
            // `ProxyConfig`'s derived `Default` gives `enabled: false` (the
            // serde default is `true`, so only a hand-built config sees this),
            // and `with_unsafe_features` retains only enabled entries — without
            // this the vnet proxy is dropped and `local_vnet_set` is empty.
            enabled: true,
            ..Default::default()
        });
        Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
            .await
            .expect("service init must succeed")
    }

    /// The extracted `VnetPacket` arm, driven directly. No lane puts a
    /// `VnetPacket` on the wire to a client `Service` (the `vnet` feature is in
    /// no default build, and a server forwards one only to a peer that shares
    /// the virtual net), so this is the direct test for the arm's three
    /// behaviours: a decoded payload reaches the TUN channel registered for the
    /// proxy, an undecodable payload is dropped, and a packet for a proxy with
    /// neither a visitor nor a TUN channel is dropped.
    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn vnet_packet_arm_delivers_to_tun_channel_and_drops_bad_input() {
        let service = vnet_service().await;
        let packet = vec![0x45u8, 0x00, 0x00, 0x14, 0xde, 0xad];
        let (tx, mut rx) = mpsc::channel::<Arc<[u8]>>(4);
        service
            .vnet_tun_tx
            .lock()
            .unwrap()
            .insert("vnet-a".to_string(), tx);

        service
            .handle_vnet_packet_arm(msg::VnetPacket {
                proxy_name: "vnet-a".to_string(),
                data: frp_core::base64::encode(&packet),
            })
            .await;
        let delivered = rx
            .try_recv()
            .expect("a decoded packet must reach the proxy's TUN channel");
        assert_eq!(&*delivered, &packet[..]);

        // Undecodable payload: warn, no delivery.
        service
            .handle_vnet_packet_arm(msg::VnetPacket {
                proxy_name: "vnet-a".to_string(),
                data: "!!!!".to_string(),
            })
            .await;
        assert!(rx.try_recv().is_err(), "a decode error must not deliver");

        // Neither a visitor route nor a TUN channel for the name: dropped.
        service
            .handle_vnet_packet_arm(msg::VnetPacket {
                proxy_name: "unknown".to_string(),
                data: frp_core::base64::encode(&packet),
            })
            .await;
        assert!(rx.try_recv().is_err(), "an unknown target must not deliver");
    }

    /// The extracted `VnetRouteAdvertise` arm, driven directly. A route for a
    /// virtual net this client does not participate in is ignored; one for a
    /// participating net lands in the shared route table, and (only when a
    /// local TUN owns that net) is recorded as a peer route and injected at the
    /// OS level.
    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn vnet_route_advertise_arm_isolates_vnets_and_records_routes() {
        let service = vnet_service().await;

        // Foreign virtual net: ignored, route table and peer map untouched.
        service
            .handle_vnet_route_advertise_arm(msg::VnetRouteAdvertise {
                proxy_name: "peer-foreign".to_string(),
                subnet: "10.9.0.0/24".to_string(),
                virtual_net: Some("other-net".to_string()),
            })
            .await;
        assert_eq!(
            service
                .vnet_controller
                .route_table()
                .read()
                .await
                .lookup("other-net", &"10.9.0.5".parse().unwrap()),
            None
        );
        assert!(service.vnet_peer_routes.lock().await.is_empty());

        // Participating net, no local TUN: the TX route is inserted and no peer
        // route is recorded (there is no local interface to inject through).
        service
            .handle_vnet_route_advertise_arm(msg::VnetRouteAdvertise {
                proxy_name: "peer-a".to_string(),
                subnet: "10.1.0.0/24".to_string(),
                virtual_net: Some("corp-net".to_string()),
            })
            .await;
        assert_eq!(
            service
                .vnet_controller
                .route_table()
                .read()
                .await
                .lookup("corp-net", &"10.1.0.5".parse().unwrap()),
            Some("peer-a")
        );
        assert!(
            service.vnet_peer_routes.lock().await.is_empty(),
            "no local TUN for the net means no OS route to track"
        );

        // Participating net with a local TUN registered: the peer route is
        // recorded and the OS route injected (best-effort, so the injected
        // command's failure is ignored by `add_os_route`). Platform-gated
        // exactly like the block it exercises.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            service
                .vnet_tun_names
                .lock()
                .await
                .insert("vnet-a".to_string(), "tun-test0".to_string());
            service
                .handle_vnet_route_advertise_arm(msg::VnetRouteAdvertise {
                    proxy_name: "peer-b".to_string(),
                    subnet: "10.2.0.0/24".to_string(),
                    virtual_net: Some("corp-net".to_string()),
                })
                .await;
            let peer_routes = service.vnet_peer_routes.lock().await;
            let (subnet, tun_name, vnet) = peer_routes
                .get("peer-b")
                .expect("a local TUN must record the peer route");
            assert_eq!(subnet, "10.2.0.0/24");
            assert_eq!(tun_name, "tun-test0");
            assert_eq!(vnet, "corp-net");
        }
    }

    /// The extracted `VnetRouteRemove` arm, driven directly. A removal for a
    /// foreign virtual net is ignored; one for a participating net drops the
    /// peer's OS route, its route-table entry and its visitor route.
    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn vnet_route_remove_arm_isolates_vnets_and_cleans_state() {
        let service = vnet_service().await;
        let (visitor_tx, _visitor_rx) = mpsc::channel::<Vec<u8>>(4);
        service
            .vnet_controller
            .register_visitor_route("peer-a", "100.86.0.1/32", visitor_tx)
            .await
            .expect("visitor route registers");
        service
            .vnet_controller
            .route_table()
            .write()
            .await
            .insert("corp-net", "peer-a", "10.1.0.0/24")
            .expect("route inserts");
        service.vnet_peer_routes.lock().await.insert(
            "peer-a".to_string(),
            (
                "10.1.0.0/24".to_string(),
                "tun-test0".to_string(),
                "corp-net".to_string(),
            ),
        );

        // Foreign virtual net: ignored, every piece of state survives.
        service
            .handle_vnet_route_remove_arm(msg::VnetRouteRemove {
                proxy_name: "peer-a".to_string(),
                virtual_net: Some("other-net".to_string()),
            })
            .await;
        assert!(service.vnet_peer_routes.lock().await.contains_key("peer-a"));
        assert_eq!(
            service
                .vnet_controller
                .route_table()
                .read()
                .await
                .lookup("corp-net", &"10.1.0.5".parse().unwrap()),
            Some("peer-a")
        );
        assert!(service
            .vnet_controller
            .deliver_visitor_packet("peer-a", vec![0x45])
            .is_ok());

        // Participating net: peer route, route-table entry and visitor route go.
        service
            .handle_vnet_route_remove_arm(msg::VnetRouteRemove {
                proxy_name: "peer-a".to_string(),
                virtual_net: Some("corp-net".to_string()),
            })
            .await;
        assert!(service.vnet_peer_routes.lock().await.is_empty());
        assert_eq!(
            service
                .vnet_controller
                .route_table()
                .read()
                .await
                .lookup("corp-net", &"10.1.0.5".parse().unwrap()),
            None
        );
        assert!(service
            .vnet_controller
            .deliver_visitor_packet("peer-a", vec![0x45])
            .is_err());
    }

    /// The extracted ping-tick arm, driven directly. No test puts the arm's
    /// timer on a live wire, so this is the direct lane for the two behaviours
    /// the arm owns: an authenticated tick sends one `Ping` and clears the
    /// failure streak, while a tick whose auth setup fails **skips** the send
    /// (the session stays up) and re-arms `ping_interval` with the exponential
    /// backoff, recording it in `ping_retry_backoff`.
    ///
    /// `client_scopes` carries `HeartBeats` so `heartbeat_requires_auth` is
    /// true, which is the precondition for the auth branch the skip path lives
    /// in.
    #[tokio::test]
    async fn ping_tick_arm_sends_ping_and_skips_on_auth_failure() {
        // Normal path: token auth resolves, so a Ping is enqueued and the
        // streak is cleared.
        let service = test_service().await;
        let (writer, mut rx) = test_control_writer_rx();
        let mut ctx = test_session_ctx();
        // `HeartBeats` makes `heartbeat_requires_auth` true, which is the
        // precondition for the auth branch: the source's token resolves, a
        // login key is attached, and the streak is cleared.
        ctx.client_scopes = vec!["HeartBeats".to_string()];
        let period = Duration::from_millis(1);
        ctx.ping_interval = Some(tokio::time::interval(period));
        // Pretend a previous failure was in flight; a non-skipped attempt must
        // clear it.
        ctx.ping_retry_backoff = Some(Duration::from_secs(2));

        service.handle_ping_tick_arm(&mut ctx, &writer).await;

        let (msg, v2) = rx
            .try_recv()
            .expect("an authenticated tick must enqueue exactly one Ping");
        match msg {
            FrpMessage::Ping(p) => {
                assert!(
                    p.privilege_key.is_some(),
                    "token auth must attach a login key to the heartbeat"
                );
                assert!(p.timestamp.is_some());
            }
            other => panic!("expected Ping, got {other:?}"),
        }
        assert!(!v2, "the test ctx negotiates V1");
        assert!(
            ctx.ping_retry_backoff.is_none(),
            "a non-skipped attempt must end the failure streak"
        );
        assert!(
            rx.try_recv().is_err(),
            "one tick must enqueue exactly one message"
        );

        // Skip path: an auth config whose token cannot resolve makes
        // `try_generate_login_key` fail, so the tick is skipped rather than
        // tearing the session down.
        let mut service = test_service().await;
        {
            let mut auth = (*service.auth_cfg).clone();
            auth.token = String::new();
            service.auth_cfg = Arc::new(auth);
        }
        let (writer, mut rx) = test_control_writer_rx();
        let mut ctx = test_session_ctx();
        ctx.client_scopes = vec!["HeartBeats".to_string()];
        let period = Duration::from_millis(10);
        ctx.ping_interval = Some(tokio::time::interval(period));
        // `ping_retry_backoff` is already `None` from `test_session_ctx()`, so
        // the skip path below (which asserts it becomes `Some`) starts from a
        // clean streak without re-assigning the handler's own line.

        service.handle_ping_tick_arm(&mut ctx, &writer).await;

        assert!(
            rx.try_recv().is_err(),
            "a failed auth setup must skip the heartbeat, not send it"
        );
        assert_eq!(
            ctx.ping_retry_backoff,
            Some(period),
            "the skip path must record the (interval-capped) exponential backoff"
        );
        assert_eq!(
            ctx.ping_interval.as_ref().expect("interval armed").period(),
            period,
            "reset_after changes the next deadline, not the period"
        );
    }

    /// The extracted proxy-retry-tick arm, driven directly. No test drives the
    /// retry timer's eligibility rules over a live `Service`, so this is the
    /// direct lane for the three decisions the arm owns: a `StartErr` proxy
    /// whose own anchor is older than `PROXY_RETRY_INTERVAL` is re-sent (and
    /// moved to `WaitStart`, re-arming the WaitStart clock), a `StartErr` proxy
    /// anchored just now is **not** re-sent, and a `WaitStart` proxy past
    /// `WAIT_START_RETRY_TIMEOUT` is re-sent.
    #[tokio::test]
    async fn proxy_retry_tick_arm_retries_by_anchor_and_prunes_maps() {
        let service = test_service().await;
        // Two live proxies whose BARE names match the `user.`-prefixed runtime
        // map keys below: the retry candidate is looked up by stripped name,
        // so a config missing the bare name silently skips the re-send.
        let mk = |name: &str, local_port: u16| frp_core::config::ProxyConfig {
            name: name.to_string(),
            proxy_type: "tcp".to_string(),
            local_port,
            remote_port: 7001,
            enabled: true,
            ..Default::default()
        };
        let (p1, p2) = (mk("p1", 8080), mk("p2", 8081));
        *service.proxies.write().await = Arc::new(vec![p1.clone(), p2.clone()]);
        {
            let mut cfg = (*service.cfg.read().await).clone();
            cfg.proxies.push(p1);
            cfg.proxies.push(p2);
            *service.cfg.write().await = cfg;
        }
        {
            let mut map = service.proxy_info_map.write().await;
            map.insert("user.p1".to_string(), proxy_info(ProxyPhase::WaitStart));
            map.insert(
                "user.p2".to_string(),
                proxy_info(ProxyPhase::StartErr("port in use".to_string())),
            );
            map.insert(
                "user.p3".to_string(),
                proxy_info(ProxyPhase::StartErr("port in use".to_string())),
            );
        }

        let (writer, mut rx) = test_control_writer_rx();
        let mut ctx = test_session_ctx();
        ctx.cfg_user = "user".to_string();
        let mut interval = tokio::time::interval(Duration::from_millis(1));
        interval.tick().await; // skip the interval's immediate first tick
        ctx.proxy_retry_interval = Some(interval);
        // The WaitStart proxy's clock is old enough to be past
        // WAIT_START_RETRY_TIMEOUT + grace; p1 is not registered in
        // WaitStart, so p2/p3 carry the StartErr anchors.
        ctx.waitstart_seen.insert(
            "user.p1".to_string(),
            Instant::now() - Duration::from_secs(600),
        );
        let mut last_start_err: HashMap<String, Instant> = HashMap::new();
        let stale_anchor = Instant::now() - Duration::from_secs(600);
        let fresh_anchor = Instant::now();
        last_start_err.insert("user.p2".to_string(), stale_anchor);
        last_start_err.insert("user.p3".to_string(), fresh_anchor);

        service
            .handle_proxy_retry_tick_arm(&mut ctx, &writer, &mut last_start_err)
            .await;

        // Collect first: the valid `to_retry` list is filled from a `HashMap`
        // walk, so the two eligible proxies may be enqueued in either order.
        let mut sent: Vec<String> = Vec::new();
        while let Ok((msg, v2)) = rx.try_recv() {
            assert!(!v2, "the test ctx negotiates V1");
            match msg {
                FrpMessage::NewProxy(np) => {
                    // `create_new_proxy_msg` strips `local_str` for Go frps
                    // compatibility, so the local address travels through the
                    // retry candidate, not through this field.
                    assert!(np.local_str.is_none());
                    sent.push(np.proxy_name);
                }
                other => panic!("expected NewProxy, got {other:?}"),
            }
        }
        sent.sort();
        assert_eq!(
            sent,
            vec!["user.p1".to_string(), "user.p2".to_string()],
            "the stuck WaitStart proxy and the StartErr proxy past its anchor \
             must be re-sent in one tick; the freshly-anchored StartErr proxy \
             must not"
        );

        {
            let map = service.proxy_info_map.read().await;
            assert_eq!(
                map.get("user.p1").expect("p1 present").phase,
                ProxyPhase::WaitStart
            );
            assert_eq!(
                map.get("user.p2").expect("p2 present").phase,
                ProxyPhase::WaitStart,
                "a retry send moves the proxy to WaitStart"
            );
            assert!(
                matches!(
                    map.get("user.p3").expect("p3 present").phase,
                    ProxyPhase::StartErr(_)
                ),
                "the freshly-anchored StartErr proxy keeps its phase"
            );
        }
        assert!(
            ctx.waitstart_seen.contains_key("user.p1"),
            "p1's WaitStart clock must be re-armed at the retry send"
        );
        // The prune pass runs before the sends, so p2 is still in StartErr
        // when it runs and its anchor survives it. That anchor is NOT re-armed
        // by the retry send: `waitstart_seen` is re-armed (the WaitStart clock
        // above), while a `last_start_err` entry is only ever written by the
        // `NewProxyResp` error path. The stale anchor is what made p2 eligible
        // and the entry is left exactly as it was.
        assert_eq!(
            last_start_err.get("user.p2").copied(),
            Some(stale_anchor),
            "the retry send must not rewrite the StartErr anchor"
        );
        assert_eq!(
            last_start_err.get("user.p3").copied(),
            Some(fresh_anchor),
            "the still-StartErr proxy keeps its original anchor"
        );
    }
    /// The extracted `xtcp_cleanup` arm, driven directly. No lane puts a
    /// cleanup key on the channel to a client `Service`, so this is the direct
    /// witness for the reclaim rule the arm owns: the key is removed from
    /// **both** NAT-hole maps (the provider `sid` and the visitor txn_id
    /// namespaces are independent, which is what makes the one lookup correct
    /// for either), unrelated keys are untouched, and an absent key is a
    /// silent no-op.
    #[tokio::test]
    async fn xtcp_cleanup_arm_reclaims_both_nat_hole_maps() {
        let service = test_service().await;
        let mut ctx = test_session_ctx();
        ctx.pending_xtcp
            .insert("sid-a".to_string(), "user.p1".to_string());
        let (visitor_tx, _visitor_rx) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
        ctx.visitor_pending.insert("sid-a".to_string(), visitor_tx);
        ctx.pending_xtcp
            .insert("txn-b".to_string(), "user.p2".to_string());
        let (visitor_tx_b, _visitor_rx_b) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
        ctx.visitor_pending
            .insert("txn-b".to_string(), visitor_tx_b);

        service
            .handle_xtcp_cleanup_arm("sid-a".to_string(), &mut ctx)
            .await;
        assert!(
            !ctx.pending_xtcp.contains_key("sid-a") && !ctx.visitor_pending.contains_key("sid-a"),
            "the reclaimed key must leave the provider and the visitor map"
        );
        assert!(
            ctx.pending_xtcp.contains_key("txn-b") && ctx.visitor_pending.contains_key("txn-b"),
            "an unrelated key must be left alone"
        );

        service
            .handle_xtcp_cleanup_arm("txn-b".to_string(), &mut ctx)
            .await;
        assert!(
            !ctx.pending_xtcp.contains_key("txn-b") && !ctx.visitor_pending.contains_key("txn-b"),
            "the visitor txn_id namespace is reclaimed by the same lookup"
        );

        service
            .handle_xtcp_cleanup_arm("absent".to_string(), &mut ctx)
            .await;
        assert!(
            ctx.pending_xtcp.is_empty() && ctx.visitor_pending.is_empty(),
            "an absent key must be a no-op"
        );
    }

    /// The extracted STUN-result arm, driven directly. This arm owns the
    /// provider write, the `pending_xtcp` bookkeeping and the defensive 15s
    /// cleanup spawn; its input's producer is the off-loop STUN task, which the
    /// XTCP-notify test below drives for real.
    #[tokio::test(start_paused = true)]
    async fn stun_result_arm_writes_client_and_reclaims_socket_on_write_failure() {
        let service = test_service().await;
        let mut ctx = test_session_ctx();
        let (writer, mut written) = test_control_writer_rx();
        let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<String>(4);

        // Success path: the `NatHoleClient` is enqueued on the control writer
        // and the sid is tracked for `NatHoleResp` routing.
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind a STUN probe socket");
        ctx.xtcp_sockets
            .lock()
            .await
            .insert("s-ok".to_string(), Arc::new(probe));
        service
            .handle_stun_result_arm(
                StunResult {
                    sid: "s-ok".to_string(),
                    proxy_name: "user.p1".to_string(),
                    msg: FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
                        transaction_id: "txn-1".to_string(),
                        proxy_name: "user.p1".to_string(),
                        sid: Some("s-ok".to_string()),
                        protocol: Some("kcp".to_string()),
                        mapped_addrs: None,
                        assisted_addrs: None,
                        visitor_addr: None,
                    })),
                },
                &mut ctx,
                &writer,
                &cleanup_tx,
            )
            .await;
        let (frame, v2) = written
            .try_recv()
            .expect("a successful write must enqueue the NatHoleClient");
        assert!(!v2, "the test ctx negotiates V1");
        assert!(matches!(frame, FrpMessage::NatHoleClient(_)));
        assert_eq!(
            ctx.pending_xtcp.get("s-ok").map(String::as_str),
            Some("user.p1"),
            "the success path tracks sid -> proxy_name for NatHoleResp routing"
        );
        assert!(
            ctx.xtcp_sockets.lock().await.contains_key("s-ok"),
            "the write itself must not reclaim the socket"
        );
        // The success branch spawned the arm's defensive cleanup task. With the
        // clock paused, waiting on the channel advances time to its 15s
        // deadline, so the assertion is on the task's real effect rather than
        // on a sleep: the socket is reclaimed and the sid is handed to the
        // cleanup arm.
        let cleaned = tokio::time::timeout(Duration::from_secs(60), cleanup_rx.recv())
            .await
            .expect("the success branch must spawn the defensive cleanup task")
            .expect("cleanup_tx is still held by this test");
        assert_eq!(
            cleaned, "s-ok",
            "the spawned cleanup task must hand the sid back after the NAT window"
        );
        assert!(
            !ctx.xtcp_sockets.lock().await.contains_key("s-ok"),
            "the cleanup task must reclaim the persisted socket"
        );

        // Failure path: nothing is enqueued, no pending entry is created, and
        // the socket the STUN task stored is reclaimed immediately — it would
        // otherwise sit until control-loop teardown.
        let probe2 = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind a second STUN probe socket");
        ctx.xtcp_sockets
            .lock()
            .await
            .insert("s-fail".to_string(), Arc::new(probe2));
        writer
            .failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        service
            .handle_stun_result_arm(
                StunResult {
                    sid: "s-fail".to_string(),
                    proxy_name: "user.p2".to_string(),
                    msg: FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
                        transaction_id: "txn-2".to_string(),
                        proxy_name: "user.p2".to_string(),
                        sid: Some("s-fail".to_string()),
                        protocol: Some("kcp".to_string()),
                        mapped_addrs: None,
                        assisted_addrs: None,
                        visitor_addr: None,
                    })),
                },
                &mut ctx,
                &writer,
                &cleanup_tx,
            )
            .await;
        assert!(
            written.try_recv().is_err(),
            "a failed control write must enqueue nothing"
        );
        assert!(
            !ctx.xtcp_sockets.lock().await.contains_key("s-fail"),
            "the socket of a failed NatHoleClient send must not leak"
        );
        assert!(
            !ctx.pending_xtcp.contains_key("s-fail"),
            "the failure path must not create a pending_xtcp entry"
        );
    }

    /// The extracted XTCP-notify arm, driven directly against a loopback STUN
    /// responder. This is the arm that **spawns**, so the test is built to
    /// witness the split rather than the code text: the handler must return
    /// with the result not yet produced (the message loop cannot stall for the
    /// STUN round-trips), the spawned task must persist the STUN socket under
    /// the sid, and the finished `NatHoleClient` must come back on
    /// `stun_result_tx` for the loop to write — the write-before-`NatHoleResp`
    /// ordering the arm's comment relies on.
    ///
    /// The responder is the minimal RFC 5389 shape of the integration lane's
    /// (`frp-client/tests/xtcp_pair_e2e.rs`, `run_mock_stun_server`): it echoes
    /// the request txid and reports the OBSERVED SOURCE as MAPPED-ADDRESS, with
    /// no OTHER-ADDRESS, so the arm's second probe re-queries this same server.
    /// A unit test cannot import an integration test's module, so this copy is
    /// the only way to drive the spawned STUN task directly.
    #[tokio::test]
    async fn xtcp_notify_arm_spawns_stun_and_hands_back_nat_hole_client() {
        // Written with `while let` + nested `if let` rather than the
        // integration lane's early-return-on-invalid shape, so this test adds
        // no loop-continue token: the file's executable-continue census stays
        // 0 (group C removed the last one) and its only textual hit stays the
        // ping handler's doc prose.
        async fn responder(socket: tokio::net::UdpSocket) {
            let mut buf = vec![0u8; 512];
            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                if n >= 20
                    && u16::from_be_bytes([buf[0], buf[1]]) == 0x0001
                    && buf[4..8] == 0x2112_A442u32.to_be_bytes()
                {
                    if let std::net::IpAddr::V4(ip) = src.ip() {
                        let mut resp = Vec::with_capacity(32);
                        resp.extend_from_slice(&0x0101u16.to_be_bytes());
                        resp.extend_from_slice(&12u16.to_be_bytes());
                        resp.extend_from_slice(&0x2112_A442u32.to_be_bytes());
                        resp.extend_from_slice(&buf[8..20]);
                        resp.extend_from_slice(&0x0001u16.to_be_bytes());
                        resp.extend_from_slice(&8u16.to_be_bytes());
                        resp.push(0x00);
                        resp.push(0x01);
                        resp.extend_from_slice(&src.port().to_be_bytes());
                        resp.extend_from_slice(&ip.octets());
                        let _ = socket.send_to(&resp, src).await;
                    }
                }
            }
        }

        let service = test_service().await;
        let mut ctx = test_session_ctx();
        let (stun_tx, mut stun_rx) = mpsc::channel::<StunResult>(4);
        ctx.stun_result_tx = Some(stun_tx);

        let stun_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the mock STUN responder");
        let stun_server = stun_socket
            .local_addr()
            .expect("responder addr")
            .to_string();
        let _responder = tokio::spawn(responder(stun_socket));

        // `SessionChannels` borrows its receivers, so the literal is built here
        // rather than returned from a helper.
        let (_health_tx, mut health_rx) = mpsc::channel::<HealthEvent>(1);
        let (_reload_tx, mut reload_rx) = mpsc::channel::<ReloadRequest>(1);
        let (_xtcp_tx, mut xtcp_rx) = mpsc::channel::<XtcpNotification>(1);
        let (_visitor_tx, mut visitor_rx) = mpsc::channel::<VisitorRequest>(1);
        let (_stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let health_cancels = Arc::new(Mutex::new(HashMap::new()));
        let channels = SessionChannels {
            health_rx: &mut health_rx,
            reload_rx: &mut reload_rx,
            xtcp_rx: &mut xtcp_rx,
            visitor_rx: &mut visitor_rx,
            stop_rx: &mut stop_rx,
            health_cancels: &health_cancels,
            nat_hole_stun_server: &stun_server,
        };

        service
            .handle_xtcp_notify_arm(
                XtcpNotification {
                    sid: "sid-1".to_string(),
                    proxy_name: "user.p1".to_string(),
                },
                &mut ctx,
                &channels,
            )
            .await;
        // The spawn/await split, witnessed: on a current-thread runtime the
        // spawned STUN task cannot have run yet (the handler body has no
        // yield point of its own), so a result already here would mean the arm
        // did the STUN inline and blocked the message loop.
        assert!(
            stun_rx.try_recv().is_err(),
            "the STUN work must be spawned off-loop, not awaited by the handler"
        );

        let stun = tokio::time::timeout(Duration::from_secs(10), stun_rx.recv())
            .await
            .expect("the spawned STUN task must hand a result back within 10s")
            .expect("stun_result_tx is still held by this test");
        assert_eq!(stun.sid, "sid-1");
        assert_eq!(stun.proxy_name, "user.p1");
        match stun.msg {
            FrpMessage::NatHoleClient(nhc) => {
                assert_eq!(nhc.proxy_name, "user.p1");
                assert_eq!(nhc.sid.as_deref(), Some("sid-1"));
                assert_eq!(
                    nhc.protocol.as_deref(),
                    Some("kcp"),
                    "Go frp v0.70 compat: the provider announces protocol \"kcp\""
                );
                // frp-client forwards `frp-core/stun` from its `kcp` and
                // `vnet` features; in a shape with neither, `frp_core::stun`
                // is the stub that errors without touching the network, so
                // the arm stores no socket and builds the message with no
                // mapped address. Both shapes are asserted, and `cfg!` is the
                // compiled truth: if it ever disagrees with what the arm
                // actually did (a forwarding change in either direction),
                // this test reds instead of skipping.
                if cfg!(any(feature = "kcp", feature = "vnet")) {
                    let mapped = nhc
                        .mapped_addrs
                        .expect("both STUN probes must report a mapped address");
                    assert_eq!(
                        mapped.len(),
                        2,
                        "no OTHER-ADDRESS in the response -> the second probe re-queries the same server"
                    );
                    // The persisted socket is the one the probes ran on, so the
                    // mapped port must equal its bound port.
                    let sockets = ctx.xtcp_sockets.lock().await;
                    let persisted = sockets
                        .get("sid-1")
                        .expect("the STUN socket must be persisted under the sid");
                    let local_port = persisted.local_addr().expect("bound").port();
                    assert_eq!(mapped[0], format!("127.0.0.1:{local_port}"));
                    assert_eq!(mapped[1], format!("127.0.0.1:{local_port}"));
                } else {
                    assert!(
                        nhc.mapped_addrs.is_none(),
                        "without frp-core/stun the probe fails, so no mapped address may be reported"
                    );
                    assert!(
                        ctx.xtcp_sockets.lock().await.is_empty(),
                        "a failed probe must not persist a socket"
                    );
                }
            }
            other => panic!("expected NatHoleClient, got {other:?}"),
        }
        assert!(
            !ctx.pending_xtcp.contains_key("sid-1"),
            "pending_xtcp is the STUN-result arm's bookkeeping, not this arm's"
        );
    }

    /// The extracted health-event arm, driven directly for both events over a
    /// real `Service` — the arm is channel-driven, and no test puts a
    /// `HealthEvent` through a live session's `health_rx`. `Close` is witnessed
    /// by the three effects the arm owns (P2P bridge token cancelled, phase
    /// moved to `CheckFailed`, `CloseProxy` enqueued) and `Recover` by the
    /// `NewProxy` it rebuilds from the stored config plus the `WaitStart` phase
    /// the `NewProxyResp` handler completes; a `Recover` with no stored config
    /// must send nothing.
    #[tokio::test]
    async fn health_event_arm_cancels_bridge_and_reregisters() {
        let service = test_service().await;
        let mut ctx = test_session_ctx();
        // The health-check tasks and `health_proxy_configs` are keyed by the
        // WIRE proxy name, so the prefix must be live for the re-registration
        // to rebuild the same name.
        ctx.cfg_user = "user".to_string();
        let (writer, mut written) = test_control_writer_rx();

        let token = CancellationToken::new();
        service
            .p2p_bridge_tokens
            .lock()
            .await
            .insert("user.p1".to_string(), token.clone());
        {
            let mut map = service.proxy_info_map.write().await;
            map.insert("user.p1".to_string(), proxy_info(ProxyPhase::Running));
            map.insert(
                "user.p2".to_string(),
                ProxyRuntimeInfo {
                    local_addr: "127.0.0.1:9009".to_string(),
                    ..proxy_info(ProxyPhase::Running)
                },
            );
        }
        // Only p2 has a stored config; p3 is the no-config branch.
        service.health_proxy_configs.lock().await.insert(
            "user.p2".to_string(),
            frp_core::config::ProxyConfig {
                name: "p2".to_string(),
                proxy_type: "tcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 9001,
                ..Default::default()
            },
        );

        // Close: cancel the bridge token, mark CheckFailed, send CloseProxy.
        service
            .handle_health_event_arm(HealthEvent::Close("user.p1".to_string()), &mut ctx, &writer)
            .await;
        assert!(
            token.is_cancelled(),
            "health Close must cancel the proxy's P2P bridge token"
        );
        assert!(
            matches!(
                service
                    .proxy_info_map
                    .read()
                    .await
                    .get("user.p1")
                    .map(|i| &i.phase),
                Some(ProxyPhase::CheckFailed)
            ),
            "health Close must mark the proxy CheckFailed before the send"
        );
        match written
            .try_recv()
            .expect("health Close must enqueue CloseProxy")
        {
            (FrpMessage::CloseProxy(cp), v2) => {
                assert_eq!(cp.proxy_name, "user.p1");
                assert!(!v2, "the test ctx negotiates V1");
            }
            other => panic!("expected CloseProxy, got {other:?}"),
        }
        assert!(written.try_recv().is_err(), "exactly one control message");

        // Recover: the stored config is re-registered from the map's local
        // address, and the phase waits for NewProxyResp.
        service
            .handle_health_event_arm(
                HealthEvent::Recover("user.p2".to_string()),
                &mut ctx,
                &writer,
            )
            .await;
        match written
            .try_recv()
            .expect("health Recover must re-send NewProxy")
        {
            (FrpMessage::NewProxy(np), v2) => {
                assert_eq!(np.proxy_name, "user.p2");
                // `local_str` is stripped by `create_new_proxy_msg` for Go frps
                // parity, so which local address the arm chose (the live
                // `proxy_info_map` entry above, not the config fallback) is not
                // observable from the message; the send, name, type and phase
                // are.
                assert!(
                    np.local_str.is_none(),
                    "create_new_proxy_msg strips local_str for Go frps parity"
                );
                assert_eq!(np.proxy_type, "tcp");
                assert!(!v2, "the test ctx negotiates V1");
            }
            other => panic!("expected NewProxy, got {other:?}"),
        }
        assert!(
            matches!(
                service
                    .proxy_info_map
                    .read()
                    .await
                    .get("user.p2")
                    .map(|i| &i.phase),
                Some(ProxyPhase::WaitStart)
            ),
            "health Recover must move the proxy to WaitStart"
        );

        // Recover with no stored config: warn only, nothing on the wire.
        service
            .handle_health_event_arm(
                HealthEvent::Recover("user.p3".to_string()),
                &mut ctx,
                &writer,
            )
            .await;
        assert!(
            written.try_recv().is_err(),
            "a Recover without a stored config must send nothing"
        );
        assert!(
            !service.proxy_info_map.read().await.contains_key("user.p3"),
            "the no-config branch must not create a proxy entry"
        );
    }

    /// The extracted visitor-request arm, driven directly over a real
    /// `Service`. This arm **spawns**, so the test witnesses the split rather
    /// than the code text: the handler returns with the 20 s cleanup not yet
    /// fired (the clock is paused), and advancing the clock fires the spawned
    /// task, which hands the txn id back on the loop-owned `xtcp_cleanup_tx`.
    /// The failure branch must complete the request's oneshot with the error
    /// and record nothing.
    #[tokio::test(start_paused = true)]
    async fn visitor_request_arm_sends_and_arms_spawned_cleanup() {
        let service = test_service().await;
        let mut ctx = test_session_ctx();
        let (writer, mut written) = test_control_writer_rx();
        let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<String>(4);

        let (reply_tx, mut reply_rx) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
        service
            .handle_visitor_request_arm(
                VisitorRequest {
                    nhv: msg::NatHoleVisitor {
                        transaction_id: "txn-1".to_string(),
                        proxy_name: "user.p1".to_string(),
                        ..Default::default()
                    },
                    reply: reply_tx,
                },
                &mut ctx,
                &writer,
                &cleanup_tx,
            )
            .await;
        let (frame, v2) = written
            .try_recv()
            .expect("a successful send must enqueue the NatHoleVisitor");
        assert!(!v2, "the test ctx negotiates V1");
        match frame {
            FrpMessage::NatHoleVisitor(nhv) => {
                assert_eq!(nhv.transaction_id, "txn-1");
                assert_eq!(nhv.proxy_name, "user.p1");
            }
            other => panic!("expected NatHoleVisitor, got {other:?}"),
        }
        assert!(written.try_recv().is_err(), "exactly one control message");
        assert!(
            ctx.visitor_pending.contains_key("txn-1"),
            "the success path records the txn for the NatHoleResp arm"
        );
        assert!(
            reply_rx.try_recv().is_err(),
            "the success path leaves the reply for the NatHoleResp arm"
        );
        // The 20 s cleanup must be off-loop: the handler body has no yield
        // point of its own, so on this current-thread runtime the spawned task
        // cannot have run yet, and with the clock paused its sleep has not
        // fired. If the arm awaited the sleep inline it would have
        // auto-advanced the paused clock and delivered the key before
        // returning, which this assertion catches.
        assert!(
            cleanup_rx.try_recv().is_err(),
            "the cleanup must be spawned off-loop, not awaited by the handler"
        );
        // Let the spawned task reach its sleep, then move the clock past the
        // 20 s deadline so the assertion is on the task's real effect.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        let cleaned = tokio::time::timeout(Duration::from_secs(5), cleanup_rx.recv())
            .await
            .expect("the spawned 20s cleanup must hand the txn id back")
            .expect("cleanup_tx is still held by this test");
        assert_eq!(cleaned, "txn-1");

        // Failure path: a failed writer enqueues nothing, records nothing and
        // completes the request's oneshot with the error.
        let (writer2, mut written2) = test_control_writer_rx();
        writer2
            .failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (reply_tx2, reply_rx2) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
        service
            .handle_visitor_request_arm(
                VisitorRequest {
                    nhv: msg::NatHoleVisitor {
                        transaction_id: "txn-2".to_string(),
                        proxy_name: "user.p2".to_string(),
                        ..Default::default()
                    },
                    reply: reply_tx2,
                },
                &mut ctx,
                &writer2,
                &cleanup_tx,
            )
            .await;
        assert!(
            written2.try_recv().is_err(),
            "a failed control send must enqueue nothing"
        );
        assert!(
            !ctx.visitor_pending.contains_key("txn-2"),
            "the failure path must not record the txn"
        );
        let err = reply_rx2
            .await
            .expect("the failure path must complete the reply")
            .expect_err("the reply must carry the send error");
        assert!(
            err.starts_with("send failed:"),
            "unexpected error text: {err}"
        );
    }
}
