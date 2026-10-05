//! The client session lifecycle: `run()` (the reconnect loop) and the
//! per-session phases it drives — `connect_and_login` (Phases 1-3),
//! `spawn_session_tasks` (Phase 5), `teardown_session` (Phase 7), the
//! visitor-listener shutdown both phases share, and the two detached-task
//! controls `cancel_detached_tasks` / `spawn_admin_server`.
//!
//! Split out of `frp-client/src/service.rs` by the P2 S4 seam as a pure move:
//! every moved line is verbatim except for two `pub(super)` tokens — on
//! `shutdown_visitor_tasks` (whose signature rustfmt re-flowed over four
//! lines, the token having crossed the 100-column limit) and on
//! `teardown_session`. They are the minimum the move requires — a private
//! method declared in a child module is not visible to the parent `service`
//! module (E0624), and the sibling `service/tests.rs` drives both directly.
//! `run` and `request_stop` keep their `pub` token: `frpc/src/main.rs` and the
//! tests call them through `Service`. This module is a *child* of `service`,
//! which is what lets the `impl Service` block below reach the parent's
//! private fields and methods; it is deployed as a child module rather than a
//! flat sibling for exactly that reason (see the P2 layout note in
//! `docs/refactor-large-modules.md`).
//!
//! The two orderings the plan flagged as load-bearing were measured before
//! the move and travel verbatim:
//!
//!   * in `spawn_session_tasks` the dedicated control-writer task is spawned
//!     first, because the vnet controllers spawned next advertise routes
//!     through its channel; the previous session's visitor listeners are then
//!     shut down and awaited before this session's listeners are spawned, so
//!     a listener still parked in `accept()` cannot hold the bind port
//!     against the new one;
//!   * in `teardown_session` the five numbered steps run in the order the
//!     comments state (signal the work-conn pool, abort this session's
//!     work-conn tasks, signal the visitor listeners, drop the control
//!     connection, abort the control-writer task), and the writer abort is
//!     last because the vnet route-removal sends above it ride that writer's
//!     channel.

use super::*;

impl Service {
    /// Wait briefly for visitor listener tasks to exit gracefully, then
    /// force-abort any still blocked in `accept()` so their listeners drop
    /// and the bind ports are released immediately. Without the abort, an
    /// idle visitor listener (no inbound traffic) never wakes from `accept()`,
    /// the dropped `JoinHandle` does NOT cancel the task, and the next
    /// session's `bind()` fails with AddrInUse — permanently killing the
    /// visitor (STCP/XTCP) until frpc restarts.
    pub(super) async fn shutdown_visitor_tasks(
        &self,
        mut handles: Vec<tokio::task::JoinHandle<()>>,
    ) {
        // &mut JoinHandle implements Future (tokio); &JoinHandle does not.
        let graceful = tokio::time::timeout(
            Duration::from_millis(500),
            futures_util::future::join_all(handles.iter_mut()),
        )
        .await;
        if graceful.is_err() {
            tracing::warn!(
                count = handles.len(),
                "Visitor shutdown timed out after 500ms; aborting stuck listener task(s) to release bind ports"
            );
            // Snapshot completion BEFORE the aborts and skip the handles that
            // are already finished. The invariant this preserves: **each handle
            // is awaited at most once, and `is_finished()` is true exactly for
            // the handles whose output `join_all` already took.** Two measured
            // facts make it the fix:
            //
            // 1. A `JoinHandle` may be polled to `Ready` only once, and
            //    `join_all` above polls every handle. The handles whose task
            //    already finished have had their output taken and now sit at
            //    `Stage::Consumed` (`store_output` puts `Stage::Finished` there,
            //    `take_output` replaces it with `Stage::Consumed`), so awaiting
            //    them again hits `take_output`'s
            //    `_ => panic!("JoinHandle polled after completion")`
            //    (tokio-1.53.1/src/runtime/task/core.rs:427). That is the
            //    SIGTERM crash: with N >= 2 visitors sharing one `bind_port`
            //    the losers' `TcpListener::bind` fails and their task returns
            //    at once, so `join_all` completes their handles while the
            //    winner stays parked in `accept()` past the 500ms grace.
            // 2. A finished task has already dropped its future, so skipping it
            //    releases nothing that this abort path exists to release. The
            //    future is dropped by `store_output` on normal completion
            //    (harness.rs:549 -> core.rs:434, where `set_stage`'s assignment
            //    drops the replaced `Stage::Running(future)`) or by
            //    `drop_future_or_output` on cancellation (harness.rs:503 ->
            //    core.rs:399), and the COMPLETE bit `is_finished` reads
            //    (join.rs:258 -> state.rs:599) is set afterwards by
            //    `transition_to_complete` (harness.rs:334). The listener socket
            //    is therefore already closed when `is_finished()` turns true.
            //    `service::tests::shutdown_visitor_tasks_releases_listeners`
            //    measures both halves of that: a finished task's port is
            //    bindable again while its handle is still un-awaited, and a
            //    parked listener's port is released by the abort+await below.
            //
            // Snapshotting before `abort()` keeps the skip set to handles that
            // were already complete when the grace window expired, so every
            // handle this branch aborts is still awaited exactly once. The
            // 500ms grace is unchanged — skipping a finished handle can only
            // make shutdown return no later than before. Observability is
            // unchanged too: this branch already discarded join results
            // (`let _ = h.await`), and a task's panic is reported by the panic
            // hook when it happens, so a panicking finished visitor is no more
            // hidden by the skip than by the await it replaces.
            let already_finished: Vec<bool> = handles.iter().map(|h| h.is_finished()).collect();
            for h in &handles {
                h.abort();
            }
            for (h, was_finished) in handles.into_iter().zip(already_finished) {
                if was_finished {
                    continue;
                }
                let _ = h.await;
            }
        }
    }

    /// Request a graceful shutdown. Safe to call from signal handler.
    /// Returns immediately; the actual shutdown happens asynchronously in run().
    pub fn request_stop(&self) {
        match self.stop_tx.try_send(()) {
            Ok(()) => tracing::info!("Stop requested, initiating graceful shutdown"),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("Stop channel full — a stop request is already queued");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("Stop channel closed — service already shutting down");
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cfg_snapshot = self.cfg.read().await.clone();
        info!(
            version = %frp_core::VERSION, server_addr = %cfg_snapshot.server_addr, server_port = %cfg_snapshot.server_port,
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, cfg_snapshot.server_addr, cfg_snapshot.server_port
        );

        let protocol: TransportProtocol = match cfg_snapshot.transport_protocol.parse() {
            Ok(p) => p,
            Err(_) => {
                return Err(format!(
                    "unknown transport protocol '{}'. Valid transports: tcp, kcp, quic, websocket, wss",
                    cfg_snapshot.transport_protocol
                )
                .into());
            }
        };
        let pool_count = cfg_snapshot.pool_count.max(0);

        // Take the receiver from self (created in constructor, consumed once).
        let mut health_rx = self
            .health_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("health_rx already taken — run() called twice?");

        // Cancellation flags for health check tasks — set to true when a proxy
        // is closed (via CloseProxy from server, admin, or health check failure).
        // Stored on self so try_reload() can cancel health checks for removed proxies.
        let health_cancels = self.health_cancels.clone();

        let all_startup_proxies = Arc::clone(&*self.proxies.read().await);
        let startup_proxies = filter_active_proxies(&cfg_snapshot, &all_startup_proxies);
        self.spawn_health_checks(
            &cfg_snapshot.user,
            &startup_proxies,
            &self.health_tx,
            &health_cancels,
            &self.health_session_gen,
        )
        .await;

        // Start admin HTTP server if configured
        let _reload_tx = self.reload_tx.clone();
        let mut reload_rx = self
            .reload_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("reload_rx already taken — run() called twice?");
        let mut xtcp_rx = self
            .xtcp_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("xtcp_rx already taken — run() called twice?");
        let mut visitor_rx = self
            .visitor_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("visitor_rx already taken — run() called twice?");
        let nat_hole_stun_server = self.nat_hole_stun_server.clone();
        let mut stop_rx = self
            .stop_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("stop_rx already taken — run() called twice?");

        // Handle of the spawned admin HTTP server task; aborted on shutdown
        // (cancel_detached_tasks). Only spawned with the `admin` feature.
        #[cfg(feature = "admin")]
        let mut admin_handle: Option<tokio::task::JoinHandle<()>> =
            self.spawn_admin_server(&_reload_tx, &self.stop_tx).await;
        #[cfg(not(feature = "admin"))]
        let mut admin_handle: Option<tokio::task::JoinHandle<()>> = None;

        // Main session loop with reconnection.
        // Go frp dev two-phase fast-backoff:
        //   Phase 1 (first 3 retries within 60s window): 200ms × full jitter (0.5-1.5)
        //   Phase 2 (after that): 1s × 2ⁿ × full jitter (0.5-1.5), cap 20s
        // Matches Go frp dev wait.FastBackoffManager (full multiplicative
        // jitter replaces the additive jitter so clients restarting together
        // de-synchronize instead of re-clustering in a narrow band).
        let mut did_login_once = false;
        let mut consecutive_err_count: u32 = 0;
        // Last computed reconnect delay — the Go fast-backoff anchors Phase 2
        // to this value (previousDuration) instead of recomputing 1s·2^n.
        let mut previous_delay: std::time::Duration = std::time::Duration::ZERO;
        let mut fast_retry_timestamps: Vec<Instant> = Vec::new();
        // When a session runs healthily for a long time, the consecutive
        // error count is reset so an occasional blip doesn't reconnect with
        // the backoff cap already reached (Go frp's FastBackoffManager only
        // counts consecutive failures).
        // Carry over run_id across reconnections (Go frp compat: previousRunID).
        let mut previous_run_id = String::new();
        // Explicitly hold the previous session's yamux handle so we can drop it
        // before creating a new connection (Go frp compat: svr.ctl.Close()).
        // Dropping the Arc causes the background yamux task to notice the
        // closed sender channel and exit, closing the TCP socket.
        #[cfg(feature = "tcp-mux")]
        let mut prev_yamux: Option<std::sync::Arc<frp_core::mux::YamuxSession>> = None;
        loop {
            // Read guard over the config instead of cloning the whole
            // ClientConfig (all proxies/visitors/strings) per connection
            // attempt. Field reads go through the guard's Deref; the guard
            // The guard is held through ctl.login().await and (on failure)
            // the backoff sleep — 800+ lines and several await points below.
            // This is safe because every cfg writer (try_reload / do_reload)
            // runs in the same task and the message loop's reload arm polls
            // internal_rx, not a blocking lock. An early drop before the
            // backoff sleep would be cleaner but is not reachable without
            // cloning: the guard is needed again below (v2, client_scopes,
            // transport locals, ping interval, heartbeat timeout, cfg_user)
            // after a successful login. The trade-off is accepted.
            let cfg_local = self.cfg.read().await;
            let all_proxies = Arc::clone(&*self.proxies.read().await);
            let proxies = filter_active_proxies(&cfg_local, &all_proxies);

            // Go frp compat (d486018): drop previous yamux session before
            // creating a new control connection. This drops the sender channel,
            // causing the background yamux task to exit and close the TCP socket.
            #[cfg(feature = "tcp-mux")]
            drop(prev_yamux.take());

            // Phases 1-3 (config snapshot, dial + login, encryption wrap,
            // yamux, heartbeat init) live in connect_and_login; it returns
            // the per-session state or the error. Backoff counters stay here.
            let mut ctx = match self
                .connect_and_login(
                    &cfg_local,
                    &protocol,
                    pool_count,
                    previous_run_id.clone(),
                    &mut did_login_once,
                )
                .await
            {
                Ok(ctx) => ctx,
                Err(e) => {
                    consecutive_err_count += 1;
                    warn!(attempt = %consecutive_err_count, error = %e, "Login failed (attempt {}): {}", consecutive_err_count, e);
                    if cfg_local.login_fail_exit && !did_login_once {
                        // Cancel detached health/admin tasks so a caller that
                        // handles the error (e.g. tests) does not keep them
                        // running after run() returns.
                        self.cancel_detached_tasks(&health_cancels, admin_handle)
                            .await;
                        return Err(e.into());
                    }
                    let delay = if did_login_once {
                        // Session reconnect: full fast-backoff with Phase 1 (200ms) + Phase 2 (exponential).
                        fast_retry_timestamps.push(Instant::now());
                        let window_count =
                            crate::backoff::prune_fast_retry_count(&mut fast_retry_timestamps);
                        let d = crate::backoff::fast_backoff_delay(
                            consecutive_err_count,
                            window_count,
                            previous_delay,
                        );
                        previous_delay = d;
                        d
                    } else {
                        // Initial login: pure exponential, no fast retry phase.
                        // Matches Go frp's loopLoginUntilSuccess (FastBackoffOptions
                        // without FastRetryCount, MaxDuration=10s).
                        // Go frp v0.70.1: initial login cap is 10s, reconnection cap is 20s.
                        // See /tmp/frp-source/client/service.go:261,286.
                        let mut delay_ms = 1000u64;
                        for _ in 0..consecutive_err_count {
                            delay_ms = delay_ms.saturating_mul(2).min(10_000);
                        }
                        let jitter_ms =
                            (rand::rng().random::<f64>() * 0.1 * delay_ms as f64) as u64;
                        Duration::from_millis(delay_ms.saturating_add(jitter_ms).min(10_000))
                    };
                    // Race the backoff against a stop request: with
                    // login_fail_exit = false and an unreachable server, the
                    // plain sleep below would hold a buffered admin/signal
                    // stop (cap-1 stop_tx) until a login eventually succeeds —
                    // shutdown would hang indefinitely (Go client/service.go
                    // loopLoginUntilSuccess has no stop path either; this is
                    // client-side robustness beyond parity, same shape as the
                    // reconnect-sleep select below). There is no ctx on the
                    // login-failure path (it is bound only in the Ok arm
                    // above), so this branch only cancels the detached
                    // health/admin tasks and returns.
                    tokio::select! {
                        Some(()) = stop_rx.recv() => {
                            info!("Stop requested while waiting to retry login, shutting down");
                            self.cancel_detached_tasks(&health_cancels, admin_handle).await;
                            return Ok(());
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    continue;
                }
            };

            // Store for explicit cleanup before next reconnect (Go frp compat d486018).
            #[cfg(feature = "tcp-mux")]
            {
                prev_yamux = ctx.yamux.clone();
            }
            previous_run_id = ctx.run_id.clone();

            // Session boundary for the long-lived health monitors (H2): this
            // login started a NEW control session whose server holds no proxy
            // registrations yet. Bump the generation so monitors re-arm and
            // re-register their proxies on the first healthy probe of this
            // session (Go parity: a fresh control.Run() builds a fresh
            // Monitor with statusOK=false). Monitors observe the change on
            // their next tick, so the bump must precede the registration
            // phase — a Recover sent before this point would ride the dead
            // previous session's writer.
            self.health_session_gen.fetch_add(1, Ordering::Relaxed);

            // Phase 4: pipelined NewProxy/NewVisitorConn registration + the
            // registration response read loop (2s visitor grace +
            // REGISTRATION_RESPONSE_TIMEOUT + heartbeat watchdog races), vnet
            // TUN opens, and the StartErr drain — extracted into
            // register_proxies. Returns false when the registration phase
            // aborted (a read error or the heartbeat watchdog fired); the
            // session continuation below is then skipped and the session
            // goes straight to teardown + reconnect.
            let aborted = !self
                .register_proxies(&mut ctx, &cfg_local, &proxies, pool_count)
                .await;

            // Control writes are funneled through a bounded channel to a
            // single dedicated writer task (audit v0.70.1 P1-A1): producers
            // never block on a slow peer, the raw write half is owned by
            // exactly one task, and a write failure wakes the control loop
            // to tear down and reconnect. Created before the guarded session
            // continuation so the teardown below can use `writer` even when
            // the continuation was skipped (registration heartbeat watchdog).
            let (control_tx, control_rx) = tokio::sync::mpsc::channel::<(FrpMessage, bool)>(1024);
            let control_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let control_notify = Arc::new(tokio::sync::Notify::new());
            ctx.writer = Some(Arc::new(ControlWriter {
                tx: control_tx,
                failed: control_failed.clone(),
                notify: control_notify.clone(),
            }));
            ctx.control_rx = Some(control_rx);
            ctx.control_failed = Some(control_failed);
            ctx.control_notify = Some(control_notify);

            // Shared graceful shutdown signal for all visitor listener tasks.
            // Set to true at session end so tasks exit cleanly (Fix 8).
            // Declared here (outside the continuation guard) because the
            // teardown below uses it even when the continuation was skipped.
            ctx.visitor_shutdown = Some(Arc::new(AtomicBool::new(false)));

            // Session continuation: split the stream, spawn the writer task
            // and vnet controllers, spawn visitor listeners, then run the
            // message loop. Skipped when the registration phase aborted (a
            // read error or the heartbeat watchdog fired): the connection is
            // unresponsive, so the session goes straight to teardown +
            // reconnect below — the same path a message-loop heartbeat
            // timeout takes. An aborted session has no spawned visitors or
            // writer task to clean up; the shared teardown below handles
            // both. The loop exit is captured as `Option` so the aborted
            // path (no loop ran) feeds into the same teardown + decision
            // tail as a `LoopExit::Reconnect` exit.
            let exit = if !aborted {
                // Phase 5: split the stream, spawn the writer task and vnet
                // controllers, cancel the previous session's visitor
                // listeners, and spawn the current session's visitors.
                self.spawn_session_tasks(
                    &mut ctx,
                    &cfg_local,
                    &proxies,
                    &protocol,
                    &nat_hole_stun_server,
                )
                .await?;

                // The message loop handles config reloads (try_reload), which
                // take the config write lock — the snapshot read guard must be
                // dropped first. `user` is the only snapshot field the loop
                // still needs; copy it here.
                ctx.cfg_user = cfg_local.user.clone();
                drop(cfg_local);

                // Phase 6: the message loop, until the session ends.
                Some(
                    self.run_message_loop(
                        &mut ctx,
                        &mut SessionChannels {
                            health_rx: &mut health_rx,
                            reload_rx: &mut reload_rx,
                            xtcp_rx: &mut xtcp_rx,
                            visitor_rx: &mut visitor_rx,
                            stop_rx: &mut stop_rx,
                            health_cancels: &health_cancels,
                            nat_hole_stun_server: &nat_hole_stun_server,
                        },
                    )
                    .await,
                )
            } else {
                // Registration aborted (read error or heartbeat watchdog):
                // no writer task or visitors were spawned; `None` means there
                // is no message-loop exit, and the session reconnects exactly
                // as a `Reconnect` exit does.
                None
            };

            // Phase 7: tear down the session exactly once, whether the
            // message loop exited or registration aborted. Returns true only
            // when a stop was requested during the session (shutdown_flag
            // set).
            let stop_requested = self
                .teardown_session(
                    &mut ctx,
                    #[cfg(feature = "tcp-mux")]
                    &mut prev_yamux,
                    &health_cancels,
                    &mut admin_handle,
                )
                .await;

            // Single exit-vs-reconnect decision point. A stop (admin API /
            // signal) always exits — the session must not reconnect. A dead
            // session or aborted registration reconnects with backoff unless
            // the teardown itself found a stop request.
            match exit {
                Some(LoopExit::Shutdown) => return Ok(()),
                Some(LoopExit::Reconnect) | None => {
                    if stop_requested {
                        return Ok(());
                    }
                }
            }

            // Session dropped — reconnect with Go frp dev two-phase fast-backoff.
            // login_fail_exit only applies to initial login, not session drops.
            // Reset the consecutive-error count when the previous session was
            // healthy for ≥5 minutes, so a stable connection followed by an
            // occasional blip reconnects from Phase 1 instead of the 20s cap.
            if healthy_resets_error_count(
                consecutive_err_count,
                Some(ctx.session_started_at),
                Instant::now(),
                Duration::from_secs(300),
            ) {
                consecutive_err_count = 0;
            }
            let delay = crate::backoff::reconnect_delay_after_session(
                &mut consecutive_err_count,
                &mut fast_retry_timestamps,
                previous_delay,
            );
            previous_delay = delay;
            warn!(delay_ms = %delay.as_millis(), attempt = %consecutive_err_count, "Session ended, reconnecting in {}ms (attempt {})...",
                delay.as_millis(), consecutive_err_count);
            // Race the backoff against a stop request: an admin/signal stop
            // must not be held up by up to 20s of reconnect sleep.
            tokio::select! {
                Some(()) = stop_rx.recv() => {
                    info!("Stop requested while waiting to reconnect, shutting down");
                    ctx.shutdown_flag.store(true, Ordering::SeqCst);
                    self.cancel_detached_tasks(&health_cancels, admin_handle).await;
                    return Ok(());
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Phases 1-3 of one connection attempt: snapshot the work-conn config
    /// fields from the current client config, dial + login a new control
    /// connection, wrap the stream in AES-128-CFB, and initialize the
    /// per-session state (yamux handle, heartbeat watchdog, auth scopes,
    /// shutdown flag) that registration and the message loop build on.
    ///
    /// Returns the per-session state on success; on failure returns the
    /// error so run() can apply backoff + reconnect exactly as before.
    /// Backoff counters (consecutive_err_count, fast_retry_timestamps,
    /// previous_run_id) stay in run() scope — `did_login_once` is passed in
    /// so it is set at login success (before the encryption wrap), matching
    /// the previous ordering where a wrap failure still saw did_login_once
    /// already true.
    async fn connect_and_login(
        &self,
        cfg_local: &ClientConfig,
        protocol: &TransportProtocol,
        pool_count: i32,
        previous_run_id: String,
        did_login_once: &mut bool,
    ) -> Result<SessionCtx, frp_core::Error> {
        // Owned copies of the snapshot fields the work-conn config needs.
        // `handle_req_work_conn` (which builds the same config) also runs from
        // the message loop, where the snapshot guard is no longer held, so the
        // fields are stored on SessionCtx instead of read from the guard.
        // Keeps the snapshot semantics (fields fixed at connection start)
        // without cloning the whole ClientConfig.
        let wc_server_addr = cfg_local.server_addr.clone();
        let wc_server_port = cfg_local.server_port;
        let wc_tls_enable = cfg_local.tls_enable;
        let wc_tls_server_name = cfg_local.tls_server_name.clone();
        let wc_tls_ca_file = opt_if_empty!(cfg_local.tls_ca_file);
        let wc_tls_cert_file = opt_if_empty!(cfg_local.tls_cert_file);
        let wc_tls_key_file = opt_if_empty!(cfg_local.tls_key_file);
        let wc_dns_server = opt_if_empty!(cfg_local.dns_server);
        // Upper bound (65507, max UDP payload) is enforced at config load
        // (frp-core config/client.rs — every load path, reload included);
        // `.max(0)` guards programmatically-built configs with a negative
        // value so the buffer size stays sane.
        let wc_udp_packet_size = cfg_local.udp_packet_size.max(0) as usize;
        let wc_disable_custom_tls_first_byte = cfg_local.disable_custom_tls_first_byte;
        let wc_keepalive_secs = cfg_local.dial_server_keepalive.max(0) as u64;
        let wc_bind_addr = opt_if_empty!(cfg_local.connect_server_local_ip);
        let wc_proxy_url = cfg_local.proxy_url.clone();
        let wc_dial_timeout_secs = cfg_local.dial_server_timeout.max(1) as u64;

        let mut ctl = ControlConnection::new(
            cfg_local.server_addr.clone(),
            cfg_local.server_port,
            self.auth_cfg.clone(),
            protocol.clone(),
            pool_count,
            cfg_local.user.clone(),
            cfg_local.client_id.clone(),
            cfg_local.tls_enable,
            cfg_local.tls_server_name.clone(),
            opt_if_empty!(cfg_local.tls_ca_file),
            cfg_local.tls_skip_verify,
            opt_if_empty!(cfg_local.tls_cert_file),
            opt_if_empty!(cfg_local.tls_key_file),
            opt_if_empty!(cfg_local.dns_server),
            cfg_local.tcp_mux,
            cfg_local.disable_custom_tls_first_byte,
            cfg_local.dial_server_keepalive.max(0) as u64,
            cfg_local.tcp_mux_keepalive_interval,
            cfg_local.tcp_mux_keepalive_timeout,
            opt_if_empty!(cfg_local.connect_server_local_ip),
            cfg_local.v2,
            cfg_local.tcp_send_buffer_size,
            cfg_local.tcp_recv_buffer_size,
            self.oidc_client.clone(),
            cfg_local.metas.clone(),
            cfg_local.proxy_url.clone(),
            previous_run_id.clone(),
            Some(ClientSpec {
                client_type: Some("frpc".into()),
                always_auth_pass: None,
            }),
            cfg_local.dial_server_timeout,
            #[cfg(feature = "quic")]
            frp_core::quic::quic_params_from_option_values(
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.keepalive_period)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_idle_timeout)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_incoming_streams)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.stream_receive_window)
                    .unwrap_or(0),
            ),
        );

        // Initialized to None: the post-login Ok arm overwrites it, and
        // the error path (below) diverges before it can be read.
        #[cfg(feature = "quic")]
        let mut quic_conn: Option<QuicConnection> = None;

        // Login and the post-login encryption wrap funnel into one Result:
        // `into_encrypted` can fail when the transport carries unconsumed
        // read-ahead bytes (remote-triggerable: a proxy injecting junk
        // after its CONNECT response), and that failure must take the
        // same retry/exit path as a login error — never panic (release
        // binaries build with panic=abort).
        let enc_result = match ctl.login().await {
            Ok(r) => {
                *did_login_once = true;
                *self.server_auth_scopes.write().await = ctl.server_auth_scopes.clone();
                // After login, wrap control stream in AES-128-CFB encryption.
                // Go frps v0.69.1 always encrypts the control connection for V1.
                #[cfg(feature = "quic")]
                let (stream, run_id, yamux, quic, udp_codec) = r;
                #[cfg(not(feature = "quic"))]
                let (stream, run_id, yamux, udp_codec) = r;
                let enc_key = encryption::derive_key(&self.auth_cfg.token);
                #[cfg(feature = "quic")]
                {
                    quic_conn = quic;
                }
                stream
                    .into_encrypted(enc_key)
                    .map(|stream| (stream, run_id, yamux, udp_codec))
                    .map_err(frp_core::Error::from)
            }
            Err(e) => Err(e),
        };
        let (control_stream, run_id, yamux_session, udp_codec) = match enc_result {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        let yamux = yamux_session.map(std::sync::Arc::new);
        #[cfg(feature = "quic")]
        let quic_conn = quic_conn.map(std::sync::Arc::new);
        let v2 = cfg_local.v2;
        info!(run_id = %run_id, "Logged in. run_id: {}", run_id);

        // --- Heartbeat state: single arm point ---
        // `last_pong` is initialized at login success so the heartbeat
        // watchdog bounds the REGISTRATION phase too: no Ping is sent
        // until the message loop starts, so a server that stays
        // connected but never answers NewProxy is detected within
        // heartbeat_timeout instead of hanging the client in
        // registration forever (Go frp's heartbeat timer also runs
        // continuously while proxies register in their own goroutines).
        // The message loop below reuses these same variables — this is
        // the only initialization point (the watchdog must not be
        // double-armed with a fresh timer after registration).
        let ping_interval = if cfg_local.heartbeat_interval > 0 {
            let secs = cfg_local.heartbeat_interval as u64;
            info!(interval = %secs, "Heartbeat interval: {}s", secs);
            Some(tokio::time::interval(Duration::from_secs(secs)))
        } else {
            info!("Heartbeat: explicitly disabled (heartbeat_interval <= 0)");
            None
        };
        let last_pong = Instant::now();
        let hb_timeout = cfg_local.heartbeat_timeout;
        let hb_timeout_dur = Duration::from_secs(hb_timeout.max(0) as u64);
        // The watchdog only makes sense while the ping loop is active:
        // with heartbeat_interval <= 0 the client never sends Pings, so
        // no Pong can ever arrive and an active watchdog would fire right
        // after login and reconnect forever (Go frp gates its heartbeat
        // on the interval too).
        let hb_watchdog_active = hb_timeout > 0 && ping_interval.is_some();

        let session_alive = Arc::new(AtomicBool::new(true));

        let client_scopes: Vec<String> = cfg_local
            .auth
            .as_ref()
            .map(|a| a.additional_auth_scopes.clone())
            .unwrap_or_default();
        let server_scopes = self.server_auth_scopes.read().await.clone();

        Ok(SessionCtx {
            control_stream: Some(control_stream),
            run_id,
            yamux,
            v2,
            #[cfg(feature = "quic")]
            quic_conn,
            ping_interval,
            ping_retry_backoff: None,
            last_pong,
            hb_timeout,
            hb_timeout_dur,
            hb_watchdog_active,
            session_alive,
            wc_server_addr,
            wc_server_port,
            wc_tls_enable,
            wc_tls_server_name,
            wc_tls_ca_file,
            wc_tls_cert_file,
            wc_tls_key_file,
            wc_dns_server,
            wc_udp_packet_size,
            wc_udp_packet_codec: udp_codec,
            wc_disable_custom_tls_first_byte,
            wc_keepalive_secs,
            wc_bind_addr,
            wc_proxy_url,
            wc_dial_timeout_secs,
            protocol: protocol.clone(),
            client_scopes,
            server_scopes,
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
            pending_xtcp: std::collections::HashMap::new(),
            xtcp_sockets: Default::default(),
            visitor_pending: std::collections::HashMap::new(),
            stun_result_tx: None,
            stun_result_rx: None,
            xtcp_cleanup_rx: None,
            proxy_retry_interval: None,
            waitstart_seen: HashMap::new(),
            cfg_user: String::new(),
        })
    }

    /// Phase 5 of one connection attempt: split the control stream into
    /// reader/writer halves, spawn the dedicated writer task (bounded
    /// channel — producers never block on a slow peer, the raw write half is
    /// owned by exactly one task, and a write failure wakes the control loop
    /// to tear down and reconnect), spawn VnetControllers for vnet proxies,
    /// cancel the previous session's visitor listener tasks, and spawn the
    /// current session's virtual_net / STCP / XTCP visitor listeners. Only
    /// called when the registration phase did not abort (the session
    /// continuation guard in run()).
    ///
    /// A split failure propagates to run() as a session error (matching the
    /// original `into_split()?` in run(), which returned from run() itself).
    async fn spawn_session_tasks(
        &self,
        ctx: &mut SessionCtx,
        cfg_local: &ClientConfig,
        #[cfg_attr(not(feature = "vnet"), allow(unused_variables))]
        proxies: &[frp_core::config::ProxyConfig],
        protocol: &TransportProtocol,
        nat_hole_stun_server: &str,
    ) -> std::io::Result<()> {
        // Split control stream for reading and writing.
        let (reader, raw_writer) = ctx
            .control_stream
            .take()
            .expect("control_stream available before split")
            .into_split()?;
        ctx.reader = Some(reader);

        {
            let failed = ctx
                .control_failed
                .as_ref()
                .expect("control_failed available before split")
                .clone();
            let notify = ctx
                .control_notify
                .as_ref()
                .expect("control_notify available before split")
                .clone();
            let control_rx = ctx
                .control_rx
                .take()
                .expect("control_rx available before split");
            // Keep the JoinHandle on SessionCtx so teardown can abort the
            // writer (F7): the raw write half lives only inside this task,
            // and against a wedged-but-alive peer a blocked write_msg would
            // otherwise keep the task + socket fd alive past session end.
            let writer_handle = tokio::spawn(async move {
                let mut rx = control_rx;
                let mut w = raw_writer;
                while let Some((msg, v2)) = rx.recv().await {
                    if let Err(e) = write_msg(&mut w, &msg, v2).await {
                        tracing::error!(error = %e, "Control writer failed: {}", e);
                        failed.store(true, std::sync::atomic::Ordering::SeqCst);
                        notify.notify_waiters();
                        break;
                    }
                }
            });
            ctx.control_writer_handle = Some(writer_handle);
        }

        // Spawn VnetControllers for all vnet proxies now that the
        // control connection writer is available.
        #[cfg(feature = "vnet")]
        for p in proxies {
            if vnet_tun_params(p, &cfg_local.virtual_net.address).is_none() {
                continue;
            }
            let writer = ctx
                .writer
                .as_ref()
                .expect("writer available before vnet controller spawn");
            if spawn_vnet_tun_controller(
                &self.vnet_tuns,
                &self.vnet_tun_tx,
                &self.vnet_tun_cancels,
                &self.vnet_controller,
                &p.name,
                &p.virtual_net,
                writer,
                ctx.v2,
            )
            .await
            .is_some()
            {
                send_vnet_route_advertise(writer, ctx.v2, p).await;
            }
        }

        // Cancel old visitor listener tasks from a previous session.
        // Signal gracefully and wait briefly for the previous session's
        // visitors to exit, instead of aborting them (Go frp compat:
        // visitor_manager.Close() closes each visitor cleanly). The
        // previous session's visitor_shutdown was already set when the
        // session ended; tasks should exit on their own. Any listener
        // still stuck in accept() after the grace period is force-aborted
        // so the bind port is released for the new session.
        self.shutdown_visitor_tasks(std::mem::take(&mut ctx.visitor_handles))
            .await;

        // Spawn STCP/XTCP visitor listeners
        let session_visitors = self.cfg.read().await.visitors.clone();
        for v in &session_visitors {
            if !v.enabled {
                continue;
            }
            if v.bind_port == 0 {
                continue;
            }
            // Virtual_net visitors do not bind a local listener; they
            // establish a persistent STCP/XTCP tunnel and register their
            // destinationIP host route with the client vnet controller.
            if v.plugin
                .as_ref()
                .is_some_and(|p| p.plugin_type == VISITOR_PLUGIN_VIRTUAL_NET)
            {
                #[cfg(feature = "vnet")]
                {
                    if let Some(adv) = virtual_net_visitor_route_adv(v) {
                        let sa = cfg_local.server_addr.clone();
                        let sp = cfg_local.server_port;
                        let pt = protocol.clone();
                        let server_name = v.server_name.clone();
                        let server_user = v.server_user.clone();
                        let secret_key = v.secret_key.clone();
                        let use_enc = v.use_encryption;
                        let use_comp = v.use_compression;
                        let name = v.name.clone();
                        let tls_enable = cfg_local.tls_enable;
                        let tls_server_name = cfg_local.tls_server_name.clone();
                        let tls_ca_file = opt_if_empty!(cfg_local.tls_ca_file);
                        let transport_proxy_url = opt_if_empty!(cfg_local.proxy_url.clone());
                        let transport_dns = opt_if_empty!(cfg_local.dns_server.clone());
                        let transport_bind =
                            opt_if_empty!(cfg_local.connect_server_local_ip.clone());
                        let transport_tls_cert = opt_if_empty!(cfg_local.tls_cert_file.clone());
                        let transport_tls_key = opt_if_empty!(cfg_local.tls_key_file.clone());
                        let transport_tcp_mux = cfg_local.tcp_mux;
                        let transport_tcp_mux_keepalive = cfg_local.tcp_mux_keepalive_interval;
                        let transport_tcp_mux_keepalive_timeout =
                            cfg_local.tcp_mux_keepalive_timeout;
                        let transport_dial_timeout = cfg_local.dial_server_timeout.max(1) as u64;
                        let transport_keepalive = cfg_local.dial_server_keepalive.max(0) as u64;
                        let transport_nocustomtls = cfg_local.disable_custom_tls_first_byte;
                        let user = cfg_local.user.clone();
                        let rid = ctx.run_id.clone();
                        let v2 = ctx.v2;
                        let controller = self.vnet_controller.clone();
                        let vnet_tun_tx = self.vnet_tun_tx.clone();
                        let tun_subnets = self.vnet_tun_subnets.clone();
                        let shutdown = ctx
                            .visitor_shutdown
                            .as_ref()
                            .expect("visitor_shutdown available before visitor spawn")
                            .clone();
                        let handle = tokio::spawn(async move {
                            crate::visitor::run_virtual_net_visitor(
                                crate::visitor::VirtualNetVisitorConfig {
                                    server_addr: sa,
                                    server_port: sp,
                                    protocol: pt,
                                    server_name,
                                    server_user,
                                    secret_key,
                                    use_encryption: use_enc,
                                    use_compression: use_comp,
                                    name,
                                    tls_enable,
                                    tls_server_name,
                                    tls_ca_file,
                                    user,
                                    run_id: rid,
                                    tcp_mux: transport_tcp_mux,
                                    tcp_mux_keepalive_interval: transport_tcp_mux_keepalive,
                                    tcp_mux_keepalive_timeout: transport_tcp_mux_keepalive_timeout,
                                    proxy_url: transport_proxy_url.clone(),
                                    dns_server: transport_dns.clone(),
                                    dial_timeout_secs: transport_dial_timeout,
                                    keepalive_secs: transport_keepalive,
                                    connect_bind_addr: transport_bind.clone(),
                                    disable_custom_tls_first_byte: transport_nocustomtls,
                                    tls_cert_file: transport_tls_cert.clone(),
                                    tls_key_file: transport_tls_key.clone(),
                                    v2,
                                    destination_cidr: adv.subnet,
                                    controller,
                                    vnet_tun_tx,
                                    tun_subnets,
                                    shutdown,
                                },
                            )
                            .await;
                        });
                        ctx.visitor_handles.push(handle);
                    }
                }
                continue;
            }
            let sa = cfg_local.server_addr.clone();
            let sp = cfg_local.server_port;
            let pt = protocol.clone();
            let server_name = v.server_name.clone();
            let server_user = v.server_user.clone();
            let secret_key = v.secret_key.clone();
            let bind_addr = format!("{}:{}", v.bind_addr, v.bind_port);
            let use_enc = v.use_encryption;
            let use_comp = v.use_compression;
            let name = v.name.clone();
            let tls_enable = cfg_local.tls_enable;
            let tls_server_name = cfg_local.tls_server_name.clone();
            let tls_ca_file = opt_if_empty!(cfg_local.tls_ca_file);
            let transport_proxy_url = opt_if_empty!(cfg_local.proxy_url.clone());
            let transport_dns = opt_if_empty!(cfg_local.dns_server.clone());
            let transport_bind = opt_if_empty!(cfg_local.connect_server_local_ip.clone());
            let transport_tls_cert = opt_if_empty!(cfg_local.tls_cert_file.clone());
            let transport_tls_key = opt_if_empty!(cfg_local.tls_key_file.clone());
            let transport_tcp_mux = cfg_local.tcp_mux;
            let transport_tcp_mux_keepalive = cfg_local.tcp_mux_keepalive_interval;
            let transport_tcp_mux_keepalive_timeout = cfg_local.tcp_mux_keepalive_timeout;
            let transport_dial_timeout = cfg_local.dial_server_timeout.max(1) as u64;
            let transport_keepalive = cfg_local.dial_server_keepalive.max(0) as u64;
            let transport_nocustomtls = cfg_local.disable_custom_tls_first_byte;
            let visitor_type = v.visitor_type.clone();
            let fallback_timeout_ms = v.fallback_timeout_ms;
            let keep_tunnel_open = v.keep_tunnel_open;
            let max_retries_an_hour = v.max_retries_an_hour;
            let min_retry_interval = v.min_retry_interval;
            // nat_hole_stun_server is a &str param here (was a String local in
            // run()); to_string() keeps the String-typed visitor field unchanged.
            let stun_server = nat_hole_stun_server.to_string();
            let fallback_to = v.fallback_to.clone();
            let disable_assisted_addrs = v.disable_assisted_addrs;
            let p2p_protocol = v.protocol.clone();
            let user = cfg_local.user.clone();
            let rid = ctx.run_id.clone();
            let v2 = ctx.v2;
            let vtx = self.visitor_tx.clone();
            let shutdown = ctx
                .visitor_shutdown
                .as_ref()
                .expect("visitor_shutdown available before visitor spawn")
                .clone();
            // Clone the negotiated UDPPacket codec before `ctx` moves into
            // the spawn (Go frp v0.71.0 sessionCtx.UDPPacketCodec).
            let ctx_udp_packet_codec = ctx.wc_udp_packet_codec.clone();
            // Client QUIC transport params for the XTCP tunnel session (Go
            // `clientCfg.Transport.QUIC`).
            //
            // `kcp` as well as `quic`: this value flows into
            // `VisitorListenerConfig::quic_params` → `XtcpPunchConfig` →
            // `do_hole_punch`'s QUIC session call, and frp-core re-exports
            // `QuicTunnelSession` only under `all(feature = "kcp", feature =
            // "quic")`. See the field gate in `frp-client/src/visitor.rs`.
            #[cfg(all(feature = "quic", feature = "kcp"))]
            let visitor_quic_params = frp_core::quic::quic_params_from_option_values(
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.keepalive_period)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_idle_timeout)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_incoming_streams)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.stream_receive_window)
                    .unwrap_or(0),
            );
            let handle = tokio::spawn(async move {
                crate::visitor::run_visitor_listener(crate::visitor::VisitorListenerConfig {
                    server_addr: sa,
                    server_port: sp,
                    protocol: pt,
                    server_name,
                    server_user,
                    secret_key,
                    bind_addr,
                    use_encryption: use_enc,
                    use_compression: use_comp,
                    name,
                    tls_enable,
                    tls_server_name,
                    tls_ca_file,
                    visitor_type,
                    fallback_timeout_ms,
                    keep_tunnel_open,
                    max_retries_an_hour,
                    min_retry_interval,
                    stun_server,
                    p2p_protocol,
                    visitor_tx: vtx,
                    fallback_to,
                    disable_assisted_addrs,
                    shutdown,
                    user,
                    run_id: rid,
                    tcp_mux: transport_tcp_mux,
                    tcp_mux_keepalive_interval: transport_tcp_mux_keepalive,
                    tcp_mux_keepalive_timeout: transport_tcp_mux_keepalive_timeout,
                    proxy_url: transport_proxy_url.clone(),
                    dns_server: transport_dns.clone(),
                    dial_timeout_secs: transport_dial_timeout,
                    keepalive_secs: transport_keepalive,
                    connect_bind_addr: transport_bind.clone(),
                    disable_custom_tls_first_byte: transport_nocustomtls,
                    tls_cert_file: transport_tls_cert.clone(),
                    tls_key_file: transport_tls_key.clone(),
                    v2,
                    // Negotiated UDPPacket codec (Go frp v0.71.0): the SUDP
                    // visitor data plane must match the provider segment's
                    // packet codec so the server keeps the zero-copy
                    // byte-stream bridge; mismatches fall back to the
                    // message-level transcoding bridge.
                    udp_packet_codec: ctx_udp_packet_codec.clone(),
                    #[cfg(all(feature = "quic", feature = "kcp"))]
                    quic_params: visitor_quic_params,
                })
                .await;
            });
            ctx.visitor_handles.push(handle);
        }

        Ok(())
    }

    /// Phase 7 of one connection attempt: tear down the session — remove
    /// vnet routes advertised by virtual_net visitors, signal the work-conn
    /// pool and visitor listeners to stop, drop the yamux handle, and wait
    /// briefly for visitor tasks to exit. Returns true when a stop was
    /// requested during the session (shutdown_flag set); run() then exits
    /// instead of reconnecting.
    pub(super) async fn teardown_session(
        &self,
        ctx: &mut SessionCtx,
        #[cfg(feature = "tcp-mux")] prev_yamux: &mut Option<
            std::sync::Arc<frp_core::mux::YamuxSession>,
        >,
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
        admin_handle: &mut Option<tokio::task::JoinHandle<()>>,
    ) -> bool {
        // Clean up vnet routes advertised by virtual_net visitors before
        // dropping the control connection. The server also removes routes
        // during control teardown; this mirrors Go frp's explicit
        // VnetRouteRemove from the visitor plugin Close().
        #[cfg(feature = "vnet")]
        {
            let writer = ctx
                .writer
                .as_ref()
                .expect("writer available before teardown")
                .clone();
            // Remove OS routes learned from peers and clear their route
            // table entries so a reconnect starts from a clean slate.
            {
                let peer_routes = self.vnet_peer_routes.lock().await;
                for (proxy_name, (subnet, tun_name, vnet)) in peer_routes.iter() {
                    remove_os_route(subnet, tun_name);
                    self.vnet_controller
                        .route_table()
                        .write()
                        .await
                        .remove(vnet, proxy_name);
                }
            }
            self.vnet_peer_routes.lock().await.clear();

            let session_visitors = self.cfg.read().await.visitors.clone();
            // The VnetRouteRemove below rides the control writer channel.
            // That channel is only consumed by the dedicated writer task,
            // which is spawned with the message loop (`control_rx.take()`).
            // On the registration-abort teardown path no writer task exists,
            // so a send would enqueue into a never-consumed channel and the
            // `info!` success log would be misleading — skip it (the local
            // route removal above already ran, and the server also removes
            // routes during control teardown).
            let writer_task_active = ctx.control_rx.is_none();
            for v in &session_visitors {
                if v.plugin.as_ref().is_none() || !v.enabled {
                    continue;
                }
                if let Some(adv) = virtual_net_visitor_route_adv(v) {
                    self.vnet_controller.unregister_visitor_route(&v.name).await;
                    if !writer_task_active {
                        debug!(visitor_name = %v.name, "vnet route removal skipped (no control writer task on registration-abort teardown)");
                        continue;
                    }
                    let rem = msg::VnetRouteRemove {
                        proxy_name: adv.proxy_name,
                        virtual_net: adv.virtual_net,
                    };
                    let msg = FrpMessage::VnetRouteRemove(rem);
                    if let Err(e) = writer.send(msg, ctx.v2) {
                        warn!(visitor_name = %v.name, error = %e, "failed to remove vnet route for visitor '{}'", v.name);
                    } else {
                        info!(visitor_name = %v.name, "vnet route removed for visitor '{}'", v.name);
                    }
                }
            }
        }

        // Go frp GracefulClose ordering: close proxies first, then visitors,
        // then the control connection. See /tmp/frp-source/client/control.go:203-210.
        // Step 1: Signal work connection pool to stop replenishment cascade.
        ctx.session_alive.store(false, Ordering::Release);

        // Step 2: Abort this session's work-conn tasks. Standalone work
        // conns (tcp/ws/kcp/quic-direct dial, tcp_mux off) own their own
        // connection to the server and would otherwise keep bridging until
        // a socket error — the orphaned-connection leak Go frp avoids by
        // closing work conns on control close (workConnManager.Close); on
        // reconnect each one lived until the peer timed it out. Under
        // tcp-mux the tasks are yamux streams on the session dropped in
        // step 4, but aborting them is also correct: it is an ordinary
        // stream close, and it releases the YamuxSession Arc clones that
        // would otherwise keep the yamux driver alive past teardown. Abort
        // is immediate; await so the sockets are closed before the next
        // session's dials.
        let mut work_conn_handles = std::mem::take(&mut ctx.work_conn_handles);
        if !work_conn_handles.is_empty() {
            debug!(
                count = work_conn_handles.len(),
                "Aborting work-conn tasks at session teardown"
            );
            for h in &work_conn_handles {
                h.abort();
            }
            // Abort only lands at the task's next await point; bound the
            // join so teardown can never hang on a stuck task (same
            // pattern as shutdown_visitor_tasks). On timeout, report the
            // stragglers and continue — the aborted tasks finish on their
            // own.
            let joined = tokio::time::timeout(
                Duration::from_secs(5),
                futures_util::future::join_all(work_conn_handles.iter_mut()),
            )
            .await;
            if joined.is_err() {
                let unfinished = work_conn_handles
                    .iter()
                    .filter(|h| !h.is_finished())
                    .count();
                warn!(
                    count = unfinished,
                    "Work-conn teardown timed out after 5s; continuing without waiting for unfinished task(s)"
                );
            }
        }

        // Step 3: Signal visitor listeners to stop accepting new connections
        // (Go frp compat: vm.Close() closes all visitors before session is torn down).
        ctx.visitor_shutdown
            .as_ref()
            .expect("visitor_shutdown available before teardown")
            .store(true, Ordering::Release);

        // Step 4: Drop the control connection (Go frp compat: closeSession()).
        // Dropping prev_yamux closes the underlying TCP socket so the background
        // yamux task exits before we attempt to reconnect. This prevents
        // dual-yamux-session leaks through a half-open TCP mux connection.
        #[cfg(feature = "tcp-mux")]
        drop(prev_yamux.take());

        // Step 5: Abort the control writer task. This must come after the
        // vnet route-removal sends above (they ride the writer channel, so
        // the writer must still be alive to drain them) and after dropping
        // the yamux session. On the tcp-mux path dropping prev_yamux already
        // closed the socket, so the writer exits on its own and this abort is
        // a no-op or immediate. On tcp_mux=false the raw write half lives
        // only inside the writer task: against a wedged-but-alive peer
        // (zero-window TCP that ACKs keepalive/window probes, or no-mux KCP
        // with no dead-conn detection) write_msg would block forever and
        // nothing else can close the socket — aborting the task drops the
        // write half (and the fd) instead of leaking one task+fd per
        // reconnect cycle.
        let control_writer_handle = std::mem::take(&mut ctx.control_writer_handle);
        if let Some(handle) = control_writer_handle {
            handle.abort();
            // Abort only lands at the task's next await point; bound the
            // join so teardown can never hang on a stuck writer (same
            // pattern as the work-conn abort above). On timeout the aborted
            // task finishes on its own — the write half it owns is dropped
            // the moment the abort takes effect.
            let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
            if joined.is_err() {
                warn!("Control writer teardown timed out after 5s; continuing without waiting for the writer task");
            }
        }

        // Wait briefly for visitor tasks to notice the shutdown signal and
        // exit gracefully (timeout so we never block reconnection).
        // Any listener still blocked in accept() after the grace period is
        // force-aborted so the bind port is released for the next session.
        self.shutdown_visitor_tasks(std::mem::take(&mut ctx.visitor_handles))
            .await;

        // Check if admin stop was requested
        if ctx.shutdown_flag.load(Ordering::SeqCst) {
            info!("frpc shutting down");
            // Cancel health check tasks and abort the admin HTTP server
            // before returning. Both are detached tokio tasks; without
            // this they keep running after run() exits (holding bind
            // ports and channels until process exit).
            self.cancel_detached_tasks(health_cancels, admin_handle.take())
                .await;
            return true;
        }
        false
    }

    /// Cancel health check tasks and abort the admin HTTP server before
    /// run() returns. Both are detached tokio tasks; without this they keep
    /// running after run() exits (holding bind ports and channels until
    /// process exit).
    async fn cancel_detached_tasks(
        &self,
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
        admin_handle: Option<tokio::task::JoinHandle<()>>,
    ) {
        {
            let mut cancels = health_cancels.lock().await;
            for cancel in cancels.values() {
                cancel.store(true, Ordering::Relaxed);
            }
            cancels.clear();
        }
        #[cfg(feature = "admin")]
        if let Some(admin) = admin_handle {
            admin.abort();
        }
        // Non-admin builds never read the handle; keep the parameter used so
        // the no-admin compile stays warning-free.
        #[cfg(not(feature = "admin"))]
        let _ = admin_handle;
    }

    /// Start the admin HTTP server if configured.
    /// Spawns as a background task; returns its JoinHandle (None when the
    /// admin server is not configured).
    #[cfg(feature = "admin")]
    async fn spawn_admin_server(
        &self,
        reload_tx: &mpsc::Sender<ReloadRequest>,
        stop_tx: &mpsc::Sender<()>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let cfg_snapshot = self.cfg.read().await.clone();
        if cfg_snapshot.web_server.port > 0 {
            let admin_addr = frp_core::format_socket_addr(
                &cfg_snapshot.web_server.addr,
                cfg_snapshot.web_server.port,
            );
            // Seed the admin config GET's dedup cell with the answer the startup
            // load just reported, so a GET does not repeat that record — and, the
            // reason it is seeded rather than left at `NO_BASELINE`, so a
            // hand-edit that *adds* `[web_server.tls] enable` **after the admin
            // server has started** is still reported (the seed recorded
            // "absent"). An edit landing between the startup load and this spawn
            // is baselined instead, because the seed reads the file only here.
            // Best-effort: an unreadable file leaves `NO_BASELINE`, and the first
            // GET then baselines silently. See
            // `crate::admin::seed_web_server_tls_enable_seen`.
            let seeded = crate::admin::seed_web_server_tls_enable_seen(self.config_file.as_deref());
            let admin_state = AdminState {
                proxy_metrics: self.proxy_metrics.clone(),
                proxies: self.proxy_info_map.clone(),
                reload_tx: reload_tx.clone(),
                stop_tx: stop_tx.clone(),
                config_path: self.config_file.clone(),
                store: self.store_source.clone(),
                web_server_tls_enable_seen: Arc::new(std::sync::atomic::AtomicU8::new(seeded)),
            };
            let admin_auth_user = cfg_snapshot.web_server.user.clone();
            let admin_auth_pwd = cfg_snapshot.web_server.password.clone();
            let admin_tls_cert = if cfg_snapshot.web_server.tls_cert().is_empty() {
                None
            } else {
                Some(cfg_snapshot.web_server.tls_cert().to_string())
            };
            let admin_tls_key = if cfg_snapshot.web_server.tls_key().is_empty() {
                None
            } else {
                Some(cfg_snapshot.web_server.tls_key().to_string())
            };
            let handle = tokio::spawn(async move {
                if let Err(e) = crate::admin::run_admin_server(
                    admin_addr,
                    admin_state,
                    admin_auth_user,
                    admin_auth_pwd,
                    admin_tls_cert,
                    admin_tls_key,
                )
                .await
                {
                    tracing::error!(error = %e, "frpc admin server failed: {}", e);
                }
            });
            info!(addr = %cfg_snapshot.web_server.addr, port = %cfg_snapshot.web_server.port, "frpc admin server starting on {}:{}", cfg_snapshot.web_server.addr, cfg_snapshot.web_server.port);
            Some(handle)
        } else {
            None
        }
    }
}
