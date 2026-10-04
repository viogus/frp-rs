//! Background tasks spawned by [`Service::run`](super::Service::run).
//!
//! The NAT-hole session cleanup task moved here from `service.rs`: its two
//! `tracing` events therefore report target `frp_server::service::tasks`
//! instead of `frp_server::service`; `RUST_LOG` target matching is a prefix
//! comparison, so a directive such as `RUST_LOG=frp_server::service=debug`
//! still enables them. This block is un-gated in `run` (`self.state.xtcp` and
//! `crate::nathole` exist in every shape), so the module is un-gated too and
//! any later task that is feature-gated carries its own `#[cfg]` on its item.
//!
//! The port-reservation pruner and the signal listener moved here the same way
//! and report the same target. Both are un-gated; the signal listener's own
//! `#[cfg(unix)]`/`#[cfg(not(unix))]` arms move with it, so the module stays
//! unconditional.
//!
//! The TLS certificate hot-reload task and the stale-control reaper moved here
//! the same way and report the same target. The TLS task is the first
//! feature-gated item in this module: its method carries
//! `#[cfg(feature = "tls")]` itself (the convention the SSH listener in
//! `listeners.rs` established) and the call site keeps the same attribute, so
//! the module and the other four tasks stay unconditional. The reaper is
//! un-gated — it reads only unconditional `AppState` fields.

use std::time::Duration;

use tracing::info;

#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor_or_generate;

#[cfg(feature = "tls")]
use crate::lock::RwLockExt;

use super::Service;

impl Service {
    /// Spawn the 60-second NAT-hole session cleanup task.
    pub(super) fn spawn_nat_hole_cleanup_task(&self) {
        let nat_hole = self.state.xtcp.nat_hole.clone();
        let nat_shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        nat_hole.expire_sessions(Duration::from_secs(120)).await;
                        // Clean expired analyzer entries to prevent unbounded memory growth.
                        let (removed, total) = nat_hole.analyzer.clean();
                        if removed > 0 {
                            tracing::debug!(removed = %removed, total = %total, "Analyzer cleanup: removed {}/{} expired entries", removed, total);
                        }
                    }
                    _ = nat_shutdown_token.cancelled() => {
                        tracing::debug!("NAT cleanup task: shutdown requested, stopping");
                        break;
                    }
                }
            }
        });
    }

    /// Spawn the 60-second port-reservation pruner task.
    pub(super) fn spawn_port_reservation_pruner_task(&self) {
        self.state
            .clone()
            .spawn_port_reservation_pruner(self.state.shutdown_token.clone());
    }

    /// Spawn the 60-second TLS certificate hot-reload task.
    #[cfg(feature = "tls")]
    pub(super) fn spawn_tls_cert_reload_task(&self) {
        let poll_state = self.state.clone();
        let cert_file = self.cfg.tls_cert_file.clone();
        let key_file = self.cfg.tls_key_file.clone();
        let ca_file = if self.cfg.tls_ca_file.is_empty() {
            None
        } else {
            Some(self.cfg.tls_ca_file.clone())
        };
        tokio::spawn(async move {
            let mut last_cert_mtime: Option<std::time::SystemTime> = None;
            let mut last_key_mtime: Option<std::time::SystemTime> = None;
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            // Skip the first tick (fires immediately).
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Stat cert and key files. If either mtime changed, rebuild.
                        let cert_meta = match std::fs::metadata(&cert_file) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let key_meta = match std::fs::metadata(&key_file) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let cert_mtime = cert_meta.modified().ok();
                        let key_mtime = key_meta.modified().ok();
                        let cert_changed = cert_mtime != last_cert_mtime;
                        let key_changed = key_mtime != last_key_mtime;
                        if cert_changed || key_changed {
                            last_cert_mtime = cert_mtime;
                            last_key_mtime = key_mtime;
                            let ca = ca_file.as_deref();
                            match build_tls_acceptor_or_generate(&cert_file, &key_file, ca) {
                                Ok(new_acceptor) => {
                                    let mut guard = poll_state.tls_acceptor.write_ok();
                                    *guard = Some(new_acceptor);
                                    tracing::info!(
                                        "TLS certificate hot-reloaded (cert: {}, key: {})",
                                        cert_file,
                                        key_file
                                    );
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to reload TLS certificate: {} (keeping old config)",
                                        e
                                    );
                                }
                            }
                        }
                    }
                    _ = poll_state.shutdown_token.cancelled() => {
                        tracing::debug!("TLS hot-reload task: shutdown requested, stopping");
                        break;
                    }
                }
            }
        });
    }

    /// Spawn the signal listener for graceful shutdown (SIGINT, and SIGTERM on unix).
    pub(super) fn spawn_signal_listener_task(&self) {
        let shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                // SIGTERM → graceful shutdown (docker stop / systemctl stop
                // send SIGTERM; ctrl_c() alone only catches SIGINT).
                let mut term_sig =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => Some(s),
                        Err(e) => {
                            tracing::warn!(error = %e, "SIGTERM handler unavailable: {}", e);
                            None
                        }
                    };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received SIGINT, initiating graceful shutdown...");
                    }
                    _ = async {
                        if let Some(sig) = term_sig.as_mut() {
                            sig.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("Received SIGTERM, initiating graceful shutdown...");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                info!("Received SIGINT, initiating graceful shutdown...");
            }
            shutdown_token.cancel();
        });
    }
    /// Spawn the 60-second stale-control reaper task.
    pub(super) fn spawn_stale_control_reaper_task(&self) {
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                // Stop promptly on graceful shutdown (port-reservation pruner
                // pattern): the drain path cancels control handlers whose
                // cleanup() already runs unregister_control, so a final sweep
                // here would be both unnecessary and a teardown-linger.
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = state.shutdown_token.cancelled() => return,
                }
                let stale: Vec<(String, u64)> = state
                    .run_id_to_ctl_tx
                    .iter()
                    .filter(|r| r.tx.is_closed())
                    .map(|r| (r.key().clone(), r.control_id))
                    .collect();
                for (run_id, control_id) in stale {
                    // Atomically remove only if the entry still belongs to the
                    // same generation: remove_if compares inside the shard
                    // lock, so a superseding control that registered a fresh
                    // sender for this run_id is never removed by this sweep
                    // (a get-then-remove would race with re-login).
                    let removed = state
                        .run_id_to_ctl_tx
                        .remove_if(&run_id, |_, cur| cur.control_id == control_id);
                    if removed.is_some() {
                        state
                            .client_registry
                            .mark_offline_by_run_id_and_control_id(&run_id, control_id);
                        // The handler exited WITHOUT running cleanup()
                        // (panic/abort), so its registrations would otherwise
                        // leak permanently: used_ports/used_udp_ports,
                        // sk_index, vhost/tcpmux routes, TCP-group listeners,
                        // per-client port counts, OIDC subjects, metrics, and
                        // the proxy registry entries. Run the full
                        // unregister_control sweep. Double-call safety: when
                        // cleanup() DID run it removes the map entry first, so
                        // remove_if above returned None and this code never
                        // runs; unregister_control is also generation-guarded
                        // (control_id) with per-proxy ownership re-checks, so
                        // it can never tear down a superseding control's fresh
                        // registrations (control_id >= 1 always, the counter
                        // starts at 1).
                        crate::control::proxy_ops::unregister_control(
                            &state, &run_id, control_id, false, true,
                        )
                        .await;
                        // Remove the proxy registry entries (mirroring
                        // control::cleanup): unregister_control deliberately
                        // leaves proxy_manager.remove() to the caller because
                        // the https SNI-sniff gate count must only be
                        // decremented when an entry was actually removed
                        // (proxy_ops.rs note). Atomic generation-guarded
                        // removal: remove_if_control_id compares control_id
                        // inside the shard lock, so a superseding control
                        // that re-registered this name between the sweep
                        // list and the removal keeps its entry (round-7
                        // audit MEDIUM — the previous get-then-remove raced
                        // re-login and could destroy the fresh registration).
                        // The removed entry's own type drives the https
                        // gate-count decrement, so no separate get is needed.
                        let proxy_names =
                            state.proxy_manager.list_client_proxy_names(&run_id).await;
                        for name in proxy_names {
                            if let Some(removed) = state
                                .proxy_manager
                                .remove_if_control_id(&name, control_id)
                                .await
                            {
                                if removed.proxy_type == "https" {
                                    state.dec_https_proxy_count();
                                }
                            }
                        }
                        // OIDC subject mapping for this run_id: unregister_
                        // control only clears it when IT removed the
                        // run_id_to_ctl_tx entry (removed_control_id), but
                        // this sweep's remove_if deleted that entry first, so
                        // the (subject, generation) entry would leak forever
                        // for an OIDC client that never reconnects. Clear it
                        // directly — generation-guarded inside the lock, so a
                        // newer control's subject entry survives (round-7
                        // audit LOW).
                        crate::control::login::remove_oidc_subject_generation(
                            &state, &run_id, control_id,
                        )
                        .await;
                        // Plugin user-info entry for this run_id: same leak
                        // shape as the OIDC subject above. unregister_control
                        // only drops it when IT removed the run_id_to_ctl_tx
                        // entry (removed_control_id), but this sweep's
                        // remove_if deleted that entry first, so the
                        // generation guard fails there and remove_user is
                        // skipped — the plugin `users` map (http.rs:110-114,
                        // "bounded by live controls") would otherwise grow by
                        // one entry per control that exited without a clean
                        // unregister: exactly the path this reaper exists
                        // for.
                        //
                        // Same-run_id reconnect guard: a control that died
                        // uncleanly and reconnected with the SAME run_id (frpc
                        // reuses its run_id) between the sweep's remove_if and
                        // here may be mid-login. login.rs records the plugin
                        // user entry AFTER its run_id_to_ctl_tx insert (same
                        // run_mu critical section — audit-fix ordering), so a
                        // fresh record only exists once a fresh generation is
                        // registered. remove_user is now generation-exact —
                        // the users map stores (control_id, UserInfo) and the
                        // entry is removed only when it still holds THIS
                        // sweep's control_id (remove-if-match under the users
                        // map's write lock) — so even an unconditional call
                        // here could no longer delete the record of a control
                        // that re-logged in with a fresh control_id (the old
                        // comment's "re-recorded on the next login hook"
                        // claim was wrong: that login already ran).
                        //
                        // Round-4 audit finding: the re-check and remove_user
                        // used to be two separate steps, so a same-run_id
                        // re-login's insert+record (login.rs, under its own
                        // run_mu — which the reaper did not hold) could land
                        // between them and delete the fresh record. The
                        // generation-exact remove_user closes that window
                        // structurally. Hold the per-run_id run_mu across
                        // both steps anyway, mirroring the login path's
                        // acquisition and lock order (run_mu →
                        // run_id_to_ctl_tx → users RwLock; the reaper
                        // otherwise takes no run_mu and no path takes the
                        // users lock then run_mu, so no inversion) — defense
                        // in depth, not the sole guard: a re-login either
                        // completed before us (its fresh generation is
                        // visible in the re-check below → skip) or is queued
                        // on run_mu until this removal is done (its record is
                        // not yet made → remove_user cannot delete it). With
                        // run_mu held, re-check run_id_to_ctl_tx: a NEWER
                        // control_id → the fresh control re-logged in and its
                        // record is in place → skip; no entry (or still the
                        // swept generation) → remove_user (leak fix stands;
                        // the generation-exact entry check makes even a
                        // racing re-login's fresh record immune).
                        let (run_mu, _run_mu_guard) = state.get_run_mu(&run_id);
                        let reaper_run_guard = run_mu.lock().await;
                        let fresh_generation_present = state
                            .run_id_to_ctl_tx
                            .get(&run_id)
                            .is_some_and(|cur| cur.control_id != control_id);
                        if !fresh_generation_present {
                            state.plugin_manager.remove_user(&run_id, control_id);
                        }
                        drop(reaper_run_guard);
                        tracing::info!(
                            run_id = %run_id,
                            "removed stale control entry (handler died)"
                        );
                    }
                }
            }
        });
    }
}
