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

use std::time::Duration;

use tracing::info;

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
}
