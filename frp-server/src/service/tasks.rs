//! Background tasks spawned by [`Service::run`](super::Service::run).
//!
//! The NAT-hole session cleanup task moved here from `service.rs`: its two
//! `tracing` events therefore report target `frp_server::service::tasks`
//! instead of `frp_server::service`; `RUST_LOG` target matching is a prefix
//! comparison, so a directive such as `RUST_LOG=frp_server::service=debug`
//! still enables them. This block is un-gated in `run` (`self.state.xtcp` and
//! `crate::nathole` exist in every shape), so the module is un-gated too and
//! any later task that is feature-gated carries its own `#[cfg]` on its item.

use std::time::Duration;

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
}
