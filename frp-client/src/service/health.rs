//! Health-check plumbing: `spawn_health_checks` (the per-proxy probe tasks),
//! the `health_check_monitored` registration-parity gate that decides which
//! proxies are monitored at all, and `healthy_resets_error_count` (the
//! reconnect-backoff reset decision).
//!
//! Split out of `frp-client/src/service.rs` by the P2 S5 seam as a pure move:
//! every moved line is byte-identical to the base except for three
//! `pub(super)` tokens. `spawn_health_checks` is called from `run()` (now in
//! `frp-client/src/service/session.rs`) and from the sibling
//! `frp-client/src/service/reload_apply.rs`; `health_check_monitored` is
//! called from the parent (`Service::with_unsafe_features`, which stays in
//! `frp-client/src/service.rs`) and from the siblings
//! `frp-client/src/service/registration.rs` and
//! `frp-client/src/service/reload_apply.rs`; `healthy_resets_error_count` is
//! called from `run()` and from `frp-client/src/service/tests.rs`. All three
//! therefore need `pub(super)`, and the parent re-exports the two free
//! functions with a private `use`, which preserves exactly the reach they had
//! as private items of `service` (unqualified spellings in the sibling and
//! test modules keep resolving through their existing `use super::*;`). This
//! module is a *child* of `service`, which is what lets the `impl Service`
//! block below reach the parent's private fields and methods; it is deployed
//! as a child module rather than a flat sibling for exactly that reason (see
//! the P2 layout note in `docs/refactor-large-modules.md`).

use super::*;

/// Go frp v0.71.0 parity gate for health monitoring.
///
/// Go `client/proxy/proxy_wrapper.go` NewWrapper arms the health monitor —
/// and sets `health = 1` so registration waits for the first healthy probe —
/// only when `HealthCheck.Type != "" && LocalPort > 0`. Plugin proxies carry
/// `local_port == 0` (their real listener is the plugin socket on
/// 127.0.0.1), so a health config on them is inert: the proxy is never
/// monitored, registers immediately like a non-health proxy, and no probe
/// is ever aimed at a plugin listener that does not speak the probe
/// protocol (a plain-HTTP GET against a socks5 listener, for instance,
/// could never succeed — wedging the proxy unregistered forever).
pub(super) fn health_check_monitored(p: &frp_core::config::ProxyConfig) -> bool {
    !p.health_check_type.is_empty() && p.local_port > 0
}

impl Service {
    /// Spawn per-proxy health check tasks (once, outside reconnect loop).
    /// Reads local address from proxy_info_map to determine what to check.
    /// `user` is explicit: during a reload the caller passes the NEW user
    /// (self.cfg is only refreshed at the end of try_reload), so the tasks
    /// and their health_cancels/health_proxy_configs keys match the wire
    /// names the reload registers.
    pub(super) async fn spawn_health_checks(
        &self,
        user: &str,
        proxies: &[frp_core::config::ProxyConfig],
        health_tx: &mpsc::Sender<HealthEvent>,
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
        session_gen: &Arc<AtomicU64>,
    ) {
        for p in proxies {
            let wn = wire_proxy_name(user, &p.name);
            // Go parity gate (health_check_monitored): monitor only when a
            // health type is configured AND local_port > 0. A plugin proxy
            // (local_port == 0) with a health config is never monitored —
            // its "listener" is the plugin socket, which never answers the
            // probe protocol.
            if !health_check_monitored(p) {
                continue;
            }
            let hc_type = p.health_check_type.clone();
            if hc_type != "tcp" && hc_type != "http" {
                warn!(health_check_type = %hc_type, proxy_name = %p.name, "Health check type '{}' not yet supported for '{}'", hc_type, p.name);
                continue;
            }
            let la = self
                .proxy_info_map
                .read()
                .await
                .get(&wn)
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let pn = wn.clone();
            // Round 10 (MEDIUM, Go parity): Go only substitutes defaults when
            // the configured value is <= 0 (health.go:57-64; the fields are
            // u64 here, so a negative config fails deserialization up front).
            // `.max(N)` silently rewrote an explicit 1-9s value, so an
            // operator asking for fast 2s checks got 10s instead.
            let interval =
                std::time::Duration::from_secs(if p.health_check_interval_seconds == 0 {
                    10
                } else {
                    p.health_check_interval_seconds
                });
            let timeout = std::time::Duration::from_secs(if p.health_check_timeout_seconds == 0 {
                3
            } else {
                p.health_check_timeout_seconds
            });
            let max_failed = if p.health_check_max_failed == 0 {
                1
            } else {
                p.health_check_max_failed
            };
            let tx = health_tx.clone();
            let hc_url = if hc_type == "http" {
                let url = p.health_check_url.clone();
                if !url.contains("://") {
                    // Go frp compat: auto-construct URL as
                    // "http://{local_ip}:{local_port}/{path}" (Go
                    // proxy_wrapper.go:125 JoinHostPort + health.go:68-76).
                    // An empty path config means "/" (Go health.go:68-76
                    // checks the bare address) — and build_health_check_url
                    // brackets literal IPv6, where the old split(':') here
                    // mangled unbracketed "::1:8080" into "http://:/path".
                    crate::health::build_health_check_url(&la, &url)
                } else {
                    url
                }
            } else {
                String::new()
            };
            let hc_headers = p.health_check_http_headers.clone();
            let cancel = Arc::new(AtomicBool::new(false));
            {
                let mut cancels = health_cancels.lock().await;
                cancels.insert(pn.clone(), cancel.clone());
            }
            let session_gen = session_gen.clone();
            tokio::spawn(async move {
                crate::health::run_health_check(crate::health::HealthCheckConfig {
                    proxy_name: pn,
                    local_addr: la,
                    check_type: hc_type,
                    check_url: hc_url,
                    hc_headers,
                    interval,
                    timeout,
                    max_failed,
                    health_tx: tx,
                    cancel,
                    session_gen,
                })
                .await;
            });
        }
    }
}

/// Whether a session that stayed up for at least `healthy_duration` warrants
/// resetting the consecutive-error count before the next reconnect backoff.
///
/// A long-healthy session followed by an occasional blip must reconnect from
/// Phase 1 (fast retry) instead of the 20s exponential cap — Go frp's
/// FastBackoffManager only counts consecutive failures. Sessions shorter than
/// the healthy duration keep their error count so the backoff cap is
/// preserved across rapid reconnects.
///
/// Pure decision (no clock reads) so the 5-minute production window can be
/// unit-tested without wall-clock sleeps; the call site supplies `now` and
/// the production healthy duration.
pub(super) fn healthy_resets_error_count(
    consecutive_err_count: u32,
    last_session_start: Option<Instant>,
    now: Instant,
    healthy_duration: Duration,
) -> bool {
    consecutive_err_count > 0
        && last_session_start.is_some_and(|start| now.duration_since(start) > healthy_duration)
}
