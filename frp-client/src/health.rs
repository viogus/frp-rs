use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::service::HealthEvent;

// NOTE: Go frp does NOT support group-level health checks. Go frp's validation
// (pkg/config/v1/validation/proxy.go) only accepts "", "tcp", and "http" for
// health check types. The proxy Group field is used solely for server-side load
// balancing, not health checking. Per-proxy health checks are fully supported.
// If group-level health checking is desired as a frp-rs extension, implement:
//   1. GroupHealthState struct: name->healthy mapping per group, group->proxy_names mapping.
//   2. Shared Arc<Mutex<HashMap<group_name, GroupHealthState>>> across health check tasks.
//   3. HealthCheckConfig::group_name + group_state fields.
//   4. Modified failure/recovery logic in run_health_check.
//   5. service.rs: accept "group" check_type, pass group state, handle multi-proxy CloseProxy.

/// Configuration for a health check task.
pub(crate) struct HealthCheckConfig {
    pub proxy_name: String,
    pub local_addr: String,
    pub check_type: String,
    pub check_url: String,
    pub hc_headers: Vec<frp_core::config::HealthCheckHttpHeader>,
    pub interval: Duration,
    pub timeout: Duration,
    pub max_failed: u32,
    pub health_tx: mpsc::Sender<HealthEvent>,
    pub cancel: Arc<AtomicBool>,
}

/// Run a health check for a proxy.
/// Supports "tcp" (connect only) and "http" (GET + check 2xx status).
///
/// Go frp compat: the monitor keeps running after max_failed and sends
/// recovery events when the service comes back. Matches Go frp's health.Monitor:
///   - On max_failed: calls statusFailedFn (sends Close event), keeps running
///   - On recovery after failure: calls statusNormalFn (sends Recover event)
///   - Only stops when `cancel` is set (proxy removed, not on health failure).
pub(crate) async fn run_health_check(config: HealthCheckConfig) {
    let HealthCheckConfig {
        proxy_name,
        local_addr,
        check_type,
        check_url,
        hc_headers,
        interval,
        timeout,
        max_failed,
        health_tx,
        cancel,
    } = config;
    info!(check_type = %check_type, proxy_name = %proxy_name, local_addr = %local_addr, interval = ?interval, timeout = ?timeout, "Health check ({}) started for '{}' -> {} (interval: {:?}, timeout: {:?})",
        check_type, proxy_name, local_addr, interval, timeout);

    // Go frp compat: failedTimes resets on a successful check (#5502, dev).
    // State transitions are tracked by was_failed/statusOK; the counter
    // counts only the CURRENT failure streak.
    let mut state = HealthState::new();

    // Go frp v0.70.1 compat: add 500ms startup delay before the first check.
    // This prevents a thundering herd of health checks when many proxies
    // register simultaneously at client startup.
    tokio::time::sleep(Duration::from_millis(500)).await;

    loop {
        // Check cancellation before each check cycle.
        if cancel.load(Ordering::Relaxed) {
            info!(proxy_name = %proxy_name, "Health check cancelled for '{}'", proxy_name);
            return;
        }

        // Run check first, then sleep (Go frp compat: check happens immediately on start,
        // then sleep for interval duration before the next check).
        let result = if check_type == "http" {
            run_http_check(&local_addr, &check_url, timeout, &hc_headers).await
        } else {
            run_tcp_check(&local_addr, timeout).await
        };

        // Close is only ever fired from a FAILURE tick (Go frp: statusFailedFn
        // runs in the error branch). The old guard ran on every tick, so the
        // first success after a failure sent Recover AND re-fired Close in the
        // same tick (failures was monotonic and was_failed had just been cleared)
        // — flapping CloseProxy/NewProxy every health interval.
        match state.on_check(result.is_ok(), max_failed) {
            HealthAction::Recover => {
                // Service recovered. Notify control loop to re-register.
                info!(proxy_name = %proxy_name, "Health check recovered for '{}', sending Recover event", proxy_name);
                // try_send: during a reconnect the control-loop consumer
                // is gone and the bounded channel may be full — blocking
                // here would pause health probing. On failure keep
                // was_failed=true so the next successful check retries.
                if health_tx
                    .try_send(HealthEvent::Recover(proxy_name.clone()))
                    .is_ok()
                {
                    state.confirm_recover();
                }
            }
            HealthAction::Close => {
                warn!(proxy_name = %proxy_name, max_failed = %max_failed, "Health check: proxy '{}' exceeded max failures ({}), sending Close event",
                    proxy_name, max_failed);
                // try_send: during a reconnect the consumer may be gone and the
                // channel full — never block probing. On failure keep
                // was_failed=false; the next failed check retries the Close.
                if health_tx
                    .try_send(HealthEvent::Close(proxy_name.clone()))
                    .is_ok()
                {
                    state.confirm_close();
                }
                // Keep running -- monitor for recovery (Go frp compat).
            }
            HealthAction::None => {}
        }

        if let Err(e) = result {
            warn!(proxy_name = %proxy_name, failures = %state.failures, error = %e, "Health check FAIL for '{}' ({}): {}", proxy_name, state.failures, e);
        } else {
            debug!(proxy_name = %proxy_name, "Health check OK for '{}'", proxy_name);
        }

        tokio::time::sleep(interval).await;
    }
}

/// Action a health-check monitor should take after one probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthAction {
    /// No event; the check was healthy (or a failure below the threshold).
    None,
    /// The proxy exceeded `max_failed` failures and must be closed.
    Close,
    /// The proxy recovered and must be re-registered.
    Recover,
}

/// Health-check state machine mirroring Go frp's `health.Monitor`
/// (`statusOK`/`failedTimes` transitions). Pure and unit-testable.
struct HealthState {
    /// Consecutive failure count since the last successful check. Go frp
    /// v0.71.0 released with a monotonic counter that never reset (a failure
    /// streak could accumulate across recovery and misfire Close); fatedier
    /// fixed it in #5502 (dev) by resetting on success — mirrored here.
    failures: u64,
    /// A Close event was emitted and no Recover has been delivered yet.
    was_failed: bool,
    /// The proxy was observed healthy at least once (Go frp: statusOK).
    /// Close is only fired after the proxy was healthy at least once.
    was_healthy: bool,
}

impl HealthState {
    fn new() -> Self {
        HealthState {
            failures: 0,
            // Go frp v0.71.0 proxy_wrapper: a health-checked proxy starts with
            // health=1 ("failed") and is NOT registered until the FIRST
            // successful probe flips it healthy. Initial was_failed=true makes
            // that first success emit a Recover event, which registers the
            // proxy (mirroring Go's statusOKFn clearing pw.health).
            was_failed: true,
            was_healthy: false,
        }
    }

    /// Process one probe result and return the event the monitor should emit.
    ///
    /// Transitions are NOT committed here: the caller confirms them via
    /// [`confirm_recover`]/[`confirm_close`] only after the corresponding
    /// event was actually delivered (`try_send` can fail during a reconnect,
    /// in which case the transition is retried on the next matching tick).
    fn on_check(&mut self, ok: bool, max_failed: u32) -> HealthAction {
        if ok {
            // Go frp compat (fatedier/frp #5502, dev): failedTimes is reset
            // on a successful check, so a failure streak never accumulates
            // across recovery — a proxy that recovers must fail max_failed
            // times in a row again before Close fires.
            self.failures = 0;
            self.was_healthy = true;
            if self.was_failed {
                HealthAction::Recover
            } else {
                HealthAction::None
            }
        } else {
            self.failures += 1;
            // Go frp compat: only fire Close after the proxy was ever healthy
            // (statusOK must be true before transitioning to false triggers the
            // callback). Evaluated ONLY on failure ticks.
            if self.was_healthy && self.failures >= max_failed as u64 && !self.was_failed {
                HealthAction::Close
            } else {
                HealthAction::None
            }
        }
    }

    /// Commit a delivered Recover event (was_failed=false).
    fn confirm_recover(&mut self) {
        self.was_failed = false;
    }

    /// Commit a delivered Close event (was_failed=true).
    fn confirm_close(&mut self) {
        self.was_failed = true;
    }
}

/// TCP health check: connect to addr, then close. Success = connection established.
pub(crate) async fn run_tcp_check(addr: &str, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Go parity: health checks dial with net/http (NoDelay=true
            // default). Cosmetic for a connect+close probe, but keeps the
            // "every raw TcpStream" nodelay invariant uniform.
            frp_core::transport::set_nodelay(&stream);
            Ok(())
        }
        Ok(Err(e)) => Err(format!("TCP connect: {e}")),
        Err(_) => Err("timeout".into()),
    }
}

/// HTTP health check: connect, send GET, verify 2xx status code.
/// Uses raw TCP to avoid adding an HTTP client dependency.
pub(crate) async fn run_http_check(
    addr: &str,
    url: &str,
    timeout: Duration,
    headers: &[frp_core::config::HealthCheckHttpHeader],
) -> Result<(), String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("TCP connect: {e}"))?;
    // Go's health checks dial with net/http (NoDelay=true by default); the
    // small GET must not sit in Nagle's buffer waiting for the ACK. This
    // probe is not a relay, so no buffer-size setup is needed — just nodelay.
    frp_core::transport::set_nodelay(&stream);

    // Extract host from addr for the Host header. Go URL.Hostname():
    // port stripped, IPv6 brackets removed — a plain split(':') would
    // mangle "[::1]:8080" into "[" and unbracketed "::1:8080" into "".
    let default_host = addr
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.ip().to_string())
        .unwrap_or_else(|_| {
            // Bracketed IPv6 with port: "[::1]:8080" → "::1".
            if let Some(rest) = addr.strip_prefix('[') {
                if let Some((host, _)) = rest.split_once(']') {
                    return host.to_string();
                }
            }
            // Last-colon split only when the port part is numeric (Go
            // splitHostPort's validOptionalPort gate; a hostname or an
            // unbracketed IPv6 keeps its colons as-is).
            match addr.rsplit_once(':') {
                Some((host, port))
                    if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
                {
                    host.to_string()
                }
                _ => addr.to_string(),
            }
        });
    // Support custom Host header override from user-configured headers (Go frp compat).
    let host = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| h.value.as_str())
        .unwrap_or(default_host.as_str());
    // Use HTTP/1.1 (Go frp compat: http.NewRequestWithContext defaults to HTTP/1.1).
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close",
        url, host
    );
    for h in headers {
        // Skip Host header — already included above with the resolved host value.
        if h.name.eq_ignore_ascii_case("host") {
            continue;
        }
        req.push_str(&format!("\r\n{}: {}", h.name, h.value));
    }
    req.push_str("\r\n\r\n");

    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;

    if n == 0 {
        return Err("empty response".into());
    }
    let response = String::from_utf8_lossy(&buf[..n]);
    let status_line = response.lines().next().unwrap_or("");
    // Proper HTTP status parsing: check "HTTP/1." prefix, extract the 3-digit
    // numeric status code, and verify 200 <= code < 300. Substring matching
    // ("200" or " 2") could misparse multi-line responses or body content.
    // Matches Go frp's resp.StatusCode / 100 == 2 check.
    if status_line.starts_with("HTTP/1.") {
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            if let Ok(code) = parts[1].parse::<u16>() {
                if (200..300).contains(&code) {
                    return Ok(());
                }
            }
        }
    }
    Err(format!("non-2xx status: {}", status_line))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the Close guard must only ever run on FAILURE ticks. The
    /// old guard (`was_healthy && failures >= max_failed && !was_failed`) ran
    /// after every tick including successes, so the first success after a
    /// recovery sent Recover AND re-fired Close in the same tick (failures was
    /// monotonic and was_failed had just been cleared) — flapping
    /// CloseProxy/NewProxy every health interval.
    #[test]
    fn success_tick_after_recovery_emits_recover_but_not_close() {
        let mut st = HealthState::new();
        // Go v0.71.0: a health-checked proxy starts "failed" (health=1), so
        // the FIRST success emits Recover and registers the proxy.
        assert_eq!(st.on_check(true, 2), HealthAction::Recover);
        st.confirm_recover();
        // Healthy baseline: no events.
        assert_eq!(st.on_check(true, 2), HealthAction::None);
        // Failure 1: below max_failed, no event.
        assert_eq!(st.on_check(false, 2), HealthAction::None);
        // Failure 2: reaches max_failed -> Close.
        assert_eq!(st.on_check(false, 2), HealthAction::Close);
        st.confirm_close();
        // Further failures while closed: no re-fire.
        assert_eq!(st.on_check(false, 2), HealthAction::None);
        // Success after a failure streak: Recover only.
        assert_eq!(st.on_check(true, 2), HealthAction::Recover);
        st.confirm_recover();
        // Success right after recovery: NO event. Regression: the old guard
        // fired Close here because `failures` was monotonic and was_failed
        // had just been cleared by the Recover above.
        assert_eq!(st.on_check(true, 2), HealthAction::None);
        // A later failure does NOT re-close immediately: the successful check
        // reset the counter (Go #5502), so the streak restarts from zero.
        assert_eq!(st.on_check(false, 2), HealthAction::None);
        // One more failure reaches max_failed again -> Close.
        assert_eq!(st.on_check(false, 2), HealthAction::Close);
        // The first success after Close recovers (was_failed=true)...
        st.confirm_close();
        assert_eq!(st.on_check(true, 2), HealthAction::Recover);
        st.confirm_recover();
        // ...and the following success tick is silent.
        assert_eq!(st.on_check(true, 2), HealthAction::None);
    }

    /// Go #5502 regression: failures must not accumulate across a recovery.
    /// Old behavior closed a proxy that failed max_failed times over SEPARATE
    /// outages (e.g. 2 failures, 10 min healthy, 1 failure with max_failed=3)
    /// because the monotonic counter never reset.
    #[test]
    fn failure_streak_does_not_accumulate_across_recovery() {
        let mut st = HealthState::new();
        // First success registers (health=1 -> 0).
        assert_eq!(st.on_check(true, 3), HealthAction::Recover);
        st.confirm_recover();
        // Outage 1: 2 failures, below max_failed=3, no Close.
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        // Recovery.
        assert_eq!(st.on_check(true, 3), HealthAction::None);
        // Outage 2: 1 failure — must NOT Close (streak restarted at 0).
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        // Outage 2 continues: 2 more failures reach max_failed in one streak.
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        assert_eq!(st.on_check(false, 3), HealthAction::Close);
    }

    /// Close is only emitted on failure ticks; success ticks can only emit
    /// Recover (or nothing).
    #[test]
    fn close_never_emitted_on_success_ticks() {
        let mut st = HealthState::new();
        // Force the closed state, then feed success ticks: never Close.
        st.on_check(false, 1);
        st.confirm_close();
        assert_eq!(st.on_check(true, 1), HealthAction::Recover);
        st.confirm_recover();
        assert_eq!(st.on_check(true, 1), HealthAction::None);
        assert_eq!(st.on_check(true, 1), HealthAction::None);
    }

    /// A proxy that was never healthy is never closed (Go frp statusOK gate).
    #[test]
    fn never_healthy_proxy_is_not_closed() {
        let mut st = HealthState::new();
        // A never-healthy proxy is never closed (Go frp statusOK gate).
        assert_eq!(st.on_check(false, 1), HealthAction::None);
        assert_eq!(st.on_check(false, 1), HealthAction::None);
        assert_eq!(st.on_check(false, 1), HealthAction::None);
        // First ever success registers the proxy (Recover; Go health=1 → 0).
        assert_eq!(st.on_check(true, 1), HealthAction::Recover);
        st.confirm_recover();
        // Healthy afterwards: no events.
        assert_eq!(st.on_check(true, 1), HealthAction::None);
    }
}
