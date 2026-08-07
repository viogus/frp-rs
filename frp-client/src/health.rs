use std::collections::HashMap;
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
    pub hc_headers: HashMap<String, String>,
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

    // Go frp v0.70.1 compat: failedTimes is a monotonic uint64 that NEVER resets.
    // State transitions are tracked by was_failed/statusOK, not by resetting the counter.
    // See /tmp/frp-source/client/health/health.go:45,128-135.
    let mut failures: u64 = 0;
    let mut was_failed = false;
    // Track whether the proxy has ever been healthy (Go frp: statusOK).
    // Close is only fired after the proxy was healthy at least once.
    let mut was_healthy = false;

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

        match result {
            Ok(()) => {
                // Go frp compat: failedTimes is NEVER reset on success — monotonic.
                // See /tmp/frp-source/client/health/health.go:121-127.
                was_healthy = true;
                if was_failed {
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
                        was_failed = false;
                    }
                }
                debug!(proxy_name = %proxy_name, "Health check OK for '{}'", proxy_name);
            }
            Err(e) => {
                failures += 1;
                warn!(proxy_name = %proxy_name, failures = %failures, error = %e, "Health check FAIL for '{}' ({}): {}", proxy_name, failures, e);
            }
        }

        // Go frp compat: only fire Close after the proxy was ever healthy.
        // (statusOK must be true before transitioning to false triggers the callback).
        if was_healthy && failures >= max_failed as u64 && !was_failed {
            warn!(proxy_name = %proxy_name, max_failed = %max_failed, "Health check: proxy '{}' exceeded max failures ({}), sending Close event",
                proxy_name, max_failed);
            // try_send: during a reconnect the consumer may be gone and the
            // channel full — never block probing. On failure keep
            // was_failed=false; the next failed check retries the Close.
            if health_tx
                .try_send(HealthEvent::Close(proxy_name.clone()))
                .is_ok()
            {
                was_failed = true;
            }
            // Keep running -- monitor for recovery (Go frp compat).
        }

        tokio::time::sleep(interval).await;
    }
}

/// TCP health check: connect to addr, then close. Success = connection established.
pub(crate) async fn run_tcp_check(addr: &str, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
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
    headers: &HashMap<String, String>,
) -> Result<(), String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("TCP connect: {e}"))?;

    // Extract host from addr (strip port for Host header).
    let default_host = addr.split(':').next().unwrap_or(addr);
    // Support custom Host header override from user-configured headers (Go frp compat).
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .unwrap_or(default_host);
    // Use HTTP/1.1 (Go frp compat: http.NewRequestWithContext defaults to HTTP/1.1).
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close",
        url, host
    );
    for (key, value) in headers {
        // Skip Host header — already included above with the resolved host value.
        if key.eq_ignore_ascii_case("host") {
            continue;
        }
        req.push_str(&format!("\r\n{}: {}", key, value));
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
