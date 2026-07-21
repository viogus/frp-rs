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

    let mut failures: u32 = 0;
    let mut was_failed = false;

    loop {
        // Check cancellation before each sleep/check cycle.
        if cancel.load(Ordering::Relaxed) {
            info!(proxy_name = %proxy_name, "Health check cancelled for '{}'", proxy_name);
            return;
        }

        tokio::time::sleep(interval).await;

        let result = if check_type == "http" {
            run_http_check(&local_addr, &check_url, timeout, &hc_headers).await
        } else {
            run_tcp_check(&local_addr, timeout).await
        };

        match result {
            Ok(()) => {
                failures = 0;
                if was_failed {
                    // Service recovered. Notify control loop to re-register.
                    info!(proxy_name = %proxy_name, "Health check recovered for '{}', sending Recover event", proxy_name);
                    let _ = health_tx
                        .send(HealthEvent::Recover(proxy_name.clone()))
                        .await;
                    was_failed = false;
                }
                debug!(proxy_name = %proxy_name, "Health check OK for '{}'", proxy_name);
            }
            Err(e) => {
                failures += 1;
                warn!(proxy_name = %proxy_name, failures = %failures, error = %e, "Health check FAIL for '{}' ({}): {}", proxy_name, failures, e);
            }
        }

        if failures >= max_failed && !was_failed {
            was_failed = true;
            warn!(proxy_name = %proxy_name, max_failed = %max_failed, "Health check: proxy '{}' exceeded max failures ({}), sending Close event",
                proxy_name, max_failed);
            let _ = health_tx.send(HealthEvent::Close(proxy_name.clone())).await;
            // Keep running -- monitor for recovery (Go frp compat).
        }
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

    // Extract host from addr (strip port for Host header)
    let host = addr.split(':').next().unwrap_or(addr);
    let mut req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close",
        url, host
    );
    for (key, value) in headers {
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
    if status_line.contains("200") || status_line.contains(" 2") {
        Ok(())
    } else {
        Err(format!("non-2xx status: {}", status_line))
    }
}
