use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Run a health check for a proxy.
/// Supports "tcp" (connect only) and "http" (GET + check 2xx status).
/// When the local service exceeds max_failed consecutive failures, sends
/// the proxy name on `health_tx` so the control loop can send CloseProxy
/// to the server.
/// The `cancel` flag is set externally when the proxy is closed; the task
/// checks it before each health check interval and exits when true.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_health_check(
    proxy_name: String,
    local_addr: String,
    check_type: String,
    check_url: String,
    hc_headers: HashMap<String, String>,
    interval: Duration,
    timeout: Duration,
    max_failed: u32,
    health_tx: mpsc::UnboundedSender<String>,
    cancel: Arc<AtomicBool>,
) {
    info!(check_type = %check_type, proxy_name = %proxy_name, local_addr = %local_addr, interval = ?interval, timeout = ?timeout, "Health check ({}) started for '{}' -> {} (interval: {:?}, timeout: {:?})",
        check_type, proxy_name, local_addr, interval, timeout);

    let mut failures: u32 = 0;

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
                debug!(proxy_name = %proxy_name, "Health check OK for '{}'", proxy_name);
            }
            Err(e) => {
                failures += 1;
                warn!(proxy_name = %proxy_name, failures = %failures, error = %e, "Health check FAIL for '{}' ({}): {}", proxy_name, failures, e);
            }
        }

        if failures >= max_failed {
            warn!(proxy_name = %proxy_name, max_failed = %max_failed, "Health check: proxy '{}' exceeded max failures ({}), sending CloseProxy",
                proxy_name, max_failed);
            let _ = health_tx.send(proxy_name.clone());
            // Stop this health check task — the proxy is being closed.
            info!(proxy_name = %proxy_name, "Health check stopped for '{}' after CloseProxy", proxy_name);
            return;
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
