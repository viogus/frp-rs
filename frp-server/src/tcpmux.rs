use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, debug};

use crate::service::{AppState, InternalMsg};

/// A route mapping: domain → proxy info for tcpmux CONNECT routing.
#[derive(Debug, Clone)]
pub struct TcpMuxRoute {
    pub proxy_name: String,
    pub run_id: String,
    /// HTTP Basic Auth credentials (empty = no auth).
    pub http_user: String,
    pub http_pwd: String,
}

/// Manages TCPMux routing table (domain → proxy).
/// Maps Host header values from HTTP CONNECT requests to the correct proxy.
pub struct TcpMuxManager {
    /// domain → route
    routes: RwLock<HashMap<String, TcpMuxRoute>>,
    /// proxy_name → domains (for unregister)
    by_proxy: RwLock<HashMap<String, Vec<String>>>,
}

impl Default for TcpMuxManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpMuxManager {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            by_proxy: RwLock::new(HashMap::new()),
        }
    }

    /// Register domains for a tcpmux proxy.
    pub async fn register(
        &self,
        proxy_name: &str,
        domains: &[String],
        run_id: &str,
        http_user: &str,
        http_pwd: &str,
    ) {
        let route = TcpMuxRoute {
            proxy_name: proxy_name.to_string(),
            run_id: run_id.to_string(),
            http_user: http_user.to_string(),
            http_pwd: http_pwd.to_string(),
        };

        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;

        let mut domains_for_proxy = Vec::new();
        for domain in domains {
            routes.insert(domain.clone(), route.clone());
            domains_for_proxy.push(domain.clone());
        }
        if !domains_for_proxy.is_empty() {
            by_proxy.insert(proxy_name.to_string(), domains_for_proxy);
        }
    }

    /// Unregister all domains for a proxy.
    pub async fn unregister(&self, proxy_name: &str) {
        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;

        if let Some(domains) = by_proxy.remove(proxy_name) {
            for domain in &domains {
                routes.remove(domain);
            }
        }
    }

    /// Look up by hostname (exact match, port-stripped).
    pub async fn lookup(&self, host: &str) -> Option<TcpMuxRoute> {
        // Strip port if present: example.com:443 → example.com
        // Handle bracketed IPv6: [::1]:443 → ::1
        let hostname = if host.starts_with('[') {
            if let Some(end) = host.find(']') {
                &host[1..end]
            } else {
                host
            }
        } else {
            host.rsplitn(2, ':').last().unwrap_or(host)
        };
        self.routes.read().await.get(hostname).cloned()
    }
}

/// Run a TCPMux HTTP CONNECT listener on the given address.
///
/// Accepts connections, reads CONNECT method + headers, parses Host header,
/// matches against registered tcpmux proxy domains, responds `200 Connection
/// Established`, and forwards the connection via InternalMsg to the control
/// handler for bridging through a work connection.
pub async fn run_tcpmux_listener(
    addr: String,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "TCPMux HTTP CONNECT listener started on {}", addr);

    loop {
        let (mut stream, peer) = listener.accept().await?;
        frp_core::transport::set_nodelay(&stream);
        let state = state.clone();

        tokio::spawn(async move {
            // Read CONNECT line + headers (up to 4KB) with 10s timeout
            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                read_http_headers(&mut stream, &mut buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };

            let request_text = String::from_utf8_lossy(&buf[..n]);

            // Parse CONNECT line: CONNECT host:port HTTP/1.1
            let first_line = match request_text.lines().next() {
                Some(line) => line,
                None => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        .await;
                    return;
                }
            };

            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");

            if !method.eq_ignore_ascii_case("CONNECT") {
                warn!(
                    method = %method, peer = %peer,
                    "TCPMux: expected CONNECT, got {} from {}",
                    method, peer
                );
                let _ = stream
                    .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                    .await;
                return;
            }

            // Extract Host header
            let host = match extract_host_header(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    warn!(peer = %peer, "TCPMux: no Host header from {}", peer);
                    let _ = stream
                        .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        .await;
                    return;
                }
            };

            debug!(
                target = %target, host = %host, peer = %peer,
                "TCPMux CONNECT target='{}' host='{}' from {}",
                target, host, peer
            );

            // Look up route
            let route = match state.tcpmux_manager.lookup(&host).await {
                Some(r) => r,
                None => {
                    warn!(
                        host = %host, peer = %peer,
                        "TCPMux: no route for host '{}' from {}",
                        host, peer
                    );
                    crate::vhost::write_http_error(
                        &mut stream,
                        "HTTP/1.1 404 Not Found",
                        &state.custom_404_page,
                    ).await;
                    return;
                }
            };

            // Check Proxy-Authorization if configured
            if !route.http_user.is_empty() {
                let auth_ok = extract_proxy_auth(&request_text)
                    .map(|(u, p)| crate::constant_time_eq_str(&u, &route.http_user) && crate::constant_time_eq_str(&p, &route.http_pwd))
                    .unwrap_or(false);
                if !auth_ok {
                    let _ = stream.write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"frp\"\r\n\r\n",
                    ).await;
                    return;
                }
            }

            // Send 200 Connection Established to the external client
            if let Err(e) = stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
            {
                debug!(peer = %peer, error = %e, "TCPMux: failed to write 200 to {}: {}", peer, e);
                return;
            }

            // Forward to the control handler for work connection bridging.
            // No pre_read bytes — the CONNECT request is fully consumed.
            let internal_tx = {
                let map = state.run_id_to_ctl_tx.read().await;
                map.get(&route.run_id).cloned()
            };

            if let Some(ctl_tx) = internal_tx {
                let _ = ctl_tx
                    .tx
                    .send(InternalMsg::ProxyUserConn {
                        proxy_name: route.proxy_name.clone(),
                        user_conn: frp_core::transport::IoStream::Tcp(stream),
                        pre_read: Vec::new(),
                    })
                    .ok();
            } else {
                warn!(
                    host = %host,
                    "TCPMux: route for '{}' found but control handler gone",
                    host
                );
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await;
            }
        });
    }
}

/// Read HTTP request headers up to \r\n\r\n delimiter.
/// Returns the number of bytes read into buf.
async fn read_http_headers(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut [u8],
) -> Result<usize, String> {
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            return Err("headers too large".into());
        }
        // Read in chunks instead of byte-by-byte.
        let chunk_end = (total + 512).min(buf.len());
        let n = stream
            .read(&mut buf[total..chunk_end])
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        total += n;
        // Search for \r\n\r\n terminator in the newly read data
        // plus a 3-byte overlap from the previous chunk tail.
        let search_start = if total >= n + 3 { total - n - 3 } else { 0 };
        if let Some(pos) = buf[search_start..total]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {
            return Ok(search_start + pos + 4);
        }
    }
}

/// Extract the Host header value from an HTTP request (hostname only, no port).
fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        if line.len() < 6 {
            continue;
        }
        if !line[..5].eq_ignore_ascii_case("host:") {
            continue;
        }
        let value = line[5..].trim();
        // Handle IPv6: [::1]:8080 → ::1
        if value.starts_with('[') {
            return value.find(']').map(|end| &value[1..end]);
        }
        // Strip port: example.com:8080 → example.com
        return Some(value.rsplitn(2, ':').last().unwrap_or(value));
    }
    None
}

/// Extract Proxy-Authorization Basic credentials.
fn extract_proxy_auth(request: &str) -> Option<(String, String)> {
    let auth_line = request.lines().find(|line| {
        line.len() >= 20 && line[..20].eq_ignore_ascii_case("proxy-authorization:")
    })?;
    let value = auth_line[20..].trim();
    let encoded = if value.len() > 6 && value[..6].eq_ignore_ascii_case("Basic ") {
        value[6..].trim()
    } else {
        return None;
    };
    let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pwd) = creds.split_once(':')?;
    Some((user.to_string(), pwd.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_header_basic() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("example.com"));
    }

    #[test]
    fn test_extract_host_header_no_port() {
        let req = "CONNECT foo.bar HTTP/1.1\r\nHost: foo.bar\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("foo.bar"));
    }

    #[test]
    fn test_extract_host_header_missing() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_host_header(req), None);
    }

    #[test]
    fn test_extract_proxy_auth() {
        // "user:pass" in base64 = dXNlcjpwYXNz
        let req = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        let (user, pwd) = extract_proxy_auth(req).unwrap();
        assert_eq!(user, "user");
        assert_eq!(pwd, "pass");
    }

    #[test]
    fn test_extract_proxy_auth_missing() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_proxy_auth(req), None);
    }

    #[tokio::test]
    async fn test_tcpmux_manager_register_lookup_unregister() {
        let mgr = TcpMuxManager::new();

        mgr.register("p1", &["a.example.com".into()], "run-1", "", "")
            .await;

        // Exact match
        let r = mgr.lookup("a.example.com").await.unwrap();
        assert_eq!(r.proxy_name, "p1");

        // With port
        let r = mgr.lookup("a.example.com:443").await.unwrap();
        assert_eq!(r.proxy_name, "p1");

        // No match
        assert!(mgr.lookup("other.example.com").await.is_none());

        // Unregister
        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_tcpmux_manager_multiple_domains() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["a.example.com".into(), "b.example.com".into()],
            "run-1",
            "",
            "",
        )
        .await;

        assert!(mgr.lookup("a.example.com").await.is_some());
        assert!(mgr.lookup("b.example.com").await.is_some());
        assert!(mgr.lookup("c.example.com").await.is_none());

        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com").await.is_none());
        assert!(mgr.lookup("b.example.com").await.is_none());
    }
}
