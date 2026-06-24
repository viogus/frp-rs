use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, debug};

use crate::service::{AppState, InternalMsg};

/// A route mapping: domain or location -> proxy entry.
#[derive(Debug, Clone)]
pub struct VhostRoute {
    pub proxy_name: String,
    pub run_id: String,
    /// Location prefixes for this proxy (empty = host-only routing).
    pub locations: Vec<String>,
}

/// Manages HTTP VHost routing table (domain + location → proxy).
pub struct VhostManager {
    /// domain → route (host-based routing)
    routes: RwLock<HashMap<String, VhostRoute>>,
    /// path prefix → route (location-based routing, sorted by prefix length desc)
    location_routes: RwLock<HashMap<String, VhostRoute>>,
    /// proxy_name → domains
    by_proxy: RwLock<HashMap<String, Vec<String>>>,
    /// proxy_name → location prefixes
    by_proxy_locations: RwLock<HashMap<String, Vec<String>>>,
}

impl VhostManager {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            location_routes: RwLock::new(HashMap::new()),
            by_proxy: RwLock::new(HashMap::new()),
            by_proxy_locations: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(
        &self,
        proxy_name: &str,
        domains: &[String],
        locations: &[String],
        run_id: &str,
    ) {
        let route = VhostRoute {
            proxy_name: proxy_name.to_string(),
            run_id: run_id.to_string(),
            locations: locations.to_vec(),
        };

        let mut routes = self.routes.write().await;
        let mut location_routes = self.location_routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;
        let mut by_proxy_locations = self.by_proxy_locations.write().await;

        let mut domains_for_proxy = Vec::new();
        for domain in domains {
            routes.insert(domain.clone(), route.clone());
            domains_for_proxy.push(domain.clone());
        }
        if !domains_for_proxy.is_empty() {
            by_proxy.insert(proxy_name.to_string(), domains_for_proxy);
        }

        let mut locs_for_proxy = Vec::new();
        for loc in locations {
            location_routes.insert(loc.clone(), route.clone());
            locs_for_proxy.push(loc.clone());
        }
        if !locs_for_proxy.is_empty() {
            by_proxy_locations.insert(proxy_name.to_string(), locs_for_proxy);
        }
    }

    pub async fn unregister(&self, proxy_name: &str) {
        let mut routes = self.routes.write().await;
        let mut location_routes = self.location_routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;
        let mut by_proxy_locations = self.by_proxy_locations.write().await;

        if let Some(domains) = by_proxy.remove(proxy_name) {
            for domain in &domains {
                routes.remove(domain);
            }
        }
        if let Some(locs) = by_proxy_locations.remove(proxy_name) {
            for loc in &locs {
                location_routes.remove(loc);
            }
        }
    }

    /// Look up by domain (exact match).
    pub async fn lookup(&self, domain: &str) -> Option<VhostRoute> {
        self.routes.read().await.get(domain).cloned()
    }

    /// Look up by URL path (longest prefix match among registered locations).
    /// Returns the VhostRoute whose location prefix best matches the given path.
    pub async fn lookup_by_path(&self, path: &str) -> Option<VhostRoute> {
        let routes = self.location_routes.read().await;
        // Find longest matching prefix
        let mut best: Option<(&str, &VhostRoute)> = None;
        for (prefix, route) in routes.iter() {
            if path.starts_with(prefix.as_str()) {
                match best {
                    Some((best_prefix, _)) if prefix.len() > best_prefix.len() => {
                        best = Some((prefix, route));
                    }
                    None => {
                        best = Some((prefix, route));
                    }
                    _ => {}
                }
            }
        }
        best.map(|(_, route)| route.clone())
    }

    /// Combined lookup: tries domain match first, then falls back to path-only match.
    /// If domain matches, returns that route (the route already carries its locations
    /// for the caller to verify path prefix).
    /// If no domain match, tries location-only routing.
    pub async fn lookup_combined(&self, domain: &str, path: &str) -> Option<VhostRoute> {
        // Try host-based routing first
        if let Some(route) = self.lookup(domain).await {
            // If the route has locations, verify path matches one of them
            if route.locations.is_empty() {
                return Some(route);
            }
            for loc in &route.locations {
                if path.starts_with(loc) {
                    return Some(route);
                }
            }
            // Domain matched but no location matched — fall through to location-only
        }
        // Try location-only routing (for proxies without custom_domains)
        self.lookup_by_path(path).await
    }
}

/// Run an HTTP VHost listener on the given address.
/// Accepts connections, reads the Host header, and routes via InternalMsg.
pub async fn run_vhost_http_listener(
    addr: String,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTP VHost listener started on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            // Read the first 4096 bytes to extract Host header (with 10s timeout)
            let mut buf = [0u8; 4096];
            let mut stream = stream;
            let n = match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };

            let pre_read = buf[..n].to_vec();
            let request_text = String::from_utf8_lossy(&buf[..n]);
            let host = match extract_host_header(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                }
            };
            let path = extract_path(&request_text).unwrap_or("/");

            debug!("HTTP VHost request for '{}' path '{}' from {}", host, path, peer);

            if let Some(route) = state.vhost_manager.lookup_combined(&host, path).await {
                let internal_tx = {
                    let map = state.run_id_to_ctl_tx.read().await;
                    map.get(&route.run_id).cloned()
                };

                if let Some(ctl_tx) = internal_tx {
                    let _ = ctl_tx.tx.send(InternalMsg::ProxyUserConn {
                        proxy_name: route.proxy_name.clone(),
                        user_conn: frp_core::transport::IoStream::Tcp(stream),
                        pre_read,
                    }).ok();
                } else {
                    warn!("VHost route for '{}' path '{}' found but control handler gone", host, path);
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                }
            } else {
                warn!("No VHost route for '{}' path '{}' from {}", host, path, peer);
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            }
        });
    }
}

/// Run an HTTPS VHost listener on the given address.
/// Performs TLS handshake, then extracts Host header and routes via InternalMsg.
pub async fn run_vhost_https_listener(
    addr: String,
    tls_cert_file: String,
    tls_key_file: String,
    state: std::sync::Arc<crate::service::AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    use frp_core::transport::build_tls_acceptor;
    let acceptor = build_tls_acceptor(&tls_cert_file, &tls_key_file)?;
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTPS VHost listener started on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer, e);
                    return;
                }
            };

            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout(std::time::Duration::from_secs(10), tls_stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };

            let pre_read = buf[..n].to_vec();
            let request_text = String::from_utf8_lossy(&buf[..n]);
            let host = match extract_host_header(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut tls_stream, b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                }
            };
            let path = extract_path(&request_text).unwrap_or("/");

            debug!("HTTPS VHost request for '{}' path '{}' from {}", host, path, peer);

            if let Some(route) = state.vhost_manager.lookup_combined(&host, path).await {
                let internal_tx = {
                    let map = state.run_id_to_ctl_tx.read().await;
                    map.get(&route.run_id).cloned()
                };
                if let Some(ctl_tx) = internal_tx {
                    let _ = ctl_tx.tx.send(crate::service::InternalMsg::ProxyUserConn {
                        proxy_name: route.proxy_name.clone(),
                        user_conn: frp_core::transport::IoStream::Tls(
                            tokio_rustls::TlsStream::Server(tls_stream)
                        ),
                        pre_read,
                    }).ok();
                } else {
                    warn!("HTTPS VHost route for '{}' path '{}' found but control handler gone", host, path);
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut tls_stream, b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                }
            } else {
                warn!("No VHost route for '{}' path '{}' from {}", host, path, peer);
                let _ = tokio::io::AsyncWriteExt::write_all(&mut tls_stream, b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            }
        });
    }
}

/// Extract the URL path from the HTTP request line.
/// e.g. "GET /api/v1/users HTTP/1.1" → "/api/v1/users"
fn extract_path(request: &str) -> Option<&str> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    parts.next()?; // method
    parts.next() // path
}

/// Extract the Host header value from an HTTP request (hostname only, no port).
fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        if line.len() < 6 { continue; }
        if !line[..5].eq_ignore_ascii_case("host:") { continue; }
        let value = line[5..].trim();
        // Handle IPv6: [::1]:8080 → ::1, example.com:8080 → example.com
        if value.starts_with('[') {
            return value.find(']').map(|end| &value[1..end]);
        }
        return Some(value.rsplitn(2, ':').next().unwrap_or(value));
    }
    None
}
