use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

#[cfg(feature = "tls")]
use crate::lock::RwLockExt;
use crate::service::{AppState, InternalMsg};

/// A route mapping: domain or location -> proxy entry.
#[derive(Debug, Clone)]
pub struct VhostRoute {
    pub proxy_name: String,
    pub run_id: String,
    /// Location prefixes for this proxy (empty = host-only routing).
    pub locations: Vec<String>,
    /// Rewrite Host header to this value before forwarding (Go frp compat).
    pub host_header_rewrite: String,
    /// HTTP Basic Auth credentials (empty = no auth).
    pub http_user: String,
    pub http_pwd: String,
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

impl Default for VhostManager {
    fn default() -> Self {
        Self::new()
    }
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

    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        proxy_name: &str,
        domains: &[String],
        locations: &[String],
        run_id: &str,
        host_header_rewrite: &str,
        http_user: &str,
        http_pwd: &str,
    ) {
        let route = VhostRoute {
            proxy_name: proxy_name.to_string(),
            run_id: run_id.to_string(),
            locations: locations.to_vec(),
            host_header_rewrite: host_header_rewrite.to_string(),
            http_user: http_user.to_string(),
            http_pwd: http_pwd.to_string(),
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

/// Write an HTTP error response, optionally with a custom body.
/// If custom_body is non-empty, it is used as the response body
/// with Content-Type: text/html.
pub(crate) async fn write_http_error(
    stream: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    status_line: &str,
    custom_body: &str,
) {
    // Write failures here mean the client disconnected before receiving the
    // error response — there is no recovery path, so we silently drop them.
    if custom_body.is_empty() {
        let _ = stream
            .write_all(format!("{status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await;
    } else {
        let body = custom_body.as_bytes();
        let _ = stream
            .write_all(
                format!(
                    "{status_line}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = stream.write_all(body).await;
    }
}

/// Shared per-connection VHost handling: read the request head, extract Host
/// header and path, apply Basic Auth and host_header_rewrite, then route the
/// stream via InternalMsg::ProxyUserConn. `scheme` labels log lines
/// ("HTTP"/"HTTPS"). `wrap` converts the (readable+writable) stream into the
/// IoStream variant carried to the control handler.
async fn serve_vhost_request<S>(
    mut stream: S,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    scheme: &str,
    wrap: impl FnOnce(S) -> frp_core::transport::IoStream,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Read the first 4096 bytes to extract Host header (with 10s timeout)
    let mut buf = [0u8; 4096];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
        .await
    {
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

    debug!(host = %host, path = %path, peer = %peer, "{} VHost request for '{}' path '{}' from {}", scheme, host, path, peer);

    if let Some(route) = state.vhost_manager.lookup_combined(&host, path).await {
        // HTTP Basic Auth check (Go frp compat)
        if !route.http_user.is_empty() {
            let auth_ok = extract_basic_auth(&request_text)
                .map(|(u, p)| {
                    crate::constant_time_eq_str(&u, &route.http_user)
                        && crate::constant_time_eq_str(&p, &route.http_pwd)
                })
                .unwrap_or(false);
            if !auth_ok {
                let _ = stream.write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"frp\"\r\n\r\n"
                ).await;
                return;
            }
        }

        // Apply host_header_rewrite if configured
        let pre_read = if !route.host_header_rewrite.is_empty() {
            rewrite_host_header(&pre_read, &route.host_header_rewrite)
        } else {
            pre_read
        };

        let internal_tx = {
            let map = state.run_id_to_ctl_tx.read().await;
            map.get(&route.run_id).cloned()
        };

        if let Some(ctl_tx) = internal_tx {
            let _ = ctl_tx
                .tx
                .try_send(InternalMsg::ProxyUserConn {
                    proxy_name: route.proxy_name.clone(),
                    user_conn: wrap(stream),
                    pre_read,
                })
                .ok();
        } else {
            warn!(host = %host, path = %path, "{} VHost route for '{}' path '{}' found but control handler gone", scheme, host, path);
            write_http_error(&mut stream, "HTTP/1.1 502 Bad Gateway", "").await;
        }
    } else {
        warn!(host = %host, path = %path, peer = %peer, "No {} VHost route for '{}' path '{}' from {}", scheme, host, path, peer);
        write_http_error(
            &mut stream,
            "HTTP/1.1 404 Not Found",
            &state.custom_404_page,
        )
        .await;
    }
}

/// Run an HTTP VHost listener on the given address.
/// Accepts connections, reads the Host header, and routes via InternalMsg.
#[instrument(skip(state, shutdown_token), fields(addr = %addr))]
pub async fn run_vhost_http_listener(
    addr: String,
    state: Arc<AppState>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "HTTP VHost listener started on {}", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result?;
                frp_core::transport::set_nodelay(&stream);
                let state = state.clone();

                tokio::spawn(async move {
                    serve_vhost_request(
                        stream,
                        peer,
                        state,
                        "HTTP",
                        frp_core::transport::IoStream::Tcp,
                    )
                    .await;
                });
            }
            _ = shutdown_token.cancelled() => {
                info!("HTTP VHost listener shutting down");
                break;
            }
        }
    }
    Ok(())
}

/// Run an HTTPS VHost listener on the given address.
/// Performs TLS handshake, then extracts Host header and routes via InternalMsg.
#[cfg(feature = "tls")]
#[instrument(skip(state, shutdown_token), fields(addr = %addr))]
pub async fn run_vhost_https_listener(
    addr: String,
    state: std::sync::Arc<crate::service::AppState>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "HTTPS VHost listener started on {}", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result?;
                frp_core::transport::set_nodelay(&stream);
                let state = state.clone();
                // Read the current TLS acceptor from shared state. Hot-reload
                // swaps a new acceptor under write lock; read-lock is cheap.
                let Some(acceptor) = state
                    .tls_acceptor
                    .read_ok()
                    .clone()
                else {
                    tracing::error!("TLS acceptor not initialized");
                    continue;
                };

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(peer = %peer, error = %e, "TLS handshake failed from {}: {}", peer, e);
                            return;
                        }
                    };

                    serve_vhost_request(tls_stream, peer, state, "HTTPS", |s| {
                        frp_core::transport::IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(s)))
                    })
                    .await;
                });
            }
            _ = shutdown_token.cancelled() => {
                info!("HTTPS VHost listener shutting down");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "tls"))]
pub async fn run_vhost_https_listener(
    _addr: String,
    _state: std::sync::Arc<crate::service::AppState>,
    _shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("TLS feature not enabled".into())
}

/// Extract the URL path from the HTTP request line.
/// e.g. "GET /api/v1/users HTTP/1.1" → "/api/v1/users"
fn extract_path(request: &str) -> Option<&str> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    parts.next()?; // method
    parts.next() // path
}

/// Rewrite the Host header in an HTTP request's raw bytes.
/// Finds the first `Host:` or `host:` line and replaces it with the given value.
/// Byte-oriented to avoid mangling non-UTF-8 request data.
/// Returns a new Vec<u8> with the rewritten header.
fn rewrite_host_header(data: &[u8], new_host: &str) -> Vec<u8> {
    // Search for \r\nHost: anywhere in the request data, plus first-line Host:
    let host_pos = {
        // First check if Host: is the very first header (no leading \r\n)
        let first_line = if data.len() >= 5 && data[..5].eq_ignore_ascii_case(b"host:") {
            Some(0)
        } else {
            None
        };
        // Then scan for \r\n followed by Host: anywhere
        first_line.or_else(|| {
            data.windows(7)
                .position(|w| w[..2] == *b"\r\n" && w[2..].eq_ignore_ascii_case(b"host:"))
                .map(|p| p + 2)
        })
    };

    let Some(host_start) = host_pos else {
        return data.to_vec();
    };

    // Find end of the Host header line
    let line_end = data[host_start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| host_start + p + 2)
        .unwrap_or(data.len());

    // Sanitize \r and \n to prevent HTTP header injection.
    let safe_host: String = new_host
        .chars()
        .filter(|&c| c != '\r' && c != '\n')
        .collect();
    let new_header = format!("Host: {}\r\n", safe_host);
    let mut result = Vec::with_capacity(data.len() + new_header.len());
    result.extend_from_slice(&data[..host_start]);
    result.extend_from_slice(new_header.as_bytes());
    result.extend_from_slice(&data[line_end..]);
    result
}

/// Extract HTTP Basic Auth credentials from the Authorization header.
/// Returns Some((username, password)) or None if no/invalid auth header.
fn extract_basic_auth(request: &str) -> Option<(String, String)> {
    let auth_line = request
        .lines()
        .find(|line| line.len() >= 14 && line[..14].eq_ignore_ascii_case("authorization:"))?;
    let value = auth_line[14..].trim();
    let encoded = value.strip_prefix("Basic ")?.trim();
    let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pwd) = creds.split_once(':')?;
    Some((user.to_string(), pwd.to_string()))
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
        // Handle IPv6: [::1]:8080 → ::1, example.com:8080 → example.com
        if value.starts_with('[') {
            return value.find(']').map(|end| &value[1..end]);
        }
        return Some(value.split(':').next().unwrap_or(value));
    }
    None
}

/// Extract the SNI hostname from a TLS ClientHello message (RFC 6066 §3).
///
/// `data` must start with the TLS record header (content_type = 0x16).
/// Returns the SNI hostname if found, or None.
pub fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // Minimum: TLS record header (5) + handshake header (4) + client version (2)
    // + random (32) + session_id_len (1) = 44 bytes before any variable fields
    if data.len() < 44 {
        return None;
    }

    // TLS record: content_type (1) + version (2) + length (2)
    if data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let handshake = &data[5..];
    // Handshake: type (1) + length (3)
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }
    if handshake.len() < 4 {
        return None;
    }
    let hs_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let ch = &handshake[4..4 + hs_len];
    if ch.len() < 38 {
        return None;
    }

    // Skip: version (2) + random (32) = 34 bytes to reach session_id_len
    let mut pos = 34;
    if pos >= ch.len() {
        return None;
    }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > ch.len() {
        return None;
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > ch.len() {
        return None;
    }

    // Compression methods
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > ch.len() {
        return None;
    }

    // Extensions
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > ch.len() {
        return None;
    }

    // Search extensions for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension: ServerNameList
            if pos + 2 > ch.len() {
                return None;
            }
            let list_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            pos += 2;
            let list_end = pos + list_len;
            if list_end > ext_end {
                return None;
            }

            while pos + 3 <= list_end {
                let name_type = ch[pos];
                let name_len = u16::from_be_bytes([ch[pos + 1], ch[pos + 2]]) as usize;
                pos += 3;

                if name_type == 0x00 && pos + name_len <= list_end {
                    return String::from_utf8(ch[pos..pos + name_len].to_vec()).ok();
                }
                pos += name_len;
            }
            break;
        }
        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_real_client_hello() {
        // Realistic TLS 1.2 ClientHello with SNI "example.com"
        let name = b"example.com";
        let name_bytes_len = name.len();

        // Compute lengths
        let sni_ext_data_len: u16 = 1 + 2 + name_bytes_len as u16; // name_type + name_len + name
        let sni_ext_list_len: u16 = sni_ext_data_len; // just one ServerName
        let sni_ext_len: u16 = 2 + sni_ext_list_len; // list_len + list
        let extensions_len: u16 = 4 + sni_ext_len; // ext_type + ext_len + ext_data
                                                   // ClientHello body: version(2) + random(32) + sid_len(1) + sid(0)
                                                   //   + cs_len(2) + cs_data(2) + cm_len(1) + cm_data(1) + ext_len(2) + ext_data
        let ch_body_len: u16 = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
        let hs_len: u32 = ch_body_len as u32;
        // record = hs_type(1) + hs_len(3) + ch_body
        let record_len: u16 = 4 + ch_body_len;

        let mut bytes = Vec::new();
        // TLS record header
        bytes.extend_from_slice(&[0x16, 0x03, 0x01]); // content_type + version
        bytes.extend_from_slice(&record_len.to_be_bytes());

        // Handshake header: type(1) + length(3 bytes, uint24)
        bytes.push(0x01); // ClientHello
        bytes.push((hs_len >> 16) as u8);
        bytes.push((hs_len >> 8) as u8);
        bytes.push(hs_len as u8);

        // ClientHello body
        bytes.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
                                                // Random (32 bytes)
        bytes.extend_from_slice(&[0x00u8; 32]);
        // Session ID: empty
        bytes.push(0x00);
        // Cipher suites: 1 suite (TLS_AES_128_GCM_SHA256 = 0x1301)
        bytes.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // Compression: null
        bytes.extend_from_slice(&[0x01, 0x00]);
        // Extensions
        bytes.extend_from_slice(&extensions_len.to_be_bytes());

        // SNI extension
        bytes.extend_from_slice(&[0x00, 0x00]); // type = server_name
        bytes.extend_from_slice(&sni_ext_len.to_be_bytes());
        // ServerNameList
        bytes.extend_from_slice(&sni_ext_list_len.to_be_bytes());
        // ServerName: host_name
        bytes.push(0x00); // name_type = host_name
        bytes.extend_from_slice(&(name_bytes_len as u16).to_be_bytes());
        bytes.extend_from_slice(name);

        assert_eq!(
            bytes.len(),
            5 + 4 + ch_body_len as usize,
            "record_len={} ch_body_len={} hs_len={}",
            record_len,
            ch_body_len,
            hs_len
        );

        let result = extract_sni_from_client_hello(&bytes);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_no_extension() {
        // ClientHello without extensions
        let data = vec![
            0x16, 0x03, 0x01, 0x00, 0x29, // record header
            0x01, 0x00, 0x00, 0x25, // handshake header
            0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // session_id_len = 0
            0x00, 0x02, 0x13, 0x01, // cipher suites
            0x01, 0x00, // compression
            0x00, 0x00, // extensions length = 0
        ];
        assert_eq!(extract_sni_from_client_hello(&data), None);
    }

    #[test]
    fn test_extract_sni_short_data() {
        assert_eq!(extract_sni_from_client_hello(&[0x16, 0x03]), None);
        assert_eq!(extract_sni_from_client_hello(&[]), None);
    }

    #[tokio::test]
    async fn test_write_http_error_empty_body() {
        let mut buf = Vec::new();
        write_http_error(&mut buf, "HTTP/1.1 404 Not Found", "").await;
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("HTTP/1.1 404 Not Found"));
        assert!(resp.contains("Content-Length: 0"));
    }

    #[tokio::test]
    async fn test_write_http_error_custom_body() {
        let mut buf = Vec::new();
        write_http_error(&mut buf, "HTTP/1.1 404 Not Found", "<h1>Not Found</h1>").await;
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("HTTP/1.1 404 Not Found"));
        assert!(resp.contains("Content-Type: text/html"));
        assert!(resp.contains("<h1>Not Found</h1>"));
    }
}
