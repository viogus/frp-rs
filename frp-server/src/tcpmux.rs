use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

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
    /// Live count of registered `*.` wildcard routes. Lets `lookup` skip the
    /// label-walk (each iteration allocates a joined host) entirely when no
    /// wildcard route exists — the common case, where `example.com` lookups
    /// never matched anything but the exact map hit anyway.
    wildcard_count: std::sync::atomic::AtomicUsize,
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
            wildcard_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Register domains for a tcpmux proxy.
    ///
    /// Returns `Err(conflict)` when any domain is already routed to a
    /// different proxy. Every domain is validated BEFORE any insert, so a
    /// rejected registration leaves no partial state — mirroring the VHost
    /// manager. Previously the result was ignored and the last registration
    /// silently overwrote the first (audit finding 5), which meant closing
    /// the overwriting proxy deleted the live sibling's route.
    pub async fn register(
        &self,
        proxy_name: &str,
        domains: &[String],
        run_id: &str,
        http_user: &str,
        http_pwd: &str,
        _headers: &[(String, String)],
    ) -> Result<(), String> {
        let route = TcpMuxRoute {
            proxy_name: proxy_name.to_string(),
            run_id: run_id.to_string(),
            http_user: http_user.to_string(),
            http_pwd: http_pwd.to_string(),
        };

        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;

        // Go frp compat (pkg/util/vhost/router.go): domains are stored
        // lowercased (`Routers.Add` → strings.ToLower), so CONNECT Host
        // lookups are case-insensitive. Lowercase each domain ONCE, before
        // the conflict check, the insert, and the by_proxy bookkeeping,
        // keeping register/unregister symmetric.
        let domains: Vec<String> = domains.iter().map(|d| d.to_lowercase()).collect();

        // Re-registration with a changed domain list (server reload): drop
        // routes that left the list — otherwise a shrunken reload orphans
        // the dropped `*.` route (and its wildcard count) forever. Same
        // ownership guard as unregister: a sibling's live route survives.
        if let Some(old) = by_proxy.get(proxy_name) {
            for domain in old {
                if !domains.contains(domain)
                    && routes
                        .get(domain)
                        .is_some_and(|r| r.proxy_name == proxy_name)
                {
                    if domain.starts_with("*.") {
                        self.wildcard_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    routes.remove(domain);
                }
            }
        }

        // Validate every domain before inserting anything (no partial state).
        // Re-registration by the same proxy name is allowed (idempotent).
        for domain in &domains {
            if let Some(existing) = routes.get(domain) {
                if existing.proxy_name != proxy_name {
                    return Err(format!(
                        "tcpmux route conflict for domain '{}': proxy '{}' vs '{}'",
                        domain, existing.proxy_name, proxy_name
                    ));
                }
            }
        }

        let mut domains_for_proxy = Vec::new();
        for domain in &domains {
            // insert returns the overwritten route: a re-registration of the
            // same domain by the same proxy must not double-count the wildcard.
            if routes.insert(domain.clone(), route.clone()).is_none() && domain.starts_with("*.") {
                self.wildcard_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            domains_for_proxy.push(domain.clone());
        }
        if !domains_for_proxy.is_empty() {
            by_proxy.insert(proxy_name.to_string(), domains_for_proxy);
        }
        Ok(())
    }

    /// Unregister all domains for a proxy.
    ///
    /// A domain's route is removed only when it still belongs to `proxy_name`:
    /// if a concurrent registration (or a stale by_proxy entry from the
    /// pre-fix last-writer-wins behavior) points the domain at another proxy,
    /// that sibling's live route must survive (audit finding 5).
    pub async fn unregister(&self, proxy_name: &str) {
        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;

        if let Some(domains) = by_proxy.remove(proxy_name) {
            for domain in &domains {
                if routes
                    .get(domain)
                    .is_some_and(|r| r.proxy_name == proxy_name)
                {
                    // Same guard as the removal: only count down routes this
                    // proxy actually owned (a sibling's `*.` route pointing at
                    // the same domain must keep its count).
                    if domain.starts_with("*.") {
                        self.wildcard_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    routes.remove(domain);
                }
            }
        }
    }

    /// Look up by hostname with wildcard fallback (Go frp vhost.Muxer →
    /// getByRoute): exact match, then progressively replace the leftmost
    /// label with "*" while >=3 labels remain, then the "*" catch-all.
    /// Port-stripped, trailing-dot-trimmed, case-insensitive.
    pub async fn lookup(&self, host: &str) -> Option<TcpMuxRoute> {
        // Strip port if present: example.com:443 → example.com; bracketed
        // IPv6: [::1]:443 → ::1; then exactly one trailing dot (Go frp
        // CanonicalHost, pkg/util/http/http.go).
        let hostname = canonicalize_host(host)?;
        // Go frp compat (pkg/util/vhost/router.go): `Get` lowercases the
        // host — domains are stored lowercased at register. Alloc-free ASCII
        // fast path (Go's strings.ToLower skips allocation for all-lowercase
        // input); Unicode case mapping can expand length (İ → "i̇") vs Go's
        // single-rune map, but real hostnames are IDNA/punycode ASCII —
        // divergence accepted.
        let lowered;
        let host_key: &str = if hostname.bytes().all(|b| !b.is_ascii_uppercase()) {
            hostname
        } else {
            lowered = hostname.to_lowercase();
            &lowered
        };

        let routes = self.routes.read().await;
        // 1. Exact match
        if let Some(route) = routes.get(host_key) {
            return Some(route.clone());
        }
        // 2. Replace the leftmost label with "*" progressively. Only for
        //    hosts with >=3 labels (Go's `for len(hostSplit) >= 3` —
        //    prevents `*.com` from matching `example.com`). Each iteration
        //    allocates a joined host string, so skip the walk entirely when
        //    no `*.` route is registered (the common case).
        if self
            .wildcard_count
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
        {
            let mut parts: Vec<&str> = host_key.split('.').collect();
            while parts.len() > 2 {
                parts[0] = "*";
                let wildcard_host = parts.join(".");
                if let Some(route) = routes.get(&wildcard_host) {
                    return Some(route.clone());
                }
                parts.remove(0);
            }
        }
        // 3. Catch-all "*"
        routes.get("*").cloned()
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
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "TCPMux HTTP CONNECT listener started on {}", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut stream, peer) = result?;
        frp_core::transport::set_nodelay(&stream);
        if state.tcp_keepalive > 0 {
            frp_core::transport::set_keepalive(&stream, state.tcp_keepalive as u64);
        }
        let permit = state
            .conn_semaphore
            .as_ref()
            .and_then(|s| s.clone().try_acquire_owned().ok());
        if permit.is_none() && state.conn_semaphore.is_some() {
            warn!(addr = %peer, "Max connections reached, rejecting from {}", peer);
            continue;
        }
        let rate_wait = if state.accept_rate_limiter.rate() > 0.0 {
            state.accept_rate_limiter.try_acquire().err()
        } else {
            None
        };
        if let Some(wait) = rate_wait {
            warn!(addr = %peer, wait_ms = wait.as_millis(), "accept rate limit reached, delaying {}ms", wait.as_millis());
            // Release the semaphore permit before sleeping — the connection
            // is being delayed, not accepted, so it must not hold a
            // connection slot while we wait.
            drop(permit);
            tokio::time::sleep(wait).await;
            continue;
        }
        let state = state.clone();

        tokio::spawn(async move {
            let _permit = permit;
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
                    // Client disconnected or sent garbage — write failure is
                    // expected and there is no recovery path.
                    if let Err(e) = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await {
                        tracing::debug!(error = %e, peer = %peer, "failed to write HTTP error response");
                    }
                    return;
                }
            };

            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");

            // Case-sensitive like Go: httpconnect.go's `req.Method !=
            // "CONNECT"` (and justAuthority, which only treats an exact
            // "CONNECT" as authority-form — a lowercase "connect" has no
            // URL host and errors).
            if method != "CONNECT" {
                warn!(
                    method = %method, peer = %peer,
                    "TCPMux: expected CONNECT, got {} from {}",
                    method, peer
                );
                if let Err(e) = stream
                    .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                    .await
                {
                    tracing::debug!(error = %e, peer = %peer, "failed to write HTTP error response");
                }
                return;
            }

            // Route on the request-line authority (CONNECT target) — Go
            // net/http fills req.Host from req.URL.Host and ignores the
            // Host header for CONNECT (RFC 7230 §5.3; see
            // `extract_route_host`). 400 only when both are absent.
            let host = match extract_route_host(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    warn!(peer = %peer, "TCPMux: no Host header or CONNECT target from {}", peer);
                    if let Err(e) = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await {
                        tracing::debug!(error = %e, peer = %peer, "failed to write HTTP error response");
                    }
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
                    )
                    .await;
                    return;
                }
            };

            // Check Proxy-Authorization if configured
            if !route.http_user.is_empty() {
                let auth_ok = extract_proxy_auth(&request_text)
                    .map(|(u, p)| {
                        crate::constant_time_eq_str(&u, &route.http_user)
                            && crate::constant_time_eq_str(&p, &route.http_pwd)
                    })
                    .unwrap_or(false);
                if !auth_ok {
                    if let Err(e) = stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"frp\"\r\n\r\n",
                        )
                        .await
                    {
                        tracing::debug!(error = %e, peer = %peer, "failed to write HTTP error response");
                    }
                    return;
                }
            }

            // Send 200 only in non-passthrough mode (Go frp compat:
            // tcpmux/httpconnect.go sendConnectResponse).
            let pre_read = if state.tcp_mux_passthrough {
                // Passthrough: forward the full CONNECT request bytes
                // to the backend so it sees the original HTTP request.
                buf[..n].to_vec()
            } else {
                // Non-passthrough: send the 200 response.
                if let Err(e) = stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                {
                    debug!(peer = %peer, error = %e, "TCPMux: failed to write 200 to {}: {}", peer, e);
                    return;
                }
                Vec::new()
            };

            // Forward to the control handler for work connection bridging.
            let internal_tx = state
                .run_id_to_ctl_tx
                .get(&route.run_id)
                .map(|v| v.clone());

            if let Some(ctl_tx) = internal_tx {
                // send().await: backpressure is correct — a full control
                // channel must not silently drop a user connection (Go frp
                // blocks and lets the TCP backlog absorb the burst). This
                // runs in a per-connection spawned task, so the await is
                // free. A closed channel means the control handler died
                // between lookup and dispatch; the connection drops.
                if let Err(e) = ctl_tx
                    .tx
                    .send(InternalMsg::ProxyUserConn {
                        proxy_name: route.proxy_name.clone(),
                        user_conn: frp_core::transport::IoStream::Tcp(stream),
                        pre_read,
                        user_conn_permit: None,
                        // Local sender — no group selection was done.
                        group_selected: false,
                    })
                    .await
                {
                    warn!(host = %host, error = %e, "TCPMux: route for '{}' found but control channel closed", host);
                }
            } else {
                warn!(
                    host = %host,
                    "TCPMux: route for '{}' found but control handler gone",
                    host
                );
                if let Err(e) = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await {
                    tracing::debug!(error = %e, peer = %peer, "failed to write HTTP error response");
                }
            }
        });
            }
            _ = shutdown_token.cancelled() => {
                info!("TCPMux HTTP CONNECT listener shutting down");
                break;
            }
        }
    }
    Ok(())
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

/// Canonicalize a routing host (Go frp `CanonicalHost`,
/// pkg/util/http/http.go). Lowercasing happens in `lookup`; registration
/// is NOT canonicalized — a registered "example.com." is unroutable in Go
/// too (CanonicalHost applies at lookup only).
///
/// Port handling follows Go's `hasPort` gate: the port is split only when
/// the value has exactly one colon (host:port / IPv4:port) or is a
/// bracket-start with `]:` (bracketed IPv6). A split port must be numeric
/// — `net.SplitHostPort` rejects anything else and Go frp discards the
/// error, so "example.com:abc" is unroutable (caller replies 400).
/// Portless values are used as-is: "example.com", "[::1]" (stays
/// bracketed — nothing registers brackets, so it is unroutable), or
/// unbracketed multi-colon "::1:443". Then trim exactly one trailing dot
/// (Go TrimSuffix — one dot only, so "example.com.." stays unroutable).
fn canonicalize_host(host: &str) -> Option<&str> {
    let colons = host.bytes().filter(|b| *b == b':').count();
    let hostname = if colons == 1 {
        // host:port — the port must be numeric (SplitHostPort rejects
        // "example.com:abc" and "example.com:").
        let (h, port) = host.rsplit_once(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        h
    } else if colons >= 2 && host.starts_with('[') && host.contains("]:") {
        // Bracketed IPv6 with port: [::1]:443 → ::1. "[::1]" without a
        // "]:port" is portless in Go too (hasPort false) and stays
        // bracketed — unroutable.
        let end = host.find(']')?;
        let port = &host[end + 2..];
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        &host[1..end]
    } else {
        // No port: portless hostname, bracketed IPv6 without "]:", or
        // unbracketed multi-colon — Go leaves the value untouched.
        host
    };
    Some(trim_trailing_dot(hostname))
}

/// Strip exactly one trailing dot from a hostname (Go CanonicalHost's
/// `TrimSuffix(host, ".")`).
fn trim_trailing_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

/// Extract the Host header value from an HTTP request (hostname only, no
/// port, exactly one trailing dot trimmed — Go frp `CanonicalHost`).
fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        if line.len() < 6 {
            continue;
        }
        if !line[..5].eq_ignore_ascii_case("host:") {
            continue;
        }
        let value = line[5..].trim();
        return canonicalize_host(value);
    }
    None
}

/// Extract the routing host from a CONNECT request: the request-line
/// authority (CONNECT target) when present, else the Host header. Go
/// net/http ReadRequest sets `req.Host = req.URL.Host` and falls back to
/// the Host header only when the URL carries no host (RFC 7230 §5.3 —
/// "in the second case, any Host header is ignored"); for CONNECT the
/// authority is always present, so the header is effectively ignored.
/// The target goes through the same canonicalization (port-strip,
/// bracketed IPv6, trailing-dot trim). Returns None when the request
/// line is malformed or neither source is present (caller replies 400).
fn extract_route_host(request: &str) -> Option<&str> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    // Go net/http parseRequestLine requires "METHOD TARGET VERSION": a
    // 2-part line ("CONNECT HTTP/1.1", versionless "CONNECT
    // example.com:443") errors the whole ReadRequest regardless of any
    // Host header, so the connection is closed with 400. A bare-version
    // line must not route on the version string.
    if target.is_empty() || parts.next().is_none() || target.starts_with("HTTP/") {
        return None;
    }
    // Path-form targets ("GET /path") carry no URL host in Go — fall back
    // to the header (the caller rejects non-CONNECT upstream anyway). Same
    // for any non-"CONNECT" method: Go's justAuthority check is
    // case-sensitive, so a lowercase "connect" has no URL host and must
    // not route on the target.
    if method != "CONNECT" || target.starts_with('/') {
        return extract_host_header(request);
    }
    // Authority-form: req.Host = req.URL.Host (RFC 7230 §5.3 — any Host
    // header is ignored).
    canonicalize_host(target)
}

/// Extract Proxy-Authorization Basic credentials.
fn extract_proxy_auth(request: &str) -> Option<(String, String)> {
    let auth_line = request
        .lines()
        .find(|line| line.len() >= 20 && line[..20].eq_ignore_ascii_case("proxy-authorization:"))?;
    let value = auth_line[20..].trim();
    let encoded = if value.len() > 6 && value[..6].eq_ignore_ascii_case("Basic ") {
        value[6..].trim()
    } else {
        return None;
    };
    let decoded = frp_core::base64::decode(encoded).ok()?;
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
    fn test_extract_host_header_trailing_dot() {
        // Go CanonicalHost: port-strip first, then TrimSuffix one dot.
        let req = "CONNECT example.com.:443 HTTP/1.1\r\nHost: example.com.:443\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("example.com"));
        let req = "CONNECT example.com. HTTP/1.1\r\nHost: example.com.\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("example.com"));
        // Two trailing dots: only one is trimmed (Go TrimSuffix trims one).
        let req = "CONNECT example.com.. HTTP/1.1\r\nHost: example.com..\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("example.com."));
        // Bracketed IPv6 keeps its brackets-free form.
        let req = "CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("::1"));
    }

    #[test]
    fn test_extract_host_header_missing() {
        // No Host header: extraction itself returns None...
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_host_header(req), None);
        // ...but the routing host comes from the request-line authority
        // (Go net/http ReadRequest fills req.Host from req.URL.Host, so Go
        // routes Host-less CONNECTs), through the same canonicalization.
        assert_eq!(extract_route_host(req), Some("example.com"));
    }

    #[test]
    fn test_extract_route_host_authority_wins() {
        // CONNECT authority precedence (Go net/http ReadRequest fills
        // req.Host from req.URL.Host — RFC 7230 §5.3 "any Host header is
        // ignored"): port-strip, bracketed IPv6, trailing-dot trim.
        assert_eq!(
            extract_route_host("CONNECT example.com.:443 HTTP/1.1\r\n\r\n"),
            Some("example.com")
        );
        assert_eq!(
            extract_route_host("CONNECT [::1]:443 HTTP/1.1\r\n\r\n"),
            Some("::1")
        );
        // A conflicting Host header is ignored — the authority routes.
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: other.net\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("example.com"));
        // Path-form requests (rejected 405 upstream) carry no URL host in
        // Go — the header fallback applies.
        let req = "GET /path HTTP/1.1\r\nHost: foo.bar\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("foo.bar"));
    }

    #[test]
    fn test_extract_route_host_missing_both() {
        // Neither a Host header nor a request-line target: 400 stays. The
        // "CONNECT HTTP/1.1" line has no authority either — the second
        // token is the HTTP version, which must not be routed on.
        let req = "CONNECT HTTP/1.1\r\n\r\n";
        assert_eq!(extract_route_host(req), None);
        assert_eq!(extract_route_host(""), None);
    }

    #[test]
    fn test_extract_route_host_go_parity_edge_cases() {
        // Portless CONNECT authority routes fine (Go hasPort false → no
        // SplitHostPort).
        assert_eq!(
            extract_route_host("CONNECT example.com HTTP/1.1\r\n\r\n"),
            Some("example.com")
        );
        // Non-numeric port: net.SplitHostPort errors, Go frp discards the
        // CanonicalHost error → host "" → unroutable → 400.
        assert_eq!(
            extract_route_host("CONNECT example.com:abc HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            extract_route_host("CONNECT example.com: HTTP/1.1\r\n\r\n"),
            None
        );
        // Versionless request line: Go parseRequestLine needs 3 parts and
        // errors → 400, no routing on the Host header either.
        let req = "CONNECT example.com:443\r\nHost: other.net\r\n\r\n";
        assert_eq!(extract_route_host(req), None);
        // Lowercase method: Go justAuthority is case-sensitive → no URL
        // host → Host header fallback (the caller 405s non-"CONNECT").
        let req = "connect example.com:443 HTTP/1.1\r\nHost: header.net\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("header.net"));
        // Non-numeric port in the Host header fallback is unroutable too.
        let req = "CONNECT /path HTTP/1.1\r\nHost: example.com:abc\r\n\r\n";
        assert_eq!(extract_route_host(req), None);
        // Bracketed IPv6 without a port stays bracketed (hasPort false) —
        // unroutable, but not an error.
        let req = "CONNECT [::1] HTTP/1.1\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("[::1]"));
        // Bracketed IPv6 with a non-numeric port is unroutable.
        assert_eq!(
            extract_route_host("CONNECT [::1]:abc HTTP/1.1\r\n\r\n"),
            None
        );
    }

    #[test]
    fn test_extract_proxy_auth() {
        // "user:pass" in base64 = dXNlcjpwYXNz
        let req =
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
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

        mgr.register("p1", &["a.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("first registration must succeed");

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

    /// Go frp compat (pkg/util/vhost/router.go): tcpmux domains are stored
    /// lowercased at register and lookups lowercase the host, so a
    /// mixed-case customDomain must resolve for any casing. Conflict
    /// detection and unregister must also be case-insensitive.
    #[tokio::test]
    async fn test_tcpmux_register_lookup_case_insensitive() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["MixedCase.Example.com".into()],
            "run-1",
            "",
            "",
            &[],
        )
        .await
        .expect("registration must succeed");

        // Lookup must resolve for lowercase, uppercase, and the original
        // mixed case (Host header arrives verbatim from extract_host_header).
        for host in [
            "mixedcase.example.com",
            "MIXEDCASE.EXAMPLE.COM",
            "MixedCase.Example.com",
            "MixedCase.Example.com:443",
        ] {
            let r = mgr
                .lookup(host)
                .await
                .unwrap_or_else(|| panic!("lookup for '{host}' must resolve"));
            assert_eq!(r.proxy_name, "p1");
        }

        // A second proxy claiming the same domain in a different case must
        // be rejected as a conflict (Add checks the lowered key).
        let err = mgr
            .register(
                "p2",
                &["MIXEDCASE.EXAMPLE.COM".into()],
                "run-2",
                "",
                "",
                &[],
            )
            .await
            .expect_err("case-variant conflict must be rejected");
        assert!(
            err.contains("example.com"),
            "conflict must name the lowered domain: {err}"
        );

        // Unregister removes the route regardless of the original casing
        // (by_proxy bookkeeping holds the same lowered keys).
        mgr.unregister("p1").await;
        assert!(mgr.lookup("mixedcase.example.com").await.is_none());
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
            &[],
        )
        .await
        .expect("registration must succeed");

        assert!(mgr.lookup("a.example.com").await.is_some());
        assert!(mgr.lookup("b.example.com").await.is_some());
        assert!(mgr.lookup("c.example.com").await.is_none());

        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com").await.is_none());
        assert!(mgr.lookup("b.example.com").await.is_none());
    }

    /// Go frp v0.71.0 compat (vhost.Muxer → getByRoute): tcpmux lookup
    /// walks exact → leftmost-label wildcard (>=3 labels) → "*" catch-all.
    #[tokio::test]
    async fn test_tcpmux_lookup_wildcard_leftmost_label() {
        let mgr = TcpMuxManager::new();

        mgr.register("p1", &["*.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("registration must succeed");

        // Any host under the wildcard matches.
        assert!(mgr
            .lookup("a.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        assert!(mgr
            .lookup("a.b.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        // Two-label hosts never match the wildcard (Go's >=3-label guard
        // keeps `*.com` from matching `example.com`).
        assert!(mgr.lookup("example.com").await.is_none());
        // Unrelated suffixes stay misses.
        assert!(mgr.lookup("a.example.net").await.is_none());
    }

    #[tokio::test]
    async fn test_tcpmux_lookup_wildcard_catch_all() {
        let mgr = TcpMuxManager::new();
        mgr.register("p1", &["*".into()], "run-1", "", "", &[])
            .await
            .expect("catch-all registration must succeed");

        for host in [
            "anything.example.com",
            "example.com",
            "localhost",
            "localhost:8080",
        ] {
            assert!(
                mgr.lookup(host).await.is_some_and(|r| r.proxy_name == "p1"),
                "catch-all must match '{host}'"
            );
        }
    }

    #[tokio::test]
    async fn test_tcpmux_lookup_exact_beats_wildcard() {
        let mgr = TcpMuxManager::new();

        mgr.register("p1", &["a.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("exact registration must succeed");
        mgr.register("p2", &["*.example.com".into()], "run-2", "", "", &[])
            .await
            .expect("wildcard registration must succeed");

        // Exact match wins; the wildcard catches everything else under the
        // domain, including deeper hosts (leftmost-label walk).
        assert!(mgr
            .lookup("a.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        assert!(mgr
            .lookup("b.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p2"));
        assert!(mgr
            .lookup("x.y.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p2"));
    }

    /// Go CanonicalHost: lookup trims exactly one trailing dot, so
    /// "example.com." and "example.com.:443" route to "example.com"
    /// (registration is not canonicalized — a registered "example.com."
    /// stays unroutable, matching Go).
    #[tokio::test]
    async fn test_tcpmux_lookup_trailing_dot() {
        let mgr = TcpMuxManager::new();
        mgr.register("p1", &["example.com".into()], "run-1", "", "", &[])
            .await
            .expect("registration must succeed");

        assert!(mgr
            .lookup("example.com.")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        assert!(mgr
            .lookup("example.com.:443")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        // Two trailing dots: only one is trimmed → no route.
        assert!(mgr.lookup("example.com..").await.is_none());
    }

    /// Regression test for audit finding 5: a second proxy claiming an
    /// already-routed domain must be rejected, not silently overwrite the
    /// first registration (which previously let the closing proxy delete a
    /// live sibling's route).
    #[tokio::test]
    async fn test_tcpmux_manager_conflict_rejects_second_proxy() {
        let mgr = TcpMuxManager::new();

        mgr.register("p1", &["a.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("first registration must succeed");

        let err = mgr
            .register("p2", &["a.example.com".into()], "run-2", "", "", &[])
            .await
            .expect_err("conflicting domain must be rejected");
        assert!(
            err.contains("a.example.com"),
            "conflict must name the domain: {err}"
        );

        // The first proxy's route is intact; the second never registered.
        assert!(mgr
            .lookup("a.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));

        // Same-name re-registration is idempotent (allowed).
        mgr.register("p1", &["a.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("same-proxy re-registration must succeed");
        assert!(mgr
            .lookup("a.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
    }

    /// Regression test for audit finding 5: unregister must not delete a
    /// route that now belongs to a different proxy (defense-in-depth for
    /// stale by_proxy state from the pre-fix last-writer-wins behavior).
    #[tokio::test]
    async fn test_tcpmux_unregister_keeps_foreign_route() {
        let mgr = TcpMuxManager::new();

        mgr.register("p1", &["a.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("registration must succeed");

        // Simulate the pre-fix last-writer-wins state: the route now belongs
        // to p2, and p2's by_proxy entry also lists the domain.
        {
            let mut routes = mgr.routes.write().await;
            routes.insert(
                "a.example.com".to_string(),
                TcpMuxRoute {
                    proxy_name: "p2".to_string(),
                    run_id: "run-2".to_string(),
                    http_user: String::new(),
                    http_pwd: String::new(),
                },
            );
            mgr.by_proxy
                .write()
                .await
                .insert("p2".to_string(), vec!["a.example.com".to_string()]);
        }

        mgr.unregister("p1").await;
        assert!(
            mgr.lookup("a.example.com")
                .await
                .is_some_and(|r| r.proxy_name == "p2"),
            "p1's unregister must not delete p2's live route"
        );

        mgr.unregister("p2").await;
        assert!(mgr.lookup("a.example.com").await.is_none());
    }

    /// The wildcard fast-exit count stays symmetric across register,
    /// idempotent re-registration, a shrunken domain list (server reload),
    /// unregister, and a foreign-owned wildcard route.
    #[tokio::test]
    async fn test_tcpmux_wildcard_count_symmetry() {
        use std::sync::atomic::Ordering;
        let mgr = TcpMuxManager::new();

        // Register exact + wildcard: count 1.
        mgr.register(
            "p1",
            &["a.example.com".into(), "*.wild.example.com".into()],
            "run-1",
            "",
            "",
            &[],
        )
        .await
        .expect("registration must succeed");
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 1);

        // Same-name re-registration must not double-count.
        mgr.register(
            "p1",
            &["a.example.com".into(), "*.wild.example.com".into()],
            "run-1",
            "",
            "",
            &[],
        )
        .await
        .expect("idempotent re-registration must succeed");
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 1);

        // A wildcard lookup hits the registered route.
        assert!(mgr
            .lookup("x.wild.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));

        // Shrunken re-registration (server reload drops the wildcard):
        // the route and its count must leave the map.
        mgr.register("p1", &["a.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("shrunken re-registration must succeed");
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 0);
        assert!(mgr.lookup("x.wild.example.com").await.is_none());

        // unregister decrements on the route the proxy still owns.
        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com").await.is_none());

        // A wildcard route owned by a DIFFERENT proxy (legacy by_proxy
        // state) keeps both the route and the count through p1's
        // unregister.
        mgr.register("p1", &["*.shared.example.com".into()], "run-1", "", "", &[])
            .await
            .expect("registration must succeed");
        {
            let mut routes = mgr.routes.write().await;
            routes.insert(
                "*.shared.example.com".to_string(),
                TcpMuxRoute {
                    proxy_name: "p2".to_string(),
                    run_id: "run-2".to_string(),
                    http_user: String::new(),
                    http_pwd: String::new(),
                },
            );
        }
        mgr.unregister("p1").await;
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 1);
        assert!(mgr
            .lookup("x.shared.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "p2"));
    }
}
