use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::service::{AppState, InternalMsg};

/// HTTP/2 cleartext (h2c) vhost handling — see `vhost_h2c.rs`.
/// Only compiled when the `http-proxy` feature is enabled (audit round 5:
/// `h2` is now optional, so micro/tiny builds without vhosts skip it).
#[cfg(feature = "http-proxy")]
#[path = "vhost_h2c.rs"]
mod vhost_h2c;

/// A route mapping: domain or location -> proxy entry.
///
/// String fields are `Arc<str>` (refcounted) so that per-request route
/// matching can hand out clones without allocating: `VhostRouteMatch` bumps
/// the refcount instead of copying every `String`.
#[derive(Debug, Clone)]
pub struct VhostRoute {
    pub proxy_name: Arc<str>,
    pub run_id: Arc<str>,
    /// Scheme this route was registered under: "http" or "https". Go frp
    /// keeps SEPARATE router sets per muxer — HTTP proxies share
    /// `httpVhostRouter` (server/service.go:179) while HTTPS proxies
    /// register in their own Muxer's `registryRouter` (vhost/vhost.go:56-70)
    /// — so an HTTP proxy and an HTTPS proxy for the same domain never
    /// conflict in Go, and lookups never cross schemes: http.go routes by
    /// Host inside httpVhostRouter only, https.go by SNI inside the HTTPS
    /// Muxer's registryRouter only. frp-rs stores both schemes in one
    /// VhostTables, so the scheme partitions BOTH the conflict check and
    /// every lookup — find_matching_route only matches routes whose scheme
    /// equals the lookup's (HTTP call sites pass "http", SNI call sites
    /// "https"), so a plain HTTP request can never land on an HTTPS
    /// proxy's backend nor an SNI connection on an HTTP proxy's backend.
    pub scheme: String,
    /// Non-empty when this route belongs to an HTTP/HTTPS group (Go frp
    /// v0.71.0 HTTPGroup): requests are dispatched round-robin across the
    /// group's members instead of always to `proxy_name`. The route is
    /// created by the group's first member; `proxy_name`/`run_id` carry the
    /// first member's identity for fallback (e.g. route_by_http_user miss).
    pub group: Arc<str>,
    /// Location prefixes for this proxy (empty = host-only routing).
    pub locations: Vec<String>,
    /// Rewrite Host header to this value before forwarding (Go frp compat).
    pub host_header_rewrite: Arc<str>,
    /// HTTP Basic Auth credentials (empty = no auth).
    pub http_user: Arc<str>,
    pub http_pwd: Arc<str>,
    /// Per-user routing: extract username from Authorization header and route
    /// to proxy `{route_by_http_user}.{username}` (Go frp compat).
    pub route_by_http_user: Arc<str>,
    /// Request headers to inject before forwarding (Go frp compat:
    /// requestHeaders). Set semantics — override same-name headers.
    pub headers: Arc<Vec<(String, String)>>,
}

/// Borrowed match result — avoids cloning VhostRoute (especially the locations Vec)
/// on every HTTP request. Fields are owned `Arc<str>` because the caller holds them
/// across await points after the RwLock read guard is dropped; cloning the match is
/// an O(1) refcount bump per field rather than a String allocation.
#[derive(Debug, Clone)]
pub struct VhostRouteMatch {
    pub proxy_name: Arc<str>,
    pub run_id: Arc<str>,
    /// Non-empty when the matched route belongs to an HTTP group; the
    /// request must be dispatched round-robin across the group members.
    pub group: Arc<str>,
    pub host_header_rewrite: Arc<str>,
    pub http_user: Arc<str>,
    pub http_pwd: Arc<str>,
    pub route_by_http_user: Arc<str>,
    /// Request headers to inject before forwarding (Go frp requestHeaders).
    pub headers: Arc<Vec<(String, String)>>,
}

impl VhostRouteMatch {
    fn from_route(route: &VhostRoute) -> Self {
        Self {
            proxy_name: Arc::clone(&route.proxy_name),
            run_id: Arc::clone(&route.run_id),
            group: Arc::clone(&route.group),
            host_header_rewrite: Arc::clone(&route.host_header_rewrite),
            http_user: Arc::clone(&route.http_user),
            http_pwd: Arc::clone(&route.http_pwd),
            route_by_http_user: Arc::clone(&route.route_by_http_user),
            headers: Arc::clone(&route.headers),
        }
    }
}

/// Error returned when an exact (domain, route_by_http_user) route already exists.
/// Corresponds to Go frp's `ErrRouterConfigConflict`.
#[derive(Debug, Clone)]
pub struct RouterConfigConflict {
    pub domain: String,
    pub route_by_http_user: String,
    pub existing_proxy: String,
    pub incoming_proxy: String,
}

impl std::fmt::Display for RouterConfigConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "router config conflict for domain '{}' route_by_http_user '{}': proxy '{}' vs '{}'",
            self.domain, self.route_by_http_user, self.existing_proxy, self.incoming_proxy
        )
    }
}

impl std::error::Error for RouterConfigConflict {}

/// Find the first route in a sorted Vec whose scheme matches and whose
/// location prefix-matches the path.
/// If the route has no locations (e.g. HTTPS SNI routes), it matches any path.
/// The scheme filter mirrors Go's separate router sets (httpVhostRouter vs
/// the HTTPS Muxer's registryRouter): an HTTP lookup must never match an
/// HTTPS route and vice versa. Same-scheme first-match order is preserved —
/// within a scheme, the first route in the Go-sorted order wins.
fn find_matching_route(vrs: &[VhostRoute], path: &str, scheme: &str) -> Option<VhostRouteMatch> {
    for route in vrs {
        if route.scheme != scheme {
            continue;
        }
        if route.locations.is_empty() {
            return Some(VhostRouteMatch::from_route(route));
        }
        for loc in &route.locations {
            if path.starts_with(loc.as_str()) {
                return Some(VhostRouteMatch::from_route(route));
            }
        }
    }
    None
}

/// Find best matching route for a given host, path, httpUser, and scheme.
/// Corresponds to Go frp's `getLocked` + calls through `getExactOrAllUsersLocked`:
/// tries httpUser-specific routes first, then falls back to empty-string httpUser.
/// `scheme` is the route-scheme key ("http"/"https") — see find_matching_route.
fn get_locked(
    routes: &HashMap<String, HashMap<String, Vec<VhostRoute>>>,
    host: &str,
    path: &str,
    http_user: &str,
    scheme: &str,
) -> Option<VhostRouteMatch> {
    // Go frp compat (pkg/util/vhost/router.go): `Get` does
    // `strings.ToLower(host)` before lookup — domains are stored lowercased
    // at register, so a mixed-case Host/SNI must resolve case-insensitively.
    // Alloc-free ASCII fast path (Go's strings.ToLower avoids allocating for
    // all-lowercase input); Unicode case mapping can expand length (İ → "i̇")
    // vs Go's single-rune map, but real hostnames are IDNA/punycode ASCII —
    // divergence accepted.
    let lowered;
    let host_key: &str = if host.bytes().all(|b| !b.is_ascii_uppercase()) {
        host
    } else {
        lowered = host.to_lowercase();
        &lowered
    };
    let user_map = routes.get(host_key)?;
    // Try httpUser-specific first
    if let Some(vrs) = user_map.get(http_user) {
        if let Some(route) = find_matching_route(vrs, path, scheme) {
            return Some(route);
        }
    }
    // Fall back to empty-string httpUser (matching Go frp's all-users fallback)
    if let Some(vrs) = user_map.get("") {
        if let Some(route) = find_matching_route(vrs, path, scheme) {
            return Some(route);
        }
    }
    None
}

/// Sort a Vec<VhostRoute> the way Go frp's vhost router does
/// (`slices.SortFunc` with `-cmp.Compare(a.location, b.location)` in
/// pkg/util/vhost/router.go — lexicographic DESCENDING on the location).
///
/// Round 6 (A6): the old comparator keyed on location LENGTH. Length
/// sorting happens to agree with Go on single-location routes whose
/// locations overlap as prefixes, but diverges across routes: with
/// proxy A at "/aa" and proxy B at "/aa/bb/cc", Go tries "/aa/bb/cc"
/// first for path "/aa/bb/cc..." (routing to B), while length-sort also
/// puts B first — but for path "/aa/bb" Go's "/aa/bb/cc" misses and
/// "/aa" hits (→ A), whereas length-sort's B would then match its
/// shorter "/aa" first only if B were probed with that location; the
/// flattened Go order is exact, so we reproduce it: the comparator key
/// is the route's lexicographically-largest location — the first one Go
/// would try for that route — and prefix-match order (the only case
/// where ordering matters) then matches Go exactly. Empty-location
/// routes (HTTPS SNI) sort last, like Go's empty location string.
fn sort_by_longest_location(vrs: &mut [VhostRoute]) {
    vrs.sort_by(|a, b| {
        let a_max = a.locations.iter().max().map(|l| l.as_str()).unwrap_or("");
        let b_max = b.locations.iter().max().map(|l| l.as_str()).unwrap_or("");
        b_max.cmp(a_max) // lexicographic descending
    });
}

/// Internal tables held under a single RwLock.
struct VhostTables {
    /// domain -> { route_by_http_user -> Vec<VhostRoute> }
    /// Multiple routes per (domain, route_by_http_user) are allowed if they
    /// have different location prefixes (matching Go frp's `map[string]routerByHTTPUser`
    /// where each httpUser maps to a slice of Routers sorted by location descending).
    routes: HashMap<String, HashMap<String, Vec<VhostRoute>>>,
    /// proxy_name -> Vec<(domain, route_by_http_user)>
    by_proxy: HashMap<String, Vec<(String, String)>>,
}

/// Manages HTTP VHost routing table (domain + location -> proxy).
pub struct VhostManager {
    inner: RwLock<VhostTables>,
}

impl Default for VhostManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VhostManager {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(VhostTables {
                routes: HashMap::new(),
                by_proxy: HashMap::new(),
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        proxy_name: &str,
        domains: &[String],
        scheme: &str,
        locations: &[String],
        run_id: &str,
        host_header_rewrite: &str,
        http_user: &str,
        http_pwd: &str,
        route_by_http_user: &str,
        headers: &[(String, String)],
        group: &str,
    ) -> Result<(), RouterConfigConflict> {
        let route = VhostRoute {
            proxy_name: proxy_name.into(),
            run_id: run_id.into(),
            scheme: scheme.to_string(),
            group: group.into(),
            locations: locations.to_vec(),
            host_header_rewrite: host_header_rewrite.into(),
            http_user: http_user.into(),
            http_pwd: http_pwd.into(),
            route_by_http_user: route_by_http_user.into(),
            headers: Arc::new(headers.to_vec()),
        };

        let mut tables = self.inner.write().await;

        // Go frp compat (pkg/util/vhost/router.go): `Routers.Add` does
        // `strings.ToLower(domain)` — domains are stored lowercased, so
        // lookups are case-insensitive. Lowercase each domain ONCE, before
        // the conflict check, the routes insert, and the by_proxy
        // bookkeeping, keeping register/unregister symmetric (unregister
        // looks up by the same lowered key).
        //
        // Go buildDomains parity (server/proxy/proxy.go:218-229): empty
        // custom_domains entries are SKIPPED (`if d != ""`) — so
        // custom_domains=["",""] yields ZERO domains, the register loop
        // never runs, and the proxy is accepted (listening nothing). The
        // skip happens before lowercasing in Go; filtering here is
        // equivalent. An empty domains list also keeps the same-call
        // dedup from tripping on the ("","") duplicate.
        let domains: Vec<String> = domains
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| d.to_lowercase())
            .collect();

        // Effective location set for conflict checking. HTTPS/SNI (and the
        // tcpmux-mirroring) registrations pass an empty location list, but Go
        // registers them with location "" (`listenForDomain` → `Muxer.Listen`
        // → `Routers.Add(domain, "", routeByHTTPUser)`), so an empty list
        // means the single location "".
        let effective_locations: Vec<&str> = if locations.is_empty() {
            vec![""]
        } else {
            locations.iter().map(String::as_str).collect()
        };

        // A route registered with an empty location list covers ONLY the
        // location "" — Go stores the catch-all as `Router.location = ""`
        // and `exist()` compares `path == route.location` exactly. The
        // lookup-side "empty locations match any path" convenience
        // (find_matching_route) must not widen the conflict check.
        let route_covers = |vr: &VhostRoute, loc: &str| {
            (vr.locations.is_empty() && loc.is_empty()) || vr.locations.iter().any(|vl| vl == loc)
        };

        // Cross-call conflicts: each (domain, route_by_http_user, location)
        // triple must be unique against already-registered routes. Matching
        // Go's exist() which checks exact location match. The scheme
        // partitions the check: Go keeps separate router sets for HTTP and
        // HTTPS (shared httpVhostRouter vs per-muxer registryRouter), so an
        // HTTP and an HTTPS proxy for the same domain never conflict even
        // when both would land on effective location "".
        for domain in &domains {
            if let Some(user_map) = tables.routes.get(domain) {
                if let Some(vrs) = user_map.get(route_by_http_user) {
                    for loc in &effective_locations {
                        if let Some(vr) = vrs
                            .iter()
                            .find(|vr| vr.scheme == scheme && route_covers(vr, loc))
                        {
                            return Err(RouterConfigConflict {
                                domain: domain.clone(),
                                route_by_http_user: route_by_http_user.to_string(),
                                existing_proxy: vr.proxy_name.to_string(),
                                incoming_proxy: proxy_name.to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Same-call duplicate detection. Go's registration loops call
        // `Routers.Add` once per (domain, location, routeByHTTPUser) triple
        // (http.go:78-101, https.go:54-90, tcpmux.go:73-105) and buildDomains
        // (proxy.go:218-229) does NO dedup — so a triple that repeats WITHIN
        // one proxy's own domain list — a duplicate custom_domains entry,
        // subdomain expansion (`subDomain + "." + SubDomainHost`) colliding
        // with a custom_domains entry, or a case-only variant (Add
        // lowercases) — hits exist() on the second Add and REJECTS the whole
        // registration. The old proxy_ops `contains` guards made frp-rs more
        // lenient than Go; duplicates now flow through to this check.
        // route_by_http_user is registration-constant, so (domain, location)
        // is the full triple.
        let mut seen: HashSet<(&str, &str)> = HashSet::with_capacity(domains.len());
        for domain in &domains {
            for loc in &effective_locations {
                if !seen.insert((domain.as_str(), *loc)) {
                    return Err(RouterConfigConflict {
                        domain: domain.clone(),
                        route_by_http_user: route_by_http_user.to_string(),
                        existing_proxy: proxy_name.to_string(),
                        incoming_proxy: proxy_name.to_string(),
                    });
                }
            }
        }

        // Register domain routes: append to Vec; sort once after all inserts.
        let mut domain_entries = Vec::new();
        for domain in &domains {
            let vrs = tables
                .routes
                .entry(domain.clone())
                .or_default()
                .entry(route_by_http_user.to_string())
                .or_default();
            vrs.push(route.clone());
            domain_entries.push((domain.clone(), route_by_http_user.to_string()));
        }
        // Sort once after all domain insertions (was O(N) per registration).
        for domain in &domains {
            if let Some(user_map) = tables.routes.get_mut(domain) {
                if let Some(vrs) = user_map.get_mut(route_by_http_user) {
                    sort_by_longest_location(vrs);
                }
            }
        }
        if !domain_entries.is_empty() {
            tables
                .by_proxy
                .insert(proxy_name.to_string(), domain_entries);
        }

        Ok(())
    }

    pub async fn unregister(&self, proxy_name: &str) {
        let mut tables = self.inner.write().await;

        if let Some(entries) = tables.by_proxy.remove(proxy_name) {
            for (domain, rubu) in &entries {
                if let Some(user_map) = tables.routes.get_mut(domain) {
                    if let Some(vrs) = user_map.get_mut(rubu) {
                        // Remove ONLY the VhostRoute with this proxy_name, keeping
                        // other routes for the same (domain, rubu) pair.
                        vrs.retain(|r| r.proxy_name.as_ref() != proxy_name);
                        if vrs.is_empty() {
                            user_map.remove(rubu);
                        }
                    }
                    if user_map.is_empty() {
                        tables.routes.remove(domain);
                    }
                }
            }
        }
    }

    /// Look up by domain (exact match) with path prefix matching.
    /// Tries httpUser-specific routes first, then falls back to empty-string httpUser
    /// (matching Go frp's `getLocked` → `getExactOrAllUsersLocked`).
    /// `scheme` partitions the lookup like Go's separate router sets: pass
    /// "http" from HTTP request paths and "https" from SNI paths.
    pub async fn lookup(
        &self,
        domain: &str,
        path: &str,
        http_user: &str,
        scheme: &str,
    ) -> Option<VhostRouteMatch> {
        let tables = self.inner.read().await;
        get_locked(&tables.routes, domain, path, http_user, scheme)
    }

    /// Look up by domain with wildcard and path prefix support (Go frp dev compat).
    /// Tries exact match first, then progressively replaces the leftmost
    /// label with "*" (e.g. "a.b.c" → "*.b.c"), then tries the catch-all "*".
    ///
    /// For each candidate, calls get_locked which tries httpUser-specific routes
    /// first, then falls back to empty-string httpUser, and finds the first route
    /// whose location prefix-matches the given path (Go frp's getLocked pattern).
    ///
    /// Only checks wildcards for domains with >=3 labels (matching Go frp's
    /// `for len(hostSplit) >= 3` — prevents matching `*.com` for `example.com`).
    /// `scheme` partitions the lookup like Go's separate router sets: pass
    /// "http" from HTTP request paths and "https" from SNI paths.
    pub async fn lookup_wildcard(
        &self,
        domain: &str,
        path: &str,
        http_user: &str,
        scheme: &str,
    ) -> Option<VhostRouteMatch> {
        let tables = self.inner.read().await;

        // 1. Exact match
        if let Some(route) = get_locked(&tables.routes, domain, path, http_user, scheme) {
            return Some(route);
        }
        // 2. Replace leftmost label with "*" progressively.
        //    Only for domains with >=3 labels (matching Go's `for len(hostSplit) >= 3`).
        let mut parts: Vec<&str> = domain.split('.').collect();
        while parts.len() > 2 {
            parts[0] = "*";
            let wildcard_host = parts.join(".");
            if let Some(route) = get_locked(&tables.routes, &wildcard_host, path, http_user, scheme)
            {
                return Some(route);
            }
            parts.remove(0);
        }
        // 3. Catch-all "*"
        get_locked(&tables.routes, "*", path, http_user, scheme)
    }

    /// Combined lookup: domain match with wildcard expansion and location
    /// prefix matching (Go frp's getLocked/getByRoute pattern).
    /// `http_user` is the Basic Auth username from the request (empty if none).
    ///
    /// Round 10 (MEDIUM, Go parity): the path-only fallback was removed. Go
    /// registers HTTP proxies as `for domain { for location { register } }`
    /// (server/proxy/http.go:78-101) — a proxy with empty customDomains gets
    /// ZERO routes, and every location is always scoped under a domain. The
    /// host-agnostic `lookup_by_path` fallback let an authenticated client
    /// register `custom_domains=[]` + `locations=[""]` and capture every
    /// fallthrough request on the vhost port (the round-6 catch-all hijack
    /// recreated via the path table). Domain-scoped locations still work
    /// through `lookup_wildcard`'s get_locked path-matching.
    /// `scheme` partitions the lookup like Go's separate router sets: pass
    /// "http" from HTTP request paths and "https" from SNI paths.
    pub async fn lookup_combined(
        &self,
        domain: &str,
        path: &str,
        http_user: &str,
        scheme: &str,
    ) -> Option<VhostRouteMatch> {
        // Host-based routing with wildcard support and path matching.
        // lookup_wildcard internally calls get_locked which finds the first
        // route whose location prefix-matches the path.
        self.lookup_wildcard(domain, path, http_user, scheme).await
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
    // They are still logged at debug so a hung client that never reads the
    // error response remains observable in traces (audit-round4 H5).
    if custom_body.is_empty() {
        if let Err(e) = stream
            .write_all(format!("{status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await
        {
            tracing::debug!(error = %e, "failed to write HTTP error response");
        }
    } else {
        let body = custom_body.as_bytes();
        if let Err(e) = stream
            .write_all(
                format!(
                    "{status_line}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
        {
            tracing::debug!(error = %e, "failed to write HTTP error response header");
        }
        if let Err(e) = stream.write_all(body).await {
            tracing::debug!(error = %e, "failed to write HTTP error response body");
        }
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
    // Read the first 4096 bytes to extract Host header (with configured timeout)
    let timeout_secs = state.vhost_http_timeout.max(1);
    let mut buf = [0u8; 4096];
    let n = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };

    let pre_read = buf[..n].to_vec();

    // HTTP/2 prior-knowledge preface (h2c): binary frames, no text Host
    // header. The listener's single read may return a partial preface (TCP
    // can deliver fewer bytes), so a prefix match is completed before
    // dispatching to the h2 server path (Go's bufio-based h2 server waits
    // for all 24 preface bytes). `H2_PREFACE.starts_with(&pre_read)` covers
    // the short-prefix case; `pre_read.starts_with(H2_PREFACE)` the case
    // where frames arrived together with the preface.
    #[cfg(feature = "http-proxy")]
    {
        let is_h2 = pre_read.starts_with(vhost_h2c::H2_PREFACE)
            || (vhost_h2c::H2_PREFACE.starts_with(&pre_read) && n < vhost_h2c::H2_PREFACE.len());
        if is_h2 {
            // A short first read may be a partial HTTP/2 preface ("P", "PR",
            // "PRI"…) — read the remaining bytes and confirm the full 24-byte
            // preface before committing to the h2 path. A truncated HTTP/1.1
            // request (e.g. "POST …" cut to "P") falls back to the HTTP/1.1
            // parser (Go's bufio-based h2 server matches the exact line).
            let mut prefix_len = n;
            while prefix_len < vhost_h2c::H2_PREFACE.len() {
                let m = match tokio::time::timeout(
                    std::time::Duration::from_secs(timeout_secs),
                    stream.read(&mut buf[prefix_len..vhost_h2c::H2_PREFACE.len()]),
                )
                .await
                {
                    Ok(Ok(m)) if m > 0 => m,
                    _ => return,
                };
                prefix_len += m;
            }
            if buf[..vhost_h2c::H2_PREFACE.len()] == *vhost_h2c::H2_PREFACE {
                return vhost_h2c::serve_h2c_request(
                    stream,
                    buf[..prefix_len].to_vec(),
                    state,
                    peer,
                )
                .await;
            }
            return handle_http1_request(
                stream,
                buf[..prefix_len].to_vec(),
                state,
                peer,
                scheme,
                wrap,
            )
            .await;
        }
    }
    return handle_http1_request(stream, pre_read, state, peer, scheme, wrap).await;
}

/// HTTP/1.1 vhost path: finish reading the request head (up to 4096 bytes or
/// the \r\n\r\n terminator), extract Host/path/auth, resolve the route, and
/// forward the stream via InternalMsg::ProxyUserConn.
async fn handle_http1_request<S>(
    mut stream: S,
    mut pre_read: Vec<u8>,
    state: Arc<AppState>,
    peer: std::net::SocketAddr,
    scheme: &str,
    wrap: impl FnOnce(S) -> frp_core::transport::IoStream,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // The vhost listener's single read may be short (e.g. an h2c-misdetected
    // HTTP/1.1 request): keep reading until the head terminator or the cap.
    let timeout_secs = state.vhost_http_timeout.max(1);
    // Single absolute deadline for the whole head (audit fix): a slow-drip
    // client sending one byte per read window would otherwise stretch the
    // head read to 4096 × timeout. The whole head must arrive within
    // vhost_http_timeout, matching Go frp's connReadTimeout semantics.
    let head_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while pre_read.len() < 4096 && !pre_read.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buf = [0u8; 4096];
        let m = match tokio::time::timeout_at(head_deadline, stream.read(&mut buf)).await {
            Ok(Ok(m)) if m > 0 => m,
            _ => break,
        };
        pre_read.extend_from_slice(&buf[..m]);
    }

    // The head is capped at 4096 bytes. If the cap fills without the
    // \r\n\r\n terminator, respond 431 Request Header Fields Too Large
    // instead of forwarding a truncated head — forwarding it makes the
    // backend block waiting for the rest of the head, tying up a work-conn
    // slot (limited DoS on shared vhosts).
    if pre_read.len() >= 4096 && !pre_read.windows(4).any(|w| w == b"\r\n\r\n") {
        let resp = b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp).await;
        return;
    }

    // Parse the head text once, borrowing from the pre-read bytes (no full
    // copy — `into_owned()` would duplicate up to 4096 bytes per request).
    // `host`/`path` must still be owned Strings: `pre_read` is moved by
    // value into `resolve_vhost_request` below, so we cannot keep references
    // into it across that call.
    // Only the header block up to the first \r\n\r\n is parsed (audit fix):
    // bytes past the terminator are entity body or pipelined requests and
    // must not influence routing/auth — a body line like
    // "authorization: Basic ..." must not authenticate the request. Same
    // bound as inject_vhost_request_headers below.
    // Zero-allocation parse for the common ASCII case; fall back to lossy
    // replacement for non-UTF-8 heads. A 400 here would diverge from Go frp,
    // which tolerates obs-text (0x80-0xFF) bytes in header values.
    let head_end = pre_read
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(pre_read.len());
    let head = &pre_read[..head_end];
    let request_text_cow;
    let request_text: &str = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => {
            request_text_cow = String::from_utf8_lossy(head);
            &request_text_cow
        }
    };
    // Round 6 (A3/A4/A7): Go net/http request-line semantics — version
    // gates (malformed shape → 400, non-1.x → 505), absolute-form routing
    // (req.Host = req.URL.Host — Host header ignored), path minus query.
    let (host, path) = match parse_vhost_request_line(request_text) {
        RequestLine::Ok { host, path } => {
            let Some(host) = host else {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return;
            };
            (host.to_string(), path.to_string())
        }
        RequestLine::BadRequest => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        }
        RequestLine::VersionNotSupported => {
            let _ = stream
                .write_all(b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\n\r\n")
                .await;
            return;
        }
    };
    // RFC 7230 §5.4: a request with more than one Host header is invalid.
    // Go's net/http server (which Go frp uses for vhost routing) rejects
    // such requests with 400; forwarding duplicates verbatim would let a
    // second Host shadow the routed proxy's host_header_rewrite. Applies
    // to origin-form and absolute-form alike (Go's readRequest rejects
    // duplicate Host headers before either routing path).
    if count_host_headers(request_text) > 1 {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return;
    }

    // Parse Basic Auth once — reused for route matching, auth check,
    // and per-user routing (Go frp compat: getByRoute(host, path, username)).
    let http_auth = extract_basic_auth(request_text);

    debug!(host = %host, path = %path, peer = %peer, "{} VHost request for '{}' path '{}' from {}", scheme, host, path, peer);

    match resolve_vhost_request(
        &state,
        &host,
        &path,
        http_auth.as_ref(),
        pre_read,
        peer,
        scheme,
    )
    .await
    {
        Ok(forward) => {
            let internal_tx = state
                .run_id_to_ctl_tx
                .get(&forward.run_id)
                .map(|v| v.clone());
            if let Some(ctl_tx) = internal_tx {
                // send().await: backpressure is correct — a full control
                // channel must not silently drop a user connection (Go frp
                // blocks and lets the TCP backlog absorb the burst). This
                // runs in a per-connection spawned task, so the await is
                // free. Bounded (audit H3): a control handler that stops
                // draining must not pin this task + fd + permit forever;
                // after CTL_SEND_TIMEOUT the connection drops.
                match tokio::time::timeout(
                    crate::state::CTL_SEND_TIMEOUT,
                    ctl_tx.tx.send(InternalMsg::ProxyUserConn {
                        proxy_name: forward.proxy_name,
                        user_conn: wrap(stream),
                        pre_read: forward.request_head,
                        user_conn_permit: None,
                        // Local sender — no group selection was done.
                        group_selected: false,
                    }),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        // Channel closed: control handler died between lookup
                        // and dispatch; the connection drops.
                        warn!(host = %host, path = %path, "{} VHost route for '{}' path '{}' found but control channel closed", scheme, host, path);
                    }
                    Err(_elapsed) => {
                        warn!(host = %host, path = %path, "{} VHost route for '{}' path '{}' found but control channel send timed out; dropping conn", scheme, host, path);
                    }
                }
            } else {
                warn!(host = %host, path = %path, "{} VHost route for '{}' path '{}' found but control handler gone", scheme, host, path);
                write_http_error(&mut stream, "HTTP/1.1 502 Bad Gateway", "").await;
            }
        }
        Err(VhostResolveError::Unauthorized) => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"frp\"\r\n\r\n",
                )
                .await;
        }
        Err(VhostResolveError::NotFound) => {
            write_http_error(
                &mut stream,
                "HTTP/1.1 404 Not Found",
                &state.custom_404_page,
            )
            .await;
        }
    }
}

/// Result of resolving a vhost request: target proxy/run_id plus the
/// forwarded HTTP/1.1 request head (Host rewritten and requestHeaders /
/// X-Forwarded-For injected).
pub(crate) struct VhostForward {
    pub proxy_name: String,
    pub run_id: String,
    pub request_head: Vec<u8>,
}

/// Rejection reasons that map to a client-visible HTTP error.
#[derive(Debug)]
pub(crate) enum VhostResolveError {
    /// No route matched → 404.
    NotFound,
    /// HTTP Basic Auth failed → 401.
    Unauthorized,
}

/// Shared routing + header rewriting for HTTP/1.1 and h2c vhost requests.
///
/// Extracted from `serve_vhost_request`: looks up the route (domain/wildcard/
/// path + httpUser), enforces Basic Auth, applies per-user routing
/// (`route_by_http_user`), then rewrites the Host header and injects
/// X-Forwarded-For / requestHeaders into the forwarded head. The caller
/// renders rejection (404/401) or success (ProxyUserConn dispatch) in its own
/// protocol (HTTP/1.1 text vs HTTP/2 frames).
pub(crate) async fn resolve_vhost_request(
    state: &AppState,
    host: &str,
    path: &str,
    http_auth: Option<&(String, String)>,
    request_head: Vec<u8>,
    peer: std::net::SocketAddr,
    scheme: &str,
) -> Result<VhostForward, VhostResolveError> {
    let http_user = http_auth
        .as_ref()
        .map(|(u, _)| u.as_str())
        .unwrap_or_default();

    // Route-scheme key for the lookup. Routes are registered with lowercase
    // "http"/"https"; callers of resolve_vhost_request pass the scheme as a
    // log label ("HTTP"). The lookup must be scheme-partitioned — Go routes
    // plain-HTTP requests exclusively through httpVhostRouter, so they must
    // never match an HTTPS proxy's SNI route (which would bypass the HTTP
    // proxy's http_user/auth gate and land on the HTTPS backend).
    let scheme_key = if scheme.eq_ignore_ascii_case("http") {
        "http"
    } else {
        "https"
    };
    let Some(route) = state
        .vhost_manager
        .lookup_combined(host, path, http_user, scheme_key)
        .await
    else {
        warn!(host = %host, path = %path, peer = %peer, "No {} VHost route for '{}' path '{}' from {}", scheme, host, path, peer);
        return Err(VhostResolveError::NotFound);
    };

    // HTTP Basic Auth check (Go frp compat)
    if !route.http_user.is_empty() {
        let auth_ok = http_auth
            .map(|(u, p)| {
                crate::constant_time_eq_str(u, &route.http_user)
                    && crate::constant_time_eq_str(p, &route.http_pwd)
            })
            .unwrap_or(false);
        if !auth_ok {
            return Err(VhostResolveError::Unauthorized);
        }
    }

    // HTTP/HTTPS group routing (Go frp v0.71.0 HTTPGroup.chooseEndpoint):
    // when the matched route belongs to a group, pick a member round-robin.
    // The chosen member becomes the fallback target; route_by_http_user
    // (below) may override it with a user-specific proxy when configured.
    let (group_proxy_name, group_run_id) = if route.group.is_empty() {
        (route.proxy_name.to_string(), route.run_id.to_string())
    } else {
        match state.http_group_ctl.choose_endpoint(&route.group).await {
            Some(member) => match state.proxy_manager.get(&member).await {
                Some(info) => {
                    debug!(
                        host = %host, path = %path, group = %route.group, member = %member,
                        "{} VHost group '{}' -> member '{}'", scheme, route.group, member
                    );
                    (member, info.run_id.clone())
                }
                None => {
                    // Member gone between choose and lookup — fall back to
                    // the route's recorded proxy (first member).
                    warn!(
                        group = %route.group, member = %member,
                        "{} VHost: group member '{}' not registered, falling back to '{}'",
                        scheme, member, route.proxy_name
                    );
                    (route.proxy_name.to_string(), route.run_id.to_string())
                }
            },
            None => {
                // Group has no members (all unregistered) — route the
                // request to the first member anyway; the control dispatch
                // will fail cleanly if it is gone too.
                (route.proxy_name.to_string(), route.run_id.to_string())
            }
        }
    };

    // Per-user routing (Go frp compat): when route_by_http_user is set,
    // extract the Basic Auth username and look up proxy
    // `{route_by_http_user}.{username}` in the proxy manager.
    let (target_proxy_name, target_run_id) = if !route.route_by_http_user.is_empty() {
        if let Some((username, _password)) = http_auth {
            let user_proxy = format!("{}.{}", route.route_by_http_user, username);
            debug!(
                host = %host, route_by_http_user = %route.route_by_http_user,
                username = %username, user_proxy = %user_proxy,
                "{} VHost: trying user-based routing to '{}'", scheme, user_proxy
            );
            if let Some(user_info) = state.proxy_manager.get(&user_proxy).await {
                (user_proxy, user_info.run_id.clone())
            } else {
                // User-specific proxy not found — fall through to
                // the route's own proxy (matching Go frp behavior
                // when the target proxy doesn't exist).
                debug!(
                    user_proxy = %user_proxy,
                    "{} VHost: user-based proxy '{}' not found, falling back to '{}'",
                    scheme, user_proxy, group_proxy_name
                );
                (group_proxy_name, group_run_id)
            }
        } else {
            // No Authorization header — fall through to route's proxy.
            (group_proxy_name, group_run_id)
        }
    } else {
        (group_proxy_name, group_run_id)
    };

    // Apply host_header_rewrite if configured
    let request_head = if !route.host_header_rewrite.is_empty() {
        rewrite_host_header(request_head, &route.host_header_rewrite)
    } else {
        request_head
    };

    // Go frp compat (pkg/util/vhost/http.go reverse proxy): inject
    // X-Forwarded-For (append to existing value) and requestHeaders
    // (Set semantics) into the forwarded request head.
    let request_head = inject_vhost_request_headers(request_head, peer, route.headers.as_slice());

    Ok(VhostForward {
        proxy_name: target_proxy_name,
        run_id: target_run_id,
        request_head,
    })
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
                    // Release the semaphore permit before sleeping — the
                    // connection is being delayed, not accepted, so it must
                    // not hold a connection slot while we wait.
                    drop(permit);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                let state = state.clone();

                tokio::spawn(async move {
                    let _permit = permit;
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
///
/// Go frp compat (`pkg/util/vhost/https.go`): frps does NOT terminate TLS for
/// HTTPS vhosts. It reads only the ClientHello SNI, routes by SNI, and
/// forwards the original encrypted bytes (as pre_read) to the matching frpc
/// HTTPS proxy — the TLS session stays end-to-end between the user and the
/// backend.
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
                    // Release the semaphore permit before sleeping — the
                    // connection is being delayed, not accepted, so it must
                    // not hold a connection slot while we wait.
                    drop(permit);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                let state = state.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let timeout_secs = state.vhost_http_timeout.max(1);
                    // Read the TLS ClientHello (SNI lives in the first
                    // record; 4096 bytes comfortably covers it).
                    let mut buf = [0u8; 4096];
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_secs(timeout_secs),
                        read_client_hello_prefix(&mut stream, &mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return,
                    };
                    let pre_read = buf[..n].to_vec();

                    let Some(sni) = extract_sni_from_client_hello(&buf[..n]) else {
                        warn!(peer = %peer, "HTTPS VHost: no SNI in ClientHello from {}", peer);
                        return;
                    };
                    debug!(sni = %sni, peer = %peer, "HTTPS VHost SNI '{}' from {}", sni, peer);

                    // Route by SNI (host), path "/" (Go https.go getByRoute).
                    // Go frp lowercases the host before lookup (router.go
                    // `Get` → strings.ToLower), so a mixed-case SNI must
                    // resolve case-insensitively. get_locked is the sole
                    // routing lowercaser, so pass the raw SNI here — the
                    // debug/warn lines below log it case-preserved.
                    // Scheme "https": the HTTPS Muxer's registryRouter only
                    // (Go parity) — SNI must never match an HTTP route.
                    if let Some(route) = state
                        .vhost_manager
                        .lookup_combined(&sni, "/", "", "https")
                        .await
                    {
                        let internal_tx = state
                            .run_id_to_ctl_tx
                            .get(route.run_id.as_ref())
                            .map(|v| v.clone());
                        if let Some(ctl_tx) = internal_tx {
                            // send().await: same backpressure rationale as the
                            // HTTP vhost path — runs in a per-connection
                            // spawned task, so the await is free. Bounded
                            // (audit H3, same as the HTTP path above): a
                            // control handler that stops draining must not
                            // pin this task + fd + permit forever; after
                            // CTL_SEND_TIMEOUT the connection drops.
                            match tokio::time::timeout(
                                crate::state::CTL_SEND_TIMEOUT,
                                ctl_tx.tx.send(InternalMsg::ProxyUserConn {
                                    proxy_name: route.proxy_name.to_string(),
                                    // Passthrough: raw encrypted bytes, no TLS wrap.
                                    user_conn: frp_core::transport::IoStream::Tcp(stream),
                                    pre_read,
                                    user_conn_permit: None,
                                    // Local sender — no group selection was done.
                                    group_selected: false,
                                }),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    warn!(sni = %sni, "HTTPS VHost route for '{}' found but control channel closed", sni);
                                }
                                Err(_elapsed) => {
                                    warn!(sni = %sni, "HTTPS VHost route for '{}' found but control channel send timed out; dropping conn", sni);
                                }
                            }
                        } else {
                            warn!(sni = %sni, "HTTPS VHost route for '{}' found but control handler gone", sni);
                        }
                    } else {
                        warn!(sni = %sni, peer = %peer, "No HTTPS VHost route for '{}' from {}", sni, peer);
                    }
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

/// Read up to `buf.len()` bytes for the TLS ClientHello. Reads until we have
/// the full ClientHello record (content type 0x16 + TLS record header), or
/// the buffer is full, or EOF.
#[allow(dead_code)] // TLS/HTTPS vhost paths only; absent in the micro build
async fn read_client_hello_prefix<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    let n = stream.read(buf).await?;
    if n == 0 {
        return Ok(0);
    }
    // A ClientHello handshake record is: 0x16 | version(2) | len(2) | handshake...
    // If the first record is a full ClientHello and we already have it all,
    // stop reading (avoids blocking on a keep-alive connection).
    let record_len = if n >= 5 && buf[0] == 0x16 {
        (u16::from_be_bytes([buf[3], buf[4]]) as usize) + 5
    } else {
        0
    };
    if record_len > 0 && n >= record_len {
        return Ok(n);
    }
    if record_len > 0 && record_len <= buf.len() {
        let mut total = n;
        while total < record_len {
            let m = stream.read(&mut buf[total..record_len]).await?;
            if m == 0 {
                break;
            }
            total += m;
        }
        Ok(total)
    } else {
        Ok(n)
    }
}

#[cfg(not(feature = "tls"))]
pub async fn run_vhost_https_listener(
    _addr: String,
    _state: std::sync::Arc<crate::service::AppState>,
    _shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("TLS feature not enabled".into())
}

/// Outcome of parsing the HTTP request line with Go net/http semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestLine<'a> {
    /// host: None when no Host header is present (caller replies 400).
    Ok {
        host: Option<&'a str>,
        path: &'a str,
    },
    /// Malformed version shape or malformed absolute URL (Go 400).
    BadRequest,
    /// Non-HTTP/1.x version (Go 505 HTTP Version Not Supported).
    VersionNotSupported,
}

/// Parse the request line with Go net/http `readRequest` semantics for the
/// vhost path (round 6: A3/A4/A7, verified against Go 1.25.0 stdlib).
///
/// Version handling mirrors `ParseHTTPVersion` + `http1ServerSupportsRequest`:
/// - no version token (2-part line) → `VersionNotSupported`. Go's
///   `parseRequestLine` defaults a missing version to "HTTP/0.9", which
///   `http1ServerSupportsRequest` rejects (only major 1 passes, plus the
///   binary-h2 PRI preface this text path never sees) → 505;
/// - version not exactly 8 chars "HTTP/X.Y" with single digits
///   ("HTTP/1.10", "HTTP/1.x", "HTTP/11.0") → `BadRequest` (Go 400
///   "malformed HTTP version");
/// - "HTTP/0.x" / "HTTP/2.x" / "HTTP/9.9" → `VersionNotSupported` (505);
/// - "HTTP/1.x" → routed.
///
/// Host/path follow RFC 7230 §5.3 as implemented by `readRequest`: an
/// absolute-form target ("GET http://host/path HTTP/1.1") routes on the
/// URL authority — `req.Host = req.URL.Host`, ANY Host header is ignored —
/// with the URL path minus query; origin-form routes on the Host header
/// with the raw path minus query (Go `req.URL.Path` — query strings must
/// not influence location matching).
fn parse_vhost_request_line(request: &str) -> RequestLine<'_> {
    let first_line = request.lines().next().unwrap_or("");
    let mut parts = first_line.splitn(3, ' ');
    let _method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/0.9"); // Go: len(parts)<3 → HTTP/0.9

    // ParseHTTPVersion: exactly 8 chars "HTTP/X.Y", single digits.
    let valid_shape = version.len() == 8
        && version.starts_with("HTTP/")
        && version.as_bytes()[5].is_ascii_digit()
        && version.as_bytes()[6] == b'.'
        && version.as_bytes()[7].is_ascii_digit();
    if !valid_shape {
        return RequestLine::BadRequest;
    }
    // http1ServerSupportsRequest: only major 1 passes (PRI excluded).
    if version.as_bytes()[5] != b'1' {
        return RequestLine::VersionNotSupported;
    }

    // Absolute-form: "GET http://host[:port]/path?query HTTP/1.1".
    let scheme_len = if target.starts_with("http://") {
        Some(7)
    } else if target.starts_with("https://") {
        Some(8)
    } else {
        None
    };
    if let Some(scheme_len) = scheme_len {
        let rest = &target[scheme_len..];
        // Authority ends at the first '/', '?', or '#' (Go url.ParseRequestURI).
        let (authority, url_path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            // Go url.ParseRequestURI errors on a missing host → 400.
            return RequestLine::BadRequest;
        }
        let path = split_path_and_query(url_path);
        let path = if path.is_empty() { "/" } else { path };
        return RequestLine::Ok {
            host: Some(canonicalize_authority(authority)),
            path,
        };
    }

    // Origin-form: Host header + raw path minus query.
    RequestLine::Ok {
        host: extract_host_header(request),
        path: {
            let path = split_path_and_query(target);
            if path.is_empty() {
                "/"
            } else {
                path
            }
        },
    }
}

/// Strip the query/fragment from a URL path (Go `req.URL.Path` — vhost
/// routes match locations against the path only).
fn split_path_and_query(path: &str) -> &str {
    match path.find(['?', '#']) {
        Some(i) => &path[..i],
        None => path,
    }
}

/// Rewrite the Host header in an HTTP request's raw bytes.
/// Finds the first `Host:` or `host:` line and replaces it with the given value.
/// Byte-oriented to avoid mangling non-UTF-8 request data.
/// Returns a new Vec<u8> with the rewritten header. When no Host header is
/// present, the input is returned unchanged (ownership transferred, no copy).
fn rewrite_host_header(data: Vec<u8>, new_host: &str) -> Vec<u8> {
    // Only the header block up to the first \r\n\r\n is scanned (audit fix):
    // bytes past the terminator are entity body / pipelined requests and
    // must not be rewritten — a body containing "\r\nhost: evil" must never
    // be mutated, and a head without a Host header must not rewrite a body
    // line. Same bound as inject_vhost_request_headers.
    let head_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(data.len());
    let head = &data[..head_end];
    // Search for \r\nHost: anywhere in the head, plus first-line Host:
    let host_pos = {
        // First check if Host: is the very first header (no leading \r\n)
        let first_line = if head.len() >= 5 && head[..5].eq_ignore_ascii_case(b"host:") {
            Some(0)
        } else {
            None
        };
        // Then scan for \r\n followed by Host: anywhere
        first_line.or_else(|| {
            head.windows(7)
                .position(|w| w[..2] == *b"\r\n" && w[2..].eq_ignore_ascii_case(b"host:"))
                .map(|p| p + 2)
        })
    };

    let Some(host_start) = host_pos else {
        return data;
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

/// Inject `X-Forwarded-For` (append semantics, Go httputil.ReverseProxy) and
/// configured requestHeaders (Set semantics, Go `req.Header.Set`) into the
/// request head bytes. Only the header block up to `\r\n\r\n` is touched.
/// When no request headers are configured, the input is returned unchanged
/// (ownership transferred, no copy).
fn inject_vhost_request_headers(
    data: Vec<u8>,
    peer: std::net::SocketAddr,
    request_headers: &[(String, String)],
) -> Vec<u8> {
    if request_headers.is_empty() {
        return data;
    }
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(data.len());
    let head = &data[..header_end];
    let tail = &data[header_end..];

    // Collect header lines, dropping ones that request_headers will override
    // (case-insensitive Set semantics) and X-Forwarded-For (re-emitted with
    // the peer appended).
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut existing_xff: Vec<u8> = Vec::new();
    // Precompute override prefixes once (case-insensitive ASCII set semantics):
    // `format!("{}:", ...)` + `to_lowercase()` per header line per request is
    // wasted allocation — header names are ASCII.
    let override_prefixes: Vec<Vec<u8>> = request_headers
        .iter()
        .map(|(k, _)| {
            let mut p = k.as_bytes().to_ascii_lowercase();
            p.push(b':');
            p
        })
        .collect();
    for line in head.split_inclusive(|&b| b == b'\n') {
        let trimmed = line
            .strip_suffix(b"\n")
            .unwrap_or(line)
            .strip_suffix(b"\r")
            .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line));
        if trimmed.is_empty() {
            continue;
        }
        // Case-insensitive ASCII compare against the precomputed prefixes;
        // `[u8]::eq_ignore_ascii_case` is equivalent to lowercasing for
        // ASCII header names and avoids the per-line allocations.
        let is_override = override_prefixes
            .iter()
            .any(|p| trimmed.len() >= p.len() && trimmed[..p.len()].eq_ignore_ascii_case(p));
        if is_override {
            continue;
        }
        if trimmed
            .get(..16)
            .is_some_and(|t| t.eq_ignore_ascii_case(b"x-forwarded-for:"))
        {
            let value = match trimmed.iter().position(|&b| b == b':') {
                Some(i) => &trimmed[i + 1..],
                None => trimmed,
            };
            let value = value
                .iter()
                .position(|&b| b != b' ' && b != b'\t')
                .map(|i| &value[i..])
                .unwrap_or(value);
            if !value.is_empty() {
                existing_xff.extend_from_slice(value);
                existing_xff.extend_from_slice(b", ");
            }
            continue;
        }
        lines.push(line);
    }

    let mut out = Vec::with_capacity(data.len() + 64 + request_headers.len() * 24);
    for line in &lines {
        out.extend_from_slice(line);
    }
    // X-Forwarded-For: append peer (Go ReverseProxy appends to prior value).
    let mut xff = existing_xff;
    xff.extend_from_slice(peer.ip().to_string().as_bytes());
    out.extend_from_slice(b"X-Forwarded-For: ");
    out.extend_from_slice(&xff);
    out.extend_from_slice(b"\r\n");
    // Configured request headers. Sanitize names/values against CR/LF to
    // prevent HTTP header injection / request smuggling — same filter as the
    // response-header path in bridge.rs and the Host rewrite above. A header
    // whose name is empty after sanitization is dropped.
    for (k, v) in request_headers {
        let safe_k: String = k.chars().filter(|&c| c != '\r' && c != '\n').collect();
        let safe_v: String = v.chars().filter(|&c| c != '\r' && c != '\n').collect();
        if safe_k.is_empty() {
            continue;
        }
        out.extend_from_slice(safe_k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(safe_v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(tail);
    out
}

/// Extract HTTP Basic Auth credentials from the Authorization header.
/// Returns Some((username, password)) or None if no/invalid auth header.
fn extract_basic_auth(request: &str) -> Option<(String, String)> {
    let auth_line = request
        .lines()
        .find(|line| line.len() >= 14 && line[..14].eq_ignore_ascii_case("authorization:"))?;
    let value = auth_line[14..].trim();
    let encoded = value.strip_prefix("Basic ")?.trim();
    let decoded = frp_core::base64::decode(encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pwd) = creds.split_once(':')?;
    Some((user.to_string(), pwd.to_string()))
}

/// Count Host header lines (RFC 7230 §5.4 allows at most one). Must only be
/// called on the head (up to the first `\r\n\r\n`) — see `handle_http1_request`.
pub(crate) fn count_host_headers(request: &str) -> usize {
    // Skip the request line: it cannot carry a Host header (RFC 7230 §5.4),
    // and a request-target beginning with "host:" must not be miscounted.
    // Every later line whose name (before the first colon) equals "host"
    // counts — including an empty-valued "Host:" line, which Go net/http's
    // MIME-header parser also counts (audit-fix: empty-valued Host and
    // request-line "host:" edge cases). The name is deliberately NOT
    // trimmed: Go's canonicalMIMEHeaderKey preserves whitespace in the
    // field name (a space makes the name invalid and the whole line is
    // skipped), so "Host : x" and " Host: x" are not counted as Host by Go
    // either — and a leading-space obs-fold continuation line must not be
    // miscounted as a second Host header.
    request
        .lines()
        .skip(1)
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("host"))
        })
        .count()
}

/// Extract the Host header value from an HTTP request (hostname only,
/// exactly one trailing dot trimmed — Go frp `CanonicalHost`,
/// pkg/util/http/http.go). Port handling follows Go's `hasPort` gate: the
/// port is split only when the value has exactly one colon (host:port /
/// IPv4:port) or is a bracket-start with `]:` (bracketed IPv6), and the
/// port itself is never validated — `net.SplitHostPort` accepts any
/// suffix, so Go routes "Host: example.com:abc" to example.com (the
/// numeric gate exists only on the CONNECT request line via
/// url.ParseRequestURI's validOptionalPort). Portless values are used
/// as-is — "example.com", or "[::1]" which stays bracketed (unroutable,
/// nothing registers brackets).
/// Canonicalize an authority value (host[:port] or [v6]:port) for vhost
/// routing — port strip, bracket handling, exactly one trailing dot.
/// Go frp `CanonicalHost` semantics (pkg/util/http/http.go), shared by
/// the Host-header path and the absolute-form URL authority path (A3).
///
/// Round 6 (A5): the bracket branch now requires the ']' to be
/// immediately followed by ':'. Go `SplitHostPort` brackets the FIRST '['
/// to the LAST ']' ("[::1]x]:8080" → host "::1]x" — unroutable); accepting
/// the first ']' would route a malformed value as "::1" when that literal
/// is registered.
fn canonicalize_authority(value: &str) -> &str {
    let colons = value.bytes().filter(|b| *b == b':').count();
    let hostname = if colons == 1 {
        // host:port — SplitHostPort never validates the port digits
        // (Go frp routes "Host: example.com:abc" to example.com); the
        // digit gate exists only on the CONNECT request line, where
        // url.ParseRequestURI enforces it (validOptionalPort).
        let (h, _port) = value.rsplit_once(':').unwrap_or((value, ""));
        h
    } else if colons >= 2 && value.starts_with('[') && value.contains("]:") {
        let end = value.find(']').unwrap_or(0);
        if !value[end + 1..].starts_with(':') {
            // ']' not immediately followed by ':' — not a bracket form.
            // Go routes the raw value (unroutable → 404); mirror that
            // rather than 400ing (the header path has no 400 trigger).
            value
        } else {
            &value[1..end]
        }
    } else {
        // No port: portless hostname, bracketed IPv6 without "]:", or
        // unbracketed multi-colon — Go leaves the value untouched.
        value
    };
    // Strip exactly one trailing dot from FQDNs (Go TrimSuffix — one
    // dot only, so "example.com.." stays unroutable; registration is
    // not canonicalized, so a user-registered "example.com." is
    // unroutable in Go too).
    hostname.strip_suffix('.').unwrap_or(hostname)
}

fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        if line.len() < 6 {
            continue;
        }
        if !line[..5].eq_ignore_ascii_case("host:") {
            continue;
        }
        let value = line[5..].trim();
        return Some(canonicalize_authority(value));
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

    /// A body line that looks like a Host header must never be rewritten
    /// when the head has no Host of its own (audit fix: the scan was
    /// previously unbounded and mutated bytes after \r\n\r\n).
    #[test]
    fn test_rewrite_host_header_does_not_touch_body() {
        let data = b"GET / HTTP/1.1\r\n\r\nbody\r\nhost: evil.example.com".to_vec();
        let out = rewrite_host_header(data.clone(), "good.example.com");
        assert_eq!(out, data, "head without Host must not rewrite a body line");

        let data = b"GET / HTTP/1.1\r\nHost: old.example.com\r\n\r\nbody\r\nhost: evil.example.com"
            .to_vec();
        let out = rewrite_host_header(data, "new.example.com");
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with(
                "GET / HTTP/1.1\r\nHost: new.example.com\r\n\r\nbody\r\nhost: evil.example.com"
            ),
            "only the head's Host may be rewritten: {text:?}"
        );
    }

    /// Go frp CanonicalHost parity: port-strip, then TrimSuffix exactly one
    /// trailing dot, before the vhost lookup ("example.com." and
    /// "example.com" route identically; registration is not canonicalized,
    /// so a user-registered "example.com." is unroutable in Go too).
    #[test]
    fn test_extract_host_header_trailing_dot() {
        assert_eq!(
            extract_host_header("GET / HTTP/1.1\r\nHost: example.com.:8080\r\n\r\n"),
            Some("example.com")
        );
        assert_eq!(
            extract_host_header("GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n"),
            Some("example.com")
        );
        // Two trailing dots: only one is trimmed (Go TrimSuffix trims one).
        assert_eq!(
            extract_host_header("GET / HTTP/1.1\r\nHost: example.com..\r\n\r\n"),
            Some("example.com.")
        );
        // Bracketed IPv6 hosts are untouched.
        assert_eq!(
            extract_host_header("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n"),
            Some("::1")
        );
    }

    #[test]
    fn test_count_host_headers() {
        let single = "GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n";
        assert_eq!(count_host_headers(single), 1);
        let dup = "GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n";
        assert_eq!(count_host_headers(dup), 2);
        let none = "GET / HTTP/1.1\r\nX-Foo: bar\r\n\r\n";
        assert_eq!(count_host_headers(none), 0);
        // The caller bounds the text to the head (up to \r\n\r\n); given a
        // bounded head, a body "host:" line is simply not present.
        assert_eq!(count_host_headers("GET / HTTP/1.1\r\n\r\n"), 0);
        // Unbounded text (caller bug) would count body lines — the caller's
        // head-bounding in handle_http1_request is what prevents this.
        assert_eq!(count_host_headers("GET / HTTP/1.1\r\n\r\nhost: x"), 1);
        // An empty-valued Host line is still a Host header (Go net/http
        // counts it — audit-fix edge case).
        assert_eq!(count_host_headers("GET / HTTP/1.1\r\nHost:\r\n\r\n"), 1);
        // A request-target beginning with "host:" is not a header
        // (audit-fix edge case); the real Host header still counts.
        assert_eq!(
            count_host_headers("host: evil\r\nHost: good.example.com\r\n\r\n"),
            1
        );
        assert_eq!(count_host_headers("host: evil\r\n\r\n"), 0);
        // Whitespace in the field name is NOT tolerated — Go's
        // canonicalMIMEHeaderKey preserves it, so "Host : x" is an invalid
        // name and the line is skipped by Go's MIME-header parser too.
        assert_eq!(count_host_headers("GET / HTTP/1.1\r\nHost : x\r\n\r\n"), 0);
        // A leading-space obs-fold continuation line is part of the
        // previous header's value, never a second Host header.
        assert_eq!(
            count_host_headers(
                "GET / HTTP/1.1\r\nHost: a.example.com\r\n Host: b.example.com\r\n\r\n"
            ),
            1
        );
    }

    #[test]
    fn test_parse_vhost_request_line_versions() {
        // A7: 2-token line → HTTP/0.9 → 505 (Go http1ServerSupportsRequest).
        assert_eq!(
            parse_vhost_request_line("GET /"),
            RequestLine::VersionNotSupported
        );
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/0.9"),
            RequestLine::VersionNotSupported
        );
        // Shape malformed → 400 (Go ParseHTTPVersion 8-char rule).
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/1.10"),
            RequestLine::BadRequest
        );
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/1.x"),
            RequestLine::BadRequest
        );
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/11.0"),
            RequestLine::BadRequest
        );
        // Non-1.x text versions → 505 (PRI excluded — binary h2 preface).
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/2.0"),
            RequestLine::VersionNotSupported
        );
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/9.9"),
            RequestLine::VersionNotSupported
        );
        // HTTP/1.x routes.
        let RequestLine::Ok { host, path } =
            parse_vhost_request_line("GET /abc HTTP/1.1\r\nHost: x.example.com\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("x.example.com"));
        assert_eq!(path, "/abc");
    }

    #[test]
    fn test_parse_vhost_request_line_absolute_form() {
        // A3/A4: absolute-form routes on the URL authority; ANY Host
        // header is ignored (RFC 7230 §5.3, req.Host = req.URL.Host).
        let RequestLine::Ok { host, path } = parse_vhost_request_line(
            "GET http://a.example.com:8080/api?x=1 HTTP/1.1\r\nHost: ignored.example.com\r\n\r\n",
        ) else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com")); // port stripped
        assert_eq!(path, "/api"); // query stripped, Go req.URL.Path
                                  // Absolute-form with no path → "/".
        let RequestLine::Ok { path, .. } =
            parse_vhost_request_line("GET http://a.example.com HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(path, "/");
        // Malformed absolute URL (empty authority) → 400.
        assert_eq!(
            parse_vhost_request_line("GET http:///x HTTP/1.1\r\nHost: x\r\n\r\n"),
            RequestLine::BadRequest
        );
        assert_eq!(
            parse_vhost_request_line("GET http:// HTTP/1.1\r\nHost: x\r\n\r\n"),
            RequestLine::BadRequest
        );
        // Bracketed IPv6 authority.
        let RequestLine::Ok { host, .. } =
            parse_vhost_request_line("GET https://[::1]:8080/ HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("::1"));
        // A5: mis-bracketed authority stays unroutable, never "::1".
        let RequestLine::Ok { host, .. } =
            parse_vhost_request_line("GET http://[::1]x]:8080/ HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("[::1]x]:8080"));
    }

    #[test]
    fn test_parse_vhost_request_line_origin_form_query() {
        // A4: origin-form path minus query (Go req.URL.Path) — query
        // strings must not influence location matching.
        let RequestLine::Ok { host, path } = parse_vhost_request_line(
            "GET /api/v1?user=admin#frag HTTP/1.1\r\nHost: a.example.com:8080\r\n\r\n",
        ) else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com"));
        assert_eq!(path, "/api/v1");
        // Missing Host header → Ok with host None (caller 400s).
        let RequestLine::Ok { host, .. } = parse_vhost_request_line("GET / HTTP/1.1\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, None);
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

    /// Go frp compat (pkg/util/vhost/router.go): domains are stored
    /// lowercased at register (`Routers.Add` → strings.ToLower) and lookups
    /// lowercase the host (`Get` → strings.ToLower), so a mixed-case
    /// customDomain must resolve for any casing. Conflict detection and
    /// unregister must also be case-insensitive (same lowered keys).
    #[tokio::test]
    async fn test_vhost_register_lookup_case_insensitive() {
        let mgr = VhostManager::new();

        // Same shared location on both registrations so the (domain, rubu,
        // location) triple conflict check fires — like Go's exist() with
        // `location == "/"`.
        mgr.register(
            "p1",
            &["MixedCase.Example.com".into()],
            "http",
            &["/".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("registration must succeed");

        // Lookup must resolve for lowercase, uppercase, and the original
        // mixed case (Host header arrives verbatim from extract_host_header).
        for host in [
            "mixedcase.example.com",
            "MIXEDCASE.EXAMPLE.COM",
            "MixedCase.Example.com",
        ] {
            let route = mgr
                .lookup(host, "/", "", "http")
                .await
                .unwrap_or_else(|| panic!("lookup for '{host}' must resolve"));
            assert_eq!(route.proxy_name.as_ref(), "p1");
        }

        // A second proxy claiming the same domain in a different case must
        // be rejected as a conflict (Go frp: Add lowercases then exist()).
        let err = mgr
            .register(
                "p2",
                &["MIXEDCASE.EXAMPLE.COM".into()],
                "http",
                &["/".into()],
                "run-2",
                "",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("case-variant conflict must be rejected");
        assert!(
            err.to_string().contains("example.com"),
            "conflict must name the lowered domain: {err}"
        );

        // Unregister removes the route regardless of the original casing
        // (by_proxy bookkeeping holds the same lowered keys).
        mgr.unregister("p1").await;
        assert!(mgr
            .lookup("mixedcase.example.com", "/", "", "http")
            .await
            .is_none());
    }

    /// Go frp parity (round 8): buildDomains does no dedup, so a duplicate
    /// custom_domains entry produces a repeated (domain, location,
    /// routeByHTTPUser) triple WITHIN one registration — Go's registration
    /// loop hits ErrRouterConfigConflict on the second Routers.Add and
    /// rejects the whole proxy. The old proxy_ops `contains` guards were
    /// more lenient than Go.
    #[tokio::test]
    async fn test_vhost_register_same_call_duplicate_domain_rejected() {
        let mgr = VhostManager::new();
        let err = mgr
            .register(
                "p1",
                &["a.example.com".into(), "a.example.com".into()],
                "http",
                &["/".into()],
                "run-1",
                "",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("duplicate custom_domains entry must be a config conflict");
        assert!(
            err.to_string().contains("a.example.com"),
            "conflict must name the duplicated domain: {err}"
        );
        // Nothing was inserted — no half-registered route.
        assert!(mgr.lookup("a.example.com", "/", "", "http").await.is_none());
    }

    /// Go parity: Routers.Add lowercases before exist(), so a case-only
    /// variant of an earlier entry in the same registration is a duplicate
    /// and rejects the registration (custom_domains "a.example.com" +
    /// "A.example.com").
    #[tokio::test]
    async fn test_vhost_register_same_call_case_variant_rejected() {
        let mgr = VhostManager::new();
        let err = mgr
            .register(
                "p1",
                &["a.example.com".into(), "A.EXAMPLE.COM".into()],
                "http",
                &["/".into()],
                "run-1",
                "",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("case-only duplicate must be a config conflict");
        assert!(
            err.to_string().contains("a.example.com"),
            "conflict must name the lowered domain: {err}"
        );
    }

    /// Go parity: the registration loop is `for domain { for location { Add } }`,
    /// so a duplicate domain repeats every (domain, location) triple — the
    /// second domain iteration conflicts even when locations differ.
    #[tokio::test]
    async fn test_vhost_register_duplicate_domain_with_multi_locations_rejected() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["d.example.com".into(), "d.example.com".into()],
            "http",
            &["/".into(), "/api".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect_err("duplicate domain × locations must conflict on the second domain");
    }

    /// Go parity: distinct (domain, location) triples within one
    /// registration are legal — one domain with several locations registers
    /// each as its own Router (http.go `for _, location := range locations`).
    #[tokio::test]
    async fn test_vhost_register_same_domain_different_locations_accepted() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["example.com".into()],
            "http",
            &["/".into(), "/api".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("one domain with distinct locations must register");
        let r = mgr
            .lookup("example.com", "/api/users", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
        let r = mgr
            .lookup("example.com", "/other", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
    }

    /// Go parity: HTTPS registration passes location "" (https.go
    /// listenForDomain → Muxer.Listen → Routers.Add(domain, "", ...)), so a
    /// duplicate domain WITHIN one HTTPS registration (duplicate
    /// custom_domains entry, or subdomain expansion colliding with a custom
    /// domain) repeats the (domain, "") SNI triple and rejects.
    #[tokio::test]
    async fn test_vhost_register_https_same_call_duplicate_domain_rejected() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["tls.example.com".into(), "tls.example.com".into()],
            "https",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect_err("HTTPS duplicate SNI domain must be a config conflict");
    }

    /// Go parity: HTTPS (empty locations = location "") also conflicts
    /// ACROSS registrations — two HTTPS proxies with the same domain are
    /// rejected by the muxer's Routers.Add (previously frp-rs skipped the
    /// conflict check entirely for empty-location registrations, letting
    /// the first proxy silently win).
    #[tokio::test]
    async fn test_vhost_register_https_cross_call_duplicate_domain_rejected() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["tls.example.com".into()],
            "https",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("first HTTPS registration must succeed");
        let err = mgr
            .register(
                "p2",
                &["tls.example.com".into()],
                "https",
                &[],
                "run-2",
                "",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("second HTTPS proxy claiming the same SNI domain must be rejected");
        assert!(
            err.to_string().contains("p1"),
            "conflict must name the existing proxy: {err}"
        );
        // The first route survives (scheme "https" — SNI lookup).
        let r = mgr
            .lookup("tls.example.com", "", "", "https")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
    }

    /// Go parity: a location-less (catch-all) route is registered with
    /// location "", so it conflicts with a new HTTPS (location "") route on
    /// the same domain — but NOT with a location-scoped HTTP route.
    #[tokio::test]
    async fn test_vhost_register_catch_all_location_conflict_parity() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["c.example.com".into()],
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("catch-all registration must succeed");
        // Location-scoped route on the same domain is a distinct triple.
        mgr.register(
            "p2",
            &["c.example.com".into()],
            "http",
            &["/".into()],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("location-scoped route must coexist with the catch-all");
        // A second location-less route is the same (domain, "") triple.
        mgr.register(
            "p3",
            &["c.example.com".into()],
            "http",
            &[],
            "run-3",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect_err("second location-less route must conflict with the catch-all");
    }

    /// Go parity: HTTP and HTTPS vhost routes live in SEPARATE router sets
    /// in Go frp — HTTP proxies share `httpVhostRouter`
    /// (server/service.go:179), HTTPS proxies register in their own Muxer's
    /// `registryRouter` (vhost/vhost.go:56-70) — so an HTTP proxy and an
    /// HTTPS proxy for the SAME domain never conflict, whatever their
    /// locations. frp-rs stores both schemes in one VhostTables, so the
    /// scheme partitions the cross-call conflict check (round-10 regression:
    /// both defaulted to effective location "" and cross-rejected a pair Go
    /// accepts).
    #[tokio::test]
    async fn test_vhost_http_https_same_domain_both_accepted() {
        let mgr = VhostManager::new();
        mgr.register(
            "http-p",
            &["example.com".into()],
            "http",
            &["/a".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTP registration must succeed");
        mgr.register(
            "https-p",
            &["example.com".into()],
            "https",
            &[],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTPS registration for the same domain must not conflict with the HTTP route");
    }

    /// The scheme partition must hold even when BOTH registrations land on
    /// effective location "" (empty locations list → [""]) — pre-diff this
    /// pair was cross-rejected as a duplicate (domain, "", "") triple,
    /// while Go accepts it (separate router sets).
    #[tokio::test]
    async fn test_vhost_http_https_same_effective_location_accepted() {
        let mgr = VhostManager::new();
        mgr.register(
            "http-p",
            &["same.example.com".into()],
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTP catch-all registration must succeed");
        mgr.register(
            "https-p",
            &["same.example.com".into()],
            "https",
            &[],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTPS registration must not conflict with the HTTP catch-all");
    }

    /// Regression (round-12 MEDIUM): the conflict check is scheme-partitioned
    /// (HTTP and HTTPS proxies for the same domain both register), and the
    /// LOOKUPS must be too — Go routes HTTP requests through httpVhostRouter
    /// and SNI through the HTTPS Muxer's registryRouter, so the two routes
    /// are independently reachable and never cross. Pre-fix the lookups were
    /// scheme-blind: find_matching_route returned whichever route came first,
    /// so a plain HTTP request could be routed to the HTTPS proxy's backend
    /// (bypassing the HTTP proxy's http_user/401 gate) and an SNI lookup
    /// could pick the HTTP route.
    #[tokio::test]
    async fn test_vhost_http_https_same_domain_scheme_partitioned_lookup() {
        let mgr = VhostManager::new();
        // HTTP proxy on the shared domain with a Basic Auth gate...
        mgr.register(
            "http-p",
            &["example.com".into()],
            "http",
            &["/".into()],
            "run-1",
            "",
            "alice",
            "secret",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTP registration must succeed");
        // ...and an HTTPS (SNI) proxy for the SAME domain.
        mgr.register(
            "https-p",
            &["example.com".into()],
            "https",
            &[],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTPS registration for the same domain must succeed");

        // HTTP lookup (scheme "http") must land on the HTTP backend only —
        // never on the HTTPS route.
        let r = mgr.lookup("example.com", "/", "", "http").await.unwrap();
        assert_eq!(r.proxy_name.as_ref(), "http-p");
        // The HTTP route carries the auth gate (http_user), so a request
        // routed to it can still be 401'd — the cross-scheme bug would have
        // handed the same request to the HTTPS backend with no gate.
        assert_eq!(r.http_user.as_ref(), "alice");
        // SNI lookup (scheme "https") must land on the HTTPS backend only.
        let r = mgr.lookup("example.com", "/", "", "https").await.unwrap();
        assert_eq!(r.proxy_name.as_ref(), "https-p");
        // The wildcard/combined paths partition identically.
        let r = mgr
            .lookup_wildcard("example.com", "/", "", "https")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "https-p");
        let r = mgr
            .lookup_combined("example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "http-p");

        // Unregistering one scheme's route leaves the other reachable.
        mgr.unregister("http-p").await;
        assert!(
            mgr.lookup("example.com", "/", "", "http").await.is_none(),
            "HTTP route must be gone"
        );
        let r = mgr.lookup("example.com", "/", "", "https").await.unwrap();
        assert_eq!(r.proxy_name.as_ref(), "https-p");
    }

    /// Within one scheme, the (domain, route_by_http_user, location) triple
    /// stays unique: a second HTTP proxy with the same domain and same
    /// location is rejected (Go httpVhostRouter Routers.Add exist()).
    #[tokio::test]
    async fn test_vhost_http_same_domain_same_location_conflict() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["dup.example.com".into()],
            "http",
            &["/".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("first HTTP registration must succeed");
        let err = mgr
            .register(
                "p2",
                &["dup.example.com".into()],
                "http",
                &["/".into()],
                "run-2",
                "",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("second HTTP proxy with the same domain+location must conflict");
        assert!(
            err.to_string().contains("p1"),
            "conflict must name the existing proxy: {err}"
        );
    }

    /// Go buildDomains parity (server/proxy/proxy.go:218-229): empty-string
    /// custom_domains entries are skipped (`if d != ""`), so
    /// custom_domains=["",""] produces ZERO domains, the register loop
    /// never runs, and the proxy is ACCEPTED (listening nothing) — for both
    /// HTTP and HTTPS. The registration must not trip the same-call dedup
    /// on the ("","") duplicate, and nothing must be routable for "".
    #[tokio::test]
    async fn test_vhost_empty_custom_domains_accepted() {
        let mgr = VhostManager::new();
        mgr.register(
            "http-p",
            &["".into(), "".into()],
            "http",
            &["/".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("HTTP custom_domains=[\"\",\"\"] must be accepted (Go buildDomains skips empties)");
        mgr.register(
            "https-p",
            &["".into(), "".into()],
            "https",
            &[],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect(
            "HTTPS custom_domains=[\"\",\"\"] must be accepted (Go buildDomains skips empties)",
        );
        // Zero domains registered — nothing resolves for "".
        assert!(mgr.lookup("", "/", "", "http").await.is_none());
        assert!(mgr.lookup_combined("", "/", "", "http").await.is_none());
        // A real domain must not resolve to either proxy either (zero
        // routes were inserted, not just ""-keyed ones).
        assert!(mgr.lookup("example.com", "/", "", "http").await.is_none());
    }

    /// Minimal AppState for routing-only tests (mirrors state.rs test_state).
    fn test_app_state() -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
            frp_core::auth::AuthConfig::with_token("test-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("test-token"),
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
            String::new(),
            true,
            30,
            7200,
            0,
            0,
            90,
            1500,
            false,
            None,
            0,
            60,
            10,
            false,
            String::new(),
            Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
            0,
            0,
            168,
            true,
            0,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    /// Hand-built VhostRoute for find_matching_route / sort_by_longest_location.
    fn route(name: &str, locations: &[String]) -> VhostRoute {
        VhostRoute {
            proxy_name: name.into(),
            run_id: "run".into(),
            scheme: "http".into(),
            group: "".into(),
            locations: locations.to_vec(),
            host_header_rewrite: "".into(),
            http_user: "".into(),
            http_pwd: "".into(),
            route_by_http_user: "".into(),
            headers: Arc::new(Vec::new()),
        }
    }

    /// Go frp v0.71.0 compat (pkg/util/vhost/router.go getByRoute): vhost
    /// lookup walks exact → leftmost-label wildcard (>=3 labels) → "*"
    /// catch-all — the same walk tcpmux uses (see the tcpmux tests).
    #[tokio::test]
    async fn test_vhost_lookup_wildcard_leftmost_label() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["*.example.com".into()],
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("wildcard registration must succeed");

        // A 4-label host walks "*.b.example.com" (miss) then "*.example.com"
        // (hit) — the progressive leftmost-label replacement.
        let r = mgr
            .lookup_wildcard("a.b.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
        // A 3-label host walks straight to "*.example.com".
        let r = mgr
            .lookup_wildcard("b.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
        // Two-label hosts never match the wildcard (Go's >=3-label guard
        // keeps `*.com` from matching `example.com`) — and no catch-all is
        // registered, so the lookup misses entirely.
        assert!(mgr
            .lookup_wildcard("example.com", "/", "", "http")
            .await
            .is_none());
        // Unrelated suffixes stay misses.
        assert!(mgr
            .lookup_wildcard("a.example.net", "/", "", "http")
            .await
            .is_none());
    }

    /// When both a specific wildcard and a broader one are registered, the
    /// first (more specific) candidate in the leftmost-label walk wins.
    #[tokio::test]
    async fn test_vhost_lookup_wildcard_most_specific_wins() {
        let mgr = VhostManager::new();
        mgr.register(
            "specific",
            &["*.b.example.com".into()],
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("specific wildcard registration must succeed");
        mgr.register(
            "broad",
            &["*.example.com".into()],
            "http",
            &[],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("broad wildcard registration must succeed");

        // "a.b.example.com": the walk hits "*.b.example.com" first.
        let r = mgr
            .lookup_wildcard("a.b.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "specific");
        // "c.example.com": "*.b.example.com" misses, "*.example.com" hits.
        let r = mgr
            .lookup_wildcard("c.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "broad");
    }

    #[tokio::test]
    async fn test_vhost_lookup_wildcard_catch_all() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["*".into()],
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("catch-all registration must succeed");

        for host in ["anything.example.com", "example.com", "localhost"] {
            let r = mgr
                .lookup_wildcard(host, "/", "", "http")
                .await
                .unwrap_or_else(|| panic!("catch-all must match '{host}'"));
            assert_eq!(r.proxy_name.as_ref(), "p1");
        }
    }

    #[tokio::test]
    async fn test_vhost_lookup_exact_beats_wildcard() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["a.example.com".into()],
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("exact registration must succeed");
        mgr.register(
            "p2",
            &["*.example.com".into()],
            "http",
            &[],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("wildcard registration must succeed");

        // Exact match wins; the wildcard catches everything else under the
        // domain.
        let r = mgr
            .lookup_wildcard("a.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
        let r = mgr
            .lookup_wildcard("b.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p2");
    }

    /// proxy_ops expands a subdomain + sub_domain_host to
    /// `format!("{}.{}", subdomain, sub_host)` before registering the vhost
    /// route; the expanded domain must register and route like any other
    /// domain, while the bare sub_domain_host itself stays unrouted.
    #[tokio::test]
    async fn test_vhost_register_subdomain_expansion_routes() {
        let mgr = VhostManager::new();
        let sub_domain_host = "example.com";
        let expanded = format!("app.{sub_domain_host}");
        mgr.register(
            "p1",
            std::slice::from_ref(&expanded),
            "http",
            &[],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("expanded subdomain registration must succeed");

        let r = mgr
            .lookup_wildcard(&expanded, "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
        // The bare host has no route — the subdomain supplies the first label.
        assert!(mgr
            .lookup_wildcard(sub_domain_host, "/", "", "http")
            .await
            .is_none());
    }

    /// Go frp compat (pkg/util/vhost/router.go): routes are sorted by
    /// lexicographically-DESCENDING location (`slices.SortFunc` with
    /// `-cmp.Compare`), and `find_matching_route` returns the FIRST route in
    /// that order whose location prefix-matches — so the longest-prefix
    /// match is found without a length comparison at match time. Routes with
    /// no locations (HTTPS SNI) sort last and match any path.
    #[test]
    fn test_find_matching_route_longest_location_precedence() {
        let mut routes = vec![
            route("a", &["/aa".into()]),
            route("b", &["/aa/bb/cc".into()]),
            route("c", &[]),
        ];
        sort_by_longest_location(&mut routes);
        assert_eq!(routes[0].proxy_name.as_ref(), "b");
        assert_eq!(routes[1].proxy_name.as_ref(), "a");
        assert_eq!(routes[2].proxy_name.as_ref(), "c");

        // Path under the longest location → b.
        let m = find_matching_route(&routes, "/aa/bb/cc/d", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "b");
        // "/aa/bb" misses b's "/aa/bb/cc" and hits a's "/aa".
        let m = find_matching_route(&routes, "/aa/bb", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "a");
        // No prefix matches → falls through to the no-location route.
        let m = find_matching_route(&routes, "/zz", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "c");
        // A no-location route matches ANY path (even an empty one).
        assert_eq!(
            find_matching_route(&routes, "", "http")
                .unwrap()
                .proxy_name
                .as_ref(),
            "c"
        );
        // The scheme filter keeps other-scheme routes out: with only an
        // "http" route in the list, an "https" lookup misses entirely.
        let m = find_matching_route(&routes, "/aa/bb/cc/d", "https");
        assert!(m.is_none(), "cross-scheme lookup must not match");
    }

    /// Re-registration must restore the sorted order, and the httpUser-
    /// specific bucket must win over the "" (all-users) fallback bucket.
    #[tokio::test]
    async fn test_vhost_sort_stable_after_reregistration_and_http_user_bucket() {
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &["example.com".into()],
            "http",
            &["/".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .unwrap();
        mgr.register(
            "p2",
            &["example.com".into()],
            "http",
            &["/api".into()],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .unwrap();
        // Longest location prefix wins.
        let r = mgr
            .lookup("example.com", "/api/users", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p2");
        let r = mgr
            .lookup("example.com", "/other", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");

        // Unregister + re-register p2: the sort must be restored so the
        // longer "/api" location still wins over "/".
        mgr.unregister("p2").await;
        mgr.register(
            "p2",
            &["example.com".into()],
            "http",
            &["/api".into()],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .unwrap();
        let r = mgr
            .lookup("example.com", "/api/users", "", "http")
            .await
            .unwrap();
        assert_eq!(
            r.proxy_name.as_ref(),
            "p2",
            "re-registration must restore longest-location order"
        );

        // httpUser-specific bucket wins for matching users; everyone else
        // falls back to the "" bucket (Go getExactOrAllUsersLocked). The
        // bucket key is route_by_http_user at register (8th arg) and the
        // request's username at lookup.
        mgr.register(
            "auth-p",
            &["example.com".into()],
            "http",
            &["/".into()],
            "run-3",
            "",
            "",
            "",
            "alice",
            &[],
            "",
        )
        .await
        .unwrap();
        let r = mgr
            .lookup("example.com", "/x", "alice", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "auth-p");
        let r = mgr
            .lookup("example.com", "/x", "bob", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
    }

    #[tokio::test]
    async fn test_vhost_locations_require_a_domain() {
        // Round 10 (MEDIUM, Go parity): Go registers HTTP proxies as
        // `for domain { for location { register } }` — zero domains means
        // zero routes, so a location without a custom_domain must never
        // route (the removed host-agnostic path-only fallback would have
        // matched "/static/...", recreating the vhost-port catch-all).
        let mgr = VhostManager::new();
        mgr.register(
            "p1",
            &[],
            "http",
            &["/static".into()],
            "run-1",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .unwrap();
        assert!(
            mgr.lookup_combined("example.com", "/static/img/logo.png", "", "http")
                .await
                .is_none(),
            "locations without custom_domains must register zero routes (Go parity)"
        );
        // Domain-scoped locations still match: same location with a domain.
        mgr.register(
            "p2",
            &["example.com".into()],
            "http",
            &["/static".into()],
            "run-2",
            "",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .unwrap();
        let r = mgr
            .lookup_combined("example.com", "/static/css/site.css", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p2");
    }

    #[test]
    fn test_extract_basic_auth_valid() {
        // base64("user:pass") = "dXNlcjpwYXNz".
        let req = "GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(
            extract_basic_auth(req),
            Some(("user".into(), "pass".into()))
        );
        // Header name is matched case-insensitively.
        let req = "GET / HTTP/1.1\r\nauthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(
            extract_basic_auth(req),
            Some(("user".into(), "pass".into()))
        );
        // Whitespace between "Basic" and the payload is trimmed.
        let req = "GET / HTTP/1.1\r\nAuthorization: Basic   dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(
            extract_basic_auth(req),
            Some(("user".into(), "pass".into()))
        );
        // Empty password after the colon.
        let req = "GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjo=\r\n\r\n";
        assert_eq!(extract_basic_auth(req), Some(("user".into(), "".into())));
    }

    #[test]
    fn test_extract_basic_auth_invalid_and_missing() {
        // Missing header.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            None
        );
        // Wrong scheme.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Bearer abc\r\n\r\n"),
            None
        );
        // "Basic" without a trailing space.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic\r\n\r\n"),
            None
        );
        // "Basic" with an empty payload.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic \r\n\r\n"),
            None
        );
        // Decodes but has no colon separator (base64("use") = "dXNl").
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic dXNl\r\n\r\n"),
            None
        );
        // Not valid base64.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic !!!\r\n\r\n"),
            None
        );
        // Decodes to non-UTF-8 bytes (base64(0xff) = "/w==").
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic /w==\r\n\r\n"),
            None
        );
        // The caller bounds the text to the head (up to \r\n\r\n); given an
        // unbounded string a body line IS found — mirroring the fn's
        // documented contract.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\n\r\nAuthorization: Basic dXNlcjpwYXNz"),
            Some(("user".into(), "pass".into()))
        );
    }

    /// HTTP Basic Auth enforcement in resolve_vhost_request uses
    /// constant_time_eq_str on both the username and the password — a wrong
    /// password (or username, or no credentials) must produce
    /// VhostResolveError::Unauthorized, and only the exact pair forwards.
    #[tokio::test]
    async fn test_vhost_resolve_auth_rejects_wrong_password() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "auth-p",
                &["auth.example.com".into()],
                "http",
                &[],
                "run-1",
                "",
                "user1",
                "pass1",
                "",
                &[],
                "",
            )
            .await
            .expect("auth route registration must succeed");
        let head = b"GET / HTTP/1.1\r\nHost: auth.example.com\r\n\r\n".to_vec();
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 1234));

        let resolve = |auth: Option<(&str, &str)>| {
            let auth = auth.map(|(u, p)| (u.to_string(), p.to_string()));
            let head = head.clone();
            // Shadow `state` with a Copy reference: the move future copies
            // the reference instead of consuming the fn-local AppState, so
            // the outer closure stays Fn and can be called repeatedly.
            let state = &state;
            async move {
                resolve_vhost_request(
                    state,
                    "auth.example.com",
                    "/",
                    auth.as_ref(),
                    head,
                    peer,
                    "HTTP",
                )
                .await
            }
        };

        // No credentials → 401.
        assert!(matches!(
            resolve(None).await,
            Err(VhostResolveError::Unauthorized)
        ));
        // Wrong password → 401.
        assert!(matches!(
            resolve(Some(("user1", "wrong"))).await,
            Err(VhostResolveError::Unauthorized)
        ));
        // Wrong username → 401.
        assert!(matches!(
            resolve(Some(("other", "pass1"))).await,
            Err(VhostResolveError::Unauthorized)
        ));
        // Correct credentials → forward to the route's proxy.
        let fwd = resolve(Some(("user1", "pass1")))
            .await
            .expect("valid credentials must forward");
        assert_eq!(fwd.proxy_name, "auth-p");
        assert_eq!(fwd.run_id, "run-1");
    }

    /// Go frp v0.71.0 HTTPGroup.chooseEndpoint fallback: when the chosen
    /// group member is not registered in the proxy manager (gone between
    /// choose_endpoint and lookup), the route's recorded proxy — the first
    /// member that owns the shared route — is the fallback target.
    #[tokio::test]
    async fn test_vhost_group_member_gone_falls_back_to_recorded_proxy() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "owner-p",
                &["g.example.com".into()],
                "http",
                &[],
                "run-1",
                "",
                "",
                "",
                "",
                &[],
                "grp-1",
            )
            .await
            .expect("route registration must succeed");
        // The group lists "member-1", but the proxy manager has no such
        // proxy — exactly the "gone between choose and lookup" state.
        state
            .http_group_ctl
            .register_member("grp-1", "key", "g.example.com", "/", "", "member-1")
            .await
            .expect("member registration must succeed");

        let fwd = resolve_vhost_request(
            &state,
            "g.example.com",
            "/",
            None,
            b"GET / HTTP/1.1\r\nHost: g.example.com\r\n\r\n".to_vec(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            "HTTP",
        )
        .await
        .expect("member-gone fallback must forward");
        assert_eq!(
            fwd.proxy_name, "owner-p",
            "member gone → recorded proxy fallback"
        );
        assert_eq!(fwd.run_id, "run-1");
    }

    /// choose_endpoint returns None when the group is not registered (or has
    /// no members) — the request routes to the route's recorded proxy.
    #[tokio::test]
    async fn test_vhost_group_no_members_falls_back_to_recorded_proxy() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "owner-p",
                &["g2.example.com".into()],
                "http",
                &[],
                "run-1",
                "",
                "",
                "",
                "",
                &[],
                "grp-ghost",
            )
            .await
            .expect("route registration must succeed");
        // "grp-ghost" is never registered with the controller, so
        // choose_endpoint returns None.
        let fwd = resolve_vhost_request(
            &state,
            "g2.example.com",
            "/",
            None,
            b"GET / HTTP/1.1\r\nHost: g2.example.com\r\n\r\n".to_vec(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            "HTTP",
        )
        .await
        .expect("no-member fallback must forward");
        assert_eq!(
            fwd.proxy_name, "owner-p",
            "no members → recorded proxy fallback"
        );
        assert_eq!(fwd.run_id, "run-1");
    }
}
