use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::service::{AppState, InternalMsg};
// Strict request-line authority canonicalization (Go url.ParseRequestURI
// semantics — digit gate on non-empty ports, mis-brackets → 400). Shared
// with tcpmux.rs, which owns it (round-3 M4).
use crate::tcpmux::canonicalize_host;

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
    /// first member's identity as fallback.
    pub group: Arc<str>,
    /// Location prefixes for this proxy (empty = host-only routing).
    pub locations: Vec<String>,
    /// Rewrite Host header to this value before forwarding (Go frp compat).
    pub host_header_rewrite: Arc<str>,
    /// HTTP Basic Auth credentials (empty = no auth).
    pub http_user: Arc<str>,
    pub http_pwd: Arc<str>,
    /// Per-user routing bucket key (Go frp compat): the router registers
    /// this proxy under the (domain, route_by_http_user) bucket, and a
    /// request whose Basic-Auth username equals the bucket value matches —
    /// the bucket lookup IS the per-user routing. No proxy-name synthesis
    /// exists in Go (audit round 3, M12 — the old
    /// `{route_by_http_user}.{username}` global lookup was removed).
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

/// Find the route whose location prefix-matches the path, preferring the
/// LONGEST matching location (Go frp flattened-Router semantics).
///
/// Go registers one `Routers` entry per (domain, location, httpUser) triple
/// and sorts ALL of them by location lexicographically descending before
/// first-match probing (router.go `slices.SortFunc` + `getLocked`). A
/// route-level scan that probes each route's locations in registration order
/// diverges when routes carry interleaved multi-location sets: route A at
/// ["/zz", "/a"] and route B at ["/aa"] — Go flattens to "/zz"(A),
/// "/aa"(B), "/a"(A) and routes path "/aa" to B, while route-first probing
/// would check A's "/a" and wrongly pick A. Scanning every (route, location)
/// pair and keeping the largest matching location reproduces the flattened
/// order exactly (a tie in the flattened order can only be the same
/// location — same route — so any tie-break is equivalent).
///
/// Routes with no locations (e.g. HTTPS SNI routes) match any path with the
/// empty-string key — Go's "" location sorts LAST, so they only win when
/// nothing else matches.
/// The scheme filter mirrors Go's separate router sets (httpVhostRouter vs
/// the HTTPS Muxer's registryRouter): an HTTP lookup must never match an
/// HTTPS route and vice versa.
fn find_matching_route(vrs: &[VhostRoute], path: &str, scheme: &str) -> Option<VhostRouteMatch> {
    let mut best: Option<(&VhostRoute, &str)> = None;
    for route in vrs {
        if route.scheme != scheme {
            continue;
        }
        if route.locations.is_empty() {
            // Go's "" location sorts last; record only as a fallback.
            if best.is_none() {
                best = Some((route, ""));
            }
            continue;
        }
        for loc in &route.locations {
            if path.starts_with(loc.as_str()) && best.is_none_or(|(_, bl)| loc.as_str() > bl) {
                best = Some((route, loc.as_str()));
            }
        }
    }
    best.map(|(route, _)| VhostRouteMatch::from_route(route))
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
    /// Number of registered wildcard domains (domain starting with `*`, e.g.
    /// `*.example.com` or bare `*`). Maintained by register/unregister. Lets
    /// the lookup fast-exit to the exact-match path when no wildcard route
    /// exists — the per-request `parts.join(".")` expansion then never runs.
    /// A re-registered proxy that leaves an orphan wildcard route behind
    /// still has that route matchable, so this counter can only over-count,
    /// never under-count; the `== 0` gate is therefore always safe.
    wildcard_count: usize,
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
                wildcard_count: 0,
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

        // Keep wildcard_count in lockstep with the routes map: every wildcard
        // domain this registration is about to add is matchable, so it must be
        // counted (see the field doc for the over-count safety argument).
        // Placed after the conflict/dedup checks so a rejected registration
        // never bumps the counter.
        tables.wildcard_count += domains.iter().filter(|d| d.starts_with('*')).count();

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
            // Decrement the contribution this proxy's registrations made.
            // If another proxy shares a wildcard domain, its own registration
            // still holds the counter up — so the subtraction never
            // under-counts below the actually-matchable wildcard set.
            tables.wildcard_count -= entries.iter().filter(|(d, _)| d.starts_with('*')).count();
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

        // Fast exit: no wildcard routes registered — the exact match IS the
        // whole answer, and the per-request `parts.join(".")` expansion for
        // >=3-label domains never runs.
        if tables.wildcard_count == 0 {
            return get_locked(&tables.routes, domain, path, http_user, scheme);
        }

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
/// Go frp v0.71.0 `NotFoundResponse` builtin body (pkg/util/http/http.go)
/// — served when no `custom_404_page` is configured. 489 bytes; with the
/// 92-byte head written by [`write_not_found_response`] the full answer is
/// 581 bytes (probe vs Go v0.71.0).
pub const GO_404_NOT_FOUND_BODY: &str = concat!(
    "<!DOCTYPE html>\n",
    "<html>\n",
    "<head>\n",
    "<title>Not Found</title>\n",
    "<style>\n",
    "    body {\n",
    "        width: 35em;\n",
    "        margin: 0 auto;\n",
    "        font-family: Tahoma, Verdana, Arial, sans-serif;\n",
    "    }\n",
    "</style>\n",
    "</head>\n",
    "<body>\n",
    "<h1>The page you requested was not found.</h1>\n",
    "<p>Sorry, the page you are looking for is currently unavailable.<br/>\n",
    "Please try again later.</p>\n",
    "<p>The server is powered by <a href=\"https://github.com/fatedier/frp\">frp</a>.</p>\n",
    "<p><em>Faithfully yours, frp.</em></p>\n",
    "</body>\n",
    "</html>\n",
);

/// Write Go frp's `NotFoundResponse` (pkg/util/http/http.go) — the 404
/// answer on a vhost/tcpmux route miss and on a control-gone (Go
/// connectHandler's CreateConnection error path answers the same 404, not
/// a 502). Head order is fixed (Content-Length, Content-Type, Server) and
/// matches the Go literal byte-for-byte; `custom_body` (custom_404_page)
/// replaces the builtin HTML when non-empty, with Content-Length tracking
/// the custom body. Go's stdlib http.Server-layer additions (Date,
/// Connection: close, charset) that http.Error-based handlers would emit
/// are absent from frp's own pre-built response — the vhost GET path
/// writes NotFoundResponse raw, like the CONNECT path.
pub(crate) async fn write_not_found_response(
    stream: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    custom_body: &str,
) {
    let body: &[u8] = if custom_body.is_empty() {
        GO_404_NOT_FOUND_BODY.as_bytes()
    } else {
        custom_body.as_bytes()
    };
    // Write failures here mean the client disconnected before receiving the
    // error response — there is no recovery path, so we silently drop them.
    // They are still logged at debug so a hung client that never reads the
    // error response remains observable in traces (audit-round4 H5).
    let head = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nContent-Type: text/html\r\nServer: frp/{}\r\n\r\n",
        body.len(),
        frp_core::VERSION
    );
    if let Err(e) = stream.write_all(head.as_bytes()).await {
        tracing::debug!(error = %e, "failed to write HTTP error response header");
        return;
    }
    if let Err(e) = stream.write_all(body).await {
        tracing::debug!(error = %e, "failed to write HTTP error response body");
    }
}

/// Write the Go `http.Error` auth-fail render (pkg/util/vhost/http.go
/// ServeHTTP: `rw.Header().Set(...); http.Error(rw, http.StatusText(code),
/// code)` → Content-Type: text/plain; charset=utf-8 + X-Content-Type-Options:
/// nosniff + Content-Length + the StatusText body with a trailing '\n').
/// The fixed fields match Go; the Date header Go's http.Server layer adds
/// to the live render is omitted in this raw write, and header order is
/// fixed (Content-Length first) rather than Go's writer order — the same
/// scoping the NotFoundResponse arms document (shape parity of the
/// frp-rs-built response, not a live-server byte capture).
async fn write_http_error_auth_response(
    stream: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    status_line: &str,
    auth_header: &str,
    body: &str,
) {
    let head = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Length: {}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         {auth_header}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         \r\n",
        body.len()
    );
    if let Err(e) = stream.write_all(head.as_bytes()).await {
        tracing::debug!(error = %e, "failed to write auth error response header");
        return;
    }
    if let Err(e) = stream.write_all(body.as_bytes()).await {
        tracing::debug!(error = %e, "failed to write auth error response body");
    }
}

/// Write the raw error response Go's `conn.serve` produces for
/// readRequest/parse failures (net/http server.go `errorHeaders`: status
/// line + Content-Type: text/plain; charset=utf-8 + Connection: close +
/// the status text as body — verified byte-for-byte against live go1.25
/// probes for the generic 400, the 431 errTooLarge render, the 505
/// statusError render, and the badRequestError renders). `status` is the
/// FULL text — the status line and the body carry the same string, detail
/// included ("505 HTTP Version Not Supported: unsupported protocol
/// version", "400 Bad Request: missing required Host header" — Go shows
/// the detail for these; the generic "malformed HTTP request" parse
/// failure is the bare "400 Bad Request"). No Content-Length (the 431
/// arm's old CL:0 line was round-9 F5 divergence), no trailing LF after
/// the body text, and no nosniff — the auth-fail render above is a
/// different http.Error shape with its own fixed fields. (F5, audit
/// round 9 — the four pre-existing bare 3-line 400/505 writers and the
/// CL:0 431 all routed through this one Go-shape emitter.)
async fn write_go_server_error(stream: &mut (impl tokio::io::AsyncWriteExt + Unpin), status: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Connection: close\r\n\
         \r\n"
    );
    if let Err(e) = stream.write_all(head.as_bytes()).await {
        tracing::debug!(error = %e, "failed to write HTTP error response header");
        return;
    }
    if let Err(e) = stream.write_all(status.as_bytes()).await {
        tracing::debug!(error = %e, "failed to write HTTP error response body");
    }
}

/// Upper cap (seconds) applied by `clamp_vhost_timeout`. 24h is far beyond
/// any real client-head bound — the value only ever clocks client-side head
/// reads / handshakes plus the h2c backend response-head read; Rust-only
/// hardening — Go frp has no comparable cap on VhostHTTPTimeout.
const VHOST_TIMEOUT_CAP_SECS: u64 = 24 * 60 * 60;

/// `vhost_http_timeout` normalization shared by every vhost accept path
/// (HTTP/1.1 head, h2c handshake, HTTPS SNI, h2c response-head): a
/// `<= 0` value floors at 60s (Go parity for the floor), positive values
/// pass through unchanged.
///
/// Role divergence from Go frp (documented, audit-r7): in Go, `vhost_http_timeout`
/// feeds ONLY the backend response-head wait — `ResponseHeaderTimeoutS` in
/// pkg/util/vhost/http.go `NewHTTPReverseProxy`, floored at 60s, a slow
/// backend head answers 504 — while the client-side head window is a
/// HARDCODED `ReadHeaderTimeout: 60 * time.Second` http.Server literal in
/// server/service.go that the config never reaches. frp-rs has one config
/// and spends it on the client-head window instead (the plain HTTP/1.1
/// bridge is raw forward with no backend response-head wait — Go's CONNECT
/// path has none either). The h2c frontend is the exception on both sides:
/// its backend response-head translation read (vhost_h2c.rs) IS clocked by
/// this config and answers 504 on expiry, the exact mirror of Go's
/// ResponseHeaderTimeoutS semantics for that path.
///
/// Positive values are additionally capped at [`VHOST_TIMEOUT_CAP_SECS`]:
/// the clamped value feeds `Instant::now() + Duration::from_secs(...)` at
/// the deadline sites below (serve_vhost_request head deadline,
/// serve_h2c_request handshake deadline), and std `Instant` PANICS when the
/// add overflows — under the release `panic=abort` profile a hostile
/// `vhost_http_timeout = u64::MAX` config would abort frps on the first
/// vhost request, before any read is attempted (audit finding S1). The
/// `tokio::time::timeout(duration)` call sites (HTTPS SNI, h2c/HTTP
/// response head) cannot overflow — tokio's checked_add degrades a huge
/// duration to a far-future deadline — but share the same clamp so the
/// config has one bounded semantic everywhere.
pub(crate) fn clamp_vhost_timeout(t: u64) -> u64 {
    let floored = if t > 0 { t } else { 60 };
    floored.min(VHOST_TIMEOUT_CAP_SECS)
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
    // Read the first 4096 bytes to extract Host header (with configured timeout).
    let timeout_secs = clamp_vhost_timeout(state.vhost_http_timeout);
    // Single absolute deadline for the ENTIRE head across all phases (audit
    // round 3, LOW): the initial read, the h2-preface completion, and the
    // HTTP/1.1 head completion used to each get a FRESH window, letting a
    // drip client ("P" → slow garbage preface → slow head) park the task for
    // up to 3× vhost_http_timeout. One window covering the whole head also
    // matches Go's vhost http.Server, which hardcodes
    // `ReadHeaderTimeout: 60 * time.Second` (server/service.go literal —
    // the config never reaches it; see clamp_vhost_timeout for the full
    // role divergence).
    let head_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 4096];
    let n = match tokio::time::timeout_at(head_deadline, stream.read(&mut buf)).await {
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
            // The preface completion shares the single head deadline from
            // serve_vhost_request entry (audit round 3): a slow-drip client
            // sending one byte per read window would otherwise stretch the
            // completion loop to 23 × timeout AND then re-open a fresh head
            // window on the HTTP/1.1 fallback (a sub-1s-per-byte drip would
            // never trip a per-read timeout and would park the task + fd +
            // permit for up to 3 × vhost_http_timeout). The full preface
            // must arrive within vhost_http_timeout of the first byte.
            let mut prefix_len = n;
            while prefix_len < vhost_h2c::H2_PREFACE.len() {
                let m = match tokio::time::timeout_at(
                    head_deadline,
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
                head_deadline,
            )
            .await;
        }
    }
    return handle_http1_request(stream, pre_read, state, peer, scheme, wrap, head_deadline).await;
}

/// HTTP/1.1 vhost path: finish reading the request head (up to 4096 bytes or
/// the blank line that ends it under Go textproto semantics — bare-LF and
/// mixed line endings are legal), extract Host/path/auth, resolve the route,
/// and forward the stream via InternalMsg::ProxyUserConn.
///
/// The 4096-byte head cap is a deliberate hardening divergence from Go frp
/// (http.Server defaultMaxHeaderBytes = 1 MiB — a hostile client can send a
/// ~1 MiB head per request slot); the h2c surface is capped at 4096 the same
/// way while Go's h2 default is 16 MiB. Policy split-surface rationale lives
/// in CLAUDE.md (round-13/14 hardening rows). An unterminated head is never
/// forwarded: if it fills the cap it gets a 431 below (Go's errTooLarge
/// analog); if the deadline expires or the peer closes mid-head with fewer
/// than 4096 bytes buffered, the connection is closed with no response
/// (audit round 8 F7 — Go's isCommonNetReadError silent close).
async fn handle_http1_request<S>(
    mut stream: S,
    mut pre_read: Vec<u8>,
    state: Arc<AppState>,
    peer: std::net::SocketAddr,
    scheme: &str,
    wrap: impl FnOnce(S) -> frp_core::transport::IoStream,
    head_deadline: tokio::time::Instant,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // The vhost listener's single read may be short (e.g. an h2c-misdetected
    // HTTP/1.1 request): keep reading until the head terminator or the cap.
    // The deadline is the ONE absolute window threaded from
    // serve_vhost_request entry (audit round 3) — a slow-drip client would
    // otherwise stretch the head read to 4096 × timeout, and re-opening a
    // fresh window here would stack on top of the preface phase. The whole
    // head must arrive within vhost_http_timeout of the first byte. (There
    // is no Go "connReadTimeout" construct behind this window: Go frp's
    // client-head window is the hardcoded 60s ReadHeaderTimeout on its
    // vhost http.Server, and on this HTTP/1.1 path the config's Go role —
    // the backend response-head wait — has no counterpart, since the bridge
    // is raw forward (Go's CONNECT path has none either); the
    // config-on-client-head divergence is documented on clamp_vhost_timeout.)
    while pre_read.len() < 4096 && frp_core::textproto::head_end(&pre_read).is_none() {
        let mut buf = [0u8; 4096];
        let m = match tokio::time::timeout_at(head_deadline, stream.read(&mut buf)).await {
            Ok(Ok(m)) if m > 0 => m,
            _ => break,
        };
        pre_read.extend_from_slice(&buf[..m]);
    }

    // The head is capped at 4096 bytes. If the cap fills without a blank
    // line (textproto semantics — Go accepts bare-LF/mixed EOL, so the
    // strict \r\n\r\n scan would 431 legal heads that merely use another
    // line-ending convention), respond 431 Request Header Fields Too Large
    // instead of forwarding a truncated head — forwarding it makes the
    // backend block waiting for the rest of the head, tying up a work-conn
    // slot (limited DoS on shared vhosts).
    if pre_read.len() >= 4096 && frp_core::textproto::head_end(&pre_read).is_none() {
        // Go's errTooLarge render (conn.serve: status line + charset +
        // Connection: close + body text — NO Content-Length; the old CL:0
        // shape was audit-round-9 F5 divergence, probe OVERSIZE).
        write_go_server_error(&mut stream, "431 Request Header Fields Too Large").await;
        return;
    }

    // F7 (audit round 8, MEDIUM): the read loop above ALSO exits without a
    // terminator when the head deadline expires or the peer closes mid-head
    // with fewer than 4096 bytes buffered. Such a head lacks its closing
    // blank line — parsing and routing it would forward a TRUNCATED head
    // that leaves the backend blocked waiting for the rest of the head,
    // pinning a work-conn slot indefinitely (attacker: partial head, then
    // silence). Go's vhost http.Server never dispatches an unterminated
    // head: a mid-head timeout or EOF surfaces as a readRequest error that
    // isCommonNetReadError classifies as "don't reply" (net/http
    // conn.serve), so Go closes the connection with NO response bytes —
    // the 431 arm above is the frp-rs cap analog of Go's errTooLarge 431.
    // Close silently: the same 0-byte precedent as the malformed-request-
    // line silent closes elsewhere in this module.
    if frp_core::textproto::head_end(&pre_read).is_none() {
        debug!(
            peer = %peer, scheme = %scheme, len = pre_read.len(),
            "closing vhost connection: unterminated request head (deadline expiry or mid-head close)"
        );
        return;
    }
    // copy — `into_owned()` would duplicate up to 4096 bytes per request).
    // `host`/`path` must still be owned Strings: `pre_read` is moved by
    // value into `resolve_vhost_request` below, so we cannot keep references
    // into it across that call.
    // Only the header block up to the blank line is parsed (audit fix):
    // bytes past the terminator are entity body or pipelined requests and
    // must not influence routing/auth — a body line like
    // "authorization: Basic ..." must not authenticate the request. Same
    // bound as inject_vhost_request_headers below. The terminator follows
    // Go net/textproto semantics (head_end): any EOL convention — the blank
    // line is "\n", "\r\n" or the bare "\n" that closes a bare-LF head.
    // Zero-allocation parse for the common ASCII case; fall back to lossy
    // replacement for non-UTF-8 heads. A 400 here would diverge from Go frp,
    // which tolerates obs-text (0x80-0xFF) bytes in header values.
    let head_end = frp_core::textproto::head_end(&pre_read).unwrap_or(pre_read.len());
    let head = &pre_read[..head_end];
    let request_text_cow;
    let request_text: &str = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => {
            request_text_cow = String::from_utf8_lossy(head);
            &request_text_cow
        }
    };
    // Rounds 6 + audit round 9 (F1/F4/F5): Go net/http request-line
    // semantics — version gates (malformed shape OR missing version → 400,
    // non-1.x → 505), absolute-form routing (req.Host = req.URL.Host — Host
    // header ignored for routing), path minus query. The parse-Ok arm no
    // longer answers for a missing Host value: the wire-Host gate below
    // decides (F4) — an HTTP/1.1 non-CONNECT request with NO Host header
    // line is 400 "missing required Host header" (Go conn.readRequest); the
    // gate-exempt shapes (HTTP/1.0, CONNECT, an empty-valued "Host:" line)
    // route on "" (Go req.Host fallback) and miss → 404.
    // Rounds 6 + audit round 9 (F1/F4/F5) + review round: Go net/http
    // error ORDER (go1.25): readRequest parses the request line (shape
    // failures → generic 400), reads headers (duplicate Host → generic
    // 400 — request.go:1139 "too many Host headers"), and only THEN runs
    // http1ServerSupportsRequest (major != 1 → 505) and the wire-Host
    // gate (missing required Host → 400 with detail). The arms below
    // follow that order, so a "HTTP/2.0" request that also carries two
    // Host lines answers Go's 400 (not the 505) and a version-shape
    // failure beats both.
    let parse = parse_vhost_request_line(request_text);
    if matches!(parse, RequestLine::BadRequest) {
        // Go: "malformed HTTP request" / "malformed HTTP version" parse
        // failures — generic 400 render (probes T2TOK/TABJOIN).
        write_go_server_error(&mut stream, "400 Bad Request").await;
        return;
    }
    // Go ServeHTTP (pkg/util/vhost/http.go:282-285): a request whose METHOD
    // is CONNECT is handed to connectHandler, which forwards the head RAW —
    // the Rewrite hook (X-Forwarded-*) and rc.Headers (requestHeaders) never
    // run, and no host rewrite applies. Case-sensitive method gate (Go
    // http.MethodConnect): lowercase "connect" takes the normal proxy path.
    // Covers both authority-form CONNECT and an origin-form request line
    // with the CONNECT method — Go's gate is the method alone (justAuthority
    // only changes how the target parses).
    let is_connect = request_text
        .split(' ')
        .next()
        .is_some_and(|m| m == "CONNECT");
    // RFC 7230 §5.4: a request with more than one Host header is invalid.
    // Go's net/http server (which Go frp uses for vhost routing) rejects
    // such requests with 400; forwarding duplicates verbatim would let a
    // second Host shadow the routed proxy's host_header_rewrite. Applies
    // to origin-form and absolute-form alike (Go's readRequest rejects
    // duplicate Host headers before the 505 gate — probe DUPHOST11:
    // generic 400; a "HTTP/2.0" + duplicate-Host request answers this 400
    // in Go, where the 505 gate runs after the header parse).
    if count_host_headers(request_text) > 1 {
        write_go_server_error(&mut stream, "400 Bad Request").await;
        return;
    }
    let (host, path, is_absolute_form) = match parse {
        RequestLine::Ok {
            host,
            path,
            absolute_form,
        } => (host.map(str::to_string), path.to_string(), absolute_form),
        RequestLine::VersionNotSupported => {
            // Go conn.readRequest's http1ServerSupportsRequest gate — the
            // detail is carried on the status line AND the body (probe
            // EXPL20).
            write_go_server_error(
                &mut stream,
                "505 HTTP Version Not Supported: unsupported protocol version",
            )
            .await;
            return;
        }
        RequestLine::BadRequest => {
            unreachable!("BadRequest returned above")
        }
    };
    // F4 (audit round 9): Go conn.readRequest's wire-Host gate
    // (server.go:1056-1059): `req.ProtoAtLeast(1, 1) && (!haveHost ||
    // len(hosts) == 0) && !isH2Upgrade && req.Method != "CONNECT"` →
    // badRequestError("missing required Host header"), rendered with the
    // detail (probes 1.1NOHOST / ABS1.1NOHOST: ": missing required Host
    // header" on the status line and body). "haveHost" means a Host header
    // LINE exists — Go's MIME parser counts an empty-valued "Host:" as
    // present (probe EMPTYHOSTV: served with Host=""), so the gate is a
    // count==0 test. Only parse-Ok requests reach here, so
    // ProtoAtLeast(1,1) is a minor-digit >= 1 check ("HTTP/1.0" exempt —
    // probe 1.0NOHOST: served with Host=""). CONNECT is exempt by method
    // (case-sensitive — Go compares the literal "CONNECT", so lowercase
    // "connect" is NOT exempt).
    if !is_connect
        && count_host_headers(request_text) == 0
        && request_line_minor_gte_1(request_text)
    {
        write_go_server_error(&mut stream, "400 Bad Request: missing required Host header").await;
        return;
    }
    // No usable Host value (no Host line on a gate-exempt request, or an
    // empty-valued "Host:") routes on "" — Go's req.Host == "" fallback;
    // the frp router has no "" route, so the request answers Go's 404
    // route-miss response. (Pre-F4 this arm wrote a bare 400.)
    let host = host.unwrap_or_default();

    // Parse Basic Auth once — reused for route matching, auth check,
    // and per-user routing (Go frp compat: getByRoute(host, path, username)).
    // Go `checkRouteAuthByRequest`: an absolute-form request target
    // (req.URL.Host != "") authenticates against `Proxy-Authorization`
    // only; origin-form against `Authorization` (and answers 407 vs 401
    // below accordingly).
    let http_auth = if is_absolute_form {
        extract_basic_auth_named(request_text, "proxy-authorization:")
    } else {
        extract_basic_auth(request_text)
    };
    // Go getRequestRouteUser (pkg/util/vhost/http.go:231-243): ROUTING
    // ONLY — an absolute-form request without Proxy-Authorization falls
    // back to the Authorization header's Basic Auth username so the request
    // still hits the matched per-user route and returns 407 instead of 404.
    // Go falls back ONLY when `proxyAuth == ""` (absent or empty-valued);
    // a PRESENT but malformed Proxy-Authorization makes `ParseBasicAuth`
    // fail and Go routes to the EMPTY user bucket ("") — never to the
    // Authorization header's username. Auth validation deliberately does
    // not share the fallback (checkRouteAuthByRequest reads
    // Proxy-Authorization only on absolute-form); http_auth above stays
    // the single source of truth for the credential check.
    let route_user: Option<String> = if is_absolute_form && http_auth.is_none() {
        if has_nonempty_header(request_text, "proxy-authorization:") {
            // Header present but unparseable — Go ParseBasicAuth fails →
            // empty user bucket (Some("") ≡ "", no Authorization fallback).
            Some(String::new())
        } else {
            // Header absent or empty-valued — Go's `proxyAuth == ""`
            // fallback to the Authorization header's Basic username.
            extract_basic_auth(request_text).map(|(u, _)| u)
        }
    } else {
        None
    };

    debug!(host = %host, path = %path, peer = %peer, "{} VHost request for '{}' path '{}' from {}", scheme, host, path, peer);

    // X-Forwarded-Host value: inbound Host as received (Go r.In.Host),
    // extracted from the ORIGINAL head — `host` above is canonicalized
    // (port stripped) and `pre_read` is rewritten later. Owned: `request_text`
    // borrows `pre_read`, which is moved into resolve_vhost_request below.
    let raw_host = extract_raw_request_host(request_text, is_absolute_form).to_string();

    match resolve_vhost_request(
        &state,
        &host,
        &path,
        &raw_host,
        http_auth.as_ref(),
        route_user.as_deref(),
        pre_read,
        peer,
        scheme,
        is_absolute_form,
        is_connect,
    )
    .await
    {
        Ok(forward) => {
            // DELIBERATE DIVERGENCE (audit round 9, F4 — documented, not
            // fixed): the HTTP/1.1 vhost path is a RAW BYTE RELAY — one
            // routed backend per client connection. `forward` carries the
            // edited request head (routing/auth were applied once, above);
            // from here the connection is handed to the control handler,
            // which bridges the head + tail bytes to the backend and relays
            // bytes both ways until EOF. Consequences, all accepted:
            //   * routing/auth/route membership are resolved ONCE per
            //     connection — a pipelined second request on the same
            //     connection is NOT re-routed or re-authenticated (Go frp
            //     uses httputil.ReverseProxy, which re-parses and re-routes
            //     every request on the keep-alive connection);
            //   * the response is relayed raw — Go's ReverseProxy instead
            //     re-parses the response and strips its hop-by-hop headers
            //     (the mirror of the request-side strip in
            //     strip_vhost_hop_by_hop_headers);
            //   * only one backend request per connection — the client
            //     connection is dropped when the bridge ends, and HTTP/1.1
            //     keep-alive semantics beyond that are not honored.
            // Per-request routing after request 1 would require parsing
            // response boundaries (Content-Length/chunk framing) on the
            // relayed stream — a stateful HTTP parser in the data path —
            // for a feature (HTTP keep-alive through a proxy tunnel) Go frp
            // itself only offers on the plain-HTTP vhost surface. The
            // request-side head surgery (rewrite/inject/hop-strip) still
            // matches Go byte-for-byte for the ONE request that is routed.
            // Only the mpsc::Sender is consumed here — the full-ControlTx
            // clone (two Strings + two Arc bumps) per vhost forward was pure
            // waste (round-3 server finding 6).
            let internal_tx = state
                .run_id_to_ctl_tx
                .get(&forward.run_id)
                .map(|v| v.tx.clone());
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
                    ctl_tx.send(InternalMsg::ProxyUserConn {
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
                // Go parity: a CONNECT whose control died surfaces in
                // connectHandler's CreateConnection failure path
                // (pkg/util/vhost/http.go:262), which writes the raw
                // NotFoundResponse — byte-identical here (581B + close). A
                // GET whose control died goes through the reverse-proxy
                // ErrorHandler instead (http.go:128-137, a net/http
                // server-layer render with Date etc.); both arms serve the
                // same 404 status/body in frp-rs, with the NotFound arm's
                // documented fixed-shape scoping (no server-layer headers).
                // NotFoundResponse() (pkg/util/vhost/resource.go) re-reads
                // custom404Page on EVERY call, so this arm serves the
                // configured page too — not just the builtin body.
                write_not_found_response(&mut stream, &state.custom_404_page).await;
            }
        }
        Err(VhostResolveError::Unauthorized { proxy_form: true }) => {
            // Absolute-form request → Go checkRouteAuthByRequest answers
            // 407 + Proxy-Authenticate, realm "Restricted"
            // (pkg/util/vhost/http.go:272-274), rendered by http.Error —
            // body = http.StatusText(407) + "\n" ("Proxy Authentication
            // Required\n", 30 bytes). The bare 3-line 407 (no body, no
            // Content-Length) this arm used to write diverged (round-3
            // review).
            write_http_error_auth_response(
                &mut stream,
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"Restricted\"",
                "Proxy Authentication Required\n",
            )
            .await;
        }
        Err(VhostResolveError::Unauthorized { proxy_form: false }) => {
            // Origin-form → Go http.Error 401 + WWW-Authenticate, realm
            // "Restricted" (http.go:275-277 — Go frp's realm is NOT the old
            // "frp"), body = http.StatusText(401) + "\n" ("Unauthorized\n",
            // 12 bytes).
            write_http_error_auth_response(
                &mut stream,
                "401 Unauthorized",
                "WWW-Authenticate: Basic realm=\"Restricted\"",
                "Unauthorized\n",
            )
            .await;
        }
        Err(VhostResolveError::NotFound) => {
            // Go parity: the vhost GET path answers Go's NotFoundResponse
            // (the 489-byte builtin body below, or custom_404_page content).
            // Go's copy additionally carries Date / Connection: close /
            // charset headers — those are added by net/http's response
            // writer (http.Server layer), not by Go frp, and frp-rs writes
            // raw bytes instead. Shape parity with the fixed fields is the
            // goal, not byte-exactness with a live Go server's dated copy.
            write_not_found_response(&mut stream, &state.custom_404_page).await;
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
    /// HTTP Basic Auth failed. `proxy_form` mirrors Go
    /// `checkRouteAuthByRequest` (`req.URL.Host != ""`): absolute-form
    /// requests (h2c always; HTTP/1.1 absolute-form request lines) answer
    /// 407 + Proxy-Authenticate, origin-form 401 + WWW-Authenticate.
    Unauthorized { proxy_form: bool },
}

/// Shared routing + header rewriting for HTTP/1.1 and h2c vhost requests.
///
/// Extracted from `serve_vhost_request`: looks up the route (domain/wildcard/
/// path + httpUser), enforces Basic Auth, applies per-user routing
/// (`route_by_http_user`), then rewrites the Host header, strips the Go
/// ReverseProxy hop-by-hop set (non-CONNECT only, F3), and injects
/// X-Forwarded-For / X-Forwarded-Host / X-Forwarded-Proto / requestHeaders
/// into the forwarded head. `raw_host` is the inbound Host exactly as
/// received (case + port preserved, NOT canonicalized) — Go's
/// `SetXForwarded` uses `r.In.Host` (pre-rewrite); CanonicalHost feeds
/// routing only. The caller renders rejection (404/401) or success
/// (ProxyUserConn dispatch) in its own protocol (HTTP/1.1 text vs HTTP/2
/// frames).
#[allow(clippy::too_many_arguments)] // mirrors tcpmux::route (same request-context tuple)
pub(crate) async fn resolve_vhost_request(
    state: &AppState,
    host: &str,
    path: &str,
    raw_host: &str,
    http_auth: Option<&(String, String)>,
    route_user: Option<&str>,
    request_head: Vec<u8>,
    peer: std::net::SocketAddr,
    scheme: &str,
    is_absolute_form: bool,
    is_connect: bool,
) -> Result<VhostForward, VhostResolveError> {
    // Routing username: the caller's routing-only BasicAuth fallback
    // (Go getRequestRouteUser) takes precedence when present; otherwise the
    // authenticated header's username. Auth validation below still checks
    // only `http_auth` — the fallback never weakens the credential gate.
    let http_user = route_user
        .or_else(|| http_auth.map(|(u, _)| u.as_str()))
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
        // Current callers pass only "HTTP"/"HTTPS" (log labels), so this
        // fallback covers "https"/"HTTPS" only — a future caller passing a
        // third scheme would silently key as "https".
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
            // Go checkRouteAuthByRequest: the response shape depends on the
            // request form — absolute-form → 407 + Proxy-Authenticate,
            // origin-form → 401 + WWW-Authenticate (the caller renders it).
            return Err(VhostResolveError::Unauthorized {
                proxy_form: is_absolute_form,
            });
        }
    }

    // HTTP/HTTPS group routing (Go frp v0.71.0 HTTPGroup.chooseEndpoint):
    // when the matched route belongs to a group, pick a member round-robin.
    // The chosen member becomes the fallback target; route_by_http_user
    // (below) may override it with a user-specific proxy when configured.
    let (group_proxy_name, group_run_id) = if route.group.is_empty() {
        (route.proxy_name.to_string(), route.run_id.to_string())
    } else {
        // Kind registry selection: an http group and an https group may
        // share a name (Go keeps separate controllers per muxer). The
        // dispatch scheme picks the kind — an HTTPS SNI hit must round-robin
        // over the https group's members only.
        let group_is_https = scheme_key == "https";
        match state
            .http_group_ctl
            .choose_endpoint(&route.group, group_is_https)
            .await
        {
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

    // The route's own member (or group-chosen member above) IS the per-user
    // target: the bucket lookup in lookup_combined already matched on the
    // request's Basic-Auth username (Go router semantics — route_by_http_user
    // is a registration-side bucket key, never a proxy-name prefix). The old
    // synthesized `{route_by_http_user}.{username}` global proxy lookup was a
    // cross-tenant hijack (any registered proxy could impersonate the
    // redirect target) and is removed (audit round 3, M12).

    // EOL canonicalization: the read loop accepts bare-LF/mixed-EOL heads
    // (Go textproto semantics), but Go net/http re-serializes every parsed
    // request head with CRLF on write (`req.Write(remote)` — connectHandler
    // and the reverse proxy both forward the parsed request, never the raw
    // inbound bytes). The head region is therefore re-encoded here, before
    // the rewrite/inject block below edits it and before either branch
    // forwards it; the host-line and header-line scans that follow may rely
    // on CRLF anchors. Tail bytes (entity body / pipelined requests) are
    // forwarded verbatim — Go copies the body separately, and a body line
    // must never be mistaken for a header (audit fix). A CRLF-only head maps
    // byte-identically (no copy) — the common case.
    let request_head = frp_core::textproto::canonicalize_head_crlf(request_head);

    // Host rewrite + forwarded-header injection apply only to non-CONNECT
    // requests: Go's ServeHTTP routes CONNECT to connectHandler, which writes
    // `req.Write(remote)` RAW (http.go:282-285) — no host rewrite, no
    // SetXForwarded, no rc.Headers. Auth still gates above: checkRouteAuthByRequest
    // runs BEFORE the method gate, so a CONNECT to an auth-protected route is
    // still 407/401 before any byte is forwarded.
    let request_head = if !is_connect && !route.host_header_rewrite.is_empty() {
        rewrite_host_header(request_head, &route.host_header_rewrite)
    } else {
        request_head
    };

    // Go frp compat (pkg/util/vhost/http.go reverse proxy + stdlib
    // httputil.ProxyRequest.SetXForwarded): inject X-Forwarded-For (append
    // to existing value), X-Forwarded-Host (inbound Host as received, BEFORE
    // host_header_rewrite — Go rewrites `req.Host` after SetXForwarded),
    // X-Forwarded-Proto (always "http" here: r.In.TLS == nil on this plain
    // HTTP path; the HTTPS vhost muxer is SNI passthrough and never
    // injects), then requestHeaders (Set semantics — user-configured
    // overrides win, exactly like Go's rc.Headers loop after SetXForwarded).
    // The hop-by-hop strip (F3) runs FIRST, mirroring Go's ServeHTTP order:
    // removeHopByHopHeaders (with its Te/Upgrade re-adds) happens before the
    // Rewrite hook that SetXForwarded and the rc.Headers loop live in.
    let request_head = if is_connect {
        // CONNECT forwards raw — Go connectHandler (http.go:282-285):
        // no hop strip, no forwarded-header injection (Rewrite never runs).
        request_head
    } else {
        let (request_head, req_up_type) = strip_vhost_hop_by_hop_headers(request_head);
        // Go checks the requested upgrade protocol's printability BEFORE
        // stripping (reverseproxy.go: `if !ascii.IsPrint(reqUpType)`) and
        // answers through the proxy ErrorHandler — Go frp's 404 route-miss
        // response (http.go:128-137). req_up_type is Some only when the
        // Connection value named Upgrade; a non-printable value must never
        // reach a backend.
        if let Some(up) = &req_up_type {
            if !up.iter().all(|b| (0x20..=0x7e).contains(b)) {
                warn!(host = %host, path = %path, peer = %peer, "{} VHost: rejecting request for non-printable upgrade protocol (Go ascii.IsPrint gate)", scheme);
                return Err(VhostResolveError::NotFound);
            }
        }
        inject_vhost_request_headers(request_head, peer, raw_host, route.headers.as_slice())
    };

    Ok(VhostForward {
        proxy_name: group_proxy_name,
        run_id: group_run_id,
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
                    // Read the TLS ClientHello (SNI lives in the first
                    // record; 4096 bytes comfortably covers it). Deadline is
                    // Go's FIXED vhostReadWriteTimeout (service.go:65/342 —
                    // the HTTPS Muxer is constructed with it), immune to the
                    // user's vhost_http_timeout: the old config-derived
                    // clamp made the SNI read window stretch to the 24h cap
                    // under a hostile timeout setting.
                    let mut buf = [0u8; 4096];
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_secs(30),
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
                        // HTTPS group members share one SNI route, and Go
                        // dispatches each conn to whichever member accepts
                        // first (HTTPSGroup = baseGroup: every member's
                        // Listener reads the same acceptCh). frp-rs picks
                        // deterministically: round-robin over the https-kind
                        // members via the kind-keyed registry (the http and
                        // https groups may share the name). Owner-sticky
                        // routing would strand every conn on the first
                        // member while siblings stay idle.
                        let (proxy_name, run_id) = if route.group.is_empty() {
                            (route.proxy_name.to_string(), route.run_id.to_string())
                        } else {
                            match state
                                .http_group_ctl
                                .choose_endpoint(&route.group, true)
                                .await
                            {
                                Some(member) => {
                                    match state.proxy_manager.get(&member).await {
                                        Some(info) => {
                                            debug!(
                                                sni = %sni, group = %route.group,
                                                member = %member,
                                                "HTTPS VHost group '{}' -> member '{}'",
                                                route.group, member
                                            );
                                            (member, info.run_id.clone())
                                        }
                                        None => {
                                            // Member gone between choose and
                                            // lookup — fall back to the
                                            // route's recorded proxy.
                                            warn!(
                                                group = %route.group, member = %member,
                                                "HTTPS VHost: group member '{}' not registered, falling back to '{}'",
                                                member, route.proxy_name
                                            );
                                            (route.proxy_name.to_string(), route.run_id.to_string())
                                        }
                                    }
                                }
                                None => {
                                    // Group has no members — route to the
                                    // first member anyway; the control
                                    // dispatch will fail cleanly if it is
                                    // gone too.
                                    (route.proxy_name.to_string(), route.run_id.to_string())
                                }
                            }
                        };
                        let internal_tx = state
                            .run_id_to_ctl_tx
                            .get(run_id.as_str())
                            .map(|v| v.tx.clone());
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
                                ctl_tx.send(InternalMsg::ProxyUserConn {
                                    proxy_name,
                                    // Passthrough: raw encrypted bytes, no TLS wrap.
                                    user_conn: frp_core::transport::IoStream::Tcp(stream),
                                    pre_read,
                                    user_conn_permit: None,
                                    // Group selection was done here (choose_endpoint
                                    // above) — TCP-group re-selection must not
                                    // rerun. The receiving handler routes to the
                                    // named proxy as-is (group LB applies to TCP
                                    // groups only; http/https group members are
                                    // always pre-selected by the vhost router).
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
                        // Best-effort TLS alert before the drop: fatal
                        // unrecognized_name — record type 0x15 (alert),
                        // TLS 1.2 record, 2-byte payload 0x02 0x70
                        // (fatal, alertUnrecognizedName=112) — so a TLS
                        // client fails fast instead of hanging on a
                        // handshake timeout. Write failure is ignored;
                        // the connection is dropped either way.
                        let _ = stream
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70])
                            .await;
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
    /// host: None when no usable Host value is present (no Host header
    /// line, or an empty-valued "Host:" line — Go's MIME parser counts the
    /// line as present, but the value is ""). The caller applies Go's
    /// conn.readRequest wire-Host gate: HTTP/1.1 non-CONNECT with no Host
    /// LINE → 400 missing required Host header; every exempt shape routes
    /// on "" (Go req.Host fallback — always a route miss → 404). An
    /// absolute-form target with no wire Host carries its authority here
    /// and is still gated on the wire headers (Go checks the headers, not
    /// req.Host — probe ABS1.1NOHOST).
    /// `absolute_form` mirrors Go `req.URL.Host != ""` — an absolute-form
    /// request target ("GET http://host/…") — and drives the auth shape
    /// (Proxy-Authorization + 407, Go `checkRouteAuthByRequest`).
    Ok {
        host: Option<&'a str>,
        path: &'a str,
        absolute_form: bool,
    },
    /// Malformed version shape or malformed absolute URL (Go 400).
    BadRequest,
    /// Non-HTTP/1.x version (Go 505 HTTP Version Not Supported).
    VersionNotSupported,
}

/// Parse the request line with Go net/http `readRequest` semantics for the
/// vhost path (rounds 6 A3/A4/A7 + audit round 9 F1, verified against Go
/// 1.25.0 stdlib source and live probes).
///
/// Version handling mirrors `parseRequestLine` + `ParseHTTPVersion` +
/// `http1ServerSupportsRequest`:
/// - fewer than three SP-separated tokens (2-part "GET /", a bare method,
///   a tab-joined "GET /\tHTTP/1.1") → `BadRequest`. Go's parseRequestLine
///   requires TWO literal single-space cuts (method SP target SP version)
///   and fails the whole parse otherwise → 400 "malformed HTTP request".
///   (Go ≤1.19 instead defaulted a missing version to "HTTP/0.9" and 505'd
///   at the server gate; the default was removed with HTTP/0.9 support in
///   Go 1.20 — probes vs go1.25: all of these answer 400, never 505. An
///   EXPLICIT "HTTP/0.9" still parses and 505s at the gate below.)
/// - version not exactly 8 chars "HTTP/X.Y" with single digits
///   ("HTTP/1.10", "HTTP/1.x", "HTTP/11.0", trailing-space "HTTP/1.1 ") →
///   `BadRequest` (Go 400 "malformed HTTP version");
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
    // Go readRequest parity: a request that opens with a blank line is
    // "malformed HTTP request" → 400.
    if first_line.is_empty() {
        return RequestLine::BadRequest;
    }
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    // Go readRequest parity (F1, audit round 9): parseRequestLine returns
    // ok=false when EITHER literal-space Cut fails — a missing version
    // token ("GET /"), a bare method, or a tab-joined line all fail the
    // parse → 400 "malformed HTTP request". Go 1.20 removed the HTTP/0.9
    // default that made Go ≤1.19 505 these (probe vs go1.25: 400).
    let Some(version) = parts.next() else {
        return RequestLine::BadRequest;
    };

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

    // CONNECT authority-form (RFC 7230 §5.3.3 — Go net/http readRequest
    // `justAuthority`): Go prefixes the target with "http://" and runs
    // url.ParseRequestURI, so req.Host = req.URL.Host = the request-line
    // authority (any Host header is IGNORED for routing; probe vs Go
    // v0.71.0: a CONNECT with a mismatched Host header still reached the
    // authority's own proxy), req.URL.Path is the URL path — "" for a bare
    // "host:port" target, so a plain CONNECT must never match a
    // location-scoped route (probe: CONNECT to a locations-only host was
    // 404), and the auth shape is proxy-form — checkRouteAuthByRequest
    // sees URL.Host != "" and reads Proxy-Authorization only, answering
    // 407 + Proxy-Authenticate (probes: 407 with or without an
    // Authorization header; the right Proxy-Authorization creds tunnel).
    // The method gate is case-sensitive: a lowercase "connect" is not
    // justAuthority, Go parses its scheme-looking target as a URL whose
    // host is empty and 404s on the "" route — frp-rs routes the Host
    // header instead (accepted divergence on a garbage line: routing on
    // the Host header reaches only proxies the client could reach with a
    // valid request anyway).
    if method == "CONNECT" && !target.starts_with('/') {
        // Authority runs to the first '/', '?' or '#' (url.ParseRequestURI).
        let (authority, url_path) = match target.find(['/', '?', '#']) {
            Some(i) => (&target[..i], &target[i..]),
            None => (target, ""),
        };
        if authority.is_empty() {
            // "http://" + "" parses with URL.Host == "" (probe: an empty
            // CONNECT target was a 404 route-miss, never a 400): req.Host
            // falls back to the Host header and the request takes
            // origin-form semantics — the same fallback as "GET http://"
            // on an auth host (probe: 401 + WWW-Authenticate, not 407).
            return RequestLine::Ok {
                host: extract_host_header(request),
                path: split_path_and_query(url_path),
                absolute_form: false,
            };
        }
        // url.ParseRequestURI rejects a malformed authority BEFORE routing:
        // a non-empty non-digit port ("host:abc", "[::1]:80:90") or a
        // broken bracket pair ("[::1]x]:8080") is a 400 (probes: all 400
        // Bad Request). An empty port is legal ("host:" → "host"). This is
        // tcpmux's strict canonicalize_host — vhost's own
        // canonicalize_authority is the LENIENT Host-header variant (Go
        // routes "Host: example.com:abc"; the request line alone carries
        // url.ParseRequestURI's digit gate).
        let Some(host) = canonicalize_host(authority, true) else {
            return RequestLine::BadRequest;
        };
        return RequestLine::Ok {
            host: Some(host),
            path: split_path_and_query(url_path),
            absolute_form: true,
        };
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
            // Go url.ParseRequestURI("http://") and "http:///x" SUCCEED
            // with URL.Host == "" (probes vs Go v0.71.0: "GET http://" and
            // "GET http:///x" on an auth host answered 401 +
            // WWW-Authenticate — the origin shape, never 400, never 407):
            // req.Host falls back to the Host header, the request takes
            // origin-form semantics, and the path is the URL's path. The
            // old unconditional BadRequest here was wrong.
            return RequestLine::Ok {
                host: extract_host_header(request),
                path: {
                    let path = split_path_and_query(url_path);
                    if path.is_empty() {
                        "/"
                    } else {
                        path
                    }
                },
                absolute_form: false,
            };
        }
        // The same url.ParseRequestURI gate as CONNECT: a non-digit port
        // or mis-bracketed authority is a 400 (probes), an empty port is
        // legal. The pre-fix code canonicalized leniently and returned an
        // unroutable "" host — wrong: ParseRequestURI rejects before
        // CanonicalHost ever sees the value.
        let Some(host) = canonicalize_host(authority, true) else {
            return RequestLine::BadRequest;
        };
        let path = split_path_and_query(url_path);
        let path = if path.is_empty() { "/" } else { path };
        return RequestLine::Ok {
            host: Some(host),
            path,
            absolute_form: true,
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
        absolute_form: false,
    }
}

/// Go `req.ProtoAtLeast(1, 1)` on the raw request line — the wire-Host gate
/// (F4, audit round 9) only fires for HTTP/1.1+ (HTTP/1.0 and earlier are
/// exempt — probe 1.0NOHOST). Only "HTTP/1.x" version tokens survive
/// `parse_vhost_request_line`, so this reduces to a minor-digit check on
/// the third SP-separated token ("HTTP/1.0" → false). Callers have already
/// lossy-converted the head to UTF-8 (`request_text`), so byte access is
/// safe; `get(7)` guards a short token.
fn request_line_minor_gte_1(request: &str) -> bool {
    let Some(version) = request.lines().next().unwrap_or("").splitn(3, ' ').nth(2) else {
        return false;
    };
    version
        .as_bytes()
        .get(7)
        .is_some_and(|minor| *minor >= b'1')
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
    // Only the header block up to the first blank line is scanned (audit
    // fix): bytes past the terminator are entity body / pipelined requests
    // and must not be rewritten — a body containing "\r\nhost: evil" must
    // never be mutated, and a head without a Host header must not rewrite a
    // body line. Same bound as inject_vhost_request_headers. The caller
    // (resolve_vhost_request) canonicalized the head region to CRLF already,
    // so the textproto scan and the CRLF-anchored line searches below see
    // canonical input; the head_end helper still beats a raw "\r\n\r\n"
    // window scan when a tail that begins "\r\n" would otherwise extend the
    // window past the true blank line.
    let head_end = frp_core::textproto::head_end(&data).unwrap_or(data.len());
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

/// Audit round 9 (F3): remove the Go `httputil.ReverseProxy` hop-by-hop
/// header set from a forwarded non-CONNECT request head — the
/// `removeHopByHopHeaders` call in ServeHTTP (reverseproxy.go), mirrored in
/// Go's exact order and with Go's exact re-adds:
/// 1. every header NAMED by a Connection value token is removed (pass 1);
/// 2. the fixed hop set is removed (pass 2): Connection, Proxy-Connection,
///    Keep-Alive, Proxy-Authenticate, Proxy-Authorization, Te, Trailer,
///    Transfer-Encoding, Upgrade;
/// 3. `Te: trailers` is re-added when the INBOUND Te value contained the
///    "trailers" token (the Issue 21096 block — Go reads req.Header, the
///    pre-strip request);
/// 4. when the inbound Connection named Upgrade, exactly
///    `Connection: Upgrade` + `Upgrade: <value>` are re-added (the upgrade
///    value is captured BEFORE stripping — Go's upgradeType).
///
/// Why this exists: the old head forward passed every header verbatim, so
/// the client's route credential leaked to the local backend —
/// Proxy-Authorization, which an absolute-form request authenticated with
/// at the vhost gate (Go strips it from the outbound request and reads it
/// only at its own auth check, pkg/util/vhost/http.go
/// checkRouteAuthByRequest).
///
/// Entity headers are untouched — Authorization (origin-form credentials
/// belong to the backend, not the proxy), X-* and custom headers all
/// survive, as in Go.
///
/// Wire-framing notes where the raw-byte forward diverges from Go's
/// re-serialization: Go strips the Transfer-Encoding and Trailer map
/// entries and the transport then re-encodes the OUTBOUND request from
/// parsed state, putting `Transfer-Encoding: chunked` and the declared
/// trailer names back on the wire (chunk framing re-derived from
/// req.TransferEncoding / req.Trailer). frp-rs forwards the client's RAW
/// body bytes, so the framing lines must survive in the head: a
/// Transfer-Encoding line whose value is exactly "chunked" is dropped and
/// re-emitted canonically, and Trailer declaration lines are kept verbatim
/// — the backend needs both to frame the body it is about to receive. A
/// NON-chunked Transfer-Encoding value is kept verbatim too: Go's server
/// would have 501-rejected it before the proxy ran, but frp-rs has no such
/// gate and dropping the line would silently deframe a body that is
/// currently forwarded. Response-side stripping does not apply: the
/// frp-rs HTTP/1.1 bridge relays the backend's response bytes raw (the
/// divergence note at the ProxyUserConn bridge-handoff site).
///
/// CONNECT never passes through here — Go's ServeHTTP routes CONNECT to
/// connectHandler, which writes `req.Write(remote)` raw (http.go:282-285)
/// with every header as parsed. The caller runs this only on the
/// non-CONNECT arm, before the header injection (Go: removeHopByHopHeaders
/// runs before the Rewrite hook).
///
/// Returns the rewritten head plus the requested upgrade protocol
/// (Some(value)) when the inbound Connection named Upgrade — the caller
/// enforces Go's `!ascii.IsPrint(reqUpType)` rejection (checked BEFORE
/// stripping in ServeHTTP, answered via the proxy ErrorHandler → Go frp's
/// 404 route-miss response).
fn strip_vhost_hop_by_hop_headers(data: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) {
    let header_end = frp_core::textproto::head_end(&data).unwrap_or(data.len());
    let head = &data[..header_end];
    let tail = &data[header_end..];

    // OWS trim (space/tab) — Go textproto.TrimString.
    fn trim_ows(b: &[u8]) -> &[u8] {
        let s = b
            .iter()
            .position(|c| *c != b' ' && *c != b'\t')
            .unwrap_or(b.len());
        let e = b
            .iter()
            .rposition(|c| *c != b' ' && *c != b'\t')
            .map(|i| i + 1)
            .unwrap_or(s);
        &b[s..e]
    }

    let mut out: Vec<&[u8]> = Vec::with_capacity(16);
    // Connection value tokens — the names pass 1 removes (Go splits
    // h["Connection"] on commas, OWS-trimming each token).
    let mut conn_named: Vec<Vec<u8>> = Vec::new();
    // Upgrade value captured pre-strip (Go upgradeType: a Connection token
    // equal to "upgrade" gates the read of the first Upgrade header value).
    let mut upgrade_value: Option<Vec<u8>> = None;
    let mut connection_upgrade = false;
    // Inbound Te token list mentions "trailers" → the Issue-21096 re-add.
    let mut te_trailers = false;
    // A "Transfer-Encoding: chunked" line → dropped, re-emitted canonically
    // (the raw-body framing equivalent of Go's transport re-encode).
    let mut te_chunked = false;

    let mut lines = head.split_inclusive(|&b| b == b'\n');
    if let Some(request_line) = lines.next() {
        out.push(request_line); // the request line is not a header
    }
    for line in lines {
        // CRLF or bare-LF — the caller canonicalized the head region to
        // CRLF already, but the line walk tolerates both (and a
        // terminator-less final line) like the injector below.
        let trimmed = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(line);
        if trimmed.is_empty() {
            continue; // blank line — head_end already cut before it
        }
        let Some(colon) = trimmed.iter().position(|&b| b == b':') else {
            // No colon — obs-fold continuation or junk the MIME parser
            // never made a header; keep verbatim (same tolerance as the
            // header-value walk below).
            out.push(line);
            continue;
        };
        let name = &trimmed[..colon];
        let value = trim_ows(&trimmed[colon + 1..]);
        let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());

        if is("connection") {
            for tok in value.split(|&b| b == b',') {
                let tok = trim_ows(tok);
                if tok.is_empty() {
                    continue;
                }
                if tok.eq_ignore_ascii_case(b"upgrade") {
                    connection_upgrade = true;
                }
                if !conn_named.iter().any(|c| c == tok) {
                    conn_named.push(tok.to_vec());
                }
            }
            continue; // the Connection line itself never survives
        }
        if is("te") {
            te_trailers = value
                .split(|&b| b == b',')
                .map(trim_ows)
                .any(|t| t.eq_ignore_ascii_case(b"trailers"));
            continue;
        }
        if is("upgrade") {
            if upgrade_value.is_none() {
                upgrade_value = Some(value.to_vec()); // Go Header.Get: first
            }
            continue; // re-added below when Connection named Upgrade
        }
        if is("transfer-encoding") {
            if value.eq_ignore_ascii_case(b"chunked") {
                te_chunked = true;
                continue; // re-emitted canonically below
            }
            out.push(line); // non-chunked value — see the doc note
            continue;
        }
        if is("trailer") {
            // Trailer DECLARATIONS survive the drop (raw-body framing — see
            // the doc note; Go strips the line and the transport re-declares
            // the names on re-serialization, so keeping the verbatim line is
            // the wire-parity equivalent).
            out.push(line);
            continue;
        }
        if is("proxy-connection")
            || is("keep-alive")
            || is("proxy-authenticate")
            || is("proxy-authorization")
        {
            continue; // fixed hop set (pass 2) — Upgrade/Te/Connection fell
                      // out above, Trailer survives just above
        }
        if conn_named.iter().any(|c| name.eq_ignore_ascii_case(c)) {
            continue; // pass 1: Connection-named token removal
        }
        out.push(line);
    }

    let mut out_vec = Vec::with_capacity(data.len());
    for l in &out {
        out_vec.extend_from_slice(l);
    }
    // Go re-adds (ServeHTTP order): the Te block first, then the upgrade
    // pair.
    if te_trailers {
        out_vec.extend_from_slice(b"Te: trailers\r\n");
    }
    if te_chunked {
        out_vec.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    let upgrade = if connection_upgrade {
        upgrade_value
    } else {
        None
    };
    if let Some(u) = &upgrade {
        out_vec.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: ");
        out_vec.extend_from_slice(u);
        out_vec.extend_from_slice(b"\r\n");
    }
    out_vec.extend_from_slice(b"\r\n");
    out_vec.extend_from_slice(tail);
    (out_vec, upgrade)
}

/// Inject `X-Forwarded-For` (append semantics, Go httputil.ReverseProxy),
/// `X-Forwarded-Host` / `X-Forwarded-Proto` (Go `ProxyRequest.SetXForwarded`)
/// and configured requestHeaders (Set semantics, Go `req.Header.Set`) into
/// the request head bytes. Only the header block up to the first blank line
/// is touched (textproto head_end — the caller canonicalized the region to
/// CRLF already, so the split_inclusive line walk below sees canonical
/// input). The injection runs even when no requestHeaders are configured —
/// Go's Rewrite hook (pkg/util/vhost/http.go) unconditionally calls
/// `r.SetXForwarded()`; a configured header list is not a gate.
/// `x_forwarded_host` must be the PRE-rewrite inbound Host (Go's
/// SetXForwarded reads `r.In.Host`; host_header_rewrite lands on
/// `r.Out.Host` after it); empty → line omitted (Go `r.In.Host != ""`).
fn inject_vhost_request_headers(
    data: Vec<u8>,
    peer: std::net::SocketAddr,
    x_forwarded_host: &str,
    request_headers: &[(String, String)],
) -> Vec<u8> {
    let header_end = frp_core::textproto::head_end(&data).unwrap_or(data.len());
    let head = &data[..header_end];
    let tail = &data[header_end..];

    // Collect header lines, dropping ones that request_headers will override
    // (case-insensitive Set semantics) and X-Forwarded-For (re-emitted with
    // the peer appended).
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut existing_xff: Vec<u8> = Vec::new();
    // Precompute override prefixes once (case-insensitive ASCII set semantics):
    // `format!("{}:", ...)` + `to_lowercase()` per header line per request is
    // wasted allocation — header names are ASCII, and the trailing ':' is the
    // line-compare boundary itself. The same Vec gates the auto-emitted
    // X-Forwarded-* lines below (Go Set-replaces them); stripping the ':'
    // yields the bare name for those comparisons.
    let mut override_prefixes: Vec<Vec<u8>> = Vec::with_capacity(request_headers.len());
    for (k, _) in request_headers {
        let mut p = k.as_bytes().to_ascii_lowercase();
        p.push(b':');
        override_prefixes.push(p);
    }
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
    // Go Rewrite-hook order (pkg/util/vhost/http.go:59-87): SetXForwarded
    // emits the auto X-Forwarded-* lines FIRST, then the rc.Headers loop
    // applies each configured requestHeader with `req.Header.Set` — Set
    // REPLACES the value SetXForwarded just wrote, so a requestHeader named
    // x-forwarded-for / x-forwarded-host / x-forwarded-proto suppresses the
    // auto line and ships the configured value alone (single header, config
    // wins — never two lines, never an append).
    let overrides_xff = override_prefixes
        .iter()
        .any(|p| &p[..p.len() - 1] == b"x-forwarded-for");
    let overrides_xfh = override_prefixes
        .iter()
        .any(|p| &p[..p.len() - 1] == b"x-forwarded-host");
    let overrides_xfp = override_prefixes
        .iter()
        .any(|p| &p[..p.len() - 1] == b"x-forwarded-proto");
    // X-Forwarded-For: append peer (Go ReverseProxy appends to prior value).
    if !overrides_xff {
        let mut xff = existing_xff;
        xff.extend_from_slice(peer.ip().to_string().as_bytes());
        out.extend_from_slice(b"X-Forwarded-For: ");
        out.extend_from_slice(&xff);
        out.extend_from_slice(b"\r\n");
    }
    // X-Forwarded-Host: inbound Host as received (Go SetXForwarded:
    // `r.In.Host != ""` guard, pre-rewrite value). Emitted AFTER XFF, both
    // before the configured headers, which may override them (Go `Header.Set`
    // semantics — the rc.Headers loop runs after SetXForwarded).
    if !overrides_xfh && !x_forwarded_host.is_empty() {
        out.extend_from_slice(b"X-Forwarded-Host: ");
        out.extend_from_slice(x_forwarded_host.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // X-Forwarded-Proto: "http" — Go `r.In.TLS == nil → "http"`. This
    // injector only ever runs on the plain-HTTP vhost path (HTTP/1.1 + h2c);
    // the HTTPS vhost muxer is SNI passthrough with no HTTP layer to inject
    // into, so "https" is unreachable here.
    if !overrides_xfp {
        out.extend_from_slice(b"X-Forwarded-Proto: http\r\n");
    }
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
    extract_basic_auth_named(request, "authorization:")
}

/// Same parser with a configurable header name — absolute-form requests
/// (Go `req.URL.Host != ""`) carry credentials in `Proxy-Authorization`
/// instead (Go `checkRouteAuthByRequest` reads ONLY that header there).
/// `header` must include the trailing colon (e.g. "proxy-authorization:").
fn extract_basic_auth_named(request: &str, header: &str) -> Option<(String, String)> {
    // `get(..header.len())`, not `line[..header.len()]`: a hostile header
    // line with a multibyte UTF-8 char straddling the fixed-offset cut
    // would panic the slice (process abort under panic=abort) on EVERY
    // vhost request. get() returns None at any length/boundary violation
    // and behaves identically when the cut is on a char boundary.
    let auth_line = request.lines().find(|line| {
        line.get(..header.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(header))
    })?;
    // Go parity (pkg/util/http/http.go ParseBasicAuth, net/textproto
    // readMIMEHeader): the MIME reader trims the value's outer whitespace
    // (leading AND trailing — `trim` in readContinuedLineSlice), the
    // "Basic " scheme prefix matches CASE-INSENSITIVELY (Go Issue 22736),
    // and the base64 payload is taken verbatim — NO interior trim, so
    // "Basic  xyz" (double space) fails the decode exactly like Go's
    // base64.StdEncoding.
    let value = auth_line[header.len()..].trim();
    let encoded = if value
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("Basic "))
    {
        &value[6..]
    } else {
        return None;
    };
    let decoded = frp_core::base64::decode(encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pwd) = creds.split_once(':')?;
    Some((user.to_string(), pwd.to_string()))
}

/// Does the head carry a `header:` line with a non-empty value? Go
/// `http.Header.Get` returns "" both for an absent header and an
/// empty-valued one, so the two are indistinguishable there — only a
/// PRESENT non-empty value forces the `ParseBasicAuth` path in
/// `getRequestRouteUser` (a malformed value then routes to the "" user
/// bucket instead of falling back to Authorization).
///
/// FIRST-VALUE semantics: Go readMIMEHeader stores duplicate headers as a
/// slice and `Header.Get` returns `v[0]` only — a first empty-valued line
/// shadows a later non-empty one (keeping the "" → Authorization
/// fallback). `.any()` would see the later line and force the "" bucket;
/// `.find()` by header name + value check on THAT line matches Go. The
/// `get(..header.len())` scan (not `line[..header.len()]`) also keeps a
/// multibyte char straddling the cut from panicking (panic=abort).
fn has_nonempty_header(request: &str, header: &str) -> bool {
    request
        .lines()
        .find(|line| {
            line.get(..header.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(header))
        })
        .is_some_and(|line| !line[header.len()..].trim().is_empty())
}

/// Count Host header lines (RFC 7230 §5.4 allows at most one). Must only be
/// called on the textproto head region (up to the first blank line, any EOL
/// convention) — see `handle_http1_request`.
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

/// Canonicalize an authority value (host[:port] or [v6]:port) for vhost
/// routing — port strip, bracket handling, exactly one trailing dot.
/// Go frp `CanonicalHost` semantics (pkg/util/http/http.go:54-67), shared
/// by the Host-header path, the absolute-form URL authority path (A3), and
/// the h2c path (vhost_h2c.rs): `hasPort` gate (colons==1, or
/// bracket-start with `]:`), then `net.SplitHostPort`, then exactly one
/// trailing dot trimmed. (CanonicalHost also lowercases — `strings.ToLower`
/// before the gate; here the lowercase lives at the ROUTE LOOKUP instead —
/// router.go `Get` parity, see `get_locked` — with identical
/// case-insensitive routing and the same accepted Unicode-case divergence.
/// The function stays borrowed `&str` because vhost_h2c.rs shares it.)
///
/// SplitHostPort ACCEPTS an empty port — it slices `port = hostport[i+1:]`
/// unconditionally (net/ipsock.go; the official test pins {"golang.org:",
/// "golang.org", ""}) — so "example.com:" routes to "example.com" — and
/// never validates the port digits ("example.com:abc" → "example.com"; the
/// digit gate exists only on the CONNECT request line via
/// url.ParseRequestURI's validOptionalPort). Bracket errors are
/// fail-closed: a ']' not immediately followed by the last colon
/// ("[::1]x]:8080" → "missing port in address") and a second colon after
/// the bracket's port ("[::1]:80:90" → "too many colons in address") are
/// SplitHostPort ERRORS → "" (unroutable), never the bare "::1". Portless
/// values are used as-is — "example.com", or "[::1]" which stays bracketed
/// (unroutable, nothing registers brackets).
fn canonicalize_authority(value: &str) -> &str {
    let colons = value.bytes().filter(|b| *b == b':').count();
    let hostname = if colons == 1 {
        // host:port — SplitHostPort never validates the port digits
        // (Go frp routes "Host: example.com:abc" to example.com); the
        // digit gate exists only on the REQUEST LINE (CONNECT
        // authority-form and absolute-form targets), where
        // url.ParseRequestURI enforces it (validOptionalPort) — handled
        // by tcpmux's strict canonicalize_host, imported above. An EMPTY
        // port part ("example.com:") is legal — Go slices `port =
        // hostport[i+1:]` unconditionally and its own test suite pins
        // {"golang.org:", "golang.org", ""} — CanonicalHost routes the
        // bare hostname (lowercased, trailing dot trimmed).
        value.rsplit_once(':').unwrap_or((value, "")).0
    } else if colons >= 2 && value.starts_with('[') && value.contains("]:") {
        let end = value.find(']').unwrap_or(0);
        if !value[end + 1..].starts_with(':') {
            // ']' not immediately followed by ':' — Go SplitHostPort
            // errors ("missing port in address": the bracket's port must
            // run to the LAST colon) → CanonicalHost "" (unroutable).
            ""
        } else if value[end + 2..].contains(':') {
            // Too many colons ("[::1]:80:90") — Go ipsock.go errors when
            // the colon behind the ']' is not the last one ("too many
            // colons in address") → CanonicalHost "" (unroutable).
            ""
        } else {
            // Bracket form with a port (possibly empty: "[::1]:" → "::1")
            // — Go's bracket branch strips the brackets
            // (`host = hostport[1:end]`).
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

/// Raw inbound host for X-Forwarded-Host — Go net/http `req.Host`, NOT
/// canonicalized: absolute-form → request-line authority verbatim (port and
/// case preserved; Go `req.Host = req.URL.Host`); origin-form → the Host
/// header value, OWS-trimmed only (Go keeps the value as received).
/// CanonicalHost (lowercase, port strip) feeds ROUTING only — SetXForwarded
/// uses `r.In.Host` as received, so `canonicalize_authority` must not run
/// here ("example.com:8080" keeps its port, "ExAmPlE.com." keeps its dot).
fn extract_raw_request_host(request: &str, is_absolute_form: bool) -> &str {
    if is_absolute_form {
        // First-line request target — Go req.Host = req.URL.Host, used
        // verbatim (port and case preserved). Absolute-form GETs carry
        // "scheme://authority[/…]" (authority ends at the first '/', '?'
        // or '#' — url.ParseRequestURI); a bare CONNECT authority has no
        // scheme, so the target itself is the authority, truncated at the
        // same delimiters (round-3 M4: previously the no-scheme fallback
        // returned "", losing the port from X-Forwarded-Host).
        let target = request
            .lines()
            .next()
            .unwrap_or("")
            .split(' ')
            .nth(1)
            .unwrap_or("");
        let rest = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
            .unwrap_or(target);
        return rest.split(['/', '?', '#']).next().unwrap_or("");
    }
    for line in request.lines() {
        if line.len() < 5 {
            continue;
        }
        if line
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("host:"))
        {
            return line[5..].trim();
        }
    }
    ""
}

fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        if line.len() < 6 {
            continue;
        }
        // `get(..5)`, not `line[..5]`: len ≥ 6 does NOT imply byte 5 is a
        // char boundary — "abcéé…" has é (2 bytes) straddling the cut, and
        // the fixed-offset slice panicked (process abort under panic=abort)
        // on every origin-form vhost request. get() returns None on any
        // boundary violation; identical match when byte 5 is a boundary.
        if !line
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("host:"))
        {
            continue;
        }
        // Safe: the get(..5) match above guarantees byte 5 is a boundary.
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

    /// Round-15 correction: a trailing colon with an EMPTY port part is
    /// LEGAL — Go `net.SplitHostPort` slices `port = hostport[i+1:]`
    /// unconditionally (net/ipsock.go; the official test pins
    /// {"golang.org:", "golang.org", ""}) → `CanonicalHost` routes the
    /// bare hostname (lowercased, trailing dot trimmed).
    #[test]
    fn test_canonicalize_authority_empty_port() {
        // "example.com:" routes to "example.com".
        assert_eq!(canonicalize_authority("example.com:"), "example.com");
        // Lowercase is applied at the route lookup (Go router.go `Get` —
        // see `get_locked`), not here — identical case-insensitive routing
        // to Go's CanonicalHost while keeping the borrowed `&str` that
        // vhost_h2c.rs shares.
        assert_eq!(canonicalize_authority("GOLANG.ORG:"), "GOLANG.ORG");
        // The trailing-dot trim still applies after the port strip.
        assert_eq!(canonicalize_authority("example.com.:"), "example.com");
        // A normal port still strips (and is never digit-validated —
        // SplitHostPort accepts any suffix).
        assert_eq!(canonicalize_authority("example.com:8080"), "example.com");
        assert_eq!(canonicalize_authority("example.com:abc"), "example.com");
        // Bracketed IPv6 with a port — possibly empty — strips the
        // brackets (Go bracket branch `host = hostport[1:end]`).
        assert_eq!(canonicalize_authority("[::1]:8080"), "::1");
        assert_eq!(canonicalize_authority("[::1]:"), "::1");
        // Too many colons after the bracket: Go errors ("too many colons
        // in address") → "" (unroutable), NOT the bare "::1".
        assert_eq!(canonicalize_authority("[::1]:80:90"), "");
        // ']' not immediately followed by the last colon: Go errors
        // ("missing port in address") → "" (unroutable).
        assert_eq!(canonicalize_authority("[::1]x]:8080"), "");
        // Portless values and other shapes are untouched.
        assert_eq!(canonicalize_authority("example.com"), "example.com");
        assert_eq!(canonicalize_authority("[::1]"), "[::1]");
        assert_eq!(
            canonicalize_authority("example.com:8080:90"),
            "example.com:8080:90"
        );
    }

    /// The header-scan helpers must never panic on hostile multi-byte
    /// input: they used to slice `&str` at fixed byte offsets
    /// (`line[..header.len()]` / `line[..5]`), and a UTF-8 char straddling
    /// the cut aborted the process (panic=abort) on ANY vhost request.
    /// Now `line.get(..n)` returns None at a non-boundary cut, so the line
    /// is skipped like any non-matching one.
    #[test]
    fn test_header_scans_panic_proof_multibyte() {
        // é (U+00E9) = 0xC3 0xA9. "x-pad: abcdefé": byte 13 is the FIRST
        // byte of é → the 14-byte "authorization:" scan cuts mid-char.
        let req = "GET / HTTP/1.1\r\nx-pad: abcdefé\r\n\r\n";
        assert_eq!(extract_basic_auth(req), None);
        assert!(!has_nonempty_header(req, "authorization:"));
        // Same shape for the 20-byte "proxy-authorization:" scan: é spans
        // bytes 19-20 of "proxy-authorizationé".
        let req = "GET / HTTP/1.1\r\nproxy-authorizationé\r\n\r\n";
        assert_eq!(extract_basic_auth_named(req, "proxy-authorization:"), None);
        assert!(!has_nonempty_header(req, "proxy-authorization:"));
        // "abcéé": byte 4 is the CONTINUATION byte of the first é → the
        // 5-byte "host:" scan cuts mid-char. The scan skips the line and
        // still finds the real Host header...
        let req = "GET / HTTP/1.1\r\nabcéé\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("example.com"));
        // ...and a head with no Host at all yields None, not a panic.
        assert_eq!(
            extract_host_header("GET / HTTP/1.1\r\nabcéé\r\nx-pad: abcdefé\r\n\r\n"),
            None
        );
    }

    /// Go frp ParseBasicAuth parity (pkg/util/http/http.go:81-97): the
    /// "Basic " scheme prefix matches CASE-INSENSITIVELY (Go Issue 22736)
    /// and the base64 payload is taken verbatim — an interior space after
    /// the scheme ("Basic  xyz") fails the decode exactly like Go's
    /// base64.StdEncoding, while line-end whitespace is stripped by the
    /// MIME reader in both (textproto `trim` handles both ends). An
    /// unpadded payload is rejected: Go StdEncoding requires padding and
    /// the inline codec requires `len % 4 == 0`.
    #[test]
    fn test_extract_basic_auth_case_insensitive_no_trim() {
        // Case-insensitive scheme prefix.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: bAsIc dXNlcjpwYXNz\r\n\r\n"),
            Some(("user".to_string(), "pass".to_string()))
        );
        // "user:pass" (9 bytes) encodes without '=' padding — decodes fine.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"),
            Some(("user".to_string(), "pass".to_string()))
        );
        // Interior whitespace after the scheme is NOT trimmed (Go takes
        // auth[6:] verbatim) → base64 decode fails → None.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic  dXNlcjpwYXNz\r\n\r\n"),
            None
        );
        // An unpadded payload (this one needs "==") is rejected — Go
        // StdEncoding and the inline codec agree.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzIQ\r\n\r\n"),
            None
        );
        // Trailing line whitespace: Go's textproto trims both ends of the
        // value, so this decodes — unlike the interior-space case above.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz  \r\n\r\n"),
            Some(("user".to_string(), "pass".to_string()))
        );
        // Wrong scheme still fails.
        assert_eq!(
            extract_basic_auth("GET / HTTP/1.1\r\nAuthorization: Bearer dXNlcjpwYXNz\r\n\r\n"),
            None
        );
    }

    #[test]
    fn test_clamp_vhost_timeout() {
        // Go parity: `<= 0` floors at 60s; positive values pass through up
        // to the 24h cap. Above it (incl. u64::MAX from a hostile config)
        // the value would overflow the `Instant::now() + from_secs` deadline
        // add at serve_vhost_request / serve_h2c_request — an abort under
        // the release `panic=abort` profile — so it clamps instead.
        assert_eq!(clamp_vhost_timeout(0), 60);
        assert_eq!(clamp_vhost_timeout(1), 1);
        assert_eq!(clamp_vhost_timeout(30), 30);
        assert_eq!(clamp_vhost_timeout(60), 60);
        assert_eq!(clamp_vhost_timeout(120), 120);
        assert_eq!(
            clamp_vhost_timeout(VHOST_TIMEOUT_CAP_SECS),
            VHOST_TIMEOUT_CAP_SECS
        );
        assert_eq!(
            clamp_vhost_timeout(VHOST_TIMEOUT_CAP_SECS + 1),
            VHOST_TIMEOUT_CAP_SECS
        );
        assert_eq!(clamp_vhost_timeout(u64::MAX), VHOST_TIMEOUT_CAP_SECS);
    }

    #[test]
    fn test_has_nonempty_header() {
        // Absent → false (Go Header.Get returns "" for absent too).
        assert!(!has_nonempty_header(
            "GET http://x.example.com/ HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
            "proxy-authorization:"
        ));
        // Present with a value → true (forces the ParseBasicAuth path).
        assert!(has_nonempty_header(
            "GET http://x.example.com/ HTTP/1.1\r\nProxy-Authorization: Basic !!!\r\n\r\n",
            "proxy-authorization:"
        ));
        // Empty-valued / whitespace-only → false (Go Get returns "").
        assert!(!has_nonempty_header(
            "GET http://x.example.com/ HTTP/1.1\r\nProxy-Authorization:\r\n\r\n",
            "proxy-authorization:"
        ));
        assert!(!has_nonempty_header(
            "GET http://x.example.com/ HTTP/1.1\r\nProxy-Authorization:   \r\n\r\n",
            "proxy-authorization:"
        ));
        // Case-insensitive header name match.
        assert!(has_nonempty_header(
            "GET http://x.example.com/ HTTP/1.1\r\nproxy-authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            "proxy-authorization:"
        ));
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
        // F1 (audit round 9): Go 1.25 parseRequestLine requires TWO literal
        // space cuts — method SP target SP version — so a missing version
        // token is a parse failure → 400 "malformed HTTP request" (probe
        // T2TOK vs go1.25: 400). The HTTP/0.9 default + 505 was Go ≤1.19
        // behavior; HTTP/0.9 support was removed in Go 1.20.
        assert_eq!(parse_vhost_request_line("GET /"), RequestLine::BadRequest);
        // Tab-joined request line: the tab is not the SP the parser cuts
        // on, so the version token never parses → 400 (probe TABJOIN).
        assert_eq!(
            parse_vhost_request_line("GET /\tHTTP/1.1"),
            RequestLine::BadRequest
        );
        // A bare method (no target, no version) → first Cut fails → 400.
        assert_eq!(parse_vhost_request_line("GET"), RequestLine::BadRequest);
        // Explicit HTTP/0.9 still PARSES (ParseHTTPVersion accepts the
        // 8-char shape) and 505s at the http1ServerSupportsRequest gate —
        // only the IMPLICIT missing-version default was removed (probe
        // EXPL09: 505).
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/0.9"),
            RequestLine::VersionNotSupported
        );
        // Trailing-space version token: splitn(3, ' ') keeps the space in
        // the third token ("HTTP/1.1 ") — the 8-char shape check fails,
        // like Go's Cut + ParseHTTPVersion ("malformed HTTP version", 400).
        assert_eq!(
            parse_vhost_request_line("GET / HTTP/1.1 "),
            RequestLine::BadRequest
        );
        // Empty third token ("GET / " → "") is an empty version → 400.
        assert_eq!(parse_vhost_request_line("GET / "), RequestLine::BadRequest);
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
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line("GET /abc HTTP/1.1\r\nHost: x.example.com\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("x.example.com"));
        assert_eq!(path, "/abc");
        assert!(!absolute_form, "origin-form must not be marked absolute");
    }

    #[test]
    fn test_parse_vhost_request_line_absolute_form() {
        // A3/A4: absolute-form routes on the URL authority; ANY Host
        // header is ignored (RFC 7230 §5.3, req.Host = req.URL.Host).
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line(
            "GET http://a.example.com:8080/api?x=1 HTTP/1.1\r\nHost: ignored.example.com\r\n\r\n",
        )
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com")); // port stripped
        assert_eq!(path, "/api"); // query stripped, Go req.URL.Path
        assert!(absolute_form, "absolute-form must be marked");
        // Absolute-form with no path → "/".
        let RequestLine::Ok { path, .. } =
            parse_vhost_request_line("GET http://a.example.com HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(path, "/");
        // M4 (empirical probes vs Go frp v0.71.0): url.ParseRequestURI
        // ACCEPTS an empty authority — "http://" and "http:///x" both
        // parse with URL.Host == "" → req.Host falls back to the Host
        // header and the request takes origin-form semantics ("GET http://"
        // on an auth host answered 401 + WWW-Authenticate, never 400,
        // never 407). The old unconditional BadRequest pins were wrong.
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line("GET http:///x HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("x")); // Host header fallback
        assert_eq!(path, "/x"); // the URL's own path
        assert!(!absolute_form, "origin-form semantics");
        let RequestLine::Ok { path, .. } =
            parse_vhost_request_line("GET http:// HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(path, "/");
        // Empty authority with NO Host header → host None (caller 400s —
        // Go readRequest "missing required Host header").
        let RequestLine::Ok { host, .. } = parse_vhost_request_line("GET http:// HTTP/1.1\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, None);
        // Bracketed IPv6 authority.
        let RequestLine::Ok { host, .. } =
            parse_vhost_request_line("GET https://[::1]:8080/ HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("::1"));
        // M4 (probes): url.ParseRequestURI rejects a malformed authority
        // BEFORE routing — mis-brackets and non-digit ports are 400s.
        assert_eq!(
            parse_vhost_request_line("GET http://[::1]x]:8080/ HTTP/1.1\r\nHost: x\r\n\r\n"),
            RequestLine::BadRequest
        );
        assert_eq!(
            parse_vhost_request_line("GET http://a.example.com:abc/ HTTP/1.1\r\nHost: x\r\n\r\n"),
            RequestLine::BadRequest
        );
        assert_eq!(
            parse_vhost_request_line("GET http://[::1]:80:90/ HTTP/1.1\r\nHost: x\r\n\r\n"),
            RequestLine::BadRequest
        );
        // Empty port stays legal (probe: routed, not 400).
        let RequestLine::Ok { host, .. } =
            parse_vhost_request_line("GET http://a.example.com: HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com"));
    }

    #[test]
    fn test_parse_vhost_request_line_connect_authority_form() {
        // M4 (empirical probe matrix vs Go frp v0.71.0, rows 04-19):
        // a CONNECT with a non-"/" target is authority-form (Go readRequest
        // justAuthority → "http://" + target → ParseRequestURI) — req.Host
        // = the request-line authority, Host header IGNORED.
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line("CONNECT a.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com")); // port stripped
        assert_eq!(path, ""); // Go req.URL.Path — plain CONNECTs must not
                              // match location-scoped routes (probe: 404)
        assert!(absolute_form, "proxy-form auth + authority routing");
        // A mismatched Host header is ignored entirely (probe 14: the
        // authority's own proxy was reached).
        let RequestLine::Ok { host, .. } = parse_vhost_request_line(
            "CONNECT a.example.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n",
        ) else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com"));
        // Portless and empty-port authorities are legal (probes 06/07).
        for target in [
            "CONNECT a.example.com HTTP/1.1",
            "CONNECT a.example.com: HTTP/1.1",
        ] {
            let line = format!("{target}\r\nHost: x\r\n\r\n");
            let RequestLine::Ok { host, path, .. } = parse_vhost_request_line(&line) else {
                panic!("expected Ok for {target}");
            };
            assert_eq!(host, Some("a.example.com"));
            assert_eq!(path, "");
        }
        // url.ParseRequestURI 400-gates (probes 05/18/29): non-digit port,
        // mis-brackets, extra colon after the bracket.
        for target in [
            "CONNECT a.example.com:abc HTTP/1.1",
            "CONNECT [::1]x]:8080 HTTP/1.1",
            "CONNECT [::1]:80:90 HTTP/1.1",
        ] {
            assert_eq!(
                parse_vhost_request_line(&format!("{target}\r\nHost: x\r\n\r\n")),
                RequestLine::BadRequest,
                "{target} must 400"
            );
        }
        // Colon-only authority ":443" → SplitHostPort host "" → routes
        // nothing (probe 26: 404; Go URL.Host ":443" is non-empty so the
        // request stays authority-form).
        let RequestLine::Ok {
            host,
            absolute_form,
            ..
        } = parse_vhost_request_line("CONNECT :443 HTTP/1.1\r\nHost: a.example.com\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some(""));
        assert!(absolute_form);
        // Bracketed IPv6 parses to the bare address (probe 19: parse Ok,
        // no route for "::1" → 404).
        let RequestLine::Ok { host, .. } =
            parse_vhost_request_line("CONNECT [::1]:8080 HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("::1"));
        // Empty target → origin-form fallback on the Host header (probe 16:
        // 404 route-miss — "http://" parses with URL.Host "" → req.Host =
        // Host header; never a 400).
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line("CONNECT  HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("x"));
        assert_eq!(path, "");
        assert!(!absolute_form);
        // Scheme-bearing target: Go url.Parse sees scheme "http" then an
        // authority of "http:" (the second scheme's colon) — the route key
        // is the garbage host "http" and no route matches → 404 (probe 17).
        let RequestLine::Ok { host, path, .. } =
            parse_vhost_request_line("CONNECT http://a.example.com/ HTTP/1.1\r\nHost: x\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("http"));
        assert_eq!(path, "//a.example.com/");
        // Lowercase "connect" is NOT authority-form (Go method gate is
        // case-sensitive — probe 15: 404): stays origin-form, routing on
        // the Host header. Accepted divergence on a garbage line.
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line(
            "connect a.example.com:443 HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
        )
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com"));
        assert_eq!(path, "a.example.com:443");
        assert!(!absolute_form);
        // Path-form CONNECT stays origin-form (Go justAuthority requires
        // a non-"/" target).
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line("CONNECT /tunnel HTTP/1.1\r\nHost: a.example.com\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com"));
        assert_eq!(path, "/tunnel");
        assert!(!absolute_form);
    }

    #[test]
    fn test_parse_vhost_request_line_origin_form_query() {
        // A4: origin-form path minus query (Go req.URL.Path) — query
        // strings must not influence location matching.
        let RequestLine::Ok {
            host,
            path,
            absolute_form,
        } = parse_vhost_request_line(
            "GET /api/v1?user=admin#frag HTTP/1.1\r\nHost: a.example.com:8080\r\n\r\n",
        )
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, Some("a.example.com"));
        assert_eq!(path, "/api/v1");
        assert!(!absolute_form, "origin-form must not be marked absolute");
        // Missing Host header → Ok with host None (caller 400s).
        let RequestLine::Ok { host, .. } = parse_vhost_request_line("GET / HTTP/1.1\r\n\r\n")
        else {
            panic!("expected Ok");
        };
        assert_eq!(host, None);
    }

    #[tokio::test]
    async fn test_write_not_found_response_go_shape() {
        let mut buf = Vec::new();
        write_not_found_response(&mut buf, "").await;
        // Head is fixed-order and fixed-shape vs Go's NotFoundResponse
        // literal; builtin body is 489 bytes → Content-Length: 489.
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 489\r\nContent-Type: text/html\r\nServer: frp/"
        ));
        let head_end = resp.find("\r\n\r\n").expect("blank line after the head") + 4;
        // The body byte count must match the declared Content-Length.
        assert_eq!(
            resp.len() - head_end,
            489,
            "body length must match Content-Length: 489"
        );
        assert!(resp.contains("The page you requested was not found."));
    }

    #[tokio::test]
    async fn test_write_not_found_response_custom_body() {
        let mut buf = Vec::new();
        write_not_found_response(&mut buf, "<h1>Not Found</h1>").await;
        let resp = String::from_utf8_lossy(&buf);
        // "<h1>Not Found</h1>" is 18 bytes → Content-Length: 18.
        assert!(resp.starts_with(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 18\r\nContent-Type: text/html\r\nServer: frp/"
        ));
        assert!(resp.ends_with("\r\n\r\n<h1>Not Found</h1>"));
        // A non-empty custom body (even whitespace) replaces the builtin.
        let mut buf = Vec::new();
        write_not_found_response(&mut buf, " ").await;
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("Content-Length: 1"));
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

    /// wildcard_count stays symmetric across register/unregister, and the
    /// fast-exit (no wildcard routes registered) resolves the exact match
    /// without running the wildcard expansion.
    #[tokio::test]
    async fn test_vhost_wildcard_count_gate() {
        let mgr = VhostManager::new();
        // Exact-only registrations leave the counter at 0.
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
        {
            let tables = mgr.inner.read().await;
            assert_eq!(tables.wildcard_count, 0, "exact route must not count");
        }
        // Wildcard registration bumps the counter once per wildcard domain.
        mgr.register(
            "p2",
            &["*.example.com".into(), "exact2.example.com".into()],
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
        {
            let tables = mgr.inner.read().await;
            assert_eq!(tables.wildcard_count, 1, "one wildcard domain counted");
        }
        // The gate still routes the exact match when a wildcard exists.
        let r = mgr
            .lookup_wildcard("a.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");

        // Unregistering the wildcard proxy restores the counter.
        mgr.unregister("p2").await;
        {
            let tables = mgr.inner.read().await;
            assert_eq!(tables.wildcard_count, 0, "unregister must decrement");
        }
        // With no wildcards left, the fast-exit path answers the exact match.
        let r = mgr
            .lookup_wildcard("a.example.com", "/", "", "http")
            .await
            .unwrap();
        assert_eq!(r.proxy_name.as_ref(), "p1");
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

    /// Go registers one Router per (domain, location, httpUser) triple and
    /// sorts ALL of them flat before first-match probing. A route-first scan
    /// over interleaved multi-location sets diverges: with A at
    /// ["/zz", "/a"] and B at ["/aa"], Go's flattened order "/zz"(A),
    /// "/aa"(B), "/a"(A) routes "/aa" to B — a route-first probe would check
    /// A's "/a" first and wrongly pick A. The best-match scan reproduces the
    /// flattened order exactly.
    #[test]
    fn test_find_matching_route_interleaved_multi_location() {
        let mut routes = vec![
            route("a", &["/zz".into(), "/a".into()]),
            route("b", &["/aa".into()]),
        ];
        sort_by_longest_location(&mut routes);
        // A sorts first (its "/zz" key is largest), so a route-first
        // first-match scan would probe A first.
        assert_eq!(routes[0].proxy_name.as_ref(), "a");

        // "/aa" → B (flattened order: "/aa" before "/a").
        let m = find_matching_route(&routes, "/aa", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "b");
        // "/a" → A (B's "/aa" does not prefix-match "/a").
        let m = find_matching_route(&routes, "/a", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "a");
        // "/zzzz" → A (A's "/zz").
        let m = find_matching_route(&routes, "/zzzz", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "a");
        // "/aab" → B ("/aa" is longer than "/a").
        let m = find_matching_route(&routes, "/aab", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "b");
        // A no-location route only wins when nothing else matches.
        let mut with_catchall = vec![
            route("a", &["/zz".into(), "/a".into()]),
            route("b", &["/aa".into()]),
            route("c", &[]),
        ];
        sort_by_longest_location(&mut with_catchall);
        let m = find_matching_route(&with_catchall, "/none", "http").unwrap();
        assert_eq!(m.proxy_name.as_ref(), "c");
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
        // Whitespace between "Basic" and the payload is NOT trimmed (Go
        // takes auth[6:] verbatim — a space is an invalid base64 char, so
        // StdEncoding fails → None, exactly like the round-16 fix's
        // test_extract_basic_auth_case_insensitive_no_trim).
        let req = "GET / HTTP/1.1\r\nAuthorization: Basic   dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(extract_basic_auth(req), None);
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

        // `head` is passed in per call (a clone) so the closure never
        // borrows the fn-local `head` — the `abs_bad` block below MOVES
        // `head` into its future, which would otherwise collide with the
        // closure's capture borrow.
        let resolve = |auth: Option<(&str, &str)>, head: Vec<u8>| {
            let auth = auth.map(|(u, p)| (u.to_string(), p.to_string()));
            // Shadow `state` with a Copy reference: the move future copies
            // the reference instead of consuming the fn-local AppState, so
            // the outer closure stays Fn and can be called repeatedly.
            let state = &state;
            async move {
                resolve_vhost_request(
                    state,
                    "auth.example.com",
                    "/",
                    "auth.example.com", // raw inbound Host (test head's Host)
                    auth.as_ref(),
                    None, // no routing-only fallback user
                    head,
                    peer,
                    "HTTP",
                    false, // origin-form request
                    false, // non-CONNECT request
                )
                .await
            }
        };

        // No credentials → origin-form 401 shape.
        assert!(matches!(
            resolve(None, head.clone()).await,
            Err(VhostResolveError::Unauthorized { proxy_form: false })
        ));
        // Wrong password → 401 shape.
        assert!(matches!(
            resolve(Some(("user1", "wrong")), head.clone()).await,
            Err(VhostResolveError::Unauthorized { proxy_form: false })
        ));
        // Wrong username → 401 shape.
        assert!(matches!(
            resolve(Some(("other", "pass1")), head.clone()).await,
            Err(VhostResolveError::Unauthorized { proxy_form: false })
        ));
        // Absolute-form shape: the SAME auth failure must be flagged
        // `proxy_form: true` so the caller answers 407 + Proxy-Authenticate.
        let abs = {
            let auth = Some(("user1".to_string(), "pass1".to_string()));
            let state = &state;
            let head = head.clone(); // the async move below captures it by value
            async move {
                resolve_vhost_request(
                    state,
                    "auth.example.com",
                    "/",
                    "auth.example.com", // raw inbound Host (test head's Host)
                    auth.as_ref(),
                    None, // no routing-only fallback user
                    head,
                    peer,
                    "HTTP",
                    true,  // absolute-form request
                    false, // non-CONNECT request
                )
                .await
            }
        };
        // Correct credentials pass on the absolute-form path too — the flag
        // must not change the credential check itself.
        assert!(
            abs.await.is_ok(),
            "valid credentials must forward on both forms"
        );
        let abs_bad = {
            let auth = Some(("user1".to_string(), "wrong".to_string()));
            let state = &state;
            let head = head.clone(); // `head` is still needed by the final resolve() below
            async move {
                resolve_vhost_request(
                    state,
                    "auth.example.com",
                    "/",
                    "auth.example.com", // raw inbound Host (test head's Host)
                    auth.as_ref(),
                    None, // no routing-only fallback user
                    head,
                    peer,
                    "HTTP",
                    true,
                    false, // non-CONNECT request
                )
                .await
            }
        };
        assert!(matches!(
            abs_bad.await,
            Err(VhostResolveError::Unauthorized { proxy_form: true })
        ));
        // Correct credentials → forward to the route's proxy (moves `head`).
        let fwd = resolve(Some(("user1", "pass1")), head)
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
            "g.example.com", // raw inbound Host (test head's Host)
            None,
            None, // no routing-only fallback user
            b"GET / HTTP/1.1\r\nHost: g.example.com\r\n\r\n".to_vec(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            "HTTP",
            false,
            false, // non-CONNECT request
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
            "g2.example.com", // raw inbound Host (test head's Host)
            None,
            None, // no routing-only fallback user
            b"GET / HTTP/1.1\r\nHost: g2.example.com\r\n\r\n".to_vec(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            "HTTP",
            false,
            false, // non-CONNECT request
        )
        .await
        .expect("no-member fallback must forward");
        assert_eq!(
            fwd.proxy_name, "owner-p",
            "no members → recorded proxy fallback"
        );
        assert_eq!(fwd.run_id, "run-1");
    }

    // ---------------------------------------------------------------
    // F3 pin: X-Forwarded-Host / X-Forwarded-Proto injection (Go
    // `ProxyRequest.SetXForwarded` parity — the tri-plet, not XFF alone)
    // ---------------------------------------------------------------

    /// The injection must emit X-Forwarded-Host (pre-rewrite inbound Host)
    /// and X-Forwarded-Proto (always "http" on the plain vhost path) in
    /// addition to the existing X-Forwarded-For append. Before F3, only XFF
    /// was injected — the Go frp tri-plet (SetXForwarded) was missing.
    #[test]
    fn inject_xfh_xfp_triplet_with_existing_xff() {
        let head =
            b"GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For: 203.0.113.1\r\n\r\nbody"
                .to_vec();
        let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
        let out = inject_vhost_request_headers(head, peer, "app.example.com", &[]);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("GET / HTTP/1.1\r\nHost: app.example.com\r\n"),
            "original head must be preserved first: {text:?}"
        );
        // XFF: existing value chained with the peer (Go ReverseProxy append).
        assert!(
            text.contains("X-Forwarded-For: 203.0.113.1, 192.0.2.55\r\n"),
            "XFF must chain peer to the existing value: {text:?}"
        );
        // F3: X-Forwarded-Host = inbound Host as received (Go r.In.Host).
        assert!(
            text.contains("X-Forwarded-Host: app.example.com\r\n"),
            "X-Forwarded-Host must be injected with the inbound Host: {text:?}"
        );
        // F3: X-Forwarded-Proto always "http" (Go r.In.TLS == nil).
        assert!(
            text.contains("X-Forwarded-Proto: http\r\n"),
            "X-Forwarded-Proto must be injected as http: {text:?}"
        );
        // Header block only — body untouched.
        assert!(
            text.ends_with("\r\n\r\nbody"),
            "body must survive: {text:?}"
        );
    }

    /// Empty inbound Host → the X-Forwarded-Host line is OMITTED (Go
    /// `r.In.Host != ""` guard); XFF and XFP still emit.
    #[test]
    fn inject_xfh_omitted_when_host_empty() {
        let head = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
        let out = inject_vhost_request_headers(head, peer, "", &[]);
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("X-Forwarded-Host:"),
            "empty inbound Host must omit X-Forwarded-Host: {text:?}"
        );
        assert!(text.contains("X-Forwarded-For: 192.0.2.55\r\n"), "{text:?}");
        assert!(text.contains("X-Forwarded-Proto: http\r\n"), "{text:?}");
    }

    /// Configured requestHeaders may override the forwarded headers (Go
    /// `req.Header.Set` runs after SetXForwarded) but must not duplicate an
    /// X-Forwarded-For value (case-insensitive re-emit with the peer chain).
    #[test]
    fn inject_request_headers_override_after_forwarded() {
        let head = b"GET / HTTP/1.1\r\nx-forwarded-for: 198.51.100.7\r\n\r\n".to_vec();
        let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
        let overrides = [("X-Forwarded-Proto".to_string(), "https".to_string())];
        let out = inject_vhost_request_headers(head, peer, "h.example.com", &overrides);
        let text = String::from_utf8(out).unwrap();
        // The old lowercase xff is re-emitted exactly once, chained.
        let xff_count = text.matches("X-Forwarded-For:").count();
        assert_eq!(xff_count, 1, "XFF must appear exactly once: {text:?}");
        assert!(
            text.contains("X-Forwarded-For: 198.51.100.7, 192.0.2.55\r\n"),
            "{text:?}"
        );
        // Configured header wins over the forwarded default (Go Set semantics).
        assert!(
            text.contains("X-Forwarded-Proto: https\r\n"),
            "configured requestHeader must override: {text:?}"
        );
    }

    /// A requestHeader named x-forwarded-for REPLACES the auto line entirely
    /// (Go Rewrite hook order: SetXForwarded runs first, then the rc.Headers
    /// loop does `req.Header.Set` — single header, config value alone, never
    /// the auto peer chain, never two lines). The old code emitted the auto
    /// line AND appended the config verbatim — the dup survived the
    /// `contains` assertions above.
    #[test]
    fn inject_config_xff_replaces_auto_line() {
        let head =
            b"GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For: 203.0.113.1\r\n\r\nbody"
                .to_vec();
        let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
        let overrides = [(
            "X-Forwarded-For".to_string(),
            "edge.example.net".to_string(),
        )];
        let out = inject_vhost_request_headers(head, peer, "app.example.com", &overrides);
        let text = String::from_utf8(out).unwrap();
        let xff_count = text.matches("X-Forwarded-For:").count();
        assert_eq!(xff_count, 1, "XFF must appear exactly once: {text:?}");
        assert!(
            text.contains("X-Forwarded-For: edge.example.net\r\n"),
            "config value alone, no peer chain: {text:?}"
        );
        assert!(
            !text.contains("203.0.113.1") && !text.contains("192.0.2.55"),
            "inbound value and peer must not survive an override: {text:?}"
        );
        assert!(
            text.ends_with("\r\n\r\nbody"),
            "body must survive: {text:?}"
        );
    }

    /// x-forwarded-host / x-forwarded-proto overrides (mixed case in config
    /// names — case-insensitive Set semantics) suppress the auto lines: one
    /// line each, config value wins. XFF stays auto (not overridden).
    #[test]
    fn inject_config_xfh_xfp_replace_auto_lines() {
        let head = b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n".to_vec();
        let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
        let overrides = [
            (
                "x-forwarded-host".to_string(),
                "cfg.example.com".to_string(),
            ),
            ("X-Forwarded-Proto".to_string(), "https".to_string()),
        ];
        let out = inject_vhost_request_headers(head, peer, "h.example.com", &overrides);
        let text = String::from_utf8(out).unwrap();
        // Header names are case-insensitive on the wire; the config loop
        // emits the configured name verbatim (lowercase here), so count
        // case-insensitively.
        let lower = text.to_ascii_lowercase();
        let xfh_count = lower.matches("x-forwarded-host:").count();
        assert_eq!(xfh_count, 1, "XFH must appear exactly once: {text:?}");
        assert!(
            lower.contains("x-forwarded-host: cfg.example.com\r\n"),
            "config XFH wins, auto inbound-host line gone: {text:?}"
        );
        let xfp_count = lower.matches("x-forwarded-proto:").count();
        assert_eq!(xfp_count, 1, "XFP must appear exactly once: {text:?}");
        assert!(
            text.contains("X-Forwarded-Proto: https\r\n"),
            "config XFP wins, auto http line gone: {text:?}"
        );
        assert!(
            !text.contains("h.example.com"),
            "auto XFH from the inbound host must not emit under override: {text:?}"
        );
        // Unoverridden auto line still emits (peer-only XFF).
        assert!(text.contains("X-Forwarded-For: 192.0.2.55\r\n"), "{text:?}");
    }

    /// F5/A3 + F4/A5 (audit round 9): every HTTP/1.1 vhost error render must
    /// match Go's conn.serve raw error shape byte-for-byte (live probes vs
    /// go1.25 on disk): `HTTP/1.1 {status}\r\nContent-Type: text/plain;
    /// charset=utf-8\r\nConnection: close\r\n\r\n{status}` — no
    /// Content-Length (the old 431 CL:0 line was round-9 F5 divergence), no
    /// trailing LF after the body text, and the detail text (": …") carried
    /// on BOTH the status line and the body where Go carries it. And the A5
    /// missing-required-Host gate + exempt shapes (HTTP/1.0 / empty-value
    /// Host must ROUTE on "", never 400).
    #[tokio::test]
    async fn test_vhost_http1_error_shapes_match_go() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let state = test_app_state();

        // Drive serve_vhost_request over a duplex pair; collect the exact
        // response bytes. The error arms never call `wrap`, so the closure
        // panics if a bug ever routes one of these to the Ok(forward) arm —
        // the spawned task dies and the short response fails the assert.
        async fn respond(state: Arc<AppState>, raw: &[u8]) -> Vec<u8> {
            let (mut client, server) = tokio::io::duplex(8192);
            client.write_all(raw).await.unwrap();
            tokio::spawn(serve_vhost_request(
                server,
                std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
                state,
                "HTTP",
                |_| unreachable!("error arms never wrap the stream"),
            ));
            let mut resp = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let r =
                    tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut buf))
                        .await;
                match r {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
                }
            }
            resp
        }

        let dup_host = respond(
            state.clone(),
            // Go readRequest rejects a duplicate Host ("too many Host
            // headers") with a GENERIC 400 — the message is suppressed
            // (probe DUPHOST11).
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        )
        .await;
        assert_eq!(
            dup_host,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "dup-Host render must be Go's conn.serve generic 400 shape"
        );

        // 505: the http1ServerSupportsRequest gate carries the detail on
        // the status line AND the body (probe EXPL20).
        let v505 = respond(
            state.clone(),
            b"GET / HTTP/2.0\r\nHost: a.example.com\r\n\r\n",
        )
        .await;
        assert_eq!(
            v505,
            b"HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n505 HTTP Version Not Supported: unsupported protocol version",
            "505 render must be Go's conn.serve shape with the detail"
        );

        // Review-round order pin: Go rejects a duplicate Host while parsing
        // headers — BEFORE http1ServerSupportsRequest 505s a major-2
        // version — so "HTTP/2.0" + duplicate Host answers the GENERIC 400,
        // not the 505. (The old arm order 505'd first.) Verified against
        // go1.25 server.go: readRequest returns the dup-Host error, the
        // supports-request gate only runs after it returns.
        let v505_dup = respond(
            state.clone(),
            b"GET / HTTP/2.0\r\nHost: a\r\nHost: b\r\n\r\n",
        )
        .await;
        assert_eq!(
            v505_dup,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "dup-Host precedes the 505 major-version gate (Go readRequest order)"
        );

        // 431 oversized head (Go errTooLarge render — no Content-Length).
        let mut big = Vec::with_capacity(5000);
        big.extend_from_slice(b"GET / HTTP/1.1\r\nHost: a.example.com\r\n");
        while big.len() < 4096 {
            big.extend_from_slice(b"X-Junk: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        let v431 = respond(state.clone(), &big).await;
        assert_eq!(
            v431,
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large",
            "431 render must be Go's conn.serve shape (no Content-Length)"
        );

        // A5 gate: HTTP/1.1 with NO Host header line → 400 missing required
        // Host header (Go conn.readRequest server.go:1058; detail carried,
        // probe 1.1NOHOST).
        let nohost11 = respond(state.clone(), b"GET / HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            nohost11,
            b"HTTP/1.1 400 Bad Request: missing required Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: missing required Host header",
            "1.1-without-Host must answer Go's missing-required-Host 400"
        );

        // The gate checks WIRE Host headers — an absolute-form target with
        // no wire Host 400s too (probe ABS1.1NOHOST).
        let abs_nohost = respond(
            state.clone(),
            b"GET http://a.example.com/x HTTP/1.1\r\n\r\n",
        )
        .await;
        assert_eq!(
            abs_nohost,
            b"HTTP/1.1 400 Bad Request: missing required Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: missing required Host header",
            "absolute-form 1.1 without a wire Host must 400 missing Host"
        );

        // Gate-exempt shapes ROUTE on "" (never 400): HTTP/1.0 without Host
        // (Go probe 1.0NOHOST: served with Host="") → frp router miss on ""
        // → Go NotFoundResponse 404.
        let nohost10 = respond(state.clone(), b"GET / HTTP/1.0\r\n\r\n").await;
        assert!(
            nohost10.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
            "HTTP/1.0 without Host must route on \"\" → 404, got: {:?}",
            String::from_utf8_lossy(&nohost10)
        );

        // Empty-value "Host:" — the header line is PRESENT, so the gate is
        // exempt (Go probe EMPTYHOSTV: served with Host=""); routing "" →
        // 404. (The pre-fix code 400'd on the unparseable empty value.)
        let empty_host = respond(state.clone(), b"GET / HTTP/1.1\r\nHost:\r\n\r\n").await;
        assert!(
            empty_host.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
            "empty-value Host must route on \"\" → 404, got: {:?}",
            String::from_utf8_lossy(&empty_host)
        );

        // 2-token request line → parse failure → generic 400 (probe T2TOK).
        // The head must be terminated (\r\n\r\n) for the vhost read loop to
        // finish — the probe's line + blank line — so the request LINE is
        // "GET /" with no version token.
        let two_tok = respond(state.clone(), b"GET /\r\n\r\n").await;
        assert_eq!(
            two_tok,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "2-token request line must answer Go's malformed-request 400"
        );

        // Tab-joined request line → 400 (probe TABJOIN).
        let tab_join = respond(state.clone(), b"GET /\tHTTP/1.1\r\n\r\n").await;
        assert_eq!(
            tab_join,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "tab-joined request line must answer Go's malformed-request 400"
        );
    }

    /// Registers a route for `hop.example.com` and resolves a raw head
    /// through `resolve_vhost_request` — the shared h1/h2c forward path.
    async fn resolve_hop_head(
        state: &AppState,
        head: Vec<u8>,
    ) -> Result<VhostForward, VhostResolveError> {
        resolve_vhost_request(
            state,
            "hop.example.com",
            "/",
            "hop.example.com", // raw inbound Host (test head's Host)
            None,
            None, // no routing-only fallback user
            head,
            std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            "HTTP",
            false, // origin-form request
            false, // non-CONNECT request
        )
        .await
    }

    /// F3 (audit round 9, MEDIUM): the non-CONNECT forward arm must strip
    /// Go's ReverseProxy hop-by-hop set (removeHopByHopHeaders in
    /// reverseproxy.go): Connection-named tokens FIRST, then
    /// Connection/Proxy-Connection/Keep-Alive/Proxy-Authenticate/
    /// Proxy-Authorization/Te/Trailer/Transfer-Encoding/Upgrade — while
    /// entity headers (Authorization — origin-form credentials belong to
    /// the backend, not the proxy — plus custom headers) survive, and the
    /// Go Te-trailers re-add (Issue 21096 block) restores what stripping
    /// took from a backend that cares about trailer support.
    #[tokio::test]
    async fn test_vhost_resolve_strips_hop_by_hop_non_connect() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "hop-p",
                &["hop.example.com".into()],
                "http",
                &[],
                "run-1",
                "", // host_header_rewrite
                "", // http_user
                "", // http_pwd
                "", // route_by_http_user
                &[("X-Added".to_string(), "cfg".to_string())],
                "", // group
            )
            .await
            .expect("route registration must succeed");

        let fwd = resolve_hop_head(
            &state,
            b"GET / HTTP/1.1\r\n\
              Host: hop.example.com\r\n\
              Connection: keep-alive\r\n\
              Keep-Alive: 5\r\n\
              Proxy-Authenticate: Basic realm=\"Restricted\"\r\n\
              Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
              Te: trailers\r\n\
              Trailer: X-Checksum\r\n\
              Upgrade: h2c\r\n\
              X-Custom: keep-me\r\n\
              Authorization: Basic dXNlcjpwYXNz\r\n\
              \r\n"
                .to_vec(),
        )
        .await
        .expect("strip test route must forward");
        let text = String::from_utf8(fwd.request_head).expect("utf8 head");
        let name = |l: &str| l.split(':').next().unwrap_or("").to_ascii_lowercase();
        for banned in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "upgrade",
        ] {
            assert!(
                !text.lines().any(|l| name(l) == banned),
                "hop-by-hop header {banned} must be stripped from the forwarded head: {text:?}"
            );
        }
        // Go Issue 21096: the inbound Te line is stripped and Te: trailers
        // re-added (the ONLY te-named line in the forwarded head) when the
        // inbound Te value contained the "trailers" token.
        let te_lines: Vec<&str> = text.lines().filter(|l| name(l) == "te").collect();
        assert_eq!(
            te_lines,
            vec!["Te: trailers"],
            "Te: trailers must be re-added (Go Issue 21096): {text:?}"
        );
        // Trailer declarations stay (raw-body forwarding keeps the line —
        // Go's transport re-declares them on re-serialization).
        assert!(
            text.lines()
                .any(|l| name(l) == "trailer" && l.contains("X-Checksum")),
            "Trailer declaration must be preserved: {text:?}"
        );
        // Entity headers survive the strip.
        assert!(
            text.lines().any(|l| name(l) == "authorization"),
            "Authorization is an entity header and must be forwarded: {text:?}"
        );
        assert!(
            text.lines()
                .any(|l| name(l) == "x-custom" && l.contains("keep-me")),
            "custom header must be forwarded: {text:?}"
        );
        // Configured requestHeaders still apply (inject runs AFTER the
        // strip — Go's Rewrite hook after removeHopByHopHeaders).
        assert!(
            text.lines()
                .any(|l| name(l) == "x-added" && l.contains("cfg")),
            "config requestHeader must apply after the strip: {text:?}"
        );
        assert!(
            text.lines().any(|l| l.starts_with("X-Forwarded-For: ")),
            "XFF injection must still run: {text:?}"
        );
    }

    /// Connection-token semantics: a header NAMED by the Connection value
    /// list is removed even when it is not in the fixed hop set (Go's
    /// removeHopByHopHeaders pass 1), while `Transfer-Encoding: chunked` is
    /// re-emitted (canonical line) and `Trailer` declarations survive — the
    /// backend needs both to frame the raw-forwarded body.
    #[tokio::test]
    async fn test_vhost_resolve_connection_named_and_chunked_te() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "hop-p",
                &["hop.example.com".into()],
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
            .expect("route registration must succeed");

        let fwd = resolve_hop_head(
            &state,
            b"POST /submit HTTP/1.1\r\n\
              Host: hop.example.com\r\n\
              Connection: X-Sum, keep-alive\r\n\
              X-Sum: 42\r\n\
              Transfer-Encoding: chunked\r\n\
              Trailer: X-Sum\r\n\
              \r\n"
                .to_vec(),
        )
        .await
        .expect("must forward");
        let text = String::from_utf8(fwd.request_head).expect("utf8 head");
        let name = |l: &str| l.split(':').next().unwrap_or("").to_ascii_lowercase();
        assert!(
            !text.lines().any(|l| name(l) == "connection"),
            "Connection line must be stripped: {text:?}"
        );
        assert!(
            !text.lines().any(|l| name(l) == "x-sum"),
            "Connection-named X-Sum must be stripped (Go pass-1 token removal): {text:?}"
        );
        let te_lines: Vec<&str> = text
            .lines()
            .filter(|l| name(l) == "transfer-encoding")
            .collect();
        assert_eq!(
            te_lines,
            vec!["Transfer-Encoding: chunked"],
            "chunked Transfer-Encoding must survive as the single canonical line: {text:?}"
        );
        assert!(
            text.lines()
                .any(|l| name(l) == "trailer" && l.contains("X-Sum")),
            "Trailer declaration must survive: {text:?}"
        );
    }

    /// Protocol-upgrade requests: Go strips every hop header and then
    /// RE-ADDS exactly `Connection: Upgrade` + `Upgrade: <value>` when the
    /// inbound Connection named Upgrade (reverseproxy.go) — the vhost
    /// WebSocket path must keep working through the strip.
    #[tokio::test]
    async fn test_vhost_resolve_upgrade_readd() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "hop-p",
                &["hop.example.com".into()],
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
            .expect("route registration must succeed");

        let fwd = resolve_hop_head(
            &state,
            b"GET /ws HTTP/1.1\r\n\
              Host: hop.example.com\r\n\
              Connection: keep-alive, Upgrade\r\n\
              Upgrade: websocket\r\n\
              \r\n"
                .to_vec(),
        )
        .await
        .expect("upgrade must forward");
        let text = String::from_utf8(fwd.request_head).expect("utf8 head");
        let conn_lines: Vec<&str> = text
            .lines()
            .filter(|l| {
                l.split(':')
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("connection")
            })
            .collect();
        assert_eq!(
            conn_lines,
            vec!["Connection: Upgrade"],
            "exactly one canonical Connection: Upgrade after the strip: {text:?}"
        );
        assert!(
            text.lines()
                .any(|l| l.eq_ignore_ascii_case("Upgrade: websocket")),
            "Upgrade value must be re-added: {text:?}"
        );
    }

    /// Go checks `ascii.IsPrint(reqUpType)` BEFORE stripping and answers
    /// through the proxy ErrorHandler — Go frp's 404 route-miss response.
    /// A Connection: Upgrade whose Upgrade value carries a control byte
    /// must be rejected (route-miss), never forwarded to a backend.
    #[tokio::test]
    async fn test_vhost_resolve_nonprintable_upgrade_rejected() {
        let state = test_app_state();
        state
            .vhost_manager
            .register(
                "hop-p",
                &["hop.example.com".into()],
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
            .expect("route registration must succeed");

        let res = resolve_hop_head(
            &state,
            b"GET /ws HTTP/1.1\r\n\
              Host: hop.example.com\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\x01x\r\n\
              \r\n"
                .to_vec(),
        )
        .await;
        assert!(
            matches!(res, Err(VhostResolveError::NotFound)),
            "non-printable upgrade protocol must be a 404 route-miss (Go ascii.IsPrint gate)"
        );
    }
}
