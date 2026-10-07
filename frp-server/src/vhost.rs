use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
// `AsyncWriteExt`'s only direct method use in this file is the TLS-alert
// write in the `tls`-gated HTTPS vhost listener; the two response writers
// take `impl AsyncWriteExt` bounds, which resolve their own method calls.
// Gating on `http-proxy` instead would warn in an `http-proxy`-only build.
#[cfg(feature = "tls")]
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::service::{AppState, InternalMsg};
// Pure HTTP head parsing helpers (see `head.rs`): strict authority
// canonicalization (Go url.ParseRequestURI semantics) shared with tcpmux.rs,
// which owns `canonicalize_host` (round-3 M4).

mod head;
/// HTTP/2 cleartext (h2c) vhost handling — see `vhost_h2c.rs`.
/// Only compiled when the `http-proxy` feature is enabled (audit round 5:
/// `h2` is now optional, so micro/tiny builds without vhosts skip it).
#[cfg(feature = "http-proxy")]
#[path = "vhost_h2c.rs"]
mod vhost_h2c;
pub(crate) use head::count_host_headers;
#[cfg(test)]
use head::{canonicalize_authority, extract_host_header};
use head::{
    extract_basic_auth, extract_basic_auth_named, extract_raw_request_host, has_nonempty_header,
    parse_vhost_request_line, request_line_minor_gte_1, validate_vhost_head_lines, HeadLineVerdict,
    RequestLine,
};

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
    /// `host_header_rewrite` with CR/LF stripped, precomputed at registration
    /// (audit §3 item 4): the sanitized rewrite value is immutable per route,
    /// so the request path appends it to the forwarded head with no
    /// per-request filter walk or `format!` String. The rewrite GATE still
    /// tests the raw `host_header_rewrite` above — a raw value that
    /// sanitizes to empty still emits `Host: \r\n`, byte-identical to the
    /// old per-request filter.
    pub host_header_rewrite_sanitized: Arc<str>,
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
    /// Pre-sanitized rewrite value — see `VhostRoute::host_header_rewrite_sanitized`.
    pub host_header_rewrite_sanitized: Arc<str>,
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
            host_header_rewrite_sanitized: Arc::clone(&route.host_header_rewrite_sanitized),
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
            // Sanitize ONCE here instead of per request (audit §3 item 4).
            // \r and \n are stripped to prevent HTTP header injection.
            host_header_rewrite_sanitized: sanitize_rewrite_host(host_header_rewrite).into(),
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
/// Go frp v0.71.0 `NotFoundResponse` writer (pkg/util/http/http.go) —
/// re-exported from frp-core so the work→user bridge Err arm (Go
/// ErrorHandler parity: non-timeout backend failures answer this same 404,
/// pkg/util/vhost/http.go:128-138) and the vhost/tcpmux route-miss +
/// control-gone writers share one byte template (and one builtin body,
/// `frp_core::bridge::GO_404_NOT_FOUND_BODY`). See frp-core for the doc:
/// 489-byte builtin body (probe vs Go v0.71.0), head order fixed
/// (Content-Length, Content-Type, Server), `custom_body`
/// (custom_404_page) replacing the builtin HTML when non-empty.
pub(crate) use frp_core::bridge::write_not_found_response;

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
/// The input is Go's signed `int64` (config field and flag alike), so a
/// negative value reaches here instead of being refused at parse time; the
/// `<= 0` floor is what gives it meaning, exactly as Go's own use of the
/// value tolerates a negative `Duration` from the same field. Values above
/// the cap saturate at [`VHOST_TIMEOUT_CAP_SECS`], which is why the return
/// type stays `u64` — every caller feeds it to `Duration::from_secs` or an
/// `Instant` addition.
///
/// Role split of `vhost_http_timeout` (Go-mirrored since rounds 13/14;
/// the audit-r7 "plain HTTP/1.1 bridge is raw forward" reading is stale):
/// Go's config feeds the ReverseProxy backend response-head wait —
/// `ResponseHeaderTimeoutS` in pkg/util/vhost/http.go `NewHTTPReverseProxy`,
/// a slow backend head answers 504 — while the client-side head window is a
/// HARDCODED `ReadHeaderTimeout: 60 * time.Second` http.Server literal in
/// server/service.go that the config never reaches. frp-rs now mirrors
/// BOTH halves with its one config. The backend-response-head half runs on
/// EVERY `proxy_type == "http"` non-CONNECT leg, h1 AND h2c: on the h1 legs
/// the wait lives in frp-server's ResponseHeaderInjector
/// (frp-server/src/control/bridge.rs), which arms an absolute
/// `vhost_http_timeout` deadline on exactly the Go gate (http non-CONNECT
/// only), sits UPSTREAM of the transport snappy decode — the layer where Go
/// runs ModifyResponse — and maps expiry to a 504 through the frp-core
/// read-error arms (TimedOut → bare 504, the Go ErrorHandler shape;
/// frp-core/src/bridge.rs documents the round-15 model). The h2c frontend
/// is the same leg family, not an exception: its backend response-head
/// translation read (vhost_h2c.rs) is clocked by this config and answers
/// 504 on expiry, the exact mirror of Go's ResponseHeaderTimeoutS
/// semantics. CONNECT and https legs raw-forward with NO response-head
/// wait (Go connectHandler hijacks and joins raw — the ReverseProxy never
/// arms — and the https muxer routes raw TLS bytes); TCP/STCP/XTCP bridges
/// have no such semantic.
///
/// The remaining divergence (audit-r7, still current): frp-rs's one config
/// ALSO clocks the client-head/preface window of the vhost accept paths
/// (serve_vhost_request head deadline here, serve_h2c_request handshake
/// deadline), where Go's hardcoded 60s http.Server literal keeps the
/// config out.
///
/// Positive values are additionally capped at [`VHOST_TIMEOUT_CAP_SECS`]:
/// the clamped value feeds `Instant::now() + Duration::from_secs(...)` at
/// the deadline sites below (serve_vhost_request head deadline,
/// serve_h2c_request handshake deadline), and std `Instant` PANICS when the
/// add overflows — under the release `panic=abort` profile a hostile
/// `vhost_http_timeout = i64::MAX` config would abort frps on the first
/// vhost request, before any read is attempted (audit finding S1). The
/// `tokio::time::timeout(duration)` call sites (HTTPS SNI, h2c/HTTP
/// response head) cannot overflow — tokio's checked_add degrades a huge
/// duration to a far-future deadline — but share the same clamp so the
/// config has one bounded semantic everywhere.
pub(crate) fn clamp_vhost_timeout(t: i64) -> u64 {
    let floored = if t > 0 { t as u64 } else { 60 };
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

    // Capacity hint (audit §3 item 4): the head buffer can grow to the 4096
    // read cap below, so allocate that once instead of letting `to_vec()`'s
    // exact-size Vec realloc its way up one drip read at a time.
    let mut pre_read = Vec::with_capacity(4096);
    pre_read.extend_from_slice(&buf[..n]);

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
/// The 4096-byte head cap is a deliberate hardening divergence from Go frp.
/// Head-cap values are NOT uniform across the frp-rs surfaces (audit round
/// 18 C4); the matrix: this HTTP/1.1 vhost front and the tcpmux CONNECT
/// front cap the client head at 4096 and answer 431 at the cap (fail-closed
/// hardening); the h2c vhost front caps the h2-frame header block at 4096
/// too (vhost_h2c.rs max_header_list_size — Go's h2 default is 16 MiB); the
/// backend-response/plugin faces read with the 1 MiB + 4096 readLimit model
/// instead — a terminated head up to ~1 MiB + 4096 serves, only an
/// unterminated one errors (vhost_h2c.rs read_until_head_from + the plugin
/// read_until_head sites; Go MaxHeaderBytes + bufio slop). Go's own fronts
/// are looser: http.Server reads to defaultMaxHeaderBytes = 1 MiB per
/// request slot (net/http server.go — the 431 arm below is the errTooLarge
/// analog) and the tcpmux CONNECT reader (http.ReadRequest in
/// pkg/util/tcpmux/httpconnect.go) has NO cap at all, while Go's Transport
/// bounds a backend response head at 10 MiB (maxHeaderResponseSize). An
/// unterminated head is never forwarded: if it fills the cap it gets a 431
/// below; if the deadline expires or the peer closes mid-head with fewer
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
    // vhost http.Server, and the config's Go role — the backend
    // response-head wait, `ResponseHeaderTimeoutS` — runs on the bridge
    // leg instead (http_leg_head_deadline in bridge/assign.rs, on every http
    // non-CONNECT leg), not here on the client-head window; CONNECT and
    // https legs raw-forward with neither, as does this window's Go
    // literal. The config-on-client-head divergence is documented on
    // clamp_vhost_timeout.)

    // Head-end scan, incremental (audit §3 item 4), owning the reads too:
    // `HeadEndScanner` carries the line offset across feeds (the buffer
    // only ever grows here) and reports the FIRST blank line exactly as a
    // whole-buffer `head_end` rescan does, so the verdicts below are
    // byte-identical; the vhost_h2c and bridge head loops already work this
    // way. Keeping the old rescan loop alongside it would have re-scanned
    // every earlier chunk per read (O(n²) for a drip-fed head) AND made
    // this loop unreachable (it can only be entered once the cap or EOF
    // was already hit). One scan serves all three consumers: the 431 cap
    // gate, the unterminated-head gate, and the head slice.
    let mut head_scanner = frp_core::textproto::HeadEndScanner::new();
    let mut head_end = head_scanner.feed(&pre_read);
    while pre_read.len() < 4096 && head_end.is_none() {
        let mut buf = [0u8; 4096];
        let m = match tokio::time::timeout_at(head_deadline, stream.read(&mut buf)).await {
            Ok(Ok(m)) if m > 0 => m,
            _ => break,
        };
        pre_read.extend_from_slice(&buf[..m]);
        head_end = head_scanner.feed(&pre_read);
    }

    // The head is capped at 4096 bytes. If the cap fills without a blank
    // line (textproto semantics — Go accepts bare-LF/mixed EOL, so the
    // strict \r\n\r\n scan would 431 legal heads that merely use another
    // line-ending convention), respond 431 Request Header Fields Too Large
    // instead of forwarding a truncated head — forwarding it makes the
    // backend block waiting for the rest of the head, tying up a work-conn
    // slot (limited DoS on shared vhosts).
    if pre_read.len() >= 4096 && head_end.is_none() {
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
    if head_end.is_none() {
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
    let head_end = head_end.unwrap_or(pre_read.len());
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
    // Round-18 (Go conn.serve parity): the read-time header-block classes
    // end the head HERE — before the dup-Host / 505 / missing-Host gates
    // below. Go's flow is conn.readRequest → package readRequest, which
    // parses the request line, then runs ReadMIMEHeader over the header
    // lines, then rejects duplicate Host (request.go:1139) — all of that
    // BEFORE conn.readRequest's http1ServerSupportsRequest 505 gate and
    // its wire-Host "missing required Host header" gate (server.go). A
    // textproto read-time rejection — the "malformed MIME header initial
    // line" class (a FIRST header line starting with SP/HTAB,
    // textproto/reader.go:536-544), a colonless group-first line, a
    // non-tchar/empty name, a CTL/DEL in a value or fold — makes Go's
    // ReadMIMEHeader return the error, so conn.serve renders its generic
    // 103-byte 400 and none of the later gates ever run: a multi-defect
    // head that also lacks a Host, or carries a major-2 version, answers
    // the GENERIC 400 — never "missing required Host header", never 505
    // (probes: a fold-first head under 1.1-without-Host and under
    // HTTP/2.0 both answered the bare 400). The client-plugin face
    // already validated the header block before its 505 classification
    // (frp-client/src/plugin/http.rs
    // `http_proxy_505_classified_head_validates_header_block_first`);
    // both faces now agree on the order.
    // Only the `Malformed` class moves up: the statusError DETAILS
    // (malformed Host value / invalid header name) keep their Go position
    // AFTER the three gates, in the match at the end of this block.
    let head_verdict = validate_vhost_head_lines(request_text);
    if matches!(head_verdict, HeadLineVerdict::Malformed) {
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
    // Single scan (audit §3 item 4): the dup-Host 400 gate and the
    // missing-Host 400 gate below both consume this count, so the head is
    // walked once per request instead of twice.
    let host_header_count = count_host_headers(request_text);
    if host_header_count > 1 {
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
    if !is_connect && host_header_count == 0 && request_line_minor_gte_1(request_text) {
        write_go_server_error(&mut stream, "400 Bad Request: missing required Host header").await;
        return;
    }
    // FIX 6 (audit round 14): Go conn.readRequest's server-layer head
    // validation (server.go:1061-1072) — dup-Host → 505 → missing-Host
    // keep their Go order above, then Go validates the Host value
    // (ValidHostHeader) and the per-header name bytes. Applies to EVERY
    // parse-Ok request — CONNECT and absolute-form included (Go validates
    // the wire headers regardless of routing); only the read-time
    // `Malformed` class returned earlier (round-18), so this match carries
    // the statusError DETAILS only. Render classes verified
    // byte-for-byte with probes vs go1.25.0: textproto read-time classes
    // (CTL in a value, non-token non-space name bytes) answer the GENERIC
    // 400 (e.g. "Host: a.co\x01m" never reaches the malformed-Host gate);
    // a space-containing name reaches the http layer and answers the
    // DETAILED "invalid header name"; an invalid single Host value (e.g.
    // "Host: a.com b.com") answers the DETAILED "malformed Host header".
    // Residual ordering nuances (documented, not fixed):
    // (1) The 431 cap arm and the unterminated-head silent close above
    // fire BEFORE the request-line parse (go1.25 conn.readRequest reads
    // and parses line 1 first — setReadLimit then readRequest — and the
    // errTooLarge special-case only runs AFTER readRequest returns, i.e.
    // after a line-1 parse success). Two multi-defect shapes therefore
    // answer differently from Go: {unparseable request line} × {head ≥
    // 4096 without a blank line} → 431 here where Go's line-1 parse
    // failure answers its generic 400 first, and {unparseable line,
    // terminated} × {peer EOF mid-head, < 4096 total} → silent close here
    // where Go's line-1 parse already failed and answered 400. Both fail
    // closed (431/0-byte vs Go 400); kept because the cap and EOF arms
    // decide from buffer size alone, before any parse.
    // (2) The arm order otherwise mirrors Go conn.readRequest's
    // classification chain (go1.25 net/http server.go, conn.readRequest):
    // the read-time header-block classes (`Malformed`, round-18 above) →
    // dup-Host → the http1ServerSupportsRequest 505 gate → the missing-
    // Host gate → the ValidHostHeader / header-name statusError details
    // (the match below); the head-cap error — hitReadLimit → errTooLarge,
    // the analog of the unterminated-at-cap 431 arm above — is classified
    // before the version gate.
    match head_verdict {
        // `Malformed` was answered above — Go's read-time classes precede
        // every gate and detail render.
        HeadLineVerdict::Ok | HeadLineVerdict::Malformed => {}
        HeadLineVerdict::Detailed(text) => {
            write_go_server_error(&mut stream, text).await;
            return;
        }
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
                        // vhost CONNECT tunnels raw — the bridge's injector
                        // must skip them (Go connectHandler joins raw,
                        // ModifyResponse never runs).
                        request_is_connect: is_connect,
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
            // 12 bytes). The header name is written in net/http's
            // canonical casing "Www-Authenticate" (Header.WriteSubset via
            // textproto.CanonicalMIMEHeaderKey — probe vs go1.25.12 and Go
            // frp v0.71.0 both emit Www-Authenticate; registry casing
            // "WWW-Authenticate" never reaches the wire).
            write_http_error_auth_response(
                &mut stream,
                "401 Unauthorized",
                "Www-Authenticate: Basic realm=\"Restricted\"",
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
        rewrite_host_header(request_head, &route.host_header_rewrite_sanitized)
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
                                    // Raw encrypted passthrough — never an HTTP
                                    // request the injector could splice (the
                                    // bridge sees TLS bytes, not a response
                                    // head). false matches every non-vhost
                                    // producer.
                                    request_is_connect: false,
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

/// Strip CR/LF from a configured `host_header_rewrite` value to prevent HTTP
/// header injection. Called ONCE per route at registration
/// (`VhostManager::register`); the request path uses the stored
/// `VhostRoute::host_header_rewrite_sanitized` directly (audit §3 item 4).
fn sanitize_rewrite_host(host: &str) -> String {
    host.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// Rewrite the Host header in an HTTP request's raw bytes.
/// Finds the first `Host:` or `host:` line and replaces it with the given value.
/// Byte-oriented to avoid mangling non-UTF-8 request data.
/// Returns a new Vec<u8> with the rewritten header. When no Host header is
/// present, the input is returned unchanged (ownership transferred, no copy).
///
/// `new_host` must already be CR/LF-sanitized — every caller passes the
/// route's registration-time `host_header_rewrite_sanitized`.
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

    // The rewrite value is pre-sanitized at registration (audit §3 item 4),
    // so the header line is framed straight into the result buffer — the
    // per-request `chars().filter().collect()` String and the
    // `format!("Host: {}\r\n")` intermediate are gone. Byte-identical to
    // the old framing for every input: same "Host: " prefix, same
    // stripped value, same CRLF.
    let mut result = Vec::with_capacity(data.len() + 6 + new_host.len() + 2);
    result.extend_from_slice(&data[..host_start]);
    result.extend_from_slice(b"Host: ");
    result.extend_from_slice(new_host.as_bytes());
    result.extend_from_slice(b"\r\n");
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
/// `r.Out.Host` after it). An empty value still emits
/// `X-Forwarded-Host:` — Go `Header.Set` on a missing header writes an
/// empty-valued line unconditionally (pinned by the unit test below).
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
    // (case-insensitive Set semantics), X-Forwarded-For (re-emitted with
    // the peer appended), and the forwarding lines go1.25's ReverseProxy
    // deletes before the Rewrite hook — all FOUR of Forwarded,
    // X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, one Del each at
    // reverseproxy.go:434-437. The XFF branch re-emits what Go frp's Rewrite
    // rebuilds (pkg/util/vhost/http.go:59-61 copies the inbound chain across,
    // then SetXForwarded — reverseproxy.go:80-93 — appends the real peer);
    // X-Forwarded-Host / X-Forwarded-Proto are re-Set to canonical values
    // below, and `Forwarded` is never re-added.
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
    // Physical lines of the head (EOL retained). An obs-fold continuation
    // line (leading SP/HT, RFC 7230 §3.2.4) BELONGS to the previous
    // header; Go's textproto reader unfolds it before any header logic
    // runs (readContinuedLineSlice joins continuation content with a
    // single space), so a stripped or chained header must take its
    // continuations with it — a dropped `X-Forwarded-For:` name line must
    // not leave its fold tail behind to obs-fold onto the PRECEDING kept
    // header at the backend (round-13 review, 2 independent reviewers).
    // Kept headers stay byte-identical (folded form preserved); only
    // dropped/chained headers are unfolded.
    let physical: Vec<&[u8]> = head.split_inclusive(|&b| b == b'\n').collect();
    // Advance `i` past the obs-fold continuation lines that follow the
    // line at `*i` (a dropped/chained header takes its continuations).
    let swallow_continuations = |i: &mut usize| {
        while *i < physical.len() {
            let t = physical[*i]
                .strip_suffix(b"\n")
                .unwrap_or(physical[*i])
                .strip_suffix(b"\r")
                .unwrap_or(physical[*i]);
            if matches!(t.first(), Some(b' ' | b'\t')) {
                *i += 1;
            } else {
                break;
            }
        }
    };
    let mut i = 0;
    while i < physical.len() {
        let line = physical[i];
        let trimmed = line
            .strip_suffix(b"\n")
            .unwrap_or(line)
            .strip_suffix(b"\r")
            .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line));
        if trimmed.is_empty() {
            i += 1;
            continue;
        }
        // Case-insensitive ASCII compare against the precomputed prefixes;
        // `[u8]::eq_ignore_ascii_case` is equivalent to lowercasing for
        // ASCII header names and avoids the per-line allocations.
        let is_override = override_prefixes
            .iter()
            .any(|p| trimmed.len() >= p.len() && trimmed[..p.len()].eq_ignore_ascii_case(p));
        if is_override {
            // request_headers will Set-replace this header — swallow its
            // folded continuation lines whole.
            i += 1;
            swallow_continuations(&mut i);
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
            // Go parity (go1.25 SetXForwarded): the chain is
            // `strings.Join(prior, ", ") + ", " + peer` — a single
            // EMPTY-valued inbound XFF line joins to "" and leaves a
            // leading ", " in the chain (", 127.0.0.1"), so empty
            // values are kept, not skipped.
            existing_xff.extend_from_slice(value);
            // Folded continuation content joins the value with a single
            // space (Go textproto unfold — readContinuedLineSlice), so
            // the chain carries the whole inbound logical value before
            // the ", " separator.
            i += 1;
            while i < physical.len() {
                let t = physical[i]
                    .strip_suffix(b"\n")
                    .unwrap_or(physical[i])
                    .strip_suffix(b"\r")
                    .unwrap_or(physical[i]);
                match t.first() {
                    Some(b' ' | b'\t') => {
                        let content = t
                            .iter()
                            .position(|&b| b != b' ' && b != b'\t')
                            .map(|p| &t[p..])
                            .unwrap_or(&[]);
                        existing_xff.push(b' ');
                        existing_xff.extend_from_slice(content);
                        i += 1;
                    }
                    _ => break,
                }
            }
            existing_xff.extend_from_slice(b", ");
            continue;
        }
        // Go go1.25 reverseproxy.go:434-437 deletes every client-supplied
        // `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and
        // `X-Forwarded-Proto` line from the outbound request BEFORE the
        // Rewrite hook runs (`X-Forwarded-For` left this head through the
        // branch above — Go frp's Rewrite copies the inbound chain across
        // and SetXForwarded appends the peer, pkg/util/vhost/http.go:59-61);
        // SetXForwarded then re-Sets X-Forwarded-Host / X-Forwarded-Proto
        // to single canonical values (emitted below) and Go never re-adds
        // `Forwarded` at all. Exact-name + ':' compare — an invented
        // `x-forwarded-hostile:` header is not stripped.
        let is_go_stripped = (trimmed.len() >= 17
            && trimmed[..17].eq_ignore_ascii_case(b"x-forwarded-host:"))
            || (trimmed.len() >= 18 && trimmed[..18].eq_ignore_ascii_case(b"x-forwarded-proto:"))
            || (trimmed.len() >= 10 && trimmed[..10].eq_ignore_ascii_case(b"forwarded:"));
        if is_go_stripped {
            // Swallow this header's folded continuation lines too — they
            // belong to the deleted logical header.
            i += 1;
            swallow_continuations(&mut i);
            continue;
        }
        lines.push(line);
        i += 1;
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
        use std::io::Write;
        let mut xff = existing_xff;
        // Format the peer address straight into the chain (audit §3 item 4):
        // `peer.ip().to_string()` allocated a String per request just to be
        // copied into the output. Same bytes for every address family, no
        // heap allocation. The discard is safe — writing to a Vec cannot
        // fail — and is commented per project convention.
        let _ = write!(xff, "{}", peer.ip());
        out.extend_from_slice(b"X-Forwarded-For: ");
        out.extend_from_slice(&xff);
        out.extend_from_slice(b"\r\n");
    }
    // X-Forwarded-Host: inbound Host as received (Go SetXForwarded reads
    // `r.In.Host`, the pre-rewrite value — go1.25 sets it UNCONDITIONALLY,
    // `Header.Set("X-Forwarded-Host", r.In.Host)`, so an HTTP/1.0 request
    // with no Host header emits the header with an empty value, exactly as
    // Go writes `Set(k, "")`). Emitted AFTER XFF, both before the
    // configured headers, which may override them (Go `Header.Set`
    // semantics — the rc.Headers loop runs after SetXForwarded).
    if !overrides_xfh {
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
mod tests;
