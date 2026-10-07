//! Vhost routing table: route registration, wildcard/location matching.
//!
//! Split out of `vhost.rs` as a pure text move; the parent re-exports the
//! public routing types (`VhostManager`, `VhostRoute`, `VhostRouteMatch`,
//! `RouterConfigConflict`) and the sibling test module re-imports the
//! matching helpers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::sanitize_rewrite_host;

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
pub(super) fn find_matching_route(
    vrs: &[VhostRoute],
    path: &str,
    scheme: &str,
) -> Option<VhostRouteMatch> {
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
pub(super) fn sort_by_longest_location(vrs: &mut [VhostRoute]) {
    vrs.sort_by(|a, b| {
        let a_max = a.locations.iter().max().map(|l| l.as_str()).unwrap_or("");
        let b_max = b.locations.iter().max().map(|l| l.as_str()).unwrap_or("");
        b_max.cmp(a_max) // lexicographic descending
    });
}

/// Internal tables held under a single RwLock.
pub(super) struct VhostTables {
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
    pub(super) wildcard_count: usize,
}

/// Manages HTTP VHost routing table (domain + location -> proxy).
pub struct VhostManager {
    pub(super) inner: RwLock<VhostTables>,
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
