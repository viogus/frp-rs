use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::service::{AppState, InternalMsg};

/// A route mapping: (domain, route_by_http_user) → proxy info for tcpmux
/// CONNECT routing.
#[derive(Debug, Clone)]
pub struct TcpMuxRoute {
    pub proxy_name: String,
    pub run_id: String,
    /// HTTP Basic Auth credentials (empty = no auth).
    pub http_user: String,
    pub http_pwd: String,
    /// Go frp `RouteConfig.RouteByHTTPUser` (round 6, A2): a second routing
    /// dimension. CONNECT lookups try the request's Proxy-Authorization
    /// username first, then fall back to the `""` bucket (Go
    /// `getExactOrAllUsersLocked`).
    pub route_by_http_user: String,
    /// Load-balancing group name (Go frp group.TCPMuxGroup). Non-empty only
    /// on the FIRST member's shared route: the lookup returns this route
    /// for every member of the group, and the accept side fans the CONNECT
    /// out to a group member round-robin via the group controller instead
    /// of dispatching to the route's own proxy.
    pub group: String,
}

/// Manages TCPMux routing table (domain + routeByHTTPUser → proxy).
/// Maps Host header values from HTTP CONNECT requests to the correct proxy.
pub struct TcpMuxManager {
    /// domain → route_by_http_user → route. Mirrors Go's
    /// `indexByDomain[domain][httpUser]` (pkg/util/vhost/router.go): a
    /// domain can carry several route_by_http_user buckets; lookup tries
    /// the request's user bucket, then the `""` (all-users) bucket, then
    /// moves on to wildcard levels.
    routes: RwLock<HashMap<String, HashMap<String, TcpMuxRoute>>>,
    /// proxy_name → domains (for unregister)
    by_proxy: RwLock<HashMap<String, Vec<String>>>,
    /// Live count of registered `*.` wildcard routes (one per distinct
    /// (domain, route_by_http_user) bucket). Lets `lookup` skip the
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
    /// Returns `Err(conflict)` when a (domain, route_by_http_user) pair is
    /// already routed to a different proxy — same conflict rule as Go's
    /// `Routers.Add` (`exist(domain, location, httpUser)`); a domain MAY
    /// carry multiple route_by_http_user buckets from different proxies.
    /// Every domain is validated BEFORE any insert, so a rejected
    /// registration leaves no partial state — mirroring the VHost manager.
    /// Previously the result was ignored and the last registration
    /// silently overwrote the first (audit finding 5), which meant closing
    /// the overwriting proxy deleted the live sibling's route.
    ///
    /// `group` is empty for plain proxies. A non-empty group marks the
    /// FIRST member's shared route (M2: tcpmux group fan-out): the caller
    /// registers the route only for the first member, and the route's
    /// `group` field routes accept-side dispatch through the group
    /// controller's round-robin member list. Joining members register no
    /// route of their own — the shared route (and its wildcard_count) is
    /// owned by the first member until the group empties.
    #[allow(clippy::too_many_arguments)] // mirrors VhostManager::register (same route tuple)
    pub async fn register(
        &self,
        proxy_name: &str,
        domains: &[String],
        run_id: &str,
        http_user: &str,
        http_pwd: &str,
        route_by_http_user: &str,
        _headers: &[(String, String)],
        group: &str,
    ) -> Result<(), String> {
        let route = TcpMuxRoute {
            proxy_name: proxy_name.to_string(),
            run_id: run_id.to_string(),
            http_user: http_user.to_string(),
            http_pwd: http_pwd.to_string(),
            route_by_http_user: route_by_http_user.to_string(),
            group: group.to_string(),
        };

        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;

        // Go frp compat (pkg/util/vhost/router.go): domains are stored
        // lowercased (`Routers.Add` → strings.ToLower), so CONNECT Host
        // lookups are case-insensitive. Lowercase each domain ONCE, before
        // the conflict check, the insert, and the by_proxy bookkeeping,
        // keeping register/unregister symmetric.
        let domains: Vec<String> = domains.iter().map(|d| d.to_lowercase()).collect();

        // Same-call duplicate detection (Go parity): Go's registration loop
        // calls `Routers.Add` once per domain, and the SECOND Add of a
        // duplicate (domain, location, httpUser) triple hits `exist()` →
        // conflict → the whole registration fails. A duplicate inside one
        // call must therefore reject the registration, not silently register
        // the domain once (which would leave unregister's by_proxy list
        // containing the duplicate). Mirrors the vhost manager's same-call
        // dedup check.
        let mut seen: HashSet<&str> = HashSet::with_capacity(domains.len());
        for domain in &domains {
            if !seen.insert(domain.as_str()) {
                return Err(format!(
                    "tcpmux duplicate domain '{}' in registration for proxy '{}'",
                    domain, proxy_name
                ));
            }
        }

        // Validate every domain before inserting anything (no partial state).
        // Re-registration by the same proxy name is allowed (idempotent).
        // Conflict is per (domain, route_by_http_user) — Go `exist()`.
        for domain in &domains {
            if let Some(user_map) = routes.get(domain) {
                if let Some(existing) = user_map.get(route_by_http_user) {
                    if existing.proxy_name != proxy_name {
                        return Err(format!(
                            "tcpmux route conflict for domain '{}' (route_by_http_user '{}'): proxy '{}' vs '{}'",
                            domain, route_by_http_user, existing.proxy_name, proxy_name
                        ));
                    }
                }
            }
        }

        // Re-registration with a changed domain list (server reload): drop
        // routes that left the list — otherwise a shrunken reload orphans
        // the dropped `*.` route (and its wildcard count) forever. Runs
        // AFTER the conflict check so a rejected registration leaves the
        // old routes intact (no partial state — the caller's rollback is
        // a no-op for tcpmux). Same ownership guard as unregister: a
        // sibling's live route survives.
        if let Some(old) = by_proxy.get(proxy_name) {
            for domain in old {
                if !domains.contains(domain) {
                    if let Some(user_map) = routes.get_mut(domain) {
                        if user_map
                            .get(route_by_http_user)
                            .is_some_and(|r| r.proxy_name == proxy_name)
                        {
                            user_map.remove(route_by_http_user);
                            if user_map.is_empty() {
                                routes.remove(domain);
                                if domain.starts_with("*.") {
                                    self.wildcard_count
                                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut domains_for_proxy = Vec::new();
        for domain in &domains {
            let user_map = routes.entry(domain.clone()).or_default();
            // insert returns the overwritten route: a re-registration of the
            // same (domain, route_by_http_user) by the same proxy must not
            // double-count the wildcard.
            let fresh = user_map
                .insert(route_by_http_user.to_string(), route.clone())
                .is_none();
            if fresh && domain.starts_with("*.") {
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
                if let Some(user_map) = routes.get_mut(domain) {
                    // Remove every bucket this proxy owned (a proxy has one
                    // route_by_http_user, but keep the loop general).
                    let before = user_map.len();
                    user_map.retain(|_, r| r.proxy_name != proxy_name);
                    if user_map.is_empty() {
                        routes.remove(domain);
                        // Same guard as the removal: only count down routes
                        // this proxy actually owned (a sibling's `*.` route
                        // pointing at the same domain keeps its count).
                        if domain.starts_with("*.") && before > 0 {
                            self.wildcard_count
                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    /// Look up by hostname with wildcard fallback (Go frp vhost.Muxer →
    /// getByRoute → getExactOrAllUsersLocked): exact match, then
    /// progressively replace the leftmost label with "*" while >=3 labels
    /// remain, then the "*" catch-all. Each candidate domain tries the
    /// request's Proxy-Authorization username bucket first, then the ""
    /// (all-users) bucket. Port-stripped, trailing-dot-trimmed,
    /// case-insensitive.
    pub async fn lookup(&self, host: &str, http_user: &str) -> Option<TcpMuxRoute> {
        // Strip port if present: example.com:443 → example.com; bracketed
        // IPv6: [::1]:443 → ::1; then exactly one trailing dot (Go frp
        // CanonicalHost, pkg/util/http/http.go).
        // Lenient port mode: the caller already applied the request-line
        // (strict) or Host-header (lenient) gate before routing here.
        let hostname = canonicalize_host(host, false)?;
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
        // Exact user bucket, then the "" (all-users) fallback — Go
        // getExactOrAllUsersLocked. A route registered with a
        // route_by_http_user only matches requests carrying that exact
        // Proxy-Authorization username.
        let try_buckets = |user_map: &HashMap<String, TcpMuxRoute>| -> Option<TcpMuxRoute> {
            user_map
                .get(http_user)
                .or_else(|| user_map.get(""))
                .cloned()
        };
        // 1. Exact match
        if let Some(user_map) = routes.get(host_key) {
            if let Some(route) = try_buckets(user_map) {
                return Some(route);
            }
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
                if let Some(user_map) = routes.get(&wildcard_host) {
                    if let Some(route) = try_buckets(user_map) {
                        return Some(route);
                    }
                }
                parts.remove(0);
            }
        }
        // 3. Catch-all "*"
        routes.get("*").and_then(try_buckets)
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
            // Read CONNECT line + headers (up to 4KB) under Go's fixed
            // vhostReadWriteTimeout (service.go:65/199: 30s, NOT the 10s
            // that this read used — a slow-loris client on a heavily loaded
            // box could outlast 10s on a legitimate dial). (n, total): total
            // can exceed n — bytes past \r\n\r\n that a single chunk read
            // consumed (M6); they are forwarded below.
            let mut buf = [0u8; 4096];
            let (n, total) = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                read_http_headers(&mut stream, &mut buf),
            )
            .await
            {
                Ok(Ok((n, total))) if n > 0 => (n, total),
                _ => return,
            };

            let request_text = String::from_utf8_lossy(&buf[..n]);

            // Parse CONNECT line: CONNECT host:port HTTP/1.1
            let Some(first_line) = request_text.lines().next() else {
                // No first line = a Go http.ReadRequest error
                // (readHTTPConnectRequest → vhost handle `_ = c.Close()`):
                // the conn closes with ZERO bytes (probe vs Go v0.71.0) —
                // the old code answered 400.
                tracing::debug!(peer = %peer, "TCPMux: empty request from {}", peer);
                return;
            };

            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");

            // Case-sensitive like Go: httpconnect.go's `req.Method !=
            // "CONNECT"` (and justAuthority, which only treats an exact
            // "CONNECT" as authority-form — a lowercase "connect" has no
            // URL host and errors). A non-CONNECT method is a readHTTPConnectRequest
            // error in Go → silent close, zero bytes (probe vs Go v0.71.0:
            // no 405 on the wire — the old code wrote one).
            if method != "CONNECT" {
                warn!(
                    method = %method, peer = %peer,
                    "TCPMux: expected CONNECT, got {} from {}",
                    method, peer
                );
                return;
            }

            // Route on the request-line authority (CONNECT target) — Go
            // net/http fills req.Host from req.URL.Host and ignores the
            // Host header for CONNECT (RFC 7230 §5.3; see
            // `extract_route_host`). An unroutable line — 2-token shapes,
            // a malformed version token, a non-numeric authority port —
            // is a net/http ReadRequest error in Go, and readHTTPConnectRequest
            // errors reach vhost handle as a silent ZERO-byte close (probe
            // vs Go v0.71.0: "CONNECT HTTP/1.1", "CONNECT host:22",
            // "CONNECT h:22 GARBAGE", and "connect h:22 HTTP/1.1" all
            // answer nothing). The old code wrote "400 Bad Request" — not
            // Go bytes (round-3 review 2a).
            let host = match extract_route_host(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    warn!(peer = %peer, "TCPMux: no Host header or CONNECT target from {}", peer);
                    return;
                }
            };

            // Go net/http readRequest: `len(req.Header["Host"]) > 1` is a
            // "too many Host headers" error (RFC 7230 §5.4) — which reaches
            // readHTTPConnectRequest as an err → vhost handle closes with
            // ZERO bytes (probe vs Go v0.71.0). Applies even when the
            // CONNECT authority ignores the header for routing — the
            // duplicate check runs before any routing (round 6, LOW A9;
            // counting semantics shared with the vhost path).
            if crate::vhost::count_host_headers(&request_text) > 1 {
                warn!(peer = %peer, "TCPMux: too many Host headers from {}", peer);
                return;
            }

            debug!(
                target = %target, host = %host, peer = %peer,
                "TCPMux CONNECT target='{}' host='{}' from {}",
                target, host, peer
            );

            // Look up route (A2: the request's Proxy-Authorization username
            // is the second routing dimension — Go `getExactOrAllUsersLocked`
            // tries the exact user bucket, then the "" all-users bucket).
            let http_user = extract_proxy_auth(&request_text)
                .map(|(u, _)| u)
                .unwrap_or_default();
            let route = match state.tcpmux_manager.lookup(&host, &http_user).await {
                Some(r) => r,
                None => {
                    warn!(
                        host = %host, http_user = %http_user, peer = %peer,
                        "TCPMux: no route for host '{}' (http_user '{}') from {}",
                        host, http_user, peer
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

            // Go successHook-before-checkAuth order (vhost.go handle
            // 192-209): the 200 OK is written on the route BEFORE the
            // Proxy-Authorization check — an unauthorized client receives
            // "200 OK" then the 407, both on the same conn, before close
            // (probe vs Go v0.71.0). Reason phrase is Go's canonical
            // "200 OK" (http.go OkResponse) — the old "200 Connection
            // Established" diverged. Passthrough mode sends NO 200 at all
            // (httpconnect.go sendConnectResponse: `if muxer.passthrough {
            // return nil }`). pre_read carries every byte consumed past the
            // header terminator: passthrough forwards the whole request
            // INCLUDING the pipelined tail — Go parity (httpconnect.go
            // getHostFromHTTPConnect hands the passthrough path a
            // SharedConn whose io.TeeReader replays the read-ahead; the
            // pre-fix buf[..n] silently dropped them — M6). The
            // non-passthrough tail-forward after the 200 is a frp-rs
            // improvement, not parity: Go returns the RAW conn there and
            // abandons the tee buffer, dropping pipelined tunnel data
            // behind the CONNECT.
            let pre_read = if state.tcp_mux_passthrough {
                buf[..total].to_vec()
            } else {
                if let Err(e) = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await {
                    debug!(peer = %peer, error = %e, "TCPMux: failed to write 200 to {}: {}", peer, e);
                    return;
                }
                buf[n..total].to_vec()
            };

            // Check Proxy-Authorization if configured — AFTER the 200 (Go
            // order; the successHook write above ran first). 407 body = Go
            // ProxyUnauthorizedResponse (util/http/http.go): realm
            // "Restricted", NOT "frp".
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
                          Proxy-Authenticate: Basic realm=\"Restricted\"\r\n\r\n",
                        )
                        .await
                    {
                        tracing::debug!(error = %e, peer = %peer, "failed to write HTTP error response");
                    }
                    return;
                }
            }

            // TCPMux group fan-out (Go frp v0.71.0 TCPMuxGroup: accepted
            // conns on the shared route are delivered to ONE group member;
            // frp-rs round-robins like its HTTP group path — Go's acceptCh
            // is a member race). The lookup returned the FIRST member's
            // shared route; pick the dispatch target from the group's live
            // member list and fall back to the route owner when the chosen
            // member raced away (vhost group precedent). Auth above already
            // ran against the shared route — members are validated equal at
            // join (register_member), so the credentials are group-wide.
            let (dispatch_proxy_name, dispatch_run_id) = if route.group.is_empty() {
                (route.proxy_name.clone(), route.run_id.clone())
            } else {
                match state.tcpmux_group_ctl.choose_endpoint(&route.group).await {
                    Some(member) => match state.proxy_manager.get(&member).await {
                        Some(info) => {
                            debug!(
                                host = %host, group = %route.group, member = %member,
                                "TCPMux group '{}' -> member '{}'", route.group, member
                            );
                            (member, info.run_id.clone())
                        }
                        None => {
                            // Member gone between choose and lookup — fall
                            // back to the route's recorded proxy (first
                            // member).
                            warn!(
                                group = %route.group, member = %member,
                                "TCPMux: group member '{}' not registered, falling back to '{}'",
                                route.group, route.proxy_name
                            );
                            (route.proxy_name.clone(), route.run_id.clone())
                        }
                    },
                    None => {
                        // Group has no members (all unregistered) — route the
                        // conn to the first member anyway; the control
                        // dispatch will fail cleanly if it is gone too.
                        (route.proxy_name.clone(), route.run_id.clone())
                    }
                }
            };

            // Forward to the control handler for work connection bridging.
            let internal_tx = state
                .run_id_to_ctl_tx
                .get(&dispatch_run_id)
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
                        proxy_name: dispatch_proxy_name,
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
                        // Channel closed: control handler died between lookup
                        // and dispatch; the connection drops.
                        warn!(host = %host, "TCPMux: route for '{}' found but control channel closed", host);
                    }
                    Err(_elapsed) => {
                        warn!(host = %host, "TCPMux: route for '{}' found but control channel send timed out; dropping conn", host);
                    }
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
/// Returns (header_len, total_read): header_len is the position just past
/// the terminator; total_read may be LARGER — a single `read` into the
/// 512-byte chunk can consume pipelined bytes past the headers, and those
/// bytes must survive (the caller forwards them as pre-read data; M6 —
/// round-3 finding: they were dropped, corrupting any request that
/// pipelined payload bytes in the same TCP segment as its CONNECT).
async fn read_http_headers(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut [u8],
) -> Result<(usize, usize), String> {
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
            return Ok((search_start + pos + 4, total));
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
/// bracket-start with `]:` (bracketed IPv6). `strict_port` mirrors the
/// source's validation: on the CONNECT request line, url.ParseRequestURI
/// rejects a non-numeric port (validOptionalPort `^:\d*$` — an empty
/// port is legal), so strict mode 400s "example.com:abc" but routes
/// "example.com:"; on the Host header, `net.SplitHostPort` never
/// validates the port (Go frp routes "Host: example.com:abc" to
/// example.com), so lenient mode accepts any suffix. Portless values are
/// used as-is: "example.com", "[::1]" (stays bracketed — nothing
/// registers brackets, so it is unroutable), or unbracketed multi-colon
/// "::1:443". Then trim exactly one trailing dot (Go TrimSuffix — one dot
/// only, so "example.com.." stays unroutable).
/// Shared with vhost.rs request-line parsing (CONNECT authority-form and
/// absolute-form request targets): Go `url.ParseRequestURI` enforces the
/// strict rules on the REQUEST LINE (a "GET http://h:abc/" or a
/// "CONNECT h:abc" is a 400 before routing; probes vs Go frp v0.71.0),
/// while the Host HEADER stays lenient. vhost.rs imports this via
/// `crate::tcpmux::canonicalize_host` (round-3 M4).
pub(crate) fn canonicalize_host(host: &str, strict_port: bool) -> Option<&str> {
    let colons = host.bytes().filter(|b| *b == b':').count();
    let hostname = if colons == 1 {
        // host:port — strict mode requires the port to be empty or
        // numeric (url.ParseRequestURI); lenient mode takes any suffix.
        let (h, port) = host.rsplit_once(':')?;
        if strict_port && !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        h
    } else if colons >= 2 && host.starts_with('[') && host.contains("]:") {
        // Bracketed IPv6 with port: [::1]:443 → ::1. "[::1]" without a
        // "]:port" is portless in Go too (hasPort false) and stays
        // bracketed — unroutable.
        let end = host.find(']')?;
        // Round 6 (A5): Go SplitHostPort brackets the FIRST '[' to the
        // LAST ']' — "[::1]x]:8080" → host "::1]x" (unroutable). The ']'
        // must be immediately followed by ':'; when it is not, strict
        // mode 400s (url.ParseRequestURI rejects a mis-bracketed
        // authority on the CONNECT line) and lenient mode routes the raw
        // value — same unroutable 404 as Go's "::1]x".
        if !host[end + 1..].starts_with(':') {
            if strict_port {
                return None;
            }
            return Some(trim_trailing_dot(host));
        }
        let port = &host[end + 2..];
        if strict_port && !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
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
/// Lenient port mode: Go routes "Host: example.com:abc" (SplitHostPort
/// never validates the port).
fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        // `get(..5)`, not `line[..5]`: len >= 6 does NOT imply byte 5 is a
        // char boundary — a multibyte-UTF-8 header line ("éééé" is 8 bytes)
        // panics on the direct slice under panic=abort. Same fix as vhost.rs
        // round-16; tcpmux was the unsynced copy. get() skips = non-match.
        if !line
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("host:"))
        {
            continue;
        }
        // Safe: the get(..5) match above proves bytes 0-4 are ASCII
        // (eq_ignore_ascii_case only matches an ASCII prefix), so byte 5 is
        // a char boundary.
        let value = line[5..].trim();
        return canonicalize_host(value, false);
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
    // Go net/http parseRequestLine splits on SPACE only, at most 3 tokens
    // (SplitN(line, " ", 3)): "METHOD TARGET VERSION". A 2-part line
    // (versionless, or "CONNECT HTTP/1.1" — the version string in the
    // target slot) errors the whole ReadRequest regardless of any Host
    // header → the caller closes silently (zero bytes, probe vs Go
    // v0.71.0). Tab-separated versions merge into the target token and
    // fail the authority parse below (Go's space-only split makes the
    // whole line malformed). The version must be the exact 8-char shape
    // "HTTP/X.Y" (ParseHTTPVersion; "HTTP/2.0" is accepted, "HTTP/1.10"
    // rejected — see is_valid_version) — "HTTP/2", "garbage", and 4-token
    // lines (version + trailing junk) all error in Go the same way.
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if target.is_empty()
        || version.is_empty()
        || !is_valid_version(version)
        || target.starts_with("HTTP/")
    {
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
    // header is ignored). Strict port mode: url.ParseRequestURI rejects a
    // non-numeric port ("example.com:abc" → 400) but accepts an empty
    // one ("example.com:" routes to example.com).
    canonicalize_host(target, true)
}

/// Go net/http ParseHTTPVersion (Go 1.25): exactly 8 chars "HTTP/X.Y"
/// with single-digit major and minor. "HTTP/1.10" (9 chars), "HTTP/1.x",
/// and "HTTP/11.0" all fail the shape → malformed → the caller closes
/// silently (zero bytes, probe vs Go v0.71.0). NOTE: "HTTP/2.0" parses
/// fine and is accepted — tcpmux uses http.ReadRequest (client-side
/// parse), which has NO ProtoMajor gate (the 505 gate is http.Server-
/// specific and does not apply here; the vhost path has its own, see
/// vhost.rs A7). The round-5 comment claiming "major 1" was wrong,
/// verified against Go 1.25.0 stdlib source.
fn is_valid_version(version: &str) -> bool {
    if version.len() != 8 || !version.starts_with("HTTP/") {
        return false;
    }
    let b = version.as_bytes();
    b[5].is_ascii_digit() && b[6] == b'.' && b[7].is_ascii_digit()
}

/// Extract Proxy-Authorization Basic credentials.
fn extract_proxy_auth(request: &str) -> Option<(String, String)> {
    let auth_line = request.lines().find(|line| {
        // `get(..20)`, not `line[..20]`: a line >= 20 bytes whose byte 19
        // starts a multibyte UTF-8 char panics on the direct slice (round-16
        // vhost fix; tcpmux was the unsynced copy). Reachable pre-auth on
        // every CONNECT (this runs before route lookup) — a hostile header
        // line of 19 ASCII bytes + one non-ASCII char aborts frps. get()
        // skips = non-match.
        line.get(..20)
            .is_some_and(|p| p.eq_ignore_ascii_case("proxy-authorization:"))
    })?;
    // Safe: the match above proves bytes 0-19 are ASCII → byte 20 boundary.
    // Outer whitespace is trimmed once (Go textproto readMIMEHeader strips
    // the surrounding OWS of the header value before auth parsing).
    let value = auth_line[20..].trim();
    let encoded = if value
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("Basic "))
    {
        // Safe: match proves bytes 0-5 ASCII → byte 6 is a boundary. The
        // payload after "Basic " is passed to base64 VERBATIM — no interior
        // trim (Go http.go:81-99 ParseBasicAuth decodes `auth[len(prefix):]`
        // with StdEncoding, which rejects interior whitespace). "Basic  x"
        // (double space) or "Basic \tx" must fail like Go, or a padded
        // credential would authenticate where Go rejects it.
        &value[6..]
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
        // Neither a Host header nor a request-line target: no route. The
        // "CONNECT HTTP/1.1" line has no authority either — the second
        // token is the HTTP version, which must not be routed on. The
        // caller's None arm closes silently (Go ReadRequest error class,
        // probe vs Go v0.71.0: zero bytes).
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
        // Non-numeric port on the request line: url.ParseRequestURI's
        // validOptionalPort rejects it → Go ReadRequest error → the
        // caller closes silently (zero bytes, probe vs Go v0.71.0).
        assert_eq!(
            extract_route_host("CONNECT example.com:abc HTTP/1.1\r\n\r\n"),
            None
        );
        // Empty port is legal (validOptionalPort `^:\d*$`) — Go routes
        // "CONNECT example.com:" to example.com.
        assert_eq!(
            extract_route_host("CONNECT example.com: HTTP/1.1\r\n\r\n"),
            Some("example.com")
        );
        // Versionless request line: Go parseRequestLine needs 3 parts and
        // errors → silent close, no routing on the Host header either.
        let req = "CONNECT example.com:443\r\nHost: other.net\r\n\r\n";
        assert_eq!(extract_route_host(req), None);
        // Version content is validated (parseProtoVersion: major 1,
        // numeric minor) — "HTTP/2" and trailing junk 400 in Go.
        assert_eq!(
            extract_route_host("CONNECT example.com:443 HTTP/2\r\n\r\n"),
            None
        );
        assert_eq!(
            extract_route_host("CONNECT example.com:443 HTTP/1.1 EXTRA\r\n\r\n"),
            None
        );
        // Tab between target and version: Go splits on SPACE only → the
        // line is malformed (2 tokens) → 400.
        assert_eq!(
            extract_route_host("CONNECT example.com:443\tHTTP/1.1\r\n\r\n"),
            None
        );
        // Lowercase method: Go justAuthority is case-sensitive → no URL
        // host → Host header fallback (the caller 405s non-"CONNECT").
        let req = "connect example.com:443 HTTP/1.1\r\nHost: header.net\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("header.net"));
        // Host header port is NOT validated (SplitHostPort accepts any
        // suffix) — Go routes "Host: example.com:abc" to example.com.
        let req = "CONNECT /path HTTP/1.1\r\nHost: example.com:abc\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("example.com"));
        // Bracketed IPv6 without a port stays bracketed (hasPort false) —
        // unroutable, but not an error.
        let req = "CONNECT [::1] HTTP/1.1\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("[::1]"));
        // Bracketed IPv6 with a non-numeric port is unroutable on the
        // request line; an empty port routes.
        assert_eq!(
            extract_route_host("CONNECT [::1]:abc HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            extract_route_host("CONNECT [::1]: HTTP/1.1\r\n\r\n"),
            Some("::1")
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

    #[test]
    fn test_extract_proxy_auth_go_verbatim_payload_parity() {
        // Go parity matrix (pkg/util/http/http.go:81-99 ParseBasicAuth +
        // textproto header trimming): the header VALUE is trimmed of outer
        // whitespace once, then the payload after "Basic " is passed to
        // StdEncoding VERBATIM — interior whitespace is never trimmed, so
        // "Basic  <token>" (double space) and "Basic \t<token>" must fail
        // base64 decode exactly like Go. frp-rs's auth.go:81-97 sibling in
        // vhost.rs already carries these pins; tcpmux's extract_proxy_auth
        // was the unsynced copy.
        let mut b64 = "dXNlcjpwYXNz"; // "user:pass"
                                      // Single space: accepted.
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            b64
        );
        assert_eq!(
            extract_proxy_auth(&req),
            Some(("user".into(), "pass".into()))
        );
        // Double space after "Basic ": rejected.
        let req =
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic   dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(extract_proxy_auth(req), None);
        // Tab after "Basic ": rejected.
        let req =
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic \tdXNlcjpwYXNz\r\n\r\n";
        assert_eq!(extract_proxy_auth(req), None);
        // Trailing OWS on the header line is trimmed BEFORE auth parsing
        // (Go readMIMEHeader strips outer whitespace) — the payload itself
        // is then verbatim single-space: accepted.
        let req = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz  \t\r\n\r\n";
        assert_eq!(
            extract_proxy_auth(req),
            Some(("user".into(), "pass".into()))
        );
        // Empty payload after "Basic ": header OWS trims the value to
        // "Basic", which fails the "Basic " prefix match — Go readMIMEHeader
        // trims the same way before ParseBasicAuth, so both reject.
        let req = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic\r\n\r\n";
        assert_eq!(extract_proxy_auth(req), None);
        // b64 = "user:" (trailing-colon creds) — empty password is legal.
        b64 = "dXNlcjo=";
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            b64
        );
        assert_eq!(extract_proxy_auth(&req), Some(("user".into(), "".into())));
    }

    #[test]
    fn test_extract_host_header_multibyte_utf8_no_panic() {
        // Regression for the round-16 A1 abort vector (this file's copy was
        // left unfixed): a header line of 4 multibyte chars is 8 bytes (>= 6)
        // but byte 5 is NOT a char boundary — `line[..5]` panicked under
        // panic=abort on every path-form CONNECT. get(..5) skips instead.
        let req = "CONNECT /path HTTP/1.1\r\néééé\r\n\r\n";
        assert_eq!(extract_host_header(req), None);
        assert_eq!(extract_route_host(req), None);
        // A valid Host line after a hostile one still parses.
        let req = "CONNECT /path HTTP/1.1\r\néééé\r\nHost: foo.bar\r\n\r\n";
        assert_eq!(extract_route_host(req), Some("foo.bar"));
        // A "Host:" prefix followed by a multibyte value: the prefix is pure
        // ASCII so byte 5 is a boundary — the value parses as an (unroutable)
        // hostname instead of panicking.
        let req = "CONNECT /path HTTP/1.1\r\nHost: éééé\r\n\r\n";
        assert_eq!(extract_host_header(req), Some("éééé"));
    }

    #[tokio::test]
    async fn test_read_http_headers_basic_and_multiline() {
        // Simple single-header request: header_len is just past \r\n\r\n.
        let (mut a, mut b) = tokio::io::duplex(1024);
        b.write_all(b"CONNECT x.example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let (header_len, total) = read_http_headers(&mut a, &mut buf).await.unwrap();
        assert_eq!(
            &buf[..header_len],
            b"CONNECT x.example.com:443 HTTP/1.1\r\n\r\n"
        );
        assert_eq!(total, header_len, "no pipelined bytes expected");

        // Multi-header request: auth + host lines, terminator at the end.
        let (mut a, mut b) = tokio::io::duplex(1024);
        b.write_all(
            b"CONNECT x.example.com:443 HTTP/1.1\r\n\
              Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
              Host: x.example.com:443\r\n\
              \r\n",
        )
        .await
        .unwrap();
        let mut buf = [0u8; 4096];
        let (header_len, total) = read_http_headers(&mut a, &mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..header_len]);
        assert!(head.ends_with("\r\n\r\n"));
        assert!(head.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
        assert!(head.contains("Host: x.example.com:443"));
        assert_eq!(total, header_len);
    }

    #[tokio::test]
    async fn test_read_http_headers_pipelined_tail_preserved() {
        // M6 pin (round-3 finding): a CONNECT whose payload bytes ride in the
        // same TCP segment as the header terminator must not lose them —
        // read_http_headers returns header_len < total and the tail must
        // survive verbatim for the caller's pre-read forwarding.
        let (mut a, mut b) = tokio::io::duplex(1024);
        b.write_all(b"CONNECT x.example.com:443 HTTP/1.1\r\n\r\nPAYLOAD-123")
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let (header_len, total) = read_http_headers(&mut a, &mut buf).await.unwrap();
        assert_eq!(
            &buf[..header_len],
            b"CONNECT x.example.com:443 HTTP/1.1\r\n\r\n"
        );
        assert!(
            total > header_len,
            "pipelined tail must be counted: header {header_len} total {total}"
        );
        assert_eq!(
            &buf[header_len..total],
            b"PAYLOAD-123",
            "pipelined tail bytes must survive byte-exact"
        );
    }

    #[tokio::test]
    async fn test_read_http_headers_terminator_across_chunk_boundary() {
        // The \r\n\r\n terminator may straddle two 512-byte chunk reads; the
        // 3-byte overlap window must find it and the length must be exact.
        let (mut a, mut b) = tokio::io::duplex(4096);
        // 510 filler bytes + a terminator starting at offset 510 (byte 510 is
        // the first \r) + a tail past the terminator.
        let mut input = Vec::new();
        input.extend_from_slice(&b"A".repeat(510));
        input.extend_from_slice(b"\r\n\r\n");
        input.extend_from_slice(b"TAIL!");
        b.write_all(&input).await.unwrap();
        let mut buf = [0u8; 4096];
        let (header_len, total) = read_http_headers(&mut a, &mut buf).await.unwrap();
        assert_eq!(header_len, 510 + 4);
        assert_eq!(total, 510 + 4 + 5);
        assert_eq!(&buf[header_len..total], b"TAIL!");
    }

    #[tokio::test]
    async fn test_read_http_headers_oversized_rejected() {
        // A header block larger than the caller's buffer is an error, never a
        // partial parse — the shared listener maps this to a silent close.
        let (mut a, mut b) = tokio::io::duplex(1024);
        b.write_all(&b"X".repeat(100)).await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(
            read_http_headers(&mut a, &mut buf).await.unwrap_err(),
            "headers too large"
        );
    }

    #[tokio::test]
    async fn test_read_http_headers_eof_before_terminator() {
        // Peer closed mid-headers (no terminator, no oversize): the reader
        // reports the close instead of hanging.
        let (mut a, mut b) = tokio::io::duplex(1024);
        b.write_all(b"CONNECT x.example.com:443 HTTP/1.1\r\nHost: x")
            .await
            .unwrap();
        drop(b); // EOF
        let mut buf = [0u8; 4096];
        assert_eq!(
            read_http_headers(&mut a, &mut buf).await.unwrap_err(),
            "connection closed"
        );
    }

    #[test]
    fn test_extract_proxy_auth_multibyte_utf8_no_panic() {
        // Regression for the round-16 A1 abort vector (tcpmux copy): this
        // runs pre-auth on EVERY CONNECT (route lookup happens after), so a
        // hostile header line was an unauthenticated remote process kill.
        // Shape 1: 19 ASCII bytes + one multibyte char — byte 19 starts é,
        // so byte 20 is not a boundary; `line[..20]` panicked. No real
        // proxy-authorization prefix needed.
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\n{}\r\n\r\n",
            "A".repeat(19) + "é"
        );
        assert_eq!(extract_proxy_auth(&req), None);
        // Shape 2: real prefix, Basic value whose byte 6 straddles a char.
        let req = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: ééAéX\r\n\r\n";
        assert_eq!(extract_proxy_auth(req), None);
        // Shape 3: hostile filler line + valid auth line — the valid line
        // still matches (skip semantics, not whole-request rejection).
        let req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\n{}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            "é".repeat(30)
        );
        let (user, pwd) = extract_proxy_auth(&req).unwrap();
        assert_eq!((user.as_str(), pwd.as_str()), ("user", "pass"));
    }

    #[test]
    fn test_is_valid_version_go_parse_http_version_shape() {
        // Go 1.25 ParseHTTPVersion: exactly 8 chars "HTTP/X.Y", digits.
        assert!(is_valid_version("HTTP/1.1"));
        assert!(is_valid_version("HTTP/1.0"));
        assert!(is_valid_version("HTTP/0.9"));
        assert!(is_valid_version("HTTP/2.0")); // parse accepts; no server gate on ReadRequest
        assert!(!is_valid_version("HTTP/1.10")); // 9 chars — malformed
        assert!(!is_valid_version("HTTP/1.")); // 7 chars
        assert!(!is_valid_version("HTTP/1.x"));
        assert!(!is_valid_version("HTTP/11.0"));
        assert!(!is_valid_version("HTTP/1"));
        assert!(!is_valid_version("garbage"));
        assert!(!is_valid_version(""));
    }

    #[test]
    fn test_canonicalize_host_bracket_requires_colon_after_close() {
        // A5: "[::1]x]:8080" is NOT a bracket form — Go SplitHostPort
        // yields host "::1]x" (unroutable), not "::1".
        assert_eq!(canonicalize_host("[::1]:8080", false), Some("::1"));
        assert_eq!(
            canonicalize_host("[::1]x]:8080", false),
            Some("[::1]x]:8080")
        );
        // strict mode (CONNECT line): mis-bracketed → 400 (None).
        assert_eq!(canonicalize_host("[::1]x]:8080", true), None);
        assert_eq!(canonicalize_host("[::1]:8080", true), Some("::1"));
        // "[]:extra" — empty bracketed host + junk port: colons==1 splits
        // to host "[]" (unroutable); strict rejects the non-numeric port.
        assert_eq!(canonicalize_host("[]:extra", false), Some("[]"));
        assert_eq!(canonicalize_host("[]:extra", true), None);
    }

    #[tokio::test]
    async fn test_tcpmux_manager_register_lookup_unregister() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("first registration must succeed");

        // Exact match
        let r = mgr.lookup("a.example.com", "").await.unwrap();
        assert_eq!(r.proxy_name, "p1");

        // With port
        let r = mgr.lookup("a.example.com:443", "").await.unwrap();
        assert_eq!(r.proxy_name, "p1");

        // No match
        assert!(mgr.lookup("other.example.com", "").await.is_none());

        // Unregister
        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com", "").await.is_none());
    }

    /// Go parity: the registration loop calls `Routers.Add` once per domain,
    /// and the second Add of a duplicate (domain, location, httpUser) triple
    /// hits `exist()` → conflict → the WHOLE registration fails. A duplicate
    /// inside a single call (including case variants, which collapse via
    /// lowercase) must reject the registration with no partial state.
    #[tokio::test]
    async fn test_tcpmux_register_same_call_duplicate_domain_rejected() {
        let mgr = TcpMuxManager::new();

        let err = mgr
            .register(
                "p1",
                &["a.example.com".into(), "A.EXAMPLE.COM".into()],
                "run-1",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("same-call duplicate domain must be rejected");
        assert!(
            err.contains("duplicate domain"),
            "error must name the duplicate: {err}"
        );

        // No partial state: nothing was registered, and the proxy is free to
        // re-register with a clean domain list.
        assert!(mgr.lookup("a.example.com", "").await.is_none());
        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("clean re-registration must succeed");
        let r = mgr.lookup("a.example.com", "").await.unwrap();
        assert_eq!(r.proxy_name, "p1");

        // Distinct domains in one call stay legal.
        mgr.register(
            "p2",
            &["x.example.com".into(), "y.example.com".into()],
            "run-2",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("distinct domains in one call must succeed");
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
            "MixedCase.Example.com:443",
        ] {
            let r = mgr
                .lookup(host, "")
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
                "",
                &[],
                "",
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
        assert!(mgr.lookup("mixedcase.example.com", "").await.is_none());
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
            "",
            &[],
            "",
        )
        .await
        .expect("registration must succeed");

        assert!(mgr.lookup("a.example.com", "").await.is_some());
        assert!(mgr.lookup("b.example.com", "").await.is_some());
        assert!(mgr.lookup("c.example.com", "").await.is_none());

        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com", "").await.is_none());
        assert!(mgr.lookup("b.example.com", "").await.is_none());
    }

    /// Go frp v0.71.0 compat (vhost.Muxer → getByRoute): tcpmux lookup
    /// walks exact → leftmost-label wildcard (>=3 labels) → "*" catch-all.
    #[tokio::test]
    async fn test_tcpmux_lookup_wildcard_leftmost_label() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["*.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("registration must succeed");

        // Any host under the wildcard matches.
        assert!(mgr
            .lookup("a.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        assert!(mgr
            .lookup("a.b.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        // Two-label hosts never match the wildcard (Go's >=3-label guard
        // keeps `*.com` from matching `example.com`).
        assert!(mgr.lookup("example.com", "").await.is_none());
        // Unrelated suffixes stay misses.
        assert!(mgr.lookup("a.example.net", "").await.is_none());
    }

    /// Go frp v0.71.0 compat (RouteConfig.RouteByHTTPUser +
    /// getExactOrAllUsersLocked, round 6 A2): route_by_http_user is a
    /// second routing dimension. A request only matches the bucket whose
    /// route_by_http_user equals its Proxy-Authorization username; the ""
    /// (all-users) bucket is the fallback. Same domain can host both.
    #[tokio::test]
    async fn test_tcpmux_lookup_route_by_http_user() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["example.com".into()],
            "run-1",
            "u1",
            "p1",
            "team-a",
            &[],
            "",
        )
        .await
        .expect("p1 registration must succeed");
        mgr.register("p2", &["example.com".into()], "run-2", "", "", "", &[], "")
            .await
            .expect("p2 registration must succeed (different rubu bucket)");

        // Same-domain different-rubu buckets coexist (Go exist() is per
        // (domain, httpUser)) — but a same-rubu claim conflicts.
        let err = mgr
            .register(
                "p3",
                &["example.com".into()],
                "run-3",
                "",
                "",
                "team-a",
                &[],
                "",
            )
            .await
            .expect_err("same (domain, rubu) claim must conflict");
        assert!(err.contains("team-a"), "conflict names the rubu: {err}");

        // Request user "alice" misses the "team-a" bucket, falls to "" (p2).
        let r = mgr.lookup("example.com", "alice").await.unwrap();
        assert_eq!(r.proxy_name, "p2");
        // Request user "team-a" hits the exact bucket (p1).
        let r = mgr.lookup("example.com", "team-a").await.unwrap();
        assert_eq!(r.proxy_name, "p1");
        // No auth at all → "" fallback.
        let r = mgr.lookup("example.com", "").await.unwrap();
        assert_eq!(r.proxy_name, "p2");

        // Unregister p1 removes only its bucket; p2's "" bucket survives.
        mgr.unregister("p1").await;
        let r = mgr.lookup("example.com", "team-a").await.unwrap();
        assert_eq!(r.proxy_name, "p2");
        assert!(mgr.lookup("example.com", "alice").await.is_some());
    }

    #[tokio::test]
    async fn test_tcpmux_lookup_wildcard_catch_all() {
        let mgr = TcpMuxManager::new();
        mgr.register("p1", &["*".into()], "run-1", "", "", "", &[], "")
            .await
            .expect("catch-all registration must succeed");

        for host in [
            "anything.example.com",
            "example.com",
            "localhost",
            "localhost:8080",
        ] {
            assert!(
                mgr.lookup(host, "")
                    .await
                    .is_some_and(|r| r.proxy_name == "p1"),
                "catch-all must match '{host}'"
            );
        }
    }

    #[tokio::test]
    async fn test_tcpmux_lookup_exact_beats_wildcard() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
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
            "run-2",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("wildcard registration must succeed");

        // Exact match wins; the wildcard catches everything else under the
        // domain, including deeper hosts (leftmost-label walk).
        assert!(mgr
            .lookup("a.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        assert!(mgr
            .lookup("b.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p2"));
        assert!(mgr
            .lookup("x.y.example.com", "")
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
        mgr.register("p1", &["example.com".into()], "run-1", "", "", "", &[], "")
            .await
            .expect("registration must succeed");

        assert!(mgr
            .lookup("example.com.", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        assert!(mgr
            .lookup("example.com.:443", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
        // Two trailing dots: only one is trimmed → no route.
        assert!(mgr.lookup("example.com..", "").await.is_none());
    }

    /// Regression test for audit finding 5: a second proxy claiming an
    /// already-routed domain must be rejected, not silently overwrite the
    /// first registration (which previously let the closing proxy delete a
    /// live sibling's route).
    #[tokio::test]
    async fn test_tcpmux_manager_conflict_rejects_second_proxy() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("first registration must succeed");

        let err = mgr
            .register(
                "p2",
                &["a.example.com".into()],
                "run-2",
                "",
                "",
                "",
                &[],
                "",
            )
            .await
            .expect_err("conflicting domain must be rejected");
        assert!(
            err.contains("a.example.com"),
            "conflict must name the domain: {err}"
        );

        // The first proxy's route is intact; the second never registered.
        assert!(mgr
            .lookup("a.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));

        // Same-name re-registration is idempotent (allowed).
        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("same-proxy re-registration must succeed");
        assert!(mgr
            .lookup("a.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));
    }

    /// Regression test for audit finding 5: unregister must not delete a
    /// route that now belongs to a different proxy (defense-in-depth for
    /// stale by_proxy state from the pre-fix last-writer-wins behavior).
    #[tokio::test]
    async fn test_tcpmux_unregister_keeps_foreign_route() {
        let mgr = TcpMuxManager::new();

        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("registration must succeed");

        // Simulate the pre-fix last-writer-wins state: the route now belongs
        // to p2, and p2's by_proxy entry also lists the domain.
        {
            let mut routes = mgr.routes.write().await;
            routes
                .entry("a.example.com".to_string())
                .or_default()
                .insert(
                    String::new(),
                    TcpMuxRoute {
                        proxy_name: "p2".to_string(),
                        run_id: "run-2".to_string(),
                        http_user: String::new(),
                        http_pwd: String::new(),
                        route_by_http_user: String::new(),
                        group: String::new(),
                    },
                );
            mgr.by_proxy
                .write()
                .await
                .insert("p2".to_string(), vec!["a.example.com".to_string()]);
        }

        mgr.unregister("p1").await;
        assert!(
            mgr.lookup("a.example.com", "")
                .await
                .is_some_and(|r| r.proxy_name == "p2"),
            "p1's unregister must not delete p2's live route"
        );

        mgr.unregister("p2").await;
        assert!(mgr.lookup("a.example.com", "").await.is_none());
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
            "",
            &[],
            "",
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
            "",
            &[],
            "",
        )
        .await
        .expect("idempotent re-registration must succeed");
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 1);

        // A wildcard lookup hits the registered route.
        assert!(mgr
            .lookup("x.wild.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p1"));

        // Shrunken re-registration (server reload drops the wildcard):
        // the route and its count must leave the map.
        mgr.register(
            "p1",
            &["a.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("shrunken re-registration must succeed");
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 0);
        assert!(mgr.lookup("x.wild.example.com", "").await.is_none());

        // unregister decrements on the route the proxy still owns.
        mgr.unregister("p1").await;
        assert!(mgr.lookup("a.example.com", "").await.is_none());

        // A wildcard route owned by a DIFFERENT proxy (legacy by_proxy
        // state) keeps both the route and the count through p1's
        // unregister.
        mgr.register(
            "p1",
            &["*.shared.example.com".into()],
            "run-1",
            "",
            "",
            "",
            &[],
            "",
        )
        .await
        .expect("registration must succeed");
        {
            let mut routes = mgr.routes.write().await;
            routes
                .entry("*.shared.example.com".to_string())
                .or_default()
                .insert(
                    String::new(),
                    TcpMuxRoute {
                        proxy_name: "p2".to_string(),
                        run_id: "run-2".to_string(),
                        http_user: String::new(),
                        http_pwd: String::new(),
                        route_by_http_user: String::new(),
                        group: String::new(),
                    },
                );
        }
        mgr.unregister("p1").await;
        assert_eq!(mgr.wildcard_count.load(Ordering::Relaxed), 1);
        assert!(mgr
            .lookup("x.shared.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "p2"));
    }
}
