//! Vhost request resolution and HTTP/1.1 request-head rewriting.
//!
//! Split out of `vhost.rs` as a pure text move; the parent re-imports the
//! resolver entry point/types its request path and `vhost_h2c.rs` use, and the
//! rewrite helpers the sibling test module exercises.

use crate::service::AppState;
use tracing::{debug, warn};

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

/// Strip CR/LF from a configured `host_header_rewrite` value to prevent HTTP
/// header injection. Called ONCE per route at registration
/// (`VhostManager::register`); the request path uses the stored
/// `VhostRoute::host_header_rewrite_sanitized` directly (audit §3 item 4).
pub(super) fn sanitize_rewrite_host(host: &str) -> String {
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
pub(super) fn rewrite_host_header(data: Vec<u8>, new_host: &str) -> Vec<u8> {
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
pub(super) fn strip_vhost_hop_by_hop_headers(data: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) {
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
pub(super) fn inject_vhost_request_headers(
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
