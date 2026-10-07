//! Pure HTTP head parsing helpers for the vhost path.
//!
//! Split out of `vhost.rs` as a pure text move; the parent re-imports the
//! validators/parsers its request path and sibling test module still call.

use crate::tcpmux::canonicalize_host;

/// RFC 7230 tchar (ALPHA / DIGIT / "!#$%&'*+-.^_`|~") — Go's method and
/// header-name byte set (httpguts `ValidHeaderFieldName` / textproto
/// `validHeaderFieldByte`). 0x80+ obs-text is never tchar; lossy-converted
/// heads (U+FFFD = EF BF BD) are rejected for names exactly like Go rejects
/// obs-text names.
fn is_vhost_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// textproto `validHeaderValueByte` complement: a value byte is a parse
/// error when it is a CTL other than HTAB (< 0x20, != 0x09) or DEL (0x7f).
/// obs-text (0x80+) is legal.
fn is_bad_vhost_value_byte(b: u8) -> bool {
    (b < b' ' && b != b'\t') || b == 0x7f
}

/// httpguts `validHostByte` (httplex.go:225-263) — the lenient
/// `ValidHostHeader` byte set: RFC 3986 unreserved + sub-delims plus
/// ':' '[' ']' and '%' (pct-encoding / IPv6 zones).
fn is_valid_vhost_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'$'
                | b'%'
                | b'&'
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b':'
                | b';'
                | b'='
                | b'['
                | b'\''
                | b']'
                | b'_'
                | b'~'
        )
}

/// Verdict of the FIX-6 head-line validation (Go conn.readRequest's
/// server-layer checks, server.go:1061-1072). PartialEq/Eq/Debug for the
/// verdict unit tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HeadLineVerdict {
    /// No defect in the prescribed classes.
    Ok,
    /// Generic 400 render ("400 Bad Request") — Go textproto read-time
    /// classes. They precede the dup-Host/505/missing-Host gates in Go,
    /// and the round-18 caller dispatch runs this arm before those gates
    /// too (see the caller comment).
    Malformed,
    /// Go statusError — carries the FULL status text (detail appended on
    /// the status line AND the body: "400 Bad Request: malformed Host
    /// header"), ready for write_go_server_error.
    Detailed(&'static str),
}

/// FIX 6 (audit round 14): Go conn.readRequest's post-gate head
/// validation (server.go:1061-1072), verified byte-for-byte with probes
/// against go1.25.0. The caller emits the `Malformed` verdict BEFORE the
/// earlier arms (dup-Host → 505 → missing-Host — Go's read-time parse
/// errors precede all three; round 18) and emits the `Detailed` verdicts
/// after them, over the RAW wire lines (textproto merges
/// obs-fold continuations into the preceding header's value with a single
/// SP per fold after a SP/HTAB-only trim of each physical line — reader.go
/// trim, see the value-scan comment below for the edge-CTL consequence):
///
/// 1. CTL/DEL in any header VALUE — the group-first line's after-colon
///    bytes AND every obs-fold continuation of that group (Go's value
///    byte check runs on the MERGED line) → `Malformed` (generic 400).
///    This class includes a CTL byte in the Host value: probe
///    "Host: a.co\x01m" answers the GENERIC 400 — textproto rejects at
///    read time, before the ValidHostHeader gate would ever see it.
/// 2. A header NAME byte that is neither tchar nor SPACE — parens, tab,
///    DEL, obs-text — or an empty name (" : x") → `Malformed` (generic
///    400): textproto `canonicalMIMEHeaderKey` accepts ONLY SPACE in a
///    name (go.dev/issue/34540 — probe: "Bad Name: x" reaches the http
///    layer while "Bad(Name: x" errors at read time). SPACE in a name is
///    deliberately NOT a generic error.
/// 3. The single Host value (fold-merged) failing httpguts
///    `ValidHostHeader` → `Detailed("malformed Host header")`. Any
///    obs-fold after the Host line fails: the merge inserts a SP into
///    the value (probe: "Host: a.com b.com" → malformed-Host detail).
///    Empty value passes (ValidHostHeader("") == true).
/// 4. A SPACE-containing header name → `Detailed("invalid header name")`
///    (server.go:1065 — textproto stored the line; the http layer
///    rejects the non-token key).
///
/// Render precedence inside this function mirrors Go: the read-time
/// generic classes (1/2) beat the statusError details (3/4), and the Host
/// check (3) precedes the name check (4). The textproto read-time classes
/// fire BEFORE Go's dup-Host/505/missing-Host gates — the caller dispatch
/// matches that order since round 18 (its `Malformed` arm returns before
/// those gates); the `Detailed` classes keep their Go position after them.
pub(super) fn validate_vhost_head_lines(request: &str) -> HeadLineVerdict {
    let mut lines = request.lines().skip(1).peekable();
    let mut malformed = false;
    let mut space_name = false;
    // First Host group's merged value (Go Header map: first Host line
    // wins — extract_host_header uses the same .find() order).
    let mut host_value: Option<String> = None;
    while let Some(first) = lines.next() {
        // The head's terminating blank line. The caller's head slice
        // INCLUDES the terminator — head_end returns the index past the
        // final `\n` — so `str::lines()` yields a final "" element on
        // EVERY well-formed head (exactly ONE for a CRLFCRLF terminator:
        // `str::lines()` splits at each `\r\n`/`\n` and drops the empty
        // tail after the final line ending). A blank must END the header
        // block like Go's textproto: `readMIMEHeader` returns at the first
        // empty line and never parses past it. Without the break, the
        // terminal "" would fall through to the missing-colon class below
        // and reject every legal terminated head — the break firing on the
        // terminal "" is precisely what keeps the colonless group-first
        // rule safe (the round-14 tcpmux 9ff87ca trap, mirrored here).
        if first.is_empty() {
            break;
        }
        if first.starts_with(' ') || first.starts_with('\t') {
            // obs-fold continuation directly after the REQUEST line: Go
            // textproto "malformed MIME header initial line" — generic.
            // (A fold after a real header group is consumed inside the
            // group loop below; its bytes face the value CTL check there.)
            malformed = true;
            continue;
        }
        let Some(colon) = first.find(':') else {
            // Group-first line without a colon — Go textproto's
            // missing-colon class (reader.go:543-545: the group-start
            // physical line must carry a colon or readMIMEHeader returns
            // the ProtocolError → conn.serve generic 400, the FIX-6 probe
            // shape). Round-15 W1: this used to `continue` (route the head
            // unchanged) — a colonless line is a read-time rejection, not
            // a legal header.
            malformed = true;
            continue;
        };
        let name = &first[..colon];
        let value = &first[colon + 1..];
        // Class 2: name bytes. textproto accepts SPACE (no
        // canonicalization — go.dev/issue/34540) and rejects everything
        // else that is not tchar, including an empty name.
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.iter().any(|b| !is_vhost_tchar(*b) && *b != b' ') {
            malformed = true;
        } else if name_bytes.contains(&b' ') {
            space_name = true;
        }
        // Class 1 + obs-fold merge: the group's value is the first line's
        // after-colon bytes plus each continuation line (Go
        // readContinuedLineSlice joins with " " + the fold after trimming
        // each PHYSICAL line of SP/HTAB ONLY at both ends — reader.go
        // trim; bufio elides just the \r\n/\n terminator). CTL/DEL
        // anywhere in the merged value is a generic read-time error
        // (probe: CTL inside a fold → ERR). The trims below therefore use
        // Go's SP/HTAB-only charset (round-16 finding: the old Rust
        // Unicode-whitespace trims stripped \r/\x0b/\x0c at value/fold
        // EDGES before the scan, and the head routed where Go's read-time
        // scan rejects). An edge CTL byte survives the trim exactly like
        // Go: the second `\r` of a `\r\r\n`-terminated line (bufio drops
        // exactly one), a trailing \x0b/\x0c, a `\r` opening the fold
        // contents after its leading SP — all generic 400s.
        let mut value_has_ctl = value
            .trim_end_matches([' ', '\t'])
            .bytes()
            .any(is_bad_vhost_value_byte);
        let mut merged: Option<String> =
            if name.eq_ignore_ascii_case("host") && host_value.is_none() {
                // Go stored value: readContinuedLineSlice trim()s the whole
                // PHYSICAL line first (SP/HTAB at BOTH ends — reader.go
                // trim), so trailing "Host: a.com  " OWS is gone before
                // readMIMEHeader's TrimLeft(v, " \t") keeps the value
                // (probe vs go1.25: trailing-OWS Host is served, 200).
                Some(String::from(value.trim_matches([' ', '\t'])))
            } else {
                None
            };
        while let Some(fold) = lines.next_if(|l| l.starts_with(' ') || l.starts_with('\t')) {
            // SP/HTAB-only, both ends — Go reader.go trim (see the
            // comment above: an edge CTL byte must survive into the scan).
            let fold = fold.trim_matches([' ', '\t']);
            if fold.bytes().any(is_bad_vhost_value_byte) {
                value_has_ctl = true;
            }
            if let Some(m) = merged.as_mut() {
                m.push(' ');
                m.push_str(fold);
            }
        }
        if value_has_ctl {
            // Read-time textproto class — beats every statusError detail
            // (Go rejects the head during ReadMIMEHeader, before the
            // dup-Host / 505 / missing-Host / host / name gates).
            malformed = true;
        }
        if host_value.is_none() {
            host_value = merged;
        }
    }
    if malformed {
        return HeadLineVerdict::Malformed;
    }
    // Class 3: the single Host value — Go conn.readRequest runs this
    // after the missing-Host gate, before the per-name loop (the caller
    // already rejected >1 Host lines with the dup-Host 400). Fold-merging
    // puts a SP into the value → always invalid (probe: "Host: a.com
    // b.com" → malformed Host detail); an empty value passes
    // (ValidHostHeader("") == true).
    if let Some(host) = host_value {
        if !host.bytes().all(is_valid_vhost_host_byte) {
            return HeadLineVerdict::Detailed("400 Bad Request: malformed Host header");
        }
    }
    if space_name {
        return HeadLineVerdict::Detailed("400 Bad Request: invalid header name");
    }
    HeadLineVerdict::Ok
}

/// Outcome of parsing the HTTP request line with Go net/http semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestLine<'a> {
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
pub(super) fn parse_vhost_request_line(request: &str) -> RequestLine<'_> {
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

    // Go readRequest parity — validMethod (request.go:1101-1103), which
    // runs right after the parseRequestLine shape gate and BEFORE
    // ParseHTTPVersion: the method must be a non-empty RFC 7230 token
    // (Go httpguts.ValidHeaderFieldName, which rejects "" — probes vs
    // go1.25: "GET( ..." / "GET\tFOO ..." / " / HTTP/1.1" all answer the
    // same generic 400). The generic-400 class is preserved even when the
    // version token alone would 505: "GET( / HTTP/2.0" is a 400 in Go,
    // never a 505 — the version-shape/505 checks below must not run first.
    if method.is_empty() || !method.bytes().all(is_vhost_tchar) {
        return RequestLine::BadRequest;
    }

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
pub(super) fn request_line_minor_gte_1(request: &str) -> bool {
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

/// Extract HTTP Basic Auth credentials from the Authorization header.
/// Returns Some((username, password)) or None if no/invalid auth header.
pub(super) fn extract_basic_auth(request: &str) -> Option<(String, String)> {
    extract_basic_auth_named(request, "authorization:")
}

/// Same parser with a configurable header name — absolute-form requests
/// (Go `req.URL.Host != ""`) carry credentials in `Proxy-Authorization`
/// instead (Go `checkRouteAuthByRequest` reads ONLY that header there).
/// `header` must include the trailing colon (e.g. "proxy-authorization:").
pub(super) fn extract_basic_auth_named(request: &str, header: &str) -> Option<(String, String)> {
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
pub(super) fn has_nonempty_header(request: &str, header: &str) -> bool {
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
pub(super) fn canonicalize_authority(value: &str) -> &str {
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
pub(super) fn extract_raw_request_host(request: &str, is_absolute_form: bool) -> &str {
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

pub(super) fn extract_host_header(request: &str) -> Option<&str> {
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
