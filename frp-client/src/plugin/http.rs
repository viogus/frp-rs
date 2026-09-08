use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::debug;

use frp_core::config::PluginConfig;

use super::{base64_decode, serve_plugin, split_host_port, PluginHandle};

/// Start an HTTP proxy plugin server.
///
/// Returns a handle with the bound address. The server handles:
/// - CONNECT tunneling (HTTPS)
/// - Plain HTTP forwarding
/// - Optional basic auth via `http_user` / `http_password`
pub async fn start_http_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let auth = HttpProxyAuth::from_config(cfg);
    serve_plugin("http_proxy", auth, |stream, peer, auth| async move {
        if let Err(e) = handle_http_proxy_conn(stream, auth).await {
            debug!(%peer, error = %e, "http_proxy: {peer} error: {e}");
        }
    })
    .await
}

#[derive(Clone)]
pub struct HttpProxyAuth {
    user: Option<String>,
    password: Option<String>,
}

/// Result of the http_proxy basic-auth check.
///
/// Go frp http_proxy.go `Auth()` semantics: a header that fails to parse
/// into a user:pass pair rejects instantly; only a decoded pair that fails
/// the constant-time compare triggers the 200 ms anti-brute-force delay (the
/// sleep sits inside `Auth()` at the compare, below the shape failures).
pub enum AuthVerdict {
    Accept,
    RejectInstant,
    RejectDelayed,
}

impl HttpProxyAuth {
    pub fn from_config(cfg: &PluginConfig) -> Self {
        let user = if cfg.http_user.is_empty() {
            None
        } else {
            Some(cfg.http_user.clone())
        };
        let password = if cfg.http_password.is_empty() {
            None
        } else {
            Some(cfg.http_password.clone())
        };
        Self { user, password }
    }

    /// static_file (Go `NewHTTPAuthMiddleware` → net/http `r.BasicAuth()`):
    /// case-insensitive `Basic ` prefix gate (Go Issue 22736 does
    /// ascii.EqualFold on the prefix), then decode + compare. The middleware
    /// sleeps on EVERY reject when credentials are configured, so this bool
    /// shape (used by static_file.rs, which owns its delay) is enough.
    pub fn check(&self, header: &str) -> bool {
        match (self.user.as_deref(), self.password.as_deref()) {
            // No auth configured — accept all connections
            (None, None) => true,
            // Both configured — require both to match
            (Some(expected_user), Some(expected_pass)) => {
                let b = header.as_bytes();
                if b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"basic ") {
                    if let Ok(decoded) = base64_decode(&header[6..]) {
                        if let Some((user, pass)) = decoded.split_once(':') {
                            // Constant-time comparison (parity with
                            // control/admin/SSH auth): the short-circuit `==`
                            // above leaks whether the username matched via
                            // timing. Both comparisons must run — bitwise `&`
                            // (not `&&`) so a mismatched username cannot skip
                            // the password comparison.
                            let user_ok = frp_core::auth::constant_time_eq_str(user, expected_user);
                            let pass_ok = frp_core::auth::constant_time_eq_str(pass, expected_pass);
                            return user_ok & pass_ok;
                        }
                    }
                }
                false
            }
            // Partially configured (only user or only password) — reject all.
            // This is a config error; logging happens once at config load.
            (Some(_), None) | (None, Some(_)) => false,
        }
    }

    /// http_proxy plugin (`http_proxy.go` `Auth()`): Go splits the header on
    /// the FIRST space and decodes the payload WITHOUT checking the scheme
    /// token — `SplitN(header, " ", 2)` never compares `s[0]` against
    /// "Basic". Shape failures (no space, undecodable payload, no `:` in the
    /// pair) return `RejectInstant`; a compare failure returns
    /// `RejectDelayed` (Go sleeps 200 ms exactly there).
    pub fn classify_proxy_auth(&self, header: &str) -> AuthVerdict {
        match (self.user.as_deref(), self.password.as_deref()) {
            (None, None) => AuthVerdict::Accept,
            (Some(expected_user), Some(expected_pass)) => {
                let Some((_scheme, payload)) = header.split_once(' ') else {
                    return AuthVerdict::RejectInstant;
                };
                let Ok(decoded) = base64_decode(payload) else {
                    return AuthVerdict::RejectInstant;
                };
                let Some((user, pass)) = decoded.split_once(':') else {
                    return AuthVerdict::RejectInstant;
                };
                let user_ok = frp_core::auth::constant_time_eq_str(user, expected_user);
                let pass_ok = frp_core::auth::constant_time_eq_str(pass, expected_pass);
                if user_ok & pass_ok {
                    AuthVerdict::Accept
                } else {
                    AuthVerdict::RejectDelayed
                }
            }
            // Partially configured — config error at load; reject instantly.
            (Some(_), None) | (None, Some(_)) => AuthVerdict::RejectInstant,
        }
    }
}

/// Go conn.serve statusError render for the version gate (server.go —
/// http1ServerSupportsRequest, "unsupported protocol version"; wire shape
/// probe-verified against go1.25): a DETAILED errorHeaders render ("HTTP/
/// 1.1 %d %s: %s" + headers + the reason echoed in the body), unlike the
/// no-detail GO_400_RENDER/GO_431_RENDER from the default arm.
pub(super) const GO_505_RENDER: &str =
    "HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Connection: close\r\n\
    \r\n\
    505 HTTP Version Not Supported: unsupported protocol version";

/// Go conn.serve render for the `*unsupportedTEError` arm (server.go
/// conn.serve error switch: `"HTTP/1.1 %d %s" + errorHeaders +
/// "Unsupported transfer encoding"` — the value is deliberately NOT
/// echoed, mitigating reflected-XSS; wire shape probe-verified against
/// go1.25). Distinct from the 400/431/505 family: a fixed phrase body,
/// no detail line, no trailing newline. Fired only by the
/// Transfer-Encoding gate, which now runs on EVERY terminated head —
/// parseable major-1 shapes included (audit round-16 review finding E) —
/// mirroring Go's readRequest order; see [`GoConnHeadClass`].
const GO_501_TE_RENDER: &str = "HTTP/1.1 501 Not Implemented\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Connection: close\r\n\
    \r\n\
    Unsupported transfer encoding";

/// Go `ParseHTTPVersion` (net/http/request.go) shape parse: `HTTP/1.0`
/// and `HTTP/1.1` short-circuit; every other version parses only when it
/// is exactly 8 chars `HTTP/X.Y` with single ASCII digits. Returns
/// (major, minor). (Not the mod.rs `go_parse_http_version_ok`: that one
/// accepts only major 1 — this parse must classify every major to find
/// the 505 class and drive the protoAtLeast(1,1) Transfer-Encoding gate.)
pub(super) fn parseable_version(version: &str) -> Option<(u8, u8)> {
    match version {
        "HTTP/1.0" => Some((1, 0)),
        "HTTP/1.1" => Some((1, 1)),
        _ => {
            let b = version.as_bytes();
            (b.len() == 8
                && b.starts_with(b"HTTP/")
                && b[5].is_ascii_digit()
                && b[6] == b'.'
                && b[7].is_ascii_digit())
            .then(|| (b[5] - b'0', b[7] - b'0'))
        }
    }
}

/// Audit round-16 review findings E/A/B (+ the C classifier gates): the
/// full Go `conn.readRequest` error-class model over a TERMINATED head —
/// now covering EVERY terminated head, not only the 505-shaped request
/// lines the round-16 classifier saw. The plain arm's face is Go's
/// http.Server conn: readRequest parses the whole head (request line,
/// then ReadMIMEHeader, dup-Host, readTransfer) BEFORE
/// http1ServerSupportsRequest runs, and a head that PARSES with major 1
/// is served — so a parseable 1.1-shaped head carrying an unsupported or
/// repeated Transfer-Encoding reached the forward path where Go renders
/// its fixed 501 (finding E), and the TE/CL gates only ever saw
/// 505-shaped lines. In Go's error-precedence order:
///  1. request line — parseRequestLine (3 literal-space parts, every part
///     non-empty), the validMethod tchar gate, and ParseHTTPVersion's
///     lenient 8-char shape (exact-switch HTTP/1.0/1.1 short-circuit,
///     else `HTTP/X.Y` with single digits — majors 0 and 2..9 included:
///     they may 505 later, an unparseable token 400s now);
///  2. url.ParseRequestURI over the target — a CTL byte (0x00-0x1F, 0x7F)
///     ANYWHERE in the target (query included) errors, and an invalid
///     %-escape in the pre-'?' region (the query is cut RAW at the FIRST
///     '?') errors — the same mode-aware gate the mod.rs
///     [`parse_request_line`](super::parse_request_line) applies
///     (CONNECT authority included), running before any version gate →
///     400 (finding A);
///  3. ReadMIMEHeader — the four structural shapes below → 400;
///  4. more than one Host group under the canonical-key merge ("Host" +
///     "host" fold into one map key) → "too many Host headers" 400;
///  5. parseTransferEncoding — a Transfer-Encoding group list that is not
///     exactly ONE header whose stored value EqualFolds "chunked" →
///     `*unsupportedTEError` → Go's fixed 501 render (transfer.go: "too
///     many transfer encodings" / "unsupported transfer encoding", value
///     never echoed). protoAtLeast(1,1) gate: HTTP/1.0 and HTTP/0.9
///     IGNORE their Transfer-Encoding entirely (Issue 12785 — the
///     header is dropped, no error, at any line shape);
///  6. fixLength — multiple Content-Length groups are legal only when
///     every value is TrimString-identical (Issue 16490 dedupe), then
///     parseContentLength: the TrimString'd value must be a non-empty
///     unsigned decimal integer < 2^63 (ParseUint 10/63 — leading zeros
///     legal, "5 " parses, ""/"abc"/≥2^63 error; the round-16 length-19
///     heuristic rejected 19+-digit values Go accepts) → 400 (finding
///     B). The RFC 9112 chunked-discard arm sits at the END of
///     fixLength, after both CL checks;
///  7. the version gate (http1ServerSupportsRequest, server.go:1113-1121)
///     — a head that cleared everything with parseable major 1 is SERVED
///     (the caller forwards); any other major fires the detailed 505
///     except the exact 3-token "PRI * HTTP/2.0" upgrade shape (the PRI
///     predicate is Method/RequestURI/Proto, unconditional — no h2c
///     feature gate), which Go's conn serves as h2c prior knowledge:
///     the exempted head still faces the conn gates below, and when they
///     pass it is SERVED to the handler. Round-16's "maps to the
///     no-detail 400 arm" was wrong — probe vs go1.25: a zero-header
///     "PRI * HTTP/2.0" reaches the handler, whose RoundTrip 500s on
///     the scheme (the caller's scheme-500 arm renders that 500; a PRI
///     carrying any header loses the isH2Upgrade exemption and answers
///     the detailed missing-Host 400 — no Host group);
///  8. the conn gates (server.go c.readRequest, AFTER the version gate
///     — server.go:1054-1071, round-17 audit finding F1): "missing
///     required Host header" (ProtoAtLeast(1,1) && zero Host groups &&
///     !isH2Upgrade && method != "CONNECT" — isH2Upgrade = PRI + empty
///     header map + "*" + HTTP/2.0, request.go:529-532); "malformed
///     Host header" (exactly one Host group whose merged stored value
///     fails Go's ValidHostHeader byte table — an empty value passes,
///     probe: "Host: " and "Host:  " are served); "invalid header
///     name" (a map key holding SPACE — issue 34540: SPACE names skip
///     canonicalization and survive ReadMIMEHeader, every other bad
///     name byte died at read time in shape (c)); "invalid header
///     value" — UNREACHABLE in go1.25: textproto's validHeaderValueByte
///     rejects CTL/DEL values at read time, so shape (d) already
///     answered the no-detail 400 — the detailed-400 row the audit
///     prompt listed for the value gate is not on the wire (probe:
///     "X-A: ok\x01bad" → the 103-byte generic 400). The three
///     reachable gates render the DETAILED 400 statusError shape
///     (163/149/145 bytes — see GO_400_MISSING_HOST_RENDER &
///     friends in mod.rs). CONNECT-method heads pass all three gates
///     (the missing gate's method exemption; malformed/name only
///     examine Host groups and names, which CONNECT heads carry like
///     any other) — on the plain face a CONNECT head is served to the
///     handler, which 500s on the scheme.
///
/// The header walker shapes (in Go's error-precedence order):
///  (a) the FIRST header line opens with SP/HTAB — textproto's "malformed
///      MIME header initial line" → 400;
///  (b) any group-first header line without a colon — "malformed MIME
///      header: missing colon" → 400. obs-fold continuation lines
///      (SP/HTAB leading) are EXEMPT — they merge into the previous
///      header's value. A blank group-first line is the head's
///      terminating blank line (reader.go:543-545): a head with zero
///      header lines is legal;
///  (c) a header NAME byte that is neither tchar nor SPACE, or an empty
///      name (": x") → 400 — canonicalMIMEHeaderKey accepts SPACE in a
///      name without canonicalizing (go.dev/issue/34540);
///  (d) CTL (< 0x20 except HTAB) or DEL (0x7f) in any header VALUE, over
///      the obs-fold-MERGED line → 400. Each physical line is trimmed of
///      SP/HTAB ONLY at both ends before the merge (reader.go trim;
///      bufio elides just the \r\n/\n terminator) — an EDGE CTL byte
///      (the second `\r` of a `\r\r\n`-terminated line, a trailing
///      \x0b/\x0c, a fold-opening `\r`) survives into the scan like Go.
///      The records below carry the Go-merged stored value:
///      readContinuedLineSlice `trim`s EVERY physical line (both ends),
///      skipSpace consumes a fold's leading whitespace wholesale, and
///      the fold is re-joined with exactly ONE space — a stored value
///      never ends in OWS ("Transfer-Encoding: chunked " stores
///      "chunked").
///
/// Render mapping (Go conn.serve error switch): readRequest classes
/// (1-4, 6) → the no-detail GO_400_RENDER; 5 → GO_501_TE_RENDER; a head
/// that clears every gate with major != 1 (non-PRI) → GO_505_RENDER; the
/// conn gates (8) → the detailed GO_400_MISSING_HOST_RENDER /
/// GO_400_MALFORMED_HOST_RENDER / GO_400_INVALID_HEADER_NAME_RENDER.
///
/// Face split (round-17 audit finding F2): the CONNECT arm
/// (http_proxy.go sniff; package http.ReadRequest, which has NO
/// conn.serve) renders nothing for any rejection class AND skips the
/// version gate and the conn gates — a parseable HTTP/2.0 or HTTP/1.9
/// CONNECT head is SERVED (the caller dials; probe: both answer the
/// 47-byte dial-400) while an unparseable version token still closes
/// silently. `connect_face` selects the face; the plain face runs the
/// full gate ladder.
///
/// Per-line EOL: `str::lines()` keeps the trailing `\r` of a CRLF line,
/// so ONE trailing `\r` is stripped per physical line before every check
/// (Go textproto ReadLine strips it; the lossy-converted head's obs-text
/// — U+FFFD = EF BF BD — rejects an obs-text name byte exactly like Go,
/// the same non-tchar argument as the tcpmux walker).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum GoConnHeadClass<'a> {
    /// The head cleared every readRequest gate AND, on the plain face,
    /// the version gate and the conn gates — Go's conn serves it. The
    /// caller forwards with the parsed (method, target, version). The
    /// PRI * HTTP/2.0 upgrade shape reaches this variant through the
    /// version gate's exemption when its conn gates pass (round-17 F3:
    /// the caller's forward side then 500s on the unforwardable
    /// scheme, mirroring Go's handler). On the CONNECT face every
    /// readRequest-clean head lands here, any version.
    Serve(&'a str, &'a str, &'a str),
    /// A badStringError-class head error (request-line shapes, URL
    /// escape/CTL, ReadMIMEHeader shapes, dup Host, Content-Length) →
    /// the no-detail 400.
    BadRequest400,
    /// An `*unsupportedTEError` → the fixed 501 render.
    TeUnsupported501,
    /// The whole head parsed; only http1ServerSupportsRequest fires →
    /// the detailed 505.
    Version505,
    /// Conn gate: no Host group on a >= HTTP/1.1 non-CONNECT non-upgrade
    /// request → the detailed "missing required Host header" 400.
    MissingHost400,
    /// Conn gate: one Host group whose stored value fails ValidHostHeader
    /// → the detailed "malformed Host header" 400.
    MalformedHost400,
    /// Conn gate: a header name containing SPACE (issue 34540) → the
    /// detailed "invalid header name" 400.
    InvalidHeaderName400,
}

/// Classify a terminated, non-too-large head with the full Go readRequest
/// error-class model (see the type doc). Every terminated head is
/// classified — parse success and failure alike. `connect_face` selects
/// the http_proxy CONNECT arm semantics (see the type doc's face split).
fn go_conn_head_class(head: &str, connect_face: bool) -> GoConnHeadClass<'_> {
    let mut lines = head.lines();
    let Some(request_line) = lines.next() else {
        return GoConnHeadClass::BadRequest400;
    };
    let mut parts = request_line.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return GoConnHeadClass::BadRequest400;
    };
    if target.is_empty() || !super::go_valid_method_ok(method) {
        return GoConnHeadClass::BadRequest400;
    }
    // The classification runs on the raw head bytes (`lines()` keeps the
    // trailing `\r` of a CRLF line) — Go's textproto strips ONE trailing
    // `\r` before ParseHTTPVersion sees the token, so strip it here too.
    // Any other trailing character (a stray space, extra token) must keep
    // failing the 8-char shape the way Go's version-token length check does.
    let version = version.strip_suffix('\r').unwrap_or(version);
    let Some((v_maj, v_min)) = parseable_version(version) else {
        return GoConnHeadClass::BadRequest400;
    };
    // Finding A: url.ParseRequestURI runs before the version gate at
    // every line shape. The shared mod.rs gate now rejects CTL bytes
    // anywhere in the whole target too (finding A's second half) — the
    // query is included, exactly like Go's whole-string CTL pass.
    if super::request_target_has_invalid_escape(method, target) {
        return GoConnHeadClass::BadRequest400;
    }
    // http1ServerSupportsRequest's PRI predicate (checked at the version
    // gate below — the upgrade shape still faces the full readRequest
    // validation first, so a PRI head carrying garbage Transfer-Encoding
    // 501s like any other).
    let pri_exempt = method == "PRI" && target == "*" && version == "HTTP/2.0";
    // parseTransferEncoding's protoAtLeast(1, 1) gate: HTTP/1.0 and
    // HTTP/0.9 skip the TE check entirely (the header is dropped, Issue
    // 12785); HTTP/1.1+ and every 2.x..9.x major run it. fixLength's CL
    // checks run at every version.
    let te_checked = v_maj > 1 || (v_maj == 1 && v_min >= 1);
    let mut host_groups = 0usize;
    // Every header record — the conn gate's `len(req.Header) == 0` proxy
    // (Go merges duplicate canonical keys into one map entry, so any
    // record implies a non-empty Header map).
    let mut header_groups = 0usize;
    // A name byte of SPACE — the only bad-name shape that survives the
    // textproto read (shape (c) allows SPACE through) to the conn gate.
    let mut name_has_space = false;
    // The textproto-stored value of the single Host group (OWS-free:
    // both ends trimmed per physical line, folds joined single-space —
    // see the walker doc). Only meaningful when `host_groups == 1`.
    let mut host_value: Option<String> = None;
    let mut te_values: Vec<String> = Vec::new();
    let mut cl_values: Vec<String> = Vec::new();

    let mut lines = lines.peekable();
    let mut first_header = true;
    while let Some(group_first_raw) = lines.next() {
        let group_first = group_first_raw
            .strip_suffix('\r')
            .unwrap_or(group_first_raw);
        if group_first.is_empty() {
            // The head's terminating blank line: the header block ends
            // here, legal — classify the records below.
            break;
        }
        if first_header {
            first_header = false;
            // Shape (a): the first header line must not open with SP/HTAB.
            if group_first.starts_with(' ') || group_first.starts_with('\t') {
                return GoConnHeadClass::BadRequest400;
            }
        }
        // Shape (b): group-first lines must carry a colon
        // (mustHaveFieldNameColon — the fold-merge validation runs on
        // the FIRST physical line of the group only; folds are consumed
        // below).
        let Some(colon) = group_first.find(':') else {
            return GoConnHeadClass::BadRequest400;
        };
        let name = &group_first[..colon];
        let value = &group_first[colon + 1..];
        // Shape (c): name bytes — empty or non-(tchar|SP) → error.
        if name.is_empty() || name.bytes().any(|b| !is_token_byte(b) && b != b' ') {
            return GoConnHeadClass::BadRequest400;
        }
        // Shape (d): CTL/DEL in the merged value (first line + folds; Go
        // checks the obs-fold-MERGED line). SP/HTAB trimmed ONLY at the
        // ends (see the walker doc — an edge CTL survives into the scan
        // like Go).
        let mut value_has_ctl = value
            .trim_end_matches([' ', '\t'])
            .bytes()
            .any(is_bad_value_byte);
        let value_trimmed = value.trim_end_matches([' ', '\t']);
        let mut merged: Option<String> = None;
        while let Some(fold_raw) = lines.next_if(|l| l.starts_with(' ') || l.starts_with('\t')) {
            let fold = fold_raw.strip_suffix('\r').unwrap_or(fold_raw);
            if fold
                .trim_matches([' ', '\t'])
                .bytes()
                .any(is_bad_value_byte)
            {
                value_has_ctl = true;
            }
            let merged = merged.get_or_insert_with(|| String::from(value_trimmed));
            merged.push(' ');
            merged.push_str(fold.trim_matches([' ', '\t']));
        }
        if value_has_ctl {
            return GoConnHeadClass::BadRequest400;
        }
        // Canonical-key records: Go's dup-Host/TE/CL checks read the
        // ReadMIMEHeader map, whose keys canonicalize (lowercase, first
        // letter upper-cased — case-insensitive equality here is the
        // same merge). Names containing SPACE skip canonicalization
        // (noCanon) and can never equal these keys.
        let record_value = merged.as_deref().unwrap_or(value_trimmed);
        header_groups += 1;
        if name.bytes().any(|b| b == b' ') {
            // Conn gate "invalid header name" (issue 34540): SPACE in a
            // name skips canonicalization (noCanon) and survives the
            // textproto read; the detailed 400 fires at the conn, after
            // the version gate and the missing/malformed-Host gates
            // (server.go order). Every other bad name byte already
            // errored the read in shape (c) above.
            name_has_space = true;
        }
        if name.eq_ignore_ascii_case("host") {
            host_groups += 1;
            if host_value.is_none() {
                // Go's stored Host map value is TrimLeft'd once after the
                // colon cut (the per-line end trim already killed the
                // trailing OWS), so the first Host record's value is the
                // gate's `hosts[0]`.
                host_value = Some(record_value.trim_start_matches([' ', '\t']).to_string());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // Leading OWS only (Go stores TrimLeft of the value part; a
            // TRAILING space never survives — textproto trim() strips it
            // per physical line before the merge, so "chunked " reaches
            // EqualFold as "chunked").
            te_values.push(record_value.trim_start_matches([' ', '\t']).to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            cl_values.push(record_value.trim_start_matches([' ', '\t']).to_string());
        }
    }

    // Post-walk classification in Go's readRequest order.
    if host_groups > 1 {
        // request.go: "too many Host headers" — fires before the TE/CL
        // checks, at every protocol version.
        return GoConnHeadClass::BadRequest400;
    }
    // parseTransferEncoding errors before fixLength ever runs; a legal
    // single "chunked" falls through to the CL block below — fixLength's
    // RFC 9112 override arm sits at the END of the function
    // (parseContentLength and the dup-CL check run FIRST, so CL headers
    // are still fully validated under chunked; the arm only discards a
    // VALID Content-Length).
    if te_checked
        && !te_values.is_empty()
        && (te_values.len() != 1 || !te_values[0].eq_ignore_ascii_case("chunked"))
    {
        return GoConnHeadClass::TeUnsupported501;
    }
    if !cl_values.is_empty() {
        // Finding B: fixLength — multiple CL values must be
        // TrimString-identical (deduped per Issue 16490);
        // parseContentLength then parses the TrimString'd value with Go
        // ParseUint 10/63 semantics: non-empty, all ASCII digits, value
        // < 2^63 — leading zeros are legal and any 19+-digit value below
        // the bound parses (the round-16 length-19 heuristic wrongly
        // rejected e.g. "000…005"), while ""/"abc"/"5x"/≥2^63 error.
        let first = cl_values[0].trim_matches([' ', '\t']);
        let dupes_identical = cl_values[1..]
            .iter()
            .all(|v| first == v.trim_matches([' ', '\t']));
        let parses = !first.is_empty()
            && first.bytes().all(|b| b.is_ascii_digit())
            && first.parse::<u64>().is_ok_and(|n| n < (1u64 << 63));
        if !dupes_identical || !parses {
            return GoConnHeadClass::BadRequest400;
        }
    }
    // The version gate (http1ServerSupportsRequest, server.go:1113-1121):
    // parseable HTTP/1.x passes; every other parseable version renders the
    // detailed 505 — EXCEPT the h2c-preface shape (ProtoMajor 2 +
    // ProtoMinor 0 + method PRI + RequestURI "*", the `pri_exempt`
    // predicate above), which passes the gate and reaches the conn gates
    // below. The CONNECT face has NO version gate and NO conn gates (its
    // caller is frp's own dial after package http.ReadRequest — probe:
    // CONNECT HTTP/2.0 and HTTP/1.9 heads are served and answer the
    // 47-byte dial 400, while the unparseable HTTP/1.10 token still closes
    // silently), so a readRequest-clean head of any parseable version is
    // served there.
    if !connect_face && !pri_exempt && v_maj != 1 {
        return GoConnHeadClass::Version505;
    }
    if !connect_face {
        // Conn gates (conn.readRequest's c.readRequest wrapper,
        // server.go:1049-1071 — after the 505 gate, in Go's order):
        //   - missing-Host: `ProtoAtLeast(1, 1) && !haveHost &&
        //     !isH2Upgrade && Method != "CONNECT"` — the malformed and
        //     name gates below carry NO proto or method exemption
        //     (HTTP/1.0 with a malformed Host 400s);
        //   - malformed-Host: `len(hosts) == 1 &&
        //     !ValidHostHeader(hosts[0])` — an empty stored value passes
        //     (probe: "Host: " and "Host:  " served);
        //   - invalid-name: SPACE in a map key (`name_has_space`) — every
        //     other bad name byte already errored the textproto read;
        //   - invalid-value: UNREACHABLE in go1.25 — textproto's
        //     validHeaderValueByte rejects CTL/DEL values at read time
        //     (shape (d) answered the no-detail 400), so no stored value
        //     ever fails ValidHeaderFieldValue here (probe: "X-A:
        //     ok\x01bad" → the 103-byte generic 400).
        // `isH2Upgrade` = the h2c-preface predicate AND a zero-header map
        // (request.go:529-531), exempting the bare PRI * HTTP/2.0 head
        // from the missing-Host gate.
        let is_h2_upgrade = pri_exempt && header_groups == 0;
        if v_maj == 1 && v_min >= 1 && host_groups == 0 && !is_h2_upgrade && method != "CONNECT" {
            return GoConnHeadClass::MissingHost400;
        }
        if host_groups == 1 && !valid_host_header(host_value.as_deref().unwrap_or("")) {
            return GoConnHeadClass::MalformedHost400;
        }
        if name_has_space {
            return GoConnHeadClass::InvalidHeaderName400;
        }
    }
    GoConnHeadClass::Serve(method, target, version)
}

/// Go `httpguts.ValidHostHeader` (httplex.go): the whole stored Host
/// value must consist of `validHostByte` bytes — alphanumerics plus the
/// sub-delims/unreserved set `! $ % & ' ( ) * + , - . : ; = [ ] _ ~` and
/// nothing else (`< > "` are shouldEscape-exempt in the URL but NOT
/// host-legal); an EMPTY value passes (the loop never runs). Shared with
/// the mod.rs http2http-family legs (round-17 audit F7 conn gates).
pub(super) fn valid_host_header(v: &str) -> bool {
    v.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
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
                    | b']'
                    | b'_'
                    | b'~'
            )
    })
}

/// RFC 7230 tchar (ALPHA / DIGIT / "!#$%&'*+-.^_`|~") — Go textproto
/// `validHeaderFieldByte` / httpguts `ValidHeaderFieldName` byte set (the
/// frp-server tcpmux.rs `is_token_byte` twin; the method gate in mod.rs
/// inlines the same set).
fn is_token_byte(b: u8) -> bool {
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
fn is_bad_value_byte(b: u8) -> bool {
    (b < b' ' && b != b'\t') || b == 0x7f
}

/// Go conn.readRequest `setReadLimit(initialReadLimitSize)` value
/// (server.go): MaxHeaderBytes default (1 MiB) + the 4096-byte bufio slop.
/// Go errors errTooLarge exactly when the limit is CONSUMED with the head
/// still incomplete — the served/431 boundary in frp-rs is byte-aligned
/// with Go's because the head-read loop clamps its reads to this limit
/// (round-17 audit F9: the old loop read in unclamped 4 KiB chunks and
/// served terminated heads up to ~1 MiB + 8192, up to 4096 bytes past
/// Go's boundary).
const HEAD_READ_LIMIT: usize = 1024 * 1024 + 4096;

async fn handle_http_proxy_conn(mut client: TcpStream, auth: HttpProxyAuth) -> Result<(), String> {
    // Read the request head in chunks. Head end follows Go textproto
    // semantics (the engine behind http.ReadRequest): each line ends at the
    // next '\n' with ONE trailing '\r' stripped, and the first empty line
    // ends the head — so LF-only and mixed-EOL heads are legal, not just
    // \r\n\r\n. Stop at the first empty line anywhere in the buffer (not
    // only at its end): with a request body the head terminator is followed
    // by body bytes, and reading past it would swallow the body into the
    // "headers" until the cap.
    // Go parity: http.Server ReadHeaderTimeout (60s) — one absolute deadline
    // over the whole header read, so a slowloris "trickle" cannot park the
    // task + fd + plugin listener slot indefinitely (audit round-8 F8; the
    // shared const PLUGIN_HEADER_READ_TIMEOUT has the same absolute-window
    // semantics).
    // The 1 MiB cap below is Go's http.Server MaxHeaderBytes DEFAULT on the
    // PLAIN arm (audit: the old 64 KiB cap rejected request heads Go serves
    // — 100+ KiB Cookie or Authorization headers are legal HTTP). Go
    // enforces it as a READ LIMIT, not a size gate: conn.readRequest sets
    // c.r.setReadLimit(initialReadLimitSize) = maxHeaderBytes + 4096 bufio
    // slop (server.go), and the parser only errors when the limit is
    // consumed with the head still INCOMPLETE — a head whose empty-line
    // terminator arrived within the limit parses and serves (probed: a
    // terminated ~1 MiB+64 head answers 200; only a terminator beyond the
    // limit — or no terminator at all — trips the 431). The loop below
    // mirrors that: the terminator scan runs BEFORE the cap check, so a
    // completed head serves no matter how large the buffer grew. The reads
    // are CLAMPED to the remaining limit (F9): the buffer never overshoots
    // HEAD_READ_LIMIT, so the served/431 boundary is byte-exact with Go —
    // a head whose terminator ends at byte 1,049,600 exactly serves, one
    // byte more errors (Go: consumed-past-limit mid-head).
    // On the CONNECT arm the cap stays a fail-closed Rust-only divergence:
    // frp http_proxy.go sniffs the method prefix and then calls
    // http.ReadRequest directly, which has NO size cap (bounded only by the
    // ReadHeaderTimeout window). The sniff runs after this read loop, so
    // the cap cannot know the arm yet — a breach is not a read error: the
    // buffer is carried back so the arm classification below can answer 431
    // on the plain arm the way Go's server would (it errors the read itself
    // and writes the render BEFORE the handler — http_proxy.go's plain arm
    // never sees the giant head at all), while the CONNECT arm closes
    // silently (see the arm notes below).
    enum HeadRead {
        /// Head ended at the first empty line (Go textproto semantics).
        Done(Vec<u8>),
        /// HEAD_READ_LIMIT consumed with NO empty line in the buffer (Go's
        /// readLimit model: the limit ran out mid-head — errTooLarge). A
        /// completed head is never "too large"; only a head whose
        /// terminator ends past byte 1,049,600 breaches (F9: byte-exact
        /// with Go's served/431 boundary).
        TooLarge(Vec<u8>),
        /// EOF mid-head: the client closed before any empty line. Not a
        /// hard read error — the partial head is carried back so the arm
        /// classification below can mirror Go: http.Server answers 400
        /// once ANY request bytes arrived (the server errors the read and
        /// renders), while a zero-byte close, the <7-byte probe failure,
        /// and the CONNECT arm all close silently.
        Eof(Vec<u8>),
    }
    // The match arms pin the closure's error type to String (the `Err(e) =>
    // return Err(e)` arm unifies with this fn's `Result<(), String>`), so
    // the inner `?`s on the read error resolve without annotation.
    let head = match tokio::time::timeout(super::PLUGIN_HEADER_READ_TIMEOUT, async {
        let mut buf = Vec::new();
        // 4 KiB chunks: the cap check runs after the terminator scan, so
        // a head completed in time always serves; the reads clamp to the
        // remaining HEAD_READ_LIMIT so the buffer NEVER overshoots it —
        // the served/431 boundary is byte-exact with Go's
        // MaxHeaderBytes + 4096 (F9), not "within one chunk" of it.
        let mut chunk = [0u8; 4096];
        // Round-17 audit D: the carried scanner replaces the per-chunk
        // full-buffer `head_end` rescan (O(n²) over the chunks of one
        // head) with a resume-from-line-start scan; byte-identical
        // results for this feed-until-terminator loop.
        let mut scanner = frp_core::textproto::HeadEndScanner::new();
        loop {
            // Terminator scan FIRST: Go's read limit only errors when the
            // limit is consumed with the head still incomplete — a head
            // whose empty line is already in the buffer was completed in
            // time and parses (probed: terminated ~1 MiB+64 is served).
            // Only a limit-consumed head with NO terminator is a breach
            // (431 on the plain arm — Go errTooLarge renders before the
            // handler runs).
            if scanner.feed(&buf).is_some() {
                return Ok(HeadRead::Done(buf));
            }
            if buf.len() >= HEAD_READ_LIMIT {
                return Ok(HeadRead::TooLarge(buf));
            }
            let want = (HEAD_READ_LIMIT - buf.len()).min(chunk.len());
            let n = client
                .read(&mut chunk[..want])
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Ok(HeadRead::Eof(buf));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    {
        Ok(Ok(head)) => head,
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => return Err("read headers timed out".to_string()),
    };
    let (buf, head_too_large, head_eof) = match head {
        HeadRead::Done(buf) => (buf, false, false),
        HeadRead::TooLarge(buf) => (buf, true, false),
        HeadRead::Eof(buf) => (buf, false, true),
    };

    // Arm classification: Go frp http_proxy.go reads the FIRST 7 stream
    // bytes (io.ReadFull) and EqualFolds them against "CONNECT" BEFORE any
    // head parsing — the sniff, not the parse outcome, picks the failure
    // behavior of everything downstream:
    //   - CONNECT arm (sniff true): http.ReadRequest errors close silently
    //     — the handler has no response writer for a head it never parsed.
    //     Go-parity for EOF / deadline / malformed heads. For the 1 MiB cap
    //     this arm is NOT Go parity (Go's ReadRequest is uncapped): the
    //     silent close on a too-large CONNECT head is deliberate fail-closed
    //     hardening on this operator-local 127.0.0.1 listener surface — Go
    //     would read on until the 60s window or a body-less head end.
    //   - Plain arm (sniff false): the head goes through PutConn into the
    //     http.Server, which renders its own error (400 malformed request,
    //     431 header block over the cap) before ServeHTTP ever runs.
    //   - EOF mid-head after partial bytes (plain arm, >= 7 bytes): the
    //     server already has bytes — it errors the read and renders 400
    //     errorHeaders (Go http.Server: only a clean EOF with ZERO bytes
    //     received is a silent close).
    //   - Fewer than 7 bytes at the head read: ReadFull fails (EOF or the
    //     60s deadline) → silent close, both arms.
    let is_connect = super::head_starts_connect(&buf);
    let head_short = buf.len() < 7;

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line: METHOD URL HTTP/1.x. Strict Go parseRequestLine
    // semantics via the shared helper (literal-space splitn(3), every part
    // non-empty, the method token gated by Go's validMethod (a non-tchar
    // "G@T" is a 400 before routing — request.go readRequest), request-side
    // Go ParseHTTPVersion semantics restricted to major 1 — see plugin/
    // mod.rs `parse_request_line`). The major-1 restriction is NOT a
    // network-position claim: it holds only under http/https-typed frps
    // entries, whose vhost front has already 505-gated every request it
    // tunnels. Under tcp/tcpmux/xtcp-typed entries this listener receives
    // RAW client bytes, and its own face is the full http.Server conn
    // machinery (frp http_proxy.go PutConns the plain arm into an
    // http.Server): conn.readRequest's http1ServerSupportsRequest gate
    // (server.go) renders 505 for a fully parsed head whose version token
    // is a parseable non-1.x HTTP/X.Y, while Go serves every parseable 1.x
    // (HTTP/1.2..1.9 included — ProtoMajor 1 passes). The old
    // split_whitespace collapsed every whitespace run, so tab-joined tokens
    // parsed and the request was dialed/forwarded — accept-where-Go-
    // rejects.
    // A failed head renders Go's server error on the plain arm, then
    // closes; silent arms (CONNECT sniff / fewer than 7 bytes, mirroring
    // ReadFull) close without a byte. Three distinct renders, ordered as
    // Go classifies them:
    //   - a TooLarge head renders Go's 431 — the read limit ran out
    //     mid-head, which in Go errors the read before any line is
    //     validated (431 either way, line valid or not — the version gate
    //     is never reached);
    //   - a TERMINATED head whose first line carries a parseable non-1.x
    //     version token renders Go's 505 — Go parses the whole head first
    //     (request line, then ReadMIMEHeader over the header block, then
    //     the dup-Host check, then readTransfer's Transfer-Encoding and
    //     Content-Length checks), and only then does
    //     http1ServerSupportsRequest reject the version. The header block
    //     must PARSE for the 505 to fire: on a 505-shaped line the full
    //     readRequest error set still applies — ReadMIMEHeader structural
    //     errors (missing-colon line, CTL in a value, bad field name),
    //     the dup-Host error and the Content-Length errors answer the
    //     no-detail 400, an unsupported Transfer-Encoding answers Go's
    //     fixed 501 — see [`go_conn_head_class`] (round-17 audit findings
    //     E/A/B: the model now classifies EVERY terminated head — a
    //     parseable 1.x head carrying a garbage or repeated
    //     Transfer-Encoding answers Go's fixed 501, and dup-Host / bad
    //     Content-Length shapes answer the 400, instead of being
    //     forwarded; the round-16 classifier only ever saw 505-shaped
    //     lines);
    //   - every other parse failure (malformed line, method gate, version
    //     shape — Go badStringError, the no-detail default arm) and Eof
    //     heads (INCOMPLETE by construction — Eof is only returned when no
    //     empty line was seen, so even a buffer whose first line parses
    //     cleanly ("GET / HTTP/1.1\r\nHost: ..." then EOF) must never be
    //     forwarded: Go errors the read and renders 400) render Go's 400.
    // Findings E/A/B: classify the WHOLE terminated head — parse success
    // and parse failure alike — with the full Go readRequest model
    // ([`go_conn_head_class`]; the round-16 flow only walked the header
    // block on 505-shaped lines, so a parseable 1.1 head carrying a
    // garbage or repeated Transfer-Encoding was forwarded where Go's
    // conn renders its fixed 501, and dup-Host / bad Content-Length
    // shapes on parseable 1.x heads forwarded where Go 400s).
    let (method, url, version) = if head_too_large || head_eof {
        if !is_connect && !head_short {
            let render = if head_too_large {
                super::GO_431_RENDER
            } else {
                // EOF mid-head (INCOMPLETE by construction — Eof is only
                // returned when no empty line was seen, so even a buffer
                // whose first line parses cleanly then EOFs must never be
                // forwarded: Go errors the read and renders 400).
                super::GO_400_RENDER
            };
            if let Err(e) = client.write_all(render.as_bytes()).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            if head_too_large {
                // Round-17 F9: the head read clamped at HEAD_READ_LIMIT, so
                // the kernel still holds whatever the client sent past the
                // cap (row: a limit + 1 head leaves 1 unread byte). Closing
                // now would make Linux send RST and the just-written 431
                // could be discarded before the client reads it — Go has
                // the identical race (its conn errors and closes without
                // draining). frp-rs drains for a bounded 250 ms instead so
                // the 431 explainer reaches the client behind a clean FIN:
                // a hardened error path, strictly better than racing RST.
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
                let mut scratch = [0u8; 4096];
                loop {
                    match tokio::time::timeout_at(deadline, client.read(&mut scratch)).await {
                        // EOF (client half-closed) or a read error: done.
                        Ok(Ok(0)) | Ok(Err(_)) => break,
                        // Discarded — the request is rejected regardless of
                        // anything the client pipelined past the cap.
                        Ok(Ok(_)) => {}
                        // Deadline: enough draining, close now.
                        Err(_elapsed) => break,
                    }
                }
            }
        }
        return Err("bad request line".into());
    } else {
        match go_conn_head_class(&headers_str, is_connect) {
            GoConnHeadClass::Serve(m, u, v) => (m, u, v),
            class => {
                // Round-17 F2: on the CONNECT face (is_connect) no
                // rejection class renders — package http.ReadRequest
                // errors close silently (probe: dup Host / TE / CL /
                // CTL-value CONNECT heads answer zero bytes). The plain
                // face renders what conn.serve's error switch would.
                if !is_connect && !head_short {
                    let render = match class {
                        GoConnHeadClass::TeUnsupported501 => GO_501_TE_RENDER,
                        GoConnHeadClass::Version505 => GO_505_RENDER,
                        GoConnHeadClass::Serve(..) => unreachable!(),
                        GoConnHeadClass::MissingHost400 => super::GO_400_MISSING_HOST_RENDER,
                        GoConnHeadClass::MalformedHost400 => super::GO_400_MALFORMED_HOST_RENDER,
                        GoConnHeadClass::InvalidHeaderName400 => {
                            super::GO_400_INVALID_HEADER_NAME_RENDER
                        }
                        // badStringError classes (request-line shapes,
                        // URL escape/CTL, ReadMIMEHeader shapes, dup Host,
                        // Content-Length) → the no-detail 400.
                        GoConnHeadClass::BadRequest400 => super::GO_400_RENDER,
                    };
                    if let Err(e) = client.write_all(render.as_bytes()).await {
                        tracing::debug!(error = %e, "plugin relay error: {}", e);
                    }
                }
                return Err("bad request line".into());
            }
        }
    };

    // Parse headers. The request line was classified above and `lines`
    // still leads with it — drop it before the auth scan (a "method
    // target:port" colon can never be a header colon). The scan ends at
    // the head's blank line (round-17 F4: the buffer may carry PIPELINED
    // bytes past the head — tunnel data a client wrote in the same TCP
    // segment as the CONNECT head — and those bytes must never be read as
    // headers; Go reads auth from the parsed head only).
    lines.next();
    let mut proxy_auth = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("proxy-authorization") {
                proxy_auth = value.trim().to_string();
            }
        }
    }

    // Check auth. Response arms verified byte-for-byte against Go v0.71.0
    // (probe): CONNECT failures go through handleConnectReq →
    // getBadResponse — status TEXT "Not authorized" (Go's custom Status
    // field, not the standard reason) + `Connection: close`; plain-request
    // failures go through net/http ServeHTTP — standard status text, no
    // Connection header (Go keeps the conn reusable; frp-rs serves one
    // request per tunnel conn and closes after — response bytes identical).
    // Both arms send `Proxy-Authenticate: Basic` with no realm. Go's `Date`
    // header comes from net/http and is omitted here like every other
    // frp-rs manual response writer.
    match auth.classify_proxy_auth(&proxy_auth) {
        AuthVerdict::Accept => {}
        verdict => {
            if matches!(verdict, AuthVerdict::RejectDelayed) {
                // Go frp http_proxy.go Auth(): 200ms delay only when a
                // decoded user:pass pair fails the compare (shape failures
                // answer instantly — no sleep below the early returns).
                sleep(Duration::from_millis(200)).await;
            }
            let resp: &'static [u8] = if is_connect {
                b"HTTP/1.1 407 Not authorized\r\nConnection: close\r\n\
                  Proxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
            } else {
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
            };
            if let Err(e) = client.write_all(resp).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err("auth failed".into());
        }
    }

    // Case-insensitive CONNECT match: Go frp http_proxy.go uses
    // strings.EqualFold(string(firstBytes), http.MethodConnect) — a
    // lowercase "connect" is accepted.
    if is_connect {
        // Round-17 audit F4: the head read loop stops at the terminator
        // but a read chunk can carry bytes PAST it — tunnel data a client
        // pipelined in the same write as the CONNECT head (the 7-byte
        // sniff + ReadRequest in Go frp consume the same bytes through
        // the SharedConn tee, so Go's relay drains them to the remote
        // first). Splitting the tail here and flushing it inside
        // handle_connect mirrors that: the old path dropped the over-read
        // bytes, losing the client's early tunnel data.
        let head_end = frp_core::textproto::head_end(&buf).unwrap_or(buf.len());
        let connect_tail = buf[head_end.min(buf.len())..].to_vec();
        handle_connect(client, url, &connect_tail).await
    } else {
        handle_http_forward(client, &buf, method, url, version).await
    }
}

/// Round-17 audit C: the CONNECT dial address. Go dials `req.URL.Host`
/// (http_proxy.go handleConnectReq net.Dial("tcp", r.Host)); URL.Host is
/// derived from the authority by url.Parse, so the dial target here
/// mirrors that derivation over the classifier-gated raw target:
///   1. the query is cut RAW at the FIRST '?' before anything else —
///      "CONNECT host:port?x=1" tunnels host:port, the rest is RawQuery
///      (Go url.parse query cut; the escape gate above already ran on
///      the pre-'?' region only);
///   2. userinfo splits off at the LAST literal '@' on the raw bytes
///      (Go parseAuthority LastIndex) and never reaches the dial;
///   3. the host:port region's %-escapes are DECODED (%XX → byte)
///      exactly like Go's encodeHost unescape produces URL.Host — the
///      classifier rejected every ill-formed or forbidden escape
///      (first hex digit < 8, RFC 6874 %25 carve-out included), so
///      decoding cannot re-introduce a delimiter. Non-UTF-8 decode is
///      lossy — such a host fails the dial below like Go's DNS lookup.
///
/// A path-form target (leading '/') returns verbatim: Go dials an empty
/// Host and lands in the caller's 400 arm; dialing the path fails the
/// same way.
fn authority_dial_target(target: &str) -> String {
    let authority = match target.split_once('?') {
        Some((a, _)) => a,
        None => target,
    };
    if authority.starts_with('/') {
        return target.to_string();
    }
    let hostport = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let bytes = hostport.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(h), Some(l)) = (
                bytes.get(i + 1).and_then(|&b| hex_val(b)),
                bytes.get(i + 2).and_then(|&b| hex_val(b)),
            ) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn handle_connect(
    mut client: TcpStream,
    target: &str,
    pipelined: &[u8],
) -> Result<(), String> {
    // Round-17 audit C: dial the authority exactly as Go dials
    // `req.URL.Host` — the classifier gated the raw target's escapes and
    // the helper cuts the query, strips userinfo and decodes the host
    // region per url.Parse (see authority_dial_target).
    let dial_target = authority_dial_target(target);
    let mut remote = match TcpStream::connect(&dial_target).await {
        Ok(s) => s,
        Err(e) => {
            // Go frp http_proxy.go handleConnectReq dial-failure arm: it
            // writes a bare http.Response{StatusCode: 400}.Write — probed
            // against Go frp v0.71.0: byte-exactly "HTTP/1.1 400 Bad
            // Request\r\nContent-Length: 0\r\n\r\n". NO Connection header
            // (Connection: close belongs to the 407 getBadResponse arm
            // only), no body. The round-13-era writer here added a
            // spurious "Connection: close" the Go raw response does not
            // carry.
            // Audit: the ":443" default-append is GONE — Go dials
            // `req.URL.Host` as-is (http_proxy.go handleConnectReq
            // net.Dial("tcp", r.Host)) and a port-less host is a DIAL
            // failure ("missing port in address"), so the request lands in
            // this same 400 arm. Appending :443 made "CONNECT example.com"
            // dial example.com:443 where Go answers 400.
            let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            if let Err(we) = client.write_all(resp).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("connect to {dial_target}: {e}"));
        }
    };
    frp_core::transport::set_nodelay(&remote);

    // Tell client connection established. Phrase parity: Go frp writes
    // "HTTP/1.1 200 OK" on CONNECT success (pkg/plugin/client/http_proxy.go
    // httpProxy.go:188 `resp.Status = "200 OK"`) — not the conventional
    // "200 Connection Established".
    let resp = b"HTTP/1.1 200 OK\r\n\r\n";
    client
        .write_all(resp)
        .await
        .map_err(|e| format!("write: {e}"))?;

    // Round-17 audit F4: flush the head-read over-run (bytes the client
    // pipelined with the CONNECT head) to the remote BEFORE the relay
    // starts reading fresh client bytes — Go's SharedConn tee drains them
    // first, so the remote sees the client's early tunnel data in order.
    if !pipelined.is_empty() {
        if let Err(e) = remote.write_all(pipelined).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
            return Err(format!("write pipelined tail: {e}"));
        }
    }

    // Bidirectional relay through pooled buffers (audit round-8 P1: the
    // copy_bidirectional_with_sizes pair of fresh buffers per conn is gone;
    // relay_plain_pooled has identical FIN-propagation semantics).
    if let Err(e) = frp_core::bridge::relay_plain_pooled(client, remote).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
    Ok(())
}

async fn handle_http_forward(
    mut client: TcpStream,
    raw_headers: &[u8],
    method: &str,
    url: &str,
    version: &str,
) -> Result<(), String> {
    // Parse host:port from URL. Round-17 F3: a Serve-classified head whose
    // target is not absolute-form http:// reaches Go's HTTPHandler
    // (http_proxy.go = DefaultTransport.RoundTrip), which errors on the
    // scheme → http.Error 500 with the scheme text (probe, modeA rows):
    //   - origin-form ("/x"), "GET *", CONNECT-method, PRI * → body
    //     `unsupported protocol scheme ""` (request.go strips the CONNECT
    //     justAuthority "http://" back off; origin-form/* never had one);
    //   - opaque-URI shapes keep their parsed scheme (`"h"` for "h:80",
    //     `"ftp"`, `"mailto"` — url.ParseRequestURI scheme token,
    //     lowercased);
    //   - uppercase-http and https:// absolute forms are NOT scheme
    //     errors in Go (RoundTrip accepts "HTTP://…" and TLS-dials
    //     "https://…") — frp-rs keeps the old silent close for both
    //     (documented divergence: no TLS leg on this face; parse_http_url
    //     is case-sensitive on the prefix).
    let (host, port, path) = match parse_http_url(url) {
        Ok(x) => x,
        Err(_) => {
            let scheme = plain_face_go_scheme(method, url);
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
                // "HTTP://…" / "https://…" absolute forms: Go's RoundTrip
                // would dial them (plaintext resp. TLS) — frp-rs has no
                // TLS leg here and keeps the old silent close (see the
                // arm doc above).
                return Err(format!("unsupported scheme: {url}"));
            }
            // Same render shape as the dial-fail arm below (Go adds a
            // Date header and omits Connection: close except on the
            // Close=true PRI upgrade head; frp-rs omits Date and always
            // writes Connection: close — truthful, one request per tunnel
            // conn — by the established convention of every frp-rs
            // manual response writer).
            let body = format!("unsupported protocol scheme \"{scheme}\"\n");
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(we) = client.write_all(resp.as_bytes()).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("unsupported protocol scheme \"{scheme}\""));
        }
    };

    let mut remote = match TcpStream::connect(format!("{host}:{port}")).await {
        Ok(s) => s,
        Err(e) => {
            // Go frp http_proxy.go HTTPHandler dial-failure arm:
            // http.Error(rw, err.Error(), http.StatusInternalServerError)
            // — probed against Go frp v0.71.0 (backend = refused port):
            // "HTTP/1.1 500 Internal Server Error\r\nContent-Type:
            // text/plain; charset=utf-8\r\nX-Content-Type-Options:
            // nosniff\r\nDate: ...\r\nContent-Length: N\r\nConnection:
            // close\r\n\r\n<dial error text>\n". Go adds Connection: close
            // whenever the connection closes after the response; frp-rs
            // serves exactly one request per tunnel conn and closes after
            // every response, so the header is always truthful and written
            // unconditionally. Date is omitted like every other frp-rs
            // manual response writer; the body is the std dial error
            // Display text + '\n' (Go fmt.Fprintln), with the real
            // Content-Length. The old code closed the conn with ZERO
            // bytes — a refused backend was indistinguishable from a
            // vanished proxy.
            let body = format!("{e}\n");
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(we) = client.write_all(resp.as_bytes()).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("connect to {host}:{port}: {e}"));
        }
    };
    frp_core::transport::set_nodelay(&remote);

    // Split the head from any pre-read body data at the first empty line
    // (Go textproto semantics — the same helper the read loop above used,
    // so the split lands exactly where the loop stopped; for CRLF input the
    // index is byte-identical to the old \r\n\r\n scan).
    let header_end = frp_core::textproto::head_end(raw_headers).unwrap_or(raw_headers.len());
    let header_bytes = &raw_headers[..header_end];
    let body_bytes = &raw_headers[header_end..];

    // Build forwarded request: rewrite request line, strip hop-by-hop and
    // proxy headers (Go removeProxyHeaders: Connection, Proxy-Connection,
    // Keep-Alive, Proxy-Authorization, Proxy-Authenticate, TE, Trailer(s),
    // Transfer-Encoding, Upgrade; Expect is stripped too — the plugin
    // cannot relay the interim 100-continue response, and a strict client
    // that gates its body-send on it would deadlock against the body read,
    // RFC 7231 §5.1.1), add Connection: close.
    let headers_str = String::from_utf8_lossy(header_bytes);
    let hop_by_hop: &[&str] = &[
        "transfer-encoding:",
        "proxy-authorization:",
        "proxy-connection:",
        "proxy-authenticate:",
        "te:",
        "trailer:",
        "upgrade:",
        "connection:",
        "keep-alive:",
        "expect:",
    ];
    let mut header_lines: Vec<&str> = headers_str.lines().skip(1).collect();
    // Body framing is parsed from the original headers — Transfer-Encoding
    // is stripped below as hop-by-hop and re-added only when chunked.
    // Round-17 audit E (version-aware): Go's parseTransferEncoding gates
    // the whole TE read on protoAtLeast(1,1) (transfer.go, Issue 12785) —
    // an HTTP/1.0 request IGNORES its Transfer-Encoding (the header is
    // dropped silently, never chunked-framed). The classifier above
    // already rejected every >=1.1 TE that is not exactly "chunked" with
    // Go's fixed 501, so only an HTTP/1.0 head can carry a TE line this
    // deep — its framing resolves Content-Length alone.
    let framing = if version == "HTTP/1.0" {
        super::resolve_content_length(headers_str.lines().skip(1))
            .ok()
            .flatten()
            .map(super::BodyFraming::Length)
    } else {
        super::parse_request_body_framing(headers_str.lines().skip(1))
    };
    // Content-Length is resolved per RFC 7230 §3.3.2 ("reject or replace
    // with a single value") under Go fixLength/parseContentLength
    // semantics: duplicate identical values collapse to one line, while
    // list-form values ("5, 5"), non-decimal values, and conflicting
    // values make the request framing invalid — reject (the connection
    // closes). Resolution runs UNCONDITIONALLY, chunked requests included:
    // Go probes the CL values even when chunked wins the framing — probed
    // against the Go frp v0.71.0-era stdlib (go1.25.12): chunked + "5, 5",
    // chunked + "5x", and chunked + conflicting values all 400, while a
    // chunked + valid "5" is accepted and the header deleted. The retain
    // gate below drops every Content-Length line on chunked requests and
    // the canonical-line append keys on `framing != Chunked`, so a valid
    // resolution is never forwarded under chunked — matching Go's delete.
    let content_length = super::resolve_content_length(headers_str.lines().skip(1))?;
    header_lines.retain(|line| {
        // Skip the head's trailing blank line(s) too: lines() yields "" for
        // the \r\n\r\n terminator, and forwarding it would terminate the
        // head early, pushing `Connection: close` into the body.
        // Round-17 audit E: zero-alloc ASCII case-insensitive prefix scan
        // (was a per-line lowercase String).
        if line.is_empty()
            || hop_by_hop
                .iter()
                .any(|h| super::starts_with_ignore_ascii_case(line, h))
        {
            return false;
        }
        // Drop every original Content-Length line: when chunked per RFC
        // 7230 §3.3.3, or when a usable Content-Length was resolved — all
        // CL lines are then replaced by a single canonical line appended
        // after the loop (RFC 7230 §3.3.2; forwarding duplicate/conflicting
        // values would desync the backend).
        if super::starts_with_ignore_ascii_case(line, "content-length:")
            && (framing == Some(super::BodyFraming::Chunked) || content_length.is_some())
        {
            return false;
        }
        true
    });

    let fwd = build_forward_head(method, &path, &header_lines, framing, content_length);

    remote
        .write_all(&fwd)
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Stream the request body (pre-read bytes plus the rest per its framing)
    // before relaying the response — Go's http.DefaultTransport streams it,
    // and a backend that waits for the full request would stall otherwise.
    // A body-forward error must NOT drop the connection: backends reply early
    // without reading the full request (e.g. nginx's 413 client_max_body_size),
    // and Go's Transport still delivers those responses.
    if let Err(e) =
        super::forward_request_body(&mut client, &mut remote, body_bytes, framing, method).await
    {
        tracing::debug!(error = %e, "request body forward failed, relaying response anyway: {}", e);
    }

    // Copy response back to client
    if let Err(e) = super::copy_stream_large(remote, &mut client).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
    Ok(())
}

/// Build the outbound request head for the forward path. The request line is
/// HTTP/1.1 — Go's http.DefaultTransport (http_proxy.go HTTPHandler path)
/// never writes HTTP/1.0 requests. The old HTTP/1.0 line silently dropped
/// chunked upload bodies: chunked Transfer-Encoding is HTTP/1.1-only, so an
/// origin that parses the request as 1.0 sees neither Transfer-Encoding nor
/// Content-Length and treats the body as empty. `Connection: close` is kept
/// (Go sends close whenever the connection closes after the response; this
/// plugin serves one request per tunnel conn and closes — the origin then
/// answers without keep-alive framing). Header lines arrive pre-filtered
/// (hop-by-hop stripped, Content-Length lines dropped when chunked or a
/// usable resolution exists); body framing is appended as one canonical line
/// per RFC 7230 §3.3.2/§3.3.3. Extracted from handle_http_forward for a
/// byte-exact unit pin (chunked POST head starts `POST <path> HTTP/1.1`,
/// carries the chunked framing line, ends `Connection: close\r\n\r\n`).
fn build_forward_head(
    method: &str,
    path: &str,
    header_lines: &[&str],
    framing: Option<super::BodyFraming>,
    content_length: Option<usize>,
) -> Vec<u8> {
    let mut fwd = Vec::new();
    fwd.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for line in header_lines {
        // Strip CR/LF from forwarded header lines: `lines()` splits only on
        // `\n`, so a lone `\r` inside a header line (malformed client) would
        // otherwise survive into the forwarded request as an injected line
        // (request-smuggling shape). Same policy as read_request_and_build_
        // forward and the h2 path, which reject CR/LF outright. Round-17
        // audit E: `lines()` already strips the trailing CRLF, so the common
        // path (no mid-line `\r`) appends the slice directly, no String.
        if line.contains(['\r', '\n']) {
            let safe_line: String = line.chars().filter(|&c| c != '\r' && c != '\n').collect();
            fwd.extend_from_slice(safe_line.as_bytes());
        } else {
            fwd.extend_from_slice(line.as_bytes());
        }
        fwd.extend_from_slice(b"\r\n");
    }
    if framing == Some(super::BodyFraming::Chunked) {
        fwd.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = content_length {
        // Exactly one Content-Length line (RFC 7230 §3.3.2), matching the
        // byte count the body forward will stream.
        fwd.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    fwd.extend_from_slice(b"Connection: close\r\n\r\n");
    fwd
}

/// The Go URL scheme a plain-face request target carries into
/// `DefaultTransport.RoundTrip` (request.go readRequest + url.parse
/// getScheme, probe-pinned): a CONNECT-method target parses as
/// "http://"+target with the bogus scheme STRIPPED back off
/// (readRequest justAuthority), so it always quotes ""; origin-form
/// ("/…") and "*" targets never had a scheme — ""; every other
/// parseable target keeps its url.parse scheme token — `[A-Za-z]
/// [A-Za-z0-9+.-]*` up to the first ':', lowercased by url.parse
/// (probe: "h:80" → "h", "ftp://h/x" → "ftp", "mailto:x" →
/// "mailto"). Shapes url.ParseRequestURI rejects (relative "h",
/// digit-leading "1abc:x") never reach a handler in Go (readRequest
/// errors → 400) — here they fall to the "" arm; a documented
/// residual (the classifier has no readRequest-URL error class for
/// them).
fn plain_face_go_scheme(method: &str, target: &str) -> String {
    if method == "CONNECT" {
        return String::new();
    }
    if !target.starts_with('/') {
        if let Some(colon) = target.find(':') {
            let tok = &target[..colon];
            if tok
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_alphabetic())
                && tok
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            {
                return tok.to_ascii_lowercase();
            }
        }
    }
    String::new()
}

/// Parse an HTTP URL into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    // Handle absolute URLs: http://host:port/path
    if let Some(rest) = url.strip_prefix("http://") {
        let (host_port, path) = rest.split_once('/').unwrap_or((rest, "/"));
        let path = format!("/{path}");
        let (host, port) = split_host_port(host_port);
        return Ok((host.to_string(), port, path));
    }
    // Handle relative URLs — assume they have Host header (parsed elsewhere)
    // For now, default to port 80
    Err("only absolute HTTP URLs supported".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scheme-500 render for scheme-less Serve-classified targets
    /// (origin-form, "GET *", plain-face CONNECT, PRI * with a passing
    /// conn-gate set): Go's RoundTrip error http.Error 500, body
    /// `unsupported protocol scheme ""\n` (probe row: CL 31) in the
    /// frp-rs render shape (Connection: close, no Date).
    const SCHEME_500_EMPTY_RENDER: &str = "HTTP/1.1 500 Internal Server Error\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        X-Content-Type-Options: nosniff\r\n\
        Content-Length: 31\r\n\
        Connection: close\r\n\r\n\
        unsupported protocol scheme \"\"\n";

    /// The version-gate matrix moved to plugin/mod.rs with the shared
    /// `parse_request_line` helper (test_go_parse_http_version_ok_matrix
    /// lives next to it there).

    #[test]
    fn test_parse_http_url() {
        let (host, port, path) = parse_http_url("http://example.com:8080/foo/bar").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo/bar");

        let (host, port, path) = parse_http_url("http://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    /// B1: the outbound forward head speaks HTTP/1.1 — Go's
    /// http.DefaultTransport (http_proxy.go HTTPHandler) never writes
    /// HTTP/1.0 requests. Chunked bodies are the canary: chunked
    /// Transfer-Encoding is HTTP/1.1-only, so under the old HTTP/1.0
    /// request line an origin saw neither TE nor CL and silently dropped
    /// the upload body. Pins the exact head bytes.
    #[test]
    fn build_forward_head_chunked_post_is_http11() {
        let lines = [
            "Host: 127.0.0.1:8080",
            "Content-Type: application/octet-stream",
        ];
        let head = build_forward_head(
            "POST",
            "/up",
            &lines,
            Some(crate::plugin::BodyFraming::Chunked),
            None,
        );
        let head = String::from_utf8(head).unwrap();
        assert!(
            head.starts_with("POST /up HTTP/1.1\r\n"),
            "outbound request line must be HTTP/1.1: {head:?}"
        );
        assert!(!head.contains("HTTP/1.0"), "HTTP/1.0 leaks: {head:?}");
        assert!(
            head.contains("Host: 127.0.0.1:8080\r\n"),
            "host line kept: {head:?}"
        );
        assert!(
            head.contains("Content-Type: application/octet-stream\r\n"),
            "header lines kept: {head:?}"
        );
        assert!(
            head.contains("Transfer-Encoding: chunked\r\n"),
            "chunked framing re-added after the hop-by-hop strip: {head:?}"
        );
        assert!(
            head.ends_with("Connection: close\r\n\r\n"),
            "head ends with the close terminator: {head:?}"
        );

        // Content-Length framing: exactly one canonical CL line, no
        // Transfer-Encoding, still HTTP/1.1.
        let cl_head = build_forward_head("POST", "/up", &lines, None, Some(5));
        let cl_head = String::from_utf8(cl_head).unwrap();
        assert!(cl_head.starts_with("POST /up HTTP/1.1\r\n"), "{cl_head:?}");
        assert!(cl_head.contains("Content-Length: 5\r\n"), "{cl_head:?}");
        assert!(!cl_head.contains("Transfer-Encoding:"), "{cl_head:?}");
        assert!(
            cl_head.ends_with("Connection: close\r\n\r\n"),
            "{cl_head:?}"
        );
    }

    fn auth(user: &str, pass: &str) -> HttpProxyAuth {
        HttpProxyAuth {
            user: Some(user.into()),
            password: Some(pass.into()),
        }
    }

    fn b64(s: &str) -> String {
        frp_core::base64::encode(s.as_bytes())
    }

    fn basic(u: &str, p: &str) -> String {
        format!("Basic {}", b64(&format!("{u}:{p}")))
    }

    /// Go http_proxy.go `Auth()` verdict matrix (source + probe-verified):
    /// shape failures reject INSTANTLY; only a decoded pair failing the
    /// compare delays 200 ms; the scheme token is never inspected (SplitN
    /// decodes `s[1]` unconditionally — "Bearer <b64>" with valid creds is
    /// ACCEPTED by Go frp).
    #[test]
    fn test_classify_proxy_auth_go_verdict_matrix() {
        let a = auth("u1", "p1");
        // Valid creds — accepted with the canonical Basic scheme.
        assert!(matches!(
            a.classify_proxy_auth(&basic("u1", "p1")),
            AuthVerdict::Accept
        ));
        // Go ignores the scheme token entirely: a Bearer-spelled header with
        // valid creds passes (http_proxy.go Auth() never checks s[0]).
        assert!(matches!(
            a.classify_proxy_auth(&format!("Bearer {}", b64("u1:p1"))),
            AuthVerdict::Accept
        ));
        // Wrong creds — the only DELAYED verdict (Go's 200ms sleep sits in
        // Auth() after the shape gates, at the compare).
        assert!(matches!(
            a.classify_proxy_auth(&basic("u1", "zz")),
            AuthVerdict::RejectDelayed
        ));
        // Shape failures — instant (Go returns before the sleep line).
        assert!(matches!(
            a.classify_proxy_auth(""),
            AuthVerdict::RejectInstant
        )); // no header
        assert!(matches!(
            a.classify_proxy_auth("Basic"),
            AuthVerdict::RejectInstant
        )); // no space -> SplitN len 1
        assert!(matches!(
            a.classify_proxy_auth(&format!("Basic {}", b64("no-colon"))),
            AuthVerdict::RejectInstant // decoded pair has no colon
        ));
        assert!(matches!(
            a.classify_proxy_auth("Basic notbase64!!!"),
            AuthVerdict::RejectInstant // undecodable payload
        ));
        assert!(matches!(
            a.classify_proxy_auth("Basic  dTE6cDE="),
            AuthVerdict::RejectInstant // double space -> payload has a leading space, decode fails
        ));
        // Unconfigured accepts everything; partial config is a load-time
        // error -> reject.
        assert!(matches!(
            HttpProxyAuth {
                user: None,
                password: None
            }
            .classify_proxy_auth(""),
            AuthVerdict::Accept
        ));
        assert!(matches!(
            HttpProxyAuth {
                user: Some("u".into()),
                password: None
            }
            .classify_proxy_auth(""),
            AuthVerdict::RejectInstant
        ));
    }

    /// static_file middleware parity: the `Basic ` prefix gate is
    /// case-insensitive (Go net/http parseBasicAuth, Issue 22736:
    /// ascii.EqualFold on the prefix) — lowercase "basic " must pass the
    /// shape check and reach the credential compare.
    #[test]
    fn test_check_static_file_basic_prefix_case_insensitive() {
        let a = auth("admin", "s3cret");
        let lower = format!("basic {}", b64("admin:s3cret"));
        assert!(
            a.check(&lower),
            "Go EqualFold prefix: lowercase basic accepted"
        );
        assert!(
            a.check(&basic("admin", "s3cret")),
            "canonical form accepted"
        );
        assert!(!a.check(&basic("admin", "wrong")), "wrong creds rejected");
        // No prefix at all -> reject (std BasicAuth requires the scheme).
        assert!(
            !a.check(&b64("admin:s3cret")),
            "scheme-less header rejected"
        );
    }

    /// B6: audit round-8 F8 pin through the REAL http_proxy listener — the
    /// head-read loop here in http.rs (a verbatim twin of the loop in
    /// plugin/mod.rs, which has its own copy of this pin). A slowloris peer
    /// that drips ONE byte per 59 s never trips a per-read re-armed deadline
    /// (every byte resets the clock) but MUST be released by the single
    /// absolute PLUGIN_HEADER_READ_TIMEOUT window over the whole head read
    /// (Go http.Server ReadHeaderTimeout = 60 s): the handler errors out at
    /// virtual t=60 s and drops the conn, and the client observes EOF.
    /// Paused time keeps the 300 s outer bound deterministic. RED (per-read
    /// re-arm): the outer bound trips and the test panics.
    #[tokio::test(start_paused = true)]
    async fn http_proxy_head_read_absolute_window_releases_trickler() {
        use tokio::io::AsyncWriteExt;
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let (mut reader, mut trickle_io) = tokio::io::split(client);
        // One byte per 59 s forever — the head never completes (no blank
        // line, no EOF), and each byte would re-arm a per-read deadline.
        let trickle = tokio::spawn(async move {
            loop {
                if trickle_io.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(59)).await;
            }
        });
        let mut buf = [0u8; 1];
        let res = tokio::time::timeout(Duration::from_secs(300), reader.read(&mut buf)).await;
        drop(trickle);
        match res {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a trickled head read"),
            Ok(Err(e)) => panic!("read error from a trickled head read: {e}"),
            Err(_elapsed) => panic!(
                "trickled head read was not released: the 60 s absolute window never fired \
                 (per-read re-arm lets 1 B/59 s beat it)"
            ),
        }
    }

    /// Audit FIX 4 pin: Go frp dials CONNECT targets verbatim
    /// (http_proxy.go handleConnectReq `net.Dial("tcp", r.Host)`) — a
    /// port-less authority is a DIAL failure ("missing port in address"),
    /// so "CONNECT example.com HTTP/1.1" answers Go's bare-400 render,
    /// never a tunnel to :443 (the deleted default-append used to dial
    /// example.com:443 and CONNECT-succeed). Wire = probe capture.
    #[tokio::test]
    async fn http_proxy_connect_without_port_answers_go_400() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let _ = client
            .write_all(b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
            "port-less CONNECT must answer Go's bare 400, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Audit FIX 5 pin: a malformed head on the PLAIN arm renders Go's
    /// http.Server 400 (in Go the head went through PutConn — the server
    /// errors the read and writes errorHeaders + the status-text body
    /// before ServeHTTP ever runs; http_proxy.go's plain arm only ever
    /// serves parseable heads). Probe-captured from go1.25.12 with the same
    /// tab-joined garbage line. EOF/timeout and the CONNECT arm stay silent
    /// (ReadRequest error — no writer), pinned by the trickler above and
    /// http_proxy_oversized_connect_head_closes_silently below.
    #[tokio::test]
    async fn http_proxy_malformed_plain_head_answers_go_400() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let _ = client.write_all(b"GARBAGE\tLINE\r\n\r\n").await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            super::super::GO_400_RENDER.as_bytes(),
            "malformed plain head must render Go's 400, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Audit pin (round-16 FIX 1, arm a; breach boundary updated by
    /// round-17 F9): an UNTERMINATED plain-arm head past the read limit
    /// renders Go's 431 — the read-limit model: the terminator scan never
    /// fires (no blank line is ever sent), so the limit is the only way
    /// the read can end, and an unfinished head is errTooLarge in Go.
    /// The limit is Go's `initialReadLimitSize` = MaxHeaderBytes (1 MiB)
    /// + the 4096-byte bufio slop — 1,049,600 bytes exactly (F9: the
    /// reads clamp to the remaining limit, so the breach boundary no
    /// longer drifts by a chunk; a head between the old 1 MiB check and
    /// the true limit is legal input Go still reads). The head size
    /// exceeds the limit while keeping the whole client payload consumed
    /// before the breach fires, so the close is clean and the render
    /// always arrives.
    #[tokio::test]
    async fn http_proxy_oversized_plain_head_answers_go_431() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let mut head = Vec::with_capacity(1024 * 1024 + 4096 + 128);
        head.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ");
        head.resize(1024 * 1024 + 4096 + 128, b'A');
        let _ = client.write_all(&head).await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            super::super::GO_431_RENDER.as_bytes(),
            "oversized plain head must render Go's 431, got {} bytes",
            resp.len()
        );
    }

    /// Audit FIX 5 pin: the CONNECT arm of an oversized head closes
    /// SILENTLY. Note the divergence carefully: Go's http_proxy.go sniffs
    /// CONNECT and then hands the stream to http.ReadRequest, which has NO
    /// size cap (only the ReadHeaderTimeout window) — a giant CONNECT head
    /// never fails in Go. The 1 MiB cap here is fail-closed Rust-only
    /// hardening on the operator-local 127.0.0.1 surface; the silent close
    /// (no 431 exists on this arm — no parsed head, no writer) mirrors the
    /// ReadFull-short EOF behavior.
    #[tokio::test]
    async fn http_proxy_oversized_connect_head_closes_silently() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let mut head = Vec::with_capacity(1024 * 1024 + 4096 + 128);
        head.extend_from_slice(b"CONNECT example.com HTTP/1.1\r\nHost: x\r\nX-Big: ");
        // Past the F9 read limit (1 MiB + 4096): an unterminated head of
        // 1,048,608 bytes no longer breaches (it is legal input Go still
        // reads) — it would hang to the 60s header timeout and pass only
        // vacuously. Breach now fires at 1,049,600 consumed.
        head.resize(1024 * 1024 + 4096 + 128, b'A');
        let _ = client.write_all(&head).await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert!(
            resp.is_empty(),
            "oversized CONNECT head must close silently, got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(200)])
        );
    }

    /// Audit FIX 1 pin: a mid-head EOF after partial bytes on the PLAIN arm
    /// renders Go's 400 errorHeaders. In Go, http_proxy.go's 7-byte probe
    /// succeeded (>= 7 bytes, non-CONNECT) so the shared conn went through
    /// PutConn into http.Server — a read error with ANY bytes received is
    /// a server error and conn.serve writes errorHeaders; only a clean EOF
    /// with ZERO bytes is a silent close. The request line here is complete
    /// but the HEAD is not (headers unterminated — no empty line): the old
    /// code closed silently on every mid-head EOF, this one must answer the
    /// same render as the malformed-line pin.
    #[tokio::test]
    async fn http_proxy_mid_head_eof_answers_go_400() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let _ = client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Truncated: abc")
            .await;
        // Half-close the write side: the server's head read now returns EOF
        // mid-head (no empty line was ever seen).
        let _ = client.shutdown().await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            super::super::GO_400_RENDER.as_bytes(),
            "EOF mid-head after partial bytes must render Go's 400, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Audit FIX 1 pin (other edge): a clean EOF with ZERO bytes received
    /// stays a silent close. Go: the 7-byte ReadFull probe itself fails on
    /// the empty conn and http_proxy.go closes without a byte; http.Server
    /// never answers a conn it never read from. Also covers the 1-6 byte
    /// short-reads (probe failure — the head_short arm) via the same
    /// no-render path.
    #[tokio::test]
    async fn http_proxy_zero_byte_eof_closes_silently() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let _ = client.shutdown().await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert!(
            resp.is_empty(),
            "zero-byte EOF must close silently, got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp)
        );
    }

    /// Round-16 FIX 1 pin (the flip): a plain-arm head whose TERMINATOR
    /// arrived is SERVED even when its total size exceeds 1 MiB — Go's cap
    /// is a READ LIMIT (MaxHeaderBytes + 4096 bufio slop) that errors only
    /// when the limit is consumed with the head still incomplete
    /// (probe-verified: a terminated ~1 MiB+64 head answers 200 in Go).
    /// The head targets a bind-then-drop refused port, so "served" shows
    /// up as the plugin's dial-fail 500 render: the head reached the parse
    /// + forward path (no 431), the backend dial was attempted, and the
    /// conn closed after the render. RED on the old cap-before-scan order
    /// (it 431'd this exact head).
    #[tokio::test]
    async fn http_proxy_terminated_oversized_plain_head_is_served() {
        use tokio::net::TcpListener;
        // Bind then drop: the port is closed, so the backend dial is a
        // deterministic ECONNREFUSED (a live backend would have to drain
        // ~1 MiB of forwarded head before answering — the refused-port
        // 500 proves the forward path ran without that machinery).
        let refused = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let refused_addr = refused.local_addr().unwrap();
        drop(refused);

        let cfg = PluginConfig::default();
        let handle = start_http_proxy(&cfg)
            .await
            .expect("plugin start failed — test-environment or regression signal, not a skip");
        let mut client = TcpStream::connect(handle.local_addr)
            .await
            .expect("cannot connect to the plugin listener (sandboxed?)");
        let mut head = Vec::with_capacity(1024 * 1024 + 128);
        head.extend_from_slice(
            format!("GET http://{refused_addr}/ HTTP/1.1\r\nHost: x\r\nX-Big: ").as_bytes(),
        );
        // ~1 MiB + 64 of header content plus the prefix: the terminator
        // ends ~1 MiB + 125 bytes in — inside the 1 MiB + 4096 serve
        // boundary (Go serves a terminated head at this size; probe).
        head.resize(1024 * 1024 + 64, b'A');
        head.extend_from_slice(b"\r\n\r\n");
        let _ = client.write_all(&head).await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert!(
            resp.starts_with(b"HTTP/1.1 500 Internal Server Error"),
            "terminated oversized plain head must be SERVED (dial-fail 500 on \
             the refused target proves the head was parsed and forwarded, not \
             431'd), got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(120)])
        );
    }

    /// Round-16 FIX 1 pin (arm b): a terminated head whose terminator lies
    /// PAST the serve boundary (total ~1 MiB + 8192, terminator far beyond
    /// 1 MiB + 4096) still 431s — Go's errTooLarge fires when the limit is
    /// consumed mid-head; the terminator never arrives in time to complete
    /// it. The breach fires as soon as the buffer passes 1 MiB without an
    /// empty line, so the client-side write outruns the read: the payload
    /// is written from a spawned task (it may error when the server closes
    /// mid-send) while this task reads the render, bounded by a 10 s
    /// deadline.
    #[tokio::test]
    async fn http_proxy_terminated_past_slack_plain_head_answers_go_431() {
        let cfg = PluginConfig::default();
        let handle = start_http_proxy(&cfg)
            .await
            .expect("plugin start failed — test-environment or regression signal, not a skip");
        let client = TcpStream::connect(handle.local_addr)
            .await
            .expect("cannot connect to the plugin listener (sandboxed?)");
        let (mut rd, mut wr) = tokio::io::split(client);
        let mut head = Vec::with_capacity(1024 * 1024 + 16 * 1024);
        head.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ");
        head.resize(1024 * 1024 + 8192, b'A');
        head.extend_from_slice(b"\r\n\r\n");
        tokio::spawn(async move {
            // The server breaches at the F9 limit (1 MiB + 4096 —
            // 1,049,600 consumed with no terminator in the window) and
            // closes; the rest of the payload is never consumed. The
            // write errors — that is the expected outcome, ignored here.
            let _ = wr.write_all(&head).await;
        });
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            rd.read_to_end(&mut resp),
        )
        .await
        .expect("timed out waiting for the 431 render — regression?");
        assert_eq!(
            resp,
            super::super::GO_431_RENDER.as_bytes(),
            "terminated head past the serve boundary must render Go's 431, \
             got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(120)])
        );
    }

    /// Round-16 FIX 2 pin: on the PLAIN arm a TERMINATED head whose first
    /// line carries a parseable non-1.x version token renders Go's 505 —
    /// the http.Server conn face frp http_proxy.go PutConns plain heads
    /// into answers 505 via http1ServerSupportsRequest only AFTER the
    /// whole head parsed (probe-verified wire bytes for HTTP/2.0 / HTTP/0.9
    /// / HTTP/9.9). This face is reachable with raw bytes under
    /// tcp/tcpmux/xtcp-typed frps entries (the vhost front's 505 gate only
    /// covers http/https entries). Lenient version SHAPES (HTTP/1.10) stay
    /// Go's no-detail 400 — badStringError renders before the gate.
    /// Round-16 post-fix (FIX 3, corrected round-17 F3): the
    /// "PRI * HTTP/2.0" h2c-prior-knowledge shape is EXEMPT from the 505
    /// class — http1ServerSupportsRequest passes it unconditionally
    /// (request.go, no feature gate). The harness appends `Host: x`, so
    /// the conn gates pass and the head is SERVED to the forward path
    /// (Go probe: PRI + Host answers the handler's 500), where the
    /// scheme-less "*" target hits the caller's scheme-500 arm — Go's
    /// `unsupported protocol scheme ""` http.Error, not the 505 and not
    /// the no-detail 400 the round-16 classifier answered.
    #[tokio::test]
    async fn http_proxy_plain_head_non_1x_version_answers_go_505() {
        let cfg = PluginConfig::default();
        let handle = start_http_proxy(&cfg)
            .await
            .expect("plugin start failed — test-environment or regression signal, not a skip");
        for (line, expect) in [
            ("GET /x HTTP/2.0", GO_505_RENDER.as_bytes()),
            ("GET /x HTTP/0.9", GO_505_RENDER.as_bytes()),
            ("GET /x HTTP/9.9", GO_505_RENDER.as_bytes()),
            // Lenient version shape: parseable as neither 1.x nor any
            // HTTP/X.Y — Go's malformed-version 400 (no-detail).
            ("GET /x HTTP/1.10", super::super::GO_400_RENDER.as_bytes()),
            ("GET /x HTTP/2", super::super::GO_400_RENDER.as_bytes()),
            // The h2c-prior-knowledge upgrade shape passes the version
            // gate (505-exempt) and, with the harness's Host: x, the conn
            // gates — the head is SERVED and the caller's scheme-500 arm
            // renders Go's `unsupported protocol scheme ""` (CL 31 body;
            // Connection: close per the frp-rs render convention — Go
            // only adds it on the zero-header PRI head's Close=true).
            // RED on the round-16-wave code, which 505'd the shape via
            // the plain major!=1 classify, and on round-16-FIX-3 code,
            // which answered the no-detail 400.
            ("PRI * HTTP/2.0", SCHEME_500_EMPTY_RENDER.as_bytes()),
            // Not the exact PRI shape: a different target or version must
            // keep classifying by version major (Go: only Method PRI +
            // Path "*" + Proto HTTP/2.0 together pass the exemption).
            ("PRI /x HTTP/2.0", GO_505_RENDER.as_bytes()),
            ("PRI * HTTP/3.0", GO_505_RENDER.as_bytes()),
        ] {
            let mut client = TcpStream::connect(handle.local_addr)
                .await
                .expect("cannot connect to the plugin listener (sandboxed?)");
            let head = format!("{line}\r\nHost: x\r\n\r\n");
            client.write_all(head.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = client.read_to_end(&mut resp).await;
            assert_eq!(
                resp,
                expect,
                "request line {line:?} must render Go's error, got: {:?}",
                String::from_utf8_lossy(&resp)
            );
        }
    }

    /// Round-16 post-fix FIX 4 pin: a 505-shaped request line whose
    /// HEADER BLOCK is malformed answers Go's no-detail 400, never 505 —
    /// http.Server readRequest parses the whole head (request line, then
    /// ReadMIMEHeader over the header lines) before
    /// http1ServerSupportsRequest runs, so header-content errors
    /// (missing-colon line, initial obs-fold, CTL/DEL in a value) fire
    /// first and render the badStringError 400. Headers that PARSE keep
    /// the 505. RED on the round-16-wave code, which rendered 505 from
    /// the request line alone.
    #[tokio::test]
    async fn http_proxy_505_classified_head_validates_header_block_first() {
        let cfg = PluginConfig::default();
        let handle = start_http_proxy(&cfg)
            .await
            .expect("plugin start failed — test-environment or regression signal, not a skip");
        // (request line, expected render) — every fixture carries a
        // 505-classified first line (parseable HTTP/2.0).
        for (head, expect) in [
            // Colonless group-first header line (missing colon).
            (
                "GET /x HTTP/2.0\r\nBadHeader\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // obs-fold continuation with nothing to continue (textproto's
            // "malformed MIME header initial line").
            (
                "GET /x HTTP/2.0\r\n Host: x\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // Empty header name (": x").
            (
                "GET /x HTTP/2.0\r\n: x\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // CTL byte in a header value.
            (
                "GET /x HTTP/2.0\r\nX-A: ok\x01bad\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // DEL in a header value.
            (
                "GET /x HTTP/2.0\r\nX-A: ok\x7f\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // CTL in an obs-fold continuation (merged-line check).
            (
                "GET /x HTTP/2.0\r\nX-A: ok\r\n \x01fold\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // An obs-fold that PARSES (legal continuation) keeps the 505.
            (
                "GET /x HTTP/2.0\r\nX-A: one\r\n two\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // A legal zero-header head keeps the 505.
            ("GET /x HTTP/2.0\r\n\r\n", GO_505_RENDER.as_bytes()),
        ] {
            let mut client = TcpStream::connect(handle.local_addr)
                .await
                .expect("cannot connect to the plugin listener (sandboxed?)");
            client.write_all(head.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = client.read_to_end(&mut resp).await;
            assert_eq!(
                resp,
                expect,
                "head {:?} must render Go's error, got: {:?}",
                head,
                String::from_utf8_lossy(&resp)
            );
        }
    }

    /// Review-round fix: the 505-arm header gate covers Go's FULL
    /// readRequest error set in precedence order — the four
    /// ReadMIMEHeader shapes, then the dup-Host 400 (request.go "too
    /// many Host headers", read off the canonical-key-merged map), then
    /// readTransfer's Transfer-Encoding 501 (transfer.go
    /// parseTransferEncoding: exactly ONE header whose stored value
    /// EqualFolds "chunked", else `*unsupportedTEError` — Go's fixed 501
    /// render), then the Content-Length 400 (fixLength: multiple values
    /// legal only when TrimString-identical, Issue 16490 dedupe;
    /// parseContentLength: non-empty unsigned decimal < 2^63), and only a
    /// head clearing every gate renders the 505 (the
    /// http1ServerSupportsRequest version gate). Every fixture carries a
    /// 505-classified first line (parseable HTTP/2.0 unless noted).
    /// RED on pre-fix code: the FIX-4 walker validated only the four
    /// ReadMIMEHeader shapes, so every dup-Host / Transfer-Encoding /
    /// Content-Length fixture below rendered GO_505_RENDER where Go
    /// answers its 400 or fixed 501 (the FIX-4-shape entries — empty
    /// name, name CTL, value CTL — were already 400 pre-fix; they stay
    /// as regression guards).
    #[tokio::test]
    async fn http_proxy_505_classified_head_validates_full_read_request_error_classes() {
        let cfg = PluginConfig::default();
        let handle = start_http_proxy(&cfg)
            .await
            .expect("plugin start failed — test-environment or regression signal, not a skip");
        // (case, head, expected render).
        for (case, head, expect) in [
            // ── dup Host (request.go, after ReadMIMEHeader, before
            // readTransfer, at every protocol version) → 400.
            // RED on pre-fix: rendered GO_505_RENDER (no dup-Host gate).
            (
                "dup-host",
                "GET /x HTTP/2.0\r\nHost: a\r\nHost: b\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // "Host" + "host" merge into one canonical map key
            // (textproto canonicalMIMEHeaderKey) — still two values.
            // RED on pre-fix: rendered GO_505_RENDER.
            (
                "dup-host-lower",
                "GET /x HTTP/2.0\r\nHost: a\r\nhost: b\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // Identical dup Host lines count too (Go counts map values;
            // no Host dedupe). RED on pre-fix: rendered GO_505_RENDER.
            (
                "dup-host-identical",
                "GET /x HTTP/2.0\r\nHost: a\r\nHost: a\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // ── ReadMIMEHeader name/value shapes (FIX-4 era, regression
            // guards — these were already 400 pre-fix).
            // Empty header name (": x").
            (
                "empty-name",
                "GET /x HTTP/2.0\r\n: x\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // CTL byte in a header name (shape 3).
            (
                "name-ctl",
                "GET /x HTTP/2.0\r\nBad\x01Name: x\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // CTL byte in a header value (shape 4).
            (
                "value-ctl",
                "GET /x HTTP/2.0\r\nX-A: ok\x01bad\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // SPACE in a header name is legal (canonicalMIMEHeaderKey
            // noCanon, go.dev/issue/34540) and never canonicalizes into a
            // Host/TE/CL record key — the head keeps the 505.
            (
                "name-space",
                "GET /x HTTP/2.0\r\nBad Name: x\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // ── Transfer-Encoding (transfer.go parseTransferEncoding,
            // runs BEFORE the Content-Length checks) → the fixed 501.
            // RED on pre-fix: every TE fixture below rendered 505.
            (
                "te-garbage",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: gzip\r\n\r\n",
                GO_501_TE_RENDER.as_bytes(),
            ),
            // Repeated TE headers — "too many transfer encodings", 501
            // (Go does not merge; len(raw) != 1 errors).
            (
                "te-dup",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                GO_501_TE_RENDER.as_bytes(),
            ),
            // A list value is not "chunked" — 501.
            (
                "te-gzip-chunked",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                GO_501_TE_RENDER.as_bytes(),
            ),
            // A trailing space is NOT part of the stored value — textproto
            // trim() strips trailing OWS from every physical line before
            // the merge (reader.go), so "chunked " reaches EqualFold as
            // "chunked" and stays legal → 505. Guard pin: a TrimLeft-only
            // stored-value model (the draft shape of this fix) answers
            // 501 here — Go parses the head (pre-fix FIX-4 walker had no
            // TE gate at all and also answered 505).
            (
                "te-trailing-space",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: chunked \r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // Legal single "chunked" keeps the 505.
            (
                "te-chunked",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: chunked\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // Case-insensitive "chunked" is legal (ascii.EqualFold).
            (
                "te-chunked-upper",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: Chunked\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // HTTP/0.9 skips the TE check entirely (parseTransferEncoding
            // protoAtLeast(1, 1)) — a garbage TE on a 0.9 line still 505s.
            // RED on a naive unconditional TE gate (which would 501 this).
            (
                "te-garbage-http09",
                "GET /x HTTP/0.9\r\nTransfer-Encoding: gzip\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // ── Content-Length (fixLength/parseContentLength) → 400.
            // RED on pre-fix: every CL error fixture below rendered 505.
            // Differing multi-CL values — the request-smuggling shape.
            (
                "dup-cl-differing",
                "GET /x HTTP/2.0\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // TrimString-IDENTICAL multi-CL values dedupe (Go Issue 16490)
            // and the head parses — 505. RED only on a blanket
            // ">1 CL → 400" implementation (Go accepts the dup).
            (
                "dup-cl-identical",
                "GET /x HTTP/2.0\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // Non-numeric CL value.
            (
                "bad-cl",
                "GET /x HTTP/2.0\r\nContent-Length: abc\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // Empty CL value (TrimString'd → "").
            (
                "cl-empty",
                "GET /x HTTP/2.0\r\nContent-Length: \r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // A comma value is one token to parseContentLength (go1.25
            // has no comma split in readRequest — that logic lives in the
            // chunked-forward framing) — ParseUint fails → 400.
            (
                "cl-comma",
                "GET /x HTTP/2.0\r\nContent-Length: 5, 5\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // 2^63 (ParseUint bitSize 63 overflow) → 400.
            (
                "cl-2pow63",
                "GET /x HTTP/2.0\r\nContent-Length: 9223372036854775808\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // Trailing SP/HTAB never reaches parseContentLength — textproto
            // trim() strips it per physical line (parseContentLength's own
            // TrimString is the second line of defense) — legal, 505.
            (
                "cl-trailing-space",
                "GET /x HTTP/2.0\r\nContent-Length: 5 \r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // 2^63 - 1 parses — keeps the 505.
            (
                "cl-2pow63-minus-1",
                "GET /x HTTP/2.0\r\nContent-Length: 9223372036854775807\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // ── TE + CL interaction: fixLength validates Content-Length
            // BEFORE its RFC 9112 chunked-discard arm (transfer.go — both
            // CL checks sit above the `if chunked` delete), so chunked TE
            // exempts only VALID Content-Length values.
            // Legal chunked + valid CL: parsed, then discarded by the
            // chunked arm → the version gate fires, 505.
            (
                "te-chunked-plus-cl",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
                GO_505_RENDER.as_bytes(),
            ),
            // Legal chunked + garbage CL: parseContentLength errors BEFORE
            // the discard arm → 400. RED on pre-fix code: the classifier
            // short-circuited legal-chunked heads past CL validation and
            // rendered GO_505_RENDER where Go answers 400.
            (
                "te-chunked-plus-cl-garbage",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: chunked\r\nContent-Length: abc\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // Legal chunked + DIFFERING duplicate CL: the fixLength dup
            // check runs before the discard arm too → 400. RED on pre-fix
            // code (same short-circuit as the garbage row).
            (
                "te-chunked-plus-dup-cl-differing",
                "GET /x HTTP/2.0\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
            // ── HTTP/1.1-line gates (R1's primary case): the same
            // parseTransferEncoding/fixLength arms run on 1.1 lines before
            // the Serve branch. Pre-fix code had NO TE gate on the 1.1
            // serve path — a garbage-TE 1.1 head forwarded to the local
            // backend where Go answers its 501 (probe5 rows
            // h11-te-garbage/h11-te-dup).
            (
                "te-garbage-h11",
                "GET /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n",
                GO_501_TE_RENDER.as_bytes(),
            ),
            (
                "te-dup-h11",
                "GET /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                GO_501_TE_RENDER.as_bytes(),
            ),
            // Differing dup CL on a 1.1 line → the fixLength 400 (the CL
            // checks are not version-gated — same arm the 2.0 rows pin).
            (
                "dup-cl-differing-h11",
                "GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                super::super::GO_400_RENDER.as_bytes(),
            ),
        ] {
            let mut client = TcpStream::connect(handle.local_addr)
                .await
                .expect("cannot connect to the plugin listener (sandboxed?)");
            client.write_all(head.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = client.read_to_end(&mut resp).await;
            assert_eq!(
                resp,
                expect,
                "case {case}: head {:?} must render Go's error, got: {:?}",
                head,
                String::from_utf8_lossy(&resp)
            );
        }
    }

    /// Review-round fix: a CONNECT authority carrying a well-formed
    /// ASCII-decoding %-escape ("CONNECT h%41st:443" — "invalid URL
    /// escape" under Go's HOST-mode unescape, net/url/url.go:226) is a
    /// ReadRequest error, and the Go frp http_proxy.go CONNECT arm
    /// closes SILENTLY on any ReadRequest error (no render — the handler
    /// has no response writer for a head it never parsed). RED on
    /// pre-fix code: the shared escape scan was path-mode, so the
    /// well-formed ASCII authorities parsed and reached handle_connect's
    /// dial-failure 400 render; only malformed %zz silent-closed. The
    /// "%25" exemption (decodes to '%') and obs-text decodes ("%C3%A9"
    /// → 'é') keep clearing the parse gate: the accepted heads below
    /// land on the dial-failure arm (neither verbatim authority can ever
    /// resolve) and answer the bare Go 400 — byte-proof they passed the
    /// gate instead of silent-closing.
    #[tokio::test]
    async fn http_proxy_connect_authority_host_mode_escapes() {
        let cfg = PluginConfig::default();
        let handle = start_http_proxy(&cfg)
            .await
            .expect("plugin start failed — test-environment or regression signal, not a skip");
        // Rejected authorities: silent close, 0 bytes.
        for target in [
            "h%41st:443", // '%41' = 'A' — ASCII decode → host-mode reject
            "h%2Fst:443", // '%2F' = '/'
            "h%5Bst:443", // '%5B' = '['
            "h%40st:443", // '%40' = '@'
            "h%zzst:443", // malformed (rejected pre-fix too — kept)
            "h:4%31",     // port region — same ReadRequest-error class
        ] {
            let mut client = TcpStream::connect(handle.local_addr)
                .await
                .expect("cannot connect to the plugin listener (sandboxed?)");
            let head = format!("CONNECT {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            client.write_all(head.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = client.read_to_end(&mut resp).await;
            assert_eq!(
                resp,
                b"",
                "CONNECT {target:?} must silent-close (host-mode escape → \
                 ReadRequest error → http_proxy.go CONNECT arm closes), got: {:?}",
                String::from_utf8_lossy(&resp)
            );
        }
        // Accepted authorities: they clear the parse gate and reach the
        // CONNECT dial, whose verbatim (never-resolvable) target fails →
        // the bare Go 400 render. Port-less on purpose: the dial fails
        // instantly on the missing port, no DNS involved.
        for target in ["h%25st", "h%C3%A9st"] {
            let mut client = TcpStream::connect(handle.local_addr)
                .await
                .expect("cannot connect to the plugin listener (sandboxed?)");
            let head = format!("CONNECT {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            client.write_all(head.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = client.read_to_end(&mut resp).await;
            assert_eq!(
                resp,
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
                "CONNECT {target:?} must clear the parse gate and land on \
                 the dial-fail 400 render, got: {:?}",
                String::from_utf8_lossy(&resp)
            );
        }
    }
}
