use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{debug, info, instrument, warn};

use crate::service::{AppState, InternalMsg};
// Pure HTTP head parsing helpers (see `head.rs`): strict authority
// canonicalization (Go url.ParseRequestURI semantics) shared with tcpmux.rs,
// which owns `canonicalize_host` (round-3 M4).

mod forward;
mod head;
mod https;
pub use https::{extract_sni_from_client_hello, run_vhost_https_listener};
mod router;
#[cfg(test)]
use forward::VhostForward;
#[cfg(test)]
use forward::{inject_vhost_request_headers, rewrite_host_header};
use forward::{resolve_vhost_request, sanitize_rewrite_host, VhostResolveError};
#[cfg(test)]
use router::{find_matching_route, sort_by_longest_location};
pub use router::{RouterConfigConflict, VhostManager, VhostRoute, VhostRouteMatch};

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

#[cfg(test)]
mod tests;
