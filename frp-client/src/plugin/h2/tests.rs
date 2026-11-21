use super::{
    build_http1_request_head, cap_chunk, header_value, parse_hex, parse_response_head,
    serve_h2_connection, Backend,
};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn parse_hex_rejects_go_invalid_chunk_sizes() {
    assert_eq!(parse_hex(b"1a").unwrap(), 26);
    assert_eq!(parse_hex(b" 1A ").unwrap(), 26); // whitespace trimmed
    assert!(parse_hex(b"").is_err());
    assert!(parse_hex(b"zz").is_err());
    assert!(parse_hex(b"-1").is_err());
    // Go parseHexUint accepts ONLY 0-9a-fA-F — "+5" is an invalid byte
    // in a chunk length even though Rust's from_str_radix would accept
    // the leading '+' for radix 16 (server twin vhost_h2c.rs:1294).
    assert!(parse_hex(b"+5").is_err());
}

#[test]
fn parse_response_head_parses_normal_head() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nbody";
    let parsed = parse_response_head(head).expect("normal head should parse");
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.headers.len(), 1);
    assert!(
        parsed.headers[0]
            .0
            .as_str()
            .eq_ignore_ascii_case("content-length"),
        "expected content-length header, got {}",
        parsed.headers[0].0
    );
    assert_eq!(parsed.headers[0].1.to_str().unwrap(), "5");
    // body_offset points at the start of "body" (right after "\r\n\r\n").
    assert_eq!(&head[parsed.body_offset..], b"body");
}

#[test]
fn parse_response_head_status_token_is_exactly_three_digits() {
    // Go http.ReadResponse checks the status-code token length == 3
    // BEFORE strconv.Atoi (net/http/response.go): a 4-digit token —
    // "1000" (out of u16 range is irrelevant) or "0200" (leading zero) —
    // is a malformed response, never a status. Round-3 review: the old
    // "accepts any u16" behavior was false parity. 100..=999 is the
    // complete valid range (builder rejects only < 100 / > 999).
    assert!(parse_response_head(b"HTTP/1.1 1000 Weird\r\n\r\n").is_none());
    assert!(parse_response_head(b"HTTP/1.1 0200 OK\r\n\r\n").is_none());
    let parsed = parse_response_head(b"HTTP/1.1 999 Weird\r\n\r\n").expect("999 is 3 digits");
    assert_eq!(parsed.status, 999);

    // Locks in the fix contract: production code maps the builder error to
    // Err (h2::Error) instead of panicking with expect. If someone reverts
    // `map_err` to `expect`, this test fails.
    assert!(http::Response::builder()
        .status(1000u16)
        .body(())
        .map_err(|_| h2::Error::from(h2::Reason::INTERNAL_ERROR))
        .is_err());
}

#[test]
fn parse_response_head_malformed_returns_none() {
    // No "\r\n\r\n" terminator and an empty head both yield None.
    assert!(parse_response_head(b"garbage\r\n\r\n").is_none());
    assert!(parse_response_head(b"").is_none());
    // Tab-separated status line → None: Go strings.Cut splits at the
    // first literal space, so the tab stays inside the version token and
    // ParseHTTPVersion rejects it (split_whitespace used to accept and
    // forward such heads — round-7 review NIT).
    assert!(parse_response_head(b"HTTP/1.1\t200 OK\r\n\r\n").is_none());
    // Multi-space between version and code stays legal (Go TrimLeft).
    let parsed = parse_response_head(b"HTTP/1.1  200 OK\r\n\r\n").expect("multi-space parses");
    assert_eq!(parsed.status, 200);
}

#[test]
fn cap_chunk_limits_to_declared_content_length() {
    // A request body stream longer than the declared Content-Length:
    // exactly Content-Length bytes are forwarded, the surplus is dropped
    // (Go's http.Transport body reader stops at the declared length, so
    // the surplus must not reach the HTTP/1.1 connection as a pipelined
    // request).
    let mut remaining = Some(10usize);
    let mut forwarded = 0usize;
    for chunk in [8usize, 5, 3, 4] {
        let (next, n) = cap_chunk(chunk, remaining);
        forwarded += n;
        remaining = next;
    }
    assert_eq!(
        forwarded, 10,
        "surplus bytes beyond the declared Content-Length must be dropped"
    );
    assert_eq!(remaining, Some(0));

    // Chunks arriving after the budget drained forward nothing.
    assert_eq!(cap_chunk(4, Some(0)), (Some(0), 0));

    // A chunk exactly at the remaining budget is fully forwarded and the
    // budget drains to zero; a smaller chunk keeps the remainder.
    assert_eq!(cap_chunk(5, Some(5)), (Some(0), 5));
    assert_eq!(cap_chunk(3, Some(7)), (Some(4), 3));

    // The chunked path (no declared Content-Length) is untouched: every
    // chunk is forwarded whole and `None` propagates.
    assert_eq!(cap_chunk(7, None), (None, 7));
    assert_eq!(cap_chunk(0, None), (None, 0));
}

// -- M9: X-Forwarded-For appends the REAL tunnel peer (Go https2http.go
//    SetXForwarded semantics: client chain preserved, peer appended;
//    configured request_headers replaces the whole chain).

fn build_req(xff: Option<&[&str]>) -> http::Request<bytes::Bytes> {
    let mut b = http::Request::builder()
        .method("GET")
        .uri("http://backend.example.com/path")
        .header("user-agent", "test");
    if let Some(values) = xff {
        for v in values {
            b = b.header("x-forwarded-for", *v);
        }
    }
    b.body(bytes::Bytes::new()).expect("valid request")
}

fn head_lines(head: &[u8]) -> String {
    String::from_utf8_lossy(head).to_string()
}

fn real_ip() -> std::net::IpAddr {
    "198.51.100.23".parse().unwrap()
}

#[test]
fn h2_head_appends_real_peer_when_no_client_xff() {
    let head = head_lines(&build_http1_request_head(
        &build_req(None),
        "",
        &HashMap::new(),
        real_ip(),
        true,
    ));
    assert!(
        head.contains("X-Forwarded-For: 198.51.100.23\r\n"),
        "real tunnel peer must be appended, head:\n{head}"
    );
    assert_eq!(head.matches("X-Forwarded-For").count(), 1);
}

#[test]
fn h2_head_preserves_client_chain_and_appends_real_peer() {
    let head = head_lines(&build_http1_request_head(
        &build_req(Some(&["203.0.113.9", "10.0.0.4"])),
        "",
        &HashMap::new(),
        real_ip(),
        true,
    ));
    // Go SetXForwarded: strings.Join(prior, ", ") + ", " + clientIP.
    assert!(
        head.contains("X-Forwarded-For: 203.0.113.9, 10.0.0.4, 198.51.100.23\r\n"),
        "client chain preserved and real peer appended, head:\n{head}"
    );
    assert_eq!(head.matches("X-Forwarded-For").count(), 1);
}

#[test]
fn h2_head_configured_xff_replaces_chain_and_peer() {
    let mut headers = HashMap::new();
    headers.insert("X-Forwarded-For".to_string(), "192.0.2.1".to_string());
    let head = head_lines(&build_http1_request_head(
        &build_req(Some(&["203.0.113.9"])),
        "",
        &headers,
        real_ip(),
        true,
    ));
    // Go order: SetXForwarded appends, then rewriteHTTPPluginRequest's
    // Header.Set replaces the whole value — only the configured one
    // survives, and the real peer must NOT be appended.
    assert!(
        head.contains("X-Forwarded-For: 192.0.2.1\r\n"),
        "configured x-forwarded-for must replace the chain, head:\n{head}"
    );
    assert_eq!(head.matches("X-Forwarded-For").count(), 1);
    assert!(
        !head.contains("198.51.100.23"),
        "peer must not leak: {head}"
    );
}

/// Round-18 FIX 4 pin (mirror of the h1 twin's
/// `l3_empty_xff_row_kept_in_chain` and the vhost.rs round-13 empty-XFF
/// pin): an EMPTY-value X-Forwarded-For row is a real chain element —
/// Go `strings.Join(prior, ", ")` keeps empty elements, so a sole empty
/// row emits ", {peer}" with the leading comma. Only the NO-row case
/// emits the bare peer (`h2_head_appends_real_peer_when_no_client_xff`
/// above). RED pre-fix: the `xff.is_empty()` STRING check conflated the
/// two and dropped the row.
#[test]
fn h2_head_empty_client_xff_row_kept_in_chain() {
    let head = head_lines(&build_http1_request_head(
        &build_req(Some(&[""])),
        "",
        &HashMap::new(),
        real_ip(),
        true,
    ));
    assert!(
        head.contains("X-Forwarded-For: , 198.51.100.23\r\n"),
        "an empty inbound XFF row must contribute an empty chain element, head:\n{head}"
    );
    assert_eq!(head.matches("X-Forwarded-For").count(), 1);
}

/// Go's Header.WriteSubset trims the whole synthesized XFF value at
/// egress (textproto.TrimString) — OUTER padding only, so a padded
/// inbound row keeps its tail padding (before the ", " join) while the
/// chain's leading space is dropped. RED pre-fix: the joined string was
/// emitted verbatim (`X-Forwarded-For:  192.0.2.1 , ...`).
#[test]
fn h2_head_padded_client_xff_row_outer_trimmed() {
    let head = head_lines(&build_http1_request_head(
        &build_req(Some(&[" 192.0.2.1 "])),
        "",
        &HashMap::new(),
        real_ip(),
        true,
    ));
    assert!(
        head.contains("X-Forwarded-For: 192.0.2.1 , 198.51.100.23\r\n"),
        "outer padding of the joined chain must be trimmed, head:\n{head}"
    );
    assert_eq!(head.matches("X-Forwarded-For").count(), 1);
}

// -- Round-18 egress parity (Go http.Transport / transferWriter):
//    forwarded values are TrimString'd, a body-less GET/HEAD omits
//    Content-Length, and the chunked arm re-announces declared trailers.

fn req_with(method: &str, headers: &[(&str, &str)]) -> http::Request<bytes::Bytes> {
    let mut b = http::Request::builder()
        .method(method)
        .uri("http://backend.example.com/path")
        .header("user-agent", "test");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(bytes::Bytes::new()).expect("valid request")
}

fn head_of(request: &http::Request<bytes::Bytes>, body_end_stream: bool) -> String {
    head_lines(&build_http1_request_head(
        request,
        "",
        &HashMap::new(),
        real_ip(),
        body_end_stream,
    ))
}

/// Go `Header.WriteSubset` runs every forwarded value through
/// `textproto.TrimString` (ASCII SP/HTAB at both ends). RED pre-fix: the
/// inbound value was copied byte-for-byte, so `  abc  ` reached the
/// backend padded.
#[test]
fn h2_head_trims_forwarded_values() {
    let head = head_of(
        &req_with("GET", &[("x-pad", "  abc  "), ("x-tab", "\tabc\t")]),
        true,
    );
    assert!(
        head.contains("x-pad: abc\r\n"),
        "SP-padded value must be trimmed, head:\n{head}"
    );
    assert!(
        head.contains("x-tab: abc\r\n"),
        "HTAB-padded value must be trimmed, head:\n{head}"
    );
    assert!(
        !head.contains("  abc") && !head.contains("abc  "),
        "no padding may survive, head:\n{head}"
    );
}

/// Go `shouldSendContentLength` (transfer.go:254-276): a body-less GET
/// emits NO Content-Length line. RED pre-fix: `Content-Length: 0` was
/// synthesized unconditionally on the end-stream arm.
#[test]
fn h2_head_get_end_stream_omits_content_length() {
    let head = head_of(&req_with("GET", &[]), true);
    assert!(
        !head.contains("Content-Length"),
        "body-less GET must omit Content-Length, head:\n{head}"
    );
    assert!(!head.contains("Transfer-Encoding"), "head:\n{head}");
    // Same for HEAD.
    let head = head_of(&req_with("HEAD", &[]), true);
    assert!(
        !head.contains("Content-Length"),
        "body-less HEAD must omit Content-Length, head:\n{head}"
    );
    // The end-stream arm never declares trailers.
    let head = head_of(&req_with("GET", &[("trailer", "X-Checksum")]), true);
    assert!(
        !head.contains("Trailer:"),
        "no trailer announcement without a body, head:\n{head}"
    );
}

/// The complement of the GET/HEAD arm: every other method still gets
/// `Content-Length: 0` for a body-less request.
#[test]
fn h2_head_non_get_end_stream_keeps_content_length_zero() {
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND"] {
        let head = head_of(&req_with(method, &[]), true);
        assert!(
            head.contains("Content-Length: 0\r\n"),
            "{method} must announce Content-Length: 0, head:\n{head}"
        );
        assert!(
            !head.contains("Transfer-Encoding"),
            "{method} must not be chunked, head:\n{head}"
        );
    }
}

/// Go `transferWriter` re-announces declared trailer keys on the chunked
/// leg, right after the Transfer-Encoding line: split on ',', trimmed,
/// canonicalized, sorted, deduped, comma-joined WITHOUT a space. The raw
/// lowercase `trailer` declaration row stays dropped (hop-by-hop).
#[test]
fn h2_head_chunked_announces_trailers() {
    let head = head_of(&req_with("POST", &[("trailer", "X-T, b-key")]), false);
    assert!(
        head.contains("Transfer-Encoding: chunked\r\nTrailer: B-Key,X-T\r\n"),
        "canonical trailer line must follow the Transfer-Encoding line, head:\n{head}"
    );
    assert!(
        !head.contains("\r\ntrailer:"),
        "raw lowercase declaration must not be forwarded, head:\n{head}"
    );
}

/// Framing headers are never announced as trailers (Go skips
/// Transfer-Encoding/Trailer/Content-Length in the announcement loop).
#[test]
fn h2_head_trailer_framing_names_dropped() {
    let head = head_of(
        &req_with(
            "POST",
            &[("trailer", "Content-Length, Trailer, Transfer-Encoding")],
        ),
        false,
    );
    assert!(
        head.contains("Transfer-Encoding: chunked\r\n"),
        "chunked arm still frames the body, head:\n{head}"
    );
    assert!(
        !head.contains("Trailer:"),
        "framing names must not be announced, head:\n{head}"
    );
}

/// Audit round-7 S1 pin (mirrors the frp-server vhost_h2c
/// test_parse_response_head_textproto_eol shapes): response heads whose
/// EOLs are not CRLF throughout still parse. RED pre-fix: the strict
/// \r\n\r\n + \r\n scans returned None for every shape below (LF-only,
/// mixed, and CRLF-lines + LF-blank).
#[test]
fn parse_response_head_textproto_eol() {
    // LF-only backend response head.
    let head = b"HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 11\n\nbody";
    let parsed = parse_response_head(head).expect("LF-only head parses");
    assert_eq!(parsed.status, 200);
    assert_eq!(
        parsed.body_offset,
        head.len() - 4,
        "body starts after the LF blank line"
    );
    assert_eq!(
        header_value(&parsed.headers, "content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain"
    );
    assert_eq!(
        header_value(&parsed.headers, "content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "11"
    );
    // Mixed EOLs in one head: LF status line + CRLF headers + LF blank.
    let head = b"HTTP/1.1 200 OK\nX-A: 1\r\nX-B: 2\n\nbody";
    let parsed = parse_response_head(head).expect("mixed-EOL head parses");
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.body_offset, head.len() - 4);
    assert_eq!(
        header_value(&parsed.headers, "x-a")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );
    assert_eq!(
        header_value(&parsed.headers, "x-b")
            .unwrap()
            .to_str()
            .unwrap(),
        "2"
    );
    // CRLF status line + LF-only blank line (contains neither \r\n\r\n
    // nor the \r\n-scanned blank the pre-fix arithmetic expected).
    let head = b"HTTP/1.1 200 OK\r\nX-C: 3\n\nbody";
    let parsed = parse_response_head(head).expect("CRLF lines + LF blank parses");
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.body_offset, head.len() - 4);
    assert_eq!(
        header_value(&parsed.headers, "x-c")
            .unwrap()
            .to_str()
            .unwrap(),
        "3"
    );
}

// --- Round-18 M1: the version-token gate is Go ParseHTTPVersion's
// LENIENT shape (exact rows HTTP/1.0|HTTP/1.1, else exactly-8-char
// `HTTP/X.Y` with single ASCII digits), NOT the round-7 exact-switch
// misreading. HTTP/9.9-style response heads PARSE and forward; only
// shape violations fail. (The REQUEST faces keep their own major-1
// http1ServerSupportsRequest gates on top — those never see response
// heads.)
#[test]
fn parse_response_head_version_token_lenient_like_go() {
    for ok in ["HTTP/9.9", "HTTP/0.9", "HTTP/4.0", "HTTP/1.2", "HTTP/0.0"] {
        let head = format!("{ok} 200 OK\r\n\r\n");
        let parsed = parse_response_head(head.as_bytes())
            .unwrap_or_else(|| panic!("parseable proto {ok} must parse"));
        assert_eq!(parsed.status, 200, "{ok}");
    }
    for bad in [
        "HTTP/1.10",
        "HTTP/10.0",
        "HTTP/9.10",
        "FOO",
        "http/1.1",
        "XXXXX9.9",
    ] {
        let head = format!("{bad} 200 OK\r\n\r\n");
        assert!(
            parse_response_head(head.as_bytes()).is_none(),
            "shape-violating proto {bad:?} must fail"
        );
    }
}

// --- Round-18 M4: response-head rows are parsed with Go textproto
// ReadMIMEHeader semantics — obs-fold lines merge into the open
// record's value, and ANY malformed record fails the WHOLE head
// (502), never a silently dropped row.
#[test]
fn parse_response_head_m4_textproto_record_semantics() {
    // obs-fold: a SP/HTAB-leading line continues the open record with
    // ' ' + both-trimmed content (Go readContinuedLineSlice).
    let head = b"HTTP/1.1 200 OK\r\nX-A: one\r\n two\r\nX-B: y\r\n\r\n";
    let parsed = parse_response_head(head).expect("obs-fold head must parse");
    assert_eq!(
        header_value(&parsed.headers, "x-a")
            .unwrap()
            .to_str()
            .unwrap(),
        "one two",
        "folded continuation joins with a single space"
    );
    // An all-whitespace fold contributes a bare ' ' — trailing spaces
    // survive TrimLeft storage (round-17 R1 semantics).
    let head = b"HTTP/1.1 200 OK\r\nX-A: one\r\n \r\n\r\n";
    let parsed = parse_response_head(head).expect("all-space fold head must parse");
    assert_eq!(
        header_value(&parsed.headers, "x-a")
            .unwrap()
            .to_str()
            .unwrap(),
        "one ",
        "fold of an all-space line stores a trailing space"
    );
    // Malformed records fail the whole head (Go ReadMIMEHeader read-time
    // errors). The old code silently skipped each bad row and forwarded
    // the rest — RED on every shape below.
    for bad in [
        &b"HTTP/1.1 200 OK\r\nX-No-Colon here\r\n\r\n"[..], // colonless record
        &b"HTTP/1.1 200 OK\r\n: empty-name\r\n\r\n"[..],    // empty name
        &b"HTTP/1.1 200 OK\r\nX@Y: bad name byte\r\n\r\n"[..], // non-token name
        &b"HTTP/1.1 200 OK\r\nX-Y: a\x01b\r\n\r\n"[..],     // CTL 0x01 in value
        &b"HTTP/1.1 200 OK\r\nX-Y: a\x7fb\r\n\r\n"[..],     // DEL in value
        &b"HTTP/1.1 200 OK\r\n X-Y: leading fold\r\n\r\n"[..], // SP-leading block line
    ] {
        assert!(
            parse_response_head(bad).is_none(),
            "malformed record must fail the whole head: {:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // SPACE-in-name: Go tolerates it stored uncanonicalized (issue
    // 34540); http::HeaderName cannot represent it, so frp-rs fails the
    // head (fail-closed divergence, documented at parse_response_head).
    assert!(
        parse_response_head(b"HTTP/1.1 200 OK\r\nX Y: v\r\n\r\n").is_none(),
        "space-in-name must fail the head"
    );
    // obs-text value bytes are legal (Go validHeaderValueByte: VCHAR /
    // SP / HTAB / obs-text) and survive as raw bytes — no UTF-8 gate.
    let head = b"HTTP/1.1 200 OK\r\nX-Y: caf\xe9\r\n\r\n";
    let parsed = parse_response_head(head).expect("obs-text value must parse");
    assert_eq!(
        parsed.headers[0].1.as_bytes(),
        b"caf\xe9",
        "obs-text row keeps its raw bytes"
    );
}

// --- Round-18 M2: duplicate Content-Length rows resolve like Go's
// fixLength (net/http/transfer.go) — identical values dedupe to ONE
// row (Issue 16490), differing values fail the WHOLE head. readTransfer
// runs on every head ReadResponse draws, so the check lives in the
// shared parse (interim 1xx heads included).
#[test]
fn parse_response_head_duplicate_content_length_rows() {
    // Identical dup rows (case-variant names included) dedupe to one,
    // keeping the first row's value.
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\nbody";
    let parsed = parse_response_head(head).expect("identical dup CL dedupes");
    assert_eq!(parsed.headers.len(), 1);
    assert_eq!(parsed.headers[0].1.to_str().unwrap(), "5");
    // Differing values fail the whole head → the caller's 502.
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nbody";
    assert!(
        parse_response_head(head).is_none(),
        "conflicting duplicate Content-Length must fail the head"
    );
    // Duplicate non-CL rows keep BOTH rows (the copy loop appends; Go
    // copyHeader Add parity — Set-Cookie multi-values must survive).
    let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
    let parsed = parse_response_head(head).expect("dup non-CL rows keep both");
    assert_eq!(parsed.headers.len(), 2);
    assert_eq!(
        header_value(&parsed.headers, "set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
        "a=1"
    );
    assert_eq!(parsed.headers[1].1.to_str().unwrap(), "b=2");
}

// --- Round-18 deviation-3: parseContentLength value gate (Go
// net/http/transfer.go, server twin vhost_h2c.rs). readTransfer fails the
// WHOLE head on a garbage / empty / overflowing Content-Length, so the
// body leg must never fall back to read-body-to-EOF past a declared
// length (RED pre-fix: the garbage row was forwarded and the body read to
// EOF). The validated count rides out on ParsedHead because the stored
// row keeps its trailing SP/HTAB — re-parsing the raw row would reject
// the legal padded form "5 " this gate just TrimString'ed.
#[test]
fn parse_response_head_content_length_value_gate() {
    // Legal values carry the parsed count, padded row included
    // (textproto.TrimString: "5 " ≡ "5"); no CL row at all → None.
    for (head, want) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nbody"[..],
            Some(5u64),
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5 \r\n\r\nbody"[..],
            Some(5u64),
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 07\r\n\r\nbody"[..],
            Some(7u64),
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
            Some(0u64),
        ),
        (&b"HTTP/1.1 200 OK\r\nNo-Length: 5\r\n\r\nbody"[..], None),
    ] {
        let parsed = parse_response_head(head).expect("legal head parses");
        assert_eq!(
            parsed.content_length,
            want,
            "carried Content-Length wrong for {:?}",
            String::from_utf8_lossy(head)
        );
        // The stored row must ALSO reach the h2 head trimmed (h2 value
        // hygiene, RFC 9113 §8.2.1): a verbatim "5 " is rejected by the
        // h2 client with PROTOCOL_ERROR at the head, so the body leg
        // never runs.
        if let Some(v) = header_value(&parsed.headers, "content-length") {
            let bytes = v.as_bytes();
            assert!(
                !matches!(bytes.first(), Some(b' ' | b'\t'))
                    && !matches!(bytes.last(), Some(b' ' | b'\t')),
                "padded Content-Length row must be normalized: {:?}",
                String::from_utf8_lossy(head)
            );
        }
    }
    // parseContentLength failures: empty (both spellings), non-digit,
    // sign-prefixed (the digit gate rejects "+5" the way Go's ParseUint
    // does — leading zeros ARE legal), and anything past 2^63-1.
    for bad in [
        &b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775808\r\n\r\n"[..], // 2^63
    ] {
        assert!(
            parse_response_head(bad).is_none(),
            "parseContentLength failure must fail the whole head: {:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // The largest legal value (2^63-1) is accepted and carried verbatim.
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775807\r\n\r\n";
    let parsed = parse_response_head(head).expect("2^63-1 is legal");
    assert_eq!(parsed.content_length, Some(i64::MAX as u64));
}

// --- Round-18 FIX 2: Transfer-Encoding resolution is Go
// parseTransferEncoding (net/http/transfer.go): no row → not chunked;
// EXACTLY one row whose trimmed value EqualFolds "chunked" → chunked;
// anything else ("gzip", a list, two rows) fails readTransfer → the
// WHOLE head is malformed (the caller's 502). RED pre-fix: the
// `contains("chunked")` scan chunk-decoded "chunked, gzip" and read
// every other shape to EOF, forwarding bodies Go refuses.
#[test]
fn parse_response_head_transfer_encoding_go_strictness() {
    // Chunked spellings Go accepts: one row, EqualFold, padded value
    // legal (textproto TrimString storage).
    for ok in [
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding:  chunked \r\n\r\n"[..],
    ] {
        let parsed = parse_response_head(ok).expect("Go-legal chunked row parses");
        assert!(
            parsed.chunked,
            "single EqualFold chunked row must enable chunked framing: {:?}",
            String::from_utf8_lossy(ok)
        );
    }
    // No TE row at all → not chunked (the CL/EOF framings stay).
    let parsed = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .expect("head without TE parses");
    assert!(!parsed.chunked);
    // Shapes Go's parseTransferEncoding refuses → whole-head failure.
    for bad in [
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"[..], // other coding
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"[..], // list
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"[..], // list
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"[..], // two rows
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\n\r\n"[..], // empty value
    ] {
        assert!(
            parse_response_head(bad).is_none(),
            "unsupported Transfer-Encoding must fail the whole head: {:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // A garbage Content-Length under chunked still fails the head: the
    // CL gates run BEFORE the framing decision, like Go's readTransfer
    // (round-8 F9 semantics on the response face too).
    assert!(
        parse_response_head(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5x\r\n\r\n"
        )
        .is_none(),
        "garbage Content-Length must fail the head even under chunked"
    );
    // A VALID Content-Length under chunked parses (Go deletes the row
    // with the chunked framing — the wire-side strip is pinned by the
    // e2e below).
    let parsed = parse_response_head(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
    )
    .expect("valid CL under chunked parses");
    assert!(parsed.chunked);
}

// --- Audit FIX 2: interim 1xx heads are swallowed, the FINAL head is
// the h2 response (Go Transport readResponse loop parity). Harness: a
// scripted HTTP/1.1 backend + serve_h2_connection on one duplex end + a
// real h2 client on the other — the full h2 path the plugins serve.

/// Scripted backend: accept one conn, drain the forwarded request head,
/// then emit `staged` byte chunks with `delay_ms` between them; the conn
/// drops when the script ends.
fn spawn_scripted_backend(
    listener: TcpListener,
    staged: Vec<Vec<u8>>,
    delay_ms: u64,
) -> std::net::SocketAddr {
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Drain the request head the plugin forwards (the backend then
        // behaves like a server that read before replying).
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf).await;
        for (i, chunk) in staged.iter().enumerate() {
            if conn.write_all(chunk).await.is_err() {
                return;
            }
            if i + 1 < staged.len() && delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
        // conn drops here — the scripted end.
    });
    addr
}

/// Scripted backend that reads the forwarded request head, writes
/// `head` and then HOLDS the connection open. The FIX 1 pins need a
/// backend that never sends the body it declared (and never EOFs): the
/// pre-fix body leg parks on it forever and only the plugin's 10 s drain
/// deadline turns the regression into a failure — with a clean-EOF
/// backend the CL arm would instead RST (round-18 M3), a different
/// failure mode than the hang these pins target.
fn spawn_held_open_backend(listener: TcpListener, head: &'static [u8]) -> std::net::SocketAddr {
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf).await;
        if conn.write_all(head).await.is_err() {
            return;
        }
        // Hold the conn open: the body the response declared can never
        // come. Dropped when the test runtime shuts down.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    });
    addr
}

/// Bind an ephemeral listener, or report the sandbox and skip.
async fn bind_or_skip() -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => Some(l),
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            None
        }
    }
}

/// One request/response round through the real h2 plugin chain. Returns
/// (status, body bytes) and asserts the body stream ended CLEAN — a
/// backend-body truncation is exactly what the round-18 M3 pins must
/// observe, so the clean wrappers fail loudly if the stream was reset.
async fn h2_round_trip(backend_addr: std::net::SocketAddr) -> (http::StatusCode, Vec<u8>) {
    let (status, _headers, out, err) = h2_round_trip_core(backend_addr).await;
    assert!(
        err.is_none(),
        "clean-backend rounds must end with END_STREAM, got a stream error: {err:?}"
    );
    (status, out)
}

/// Round like [`h2_round_trip`] but also returns the response header
/// rows with duplicates preserved (the multi-value rows a backend sends
/// must all reach the h2 client — round-18 M2 Set-Cookie pin).
async fn h2_round_trip_full(
    backend_addr: std::net::SocketAddr,
) -> (http::StatusCode, Vec<(String, String)>, Vec<u8>) {
    let (status, headers, out, err) = h2_round_trip_core(backend_addr).await;
    assert!(
        err.is_none(),
        "clean-backend rounds must end with END_STREAM, got a stream error: {err:?}"
    );
    (status, headers, out)
}

/// [`h2_round_trip_full`] with an explicit request method — the round-18
/// FIX 1 pins drive HEAD through the same clean-end assertion.
async fn h2_round_trip_full_method(
    method: &str,
    backend_addr: std::net::SocketAddr,
) -> (http::StatusCode, Vec<(String, String)>, Vec<u8>) {
    let (status, headers, out, err) = h2_round_trip_core_method(method, backend_addr).await;
    assert!(
        err.is_none(),
        "clean-backend rounds must end with END_STREAM, got a stream error: {err:?}"
    );
    (status, headers, out)
}

/// Round like [`h2_round_trip`] but returns the body-stream error
/// instead of asserting it away (the round-18 M3 truncation pins).
async fn h2_round_trip_body_err(
    backend_addr: std::net::SocketAddr,
) -> (http::StatusCode, Vec<u8>, Option<h2::Error>) {
    let (status, _headers, out, err) = h2_round_trip_core(backend_addr).await;
    (status, out, err)
}

/// The shared round machinery: status + ordered header rows + body
/// bytes + the body-stream error. A stream error (Some) means the
/// plugin reset the stream; None means a clean END_STREAM. The drain
/// distinguishes them — the plain `while let Some(Ok(d))` form
/// swallowed resets into a silent clean end, which is precisely what
/// the M3 truncation pins must not do.
async fn h2_round_trip_core(
    backend_addr: std::net::SocketAddr,
) -> (
    http::StatusCode,
    Vec<(String, String)>,
    Vec<u8>,
    Option<h2::Error>,
) {
    h2_round_trip_core_method("GET", backend_addr).await
}

/// [`h2_round_trip_core`] with an explicit request method — the round-18
/// FIX 1 pins drive a HEAD request through the same machinery.
async fn h2_round_trip_core_method(
    method: &str,
    backend_addr: std::net::SocketAddr,
) -> (
    http::StatusCode,
    Vec<(String, String)>,
    Vec<u8>,
    Option<h2::Error>,
) {
    let (client_io, plugin_io) = tokio::io::duplex(1 << 17);
    let backend_host = backend_addr.ip().to_string();
    let backend_port = backend_addr.port();
    tokio::spawn(async move {
        let _ = serve_h2_connection(
            plugin_io,
            String::new(),
            String::new(),
            HashMap::new(),
            Backend::Plain {
                host: backend_host,
                port: backend_port,
            },
            "127.0.0.1".parse().unwrap(),
        )
        .await;
    });
    let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let req = http::Request::builder()
        .method(method)
        .uri("/probe")
        .body(())
        .unwrap();
    let (response, _) = send_request.send_request(req, true).unwrap();
    let resp = match tokio::time::timeout(std::time::Duration::from_secs(5), response).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("h2 request failed: {e}"),
        Err(_) => panic!("h2 request timed out"),
    };
    let status = resp.status();
    // Header rows in wire order; duplicates arrive as separate rows.
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let mut body = resp.into_body();
    let mut out = Vec::new();
    let mut stream_err: Option<h2::Error> = None;
    // Bounded body drain: a no-response regression that keeps the
    // stream open would hang an unbounded data() loop forever (the 5s
    // cap above bounds only the response HEAD, not the body).
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match body.data().await {
                Some(Ok(d)) => out.extend_from_slice(&d),
                Some(Err(e)) => {
                    stream_err = Some(e);
                    break;
                }
                None => break,
            }
        }
    })
    .await
    .expect("timed out draining the h2 response body — regression?");
    (status, headers, out, stream_err)
}

#[tokio::test]
async fn h2_backend_1xx_then_final_same_write_serves_final() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // Interim head + final head + body in ONE backend write: the
    // leftover-bytes-after-interim seed path (the final head must
    // replay from the seeded buffer, not be lost).
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/1.1 100 Continue\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec()],
        0,
    );
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, b"hello");
}

#[tokio::test]
async fn h2_backend_interim_1xx_split_writes_serves_final() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // 103 head, then (separate write, real delay) the final head — the
    // empty-seed second read path.
    let addr = spawn_scripted_backend(
        listener,
        vec![
            b"HTTP/1.1 103 Early Hints\r\nLink: </x.css>; rel=preload\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye".to_vec(),
        ],
        100,
    );
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, b"bye");
}

#[tokio::test]
async fn h2_backend_101_answers_502() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                .to_vec(),
        ],
        0,
    );
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::BAD_GATEWAY);
    assert!(body.is_empty(), "101 must answer 502, body: {body:?}");
}

#[tokio::test]
async fn h2_backend_close_after_1xx_answers_502() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // 100 head then the backend dies before the final head: the read
    // error mid-1xx-loop is a transport error — 502 (Go RoundTrip
    // semantics; the old code would have delivered the 100 to the
    // client as the response).
    let addr = spawn_scripted_backend(listener, vec![b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()], 0);
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::BAD_GATEWAY);
    assert!(
        body.is_empty(),
        "backend-death-after-1xx must answer 502, body: {body:?}"
    );
}

#[tokio::test]
async fn h2_backend_endless_1xx_over_budget_answers_502() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // An endless stream of interim 1xx heads. Go's http.Transport caps
    // the CUMULATIVE head bytes per RoundTrip at maxHeaderResponseSize
    // (10 MiB): pc.readLimit is set once per readLoop iteration
    // (transport.go:2274) and only re-armed inside ReadResponse's 1xx
    // loop when a trace hook is set (transport.go:2486-2490) — Go frp
    // sets none, so its single 10 MiB bucket covers interim and final
    // heads alike and an endless-1xx backend fails the RoundTrip. The
    // plugin mirrors that magnitude with INTERIM_HEAD_BUDGET (the final
    // head is bounded separately by read_until_head's 1 MiB per-head
    // cap — see the giant-final-head pin below). Pre-budget code
    // swallowed 1xx forever — the backend here never EOFs, so that code
    // went red only via the 5 s round-trip timeout below; the budget
    // trip answers 502 deterministically.
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Drain the forwarded request head (backend read before replying).
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf).await;
        // ~934 B per head: far under the 1 MiB per-head cap, so only the
        // cumulative 10 MiB budget can stop the stream. Emit forever —
        // the conn drops only when the plugin stops reading (502 sent).
        let mut interim = b"HTTP/1.1 100 Continue\r\nX-Pad: ".to_vec();
        interim.extend_from_slice(&[b'A'; 900]);
        interim.extend_from_slice(b"\r\n\r\n");
        loop {
            if conn.write_all(&interim).await.is_err() {
                return;
            }
        }
    });
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::BAD_GATEWAY);
    assert!(
        body.is_empty(),
        "endless-interim backend must answer 502, body: {body:?}"
    );
}

#[tokio::test]
async fn h2_backend_giant_final_head_answers_502() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // Audit FIX 4 pin (round-16 FIX 3 comment corrected): the 10 MiB
    // INTERIM_HEAD_BUDGET only accounts interim 1xx heads, but the
    // FINAL head is separately bounded — read_until_head caps EVERY
    // head (interim and final alike) at its 1 MiB per-call cap — so a
    // single giant final head (no 1xx at all) must answer 502 exactly
    // like any other oversized backend head, never stream through
    // unbounded. (Go parity direction: Go's single per-RoundTrip
    // maxHeaderResponseSize bucket — transport.go:2274, no trace-hook
    // re-arm in Go frp — would allow one 10 MiB final head; frp-rs's
    // 1 MiB per-head cap is the stricter pre-existing bound.)
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Drain the forwarded request head (backend read before replying).
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf).await;
        // ~1.2 MiB final head, terminator only at the very end. Written
        // in 64 KiB slices so the plugin's 4 KiB reads keep draining the
        // socket; once the 1 MiB cap trips the plugin sends 502 and
        // drops the conn — the remaining writes error and we return.
        let mut head = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        head.resize(1200 * 1024, b'A');
        head.extend_from_slice(b"\r\n\r\n");
        for chunk in head.chunks(64 * 1024) {
            if conn.write_all(chunk).await.is_err() {
                return;
            }
        }
    });
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::BAD_GATEWAY);
    assert!(
        body.is_empty(),
        "giant single final head must answer 502, body: {body:?}"
    );
}

// --- Round-18 M2: Go copyHeader does Header.Add per row — duplicate
// response rows all reach the caller. The old insert-per-row copy kept
// only the LAST duplicate (RED pre-fix: the client saw just
// "Set-Cookie: b=2").
#[tokio::test]
async fn h2_backend_duplicate_rows_all_reach_the_h2_client() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok"
                .to_vec(),
        ],
        0,
    );
    let (status, headers, body) = h2_round_trip_full(addr).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, b"ok");
    let cookies: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        cookies,
        ["a=1", "b=2"],
        "every backend Set-Cookie row must reach the h2 client"
    );
}

#[tokio::test]
async fn h2_backend_duplicate_content_length_go_fixlength_parity() {
    // Identical duplicate Content-Length rows collapse to ONE (Go
    // Issue 16490) and the body still reads clean.
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        0,
    );
    let (status, headers, body) = h2_round_trip_full(addr).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, b"ok");
    assert_eq!(
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .count(),
        1,
        "identical duplicate Content-Length rows must collapse to one on the wire"
    );

    // Differing duplicate Content-Length values fail the WHOLE head →
    // 502 (Go fixLength error → ReadResponse error). The old parse kept
    // both rows and answered 200 with a body framing that could not
    // match its headers — RED pre-fix.
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello".to_vec()],
        0,
    );
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(
        status,
        http::StatusCode::BAD_GATEWAY,
        "conflicting duplicate Content-Length must answer 502"
    );
    assert!(body.is_empty(), "502 carries no body: {body:?}");
}

// --- Round-18 M3: a backend body cut short of its framing NEVER ends
// clean. Go ReverseProxy's copyResponse aborts mid-body
// (panic(ErrAbortHandler)) and the h2 server answers the panic with
// RST_STREAM + INTERNAL_ERROR (h2_bundle.go handlerPanicRST) — a clean
// END_STREAM would read like a complete, valid response.
#[tokio::test]
async fn h2_backend_truncated_cl_body_resets_stream() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // Declared 10 body bytes, backend delivers 2 then drops the conn.
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi".to_vec()],
        0,
    );
    let (status, _body, err) = h2_round_trip_body_err(addr).await;
    assert_eq!(status, http::StatusCode::OK, "the head itself is valid");
    assert!(
        err.is_some(),
        "a Content-Length-bounded body cut short must reset the stream, not end clean \
         (RED pre-fix: clean END_STREAM)"
    );
}

#[tokio::test]
async fn h2_backend_truncated_chunked_body_resets_stream() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    // Chunked body cut MID-CHUNK: declares 5 bytes, delivers 2, then the
    // conn drops. The chunked walk's read error must abort the stream
    // (round-18 M3 extends the CL-arm fix here — Go copyResponse aborts
    // on every leg; the old chunked arm swallowed the error and ended
    // clean, RED pre-fix).
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe".to_vec()],
        0,
    );
    let (status, _body, err) = h2_round_trip_body_err(addr).await;
    assert_eq!(status, http::StatusCode::OK, "the head itself is valid");
    assert!(
        err.is_some(),
        "a chunked body cut mid-chunk must reset the stream, not end clean"
    );
}

// --- Round-18 M1 e2e: HTTP/9.9 is a PARSEABLE version token (Go
// ParseHTTPVersion lenient 8-char shape) — the response forwards, it
// does not 502. RED pre-fix: the round-7 exact-switch gate answered
// 502.
#[tokio::test]
async fn h2_backend_http_9_9_version_token_forwards() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/9.9 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        0,
    );
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(status, http::StatusCode::OK, "HTTP/9.9 head must forward");
    assert_eq!(body, b"ok");
}

// --- Round-18 FIX 1 e2e: HEAD / 204 / 304 responses end the h2 stream at
// the response head. The backend declares a body length (or omits all
// framing) and then HOLDS the connection open without ever sending the
// bytes — a HEAD response has no body by definition, 204/304 none by RFC
// — so the pre-fix body legs park on it (the drain deadline below turns
// that into a failure) and, on a backend EOF, the round-18 M3 CL arm
// would instead RST a truthful HEAD Content-Length as a truncated body.
#[tokio::test]
async fn h2_head_and_nobody_statuses_end_stream_at_the_head() {
    // HEAD → 200 keeps its truthful Content-Length: it describes the GET
    // the client would receive (RFC 9110 §8.6).
    let Some(listener) = bind_or_skip().await else {
        return;
    };
    let addr = spawn_held_open_backend(listener, b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
    let (status, headers, body) = h2_round_trip_full_method("HEAD", addr).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.as_str()),
        Some("100"),
        "a HEAD response keeps the declared Content-Length: {headers:?}"
    );
    assert!(body.is_empty(), "a HEAD response must carry no DATA body");

    // GET → 204 with a declared (lying) Content-Length: the CL body-leg
    // shape, and the CL row must be stripped (RFC 9110 §8.6).
    let Some(listener) = bind_or_skip().await else {
        return;
    };
    let addr = spawn_held_open_backend(
        listener,
        b"HTTP/1.1 204 No Content\r\nContent-Length: 50\r\n\r\n",
    );
    let (status, headers, body) = h2_round_trip_full_method("GET", addr).await;
    assert_eq!(status, http::StatusCode::NO_CONTENT);
    assert!(
        !headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length")),
        "204 must not carry Content-Length: {headers:?}"
    );
    assert!(body.is_empty(), "204 must carry no DATA body");

    // GET → 304 with NO length framing: the read-to-EOF body-leg shape
    // (the pre-fix leg blocks on the held-open conn).
    let Some(listener) = bind_or_skip().await else {
        return;
    };
    let addr = spawn_held_open_backend(listener, b"HTTP/1.1 304 Not Modified\r\n\r\n");
    let (status, headers, body) = h2_round_trip_full_method("GET", addr).await;
    assert_eq!(status, http::StatusCode::NOT_MODIFIED);
    assert!(
        !headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length")),
        "304 must not carry Content-Length: {headers:?}"
    );
    assert!(body.is_empty(), "304 must carry no DATA body");
}

// --- Round-18 FIX 2 e2e: a Transfer-Encoding Go's parseTransferEncoding
// refuses ("gzip") fails the WHOLE head — the same 502 class as every
// other malformed backend head. RED pre-fix: not chunked and no CL meant
// the body leg read to EOF and forwarded a 200 with the backend's bytes.
#[tokio::test]
async fn h2_backend_unsupported_transfer_encoding_answers_502() {
    let Some(listener) = bind_or_skip().await else {
        return;
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nJUNK".to_vec()],
        0,
    );
    let (status, body) = h2_round_trip(addr).await;
    assert_eq!(
        status,
        http::StatusCode::BAD_GATEWAY,
        "an unsupported Transfer-Encoding must answer 502"
    );
    assert!(body.is_empty(), "502 carries no body: {body:?}");
}

// --- Round-18 FIX 3 e2e: a chunked response must not forward the
// backend's Content-Length row. Go deletes it once chunked framing wins
// (net/http/transfer.go); RFC 9113 §8.1.1 lets an h2 peer fail the
// stream on a declared length that disagrees with the decoded DATA
// length. RED pre-fix: the copy loop kept the row (only hop-by-hop
// names were skipped).
#[tokio::test]
async fn h2_backend_chunked_response_strips_content_length() {
    let Some(listener) = bind_or_skip().await else {
        return;
    };
    let addr = spawn_scripted_backend(
        listener,
        vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n\
              5\r\nhello\r\n0\r\n\r\n"
                .to_vec(),
        ],
        0,
    );
    let (status, headers, body) = h2_round_trip_full(addr).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, b"hello", "the chunked body still decodes");
    assert!(
        !headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length")),
        "a chunked response must drop the backend Content-Length row: {headers:?}"
    );
}
