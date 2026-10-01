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
        0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // session_id_len = 0
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

    let data =
        b"GET / HTTP/1.1\r\nHost: old.example.com\r\n\r\nbody\r\nhost: evil.example.com".to_vec();
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
    // to the 24h cap. Above it (incl. i64::MAX from a hostile config)
    // the value would overflow the `Instant::now() + from_secs` deadline
    // add at serve_vhost_request / serve_h2c_request — an abort under
    // the release `panic=abort` profile — so it clamps instead.
    assert_eq!(clamp_vhost_timeout(0), 60);
    assert_eq!(
        clamp_vhost_timeout(-1),
        60,
        "Go's int64 accepts a negative flag/config value; the floor is what gives it meaning"
    );
    assert_eq!(clamp_vhost_timeout(i64::MIN), 60);
    assert_eq!(clamp_vhost_timeout(1), 1);
    assert_eq!(clamp_vhost_timeout(30), 30);
    assert_eq!(clamp_vhost_timeout(60), 60);
    assert_eq!(clamp_vhost_timeout(120), 120);
    assert_eq!(
        clamp_vhost_timeout(VHOST_TIMEOUT_CAP_SECS as i64),
        VHOST_TIMEOUT_CAP_SECS
    );
    assert_eq!(
        clamp_vhost_timeout(VHOST_TIMEOUT_CAP_SECS as i64 + 1),
        VHOST_TIMEOUT_CAP_SECS
    );
    assert_eq!(clamp_vhost_timeout(i64::MAX), VHOST_TIMEOUT_CAP_SECS);
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
        count_host_headers("GET / HTTP/1.1\r\nHost: a.example.com\r\n Host: b.example.com\r\n\r\n"),
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
    let RequestLine::Ok { host, .. } = parse_vhost_request_line("GET / HTTP/1.1\r\n\r\n") else {
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
    .expect("HTTPS custom_domains=[\"\",\"\"] must be accepted (Go buildDomains skips empties)");
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
        None,
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
        host_header_rewrite_sanitized: "".into(),
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

/// Empty inbound Host → the X-Forwarded-Host line is emitted WITH AN
/// EMPTY VALUE (go1.25 `SetXForwarded` sets `X-Forwarded-Host` to
/// `r.In.Host` UNCONDITIONALLY — no `!= ""` guard — and an HTTP/1.0
/// request with no Host header ships `Header.Set(k, "")`, which Go
/// serializes as `X-Forwarded-Host: ` + CRLF exactly like any other
/// empty-value header line). Round-13 audit flipped the old
/// "omitted-on-empty" pin to the source-verified semantics.
#[test]
fn inject_xfh_empty_value_when_host_empty() {
    let head = b"GET / HTTP/1.1\r\n\r\n".to_vec();
    let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
    let out = inject_vhost_request_headers(head, peer, "", &[]);
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("X-Forwarded-Host: \r\n"),
        "empty inbound Host must emit an empty-value X-Forwarded-Host: {text:?}"
    );
    assert!(text.contains("X-Forwarded-For: 192.0.2.55\r\n"), "{text:?}");
    assert!(text.contains("X-Forwarded-Proto: http\r\n"), "{text:?}");
}

/// An EMPTY-VALUED inbound `X-Forwarded-For:` line survives into the
/// chain — Go `SetXForwarded` joins the prior value slice with ", " and
/// an empty element is not skipped (`["", ip]` → ", ip"), so the
/// re-emitted line keeps its leading ", ". Round-13 review B8: the
/// empty-value shape had no pin.
#[test]
fn inject_xff_empty_value_kept_in_chain() {
    let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));

    // Single empty-valued line → ", peer" (empty element + separator).
    let head = b"GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For:\r\n\r\nbody".to_vec();
    let out = inject_vhost_request_headers(head, peer, "app.example.com", &[]);
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("X-Forwarded-For: , 192.0.2.55\r\n"),
        "empty XFF value must survive as a leading empty element: {text:?}"
    );
    assert!(
        text.ends_with("\r\n\r\nbody"),
        "body must survive: {text:?}"
    );

    // Empty first line + non-empty second → ", 203.0.113.1, peer"
    // (Go Header.Get / Join element order).
    let multi = b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\
          X-Forwarded-For:\r\nX-Forwarded-For: 203.0.113.1\r\n\r\nbody"
        .to_vec();
    let out = inject_vhost_request_headers(multi, peer, "app.example.com", &[]);
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("X-Forwarded-For: , 203.0.113.1, 192.0.2.55\r\n"),
        "element order must follow the inbound lines: {text:?}"
    );
}

/// Client-supplied X-Forwarded-Host / X-Forwarded-Proto / Forwarded
/// lines are STRIPPED and re-emitted as the canonical single line (Go
/// go1.25 reverseproxy.go:434-437 deletes all three before the Rewrite
/// hook; SetXForwarded re-Sets the two X-Forwarded names, `Forwarded`
/// is never re-added). An invented lookalike (`x-forwarded-hostile`)
/// is not stripped.
#[test]
fn inject_strips_client_forwarded_lines() {
    let head = b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\
        X-Forwarded-For: 203.0.113.1\r\n\
        X-Forwarded-Host: spoofed.example.com\r\n\
        X-Forwarded-Proto: https\r\n\
        Forwarded: for=1.2.3.4\r\n\
        x-forwarded-hostile: keep-me\r\n\r\n"
        .to_vec();
    let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
    let out = inject_vhost_request_headers(head, peer, "app.example.com", &[]);
    let text = String::from_utf8(out).unwrap();
    assert!(
        !text.contains("spoofed.example.com"),
        "client X-Forwarded-Host must not survive: {text:?}"
    );
    assert!(
        !text.contains("Forwarded: for="),
        "client Forwarded must not survive: {text:?}"
    );
    // Canonical single lines: XFH = inbound Host, XFP = http, XFF
    // chained with the peer — and exactly ONE of each.
    assert_eq!(
        text.matches("X-Forwarded-Host: ").count(),
        1,
        "exactly one canonical X-Forwarded-Host: {text:?}"
    );
    assert_eq!(
        text.matches("X-Forwarded-Proto: ").count(),
        1,
        "exactly one canonical X-Forwarded-Proto: {text:?}"
    );
    assert!(
        text.contains("X-Forwarded-Host: app.example.com\r\n"),
        "{text:?}"
    );
    assert!(text.contains("X-Forwarded-Proto: http\r\n"), "{text:?}");
    // XFF chained (empty join semantics untouched by the strip).
    assert!(
        text.contains("X-Forwarded-For: 203.0.113.1, 192.0.2.55\r\n"),
        "{text:?}"
    );
    assert!(
        text.contains("x-forwarded-hostile: keep-me\r\n"),
        "lookalike header must survive the exact-name strip: {text:?}"
    );
}

/// obs-fold continuation lines (RFC 7230 §3.2.4 — leading SP/HT)
/// BELONG to the previous logical header. Go's textproto unfolds before
/// any header logic, so a stripped header takes its continuations with
/// it — a leftover fold tail must not obs-fold onto the preceding kept
/// `Host` line at the backend (round-13 review, 2 independent
/// reviewers), and an XFF fold tail joins the chained value with a
/// single space (Go readContinuedLineSlice).
#[test]
fn inject_folded_stripped_and_xff_lines_swallow_continuations() {
    // One literal line: Rust `\` string continuation would eat the fold
    // lines' leading spaces (obs-fold is leading SP/HT — must be real
    // bytes).
    let head = b"GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-Host: evil.example.com\r\n fold-tail-1\r\nX-Forwarded-For: 203.0.113.1\r\n 5.6.7.8\r\nx-kept: v\r\n\r\nbody"
        .to_vec();
    let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
    let out = inject_vhost_request_headers(head, peer, "app.example.com", &[]);
    let text = String::from_utf8(out).unwrap();
    // The stripped header and its fold tail are gone whole — the tail
    // must not survive as a dangling line that obs-folds onto `Host`
    // (backend would read `Host: app.example.com fold-tail-1`).
    assert!(
        !text.contains("fold-tail-1"),
        "fold continuation of a stripped header must not survive: {text:?}"
    );
    // The XFF fold tail joined the chained value (single space, Go
    // unfold) — no dangling continuation line in the emitted head.
    assert!(
        text.contains("X-Forwarded-For: 203.0.113.1 5.6.7.8, 192.0.2.55\r\n"),
        "folded XFF value must chain as one logical value: {text:?}"
    );
    assert!(
        !text.contains("\r\n 5.6.7.8"),
        "no dangling XFF continuation line: {text:?}"
    );
    assert!(text.contains("x-kept: v\r\n"), "{text:?}");
    assert!(text.ends_with("\r\nbody"), "body tail untouched: {text:?}");
}

/// A requestHeaders override swallows the backend header's folded
/// continuation lines too (Go Header.Set replaces the whole unfolded
/// logical header).
#[test]
fn inject_override_drops_folded_header_whole() {
    let head = b"GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Custom: a\r\n b\r\n\r\n".to_vec();
    let peer = std::net::SocketAddr::from(([192, 0, 2, 55], 4242));
    let overrides = [("X-Custom".to_string(), "cfg".to_string())];
    let out = inject_vhost_request_headers(head, peer, "app.example.com", &overrides);
    let text = String::from_utf8(out).unwrap();
    assert!(
        !text.contains("X-Custom: a"),
        "backend value must be replaced (Set semantics): {text:?}"
    );
    assert!(
        !text.contains("\r\n b\r\n"),
        "fold tail of the replaced header must not dangle: {text:?}"
    );
    assert!(
        text.contains("X-Custom: cfg\r\n"),
        "configured value alone: {text:?}"
    );
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
            let r = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut buf))
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

    // Round-18 ordering pins (Go conn.serve): the read-time header-block
    // classes are classified BEFORE the dup-Host / 505 / missing-Host
    // gates, so a multi-defect head takes the GENERIC 400 — Go's
    // ReadMIMEHeader error returns before conn.readRequest reaches those
    // gates. RED pre-fix: the fold-first head without a Host answered
    // "missing required Host header" and the HTTP/2.0 one answered 505.
    let generic_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request";

    // obs-fold FIRST header line (no header to continue) + no Host line:
    // textproto "malformed MIME header initial line" → generic 400, NOT
    // the missing-Host gate's detailed 400.
    let fold_no_host = respond(state.clone(), b"GET / HTTP/1.1\r\n fold: x\r\n\r\n").await;
    assert_eq!(
        fold_no_host, generic_400,
        "a fold-first head read-time error precedes the missing-Host gate (Go conn.serve)"
    );

    // The same head under a 505-classified version: the read-time error
    // precedes http1ServerSupportsRequest too → generic 400, NOT 505.
    let fold_505 = respond(state.clone(), b"GET / HTTP/2.0\r\n fold: x\r\n\r\n").await;
    assert_eq!(
        fold_505, generic_400,
        "a fold-first head read-time error precedes the 505 version gate (Go conn.serve)"
    );

    // A fold whose content LOOKS like a Host header is still a fold —
    // Go's textproto fails the initial line before any Host line is
    // stored, so this stays the same generic 400 class (never the
    // missing-Host render, never a route on the folded value).
    let fold_host = respond(state.clone(), b"GET / HTTP/1.1\r\n Host: a.com\r\n\r\n").await;
    assert_eq!(
        fold_host, generic_400,
        "a fold-wrapped \"Host: a.com\" line is never a Host header (Go textproto initial-line error)"
    );

    // Non-malformed flow unchanged: a well-formed head still routes
    // (unregistered host → Go's 404 route-miss page).
    let ok_head = respond(state.clone(), b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n").await;
    assert!(
        ok_head.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
        "a well-formed head must keep routing (404 route miss), got: {:?}",
        String::from_utf8_lossy(&ok_head)
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

/// FIX 5: Go readRequest `validMethod` — a non-empty RFC 7230 token.
/// All shapes below answer Go's generic 400 (probes vs go1.25: same
/// 103 bytes as the parse-failure render), so every one maps to
/// `BadRequest`. The leading-space line fails on its version token
/// (shape gate) and the empty-method " / HTTP/1.1" on the token check —
/// Go rejects "" via httpguts.ValidHeaderFieldName.
#[test]
fn test_parse_vhost_request_line_method_token() {
    // Paren method — validMethod fails (probe: generic 400).
    assert_eq!(
        parse_vhost_request_line("GET( / HTTP/1.1\r\nHost: a.com\r\n\r\n"),
        RequestLine::BadRequest
    );
    // Tab-joined method — isToken fails on \t (probe: generic 400).
    assert_eq!(
        parse_vhost_request_line("GET\tFOO / HTTP/1.1\r\nHost: a.com\r\n\r\n"),
        RequestLine::BadRequest
    );
    // Empty method (leading-space line — probe: generic 400).
    assert_eq!(
        parse_vhost_request_line(" / HTTP/1.1\r\nHost: a.com\r\n\r\n"),
        RequestLine::BadRequest
    );
    // Leading-space line with a real method — the version token is
    // contaminated ("/ HTTP/1.1") → shape gate (probe: generic 400).
    assert_eq!(
        parse_vhost_request_line(" GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"),
        RequestLine::BadRequest
    );
    // A non-token method 400s even when the version would 505 (Go's
    // validMethod runs before ParseHTTPVersion — request.go:1101-1104).
    assert_eq!(
        parse_vhost_request_line("GET( / HTTP/2.0\r\nHost: a.com\r\n\r\n"),
        RequestLine::BadRequest
    );
    // Method token bounds: all-tchar extension methods route.
    let RequestLine::Ok { .. } =
        parse_vhost_request_line("M-SEARCH * HTTP/1.1\r\nHost: a.com\r\n\r\n")
    else {
        panic!("tchar-only method must route");
    };
}

/// FIX 6: Go conn.readRequest server-layer head validation classes
/// (server.go:1061-1072), probe-verified vs go1.25.
#[test]
fn test_validate_vhost_head_lines_verdicts() {
    // Clean head (the common case) validates Ok.
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nX-A: v\r\n\r\n"),
        HeadLineVerdict::Ok
    );
    // obs-text (0x80+) in a value is legal — textproto + httpguts both
    // allow it (probe: 200 served). Multi-byte chars model the lossy
    // path's obs-text bytes (every byte >= 0x20, never a CTL).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nX-A: aé b\r\n\r\n"),
        HeadLineVerdict::Ok
    );
    // Class 3: a space in the single Host value → detailed malformed
    // Host (probe: ": malformed Host header" on status line + body).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com b.com\r\n\r\n"),
        HeadLineVerdict::Detailed("400 Bad Request: malformed Host header")
    );
    // obs-fold after the Host line merges a SP into the value → the
    // same detailed malformed Host (Go readContinuedLineSlice joins
    // with a single space).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\n folded\r\n\r\n"),
        HeadLineVerdict::Detailed("400 Bad Request: malformed Host header")
    );
    // A trailing-OWS Host value is trimmed first — no false detail
    // (Go line-level TrimSpace runs before the ValidHostHeader gate).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com  \r\n\r\n"),
        HeadLineVerdict::Ok
    );
    // Empty-valued Host passes (ValidHostHeader("") == true).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost:\r\n\r\n"),
        HeadLineVerdict::Ok
    );
    // Class 4: a SPACE-containing name reaches the http layer →
    // detailed invalid header name (probe: Go textproto stores
    // "Bad Name" verbatim, server.go:1065 rejects the non-token key).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nBad Name: x\r\n\r\n"),
        HeadLineVerdict::Detailed("400 Bad Request: invalid header name")
    );
    // Class 1 + class 2 generics: CTL bytes in values and non-token
    // non-space name bytes are textproto read-time errors → generic
    // (probes: CTL-in-host-value / paren-name / DEL-in-name all
    // answer the bare generic 400, never a detail).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.co\x01m\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nBad(Name: x\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nX-A: a\x7fb\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\n: x\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines(
            "GET / HTTP/1.1\r\nHost: a.com\r\nX-Bad: v\r\n\tfold\x01c\r\n\r\n"
        ),
        HeadLineVerdict::Malformed
    );
    // Round-16 (SP/HTAB-only trims): an EDGE CTL byte survives the
    // value/fold trim exactly like Go's reader.go trim — bufio elides
    // only the \r\n terminator, so a `\r\r\n` line keeps its second
    // `\r` in the value; a trailing \x0b (and \x0c) is CTL; a `\r`
    // opening the fold contents after its leading SP errors too. All
    // generic 400s (probe: Go 400). Pre-fix the Rust Unicode-
    // whitespace trims stripped these edges and the head routed.
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nX-A: v\r\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\nHost: a.com\nX-A: v\x0b\n\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nX-A: v\r\n \rv\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    // The edge-CTL rejection applies to the Host line's own value too —
    // the generic read-time class beats the ValidHostHeader detail.
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    // Generic read-time classes beat the statusError details (Go
    // rejects during ReadMIMEHeader, before the host/name gates):
    // a space-name head that ALSO carries a CTL value answers generic.
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nHost: a.com\r\nBad Name: a\x01b\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    // obs-fold continuation after the REQUEST line — Go textproto
    // "malformed MIME header initial line" → generic.
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\n Host: a.com\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    // Round-18: the fold-first class is Host- and version-independent —
    // the verdict feeding the caller's early generic-400 arm (before
    // the dup-Host / 505 / missing-Host gates) is Malformed either way.
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\n fold: x\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/2.0\r\n fold: x\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
    // Round-15 W1: a group-first line without a colon is Go
    // textproto's missing-colon read-time error (reader.go:543-545) —
    // generic 400, never routed. This used to `continue` (forwarded).
    assert_eq!(
        validate_vhost_head_lines(
            "GET / HTTP/1.1\r\nHost: a.com\r\nno colon here\r\nX-A: v\r\n\r\n"
        ),
        HeadLineVerdict::Malformed
    );
    // The blank terminator itself never reaches the missing-colon
    // class: CRLFCRLF (the single terminal `""` element `str::lines()`
    // yields for a terminated head), LF-only, and a pipelined
    // next-request body past the blank all validate the head and stop
    // at the first empty line (the round-14 tcpmux 9ff87ca trap,
    // mirrored — a blank ends the header block like Go textproto
    // readMIMEHeader).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\n\r\n"),
        HeadLineVerdict::Ok
    );
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\nHost: a.com\n\n"),
        HeadLineVerdict::Ok
    );
    assert_eq!(
        validate_vhost_head_lines(
            "GET / HTTP/1.1\r\nHost: a.com\r\n\r\nGET / HTTP/1.1\r\nX-A: v\r\n\r\n"
        ),
        HeadLineVerdict::Ok
    );
    // A colonless line between blank-terminated halves is still read
    // (headers precede the blank).
    assert_eq!(
        validate_vhost_head_lines("GET / HTTP/1.1\r\nno colon here\r\n\r\n"),
        HeadLineVerdict::Malformed
    );
}
