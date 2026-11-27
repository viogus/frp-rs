use super::*;

/// M9 pin: the real-tunnel-peer registry is take-once per dialer port,
/// newest registration wins on port reuse (a stale entry from an earlier
/// conn must not shadow the current dial), and unknown ports miss.
#[cfg(feature = "tls")] // take_plugin_peer/plugin_peer_ip are tls-only
#[test]
fn real_tunnel_peer_registry_take_once() {
    let dialer = SocketAddr::from(([127, 0, 0, 1], 44444));
    // The guard keeps the entry alive for its registration's lifetime
    // (F5). Take-once: the accept handler consumes the entry.
    let _g1 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 7], 5555)));
    assert_eq!(
        plugin_peer_ip_now(dialer),
        std::net::IpAddr::V4("203.0.113.7".parse().unwrap())
    );
    assert_eq!(take_plugin_peer(dialer.port()), None);
    // Overwrite on dialer-port reuse (kernel ephemeral recycle).
    let _g2 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 8], 5556)));
    let _g3 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 9], 5557)));
    assert_eq!(
        plugin_peer_ip_now(dialer),
        std::net::IpAddr::V4("203.0.113.9".parse().unwrap())
    );
    // Unknown port → miss (health-check/stray dials fall back to peer.ip()).
    assert_eq!(take_plugin_peer(1), None);
}

/// F5 pin: a dropped guard removes its own registry entry, so every
/// work-conn exit path (normal end, early return, abort) cleans up.
#[cfg(feature = "tls")] // take_plugin_peer is tls-only
#[test]
fn plugin_peer_guard_drop_removes_entry() {
    let dialer = SocketAddr::from(([127, 0, 0, 1], 44445));
    let real = SocketAddr::from(([203, 0, 113, 7], 5555));
    let guard = register_plugin_peer(dialer.port(), real);
    assert_eq!(take_plugin_peer(dialer.port()), Some(real));
    // Consumed entries are gone; dropping the guard is a no-op.
    drop(guard);
    assert_eq!(take_plugin_peer(dialer.port()), None);

    // Un-consumed entry: the guard drop removes it (the work-conn task
    // ended before the accept handler ran).
    let guard = register_plugin_peer(dialer.port(), real);
    drop(guard);
    assert_eq!(take_plugin_peer(dialer.port()), None);
}

/// F5 pin: a guard from a SUPERSEDED registration must not delete its
/// successor's live entry (newest-registration-wins on port recycle).
#[cfg(feature = "tls")] // take_plugin_peer is tls-only
#[test]
fn plugin_peer_guard_drop_keeps_newer_entry() {
    let dialer = SocketAddr::from(([127, 0, 0, 1], 44446));
    let g2 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 8], 5556)));
    let _g3 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 9], 5557)));
    // g2's registration was overwritten: dropping g2 must NOT remove the
    // live g3 entry.
    drop(g2);
    assert_eq!(
        take_plugin_peer(dialer.port()),
        Some(SocketAddr::from(([203, 0, 113, 9], 5557)))
    );
}

/// F5 pin: serve_plugin teardown's wholesale clear empties the registry
/// (defense in depth for connections whose guard never ran).
#[cfg(feature = "tls")] // take_plugin_peer is tls-only
#[test]
fn clear_plugin_peers_empties_registry() {
    let dialer = SocketAddr::from(([127, 0, 0, 1], 44447));
    let _g = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 7], 5555)));
    let _g2 = register_plugin_peer(44448, SocketAddr::from(([203, 0, 113, 7], 5556)));
    clear_plugin_peers();
    assert_eq!(take_plugin_peer(dialer.port()), None);
    assert_eq!(take_plugin_peer(44448), None);
    assert_eq!(
        real_tunnel_peer_map()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
        0
    );
}

/// Sync resolution for the test above (plugin_peer_ip's retry loop would
/// add 8 ms per miss; here the entry always exists on the first attempt).
#[cfg(feature = "tls")] // take_plugin_peer is tls-only
fn plugin_peer_ip_now(peer: SocketAddr) -> std::net::IpAddr {
    take_plugin_peer(peer.port())
        .map(|a| a.ip())
        .unwrap_or(peer.ip())
}

/// Notify-backed resolution wakes immediately when a concurrent dialer
/// registers its mapping after `plugin_peer_ip` has already checked the map.
#[cfg(feature = "tls")]
#[tokio::test]
async fn plugin_peer_ip_wakes_on_concurrent_registration() {
    let dialer = SocketAddr::from(([127, 0, 0, 1], 44449));
    let real = SocketAddr::from(([198, 51, 100, 42], 6000));
    let resolver = tokio::spawn(plugin_peer_ip(dialer));
    tokio::task::yield_now().await;
    let _guard = register_plugin_peer(dialer.port(), real);
    let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), resolver)
        .await
        .expect("resolver must wake promptly")
        .expect("resolver task must not panic");
    assert_eq!(resolved, real.ip());
}

/// Fake AsyncRead for BodyReader tests: serves a fixed byte blob in
/// fixed-size chunks, counting the bytes handed out in a shared counter
/// (readable while the reader still borrows the stream).
struct FakeStream {
    data: Vec<u8>,
    chunk: usize,
    pos: usize,
    served: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl FakeStream {
    fn new(data: Vec<u8>, chunk: usize) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Self {
                data,
                chunk,
                pos: 0,
                served: served.clone(),
            },
            served,
        )
    }
}

impl tokio::io::AsyncRead for FakeStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos >= self.data.len() {
            return std::task::Poll::Ready(Ok(()));
        }
        let n = (self.data.len() - self.pos)
            .min(self.chunk)
            .min(buf.remaining());
        buf.put_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.served
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        std::task::Poll::Ready(Ok(()))
    }
}

/// Property guard, not a placement-regression catch: the bytes consumed
/// for an over-long stream-delivered line stay bounded near the cap —
/// at most one 4096-byte chunk past the boundary, never the whole
/// over-long line. This also held on the pre-fix code (its cap check
/// ran one iteration later and errored at the same byte count with the
/// same kind/message); the genuinely new cap enforcement on the
/// terminator-found paths is covered by
/// `read_line_caps_over_long_pending_line` (pending branch) and
/// `read_line_terminates_on_stream_line` (stream-terminator scanning).
#[tokio::test]
async fn read_line_caps_over_long_stream_line() {
    let mut data = vec![b'x'; CHUNK_LINE_MAX + 8192];
    data.push(b'\n');
    let total = data.len();
    let (stream, served) = FakeStream::new(data, 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &[]);
    let err = reader.read_line(CHUNK_LINE_MAX).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let served = served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(served > CHUNK_LINE_MAX, "the cap must have been crossed");
    assert!(
        served <= CHUNK_LINE_MAX + 4096,
        "read {served} bytes past a {CHUNK_LINE_MAX} cap"
    );
    assert!(
        served < total,
        "the whole over-long line must not be consumed"
    );
}

/// Regression: a line delivered via the stream (not coalesced with the
/// head) must still terminate. Previously only the pending prefix was
/// scanned for `\n`, so a stream-delivered line ran to EOF ("eof in
/// line") and the chunked forward failed. Bytes past the terminator
/// must stay staged for the next reads (chunk data, CRLF, next line).
#[tokio::test]
async fn read_line_terminates_on_stream_line() {
    let (stream, _served) = FakeStream::new(b"5\r\nhello\r\n0\r\n\r\n".to_vec(), 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &[]);
    let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
    assert_eq!(line, b"5\r\n");
    let mut buf = [0u8; 5];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await.unwrap();
    assert_eq!(&crlf, b"\r\n");
    assert_eq!(reader.read_line(CHUNK_LINE_MAX).await.unwrap(), b"0\r\n");
    assert_eq!(reader.read_line(CHUNK_LINE_MAX).await.unwrap(), b"\r\n");
}

/// The `\r` of a CRLF at the end of one stream chunk with the `\n`
/// opening the next must still terminate the line (only `\n` is
/// scanned for), and the bytes past the terminator must be staged.
#[tokio::test]
async fn read_line_crlf_split_across_stream_chunks() {
    // Stream reads are 4096 bytes: 4095 x's plus `\r` fill the first
    // read, `\n` opens the second — the worst-case split.
    let mut data = vec![b'x'; 4095];
    data.extend_from_slice(b"\r\nhello\r\n");
    let (stream, _served) = FakeStream::new(data, 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &[]);
    let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
    assert_eq!(line.len(), 4097);
    assert!(line[..4095].iter().all(|&b| b == b'x'));
    assert!(line.ends_with(b"\r\n"));
    // The next line ("hello\r\n") was staged, not lost.
    let mut buf = [0u8; 5];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await.unwrap();
    assert_eq!(&crlf, b"\r\n");
}

/// A partial line followed by EOF must error ("eof in line"), never
/// return the truncated line.
#[tokio::test]
async fn read_line_eof_mid_line_errors() {
    let (stream, _served) = FakeStream::new(b"hello".to_vec(), 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &[]);
    let err = reader.read_line(CHUNK_LINE_MAX).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    assert_eq!(err.to_string(), "eof in line");
}

/// A line delivered entirely with the head is served from the pending
/// prefix without touching the stream (existing behavior preserved).
#[tokio::test]
async fn read_line_serves_pending_prefix_line() {
    let (stream, served) = FakeStream::new(Vec::new(), 4096);
    let mut boxed = Box::new(stream);
    let prefix = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
    let mut reader = BodyReader::new(&mut boxed, &prefix);
    assert_eq!(reader.read_line(CHUNK_LINE_MAX).await.unwrap(), b"5\r\n");
    assert_eq!(
        served.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the stream must not be read"
    );
    let mut buf = [0u8; 5];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}

/// A line exactly `max` bytes long (terminator included) is accepted;
/// only EXCEEDING the cap errors.
#[tokio::test]
async fn read_line_accepts_line_at_cap() {
    let mut data = vec![b'x'; CHUNK_LINE_MAX - 1];
    data.push(b'\n');
    let (stream, _served) = FakeStream::new(data, 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &[]);
    let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
    assert_eq!(line.len(), CHUNK_LINE_MAX);
    assert!(line.ends_with(b"\n"));
}

/// A line exactly `max` bytes long delivered via the pending prefix is
/// accepted (boundary is `>` not `>=`); the stream-path boundary is
/// covered by `read_line_accepts_line_at_cap`.
#[tokio::test]
async fn read_line_accepts_at_cap_pending_prefix_line() {
    let mut prefix = vec![b'x'; CHUNK_LINE_MAX - 1];
    prefix.push(b'\n');
    let (stream, served) = FakeStream::new(Vec::new(), 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &prefix);
    let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
    assert_eq!(line.len(), CHUNK_LINE_MAX);
    assert!(line.ends_with(b"\n"));
    assert_eq!(
        served.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the stream must not be read"
    );
}

/// An over-long line arriving entirely with the head errors from the
/// prefix alone — the stream is never read.
#[tokio::test]
async fn read_line_caps_over_long_pending_line() {
    let mut prefix = vec![b'x'; CHUNK_LINE_MAX + 1];
    prefix.push(b'\n');
    let (stream, served) = FakeStream::new(Vec::new(), 4096);
    let mut boxed = Box::new(stream);
    let mut reader = BodyReader::new(&mut boxed, &prefix);
    let err = reader.read_line(CHUNK_LINE_MAX).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        served.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the stream must not be read"
    );
}

#[test]
fn test_base64_decode() {
    // "test:pass" = dGVzdDpwYXNz (payload length a multiple of 3)
    let result = base64_decode("dGVzdDpwYXNz").unwrap();
    assert_eq!(result, "test:pass");
    // Padded payload whose length is NOT a multiple of 3: the leftover
    // bits before '=' are zero-fill. The old decoder emitted them as a
    // spurious trailing NUL byte ("u1:p1\0") — the auth compare then
    // rejected every valid credential of that shape. RED on the old
    // `bits >= 2` flush at padding.
    let result = base64_decode("dTE6cDE=").unwrap();
    assert_eq!(result, "u1:p1");
}

#[test]
fn test_split_host_port() {
    assert_eq!(split_host_port("host:443"), ("host", 443));
    assert_eq!(split_host_port("host"), ("host", 80));
    assert_eq!(split_host_port("1.2.3.4:8080"), ("1.2.3.4", 8080));
}

#[test]
fn test_urlencoding_decode() {
    // Byte-level decode (audit round-16 FIX 2): results are raw bytes,
    // not chars.
    assert_eq!(urlencoding_decode("hello%20world"), b"hello world".to_vec());
    assert_eq!(
        urlencoding_decode("%2Fetc%2Fpasswd"),
        b"/etc/passwd".to_vec()
    );
    assert_eq!(urlencoding_decode("noencoding"), b"noencoding".to_vec());
    // '+' is LITERAL in path decoding — Go's PlusToSpace is query-only
    // (url.Parse decodes paths without it). Flip: the old x-www-form
    // behavior served "a b" for "/a+b".
    assert_eq!(urlencoding_decode("a+b"), b"a+b".to_vec());
    // Invalid hex stays literal on decode (Go url.Parse leaves bad
    // escapes untouched) — parse_request_line's gate rejects such
    // targets before decode anyway.
    assert_eq!(urlencoding_decode("%gg"), b"%gg".to_vec());
    // FIX 2 mojibake pin: %C3%AF decodes to the UTF-8 bytes C3 AF, NOT
    // the Latin-1 cast ï = C3 (which re-encoded as C3 83 C2 AF and
    // served "naÃ¯ve.txt" for "naïve.txt").
    assert_eq!(urlencoding_decode("na%C3%AFve.txt"), b"na\xc3\xafve.txt");
    assert_eq!(urlencoding_decode("%FF"), b"\xff".to_vec());
}

/// Matrix for the shared request-side version gate — moved from
/// plugin/http.rs when the request-line parser became shared. Request
/// side: ParseHTTPVersion accepts every 8-char "HTTP/X.Y" with a single
/// ASCII digit (go1.25 request.go:817-838; "HTTP/1.0"/"HTTP/1.1"
/// short-circuit), and the plugin gate additionally requires major 1
/// (the frps vhost front 505s everything else — HTTP/2.0 tokens never
/// reach the plugin legs in either ecosystem).
#[test]
fn test_go_parse_http_version_ok_matrix() {
    // Lenient-but-parseable: single-digit minor, majors 2..9 parse in
    // Go ParseHTTPVersion but the major-1 gate rejects them.
    assert!(go_parse_http_version_ok("HTTP/1.0"));
    assert!(go_parse_http_version_ok("HTTP/1.1"));
    assert!(go_parse_http_version_ok("HTTP/1.2"));
    assert!(go_parse_http_version_ok("HTTP/1.9"));
    assert!(!go_parse_http_version_ok("HTTP/2.0"));
    assert!(!go_parse_http_version_ok("HTTP/3.0"));
    assert!(!go_parse_http_version_ok("HTTP/9.9"));
    // Malformed tokens.
    assert!(!go_parse_http_version_ok("HTTP/1.10")); // 9 bytes
    assert!(!go_parse_http_version_ok("HTTP/1.1 "));
    assert!(!go_parse_http_version_ok("HTTP/.1"));
    assert!(!go_parse_http_version_ok("http/1.1"));
    assert!(!go_parse_http_version_ok(""));
    assert!(!go_parse_http_version_ok("HTTP/1\t1"));
    assert!(!go_parse_http_version_ok("HTTP/10.1"));
    assert!(!go_parse_http_version_ok("HTTP/1.1."));
}

#[test]
fn test_parse_request_line() {
    // Well-formed three-part lines.
    assert_eq!(
        parse_request_line("GET /path HTTP/1.1"),
        Some(("GET", "/path", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT host:443 HTTP/1.1"),
        Some(("CONNECT", "host:443", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("GET /x HTTP/1.2"),
        Some(("GET", "/x", "HTTP/1.2"))
    );
    // Go parseRequestLine: literal-space cuts only, so a 2-token line
    // ("GET /x", HTTP/0.9-style — Go dropped the 0.9 fallback), a
    // tab-joined "GET\t/x\tHTTP/1.1" (no literal second space), an empty
    // version slot ("GET /x " — splitn finds nothing after the last
    // space), and an empty target ("GET  HTTP/1.1") all malformed.
    assert_eq!(parse_request_line("GET /x"), None);
    assert_eq!(parse_request_line("GET\t/x\tHTTP/1.1"), None);
    assert_eq!(parse_request_line("GET /x "), None);
    assert_eq!(parse_request_line("GET  HTTP/1.1"), None);
    assert_eq!(parse_request_line(" HTTP/1.1"), None);
    // The two-Cut parse leaves the SECOND space as an empty slot:
    // "GET  /x HTTP/1.1" → requestURI "" (Go: url.ParseRequestURI("")
    // fails "empty url"), "GET /x  HTTP/1.1" → proto " HTTP/1.1"
    // (leading space — ParseHTTPVersion fails). Both malformed in Go.
    assert_eq!(parse_request_line("GET  /x HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET /x  HTTP/1.1"), None);
    // Version gate.
    assert_eq!(parse_request_line("GET /x HTTP/2.0"), None);
    assert_eq!(parse_request_line("GET /x garbage"), None);
    assert_eq!(parse_request_line("GET /x HTTP/1.1 trailing"), None);
    assert_eq!(parse_request_line(""), None);
    // Go conn.readRequest validMethod gate: the method token must be
    // non-empty and made of RFC 7230 tchar bytes only. Lowercase "get"
    // is a LEGAL token (validMethod has no case rule — gorilla mux
    // Method("GET") 405s it later in Go); "G@T" is a 400 before
    // routing. A tab EMBEDDED in the method ("GE\tT /x") splits on the
    // literal space into a parseable line whose token then fails the
    // gate — accept-where-Go-rejects before the gate, now rejected.
    assert_eq!(
        parse_request_line("get /x HTTP/1.1"),
        Some(("get", "/x", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("M-SEARCH /x HTTP/1.1"),
        Some(("M-SEARCH", "/x", "HTTP/1.1"))
    );
    assert_eq!(parse_request_line("G@T /x HTTP/1.1"), None);
    assert_eq!(parse_request_line("GE(T /x HTTP/1.1"), None);
    assert_eq!(parse_request_line("GE\tT /x HTTP/1.1"), None);
    // Non-ASCII byte in the method token.
    assert_eq!(parse_request_line("GÉT /x HTTP/1.1"), None);
    // Empty method token.
    assert_eq!(parse_request_line(" /x HTTP/1.1"), None);
    // Audit round-16 FIX 13: invalid %-escapes in the request-target's
    // pre-'?' portion — Go url.Parse "invalid URL escape" inside
    // ReadRequest → 400 before routing/auth (probe vs go1.25.12:
    // /x%zz, /x%, /x%2 all 400). A '%' must be followed by two hex
    // digits, anywhere before the query (path and absolute-form
    // authority alike — Go parses one URL). The post-fix round then
    // proved the scan must STOP at the first '?': url.Parse Cuts the
    // query RAW before any unescape, so a garbage escape in the query
    // is never decoded, never validated, and never an error (probe:
    // /x?q=%zz, /x?q=%2, /x?q=%zz%2 all answer 200). '#' is not a
    // fragment separator under ParseRequestURI, so escapes after it
    // stay path-validated and 400 like any other path escape.
    assert_eq!(parse_request_line("GET /x%zz HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET /x%2 HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET /x% HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET %zz HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT host%zz:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET http://h/x%zz HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET /x%zz?q=1 HTTP/1.1"), None);
    assert_eq!(parse_request_line("GET /x%zz#f%zz HTTP/1.1"), None);
    // Query-only escapes parse (the query stays raw — Go never
    // unescape-validates it).
    assert_eq!(
        parse_request_line("GET /x?q=%zz HTTP/1.1"),
        Some(("GET", "/x?q=%zz", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("GET /x?q=%zz%2 HTTP/1.1"),
        Some(("GET", "/x?q=%zz%2", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT host:443?a=%zz HTTP/1.1"),
        Some(("CONNECT", "host:443?a=%zz", "HTTP/1.1"))
    );
    // Valid escapes and literal '%'-free targets pass.
    assert_eq!(
        parse_request_line("GET /x%20y%2Fz HTTP/1.1"),
        Some(("GET", "/x%20y%2Fz", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("GET /100%25done HTTP/1.1"),
        Some(("GET", "/100%25done", "HTTP/1.1"))
    );
    // Absolute-form target (non-CONNECT): path mode over the whole
    // pre-'?' slice. A WELL-FORMED ASCII escape in the absolute-form
    // HOST parses here — documented divergence, kept per the review
    // scope (the host-mode gate below covers the CONNECT authority
    // only): Go host-modes that region too (probe vs go1.25
    // http.Server: "GET http://h%41st/x HTTP/1.1" answers 400), and
    // frp-rs dials absolute-form hosts verbatim, so a %41 host fails
    // the dial anyway. Malformed escapes in the absolute-form host
    // reject here exactly like Go ("GET http://h%zzst/x" → 400 —
    // url.Parse errors before routing, both modes).
    assert_eq!(
        parse_request_line("GET http://h%41st/x HTTP/1.1"),
        Some(("GET", "http://h%41st/x", "HTTP/1.1"))
    );
    assert_eq!(parse_request_line("GET http://h%zzst/x HTTP/1.1"), None);
}

/// Review-round fix: a CONNECT authority-form target is validated
/// with Go's HOST-mode unescape (net/url/url.go:226 — parseHost over
/// the authority of readRequest justAuthority's "http://" + target
/// rewrite): a well-formed escape that decodes to an ASCII byte
/// (first hex digit < 8) is an error UNLESS it is the literal "%25"
/// (the RFC 6874 zone exemption — "%25" decodes to '%'), while
/// escapes decoding to obs-text (first hex digit >= 8, "%C3%A9") and
/// the "%25" literal pass. Malformed escapes reject in every mode.
/// The region split mirrors Go's parse: the authority runs to the
/// target's FIRST '/', the remainder (from the '/' on) is the path
/// (path mode), the query stays raw. Probe vs go1.25 http.Server:
/// "CONNECT h%41st:443" / h%2Fst / h%zzst → 400; h%25st / h%C3%A9st
/// → 200 (the "h:4%31" port shape rejects earlier in Go — parseHost's
/// validOptionalPort digits-only gate — but same ReadRequest-error
/// class). RED on pre-fix code: the escape scan was path-mode over
/// the whole target, so the well-formed ASCII escapes (%41/%2F/%40)
/// parsed and reached the CONNECT dial — only malformed %zz
/// rejected.
#[test]
fn test_parse_request_line_connect_host_mode_escapes() {
    // ASCII-decoding escapes in the authority: host-mode rejects
    // (Go: "invalid URL escape", ReadRequest → 400 → silent close
    // on the http_proxy CONNECT arm).
    assert_eq!(parse_request_line("CONNECT h%41st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h%2Fst:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h%5Bst:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h%40st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h%7Fst:443 HTTP/1.1"), None);
    // Port-region escape: same rejection class (Go's validOptionalPort
    // digit gate fires first there — either way a ReadRequest error).
    assert_eq!(parse_request_line("CONNECT h:4%31 HTTP/1.1"), None);
    // Malformed escapes reject (both modes agree).
    assert_eq!(parse_request_line("CONNECT h%zzst:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h%2:443 HTTP/1.1"), None);
    // "%25" (the exemption — decodes to '%') and obs-text decodes
    // ("%C3%A9" → 'é') pass.
    assert_eq!(
        parse_request_line("CONNECT h%25st:443 HTTP/1.1"),
        Some(("CONNECT", "h%25st:443", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT h%C3%A9st:443 HTTP/1.1"),
        Some(("CONNECT", "h%C3%A9st:443", "HTTP/1.1"))
    );
    // Region split at the first '/': authority host-mode, path (from
    // the '/') path-mode, query raw.
    assert_eq!(
        parse_request_line("CONNECT h%25st:443/a%41?q=%zz HTTP/1.1"),
        Some(("CONNECT", "h%25st:443/a%41?q=%zz", "HTTP/1.1"))
    );
    assert_eq!(parse_request_line("CONNECT h%25st:443/a%zz HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h%41st:443/a HTTP/1.1"), None);
    // '/'-prefixed CONNECT targets are path-form in Go (justAuthority
    // only applies when the target does NOT start with '/') — path
    // mode throughout.
    assert_eq!(
        parse_request_line("CONNECT /rpc%41 HTTP/1.1"),
        Some(("CONNECT", "/rpc%41", "HTTP/1.1"))
    );
}

/// Round-17 audit finding F6: the raw-ASCII sweep. Go's unescape
/// default arm rejects `s[i] < 0x80 && shouldEscape(s[i], mode)` in
/// host and zone modes (InvalidHostError — ReadRequest → silent close
/// on the http_proxy CONNECT arm). The pre-fix gate charset-validated
/// only %-escaped bytes, so raw '^'/'|'/'{' authorities passed and
/// died at the dial with a 400 render where Go closes silently.
#[test]
fn test_parse_request_line_connect_host_raw_ascii_sweep() {
    // Raw non-legal ASCII in the authority host region → reject
    // (Go InvalidHostError; probe vs go1.25: "CONNECT h^st:80" /
    // "h|st" answer 0 bytes on the http_proxy CONNECT arm).
    assert_eq!(parse_request_line("CONNECT h^st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h|st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h{st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h`st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h\\st:443 HTTP/1.1"), None);
    assert_eq!(parse_request_line("CONNECT h#st:443 HTTP/1.1"), None);
    // Raw DEL is swept by the CTL pass (b == 0x7f) even before F6.
    assert_eq!(parse_request_line("CONNECT h\u{7f}st:443 HTTP/1.1"), None);
    // A raw space in the authority never survives the 3-part
    // request-line split — the second space makes "st:443" the
    // version token, which fails the version shape (Go: the line
    // parses to a 2-part request line → malformed 400; same class).
    assert_eq!(parse_request_line("CONNECT h st:443 HTTP/1.1"), None);
    // Raw obs-text is LEGAL (the sweep gates on < 0x80) — Go parses
    // it and dies at the dial.
    assert_eq!(
        parse_request_line("CONNECT h\u{ff}st:443 HTTP/1.1"),
        Some(("CONNECT", "h\u{ff}st:443", "HTTP/1.1"))
    );
}

/// Round-17 audit finding F5: the unreserved-marks switch. Go's
/// shouldEscape has an UNCONDITIONAL second switch exempting '-', '_',
/// '.' and '~' that runs for host/zone modes too — the pre-fix set
/// lacked the four marks, so a raw '~' host passed only by accident
/// (no raw sweep existed) but a zone escape like "%2D" was rejected
/// where Go accepts it (probe: CONNECT [fe80::1%25en%2D0]:80 parses in
/// go1.25 — redundant escaping of a zone-legal byte).
#[test]
fn test_parse_request_line_connect_host_unreserved_marks() {
    // Raw marks in the authority host region stay legal under the F6
    // sweep (they must — the sweep calls should_escape_encode_host).
    assert_eq!(
        parse_request_line("CONNECT h-st:443 HTTP/1.1"),
        Some(("CONNECT", "h-st:443", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT h_st:443 HTTP/1.1"),
        Some(("CONNECT", "h_st:443", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT h.st:443 HTTP/1.1"),
        Some(("CONNECT", "h.st:443", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT h~st:443 HTTP/1.1"),
        Some(("CONNECT", "h~st:443", "HTTP/1.1"))
    );
    // Zone redundant escapes of the marks decode to host-legal bytes:
    // %2D / %7E inside a zone pass (Go probe row above); the host-mode
    // %2D (outside any zone) stays rejected (escapes of host-legal
    // bytes are still invalid under the ASCII-escape rule).
    assert_eq!(
        parse_request_line("CONNECT [fe80::1%25en%2D0]:80 HTTP/1.1"),
        Some(("CONNECT", "[fe80::1%25en%2D0]:80", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT [fe80::1%25en-0]:80 HTTP/1.1"),
        Some(("CONNECT", "[fe80::1%25en-0]:80", "HTTP/1.1"))
    );
    assert_eq!(
        parse_request_line("CONNECT [fe80::1%25en%7E0]:80 HTTP/1.1"),
        Some(("CONNECT", "[fe80::1%25en%7E0]:80", "HTTP/1.1"))
    );
    assert_eq!(parse_request_line("CONNECT h%2Dst:443 HTTP/1.1"), None);
    // Zone raw-ASCII sweep (F6 in zone mode): a raw '^' inside the
    // zone region rejects like the host region.
    assert_eq!(
        parse_request_line("CONNECT [fe80::1%25en^0]:80 HTTP/1.1"),
        None
    );
}

/// Go conn.readRequest `validMethod` (request.go go1.25): non-empty +
/// tchar-only (alnum and `!#$%&'*+-.^_`|~`). No case rule — lowercase
/// "get" passes, exactly like Go (gorilla's Method("GET") route check
/// is where lowercase 405s later).
#[test]
fn test_go_valid_method_ok() {
    assert!(go_valid_method_ok("GET"));
    assert!(go_valid_method_ok("get"), "lowercase is a legal token");
    assert!(go_valid_method_ok("CONNECT"));
    assert!(go_valid_method_ok("PATCH"));
    assert!(go_valid_method_ok("M-SEARCH"));
    assert!(go_valid_method_ok("_foo"));
    assert!(go_valid_method_ok("!#$%&'*+-.^_`|~0123456789"));
    assert!(go_valid_method_ok(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    ));
    assert!(!go_valid_method_ok(""));
    assert!(!go_valid_method_ok("G@T"));
    assert!(!go_valid_method_ok("GE(T"));
    assert!(!go_valid_method_ok("GET:FOO")); // colon is not tchar
    assert!(!go_valid_method_ok("/GET")); // slash is not tchar
    assert!(!go_valid_method_ok("GET\u{7f}"));
    assert!(!go_valid_method_ok("GÉT")); // non-ASCII bytes are not tchar
    assert!(!go_valid_method_ok("GE T")); // space is not tchar
}

#[test]
fn test_go_render_shapes() {
    // Exact Go probe captures — any future edit to these renders changes
    // the bytes peers see.
    assert_eq!(
        GO_502_RENDER,
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(GO_502_RENDER.len(), 47);
    assert!(!GO_400_RENDER.contains("Content-Length"));
    assert!(GO_400_RENDER.ends_with("400 Bad Request"));
    assert!(!GO_431_RENDER.contains("Content-Length"));
    assert!(GO_431_RENDER.starts_with("HTTP/1.1 431 Request Header Fields Too Large"));
    assert!(GO_404_NOT_FOUND_RENDER.ends_with("404 page not found\n"));
    assert!(GO_404_NOT_FOUND_RENDER.contains("Content-Length: 19"));
    assert!(!head_starts_connect(GO_400_RENDER.as_bytes()));
    assert!(head_starts_connect(b"CONNECT host:443 HTTP/1.1"));
    assert!(head_starts_connect(b"connect"));
    assert!(head_starts_connect(b"Connect"));
    assert!(!head_starts_connect(b"GET / HTTP/1.1"));
    assert!(!head_starts_connect(b"CONNEC")); // 6 bytes: short of the 7-byte read
}

#[test]
fn test_parse_request_body_framing() {
    // No body framing headers → no body.
    assert_eq!(parse_request_body_framing("".lines()), None);
    assert_eq!(
        parse_request_body_framing("Host: example.com".lines()),
        None
    );
    // Content-Length framing.
    assert_eq!(
        parse_request_body_framing("Content-Length: 42".lines()),
        Some(BodyFraming::Length(42))
    );
    assert_eq!(
        parse_request_body_framing("Content-Length: 0".lines()),
        Some(BodyFraming::Length(0))
    );
    // Chunked transfer-encoding.
    assert_eq!(
        parse_request_body_framing("Transfer-Encoding: chunked".lines()),
        Some(BodyFraming::Chunked)
    );
    assert_eq!(
        parse_request_body_framing("Transfer-Encoding: Chunked".lines()),
        Some(BodyFraming::Chunked)
    );
    // Chunked must be the FINAL coding of the list (RFC 7230 §3.3.3);
    // "gzip, chunked" is chunked, "chunkedfoo" or a coding after chunked
    // is not.
    assert_eq!(
        parse_request_body_framing("Transfer-Encoding: gzip, chunked".lines()),
        Some(BodyFraming::Chunked)
    );
    assert_eq!(
        parse_request_body_framing("Transfer-Encoding: chunkedfoo".lines()),
        None
    );
    assert_eq!(
        parse_request_body_framing("Transfer-Encoding: chunked, gzip".lines()),
        None
    );
    // Chunked wins over Content-Length (RFC 7230 §3.3.3).
    assert_eq!(
        parse_request_body_framing("Content-Length: 42\r\nTransfer-Encoding: chunked".lines()),
        Some(BodyFraming::Chunked)
    );
    // List-form Content-Length ("5, 5") is malformed: Go's
    // strconv.ParseUint takes no commas, so net/http (the server
    // inside Go frp's http_proxy plugin) answers 400. resolve_
    // content_length errors, and the head builders reject the request
    // on that error — no framing is inferred here.
    assert_eq!(
        parse_request_body_framing("Content-Length: 5, 5".lines()),
        None
    );
    // Duplicate identical Content-Length lines collapse to one value.
    assert_eq!(
        parse_request_body_framing("Content-Length: 5\r\nContent-Length: 5".lines()),
        Some(BodyFraming::Length(5))
    );
    // Unparseable Content-Length is malformed — Go's server rejects
    // the request outright (400 "bad Content-Length"). resolve_
    // content_length errors, and the head builders reject the request
    // on that error.
    assert_eq!(
        parse_request_body_framing("Content-Length: abc".lines()),
        None
    );
}

/// Go parity (probed against the Go frp v0.71.0-era stdlib, go1.25.12):
/// Go validates Content-Length values even when Transfer-Encoding:
/// chunked wins the framing — chunked + "5, 5" is still 400 "bad
/// Content-Length". The F9 resolve gate in the head builders therefore
/// runs UNCONDITIONALLY: the old chunked-skip accepted garbage CL
/// under chunked and forwarded the request (round-8 F9). A chunked
/// request carrying a VALID Content-Length still forwards with the CL
/// line dropped (Go deletes the header once chunked wins) and the
/// Transfer-Encoding preserved.
#[tokio::test]
async fn chunked_request_resolves_content_length() {
    use tokio::io::AsyncWriteExt;
    // Malformed (list-form) Content-Length under chunked fails the
    // forward build, mirroring Go's 400.
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    client_io
        .write_all(
            b"POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nContent-Length: 5, 5\r\n\r\n",
        )
        .await
        .unwrap();
    client_io.flush().await.unwrap();
    let err = read_request_and_build_forward(&mut server_io, "", &Default::default(), None).await;
    let err = match err {
        Ok(_) => {
            panic!("chunked + list-form Content-Length must reject the forward build (regression)")
        }
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("Content-Length"),
        "rejection must name the header, got: {err}"
    );

    // A VALID Content-Length under chunked is accepted; the retain
    // gate drops the CL line and the Transfer-Encoding survives.
    let head = build_forward(
        b"POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert!(
        !head
            .lines()
            .any(|l| starts_with_ignore_ascii_case(l, "content-length:")),
        "Content-Length must be dropped under chunked, got: {head}"
    );
    assert!(
        head.contains("Transfer-Encoding: chunked"),
        "chunked framing must survive, got: {head}"
    );
}

#[test]
fn test_resolve_content_length() {
    // No Content-Length header → no length.
    assert_eq!(
        resolve_content_length("Host: example.com".lines()).unwrap(),
        None
    );
    // Single value.
    assert_eq!(
        resolve_content_length("Content-Length: 42".lines()).unwrap(),
        Some(42)
    );
    // Zero is a legal body length.
    assert_eq!(
        resolve_content_length("Content-Length: 0".lines()).unwrap(),
        Some(0)
    );
    // Leading zeros and trailing ASCII OWS are accepted (Go
    // textproto.TrimString + strconv.ParseUint).
    assert_eq!(
        resolve_content_length("Content-Length: 05".lines()).unwrap(),
        Some(5)
    );
    assert_eq!(
        resolve_content_length("Content-Length: 5   ".lines()).unwrap(),
        Some(5)
    );
    // Duplicate identical lines collapse to one copy (Go fixLength
    // dedupes — the comparison is on the ASCII-OWS-trimmed raw text).
    assert_eq!(
        resolve_content_length("Content-Length: 5\r\nContent-Length: 5".lines()).unwrap(),
        Some(5)
    );
    assert_eq!(
        resolve_content_length("Content-Length: 5 \r\nContent-Length: 5".lines()).unwrap(),
        Some(5)
    );
    // Conflicting values invalidate the request framing (Go answers
    // 400 "message cannot contain multiple Content-Length headers").
    assert!(resolve_content_length("Content-Length: 5\r\nContent-Length: 100".lines()).is_err());
    // ... including raw-text differences that parse to the same number
    // ("05" == 5 numerically, but the trimmed texts differ).
    assert!(resolve_content_length("Content-Length: 05\r\nContent-Length: 5".lines()).is_err());
    // List forms are NOT legal. Go strconv.ParseUint rejects any
    // non-digit, so a comma list ("5, 5", RFC 7230 §3.3.2's legal form
    // notwithstanding) is a 400. Probed against the Go frp v0.71.0
    // binary (built with go1.25.12): every list shape below is answered
    // "HTTP/1.1 400 Bad Request".
    assert!(resolve_content_length("Content-Length: 5, 5".lines()).is_err());
    assert!(resolve_content_length("Content-Length: 5, 7".lines()).is_err());
    assert!(resolve_content_length("Content-Length:  5 , 5 ".lines()).is_err());
    assert!(resolve_content_length("Content-Length: 5,5,5".lines()).is_err());
    // ... and identical list lines do not rescue the form.
    assert!(
        resolve_content_length("Content-Length: 5, 5\r\nContent-Length: 5, 5".lines()).is_err()
    );
    // Control bytes other than space/tab in the value are NOT trimmed
    // (textproto.isASCIISpace has no \x0b/\x0c; Go rejects them while
    // reading the head — round-3 review, audit round 8): a \x0b-wrapped
    // "5" survives to the digit parse and fails it.
    assert!(resolve_content_length("Content-Length: \x0b5".lines()).is_err());
    assert!(resolve_content_length("Content-Length: 5\x0c".lines()).is_err());
    // Non-numeric values are errors (Go 400 "bad Content-Length") —
    // including empty values (Go "invalid empty Content-Length") and
    // any sign (strconv.ParseUint accepts no sign, not even '+').
    assert!(resolve_content_length("Content-Length: abc".lines()).is_err());
    assert!(resolve_content_length("Content-Length:".lines()).is_err());
    assert!(resolve_content_length("Content-Length:   ".lines()).is_err());
    assert!(resolve_content_length("Content-Length: -5".lines()).is_err());
    assert!(resolve_content_length("Content-Length: +5".lines()).is_err());
    // 63-bit cap (Go ParseUint bitSize=63): 2^63-1 is the largest
    // accepted value; anything larger is an error even when it fits u64.
    assert_eq!(
        resolve_content_length("Content-Length: 9223372036854775807".lines()).unwrap(),
        Some(i64::MAX as usize)
    );
    assert!(resolve_content_length("Content-Length: 9223372036854775808".lines()).is_err());
    assert!(resolve_content_length("Content-Length: 9999999999999999999".lines()).is_err());
}

/// Drive `read_request_and_build_forward` over a duplex stream and
/// return the forwarded head.
async fn build_forward(
    raw_head: &[u8],
    request_headers: &std::collections::HashMap<String, String>,
    x_forwarded_for: Option<std::net::IpAddr>,
) -> String {
    use tokio::io::AsyncWriteExt;
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    client_io.write_all(raw_head).await.unwrap();
    client_io.flush().await.unwrap();
    let fwd = read_request_and_build_forward(&mut server_io, "", request_headers, x_forwarded_for)
        .await
        .expect("forward build");
    fwd.head
}

fn xff_lines(head: &str) -> Vec<&str> {
    head.lines()
        .filter(|l| starts_with_ignore_ascii_case(l, "x-forwarded-for:"))
        .collect()
}

/// Audit round-9 B1 twin (http.rs `build_forward_head_chunked_post_is_
/// http11`): the shared forward builder speaks HTTP/1.1 on the outbound
/// leg — Go's http.DefaultTransport (the ReverseProxy backend of the
/// http2http/http2https/https2http/https2https plugins, http2http.go)
/// never writes HTTP/1.0 requests. Chunked bodies are the canary:
/// chunked Transfer-Encoding is HTTP/1.1-only, so under the old
/// HTTP/1.0 request line an origin saw neither TE nor CL and silently
/// dropped the upload body. Pins the exact head bytes: request line,
/// re-added chunked framing, `Connection: close` terminator. RED on the
/// HTTP/1.0 request line (byte-exact compare fails).
#[tokio::test]
async fn build_forward_chunked_post_head_is_http11() {
    let head = build_forward(
        b"POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(
        head,
        "POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        "byte-exact outbound head (chunked POST)"
    );

    // A Content-Length-framed request keeps its canonical CL line and
    // stays HTTP/1.1.
    let cl_head = build_forward(
        b"POST /p HTTP/1.1\r\nHost: b\r\nContent-Length: 3\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(
        cl_head, "POST /p HTTP/1.1\r\nHost: b\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",
        "byte-exact outbound head (CL POST)"
    );
}

/// R5 pin: the https plugins (peer-present) append the tunnel peer to
/// the INBOUND X-Forwarded-For chain — one canonical line, the chain
/// preserved and extended (Go SetXForwarded semantics).
#[tokio::test]
async fn forward_xff_appends_peer_to_inbound_chain() {
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 1.2.3.4, 5.6.7.8\r\nUser-Agent: t\r\n\r\n",
        &Default::default(),
        Some("203.0.113.9".parse().unwrap()),
    )
    .await;
    let lines = xff_lines(&head);
    assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
    assert_eq!(
        lines[0].trim(),
        "X-Forwarded-For: 1.2.3.4, 5.6.7.8, 203.0.113.9",
        "inbound chain preserved and peer appended"
    );
}

/// R5 pin: a configured X-Forwarded-For REPLACES the appended chain
/// (peer + inbound) — one canonical line with the configured value only
/// (Go Header.Set runs after SetXForwarded).
#[tokio::test]
async fn forward_configured_xff_replaces_chain() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Forwarded-For".to_string(), "cfg-value".to_string());
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 1.2.3.4, 5.6.7.8\r\n\r\n",
        &headers,
        Some("203.0.113.9".parse().unwrap()),
    )
    .await;
    let lines = xff_lines(&head);
    assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
    assert_eq!(
        lines[0].trim(),
        "X-Forwarded-For: cfg-value",
        "configured value replaces the chain (no chain, no peer)"
    );
    assert!(
        !head.contains("1.2.3.4") && !head.contains("203.0.113.9"),
        "chain and peer must not leak alongside the configured value"
    );
}

/// R5 pin: the http2http/http2https plugins (peer absent) pass an
/// inbound X-Forwarded-For through untouched — single line, verbatim.
#[tokio::test]
async fn forward_xff_passthrough_when_no_peer() {
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    let lines = xff_lines(&head);
    assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
    assert_eq!(
        lines[0].trim(),
        "X-Forwarded-For: 9.9.9.9",
        "inbound XFF passes through verbatim when no peer appends"
    );
}

/// R5 pin (divergence regression): a configured X-Forwarded-For in the
/// no-peer plugins must STILL be exactly one header — Go Header.Set
/// replaces the inbound value whether or not ReverseProxy later appends
/// a peer. Pre-fix this emitted the configured value twice (once in the
/// request_headers loop, once in the canonical tail) plus the inbound
/// chain.
#[tokio::test]
async fn forward_configured_xff_single_line_without_peer() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Forwarded-For".to_string(), "cfg-value".to_string());
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
        &headers,
        None,
    )
    .await;
    let lines = xff_lines(&head);
    assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
    assert_eq!(
        lines[0].trim(),
        "X-Forwarded-For: cfg-value",
        "configured value is the only XFF line even without a peer"
    );
    assert!(
        !head.contains("1.2.3.4"),
        "inbound chain must not leak alongside the configured value"
    );
}

/// Audit round-7 S1 pin: an LF-only request head (request line + one
/// header + LF blank line) terminates the read loop and builds the
/// forward — Go http.ReadRequest/textproto semantics. RED pre-fix: the
/// \r\n\r\n scan never matched, the loop read on and hit EOF once the
/// writer half dropped ("connection closed"); the dropped writer makes
/// the RED arm fail fast instead of stalling the 60 s per-read timeout.
#[tokio::test]
async fn forward_lf_only_head_terminates() {
    use tokio::io::AsyncWriteExt;
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    client_io
        .write_all(b"GET /p HTTP/1.1\nHost: b\nX-A: 1\n\n")
        .await
        .unwrap();
    client_io.flush().await.unwrap();
    drop(client_io); // EOF after the buffered head drains
    let fwd = read_request_and_build_forward(&mut server_io, "", &Default::default(), None)
        .await
        .expect("LF-only head must end the head read, not EOF-error");
    assert!(
        fwd.head.starts_with("GET /p HTTP/1.1\r\n"),
        "forwarded head: {}",
        fwd.head
    );
    assert!(
        fwd.head.contains("X-A: 1\r\n"),
        "LF header line must be forwarded: {}",
        fwd.head
    );
    assert!(fwd.body_prefix.is_empty(), "no body bytes were pre-read");
}

/// Round-17 audit E pins (mod.rs sibling legs): Go parseTransferEncoding
/// gates its whole read on protoAtLeast(1, 1) (transfer.go, Issue
/// 12785) — the 1.0 ignore-arm and the >=1.1 reject-arm of this
/// operator-local listener class. RED on pre-fix code: a garbage-TE
/// 1.1 head was forwarded (TE stripped hop-by-hop, body CL-framed)
/// where Go's http.Server faces answer their 501; a garbage-TE 1.0
/// head reached the chunked-framing resolution where Go drops the
/// header and reads a body-less request.
#[tokio::test]
async fn transfer_encoding_garbage_rejects_11_ignores_10() {
    use tokio::io::AsyncWriteExt;
    // HTTP/1.1 + non-chunked TE → Err (the sibling-face 501 class).
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    client_io
        .write_all(b"GET /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: gzip\r\n\r\n")
        .await
        .unwrap();
    match read_request_and_build_forward(&mut server_io, "", &Default::default(), None).await {
        Err(e) => assert_eq!(e, "unsupported transfer encoding"),
        Ok(fwd) => panic!(
            "1.1 garbage TE must reject the read, forwarded: {}",
            fwd.head
        ),
    }
    // HTTP/1.0 + garbage TE → the header is ignored (Issue 12785):
    // the head forwards with the TE line dropped and no chunked
    // framing (CL resolution only — no CL header, no body expected).
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    client_io
        .write_all(b"GET /p HTTP/1.0\r\nTransfer-Encoding: gzip\r\n\r\n")
        .await
        .unwrap();
    let fwd = read_request_and_build_forward(&mut server_io, "", &Default::default(), None)
        .await
        .expect("1.0 garbage Transfer-Encoding must be ignored, not rejected");
    assert!(
        !fwd.head.contains("Transfer-Encoding"),
        "the ignored TE header must be dropped from the forward: {}",
        fwd.head
    );
    assert!(
        !fwd.head.contains("chunked"),
        "1.0 framing must not resolve chunked: {}",
        fwd.head
    );
    assert!(fwd.body_prefix.is_empty(), "no body bytes were pre-read");
}

/// Audit round-8 F8 pin: a slowloris peer that drips ONE byte per 59 s
/// never trips a per-read re-armed deadline (every byte resets the
/// clock), but MUST be released by one absolute window over the whole
/// head read (Go http.Server ReadHeaderTimeout = 60 s inside Go frp's
/// http_proxy plugin). Paused time keeps the 300 s outer bound
/// deterministic: RED (per-read re-arm) trips the OUTER timeout instead
/// of the 60 s window; GREEN (single absolute window) returns
/// "timed out reading request headers" at virtual t=60 s.
#[tokio::test(start_paused = true)]
async fn header_read_single_absolute_window_beats_trickle() {
    use tokio::io::AsyncWriteExt;
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    // One byte per 59 s forever — the head never completes (no blank
    // line) and each byte would re-arm a per-read deadline.
    let trickle = tokio::spawn(async move {
        loop {
            if client_io.write_all(b"x").await.is_err() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(59)).await;
        }
    });
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        read_request_and_build_forward(&mut server_io, "", &Default::default(), None),
    )
    .await;
    drop(trickle);
    match res {
        Ok(Ok(_)) => panic!("a trickled, unterminated head must not build a forward"),
        Ok(Err(e)) => {
            assert_eq!(
                e, "timed out reading request headers",
                "the single absolute window must trip at 60 s"
            );
        }
        Err(_elapsed) => {
            panic!("per-read deadline re-arms on every byte: 1 B/59 s trickle beat the 60 s bound")
        }
    }
}

/// Drive `read_request_and_build_forward` over a duplex stream and
/// return the bytes the REJECTING side wrote before its Err (the F7
/// render) plus the Err text. Reading the render back requires the
/// writer half to drop first (duplex EOF), so the caller's Err borrow
/// must be released before the read — the helper owns that order.
async fn reject_bytes(raw_head: &[u8]) -> (Vec<u8>, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_io, mut server_io) = tokio::io::duplex(8192);
    client_io.write_all(raw_head).await.unwrap();
    client_io.flush().await.unwrap();
    let err =
        match read_request_and_build_forward(&mut server_io, "", &Default::default(), None).await {
            Ok(fwd) => panic!("head must be rejected, built forward: {}", fwd.head),
            Err(e) => e,
        };
    drop(server_io);
    let mut render = Vec::new();
    client_io.read_to_end(&mut render).await.unwrap();
    (render, err)
}

/// Round-17 audit F7: Go conn.readRequest gates on the http2http-family
/// legs — every rejected class answers the byte-exact render Go's
/// http.Server face writes on the same head (probe-verified against
/// go1.25.12), instead of the old bare close.
#[tokio::test]
async fn f7_conn_gates_render_go_byte_exact_shapes() {
    // dup-Host fires inside package readRequest (before readTransfer):
    // plain error, no-detail 400.
    let (render, err) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_RENDER.as_bytes(),
        "dup-Host render must be the generic 400"
    );
    assert!(
        err.contains("too many Host headers"),
        "dup-Host Err must name the class, got: {err}"
    );
    // Same class through case-folded duplicate keys (canonical merge).
    let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: a\r\nHOST: b\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_RENDER.as_bytes(),
        "case-folded dup Host keys merge under one canonical key in Go"
    );
    // Missing Host on >=1.1 non-CONNECT, non-PRI heads: detailed 400
    // ("missing required Host header").
    let (render, err) = reject_bytes(b"GET /x HTTP/1.1\r\nUser-Agent: t\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_MISSING_HOST_RENDER.as_bytes(),
        "missing-Host must render the detailed 163B 400"
    );
    assert!(err.contains("missing required Host header"), "got: {err}");
    // Malformed Host value: detailed 149B (no version gate in Go).
    let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h/x\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_MALFORMED_HOST_RENDER.as_bytes(),
        "malformed-Host must render the detailed 149B 400"
    );
    // SPACE in a header NAME (issue 34540 noCanon survivor): detailed
    // 145B.
    let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h\r\nBad Name: y\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_INVALID_HEADER_NAME_RENDER.as_bytes(),
        "space-in-name must render the detailed 145B 400"
    );
    // CTL in a header VALUE: Go's detailed invalid-value conn gate is
    // UNREACHABLE (textproto errors at read) — the generic 400 answers.
    let (render, err) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h\r\nX-A: ok\x01bad\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_RENDER.as_bytes(),
        "CTL value byte dies at textproto read: generic 400, NOT the detailed arm"
    );
    assert!(err.contains("CTL byte in value"), "got: {err}");
    // Colonless header line: textproto missing-colon read error →
    // generic 400.
    let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h\r\nNoColonHere\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_RENDER.as_bytes(),
        "colonless record renders the generic 400"
    );
    // Leading-SP first header line: "malformed MIME header initial
    // line" → generic 400.
    let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\n Bad\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_RENDER.as_bytes(),
        "initial-line leading whitespace renders the generic 400"
    );
    // Parseable non-1.x version (HTTP/2.0) past every read gate:
    // detailed 505 (http1ServerSupportsRequest).
    let (render, err) = reject_bytes(b"GET /x HTTP/2.0\r\nHost: h\r\n\r\n").await;
    assert_eq!(
        render,
        http::GO_505_RENDER.as_bytes(),
        "HTTP/2.0 head must render the detailed 505"
    );
    assert!(err.contains("unsupported protocol version"), "got: {err}");
    // PRI * HTTP/2.0 WITH headers and no Host is NOT the h2-upgrade
    // zero-header exemption: missing-Host fires.
    let (render, _) = reject_bytes(b"PRI * HTTP/2.0\r\nX-A: b\r\n\r\n").await;
    assert_eq!(
        render,
        GO_400_MISSING_HOST_RENDER.as_bytes(),
        "PRI-with-headers has no missing-Host exemption"
    );
}

/// Round-17 audit F7 rows that must still FORWARD (Go serves them):
/// HTTP/1.0 has no Host requirement, CONNECT is exempt from the
/// missing-Host gate, and the h2c-preface "PRI * HTTP/2.0" zero-header
/// head clears every gate (its scheme-500 fate is decided later, at
/// the handler — as in Go, where the request is served to the handler
/// and the plugin's RoundTrip errors on the empty scheme).
#[tokio::test]
async fn f7_gates_spare_served_classes() {
    // HTTP/1.0 without Host: protoAtLeast(1,1) false — no gate.
    let head = build_forward(b"GET /x HTTP/1.0\r\n\r\n", &Default::default(), None).await;
    assert!(
        head.starts_with("GET /x HTTP/1.1"),
        "1.0 head forwards: {head}"
    );
    // HTTP/1.0 ignores Transfer-Encoding (Issue 12785).
    let head = build_forward(
        b"GET /x HTTP/1.0\r\nTransfer-Encoding: gzip\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert!(
        head.starts_with("GET /x HTTP/1.1"),
        "1.0 TE head forwards: {head}"
    );
    // CONNECT heads are exempt from the missing-Host gate.
    let head = build_forward(b"CONNECT h:80 HTTP/1.1\r\n\r\n", &Default::default(), None).await;
    assert!(
        head.starts_with("CONNECT h:80 HTTP/1.1"),
        "CONNECT no-Host forwards: {head}"
    );
    // The h2c preface: zero headers → isH2Upgrade → the missing-Host
    // gate skips it (only the malformed/name gates could catch it).
    let head = build_forward(b"PRI * HTTP/2.0\r\n\r\n", &Default::default(), None).await;
    assert!(
        head.starts_with("PRI * HTTP/1.1"),
        "zero-header PRI * HTTP/2.0 clears the conn gates (outbound line always 1.1): {head}"
    );
    // An empty Host VALUE passes Go's ValidHostHeader (empty is legal)
    // — forwarded, not 400'd.
    let head = build_forward(
        b"GET /x HTTP/1.1\r\nHost: \r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert!(
        head.starts_with("GET /x HTTP/1.1"),
        "empty Host value forwards: {head}"
    );
    // HTAB inside a header value is legal (only CTL < 0x20 minus HTAB
    // dies at read).
    let head = build_forward(
        b"GET /x HTTP/1.1\r\nHost: h\r\nX-A: y \tz\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert!(
        head.starts_with("GET /x HTTP/1.1"),
        "HTAB in value forwards: {head}"
    );
}

/// Round-17 audit F7: `walk_leg_head` textproto-shape facts feeding
/// the gates — Host record counting (incl. fold continuation joining
/// and case-folded keys), value shape, and every read-time error
/// class the generic 400 render answers.
#[test]
fn f7_walk_leg_head_textproto_shapes() {
    // Host line + a folded header: the fold joins X-A's value with one
    // space; Host counts once with the TrimLeft'd value.
    let w = walk_leg_head("GET / HTTP/1.1\r\nX-A: b\r\n \t c\r\nHost:  h\r\n\r\n").unwrap();
    assert_eq!(w.header_groups, 2, "two records, got: {w:?}");
    assert_eq!(w.host_groups, 1, "one Host record, got: {w:?}");
    assert_eq!(
        w.host_value.as_deref(),
        Some("h"),
        "Host value TrimLeft'd, got: {w:?}"
    );
    // Case-folded keys are one canonical Host (Go lowercases at read).
    let w = walk_leg_head("GET / HTTP/1.1\r\nHOST: a\r\nhost: b\r\n\r\n").unwrap();
    assert_eq!(w.host_groups, 2, "two canonical-Host records, got: {w:?}");
    assert_eq!(
        w.host_value.as_deref(),
        Some("a"),
        "first Host value wins, got: {w:?}"
    );
    // SPACE in a key sets the flag but is not a read error.
    let w = walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nBad Name: y\r\n\r\n").unwrap();
    assert!(w.name_has_space, "space key survives the read, got: {w:?}");
    assert_eq!(w.host_groups, 1);
    // "Host " (trailing space) is NOT the Host key — canonical merge
    // keeps it separate.
    let w = walk_leg_head("GET / HTTP/1.1\r\nHost : h\r\n\r\n").unwrap();
    assert_eq!(w.host_groups, 0, "'Host ' never canonicalizes to Host");
    assert!(w.name_has_space);
    // A space-only line between records is an obs-fold continuation
    // of the OPEN record — it never starts a record, and it joins
    // with a ' ' that survives (reader.go appends the join space
    // before trimming the piece): Host "h" + " \t " folds to stored
    // "h ", which the consumer's ValidHostHeader gate rejects (the
    // 149B malformed-Host render). The round-17 code skipped
    // empty-piece folds and stored "h" (served/forwarded).
    let w = walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\n \t \r\nX-A: b\r\n\r\n").unwrap();
    assert_eq!(w.header_groups, 2);
    assert_eq!(
        w.host_value.as_deref(),
        Some("h "),
        "all-WS fold appends the join space, got: {w:?}"
    );
    // PR-review R1 pin: "Host: b" + a single all-whitespace fold
    // (" ") — stored "b " (space join unconditional, not "b").
    let w = walk_leg_head("GET / HTTP/1.1\r\nHost: b\r\n \r\n\r\n").unwrap();
    assert_eq!(
        w.host_value.as_deref(),
        Some("b "),
        "single-space fold appends the join space, got: {w:?}"
    );
    // Read-time error classes (each answers the generic 400 e2e).
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\n Bad\r\n\r\n").is_err(),
        "initial-line fold"
    );
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\nNoColon\r\n\r\n").is_err(),
        "colonless"
    );
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\n: v\r\n\r\n").is_err(),
        "empty key"
    );
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\nX-B\x01d: v\r\n\r\n").is_err(),
        "CTL in key"
    );
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: ok\x01bad\r\n\r\n").is_err(),
        "CTL in value"
    );
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: v\x7fz\r\n\r\n").is_err(),
        "DEL in value"
    );
    // Leading CTL in a value errors too (Go validates the raw
    // post-colon bytes before TrimLeft).
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: \x01v\r\n\r\n").is_err(),
        "leading CTL in value"
    );
    // Folded content is CTL-scanned.
    assert!(
        walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: b\r\n \x01c\r\n\r\n").is_err(),
        "CTL in folded piece"
    );
    // HTAB is legal in values; the head-terminator "" and whitespace
    // lines never count as records.
    let w = walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: y \tz\r\n\r\n").unwrap();
    assert_eq!(w.header_groups, 2);
    assert_eq!(w.host_groups, 1);
}

/// Round-18 audit L2 pin: an obs-fold under a STRIPPED hop-by-hop
/// record must be swallowed with it — never emitted as a bare line
/// that obs-folds onto the preceding EMITTED record at the backend
/// (worst case appending " folded" to the "Host:" line that follows
/// the stripped Proxy-Authorization in Go's canonical head order).
/// RED on the pre-fix loop: the fold re-emitted raw, byte-exact
/// compare fails with "Host: a folded".
#[tokio::test]
async fn l2_hop_stripped_record_fold_swallowed() {
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: a\r\nProxy-Authorization: secret\r\n \tfolded\r\nUser-Agent: t\r\n\r\n",
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(
        head, "GET /p HTTP/1.1\r\nHost: a\r\nUser-Agent: t\r\nConnection: close\r\n\r\n",
        "stripped hop record AND its fold must vanish from the forwarded head"
    );
}

/// Round-18 audit L2 pin, request_headers-override arm: a fold under a
/// record that request_headers will REPLACE (Go Header.Set replaces
/// the whole record, folded value included) must be swallowed too —
/// the pre-fix loop emitted it as an orphan line that obs-folded onto
/// whatever the override re-injection emitted above it.
#[tokio::test]
async fn l2_overridden_record_fold_swallowed() {
    let mut request_headers = std::collections::HashMap::new();
    request_headers.insert("x-a".to_string(), "2".to_string());
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: a\r\nX-A: 1\r\n folded\r\n\r\n",
        &request_headers,
        None,
    )
    .await;
    assert_eq!(
        head, "GET /p HTTP/1.1\r\nHost: a\r\nx-a: 2\r\nConnection: close\r\n\r\n",
        "overridden record's fold must vanish; only the injected value reaches the backend"
    );
}

/// Round-18 audit L3 pin (server-side vhost mirror: vhost.rs round-13
/// empty-XFF pin): an EMPTY-value X-Forwarded-For row is a real chain
/// element — Go `strings.Join(prior, ", ")` (reverseproxy.go
/// setXForwarded) keeps empty elements, so a sole empty row emits
/// ", {peer}" with the leading comma. The old ASCII-trim +
/// non-empty gate dropped the row and emitted a bare peer line.
#[tokio::test]
async fn l3_empty_xff_row_kept_in_chain() {
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: \r\nUser-Agent: t\r\n\r\n",
        &Default::default(),
        Some("203.0.113.9".parse().unwrap()),
    )
    .await;
    let lines = xff_lines(&head);
    assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
    assert_eq!(
        lines[0], "X-Forwarded-For: , 203.0.113.9",
        "empty row contributes an empty chain element (leading comma)"
    );
}

/// Round-18 audit L3 pin: obs-fold continuations are part of their
/// row's STORED value (Go textproto joins ' ' + trimmed piece), so an
/// inbound folded XFF row must merge into one chain element, then join
/// the following rows — `1.2.3.4 5.6.7.8, 9.9.9.9, {peer}`.
#[tokio::test]
async fn l3_xff_fold_merges_into_row_value() {
    let head = build_forward(
        b"GET /p HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.4\r\n 5.6.7.8\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
        &Default::default(),
        Some("203.0.113.9".parse().unwrap()),
    )
    .await;
    let lines = xff_lines(&head);
    assert_eq!(
        lines.len(),
        1,
        "exactly one canonical XFF line, got: {lines:?}"
    );
    assert_eq!(
        lines[0], "X-Forwarded-For: 1.2.3.4 5.6.7.8, 9.9.9.9, 203.0.113.9",
        "fold merges into its row's value with a single space; rows join with ', '"
    );
}

/// Pin for `serve_plugin`'s reaping: a `JoinSet` retains a finished
/// task's cell until its handle is joined, so `len` stays at the
/// cumulative spawn count — the leak the accept loop must not inherit.
/// `reap_finished_handlers` drops exactly those finished entries.
#[tokio::test]
async fn reap_finished_handlers_releases_finished_tasks() {
    const N: usize = 8;
    let mut handlers: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    // Capacity N, so each send cannot block and is the task's last action:
    // receiving all N messages proves every task body has run to
    // completion.
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(N);
    for _ in 0..N {
        let done_tx = done_tx.clone();
        handlers.spawn(async move {
            let _ = done_tx.send(()).await;
        });
    }
    drop(done_tx);
    for _ in 0..N {
        done_rx.recv().await.expect("handler task completed");
    }
    // Let the runtime finish JoinSet bookkeeping for the completed tasks.
    tokio::task::yield_now().await;

    assert_eq!(
        handlers.len(),
        N,
        "finished-but-unjoined tasks are retained by the JoinSet (the leak)"
    );
    reap_finished_handlers(&mut handlers);
    assert_eq!(
        handlers.len(),
        0,
        "reaping must release every finished task"
    );
}

/// Pin the accept-loop idiom the fix relies on: reaping once per
/// accepted connection keeps the listener's `JoinSet` bounded by
/// in-flight handlers, not by cumulative accepts. Each iteration is
/// `serve_plugin`'s accept arm (spawn, then reap) minus the socket.
#[tokio::test]
async fn per_accept_reap_keeps_joinset_bounded() {
    const ACCEPTS: usize = 64;
    let mut handlers: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let mut max_len = 0;
    for _ in 0..ACCEPTS {
        handlers.spawn(async {});
        reap_finished_handlers(&mut handlers);
        max_len = max_len.max(handlers.len());
        // Let the handler body run; in the real loop the spawned task
        // runs concurrently and is reaped by a later accept.
        tokio::task::yield_now().await;
    }
    reap_finished_handlers(&mut handlers);
    assert!(
        max_len <= 2,
        "JoinSet grew to {max_len}; it must track concurrency, not {ACCEPTS} cumulative accepts"
    );
    assert_eq!(handlers.len(), 0, "all finished handlers released");
}
