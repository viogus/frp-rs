//! HTTP/2 (TLS ALPN `h2`) support for the `https2http` / `https2https` plugins.
//!
//! Go frp's `https2http` / `https2https` plugins accept HTTP/2 clients on the
//! TLS listener when `enableHTTP2` is not explicitly `false` (default `true`):
//! `net/http` negotiates h2 via ALPN and `httputil.ReverseProxy` forwards each
//! request to the backend as plain HTTP/1.1 (with `requestHeaders` injection
//! and `hostHeaderRewrite`). The byte-level plugin bridge cannot decode h2
//! frames, so this module implements the h2 path on top of the `h2` crate —
//! the same approach as the server-side h2c vhost path
//! (`frp-server/src/vhost_h2c.rs`): decode inbound h2 requests, forward to the
//! backend as HTTP/1.1, and re-encode the backend's HTTP/1.1 response
//! (including chunked decoding) as h2 frames.
//!
//! `http2http` / `http2https` are unaffected: Go defines no `enableHTTP2`
//! field on those options (plaintext inbound, HTTP/1.1 only).

use std::collections::HashMap;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use frp_core::transport::set_nodelay;

/// Backend the h2 request is forwarded to. `https2http` uses plain TCP;
/// `https2https` wraps it in TLS (Go https2https.go connects with
/// `InsecureSkipVerify=true`, see the plugin's connector construction).
#[derive(Clone)]
pub(crate) enum Backend {
    Plain {
        host: String,
        port: u16,
    },
    Tls {
        connector: tokio_rustls::TlsConnector,
        host: String,
        port: u16,
    },
}

type DynStream = Box<dyn DynIo>;

trait DynIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DynIo for T {}

/// Serve one inbound TLS connection whose ALPN negotiated `h2`.
pub(crate) async fn serve_h2_connection<S>(
    stream: S,
    target: String,
    host_rewrite: String,
    request_headers: HashMap<String, String>,
    backend: Backend,
    real_peer: std::net::IpAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection: h2::server::Connection<S, Bytes> = match h2::server::Builder::new()
        // Bound concurrent streams like Go's http.Server (default 250) to
        // cap per-connection memory (same as the vhost h2c path).
        .max_concurrent_streams(100)
        // Go parity: the https2http/https2https plugins serve with net/http
        // (x/net/http2 defaultMaxHeaderListSize = 16 MiB), so legitimately
        // large header lists — big Cookie jars, JWTs — must not be rejected.
        // Unlike the server-side vhost h2c path (frp-server vhost_h2c.rs),
        // which deliberately stays at 4096 because it accepts connections
        // from ANY client on an untrusted public surface, this listener is
        // the operator's own: the plugin binds 127.0.0.1:local_port and
        // serves only the local user's browser, so 16 MiB is safe here.
        .max_header_list_size(16 * 1024 * 1024)
        .handshake(stream)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "https plugin h2 handshake failed");
            return;
        }
    };

    // Per-stream handlers, collected so they cannot outlive this h2
    // connection. The enclosing serve_plugin JoinSet tracks the connection
    // handler task only — a bare spawn here would escape it, leaving an
    // in-flight stream (holding its backend TCP connection) detached until
    // its own I/O resolves after the connection is gone.
    let mut streams: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        match connection.accept().await {
            Some(Ok((request, respond))) => {
                let target = target.clone();
                let host_rewrite = host_rewrite.clone();
                let request_headers = request_headers.clone();
                let backend = backend.clone();
                streams.spawn(async move {
                    if let Err(e) = handle_stream(
                        request,
                        respond,
                        &target,
                        &host_rewrite,
                        &request_headers,
                        backend,
                        real_peer,
                    )
                    .await
                    {
                        debug!(error = %e, "https plugin h2 stream error");
                    }
                });
                // Reap completed stream tasks so their JoinSet nodes and
                // outputs do not accumulate for this connection's lifetime —
                // a keep-alive h2 connection can open hundreds of streams,
                // but memory and scan cost must track concurrency, not
                // cumulative stream count. Errors are already logged inside
                // the handler, so the () output is dropped.
                while streams.try_join_next().is_some() {}
            }
            Some(Err(e)) => {
                debug!(error = %e, "https plugin h2 connection error");
                break;
            }
            None => break,
        }
    }
    // Streams cannot outlive the connection (Go http.Server.Close() closes
    // active streams too): abort any still-running stream task — a stall
    // against the backend must not linger detached past the connection.
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

/// Handle one HTTP/2 stream: forward to the backend as plain HTTP/1.1 and
/// re-encode the backend's response (with chunked decoding) as h2 frames.
async fn handle_stream(
    request: http::Request<RecvStream>,
    respond: SendResponse<Bytes>,
    target: &str,
    host_rewrite: &str,
    request_headers: &HashMap<String, String>,
    backend: Backend,
    real_peer: std::net::IpAddr,
) -> Result<(), h2::Error> {
    let has_content_length = request.headers().contains_key("content-length");
    // Declared Content-Length for the request body. The h2 crate validates
    // content-length per RFC 7540 §8.1.2.6 before delivering the request, so
    // an unparseable value is unreachable in practice; a None falls back to
    // forwarding all data frames (matches the previous behavior).
    let declared_length = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let head = build_http1_request_head(
        &request,
        host_rewrite,
        request_headers,
        real_peer,
        request.body().is_end_stream(),
    );

    // A refused/unreachable backend answers 502 (Go ReverseProxy ErrorHandler).
    let remote = match connect_backend(&backend).await {
        Ok(r) => r,
        Err(e) => {
            debug!(target = %target, error = %e, "https plugin h2 backend connect failed");
            return send_h2_error(respond, 502, &[], Bytes::new()).await;
        }
    };

    // Forward the h2 request body on a separate task so a slow upload cannot
    // block reading the backend's (possibly early) response — Go ReverseProxy
    // streams both directions concurrently (vhost_h2c uses the same pattern
    // through a duplex pair). A head without Content-Length was emitted with
    // `Transfer-Encoding: chunked` (Go http.Transport behavior for
    // unknown-length bodies), so body bytes are framed accordingly.
    let (mut remote_r, mut remote_w) = tokio::io::split(remote);
    let mut body = request.into_body();
    let end_stream = body.is_end_stream();
    let body_task = tokio::spawn(async move {
        if remote_w.write_all(&head).await.is_err() {
            return;
        }
        // Forward at most the declared Content-Length body bytes: surplus h2
        // DATA frames are dropped (Go's http.Transport body reader stops at
        // the declared length) so the backend cannot misread the surplus as
        // a pipelined request on the HTTP/1.1 connection.
        let mut remaining = declared_length;
        while let Some(Ok(data)) = body.data().await {
            let len = data.len();
            if !data.is_empty() {
                let (next_remaining, n) = cap_chunk(len, remaining);
                if remaining.is_none() {
                    // Chunked framing for an unknown-length body (no
                    // Content-Length): the full chunk is written framed.
                    let frame = format!("{:X}\r\n", len);
                    if remote_w.write_all(frame.as_bytes()).await.is_err()
                        || remote_w.write_all(&data).await.is_err()
                        || remote_w.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                } else if n > 0 {
                    // Content-Length bounded: forward at most the remaining
                    // bytes; the surplus is dropped.
                    if remote_w.write_all(&data[..n]).await.is_err() {
                        return;
                    }
                }
                remaining = next_remaining;
            }
            let _ = body.flow_control().release_capacity(len);
        }
        if !has_content_length && !end_stream {
            // Stream had an open body: terminate the chunked framing.
            if let Err(e) = remote_w.write_all(b"0\r\n\r\n").await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
        }
        if let Err(e) = remote_w.flush().await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        if let Err(e) = remote_w.shutdown().await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
    });

    // Read the backend's HTTP/1.1 response and re-encode it as h2. Once the
    // response is fully relayed the body forwarder has served its purpose —
    // stop it so the h2 stream can wind down even if the client is still
    // trickling request bytes (same as vhost_h2c).
    let result = stream_h2_response(&mut remote_r, respond).await;
    body_task.abort();
    result
}

async fn connect_backend(backend: &Backend) -> std::io::Result<DynStream> {
    match backend {
        Backend::Plain { host, port } => {
            let s = TcpStream::connect((host.as_str(), *port)).await?;
            set_nodelay(&s);
            Ok(Box::new(s))
        }
        Backend::Tls {
            connector,
            host,
            port,
        } => {
            let tcp = TcpStream::connect((host.as_str(), *port)).await?;
            set_nodelay(&tcp);
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad backend hostname")
                })?;
            let tls = connector.connect(server_name, tcp).await?;
            Ok(Box::new(tls))
        }
    }
}

/// Bytes of one request-body chunk to forward to the backend, given the
/// remaining declared Content-Length. Surplus beyond the declared length is
/// dropped — Go's `http.Transport` body reader stops at the declared length,
/// so the surplus must not reach the HTTP/1.1 connection as a pipelined
/// request. Returns `(new remaining budget, bytes to write)`.
///
/// `None` remaining means the request had no Content-Length: the whole chunk
/// is forwarded (the caller applies chunked framing) and `None` is returned.
fn cap_chunk(len: usize, remaining: Option<usize>) -> (Option<usize>, usize) {
    match remaining {
        None => (None, len),
        Some(rem) if rem >= len => (Some(rem - len), len),
        Some(rem) => (Some(0), rem),
    }
}

/// Hop-by-hop headers dropped when converting between HTTP/1.1 and HTTP/2
/// (RFC 7540 §8.1.2.2 forbids them; Go's net/http drops them too). This is
/// Go httputil.hopHeaders' full list — proxy-authenticate, proxy-
/// authorization, te, and trailer were missing, so a backend's
/// Proxy-Authenticate challenge would have been forwarded to the h2 client
/// as a connection-scoped header, and a client's Proxy-Authorization would
/// have leaked to the backend.
fn is_hop_by_hop(name: &str) -> bool {
    const HOP: [&str; 9] = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Re-encode an h2 request as an HTTP/1.1 request head with the plugin's
/// `request_headers` injected (Go `Header.Set` semantics: an existing header
/// with the same name is replaced) and `host_header_rewrite` applied. A body
/// without Content-Length is forwarded with `Transfer-Encoding: chunked` (Go
/// http.Transport behavior for unknown-length bodies).
///
/// Generic over the body so tests can drive it with a body-less request
/// (h2's `RecvStream` has no public constructor); `body_end_stream` is the
/// h2 end-stream flag the caller reads off the real stream.
fn build_http1_request_head<B>(
    request: &http::Request<B>,
    host_rewrite: &str,
    request_headers: &HashMap<String, String>,
    real_peer: std::net::IpAddr,
    body_end_stream: bool,
) -> Vec<u8> {
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(request.method().as_str().as_bytes());
    head.push(b' ');
    let target = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    head.extend_from_slice(target.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");

    // M9 (Go https2http.go:44-46 parity): the plugin appends the REAL tunnel
    // peer as X-Forwarded-For (SetXForwarded runs on every request, h1 and h2
    // alike). A configured x-forwarded-for request header replaces the whole
    // chain (Go Header.Set runs after SetXForwarded), so the append is
    // skipped when one is configured; otherwise the client's own chain is
    // preserved and the peer appended, exactly like the h1 path in
    // read_request_and_build_forward.
    let configured_xff = request_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("x-forwarded-for"));
    let client_xff: Vec<String> = if configured_xff {
        Vec::new()
    } else {
        request
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str().eq_ignore_ascii_case("x-forwarded-for"))
            .filter_map(|(_, value)| value.to_str().ok().map(|s| s.to_string()))
            .collect()
    };

    let has_content_length = request.headers().contains_key("content-length");
    for (name, value) in request.headers() {
        let n = name.as_str();
        if is_hop_by_hop(n) || n.eq_ignore_ascii_case("host") {
            continue;
        }
        // Skip headers that request_headers will override (Go Header.Set).
        if request_headers.keys().any(|k| k.eq_ignore_ascii_case(n)) {
            continue;
        }
        // X-Forwarded-For is re-emitted canonically below with the tunnel
        // peer appended (Go SetXForwarded semantics).
        if !configured_xff && n.eq_ignore_ascii_case("x-forwarded-for") {
            continue;
        }
        // Guard against HTTP header injection via h2 header values — Go's
        // http.Transport rejects CR/LF in header values.
        if value.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
            continue;
        }
        head.extend_from_slice(n.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    // Host: host_header_rewrite wins; "host" in request_headers is skipped
    // (Go's Header.Set cannot set Host — it is controlled by
    // hostHeaderRewrite or the original request); else the `:authority`.
    let host_value = if !host_rewrite.is_empty() {
        Some(host_rewrite.as_bytes())
    } else {
        request.uri().authority().map(|a| a.as_str().as_bytes())
    };
    if let Some(h) = host_value {
        head.extend_from_slice(b"Host: ");
        head.extend_from_slice(h);
        head.extend_from_slice(b"\r\n");
    }
    // Inject configured request headers (Go rewriteHTTPPluginRequest).
    for (k, v) in request_headers {
        if k.eq_ignore_ascii_case("host") || is_hop_by_hop(k) {
            continue;
        }
        if v.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
            continue;
        }
        head.extend_from_slice(k.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(v.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    // Append the real tunnel peer to the client's X-Forwarded-For chain (Go
    // SetXForwarded: `strings.Join(prior, ", ") + ", " + clientIP`). Skipped
    // when a configured x-forwarded-for replaced the chain above.
    if !configured_xff {
        let mut xff = client_xff.join(", ");
        if xff.is_empty() {
            xff = real_peer.to_string();
        } else {
            xff.push_str(", ");
            xff.push_str(&real_peer.to_string());
        }
        head.extend_from_slice(b"X-Forwarded-For: ");
        head.extend_from_slice(xff.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if !has_content_length {
        if body_end_stream {
            head.extend_from_slice(b"Content-Length: 0\r\n");
        } else {
            head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    head
}

/// Send a body-less (or single-chunk) HTTP/2 error response.
async fn send_h2_error(
    mut respond: SendResponse<Bytes>,
    status: u16,
    extra: &[(&str, &str)],
    body: Bytes,
) -> Result<(), h2::Error> {
    let mut resp = http::Response::builder()
        .status(status)
        .body(())
        .expect("h2 plugin status code (502) is a valid HTTP status");
    for &(k, v) in extra {
        let name = http::header::HeaderName::from_bytes(k.as_bytes())
            .expect("h2 plugin extra header name must be valid");
        resp.headers_mut().insert(
            name,
            http::HeaderValue::from_str(v).expect("h2 plugin extra header value must be valid"),
        );
    }
    if body.is_empty() {
        respond.send_response(resp, true)?;
        return Ok(());
    }
    resp.headers_mut()
        .insert("content-type", http::HeaderValue::from_static("text/html"));
    let mut send = respond.send_response(resp, false)?;
    send.send_data(body, true)?;
    Ok(())
}

/// Read bytes until the end of the HTTP/1.1 response head, returning head +
/// any body bytes that arrived with it.
///
/// Head end follows Go `textproto` semantics (the engine behind
/// `http.ReadResponse`): each line ends at the next `\n` with ONE trailing
/// `\r` stripped, and the first empty line ends the head — so LF-only and
/// mixed-EOL backends are legal, not just `\r\n\r\n`.
async fn read_until_head(r: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if frp_core::textproto::head_end(&buf).is_some() {
            return Ok(buf);
        }
        // Guard against a malicious backend with unbounded headers.
        if buf.len() > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response head exceeds 1 MiB",
            ));
        }
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before response head",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Parsed HTTP/1.1 response head.
struct ParsedHead {
    status: u16,
    headers: Vec<(http::HeaderName, http::HeaderValue)>,
    /// Offset into the original head buffer where the body begins.
    body_offset: usize,
}

fn trim_ascii_ws(mut b: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = b.split_first() {
        if first == b' ' || first == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = b.split_last() {
        if last == b' ' || last == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn parse_response_head(head: &[u8]) -> Option<ParsedHead> {
    // Head end under Go textproto semantics (same helper as read_until_head),
    // so LF-only / mixed-EOL backends parse instead of falling through to the
    // caller's malformed-head 502.
    let head_end = frp_core::textproto::head_end(head)?;
    let head_bytes = &head[..head_end];
    // Status line = first line under the same textproto rule: up to the next
    // `\n`, ONE trailing `\r` stripped.
    let first_nl = head_bytes.iter().position(|&b| b == b'\n')?;
    let mut status_line = &head_bytes[..first_nl];
    if status_line.last() == Some(&b'\r') {
        status_line = &status_line[..status_line.len() - 1];
    }
    let status_line = std::str::from_utf8(status_line).ok()?;
    let mut parts = status_line.split_whitespace();
    // Go http.ReadResponse gates (response.go — round-3 review): the
    // version token must be one of ParseHTTPVersion's exact-match set and
    // the code token exactly 3 digits BEFORE conversion, so "HTTP/9.9 200"
    // / "HTTP/1.1 0200 OK" / "FOO 200 OK" are all malformed → 502, never
    // forwarded.
    let version = parts.next()?;
    if !frp_core::textproto::is_valid_http_version(version) {
        return None;
    }
    let code_token = parts.next()?;
    if code_token.len() != 3 || !code_token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status: u16 = code_token.parse().ok()?;

    let mut headers = Vec::new();
    // Header lines run from after the status line to head_end (which includes
    // the terminating blank line); splitting on '\n' with a single trailing
    // '\r' strip makes the final blank line split into an empty entry that
    // the empty check below skips — uniform for CRLF and LF heads alike.
    for line in head_bytes[first_nl + 1..head_end].split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = trim_ascii_ws(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|&b| b == b':')?;
        let name = std::str::from_utf8(&line[..colon]).ok()?;
        let value = std::str::from_utf8(trim_ascii_ws(&line[colon + 1..])).ok()?;
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.push((n, v));
        }
    }
    Some(ParsedHead {
        status,
        headers,
        body_offset: head_end,
    })
}

fn header_value<'a>(
    headers: &'a [(http::HeaderName, http::HeaderValue)],
    name: &str,
) -> Option<&'a http::HeaderValue> {
    headers
        .iter()
        .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

fn parse_hex(b: &[u8]) -> std::io::Result<usize> {
    let s = std::str::from_utf8(b)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))?;
    let s = s.trim();
    // Go parseHexUint (net/http/transfer.go) accepts ONLY 0-9a-fA-F — a
    // leading '+' is "invalid byte in chunk length". Rust's from_str_radix
    // accepts "+5" for any radix; reject the '+' explicitly ('-' already
    // fails from_str_radix for radix 16). Twin of frp-server vhost_h2c.rs.
    if s.starts_with('+') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad chunk size",
        ));
    }
    usize::from_str_radix(s, 16)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))
}

/// Per-slice cap for streaming chunked bodies (round 10 MEDIUM): a chunk is
/// forwarded in bounded slices instead of one `read_exact(size)` allocation.
const MAX_CHUNK_SIZE: usize = 64 * 1024;

/// Incremental response-body reader that starts with the bytes that arrived
/// together with the response head.
struct BodyReader<'a, R: AsyncRead + Unpin> {
    inner: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a, R: AsyncRead + Unpin> BodyReader<'a, R> {
    fn new(inner: &'a mut R, initial: Vec<u8>) -> Self {
        Self {
            inner,
            buf: initial,
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    /// Append more bytes from the inner stream. Returns `Ok(false)` on EOF.
    /// The consumed prefix is dropped before refilling, so `self.buf` never
    /// holds more than the unconsumed portion plus one refill — the
    /// `CHUNK_LINE_MAX` check in `read_line` on `available()` is therefore
    /// the true memory bound (a `buf.len()` check would double-count bytes
    /// already consumed, and without the drain the consumed prefix could
    /// accumulate when lines are split across reads with a tail left over).
    async fn read_more(&mut self) -> std::io::Result<bool> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut tmp = [0u8; 8192];
        let n = self.inner.read(&mut tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    async fn read_exact(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n.min(8192));
        while out.len() < n {
            if self.available().is_empty() && !self.read_more().await? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in response body",
                ));
            }
            let take = (n - out.len()).min(self.available().len());
            out.extend_from_slice(&self.available()[..take]);
            self.consume(take);
        }
        Ok(out)
    }

    /// Read one CRLF (or LF) terminated line including its terminator.
    ///
    /// A line exceeding [`super::CHUNK_LINE_MAX`] errors instead of growing
    /// `self.buf` without bound (a backend that never terminates its chunk
    /// line would otherwise balloon memory). Same cap semantics as the
    /// mod.rs body reader: the check runs on the terminator-found paths too,
    /// so an over-long line is never returned.
    async fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            let avail = self.available();
            if let Some(rel) = avail.windows(2).position(|w| w == b"\r\n") {
                let line = avail[..rel + 2].to_vec();
                if line.len() > super::CHUNK_LINE_MAX {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "chunk line too long",
                    ));
                }
                self.consume(rel + 2);
                return Ok(line);
            }
            if let Some(rel) = avail.iter().position(|&b| b == b'\n') {
                let line = avail[..rel + 1].to_vec();
                if line.len() > super::CHUNK_LINE_MAX {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "chunk line too long",
                    ));
                }
                self.consume(rel + 1);
                return Ok(line);
            }
            // No terminator in the buffer: the available portion is one
            // (partial) line — bound it before extending. Checking
            // `available()` (not `buf.len()`) keeps consumed bytes out of
            // the accounting when `pos > 0`; `read_more` drains the consumed
            // prefix on refill, so this is also the true memory bound. A
            // line exactly at the cap whose terminator is split across reads
            // is still served (the scan above finds it once the extension
            // lands; the line-length check on the terminator paths then
            // applies).
            if self.available().len() > super::CHUNK_LINE_MAX {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk line too long",
                ));
            }
            if !self.read_more().await? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in chunk line",
                ));
            }
        }
    }
}

fn is_blank_line(b: &[u8]) -> bool {
    b.iter().all(|&c| matches!(c, b'\r' | b'\n' | b' ' | b'\t'))
}

/// Decode a chunked response body and stream it as HTTP/2 DATA frames.
/// Read errors truncate the body (Go treats an aborted backend body as EOF).
async fn stream_chunked_body(
    reader: &mut BodyReader<'_, impl AsyncRead + Unpin>,
    send: &mut SendStream<Bytes>,
) -> Result<(), h2::Error> {
    loop {
        let line = match reader.read_line().await {
            Ok(l) => l,
            Err(_) => return Ok(()),
        };
        let mut line = line.as_slice();
        if line.ends_with(b"\r\n") {
            line = &line[..line.len() - 2];
        } else if line.ends_with(b"\n") {
            line = &line[..line.len() - 1];
        }
        let line = trim_ascii_ws(line);
        if line.is_empty() {
            continue;
        }
        // Drop chunk extensions ("size;ext=val").
        let size_part = line.split(|&b| b == b';').next().unwrap_or(line);
        let size = match parse_hex(trim_ascii_ws(size_part)) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        if size == 0 {
            // Trailing headers until the final blank line (RFC 7230 §4.1.2).
            loop {
                match reader.read_line().await {
                    Ok(t) if !is_blank_line(&t) => continue,
                    Ok(_) | Err(_) => break,
                }
            }
            return Ok(());
        }
        // Round 10 (MEDIUM): `size` comes from the backend's chunk-size
        // line — buffering it in one `read_exact(size)` allocates
        // attacker-influenced memory (a misbehaving backend or proxied
        // origin can emit an arbitrarily large chunk). Stream the chunk
        // in bounded slices instead; the frame stays chunked
        // (end_stream=false on every slice).
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(MAX_CHUNK_SIZE);
            let data = match reader.read_exact(n).await {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };
            send.send_data(Bytes::from(data), false)?;
            remaining -= n;
        }
        if reader.read_exact(2).await.is_err() {
            return Ok(()); // missing trailing CRLF
        }
    }
}

/// Read the backend HTTP/1.1 response from `r`, send the HTTP/2 response head,
/// then stream the body (decoding chunked transfer-encoding) as HTTP/2 DATA
/// frames. A backend that closes before the head produces `502 Bad Gateway`
/// (Go ReverseProxy semantics).
async fn stream_h2_response<R: AsyncRead + Unpin>(
    r: &mut R,
    mut respond: SendResponse<Bytes>,
) -> Result<(), h2::Error> {
    let head = match read_until_head(r).await {
        Ok(h) => h,
        Err(_e) => {
            debug!("https plugin backend closed before response head, sending 502");
            return send_h2_error(respond, 502, &[], Bytes::new()).await;
        }
    };
    let Some(parsed) = parse_response_head(&head) else {
        debug!("https plugin backend sent a malformed response head, sending 502");
        return send_h2_error(respond, 502, &[], Bytes::new()).await;
    };
    let ParsedHead {
        status,
        headers,
        body_offset,
    } = parsed;

    let mut resp = http::Response::builder()
        .status(status)
        .body(())
        .map_err(|e| {
            debug!(
                error = %e,
                backend_status = status,
                "https plugin backend sent an invalid HTTP status code"
            );
            h2::Error::from(h2::Reason::INTERNAL_ERROR)
        })?;
    for (n, v) in &headers {
        if is_hop_by_hop(n.as_str()) {
            continue;
        }
        resp.headers_mut().insert(n.clone(), v.clone());
    }

    let content_length = header_value(&headers, "content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let chunked = header_value(&headers, "transfer-encoding")
        .map(|v| {
            v.to_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("chunked")
        })
        .unwrap_or(false);

    let mut send = respond.send_response(resp, false)?;
    let mut reader = BodyReader::new(r, head[body_offset..].to_vec());

    if chunked {
        stream_chunked_body(&mut reader, &mut send).await?;
    } else if let Some(mut remaining) = content_length {
        while remaining > 0 {
            let n = remaining.min(8192);
            let data = match reader.read_exact(n).await {
                Ok(d) => d,
                Err(_) => break, // truncated body
            };
            remaining -= data.len();
            send.send_data(Bytes::from(data), false)?;
        }
    } else {
        // No length framing: read to EOF (the backend closes the connection).
        loop {
            if reader.available().is_empty() {
                match reader.read_more().await {
                    Ok(true) => {}
                    Ok(false) | Err(_) => break,
                }
            }
            if reader.available().is_empty() {
                break;
            }
            let data = reader.available().to_vec();
            reader.consume(data.len());
            send.send_data(Bytes::from(data), false)?;
        }
    }
    send.send_data(Bytes::new(), true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_http1_request_head, cap_chunk, header_value, parse_hex, parse_response_head,
    };
    use std::collections::HashMap;

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
}
