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
        // Deliberate per-connection cap — NOT a Go default (Go's
        // http.Server allows 250 concurrent streams; 100 is this plugin's
        // own bound on per-connection memory, matching the server-side
        // vhost h2c path).
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
    // Captured before the body is consumed: a HEAD response never carries a
    // DATA body (RFC 9113 §8.1), and the no-body statuses 204/304 never do
    // either — `stream_h2_response` ends those streams at the response head
    // instead of running a body leg against bytes that can never come
    // (round-18 FIX 1, mirroring the server twin vhost_h2c's `is_head`).
    let is_head = request.method() == http::Method::HEAD;
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
    let result = stream_h2_response(&mut remote_r, respond, is_head).await;
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
/// with the same name is replaced) and `host_header_rewrite` applied.
///
/// The egress framing and hygiene follow Go `http.Transport`
/// (`transferWriter` + `Header.WriteSubset`): every forwarded value is
/// trimmed of ASCII SP/HTAB on both ends; a body without Content-Length is
/// forwarded with `Transfer-Encoding: chunked`, and its declared trailer keys
/// are re-announced on a canonical `Trailer:` line right after it; a
/// body-less request emits `Content-Length: 0` unless the method is GET or
/// HEAD, which omit the line (shouldSendContentLength, transfer.go:254-276).
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
        // Go's http.Transport writes every forwarded value through
        // textproto.TrimString (Request.write → Header.WriteSubset), so a
        // padded inbound value reaches the backend trimmed
        // (`x-pad:  abc ` → `X-Pad: abc`). Copied verbatim pre-round-18.
        // Header NAMES are still forwarded verbatim — name canonicalization
        // is a separate divergence, deliberately not part of this change.
        let value = trim_ascii_ws(value.as_bytes());
        // Guard against HTTP header injection via h2 header values — Go's
        // http.Transport rejects CR/LF in header values. (Trimming only
        // ASCII SP/HTAB cannot introduce one.)
        if value.iter().any(|&b| b == b'\r' || b == b'\n') {
            continue;
        }
        head.extend_from_slice(n.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
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
    // Inject configured request headers (Go rewriteHTTPPluginRequest). These
    // land in `outreq.Header` too, so the same TrimString pass applies on the
    // way out (Go Header.WriteSubset trims EVERY value it writes, configured
    // ones included).
    for (k, v) in request_headers {
        if k.eq_ignore_ascii_case("host") || is_hop_by_hop(k) {
            continue;
        }
        let v = trim_ascii_ws(v.as_bytes());
        if v.iter().any(|&b| b == b'\r' || b == b'\n') {
            continue;
        }
        head.extend_from_slice(k.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(v);
        head.extend_from_slice(b"\r\n");
    }
    // Append the real tunnel peer to the client's X-Forwarded-For chain (Go
    // SetXForwarded: `strings.Join(prior, ", ") + ", " + clientIP`, the
    // prior chain being the SLICE of inbound row values). Skipped when a
    // configured x-forwarded-for replaced the chain above.
    //
    // The presence test is on the ROW LIST, not on the joined string
    // (round-18 FIX 4): an EMPTY-value inbound row is a real (empty) chain
    // element — `strings.Join(["", peer], ", ")` is ", <peer>" with the
    // leading comma — while only the NO-row case (nil slice) emits the bare
    // peer. The old `xff.is_empty()` string check conflated the two and
    // dropped the row; same semantics as the h1 twin
    // (plugin/mod.rs `l3_empty_xff_row_kept_in_chain`) and the vhost.rs
    // round-13 empty-XFF pin.
    if !configured_xff {
        let mut xff = client_xff.join(", ");
        if !client_xff.is_empty() {
            xff.push_str(", ");
        }
        xff.push_str(&real_peer.to_string());
        head.extend_from_slice(b"X-Forwarded-For: ");
        head.extend_from_slice(xff.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if !has_content_length {
        // Go http.Transport egress framing (transferWriter): an open stream of
        // unknown length is chunked-framed; a body-less request emits
        // `Content-Length: 0` — except for GET and HEAD, which omit the line
        // entirely (shouldSendContentLength, transfer.go:254-276: a zero
        // length with identity coding is announced for POST/PUT/PATCH and for
        // every other method, but NOT for GET/HEAD).
        if body_end_stream {
            let m = request.method();
            if m != http::Method::GET && m != http::Method::HEAD {
                head.extend_from_slice(b"Content-Length: 0\r\n");
            }
        } else {
            head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            // Go transferWriter re-announces the trailer keys on the chunked
            // leg, immediately after the Transfer-Encoding line
            // (transfer.go:310-332). The inbound hop-by-hop `trailer`
            // declaration row is still dropped by the header loop above — the
            // canonical line emitted here is its only egress form.
            if let Some(keys) = frp_core::textproto::go_trailer_announcement(
                request
                    .headers()
                    .get_all("trailer")
                    .iter()
                    .filter_map(|v| v.to_str().ok()),
            ) {
                head.extend_from_slice(b"Trailer: ");
                head.extend_from_slice(keys.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
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
///
/// `buf` seeds the read: after swallowing an interim 1xx head, the bytes
/// past ITS terminator may already hold the final head (or its body) and
/// must replay — the loop scans the seeded buffer before touching the
/// stream (mirror of frp-server vhost_h2c's `read_until_head_from`).
async fn read_until_head(
    r: &mut (impl AsyncRead + Unpin),
    mut buf: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let mut tmp = [0u8; 4096];
    // Round-18 finding C2: the per-iteration `head_end` full-buffer rescan
    // is O(n²) for a head that arrives in many small chunks (each read
    // re-scans every byte of every earlier chunk; a drip-fed giant head
    // cost ~n²/2 comparisons). The incremental scanner is byte-identical
    // for the feed-until-`Some` pattern (same first-blank-line semantics
    // as `head_end`, frp-core textproto). `buf` is monotonic within this
    // function (seeded once, only extended), so one scanner created at
    // entry — its first feed scans the seed — is safe across reads.
    let mut scanner = frp_core::textproto::HeadEndScanner::new();
    loop {
        // Terminator scan before the cap check (round-16 readLimit model;
        // round-18 L1 precision): the cap fires when buf.len() > 1 MiB at
        // a feed-check with no terminator found, and reads are
        // 4096-quantized — a terminated head up to ~1 MiB always serves;
        // up to ~1 MiB + 4096 serves when the terminator tail arrives in
        // the single read that crosses 1 MiB; only an unterminated head
        // errors TooLarge.
        if scanner.feed(&buf).is_some() {
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
    /// Validated Content-Length value (Go `parseContentLength`), carried out
    /// of the head parse because the stored header keeps trailing SP/HTAB
    /// (TrimLeft storage) — re-parsing the raw row would reject the legal
    /// padded form "5 " that this value was trimmed from.
    content_length: Option<u64>,
    /// Go `parseTransferEncoding` verdict (net/http/transfer.go): true only
    /// for EXACTLY one Transfer-Encoding row whose trimmed value
    /// EqualFolds "chunked". Carried out of the head parse so the body leg
    /// never re-derives the framing from the raw row (round-18 FIX 2) — a
    /// head whose TE shape Go refuses never reaches the body leg at all.
    chunked: bool,
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
    // Go http.ReadResponse splits the status line at the FIRST literal
    // space (strings.Cut, response.go) — a tab-separated
    // "HTTP/1.1\t200 OK" keeps the tab inside the version token and fails
    // ParseHTTPVersion below. split(' ') + empty-skip mirrors that
    // (multi-space between version and code stays legal, like Go's
    // TrimLeft).
    let mut parts = status_line.split(' ');
    // Go http.ReadResponse gates (net/http/response.go): the version token
    // must pass ParseHTTPVersion's LENIENT shape — exact rows HTTP/1.0/1.1,
    // else exactly-8-char `HTTP/X.Y` single-digit tokens (HTTP/9.9 200
    // parses and forwards; round-18 M1: the round-7 "exact-match set"
    // reading was a Go-source misreading) — and the code token exactly 3
    // digits BEFORE conversion, so "HTTP/1.1 0200 OK" / "FOO 200 OK" are
    // malformed → 502, never forwarded.
    let version = parts.next()?;
    if !frp_core::textproto::is_valid_http_version(version) {
        return None;
    }
    let code_token = parts.find(|p| !p.is_empty())?;
    if code_token.len() != 3 || !code_token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status: u16 = code_token.parse().ok()?;

    let mut headers: Vec<(http::HeaderName, http::HeaderValue)> = Vec::new();
    // Go textproto ReadMIMEHeader semantics (net/textproto/reader.go, the
    // engine behind ReadResponse) — round-18 M4: ANY malformed record
    // fails the WHOLE head (502), never a forwarded response missing rows.
    // The old code silently skipped rows whose name/value failed to
    // convert and re-split obs-fold lines into orphan "invalid names";
    // Go does neither. Per record, in Go order:
    //   - the block's first line must not start with SP/HTAB (initial-line
    //     error);
    //   - a record's first line must contain a colon
    //     (mustHaveFieldNameColon);
    //   - a line whose RAW first byte is SP/HTAB continues the OPEN record
    //     (readContinuedLineSlice): its both-trimmed content joins the
    //     value as ' ' + content — an all-whitespace fold contributes a
    //     bare ' ' (round-17 R1); a fold with no open record (block start
    //     only) is the initial-line error above;
    //   - the name is the bytes before the record's first colon: empty or
    //     containing any non-token byte fails (canonicalMIMEHeaderKey).
    //     Go tolerates SPACE-in-name stored uncanonicalized (issue 34540)
    //     — http::HeaderName cannot represent it, so frp-rs fails the head
    //     here (fail-closed 502 vs Go forwarding a wire-invalid name for
    //     the h2 peer to reject);
    //   - every value line is CTL-checked (validHeaderValueByte:
    //     VCHAR/SP/HTAB/obs-text only; CTL incl. DEL fails the head) — the
    //     check runs on the SP/HTAB-trimmed span, which is equivalent to
    //     Go's raw-span check because the trim removes only legal bytes;
    //   - the record's first line is end-trimmed and each fold is
    //     both-trimmed (Go trims every physical line); the stored value is
    //     the merged value with leading SP/HTAB stripped (readMIMEHeader
    //     TrimLeft) — trailing spaces survive, so "X: a" + " " folds
    //     store "a ".
    let mut record: Option<(Vec<u8>, Vec<u8>)> = None; // (name, value)
    for line in head_bytes[first_nl + 1..head_end].split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue; // head terminator (already cut by head_end)
        }
        if line[0] == b' ' || line[0] == b'\t' {
            // Continuation of the open record.
            let Some((_, value)) = record.as_mut() else {
                return None; // leading-space first line: Go initial-line error
            };
            let piece = trim_ascii_ws(line);
            if value_bytes_have_ctl(piece) {
                return None; // CTL byte in a folded value line
            }
            value.push(b' ');
            value.extend_from_slice(piece);
            continue;
        }
        // New record: flush the completed one before opening the next.
        if let Some((name, value)) = record.take() {
            let Some((n, v)) = header_row(name, value) else {
                return None; // unreachable: the gates below already passed
            };
            headers.push((n, v));
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return None; // colonless line: mustHaveFieldNameColon fails
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| name_byte_ok(b)) {
            return None; // empty or non-token name: canonicalMIMEHeaderKey
        }
        // Raw value bytes run to the physical line's end; the record-level
        // end-trim (Go trims the whole first line) drops trailing SP/HTAB
        // before the merge, and leading SP/HTAB are stripped only at
        // storage (TrimLeft) — so the merged value below starts trimmed.
        let raw_value = trim_ascii_ws(&line[colon + 1..]);
        if value_bytes_have_ctl(raw_value) {
            return None; // CTL byte in a value: validHeaderValueByte fails
        }
        record = Some((name.to_vec(), raw_value.to_vec()));
    }
    if let Some((name, value)) = record.take() {
        let Some((n, v)) = header_row(name, value) else {
            return None; // unreachable: the gates above already passed
        };
        headers.push((n, v));
    }
    // Go fixLength parity (net/http/transfer.go — round-18 M2):
    // readTransfer runs on EVERY head ReadResponse draws (interim 1xx and
    // final alike), and two+ Content-Length rows whose TrimString'ed
    // values differ make it fail — the WHOLE head is malformed (502),
    // never a response whose copied rows disagree with the body count
    // that framed it (smuggling-adjacent). Identical values dedupe to ONE
    // row (Go Issue 16490: fixLength deletes the duplicates and re-adds
    // the first trimmed value). Stored values keep trailing spaces
    // (TrimLeft storage), so rows compare like textproto.TrimString —
    // SP/HTAB trimmed at both ends.
    let mut cl_row: Option<usize> = None;
    let mut i = 0;
    while i < headers.len() {
        if headers[i].0.as_str().eq_ignore_ascii_case("content-length") {
            match cl_row {
                None => cl_row = Some(i),
                Some(first) => {
                    if trim_ascii_ws(headers[first].1.as_bytes())
                        != trim_ascii_ws(headers[i].1.as_bytes())
                    {
                        return None; // conflicting duplicate Content-Length
                    }
                    headers.remove(i); // identical: keep the first row only
                    continue;
                }
            }
        }
        i += 1;
    }
    // The surviving row's TrimString'ed value must then satisfy
    // parseContentLength (Go net/http/transfer.go, mirroring the server twin
    // vhost_h2c.rs): non-empty, all-ASCII-digits, within 63 bits — a garbage
    // ("Content-Length: abc"), empty ("Content-Length:"), or overflowing
    // value fails readTransfer → the WHOLE head is malformed (502), never a
    // response whose body is read to EOF past a declared length. Padded
    // values ("5 ") are legal; the digit gate rejects sign prefixes ("+5")
    // the way Go's ParseUint does. The validated value rides out on
    // `ParsedHead` so the body leg consumes what was TrimString'ed here.
    let mut content_length: Option<u64> = None;
    if let Some(idx) = cl_row {
        // h2 value hygiene (round-18 follow-up, mirroring the server twin
        // vhost_h2c.rs): the stored row KEEPS its trailing SP/HTAB (TrimLeft
        // storage; an all-whitespace obs-fold appends a bare ' ', so
        // "Content-Length: 5\r\n \r\n" stores "5 "), and a field value with
        // leading/trailing whitespace must not reach the h2 HEADERS frame
        // (RFC 9113 §8.2.1) — the h2 client resets the stream with
        // PROTOCOL_ERROR at the head, so the body leg below never runs.
        // Normalize the row to exactly the bytes this gate validated, at the
        // one place that both trims the value and knows the row is a
        // Content-Length; the parsed count still rides out on `ParsedHead`.
        let value = trim_ascii_ws(headers[idx].1.as_bytes()).to_vec();
        let parsed = std::str::from_utf8(&value).ok().and_then(|s| {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                s.parse::<i64>().ok()
            } else {
                None
            }
        });
        let Some(n) = parsed else {
            return None; // parseContentLength failure (Go ParseUint bitSize 63)
        };
        headers[idx].1 = http::HeaderValue::from_bytes(&value).ok()?;
        content_length = Some(n as u64);
    }
    // Go parseTransferEncoding parity (net/http/transfer.go, round-18 FIX
    // 2): a missing row is not chunked; EXACTLY one row whose trimmed value
    // EqualFolds "chunked" wins chunked framing; ANY other shape — a
    // different coding ("gzip"), a list ("chunked, gzip"), or two rows —
    // fails readTransfer, so the WHOLE head is malformed (the caller's 502)
    // rather than a body Go refuses being chunk-decoded or read to EOF. The
    // Content-Length gates above run FIRST for the same reason Go validates
    // CL before the TE framing decision (a garbage CL under chunked still
    // fails the head — round-8 F9 for the request faces).
    let mut chunked = false;
    let mut te_rows = headers
        .iter()
        .filter(|(n, _)| n.as_str().eq_ignore_ascii_case("transfer-encoding"));
    if let Some((_, value)) = te_rows.next() {
        if te_rows.next().is_none()
            && trim_ascii_ws(value.as_bytes()).eq_ignore_ascii_case(b"chunked")
        {
            chunked = true;
        } else {
            return None; // unsupported / duplicated Transfer-Encoding
        }
    }
    Some(ParsedHead {
        status,
        headers,
        content_length,
        chunked,
        body_offset: head_end,
    })
}

/// Convert one validated header record into a row. The name/value gates in
/// [`parse_response_head`] run first, so both conversions are total; a
/// failure here still fails the whole head (fail-closed, never a silently
/// dropped row).
fn header_row(name: Vec<u8>, value: Vec<u8>) -> Option<(http::HeaderName, http::HeaderValue)> {
    Some((
        http::HeaderName::from_bytes(&name).ok()?,
        http::HeaderValue::from_bytes(&value).ok()?,
    ))
}

/// RFC 7230 token byte (Go `validHeaderFieldByte`, net/textproto/reader.go)
/// — the only byte set a header NAME may use.
fn name_byte_ok(b: u8) -> bool {
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

/// Go `validHeaderValueByte` parity (net/textproto/reader.go): a field
/// value may hold VCHAR (0x21-0x7E), SP, HTAB and obs-text (0x80-0xFF);
/// CTL bytes — 0x00-0x08, 0x0A-0x1F and DEL (0x7F) — fail ReadMIMEHeader.
fn value_bytes_have_ctl(b: &[u8]) -> bool {
    b.iter().any(|&c| (c < 0x20 && c != b'\t') || c == 0x7f)
}

/// First row matching `name` (case-insensitive). The production paths carry
/// the values they need out of [`parse_response_head`] (Content-Length,
/// `chunked`) instead of re-reading the rows, so this helper serves the
/// head-parse tests only.
#[cfg(test)]
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
///
/// Returns `Ok(true)` if the backend truncated or corrupted the chunked
/// stream mid-body (the h2 stream has been reset and MUST NOT end clean),
/// `Ok(false)` after a clean 0-chunk end. Go ReverseProxy parity
/// (httputil/reverseproxy.go:537-543): copyResponse panics
/// http.ErrAbortHandler on ANY mid-body read error, and the net/http h2
/// server answers that panic with RST_STREAM + ErrCodeInternal
/// (h2_bundle.go handlerPanicRST) — a truncated backend body must never
/// surface as a clean, complete response (round-18 M3). The old "Read
/// errors truncate the body (Go treats an aborted backend body as EOF)"
/// comment was a false citation: Go aborts the whole exchange.
async fn stream_chunked_body(
    reader: &mut BodyReader<'_, impl AsyncRead + Unpin>,
    send: &mut SendStream<Bytes>,
) -> Result<bool, h2::Error> {
    loop {
        let line = match reader.read_line().await {
            Ok(l) => l,
            Err(_) => return abort_stream(send).await,
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
            Err(_) => return abort_stream(send).await,
        };
        if size == 0 {
            // Trailing headers until the final blank line (RFC 7230 §4.1.2).
            // An EOF before the terminator truncates the trailer — abort,
            // like Go's chunkedReader readTrailer (ErrUnexpectedEOF).
            loop {
                match reader.read_line().await {
                    Ok(t) if !is_blank_line(&t) => continue,
                    Ok(_) => return Ok(false),
                    Err(_) => return abort_stream(send).await,
                }
            }
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
                Err(_) => return abort_stream(send).await, // chunk cut short
            };
            send.send_data(Bytes::from(data), false)?;
            remaining -= n;
        }
        if reader.read_exact(2).await.is_err() {
            return abort_stream(send).await; // missing trailing CRLF
        }
    }
}

/// Abort the response stream with INTERNAL_ERROR. Go ReverseProxy parity
/// for a backend body that died mid-response (round-18 M3): copyResponse
/// panics http.ErrAbortHandler on any mid-body error
/// (httputil/reverseproxy.go:537-543) and the net/http h2 server answers
/// that panic with RST_STREAM + ErrCodeInternal (h2_bundle.go
/// handlerPanicRST → WriteRSTStream). The abort makes the truncation
/// visible to the client as a stream error instead of a clean END_STREAM
/// that reads like a complete response. Returns the `Ok(true)` marker so
/// it can plug into the body-stream callers' error positions.
///
/// The response head must be on the wire BEFORE the reset: h2's `send_reset`
/// drops every frame still queued on the stream
/// (proto/streams/send.rs `clear_queue`, and the server side of a stream is
/// never `is_pending_open`), so a reset issued in the same poll as
/// `send_response` would make RST_STREAM the client's FIRST frame — the
/// already-valid response head (status included) is lost and the h2 client
/// errors on the response future instead of yielding the head and failing
/// only the body. Go writes the HEADERS first and resets after the
/// handler-panic (h2_bundle.go handlerPanicRST), so yield once to let the
/// connection task flush the queued HEADERS before queueing the reset.
async fn abort_stream(send: &mut SendStream<Bytes>) -> Result<bool, h2::Error> {
    tokio::task::yield_now().await;
    send.send_reset(h2::Reason::INTERNAL_ERROR);
    Ok(true)
}

/// Read the backend HTTP/1.1 response from `r`, send the HTTP/2 response head,
/// then stream the body (decoding chunked transfer-encoding) as HTTP/2 DATA
/// frames. A backend that closes before the head produces `502 Bad Gateway`
/// (Go ReverseProxy semantics).
async fn stream_h2_response<R: AsyncRead + Unpin>(
    r: &mut R,
    mut respond: SendResponse<Bytes>,
    is_head: bool,
) -> Result<(), h2::Error> {
    // Interim 1xx heads (100 Continue / 102 / 103) are swallowed and the
    // read continues to the FINAL head — Go's Transport readResponse loop
    // (go1.25 transport.go: `for` over readResponse, 1xx and 101 excluded
    // from `resp`; the old code forwarded the first 1xx head as THE
    // response, truncating every real response a backend sends after an
    // interim). 101 Switching Protocols is NOT swallowable: h2 has no raw
    // 101 representation (an upgrade handshake cannot map onto an h2
    // stream — a 101 forwarded as an h2 response is a protocol error that
    // would kill the whole h2 session), so a backend 101 answers 502 and
    // the stream ends (mirror of frp-server vhost_h2c's GOAWAY-rationale
    // handling). Read errors between heads are 502s like a missing first
    // head (Go: the RoundTrip error mid-1xx-loop is a transport error).
    // Byte budget (audit round-7 finding + round-15 FIX 4 + round-16 FIX 3
    // comment correction): the swallow loop is otherwise unbounded across
    // heads. Go's Transport enforces maxHeaderResponseSize (10 MiB default)
    // as pc.readLimit, set ONCE per readLoop iteration — i.e. per
    // RoundTrip, not per head (go1.25 transport.go:2274). The only
    // intra-response re-arm lives in readResponse's 1xx loop, gated on
    // trace.Got1xxResponse != nil (transport.go:2486-2490: without a trace
    // hook "we limit the size of all headers (including both 1xx and the
    // final response) to maxHeaderResponseSize") — and Go frp sets no
    // trace hook, so a Go frp backend read draws interim AND final heads
    // from ONE cumulative 10 MiB bucket; an endless-1xx backend exhausts
    // it and the RoundTrip fails (502). frp-rs is bounded on both axes
    // with the same magnitude: INTERIM_HEAD_BUDGET mirrors Go's single
    // bucket restricted to the 1xx class, and read_until_head caps every
    // head — interim and final alike, one per call — at its own 1 MiB read
    // cap (+ one 4 KiB read slack), far under Go's 10 MiB. A giant final
    // head therefore fails the per-head cap and answers 502 without ever
    // touching the interim budget; the worst-case cumulative (~11 MiB =
    // 10 MiB of interim heads + one 1 MiB final head) is slightly LARGER
    // than Go's 10 MiB single bucket — deliberate: this listener binds
    // the operator's own 127.0.0.1 port and serves only their local
    // browser, the same operator-local face that keeps the plugin-h2
    // max_header_list_size at Go's 16 MiB default (see the round-13
    // note in plugin/h2.rs) — the tight 10 MiB budget exists on the
    // untrusted public vhost surface, not here. Past the budget the
    // response fails the way an oversized single head fails — 502.
    // Every wire byte counts exactly once: `head` always starts with
    // the carried seed (read_until_head only appends), so `head.len() -
    // carried` is the new bytes, and bytes past the terminator that rode
    // in the read buffer are counted here and never re-counted (the next
    // iteration's seed subtraction removes them).
    let mut seed: Vec<u8> = Vec::new();
    let mut interim_bytes: usize = 0;
    // Go's own budget shape (transport.go:2274 + 2486-2490): one
    // maxHeaderResponseSize (10 MiB) readLimit per RoundTrip, covering 1xx
    // and final heads together when no trace hook is set. frp-rs splits the
    // same magnitude — interim heads accumulate against this 10 MiB
    // budget, and the final head is bounded separately by read_until_head's
    // 1 MiB per-head cap — so no backend can make this h2 stream read more
    // than ~11 MiB of heads (Go: 10 MiB).
    const INTERIM_HEAD_BUDGET: usize = 10 * 1024 * 1024;
    let (head, parsed) = loop {
        let carried = seed.len();
        let head = match read_until_head(r, seed).await {
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
        if (100..=199).contains(&parsed.status) {
            if parsed.status == 101 {
                debug!(
                    "https plugin backend sent 101 Switching Protocols, sending 502 \
                     (h2 cannot represent a raw 101 upgrade)"
                );
                return send_h2_error(respond, 502, &[], Bytes::new()).await;
            }
            interim_bytes += head.len() - carried;
            if interim_bytes > INTERIM_HEAD_BUDGET {
                debug!(
                    interim_bytes,
                    "https plugin backend exceeded the 10 MiB interim-1xx head budget, \
                     sending 502"
                );
                return send_h2_error(respond, 502, &[], Bytes::new()).await;
            }
            debug!(
                status = parsed.status,
                "https plugin backend sent an interim 1xx, reading on to the final head"
            );
            // Bytes past the interim head's terminator may already hold the
            // final head — replay them (the seed's head_end scan must not
            // lose them).
            seed = head[parsed.body_offset..].to_vec();
            continue;
        }
        break (head, parsed);
    };
    let ParsedHead {
        status,
        headers,
        content_length,
        chunked,
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
        // Go copyHeader parity (httputil/reverseproxy.go): dst.Add per row —
        // duplicate rows (Set-Cookie, Warning, ...) accumulate as separate
        // h2 header lines instead of the last row silently replacing the
        // earlier ones (round-18 M2).
        resp.headers_mut().append(n.clone(), v.clone());
    }

    // Round-18 FIX 1: responses to HEAD requests and the no-body statuses
    // 204/304 never carry a DATA body — Go's net/http suppress gate is
    // server.go:1513 (`req.Method == "HEAD" || !bodyAllowedForStatus(code)`
    // || code == StatusNoContent) with `bodyAllowedForStatus`
    // (transfer.go:459-461) false for 204/304/1xx, and `fixLength` returns 0
    // for those shapes (transfer.go:250-252, 700-703). The h2 relay must
    // therefore end the stream with the response head: the body legs below
    // would otherwise wait on a backend that DECLARES a body length (or
    // holds the connection open with no framing at all) and never sends
    // bytes that, for these responses, can never come — the pre-fix hang,
    // and behind it the round-18 M3 CL-arm RST on the backend's clean EOF
    // (a truthful HEAD Content-Length read as a truncated body).
    //
    // Content-Length is stripped for 204/304 (mirror of the server twin
    // vhost_h2c and of the h1 net/http write layer: suppressedHeadersNoBody
    // = {Content-Length, TE} for 204, suppressedHeaders304 = {Content-Type,
    // Content-Length, TE} for 304 — go1.25 server.go:1483-1497); a HEAD
    // answer to a body-bearing status KEEPS it (it truthfully describes the
    // GET the client would receive — RFC 9110 §8.6).
    if is_head || status == 204 || status == 304 {
        if status == 204 || status == 304 {
            resp.headers_mut().remove("content-length");
        }
        respond.send_response(resp, true)?;
        return Ok(());
    }
    // A chunked response must not forward the backend's Content-Length row
    // (RFC 9113 §8.1.1: a declared length need not equal the decoded DATA
    // length, and an h2 peer may fail the stream on the mismatch) — Go
    // deletes it once Transfer-Encoding: chunked wins the framing
    // (net/http/transfer.go). Round-18 FIX 3; the row is still validated
    // above (a garbage value under chunked fails the whole head).
    if chunked {
        resp.headers_mut().remove("content-length");
    }

    let mut send = respond.send_response(resp, false)?;
    let mut reader = BodyReader::new(r, head[body_offset..].to_vec());

    // Every body leg ends the stream exactly two ways: a clean, fully
    // delivered body falls through to the single END_STREAM below, and a
    // backend that dies mid-body returns here with the stream already
    // reset (abort_stream) — truncation is NEVER a clean end (round-18 M3,
    // Go copyResponse abort parity).
    if chunked {
        if stream_chunked_body(&mut reader, &mut send).await? {
            return Ok(()); // truncated: stream reset, no clean end
        }
    } else if let Some(mut remaining) = content_length {
        while remaining > 0 {
            let n = remaining.min(8192) as usize;
            let data = match reader.read_exact(n).await {
                Ok(d) => d,
                Err(_) => {
                    // Truncated CL-bounded body: the declared length was
                    // never delivered — RST, never a clean END_STREAM that
                    // reads like the full response.
                    debug!(
                        "https plugin backend truncated a Content-Length-bounded body, \
                         resetting the stream"
                    );
                    return abort_stream(&mut send).await.map(|_| ());
                }
            };
            remaining -= data.len() as u64;
            send.send_data(Bytes::from(data), false)?;
        }
    } else {
        // No length framing: read to EOF (the backend closes the connection).
        // A genuine EOF is the natural end; an io error mid-body aborts like
        // every other truncated backend body (Go copyResponse).
        loop {
            if reader.available().is_empty() {
                match reader.read_more().await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => {
                        debug!("https plugin backend body read error, resetting the stream");
                        return abort_stream(&mut send).await.map(|_| ());
                    }
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
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                [..], // two rows
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\n\r\n"[..],     // empty value
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
        let addr =
            spawn_scripted_backend(listener, vec![b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()], 0);
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
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello".to_vec(),
            ],
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
        let addr =
            spawn_held_open_backend(listener, b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
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
}
