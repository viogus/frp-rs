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
        // Go's Header.WriteSubset trims EVERY value at egress
        // (textproto.TrimString), the synthesized chain included — outer
        // padding only; inner row padding and the ", " joins survive (a
        // padded inbound row " 192.0.2.1 " yields "192.0.2.1 , <peer>").
        let xff = trim_ascii_ws(xff.as_bytes());
        head.extend_from_slice(b"X-Forwarded-For: ");
        head.extend_from_slice(xff);
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
            // canonical line emitted here is its only egress form. The
            // announcement is NEVER backed by values on the wire: Go's
            // Request.Clone gives the outgoing request a nil-valued Trailer
            // map (request.go:395), so the body ends with an EMPTY trailer
            // block (`0\r\n\r\n`) — exact Go parity, not a bug.
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
mod tests;
