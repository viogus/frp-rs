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
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use frp_core::transport::set_nodelay;

/// Per-stream HTTP/2 receive window (2 MiB), aligned with `http2connect.rs`.
const H2_STREAM_WINDOW_SIZE: u32 = 2 * 1024 * 1024;
/// Connection-wide HTTP/2 receive window (8 MiB) shared across all streams.
const H2_CONN_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
/// Max HTTP/2 DATA frame payload (64 KiB, 4× fewer frames than RFC 9113's
/// 16 KiB minimum).
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;
/// Timeout for outbound TCP/TLS backend dials (matches `http2connect.rs`).
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Threshold below which a bodyless request head is written inline instead of
/// spawning a separate `body_task` (keeps normal GET/HEAD requests zero-spawn
/// while preventing deadlock if an unusually huge header block exceeds the
/// socket send buffer).
const INLINE_HEAD_WRITE_CAP: usize = 16 * 1024;

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

type BoxedBackendRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxedBackendWrite = Box<dyn AsyncWrite + Unpin + Send>;

struct H2ConnConfig {
    target: String,
    host_rewrite: String,
    request_headers: HashMap<String, String>,
    backend: Backend,
}

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
    let mut connection: h2::server::Connection<S, Bytes> = match tokio::time::timeout(
        super::PLUGIN_HANDSHAKE_TIMEOUT,
        h2::server::Builder::new()
            // Deliberate per-connection cap — NOT a Go default (Go's
            // http.Server allows 250 concurrent streams; 100 is this plugin's
            // own bound on per-connection memory, matching the server-side
            // vhost h2c path).
            .max_concurrent_streams(100)
            // Go parity: the https2http/https2https plugins serve with net/http
            // (x/net/http2 defaultMaxHeaderListSize = 16 MiB), so legitimately
            // large header lists — big Cookie jars, JWTs — must not be rejected.
            .max_header_list_size(16 * 1024 * 1024)
            .initial_window_size(H2_STREAM_WINDOW_SIZE)
            .initial_connection_window_size(H2_CONN_WINDOW_SIZE)
            .max_frame_size(H2_MAX_FRAME_SIZE)
            .handshake(stream),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            debug!(error = %e, "https plugin h2 handshake failed");
            return;
        }
        Err(_elapsed) => {
            debug!("https plugin h2 handshake timed out");
            return;
        }
    };

    let cfg = Arc::new(H2ConnConfig {
        target,
        host_rewrite,
        request_headers,
        backend,
    });

    // Per-stream handlers, collected so they cannot outlive this h2
    // connection. Poll `streams.join_next()` alongside `connection.accept()`
    // so finished streams are reaped even while the keep-alive connection idles.
    let mut streams: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            res = connection.accept() => res,
            Some(_) = streams.join_next(), if !streams.is_empty() => continue,
        };
        match accepted {
            Some(Ok((request, respond))) => {
                let cfg = cfg.clone();
                streams.spawn(async move {
                    if let Err(e) = handle_stream(request, respond, &cfg, real_peer).await {
                        debug!(error = %e, "https plugin h2 stream error");
                    }
                });
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
    cfg: &H2ConnConfig,
    real_peer: std::net::IpAddr,
) -> Result<(), h2::Error> {
    let is_head = request.method() == http::Method::HEAD;
    let has_content_length = request.headers().contains_key("content-length");
    let declared_length = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let head = build_http1_request_head(
        &request,
        &cfg.host_rewrite,
        &cfg.request_headers,
        real_peer,
        request.body().is_end_stream(),
    );

    // A refused/unreachable/timed-out backend answers 502 (Go ReverseProxy ErrorHandler).
    let (mut remote_r, mut remote_w) = match connect_backend(&cfg.backend).await {
        Ok(halves) => halves,
        Err(e) => {
            debug!(target = %cfg.target, error = %e, "https plugin h2 backend connect failed");
            return send_h2_error(respond, 502, &[], Bytes::new()).await;
        }
    };

    let mut body = request.into_body();
    let end_stream = body.is_end_stream();
    let is_tls = matches!(cfg.backend, Backend::Tls { .. });

    // Fast path for normal bodyless requests (GET/HEAD/DELETE with modest
    // headers): write the head inline without spawning a task. On write error,
    // still read from `remote_r` so early backend rejections (e.g. 431/400)
    // reach the client instead of being masked as 502 (matching Go
    // ReverseProxy); if the backend genuinely died without replying,
    // `stream_h2_response` answers 502. Skip `shutdown()` on TLS backends so
    // we do not emit a TLS `close_notify` before reading the response.
    if end_stream && head.len() <= INLINE_HEAD_WRITE_CAP {
        if let Err(e) = remote_w.write_all(&head).await {
            debug!(error = %e, "https plugin h2 head write failed; reading backend response");
        } else {
            let _ = remote_w.flush().await;
            if !is_tls {
                let _ = remote_w.shutdown().await;
            }
        }
        drop(remote_w);
        return stream_h2_response(&mut remote_r, respond, is_head).await;
    }

    // Requests carrying a body (or a very large header block) run the write
    // direction on a separate task so a slow upload cannot deadlock an early
    // backend response. Guarded by `AbortOnDrop` so cancelling `handle_stream`
    // (e.g. via `streams.abort_all()`) aborts `body_task` and drops `remote_w`.
    let _body_guard = AbortOnDrop(tokio::spawn(async move {
        if remote_w.write_all(&head).await.is_err() {
            return;
        }
        let mut remaining = declared_length;
        let mut chunk_buf: Vec<u8> = Vec::new();
        while let Some(res) = body.data().await {
            let Ok(data) = res else {
                // Client reset/aborted the stream mid-upload: shut down the
                // write half immediately (WriteHalf on TLS has no Drop
                // shutdown) WITHOUT emitting `0\r\n\r\n`, so the backend sees
                // premature EOF instead of stalling or treating a truncated
                // upload as complete.
                let _ = remote_w.shutdown().await;
                return;
            };
            let len = data.len();
            if !data.is_empty() {
                let (next_remaining, n) = cap_chunk(len, remaining);
                if remaining.is_none() {
                    use std::io::Write;
                    const SIZE_BUF_LEN: usize = 16;
                    let mut size_buf = [0u8; SIZE_BUF_LEN];
                    let mut sink: &mut [u8] = &mut size_buf;
                    let _ = write!(sink, "{:X}\r\n", len);
                    let size_len = SIZE_BUF_LEN - sink.len();
                    if len <= MAX_CHUNK_SIZE {
                        chunk_buf.clear();
                        chunk_buf.reserve_exact(size_len + len + 2);
                        chunk_buf.extend_from_slice(&size_buf[..size_len]);
                        chunk_buf.extend_from_slice(&data);
                        chunk_buf.extend_from_slice(b"\r\n");
                        if remote_w.write_all(&chunk_buf).await.is_err() {
                            return;
                        }
                    } else if remote_w.write_all(&size_buf[..size_len]).await.is_err()
                        || remote_w.write_all(&data).await.is_err()
                        || remote_w.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                } else if n > 0 && remote_w.write_all(&data[..n]).await.is_err() {
                    return;
                }
                remaining = next_remaining;
            }
            let _ = body.flow_control().release_capacity(len);
        }
        if !has_content_length && !end_stream {
            if let Err(e) = remote_w.write_all(b"0\r\n\r\n").await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
        }
        if let Err(e) = remote_w.flush().await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        if !is_tls {
            if let Err(e) = remote_w.shutdown().await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
        }
    }));

    stream_h2_response(&mut remote_r, respond, is_head).await
}

async fn connect_backend(
    backend: &Backend,
) -> std::io::Result<(BoxedBackendRead, BoxedBackendWrite)> {
    match backend {
        Backend::Plain { host, port } => {
            let s = tokio::time::timeout(
                BACKEND_CONNECT_TIMEOUT,
                TcpStream::connect((host.as_str(), *port)),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "backend TCP connect timed out",
                )
            })??;
            set_nodelay(&s);
            let (r, w) = s.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
        Backend::Tls {
            connector,
            host,
            port,
        } => {
            let deadline = tokio::time::Instant::now() + BACKEND_CONNECT_TIMEOUT;
            let tcp = tokio::time::timeout_at(deadline, TcpStream::connect((host.as_str(), *port)))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "backend TCP connect timed out",
                    )
                })??;
            set_nodelay(&tcp);
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad backend hostname")
                })?;
            let tls = tokio::time::timeout_at(deadline, connector.connect(server_name, tcp))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "backend TLS handshake timed out",
                    )
                })??;
            let (r, w) = tokio::io::split(tls);
            Ok((Box::new(r), Box::new(w)))
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
    send_h2_data(&mut send, body, true).await
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

/// Per-slice cap for streaming chunked and Content-Length bodies (64 KiB,
/// aligned with `H2_MAX_FRAME_SIZE`).
const MAX_CHUNK_SIZE: usize = 64 * 1024;
/// Minimum spare capacity retained in `BodyReader`'s `BytesMut` slab before
/// reserving a fresh 64 KiB chunk.
const BODY_MIN_RESERVE: usize = 16 * 1024;
/// Minimum slice size eligible for zero-copy `BytesMut::split_to().freeze()`.
/// Smaller chunks are copied out via `Bytes::copy_from_slice` + `advance()` so
/// tiny chunked frames cannot promote `BytesMut` to `KIND_ARC` and pin 64 KiB
/// slabs inside `h2`'s send queue.
const ZERO_COPY_MIN_BYTES: usize = 4096;

/// RAII guard that aborts a spawned helper task when dropped, preventing a
/// detached `body_task` from leaking backend TCP/TLS sockets if `handle_stream`
/// is cancelled (e.g. via `streams.abort_all()`).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send `data` on an HTTP/2 `SendStream` respecting peer flow-control capacity
/// (`reserve_capacity` + `poll_capacity`). Prevents unbounded buffering in
/// `h2`'s internal send queue when a fast local backend streams to a slow or
/// stalled remote HTTP/2 client.
async fn send_h2_data(
    send: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> Result<(), h2::Error> {
    if data.is_empty() {
        if end_stream {
            send.send_data(Bytes::new(), true)?;
        }
        return Ok(());
    }
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = loop {
            let c = send.capacity();
            if c > 0 {
                break c;
            }
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(c)) if c > 0 => break c,
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => return Err(h2::Error::from(h2::Reason::CANCEL)),
            }
        };
        let n = cap.min(data.len());
        let is_last = n == data.len();
        let piece = if is_last {
            std::mem::take(&mut data)
        } else {
            data.split_to(n)
        };
        send.send_data(piece, end_stream && is_last)?;
    }
    Ok(())
}

/// Incremental zero-copy response-body reader backed by `BytesMut`, seeded
/// with any body bytes that arrived alongside the response head.
struct BodyReader<'a, R: AsyncRead + Unpin> {
    inner: &'a mut R,
    buf: BytesMut,
}

impl<'a, R: AsyncRead + Unpin> BodyReader<'a, R> {
    fn new(inner: &'a mut R, initial: &[u8], capacity_hint: Option<u64>) -> Self {
        let cap = capacity_hint
            .map_or(MAX_CHUNK_SIZE, |cl| cl.min(MAX_CHUNK_SIZE as u64) as usize)
            .max(initial.len());
        let mut buf = BytesMut::with_capacity(cap);
        buf.extend_from_slice(initial);
        Self { inner, buf }
    }

    /// Read more bytes directly into `self.buf` via `read_buf`. Returns
    /// `Ok(false)` on EOF.
    async fn read_more(&mut self) -> std::io::Result<bool> {
        if self.buf.capacity() - self.buf.len() < BODY_MIN_RESERVE {
            self.buf.reserve(MAX_CHUNK_SIZE);
        }
        let n = self.inner.read_buf(&mut self.buf).await?;
        Ok(n > 0)
    }

    fn take_bytes(&mut self, take: usize) -> Bytes {
        if take >= ZERO_COPY_MIN_BYTES {
            self.buf.split_to(take).freeze()
        } else {
            let out = Bytes::copy_from_slice(&self.buf[..take]);
            self.buf.advance(take);
            out
        }
    }

    /// Take up to `max_len` bytes (zero-copy when `>= ZERO_COPY_MIN_BYTES`,
    /// copied otherwise so small chunks never pin a 64 KiB slab), refilling
    /// once if empty. Errors with `UnexpectedEof` on clean EOF.
    async fn take_chunk(&mut self, max_len: usize) -> std::io::Result<Bytes> {
        if self.buf.is_empty() && !self.read_more().await? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in response body",
            ));
        }
        let take = max_len.min(self.buf.len());
        Ok(self.take_bytes(take))
    }

    /// Take up to `max_len` bytes for EOF-delimited bodies, returning
    /// `Ok(None)` on clean EOF.
    async fn take_chunk_or_eof(&mut self, max_len: usize) -> std::io::Result<Option<Bytes>> {
        if self.buf.is_empty() && !self.read_more().await? {
            return Ok(None);
        }
        let take = max_len.min(self.buf.len());
        Ok(Some(self.take_bytes(take)))
    }

    /// Fill `out` completely from the buffered reader, failing with
    /// `UnexpectedEof` when the stream ends early.
    async fn fill_exact(&mut self, out: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            if self.buf.is_empty() && !self.read_more().await? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in response body",
                ));
            }
            let take = (out.len() - filled).min(self.buf.len());
            out[filled..filled + take].copy_from_slice(&self.buf[..take]);
            self.buf.advance(take);
            filled += take;
        }
        Ok(())
    }

    /// Read one CRLF (or LF) terminated line including its terminator in a
    /// single O(n) pass. Returns an owned `Vec<u8>` + `advance()` rather than
    /// `split_to().freeze()` so framing metadata never promotes `self.buf` to
    /// a shared `KIND_ARC` slab.
    ///
    /// A line exceeding [`super::CHUNK_LINE_MAX`] errors before refilling
    /// beyond the limit.
    async fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        let mut scanned = 0usize;
        loop {
            if let Some(rel) = self.buf[scanned..].iter().position(|&b| b == b'\n') {
                let end = scanned + rel + 1;
                if end > super::CHUNK_LINE_MAX {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "chunk line too long",
                    ));
                }
                let line = self.buf[..end].to_vec();
                self.buf.advance(end);
                return Ok(line);
            }
            scanned = self.buf.len();
            if scanned >= super::CHUNK_LINE_MAX {
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
            loop {
                match reader.read_line().await {
                    Ok(t) if !is_blank_line(&t) => continue,
                    Ok(_) => return Ok(false),
                    Err(_) => return abort_stream(send).await,
                }
            }
        }
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(MAX_CHUNK_SIZE);
            let chunk = match reader.take_chunk(n).await {
                Ok(c) => c,
                Err(_) => return abort_stream(send).await, // chunk cut short
            };
            remaining -= chunk.len();
            send_h2_data(send, chunk, false).await?;
        }
        let mut terminator = [0u8; 2];
        match reader.fill_exact(&mut terminator).await {
            Ok(()) if terminator == *b"\r\n" => {}
            _ => return abort_stream(send).await, // missing/malformed trailing CRLF
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
    for (n, v) in headers {
        if is_hop_by_hop(n.as_str()) {
            continue;
        }
        resp.headers_mut().append(n, v);
    }

    if is_head || status == 204 || status == 304 {
        if status == 204 || status == 304 {
            resp.headers_mut().remove("content-length");
        }
        respond.send_response(resp, true)?;
        return Ok(());
    }
    if chunked {
        resp.headers_mut().remove("content-length");
    } else if content_length == Some(0) {
        respond.send_response(resp, true)?;
        return Ok(());
    }

    let mut send = respond.send_response(resp, false)?;
    let mut reader = BodyReader::new(
        r,
        &head[body_offset..],
        if chunked { None } else { content_length },
    );

    if chunked {
        if stream_chunked_body(&mut reader, &mut send).await? {
            return Ok(()); // truncated: stream reset, no clean end
        }
    } else if let Some(mut remaining) = content_length {
        while remaining > 0 {
            let n = remaining.min(MAX_CHUNK_SIZE as u64) as usize;
            let chunk = match reader.take_chunk(n).await {
                Ok(c) => c,
                Err(_) => {
                    debug!(
                        "https plugin backend truncated a Content-Length-bounded body, \
                         resetting the stream"
                    );
                    return abort_stream(&mut send).await.map(|_| ());
                }
            };
            remaining -= chunk.len() as u64;
            send_h2_data(&mut send, chunk, remaining == 0).await?;
        }
        return Ok(());
    } else {
        loop {
            match reader.take_chunk_or_eof(MAX_CHUNK_SIZE).await {
                Ok(Some(chunk)) => {
                    send_h2_data(&mut send, chunk, false).await?;
                }
                Ok(None) => break,
                Err(_) => {
                    debug!("https plugin backend body read error, resetting the stream");
                    return abort_stream(&mut send).await.map(|_| ());
                }
            }
        }
    }
    send.send_data(Bytes::new(), true)?;
    Ok(())
}

#[cfg(test)]
mod tests;
