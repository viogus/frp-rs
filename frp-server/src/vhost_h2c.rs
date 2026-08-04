//! HTTP/2 cleartext (h2c) support for the HTTP vhost listener.
//!
//! Go frp v0.70.1 serves HTTP vhosts with `net/http` `http.Server` configured
//! with `Protocols: HTTP1 + UnencryptedHTTP2` — an HTTP/2 prior-knowledge
//! client (binary frames after the 24-byte preface
//! `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) is accepted on the same vhost port as
//! HTTP/1.1. The Go `httputil.ReverseProxy` then forwards to the provider as
//! **plain HTTP/1.1** on the work connection (even for inbound h2c), and
//! re-encodes the backend's HTTP/1.1 response (including chunked bodies and
//! the 504/404 error responses) as HTTP/2 frames back to the client.
//!
//! The byte-level vhost bridge in [`vhost.rs`] scans for a text `Host:` header
//! and cannot decode HTTP/2 frames, so this module implements the h2c path on
//! top of the `h2` crate (tokio's official HTTP/2 implementation; Go uses
//! net/http's built-in h2c, Rust has no std HTTP/2):
//!
//! 1. [`serve_h2c_request`] detects the preface in `vhost.rs`, replays the
//!    pre-read bytes through a [`PreReadStream`] and drives the `h2` server
//!    accept loop.
//! 2. Each stream is routed through the shared `resolve_vhost_request`
//!    (domain/wildcard/path + httpUser lookup, Basic Auth, host_header_rewrite,
//!    X-Forwarded-For / requestHeaders injection) — identical to HTTP/1.1.
//! 3. The h2 request is re-encoded as an HTTP/1.1 request head and handed to
//!    the existing `InternalMsg::ProxyUserConn` machinery (work-conn pool,
//!    encryption, compression, group LB) via an in-memory `tokio::io::duplex`
//!    pair carried as `IoStream::SshChannel` (a type-erased byte stream) — so
//!    the existing byte-level bridge forwards the request body to the provider
//!    and streams the backend response back with zero control-path changes.
//! 4. The backend HTTP/1.1 response is parsed here (status line + headers +
//!    optional chunked decoding) and re-encoded as HTTP/2 frames, including
//!    `504 Gateway Timeout` on `vhost_http_timeout` (response-header timeout,
//!    Go `ReverseProxy.ResponseHeaderTimeout` semantics).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};

use super::{resolve_vhost_request, VhostResolveError};
use crate::service::{AppState, InternalMsg};

/// HTTP/2 prior-knowledge connection preface (RFC 7540 §3.5). These binary
/// bytes carry no text `Host:` header, so `vhost.rs` dispatches connections
/// starting with them to [`serve_h2c_request`] instead of the byte-level
/// bridge.
pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Hop-by-hop headers dropped when converting between HTTP/1.1 and HTTP/2
/// (RFC 7540 §8.1.2.2 forbids them; Go's net/http drops them too).
fn is_hop_by_hop(name: &str) -> bool {
    const HOP: [&str; 5] = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// A stream that replays already-consumed bytes before reading the underlying
/// transport. The vhost listener reads up to 4096 bytes (preface + SETTINGS +
/// possibly the first HEADERS frame) to detect h2c; the h2 handshake needs
/// those bytes replayed in order.
struct PreReadStream<S> {
    pre_read: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PreReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.pre_read.len() {
            let n = (self.pre_read.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.pre_read[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PreReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Serve an HTTP/2 cleartext connection on the vhost port.
///
/// `pre_read` holds the bytes already consumed by the vhost listener (the
/// 24-byte preface plus any frames that arrived with it). They are replayed
/// into the `h2` server handshake; every inbound stream is then handled by
/// [`handle_stream`].
pub(crate) async fn serve_h2c_request<S>(
    stream: S,
    pre_read: Vec<u8>,
    state: Arc<AppState>,
    peer: std::net::SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let io = PreReadStream {
        pre_read,
        pos: 0,
        inner: stream,
    };
    let mut connection: h2::server::Connection<PreReadStream<S>, Bytes> =
        match h2::server::Builder::new()
            // Bound concurrent streams like Go's http.Server (default 250) to
            // cap per-connection memory.
            .max_concurrent_streams(100)
            .handshake(io)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "h2c handshake failed from {}", peer);
                return;
            }
        };

    loop {
        match connection.accept().await {
            Some(Ok((request, respond))) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(request, respond, state, peer).await {
                        tracing::debug!(peer = %peer, error = %e, "h2c stream error from {}", peer);
                    }
                });
            }
            Some(Err(e)) => {
                tracing::debug!(peer = %peer, error = %e, "h2c connection error from {}", peer);
                break;
            }
            None => break,
        }
    }
}

/// Handle one HTTP/2 stream: route like an HTTP/1.1 vhost request, forward to
/// the provider as plain HTTP/1.1 on a work connection, and re-encode the
/// backend's HTTP/1.1 response (with chunked decoding) as HTTP/2 frames.
async fn handle_stream(
    request: http::Request<RecvStream>,
    respond: SendResponse<Bytes>,
    state: Arc<AppState>,
    peer: std::net::SocketAddr,
) -> Result<(), h2::Error> {
    // Route key from the HTTP/2 request (RFC 7540 §8.1.2.3): `:authority` is
    // the Host equivalent, `:path` carries the request-target.
    let authority = request.uri().authority().map(|a| a.as_str()).unwrap_or("");
    let host = host_from_authority(authority);
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // HTTP/2 carries Basic Auth in the regular `authorization` header (no
    // pseudo-header). Reused for route matching, auth check, and per-user
    // routing — same as the HTTP/1.1 path.
    let http_auth = extract_basic_auth_headers(request.headers());
    let http_user = http_auth
        .as_ref()
        .map(|(u, _)| u.as_str())
        .unwrap_or_default();
    tracing::debug!(host = %host, path = %path, peer = %peer, http_user = %http_user, "HTTP VHost (h2c) request for '{}' path '{}' from {}", host, path, peer);

    // Re-encode as an HTTP/1.1 request head. Go's reverse proxy forwards to
    // the provider as plain HTTP/1.1 even when the inbound request is h2c.
    let has_content_length = request.headers().contains_key("content-length");
    let request_head = build_http1_request_head(&request);

    let forward = match resolve_vhost_request(
        &state,
        host,
        path,
        http_auth.as_ref(),
        request_head,
        peer,
        "HTTP",
    )
    .await
    {
        Ok(f) => f,
        Err(VhostResolveError::Unauthorized) => {
            return send_h2_error(
                respond,
                401,
                &[("www-authenticate", "Basic realm=\"frp\"")],
                Bytes::new(),
            )
            .await;
        }
        Err(VhostResolveError::NotFound) => {
            return send_h2_error(
                respond,
                404,
                &[],
                Bytes::from(state.custom_404_page.clone()),
            )
            .await;
        }
    };

    // Locate the control handler for the target run_id (shared with the
    // HTTP/1.1 path).
    let internal_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&forward.run_id).cloned()
    };
    let Some(ctl_tx) = internal_tx else {
        tracing::warn!(host = %host, path = %path, "HTTP VHost (h2c) route for '{}' path '{}' found but control handler gone", host, path);
        return send_h2_error(respond, 502, &[], Bytes::new()).await;
    };

    // Bridge the h2 stream to the byte-level work-conn machinery through an
    // in-memory duplex pair: the h2 request body is written into the client
    // end and the existing bridge forwards it to the provider; the backend
    // HTTP/1.1 response comes back on the same pair for parsing and h2
    // re-encoding. `IoStream::SshChannel` is a type-erased byte stream —
    // exactly what the bridge expects.
    let (client, control) = tokio::io::duplex(128 * 1024);
    // send().await: backpressure is correct — a full control channel must
    // not silently drop a user connection (the HTTP/1.1 path uses the same
    // pattern). This runs in a per-connection task, so the await is free.
    // A closed channel means the control handler is gone — answer 502,
    // matching the HTTP/1.1 path.
    if ctl_tx
        .tx
        .send(InternalMsg::ProxyUserConn {
            proxy_name: forward.proxy_name,
            user_conn: frp_core::transport::IoStream::SshChannel(Box::new(control)),
            pre_read: forward.request_head,
        })
        .await
        .is_err()
    {
        return send_h2_error(respond, 502, &[], Bytes::new()).await;
    }

    let (mut client_r, client_w) = tokio::io::split(client);
    let mut body = request.into_body();

    // Forward the h2 request body to the provider. When the head carried no
    // Content-Length it was emitted with `Transfer-Encoding: chunked` (Go
    // http.Transport behavior for unknown-length bodies), so body bytes are
    // framed accordingly. Releasing the h2 flow-control capacity after each
    // write keeps backpressure end-to-end.
    let body_task = tokio::spawn(async move {
        let mut client_w = client_w;
        let end_stream = body.is_end_stream();
        while let Some(Ok(data)) = body.data().await {
            if !data.is_empty() {
                if has_content_length {
                    let _ = client_w.write_all(&data).await;
                } else {
                    let _ = client_w
                        .write_all(format!("{:X}\r\n", data.len()).as_bytes())
                        .await;
                    let _ = client_w.write_all(&data).await;
                    let _ = client_w.write_all(b"\r\n").await;
                }
            }
            let _ = body.flow_control().release_capacity(data.len());
        }
        if !has_content_length && !end_stream {
            // Stream had an open body: terminate the chunked framing.
            let _ = client_w.write_all(b"0\r\n\r\n").await;
        }
        let _ = client_w.flush().await;
        let _ = client_w.shutdown().await;
    });

    // Read the backend's HTTP/1.1 response and re-encode it as HTTP/2. The
    // response-head read is bounded by vhost_http_timeout when configured
    // (Go ResponseHeaderTimeout → 504 Gateway Timeout; 0 disables it, the
    // same semantics as the byte-level bridge).
    let head_timeout = (state.vhost_http_timeout > 0)
        .then(|| std::time::Duration::from_secs(state.vhost_http_timeout));
    let response_result = stream_h2_response(&mut client_r, respond, head_timeout).await;

    // Once the response is fully relayed the bridge has served its purpose —
    // stop the body forwarder so the h2 stream (and work conn) can wind down
    // even if the client is still trickling request bytes.
    body_task.abort();
    response_result
}

/// Strip the port from an h2 `:authority` (Host equivalent), handling IPv6
/// literals like `[::1]:8080` the same way `extract_host_header` does for
/// HTTP/1.1.
fn host_from_authority(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(authority);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// Re-encode an h2 request as an HTTP/1.1 request head. `:authority` becomes
/// `Host`, connection-specific / pseudo headers are dropped. A body without
/// Content-Length is forwarded with `Transfer-Encoding: chunked` (Go
/// http.Transport behavior for unknown-length bodies).
fn build_http1_request_head(request: &http::Request<RecvStream>) -> Vec<u8> {
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

    let has_content_length = request.headers().contains_key("content-length");
    for (name, value) in request.headers() {
        let n = name.as_str();
        if is_hop_by_hop(n) || n.eq_ignore_ascii_case("host") {
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
    if let Some(auth) = request.uri().authority() {
        head.extend_from_slice(b"Host: ");
        head.extend_from_slice(auth.as_str().as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if !has_content_length {
        // Align with Go's http.Transport: a request with no body (h2 stream
        // ended with HEADERS) is sent with Content-Length: 0; an open stream
        // with unknown length is chunked-framed.
        if request.body().is_end_stream() {
            head.extend_from_slice(b"Content-Length: 0\r\n");
        } else {
            head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// Extract Basic Auth credentials from the `authorization` header of an h2
/// request (HTTP/2 has no pseudo-header for auth).
fn extract_basic_auth_headers(headers: &http::HeaderMap) -> Option<(String, String)> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?.trim();
    let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pwd) = creds.split_once(':')?;
    Some((user.to_string(), pwd.to_string()))
}

/// Send a body-less (or single-chunk) HTTP/2 error response.
async fn send_h2_error(
    mut respond: SendResponse<Bytes>,
    status: u16,
    extra: &[(&str, &str)],
    body: Bytes,
) -> Result<(), h2::Error> {
    let mut resp = http::Response::builder().status(status).body(()).unwrap();
    for &(k, v) in extra {
        let name = http::header::HeaderName::from_bytes(k.as_bytes()).unwrap();
        resp.headers_mut()
            .insert(name, http::HeaderValue::from_str(v).unwrap());
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

/// Read bytes until the end of the HTTP/1.1 response head (`\r\n\r\n`),
/// returning head + any body bytes that arrived with it.
async fn read_until_head(r: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
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
    let head_end = head.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head_bytes = &head[..head_end];
    let first_crlf = head_bytes.windows(2).position(|w| w == b"\r\n")?;
    let status_line = std::str::from_utf8(&head_bytes[..first_crlf]).ok()?;
    let mut parts = status_line.split_whitespace();
    parts.next()?; // HTTP/1.1
    let status: u16 = parts.next()?.parse().ok()?;

    let mut headers = Vec::new();
    for line in head_bytes[first_crlf + 2..head_end - 2].split(|&b| b == b'\n') {
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
    usize::from_str_radix(s.trim(), 16)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))
}

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
    async fn read_more(&mut self) -> std::io::Result<bool> {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
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
    async fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            let avail = self.available();
            if let Some(rel) = avail.windows(2).position(|w| w == b"\r\n") {
                let line = avail[..rel + 2].to_vec();
                self.consume(rel + 2);
                return Ok(line);
            }
            if let Some(rel) = avail.iter().position(|&b| b == b'\n') {
                let line = avail[..rel + 1].to_vec();
                self.consume(rel + 1);
                return Ok(line);
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
        let data = match reader.read_exact(size).await {
            Ok(d) => d,
            Err(_) => return Ok(()),
        };
        if reader.read_exact(2).await.is_err() {
            return Ok(()); // missing trailing CRLF
        }
        send.send_data(Bytes::from(data), false)?;
    }
}

/// Read the backend HTTP/1.1 response from `r`, send the HTTP/2 response head,
/// then stream the body (decoding chunked transfer-encoding) as HTTP/2 DATA
/// frames. When `head_timeout` is `Some`, the response-head read is bounded —
/// on timeout a body-less `504 Gateway Timeout` is sent (Go semantics); a
/// backend that closes before the head produces `502 Bad Gateway`.
async fn stream_h2_response<R: AsyncRead + Unpin>(
    r: &mut R,
    mut respond: SendResponse<Bytes>,
    head_timeout: Option<std::time::Duration>,
) -> Result<(), h2::Error> {
    let head = if let Some(timeout) = head_timeout {
        match tokio::time::timeout(timeout, read_until_head(r)).await {
            Ok(Ok(h)) => h,
            Ok(Err(_e)) => {
                // Backend closed (or no work conn was ever assigned) before
                // the response head — Go's reverse proxy answers 502.
                tracing::debug!("h2c backend closed before response head, sending 502");
                return send_h2_error(respond, 502, &[], Bytes::new()).await;
            }
            Err(_elapsed) => {
                tracing::debug!("h2c backend response-head timeout, sending 504");
                return send_h2_error(respond, 504, &[], Bytes::new()).await;
            }
        }
    } else {
        match read_until_head(r).await {
            Ok(h) => h,
            Err(_e) => {
                tracing::debug!("h2c backend closed before response head, sending 502");
                return send_h2_error(respond, 502, &[], Bytes::new()).await;
            }
        }
    };
    let Some(parsed) = parse_response_head(&head) else {
        tracing::debug!("h2c backend sent a malformed response head, sending 502");
        return send_h2_error(respond, 502, &[], Bytes::new()).await;
    };
    let ParsedHead {
        status,
        headers,
        body_offset,
    } = parsed;

    let mut resp = http::Response::builder().status(status).body(()).unwrap();
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
        // No length framing: read to EOF (the work conn is closed by frpc
        // once the provider finishes).
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
