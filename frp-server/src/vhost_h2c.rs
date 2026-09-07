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
///
/// The handshake and the first accept are bounded by a single absolute
/// `vhost_http_timeout` deadline — the exact parallel of the HTTP/1.1 head
/// read at vhost.rs:635-640 (same `<= 0 → 60s` Go floor, same
/// `Instant::now() + from_secs` idiom). An unauthenticated client that sends
/// the 24-byte preface and then goes silent must not park a task, an fd, and
/// — when `max_connections` is configured — a `conn_semaphore` permit (held
/// by `let _permit = permit;` in the spawned task at vhost.rs:980) forever.
/// Only the pre-first-stream phase is bounded: once the first stream is
/// established, later accepts are deliberately NOT deadlined, since a
/// legitimately idle keep-alive h2c connection between requests is normal
/// (the HTTP/1.1 path likewise stops clocking the client once the head is in).
pub(crate) async fn serve_h2c_request<S>(
    stream: S,
    pre_read: Vec<u8>,
    state: Arc<AppState>,
    peer: std::net::SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Same absolute-deadline idiom as the HTTP/1.1 head read (vhost.rs:635-
    // 640): the whole handshake must complete within vhost_http_timeout, not
    // a per-read timeout a drip-feeding client could stretch indefinitely.
    // `<= 0` floors at 60s (Go parity, shared clamp in vhost.rs).
    let timeout_secs = super::clamp_vhost_timeout(state.vhost_http_timeout);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let io = PreReadStream {
        pre_read,
        pos: 0,
        inner: stream,
    };
    let mut connection: h2::server::Connection<PreReadStream<S>, Bytes> =
        match tokio::time::timeout_at(
            deadline,
            h2::server::Builder::new()
                // Bound concurrent streams like Go's http.Server (default 250) to
                // cap per-connection memory.
                .max_concurrent_streams(100)
                // Cap the header block at the same 4096-byte bound the HTTP/1.1
                // head path enforces (vhost.rs:641, 650-655). h2's 16 MiB default
                // × 100 concurrent streams would otherwise leave an
                // unauthenticated client a ~1.6 GiB per-connection memory ceiling
                // to park on.
                .max_header_list_size(4096)
                .handshake(io),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::debug!(peer = %peer, error = %e, "h2c handshake failed from {}", peer);
                return;
            }
            Err(_elapsed) => {
                tracing::debug!(peer = %peer, "h2c handshake from {} timed out after {}s", peer, timeout_secs);
                return;
            }
        };

    // The first accept is bounded by the same absolute deadline: a client
    // that completes the handshake but never opens a stream is the
    // post-preface variant of the same attack and must also be released.
    // Subsequent accepts are NOT deadlined — an established h2c connection
    // idling between requests is legitimate and must be allowed to sit.
    let mut first = true;
    loop {
        let accepted = if first {
            first = false;
            match tokio::time::timeout_at(deadline, connection.accept()).await {
                Err(_elapsed) => {
                    tracing::debug!(peer = %peer, "h2c first stream from {} timed out after {}s", peer, timeout_secs);
                    return;
                }
                Ok(a) => a,
            }
        } else {
            connection.accept().await
        };
        match accepted {
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
    mut respond: SendResponse<Bytes>,
    state: Arc<AppState>,
    peer: std::net::SocketAddr,
) -> Result<(), h2::Error> {
    // Route key from the HTTP/2 request (RFC 7540 §8.1.2.3): `:authority` is
    // the Host equivalent, `:path` carries the request-target. Routing uses
    // the path WITHOUT the query — Go routes on `req.URL.Path` (the h2 layer
    // is Go's http.Request, same URL.Path semantics as HTTP/1.1); the query
    // is still forwarded to the provider (build_http1_request_head keeps the
    // full path_and_query).
    let authority = request.uri().authority().map(|a| a.as_str()).unwrap_or("");
    let host = host_from_authority(authority);
    let path = request.uri().path().to_string();

    // HTTP/2 has no pseudo-header for auth; Go reads the request FORM
    // exactly like HTTP/1.1. Go's h2 server builds req.URL per
    // h2_bundle.go:6362-6430: CONNECT gets URL{Host: :authority}
    // (absolute-form); every other request gets url.ParseRequestURI(":path")
    // — URL.Host == "" for path-form targets (the normal h2 case; the
    // :scheme/:authority pseudo-headers do NOT feed the URL) and a real
    // host only when ":path" itself begins with "scheme://authority". Go
    // frp gates on `req.URL.Host != ""` (pkg/util/vhost/http.go:195, 232):
    // absolute-form reads `Proxy-Authorization` (answers 407), origin-form
    // reads `Authorization` (answers 401) — exactly like HTTP/1.1
    // origin-form. NOTE: `request.uri().scheme()` is NOT the signal — h2
    // 0.4.18's server keeps :scheme in the Uri whenever :authority is
    // present (server.rs convert_poll_message), so every normal request
    // would look absolute-form.
    let is_absolute_form = h2_request_is_absolute_form(&request);
    let (http_auth, route_user) = h2_select_auth(request.headers(), is_absolute_form);
    // CONNECT (RFC 7540 §8.3, :method CONNECT) forwards raw — no host
    // rewrite, no forwarded-header injection. Modeled on the HTTP/1.1
    // connectHandler (Go http.go:282-285), but note: Go's h2 ResponseWriter
    // implements no http.Hijacker (h2_bundle.go:4684 — "no plan for
    // StateHijacked"), so Go's connectHandler CANNOT run over h2 at all and
    // Go frp answers such a request 500 — this raw-CONNECT leg is a
    // Rust-only extension of the H1 behavior, not a Go-parity path
    // (round-13 review comment correction). http::Method equality is the
    // byte-exact "CONNECT" gate (Go http.MethodConnect). Hoisted so the
    // ProxyUserConn below carries the same verdict to the bridge's
    // injector gate.
    let is_connect = request.method() == http::Method::CONNECT;
    // Captured BEFORE `into_body()` below: a HEAD request's response never
    // carries a body no matter what the backend head declares — the relay
    // must end the h2 stream with the response head itself (FIX 1).
    let is_head = request.method() == http::Method::HEAD;
    tracing::debug!(host = %host, path = %path, peer = %peer, "HTTP VHost (h2c) request for '{}' path '{}' from {}", host, path, peer);

    // Re-encode as an HTTP/1.1 request head. Go's reverse proxy forwards to
    // the provider as plain HTTP/1.1 even when the inbound request is h2c.
    // `content_length` is the DECLARED body length (RFC 7540 §8.1.2.6
    // enforcement — see the body task below); an unparseable header value
    // degrades to "unknown" (the h2 library has already rejected invalid CL
    // frames at receipt, so this is unreachable in practice). The chunked
    // framing decision follows header PRESENCE, as before.
    let content_length: Option<u64> = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    let has_content_length = request.headers().contains_key("content-length");
    let request_head = build_http1_request_head(&request);

    // The 404 body every non-timeout backend failure answers with (FIX 2):
    // the configured custom_404_page when non-empty, else the builtin HTML —
    // the same selection the HTTP/1.1 surface makes in
    // `write_not_found_response` (Go ErrorHandler → getNotFoundPageContent,
    // pkg/util/vhost/resource.go). Computed once here because both the
    // route-miss arm above and the backend-failure arms inside
    // `stream_h2_response` need it.
    let not_found_page = h2c_not_found_body(&state.custom_404_page);

    let forward = match resolve_vhost_request(
        &state,
        host,
        path.as_str(),
        // X-Forwarded-Host = the `:authority` pseudo-header verbatim — Go's
        // h2 server sets `req.Host` from :authority for every request (with
        // port, as received), and SetXForwarded reads `r.In.Host`.
        authority,
        http_auth.as_ref(),
        route_user.as_deref(),
        request_head,
        peer,
        "HTTP",
        // Go checkRouteAuthByRequest's `req.URL.Host != ""` gate — decides
        // the 407-vs-401 response shape on auth failure below.
        is_absolute_form,
        is_connect,
    )
    .await
    {
        Ok(f) => f,
        Err(VhostResolveError::Unauthorized { proxy_form: true }) => {
            // Absolute-form → Go checkRouteAuthByRequest answers 407 +
            // Proxy-Authenticate (http.go:272-274). The render is Go's
            // `http.Error` (ServeHTTP sets Proxy-Authenticate, then
            // http.Error(rw, http.StatusText(407), 407)): Content-Type
            // text/plain; charset=utf-8 + X-Content-Type-Options: nosniff +
            // the status text with a trailing newline as body — the h2
            // mirror of the HTTP/1.1 write_http_error_auth_response shape
            // (vhost.rs). `send_h2_error` only defaults to text/html when
            // the caller set no Content-Type (FIX 3).
            return send_h2_error(
                &mut respond,
                407,
                &[
                    ("proxy-authenticate", "Basic realm=\"Restricted\""),
                    ("content-type", "text/plain; charset=utf-8"),
                    ("x-content-type-options", "nosniff"),
                ],
                Bytes::from_static(b"Proxy Authentication Required\n"),
            )
            .await;
        }
        Err(VhostResolveError::Unauthorized { proxy_form: false }) => {
            // Origin-form → Go answers 401 + WWW-Authenticate
            // (http.go:275-277), same http.Error render.
            return send_h2_error(
                &mut respond,
                401,
                &[
                    ("www-authenticate", "Basic realm=\"Restricted\""),
                    ("content-type", "text/plain; charset=utf-8"),
                    ("x-content-type-options", "nosniff"),
                ],
                Bytes::from_static(b"Unauthorized\n"),
            )
            .await;
        }
        Err(VhostResolveError::NotFound) => {
            return send_h2_404(&mut respond, &not_found_page).await;
        }
    };

    // Locate the control handler for the target run_id (shared with the
    // HTTP/1.1 path).
    let internal_tx = state
        .run_id_to_ctl_tx
        .get(&forward.run_id)
        .map(|v| v.tx.clone());
    let Some(ctl_tx) = internal_tx else {
        tracing::warn!(host = %host, path = %path, "HTTP VHost (h2c) route for '{}' path '{}' found but control handler gone", host, path);
        // FIX 2: the backend connection cannot be established — the Go
        // vhost's ErrorHandler class for non-timeout transport errors is
        // 404 + the not-found page (pkg/util/vhost/http.go:128-138), the
        // same answer the HTTP/1.1 surface gives a control-gone route
        // (Go connectHandler CreateConnection errors write NotFoundResponse,
        // not 502).
        return send_h2_404(&mut respond, &not_found_page).await;
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
    // pattern). Bounded (vhost.rs:748-764 parity): a control handler that
    // stops draining must not pin this task + fd + permit forever; after
    // CTL_SEND_TIMEOUT the send is abandoned and the h2 stream answers the
    // backend-unreachable 404 (FIX 2, see the timeout arm below).
    match tokio::time::timeout(
        crate::state::CTL_SEND_TIMEOUT,
        ctl_tx.send(InternalMsg::ProxyUserConn {
            proxy_name: forward.proxy_name,
            user_conn: frp_core::transport::IoStream::SshChannel(Box::new(control)),
            pre_read: forward.request_head,
            user_conn_permit: None,
            // Local sender — no group selection was done.
            group_selected: false,
            // vhost CONNECT tunnels raw — the bridge's injector must skip
            // them (Go connectHandler joins raw, ModifyResponse never runs).
            request_is_connect: is_connect,
        }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            // Channel closed: control handler died between lookup and
            // dispatch — the backend connection can no longer be
            // established, so the Go ErrorHandler 404 class (FIX 2).
            tracing::warn!(host = %host, path = %path, "h2c route for '{}' path '{}' found but control channel closed", host, path);
            return send_h2_404(&mut respond, &not_found_page).await;
        }
        Err(_elapsed) => {
            // CTL_SEND_TIMEOUT fired: the control handler stopped draining.
            // A local dispatch bound, NOT Go's response-head deadline — Go's
            // net.Error timeout 504 gate (http.go:131-133) applies only to
            // the reverse-proxy response-head wait, so this arm is the
            // backend-unreachable 404 class, like the other dispatch
            // failures (FIX 2).
            tracing::warn!(host = %host, path = %path, "h2c route for '{}' path '{}' found but control channel send timed out; answering 404", host, path);
            return send_h2_404(&mut respond, &not_found_page).await;
        }
    }

    let (mut client_r, client_w) = tokio::io::split(client);
    let mut body = request.into_body();

    // RFC 7540 §8.1.2.6: the request body must not extend beyond the
    // declared Content-Length. The h2 crate does FRAME-level work only —
    // it has no notion of Content-Length (that header is opaque app data
    // to the h2 codec), so nothing below this gate rejects a body longer
    // than the declared value. This app-level gate is therefore the
    // PRIMARY defense, not defense in depth: the body task counts against
    // the declared length and signals `excess` on a violation; the main
    // task answers RST_STREAM PROTOCOL_ERROR (Go's h2 server resets with
    // PROTOCOL_ERROR on the same violation). Forwarding excess bytes raw
    // would let them reach the provider as a pipelined request (request
    // smuggling).
    //
    // `Notify` is deliberate over `oneshot`: the signal must fire ONLY on an
    // actual violation. A oneshot's sender is dropped when the body task
    // finishes NORMALLY (every legitimate request), which closes the channel
    // and resolves the receiver with `Err(Closed)` — a `biased` select would
    // then take the reset arm on every forwarded request. `notified()` stays
    // pending until `notify_one()` is called, no matter how the body task
    // ends; the permit is retained if the notification beats the first poll.
    let excess = Arc::new(tokio::sync::Notify::new());
    let excess_body = excess.clone();

    // Forward the h2 request body to the provider. When the head carried no
    // Content-Length it was emitted with `Transfer-Encoding: chunked` (Go
    // http.Transport behavior for unknown-length bodies), so body bytes are
    // framed accordingly. Releasing the h2 flow-control capacity after each
    // write keeps backpressure end-to-end.
    let body_task = tokio::spawn(async move {
        let mut client_w = client_w;
        let end_stream = body.is_end_stream();
        let mut remaining = content_length;
        while let Some(Ok(data)) = body.data().await {
            if !data.is_empty() {
                if let Some(rem) = remaining {
                    if data.len() as u64 > rem {
                        // Excess body bytes beyond the declared Content-Length
                        // (RFC 7540 §8.1.2.6). Never forward them — they would
                        // arrive at the provider as a pipelined request.
                        excess_body.notify_one();
                        return;
                    }
                    remaining = Some(rem - data.len() as u64);
                }
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
    // response-head exchange is bounded by vhost_http_timeout — the Go vhost
    // maps the same config to `ResponseHeaderTimeout` and answers 504 via its
    // ErrorHandler (pkg/util/vhost/http.go), and `<= 0` floors at 60s (shared
    // clamp in vhost.rs). This leg arms its one deadline at the first
    // response-head read; Go arms the timer once the request body is fully
    // written (transport.go writeErrCh), which the response-read side cannot
    // observe — the same narrow anchor divergence documented on the
    // HTTP/1.1 ResponseHeaderInjector. The deadline is shared across the
    // whole exchange: interim 1xx heads do not re-arm it
    // (see stream_h2_response).
    let head_timeout = Some(std::time::Duration::from_secs(super::clamp_vhost_timeout(
        state.vhost_http_timeout,
    )));
    // `biased;`: if the backend completes AND the body exceeds simultaneously,
    // the protocol error wins — a declared Content-Length is a hard contract.
    let response_result = tokio::select! {
        biased;
        _ = excess.notified() => {
            body_task.abort();
            // Go's h2 server answers RST_STREAM PROTOCOL_ERROR when a DATA
            // frame exceeds the declared Content-Length.
            respond.send_reset(h2::Reason::PROTOCOL_ERROR);
            return Ok(());
        }
        r = stream_h2_response(
            &mut client_r,
            &mut respond,
            head_timeout,
            is_head,
            &not_found_page,
        ) => r,
    };

    // Once the response is fully relayed the bridge has served its purpose —
    // stop the body forwarder so the h2 stream (and work conn) can wind down
    // even if the client is still trickling request bytes.
    body_task.abort();
    response_result
}

/// Canonicalize an h2 `:authority` (Host equivalent) for routing — Go
/// `CanonicalHost` semantics (pkg/util/http/http.go:54-66), the same
/// `host[:port]` → host split the HTTP/1.1 Host-header path performs in
/// vhost.rs (`canonicalize_authority`). Implemented here directly (not
/// delegated) so the h2c side is self-contained on the SplitHostPort
/// parity details; both implementations follow the same Go spec and agree
/// on every input.
///
/// The Go `hasPort` gate: the port is split only when the value has exactly
/// one colon or is a bracketed form with `]:`. The port itself is never
/// digit-validated ("example.com:abc" → "example.com" — the numeric gate
/// exists only on the CONNECT request line via url.ParseRequestURI's
/// validOptionalPort). An EMPTY port is legal (net/ipsock.go:216
/// `port = hostport[i+1:]` unconditional) — "example.com:" → "example.com".
/// "example.com:8080:90" has two colons and is NOT a bracketed form, so Go
/// leaves it untouched (unroutable → 404) while a naive first-colon split
/// would route it to "example.com" and shadow a legitimate route.
fn host_from_authority(authority: &str) -> &str {
    let colons = authority.bytes().filter(|b| *b == b':').count();
    let hostname = if authority.starts_with('[') && authority.contains("]:") {
        // Go SplitHostPort bracket branch (net/ipsock.go:190-209): the
        // FIRST ']' must sit immediately before the LAST ':' — otherwise
        // the address errors ("too many colons", "missing port") and
        // CanonicalHost returns "" (unroutable), NOT the bare literal
        // ("[::1]:80:90" must not route as "::1"). The post-split guards
        // (ipsock.go:210-213) also reject a '[' inside the bracket host or
        // a stray ']' after the closing bracket.
        let end = authority.find(']').unwrap_or(0);
        let inner = &authority[1..end];
        let clean = !inner.contains('[') && !authority[end + 1..].contains(']');
        match authority.rfind(':') {
            Some(i) if end + 1 == i && clean => inner,
            _ => "",
        }
    } else if colons == 1 {
        // SplitHostPort host:port — the port may be empty (ipsock.go:216).
        // A '[' or ']' anywhere in a non-bracketed value is Go's
        // "unexpected '['/']' in address" error → "".
        if authority.contains(['[', ']']) {
            ""
        } else {
            let (h, _port) = authority.rsplit_once(':').unwrap_or((authority, ""));
            h
        }
    } else {
        // Portless hostname, bracketed IPv6 without "]:", or unbracketed
        // multi-colon — Go hasPort is false, the value is used as-is.
        authority
    };
    // Strip exactly one trailing dot (Go TrimSuffix — "example.com.."
    // stays unroutable). Lowercase is NOT applied here: the route lookup is
    // case-insensitive (vhost.rs get_locked), matching Go's CanonicalHost
    // while keeping the borrowed `&str`.
    hostname.strip_suffix('.').unwrap_or(hostname)
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

/// Extract Basic Auth credentials from a named header of an h2 request
/// (HTTP/2 has no pseudo-header for auth). Go `checkRouteAuthByRequest`
/// reads `Proxy-Authorization` for absolute-form requests and
/// `Authorization` for origin-form; Go `getRequestRouteUser` additionally
/// falls back to `Authorization` for ROUTING when Proxy-Authorization is
/// absent. Both readers share this one parser, which mirrors Go
/// `httppkg.ParseBasicAuth` (pkg/util/http/http.go:81-97): the "Basic "
/// prefix is matched case-insensitively (`strings.EqualFold`) and the
/// base64 payload is NOT trimmed — Go's StdEncoding rejects any whitespace
/// in the payload (a trailing space is a decode error, not padding).
fn extract_basic_auth_header(
    headers: &http::HeaderMap,
    name: &'static str,
) -> Option<(String, String)> {
    let value = headers.get(name)?.to_str().ok()?;
    // Case-insensitive "Basic " prefix — strip_prefix is case-sensitive,
    // so "basic dXNl…" was wrongly rejected (Go EqualFold accepts it).
    // `get(..n)` not `value[..n]`: h2 field values may legally carry
    // obs-text bytes (RFC 7230 §3.2 — 0x80-0xFF), so to_str() can yield a
    // multibyte char straddling the fixed 6-byte cut → the slice would
    // panic (process abort under panic=abort) on ANY request carrying such
    // a header. get() returns None at a non-boundary cut (no match).
    const PREFIX: &str = "Basic ";
    if !value
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
    {
        return None;
    }
    // Safe: the get(..6) match above guarantees byte 6 is a char boundary.
    let encoded = &value[PREFIX.len()..];
    // Deliberately NO trim: Go decodes the payload verbatim and its
    // StdEncoding rejects whitespace ("Basic  dXNl…" and "…c3Nz " fail in
    // Go; the old trim accepted both).
    let decoded = frp_core::base64::decode(encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pwd) = creds.split_once(':')?;
    Some((user.to_string(), pwd.to_string()))
}

/// Extract Basic Auth credentials from the `proxy-authorization` header.
fn extract_basic_auth_headers(headers: &http::HeaderMap) -> Option<(String, String)> {
    extract_basic_auth_header(headers, "proxy-authorization")
}

/// Go `checkRouteAuthByRequest` + `getRequestRouteUser`
/// (pkg/util/vhost/http.go:187-246) for h2 streams. Returns (credentials
/// for validation, routing-only username).
///
/// Absolute-form (`req.URL.Host != ""`): credentials come from
/// `Proxy-Authorization` ONLY (never `authorization`). Origin-form:
/// credentials come from `Authorization` (Basic) — exactly like HTTP/1.1
/// origin-form; `Proxy-Authorization` is entirely ignored.
///
/// Routing (Go getRequestRouteUser): on origin-form the Authorization
/// Basic username routes the request; on absolute-form a NON-EMPTY
/// Proxy-Authorization is parsed (malformed → "" empty user bucket, never
/// the Authorization username), while an ABSENT/empty one
/// (`Header.Get` == "" for both) falls back to the Authorization username
/// so the request still hits the matched per-user route and returns
/// 407 instead of 404. Auth validation deliberately does not share the
/// fallback — the returned credentials are the single validation source.
fn h2_select_auth(
    headers: &http::HeaderMap,
    is_absolute_form: bool,
) -> (Option<(String, String)>, Option<String>) {
    let http_auth = if is_absolute_form {
        extract_basic_auth_headers(headers)
    } else {
        extract_basic_auth_header(headers, "authorization")
    };
    let proxy_auth_present = headers
        .get("proxy-authorization")
        .is_some_and(|v| !v.is_empty());
    let route_user: Option<String> = if http_auth.is_none() {
        if is_absolute_form && proxy_auth_present {
            // Header present but unparseable — Go ParseBasicAuth fails →
            // empty user bucket (Some("") ≡ "", no Authorization fallback).
            Some(String::new())
        } else {
            // Go `req.BasicAuth()` user: origin-form always; absolute-form
            // only when Proxy-Authorization is absent/empty. A failed or
            // absent Authorization parse yields None ≡ Go's "" bucket.
            extract_basic_auth_header(headers, "authorization").map(|(u, _)| u)
        }
    } else {
        None
    };
    (http_auth, route_user)
}

/// Go-parity request-form gate for h2 streams: absolute-form ⟺
/// `req.URL.Host != ""` (pkg/util/vhost/http.go:195, 232), where Go's h2
/// server built the URL per h2_bundle.go:6362-6430 — CONNECT gets
/// URL{Host: :authority}, everything else gets url.ParseRequestURI(":path").
fn h2_request_is_absolute_form<B>(request: &http::Request<B>) -> bool {
    if request.method() == http::Method::CONNECT {
        // Go: URL{Host: :authority} — always absolute-form.
        return true;
    }
    // Non-CONNECT: the :scheme/:authority pseudo-headers do NOT feed the
    // URL (it is built from ":path" alone), so absolute-form requires
    // ":path" itself to parse as an absolute URI with a non-empty host.
    match request.uri().path_and_query() {
        Some(pq) => is_absolute_form_target(pq.as_str()),
        None => false,
    }
}

/// Go `url.ParseRequestURI(":path").Host != ""` — the non-CONNECT half of
/// the form gate. Host is set only when the target starts with
/// "scheme://authority" (a scheme parsed by getScheme — first char a
/// letter — then "://" before any path "/", then a NON-EMPTY authority;
/// "http:///x" has Host == ""). A "//host/path" network-path reference has
/// NO scheme and ParseRequestURI (viaRequest) leaves Host empty — it is
/// origin-form (go1.22 net/url/url.go: the authority branch requires a
/// scheme when viaRequest). Only the AUTH gate uses this — the routing
/// host always comes from `:authority`.
fn is_absolute_form_target(path_and_query: &str) -> bool {
    let Some(first) = path_and_query.as_bytes().first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        // getScheme needs a letter first ("1a://x", "/foo:bar"). Go 400s
        // "1a://x" at ParseRequestURI; treating it as origin-form here
        // still routes on :authority with Authorization auth enforced, so
        // the outcome is a 401/404, never an auth bypass.
        return false;
    }
    let Some(colon) = path_and_query.find(':') else {
        return false;
    };
    let scheme = &path_and_query[..colon];
    if scheme.contains('/') || scheme.contains('?') {
        // The ':' sits after the first '/' or inside the query — a path.
        return false;
    }
    let after = &path_and_query[colon + 1..];
    if !after.starts_with("//") {
        // "http:opaque" → Go URL.Opaque, Host == "".
        return false;
    }
    // The authority must be non-empty ("http:///x" → Host == "").
    after[2..].split('/').next().is_some_and(|a| !a.is_empty())
}

/// Send a body-less (or single-chunk) HTTP/2 error response.
async fn send_h2_error(
    respond: &mut SendResponse<Bytes>,
    status: u16,
    extra: &[(&str, &str)],
    body: Bytes,
) -> Result<(), h2::Error> {
    let mut resp = match http::Response::builder().status(status).body(()) {
        Ok(resp) => resp,
        Err(_) => {
            // Callers pass internal constants, but an invalid status must not
            // panic the request-serving task; fall back to 500.
            tracing::warn!("invalid status code {status} for h2 error response, using 500");
            http::Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(())
                .expect("500 is a valid status code")
        }
    };
    for &(k, v) in extra {
        match (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(v),
        ) {
            (Ok(name), Ok(value)) => {
                resp.headers_mut().insert(name, value);
            }
            _ => {
                tracing::warn!("skipping invalid h2 error header {k:?}: {v:?}");
            }
        }
    }
    if body.is_empty() {
        respond.send_response(resp, true)?;
        return Ok(());
    }
    // FIX 3: default to text/html ONLY when the caller set no Content-Type.
    // The 404-page arms rely on this default (Go serves the not-found HTML
    // as text/html); the 401/407 arms pass Go's http.Error Content-Type
    // (text/plain; charset=utf-8) via `extra` and must not have it
    // overwritten. (Go's own default would sniff the page — the html
    // default keeps the byte shape deterministic.)
    if !resp.headers().contains_key("content-type") {
        resp.headers_mut()
            .insert("content-type", http::HeaderValue::from_static("text/html"));
    }
    let mut send = respond.send_response(resp, false)?;
    send.send_data(body, true)?;
    Ok(())
}

/// The 404 answer Go frp's vhost ErrorHandler gives every non-timeout
/// backend failure (pkg/util/vhost/http.go:128-138: `WriteHeader(404)` +
/// `Write(getNotFoundPageContent())`): the custom_404_page when configured,
/// else the builtin HTML — byte-for-byte the same body the HTTP/1.1
/// surface's `write_not_found_response` serves.
async fn send_h2_404(
    respond: &mut SendResponse<Bytes>,
    not_found_page: &Bytes,
) -> Result<(), h2::Error> {
    send_h2_error(respond, 404, &[], not_found_page.clone()).await
}

/// Body selection for the h2c 404 arms: `custom_404_page` when non-empty,
/// else the crate-wide builtin (frp-core's `GO_404_NOT_FOUND_BODY`, the
/// mirror of Go frp's builtin NotFound HTML). Empty-bodied 404s are a
/// divergence from the Go shape — every Go 404 carries the page.
fn h2c_not_found_body(custom_404_page: &str) -> Bytes {
    if custom_404_page.is_empty() {
        Bytes::from_static(frp_core::bridge::GO_404_NOT_FOUND_BODY.as_bytes())
    } else {
        Bytes::from(custom_404_page.to_owned())
    }
}

/// Read bytes until the end of the HTTP/1.1 response head, returning head +
/// any body bytes that arrived with it.
///
/// Head end follows Go `textproto` semantics (the engine behind
/// `http.ReadResponse`): each line ends at the next `\n` with ONE trailing
/// `\r` stripped, and the first empty line ends the head — so LF-only and
/// mixed-EOL backends are legal, not just `\r\n\r\n`.
/// Read until the end of an HTTP/1.1 response head, seeded with bytes
/// already read (a consumed interim 1xx head's leftover — the next head's
/// start, possibly already complete).
async fn read_until_head_from(
    r: &mut (impl AsyncRead + Unpin),
    mut buf: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
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
    // caller's malformed-head 404.
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
    // Go http.ReadResponse gates (response.go — round-3 review): the
    // version token must be one of ParseHTTPVersion's exact-match set and
    // the code token exactly 3 digits BEFORE conversion, so "HTTP/9.9 200"
    // / "HTTP/1.1 0200 OK" / "FOO 200 OK" are all malformed → 404 (the
    // ErrorHandler non-timeout class), never forwarded.
    let version = parts.next()?;
    if !frp_core::textproto::is_valid_http_version(version) {
        return None;
    }
    let code_token = parts.find(|p| !p.is_empty())?;
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
    // fails from_str_radix for radix 16).
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

    /// Fill `buf` completely from the buffered reader, failing with
    /// UnexpectedEof when the stream ends early.
    async fn fill_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.available().is_empty() && !self.read_more().await? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in response body",
                ));
            }
            let take = (buf.len() - filled).min(self.available().len());
            buf[filled..filled + take].copy_from_slice(&self.available()[..take]);
            self.consume(take);
            filled += take;
        }
        Ok(())
    }

    /// Read exactly `n` bytes, appending to `out` after clearing it. The
    /// caller owns the buffer, so its allocation is REUSED across calls —
    /// chunked streaming no longer allocates (and re-grows) a fresh Vec per
    /// chunk (a 64 KiB chunk used to cost ~8 reallocations via
    /// `with_capacity(n.min(8192))` growth). The capacity grows to exactly
    /// `n` on the first call and is kept for subsequent calls.
    async fn read_exact_into(&mut self, out: &mut Vec<u8>, n: usize) -> std::io::Result<()> {
        out.clear();
        out.try_reserve_exact(n).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::OutOfMemory, "response body too large")
        })?;
        out.resize(n, 0); // no realloc: capacity already >= n
        self.fill_exact(out).await
    }

    /// Read one CRLF (or LF) terminated line including its terminator.
    /// A line longer than 64 KiB is invalid (chunk-size lines and trailing
    /// headers are tiny in practice) — the growth is bounded instead of
    /// letting a misbehaving backend accumulate 8 KiB per read_more forever.
    async fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            let avail = self.available();
            if avail.len() > MAX_CHUNK_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk line exceeds 64 KiB",
                ));
            }
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

/// Decode a chunked response body and stream it as HTTP/2 DATA frames,
/// returning the trailer section (RFC 7230 §4.1.2) the backend sent after
/// the terminating 0-chunk, if any.
///
/// Read errors truncate the body (Go treats an aborted backend body as EOF)
/// and yield no trailers; a MALFORMED chunk terminator is an explicit
/// framing error (Go chunkedReader: "malformed chunked encoding") that
/// drops the stream instead of delivering a truncated 200. `scratch` is the
/// caller-owned buffer reused for every chunk (see
/// `BodyReader::read_exact_into`).
async fn stream_chunked_body(
    reader: &mut BodyReader<'_, impl AsyncRead + Unpin>,
    send: &mut SendStream<Bytes>,
    scratch: &mut Vec<u8>,
) -> Result<http::HeaderMap, h2::Error> {
    loop {
        let line = match reader.read_line().await {
            Ok(l) => l,
            Err(_) => return Ok(http::HeaderMap::new()),
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
            Err(_) => return Ok(http::HeaderMap::new()),
        };
        if size == 0 {
            // Trailer section: trailer fields run from after the terminating
            // 0-chunk to the final blank line (RFC 7230 §4.1.2). Audit
            // round 8 (G1): these used to be read and DISCARDED here while
            // the backend's `Trailer:` announce header was still forwarded
            // into the h2 response head (it is not hop-by-hop, so the head
            // loop keeps it) — the h2c client was PROMISED trailers that
            // never arrived and then got bare END_STREAM. Collect the
            // fields; the caller delivers them as h2 trailers before
            // END_STREAM. Go semantics (pkg/util/vhost/http.go:57 —
            // httputil.ReverseProxy): what the chunked body carries is
            // delivered, announced or not; the `Trailer:` head field is the
            // pre-announce only.
            let mut trailers = http::HeaderMap::new();
            loop {
                let line = match reader.read_line().await {
                    Ok(l) if !is_blank_line(&l) => l,
                    Ok(_) | Err(_) => break,
                };
                let mut field = line.as_slice();
                if field.ends_with(b"\r\n") {
                    field = &field[..field.len() - 2];
                } else if field.ends_with(b"\n") {
                    field = &field[..field.len() - 1];
                }
                let field = trim_ascii_ws(field);
                let Some(colon) = field.iter().position(|&b| b == b':') else {
                    continue; // not a field line — ignored (tolerance as before)
                };
                // Same parse shape as parse_response_head (name and value
                // outer-trimmed; invalid names/values skipped so one hostile
                // field cannot kill delivery of the rest).
                let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(trim_ascii_ws(&field[..colon])),
                    http::HeaderValue::from_bytes(trim_ascii_ws(&field[colon + 1..])),
                ) else {
                    continue;
                };
                if is_hop_by_hop(name.as_str()) {
                    // Connection-specific fields are forbidden in ANY h2
                    // HEADERS block (RFC 9113 §8.2.2 — the h2 encoder
                    // rejects them in trailers too).
                    continue;
                }
                // `append`, not `insert`: duplicate trailer names keep every
                // value, like the response-head forward loop.
                trailers.append(name, value);
            }
            return Ok(trailers);
        }
        // Round 10 (MEDIUM): `size` comes from the backend's chunk-size
        // line — buffering it in one `read_exact(size)` allocates
        // attacker-influenced memory (a misbehaving backend or proxied
        // origin can emit an arbitrarily large chunk). Stream the chunk
        // in bounded slices instead; the frame stays chunked
        // (end_stream=false on every slice). Round 15: each slice reads
        // into the reused `scratch` (no per-chunk Vec growth); the data is
        // copied out because h2's `SendStream` consumes `Bytes`.
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(MAX_CHUNK_SIZE);
            match reader.read_exact_into(scratch, n).await {
                Ok(()) => {}
                Err(_) => return Ok(http::HeaderMap::new()),
            }
            send.send_data(Bytes::copy_from_slice(scratch), false)?;
            remaining -= n;
        }
        // Each chunk ends with CRLF (RFC 7230 §4.1); Go's chunkedReader
        // errors with "malformed chunked encoding" when the two bytes after
        // the chunk data are not CRLF. Verify instead of silently discarding
        // whatever two bytes arrived — mis-parsing the framing could let
        // garbage past as a chunk line, and a missing/malformed terminator
        // must not deliver a truncated 200. Returning Err drops the stream
        // (the h2 layer resets it with CANCEL); the caller logs the error.
        let mut terminator = [0u8; 2];
        match reader.fill_exact(&mut terminator).await {
            Ok(()) if terminator == *b"\r\n" => {}
            _ => {
                // Explicit reset with CANCEL — the same reason the h2 layer
                // would use if the SendResponse were dropped. PROTOCOL_ERROR
                // would blame the client; the violation is the backend's.
                return Err(h2::Reason::CANCEL.into());
            }
        }
    }
}

/// One response-head read bounded by an absolute deadline, continuing from
/// `seed` (bytes of a consumed interim head's leftover). Head-read failures
/// map to `HeadReadError`; the caller maps Closed → the Go ErrorHandler
/// non-timeout 404 and TimedOut → 504 (see `stream_h2_response` — the
/// ErrorHandler's net.Error Timeout gate, pkg/util/vhost/http.go:128-138).
enum HeadReadError {
    Closed,
    TimedOut,
}

async fn read_backend_head<R: AsyncRead + Unpin>(
    r: &mut R,
    seed: Vec<u8>,
    deadline: Option<tokio::time::Instant>,
) -> Result<Vec<u8>, HeadReadError> {
    match deadline {
        // timeout_at, not timeout: the caller arms ONE absolute deadline for
        // the whole response-head exchange, so each interim 1xx head consumed
        // along the way cannot restart the clock (round-13 review A3/C2).
        Some(deadline) => {
            match tokio::time::timeout_at(deadline, read_until_head_from(r, seed)).await {
                Ok(Ok(h)) => Ok(h),
                Ok(Err(_e)) => Err(HeadReadError::Closed),
                Err(_elapsed) => Err(HeadReadError::TimedOut),
            }
        }
        None => read_until_head_from(r, seed)
            .await
            .map_err(|_e| HeadReadError::Closed),
    }
}

/// Read the backend HTTP/1.1 response from `r`, send the HTTP/2 response head,
/// then stream the body (decoding chunked transfer-encoding) as HTTP/2 DATA
/// frames. When `head_timeout` is `Some`, the WHOLE response-head exchange is
/// bounded by one absolute deadline armed here at entry — interim 1xx heads
/// consumed before the final head (the loop below) do not restart the clock
/// (round-13 review A3/C2; without this, a backend answering `100` then
/// stalling parked the head read without bound, one fresh timeout per head).
/// On timeout a body-less `504 Gateway Timeout` is sent, mirroring the Go
/// vhost `ErrorHandler` mapping a `ResponseHeaderTimeout` to 504
/// (pkg/util/vhost/http.go:131-133, `net.Error` Timeout gate); every OTHER
/// backend failure — close before the head, malformed head, 101, invalid
/// status — answers `404` + the not-found page (FIX 2), the ErrorHandler's
/// non-timeout class, exactly as it does on Go frp's HTTP/1.1 vhost surface
/// (Go frp v0.71.0 serves h2c from the same net/http listener — module
/// doc above — and its ErrorHandler is transport-agnostic).
///
/// `is_head` marks a HEAD request: its response never carries a body, and
/// statuses 204/304 never do either (FIX 1 — see the tail of this fn).
/// `not_found_page` is the pre-resolved 404 body (custom_404_page or the
/// builtin HTML) shared by the failure arms below.
async fn stream_h2_response<R: AsyncRead + Unpin>(
    r: &mut R,
    respond: &mut SendResponse<Bytes>,
    head_timeout: Option<std::time::Duration>,
    is_head: bool,
    not_found_page: &Bytes,
) -> Result<(), h2::Error> {
    let deadline = head_timeout.map(|d| tokio::time::Instant::now() + d);
    let mut head = match read_backend_head(r, Vec::new(), deadline).await {
        Ok(h) => h,
        Err(HeadReadError::Closed) => {
            // Backend closed (or no work conn was ever assigned) before the
            // response head. Go frp's vhost ErrorHandler answers every
            // non-timeout transport error with 404 + its not-found page
            // (pkg/util/vhost/http.go:128-138 — only a `net.Error`
            // Timeout() maps to 504), and h2c rides the same handler on the
            // same net/http listener, so this h2 leg mirrors that 404 class
            // instead of inventing a 502 (FIX 2).
            tracing::debug!("h2c backend closed before response head, sending 404");
            return send_h2_404(respond, not_found_page).await;
        }
        Err(HeadReadError::TimedOut) => {
            // The one net.Error-equivalent arm: Go maps a
            // ResponseHeaderTimeout to a bare 504 (WriteHeader only —
            // http.go:130-133). The h2c translation read IS clocked by
            // vhost_http_timeout (clamp_vhost_timeout doc), so a deadline
            // expiry here is the exact mirror of Go's response-head timer.
            tracing::debug!("h2c backend response-head timeout, sending 504");
            return send_h2_error(respond, 504, &[], Bytes::new()).await;
        }
    };
    // Go Transport readResponse parity (round-13 review finding): non-101
    // 1xx heads (a 100 Continue answering `Expect: 100-continue`) are
    // consumed internally and never surface as the response — keep reading
    // until a final head ends the exchange. Without the skip the interim
    // head was sent to the h2 client as `:status 100` and the pipelined
    // final head streamed as its body. Go frp serves h2c from the same
    // net/http vhost listener as h1, and its reverse proxy consumes 1xx
    // the same way on both transports.
    let parsed = loop {
        let Some(parsed) = parse_response_head(&head) else {
            // Malformed backend head — a Go transport readResponse error,
            // i.e. a non-timeout ErrorHandler class → 404 (FIX 2).
            tracing::debug!("h2c backend sent a malformed response head, sending 404");
            return send_h2_404(respond, not_found_page).await;
        };
        if (100..=199).contains(&parsed.status) {
            if parsed.status == 101 {
                // A backend `101 Switching Protocols` cannot be represented
                // over HTTP/2 — h2 has no protocol switch; its 1xx are
                // informational only, and an h2 client treats a 101 head
                // that way too. Streaming the post-switch bytes as the
                // body would be DATA before the final response head, a
                // connection PROTOCOL_ERROR — the h2 crate's client
                // answers with a whole-connection GOAWAY, killing every
                // concurrent stream on the h2 conn (round-13 review B2).
                // Answer the non-timeout ErrorHandler 404 (like the
                // malformed-head/status arms below) instead of leaking a
                // conn-killing head; there is no final head to wait for
                // (FIX 2).
                tracing::debug!(
                    "h2c backend answered 101 Switching Protocols (unsupported over HTTP/2), sending 404"
                );
                return send_h2_404(respond, not_found_page).await;
            }
            // A non-101 1xx head carries no body — bytes after its blank
            // line are the next head's start (possibly already complete).
            tracing::trace!("h2c consuming backend interim {} head", parsed.status);
            let seed = head[parsed.body_offset..].to_vec();
            head = match read_backend_head(r, seed, deadline).await {
                Ok(h) => h,
                Err(HeadReadError::Closed) => {
                    // Interim head answered, then the backend closed before
                    // a final head — a truncated-response transport error →
                    // the 404 ErrorHandler class (FIX 2).
                    tracing::debug!("h2c backend closed between response heads, sending 404");
                    return send_h2_404(respond, not_found_page).await;
                }
                Err(HeadReadError::TimedOut) => {
                    tracing::debug!("h2c backend response-head timeout, sending 504");
                    return send_h2_error(respond, 504, &[], Bytes::new()).await;
                }
            };
            continue;
        }
        break parsed;
    };
    let ParsedHead {
        status,
        headers,
        body_offset,
    } = parsed;

    let mut resp = match http::Response::builder().status(status).body(()) {
        Ok(resp) => resp,
        Err(_) => {
            // The status comes from the backend head; a broken/malicious
            // backend can send a value the builder rejects (e.g. 0 or >999).
            // Degrade to the 404 ErrorHandler class like the other
            // malformed-head cases instead of panicking the request-serving
            // task (FIX 2).
            tracing::debug!("h2c backend sent invalid status code {status}, sending 404");
            return send_h2_404(respond, not_found_page).await;
        }
    };
    for (n, v) in &headers {
        if is_hop_by_hop(n.as_str()) {
            continue;
        }
        // `append`, not `insert`: a backend emitting duplicate response
        // headers (e.g. multiple Set-Cookie) must preserve ALL values —
        // `insert` collapses duplicates and the last one wins.
        resp.headers_mut().append(n.clone(), v.clone());
    }

    // FIX 1: responses to HEAD requests and the no-body statuses 204/304
    // never carry a DATA body — Go's net/http sets Body = NoBody for all of
    // them (noBodyAllowedStatuses 204/304 + the HEAD method; transport
    // response.go `bodyAllowedForStatus`), so the h2 relay must end the
    // stream with the response head. The body legs below would otherwise
    // park forever on a backend that DECLARES a Content-Length on such an
    // answer and then holds the connection open with no body bytes (a lie
    // for these statuses — HEAD says so by definition, 204/304 by RFC) —
    // the FIX-1 hang: `read_exact_into` waits for bytes that can never
    // come. RFC 9113 §8.6.1: a 204 (and any 1xx) MUST NOT carry
    // Content-Length, and Go drops it from 304 answers too — strip it for
    // both; a HEAD answer KEEPS its Content-Length (it truthfully describes
    // the GET the client would receive).
    if is_head || status == 204 || status == 304 {
        if !is_head {
            resp.headers_mut().remove("content-length");
        }
        respond.send_response(resp, true)?;
        return Ok(());
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
    // One scratch buffer for every body path — chunk slices and
    // content-length slices read into it and are copied out (h2
    // `SendStream` consumes `Bytes`), so no per-slice Vec growth.
    let mut scratch: Vec<u8> = Vec::new();

    if chunked {
        let trailers = stream_chunked_body(&mut reader, &mut send, &mut scratch).await?;
        if trailers.is_empty() {
            send.send_data(Bytes::new(), true)?;
        } else {
            // Audit round 8 (G1): the backend sent a trailer section after
            // its terminating 0-chunk — deliver it as real h2 trailers.
            // `send_trailers` ends the stream with a HEADERS frame
            // (END_STREAM), replacing the bare empty-DATA end. The values
            // were announced to the client already via the forwarded
            // `Trailer:` head field (and unannounced fields arrive too —
            // Go delivers what arrives).
            send.send_trailers(trailers)?;
        }
        return Ok(());
    }
    if let Some(mut remaining) = content_length {
        while remaining > 0 {
            let n = remaining.min(8192);
            match reader.read_exact_into(&mut scratch, n).await {
                Ok(()) => {}
                Err(_) => break, // truncated body
            }
            remaining -= scratch.len();
            send.send_data(Bytes::copy_from_slice(&scratch), false)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hop_by_hop() {
        // RFC 7540 §8.1.2.2 forbids these on the HTTP/2 side; they must be
        // dropped when re-encoding to HTTP/1.1 (Go net/http drops them too).
        for name in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(is_hop_by_hop(name), "{name} must be hop-by-hop");
            assert!(
                is_hop_by_hop(&name.to_uppercase()),
                "hop-by-hop check must be case-insensitive: {name}"
            );
        }
        // End-to-end headers pass through.
        for name in ["content-length", "host", "authorization", "x-custom", "te"] {
            assert!(!is_hop_by_hop(name), "{name} must NOT be hop-by-hop");
        }
    }

    #[test]
    fn test_host_from_authority() {
        assert_eq!(host_from_authority("example.com"), "example.com");
        // Port is stripped (host:port).
        assert_eq!(host_from_authority("example.com:8080"), "example.com");
        // Round-15 correction: an EMPTY port part is LEGAL — Go
        // net.SplitHostPort slices `port = hostport[i+1:]` unconditionally
        // (ipsock.go:216) → CanonicalHost routes the bare hostname
        // (trailing dot still trimmed after the strip).
        assert_eq!(host_from_authority("example.com:"), "example.com");
        assert_eq!(host_from_authority("example.com.:"), "example.com");
        // Bracketed IPv6 with an empty port — likewise legal.
        assert_eq!(host_from_authority("[::1]:"), "::1");
        // Exactly one trailing dot is trimmed (Go CanonicalHost
        // TrimSuffix strips ONE dot — "example.com.." becomes
        // "example.com.", which STAYS unroutable because the trailing
        // dot survives; matching canonicalize_authority in vhost.rs).
        assert_eq!(host_from_authority("example.com."), "example.com");
        assert_eq!(host_from_authority("example.com.:8080"), "example.com");
        assert_eq!(host_from_authority("example.com.."), "example.com.");
        // Bracketed IPv6: with a port the address is stripped of brackets
        // and port; WITHOUT "]:", the whole bracketed value stays — Go
        // `hasPort` returns false, CanonicalHost leaves it untouched, and it
        // is unroutable (nothing registers brackets).
        assert_eq!(host_from_authority("[::1]:8080"), "::1");
        assert_eq!(host_from_authority("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(host_from_authority("[2001:db8::1]."), "[2001:db8::1]");
        // Empty authority.
        assert_eq!(host_from_authority(""), "");
        // Two colons without brackets: Go `hasPort` is false → the value is
        // left untouched (unroutable → 404). A naive first-colon split would
        // wrongly route this to "example.com".
        assert_eq!(
            host_from_authority("example.com:8080:90"),
            "example.com:8080:90"
        );
        // Bracket form with extra colons after the "]:" — Go SplitHostPort
        // tooManyColons (ipsock.go:196-197) → host "" (unroutable), NOT the
        // bare "::1" (a naive ']'-split would route it).
        assert_eq!(host_from_authority("[::1]:80:90"), "");
        // ']' not immediately followed by the LAST colon — Go
        // missingPort (ipsock.go:206-209) → "" (unroutable).
        assert_eq!(host_from_authority("[::1]x]:8080"), "");
        // A non-numeric port still splits (Go never validates the port
        // digits on this path — the numeric gate is CONNECT-only).
        assert_eq!(host_from_authority("example.com:abc"), "example.com");
        // An UNBRACKETED IPv6 literal has two+ colons and is not a bracketed
        // form — it stays untouched (unroutable), no panic.
        assert_eq!(host_from_authority("::1"), "::1");
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex(b"1a").unwrap(), 26);
        assert_eq!(parse_hex(b"0").unwrap(), 0);
        assert_eq!(parse_hex(b"ff").unwrap(), 255);
        assert_eq!(parse_hex(b" 1A ").unwrap(), 26); // whitespace trimmed
        assert!(parse_hex(b"").is_err());
        assert!(parse_hex(b"zz").is_err());
        assert!(parse_hex(b"-1").is_err());
        assert!(parse_hex(b"1g").is_err());
        // Go parseHexUint accepts ONLY 0-9a-fA-F — "+5" is an invalid byte
        // in a chunk length even though Rust's from_str_radix would accept
        // the leading '+' for radix 16.
        assert!(parse_hex(b"+5").is_err());
        // Not valid UTF-8 → InvalidData.
        assert!(parse_hex(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn test_parse_response_head() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nbody";
        let parsed = parse_response_head(head).expect("valid head");
        assert_eq!(parsed.status, 200);
        assert_eq!(
            parsed.body_offset,
            head.len() - 4,
            "body starts after the blank line"
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

        // Header values are whitespace-trimmed; status 404 parses.
        let head = b"HTTP/1.1 404 Not Found\r\nX-Pad:   value  \r\n\r\n";
        let parsed = parse_response_head(head).unwrap();
        assert_eq!(parsed.status, 404);
        assert_eq!(
            header_value(&parsed.headers, "x-pad")
                .unwrap()
                .to_str()
                .unwrap(),
            "value"
        );

        // Malformed heads → None (the caller answers the ErrorHandler 404).
        assert!(parse_response_head(b"").is_none());
        assert!(parse_response_head(b"HTTP/1.1 200 OK\r\n").is_none()); // no blank line
        assert!(parse_response_head(b"not-http\r\n\r\n").is_none()); // no status token
        assert!(parse_response_head(b"HTTP/1.1 abc\r\n\r\n").is_none()); // non-numeric status
                                                                         // Tab-separated status line → None: Go strings.Cut splits at the
                                                                         // first literal space, so the tab stays inside the version token and
                                                                         // ParseHTTPVersion rejects it (split_whitespace used to accept and
                                                                         // forward such heads — round-7 review NIT).
        assert!(parse_response_head(b"HTTP/1.1\t200 OK\r\n\r\n").is_none());
        // Multi-space between version and code stays legal (Go TrimLeft).
        assert_eq!(
            parse_response_head(b"HTTP/1.1  200 OK\r\n\r\n")
                .unwrap()
                .status,
            200
        );
    }

    #[test]
    fn test_parse_response_head_textproto_eol() {
        // LF-only backend response head (textproto-legal; RED before the
        // audit round-7 S1 fix: strict \r\n\r\n + \r\n scans returned None).
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
        // CRLF status line + LF-only blank line (the pre-fix \r\n\r\n scan
        // missed this shape too: `\r\n\n` contains neither window).
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

    #[test]
    fn test_extract_basic_auth_headers() {
        // base64("user:pass") = "dXNlcjpwYXNz". An absolute-form h2 request
        // carries its credentials in `proxy-authorization` (Go
        // checkRouteAuthByRequest reads only that header there).
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            extract_basic_auth_headers(&h),
            Some(("user".into(), "pass".into()))
        );

        // Missing header → None.
        assert_eq!(extract_basic_auth_headers(&http::HeaderMap::new()), None);
        // A plain `authorization` header must NOT authenticate an
        // absolute-form request (Go reads only Proxy-Authorization there).
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            extract_basic_auth_headers(&h),
            None,
            "authorization must not authenticate an absolute-form request"
        );
        // Go ParseBasicAuth parity: the "Basic " prefix matches
        // case-insensitively (strings.EqualFold), the payload is NOT
        // trimmed (StdEncoding rejects whitespace), and a len-4-multiple
        // payload needs exact padding.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            extract_basic_auth_headers(&h),
            Some(("user".into(), "pass".into())),
            "lowercase 'basic ' must match (Go EqualFold)"
        );
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic  dXNlcjpwYXNz"),
        );
        assert_eq!(
            extract_basic_auth_headers(&h),
            None,
            "payload must not be trimmed (double space fails Go too)"
        );
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz "),
        );
        assert_eq!(
            extract_basic_auth_headers(&h),
            None,
            "trailing space in the payload fails Go StdEncoding too"
        );
        // A multibyte char straddling the 6-byte "Basic " cut must be
        // skipped (get(..6) → None), not panic — h2 allows obs-text bytes
        // in field values, so to_str() can succeed with "abcdeé…".
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_bytes(&b"abcde\xc3\xa9Basic dXNlcjpwYXNz"[..]).unwrap(),
        );
        assert_eq!(
            extract_basic_auth_headers(&h),
            None,
            "straddling multibyte char must be a non-match, not a panic"
        );
        // Wrong scheme → None.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(extract_basic_auth_headers(&h), None);
        // Decodes but has no colon separator (base64("use") = "dXNl") → None.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic dXNl"),
        );
        assert_eq!(extract_basic_auth_headers(&h), None);
        // Decodes to non-UTF-8 bytes (base64(0xff) = "/w==") → None.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic /w=="),
        );
        assert_eq!(extract_basic_auth_headers(&h), None);
        // Not valid base64 → None.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic !!!"),
        );
        assert_eq!(extract_basic_auth_headers(&h), None);
    }

    /// Drive a real h2 client/server pair over an in-memory duplex and hand
    /// the server-side request to `f`. h2::RecvStream has no public
    /// constructor, so `build_http1_request_head` can only be exercised
    /// through a live handshake (same pattern as tests/vhost_h2c.rs).
    ///
    /// `end_stream` is pinned on the wire, not left to handshake timing:
    /// the client ends the stream with an explicit empty DATA frame and the
    /// server task exhausts the body before `f` runs, so `is_end_stream()`
    /// is deterministic on both sides (whether the HEADERS-frame END_STREAM
    /// flag is observable at `accept()` time was a CI race). Both halves
    /// are kept alive while `f` runs: dropping `respond` (SendResponse),
    /// the connection, or the client's send half resets the stream, which
    /// flips `is_end_stream()` on the server side and would mask the
    /// branch under test — the connection survives in a driver task that
    /// keeps polling it until the client closes.
    async fn with_h2_request(
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        end_stream: bool,
        f: impl FnOnce(&http::Request<h2::RecvStream>),
    ) {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io)
                .await
                .expect("server handshake");
            let (mut request, respond) = conn.accept().await.expect("accept").expect("request");
            if end_stream {
                // Exhaust the body while polling the connection: the
                // RecvStream only observes stream state — the connection
                // drives the codec.
                tokio::select! {
                    _ = async {
                        while matches!(request.body_mut().data().await, Some(Ok(_))) {}
                    } => {}
                    _ = conn.accept() => {
                        panic!("server conn ended before the request body drained")
                    }
                }
            }
            let driver =
                tokio::spawn(async move { while let Some(Ok(_)) = conn.accept().await {} });
            (request, respond, driver)
        });
        let (mut client, client_conn) = h2::client::handshake(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = client_conn.await;
        });
        client.clone().ready().await.expect("client ready");

        let mut builder = http::Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let (response_fut, mut stream) = client
            .send_request(builder.body(()).unwrap(), false)
            .expect("send_request");
        if end_stream {
            // Empty DATA frame with END_STREAM set: the end marker goes out
            // unconditionally (an end flag riding on HEADERS alone was not
            // reliably visible at the server's accept()).
            stream
                .send_data(Bytes::new(), true)
                .expect("send end-of-stream frame");
        }
        let (request, respond, _driver) = server_task.await.expect("server task");
        let _respond = respond; // keep the server send half open while f runs
        let _stream = stream; // keep the client send half open while f runs
        let _response_fut = response_fut;
        f(&request);
    }

    #[tokio::test]
    async fn test_build_http1_request_head_end_stream() {
        with_h2_request(
            "GET",
            "http://h2c.example.com/",
            &[("x-custom", "v1"), ("x-second", "two")],
            true,
            |req| {
                let head = build_http1_request_head(req);
                let head_text = String::from_utf8_lossy(&head);
                assert!(
                    head_text.starts_with("GET / HTTP/1.1\r\n"),
                    "head: {head_text}"
                );
                assert!(
                    head_text.contains("Host: h2c.example.com\r\n"),
                    "head: {head_text}"
                );
                assert!(head_text.contains("x-custom: v1\r\n"), "head: {head_text}");
                assert!(head_text.contains("x-second: two\r\n"), "head: {head_text}");
                assert!(
                    head_text.contains("Content-Length: 0\r\n"),
                    "end_stream request needs Content-Length: 0: {head_text}"
                );
                assert!(
                    head_text.ends_with("\r\n"),
                    "head must end with the blank line: {head_text}"
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_build_http1_request_head_open_stream_chunked() {
        with_h2_request(
            "POST",
            "http://h2c.example.com/submit?q=1",
            &[],
            false,
            |req| {
                let head = build_http1_request_head(req);
                let head_text = String::from_utf8_lossy(&head);
                assert!(
                    head_text.starts_with("POST /submit?q=1 HTTP/1.1\r\n"),
                    "path_and_query must be preserved: {head_text}"
                );
                assert!(
                    head_text.contains("Host: h2c.example.com\r\n"),
                    "head: {head_text}"
                );
                assert!(
                    head_text.contains("Transfer-Encoding: chunked\r\n"),
                    "open stream must be chunked-framed: {head_text}"
                );
                assert!(
                    !head_text.contains("Content-Length"),
                    "no content length for an open stream: {head_text}"
                );
            },
        )
        .await;
    }

    #[test]
    fn test_is_absolute_form_target() {
        // Path-form targets (the normal h2 case — the :scheme/:authority
        // pseudo-headers are irrelevant) → origin-form.
        assert!(!is_absolute_form_target("/"));
        assert!(!is_absolute_form_target("/secret?q=1"));
        assert!(!is_absolute_form_target("/pa:th"));
        // Absolute-form: ":path" itself starts with "scheme://authority".
        assert!(is_absolute_form_target("http://h2c.example.com/secret"));
        assert!(is_absolute_form_target("https://example.com/"));
        // A network-path reference has no scheme and stays origin-form
        // under ParseRequestURI's viaRequest gate (go1.22 net/url/url.go).
        assert!(!is_absolute_form_target("//example.com/secret"));
        // Scheme rules: must start with a letter; the authority must be
        // non-empty ("http:///x" → URL.Host == "").
        assert!(!is_absolute_form_target("1a://x/y"));
        assert!(!is_absolute_form_target("http:///x"));
        assert!(!is_absolute_form_target("http:opaque"));
        assert!(!is_absolute_form_target(""));
    }

    #[test]
    fn test_h2_select_auth_fallbacks() {
        // Absolute-form: valid Proxy-Authorization authenticates.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            h2_select_auth(&h, true),
            (Some(("user".into(), "pass".into())), None)
        );
        // Absolute-form: malformed Proxy-Authorization → empty user bucket,
        // NO Authorization fallback (Go getRequestRouteUser ParseBasicAuth
        // failure branch).
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic !!!"),
        );
        h.insert(
            "authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(h2_select_auth(&h, true), (None, Some(String::new())));
        // Absolute-form: Proxy-Authorization ABSENT → routing falls back to
        // the Authorization username (Go `proxyAuth == ""` branch).
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(h2_select_auth(&h, true), (None, Some("user".into())));
        // Absolute-form with nothing → (None, None) ≡ Go's "" bucket.
        assert_eq!(h2_select_auth(&http::HeaderMap::new(), true), (None, None));
        // Origin-form: credentials come from Authorization; Proxy-
        // Authorization is entirely ignored (Go checkRouteAuthByRequest
        // req.BasicAuth() branch).
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            h2_select_auth(&h, false),
            (Some(("user".into(), "pass".into())), None)
        );
        // Origin-form with no Authorization → (None, None) → "" bucket.
        let mut h = http::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(h2_select_auth(&h, false), (None, None));
        // Origin-form with malformed Authorization → (None, None): the
        // failed parse yields "" for both auth and routing (Go BasicAuth
        // returns "" on failure).
        let mut h = http::HeaderMap::new();
        h.insert("authorization", http::HeaderValue::from_static("Basic !!!"));
        assert_eq!(h2_select_auth(&h, false), (None, None));
    }

    #[tokio::test]
    async fn test_h2_select_auth_origin_form_authorization() {
        // A real h2 GET always carries :scheme/:authority pseudo-headers,
        // but the :path is path-form "/secret" — Go builds the URL from
        // :path alone → req.URL.Host == "" → origin-form → the
        // `authorization` header authenticates (and a failure would answer
        // 401 + WWW-Authenticate, not 407). This pins the round-8 MEDIUM
        // fix: the old code read Proxy-Authorization on EVERY h2 request
        // and 407'd origin-form requests.
        with_h2_request(
            "GET",
            "http://h2c.example.com/secret",
            &[("authorization", "Basic dXNlcjpwYXNz")],
            true,
            |req| {
                assert!(
                    !h2_request_is_absolute_form(req),
                    "path-form :path must be origin-form"
                );
                let (auth, route_user) =
                    h2_select_auth(req.headers(), h2_request_is_absolute_form(req));
                assert_eq!(auth, Some(("user".to_string(), "pass".to_string())));
                assert_eq!(route_user, None);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_h2_select_auth_connect_proxy_authorization() {
        // CONNECT builds URL{Host: :authority} in Go's h2 server →
        // absolute-form → Proxy-Authorization authenticates. The h2 client
        // sends no :path/:scheme for CONNECT and the server-side Uri is
        // authority-form (h2 0.4.18 Pseudo::request / convert_poll_message).
        with_h2_request(
            "CONNECT",
            "example.com:443",
            &[("proxy-authorization", "Basic dXNlcjpwYXNz")],
            true,
            |req| {
                assert!(
                    h2_request_is_absolute_form(req),
                    "CONNECT must be absolute-form"
                );
                let (auth, route_user) = h2_select_auth(req.headers(), true);
                assert_eq!(auth, Some(("user".to_string(), "pass".to_string())));
                assert_eq!(route_user, None);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_chunked_body_eof_mid_chunk() {
        // A backend chunk stream that ends mid-chunk (declared size larger
        // than the remaining bytes) must fail with UnexpectedEof — never
        // hang, loop, or panic (round-15 review flagged missing coverage;
        // stream_chunked_body truncates the body on this error, Go treats
        // an aborted backend body as EOF).
        let data: &[u8] = b"5\r\nabc";
        let mut src = data;
        let mut reader = BodyReader::new(&mut src, Vec::new());
        assert_eq!(reader.read_line().await.expect("chunk size line"), b"5\r\n");
        let mut scratch = Vec::new();
        let err = reader
            .read_exact_into(&mut scratch, 5)
            .await
            .expect_err("declared 5 bytes, only 3 arrive");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        // The post-chunk terminator read sees the same clean EOF.
        let mut term = [0u8; 2];
        let err = reader
            .fill_exact(&mut term)
            .await
            .expect_err("no terminator bytes after the truncation");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// Mock backend response reader for the FIX-1/FIX-2 unit pins: serves
    /// `head` bytes, then PANICS on any further poll. The pre-FIX-1 relay
    /// read a never-arriving body after a HEAD/204/304 head (the hang under
    /// test) — a reader that just returns EOF would let the old code break
    /// out of its body loop and end the stream, passing the pin; a panic
    /// makes the regression a deterministic test failure.
    struct HeadThenPanicMock {
        data: &'static [u8],
    }

    impl HeadThenPanicMock {
        fn new(data: &'static [u8]) -> Self {
            Self { data }
        }
    }

    impl tokio::io::AsyncRead for HeadThenPanicMock {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.data.is_empty() {
                panic!(
                    "mock backend polled after its head bytes were consumed — \
                     a response-body leg must not run for HEAD/204/304 (FIX 1)"
                );
            }
            let n = self.data.len().min(buf.remaining());
            buf.put_slice(&self.data[..n]);
            self.data = &self.data[n..];
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// EOF-from-the-start backend — a `0` read is the clean-EOF signal
    /// `read_until_head_from` maps to `HeadReadError::Closed`.
    struct EofMock;

    impl tokio::io::AsyncRead for EofMock {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Drive one h2 request/response exchange: `serve` runs server-side with
    /// the accepted request's `respond` handle and returns the
    /// client-observed (status, headers, body). The h2 connection lives in a
    /// driver task so the send side flushes while `serve` answers — the
    /// `with_h2_request` pattern, extended to full responses.
    async fn h2c_test_roundtrip<F, Fut>(method: &str, serve: F) -> (u16, http::HeaderMap, Vec<u8>)
    where
        F: FnOnce(SendResponse<Bytes>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), h2::Error>> + Send + 'static,
    {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io)
                .await
                .expect("server h2 handshake");
            let (request, respond) = conn.accept().await.expect("accept").expect("request");
            let _request = request;
            let driver =
                tokio::spawn(async move { while let Some(Ok(_)) = conn.accept().await {} });
            let result = serve(respond).await;
            // Response frames written via `respond` only reach the wire when
            // the driver task polls the connection. `serve` can run to
            // completion without yielding (mock backend reads are
            // immediately ready, and h2's send_response/send_data are sync
            // enqueues), in which case the driver never gets polled before
            // the abort below drops the conn with the response still queued
            // — the h2 client then reads a clean EOF and every open stream
            // errors with h2's own "stream closed because of a broken pipe"
            // (proto/streams/state.rs recv_eof). Yield once so the driver
            // flushes the queued response frames into the duplex first.
            tokio::task::yield_now().await;
            driver.abort();
            result
        });
        let (mut client, client_conn) = h2::client::handshake(client_io)
            .await
            .expect("client h2 handshake");
        tokio::spawn(async move {
            let _ = client_conn.await;
        });
        client.clone().ready().await.expect("client ready");

        let request = http::Request::builder()
            .method(method)
            .uri("http://h2c.example.com/")
            .body(())
            .unwrap();
        let (response_fut, stream) = client.send_request(request, true).expect("send_request");
        let _stream = stream; // keep the client send half open while the server answers
        let response = response_fut.await.expect("h2 response head");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        let mut recv = response.into_body();
        while let Some(Ok(chunk)) = recv.data().await {
            body.extend_from_slice(&chunk);
        }
        server_task
            .await
            .expect("server task panicked")
            .expect("serve returned an error");
        (status, headers, body)
    }

    #[tokio::test]
    async fn test_h2_head_204_304_end_stream_without_body_legs() {
        // FIX 1 regression: a backend that DECLARES a Content-Length on a
        // HEAD / 204 / 304 answer and holds the connection open never sends
        // the declared body bytes (a HEAD response has no body by
        // definition; 204/304 have none by RFC) — the old relay parked its
        // body leg forever (read_exact_into on the length class, the
        // read-to-EOF leg on the no-length class). The relay must end the
        // stream with the response head; the panicking mock turns the
        // pre-fix read into a test failure instead of a hang.
        //
        // HEAD → 200 keeps its truthful Content-Length (it describes the
        // GET the client would receive).
        let (status, headers, body) = h2c_test_roundtrip("HEAD", |respond| async move {
            let mut respond = respond;
            let mut backend =
                HeadThenPanicMock::new(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
            let page = h2c_not_found_body("");
            stream_h2_response(&mut backend, &mut respond, None, true, &page).await
        })
        .await;
        assert_eq!(status, 200);
        assert_eq!(
            headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("100"),
            "a HEAD response keeps the declared Content-Length"
        );
        assert!(body.is_empty(), "a HEAD response must have no DATA body");

        // 204 with a declared (lying) Content-Length — the CL body-leg shape.
        let (status, headers, body) = h2c_test_roundtrip("GET", |respond| async move {
            let mut respond = respond;
            let mut backend =
                HeadThenPanicMock::new(b"HTTP/1.1 204 No Content\r\nContent-Length: 50\r\n\r\n");
            let page = h2c_not_found_body("");
            stream_h2_response(&mut backend, &mut respond, None, false, &page).await
        })
        .await;
        assert_eq!(status, 204);
        assert!(
            !headers.contains_key("content-length"),
            "204 must not carry Content-Length (RFC 9113 §8.6.1)"
        );
        assert!(body.is_empty());

        // 304 with NO length framing — the read-to-EOF body-leg shape.
        let (status, headers, body) = h2c_test_roundtrip("GET", |respond| async move {
            let mut respond = respond;
            let mut backend = HeadThenPanicMock::new(b"HTTP/1.1 304 Not Modified\r\n\r\n");
            let page = h2c_not_found_body("");
            stream_h2_response(&mut backend, &mut respond, None, false, &page).await
        })
        .await;
        assert_eq!(status, 304);
        assert!(
            !headers.contains_key("content-length"),
            "304 must not carry Content-Length (Go drops it with Body = NoBody)"
        );
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_h2_backend_failures_answer_404_with_page() {
        // FIX 2 pins: the non-timeout backend-failure arms answer Go's
        // ErrorHandler 404 — status 404, Content-Type text/html (send_h2_error's
        // default for the page body), body byte-identical to the builtin
        // page the HTTP/1.1 surface serves (GO_404_NOT_FOUND_BODY).
        let (status, headers, body) = h2c_test_roundtrip("GET", |respond| async move {
            let mut respond = respond;
            let page = h2c_not_found_body("");
            stream_h2_response(&mut EofMock, &mut respond, None, false, &page).await
        })
        .await;
        assert_eq!(status, 404, "backend close before the head → Go 404 class");
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/html")
        );
        assert_eq!(
            body,
            frp_core::bridge::GO_404_NOT_FOUND_BODY.as_bytes(),
            "the 404 body must be the not-found page, not an empty body"
        );

        let (status, headers, body) = h2c_test_roundtrip("GET", |respond| async move {
            let mut respond = respond;
            let mut backend = HeadThenPanicMock::new(b"not-http\r\n\r\n");
            let page = h2c_not_found_body("");
            stream_h2_response(&mut backend, &mut respond, None, false, &page).await
        })
        .await;
        assert_eq!(status, 404, "malformed head → Go 404 class");
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/html")
        );
        assert_eq!(body, frp_core::bridge::GO_404_NOT_FOUND_BODY.as_bytes());
    }

    #[tokio::test]
    async fn test_h2_error_render_content_type_nosniff_and_default() {
        // FIX 3: the 401/407 arms render Go's http.Error shape — explicit
        // Content-Type text/plain; charset=utf-8 + X-Content-Type-Options:
        // nosniff + the StatusText body with a trailing newline. The h2
        // error helper must NOT overwrite the caller's Content-Type with
        // its text/html default (pre-fix: every non-empty-bodied error was
        // text/html — the 401/407 arms answered with the wrong type and no
        // body).
        for (expected, want_body) in [
            (401u16, "Unauthorized\n"),
            (407u16, "Proxy Authentication Required\n"),
        ] {
            let (status, headers, body) = h2c_test_roundtrip("GET", move |respond| {
                let want_body = want_body.to_owned();
                async move {
                    let mut respond = respond;
                    send_h2_error(
                        &mut respond,
                        expected,
                        &[
                            ("content-type", "text/plain; charset=utf-8"),
                            ("x-content-type-options", "nosniff"),
                        ],
                        Bytes::from(want_body),
                    )
                    .await
                }
            })
            .await;
            assert_eq!(status, expected);
            assert_eq!(
                headers.get("content-type").and_then(|v| v.to_str().ok()),
                Some("text/plain; charset=utf-8"),
                "the caller's Content-Type must survive (not be text/html)"
            );
            assert_eq!(
                headers
                    .get("x-content-type-options")
                    .and_then(|v| v.to_str().ok()),
                Some("nosniff")
            );
            assert_eq!(body.as_slice(), want_body.as_bytes());
        }
        // The text/html default stays for the 404-page class (no
        // Content-Type passed).
        let (status, headers, body) = h2c_test_roundtrip("GET", |respond| async move {
            let mut respond = respond;
            let page = h2c_not_found_body("");
            send_h2_404(&mut respond, &page).await
        })
        .await;
        assert_eq!(status, 404);
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/html")
        );
        assert_eq!(body, frp_core::bridge::GO_404_NOT_FOUND_BODY.as_bytes());
    }
}
