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
/// (RFC 7540 §8.1.2.2 forbids the connection-specific fields of RFC 7230
/// §6.1; Go's net/http drops them too). The entries are Go
/// `httputil.hopHeaders`' full list and mirror the client twin
/// (frp-client/src/plugin/h2.rs `is_hop_by_hop`) exactly: the server twin
/// carried only the first five until the round-18 review, so a client's
/// `proxy-authorization` (Go's ReverseProxy removes it from `outreq.Header`
/// before the RoundTrip — httputil/reverseproxy.go `removeHopByHopHeaders`)
/// plus `proxy-authenticate` / `te` / `trailer` reached the provider
/// backend on the forwarded HTTP/1.1 head.
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
    // Round-18 finding C2: the per-iteration `head_end` full-buffer rescan
    // is O(n²) for a head that arrives in many small chunks (each read
    // re-scans every byte of every earlier chunk). The incremental
    // scanner is byte-identical for the feed-until-`Some` pattern (same
    // first-blank-line semantics as `head_end`, frp-core textproto).
    // `buf` is monotonic within this function (seeded once, only
    // extended), so one scanner created at entry — its first feed scans
    // the seed — is safe across reads.
    let mut scanner = frp_core::textproto::HeadEndScanner::new();
    loop {
        // Terminator scan before the cap check (round-16 readLimit model;
        // round-18 L1 precision): the cap fires when buf.len() > 1 MiB at
        // a feed-check with no terminator found, and reads are
        // 4096-quantized — a terminated head up to ~1 MiB always serves;
        // up to ~1 MiB + 4096 serves when the terminator tail arrives in
        // the single read that crosses 1 MiB (chunk-quantized, not a hard
        // +4096 bound); a terminator beyond that errors TooLarge.
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
    /// padded form "5 " that this value was trimmed from, and an
    /// unparseable re-read degrades the body leg to read-to-EOF (which parks
    /// the stream on a backend that then holds the connection open). The
    /// client https2http twin carries the same value
    /// (frp-client/src/plugin/h2.rs `ParsedHead`).
    content_length: Option<u64>,
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
    // Go http.ReadResponse gates (net/http/response.go): the version token
    // must pass ParseHTTPVersion's LENIENT shape — exact rows HTTP/1.0/1.1,
    // else exactly-8-char `HTTP/X.Y` single-digit tokens, so HTTP/9.9 200
    // parses and forwards (round-18 M1: the round-7 "exact-match set"
    // reading was a Go-source misreading) — and the code token exactly 3
    // digits BEFORE conversion, so "HTTP/1.1 0200 OK" / "FOO 200 OK" are
    // malformed → 404 (the ErrorHandler non-timeout class), never
    // forwarded.
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
    // engine behind ReadResponse) — round-18 M4 mirror of the client
    // https2http plugin fix (frp-client/src/plugin/h2.rs), applied to this
    // server h2c twin: ANY malformed record fails the WHOLE head (→ the
    // caller's 404 ErrorHandler arm), never a forwarded response missing
    // rows. The old code diverged in both directions: it trimmed every
    // line FIRST, so a legal obs-fold continuation (" two" under
    // "X-A: one") lost its leading space, read as a colonless new record,
    // and failed the whole head (404) where Go merges the fold and
    // forwards "one two"; and records whose name/value failed conversion
    // were silently dropped, forwarding the degraded head where Go fails
    // the whole read. Per record, in Go order:
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
    //     here (fail-closed 404 vs Go forwarding a wire-invalid name for
    //     the h2 peer to reject);
    //   - every value line is CTL-checked (validHeaderValueByte:
    //     VCHAR/SP/HTAB/obs-text only; CTL incl. DEL fails the head) — the
    //     check runs on the SP/HTAB-trimmed span, which is equivalent to
    //     Go's raw-span check because the trim removes only legal bytes;
    //     obs-text values are legal and now survive (the old from_str
    //     UTF-8 gate silently dropped those rows);
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
    // Go fixLength + parseContentLength parity (net/http/transfer.go —
    // round-18 M2 + deviation-3 mirrors of the client h2.rs fix):
    // readTransfer runs on EVERY head ReadResponse draws (interim 1xx and
    // final alike), and two+ Content-Length rows whose TrimString'ed
    // values differ make it fail — the WHOLE head is malformed (404),
    // never a response whose copied rows disagree with the body count
    // that framed it (smuggling-adjacent). Identical values dedupe to ONE
    // row (Go Issue 16490: fixLength deletes the duplicates and re-adds
    // the first trimmed value), so the h2 emission carries one row — the
    // copy loop below appends every parsed row verbatim, and two identical
    // CL rows would otherwise both reach the h2 client. Stored values keep
    // trailing spaces (TrimLeft storage), so rows compare like
    // textproto.TrimString — SP/HTAB trimmed at both ends. The surviving
    // row's TrimString'ed value must then satisfy parseContentLength:
    // non-empty, all-ASCII-digits, within 63 bits — a garbage
    // ("Content-Length: abc"), empty ("Content-Length:"), or overflowing
    // value fails readTransfer → the WHOLE head errors (the old code
    // forwarded the garbage row and read the body to EOF); padded values
    // ("5 ") are legal, and the validated count rides out on `ParsedHead`
    // so the body leg consumes what was TrimString'ed here — the stored row
    // keeps its trailing space (the all-whitespace obs-fold above appends a
    // bare ' '), so re-parsing the raw row in the body leg would reject a
    // value this gate just accepted (round-18 review fix, client twin
    // parity).
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
    let mut content_length: Option<u64> = None;
    if let Some(idx) = cl_row {
        // h2 value hygiene (round-18 follow-up): the stored row KEEPS its
        // trailing SP/HTAB (TrimLeft storage; an all-whitespace obs-fold
        // appends a bare ' ', so "Content-Length: 5\r\n \r\n" stores "5 "),
        // and a field value with leading/trailing whitespace must not reach
        // the h2 HEADERS frame (RFC 9113 §8.2.1) — the h2 client resets the
        // stream with PROTOCOL_ERROR at the head, so the body leg below never
        // runs. Normalize the row to exactly the bytes this gate validated,
        // at the one place that both trims the value and knows the row is a
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
    Some(ParsedHead {
        status,
        headers,
        content_length,
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

/// Abort the response stream with INTERNAL_ERROR — the server-side mirror
/// of the client plugin's `abort_stream` (frp-client/src/plugin/h2.rs,
/// round-18 M3): Go's ReverseProxy copyResponse panics http.ErrAbortHandler
/// on any mid-body error (httputil/reverseproxy.go) and the net/http h2
/// server answers that panic with RST_STREAM + ErrCodeInternal
/// (h2_bundle.go handlerPanicRST → WriteRSTStream). The abort makes a
/// backend body that died mid-response visible to the h2 client as a stream
/// error instead of a clean END_STREAM that reads like a complete response.
/// Returns `Ok(None)` — the caller treats None as "stream already reset, do
/// NOT write the clean END_STREAM".
///
/// The `yield_now` before the reset is load-bearing (round-18 follow-up;
/// Go orders the same way — HEADERS goes out before handlerPanicRST): the
/// response HEADERS frame is only QUEUED by `send_response`, and h2's
/// `send_reset` calls `clear_queue` unless the stream is locally
/// initiated and still `is_pending_open` — never true for this
/// server-side stream — so resetting in the same poll DROPS the queued
/// head and RST_STREAM becomes the client's first frame (the response head
/// never arrives, at all). One yield lets the connection task drain the
/// queue to the wire (it is woken by `queue_frame` and re-registered every
/// poll), then the reset follows the head.
async fn abort_stream(send: &mut SendStream<Bytes>) -> Result<Option<http::HeaderMap>, h2::Error> {
    tokio::task::yield_now().await;
    send.send_reset(h2::Reason::INTERNAL_ERROR);
    Ok(None)
}

/// Decode a chunked response body and stream it as HTTP/2 DATA frames,
/// returning the trailer section (RFC 7230 §4.1.2) the backend sent after
/// the terminating 0-chunk, if any.
///
/// `Ok(Some(trailers))` is a CLEAN end (empty map = no trailer section);
/// `Ok(None)` means the body was truncated and the stream was already reset
/// by [`abort_stream`] — the caller must not write END_STREAM. Every
/// mid-body error path aborts (round-18 M3 mirror): the old code returned an
/// empty trailer map on truncation and the caller ended the stream cleanly,
/// presenting a truncated body as complete — Go copyResponse aborts instead
/// (see [`abort_stream`]). That includes a MALFORMED chunk terminator, an
/// explicit framing error (Go chunkedReader: "malformed chunked encoding")
/// — the old code reset with CANCEL, which is the h2-layer fallback when a
/// SendResponse is dropped, not Go's handlerPanicRST code. `scratch` is the
/// caller-owned buffer reused for every chunk (see
/// `BodyReader::read_exact_into`).
async fn stream_chunked_body(
    reader: &mut BodyReader<'_, impl AsyncRead + Unpin>,
    send: &mut SendStream<Bytes>,
    scratch: &mut Vec<u8>,
) -> Result<Option<http::HeaderMap>, h2::Error> {
    loop {
        let line = match reader.read_line().await {
            Ok(l) => l,
            Err(_) => return abort_stream(send).await, // died mid-chunk-size-line
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
            Err(_) => return abort_stream(send).await, // malformed chunk size line
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
            // END_STREAM. Go semantics (pkg/util/vhost/http.go —
            // httputil.ReverseProxy): what the chunked body carries is
            // delivered, announced or not; the `Trailer:` head field is the
            // pre-announce only.
            let mut trailers = http::HeaderMap::new();
            loop {
                let line = match reader.read_line().await {
                    Ok(l) if !is_blank_line(&l) => l,
                    Ok(_) => break, // blank line: trailer section done
                    Err(_) => return abort_stream(send).await, // died mid-trailer
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
            return Ok(Some(trailers));
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
                Err(_) => return abort_stream(send).await, // chunk data cut short
            }
            send.send_data(Bytes::copy_from_slice(scratch), false)?;
            remaining -= n;
        }
        // Each chunk ends with CRLF (RFC 7230 §4.1); Go's chunkedReader
        // errors with "malformed chunked encoding" when the two bytes after
        // the chunk data are not CRLF. Verify instead of silently discarding
        // whatever two bytes arrived — mis-parsing the framing could let
        // garbage past as a chunk line, and a missing/malformed terminator
        // must not deliver a truncated 200. A missing terminator after
        // delivered chunk data is the same truncation as a mid-chunk EOF:
        // reset with INTERNAL_ERROR rather than deliver END_STREAM.
        let mut terminator = [0u8; 2];
        match reader.fill_exact(&mut terminator).await {
            Ok(()) if terminator == *b"\r\n" => {}
            _ => return abort_stream(send).await,
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
        content_length,
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
        // `Trailer` is in the hop set, but a backend DECLARATION is re-emitted
        // rather than dropped: Go's Transport moves the announced keys out of
        // `res.Header` into `res.Trailer` (fixTrailer, net/http/transfer.go)
        // and httputil.ReverseProxy writes them back as a `Trailer` response
        // field before WriteHeader — a Go front's client-facing response does
        // carry the announcement. The backend's verbatim line holds exactly
        // the names Go re-synthesizes, and the trailer SECTION is delivered as
        // real h2 trailers below, so the round-8 G1 pin
        // (frp-server/tests/vhost_h2c.rs, announce field + delivered
        // trailers) keeps holding while every other hop field is dropped.
        if is_hop_by_hop(n.as_str()) && !n.as_str().eq_ignore_ascii_case("trailer") {
            continue;
        }
        // `append`, not `insert`: a backend emitting duplicate response
        // headers (e.g. multiple Set-Cookie) must preserve ALL values —
        // `insert` collapses duplicates and the last one wins.
        resp.headers_mut().append(n.clone(), v.clone());
    }

    // FIX 1: responses to HEAD requests and the no-body statuses 204/304
    // never carry a DATA body — Go's net/http server suppress gate is
    // server.go:1513 (`req.Method == "HEAD" || !bodyAllowedForStatus(code)`
    // || code == StatusNoContent), with `bodyAllowedForStatus` at
    // transfer.go:459-461 returning false for 204/304/1xx — so the h2 relay
    // must end the stream with the response head. The body legs below would
    // otherwise
    // park forever on a backend that DECLARES a Content-Length on such an
    // answer and then holds the connection open with no body bytes (a lie
    // for these statuses — HEAD says so by definition, 204/304 by RFC) —
    // the FIX-1 hang: `read_exact_into` waits for bytes that can never
    // come.
    //
    // Content-Length: stripped for 204 ALWAYS — RFC 9110 §8.6 forbids the
    // header on any 204, HEAD method or not (the pre-round-15 code kept it
    // on a HEAD + 204 answer), and stripped for 304. This mirrors the h1
    // net/http write layer every Go frp h1 vhost response passes through —
    // chunkWriter.writeHeader deletes suppressed headers before
    // serialization (go1.25 server.go:1483-1497): suppressedHeadersNoBody
    // = {Content-Length, Transfer-Encoding} for 204,
    // suppressedHeaders304 = {Content-Type, Content-Length,
    // Transfer-Encoding} for 304 (transfer.go:459-485). frp-rs's own h1
    // front does the same on its http non-CONNECT legs (round-16: the
    // ResponseHeaderInjector in frp-server/src/control/bridge.rs drops
    // Content-Length from a final 204/304 head at its splice), so the two
    // fronts are consistent again. Go's H2 writer has no such suppression
    // (h2_bundle.go writeChunk moves a declared CL into the response
    // verbatim) — this strip remains a fail-closed RFC/Go-h1-parity
    // divergence from Go's h2 pass-through, narrow like the h1 sibling:
    // Content-Length only, Transfer-Encoding/Content-Type left alone.
    // A HEAD answer to a body-bearing status KEEPS its
    // Content-Length (it truthfully describes the GET the client would
    // receive; RFC 9110 §8.6 allows it).
    if is_head || status == 204 || status == 304 {
        if status == 204 || status == 304 {
            resp.headers_mut().remove("content-length");
        }
        respond.send_response(resp, true)?;
        return Ok(());
    }

    // Content-Length framing is the head parse's VALIDATED value
    // (`ParsedHead`), never a re-parse of the stored row: the parser is
    // legal for all-whitespace obs-folds that append a bare ' ' (see the
    // record walk above), so "Content-Length: 5\r\n \r\n\r\n" stores "5 "
    // — legal per textproto.TrimString — which `parse::<usize>()` on the
    // raw row rejects, silently degrading a length-bounded body to
    // read-to-EOF (a backend that then holds the connection open parked
    // the stream). The client https2http twin h2.rs consumes the same
    // carried value.
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
        // `Ok(None)` = the backend body was truncated mid-stream and
        // [`abort_stream`] already reset it — no clean END_STREAM, which
        // would present the truncated body as complete (round-18 M3
        // mirror).
        match stream_chunked_body(&mut reader, &mut send, &mut scratch).await? {
            None => return Ok(()),
            Some(trailers) => {
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
            }
        }
        return Ok(());
    }
    if let Some(mut remaining) = content_length {
        while remaining > 0 {
            let n = remaining.min(8192) as usize;
            match reader.read_exact_into(&mut scratch, n).await {
                Ok(()) => {}
                Err(_) => {
                    // Truncated Content-Length-bounded body: the declared
                    // length was never delivered — reset the stream rather
                    // than end it cleanly (round-18 M3 mirror; the old
                    // `break` fell to the clean END_STREAM below and the
                    // h2 client read a complete response out of a
                    // truncated one — Go copyResponse aborts instead).
                    tracing::debug!(
                        "h2c backend truncated a Content-Length-bounded body, resetting the stream"
                    );
                    return abort_stream(&mut send).await.map(|_| ());
                }
            }
            remaining -= scratch.len() as u64;
            send.send_data(Bytes::copy_from_slice(&scratch), false)?;
        }
    } else {
        // No length framing: read to EOF (the work conn is closed by frpc
        // once the provider finishes). A genuine EOF is the natural end of
        // a close-delimited body; an io error mid-body aborts like every
        // other truncated backend body (round-18 M3 mirror).
        loop {
            if reader.available().is_empty() {
                match reader.read_more().await {
                    Ok(true) => {}
                    Ok(false) => break, // clean EOF: body complete
                    Err(_) => {
                        tracing::debug!("h2c backend body read error, resetting the stream");
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
    use super::*;

    #[test]
    fn test_is_hop_by_hop() {
        // RFC 7540 §8.1.2.2 / RFC 7230 §6.1 list, and Go httputil.hopHeaders
        // in full (round-18 review: the server twin had only the first five
        // while the client twin carried all nine) — all must be dropped when
        // re-encoding to HTTP/1.1.
        for name in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
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
        for name in ["content-length", "host", "authorization", "x-custom"] {
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
    fn test_parse_response_head_version_token_lenient_like_go() {
        // Round-18 M1 mirror of the client plugin pin: Go ParseHTTPVersion
        // is LENIENT (request.go:819-838) — exact rows HTTP/1.0/1.1, else
        // exactly-8-char `HTTP/X.Y` single ASCII digits. HTTP/9.9, HTTP/0.9,
        // HTTP/1.2 all PARSE (and the round-7-era exact-switch rejection of
        // HTTP/9.9 was a Go-source misreading — RED here). The round-7
        // "HTTP/1.10 is rejected" shape still holds (9th char), as do
        // case/prefix failures.
        for ok in [
            "HTTP/1.0", "HTTP/1.1", "HTTP/9.9", "HTTP/0.9", "HTTP/4.0", "HTTP/1.2", "HTTP/0.0",
        ] {
            let head = format!("{ok} 200 OK\r\n\r\n");
            assert_eq!(
                parse_response_head(head.as_bytes()).unwrap().status,
                200,
                "{ok} must parse (Go ParseHTTPVersion lenient shape)"
            );
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
                "{bad} must fail the whole head (Go ParseHTTPVersion)"
            );
        }
    }

    #[test]
    fn test_parse_response_head_textproto_record_semantics() {
        // Round-18 M4 mirror of the client plugin fix: Go textproto
        // ReadMIMEHeader record semantics (net/textproto/reader.go) now
        // drive the header block — obs-folds merge into the open record
        // instead of failing the head.
        //
        // Legal fold: "X-A: one" + SP-continuation " two" → "one two".
        // RED pre-fix: the old parse trimmed the fold's leading space,
        // read it as a colonless NEW record and returned None (404).
        let head = b"HTTP/1.1 200 OK\r\nX-A: one\r\n two\r\nX-B: y\r\n\r\n";
        let parsed = parse_response_head(head).expect("obs-fold head must parse");
        assert_eq!(parsed.status, 200);
        assert_eq!(
            header_value(&parsed.headers, "x-a")
                .unwrap()
                .to_str()
                .unwrap(),
            "one two",
            "folded continuation joins the value with a single space"
        );
        assert_eq!(
            header_value(&parsed.headers, "x-b")
                .unwrap()
                .to_str()
                .unwrap(),
            "y",
            "a non-fold record after a fold still parses"
        );
        // All-whitespace fold: Go joins ' ' + both-trimmed piece — an empty
        // piece still contributes the ' ' (round-17 R1 semantics), and
        // TrimLeft storage keeps the trailing space.
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
        // HTAB-leading fold folds too.
        let head = b"HTTP/1.1 200 OK\r\nX-A: one\r\n\ttwo\r\n\r\n";
        let parsed = parse_response_head(head).expect("HTAB fold head must parse");
        assert_eq!(
            header_value(&parsed.headers, "x-a")
                .unwrap()
                .to_str()
                .unwrap(),
            "one two"
        );
        // The record's own continuation lines and the trailing row keep the
        // value CTL-checked per physical line (fold with CTL → whole-head
        // fail).
        let head = b"HTTP/1.1 200 OK\r\nX-A: one\r\n t\x01wo\r\n\r\n";
        assert!(
            parse_response_head(head).is_none(),
            "CTL byte inside a folded line fails the whole head"
        );
    }

    #[test]
    fn test_parse_response_head_malformed_rows_fail_whole_head() {
        // Round-18 M4 mirror: ANY malformed record fails the WHOLE head
        // (Go ReadMIMEHeader read-time errors) — the old parse silently
        // dropped the bad row and forwarded the degraded head (RED on every
        // shape below: pre-fix each returned Some with the row missing).
        for bad in [
            &b"HTTP/1.1 200 OK\r\nX-No-Colon here\r\n\r\n"[..], // colonless record
            &b"HTTP/1.1 200 OK\r\n: empty-name\r\n\r\n"[..],    // empty name
            &b"HTTP/1.1 200 OK\r\nX@Y: bad name byte\r\n\r\n"[..], // non-token name
            &b"HTTP/1.1 200 OK\r\nX-Y: a\x01b\r\n\r\n"[..],     // CTL in value
            &b"HTTP/1.1 200 OK\r\nX-Y: a\x0bb\r\n\r\n"[..],     // vertical tab in value
            &b"HTTP/1.1 200 OK\r\nX-Y: a\x7fb\r\n\r\n"[..],     // DEL in value
        ] {
            assert!(
                parse_response_head(bad).is_none(),
                "malformed record must fail the whole head: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // Fold-first-line (SP/HTAB after the status line with no open
        // record) = Go's initial-line error → whole-head fail.
        let head = b"HTTP/1.1 200 OK\r\n X-Y: leading fold\r\n\r\n";
        assert!(
            parse_response_head(head).is_none(),
            "SP-leading block line fails the head"
        );
        // SPACE-in-name: Go tolerates it stored uncanonicalized (issue
        // 34540) but http::HeaderName cannot represent it — frp-rs fails
        // the head, a documented fail-closed divergence (forwarding a
        // wire-invalid name would only make the h2 peer reject it).
        let head = b"HTTP/1.1 200 OK\r\nX Y: v\r\n\r\n";
        assert!(
            parse_response_head(head).is_none(),
            "SPACE-in-name fails the head (fail-closed)"
        );
        // obs-text (0x80-0xFF) value bytes are legal (Go
        // validHeaderValueByte) and now survive as raw bytes — the old
        // from_str UTF-8 gate silently dropped such rows (RED pre-fix: the
        // head parsed with the row gone).
        let head = b"HTTP/1.1 200 OK\r\nX-Y: caf\xe9\r\n\r\n";
        let parsed = parse_response_head(head).expect("obs-text value must parse");
        assert_eq!(parsed.headers.len(), 1, "obs-text row is kept, not dropped");
        assert_eq!(parsed.headers[0].1.as_bytes(), b"caf\xe9");
    }

    #[test]
    fn test_parse_response_head_content_length_gates() {
        // Round-18 M2 mirror + deviation-3 fix (client plugin parity):
        // fixLength + parseContentLength semantics from net/http/transfer.go.
        //
        // Identical duplicate CL rows (case-variant names included) dedupe
        // to ONE row keeping the FIRST value (Go Issue 16490) — the h2
        // emission copy loop appends parsed rows verbatim, so two rows
        // here would both reach the client.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\nbody";
        let parsed = parse_response_head(head).expect("identical dup CL dedupes");
        assert_eq!(parsed.headers.len(), 1, "duplicate CL rows collapse to one");
        assert_eq!(parsed.headers[0].1.to_str().unwrap(), "5");
        // Differing values fail the whole head → the caller's 404 arm.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nbody";
        assert!(
            parse_response_head(head).is_none(),
            "conflicting duplicate Content-Length fails the whole head"
        );
        // TrimString compare: padded values ("5 " ≡ "5") dedupe cleanly.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5 \r\nContent-Length: 5\r\n\r\nbody";
        let parsed = parse_response_head(head).expect("padded dup CL stays legal (TrimString)");
        assert_eq!(parsed.headers.len(), 1);
        // parseContentLength gate (deviation-3): non-numeric, empty, and
        // overflowing values fail the whole head like Go ParseUint
        // (bitSize 63; sign prefixes are NOT legal — the digit gate
        // rejects "+5" the way Go's ParseUint does).
        for bad in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775808\r\n\r\n"[..], // 2^63
        ] {
            assert!(
                parse_response_head(bad).is_none(),
                "garbage Content-Length must fail the whole head: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // A padded single row stays legal and parses to the numeric value.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5 \r\n\r\nbody";
        let parsed = parse_response_head(head).expect("padded CL stays legal");
        assert_eq!(parsed.headers[0].1.to_str().unwrap(), "5");
        // Duplicate NON-CL rows keep both (only fixLength dedupes).
        let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
        let parsed = parse_response_head(head).expect("dup non-CL rows keep both");
        assert_eq!(parsed.headers.len(), 2);
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
            &[
                ("x-custom", "v1"),
                ("x-second", "two"),
                // Round-18 review pin (Go httputil.hopHeaders): a client's
                // hop-by-hop fields must never reach the provider backend —
                // pre-fix the server list had only 5 entries, so
                // proxy-authorization (Go's ReverseProxy strips it from
                // `outreq.Header` before the RoundTrip), proxy-authenticate,
                // te and trailer were all forwarded (RED pre-fix). The h2
                // client accepts `te` only with the exactly-"trailers" value
                // (h2 0.4 streams/send.rs check_headers), so all four are
                // sendable.
                ("proxy-authorization", "Basic dXNlcjpwYXNz"),
                ("proxy-authenticate", "Basic realm=\"Restricted\""),
                ("te", "trailers"),
                ("trailer", "X-Checksum"),
            ],
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
                for line in [
                    "\r\nproxy-authorization: Basic dXNlcjpwYXNz",
                    "\r\nproxy-authenticate: Basic realm=\"Restricted\"",
                    "\r\nte: trailers",
                    "\r\ntrailer: X-Checksum",
                ] {
                    assert!(
                        !head_text.contains(line),
                        "hop-by-hop line {line:?} must not reach the backend: {head_text}"
                    );
                }
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
        // hang, loop, or panic (round-15 review flagged missing coverage).
        // This pin drives the BodyReader directly; the WALKER-level
        // consequence of this error is the round-18 M3 abort (the walker
        // used to swallow it as a clean end — Go copyResponse aborts mid-
        // body: httputil/reverseproxy.go ErrAbortHandler, h2_bundle.go
        // handlerPanicRST), pinned e2e by
        // `test_h2_backend_truncated_chunked_body_resets_stream` below.
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

    /// Slice-then-EOF backend: serves `data` then a clean 0 — the staged
    /// "backend died after N bytes" shape the round-18 M3 truncation pins
    /// need (HeadThenPanicMock panics on any post-head poll and EofMock
    /// carries no bytes at all).
    struct SliceMock {
        data: &'static [u8],
    }

    impl SliceMock {
        fn new(data: &'static [u8]) -> Self {
            Self { data }
        }
    }

    impl tokio::io::AsyncRead for SliceMock {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.data.is_empty() {
                return std::task::Poll::Ready(Ok(())); // clean EOF
            }
            let n = self.data.len().min(buf.remaining());
            buf.put_slice(&self.data[..n]);
            self.data = &self.data[n..];
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
        let (status, headers, body, err) = h2c_test_roundtrip_body_err(method, serve).await;
        assert!(
            err.is_none(),
            "clean-backend rounds must end with END_STREAM, got a stream error: {err:?}"
        );
        (status, headers, body)
    }

    /// Round like [`h2c_test_roundtrip`] but also returns the body-stream
    /// error: None = the stream ended cleanly (END_STREAM); Some = the
    /// stream was reset — the round-18 M3 mirror pins must SEE the reset,
    /// where the 3-tuple roundtrip drain (`while let Some(Ok(chunk))`)
    /// treats an aborted stream identically to a clean end.
    async fn h2c_test_roundtrip_body_err<F, Fut>(
        method: &str,
        serve: F,
    ) -> (u16, http::HeaderMap, Vec<u8>, Option<h2::Error>)
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
        // Error-distinguishing drain: Some(Err) = the server reset the
        // stream (the M3 pins); None = clean END_STREAM.
        let mut stream_err: Option<h2::Error> = None;
        loop {
            match recv.data().await {
                Some(Ok(chunk)) => body.extend_from_slice(&chunk),
                Some(Err(e)) => {
                    stream_err = Some(e);
                    break;
                }
                None => break,
            }
        }
        server_task
            .await
            .expect("server task panicked")
            .expect("serve returned an error");
        (status, headers, body, stream_err)
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
            "304 must not carry Content-Length (Go h1 suppressedHeaders304; the h2 strip is a documented fail-closed divergence — Go's h2 writer passes a declared CL through)"
        );
        assert!(body.is_empty());

        // Round-15: the 204 strip applies to a HEAD request too — RFC 9110
        // §8.6 forbids Content-Length on ANY 204, method notwithstanding
        // (pre-fix: `if !is_head` kept the header on a HEAD + 204 answer).
        // A HEAD 200 keeps its truthful CL (first pin above); a HEAD 204
        // must not.
        let (status, headers, body) = h2c_test_roundtrip("HEAD", |respond| async move {
            let mut respond = respond;
            let mut backend =
                HeadThenPanicMock::new(b"HTTP/1.1 204 No Content\r\nContent-Length: 50\r\n\r\n");
            let page = h2c_not_found_body("");
            stream_h2_response(&mut backend, &mut respond, None, true, &page).await
        })
        .await;
        assert_eq!(status, 204);
        assert!(
            !headers.contains_key("content-length"),
            "204 must not carry Content-Length even for HEAD (RFC 9110 §8.6)"
        );
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_h2_backend_failures_answer_404_with_page() {
        // FIX 2 pins: the non-timeout backend-failure arms answer Go's
        // ErrorHandler 404 — status 404, Content-Type text/html (send_h2_error's
        // default for the page body). The page body follows
        // `h2c_not_found_body`: the CONFIGURED custom_404_page when
        // non-empty (round-15 gap — every prior call passed ""), else the
        // builtin page the HTTP/1.1 surface serves byte-identical
        // (GO_404_NOT_FOUND_BODY). First arm pins the custom branch (:846),
        // second arm the builtin branch.
        let custom_page = "<html><body>custom 404</body></html>";
        let (status, headers, body) = h2c_test_roundtrip("GET", move |respond| {
            let page = h2c_not_found_body(custom_page);
            async move {
                let mut respond = respond;
                stream_h2_response(&mut EofMock, &mut respond, None, false, &page).await
            }
        })
        .await;
        assert_eq!(status, 404, "backend close before the head → Go 404 class");
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/html")
        );
        assert_eq!(
            body,
            custom_page.as_bytes(),
            "a configured custom_404_page must replace the builtin 404 body \
             (h2c_not_found_body custom branch)"
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

    // --- Round-18 wave mirrors (the client plugin h2.rs M2/M3/M4 +
    // deviation-3 fixes, applied to this server h2c twin): obs-fold heads
    // merge and serve, dup/garbage Content-Length heads behave like Go's
    // transport, and truncated bodies reset the stream instead of ending
    // clean.

    #[tokio::test]
    async fn test_h2_backend_obs_fold_head_merges_and_forwards() {
        // M4 mirror e2e: a legal obs-fold backend head now SERVES (200,
        // merged value) — RED pre-fix: the fold lost its leading space,
        // read as a colonless record, and the whole head failed → 404.
        let (status, headers, body, err) =
            h2c_test_roundtrip_body_err("GET", |respond| async move {
                let mut respond = respond;
                let mut backend = SliceMock::new(
                    b"HTTP/1.1 200 OK\r\nX-A: one\r\n two\r\nContent-Length: 2\r\n\r\nok",
                );
                let page = h2c_not_found_body("");
                stream_h2_response(&mut backend, &mut respond, None, false, &page).await
            })
            .await;
        assert_eq!(status, 200, "obs-fold head must serve, not 404");
        assert!(err.is_none());
        assert_eq!(
            headers.get("x-a").and_then(|v| v.to_str().ok()),
            Some("one two"),
            "the merged fold value reaches the h2 client"
        );
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn test_h2_backend_duplicate_rows_all_reach_the_client() {
        // M2 mirror e2e (pin): duplicate Set-Cookie rows both survive the
        // head→h2 copy (the append loop was already correct — this pins it
        // against a regression to `insert`).
        let (status, headers, body, err) = h2c_test_roundtrip_body_err("GET", |respond| async move {
            let mut respond = respond;
            let mut backend = SliceMock::new(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok",
            );
            let page = h2c_not_found_body("");
            stream_h2_response(&mut backend, &mut respond, None, false, &page).await
        })
        .await;
        assert_eq!(status, 200);
        assert!(err.is_none());
        let cookies: Vec<&str> = headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(
            cookies,
            ["a=1", "b=2"],
            "duplicate rows must ALL reach the client"
        );
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn test_h2_backend_duplicate_content_length_go_fixlength_parity() {
        // Identical dup CL rows → 200 with ONE content-length row on the
        // h2 wire (RED pre-fix: the parse kept both rows and the copy loop
        // forwarded both — fixLength dedupes, Go Issue 16490).
        let (status, headers, body, err) =
            h2c_test_roundtrip_body_err("GET", |respond| async move {
                let mut respond = respond;
                let mut backend = SliceMock::new(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
                );
                let page = h2c_not_found_body("");
                stream_h2_response(&mut backend, &mut respond, None, false, &page).await
            })
            .await;
        assert_eq!(status, 200);
        assert!(err.is_none());
        assert_eq!(body, b"ok");
        assert_eq!(
            headers.get_all("content-length").iter().count(),
            1,
            "identical duplicate CL rows collapse to one on the wire"
        );
        // Differing dup CL values fail the whole head → the Go 404 class
        // (RED pre-fix: 200 forwarded, its body framing matching neither
        // row).
        let (status, _headers, _body, _err) =
            h2c_test_roundtrip_body_err("GET", |respond| async move {
                let mut respond = respond;
                let mut backend = SliceMock::new(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
                );
                let page = h2c_not_found_body("");
                stream_h2_response(&mut backend, &mut respond, None, false, &page).await
            })
            .await;
        assert_eq!(
            status, 404,
            "conflicting duplicate Content-Length fails the whole head → Go 404 class"
        );
    }

    #[tokio::test]
    async fn test_h2_backend_garbage_content_length_go_404_class() {
        // Deviation-3 e2e: a garbage or empty Content-Length row fails the
        // whole head → the Go 404 class (RED pre-fix: 200 forwarded with
        // the garbage row and the body read to EOF).
        for staged in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nhi"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\nhi"[..],
        ] {
            let (status, _headers, _body, _err) =
                h2c_test_roundtrip_body_err("GET", move |respond| {
                    let mut backend = SliceMock::new(staged);
                    async move {
                        let mut respond = respond;
                        let page = h2c_not_found_body("");
                        stream_h2_response(&mut backend, &mut respond, None, false, &page).await
                    }
                })
                .await;
            assert_eq!(
                status,
                404,
                "garbage Content-Length row fails the whole head: {:?}",
                String::from_utf8_lossy(staged)
            );
        }
        // A padded numeric value stays legal (TrimString, Go fixLength) and
        // its body leg must deliver EXACTLY the declared bytes — the round-18
        // review fix: drive the store shape the padded value actually comes
        // from. An all-whitespace obs-fold appends a bare ' ' to the value
        // (the record walk above), so the backend head
        // "Content-Length: 5\r\n \r\n" stores "5 " — the parse gate accepts
        // it (TrimString → "5") and the VALIDATED count must ride out on
        // `ParsedHead`; re-parsing the stored row in the body leg saw "5 ",
        // failed, and read the body to EOF. The trailing "EXTRA" bytes make
        // that degradation visible: read-to-EOF delivers them, the
        // length-bounded read does not (RED pre-fix: body is
        // "helloEXTRA").
        let (status, _headers, body, err) =
            h2c_test_roundtrip_body_err("GET", |respond| async move {
                let mut respond = respond;
                let mut backend =
                    SliceMock::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n \r\n\r\nhelloEXTRA");
                let page = h2c_not_found_body("");
                stream_h2_response(&mut backend, &mut respond, None, false, &page).await
            })
            .await;
        assert_eq!(status, 200, "fold-padded Content-Length stays legal");
        assert!(err.is_none());
        assert_eq!(
            body, b"hello",
            "the declared 5 bytes are the whole body — a re-parsed \"5 \" row would \
             fall back to read-to-EOF and leak the bytes past the declaration"
        );
    }

    #[tokio::test]
    async fn test_h2_backend_truncated_cl_body_resets_stream() {
        // M3 mirror e2e: declared 10 body bytes, backend delivers 2 then
        // EOFs. Go copyResponse aborts mid-body → RST_STREAM
        // INTERNAL_ERROR; the old CL arm `Err(_) => break` fell to the
        // clean END_STREAM and the client read the truncated body as a
        // complete 200 (RED pre-fix: err is None).
        let (status, _headers, _body, err) =
            h2c_test_roundtrip_body_err("GET", |respond| async move {
                let mut respond = respond;
                let mut backend =
                    SliceMock::new(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi");
                let page = h2c_not_found_body("");
                stream_h2_response(&mut backend, &mut respond, None, false, &page).await
            })
            .await;
        assert_eq!(status, 200, "the head itself is valid and served");
        assert!(
            err.is_some(),
            "a Content-Length-bounded body cut short must reset the stream, not end clean"
        );
    }

    #[tokio::test]
    async fn test_h2_backend_truncated_chunked_body_resets_stream() {
        // M3 mirror e2e — the chunked leg: declared 5 bytes, delivers 2,
        // then EOF. The old walker returned an empty trailer map on the
        // mid-chunk EOF and the caller ended the stream cleanly (RED
        // pre-fix: err is None — the walker arms and the CRLF-mismatch
        // CANCEL path all used to swallow or reset-with-wrong-code).
        let (status, _headers, _body, err) =
            h2c_test_roundtrip_body_err("GET", |respond| async move {
                let mut respond = respond;
                let mut backend =
                    SliceMock::new(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe");
                let page = h2c_not_found_body("");
                stream_h2_response(&mut backend, &mut respond, None, false, &page).await
            })
            .await;
        assert_eq!(status, 200, "the head itself is valid and served");
        assert!(
            err.is_some(),
            "a chunked body cut mid-chunk must reset the stream, not end clean"
        );
    }
}
