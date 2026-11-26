//! HTTP/2 CONNECT plugin (frp-rs extension).
//!
//! Exposes an HTTP/2 forward proxy on the frpc side. The frp tunnel carries the
//! raw TCP stream; this plugin terminates h2c (prior knowledge) or TLS+ALPN h2
//! and supports:
//!
//! - RFC 9113 `CONNECT` — an h2 stream bridged to a target TCP connection.
//! - RFC 9298 extended `CONNECT` with `:protocol = connect-udp` — an h2 stream
//!   carrying RFC 9297 capsules. Each `DATAGRAM` (type `0x00`) value is
//!   `Context ID (varint) + UDP payload`; context 0 carries the UDP datagram.
//!   The target is encoded in the request path as `.../{host}/{port}/` (the
//!   RFC 9298 URI-template form).
//!
//! Optional `http_user` / `http_password` enforce HTTP Basic proxy auth
//! (`Proxy-Authorization`). The h2 listener is plaintext unless both
//! `crt_file` and `key_file` are set, in which case TLS with ALPN `h2` is used.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use h2::server::{Builder, SendResponse};
use h2::{RecvStream, SendStream};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::http::{AuthVerdict, HttpProxyAuth};
use super::{serve_plugin, split_host_port, urlencoding_decode, PluginHandle};

/// Per-stream HTTP/2 receive window (2 MiB). RFC 9113's 64 KiB default caps a
/// 50 ms RTT link at ~1.3 MB/s; 2 MiB keeps high-BDP streams moving while the
/// connection window bounds total buffered bytes across concurrent streams.
const H2_STREAM_WINDOW_SIZE: u32 = 2 * 1024 * 1024;
/// Connection-wide HTTP/2 receive window (8 MiB) shared across all streams.
const H2_CONN_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
/// Max HTTP/2 DATA frame payload (64 KiB), aligned with frp-rs bridge/yamux
/// chunks (4× fewer frames than RFC 9113's 16 KiB minimum).
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;
/// Target TCP read chunk size for CONNECT streams (matches `H2_MAX_FRAME_SIZE`).
const TCP_READ_CHUNK: usize = 64 * 1024;
/// Minimum spare capacity retained in a `BytesMut` slab before reserving a
/// fresh chunk (avoids tiny fragmented reads when `h2` still holds a slice).
const MIN_READ_RESERVE: usize = 16 * 1024;
/// Cap on one capsule's declared length. CONNECT-UDP datagrams are bounded by
/// the path MTU in practice; this is a memory guard, not a protocol limit.
const MAX_CAPSULE: usize = 64 * 1024;
/// Overall bound for a partially received capsule buffer.
const MAX_CAPSULE_BUFFER: usize = MAX_CAPSULE + 16;
const CAPSULE_DATAGRAM: u64 = 0x00;
/// Bound on a single target UDP reply read.
const MAX_UDP_DATAGRAM: usize = 64 * 1024;
/// Reusable `BytesMut` slab size for encoded outbound CONNECT-UDP capsules.
const UDP_CAPSULE_SLAB: usize = 16 * 1024;
/// Opportunistic non-blocking drain caps when coalescing already-queued UDP
/// replies into a single H2 DATA frame (RFC 9297 §3). Zero wait is added for
/// isolated packets; only datagrams already ready in the kernel buffer batch.
const UDP_BATCH_MAX_BYTES: usize = 16 * 1024;
const UDP_BATCH_MAX_PKTS: usize = 32;
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// After the client half-closes the CONNECT request stream, how long the
/// target may keep the response half open while silent. Without this a silent
/// target pins an fd/task after the client is done.
const TARGET_TAIL_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute cap on a half-closed tail, so a peer that trickles one byte every
/// 29 s cannot keep the association (and its fd) forever.
const TARGET_TAIL_MAX_LIFETIME: Duration = Duration::from_secs(3600);
/// Bound on a single target write. A blocked `write_all` cannot poll the h2
/// read side, so without this a target that never reads pins the fd for the
/// connection lifetime; 30 s of no progress is the documented bound.
const TARGET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Start the `http2connect` plugin.
pub async fn start_http2connect(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let auth = HttpProxyAuth::from_config(cfg);
    let tls = match (cfg.crt_file.is_empty(), cfg.key_file.is_empty()) {
        (true, true) => None,
        (false, false) => Some(frp_core::transport::build_tls_acceptor_with_alpn(
            &cfg.crt_file,
            &cfg.key_file,
            None,
            &[b"h2"],
        )?),
        _ => {
            return Err(frp_core::Error::Config(
                "http2connect plugin: crt_file and key_file must both be set or both be empty"
                    .into(),
            ))
        }
    };
    serve_plugin(
        "http2connect",
        (auth, tls),
        |stream, peer, (auth, tls)| async move {
            match tls {
                Some(acceptor) => match super::accept_tls_bounded(&acceptor, stream).await {
                    Ok(tls) => serve_h2(tls, auth).await,
                    Err(e) => debug!(%peer, error = %e, "http2connect: TLS handshake failed: {e}"),
                },
                None => serve_h2(stream, auth).await,
            }
        },
    )
    .await
}

async fn serve_h2<S>(stream: S, auth: HttpProxyAuth)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = Builder::new();
    builder
        .max_concurrent_streams(100)
        // This listener is reachable through a public frp remote port, so it
        // gets a small bound (16 KiB; vhost_h2c uses 4 KiB), not the local
        // https2http 16 MiB allowance. CONNECT needs only the pseudo-headers
        // plus proxy-authorization.
        .max_header_list_size(16 * 1024)
        .initial_window_size(H2_STREAM_WINDOW_SIZE)
        .initial_connection_window_size(H2_CONN_WINDOW_SIZE)
        .max_frame_size(H2_MAX_FRAME_SIZE);
    // RFC 8441: advertise SETTINGS_ENABLE_CONNECT_PROTOCOL so clients may use
    // extended CONNECT (`:protocol`). Without this the client's
    // `:protocol = connect-udp` request is rejected by the h2 layer.
    builder.enable_connect_protocol();
    let mut connection = match tokio::time::timeout(
        super::PLUGIN_HANDSHAKE_TIMEOUT,
        builder.handshake(stream),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            debug!(error = %e, "http2connect: h2 handshake failed: {e}");
            return;
        }
        Err(_) => {
            debug!(
                timeout = ?super::PLUGIN_HANDSHAKE_TIMEOUT,
                "http2connect: h2 preface timed out"
            );
            return;
        }
    };

    let mut streams: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept() => match accepted {
                Some(Ok((request, respond))) => {
                    let auth = auth.clone();
                    streams.spawn(async move {
                        if let Err(e) = handle_request(request, respond, auth).await {
                            debug!(error = %e, "http2connect: stream error: {e}");
                        }
                    });
                    while streams.try_join_next().is_some() {}
                }
                Some(Err(e)) => {
                    debug!(error = %e, "http2connect: connection error: {e}");
                    break;
                }
                None => break,
            },
            // Reap finished stream tasks promptly even while the H2 connection
            // sits idle between bursts.
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

async fn handle_request(
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
    auth: HttpProxyAuth,
) -> Result<(), String> {
    if request.method() != Method::CONNECT {
        return send_status(respond, StatusCode::METHOD_NOT_ALLOWED).await;
    }
    let header = request
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Same Go-parity auth shape as the http_proxy plugin: a decoded pair that
    // fails the constant-time compare costs the attacker 200 ms; shape
    // failures reject immediately.
    match auth.classify_proxy_auth(header) {
        AuthVerdict::Accept => {}
        AuthVerdict::RejectInstant => {
            return send_auth_required(respond).await;
        }
        AuthVerdict::RejectDelayed => {
            tokio::time::sleep(Duration::from_millis(200)).await;
            return send_auth_required(respond).await;
        }
    }

    enum ConnectKind {
        Tcp(String),
        Udp(String, u16),
        BadRequest,
        Unsupported(String),
    }

    let kind = match request
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(h2::ext::Protocol::as_str)
    {
        None => match request.uri().authority() {
            Some(authority) => ConnectKind::Tcp(authority.as_str().to_string()),
            None => ConnectKind::BadRequest,
        },
        Some("connect-udp") => {
            // RFC 9297 §3.4 makes `Capsule-Protocol: ?1` a SHOULD on the
            // request; the response already advertises it and `:protocol =
            // connect-udp` makes the capsule dialect unambiguous, so a client
            // that omits the request header is accepted.
            match udp_target_from_path(request.uri().path()) {
                Some((host, port)) => ConnectKind::Udp(host, port),
                None => ConnectKind::BadRequest,
            }
        }
        Some(other) => ConnectKind::Unsupported(other.to_string()),
    };

    match kind {
        ConnectKind::Tcp(authority) => tcp_connect(request.into_body(), respond, &authority).await,
        ConnectKind::Udp(host, port) => {
            udp_connect(request.into_body(), respond, &host, port).await
        }
        ConnectKind::BadRequest => send_status(respond, StatusCode::BAD_REQUEST).await,
        ConnectKind::Unsupported(other) => {
            debug!(protocol = %other, "http2connect: unsupported :protocol");
            send_status(respond, StatusCode::NOT_IMPLEMENTED).await
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientState {
    Open,
    HalfClosed,
    Gone,
}

/// Write `data` to `tcp_w` without touching the Tokio timer wheel on the
/// non-blocking fast path; only arm/reset the reusable `write_sleep` timer if
/// the kernel send buffer actually returns `WouldBlock`.
async fn write_all_with_timeout(
    tcp_w: &mut OwnedWriteHalf,
    data: &[u8],
    write_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<(), ()> {
    let mut offset = 0;
    while offset < data.len() {
        match tcp_w.try_write(&data[offset..]) {
            Ok(0) => return Err(()),
            Ok(n) => {
                offset += n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Slow path: arm (or lazily allocate) the reusable timer once
                // for the remainder of this chunk.
                let deadline = tokio::time::Instant::now() + TARGET_WRITE_TIMEOUT;
                let sleep = match write_sleep {
                    Some(s) => {
                        s.as_mut().reset(deadline);
                        s
                    }
                    None => write_sleep.insert(Box::pin(tokio::time::sleep_until(deadline))),
                };
                while offset < data.len() {
                    tokio::select! {
                        biased;
                        res = tcp_w.write(&data[offset..]) => match res {
                            Ok(0) => return Err(()),
                            Ok(n) => offset += n,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(_) => return Err(()),
                        },
                        _ = sleep.as_mut() => return Err(()),
                    }
                }
                return Ok(());
            }
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Reusable lazy half-close tail timers. On normal (open) streams neither timer
/// is ever allocated or registered with the Tokio timer wheel.
struct TailTimers {
    idle: Option<Pin<Box<tokio::time::Sleep>>>,
    max: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl TailTimers {
    fn new() -> Self {
        Self {
            idle: None,
            max: None,
        }
    }

    fn arm_or_reset_idle(&mut self) {
        let now = tokio::time::Instant::now();
        let idle_at = now + TARGET_TAIL_TIMEOUT;
        match &mut self.idle {
            Some(s) => s.as_mut().reset(idle_at),
            None => self.idle = Some(Box::pin(tokio::time::sleep_until(idle_at))),
        }
        if self.max.is_none() {
            self.max = Some(Box::pin(tokio::time::sleep_until(
                now + TARGET_TAIL_MAX_LIFETIME,
            )));
        }
    }

    fn is_armed(&self) -> bool {
        self.idle.is_some()
    }

    async fn wait_expired(&mut self) {
        let (Some(idle), Some(max)) = (&mut self.idle, &mut self.max) else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::select! {
            _ = idle.as_mut() => {}
            _ = max.as_mut() => {}
        }
    }
}

async fn tcp_connect(
    mut recv: RecvStream,
    mut respond: SendResponse<Bytes>,
    authority: &str,
) -> Result<(), String> {
    let (host, port) = split_host_port(authority);
    // CONNECT's authority must carry an explicit port; split_host_port's
    // default of 80 would silently connect to the wrong service.
    if host.is_empty() || !authority_has_port(authority) {
        return send_status(respond, StatusCode::BAD_REQUEST).await;
    }
    let remote = match tokio::time::timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(remote)) => remote,
        Ok(Err(e)) => {
            debug!(target = %authority, error = %e, "http2connect: TCP connect failed");
            return send_status(respond, StatusCode::BAD_GATEWAY).await;
        }
        Err(_) => {
            debug!(target = %authority, "http2connect: TCP connect timed out");
            return send_status(respond, StatusCode::GATEWAY_TIMEOUT).await;
        }
    };
    frp_core::transport::set_nodelay(&remote);

    let mut send = respond
        .send_response(Response::new(()), false)
        .map_err(|e| e.to_string())?;
    let (mut tcp_r, mut tcp_w) = remote.into_split();

    // Both directions run concurrently inside THIS task via `join!`: a
    // spawned `up` would be detached when `serve_h2` aborts the stream task
    // (the plugin/h2.rs rule), and a single `select!` would block the target
    // ->client direction behind a congested `tcp_w.write_all`. Parent abort
    // drops both futures, closing the target halves.
    let (client_tx, mut client_rx) = watch::channel(ClientState::Open);
    let (target_tx, mut target_rx) = watch::channel(false);

    let up = async {
        let mut write_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            tokio::select! {
                chunk = recv.data() => match chunk {
                    Some(Ok(chunk)) => {
                        if write_all_with_timeout(&mut tcp_w, &chunk, &mut write_sleep)
                            .await
                            .is_err()
                        {
                            let _ = client_tx.send(ClientState::Gone);
                            break;
                        }
                        // Release H2 receive window only after the target socket
                        // accepted the bytes so slow targets apply end-to-end
                        // flow-control backpressure to the H2 peer.
                        if recv.flow_control().release_capacity(chunk.len()).is_err() {
                            let _ = client_tx.send(ClientState::Gone);
                            break;
                        }
                    }
                    Some(Err(_)) => {
                        // RST_STREAM: the client cannot receive a tail.
                        let _ = client_tx.send(ClientState::Gone);
                        break;
                    }
                    None => {
                        // Clean half-close: tell the target no more bytes are
                        // coming (so it can produce a response/EOF), then keep
                        // the target->client direction open.
                        let _ = tcp_w.shutdown().await;
                        let _ = client_tx.send(ClientState::HalfClosed);
                        break;
                    }
                },
                changed = target_rx.changed() => {
                    if changed.is_err() || *target_rx.borrow() {
                        break;
                    }
                }
            }
        }
    };

    let down = async {
        let mut buf = BytesMut::with_capacity(TCP_READ_CHUNK);
        let mut timers = TailTimers::new();
        let mut clean_close = true;
        'down: loop {
            if buf.capacity() < MIN_READ_RESERVE {
                buf.reserve(TCP_READ_CHUNK);
            }
            tokio::select! {
                read = tcp_r.read_buf(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let mut data = buf.split().freeze();
                        while !data.is_empty() {
                            tokio::select! {
                                biased;
                                res = send_h2(&mut send, &mut data) => {
                                    if res.is_err() {
                                        clean_close = false;
                                        break 'down;
                                    }
                                }
                                changed = client_rx.changed() => {
                                    if changed.is_err() || matches!(*client_rx.borrow(), ClientState::Gone) {
                                        clean_close = false;
                                        break 'down;
                                    }
                                    if matches!(*client_rx.borrow(), ClientState::HalfClosed) {
                                        timers.arm_or_reset_idle();
                                    }
                                }
                                _ = timers.wait_expired(), if timers.is_armed() => {
                                    clean_close = false;
                                    break 'down;
                                }
                            }
                        }
                        // Idle, not absolute: a slow response keeps resetting
                        // the tail window and is never silently truncated.
                        if timers.is_armed() {
                            timers.arm_or_reset_idle();
                        }
                    }
                },
                changed = client_rx.changed() => {
                    if changed.is_err() {
                        clean_close = false;
                        break;
                    }
                    match *client_rx.borrow() {
                        ClientState::Gone => {
                            clean_close = false;
                            break;
                        }
                        ClientState::HalfClosed => {
                            timers.arm_or_reset_idle();
                        }
                        ClientState::Open => {}
                    }
                }
                _ = timers.wait_expired(), if timers.is_armed() => break,
            }
        }
        let _ = target_tx.send(true);
        if clean_close {
            let _ = send.send_data(Bytes::new(), true);
        }
    };

    tokio::join!(up, down);
    Ok(())
}

async fn udp_connect(
    mut recv: RecvStream,
    mut respond: SendResponse<Bytes>,
    host: &str,
    port: u16,
) -> Result<(), String> {
    // Try every resolved address until one both binds and connects; taking the
    // resolver's first (often AAAA-first) address would 502 a dual-stack name
    // on an IPv4-only host.
    let candidates: Vec<SocketAddr> = match tokio::time::timeout(
        TARGET_CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.collect(),
        Ok(Err(e)) => {
            debug!(host = %host, port = %port, error = %e, "http2connect: UDP target resolve failed");
            return send_status(respond, StatusCode::BAD_GATEWAY).await;
        }
        Err(_) => return send_status(respond, StatusCode::GATEWAY_TIMEOUT).await,
    };
    let mut connected = None;
    for target in candidates {
        let bind = if target.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        // `connect()` restricts the socket to the target's datagrams; the
        // ephemeral port is not a listener for arbitrary peers.
        if socket.connect(target).await.is_ok() {
            connected = Some((Arc::new(socket), target));
            break;
        }
    }
    let Some((socket, target)) = connected else {
        debug!(host = %host, port = %port, "http2connect: no usable UDP target address");
        return send_status(respond, StatusCode::BAD_GATEWAY).await;
    };

    // RFC 9298 §3: the successful response must advertise the capsule protocol.
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", HeaderValue::from_static("?1"))
        .body(())
        .map_err(|e| e.to_string())?;
    let mut send = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(e) => return Err(e.to_string()),
    };

    // Both directions run concurrently inside THIS task via `join!` so H2
    // downlink flow-control stalls cannot head-of-line block uplink datagrams.
    // Parent abort drops both futures, closing the target socket.
    let (client_tx, mut client_rx) = watch::channel(ClientState::Open);
    let (target_tx, mut target_rx) = watch::channel(false);
    let socket_up = Arc::clone(&socket);
    let socket_down = socket;

    let up = async {
        let mut pending: Vec<u8> = Vec::new();
        loop {
            tokio::select! {
                chunk = recv.data() => match chunk {
                    Some(Ok(chunk)) => {
                        let chunk_len = chunk.len();
                        let send_ok = if pending.is_empty() {
                            // Fast path: parse complete capsules directly out
                            // of the H2 `Bytes` buffer with zero copies.
                            let mut cpos = 0usize;
                            let ok = dispatch_udp_capsules(&chunk, &mut cpos, &socket_up).await;
                            if ok && cpos < chunk.len() {
                                pending.extend_from_slice(&chunk[cpos..]);
                            }
                            ok
                        } else {
                            pending.extend_from_slice(&chunk);
                            let mut ppos = 0usize;
                            let ok = dispatch_udp_capsules(&pending, &mut ppos, &socket_up).await;
                            if ppos == pending.len() {
                                pending.clear();
                            } else if ppos > 0 {
                                pending.drain(..ppos);
                            }
                            ok
                        };
                        if !send_ok {
                            let _ = client_tx.send(ClientState::Gone);
                            break;
                        }
                        if recv.flow_control().release_capacity(chunk_len).is_err() {
                            let _ = client_tx.send(ClientState::Gone);
                            break;
                        }
                    }
                    Some(Err(_)) => {
                        let _ = client_tx.send(ClientState::Gone);
                        break;
                    }
                    None => {
                        // Clean half-close: the client sends no more datagrams,
                        // but may still read replies. Give the target an idle
                        // window, reset by every reply.
                        let _ = client_tx.send(ClientState::HalfClosed);
                        break;
                    }
                },
                changed = target_rx.changed() => {
                    if changed.is_err() || *target_rx.borrow() {
                        break;
                    }
                }
            }
        }
    };

    let down = async {
        // Uninitialized spare capacity — no upfront 64 KiB zero-fill on stream
        // creation; `recv_buf` writes straight into the spare slice.
        let mut recv_buf = BytesMut::with_capacity(MAX_UDP_DATAGRAM);
        let mut out = BytesMut::with_capacity(UDP_CAPSULE_SLAB);
        let mut timers = TailTimers::new();
        let mut clean_close = true;
        'down: loop {
            recv_buf.clear();
            tokio::select! {
                result = socket_down.recv_buf(&mut recv_buf) => match result {
                    Ok(n) => {
                        push_udp_capsule(&mut out, &recv_buf[..n]);
                        // Opportunistically coalesce any datagrams already
                        // queued in the kernel socket buffer into the same H2
                        // DATA frame (RFC 9297 §3). Adds zero latency for
                        // isolated packets because `try_recv_buf` returns
                        // `WouldBlock` immediately when no second packet is ready.
                        let mut batched = 1usize;
                        while batched < UDP_BATCH_MAX_PKTS && out.len() < UDP_BATCH_MAX_BYTES {
                            recv_buf.clear();
                            match socket_down.try_recv_buf(&mut recv_buf) {
                                Ok(m) => {
                                    push_udp_capsule(&mut out, &recv_buf[..m]);
                                    batched += 1;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::ConnectionRefused
                                            | std::io::ErrorKind::ConnectionReset
                                            | std::io::ErrorKind::HostUnreachable
                                            | std::io::ErrorKind::NetworkUnreachable
                                    ) =>
                                {
                                    debug!(target = %target, error = %e, "http2connect: UDP recv transient error");
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        let mut frame = out.split().freeze();
                        while !frame.is_empty() {
                            tokio::select! {
                                biased;
                                res = send_h2(&mut send, &mut frame) => {
                                    if res.is_err() {
                                        clean_close = false;
                                        break 'down;
                                    }
                                }
                                changed = client_rx.changed() => {
                                    if changed.is_err() || matches!(*client_rx.borrow(), ClientState::Gone) {
                                        clean_close = false;
                                        break 'down;
                                    }
                                    if matches!(*client_rx.borrow(), ClientState::HalfClosed) {
                                        timers.arm_or_reset_idle();
                                    }
                                }
                                _ = timers.wait_expired(), if timers.is_armed() => {
                                    clean_close = false;
                                    break 'down;
                                }
                            }
                        }
                        if timers.is_armed() {
                            timers.arm_or_reset_idle();
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::HostUnreachable
                                | std::io::ErrorKind::NetworkUnreachable
                        ) =>
                    {
                        // A connected UDP socket surfaces ICMP errors as these
                        // kinds on Linux; one unreachable target must not kill an
                        // otherwise live association. Pause so a persistently
                        // erroring socket cannot hot-spin the loop.
                        debug!(target = %target, error = %e, "http2connect: UDP recv transient error");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        debug!(target = %target, error = %e, "http2connect: UDP recv failed");
                        break;
                    }
                },
                changed = client_rx.changed() => {
                    if changed.is_err() {
                        clean_close = false;
                        break;
                    }
                    match *client_rx.borrow() {
                        ClientState::Gone => {
                            clean_close = false;
                            break;
                        }
                        ClientState::HalfClosed => {
                            timers.arm_or_reset_idle();
                        }
                        ClientState::Open => {}
                    }
                }
                _ = timers.wait_expired(), if timers.is_armed() => break,
            }
        }
        let _ = target_tx.send(true);
        if clean_close {
            let _ = send.send_data(Bytes::new(), true);
        }
    };

    tokio::join!(up, down);
    Ok(())
}

/// Encode one RFC 9298 §4 DATAGRAM capsule (`type(0x00) + varint(1 + len) +
/// context_id(0x00) + payload`) into `out`.
#[inline]
fn push_udp_capsule(out: &mut BytesMut, payload: &[u8]) {
    let value_len = 1 + payload.len();
    let needed = 1 + varint_len(value_len as u64) + 1 + payload.len();
    if out.capacity() - out.len() < needed {
        out.reserve(needed.max(UDP_CAPSULE_SLAB));
    }
    out.put_u8(CAPSULE_DATAGRAM as u8);
    encode_varint_mut(value_len as u64, out);
    out.put_u8(0);
    out.extend_from_slice(payload);
}

async fn dispatch_udp_capsules(buf: &[u8], pos: &mut usize, socket: &UdpSocket) -> bool {
    loop {
        match take_capsule_at(buf, pos) {
            Ok(Some(value)) => {
                // RFC 9298 §4: the DATAGRAM capsule value is Context ID
                // (varint) + UDP Proxying Payload. Context 0 is the UDP
                // payload; unregistered contexts are dropped (RFC 9298 §5).
                let Some((context, ctx_len)) = decode_varint(value) else {
                    debug!("http2connect: capsule without a Context ID");
                    return false;
                };
                if context != 0 {
                    continue;
                }
                let payload = &value[ctx_len..];
                loop {
                    match socket.try_send(payload) {
                        Ok(_) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if socket.send(payload).await.is_err() {
                                return false;
                            }
                            break;
                        }
                        Err(_) => return false,
                    }
                }
            }
            Ok(None) => return true,
            Err(e) => {
                debug!(error = %e, "http2connect: malformed capsule");
                return false;
            }
        }
    }
}

async fn send_auth_required(mut respond: SendResponse<Bytes>) -> Result<(), String> {
    let response = Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("proxy-authenticate", "Basic realm=\"frp\"")
        .body(())
        .map_err(|e| e.to_string())?;
    respond
        .send_response(response, true)
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn send_status(mut respond: SendResponse<Bytes>, status: StatusCode) -> Result<(), String> {
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|e| e.to_string())?;
    respond
        .send_response(response, true)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Send DATA respecting h2 flow control, streaming slices as soon as any
/// window capacity is available so a small peer window never stalls or
/// deadlocks a larger read chunk. Cancel-safe: `data` is mutated only once
/// `send_data` accepts the slice.
async fn send_h2(send: &mut SendStream<Bytes>, data: &mut Bytes) -> Result<(), String> {
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
                Some(Err(e)) => return Err(e.to_string()),
                None => return Err("h2 stream closed".into()),
            }
        };
        let n = cap.min(data.len());
        let piece = if n == data.len() {
            std::mem::take(data)
        } else {
            data.split_to(n)
        };
        send.send_data(piece, false).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// True when a CONNECT authority carries an explicit numeric port. IPv6
/// literals need the `[addr]:port` form for this to be true.
fn authority_has_port(authority: &str) -> bool {
    let port = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']')
            .and_then(|(_, after)| after.strip_prefix(':'))
    } else {
        authority.rsplit_once(':').map(|(_, port)| port)
    };
    port.is_some_and(|p| !p.is_empty() && p.parse::<u16>().is_ok())
}

/// Parse `.../{host}/{port}/` (RFC 9298 URI-template form) from a CONNECT-UDP
/// `:path`. Returns the decoded host and port.
fn udp_target_from_path(path: &str) -> Option<(String, u16)> {
    let mut segments = path.trim_end_matches('/').rsplit('/');
    let port: u16 = segments.next()?.parse().ok()?;
    let raw_host = segments.next()?;
    if raw_host.is_empty() || port == 0 {
        return None;
    }
    let host = String::from_utf8(urlencoding_decode(raw_host)).ok()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

// ---------------------------------------------------------------
// RFC 9297 capsule framing
// ---------------------------------------------------------------

/// Encoded byte length of a QUIC-style variable-length integer (RFC 9000 §16).
#[inline]
fn varint_len(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16_384 {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Append one QUIC-style variable-length integer (RFC 9000 §16) to a `BufMut`.
#[inline]
fn encode_varint_mut(value: u64, out: &mut impl BufMut) {
    if value < 64 {
        out.put_u8(value as u8);
    } else if value < 16_384 {
        out.put_u16(0x4000 | value as u16);
    } else if value < (1 << 30) {
        out.put_u32(0x8000_0000 | value as u32);
    } else {
        out.put_u64(0xC000_0000_0000_0000 | (value & 0x3fff_ffff_ffff_ffff));
    }
}

#[cfg(test)]
fn encode_varint(value: u64, out: &mut Vec<u8>) {
    encode_varint_mut(value, out);
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

/// Borrow one DATAGRAM capsule value starting at `*pos` without allocating.
/// Returns `Ok(None)` when more data is needed; other capsule types are
/// skipped (RFC 9297 §3.3).
fn take_capsule_at<'a>(buf: &'a [u8], pos: &mut usize) -> Result<Option<&'a [u8]>, String> {
    loop {
        let data = &buf[*pos..];
        let Some((kind, type_len)) = decode_varint(data) else {
            if data.len() > MAX_CAPSULE_BUFFER {
                return Err("capsule type exceeds buffer cap".into());
            }
            return Ok(None);
        };
        let Some((len, len_len)) = decode_varint(&data[type_len..]) else {
            if data.len() > MAX_CAPSULE_BUFFER {
                return Err("capsule length exceeds buffer cap".into());
            }
            return Ok(None);
        };
        if len > MAX_CAPSULE as u64 {
            return Err(format!("capsule length {len} exceeds cap"));
        }
        let total = type_len
            .checked_add(len_len)
            .and_then(|n| n.checked_add(len as usize))
            .ok_or_else(|| "capsule length overflow".to_string())?;
        if data.len() < total {
            return Ok(None);
        }
        *pos += total;
        if kind == CAPSULE_DATAGRAM {
            return Ok(Some(&data[type_len + len_len..total]));
        }
    }
}

#[cfg(test)]
fn take_capsule(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    let mut pos = 0;
    let result = take_capsule_at(buf, &mut pos)?.map(|s| s.to_vec());
    buf.drain(..pos);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for value in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            u64::MAX >> 2,
        ] {
            let mut out = Vec::new();
            encode_varint(value, &mut out);
            assert_eq!(
                decode_varint(&out),
                Some((value, out.len())),
                "value {value}"
            );
        }
    }

    #[test]
    fn capsule_parsing_handles_split_and_unknown_types() {
        let mut buf = Vec::new();
        encode_varint(CAPSULE_DATAGRAM, &mut buf);
        encode_varint(5, &mut buf);
        buf.extend_from_slice(b"hello");
        // Unknown capsule (type 7), then a DATAGRAM.
        encode_varint(7, &mut buf);
        encode_varint(2, &mut buf);
        buf.extend_from_slice(b"xx");
        encode_varint(CAPSULE_DATAGRAM, &mut buf);
        encode_varint(3, &mut buf);
        buf.extend_from_slice(b"bye");

        // Truncated: the first 5 bytes are not a full capsule value.
        let mut partial = buf[..6].to_vec();
        assert_eq!(take_capsule(&mut partial).unwrap(), None);
        assert_eq!(partial.len(), 6);

        assert_eq!(take_capsule(&mut buf).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(take_capsule(&mut buf).unwrap(), Some(b"bye".to_vec()));
        assert_eq!(take_capsule(&mut buf).unwrap(), None);
    }

    #[test]
    fn capsule_length_cap_is_enforced() {
        let mut buf = Vec::new();
        encode_varint(CAPSULE_DATAGRAM, &mut buf);
        encode_varint(MAX_CAPSULE as u64 + 1, &mut buf);
        assert!(take_capsule(&mut buf).is_err());
    }

    #[test]
    fn connect_authority_requires_a_port() {
        assert!(authority_has_port("example.com:443"));
        assert!(authority_has_port("[::1]:443"));
        assert!(!authority_has_port("example.com"));
        assert!(!authority_has_port("[::1]"));
        assert!(!authority_has_port("[::1]:"));
        assert!(!authority_has_port("example.com:notaport"));
    }

    #[test]
    fn udp_target_path_forms() {
        assert_eq!(
            udp_target_from_path("/.well-known/masque/udp/example.com/443/"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            udp_target_from_path("/127.0.0.1/53"),
            Some(("127.0.0.1".to_string(), 53))
        );
        assert_eq!(
            udp_target_from_path("/[::1]/5353/"),
            Some(("::1".to_string(), 5353))
        );
        assert_eq!(udp_target_from_path("/host/0/"), None);
        assert_eq!(udp_target_from_path("/host"), None);
        assert_eq!(udp_target_from_path("/"), None);
    }
}
