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
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::server::{Builder, SendResponse};
use h2::{RecvStream, SendStream};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::http::{AuthVerdict, HttpProxyAuth};
use super::{serve_plugin, split_host_port, urlencoding_decode, PluginHandle};

/// Cap on one capsule's declared length. CONNECT-UDP datagrams are bounded by
/// the path MTU in practice; this is a memory guard, not a protocol limit.
const MAX_CAPSULE: usize = 64 * 1024;
/// Overall bound for a partially received capsule buffer.
const MAX_CAPSULE_BUFFER: usize = MAX_CAPSULE + 16;
const CAPSULE_DATAGRAM: u64 = 0x00;
/// Bound on a single target UDP reply read.
const MAX_UDP_DATAGRAM: usize = 64 * 1024;
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
        .max_header_list_size(16 * 1024);
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
        match connection.accept().await {
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

    let protocol = request
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|p| p.as_str().to_string());
    match protocol.as_deref() {
        None => {
            let Some(authority) = request.uri().authority().map(|a| a.as_str().to_string()) else {
                return send_status(respond, StatusCode::BAD_REQUEST).await;
            };
            tcp_connect(request.into_body(), respond, &authority).await
        }
        Some("connect-udp") => {
            // RFC 9297 §3.4 makes `Capsule-Protocol: ?1` a SHOULD on the
            // request; the response already advertises it and `:protocol =
            // connect-udp` makes the capsule dialect unambiguous, so a client
            // that omits the request header is accepted.
            let Some((host, port)) = udp_target_from_path(request.uri().path()) else {
                return send_status(respond, StatusCode::BAD_REQUEST).await;
            };
            udp_connect(request.into_body(), respond, &host, port).await
        }
        Some(other) => {
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
    let mut buf = [0u8; 16 * 1024];
    let (client_tx, mut client_rx) = watch::channel(ClientState::Open);
    let (target_tx, mut target_rx) = watch::channel(false);

    let up = async {
        loop {
            tokio::select! {
                chunk = recv.data() => match chunk {
                    Some(Ok(chunk)) => {
                        if recv.flow_control().release_capacity(chunk.len()).is_err() {
                            let _ = client_tx.send(ClientState::Gone);
                            break;
                        }
                        let write = async {
                            let mut offset = 0;
                            while offset < chunk.len() {
                                match tcp_w.write(&chunk[offset..]).await {
                                    Ok(0) | Err(_) => return Err(()),
                                    Ok(n) => offset += n,
                                }
                            }
                            Ok(())
                        };
                        match tokio::time::timeout(TARGET_WRITE_TIMEOUT, write).await {
                            Ok(Ok(())) => {}
                            _ => {
                                let _ = client_tx.send(ClientState::Gone);
                                break;
                            }
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
        let mut idle: Option<tokio::time::Instant> = None;
        let mut tail_started: Option<tokio::time::Instant> = None;
        loop {
            let deadline = idle;
            let max_deadline = tail_started.map(|t| t + TARGET_TAIL_MAX_LIFETIME);
            tokio::select! {
                read = tcp_r.read(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if send_h2(&mut send, Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        // Idle, not absolute: a slow response keeps resetting
                        // the tail window and is never silently truncated.
                        if matches!(*client_rx.borrow(), ClientState::HalfClosed) {
                            let now = tokio::time::Instant::now();
                            idle = Some(now + TARGET_TAIL_TIMEOUT);
                            tail_started.get_or_insert(now);
                        }
                    }
                },
                changed = client_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    match *client_rx.borrow() {
                        ClientState::Gone => break,
                        ClientState::HalfClosed => {
                            let now = tokio::time::Instant::now();
                            idle = Some(now + TARGET_TAIL_TIMEOUT);
                            tail_started.get_or_insert(now);
                        }
                        ClientState::Open => {}
                    }
                }
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                }, if deadline.is_some() => break,
                _ = async {
                    match max_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                }, if max_deadline.is_some() => break,
            }
        }
        let _ = target_tx.send(true);
        let _ = send.send_data(Bytes::new(), true);
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

    // Single task for both directions: abort/drop closes the target socket.
    let mut pending: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut client_open = true;
    let mut clean_close = true;
    let mut idle: Option<tokio::time::Instant> = None;
    let mut tail_started: Option<tokio::time::Instant> = None;
    'stream: loop {
        let deadline = idle;
        let max_deadline = tail_started.map(|t| t + TARGET_TAIL_MAX_LIFETIME);
        tokio::select! {
            chunk = recv.data(), if client_open => match chunk {
                Some(Ok(chunk)) => {
                    if recv.flow_control().release_capacity(chunk.len()).is_err() {
                        break 'stream;
                    }
                    pending.extend_from_slice(&chunk);
                    loop {
                        match take_capsule_at(&pending, &mut pos) {
                            Ok(Some(value)) => {
                                // RFC 9298 §4: the DATAGRAM capsule value is
                                // Context ID (varint) + UDP Proxying Payload.
                                // Context 0 is the UDP payload; unregistered
                                // contexts are dropped (RFC 9298 §5).
                                let Some((context, ctx_len)) = decode_varint(&value) else {
                                    debug!("http2connect: capsule without a Context ID");
                                    clean_close = false;
                                    break 'stream;
                                };
                                if context != 0 {
                                    continue;
                                }
                                if socket.send(&value[ctx_len..]).await.is_err() {
                                    break 'stream;
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                debug!(error = %e, "http2connect: malformed capsule");
                                clean_close = false;
                                break 'stream;
                            }
                        }
                    }
                    if pos > 0 {
                        pending.drain(..pos);
                        pos = 0;
                    }
                }
                Some(Err(_)) => {
                    clean_close = false;
                    break 'stream;
                }
                None => {
                    // Clean half-close: the client sends no more datagrams,
                    // but may still read replies. Give the target an idle
                    // window, reset by every reply.
                    client_open = false;
                    let now = tokio::time::Instant::now();
                    idle = Some(now + TARGET_TAIL_TIMEOUT);
                    tail_started.get_or_insert(now);
                }
            },
            result = socket.recv(&mut buf) => match result {
                Ok(n) => {
                    // RFC 9298 §4: Context ID 0 precedes every UDP payload.
                    let mut value = Vec::with_capacity(n + 1);
                    encode_varint(0, &mut value);
                    value.extend_from_slice(&buf[..n]);
                    let mut capsule = Vec::with_capacity(value.len() + 10);
                    encode_varint(CAPSULE_DATAGRAM, &mut capsule);
                    encode_varint(value.len() as u64, &mut capsule);
                    capsule.extend_from_slice(&value);
                    if send_h2(&mut send, Bytes::from(capsule)).await.is_err() {
                        break 'stream;
                    }
                    if !client_open {
                        let now = tokio::time::Instant::now();
                        idle = Some(now + TARGET_TAIL_TIMEOUT);
                        tail_started.get_or_insert(now);
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
                    break 'stream;
                }
            },
            _ = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            }, if deadline.is_some() => break 'stream,
            _ = async {
                match max_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            }, if max_deadline.is_some() => break 'stream,
        }
    }
    if clean_close {
        let _ = send.send_data(Bytes::new(), true);
    }
    Ok(())
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

/// Send one DATA frame respecting h2 flow control.
async fn send_h2(send: &mut SendStream<Bytes>, data: Bytes) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    send.reserve_capacity(data.len());
    while send.capacity() < data.len() {
        match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e.to_string()),
            None => return Err("h2 stream closed".into()),
        }
    }
    send.send_data(data, false).map_err(|e| e.to_string())
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

/// Append one QUIC-style variable-length integer (RFC 9000 §16).
fn encode_varint(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else if value < (1 << 30) {
        out.push(0x80 | (value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(0xC0 | ((value >> 56) & 0x3f) as u8);
        for shift in [48, 40, 32, 24, 16, 8, 0] {
            out.push((value >> shift) as u8);
        }
    }
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

/// Take one DATAGRAM capsule value starting at `*pos`. Returns `Ok(None)` when
/// more data is needed; the cursor avoids the O(n²) `Vec::drain` per capsule.
/// Other capsule types are skipped (RFC 9297 §3.3).
fn take_capsule_at(buf: &[u8], pos: &mut usize) -> Result<Option<Vec<u8>>, String> {
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
            return Ok(Some(data[type_len + len_len..total].to_vec()));
        }
    }
}

#[cfg(test)]
fn take_capsule(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    let mut pos = 0;
    let result = take_capsule_at(buf, &mut pos)?;
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
