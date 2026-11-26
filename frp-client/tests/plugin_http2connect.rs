//! Integration tests for the `http2connect` plugin (frp-rs extension):
//! HTTP/2 CONNECT (TCP) and extended CONNECT `connect-udp` with RFC 9297
//! capsules, over h2c.

#![cfg(feature = "http2http")]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use frp_core::config::PluginConfig;

const TIMEOUT: Duration = Duration::from_secs(3);

async fn start_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn start_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn plugin_cfg(auth: Option<(&str, &str)>) -> PluginConfig {
    let mut cfg = PluginConfig {
        plugin_type: "http2connect".into(),
        ..Default::default()
    };
    if let Some((user, pass)) = auth {
        cfg.http_user = user.into();
        cfg.http_password = pass.into();
    }
    cfg
}

async fn start_plugin(auth: Option<(&str, &str)>) -> frp_client::plugin::PluginHandle {
    frp_client::plugin::start_http2connect(&plugin_cfg(auth))
        .await
        .expect("start http2connect plugin")
}

fn handle_addr(handle: &frp_client::plugin::PluginHandle) -> SocketAddr {
    handle.local_addr
}

async fn h2_client(addr: SocketAddr) -> (SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (send, connection) = h2::client::handshake(tcp).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (send, task)
}

fn datagram_capsule(payload: &[u8]) -> Vec<u8> {
    // RFC 9298 §4: DATAGRAM capsule value = Context ID (varint) + UDP payload.
    let mut value = vec![0u8]; // Context ID 0 = UDP payload
    value.extend_from_slice(payload);
    let mut out = Vec::new();
    assert!(value.len() < 64);
    out.push(0); // capsule type 0 (DATAGRAM)
    out.push(value.len() as u8);
    out.extend_from_slice(&value);
    out
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

/// Pull one DATAGRAM capsule out of a possibly split or coalesced h2 DATA stream.
async fn recv_datagram_buf(recv: &mut h2::RecvStream, pending: &mut Vec<u8>) -> Vec<u8> {
    loop {
        while let Some((kind, type_len)) = decode_varint(pending) {
            let Some((len, len_len)) = decode_varint(&pending[type_len..]) else {
                break;
            };
            let total = type_len + len_len + len as usize;
            if pending.len() < total {
                break;
            }
            let value = pending[type_len + len_len..total].to_vec();
            pending.drain(..total);
            if kind == 0 {
                let (context, ctx_len) = decode_varint(&value).expect("Context ID");
                assert_eq!(context, 0, "UDP proxying uses Context ID 0");
                return value[ctx_len..].to_vec();
            }
        }
        let chunk = tokio::time::timeout(TIMEOUT, recv.data())
            .await
            .expect("capsule timeout")
            .expect("stream ended")
            .expect("h2 read");
        recv.flow_control().release_capacity(chunk.len()).unwrap();
        pending.extend_from_slice(&chunk);
    }
}

async fn recv_datagram(recv: &mut h2::RecvStream) -> Vec<u8> {
    let mut pending = Vec::new();
    recv_datagram_buf(recv, &mut pending).await
}

#[tokio::test]
async fn http2_connect_tcp_round_trip() {
    let backend = start_tcp_echo().await;
    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .body(())
        .unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();

    stream
        .send_data(Bytes::from_static(b"hello-h2"), false)
        .unwrap();
    let chunk = tokio::time::timeout(TIMEOUT, recv.data())
        .await
        .expect("echo timeout")
        .expect("stream ended")
        .expect("h2 read");
    assert_eq!(&chunk[..], b"hello-h2");
    assert!(recv.flow_control().release_capacity(chunk.len()).is_ok());
    stream.send_data(Bytes::new(), true).unwrap();
    conn.abort();
}

#[tokio::test]
async fn http2_connect_closes_target_when_client_vanishes() {
    // Regression for the detached-bridge leak: when the h2 connection is
    // aborted, the target must see EOF (fd released), not stay open until the
    // plugin handle is dropped.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap();
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf).await;
        let _ = eof_tx.send(());
    });

    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .body(())
        .unwrap();
    let (response, stream) = send.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    // Simulate the client vanishing: drop the stream + request handle and
    // abort the h2 connection task (closes the TCP socket).
    drop(stream);
    drop(send);
    conn.abort();
    tokio::time::timeout(TIMEOUT, eof_rx)
        .await
        .expect("target must see EOF after the client disconnects")
        .expect("EOF sender dropped");
}

#[tokio::test]
async fn http2_connect_half_close_still_delivers_target_tail() {
    // Client half-closes its request stream; the target reads EOF, writes a
    // final message, and closes. The plugin must forward that tail instead of
    // aborting the target->client direction.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        let _ = stream.write_all(b"tail").await;
        let _ = stream.shutdown().await;
    });

    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .body(())
        .unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    stream.send_data(Bytes::new(), true).unwrap();

    let mut recv = response.into_body();
    let chunk = tokio::time::timeout(TIMEOUT, recv.data())
        .await
        .expect("tail timeout")
        .expect("stream ended without tail")
        .expect("h2 read");
    assert_eq!(&chunk[..], b"tail");
    conn.abort();
}

#[tokio::test]
async fn http2_connect_udp_round_trip() {
    let backend = start_udp_echo().await;
    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "http://h2connect/.well-known/masque/udp/127.0.0.1/{}/",
            backend.port()
        ))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("?1")
    );
    let mut recv = response.into_body();

    stream
        .send_data(Bytes::from(datagram_capsule(b"udp-h2")), false)
        .unwrap();
    let payload = recv_datagram(&mut recv).await;
    assert_eq!(payload, b"udp-h2");
    conn.abort();
}

#[tokio::test]
async fn http2_connect_requires_proxy_auth() {
    let backend = start_tcp_echo().await;
    let handle = start_plugin(Some(("alice", "s3cret"))).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .body(())
        .unwrap();
    let (response, _) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

    // Correct Basic credentials (alice:s3cret) are accepted.
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .header("proxy-authorization", "Basic YWxpY2U6czNjcmV0")
        .body(())
        .unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    stream.send_data(Bytes::new(), true).unwrap();
    conn.abort();
}

#[tokio::test]
async fn http2_connect_udp_accepts_missing_capsule_protocol_header() {
    // RFC 9297 §3.4 makes the request header a SHOULD; `:protocol` already
    // makes the capsule dialect unambiguous, so this must be accepted.
    let proxy = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle_addr(&proxy)).await;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri("http://h2connect/127.0.0.1/53/")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, _) = send.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    conn.abort();
}

#[tokio::test]
async fn http2_connect_udp_rejects_oversized_capsule() {
    let backend = start_udp_echo().await;
    let proxy = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle_addr(&proxy)).await;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://h2connect/127.0.0.1/{}/", backend.port()))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Type 0, then a 4-byte varint length of 65537 (above the 64 KiB cap),
    // with no payload: the parser must close the stream rather than wait.
    let mut malformed = vec![0u8];
    malformed.extend_from_slice(&[0x80, 0x01, 0x00, 0x01]);
    stream.send_data(Bytes::from(malformed), false).unwrap();

    let mut recv = response.into_body();
    // An END_STREAM may arrive as an empty DATA frame; only non-empty payload
    // proves the stream kept forwarding. A timeout (hang) must fail too.
    let mut got_payload = false;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, recv.data()).await {
            Ok(Some(Ok(chunk))) => {
                if !chunk.is_empty() {
                    got_payload = true;
                    break;
                }
            }
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => panic!("oversized capsule left the stream hanging"),
        }
    }
    assert!(
        !got_payload,
        "oversized capsule should not produce payload data"
    );
    conn.abort();
}

#[tokio::test]
async fn http2_connect_rejects_wrong_credentials() {
    let backend = start_tcp_echo().await;
    let proxy = start_plugin(Some(("alice", "s3cret"))).await;
    let (mut send, conn) = h2_client(handle_addr(&proxy)).await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .header("proxy-authorization", "Basic d3Jvbmc6d3Jvbmc=")
        .body(())
        .unwrap();
    let (response, _) = send.send_request(request, false).unwrap();
    assert_eq!(
        response.await.unwrap().status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    conn.abort();
}

#[tokio::test]
async fn http2_connect_rejects_non_connect_methods() {
    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("http://h2connect/")
        .body(())
        .unwrap();
    let (response, _) = send.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    conn.abort();
}

#[tokio::test]
async fn http2_connect_bad_udp_path_is_rejected() {
    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri("http://h2connect/not-a-target/")
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, _) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    conn.abort();
}

fn encode_varint_test(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(0x80 | (value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}

fn datagram_capsule_any(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.push(0); // DATAGRAM capsule type 0
    encode_varint_test((1 + payload.len()) as u64, &mut out);
    out.push(0); // Context ID 0
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn http2_connect_tcp_streams_across_small_client_window() {
    // Regression guard: server reads up to 64 KiB chunks, while this client
    // advertises only a 16 KiB stream window. Streaming `send_h2` must split
    // slices to fit available capacity without stalling or losing bytes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap();
    let total = 256 * 1024usize;
    let expected: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let send_copy = expected.clone();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = s.write_all(&send_copy).await;
        let _ = s.shutdown().await;
    });

    let handle = start_plugin(None).await;
    let tcp = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(16 * 1024)
        .initial_connection_window_size(32 * 1024);
    let (mut send, connection) = builder.handshake::<_, Bytes>(tcp).await.unwrap();
    let conn = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .body(())
        .unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Half-close the request stream; target still streams all 256 KiB cleanly.
    stream.send_data(Bytes::new(), true).unwrap();
    let mut recv = response.into_body();

    let mut got = Vec::with_capacity(total);
    while got.len() < total {
        let chunk = tokio::time::timeout(TIMEOUT, recv.data())
            .await
            .expect("small-window download timed out (send_h2 stalled?)")
            .expect("stream ended early")
            .expect("h2 read");
        got.extend_from_slice(&chunk);
        recv.flow_control().release_capacity(chunk.len()).unwrap();
    }
    assert_eq!(got, expected);
    // Drain optional empty END_STREAM DATA frame and confirm clean EOF.
    loop {
        match tokio::time::timeout(TIMEOUT, recv.data())
            .await
            .expect("eof timeout")
        {
            Some(Ok(chunk)) if chunk.is_empty() => continue,
            None => break,
            other => panic!("expected clean EOF after payload, got {other:?}"),
        }
    }
    conn.abort();
}

#[tokio::test]
async fn http2_connect_tcp_bulk_bidirectional_echo() {
    // Stresses 64 KiB read/frame chunks, BytesMut slab reuse, 2 MiB windowing,
    // and try_write fast path + backpressure slow path end-to-end.
    let backend = start_tcp_echo().await;
    let handle = start_plugin(None).await;
    let tcp = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(4 * 1024 * 1024)
        .max_frame_size(64 * 1024);
    let (mut send, connection) = builder.handshake::<_, Bytes>(tcp).await.unwrap();
    let conn = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", backend.port()))
        .body(())
        .unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();

    let total = 2 * 1024 * 1024usize;
    let payload: Vec<u8> = (0..total).map(|i| ((i * 31) % 251) as u8).collect();
    let expected = payload.clone();

    let writer = tokio::spawn(async move {
        let mut rem = Bytes::from(payload);
        while !rem.is_empty() {
            stream.reserve_capacity(rem.len());
            let cap = loop {
                let c = stream.capacity();
                if c > 0 {
                    break c;
                }
                match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
                    Some(Ok(c)) if c > 0 => break c,
                    Some(Ok(_)) => {}
                    other => panic!("unexpected poll_capacity: {other:?}"),
                }
            };
            let n = cap.min(rem.len()).min(64 * 1024);
            let piece = rem.split_to(n);
            stream.send_data(piece, rem.is_empty()).unwrap();
        }
    });

    let mut got = Vec::with_capacity(total);
    while got.len() < total {
        let chunk = tokio::time::timeout(TIMEOUT, recv.data())
            .await
            .expect("bulk echo timeout")
            .expect("stream ended early")
            .expect("h2 read");
        got.extend_from_slice(&chunk);
        recv.flow_control().release_capacity(chunk.len()).unwrap();
    }
    writer.await.unwrap();
    assert_eq!(got, expected);
    conn.abort();
}

#[tokio::test]
async fn http2_connect_udp_handles_multi_capsule_split_and_large_datagrams() {
    let backend = start_udp_echo().await;
    let handle = start_plugin(None).await;
    let (mut send, conn) = h2_client(handle.local_addr).await;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "http://h2connect/.well-known/masque/udp/127.0.0.1/{}/",
            backend.port()
        ))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();

    // 1. Two capsules coalesced in a single H2 DATA chunk (zero-copy fast path)
    //    plus a trailing split half of a 1,400-byte capsule.
    let p1 = b"first-fast-path".to_vec();
    let p2 = vec![0xA5u8; 1200];
    let p3 = vec![0x5Au8; 1400];
    let c1 = datagram_capsule_any(&p1);
    let c2 = datagram_capsule_any(&p2);
    let c3 = datagram_capsule_any(&p3);

    let mut first_chunk = Vec::new();
    first_chunk.extend_from_slice(&c1);
    first_chunk.extend_from_slice(&c2);
    first_chunk.extend_from_slice(&c3[..500]);
    stream.send_data(Bytes::from(first_chunk), false).unwrap();
    // Send the rest of c3 in a second chunk (exercises pending reassembly + clear).
    stream
        .send_data(Bytes::from(c3[500..].to_vec()), false)
        .unwrap();

    let mut recv_pending = Vec::new();
    let mut received = vec![
        recv_datagram_buf(&mut recv, &mut recv_pending).await,
        recv_datagram_buf(&mut recv, &mut recv_pending).await,
        recv_datagram_buf(&mut recv, &mut recv_pending).await,
    ];
    received.sort();
    let mut expected = vec![p1, p2, p3];
    expected.sort();
    assert_eq!(received, expected);

    // 2. Clean half-close still allows a final reply after client sends END_STREAM.
    let p4 = vec![0x3Cu8; 4096];
    stream
        .send_data(Bytes::from(datagram_capsule_any(&p4)), true)
        .unwrap();
    assert_eq!(recv_datagram_buf(&mut recv, &mut recv_pending).await, p4);
    conn.abort();
}
