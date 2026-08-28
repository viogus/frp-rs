//! HTTP/2 cleartext (h2c) end-to-end tests for the HTTP vhost listener.
//!
//! Go frp v0.70.1 accepts h2c (prior-knowledge HTTP/2) clients on the vhost
//! port and forwards to providers as plain HTTP/1.1. These tests drive the
//! same path with `h2::client`:
//! - GET forwarded as HTTP/1.1 (Host header from `:authority`), backend
//!   HTTP/1.1 response re-encoded as HTTP/2
//! - chunked backend responses decoded before reaching the h2 client
//! - POST bodies forwarded (chunked framing when there is no Content-Length)
//! - unmapped hosts get an HTTP/2 404

mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bytes::Bytes;
use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

fn http_proxy(name: &str, domains: Vec<String>) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "http".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:8080".into()),
        remote_port: Some(0),
        custom_domains: Some(domains),
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }
}

/// Start a test frps + a provider registered with an HTTP proxy for `domain`,
/// with one work conn already pooled. Returns
/// `(bind_addr, vhost_addr, provider_control, work_conn)`.
async fn setup(
    proxy_name: &str,
    domain: &str,
) -> (SocketAddr, SocketAddr, IoStream, tokio::net::TcpStream) {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let vhost_addr: SocketAddr = format!("127.0.0.1:{vhost_port}").parse().unwrap();

    // Provider registers an HTTP proxy.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let np = FrpMessage::NewProxy(Box::new(http_proxy(proxy_name, vec![domain.into()])));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "registration failed: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Pool a work conn.
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");

    (addr, vhost_addr, provider, work_conn)
}

/// Connect an h2 client to the vhost port and drive its connection task.
async fn h2_connect(vhost_addr: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let tcp = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    let (client, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client.ready().await.expect("h2 client ready")
}

/// Read the StartWorkConn frame off the work conn.
async fn read_start_work_conn(work_conn: &mut tokio::net::TcpStream) {
    match read_msg_v1(work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert!(swc.error.is_none(), "{:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }
}

/// Read raw bytes until the end of the HTTP/1.1 request head (`\r\n\r\n`).
/// Returns the head plus any body bytes that arrived with it.
async fn read_request_bytes(work_conn: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return buf;
        }
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            work_conn.read(&mut chunk),
        )
        .await
        .expect("timeout reading forwarded request")
        .expect("read forwarded request");
        assert!(n > 0, "unexpected EOF while reading request head");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Drain the h2 response body into a single Vec.
async fn read_h2_body(mut body: h2::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        out.extend_from_slice(&chunk.expect("h2 body chunk"));
    }
    out
}

#[tokio::test]
async fn test_h2c_get_forwarded_as_http1() {
    let (_bind, vhost_addr, _provider, mut work_conn) = setup("h2c-get", "h2c.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://h2c.example.com/")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    // Provider receives StartWorkConn then a plain HTTP/1.1 request head with
    // Host from the h2 `:authority`.
    read_start_work_conn(&mut work_conn).await;
    let head = read_request_bytes(&mut work_conn).await;
    let head_text = String::from_utf8_lossy(&head);
    assert!(
        head_text.starts_with("GET / HTTP/1.1\r\n"),
        "head: {head_text}"
    );
    assert!(
        head_text.contains("Host: h2c.example.com\r\n"),
        "head: {head_text}"
    );

    // Provider answers with a plain HTTP/1.1 response (Content-Length).
    work_conn
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              Content-Length: 11\r\n\
              Content-Type: text/plain\r\n\
              \r\n\
              hello world",
        )
        .await
        .expect("write backend response");

    // h2 client sees 200 + the full body.
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers()["content-type"].to_str().unwrap(),
        "text/plain"
    );
    let body = read_h2_body(response.into_body()).await;
    assert_eq!(body, b"hello world");
}

#[tokio::test]
async fn test_h2c_chunked_backend_response() {
    let (_bind, vhost_addr, _provider, mut work_conn) =
        setup("h2c-chunked", "chunk.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://chunk.example.com/")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    read_start_work_conn(&mut work_conn).await;
    let head = read_request_bytes(&mut work_conn).await;
    assert!(
        String::from_utf8_lossy(&head).contains("Host: chunk.example.com\r\n"),
        "head: {:?}",
        String::from_utf8_lossy(&head)
    );

    // Chunked backend response: "hello" (5) + " world" (6) + terminator.
    work_conn
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .await
        .expect("write chunked backend response");

    // The h2 client receives the decoded body — no chunk markers.
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 200);
    assert!(
        !response.headers().contains_key("transfer-encoding"),
        "hop-by-hop header must not be re-encoded"
    );
    let body = read_h2_body(response.into_body()).await;
    assert_eq!(body, b"hello world");
}

#[tokio::test]
async fn test_h2c_post_body_forwarded_chunked() {
    let (_bind, vhost_addr, _provider, mut work_conn) = setup("h2c-post", "post.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("POST")
        .uri("http://post.example.com/submit")
        .body(())
        .unwrap();
    let (response_fut, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream
        .send_data(Bytes::from_static(b"hello"), false)
        .unwrap();
    send_stream
        .send_data(Bytes::from_static(b" world"), true)
        .unwrap();

    read_start_work_conn(&mut work_conn).await;
    let data = read_request_bytes(&mut work_conn).await;
    let head_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head terminator")
        + 4;
    let head_text = String::from_utf8_lossy(&data[..head_end]);
    assert!(
        head_text.starts_with("POST /submit HTTP/1.1\r\n"),
        "head: {head_text}"
    );
    assert!(
        head_text.contains("Host: post.example.com\r\n"),
        "head: {head_text}"
    );
    assert!(
        head_text.contains("Transfer-Encoding: chunked\r\n"),
        "head: {head_text}"
    );

    // Read the chunked body: 5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n
    let mut body = data[head_end..].to_vec();
    let mut chunk = [0u8; 1024];
    loop {
        if body.windows(5).any(|w| w == b"0\r\n\r\n") {
            break;
        }
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            work_conn.read(&mut chunk),
        )
        .await
        .expect("timeout reading request body")
        .expect("read request body");
        assert!(n > 0, "unexpected EOF before chunked terminator");
        body.extend_from_slice(&chunk[..n]);
    }
    let body_text = String::from_utf8_lossy(&body);
    assert!(
        body_text.contains("5\r\nhello\r\n") && body_text.contains("6\r\n world\r\n"),
        "chunked body mismatch: {body_text:?}"
    );

    work_conn
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("write backend response");
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 204);
    let body = read_h2_body(response.into_body()).await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_h2c_404_unmapped_host() {
    let (_bind, vhost_addr, _provider, _work_conn) = setup("h2c-404", "mapped.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://nope.example.com/")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 404);
    let body = read_h2_body(response.into_body()).await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_h2c_preface_then_silence_dropped_at_timeout() {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    // Short vhost_http_timeout so the handshake deadline fires quickly.
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        vhost_http_timeout: 1,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let vhost_addr: SocketAddr = format!("127.0.0.1:{vhost_port}").parse().unwrap();

    // Send only the 24-byte HTTP/2 prior-knowledge preface, then go silent —
    // no client SETTINGS frame, no HEADERS. Pre-fix this parked the h2
    // handshake forever (task + fd + conn_semaphore permit when max_connections
    // is configured); the vhost_http_timeout handshake deadline must close
    // the connection.
    let mut stream = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("write h2 preface");
    stream.flush().await.expect("flush h2 preface");

    // The server should close the connection once the ~1s handshake deadline
    // fires. h2 writes its own SETTINGS frame eagerly during the handshake, so
    // drain whatever the server sends and wait for EOF (or a reset). Bounded by
    // 5s: if that elapses the deadline never fired and the connection is parked
    // forever — fail loudly instead of hanging.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buf = [0u8; 256];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,    // clean EOF — deadline closed the connection
                Ok(_) => continue, // server SETTINGS / GOAWAY — keep draining
                Err(_) => break,   // RST is also a valid release
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "h2c handshake deadline did not release the connection within 5s"
    );
}
