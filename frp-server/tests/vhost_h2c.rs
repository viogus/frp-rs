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

fn http_proxy(
    name: &str,
    domains: Vec<String>,
    http_user: Option<&str>,
    http_pwd: Option<&str>,
) -> NewProxy {
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
        http_user: http_user.map(String::from),
        http_pwd: http_pwd.map(String::from),
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

/// Start a test frps + a provider registered with an HTTP proxy for `domain`
/// (optionally Basic-auth protected) with one work conn already pooled.
/// Returns `(bind_addr, vhost_addr, provider_control, run_id, work_conn)`.
async fn setup_auth(
    proxy_name: &str,
    domain: &str,
    http_user: Option<&str>,
    http_pwd: Option<&str>,
    vhost_http_timeout: u64,
) -> (
    SocketAddr,
    SocketAddr,
    IoStream,
    String,
    tokio::net::TcpStream,
) {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        vhost_http_timeout,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let vhost_addr: SocketAddr = format!("127.0.0.1:{vhost_port}").parse().unwrap();

    // Provider registers an HTTP proxy.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let np = FrpMessage::NewProxy(Box::new(http_proxy(
        proxy_name,
        vec![domain.into()],
        http_user,
        http_pwd,
    )));
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

    (addr, vhost_addr, provider, run_id, work_conn)
}

/// Convenience wrapper: default vhost_http_timeout (30s), no Basic auth.
async fn setup(
    proxy_name: &str,
    domain: &str,
) -> (
    SocketAddr,
    SocketAddr,
    IoStream,
    String,
    tokio::net::TcpStream,
) {
    setup_auth(proxy_name, domain, None, None, 30).await
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
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup("h2c-get", "h2c.example.com").await;

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
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
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
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup("h2c-post", "post.example.com").await;

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
    let (_bind, vhost_addr, _provider, _run_id, _work_conn) =
        setup("h2c-404", "mapped.example.com").await;

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

/// h2c Basic-auth branch: a request without credentials against an
/// `http_user`/`http_pwd` route must get an HTTP/2 407 Proxy Authentication
/// Required (with the `proxy-authenticate` challenge — h2 requests are
/// always absolute-form, so Go `checkRouteAuthByRequest` answers 407 and
/// reads `Proxy-Authorization` only) and must NOT be forwarded to a
/// backend; the same connection then succeeds with the correct
/// proxy-authorization header (base64("user:pass") = dXNlcjpwYXNz),
/// proving the auth check matches credentials rather than
/// blanket-rejecting h2.
#[tokio::test]
async fn test_h2c_407_without_credentials() {
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) = setup_auth(
        "h2c-auth",
        "auth.example.com",
        Some("user"),
        Some("pass"),
        30,
    )
    .await;

    let mut client = h2_connect(vhost_addr).await;

    // No credentials → HTTP/2 407, never forwarded.
    let request = http::Request::builder()
        .method("GET")
        .uri("http://auth.example.com/")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 407);
    assert_eq!(
        response.headers()["proxy-authenticate"].to_str().unwrap(),
        "Basic realm=\"frp\""
    );
    let body = read_h2_body(response.into_body()).await;
    assert!(body.is_empty());
    // The pooled work conn must stay silent — the 407 was generated in the
    // vhost layer, no StartWorkConn reached a backend.
    let swc = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        read_msg_v1(&mut work_conn),
    )
    .await;
    assert!(
        swc.is_err(),
        "407 request must not be forwarded to a backend (StartWorkConn sent)"
    );

    // Correct credentials on the SAME h2 connection → forwarded, 200.
    let request = http::Request::builder()
        .method("GET")
        .uri("http://auth.example.com/")
        .header("proxy-authorization", "Basic dXNlcjpwYXNz")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();
    read_start_work_conn(&mut work_conn).await;
    let head = read_request_bytes(&mut work_conn).await;
    // h2 header names are lowercase (HPACK); the module re-encodes them
    // as-is into the HTTP/1.1 head (Go's net/http would title-case them —
    // both are legal, RFC 7230 §3.2 makes field names case-insensitive).
    // The property under test is the VALUE arriving intact.
    assert!(
        String::from_utf8_lossy(&head).contains("proxy-authorization: Basic dXNlcjpwYXNz\r\n"),
        "proxy-authorization header must be forwarded intact: {}",
        String::from_utf8_lossy(&head),
    );
    work_conn
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await
        .expect("write backend response");
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 200);
    let body = read_h2_body(response.into_body()).await;
    assert_eq!(body, b"ok");
}

/// h2c keep-alive reuse across the vhost_http_timeout: two sequential
/// requests over ONE h2 connection, the second arriving after an idle
/// period longer than vhost_http_timeout (5s — wide enough that a loaded
/// CI stall between the vhost accept and the client's first h2 frame
/// cannot trip the handshake deadline). The round-8 handshake deadline
/// applies only to the first accept; later accepts must not be killed at
/// the deadline or the second request fails.
#[tokio::test]
async fn test_h2c_keepalive_reuse_survives_http_timeout() {
    let (_bind, vhost_addr, mut provider, run_id, mut work_conn) =
        setup_auth("h2c-ka", "ka.example.com", None, None, 5).await;

    let mut client = h2_connect(vhost_addr).await;

    // Request 1: consumes the pooled work conn.
    let request = http::Request::builder()
        .method("GET")
        .uri("http://ka.example.com/one")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();
    read_start_work_conn(&mut work_conn).await;
    read_request_bytes(&mut work_conn).await;
    work_conn
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
        .await
        .expect("write backend response");
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 200);
    let body = read_h2_body(response.into_body()).await;
    assert_eq!(body, b"one");

    // Idle past vhost_http_timeout (5s): if the connection were pinned to
    // the handshake deadline it would be closed here and request 2 would
    // fail.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    // Request 2 on the same connection: pool is empty, so the server
    // requests a fresh work conn via ReqWorkConn on the control channel.
    let request = http::Request::builder()
        .method("GET")
        .uri("http://ka.example.com/two")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_msg_v1(&mut provider),
    )
    .await
    .expect("ReqWorkConn within 10s")
    .expect("read ReqWorkConn")
    {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!("expected ReqWorkConn, got {:?}", other.v1_type_byte()),
    }
    let mut work_conn2 = tokio::net::TcpStream::connect(_bind)
        .await
        .expect("second work conn");
    write_msg_v1(
        &mut work_conn2,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    read_start_work_conn(&mut work_conn2).await;
    let head = read_request_bytes(&mut work_conn2).await;
    assert!(
        String::from_utf8_lossy(&head).contains("Host: ka.example.com\r\n"),
        "head must carry the second request's Host"
    );
    work_conn2
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
        .await
        .expect("write backend response");
    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 200);
    let body = read_h2_body(response.into_body()).await;
    assert_eq!(body, b"two");
}

/// Round-8 h2c preface slow-drip regression: the preface completion loop in
/// vhost.rs uses ONE absolute deadline (vhost_http_timeout from the first
/// byte), not a per-read timeout. A client dripping the 24-byte preface one
/// byte per read window (300ms here, so 23 × 300ms ≈ 6.9s to complete) must
/// be released after the 1s deadline — a per-read timeout would re-arm on
/// every received byte and park the task + fd + vhost permit for ~7s.
///
/// Assertion: the server closes the connection within 2.5s of the first
/// preface byte (1s deadline + scheduling slack). Pre-fix the connection
/// would survive past the 2.5s window (preface completes at ~6.9s).
#[tokio::test]
async fn test_h2c_preface_slow_drip_released_at_absolute_deadline() {
    let (_bind, vhost_addr, _provider, _run_id, _work_conn) =
        setup_auth("h2c-drip", "drip.example.com", None, None, 1).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let started = std::time::Instant::now();

    // Drip one byte per 300ms: the absolute 1s deadline must fire while
    // fewer than 24 bytes have arrived (first 4 bytes land before 1s).
    let mut sent = 0;
    while sent < preface.len() {
        client
            .write_all(&preface[sent..sent + 1])
            .await
            .expect("drip preface byte");
        sent += 1;
        if sent >= 4 {
            break; // enough bytes to commit the h2 path; keep the conn open
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    // The remaining drip keeps arriving but the 1s deadline must already
    // have armed (it is anchored at the first read in the completion loop).
    // Server-side release: read returns EOF or an error within 2.5s.
    let mut buf = [0u8; 64];
    match tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!(
            "server must release the slow-drip h2c client, got {} bytes: {}",
            n,
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(_)) => {}
        Err(_) => panic!(
            "slow-drip h2c preface still alive after {:.1}s (absolute deadline not enforced)",
            started.elapsed().as_secs_f32()
        ),
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "server released the slow-drip client only after {:.1}s",
        started.elapsed().as_secs_f32()
    );
}

/// Round-8 h2c oversized header block regression: the h2 server builder caps
/// max_header_list_size at 4096 (the same bound as the HTTP/1.1 head cap).
/// A request with a > 4096-byte decoded header block must be rejected by the
/// h2 layer WITHOUT dispatching a work conn to the provider — a work conn
/// forwarded to a backend that can never read the complete head would tie up
/// the pooled slot.
///
/// Rejection shape: h2 ≥0.4 implements RFC 9113 §10.5.1 — a server that
/// receives a larger header block than SETTINGS_MAX_HEADER_LIST_SIZE may
/// answer an auto-generated 431 (Request Header Fields Too Large), an error
/// recorded so the stream also gets REFUSED_STREAM and none of its data
/// frames are accepted (proto/streams/recv.rs `frame.is_over_size()` arm).
/// The frp-rs handler never sees the request either way; both the 431
/// response and a protocol error are valid h2-layer rejections.
#[tokio::test]
async fn test_h2c_oversized_header_block_rejected_no_work_conn() {
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup("h2c-big-head", "big.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://big.example.com/")
        .header("x-big", "a".repeat(5000))
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    // The h2 layer must reject the stream, never answer through a work conn:
    // either an auto-generated 431 (RFC 9113 §10.5.1, h2's implementation of
    // SETTINGS_MAX_HEADER_LIST_SIZE) or a protocol error / reset.
    match tokio::time::timeout(std::time::Duration::from_secs(5), response_fut).await {
        Ok(Ok(resp)) => assert_eq!(
            resp.status().as_u16(),
            431,
            "h2-layer rejection must be 431, got {}",
            resp.status()
        ),
        Ok(Err(_e)) => {} // protocol error / reset — also a valid rejection
        Err(_) => panic!("no h2 response within 5s"),
    }

    // The pooled work conn must stay silent: no StartWorkConn, no forwarded
    // head. (500ms negative window — the dispatch path is fast.)
    let mut buf = [0u8; 64];
    let silent = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        work_conn.read(&mut buf),
    )
    .await;
    match silent {
        Err(_) => {}
        Ok(Ok(0)) => panic!("work conn closed unexpectedly"),
        Ok(Ok(n)) => panic!(
            "oversized h2 request must not dispatch a work conn, got {} bytes: {}",
            n,
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => panic!("work conn read error: {e}"),
    }
}
