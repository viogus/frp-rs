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
    route_by_http_user: Option<&str>,
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
        route_by_http_user: route_by_http_user.map(String::from),
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
/// (optionally Basic-auth protected, optionally with `route_by_http_user`
/// set so the route lands in the named user bucket) with one work conn
/// already pooled.
/// Returns `(bind_addr, vhost_addr, provider_control, run_id, work_conn)`.
#[allow(clippy::too_many_arguments)]
async fn setup_auth_impl(
    proxy_name: &str,
    domain: &str,
    http_user: Option<&str>,
    http_pwd: Option<&str>,
    route_by_http_user: Option<&str>,
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
        route_by_http_user,
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

/// Wrapper without `route_by_http_user`.
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
    setup_auth_impl(
        proxy_name,
        domain,
        http_user,
        http_pwd,
        None,
        vhost_http_timeout,
    )
    .await
}

/// Like `setup_auth` but with `route_by_http_user = "user"` — the route is
/// registered in the "user" bucket only, so routing exercises the
/// getRequestRouteUser username fallback.
async fn setup_rubu(
    proxy_name: &str,
    domain: &str,
    http_user: Option<&str>,
    http_pwd: Option<&str>,
) -> (
    SocketAddr,
    SocketAddr,
    IoStream,
    String,
    tokio::net::TcpStream,
) {
    setup_auth_impl(proxy_name, domain, http_user, http_pwd, Some("user"), 30).await
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
/// byte), not a per-read timeout. A client dripping the FULL 24-byte preface
/// one byte per 300ms (23 × 300ms ≈ 6.9s to complete) must be released after
/// the 1s deadline — a per-read timeout would re-arm on every received byte
/// and park the task + fd + vhost permit for ~7s.
///
/// The drip runs on the split write half so the read half can observe the
/// server-side release while bytes keep arriving — a drip that stops writing
/// cannot tell "server closed" from "server stopped reading". The drip task
/// breaks on the first write error (the server's close surfaces as one).
///
/// Assertion: the server closes the connection within 3s of the first
/// preface byte (1s deadline + scheduling slack), well before the 24th byte
/// lands at ~6.9s. Pre-fix (per-read timeout) code re-arms on every 300ms
/// byte and the connection survives past the window.
#[tokio::test]
async fn test_h2c_preface_slow_drip_released_at_absolute_deadline() {
    let (_bind, vhost_addr, _provider, _run_id, _work_conn) =
        setup_auth("h2c-drip", "drip.example.com", None, None, 1).await;

    let client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let started = std::time::Instant::now();
    let (mut client_rd, mut client_wr) = tokio::io::split(client);

    // Drip ALL 24 preface bytes at 300ms each (23 × 300ms ≈ 6.9s total):
    // the absolute 1s deadline must fire mid-drip, while the h2 path is
    // already committed (the first byte "P" is a preface prefix). Breaking
    // on write error is the normal end once the server closes.
    let drip = tokio::spawn(async move {
        for &b in preface {
            if client_wr.write_all(&[b]).await.is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
    });

    // Server-side release: the read half observes EOF or an error within
    // 3s — while the drip is STILL sending bytes, proving the server (not a
    // quiet client) closed the connection.
    let mut buf = [0u8; 64];
    match tokio::time::timeout(std::time::Duration::from_secs(3), client_rd.read(&mut buf)).await {
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
        started.elapsed() < std::time::Duration::from_millis(3500),
        "server released the slow-drip client only after {:.1}s",
        started.elapsed().as_secs_f32()
    );
    drip.abort();
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

/// Round-15 Content-Length enforcement: a request body longer than the
/// declared `content-length` must be reset with RST_STREAM PROTOCOL_ERROR
/// (RFC 7540 §8.1.2.6 — Go's h2 server resets on the same violation) and the
/// excess bytes must NEVER reach the provider: forwarded raw, they would
/// arrive at the backend as a pipelined request (request smuggling). The
/// backend sees the head with the DECLARED length and then silence — the
/// body task checks the length BEFORE writing, so even the first 3 bytes of
/// a 5-byte body are withheld once the violation is known.
#[tokio::test]
async fn test_h2c_content_length_excess_resets_protocol_error() {
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup("h2c-cl-excess", "clx.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("POST")
        .uri("http://clx.example.com/")
        .header("content-length", "3")
        .body(())
        .unwrap();
    let (response_fut, mut send_stream) = client.send_request(request, false).unwrap();
    // Declared 3 bytes, send 5 with END_STREAM.
    send_stream
        .send_data(Bytes::from_static(b"hello"), true)
        .unwrap();

    // The stream must be reset with PROTOCOL_ERROR, never answered.
    match tokio::time::timeout(std::time::Duration::from_secs(5), response_fut).await {
        Ok(Err(e)) => assert_eq!(
            e.reason(),
            Some(h2::Reason::PROTOCOL_ERROR),
            "CL-excess must reset with PROTOCOL_ERROR, got: {e}"
        ),
        Ok(Ok(resp)) => panic!("CL-excess request was answered with {}", resp.status()),
        Err(_) => panic!("no reset within 5s"),
    }

    // The backend received the head (with the DECLARED length) but must not
    // receive any body bytes.
    read_start_work_conn(&mut work_conn).await;
    let head = read_request_bytes(&mut work_conn).await;
    let head_text = String::from_utf8_lossy(&head);
    assert!(
        head_text.contains("content-length: 3\r\n"),
        "head must carry the declared length: {head_text}"
    );
    let mut buf = [0u8; 64];
    match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        work_conn.read(&mut buf),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!(
            "excess body bytes reached the backend: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => panic!("work conn read error: {e}"),
    }
}

/// Round-15 route_user fallback (h2c): the route is registered ONLY in the
/// "user" bucket (`route_by_http_user = "user"`). A request with a VALID
/// `authorization` Basic header and NO proxy-authorization must route on the
/// Authorization username (Go `getRequestRouteUser`: Proxy-Authorization
/// absent → `req.BasicAuth()` fallback) and then fail the auth gate with 407
/// — NOT the 404 an empty-bucket routing would produce (the pre-fix
/// behavior). base64("user:pass") = dXNlcjpwYXNz.
#[tokio::test]
async fn test_h2c_route_user_authorization_fallback_407_not_404() {
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup_rubu("h2c-rubu", "rubu.example.com", Some("user"), Some("pass")).await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://rubu.example.com/")
        .header("authorization", "Basic dXNlcjpwYXNz")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    let response = response_fut.await.expect("h2 response");
    assert_eq!(
        response.status().as_u16(),
        407,
        "route found via Authorization fallback must fail auth with 407, not 404"
    );
    assert_eq!(
        response.headers()["proxy-authenticate"].to_str().unwrap(),
        "Basic realm=\"frp\""
    );
    let body = read_h2_body(response.into_body()).await;
    assert!(body.is_empty());
    // Never forwarded: auth failed in the vhost layer.
    let swc = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        read_msg_v1(&mut work_conn),
    )
    .await;
    assert!(
        swc.is_err(),
        "auth-failed route_user request must not be forwarded (StartWorkConn sent)"
    );
}

/// Round-15 malformed Proxy-Authorization (h2c): a PRESENT but unparseable
/// proxy-authorization must route to the EMPTY user bucket (Go
/// `getRequestRouteUser`: `ParseBasicAuth` fails → `""`), NOT fall back to
/// the valid `authorization` username. The request misses the "user"-only
/// route and answers 404 — the pre-fix code would have routed on the
/// authorization username to the "user" route and answered 407 instead.
#[tokio::test]
async fn test_h2c_malformed_proxy_auth_empty_bucket_404() {
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup_rubu("h2c-rubu2", "rubu2.example.com", Some("user"), Some("pass")).await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://rubu2.example.com/")
        .header("proxy-authorization", "Basic !!!")
        .header("authorization", "Basic dXNlcjpwYXNz")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    let response = response_fut.await.expect("h2 response");
    assert_eq!(
        response.status().as_u16(),
        404,
        "malformed proxy-authorization must route to the empty bucket (404), not the Authorization username"
    );
    let body = read_h2_body(response.into_body()).await;
    assert!(body.is_empty());
    // Never forwarded.
    let swc = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        read_msg_v1(&mut work_conn),
    )
    .await;
    assert!(
        swc.is_err(),
        "empty-bucket 404 must not be forwarded (StartWorkConn sent)"
    );
}

/// Round-15 malformed chunk tail: the backend's chunked response ends a
/// chunk with garbage ("XX") instead of the required CRLF (Go
/// `chunkedReader`: "malformed chunked encoding"). The server must drop the
/// stream — the client receives the decoded "hello" and then a reset
/// (CANCEL), never a clean truncated 200. Pre-fix the two bytes were
/// discarded silently and the response ended as if complete.
#[tokio::test]
async fn test_h2c_malformed_chunk_tail_resets_stream() {
    let (_bind, vhost_addr, _provider, _run_id, mut work_conn) =
        setup("h2c-chunk-tail", "ct.example.com").await;

    let mut client = h2_connect(vhost_addr).await;
    let request = http::Request::builder()
        .method("GET")
        .uri("http://ct.example.com/")
        .body(())
        .unwrap();
    let (response_fut, _stream) = client.send_request(request, true).unwrap();

    read_start_work_conn(&mut work_conn).await;
    read_request_bytes(&mut work_conn).await;
    // Chunk-size 5, data "hello", then "XX" DIRECTLY — the two bytes after
    // the chunk data must be CRLF (RFC 7230 §4.1); "hello\r\nXX" would be a
    // VALID chunk tail followed by a garbage chunk-size line, which the
    // reader treats as an aborted backend (clean end).
    work_conn
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX")
        .await
        .expect("write chunked backend response");

    let response = response_fut.await.expect("h2 response");
    assert_eq!(response.status().as_u16(), 200);
    let mut body = response.into_body();
    let mut got = Vec::new();
    let mut reset = false;
    // Bounded: if the stream is neither reset nor ended (server regression)
    // the data loop must fail the test, not hang it.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match body.data().await {
                Some(Ok(chunk)) => got.extend_from_slice(&chunk),
                Some(Err(_e)) => {
                    reset = true;
                    break;
                }
                None => break,
            }
        }
    })
    .await
    .expect("stream neither reset nor ended within 5s");
    // The stream must end in an ERROR, never a clean truncation. Whether the
    // already-queued "hello" DATA frame is delivered before the RST is a wire
    // race (h2 discards queued DATA of a reset stream) — either way the
    // client must NOT see a clean end.
    assert!(
        reset,
        "malformed chunk tail must reset the stream, not deliver a clean truncated 200; body so far: {:?}",
        String::from_utf8_lossy(&got)
    );
}
