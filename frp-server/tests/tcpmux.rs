mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{
    allocate_port, login_with_test_token, read_until_eof, start_test_server, test_auth_cfg,
    GO_404_NOT_FOUND_RESPONSE,
};
use frp_core::config::ServerConfig;
use frp_core::msg::{FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

/// Helper: construct a tcpmux NewProxy with minimal fields.
fn tcpmux_proxy(name: &str, domains: Vec<String>, local: &str) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "tcpmux".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some(local.into()),
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
        multiplexer: Some("httpconnect".into()),
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }
}

/// TCPMux HTTP CONNECT routing test.
///
/// Verifies that the server correctly routes HTTP CONNECT requests
/// by Host header to the registered tcpmux proxy.
#[tokio::test]
async fn test_tcpmux_connect_routing() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Provider logs in and registers tcpmux proxy
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(Box::new(tcpmux_proxy(
        "tcpmux-ssh",
        vec!["machine-a.example.com".into()],
        "127.0.0.1:22",
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");

    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "tcpmux proxy registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // External client sends CONNECT to tcpmux port
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");

    client
        .write_all(
            b"CONNECT machine-a.example.com:22 HTTP/1.1\r\n\
              Host: machine-a.example.com:22\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT");

    // Read HTTP 200 response
    let mut response = [0u8; 512];
    let n = client.read(&mut response).await.expect("read response");
    let response_text = String::from_utf8_lossy(&response[..n]);
    assert!(
        response_text.starts_with("HTTP/1.1 200"),
        "expected 200, got: {}",
        response_text
    );
    println!("TCPMux response: {}", response_text.trim());

    println!("TCPMux CONNECT routing verified");
    drop(client);
    drop(provider);
}

/// TCPMux: CONNECT to unknown domain returns Go's NotFoundResponse
/// byte-exact — the 92-byte head + 489-byte HTML body = 581 bytes, then
/// close (probe vs Go frp v0.71.0; no custom_404_page configured). The
/// old Rust answer (404 with `Content-Length: 0`, no body) diverged.
#[tokio::test]
async fn test_tcpmux_unknown_domain_returns_404() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Register a tcpmux proxy so TcpMuxManager is active
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");
    let np = FrpMessage::NewProxy(Box::new(tcpmux_proxy(
        "tcpmux-1",
        vec!["known.example.com".into()],
        "127.0.0.1:22",
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    let _ = read_msg_v1(&mut provider).await.expect("read NewProxyResp");

    // Connect to tcpmux port with unknown domain
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");

    client
        .write_all(
            b"CONNECT unknown.example.com:22 HTTP/1.1\r\n\
              Host: unknown.example.com:22\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT");

    let bytes = read_until_eof(&mut client).await;
    assert_eq!(
        bytes,
        GO_404_NOT_FOUND_RESPONSE.as_bytes(),
        "expected the Go NotFoundResponse (581 bytes), got: {}",
        String::from_utf8_lossy(&bytes)
    );

    println!("TCPMux unknown domain Go-parity 404 verified");
    drop(client);
    drop(provider);
}

/// Audit-r7 EOL fix (shared listener, non-passthrough): a CONNECT whose
/// head uses bare-LF line endings (legal Go textproto — ReadLine splits on
/// `\n` and strips one optional `\r`) must be routed and answered. The old
/// `\r\n\r\n`-window scan never saw the terminator and stalled the shared
/// listener until its 30s read timeout (silent close).
///
/// Non-passthrough semantics: the proxy consumes the head and answers 200;
/// the tunnel then carries the client's tunneled bytes (the CONNECT head
/// itself is NOT forwarded to the local service — the byte-exact head
/// forward is passthrough mode's job, covered by the passthrough test).
#[tokio::test]
async fn test_tcpmux_connect_lf_only_head_gets_200_and_tunnel() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Provider registers a tcpmux proxy and pools a work conn.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");
    let np = FrpMessage::NewProxy(Box::new(tcpmux_proxy(
        "tcpmux-lf",
        vec!["lf.example.com".into()],
        "127.0.0.1:22",
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    let _ = read_msg_v1(&mut provider).await.expect("read NewProxyResp");
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(frp_core::msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");

    // LF-only head: every line ends \n, blank line is a bare \n.
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client
        .write_all(
            b"CONNECT lf.example.com:443 HTTP/1.1\n\
              Host: lf.example.com:443\n\
              \n",
        )
        .await
        .expect("send LF-only CONNECT");

    // The 200 must arrive promptly (the old terminator scan stalled ~30s).
    let mut response = [0u8; 256];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read(&mut response),
    )
    .await
    .expect("timeout waiting for the 200 — the LF head never terminated")
    .expect("read response");
    let text = String::from_utf8_lossy(&response[..n]);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected 200 for the LF-only CONNECT, got: {text}"
    );

    // Backend: StartWorkConn for the route.
    match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn on work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "tcpmux-lf");
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got: {:?}", other.v1_type_byte()),
    }

    // The tunnel is live: bytes the client sends after the 200 arrive at
    // the backend byte-exact (the CONNECT head was consumed by the proxy).
    client
        .write_all(b"SSH-PROTO-ECHO\r\n")
        .await
        .expect("send tunneled bytes");
    let mut echoed = [0u8; 64];
    let m = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        work_conn.read(&mut echoed),
    )
    .await
    .expect("timeout waiting for tunneled bytes")
    .expect("read tunneled bytes");
    assert_eq!(
        &echoed[..m],
        b"SSH-PROTO-ECHO\r\n",
        "the tunnel must carry post-200 bytes byte-exact, got: {}",
        String::from_utf8_lossy(&echoed[..m])
    );

    drop(client);
    drop(provider);
}

/// Audit-r7 EOL fix (passthrough): with `tcpMuxPassthrough`, the server
/// forwards the WHOLE CONNECT — head included — RAW (Go parity:
/// httpconnect.go hands the backend a SharedConn whose TeeReader replays
/// the client's exact wire bytes; frps "won't do any update on traffic",
/// server.go TCPMuxPassthrough doc). The net/http CRLF re-serialization
/// exists only on the vhost connectHandler path, never the tcpmux path —
/// the earlier round-7 canonicalization was a mis-citation and was
/// reverted. A bare-LF head must arrive at the backend byte-verbatim
/// (LF kept), with the textproto-lenient head read having terminated at
/// the LF blank line.
#[tokio::test]
async fn test_tcpmux_connect_lf_head_passthrough_raw_bytes() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        tcp_mux_passthrough: true,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Provider registers a tcpmux proxy and pools a work conn.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");
    let np = FrpMessage::NewProxy(Box::new(tcpmux_proxy(
        "tcpmux-lf-pass",
        vec!["lfpass.example.com".into()],
        "127.0.0.1:22",
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    let _ = read_msg_v1(&mut provider).await.expect("read NewProxyResp");
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(frp_core::msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");

    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client
        .write_all(
            b"CONNECT lfpass.example.com:443 HTTP/1.1\n\
              Host: lfpass.example.com:443\n\
              \n",
        )
        .await
        .expect("send LF-only CONNECT");

    // No 200 in passthrough mode (the CRLF passthrough test pins that rule
    // with a longer negative window; a short one guards this test's shape).
    let mut response = [0u8; 64];
    match tokio::time::timeout(
        std::time::Duration::from_millis(400),
        client.read(&mut response),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!(
            "passthrough mode must not answer the LF CONNECT, got: {}",
            String::from_utf8_lossy(&response[..n])
        ),
        Ok(Err(e)) => panic!("client read error: {e}"),
    }

    // Backend: StartWorkConn, then the head forwarded byte-verbatim.
    match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn on work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "tcpmux-lf-pass");
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got: {:?}", other.v1_type_byte()),
    }
    let mut forwarded = Vec::new();
    let mut chunk = [0u8; 256];
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !frp_core::textproto::head_end(&forwarded).is_some() {
            let m = work_conn
                .read(&mut chunk)
                .await
                .expect("read forwarded bytes");
            assert!(m > 0, "EOF before the forwarded head");
            forwarded.extend_from_slice(&chunk[..m]);
        }
    })
    .await
    .expect("timeout waiting for the forwarded CONNECT head");
    assert_eq!(
        forwarded,
        b"CONNECT lfpass.example.com:443 HTTP/1.1\nHost: lfpass.example.com:443\n\n",
        "the LF head must be forwarded RAW (Go SharedConn replay, no net/http re-serialization on the tcpmux path), got: {}",
        String::from_utf8_lossy(&forwarded)
    );

    drop(client);
    drop(provider);
}

/// Listener-level gate: a raw socket that sends a NON-CONNECT request line
/// is a readHTTPConnectRequest error in Go (`req.Method != "CONNECT"`,
/// case-sensitive like httpconnect.go) → vhost handle `_ = c.Close()` — the
/// conn closes with ZERO bytes (probe vs Go v0.71.0: no 405 on the wire —
/// the old Rust answer diverged), and the request never reaches route lookup.
#[tokio::test]
async fn test_tcpmux_get_request_line_rejected_silent_close() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // No proxy registration needed: the gate fires before routing.
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: machine-a.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send GET request line");

    // Zero bytes must arrive before EOF — the Go-parity silent close.
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timeout waiting for close")
        .expect("read after GET");
    assert_eq!(
        n,
        0,
        "non-CONNECT must close with zero bytes (got {:?})",
        String::from_utf8_lossy(&buf[..n])
    );
    drop(client);
}

/// CONNECT without a routable host — a 2-part request line with the version
/// in the target slot ("CONNECT HTTP/1.1") — is a net/http ReadRequest
/// error in Go (parseRequestLine needs 3 tokens), so readHTTPConnectRequest
/// errors and the vhost handle closes with ZERO bytes (probe vs Go v0.71.0;
/// the old Rust "400 Bad Request" answer diverged — round-3 review 2a).
#[tokio::test]
async fn test_tcpmux_connect_without_host_closes_silently() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client
        .write_all(b"CONNECT HTTP/1.1\r\n\r\n")
        .await
        .expect("send CONNECT without host");

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timeout waiting for close")
        .expect("read after malformed CONNECT");
    assert_eq!(
        n,
        0,
        "malformed CONNECT must close with zero bytes (got {:?})",
        String::from_utf8_lossy(&buf[..n])
    );
    drop(client);
}

/// Duplicate Host headers: Go net/http readRequest errors ("too many Host
/// headers", RFC 7230 §5.4) → readHTTPConnectRequest err → vhost handle
/// `_ = c.Close()` — silent close, ZERO bytes (probe vs Go v0.71.0; the old
/// Rust 400 answer diverged). Runs before routing, even though the CONNECT
/// authority is authoritative for routing.
#[tokio::test]
async fn test_tcpmux_duplicate_host_headers_rejected_silent_close() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client
        .write_all(
            b"CONNECT machine-a.example.com:22 HTTP/1.1\r\n\
              Host: machine-a.example.com:22\r\n\
              Host: other.example.com:22\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT with duplicate Host headers");

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timeout waiting for close")
        .expect("read after dup-Host CONNECT");
    assert_eq!(
        n,
        0,
        "dup-Host CONNECT must close with zero bytes (got {:?})",
        String::from_utf8_lossy(&buf[..n])
    );
    drop(client);
}

/// TCPMux: Proxy-Authorization check.
#[tokio::test]
async fn test_tcpmux_proxy_auth() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Register tcpmux proxy with auth
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");

    let mut auth_np = tcpmux_proxy(
        "auth-proxy",
        vec!["auth.example.com".into()],
        "127.0.0.1:8080",
    );
    auth_np.http_user = Some("admin".into());
    auth_np.http_pwd = Some("secret".into());
    write_msg_v1(&mut provider, &FrpMessage::NewProxy(Box::new(auth_np)))
        .await
        .expect("send NewProxy");
    let _ = read_msg_v1(&mut provider).await.expect("read NewProxyResp");

    // Test 1: Without auth → Go successHook-before-checkAuth order
    // (vhost.go handle:192-209): "200 OK" first, then the 407 — both on the
    // same conn, then close (probe vs Go v0.71.0). 407 realm is
    // "Restricted" (Go ProxyUnauthorizedResponse).
    {
        let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
            .await
            .expect("connect");
        client
            .write_all(
                b"CONNECT auth.example.com:443 HTTP/1.1\r\n\
                  Host: auth.example.com:443\r\n\
                  \r\n",
            )
            .await
            .expect("send CONNECT");
        let mut bytes = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
                .await
                .expect("timeout waiting for the auth response + close")
                .expect("read auth response");
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n"),
            "the 200 OK success hook must precede the 407 (Go order): {}",
            text
        );
        assert!(
            text.contains("HTTP/1.1 407 Proxy Authentication Required\r\n")
                && text.contains("Basic realm=\"Restricted\""),
            "expected the Go-parity 407 + Restricted realm after the 200, got: {}",
            text
        );
        println!("Auth required: 200 OK then 407 received (Go parity)");
    }

    // Test 2: With correct auth → 200 (admin:secret = YWRtaW46c2VjcmV0)
    {
        let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
            .await
            .expect("connect");
        client
            .write_all(
                b"CONNECT auth.example.com:443 HTTP/1.1\r\n\
                  Host: auth.example.com:443\r\n\
                  Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\
                  \r\n",
            )
            .await
            .expect("send CONNECT");
        let mut response = [0u8; 512];
        let n = client.read(&mut response).await.expect("read response");
        let text = String::from_utf8_lossy(&response[..n]);
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "expected 200 with correct auth, got: {}",
            text
        );
        println!("Auth success: 200 received");
    }

    drop(provider);
}

/// TCPMux passthrough (Go frp `tcpMuxPassthrough` compat).
///
/// When enabled, the server must NOT send the HTTP 200 response and must
/// forward the full CONNECT request bytes to the backend, matching Go
/// `pkg/util/tcpmux/httpconnect.go:73-82,122-125`.
#[tokio::test]
async fn test_tcpmux_passthrough() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        tcp_mux_passthrough: true,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Provider logs in, registers tcpmux proxy, and pools a work conn.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(Box::new(tcpmux_proxy(
        "tcpmux-pass",
        vec!["pass.example.com".into()],
        "127.0.0.1:22",
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "tcpmux registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Pooled work conn so the bridge can start immediately.
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(frp_core::msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");

    // External client sends CONNECT to the tcpmux port.
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client
        .write_all(
            b"CONNECT pass.example.com:22 HTTP/1.1\r\n\
              Host: pass.example.com:22\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT");

    // Server must NOT send the 200 — the request bytes are forwarded instead.
    let mut response = [0u8; 256];
    match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client.read(&mut response),
    )
    .await
    {
        Err(_) => {} // timeout: no 200 sent, as expected in passthrough mode
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!(
            "passthrough mode must not send HTTP 200, got: {}",
            String::from_utf8_lossy(&response[..n])
        ),
        Ok(Err(e)) => panic!("client read error: {}", e),
    }

    // Negative window is not enough: a slow (but wrong) server could have
    // sent the 200 just after the 500ms cut. Give the server one more
    // second to prove no late HTTP bytes arrive — a read timeout (or EOF)
    // is the only pass.
    let mut late = [0u8; 256];
    match tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut late)).await {
        Err(_) => {} // still silent: no late 200, passthrough confirmed
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!(
            "late HTTP bytes after negative window, got: {}",
            String::from_utf8_lossy(&late[..n])
        ),
        Ok(Err(e)) => panic!("client read error: {}", e),
    }

    // Backend side: StartWorkConn first, then the raw CONNECT request bytes.
    match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn on work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "tcpmux-pass");
            assert!(
                swc.error.is_none(),
                "StartWorkConn should not have error: {:?}",
                swc.error
            );
        }
        other => panic!("expected StartWorkConn, got: {:?}", other.v1_type_byte()),
    }

    let mut forwarded = Vec::new();
    let mut chunk = [0u8; 512];
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let n = work_conn
                .read(&mut chunk)
                .await
                .expect("read forwarded bytes");
            if n == 0 {
                break;
            }
            forwarded.extend_from_slice(&chunk[..n]);
            if forwarded.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .expect("timeout waiting for forwarded CONNECT bytes");

    let text = String::from_utf8_lossy(&forwarded);
    assert!(
        text.starts_with("CONNECT pass.example.com:22 HTTP/1.1"),
        "backend should receive the full CONNECT request, got: {:?}",
        text
    );

    println!("TCPMux passthrough verified: no 200 sent, CONNECT forwarded to backend");
    drop(client);
    drop(provider);
}
