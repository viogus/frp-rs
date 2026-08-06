mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
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

/// TCPMux: CONNECT to unknown domain returns 404.
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

    let mut response = [0u8; 512];
    let n = client.read(&mut response).await.expect("read response");
    let response_text = String::from_utf8_lossy(&response[..n]);
    assert!(
        response_text.starts_with("HTTP/1.1 404"),
        "expected 404 for unknown domain, got: {}",
        response_text
    );

    println!("TCPMux unknown domain 404 verified");
    drop(client);
    drop(provider);
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

    // Test 1: Without auth → 407
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
        let mut response = [0u8; 512];
        let n = client.read(&mut response).await.expect("read response");
        let text = String::from_utf8_lossy(&response[..n]);
        assert!(
            text.starts_with("HTTP/1.1 407"),
            "expected 407 without auth, got: {}",
            text
        );
        println!("Auth required: 407 received");
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
