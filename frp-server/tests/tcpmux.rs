mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use frp_core::config::ServerConfig;
use frp_core::msg::{FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use common::{allocate_port, raw_login, start_test_server};

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
                    #[cfg(feature = "vnet")]
                    advertise_subnet: None,
                    #[cfg(feature = "vnet")]
                    vnet_ip: None,
                    #[cfg(feature = "vnet")]
                    vnet_netmask: None,
                    #[cfg(feature = "vnet")]
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
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Provider logs in and registers tcpmux proxy
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(tcpmux_proxy(
        "tcpmux-ssh",
        vec!["machine-a.example.com".into()],
        "127.0.0.1:22",
    ));
    write_msg_v1(&mut provider, &np).await.expect("send NewProxy");

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
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Register a tcpmux proxy so TcpMuxManager is active
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");
    let np = FrpMessage::NewProxy(tcpmux_proxy(
        "tcpmux-1",
        vec!["known.example.com".into()],
        "127.0.0.1:22",
    ));
    write_msg_v1(&mut provider, &np).await.expect("send NewProxy");
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
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    // Register tcpmux proxy with auth
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");

    let mut auth_np = tcpmux_proxy(
        "auth-proxy",
        vec!["auth.example.com".into()],
        "127.0.0.1:8080",
    );
    auth_np.http_user = Some("admin".into());
    auth_np.http_pwd = Some("secret".into());
    write_msg_v1(&mut provider, &FrpMessage::NewProxy(auth_np))
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
