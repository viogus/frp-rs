mod common;

use common::{allocate_port, wait_for_port, start_echo_server, init_tracing, TestHarness};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use frp_core::config::{ClientConfig, ProxyConfig, ServerConfig};
use frp_client::service::Service as ClientService;
use frp_server::service::Service as ServerService;

fn tls_cert_dir() -> PathBuf {
    // From frp-client/tests/, CARGO_MANIFEST_DIR is frp-client/
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("frp-core");
    p.push("tests");
    p.push("certs");
    p
}

/// End-to-end test: plain TCP proxy.
///
/// Starts echo server → frps → frpc with a TCP proxy.
/// Connects to the proxy port, sends data, receives echo.
#[tokio::test]
async fn test_e2e_tcp_proxy_plain() {
    let harness = TestHarness::new(false, "").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    // Write data through the proxy
    let payload = b"hello from e2e test\n";
    stream.write_all(payload).await.expect("write to proxy");
    stream.flush().await.expect("flush");

    // Read echo back
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo from proxy");

    assert_eq!(&buf, payload, "echo data should match sent data");

    // Second round-trip to verify connection is stable
    let payload2 = b"round two - still working\n";
    stream.write_all(payload2).await.expect("write 2");
    stream.flush().await.expect("flush 2");

    let mut buf2 = vec![0u8; payload2.len()];
    stream.read_exact(&mut buf2).await.expect("read 2");

    assert_eq!(&buf2, payload2, "second echo should match");
}

/// End-to-end test: encrypted TCP proxy (AES-128-CFB).
///
/// Same flow as plain test but with use_encryption=true.
/// Requires a shared auth token (key derivation source).
#[tokio::test]
async fn test_e2e_tcp_proxy_encrypted() {
    let harness = TestHarness::new(true, "e2e-encryption-token").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    let payload = b"encrypted tunnel test payload\n";
    stream.write_all(payload).await.expect("write to proxy");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo from proxy");

    assert_eq!(&buf, payload, "echo through encrypted tunnel should match");

    // Send a larger payload to exercise framing
    let large = vec![0xABu8; 4096];
    stream.write_all(&large).await.expect("write large");
    stream.flush().await.expect("flush large");

    let mut large_buf = vec![0u8; large.len()];
    stream.read_exact(&mut large_buf).await.expect("read large");

    assert_eq!(large_buf, large, "large echo through encrypted tunnel should match");
}

/// End-to-end test: TCP proxy over WebSocket transport.
///
/// Client connects to the server's main port via WebSocket (server detects
/// WS via the 'G' byte in peek_connection_type). Data flows through
/// a plain TCP proxy tunnel over WebSocket transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_e2e_tcp_proxy_over_websocket() {
    init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let proxy_port = allocate_port();

    // 1. Echo server
    let _echo = start_echo_server(echo_port);

    // 2. frps (main port only; WS detected via peek_connection_type)
    let server_cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        allow_port_start: proxy_port.saturating_sub(50),
        allow_port_end: proxy_port.saturating_add(50).min(u16::MAX),
        ..Default::default()
    };
    let server_svc = ServerService::new(server_cfg, None).await.expect("create server service");
    let _server = tokio::spawn(async move { let _ = server_svc.run().await; });

    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5)).await.expect("server ready");

    // 3. frpc with WebSocket transport pointing to main port
    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        transport_protocol: "websocket".into(),
        token: String::new(),
        login_fail_exit: false,
        pool_count: 1,
        proxies: vec![ProxyConfig {
            name: "e2e-ws".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: proxy_port,
            use_encryption: false,
            use_compression: false,
            sk: String::new(),
            plugin: None,
            custom_domains: vec![],
            subdomain: String::new(),
            http_user: String::new(),
            http_pwd: String::new(),
            http_password: String::new(),
            locations: vec![],
            host_header_rewrite: String::new(),
            headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
            route_by_http_user: String::new(),
            allow_users: vec![],
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
            annotations: std::collections::HashMap::new(),
            metas: std::collections::HashMap::new(),
            multiplexer: String::new(),
            group: String::new(),
            group_key: String::new(),
            health_check_type: String::new(),
            health_check_url: String::new(),
            health_check_interval_seconds: 0,
            health_check_timeout_seconds: 0,
            health_check_max_failed: 0,
            virtual_net: String::new(),
        }],
        ..Default::default()
    };
    let client_svc = ClientService::new(client_cfg, None).await.expect("create client");
    let _client = tokio::spawn(async move { let _ = client_svc.run().await; });

    // 4. Wait for proxy port
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    wait_for_port(proxy_addr, Duration::from_secs(10)).await.expect("proxy port ready");

    // 5. Test data round-trip through WS transport
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.expect("connect to proxy");
    let payload = b"websocket tunnel e2e\n";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, payload, "echo through WS tunnel should match");

    // Second round-trip
    let payload2 = b"ws round two\n";
    stream.write_all(payload2).await.expect("write 2");
    stream.flush().await.expect("flush 2");

    let mut buf2 = vec![0u8; payload2.len()];
    stream.read_exact(&mut buf2).await.expect("read 2");
    assert_eq!(&buf2, payload2, "second WS echo should match");
}

/// End-to-end test: TCP proxy over TLS transport.
///
/// Server has TLS enabled. Client connects via TLS for both control
/// and work connections. Data flows through AES-128-CFB encrypted proxy
/// tunnel over TLS-wrapped TCP.
#[tokio::test]
async fn test_e2e_tcp_proxy_over_tls() {
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let proxy_port = allocate_port();
    let token = "e2e-tls-token";
    let cert_dir = tls_cert_dir();

    // 1. Echo server
    let _echo = start_echo_server(echo_port);

    // 2. frps with TLS
    let server_cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: token.to_string(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
        },
        tls_enable: true,
        tls_cert_file: cert_dir.join("server.crt").to_string_lossy().into(),
        tls_key_file: cert_dir.join("server.key").to_string_lossy().into(),
        allow_port_start: proxy_port.saturating_sub(50),
        allow_port_end: proxy_port.saturating_add(50).min(u16::MAX),
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let server_svc = ServerService::new(server_cfg, None).await.expect("create server service");
    let _server = tokio::spawn(async move { let _ = server_svc.run().await; });

    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5)).await.expect("TLS server ready");

    // 3. frpc with TLS
    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.to_string(),
        login_fail_exit: false,
        pool_count: 1,
        tcp_mux: false,
        tls_enable: true,
        tls_server_name: "localhost".into(),
        tls_ca_file: cert_dir.join("ca.crt").to_string_lossy().into(), // trust CA
        proxies: vec![ProxyConfig {
            name: "e2e-tls".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: proxy_port,
            use_encryption: true,
            use_compression: false,
            sk: String::new(),
            plugin: None,
            custom_domains: vec![],
            subdomain: String::new(),
            http_user: String::new(),
            http_pwd: String::new(),
            http_password: String::new(),
            locations: vec![],
            host_header_rewrite: String::new(),
            headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
            route_by_http_user: String::new(),
            allow_users: vec![],
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
            annotations: std::collections::HashMap::new(),
            metas: std::collections::HashMap::new(),
            multiplexer: String::new(),
            group: String::new(),
            group_key: String::new(),
            health_check_type: String::new(),
            health_check_url: String::new(),
            health_check_interval_seconds: 0,
            health_check_timeout_seconds: 0,
            health_check_max_failed: 0,
            virtual_net: String::new(),
        }],
        ..Default::default()
    };
    let client_svc = ClientService::new(client_cfg, None).await.expect("create client");
    let _client = tokio::spawn(async move { let _ = client_svc.run().await; });

    // 4. Wait for proxy port
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    wait_for_port(proxy_addr, Duration::from_secs(10)).await.expect("proxy port ready");

    // 5. Test data round-trip through TLS + encrypted tunnel
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.expect("connect to proxy");
    let payload = b"tls tunnel end-to-end\n";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, payload, "echo through TLS tunnel should match");
}

/// End-to-end test: TCP proxy over yamux (tcpMux).
///
/// Server wraps TCP in yamux. Client wraps TCP in yamux. All control
/// and work connection messages flow through yamux streams. Data flows
/// through a plain TCP proxy tunnel.
#[tokio::test]
async fn test_e2e_tcp_proxy_over_yamux() {
    init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let proxy_port = allocate_port();

    // 1. Echo server
    let _echo = start_echo_server(echo_port);

    // 2. frps with tcp_mux enabled
    let server_cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        allow_port_start: proxy_port.saturating_sub(50),
        allow_port_end: proxy_port.saturating_add(50).min(u16::MAX),
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 30,
            ..Default::default()
        },
        ..Default::default()
    };
    let server_svc = ServerService::new(server_cfg, None).await.expect("create server service");
    let _server = tokio::spawn(async move { let _ = server_svc.run().await; });

    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5)).await.expect("server ready");

    // 3. frpc with tcp_mux enabled
    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: String::new(),
        login_fail_exit: false,
        pool_count: 1,
        tcp_mux: true,
        proxies: vec![ProxyConfig {
            name: "e2e-yamux".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: proxy_port,
            use_encryption: false,
            use_compression: false,
            sk: String::new(),
            plugin: None,
            custom_domains: vec![],
            subdomain: String::new(),
            http_user: String::new(),
            http_pwd: String::new(),
            http_password: String::new(),
            locations: vec![],
            host_header_rewrite: String::new(),
            headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
            route_by_http_user: String::new(),
            allow_users: vec![],
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
            annotations: std::collections::HashMap::new(),
            metas: std::collections::HashMap::new(),
            multiplexer: String::new(),
            group: String::new(),
            group_key: String::new(),
            health_check_type: String::new(),
            health_check_url: String::new(),
            health_check_interval_seconds: 0,
            health_check_timeout_seconds: 0,
            health_check_max_failed: 0,
            virtual_net: String::new(),
        }],
        ..Default::default()
    };
    let client_svc = ClientService::new(client_cfg, None).await.expect("create client");
    let _client = tokio::spawn(async move { let _ = client_svc.run().await; });

    // 4. Wait for proxy port
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
    wait_for_port(proxy_addr, Duration::from_secs(10)).await.expect("proxy port ready");

    // 5. Test data round-trip through yamux tunnel
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.expect("connect to proxy");
    let payload = b"yamux tunnel e2e\n";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, payload, "echo through yamux tunnel should match");

    // Second round-trip to verify connection is stable
    let payload2 = b"yamux round two\n";
    stream.write_all(payload2).await.expect("write 2");
    stream.flush().await.expect("flush 2");

    let mut buf2 = vec![0u8; payload2.len()];
    stream.read_exact(&mut buf2).await.expect("read 2");
    assert_eq!(&buf2, payload2, "second yamux echo should match");
}
