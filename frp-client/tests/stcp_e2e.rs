mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use common::{allocate_port, start_echo_server, start_frps, wait_for_port};

/// End-to-end STCP relay test:
/// 1. Start echo server (provider's local service)
/// 2. Start frps server
/// 3. Start frpc provider (registers STCP proxy with sk)
/// 4. Start frpc visitor (binds local port, tunnels via server to provider)
/// 5. Connect to visitor's local port, send data, verify echo
#[tokio::test]
async fn test_stcp_e2e_relay() {
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let visitor_port = allocate_port();

    let stcp_name = "stcp-echo";
    let stcp_sk = "e2e-stcp-secret";

    // 1. Start echo server
    let _echo_handle = start_echo_server(echo_port);

    // 2. Start frps
    let _server_handle = start_frps(server_port, "test-token").await;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server port ready");

    // 3. Start frpc provider (STCP proxy + visitor in same process)
    let provider_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2, // pre-spawn work connections for the STCP relay
        proxies: vec![ProxyConfig {
            name: stcp_name.into(),
            proxy_type: "stcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: 0, // STCP doesn't use a real port (no listener)
            sk: stcp_sk.into(),
            use_encryption: false,
            use_compression: false,
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
            advertise_subnet: String::new(),
            vnet_ip: String::new(),
            vnet_netmask: String::new(),
            vnet_mtu: 1420,
            health_check_http_headers: std::collections::HashMap::new(),
            proxy_protocol_version: String::new(),
            enabled: true,
            plugin: None,
        }],
        visitors: vec![VisitorConfig {
            name: "stcp-visitor".into(),
            visitor_type: "stcp".into(),
            server_name: stcp_name.into(),
            secret_key: stcp_sk.into(),
            server_user: String::new(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port,
            fallback_to: String::new(),
            fallback_timeout_ms: 5000,
            disable_assisted_addrs: false,
            use_encryption: false,
            use_compression: false,
            keep_tunnel_open: false,
            max_retries_an_hour: 0,
            min_retry_interval: 0,
        }],
        ..Default::default()
    };

    let provider_service = ClientService::new(provider_cfg, None)
        .await
        .expect("create client");
    let _client_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });

    // 4. Wait for visitor port to become connectable
    let visitor_addr: SocketAddr = format!("127.0.0.1:{}", visitor_port).parse().unwrap();
    wait_for_port(visitor_addr, Duration::from_secs(10))
        .await
        .expect("visitor port ready");

    // 5. Connect to visitor and verify data roundtrip
    let mut stream = tokio::net::TcpStream::connect(visitor_addr)
        .await
        .expect("connect to visitor");

    let payload = b"hello from STCP relay\n";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read");

    assert_eq!(&buf, payload, "echo through STCP relay should match");

    // Cleanup
    drop(stream);
}
