mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use common::{allocate_port, allocate_udp_port, start_frps, start_udp_echo_server, wait_for_port};

/// Build a SUDP provider proxy config pointing at the given local UDP service.
fn sudp_proxy(name: &str, local_port: u16) -> ProxyConfig {
    ProxyConfig {
        name: name.into(),
        proxy_type: "sudp".into(),
        local_ip: "127.0.0.1".into(),
        local_port,
        remote_port: 0, // SUDP has no remote listener port
        enabled: true,
        sk: "test-sudp-sk".into(), // SUDP requires a shared secret key
        use_encryption: false,
        use_compression: false,
        ..Default::default()
    }
}

/// Build a SUDP visitor config binding the given local UDP port.
fn sudp_visitor(name: &str, server_name: &str, bind_port: u16) -> VisitorConfig {
    VisitorConfig {
        name: name.into(),
        visitor_type: "sudp".into(),
        server_name: server_name.into(),
        secret_key: "test-sudp-sk".into(), // must match the proxy's sk
        bind_addr: "127.0.0.1".into(),
        bind_port: bind_port as i32,
        enabled: true,
        use_encryption: false,
        use_compression: false,
        ..Default::default()
    }
}

/// Fire "probe" datagrams at `target` until one is echoed back (the SUDP
/// tunnel is lazily established by the first datagram, so earlier probes may
/// be dropped while the NewVisitorConn handshake / provider work-conn bridge
/// is being set up).
async fn wait_for_udp_tunnel(
    sock: &UdpSocket,
    target: SocketAddr,
    timeout_dur: Duration,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let mut buf = [0u8; 2048];
    while start.elapsed() < timeout_dur {
        let _ = sock.send_to(b"probe", target).await;
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await
        {
            if n > 0 {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("SUDP tunnel not ready within timeout".into())
}

/// Send `payload` to `target` and assert the echoed reply equals it.
async fn udp_roundtrip(sock: &UdpSocket, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    sock.send_to(payload, target).await.expect("send datagram");
    let mut buf = vec![0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply timed out")
        .expect("recv reply");
    buf[..n].to_vec()
}

/// Start frps + a single frpc carrying both the SUDP provider proxy and the
/// SUDP visitor (mirrors stcp_e2e.rs).
async fn start_stack(server_port: u16, echo_port: u16, visitor_port: u16) {
    common::init_tracing();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server port ready");

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2,
        proxies: vec![sudp_proxy("sudp-echo", echo_port)],
        visitors: vec![sudp_visitor("sudp-visitor", "sudp-echo", visitor_port)],
        ..Default::default()
    };
    let client_service = ClientService::new(client_cfg, None)
        .await
        .expect("create client service");
    tokio::spawn(async move {
        let _ = client_service.run().await;
    });
}

/// End-to-end SUDP relay test:
/// 1. Start a UDP echo server (provider's local service)
/// 2. Start frps
/// 3. Start frpc registering a SUDP proxy (with local UDP socket bridged)
///    and a SUDP visitor binding a local UDP port
/// 4. Send a datagram to the visitor's port and verify the echo comes back
#[tokio::test]
async fn test_sudp_e2e_roundtrip() {
    let echo_port = allocate_udp_port();
    let server_port = allocate_port();
    let visitor_port = allocate_udp_port();

    let _echo_handle = start_udp_echo_server(echo_port);
    let _server_handle = start_frps(server_port, "test-token").await;
    start_stack(server_port, echo_port, visitor_port).await;

    let visitor_addr: SocketAddr = format!("127.0.0.1:{}", visitor_port).parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    wait_for_udp_tunnel(&client, visitor_addr, Duration::from_secs(15))
        .await
        .expect("SUDP tunnel ready");

    // Verify the actual data roundtrip matches byte-for-byte.
    let payloads: &[&[u8]] = &[
        b"hello from SUDP visitor",
        b"second datagram with a slightly longer payload to exercise framing",
        b"1234567890",
    ];
    for payload in payloads {
        let reply = udp_roundtrip(&client, visitor_addr, payload).await;
        assert_eq!(&reply, *payload, "echo through SUDP relay should match");
    }
}

/// Go-parity three-segment encryption: `use_encryption=true` on the SUDP
/// proxy + visitor must produce a working tunnel (visitor segment encrypted
/// with sk, provider segment with the auth token; server joins them in the
/// middle). The data plane must roundtrip byte-for-byte — ciphertext never
/// leaks to the local UDP client.
#[tokio::test]
async fn test_sudp_e2e_encrypted_roundtrip() {
    let echo_port = allocate_udp_port();
    let server_port = allocate_port();
    let visitor_port = allocate_udp_port();

    let _echo_handle = start_udp_echo_server(echo_port);
    let _server_handle = start_frps(server_port, "test-token").await;

    common::init_tracing();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server port ready");

    // Both sides configured with use_encryption=true (and compression).
    let mut proxy = sudp_proxy("sudp-echo", echo_port);
    proxy.use_encryption = true;
    proxy.use_compression = true;
    let mut visitor = sudp_visitor("sudp-visitor", "sudp-echo", visitor_port);
    visitor.use_encryption = true;
    visitor.use_compression = true;

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2,
        proxies: vec![proxy],
        visitors: vec![visitor],
        ..Default::default()
    };
    let client_service = ClientService::new(client_cfg, None)
        .await
        .expect("create client service");
    tokio::spawn(async move {
        let _ = client_service.run().await;
    });

    let visitor_addr: SocketAddr = format!("127.0.0.1:{}", visitor_port).parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    wait_for_udp_tunnel(&client, visitor_addr, Duration::from_secs(15))
        .await
        .expect("SUDP tunnel ready");

    // Payload must survive the relay byte-for-byte with encryption enabled
    // (both segments encrypted end-to-end, symmetric on both sides).
    let payload = b"encrypted-roundtrip-must-not-corrupt";
    let reply = udp_roundtrip(&client, visitor_addr, payload).await;
    assert_eq!(
        &reply, payload,
        "encrypted SUDP data plane must roundtrip without corruption"
    );
}

/// Go-parity three-segment compression only (no encryption): `use_compression=true`
/// on the SUDP proxy + visitor must produce a working tunnel (visitor segment
/// compressed with a Snappy stream, provider segment with the per-packet
/// compressor). The data plane must roundtrip byte-for-byte.
#[tokio::test]
async fn test_sudp_e2e_compressed_roundtrip() {
    let echo_port = allocate_udp_port();
    let server_port = allocate_port();
    let visitor_port = allocate_udp_port();

    let _echo_handle = start_udp_echo_server(echo_port);
    let _server_handle = start_frps(server_port, "test-token").await;

    common::init_tracing();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server port ready");

    // Both sides configured with use_compression=true (no encryption).
    let mut proxy = sudp_proxy("sudp-echo", echo_port);
    proxy.use_compression = true;
    let mut visitor = sudp_visitor("sudp-visitor", "sudp-echo", visitor_port);
    visitor.use_compression = true;

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2,
        proxies: vec![proxy],
        visitors: vec![visitor],
        ..Default::default()
    };
    let client_service = ClientService::new(client_cfg, None)
        .await
        .expect("create client service");
    tokio::spawn(async move {
        let _ = client_service.run().await;
    });

    let visitor_addr: SocketAddr = format!("127.0.0.1:{}", visitor_port).parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    wait_for_udp_tunnel(&client, visitor_addr, Duration::from_secs(15))
        .await
        .expect("SUDP tunnel ready");

    // Payload must survive the relay byte-for-byte with compression enabled
    // (a repetitive payload exercises the snappy fast path on both segments).
    // Kept under the UDP data-plane packet limit (udpPacketSize, default
    // 1500) — larger datagrams are truncated by the provider's recv buffer,
    // independent of compression.
    let payload = vec![0x41u8; 1024]; // highly compressible
    let reply = udp_roundtrip(&client, visitor_addr, &payload).await;
    assert_eq!(
        &reply, &payload,
        "compressed SUDP data plane must roundtrip without corruption"
    );
}

/// Multiple local UDP clients (different source addresses) share the single
/// visitor socket; each reply must be routed back to the datagram's origin.
#[tokio::test]
async fn test_sudp_e2e_multiple_clients() {
    let echo_port = allocate_udp_port();
    let server_port = allocate_port();
    let visitor_port = allocate_udp_port();

    let _echo_handle = start_udp_echo_server(echo_port);
    let _server_handle = start_frps(server_port, "test-token").await;
    start_stack(server_port, echo_port, visitor_port).await;

    let visitor_addr: SocketAddr = format!("127.0.0.1:{}", visitor_port).parse().unwrap();
    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("bind client A");
    wait_for_udp_tunnel(&client_a, visitor_addr, Duration::from_secs(15))
        .await
        .expect("SUDP tunnel ready");
    let client_b = UdpSocket::bind("127.0.0.1:0").await.expect("bind client B");

    // Interleaved ping-pong: each client sends its own payload and must get
    // exactly its own payload back (routing keyed by datagram source address).
    for i in 0..5u8 {
        let pa = format!("client-A-msg-{i}").into_bytes();
        let pb = format!("client-B-msg-{i}").into_bytes();
        let reply_a = udp_roundtrip(&client_a, visitor_addr, &pa).await;
        let reply_b = udp_roundtrip(&client_b, visitor_addr, &pb).await;
        assert_eq!(reply_a, pa, "client A echo should match its own payload");
        assert_eq!(reply_b, pb, "client B echo should match its own payload");
    }
}

/// The visitor tunnel is lazy and self-healing: after the provider's work
/// connection is torn down, the next datagram re-establishes the tunnel.
#[tokio::test]
async fn test_sudp_e2e_reconnect() {
    let echo_port = allocate_udp_port();
    let server_port = allocate_port();
    let visitor_port = allocate_udp_port();

    let _echo_handle = start_udp_echo_server(echo_port);
    let _server_handle = start_frps(server_port, "test-token").await;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server port ready");

    // Provider and visitor run in separate frpc processes (tasks).
    let provider_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2,
        proxies: vec![sudp_proxy("sudp-echo", echo_port)],
        ..Default::default()
    };
    let provider_service = ClientService::new(provider_cfg.clone(), None)
        .await
        .expect("create provider client");
    let provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });

    let visitor_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 0,
        visitors: vec![sudp_visitor("sudp-visitor", "sudp-echo", visitor_port)],
        ..Default::default()
    };
    let visitor_service = ClientService::new(visitor_cfg, None)
        .await
        .expect("create visitor client");
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });

    let visitor_addr: SocketAddr = format!("127.0.0.1:{}", visitor_port).parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    wait_for_udp_tunnel(&client, visitor_addr, Duration::from_secs(15))
        .await
        .expect("SUDP tunnel ready before kill");

    let before = udp_roundtrip(&client, visitor_addr, b"before-kill").await;
    assert_eq!(before, b"before-kill".to_vec());

    // Kill the provider: its control connection and work conns drop, which
    // tears down the bridge. Packets sent now are dropped.
    provider_handle.abort();
    let _ = provider_handle.await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restart the provider with the same proxy config; the next datagram must
    // re-establish the tunnel automatically.
    let provider_service2 = ClientService::new(provider_cfg, None)
        .await
        .expect("recreate provider client");
    let _provider_handle2 = tokio::spawn(async move {
        let _ = provider_service2.run().await;
    });

    wait_for_udp_tunnel(&client, visitor_addr, Duration::from_secs(15))
        .await
        .expect("SUDP tunnel ready after restart");

    let after = udp_roundtrip(&client, visitor_addr, b"after-restart").await;
    assert_eq!(after, b"after-restart".to_vec());
}
