mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig};

use common::{allocate_port, allocate_udp_port, start_frps, start_udp_echo_server, wait_for_port};

/// Build a UDP proxy config. `bw` empty → no bandwidth limit (default).
fn udp_proxy(name: &str, local_port: u16, remote_port: u16, bw: &str, mode: &str) -> ProxyConfig {
    ProxyConfig {
        name: name.into(),
        proxy_type: "udp".into(),
        local_ip: "127.0.0.1".into(),
        local_port,
        remote_port,
        enabled: true,
        bandwidth_limit: bw.into(),
        bandwidth_limit_mode: mode.into(),
        ..Default::default()
    }
}

/// Start frps + a single frpc with one UDP proxy and wait for the tunnel.
/// Returns the UDP proxy target (frps's UDP listener) and a probe socket.
async fn start_stack(
    server_port: u16,
    echo_port: u16,
    udp_port: u16,
    bw: &str,
    mode: &str,
) -> (SocketAddr, UdpSocket) {
    common::init_tracing();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    start_frps(server_port, "test-token").await;
    start_udp_echo_server(echo_port);
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
        proxies: vec![udp_proxy("udp-echo", echo_port, udp_port, bw, mode)],
        ..Default::default()
    };
    let client_service = ClientService::new(client_cfg, None)
        .await
        .expect("create client service");
    tokio::spawn(async move {
        let _ = client_service.run().await;
    });

    let target: SocketAddr = format!("127.0.0.1:{}", udp_port).parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind probe socket");
    (target, sock)
}

/// Fire small probes until the UDP tunnel is up (the first datagram lazily
/// triggers the work-conn bridge, so earlier probes may be dropped).
async fn wait_for_udp_tunnel(sock: &UdpSocket, target: SocketAddr) -> Result<(), String> {
    let start = Instant::now();
    let mut buf = [0u8; 2048];
    while start.elapsed() < Duration::from_secs(10) {
        let _ = sock.send_to(b"probe", target).await;
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await
        {
            if n > 0 {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("UDP tunnel not ready within timeout".into())
}

/// Fire `count` copies of `payload` back-to-back and collect the echoes.
/// Returns (total payload bytes echoed, elapsed). Only datagrams of exactly
/// `payload.len()` are counted — a stale 5-byte "probe" echo lingering from
/// `wait_for_udp_tunnel` (a probe can be echoed after its own recv window
/// timed out) is skipped, so the byte-count assertion cannot race the
/// tunnel warm-up. Packet size stays under the udp_packet_size cap (Go
/// default 1500), so nothing is truncated.
async fn udp_burst(
    sock: &UdpSocket,
    target: SocketAddr,
    payload: &[u8],
    count: usize,
) -> (usize, Duration) {
    let start = Instant::now();
    for _ in 0..count {
        sock.send_to(payload, target).await.expect("send datagram");
    }
    let mut received = 0usize;
    let mut echoes = 0usize;
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(20);
    while echoes < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n == payload.len() => {
                echoes += 1;
                received += n;
            }
            Ok(Ok(_)) => continue, // stale probe echo or partial — skip
            _ => break,
        }
    }
    assert_eq!(
        echoes,
        count,
        "expected {count} echoes of {} bytes, got {echoes}",
        payload.len()
    );
    (received, start.elapsed())
}

/// Default is unlimited: an 8 KiB round trip passes through fast even though
/// a limiter exists in the code path (it is not instantiated without a rate).
#[tokio::test]
async fn udp_unlimited_by_default() {
    let server_port = allocate_port();
    let udp_port = allocate_udp_port();
    let echo_port = allocate_udp_port();
    let (target, sock) = start_stack(server_port, echo_port, udp_port, "", "").await;
    wait_for_udp_tunnel(&sock, target)
        .await
        .expect("tunnel ready");

    // 12 × 1400 B = 16.8 KiB aggregate — well above any single-packet cap.
    let payload = [0xCDu8; 1400];
    let (received, elapsed) = udp_burst(&sock, target, &payload, 12).await;
    assert_eq!(received, 12 * payload.len(), "echo payload mismatch");
    assert!(
        elapsed < Duration::from_millis(1500),
        "unlimited UDP should be fast, took {elapsed:?}"
    );
}

/// Explicit `bandwidthLimit = "4KB"` with `bandwidthLimitMode = "server"`
/// throttles the tunnel: an 8 KiB round trip must take well over a second
/// (the server applies a two-direction limiter; the client applies its read
/// direction for server mode) while still delivering the payload intact.
#[tokio::test]
async fn udp_bandwidth_limits_server_mode() {
    let server_port = allocate_port();
    let udp_port = allocate_udp_port();
    let echo_port = allocate_udp_port();
    let (target, sock) = start_stack(server_port, echo_port, udp_port, "4KB", "server").await;
    wait_for_udp_tunnel(&sock, target)
        .await
        .expect("tunnel ready");

    // 12 × 1400 B = 16.8 KiB aggregate through a 4 KiB/s server-mode
    // limiter. The limiting directions (server writer + client read limiter
    // on the way in, server reader on the echo back) are pipelined, not
    // serial — measured ~1.75 s for 8 packets, ~3+ s for 12. The >= 2 s
    // floor has ample headroom while the unlimited path completes in
    // < 1.5 s, so the two tests cannot cross.
    let payload = [0xABu8; 1400];
    let (received, elapsed) = udp_burst(&sock, target, &payload, 12).await;
    assert_eq!(received, 12 * payload.len(), "echo payload mismatch");
    assert!(
        elapsed >= Duration::from_millis(2000),
        "16.8 KiB at 4 KiB/s should be throttled, took {elapsed:?}"
    );
}

/// `bandwidthLimitMode = "client"` throttles upload on frpc: the echo path
/// (local service → work conn → server → external client) crosses the
/// client's write limiter, so the round trip is throttled while the server
/// applies no limiter of its own.
#[tokio::test]
async fn udp_bandwidth_limits_client_mode() {
    let server_port = allocate_port();
    let udp_port = allocate_udp_port();
    let echo_port = allocate_udp_port();
    let (target, sock) = start_stack(server_port, echo_port, udp_port, "4KB", "client").await;
    wait_for_udp_tunnel(&sock, target)
        .await
        .expect("tunnel ready");

    let payload = [0x11u8; 1400];
    let (received, elapsed) = udp_burst(&sock, target, &payload, 12).await;
    assert_eq!(received, 12 * payload.len(), "echo payload mismatch");
    assert!(
        elapsed >= Duration::from_millis(2000),
        "16.8 KiB upload at 4 KiB/s should be throttled, took {elapsed:?}"
    );
}
