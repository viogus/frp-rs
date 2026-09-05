//! E2E pins for the TCP proxy `bandwidth_limit` path (audit round 8, G5).
//!
//! The UDP path had three real-rate e2e tests while every TCP e2e config left
//! `bandwidth_limit` unset — the TCP bridge's shared-bucket wiring was never
//! exercised at a measurable rate. This file mirrors the udp_bandwidth.rs
//! harness structure over the TCP echo path: frps + one frpc with a single
//! TCP proxy, a real-rate payload round trip, and a floor assertion on the
//! elapsed time.
//!
//! Go v0.71.0 semantics (F1/F2): `bandwidthLimitMode` picks the SIDE that
//! owns the per-proxy shared limiter — ONE token bucket covering BOTH bridge
//! directions and ALL concurrent connections of the proxy (a single
//! `*rate.Limiter` wired into `limit.NewReader` AND `limit.NewWriter`). With
//! `"server"` only the server creates it; with `"client"` only the client.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig};

use common::{allocate_port, start_echo_server, start_frps, wait_for_port};

/// Build a TCP proxy config. `bw` empty → no bandwidth limit (default).
fn tcp_proxy(name: &str, local_port: u16, remote_port: u16, bw: &str, mode: &str) -> ProxyConfig {
    ProxyConfig {
        name: name.into(),
        proxy_type: "tcp".into(),
        local_ip: "127.0.0.1".into(),
        local_port,
        remote_port,
        enabled: true,
        bandwidth_limit: bw.into(),
        bandwidth_limit_mode: mode.into(),
        ..Default::default()
    }
}

/// Start frps + a single frpc with one TCP proxy and wait for the tunnel.
/// Returns the public proxy address on frps.
async fn start_stack(
    server_port: u16,
    echo_port: u16,
    tcp_port: u16,
    bw: &str,
    mode: &str,
) -> SocketAddr {
    common::init_tracing();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    start_frps(server_port, "test-token").await;
    start_echo_server(echo_port);
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
        proxies: vec![tcp_proxy("tcp-echo", echo_port, tcp_port, bw, mode)],
        ..Default::default()
    };
    let client_service = ClientService::new(client_cfg, None)
        .await
        .expect("create client service");
    tokio::spawn(async move {
        let _ = client_service.run().await;
    });

    format!("127.0.0.1:{}", tcp_port).parse().unwrap()
}

/// Connect to the proxy and push a small probe through until the tunnel is
/// up (the first connection lazily assigns a work conn, so earlier probes
/// may stall). Returns the warmed stream.
async fn connect_tunnel(addr: SocketAddr) -> Result<TcpStream, String> {
    let start = Instant::now();
    let mut buf = [0u8; 16];
    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(mut stream) = TcpStream::connect(addr).await {
            let _ = stream.write_all(b"probe").await;
            let echoed = timeout(Duration::from_millis(400), stream.read_exact(&mut buf[..5]))
                .await
                .map(|r| r.map(|_| ()))
                .is_ok();
            if echoed && &buf[..5] == b"probe" {
                return Ok(stream);
            }
            // Tunnel not bridged yet (or a half-open conn) — retry.
            let _ = stream.shutdown().await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("TCP tunnel not ready within timeout".into())
}

/// One full round trip over the warmed stream: `payload` bytes echoed back.
/// Returns (bytes echoed, elapsed to echo completion).
async fn tcp_roundtrip(stream: &mut TcpStream, payload: &[u8]) -> (usize, Duration) {
    let start = Instant::now();
    stream
        .write_all(payload)
        .await
        .expect("write payload to proxy");
    let mut echo = vec![0u8; payload.len()];
    let n = timeout(Duration::from_secs(30), stream.read_exact(&mut echo))
        .await
        .expect("echo timed out — tunnel wedged?")
        .expect("read echo");
    assert_eq!(
        n,
        payload.len(),
        "read_exact on an echoed payload must fill the buffer"
    );
    (echo.len(), start.elapsed())
}

/// `bandwidthLimit = "4KB"` with `bandwidthLimitMode = "server"` throttles a
/// TCP round trip: the 8 KiB payload + 8 KiB echo both flow through the
/// server's single 4 KiB/s shared bucket. Earliest possible completion is
/// (2 × 8192 − 4096 burst) / 4096 ≈ 3.0 s; the 2.5 s floor sits below that
/// physical minimum (the unlimited path clears in well under 1 s), so the
/// assertion cannot race timing jitter.
#[tokio::test]
async fn tcp_bandwidth_limits_server_mode() {
    let server_port = allocate_port();
    let tcp_port = allocate_port();
    let echo_port = allocate_port();
    let addr = start_stack(server_port, echo_port, tcp_port, "4KB", "server").await;
    let mut stream = connect_tunnel(addr).await.expect("tunnel ready");

    let payload = [0xCDu8; 8192];
    let (received, elapsed) = tcp_roundtrip(&mut stream, &payload).await;
    assert_eq!(received, payload.len(), "echo payload mismatch");
    assert!(
        elapsed >= Duration::from_millis(2500),
        "16 KiB round trip at 4 KiB/s (server bucket) should be throttled, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "expected ~3 s, took {elapsed:?} — pathologically slow"
    );
}

/// `bandwidthLimitMode = "client"` throttles on frpc: the client's per-proxy
/// 4 KiB/s shared bucket gates the whole round trip (request + echo legs
/// both consume from it). Same floor math as the server-mode test.
#[tokio::test]
async fn tcp_bandwidth_limits_client_mode() {
    let server_port = allocate_port();
    let tcp_port = allocate_port();
    let echo_port = allocate_port();
    let addr = start_stack(server_port, echo_port, tcp_port, "4KB", "client").await;
    let mut stream = connect_tunnel(addr).await.expect("tunnel ready");

    let payload = [0xABu8; 8192];
    let (received, elapsed) = tcp_roundtrip(&mut stream, &payload).await;
    assert_eq!(received, payload.len(), "echo payload mismatch");
    assert!(
        elapsed >= Duration::from_millis(2500),
        "16 KiB round trip at 4 KiB/s (client bucket) should be throttled, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "expected ~3 s, took {elapsed:?} — pathologically slow"
    );
}
