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
//!
//! Go v0.71.1 regression (`71b3197`, e2e "Server Bandwidth Limit closes work
//! connection when user disconnects"): a server-side limiter must NOT keep
//! the work connection open after the user closes. frp-rs has no limiter
//! wrapper type — the bucket is a parameter threaded into
//! `bridge_plain_rate_limited` — so the Go bug (a `Close` closure that
//! re-enters the wrapper it was just installed on) is structurally absent.
//! `server_bandwidth_limit_closes_work_conn_when_user_closes` below pins the
//! teardown invariant end-to-end so a future refactor that introduces a
//! transport-layer wrapper cannot silently recreate it.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
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

/// Start frps + a single frpc with one TCP proxy pointing at `echo_port`,
/// and wait for the tunnel. Returns the public proxy address on frps.
///
/// The local backend is the caller's responsibility: the rate tests use
/// [`start_echo_server`], the teardown test installs a backend that reports
/// when its connection closes. Binding the backend before this call keeps a
/// backend failure ("address already in use") distinct from a wedged tunnel.
async fn start_stack_with_backend(
    server_port: u16,
    echo_port: u16,
    tcp_port: u16,
    bw: &str,
    mode: &str,
) -> SocketAddr {
    common::init_tracing();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    start_frps(server_port, "test-token").await;
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

/// [`start_stack_with_backend`] over the readiness-only echo backend.
async fn start_stack(
    server_port: u16,
    echo_port: u16,
    tcp_port: u16,
    bw: &str,
    mode: &str,
) -> SocketAddr {
    start_echo_server(echo_port);
    start_stack_with_backend(server_port, echo_port, tcp_port, bw, mode).await
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

/// A backend connection that the peer closed after the first message.
/// `first_message` identifies which connection closed: every tunnel probe
/// carries a different token, so a warm-up probe's close can never be
/// mistaken for the connection under test.
#[derive(Debug)]
struct BackendClosed {
    first_message: Vec<u8>,
}

/// Local TCP backend shaped like upstream's v0.71.1 e2e local server: echo
/// the first message, then drain the socket until the peer closes it, and
/// report that close on the returned channel.
///
/// The listener is bound before this function returns, so a bind failure is
/// the test's failure (not a silently wedged tunnel), and the backend is
/// ready before frpc can dial it.
async fn start_close_reporting_echo(port: u16) -> mpsc::UnboundedReceiver<BackendClosed> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("close-reporting echo bind");
    let (closed_tx, closed_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let closed_tx = closed_tx.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let first_message = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                        buf[..n].to_vec()
                    }
                };
                // Drain until the peer closes. A read error (RST) is not the
                // clean close this backend reports; only EOF is.
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
                let _ = stream.shutdown().await;
                let _ = closed_tx.send(BackendClosed { first_message });
            });
        }
    });
    closed_rx
}

/// Like [`connect_tunnel`], but returns the unique token this round trip
/// carried so the matching [`BackendClosed`] report can be recognised.
///
/// A retry that never completes its echo uses a token that never matches, so
/// the previous attempt's eventual close cannot satisfy the assertion.
async fn connect_tunnel_token(addr: SocketAddr) -> Result<(TcpStream, Vec<u8>), String> {
    let start = Instant::now();
    let mut attempt = 0u32;
    while start.elapsed() < Duration::from_secs(10) {
        let token = format!("tcp-bandwidth-teardown-{attempt}").into_bytes();
        attempt += 1;
        if let Ok(mut stream) = TcpStream::connect(addr).await {
            if stream.write_all(&token).await.is_ok() {
                let mut echo = vec![0u8; token.len()];
                let echoed = timeout(Duration::from_secs(1), stream.read_exact(&mut echo))
                    .await
                    .map(|r| r.map(|_| ()))
                    .is_ok();
                if echoed && echo == token {
                    return Ok((stream, token));
                }
            }
            // Tunnel not bridged yet (or a half-open conn) — retry with a
            // fresh token.
            let _ = stream.shutdown().await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("TCP tunnel not ready within timeout".into())
}

/// Go v0.71.1 regression (upstream `71b3197`, e2e "Server Bandwidth Limit
/// closes work connection when user disconnects"): a server-side bandwidth
/// limiter must not keep a work connection open after the user closes.
///
/// frp-rs's limiter is a parameter threaded into the bridge, and half-close
/// is the explicit `shutdown_bridge` → `w.shutdown()` (the work conn is
/// released by single-ownership drop, never by a close callback), so the Go
/// bug cannot exist while that shape holds. This test pins the observable
/// end-to-end: with `bandwidth_limit = "10MB"` and
/// `bandwidth_limit_mode = "server"`, the user's FIN must reach the local
/// backend through the rate-limited bridge.
///
/// Oracle: the backend (frpc's local dial target) sees EOF within 5 s of the
/// user closing. If a limiter wrapper swallowed the close — the Go defect —
/// the work conn would never half-close, the EOF would never propagate, and
/// the bridge would park forever; the wait times out instead.
#[tokio::test]
async fn server_bandwidth_limit_closes_work_conn_when_user_closes() {
    let server_port = allocate_port();
    let tcp_port = allocate_port();
    let echo_port = allocate_port();

    // Backend first (bound eagerly), then the stack that dials it.
    let mut closed_rx = start_close_reporting_echo(echo_port).await;
    let addr = start_stack_with_backend(server_port, echo_port, tcp_port, "10MB", "server").await;
    let (mut stream, token) = connect_tunnel_token(addr).await.expect("tunnel ready");

    // The user closes its side while the server-side 10 MB/s (i.e. 10 MiB/s)
    // bucket is active for this proxy. Keep the socket alive across the
    // assertion: a clean FIN, not an RST from dropping unread data.
    stream.shutdown().await.expect("shutdown user conn");

    // 5 s mirrors upstream's bound. The failure mode is an unbounded park
    // (the bridge join never observes EOF), while the healthy path is a
    // loopback FIN round trip — ~ms, two-plus orders of magnitude inside the
    // bound, so a loaded CI host has ample headroom.
    let closed = timeout(Duration::from_secs(5), async {
        while let Some(closed) = closed_rx.recv().await {
            if closed.first_message == token {
                return closed;
            }
        }
        panic!("backend close-report channel closed before the conn under test closed");
    })
    .await
    .expect(
        "local backend never observed EOF 5 s after the user closed — the \
         server-side bandwidth limiter kept the work conn open (Go v0.71.1 \
         `71b3197` regression)",
    );

    assert_eq!(
        closed.first_message, token,
        "the closed backend conn must be the one the test drove"
    );
    drop(stream);
}
