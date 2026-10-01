#![cfg(all(feature = "websocket", feature = "tcp-mux"))]
//! Rust↔Rust in-process e2e for the **dedicated** `websocket_port` listener.
//!
//! `ServerConfig::websocket_port` defaults to 0 (`frp-core/src/config/server.rs`),
//! so the block extracted into `frp-server/src/service/listeners.rs`
//! (`Service::start_websocket_listener`) is skipped entirely unless a test sets
//! the port explicitly. Nothing did: the `websocket` rows in
//! `scripts/compat-test.sh` point the client at the *main* bind port, which is
//! served by `Service::run`'s own transport detection
//! (`frp-server/src/handlers/transport.rs`), never by the dedicated listener.
//! This file is the regression net for that seam.
//!
//! Skeleton (in-process frps + in-process frpc, one tcp proxy, byte-exact echo
//! round-trip over the proxy port) mirrors `transport_e2e_kcp.rs`:
//!   (a) dedicated WS port, `tcp_mux=false` — control + work conns are plain
//!       V1 frames over the upgraded WebSocket stream;
//!   (b) dedicated WS port, `tcp_mux=true` — yamux streams multiplexed over
//!       the upgraded WebSocket stream.
//!
//! The client dials `server_port = websocket_port`, a port distinct from
//! `bind_port`, so a listener that never starts cannot be masked by the main
//! accept loop.
//!
//! Run: cargo test -p frp-server --test transport_e2e_websocket_port

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use frp_client::service::Service as ClientService;
use frp_core::config::{AuthServerConfig, ClientConfig, ProxyConfig, ServerConfig};

use common::{allocate_port, start_test_server, start_test_server_tcpmux_on};

/// Simple TCP echo server: copies every accepted connection bidirectionally.
fn start_echo_server(port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("echo server bind");
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    })
}

/// Poll TCP-connect until the port accepts or the timeout elapses.
///
/// Used for the dedicated `websocket_port` itself: `start_test_server` only
/// waits for `bind_port`, so this is also the assertion that fails — loudly and
/// directly — when `start_websocket_listener` is entered but does not bind.
async fn wait_for_port(port: u16, what: &str, timeout: Duration) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let start = std::time::Instant::now();
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "{what} {port} did not accept connections within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Deterministic pseudo-random bytes (xorshift64) — exercises the bridge with
/// incompressible-looking data without a rand dev-dep.
fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Byte-exact echo round-trip through the proxy port, bounded by timeouts
/// (no wall-clock races): connect, write `payload`, read the echo back in
/// chunks, assert equality.
async fn echo_round_trip(proxy_port: u16, payload: &[u8]) {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(15),
        TcpStream::connect(("127.0.0.1", proxy_port)),
    )
    .await
    .expect("connect to proxy port timed out")
    .expect("connect to proxy port");

    tokio::time::timeout(Duration::from_secs(15), stream.write_all(payload))
        .await
        .expect("write to proxy timed out")
        .expect("write to proxy");
    stream.flush().await.expect("flush");

    let mut got = Vec::with_capacity(payload.len());
    let mut buf = [0u8; 16384];
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let n = stream.read(&mut buf).await.expect("read echo");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.len() >= payload.len() {
                break;
            }
        }
    })
    .await
    .expect("echo read timed out");
    assert_eq!(
        got.len(),
        payload.len(),
        "echo returned {} bytes, expected {}",
        got.len(),
        payload.len()
    );
    assert_eq!(
        got, payload,
        "echo through the WebSocket tunnel must be byte-exact"
    );
}

/// `bind_port` and `websocket_port` are deliberately different ports.
fn server_cfg(server_port: u16, websocket_port: u16, token: &str) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        websocket_port,
        auth: AuthServerConfig {
            method: "token".into(),
            token: token.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The client's `server_port` is the **dedicated WebSocket port**, not
/// `bind_port`, and `tls_enable=false` keeps it on the plain `ws://` arm
/// (`tls_enable=true` would demand the WSS arm).
fn client_cfg(
    websocket_port: u16,
    token: &str,
    tcp_mux: bool,
    proxy_port: u16,
    echo_port: u16,
) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: websocket_port,
        transport_protocol: "websocket".into(),
        token: token.into(),
        login_fail_exit: false,
        pool_count: 1,
        tcp_mux,
        tls_enable: false,
        proxies: vec![ProxyConfig {
            name: "ws-dedicated-port-e2e".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: proxy_port,
            use_encryption: false,
            use_compression: false,
            sk: String::new(),
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Shared skeleton for the two dedicated-`websocket_port` variants.
async fn run_dedicated_websocket_port_e2e(tcp_mux: bool, token: &str) {
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let ws_port = allocate_port();
    let proxy_port = allocate_port();
    assert_ne!(
        server_port, ws_port,
        "the dedicated WebSocket port must be distinct from bind_port or this \
         test cannot tell the extracted listener apart from run()'s own \
         transport detection"
    );

    let _echo = start_echo_server(echo_port);

    // In-process frps with the dedicated WebSocket port configured. The
    // harness polls only `bind_port` for readiness, so wait for the WebSocket
    // port itself before dialling it.
    let mut cfg = server_cfg(server_port, ws_port, token);
    cfg.transport.tcp_mux = Some(tcp_mux);
    let (server_handle, _bind_port) = if tcp_mux {
        start_test_server_tcpmux_on(cfg).await
    } else {
        start_test_server(cfg).await
    };
    wait_for_port(
        ws_port,
        "dedicated WebSocket listener",
        Duration::from_secs(10),
    )
    .await;

    // In-process frpc, dialling the dedicated WebSocket port.
    let client = Arc::new(
        ClientService::new(
            client_cfg(ws_port, token, tcp_mux, proxy_port, echo_port),
            None,
        )
        .await
        .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // The proxy is registered (login over the WebSocket control stream) and
    // listening, then round-trip.
    wait_for_port(proxy_port, "proxied remote port", Duration::from_secs(10)).await;

    let payload = pseudo_random_bytes(256 * 1024);
    echo_round_trip(proxy_port, &payload).await;
    // Second round-trip on a fresh connection: the tunnel is stable, not a
    // one-shot.
    let payload2 = pseudo_random_bytes(64 * 1024);
    echo_round_trip(proxy_port, &payload2).await;

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    server_handle.abort();
    _echo.abort();
}

/// (a) Dedicated `websocket_port`, `tcp_mux=false`: control + work conns are
/// plain V1 frames over the upgraded WebSocket stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_dedicated_port_plain_echo() {
    run_dedicated_websocket_port_e2e(false, "ws-dedicated-plain-e2e-token").await;
}

/// (b) Dedicated `websocket_port`, `tcp_mux=true`: yamux streams ride the
/// upgraded WebSocket stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_dedicated_port_yamux_echo() {
    run_dedicated_websocket_port_e2e(true, "ws-dedicated-yamux-e2e-token").await;
}
