#![cfg(feature = "kcp")]
//! Rust↔Rust in-process e2e for the KCP transport combos.
//!
//! These combinations previously had local coverage only via the compat
//! script (which needs a pre-built frps/frpc and, for Go-side legs, the Go
//! binaries): test_kcp_rust_to_rust / test_kcp_rust_encrypted semantics,
//! replayed here with an in-process frps (frp_server::service::Service) and
//! an in-process frpc (frp_client::service::Service) — no external binaries.
//!
//! Three variants share one skeleton (in-process server + in-process client,
//! one tcp proxy, byte-exact echo round-trip over the proxy port):
//!   (a) bare KCP        — control + work conns are plain KCP streams;
//!   (b) tcp_mux=true    — KCP+yamux: control + work conns ride yamux
//!                         streams multiplexed over KCP (server side wraps
//!                         after V2-magic/TLS detection);
//!   (c) use_encryption  — the bridge encrypts the data plane with
//!                         AES-128-CFB (CipherStream) over the KCP stream.
//!
//! Run: cargo test -p frp-server --test transport_e2e_kcp

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

/// Poll TCP-connect until the port accepts or the timeout elapses. The
/// connect-then-drop probes trigger on-demand work conns exactly like the
/// client-side harness's wait_for_port; harmless for V1.
async fn wait_for_proxy_port(port: u16, timeout: Duration) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let start = std::time::Instant::now();
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "proxy port {port} did not accept connections within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Deterministic pseudo-random bytes (xorshift64) — exercises the bridge
/// with incompressible-looking data without a rand dev-dep.
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
        "echo through the KCP tunnel must be byte-exact"
    );
}

fn server_cfg(server_port: u16, kcp_port: u16, token: &str) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        kcp_bind_port: kcp_port,
        auth: AuthServerConfig {
            method: "token".into(),
            token: token.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn client_cfg(
    kcp_port: u16,
    token: &str,
    tcp_mux: bool,
    use_encryption: bool,
    proxy_port: u16,
    echo_port: u16,
) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: kcp_port,
        transport_protocol: "kcp".into(),
        token: token.into(),
        login_fail_exit: false,
        pool_count: 1,
        tcp_mux,
        tls_enable: false,
        proxies: vec![ProxyConfig {
            name: "kcp-e2e".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: proxy_port,
            use_encryption,
            use_compression: false,
            sk: String::new(),
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Shared skeleton for the three KCP variants.
async fn run_kcp_e2e(tcp_mux: bool, use_encryption: bool, token: &str) {
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let kcp_port = allocate_port();
    let proxy_port = allocate_port();

    let _echo = start_echo_server(echo_port);

    // In-process frps. The harness polls the TCP bind port for readiness;
    // the KCP listener binds inside run() right after (its bind is awaited),
    // so a short settle sleep removes any first-dial race. login_fail_exit
    // = false below would absorb the race anyway via the login retry loop.
    let mut cfg = server_cfg(server_port, kcp_port, token);
    cfg.transport.tcp_mux = Some(tcp_mux);
    let (server_handle, _bind_port) = if tcp_mux {
        start_test_server_tcpmux_on(cfg).await
    } else {
        start_test_server(cfg).await
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // In-process frpc.
    let client = Arc::new(
        ClientService::new(
            client_cfg(
                kcp_port,
                token,
                tcp_mux,
                use_encryption,
                proxy_port,
                echo_port,
            ),
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

    // Wait until the proxy is registered and listening, then round-trip.
    wait_for_proxy_port(proxy_port, Duration::from_secs(10)).await;

    // A few hundred KiB, byte-exact both ways.
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

/// (a) Bare KCP: control + work conns are plain KCP streams, V1 frames.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kcp_plain_echo() {
    run_kcp_e2e(false, false, "kcp-plain-e2e-token").await;
}

/// (b) KCP + tcp_mux: the KCP stream is wrapped in yamux on both ends; all
/// control and work conns ride yamux streams over the single KCP connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kcp_yamux_echo() {
    run_kcp_e2e(true, false, "kcp-yamux-e2e-token").await;
}

/// (c) KCP + use_encryption: the proxy bridge encrypts the data plane
/// (AES-128-CFB, key derived from the shared token) over the KCP stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kcp_encrypted_echo() {
    run_kcp_e2e(false, true, "kcp-encrypted-e2e-token").await;
}
