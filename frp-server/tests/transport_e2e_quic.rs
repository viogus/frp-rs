#![cfg(feature = "quic")]
//! Rust↔Rust in-process e2e for QUIC transport — V1 protocol (NOT V2: the
//! existing v2_quic_r2r.rs covers only the V2+QUIC combination with external
//! binaries).
//!
//! Mirrors the compat-script semantics of test_g2r_quic (single proxy) and
//! test_g2r_quic_multi_proxy (several tcp proxies registered concurrently),
//! with both ends in-process (frp_server::service::Service +
//! frp_client::service::Service) — no external binaries.
//!
//! The server listens for QUIC on quic_bind_port (UDP) with TLS certs from
//! frp-core/tests/certs (CA-signed, SAN localhost); the client dials QUIC
//! with transport_protocol="quic", trusting that CA and verifying
//! tls_server_name="localhost" — same trust chain as the compat config's
//! transport.tls.trustedCaFile + serverName.
//!
//! Run: cargo test -p frp-server --test transport_e2e_quic

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use frp_client::service::Service as ClientService;
use frp_core::config::{AuthServerConfig, ClientConfig, ProxyConfig, ServerConfig};

use common::{allocate_port, start_test_server};

/// Test certificates committed under frp-core/tests/certs (server.crt /
/// server.key / ca.crt, SAN localhost, valid through 2126).
fn tls_cert_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("frp-core");
    p.push("tests");
    p.push("certs");
    p
}

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

/// Deterministic pseudo-random bytes (xorshift64) — no rand dev-dep.
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

/// Byte-exact echo round-trip through the proxy port, all bounded by
/// timeouts (no wall-clock races).
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
        "echo through the QUIC tunnel must be byte-exact"
    );
}

/// In-process frps with QUIC enabled. `bind_port` (TCP) is probed for
/// readiness; the QUIC listener binds on `quic_port` (UDP) inside run() —
/// a short settle sleep removes any first-dial race and login_fail_exit
/// = false would absorb it anyway.
async fn start_quic_server(bind_port: u16, quic_port: u16, token: &str) -> JoinHandle<()> {
    let cert_dir = tls_cert_dir();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        quic_bind_port: quic_port,
        tls_enable: true,
        tls_cert_file: cert_dir.join("server.crt").to_string_lossy().into(),
        tls_key_file: cert_dir.join("server.key").to_string_lossy().into(),
        auth: AuthServerConfig {
            method: "token".into(),
            token: token.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let (handle, _port) = start_test_server(cfg).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    handle
}

fn quic_client_cfg(
    quic_port: u16,
    token: &str,
    pool_count: i32,
    proxies: Vec<ProxyConfig>,
) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: quic_port,
        transport_protocol: "quic".into(),
        token: token.into(),
        login_fail_exit: false,
        pool_count,
        tcp_mux: false,
        tls_enable: true,
        tls_server_name: "localhost".into(),
        tls_ca_file: tls_cert_dir().join("ca.crt").to_string_lossy().into(),
        proxies,
        ..Default::default()
    }
}

fn tcp_proxy(name: &str, echo_port: u16, proxy_port: u16) -> ProxyConfig {
    ProxyConfig {
        name: name.into(),
        proxy_type: "tcp".into(),
        local_ip: "127.0.0.1".into(),
        local_port: echo_port,
        remote_port: proxy_port,
        use_encryption: false,
        use_compression: false,
        sk: String::new(),
        enabled: true,
        ..Default::default()
    }
}

/// QUIC V1 control plane + data plane: one tcp proxy, byte-exact echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_v1_tcp_proxy_echo() {
    let token = "quic-v1-e2e-token";
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let quic_port = allocate_port();
    let proxy_port = allocate_port();

    let _echo = start_echo_server(echo_port);
    let server_handle = start_quic_server(server_port, quic_port, token).await;

    // In-process frpc: QUIC transport, V1 protocol (v2 stays false).
    let client = Arc::new(
        ClientService::new(
            quic_client_cfg(
                quic_port,
                token,
                1,
                vec![tcp_proxy("quic-v1", echo_port, proxy_port)],
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

    wait_for_proxy_port(proxy_port, Duration::from_secs(10)).await;

    let payload = pseudo_random_bytes(256 * 1024);
    echo_round_trip(proxy_port, &payload).await;
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

/// QUIC V1 multi-proxy (mirror of compat test_g2r_quic_multi_proxy): three
/// tcp proxies registered on one control connection, three CONCURRENT
/// round-trips with distinct payloads through distinct proxy ports. Any
/// cross-proxy mixing (wrong work-conn routing over QUIC) shows up as a
/// payload/byte mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_v1_multi_proxy_concurrent_round_trips() {
    let token = "quic-v1-multi-e2e-token";
    let echo1 = allocate_port();
    let echo2 = allocate_port();
    let echo3 = allocate_port();
    let server_port = allocate_port();
    let quic_port = allocate_port();
    let proxy1 = allocate_port();
    let proxy2 = allocate_port();
    let proxy3 = allocate_port();

    let _echo1 = start_echo_server(echo1);
    let _echo2 = start_echo_server(echo2);
    let _echo3 = start_echo_server(echo3);
    let server_handle = start_quic_server(server_port, quic_port, token).await;

    let client = Arc::new(
        ClientService::new(
            quic_client_cfg(
                quic_port,
                token,
                2,
                vec![
                    tcp_proxy("quic-p1", echo1, proxy1),
                    tcp_proxy("quic-p2", echo2, proxy2),
                    tcp_proxy("quic-p3", echo3, proxy3),
                ],
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

    for p in [proxy1, proxy2, proxy3] {
        wait_for_proxy_port(p, Duration::from_secs(10)).await;
    }

    // Three concurrent round-trips, distinct payloads and sizes.
    let payloads = [
        (proxy1, pseudo_random_bytes(256 * 1024)),
        (proxy2, pseudo_random_bytes(128 * 1024)),
        (proxy3, pseudo_random_bytes(512 * 1024)),
    ];
    let tasks: Vec<_> = payloads
        .into_iter()
        .map(|(port, payload)| tokio::spawn(async move { echo_round_trip(port, &payload).await }))
        .collect();
    tokio::time::timeout(Duration::from_secs(30), async {
        for t in tasks {
            t.await.expect("concurrent QUIC round-trip panicked");
        }
    })
    .await
    .expect("concurrent QUIC round-trips did not finish within 30s");

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    server_handle.abort();
    _echo1.abort();
    _echo2.abort();
    _echo3.abort();
}
