//! Regression tests for the server slowloris first-read deadlines.
//!
//! Go frp v0.70.1 applies a single `connReadTimeout = 10s` read deadline
//! covering the whole initial read phase (magic detection + handshakes +
//! first message). frp-rs previously left two phases unbounded:
//!
//! 1. The yamux first-stream wait in `server_mux` — the idle-kill driver
//!    task only spawns AFTER the first stream arrives, so a client that
//!    sends the magic bytes (passing detection) but no yamux frame parked
//!    its task / fd / conn_semaphore permit forever.
//! 2. The post-handshake V2-magic `read_exact` (7 bytes) after TLS / WS
//!    upgrades.
//!
//! These tests verify that a peer which completes a phase then goes silent
//! is disconnected at the ~10s accept deadline instead of being held
//! indefinitely (which would allow 512 such sockets — the default
//! max_connections — to block all new clients).

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::{allocate_port, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::transport::{dial_server, DialOptions};
use frp_server::service::Service;
use tokio::io::AsyncReadExt;

fn test_cert_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("frp-core");
    p.push("tests");
    p.push("certs");
    p
}

/// Start an in-process frps with the given config and wait until it listens.
async fn start_server(cfg: ServerConfig) {
    let service = Service::new(cfg, None).await.expect("create service");
    let _handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Wait for the server to close the connection after a completed read
/// phase with no further bytes. Asserts the close arrives around the 10s
/// accept deadline — not immediately (an accidental reject) and not ever
/// (the unbounded-hold regression this suite guards against). An abrupt
/// close (RST, missing TLS close_notify) is treated as a disconnect.
/// Inbound bytes before the close are tolerated: the yamux server emits
/// an initial WindowUpdate+SYN frame when the connection is polled.
async fn expect_disconnect_at_accept_deadline<R>(sock: &mut R, what: &str)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let start = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout(Duration::from_secs(15), sock.read(&mut buf)).await {
            Err(_) => panic!("server did not close the silent {what} within 15s"),
            Ok(Ok(0)) => break,    // EOF — the server dropped the connection
            Ok(Ok(_)) => continue, // yamux protocol frames (initial WindowUpdate+SYN)
            Ok(Err(_)) => break,   // abrupt close is a disconnect too
        }
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(8),
        "silent {what} dropped too early after {elapsed:?}; must wait the accept deadline"
    );
    eprintln!("server dropped silent {what} after {elapsed:?}");
}

/// Plain TCP + tcp_mux: the client sends 7 bytes that pass V1 detection
/// (so `server_mux` is reached) but never sends a yamux frame. The
/// first-stream wait must be bounded by the accept deadline.
#[tokio::test]
async fn silent_yamux_client_dropped_at_accept_deadline() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    start_server(cfg).await;

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", bind_port))
        .await
        .expect("dial server");
    // Not V2 magic, not "GET ", not the TLS marker bytes — classified as
    // V1, after which (tcp_mux on) the server waits for the first yamux
    // frame inside server_mux.
    use tokio::io::AsyncWriteExt;
    sock.write_all(&[0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .expect("write 7 V1-ish bytes");

    expect_disconnect_at_accept_deadline(&mut sock, "yamux client").await;
}

/// TLS handshake completes (tcp_mux off), then silence: the post-TLS
/// V2-magic `read_exact` must be bounded by the accept deadline.
#[tokio::test]
async fn tls_client_silent_after_handshake_dropped_at_accept_deadline() {
    let bind_port = allocate_port();
    let cert_dir = test_cert_dir();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tls_enable: true,
        tls_cert_file: cert_dir.join("server.crt").to_string_lossy().into(),
        tls_key_file: cert_dir.join("server.key").to_string_lossy().into(),
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: Some(false), // exercise the raw post-TLS magic read
            ..Default::default()
        },
        auth: test_auth_cfg(),
        ..Default::default()
    };
    start_server(cfg).await;

    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        tls_enable: true,
        tls_server_name: "localhost".into(),
        tls_ca_file: Some(cert_dir.join("ca.crt").to_string_lossy().into()),
        ..Default::default()
    };
    // dial_server completes the TLS handshake; the server then waits for
    // the first 7 plaintext bytes (V2 magic detection) — never sent.
    let mut io = dial_server(&opts).await.expect("TLS dial");

    expect_disconnect_at_accept_deadline(&mut io, "post-TLS client").await;
}
