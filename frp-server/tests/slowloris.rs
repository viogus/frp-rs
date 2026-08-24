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
//! 3. The post-yamux V2-magic `read_exact` (7 bytes) on the control
//!    stream after the yamux handshake completes — previously only the
//!    yamux keepalive dead-time (~90s with the default 30s keepalive)
//!    released the task and permit, and a peer that kept the yamux link
//!    alive (auto-ponging) held the permit indefinitely.
//!
//! These tests verify that a peer which completes a phase then goes silent
//! is disconnected at the phase deadline instead of being held indefinitely
//! (which would allow 512 such sockets — the default max_connections — to
//! block all new clients).
//!
//! Phase-1/2-style reads (server_mux first-stream wait, pre-handshake
//! magic) keep the 10s accept deadline. Post-handshake reads (after
//! TLS/WS/yamux, before Login) use `POST_HANDSHAKE_READ_TIMEOUT` (30s):
//! a legit client (Go frpc with OIDC) fetches its JWT after the handshake
//! and before Login, which can take >10s — the slowloris bound must not
//! be tighter than that (regression: test_g2r_oidc_proxy killed by the
//! original 10s post-handshake deadline).

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
/// phase with no further bytes. Asserts the close arrives around the
/// phase deadline — not immediately (an accidental reject) and not ever
/// (the unbounded-hold regression this suite guards against). An abrupt
/// close (RST, missing TLS close_notify) is treated as a disconnect.
/// Inbound bytes before the close are tolerated: the yamux server emits
/// an initial WindowUpdate+SYN frame when the connection is polled.
///
/// The drop lands at the ~30s post-handshake deadline
/// (POST_HANDSHAKE_READ_TIMEOUT) for post-TLS/WS/yamux reads, or at the
/// ~10s accept deadline for the server_mux first-stream wait. On the
/// yamux paths the handler task (and its conn_semaphore permit) is
/// released at that deadline, but the socket is owned by the yamux
/// driver task, which notices the shutdown at its next keepalive tick —
/// the tests set tcp_mux_keepalive_interval = 1s so the client-visible
/// close follows the deadline within ~1s. The 45s per-read window covers
/// both bounds; without the deadline fix the close never comes (keepalive
/// dead-time is ~90s, or never for a peer that keeps the yamux link alive
/// — the ponging test below pins that case).
async fn expect_silent_disconnect<R>(sock: &mut R, what: &str)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let start = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout(Duration::from_secs(45), sock.read(&mut buf)).await {
            Err(_) => panic!("server did not close the silent {what} within 45s"),
            Ok(Ok(0)) => break,    // EOF — the server dropped the connection
            Ok(Ok(_)) => continue, // yamux protocol frames (initial WindowUpdate+SYN)
            Ok(Err(_)) => break,   // abrupt close is a disconnect too
        }
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(8),
        "silent {what} dropped too early after {elapsed:?}; must wait the phase deadline"
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

    expect_silent_disconnect(&mut sock, "yamux client").await;
}

/// A valid yamux stream-open frame: WindowUpdate tag (1) with the SYN
/// flag (1) for stream 1, granting 64 KiB of credit (yamux-rs wire
/// format: [version][tag][flags:2][stream_id:4][length:4], all BE).
/// Its first 7 bytes (version 0x00, tag, flags, stream-id prefix) are
/// not V2/WS/TLS magic, so the server classifies the connection as V1
/// and (tcp_mux on) wraps the replayed bytes in yamux — `server_mux`
/// then returns the control stream and the handler blocks on the
/// post-yamux V2-magic read.
const YAMUX_STREAM_OPEN_FRAME: [u8; 12] = [
    0x00, 0x01, // version 0, tag WindowUpdate
    0x00, 0x01, // flags: SYN
    0x00, 0x00, 0x00, 0x01, // stream id 1
    0x00, 0x01, 0x00, 0x00, // credit 65536
];

/// The yamux handshake completes (a stream-open frame arrives, so
/// `server_mux` returns the control stream), then silence: the
/// post-yamux V2-magic `read_exact` must be bounded by the 30s
/// post-handshake deadline (POST_HANDSHAKE_READ_TIMEOUT). Before the
/// fix, only yamux keepalive dead-time (~90s with the default 30s
/// keepalive) released the task and its conn_semaphore permit — and a
/// peer that kept the yamux link alive (auto-ponging) held the permit
/// indefinitely.
#[tokio::test]
async fn yamux_client_silent_after_stream_open_dropped_at_post_handshake_deadline() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        // 1s driver keepalive: the yamux driver owns the socket and only
        // notices the handler's shutdown at its next keepalive tick, so a
        // short tick keeps the client-visible close ~1s after the ~30s
        // deadline (inside the 45s helper window).
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux_keepalive_interval: 1,
            ..Default::default()
        },
        auth: test_auth_cfg(),
        ..Default::default()
    };
    start_server(cfg).await;

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", bind_port))
        .await
        .expect("dial server");
    use tokio::io::AsyncWriteExt;
    sock.write_all(&YAMUX_STREAM_OPEN_FRAME)
        .await
        .expect("write yamux stream-open frame");

    expect_silent_disconnect(&mut sock, "post-yamux client").await;
}

/// The yamux handshake completes, and the client then answers every
/// keepalive ping with a pong — keeping the yamux driver (and its dead-time
/// kill) alive. Only the post-yamux V2-magic read deadline can release the
/// handler. Before the fix, a ponging peer held the task and its
/// conn_semaphore permit indefinitely: the keepalive dead-time only fires
/// for a link that goes quiet, and a peer that keeps ponging never does.
/// (The silent test above cannot prove the deadline fires — with
/// keepalive=1s the driver dead-time is also ~30s, indistinguishable from
/// POST_HANDSHAKE_READ_TIMEOUT.)
#[tokio::test]
async fn yamux_ponging_client_still_dropped_at_post_handshake_deadline() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        // 1s driver keepalive: shortens the dead-time that this test must
        // NOT rely on — the pongs keep the link alive regardless.
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux_keepalive_interval: 1,
            ..Default::default()
        },
        auth: test_auth_cfg(),
        ..Default::default()
    };
    start_server(cfg).await;

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", bind_port))
        .await
        .expect("dial server");
    use tokio::io::AsyncWriteExt;
    sock.write_all(&YAMUX_STREAM_OPEN_FRAME)
        .await
        .expect("write yamux stream-open frame");

    // Read frames and pong every ping (tag 4, no ACK, stream 0) until the
    // server closes. A pong is the same frame with the ACK flag (0x2) set
    // and the payload (ping id) echoed. Frame header:
    // [version 1][tag 1][flags 2][stream_id 4][length 4] = 12 bytes.
    let start = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut buf = [0u8; 512];
    let mut pongs = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, sock.read(&mut buf)).await {
            Err(_) => panic!("server did not close the ponging client within 45s"),
            Ok(Ok(0)) | Ok(Err(_)) => break, // EOF / abrupt close — dropped
            Ok(Ok(n)) => {
                let mut off = 0;
                while off + 12 <= n {
                    let tag = buf[off + 1];
                    let flags = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
                    let stream = u32::from_be_bytes([
                        buf[off + 4],
                        buf[off + 5],
                        buf[off + 6],
                        buf[off + 7],
                    ]);
                    let len = u32::from_be_bytes([
                        buf[off + 8],
                        buf[off + 9],
                        buf[off + 10],
                        buf[off + 11],
                    ]) as usize;
                    let total = 12 + len;
                    if total > n - off {
                        break; // truncated frame — wait for more
                    }
                    if buf[off] == 0 && tag == 4 && flags & 0x2 == 0 && stream == 0 {
                        // Ping → pong (ACK echo).
                        let mut pong = [0u8; 16];
                        pong[1] = 4;
                        pong[3] = 0x2; // ACK flag
                        pong[8..12].copy_from_slice(&buf[off + 8..off + 12]); // same length
                        pong[12..total].copy_from_slice(&buf[off + 12..off + total]); // echo id
                        sock.write_all(&pong[..total]).await.expect("write pong");
                        pongs += 1;
                    }
                    off += total;
                }
            }
        }
    }
    // Sanity: the driver must have pinged (hardcoded ~10s RTT interval, so
    // several within the 45s window) — otherwise the test proves nothing.
    assert!(pongs >= 1, "server never pinged; the test is vacuous");
    let elapsed = start.elapsed();
    // Dropped at the ~30s deadline (plus the ~1s keepalive tick before the
    // driver closes the socket), never before.
    assert!(
        elapsed >= Duration::from_secs(20),
        "ponging client dropped too early after {elapsed:?}; must wait the post-handshake deadline"
    );
    eprintln!("server dropped ponging client after {elapsed:?} ({pongs} pongs answered)");
}

/// TLS handshake completes and the yamux stream opens (tcp_mux on),
/// then silence: the post-yamux V2-magic read on the TLS+yamux path
/// must be bounded by the 30s post-handshake deadline.
#[tokio::test]
async fn tls_yamux_client_silent_after_stream_open_dropped_at_post_handshake_deadline() {
    let bind_port = allocate_port();
    let cert_dir = test_cert_dir();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tls_enable: true,
        tls_cert_file: cert_dir.join("server.crt").to_string_lossy().into(),
        tls_key_file: cert_dir.join("server.key").to_string_lossy().into(),
        // tcp_mux stays default-on: exercise the TLS+yamux post-stream read.
        // 1s driver keepalive: see yamux test above.
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux_keepalive_interval: 1,
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
    let mut io = dial_server(&opts).await.expect("TLS dial");
    use tokio::io::AsyncWriteExt;
    io.write_all(&YAMUX_STREAM_OPEN_FRAME)
        .await
        .expect("write yamux stream-open frame");
    io.flush().await.expect("flush TLS stream");

    expect_silent_disconnect(&mut io, "post-yamux TLS client").await;
}

/// TLS handshake completes (tcp_mux off), then silence: the post-TLS
/// V2-magic `read_exact` must be bounded by the 30s post-handshake
/// deadline.
#[tokio::test]
async fn tls_client_silent_after_handshake_dropped_at_post_handshake_deadline() {
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

    expect_silent_disconnect(&mut io, "post-TLS client").await;
}
