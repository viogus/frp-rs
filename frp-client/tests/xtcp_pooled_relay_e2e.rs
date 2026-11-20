#![cfg(all(feature = "quic", feature = "kcp"))]
//! End-to-end coverage for the server's `PlainPath::PooledXttpFallback` arm
//! (`frp-server/src/control/bridge.rs`): an XTCP visitor connection relayed to
//! the provider by the pooled-BUFFER relay (`relay_plain_pooled`) instead of
//! the fast relay. "Pooled" names the buffer pool, not the work-conn pool.
//!
//! Why this has to be an e2e and not an in-process socket test: the arm exists
//! because `relay_plain_fast` / `bridge_plain` half-close the provider side
//! the moment the user reader sees EOF, which races frpc's bridge startup
//! (`ECONNRESET` / premature FIN on VPS). `relay_plain_pooled` instead runs
//! both directions to completion and only shuts the work side down afterwards.
//! A raw loopback fixture cannot observe the difference — `copy_bidirectional`
//! also delivers late provider bytes — so the only honest observable is a real
//! frps + real frpc provider + real frpc visitor + a real user socket whose
//! payload is written by the provider AFTER the user's half close.
//!
//! Fixture shape (mirrors `xtcp_visitor_failure_e2e.rs`):
//! - the punch can never succeed (dead loopback UDP STUN port), so the visitor
//!   falls through to the STCP-shaped relay at
//!   `frp-client/src/visitor/stcp.rs`, which opens a `NewVisitorConn` for the
//!   XTCP proxy's own `server_name` (`stcp_proxy_name = if fb_to.is_empty()
//!   { sn } else { fb_to }`). With `fallback_to` empty that is the XTCP proxy
//!   itself, and the server's bridge then sees `proxy_type == "xtcp"` — the
//!   only production path that selects `PooledXttpFallback`.
//! - the provider's local server reads until EOF (the user's half close,
//!   relayed all the way down), then writes [`LATE_BYTES`] and closes. Those
//!   bytes can only reach the user if the server relay kept the provider side
//!   alive across the user's half close — the property the pooled arm was
//!   introduced for.
//!
//! Discrimination, measured (each mutation applied to
//! `frp-server/src/control/bridge.rs`, test re-run alone, mutation reverted):
//!
//! - Plan trigger neutralized (`plain_path(false, ...)` instead of
//!   `plain_path(proxy_info…proxy_type == "xtcp", ...)`): test still PASSES
//!   (21.7 s). On non-Linux, `relay_plain_fast_inner` *is*
//!   `relay_plain_pooled`, so the mutation changes which arm runs but not the
//!   relay function. Not yet measured on Linux, where the same mutation routes
//!   to `splice::bridge_splice` — rerun it there before treating this file as
//!   a pin on the arm's necessity.
//! - Arm body replaced by `bridge_plain` over `try_split_work_halves` (the
//!   pre-pooled semantics the arm replaced): test still PASSES (21.7 s).
//!   `bridge_plain` also runs both directions to completion, so on loopback it
//!   delivers the post-half-close bytes too; this observable does NOT falsify
//!   the arm-vs-`bridge_plain` choice, only the arm's own happy path.
//! - Arm body replaced by `return;` (no relay): test FAILS on the late-bytes
//!   assertion ("… early eof: the relay closed the user side instead of
//!   delivering the post-half-close write", 64 s). This is the evidence that
//!   the test really reaches `PlainPath::PooledXttpFallback` and that its relay
//!   is what carries the bytes — no other arm is exercised with the trigger in
//!   place.

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use common::{allocate_port, allocate_udp_port, start_frps, wait_for_port};

const TOKEN: &str = "xtcp-pooled-e2e-token";
const SK: &str = "xtcp-pooled-e2e-secret";
const XTCP_PROXY: &str = "pooled-echo-xtcp";

/// Written by the provider's local server only after the user's half close
/// has arrived there. Deliberately distinctive: a truncated/echoed/garbage
/// payload cannot masquerade as this.
const LATE_BYTES: &[u8] = b"late-provider-bytes";

/// A UDP port that is free NOW but has no listener: bind once, read the port,
/// drop. A STUN request to it fails fast (ICMP port unreachable) instead of
/// hanging, so a real hole punch can never accidentally succeed.
fn dead_udp_port() -> u16 {
    allocate_udp_port()
}

/// The provider's local server. Per accepted connection: read to EOF, THEN
/// write [`LATE_BYTES`], shut the write half down and drop. EOF here means the
/// user's `shutdown(Write)` survived the whole chain
/// (user → frps pooled relay → provider work conn → this socket); the write
/// after it is the observable the pooled arm protects.
fn start_late_reply_server(port: u16) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("late-reply server bind");
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut sink = Vec::new();
                let _ = stream.read_to_end(&mut sink).await;
                let _ = stream.write_all(LATE_BYTES).await;
                let _ = stream.shutdown().await;
            });
        }
    })
}

async fn start_provider(server_port: u16, local_port: u16) -> ClientService {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // No pre-spawned work conns: the server asks for a fresh one when the
        // visitor's relay starts. (The arm's "pooled" is the buffer pool; with
        // `pool_count: 2` the pre-spawned conns time out after 8 s waiting for
        // StartWorkConn and the server pool then hands the relay a dead one.)
        pool_count: 0,
        nat_hole_stun_server: format!("127.0.0.1:{}", dead_udp_port()),
        proxies: vec![ProxyConfig {
            name: XTCP_PROXY.into(),
            proxy_type: "xtcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port,
            remote_port: 0, // no server listener for XTCP
            sk: SK.into(),
            enabled: true, // derived Default leaves it false; serde-only default_true
            ..Default::default()
        }],
        ..Default::default()
    };
    ClientService::new(cfg, None)
        .await
        .expect("create provider service")
}

/// Visitor with NO `fallback_to`: on punch failure the client relays through
/// `server_name` itself, which keeps the proxy type `xtcp` all the way to the
/// server's bridge (see the module docs).
async fn start_visitor(server_port: u16, visitor_port: u16) -> ClientService {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Dead on purpose: the P2P punch can never complete.
        nat_hole_stun_server: format!("127.0.0.1:{}", dead_udp_port()),
        visitors: vec![VisitorConfig {
            name: "pooled-visitor".into(),
            visitor_type: "xtcp".into(),
            server_name: XTCP_PROXY.into(),
            secret_key: SK.into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port as i32,
            protocol: "quic".into(),
            fallback_to: String::new(),
            ..Default::default()
        }],
        ..Default::default()
    };
    ClientService::new(cfg, None)
        .await
        .expect("create visitor service")
}

/// One user connection: write, half close, then read the provider's late
/// bytes. The user write half MUST be closed — that is the trigger the arm
/// under test has to survive.
async fn expect_late_bytes_after_user_half_close(
    visitor_addr: SocketAddr,
    budget: Duration,
) -> Result<(), String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(visitor_addr),
    )
    .await
    .map_err(|_| "connect to the visitor port timed out".to_string())?
    .map_err(|e| format!("connect to the visitor port failed: {e}"))?;

    // Keep the read half open across the half close — the whole point.
    tokio::time::timeout(Duration::from_secs(10), stream.write_all(b"ping"))
        .await
        .map_err(|_| "write of the user payload timed out".to_string())?
        .map_err(|e| format!("write of the user payload failed: {e}"))?;
    tokio::time::timeout(Duration::from_secs(10), stream.shutdown())
        .await
        .map_err(|_| "user half close (shutdown(Write)) timed out".to_string())?
        .map_err(|e| format!("user half close (shutdown(Write)) failed: {e}"))?;

    let mut got = vec![0u8; LATE_BYTES.len()];
    tokio::time::timeout(budget, stream.read_exact(&mut got))
        .await
        .map_err(|_| {
            format!(
                "the visitor never received the {} B the provider wrote after the user's half \
                 close within {budget:?} — the server's pooled XTCP relay arm \
                 (`PlainPath::PooledXttpFallback`) did not serve this connection",
                LATE_BYTES.len()
            )
        })?
        .map_err(|e| {
            format!(
                "reading the provider's late payload failed after {e}: the relay closed the \
                 user side instead of delivering the post-half-close write"
            )
        })?;
    if got != LATE_BYTES {
        return Err(format!(
            "late payload mismatch: got {:?}, want {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(LATE_BYTES)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn test_xtcp_visitor_pooled_relay_delivers_late_provider_bytes() {
    common::init_tracing();
    let local_port = allocate_port();
    let server_port = allocate_port();
    let visitor_port = allocate_port();
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let visitor_addr: SocketAddr = format!("127.0.0.1:{visitor_port}").parse().unwrap();

    let _local_handle = start_late_reply_server(local_port);
    let _server_handle = start_frps(server_port, TOKEN).await;
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps port ready");

    let provider_service = start_provider(server_port, local_port).await;
    let _provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });
    // Registration must land before the visitor asks for a tunnel.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let visitor_service = start_visitor(server_port, visitor_port).await;
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });
    wait_for_port(visitor_addr, Duration::from_secs(15))
        .await
        .expect("visitor port became connectable within 15s");

    // Empty `fallback_to` pins the visitor's `open_tunnel` budget to Go's 20 s
    // (`frp-client/src/visitor/stcp.rs`: `if fb_to.is_empty() {
    // Duration::from_secs(20) }`), so the relay only starts ~20 s after the
    // user connection arrives. The read budget must therefore exceed that, not
    // the punch itself.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
    let mut last = String::new();
    for _attempt in 1..=2 {
        match expect_late_bytes_after_user_half_close(visitor_addr, Duration::from_secs(45)).await {
            Ok(()) => return,
            Err(e) => {
                last = e;
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    panic!(
        "pooled XTCP relay e2e: the visitor never received the provider's post-half-close \
         bytes through the server relay. Last failure: {last}"
    );
}
