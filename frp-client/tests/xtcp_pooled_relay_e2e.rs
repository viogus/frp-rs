//! Pins the server's `PlainPath::PooledXttpFallback` arm
//! (`frp-server/src/control/bridge.rs`) twice over: that the arm is *selected*
//! for an XTCP visitor fallback, and that its relay carries bytes the provider
//! writes only after the user's half close.
//!
//! Why both assertions: selection is invisible to the data path. All plain
//! relays propagate the half close — the peer's write half is FIN'd as soon as
//! a direction EOFs, which is what lets the provider's local server see the
//! user's EOF and reply late — so bytes arrive identically through this arm,
//! through `FastRelay`, and through the pre-pooled `bridge_plain`. Measured
//! 2026-11-20 on macOS: rewriting the plan's `xtcp` term to `false` still
//! passes, because `relay_plain_fast_inner` *is* `relay_plain_pooled` off
//! Linux (`frp-server/src/control/bridge.rs`). What the arm genuinely differs
//! in is relayed through pooled buffers instead of a per-conn pair, and in
//! bounding a post-half-close stall at
//! [`frp_core::bridge::HALF_CLOSE_LINGER_TIMEOUT`] rather than waiting
//! unbounded. None of that is observable per connection, so selection is
//! asserted on the counter `frp_server::control::pooled_xtcp_fallback_bridges`
//! (the same shape as `frp_core::splice::bridge_splice_calls`, which exists
//! because the zero-copy arm sat unreachable while every test passed). frps
//! runs in-process here, so the process-global counter is readable from the
//! test.
//!
//! Fixture shape (mirrors `xtcp_visitor_failure_e2e.rs`):
//! - the punch can never succeed (dead loopback UDP STUN port), so the visitor
//!   falls through to the STCP-shaped relay at
//!   `frp-client/src/visitor/stcp.rs`, which opens a `NewVisitorConn` for
//!   `stcp_proxy_name = if fb_to.is_empty() { sn } else { fb_to }`. Setting
//!   `fallback_to` to the XTCP proxy's OWN name yields that same name, so the
//!   server still sees `proxy_type == "xtcp"` — the only production path that
//!   selects `PooledXttpFallback` — while taking the branch whose timeout is
//!   configurable (an empty `fallback_to` pins the budget to Go's 20 s, which
//!   made this test 21.7 s instead of 2 s).
//! - the provider's local server reads until EOF (the user's half close,
//!   relayed all the way down), then writes [`LATE_BYTES`] and closes.
//!
//! Discrimination, measured (each mutation applied to
//! `frp-server/src/control/bridge.rs`, test re-run alone, mutation reverted;
//! timings from the 2 s fixture):
//!
//! - Plan trigger neutralized (`plain_path(false, ...)`): the late-bytes
//!   assertion still PASSES (2.1 s) — the reason both assertions exist; the
//!   counter assertion FAILS with "arm counter did not move:
//!   PlainPath::PooledXttpFallback was never taken".
//! - Arm body replaced by `bridge_plain` over `try_split_work_halves` (the
//!   pre-pooled semantics the arm replaced): still PASSES (2.1 s) — this test
//!   does not falsify arm-vs-`bridge_plain`, only arm reachability.
//! - Arm body replaced by `return;` (no relay): FAILS on the late-bytes
//!   assertion ("the relay closed the user side instead of delivering the
//!   post-half-close write", 5.5 s) — proves the arm's relay is what carries
//!   the bytes.
//!
//! On Linux `relay_plain_fast_inner` routes to `splice::bridge_splice`, so the
//! first mutation changes the relay function too; re-measure there before
//! leaning on the late-bytes half alone.

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
        // visitor's relay starts. (The arm's "pooled" is the buffer pool, not
        // the pool of work conns. With `pool_count: 2` the pre-spawned conns
        // wait for `StartWorkConn` under `start_work_conn_timeout`
        // (`frp-client/src/work_conn.rs`), i.e. `dial_timeout_secs.max(1)` —
        // 10 s by default — while the server-side pool keeps no idle expiry
        // (`frp-server/src/control/pool.rs`); the relay here does not start
        // until the punch budget expires, so every pre-spawned conn would be
        // dead before it is used.)
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
            // The proxy's OWN name — see the module docs: an empty
            // `fallback_to` also lands here but pins the punch budget to Go's
            // fixed 20 s, making the test 21.7 s instead of 2 s.
            fallback_to: XTCP_PROXY.into(),
            fallback_timeout_ms: 200,
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

    // The visitor listener is bound in `spawn_session_tasks`, i.e. after
    // login/registration (`frp-client/src/service/session.rs`), so a
    // connectable port implies the visitor is logged in.
    // `wait_for_port` opened and closed one user connection of its own, which
    // also reaches the arm a budget later; let that increment land before the
    // baseline so the assertion below is about THIS socket's relay.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = frp_server::control::pooled_xtcp_fallback_bridges();
    expect_late_bytes_after_user_half_close(visitor_addr, Duration::from_secs(20))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "pooled XTCP relay e2e: the visitor never received the provider's \
                 post-half-close bytes through the server relay. {e}"
            )
        });
    // The data path cannot tell this arm from `FastRelay` (see the module
    // docs), so selection is asserted on the counter: with the plan's `xtcp`
    // term rewritten to `false` this line is the one that goes red.
    assert!(
        frp_server::control::pooled_xtcp_fallback_bridges() > before,
        "arm counter did not move: PlainPath::PooledXttpFallback was never taken \
         (before={before}, after={})",
        frp_server::control::pooled_xtcp_fallback_bridges()
    );
}
