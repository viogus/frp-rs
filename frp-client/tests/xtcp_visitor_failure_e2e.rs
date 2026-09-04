#![cfg(all(feature = "quic", feature = "kcp"))]
//! XTCP visitor FAILURE-path end-to-end tests (audit round 3, GAP5/GAP6):
//! the same in-process frpc service skeleton as [`xtcp_pair_e2e`]'s success
//! path, but with hole punching made *impossible* — either the target proxy
//! does not exist (pre_check error) or the visitor's STUN server is dead
//! (no socket for the punch). These exercise the visitor failure arms:
//!
//! - `fallback_to` STCP relay (GAP5): when the hole punch cannot happen,
//!   user data must flow through the named STCP proxy instead.
//! - pre_check / STUN failure arms of `do_hole_punch` (GAP6): a visitor
//!   whose punch can never succeed must close user connections cleanly
//!   within the open_tunnel budget — never park them, never echo through a
//!   phantom tunnel.
//!
//! Both failure shapes are deterministic: no mock STUN responder is started,
//! and the configured `nat_hole_stun_server` points at a CLOSED loopback UDP
//! port, so the STUN binding request fails immediately (ICMP port
//! unreachable on loopback) or times out in ≤ 5 s — a real punch can never
//! accidentally succeed and pollute the assertion. The visitor's
//! `fallback_to` + a 2 s `fallback_timeout_ms` bound the open_tunnel budget
//! to `min(2s, 20s)` = 2 s (Go caps the budget at 20 s regardless), keeping
//! both tests fast.

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use common::{allocate_port, allocate_udp_port, start_echo_server, start_frps, wait_for_port};

const TOKEN: &str = "xtcp-fail-e2e-token";
const SK: &str = "xtcp-fail-e2e-secret";
const XTCP_PROXY: &str = "echo-xtcp";
const STCP_PROXY: &str = "echo-stcp";

/// A UDP port that is free NOW but has no listener: bind once, read the
/// port, drop. On loopback, a STUN request to it fails fast with ICMP port
/// unreachable instead of hanging for the full 5 s recv timeout.
fn dead_udp_port() -> u16 {
    allocate_udp_port()
}

/// One user connection that must be SERVED (echo back `pld`).
async fn expect_echo_round_trip(
    visitor_addr: SocketAddr,
    pld: &[u8],
    label: &str,
) -> Result<(), String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(visitor_addr),
    )
    .await
    .map_err(|_| format!("{label}: connect timed out"))?
    .map_err(|e| format!("{label}: connect failed: {e}"))?;
    tokio::time::timeout(Duration::from_secs(15), stream.write_all(pld))
        .await
        .map_err(|_| format!("{label}: write of {} B timed out", pld.len()))?
        .map_err(|e| format!("{label}: write failed: {e}"))?;
    let mut buf = vec![0u8; pld.len()];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut buf))
        .await
        .map_err(|_| format!("{label}: read of {} B echoed timed out", pld.len()))?
        .map_err(|e| format!("{label}: read failed: {e}"))?;
    if buf != pld {
        return Err(format!("{label}: echo mismatch ({} B)", pld.len()));
    }
    Ok(())
}

/// One user connection that must be CLOSED without service: connects (the
/// visitor listener is up), then the connection must end (EOF or reset)
/// within `within` — with no data delivered.
async fn expect_conn_closed_without_service(
    visitor_addr: SocketAddr,
    within: Duration,
    label: &str,
) -> Result<(), String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(visitor_addr),
    )
    .await
    .map_err(|_| format!("{label}: connect timed out"))?
    .map_err(|e| format!("{label}: connect failed: {e}"))?;
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(within, stream.read(&mut buf)).await;
    match read {
        Err(_elapsed) => Err(format!(
            "{label}: connection stayed OPEN past {within:?} (tunnel never failed closed)"
        )),
        Ok(Ok(0)) => Ok(()), // clean EOF: server closed the user conn
        Ok(Ok(n)) => Err(format!(
            "{label}: got {n} unexpected bytes on a conn that must fail closed"
        )),
        Ok(Err(e)) => {
            // Reset counts as closed-without-service too.
            let _ = e;
            Ok(())
        }
    }
}

async fn start_provider(server_port: u16, echo_port: u16, stcp_too: bool) -> ClientService {
    let mut proxies = vec![ProxyConfig {
        name: XTCP_PROXY.into(),
        proxy_type: "xtcp".into(),
        local_ip: "127.0.0.1".into(),
        local_port: echo_port,
        remote_port: 0, // no server listener for XTCP
        sk: SK.into(),
        enabled: true, // derived Default leaves it false; serde-only default_true
        ..Default::default()
    }];
    if stcp_too {
        proxies.push(ProxyConfig {
            name: STCP_PROXY.into(),
            proxy_type: "stcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: 0,
            sk: SK.into(),
            enabled: true, // derived Default leaves it false; serde-only default_true
            ..Default::default()
        });
    }
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2, // STCP fallback relays need pre-spawned work conns
        nat_hole_stun_server: format!("127.0.0.1:{}", dead_udp_port()),
        proxies,
        ..Default::default()
    };
    ClientService::new(cfg, None)
        .await
        .expect("create provider service")
}

async fn start_visitor(
    server_port: u16,
    visitor_port: u16,
    server_name: &str,
    fallback_to: &str,
) -> ClientService {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Dead on purpose: a punch can never complete.
        nat_hole_stun_server: format!("127.0.0.1:{}", dead_udp_port()),
        visitors: vec![VisitorConfig {
            name: "xtcp-fail-visitor".into(),
            visitor_type: "xtcp".into(),
            server_name: server_name.into(),
            secret_key: SK.into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port as i32,
            protocol: "quic".into(),
            fallback_to: fallback_to.into(),
            // Bounds the open_tunnel wait to 2 s (Go: min(20s, fallback_timeout)).
            fallback_timeout_ms: 2_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    ClientService::new(cfg, None)
        .await
        .expect("create visitor service")
}

async fn common_setup() -> (u16, u16, u16, SocketAddr, SocketAddr) {
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let visitor_port = allocate_port();
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let visitor_addr: SocketAddr = format!("127.0.0.1:{visitor_port}").parse().unwrap();
    (
        echo_port,
        server_port,
        visitor_port,
        server_addr,
        visitor_addr,
    )
}

/// C1 / GAP5: XTCP visitor whose punch can never complete falls back to the
/// named STCP proxy and user data flows through the STCP relay. The punch is
/// impossible (dead STUN server) so ANY successful echo proves the fallback
/// path carried it — the XTCP tunnel cannot exist.
#[tokio::test]
async fn test_xtcp_visitor_falls_back_to_stcp_when_punch_impossible() {
    common::init_tracing();
    let (echo_port, server_port, visitor_port, server_addr, visitor_addr) = common_setup().await;
    let _echo_handle = start_echo_server(echo_port);
    let _server_handle = start_frps(server_port, TOKEN).await;
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps port ready");

    let provider_service = start_provider(server_port, echo_port, true).await;
    let _provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(1200)).await; // registration lands first

    let visitor_service = start_visitor(server_port, visitor_port, XTCP_PROXY, STCP_PROXY).await;
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });
    wait_for_port(visitor_addr, Duration::from_secs(15))
        .await
        .expect("visitor port became connectable within 15s");

    // First connection: XTCP punch fails (dead STUN) within ~1 s, then the
    // STCP fallback relay must carry the echo. Budget the whole round trip
    // generously — CI can be slow.
    for (attempt, len) in [(1usize, 512usize), (2, 4096)] {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match expect_echo_round_trip(
                visitor_addr,
                &vec![0x5au8; len],
                &format!("fallback echo attempt {attempt}"),
            )
            .await
            {
                Ok(()) => break,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        panic!(
                            "STCP fallback e2e (attempt {attempt}): no echo before deadline: {e}"
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}

/// C2 / GAP6 (pre_check arm): the visitor targets a proxy name nobody
/// registered (`ghost-xtcp`). The server's pre_check answers "proxy not
/// found", do_hole_punch fails, and user connections must close within the
/// budget — twice in a row (the second connection re-triggers the punch path
/// and fails the same way; it must not be parked by a stuck punch).
#[tokio::test]
async fn test_xtcp_visitor_without_provider_rejects_user_connections() {
    common::init_tracing();
    let (echo_port, server_port, visitor_port, server_addr, visitor_addr) = common_setup().await;
    let _echo_handle = start_echo_server(echo_port);
    let _server_handle = start_frps(server_port, TOKEN).await;
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps port ready");

    // Provider runs but registers NO xtcp proxy the visitor could reach.
    let provider_service = start_provider(server_port, echo_port, false).await;
    let _provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Visitor targets "ghost-xtcp" — pre_check fails with "proxy not found".
    let visitor_service = start_visitor(server_port, visitor_port, "ghost-xtcp", STCP_PROXY).await;
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });
    wait_for_port(visitor_addr, Duration::from_secs(15))
        .await
        .expect("visitor port became connectable within 15s");

    for attempt in 1..=2 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            match expect_conn_closed_without_service(
                visitor_addr,
                Duration::from_secs(15),
                &format!("ghost-provider conn {attempt}"),
            )
            .await
            {
                Ok(()) => break,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        panic!("ghost-provider e2e (conn {attempt}): connection never failed closed: {e}");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}

/// C2 / GAP6 (STUN arm): the target proxy IS registered (pre_check passes)
/// but the visitor's STUN server is dead — do_hole_punch must fail on the
/// STUN phase ("STUN failed, no socket for XTCP P2P") rather than hang or
/// send a full NatHoleVisitor into a session that can never form. Same
/// fail-closed user-connection behavior as the ghost test.
#[tokio::test]
async fn test_xtcp_visitor_with_dead_stun_rejects_user_connections() {
    common::init_tracing();
    let (echo_port, server_port, visitor_port, server_addr, visitor_addr) = common_setup().await;
    let _echo_handle = start_echo_server(echo_port);
    let _server_handle = start_frps(server_port, TOKEN).await;
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps port ready");

    // Provider registers the real XTCP proxy — pre_check passes; only the
    // visitor's STUN is unreachable.
    let provider_service = start_provider(server_port, echo_port, false).await;
    let _provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let visitor_service = start_visitor(server_port, visitor_port, XTCP_PROXY, STCP_PROXY).await;
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });
    wait_for_port(visitor_addr, Duration::from_secs(15))
        .await
        .expect("visitor port became connectable within 15s");

    for attempt in 1..=2 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            match expect_conn_closed_without_service(
                visitor_addr,
                Duration::from_secs(15),
                &format!("dead-stun conn {attempt}"),
            )
            .await
            {
                Ok(()) => break,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        panic!(
                            "dead-stun e2e (conn {attempt}): connection never failed closed: {e}"
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}
