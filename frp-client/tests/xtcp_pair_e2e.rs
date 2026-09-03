#![cfg(all(feature = "quic", feature = "kcp"))]
//! XTCP NAT hole-punch end-to-end test: frps + TWO real in-process frpc
//! services (provider + visitor), the full NatHole success flow, a MakeHole
//! UDP hole punch on loopback, and user data bridged through the resulting
//! P2P tunnel and back.
//!
//! Closes the audit-round-3 test-coverage gap T1 (CONFIRMED): no existing
//! test drives the XTCP SUCCESS path through the frp-client service layer —
//! every current XTCP test either exercises raw sockets against a server
//! ([`frp-server/tests/xtcp_hole_punch.rs`], [`xtcp_edge.rs`],
//! [`xtcp_fallback.rs`]) or the core punch machinery in isolation
//! ([`frp-core/tests/xtcp_p2p.rs`]). This test runs the real clients: the
//! visitor STUNs, sends NatHoleVisitor over its control connection, the
//! server classifies both peers' NAT and answers both sides with
//! NatHoleResp, the punched sockets carry a QUIC tunnel session, and echo
//! traffic flows visitor local port -> P2P tunnel -> provider local service
//! -> and back.
//!
//! Loopback classification outcome: both clients query the local mock STUN
//! responder from the socket they will punch with, so every STUN returns the
//! same mapped address (127.0.0.1:<socket port>). The server classifies both
//! peers EasyNAT/BehaviorNoChange and the mode-0 analyzer table (all-zero
//! scores -> index 0) casts the provider as the MakeHole *sender* and the
//! visitor as the *receiver*. The mock responder is stateless and echoes the
//! request txid, so repeated punches in the same test are fine.
//!
//! Timing model: the visitor punches on demand — the first user connection
//! signals the punch (re-punches are spaced >= 10 s apart by
//! `process_tunnel_start_events`). User connections wait up to
//! `min(20s, fallback_timeout_ms)` for the tunnel, so the echo flow is a
//! bounded retry loop under one 90 s deadline rather than a fixed sleep.

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use common::{allocate_port, allocate_udp_port, start_echo_server, start_frps, wait_for_port};

const TOKEN: &str = "xtcp-e2e-token";
const SK: &str = "xtcp-e2e-secret";
const PROVIDER_PROXY: &str = "echo-provider";

/// Mock STUN responder (RFC 5389 Binding). Replies to every Binding Request
/// (type 0x0001, magic cookie, >= 20 bytes) with a Binding Success Response
/// (0x0101) that echoes the request txid and carries a MAPPED-ADDRESS
/// attribute (0x0001) set to the OBSERVED SOURCE of the request. On loopback
/// that source is the client's own UDP socket — the exact address the
/// MakeHole probe needs to reach. No OTHER-ADDRESS is sent: the client then
/// re-queries this same server for its second STUN sample (the classifier
/// only needs >= 2 mapped addresses).
async fn run_mock_stun_server(socket: tokio::net::UdpSocket) {
    let mut buf = vec![0u8; 512];
    loop {
        let Ok((n, src)) = socket.recv_from(&mut buf).await else {
            return;
        };
        // 20-byte header + Binding Request + RFC 5389 magic cookie.
        if n < 20
            || u16::from_be_bytes([buf[0], buf[1]]) != 0x0001
            || buf[4..8] != 0x2112_A442u32.to_be_bytes()
        {
            continue;
        }
        let std::net::IpAddr::V4(ip) = src.ip() else {
            continue; // bound on 127.0.0.1 — only IPv4 sources arrive
        };
        let mut resp = Vec::with_capacity(32);
        // Binding Success Response (0x0101); message length = all attribute
        // bytes after the 20-byte header (RFC 5389): 2 type + 2 length + 8
        // value for the single MAPPED-ADDRESS attribute.
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&0x2112_A442u32.to_be_bytes()); // magic cookie
        resp.extend_from_slice(&buf[8..20]); // echoed txid
        resp.extend_from_slice(&0x0001u16.to_be_bytes()); // MAPPED-ADDRESS
        resp.extend_from_slice(&8u16.to_be_bytes()); // value length (8)
        resp.push(0x00); // reserved
        resp.push(0x01); // family: IPv4
        resp.extend_from_slice(&src.port().to_be_bytes());
        resp.extend_from_slice(&ip.octets());
        let _ = socket.send_to(&resp, src).await;
    }
}

/// Deterministic payload of `len` bytes (repeating 0x00..=0xFA pattern) so
/// an echo mismatch is a corruption, not a coincidence of zeros.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// One user connection through the XTCP tunnel: connect to the visitor port,
/// write `payload`, read exactly `payload.len()` echoed bytes back, verify.
async fn single_echo_round_trip(
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
    tokio::time::timeout(Duration::from_secs(20), stream.write_all(pld))
        .await
        .map_err(|_| format!("{label}: write of {} B timed out", pld.len()))?
        .map_err(|e| format!("{label}: write failed: {e}"))?;
    let mut buf = vec![0u8; pld.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
        .await
        .map_err(|_| format!("{label}: read of {} B echoed timed out", pld.len()))?
        .map_err(|e| format!("{label}: read failed: {e}"))?;
    if buf != pld {
        return Err(format!("{label}: echo mismatch ({} B)", pld.len()));
    }
    Ok(())
}

/// Retry `single_echo_round_trip` until it succeeds or `deadline` passes.
/// A failed attempt means the punch is in flight or spaced out (>= 10 s
/// between punch starts), so the next connection simply signals again.
/// Panics with the stage + last error when the deadline expires.
async fn echo_until(
    visitor_addr: SocketAddr,
    deadline: tokio::time::Instant,
    pld: &[u8],
    stage: &str,
) {
    let mut attempt = 0u32;
    let mut failures: Vec<String> = Vec::new();
    loop {
        attempt += 1;
        let label = format!("{stage} attempt {attempt}");
        match tokio::time::timeout(
            Duration::from_secs(40),
            single_echo_round_trip(visitor_addr, pld, &label),
        )
        .await
        {
            Ok(Ok(())) => return,
            Ok(Err(e)) => failures.push(e),
            Err(_) => failures.push(format!("{label}: exceeded the 40 s per-attempt budget")),
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "XTCP e2e ({stage}): no echo through the P2P tunnel before the deadline \
                 ({attempt} attempts; last error: {})",
                failures
                    .last()
                    .map(String::as_str)
                    .unwrap_or("no attempt completed")
            );
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

/// Full XTCP NAT hole-punch relay test: frps + provider frpc (registers the
/// `echo-provider` XTCP proxy) + visitor frpc (binds a local TCP port for the
/// tunnel) + a local mock STUN responder replacing the default public STUN
/// server on BOTH clients.
#[tokio::test]
async fn test_xtcp_pair_e2e_hole_punch_relay() {
    common::init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let visitor_port = allocate_port();
    let stun_port = allocate_udp_port(); // UDP-probed: STUN runs on UDP

    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let visitor_addr: SocketAddr = format!("127.0.0.1:{visitor_port}").parse().unwrap();

    // 1. The provider's local service (the XTCP tunnel terminates here).
    let _echo_handle = start_echo_server(echo_port);

    // 2. Mock STUN responder — bound before the clients start; both sides
    //    query it on every hole punch.
    let stun_socket = tokio::net::UdpSocket::bind(("127.0.0.1", stun_port))
        .await
        .expect("bind mock STUN responder");
    let _stun_handle = tokio::spawn(run_mock_stun_server(stun_socket));
    let stun_server = format!("127.0.0.1:{stun_port}");

    // 3. frps — the control-plane NAT coordinator (never relays XTCP data).
    let _server_handle = start_frps(server_port, TOKEN).await;
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps port ready");

    // 4. Provider frpc: registers the XTCP proxy. XTCP opens no server-side
    //    listener — the provider only accepts hole-punched P2P connections.
    let provider_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2,
        nat_hole_stun_server: stun_server.clone(),
        proxies: vec![ProxyConfig {
            name: PROVIDER_PROXY.into(),
            proxy_type: "xtcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: 0, // no server listener for XTCP
            sk: SK.into(),
            enabled: true, // derived Default leaves it false; serde-only default_true
            ..Default::default()
        }],
        ..Default::default()
    };
    let provider_service = ClientService::new(provider_cfg, None)
        .await
        .expect("create provider client service");
    let _provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });
    // Head start so the provider's login + XTCP registration lands before
    // the first visitor connection fires a hole punch (a pre-check miss
    // merely costs a punch attempt, but it also spaces the next one 10 s).
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // 5. Visitor frpc (a SECOND, independent client service): binds a local
    //    TCP port and tunnels it to the provider's XTCP proxy. `protocol:
    //    "quic"` is the Go-parity default data plane (quinn over the punched
    //    socket; the provider side is the QUIC server). The 20 s
    //    `fallback_timeout_ms` gives the first user connection a full
    //    open_tunnel budget (Go caps it at 20 s anyway) — wide enough to
    //    ride out one punch + NAT exchange; `fallback_to` is empty so a
    //    slow punch never diverts to an STCP fallback.
    let visitor_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        nat_hole_stun_server: stun_server,
        visitors: vec![VisitorConfig {
            name: "xtcp-visitor".into(),
            visitor_type: "xtcp".into(),
            server_name: PROVIDER_PROXY.into(),
            secret_key: SK.into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port as i32,
            protocol: "quic".into(),
            fallback_timeout_ms: 20_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let visitor_service = ClientService::new(visitor_cfg, None)
        .await
        .expect("create visitor client service");
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });

    // 6. The visitor binds its local port immediately; these probe
    //    connections may also fire the first punch (harmless — a punch
    //    completes in the background and persists in the tunnel slot).
    wait_for_port(visitor_addr, Duration::from_secs(15))
        .await
        .expect("visitor port became connectable within 15s");

    // 7. First echo through the P2P tunnel: fires the initial hole punch,
    //    then must complete the round trip within the 90 s deadline.
    let stage1_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    echo_until(
        visitor_addr,
        stage1_deadline,
        &payload(64),
        "first user connection",
    )
    .await;

    // 8. The punched session persists in the visitor's tunnel slot, so a
    //    SECOND user connection opens a new stream on the SAME session —
    //    no re-punch. Give it a short deadline: success is normally
    //    immediate (a re-punch, if the session somehow died, is spaced
    //    >= 10 s and would need the retry loop to land after it).
    let stage2_deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    echo_until(
        visitor_addr,
        stage2_deadline,
        &payload(1 << 12),
        "second user connection (tunnel-session reuse)",
    )
    .await;
}

/// Data-volume + same-connection stability leg: one connection carries
/// three round trips (32 B, 64 KiB, 256 KiB) — every byte must come back
/// exact over the P2P tunnel. Runs after the punch is established.
#[tokio::test]
async fn test_xtcp_pair_e2e_tunnel_volume_and_stability() {
    common::init_tracing();
    // Fast path — a fresh pair of services, same shape as the relay test.
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let visitor_port = allocate_port();
    let stun_port = allocate_udp_port();

    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let visitor_addr: SocketAddr = format!("127.0.0.1:{visitor_port}").parse().unwrap();

    let _echo_handle = start_echo_server(echo_port);
    let stun_socket = tokio::net::UdpSocket::bind(("127.0.0.1", stun_port))
        .await
        .expect("bind mock STUN responder");
    let _stun_handle = tokio::spawn(run_mock_stun_server(stun_socket));
    let stun_server = format!("127.0.0.1:{stun_port}");

    let _server_handle = start_frps(server_port, TOKEN).await;
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps port ready");

    let client_cfg = |visitors: Vec<VisitorConfig>, proxies: Vec<ProxyConfig>| ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: TOKEN.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 2,
        nat_hole_stun_server: stun_server.clone(),
        proxies,
        visitors,
        ..Default::default()
    };

    let provider_cfg = client_cfg(
        vec![],
        vec![ProxyConfig {
            name: PROVIDER_PROXY.into(),
            proxy_type: "xtcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: 0,
            sk: SK.into(),
            enabled: true, // derived Default leaves it false; serde-only default_true
            ..Default::default()
        }],
    );
    let provider_service = ClientService::new(provider_cfg, None)
        .await
        .expect("create provider client service");
    let _provider_handle = tokio::spawn(async move {
        let _ = provider_service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let visitor_cfg = client_cfg(
        vec![VisitorConfig {
            name: "xtcp-visitor".into(),
            visitor_type: "xtcp".into(),
            server_name: PROVIDER_PROXY.into(),
            secret_key: SK.into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port as i32,
            protocol: "quic".into(),
            fallback_timeout_ms: 20_000,
            ..Default::default()
        }],
        vec![],
    );
    let visitor_service = ClientService::new(visitor_cfg, None)
        .await
        .expect("create visitor client service");
    let _visitor_handle = tokio::spawn(async move {
        let _ = visitor_service.run().await;
    });

    wait_for_port(visitor_addr, Duration::from_secs(15))
        .await
        .expect("visitor port became connectable within 15s");

    // Establish the tunnel with a small round trip first.
    let stage1_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    echo_until(
        visitor_addr,
        stage1_deadline,
        &payload(64),
        "establish tunnel",
    )
    .await;

    // One connection, three round trips of growing size. The tunnel is up,
    // so each leg is fast; the 90 s cap only guards against a wedged bridge.
    let mut stream = tokio::net::TcpStream::connect(visitor_addr)
        .await
        .expect("connect to visitor port after tunnel established");
    for (leg, len) in [(1usize, 32usize), (2, 64 << 10), (3, 256 << 10)] {
        let pld = payload(len);
        let label = format!("volume leg {leg} ({len} B)");
        let outcome = tokio::time::timeout(Duration::from_secs(90), async {
            stream.write_all(&pld).await?;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(buf)
        })
        .await;
        let buf = match outcome {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => panic!("{label}: tunnel I/O failed: {e}"),
            Err(_) => panic!("{label}: tunnel I/O exceeded the 90 s budget"),
        };
        assert_eq!(&buf, &pld, "{label}: echo mismatch through the P2P tunnel");
    }
    drop(stream);
}
