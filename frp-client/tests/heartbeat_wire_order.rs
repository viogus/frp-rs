//! G11 pin (audit round 8): heartbeat wire order — no Ping may leave the
//! client before the server has answered Login, and Pings begin only after
//! registration settles into the message loop.
//!
//! The client arms its heartbeat interval at login success (service.rs "single
//! arm point") but sends Pings only from the message loop, which starts after
//! registration completes. A heartbeat implementation that started ticking
//! earlier (e.g. from the dial) would leak Pings into the pre-LoginResp or
//! registration window and confuse a strict server.
//!
//! Mock timeline (heartbeat_interval = 1s):
//!   t0          client dials and sends Login;
//!   t0..t0+1.6s mock is silent: the client must send NOTHING (no Ping) while
//!               blocked in LoginResp wait — a 1.6s window spans a full
//!               heartbeat period;
//!   t0+1.6s     mock writes LoginResp;
//!               registration (NewProxy -> NewProxyResp) round-trips in ms;
//!   post-reg    the message loop starts; the FIRST frame the client writes
//!               must be a Ping (its heartbeat interval ticks immediately on
//!               first poll), and a second Ping must follow ~1s later.
//!
//! Oracles: (1) no frame in the pre-LoginResp window; (2) the first frame
//! after NewProxyResp is a Ping, on the wire within 750ms of the
//! NewProxyResp write (immediacy bound — tick 1 fires on the message loop's
//! first poll, ms after registration; a first tick that waited out its full
//! 1s period would land ~1s late and must RED; rationale in the mock
//! below); (3) a second Ping arrives ~1s after the first; (4) exactly one
//! Login over the whole session.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn no_ping_before_login_resp_pings_begin_after_registration() {
    common::init_tracing();
    let token = "heartbeat-wire-order-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let pong = FrpMessage::Pong(msg::Pong { error: None });

    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    // Signals the mock's post-registration phase completed (Ping cadence
    // verified): the client is heartbeating normally.
    let (pings_ok_tx, pings_ok_rx) = tokio::sync::oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        count.fetch_add(1, Ordering::SeqCst);

        // Oracle 1: before LoginResp the client must send NOTHING. The
        // heartbeat interval is 1s and armed only at login success, so a
        // 1.6s silent window spans a full period: any Ping leaking into it
        // is a wire-order violation. (The Login frame was already read
        // above; the window starts now.) A `timeout` never fires before its
        // deadline — an Err return alone proves the ≥1.6s window held.
        let early = tokio::time::timeout(Duration::from_millis(1600), stream.read_v1_frame()).await;
        match early {
            Err(_) => {}
            Ok(Ok(frame)) => {
                panic!("client sent a frame before LoginResp (wire-order violation): {frame:?}")
            }
            Ok(Err(e)) => panic!("control read failed before LoginResp: {e}"),
        }

        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");

        // Registration round-trip.
        let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("NewProxy timeout")
            .expect("read NewProxy");
        assert!(matches!(np, FrpMessage::NewProxy(_)));
        enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: "p1".into(),
            remote_addr: Some("127.0.0.1:8081".into()),
            error: None,
        }))
        .await
        .expect("write NewProxyResp");

        // Oracle-2 immediacy anchor: registration is complete from the
        // mock's side here; the client finishes processing this
        // NewProxyResp within ms and only then starts the message loop
        // (service.rs: register_proxies Phase 4 -> run_message_loop
        // Phase 6 — pings physically cannot leave before this point, the
        // writer task is not spawned until Phase 5). The heartbeat interval
        // is armed at login success (service.rs:1690, tokio `interval()`:
        // tick 1's deadline is the arm instant) and polled for the first
        // time at loop start, so tick 1 fires immediately: Ping#1 must
        // reach the wire ~ms after this write.
        // Bound 750ms: above the ~500ms registration-path jitter the
        // cadence oracle below already tolerates, below the ~1000ms a first
        // tick that waited out its full 1s period (e.g. an `interval_at`
        // arm, or an eager `tick()` consumed at arm time) would land —
        // indistinguishable from prompt within the old 3s read timeout.
        let reg_complete_at = Instant::now();

        // Oracles 2-3: the message loop starts at registration completion;
        // the first frame must be a Ping (interval first tick), then a
        // second Ping ~1s later.
        let f1 = tokio::time::timeout(Duration::from_secs(3), enc.read_v1_frame())
            .await
            .expect("no frame after registration")
            .expect("read first post-registration frame");
        assert!(
            matches!(f1, FrpMessage::Ping(_)),
            "first post-registration frame must be a Ping, got {f1:?}"
        );
        let first_ping_gap = reg_complete_at.elapsed();
        assert!(
            first_ping_gap <= Duration::from_millis(750),
            "first Ping arrived {}ms after the NewProxyResp write (expected \
             ~ms: tick 1 fires immediately on the message loop's first poll; \
             a first tick that waited out its full 1s period arrives ~1000ms \
             — RED)",
            first_ping_gap.as_millis()
        );
        let first_ping_at = Instant::now();
        let f2 = tokio::time::timeout(Duration::from_secs(3), enc.read_v1_frame())
            .await
            .expect("no second heartbeat")
            .expect("read second post-registration frame");
        assert!(
            matches!(f2, FrpMessage::Ping(_)),
            "second post-registration frame must be a Ping, got {f2:?}"
        );
        let second_gap = first_ping_at.elapsed();
        assert!(
            second_gap >= Duration::from_millis(500) && second_gap <= Duration::from_millis(1800),
            "heartbeat cadence off: second Ping {}ms after the first (expected ~1000ms)",
            second_gap.as_millis()
        );
        // (A wall-clock lower bound on the first Ping's arrival was dropped
        // as a tautology: it measured after f2 was read, so reg_end.elapsed()
        // ≥ second_gap ≥ 500ms by the assert above — it could never fail.)

        // Cadence verified: answer heartbeats until the test stops the
        // client.
        enc.write_v1_frame(&pong).await.expect("write Pong");
        let _ = pings_ok_tx.send(());
        loop {
            match enc.read_v1_frame().await {
                Ok(FrpMessage::Ping(_)) => {
                    enc.write_v1_frame(&pong).await.expect("write Pong");
                }
                Ok(_) => {}
                Err(_) => break, // client closed at stop
            }
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        heartbeat_interval: 1,
        heartbeat_timeout: 10,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    tokio::time::timeout(Duration::from_secs(8), pings_ok_rx)
        .await
        .expect("mock never verified the post-registration Ping cadence")
        .expect("mock task ended before verifying cadence");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the heartbeat wire-order session"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the whole session"
    );
    // The mock's final drain loop ends when the client closes the
    // connection at stop; detach it explicitly for the let_underscore lint.
    std::mem::drop(mock);
}

/// Audit pin (heartbeat re-arm wiring, service.rs "skip_ping" arm): a ping
/// whose auth setup fails must be SKIPPED (not sent, not fatal) and the
/// interval must be re-armed at the 2s Go backoff instead of waiting out the
/// rest of the heartbeat period (client/control.go:253-265 — wait.BackoffUntil
/// replaces the next ticker fire).
///
/// The run loop owns its `tokio::time::Interval` (service.rs:3266-3272 polls
/// `ctx.ping_interval.tick()`, re-armed at :3331-3335) — no unit seam exposes
/// the re-arm, so this is a wire-timing e2e through the real client service.
///
/// Trigger: heartbeat_interval = 6s with auth.additional_auth_scopes =
/// ["HeartBeats"] (heartbeat_requires_auth fires) and a file-based
/// auth.tokenSource. The skip is CLIENT-side and invisible on the wire — the
/// failing ping is never sent — so the mock cannot observe it directly (and
/// an error Pong does not engage the backoff: Go parity, service.rs:2868).
/// The empty-token window is therefore placed CAUSALLY between two
/// wire-visible pings: the mock empties the file only AFTER it has observed
/// Ping#1, so the NEXT interval tick (~6s later, a known deadline) is
/// guaranteed to find the file empty and skip. The restore is a 7s timer
/// anchored at that same Ping#1 observation — inside (skip, skip+2s): ~1s
/// after the skip tick, ~1s before the re-armed tick.
///
/// This kills the two structural corners of the earlier design (which raced
/// a fixed 1.5s restore against the client's independent 2s re-arm timer):
/// a delayed first tick cannot vacuous-pass (the empty window opens only
/// after a wire event, and the first tick must have fired for the mock to
/// see Ping#1 at all), and the mock's restore cannot double-skip unless it
/// stalls >1s past its own timer.
///
/// Mock timeline (heartbeat_interval = 6s, heartbeat_timeout = 15s):
///   L            LoginResp written (token file still populated);
///   L+ρ₁         Ping#1 — the loop's first (immediate) tick SUCCEEDS and is
///                the first frame after LoginResp (no proxies, no
///                registration frames). ρ₁ is the client's login→loop-start
///                latency, milliseconds on loopback;
///   P1           mock observes Ping#1: records P1, Pongs, then empties the
///                token file (the skip window opens HERE, not at LoginResp);
///   P1+6s−ρ₁     interval tick 2 → key-gen fails on the empty file → SKIP,
///                interval re-armed at the 2s backoff;
///   P1+7s        mock restores the token file — after the skip, ~1s before
///                the re-armed tick;
///   P1+8s−ρ₁     Ping#2 — the re-armed tick's ping (the pin: without the
///                re-arm the next interval tick fires at L+12s, ~4s later);
///   P1+14s−ρ₁    Ping#3 — the interval cadence (6s period) is back.
///
/// Oracles (all anchored at P1 — the mock's own wire observation, never at
/// test start):
///   (1) the first frame after LoginResp is a Ping (Ping#1), arriving
///       within 1s of the LoginResp write (immediacy bound: the interval's
///       first tick fires on the message loop's first poll, ms after login
///       success — a first tick that waited out its full 6s period would
///       land ~6000ms late, well inside the old 10s read timeout, so the
///       absolute bound is asserted separately);
///   (2) Ping#2 − Ping#1 ∈ [7.4s, 9.0s] — skip at ~6s + one 2s backoff. A
///   (2) Ping#2 − Ping#1 ∈ [7.4s, 9.0s] — skip at ~6s + one 2s backoff. A
///       tick that waited out the full interval lands at ~12s (RED), as does
///       a second 2s doubling (the re-armed tick firing before the restore);
///   (3) Ping#3 − Ping#2 ∈ [5.0s, 7.5s] — the 6s cadence is back (a backoff
///       that never cleared keeps re-arming 2s ticks — RED);
///   (4) exactly one Login.
///
/// Documented residual: the skip moment is the client's poll of tick 2,
/// invisible to the mock. If that poll is stalled past the P1+7s restore the
/// tick finds the file populated and succeeds — the skip is not exercised.
/// The stall must exceed ~1s AND land Ping#2 in the oracle window to pass
/// silently (1.4s-3s band); the earlier design vacuous-passed on any >1.5s
/// stall of the login→loop-start path and spuriously RED'd on a >0.5s
/// mock-side restore stall — both bounds now sit at ≥1s and the empty window
/// itself is event-gated, so the common failure modes are gone.
#[tokio::test]
async fn skipped_ping_rearms_interval_on_two_second_backoff() {
    common::init_tracing();
    let token = "heartbeat-rearm-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // File-based auth.tokenSource: Service::new resolves the real token from
    // this file (the control conn encryption key derives from it). The file
    // keeps the token through Login AND the first heartbeat tick (Ping#1);
    // the mock empties it only after observing Ping#1 on the wire, so tick 2
    // (~6s later) deterministically skips, and restores it 7s after Ping#1
    // (measured from that same wire event — no test-start anchor).
    let dir = tempfile::tempdir().expect("tempdir");
    let token_path = dir.path().join("token.txt");
    std::fs::write(&token_path, token).expect("write initial token file");

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let pong = FrpMessage::Pong(msg::Pong { error: None });

    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    // Signals the mock verified all wire-timing oracles (immediacy bound +
    // skip/re-arm cadence).
    let (pings_ok_tx, pings_ok_rx) = tokio::sync::oneshot::channel::<()>();
    let mock_token_path = token_path.clone();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        count.fetch_add(1, Ordering::SeqCst);

        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");

        // Oracle-1 immediacy anchor: the client arms its heartbeat interval
        // when it processes this LoginResp (service.rs:1690, tokio
        // `interval()`: tick 1's deadline is the arm instant). This session
        // has no proxies or visitors, so the registration phase
        // (service.rs register_proxies — nothing pending) and the loop
        // start follow within ms; the interval is polled for the first time
        // at loop start, tick 1 fires immediately, and Ping#1 must reach
        // the wire ~ms after this write.
        // Bound 1s: above the ~500ms jitter envelope this file tolerates
        // elsewhere (the [7.4s, 9.0s] / [5.0s, 7.5s] windows below), below
        // the ~6000ms a first tick that waited out its full 6s period
        // (e.g. an `interval_at` arm, or an eager `tick()` consumed at arm
        // time) would land — invisible to the old 10s read timeout alone.
        let login_resp_at = Instant::now();
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");

        // Phase 1 — the first (immediate) tick succeeds: the file still
        // holds the token. The first frame after LoginResp must be a Ping
        // (no proxies, so there is no registration traffic to precede it).
        let f1 = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("no first tick Ping after LoginResp")
            .expect("read first Ping");
        assert!(
            matches!(f1, FrpMessage::Ping(_)),
            "first frame after LoginResp must be a Ping, got {f1:?}"
        );
        let first_ping_gap = login_resp_at.elapsed();
        assert!(
            first_ping_gap <= Duration::from_secs(1),
            "first Ping arrived {}ms after LoginResp (expected ~ms: tick 1 \
             fires immediately on the message loop's first poll; a first \
             tick that waited out its full 6s period arrives ~6000ms — RED)",
            first_ping_gap.as_millis()
        );
        let p1_at = Instant::now();
        enc.write_v1_frame(&pong).await.expect("write Pong");

        // Arm the skip causally: empty the token file NOW, after Ping#1 was
        // observed on the wire. The next interval tick fires ~6s later (the
        // interval's own deadline — the client cannot tick before it), so
        // the skip window provably covers it.
        std::fs::write(&mock_token_path, "").expect("empty token file");
        // Restore 7s after Ping#1: inside (skip, skip+2s) with ~1s margins
        // on both sides (skip at ~6s, re-armed tick at ~8s minus the ms of
        // client latency folded into P1).
        tokio::time::sleep(Duration::from_secs(7)).await;
        std::fs::write(&mock_token_path, token).expect("restore token file");

        // Oracle 2: Ping#2 = the re-armed tick's ping, ~8s after Ping#1
        // (tick-2 skip at ~6s + one 2s backoff). A tick that waited out the
        // full 6s period would land at ~12s — RED.
        let f2 = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("no re-armed Ping after the skip")
            .expect("read second Ping");
        assert!(
            matches!(f2, FrpMessage::Ping(_)),
            "expected the re-armed heartbeat to send a Ping, got {f2:?}"
        );
        let ping2_gap = p1_at.elapsed();
        assert!(
            ping2_gap >= Duration::from_millis(7400) && ping2_gap <= Duration::from_millis(9000),
            "re-armed Ping arrived {}ms after Ping#1 (expected ~8000ms: tick-2 \
             skip at ~6000ms + one 2s backoff; a tick that waited out the 6s \
             period, or a second 2s doubling, lands at ~12000ms)",
            ping2_gap.as_millis()
        );
        enc.write_v1_frame(&pong).await.expect("write Pong");

        // Oracle 3: Ping#3 ~6s after Ping#2 — the interval cadence is back
        // (the successful ping cleared ping_retry_backoff; a backoff that
        // never cleared would keep re-arming 2s ticks — RED).
        let f3 = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("no third Ping")
            .expect("read third Ping");
        assert!(
            matches!(f3, FrpMessage::Ping(_)),
            "expected the next interval tick to send a Ping, got {f3:?}"
        );
        let total_gap = p1_at.elapsed();
        let gap_between_pings = total_gap.saturating_sub(ping2_gap);
        assert!(
            gap_between_pings >= Duration::from_millis(5000)
                && gap_between_pings <= Duration::from_millis(7500),
            "heartbeat cadence not restored: Ping#3 came {}ms after Ping#2 \
             (expected ~6000ms — the 6s interval period; a backoff that never \
             cleared would tick at ~2s)",
            gap_between_pings.as_millis()
        );
        enc.write_v1_frame(&pong).await.expect("write Pong");
        let _ = pings_ok_tx.send(());

        // Cadence verified: answer heartbeats until the test stops the client.
        loop {
            match enc.read_v1_frame().await {
                Ok(FrpMessage::Ping(_)) => {
                    enc.write_v1_frame(&pong).await.expect("write Pong");
                }
                Ok(_) => {}
                Err(_) => break, // client closed at stop
            }
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        // auth.tokenSource drives both the login key and the per-ping key
        // (the arm reads the file again on every ping); the literal token is
        // kept in sync so the resolved value never diverges from the mock's
        // expectation.
        auth: Some(frp_core::config::AuthClientConfig {
            method: "token".into(),
            token: token.into(),
            token_source: Some(frp_core::config::ValueSource {
                source_type: "file".into(),
                file: Some(frp_core::config::FileSource {
                    path: token_path.to_str().unwrap().to_string(),
                }),
                exec: None,
            }),
            additional_auth_scopes: vec!["HeartBeats".into()],
            ..Default::default()
        }),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        heartbeat_interval: 6,
        heartbeat_timeout: 15,
        proxies: vec![],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // Wall time: Ping#1 right after login + Ping#2 ~8s later + Ping#3 ~6s
    // after that, plus startup margin.
    tokio::time::timeout(Duration::from_secs(25), pings_ok_rx)
        .await
        .expect("mock never verified the skip/re-arm Ping cadence")
        .expect("mock task ended before verifying cadence");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the heartbeat re-arm session"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(8), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the whole session"
    );
    std::mem::drop(mock);
}
