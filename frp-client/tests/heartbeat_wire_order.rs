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
//! after NewProxyResp is a Ping; (3) a second Ping arrives ~1s after the
//! first; (4) exactly one Login over the whole session.

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
/// auth.tokenSource. The mock empties the token file right after Login, so
/// the message loop's FIRST heartbeat tick (immediate on first poll) fails
/// key generation and skips. The file is restored 1.5s later, so the re-armed
/// tick (2s out) succeeds.
///
/// Mock timeline (heartbeat_interval = 6s, heartbeat_timeout = 15s):
///   t0           LoginResp written (token file already emptied);
///   t0+1.5s      token file restored with the real token;
///   t0+~2.0s     Ping#1 — first (immediate) tick skipped + one 2s backoff
///                re-arm. Without the re-arm the next tick would fire a full
///                6s period after the first; without the backoff reset the
///                cadence would stay at 2s.
///   +~6.0s       Ping#2 — proves the interval cadence (6s period) is back.
///
/// Oracles: (1) Ping#1 arrives in [1.3s, 4.5s] after LoginResp (a tick that
/// waited out the full 6s period lands at ~6.0s — RED); (2) the Ping#1→Ping#2
/// gap is in [5.0s, 7.5s] (a backoff that never cleared re-arms 2s ticks —
/// RED); (3) exactly one Login.
#[tokio::test]
async fn skipped_ping_rearms_interval_on_two_second_backoff() {
    common::init_tracing();
    let token = "heartbeat-rearm-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // File-based auth.tokenSource: Service::new resolves the real token from
    // this file (the control conn encryption key derives from it), the mock
    // empties it after Login so the first ping's key generation fails, and
    // restores it after 1.5s so the re-armed tick's key generation succeeds.
    // An EMPTY file is used rather than a missing one so a first tick delayed
    // up to the restore moment still deterministically skips (an empty token
    // is a key-generation error; a missing file would only error before the
    // restore point).
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
    // Signals the mock verified both wire-timing oracles.
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

        // Empty the token file BEFORE LoginResp: the message loop's first
        // (immediate) heartbeat tick lands after this and must skip.
        std::fs::write(&mock_token_path, "").expect("empty token file");
        let login_resp_at = Instant::now();
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");
        // Restore the real token 1.5s in: safely inside the deleted window
        // for the immediate first tick AND before the 2s re-armed tick.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        std::fs::write(&mock_token_path, token).expect("restore token file");

        // Oracle 1: Ping#1 at ~2.0s after LoginResp (skip + one 2s backoff).
        let f1 = tokio::time::timeout(Duration::from_secs(8), enc.read_v1_frame())
            .await
            .expect("no first Ping after the skip/re-arm")
            .expect("read first Ping");
        assert!(
            matches!(f1, FrpMessage::Ping(_)),
            "expected the re-armed heartbeat to send a Ping, got {f1:?}"
        );
        let first_ping_gap = login_resp_at.elapsed();
        assert!(
            first_ping_gap >= Duration::from_millis(1300)
                && first_ping_gap <= Duration::from_millis(4500),
            "re-armed Ping arrived {}ms after LoginResp (expected ~2000ms: \
             immediate first tick skipped + one 2s backoff; a tick that \
             waited out the 6s period lands at ~6000ms)",
            first_ping_gap.as_millis()
        );
        enc.write_v1_frame(&pong).await.expect("write Pong");

        // Oracle 2: Ping#2 ~6s after Ping#1 — the interval cadence is back
        // (the backoff reset cleared ping_retry_backoff after the success).
        let f2 = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("no second Ping")
            .expect("read second Ping");
        assert!(
            matches!(f2, FrpMessage::Ping(_)),
            "expected the next interval tick to send a Ping, got {f2:?}"
        );
        // Ping#2's gap from Ping#1: the frame above was read at
        // `first_ping_gap` after LoginResp; the total elapsed since
        // LoginResp minus that gap is the inter-Ping interval.
        let total_gap = login_resp_at.elapsed();
        let gap_between_pings = total_gap.saturating_sub(first_ping_gap);
        assert!(
            gap_between_pings >= Duration::from_millis(5000)
                && gap_between_pings <= Duration::from_millis(7500),
            "heartbeat cadence not restored: Ping#2 came {}ms after Ping#1 \
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

    // Wall time: Ping#1 ~2s + Ping#2 ~6s after LoginResp plus startup margin.
    tokio::time::timeout(Duration::from_secs(20), pings_ok_rx)
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
