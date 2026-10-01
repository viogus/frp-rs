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

/// Assert `frame` is a Ping carrying the login-style key `md5(token, ts)` and
/// return its timestamp. The key is what makes the cached-snapshot pin
/// decisive: a client that re-resolved `auth.tokenSource` after the mock
/// emptied the file would either skip the ping or key it with a different
/// token, and this equality fails in both cases.
fn assert_ping_key(frame: &FrpMessage, token: &str) -> i64 {
    let (key, ts) = match frame {
        FrpMessage::Ping(p) => (
            p.privilege_key
                .clone()
                .expect("Ping must carry a privilege_key when HeartBeats is in auth scopes"),
            p.timestamp.expect("Ping must carry a timestamp"),
        ),
        other => panic!("expected Ping, got {other:?}"),
    };
    assert_eq!(
        key,
        frp_core::auth::generate_token(token, ts),
        "Ping key must be md5(startup token, ping timestamp): frpc must reuse \
         the construction-time auth.tokenSource snapshot, never re-read the \
         source (Go frp client/service.go:168 + :316 resolve once)"
    );
    ts
}

/// Audit pin (heartbeat auth snapshot wiring): with an `auth.tokenSource` the
/// client resolves the source ONCE at construction and reuses that snapshot for
/// every heartbeat — the same shape as Go frp (`client/service.go:168`
/// `auth.BuildClientAuth` resolves inside `NewService`; `:316` hands that one
/// runtime to every login; `pkg/auth/token.go` SetPing just calls
/// `util.GetAuthKey(auth.token, ts)` on the cached string). A source that
/// becomes unreadable after startup must therefore NOT skip a ping, re-arm the
/// interval, or otherwise disturb the 6s cadence.
///
/// History: this test used to pin the opposite — a ping whose auth setup failed
/// was SKIPPED (not sent, not fatal) and the interval re-armed at the 2s Go
/// backoff (`client/control.go:253-265`, `wait.BackoffUntil`). That arm is now
/// unreachable from a token source: with `AuthConfig.token_source` left unset
/// for the client, `resolve_token()` cannot fail (`frp-core/src/auth.rs:347`)
/// and the file is never re-read, so nothing can trigger the skip. The skip arm
/// still exists for the OIDC ping path (`oidc_client.set_ping`), which is not
/// exercised here — this test pins the cached-snapshot behaviour that replaced
/// the token-source skip, and keeps the event-gated wire-timing scaffolding
/// because the cadence bound is still what proves the source is not re-read.
///
/// Trigger: heartbeat_interval = 6s with auth.additional_auth_scopes =
/// ["HeartBeats"] (heartbeat_requires_auth fires) and a file-based
/// auth.tokenSource. The mock empties the file only AFTER it has observed
/// Ping#1 on the wire and never restores it, so every later tick would fail if
/// the client re-resolved the source. Each Ping also carries the login-style
/// key `md5(token, timestamp)`, checked against the STARTUP token's value — a
/// re-read of the emptied file could not produce it, which makes the key
/// assertion decisive on its own (the cadence bound is the visible symptom).
///
/// Mock timeline (heartbeat_interval = 6s, heartbeat_timeout = 15s):
///   L            LoginResp written (token file still populated);
///   L+ρ₁         Ping#1 — the loop's first (immediate) tick SUCCEEDS and is
///                the first frame after LoginResp (no proxies, no
///                registration frames). ρ₁ is the client's login→loop-start
///                latency, milliseconds on loopback;
///   P1           mock observes Ping#1: checks its key, Pongs, then empties the
///                token file and leaves it empty;
///   P1+6s−ρ₁     Ping#2 — the normal interval tick, keyed with the startup
///                snapshot. Pre-fix the tick's re-read of the emptied file
///                fails, the skip arm re-arms the interval, and because the
///                file is never restored every later tick skips too: no Ping#2
///                ever arrives (measured pre-fix: the 10s read below times out)
///                — RED;
///   P1+12s−ρ₁    Ping#3 — the 6s cadence continues with the same snapshot.
///
/// Oracles (all anchored at P1 — the mock's own wire observation, never at
/// test start):
///   (1) the first frame after LoginResp is a Ping (Ping#1), arriving within 1s
///       of the LoginResp write (immediacy bound: the interval's first tick
///       fires on the message loop's first poll, ms after login success — a
///       first tick that waited out its full 6s period would land ~6000ms
///       late, well inside the 10s read timeout, so the absolute bound is
///       asserted separately);
///   (2) every Ping's privilege_key == md5(token, its own timestamp) — the
///       startup snapshot, never a re-read of the emptied file;
///   (3) Ping#2 − Ping#1 ∈ [5.0s, 7.5s] — the 6s period. A re-read of the
///       emptied file fails and takes the skip arm, so pre-fix no further Ping
///       is sent at all and the 10s read times out (measured) — RED; a tick
///       that waited out the full 6s period would also land outside this
///       window;
///   (4) Ping#3 − Ping#2 ∈ [5.0s, 7.5s] — the cadence is steady (a backoff
///       that kept re-arming would tick at ~2s);
///   (5) exactly one Login.
///
/// Documented residual: the skip moment would be the client's poll of tick 2,
/// invisible to the mock. It can no longer be produced by a token source (see
/// History above), so this test no longer covers that arm at all.
#[tokio::test]
async fn ping_reuses_startup_token_snapshot_when_source_becomes_unreadable() {
    common::init_tracing();
    let token = "heartbeat-snapshot-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // File-based auth.tokenSource: Service::new resolves the real token from
    // this file ONCE (the control conn encryption key derives from it). The
    // file keeps the token through Login AND the first heartbeat tick (Ping#1);
    // the mock empties it only after observing Ping#1 on the wire and never
    // restores it, so every later tick proves the client reused the
    // construction-time snapshot instead of re-reading.
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
    // cached-snapshot cadence + per-ping keys).
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
        // elsewhere (the [5.0s, 7.5s] cadence windows below), below
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
        assert_ping_key(&f1, token);
        enc.write_v1_frame(&pong).await.expect("write Pong");

        // The snapshot must be reused, not re-read: empty the file NOW, after
        // Ping#1 was observed on the wire, and never restore it. Every later
        // tick would fail if the client re-resolved the source.
        std::fs::write(&mock_token_path, "").expect("empty token file");

        // Oracle 2: Ping#2 is the normal interval tick (~6s after Ping#1), not
        // a skipped tick re-armed 2s later (~8s) — and it is keyed with the
        // STARTUP token, which the emptied file could not supply.
        let f2 = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("no Ping after the token source was emptied")
            .expect("read second Ping");
        assert_ping_key(&f2, token);
        let ping2_gap = p1_at.elapsed();
        assert!(
            ping2_gap >= Duration::from_millis(5000) && ping2_gap <= Duration::from_millis(7500),
            "Ping#2 arrived {}ms after Ping#1 (expected ~6000ms — the normal 6s \
             interval). A client that re-read the emptied auth.tokenSource \
             would skip this tick and, with the file never restored, every \
             later one too — measured pre-fix: no Ping#2 arrives at all, the \
             10s read above times out — RED",
            ping2_gap.as_millis()
        );
        enc.write_v1_frame(&pong).await.expect("write Pong");

        // Oracle 3: the 6s cadence continues while the source stays
        // unreadable, still keyed with the startup snapshot.
        let f3 = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("no third Ping")
            .expect("read third Ping");
        assert_ping_key(&f3, token);
        let gap_between_pings = p1_at.elapsed().saturating_sub(ping2_gap);
        assert!(
            gap_between_pings >= Duration::from_millis(5000)
                && gap_between_pings <= Duration::from_millis(7500),
            "heartbeat cadence drifted: Ping#3 came {}ms after Ping#2 (expected \
             ~6000ms — the 6s interval period; a skip would land at ~8000ms)",
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
        // auth.tokenSource supplies the resolved snapshot at construction
        // (Service::with_unsafe_features); both the login key and the per-ping
        // key are computed from that one cached value. The literal token is
        // kept in sync so the config's own view never diverges.
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

    // Wall time: Ping#1 right after login + Ping#2 ~6s later + Ping#3 ~6s
    // after that, plus startup margin.
    tokio::time::timeout(Duration::from_secs(25), pings_ok_rx)
        .await
        .expect("mock never verified the cached-snapshot Ping cadence")
        .expect("mock task ended before verifying cadence");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the heartbeat snapshot session"
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
