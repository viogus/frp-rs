//! G8 regression (audit round 8): `request_stop` during the login-reconnect
//! backoff must interrupt the sleep and end `run()` promptly, and must not
//! allow further login attempts after the stop was requested.
//!
//! The mock accepts each login attempt, reads the Login frame, and drops the
//! connection without answering — the client's initial-login backoff grows
//! (doubling from a 1s base, 0-10% jitter, cap 10s: sleeps 2s, 4s, 8s, then
//! 10s — see service.rs, Go loopLoginUntilSuccess parity with cap 10s).
//! Once the in-flight backoff sleep is multi-second (login_count >= 4 lands
//! at ~t14s, entering the 10s sleep that follows), the test requests stop.
//!
//! Oracle 1: `run()` returns within 2s of request_stop even though the
//! in-flight backoff sleep would otherwise last seconds (RED if the backoff
//! were not cancellable by the stop signal).
//! Oracle 2: no further login attempt lands at the mock after the stop (a
//! non-cancelled backoff would fire one more connect).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::FrpMessage;
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn stop_during_reconnect_backoff_exits_promptly() {
    common::init_tracing();
    let token = "g8-stop-backoff-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_count = Arc::new(AtomicUsize::new(0));
    // The clone must be hoisted before the coroutine: `async move` captures
    // `login_count` itself when the clone call sits inside, moving the outer
    // binding the test's poll loop still needs.
    let login_count_env = login_count.clone();
    let mock = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.expect("control conn");
            let count = login_count_env.clone();
            tokio::spawn(async move {
                let mut stream = IoStream::Tcp(conn);
                let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                    .await
                    .expect("login timeout")
                    .expect("read Login");
                assert!(matches!(login, FrpMessage::Login(_)));
                count.fetch_add(1, Ordering::SeqCst);
                // No LoginResp: drop the connection so the client backs off
                // and retries.
            });
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

    // Wait until the backoff has definitely grown past the sub-second phase:
    // the 4th dropped attempt lands at ~t14s and is followed by the cap
    // sleep (10s + jitter) — request_stop lands inside it. Generous wall
    // budget for the mock round trips (doubling reaches attempt 4 by ~15s).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while login_count.load(Ordering::SeqCst) < 4 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "login attempts stalled (saw {} after 25s)",
            login_count.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // We are inside the 10s cap sleep that follows the 4th attempt now.
    let attempts_at_stop = login_count.load(Ordering::SeqCst);
    let stopped_at = std::time::Instant::now();
    client.request_stop();

    // Oracle 1: prompt exit. Without the cancellable-sleep arm run() would
    // wait out the remaining backoff (>= 3.2s minus elapsed).
    tokio::time::timeout(Duration::from_secs(2), runner)
        .await
        .expect("run() did not exit within 2s of request_stop during a multi-second reconnect backoff sleep (G8)")
        .expect("client run() panicked");
    assert!(
        stopped_at.elapsed() < Duration::from_secs(2),
        "run() exit was not prompt"
    );

    // Oracle 2: no further login attempt after the stop request.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        attempts_at_stop,
        "a login attempt fired after request_stop — the backoff sleep was not cancelled (G8)"
    );
    // Mock teardown (round-2 review, audit round 8): the mock is an
    // infinite accept loop, so abort it, then await — a JoinHandle that
    // already panicked reports Panicked even after abort, so any mid-test
    // mock assertion failure fails THIS test instead of vanishing with the
    // runtime at scope end.
    mock.abort();
    match mock.await {
        Err(e) if e.is_cancelled() => {}
        other => panic!("mock task ended abnormally: {other:?}"),
    }
}
