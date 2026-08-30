//! `login_fail_exit` semantics: with a server that ALWAYS rejects Login,
//! - `login_fail_exit = true` (the ClientConfig default): `run()` returns
//!   the login error immediately and the client does NOT retry;
//! - `login_fail_exit = false`: the client reconnects — a second Login
//!   frame arrives after the initial-login backoff (1s base ×2, cap 10s,
//!   + ≤10% jitter → first retry ≈2.0-2.2s).
//!
//! Previously the `login_fail_exit = true` path (service.rs Err arm) had no
//! test: every existing mock either completes login or runs with
//! `login_fail_exit: false`.
//!
//! The mock answers every Login with `LoginResp{error}` (rejects auth on
//! all attempts) and counts the Login frames it receives.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// Spawn a mock server that rejects every Login and counts the Login frames.
/// Returns the login counter; the listener is owned by the task.
fn spawn_rejecting_server(server_port: u16) -> (tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    // Bind synchronously: #[tokio::test] is a current-thread runtime, so a
    // listener bound inside the spawned task would not exist yet when the
    // client's first dial lands — a refused connect resolves Ready without
    // yielding, run() returns the error (login_fail_exit=true) before any
    // Login frame, and the test fails deterministically.
    let std_listener =
        std::net::TcpListener::bind(("127.0.0.1", server_port)).expect("mock server bind");
    std_listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let listener = tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
    let handle = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.expect("control conn");
            let mut stream = IoStream::Tcp(conn);
            let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                .await
                .expect("login timeout")
                .expect("read Login");
            assert!(matches!(login, FrpMessage::Login(_)));
            count.fetch_add(1, Ordering::SeqCst);
            // Reject: LoginResp carries an error, the client treats it as an
            // auth failure before any encryption wrap.
            stream
                .write_v1_frame(&FrpMessage::LoginResp(msg::LoginResp {
                    version: Some(frp_core::VERSION.into()),
                    run_id: None,
                    error: Some("invalid token".into()),
                    server_additional_auth_scopes: None,
                }))
                .await
                .expect("write LoginResp error");
            // Drain so the connection closes when the client drops it.
            tokio::spawn(async move { while stream.read_v1_frame().await.is_ok() {} });
        }
    });
    (handle, login_count)
}

fn client_cfg(server_port: u16, token: &str, login_fail_exit: bool) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit,
        tcp_mux: false,
        tls_enable: false,
        // No heartbeats: nothing else can fire during the test windows.
        heartbeat_interval: 0,
        proxies: vec![],
        visitors: vec![],
        ..Default::default()
    }
}

/// `login_fail_exit = true`: run() returns the login error immediately and
/// no second Login is ever dialed.
#[tokio::test]
async fn login_fail_exit_true_returns_without_retrying() {
    common::init_tracing();
    let token = "login-fail-exit-true-token";
    let server_port = allocate_port();
    let (mock, login_count) = spawn_rejecting_server(server_port);

    let client = Arc::new(
        ClientService::new(client_cfg(server_port, token, true), None)
            .await
            .unwrap(),
    );
    // run() returns Result<(), Box<dyn Error>> which is not Send, so it
    // cannot be tokio::spawned — await it in place with a timeout instead.
    let result = tokio::time::timeout(Duration::from_secs(10), async { client.run().await })
        .await
        .expect("client run() did not return with login_fail_exit=true");
    assert!(
        result.is_err(),
        "run() must return the login error when login_fail_exit=true"
    );

    // And it must not have reconnected: no second Login within a generous
    // window after run() returned (the first retry would land ~2s in).
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected with login_fail_exit=true"
    );

    // The mock's accept loop ends when the listener is dropped at runtime
    // shutdown; detach it explicitly for the let_underscore lint.
    std::mem::drop(mock);
}

/// `login_fail_exit = false`: the client retries — a second Login arrives
/// after the initial-login backoff (~2.0-2.2s; 8s bound is generous).
#[tokio::test]
async fn login_fail_exit_false_retries_login() {
    common::init_tracing();
    let token = "login-fail-exit-false-token";
    let server_port = allocate_port();
    let (mock, login_count) = spawn_rejecting_server(server_port);

    let client = Arc::new(
        ClientService::new(client_cfg(server_port, token, false), None)
            .await
            .unwrap(),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    tokio::time::timeout(Duration::from_secs(8), async {
        while login_count.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("client did not retry login with login_fail_exit=false");
    assert!(
        login_count.load(Ordering::SeqCst) >= 2,
        "expected a retried Login, got {}",
        login_count.load(Ordering::SeqCst)
    );

    // The client never succeeds here, so run() only ends on request_stop.
    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");

    std::mem::drop(mock);
}

/// `login_fail_exit = false` + stop during the initial-login backoff:
/// request_stop() must end run() promptly (round-8 fix — the backoff sleep
/// select!s stop_rx; a bare sleep would hold the run loop until the ~2.0-
/// 2.2s backoff elapsed, ignoring the stop request).
#[tokio::test]
async fn login_fail_exit_false_stop_during_initial_login_backoff() {
    common::init_tracing();
    let token = "login-fail-exit-backoff-token";
    let server_port = allocate_port();
    let (mock, login_count) = spawn_rejecting_server(server_port);

    let client = Arc::new(
        ClientService::new(client_cfg(server_port, token, false), None)
            .await
            .unwrap(),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // Wait for the first Login — the client has just entered the ~2.0-2.2s
    // initial backoff (1s base ×2 + ≤10% jitter). Stop right there.
    tokio::time::timeout(Duration::from_secs(5), async {
        while login_count.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("client never sent the first Login");

    client.request_stop();
    tokio::time::timeout(Duration::from_millis(800), runner)
        .await
        .expect(
            "run() did not return within 800ms of request_stop during the initial login backoff",
        )
        .expect("client run() panicked");

    // No runaway redial: at most one retry could have raced in before the
    // stop landed (the backoff is ~2.2s, so normally exactly 1).
    assert!(
        login_count.load(Ordering::SeqCst) <= 2,
        "client kept re-dialing after request_stop"
    );

    std::mem::drop(mock);
}
