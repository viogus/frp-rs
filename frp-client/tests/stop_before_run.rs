//! Go frp v0.71.1 lifecycle (55107d0): a close (`GracefulClose`) observed
//! before `Run` means `Run` must not start — Go's `closed` flag makes a
//! pre-`Run` close return without dialling/logging in/registering.
//!
//! frp-rs's stop is a one-shot `CancellationToken` (`Service::stop`) rather
//! than a queued message, so `request_stop()` before `run()` must make
//! `run()` return `Ok(())` immediately and leave the server alone.
//!
//! Oracles:
//!  1. `run()` returns `Ok(())` within ~1s (RED before the pre-run check: it
//!     dials, fails login, and with the default `login_fail_exit = true`
//!     returns `Err`).
//!  2. The mock server never accepts a connection (RED before the fix: a
//!     Login frame arrives and is dropped).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;

use common::allocate_port;

#[tokio::test]
async fn stop_before_run_returns_ok_without_dialling() {
    common::init_tracing();
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_env = accepted.clone();
    let mock = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.expect("mock accept");
            accepted_env.fetch_add(1, Ordering::SeqCst);
            // Drop the connection without answering Login.
            drop(conn);
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "stop-before-run-token".into(),
        tcp_mux: false,
        tls_enable: false,
        proxies: vec![],
        ..Default::default()
    };
    let client = ClientService::new(client_cfg, None).await.unwrap();

    // Close before Run: Go frp v0.71.1's `closed` flag.
    client.request_stop();

    let stopped_at = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), client.run())
        .await
        .expect("run() must return promptly when stopped before it starts")
        .expect("a pre-run stop is the clean-stop contract (`Ok(())`), like every other stop exit");
    assert!(
        stopped_at.elapsed() < Duration::from_secs(1),
        "run() took {:?} to honour a pre-run stop",
        stopped_at.elapsed()
    );

    // Give a (wrongly) started dial a chance to reach the mock before
    // asserting it never happened.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "run() dialled the server after a pre-run stop (Go v0.71.1: never start)"
    );

    mock.abort();
    match mock.await {
        Err(e) if e.is_cancelled() => {}
        other => panic!("mock task ended abnormally: {other:?}"),
    }
}
