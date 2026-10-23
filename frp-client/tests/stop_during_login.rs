//! frp-rs shutdown during login — stronger than Go frp v0.71.1, not parity:
//! Go's `svr.ctx` cancel aborts the dial, while the LoginResp read has its
//! own 10s deadline and `Run` waits for blocked startup
//! (`TestServiceStartupShutdownLeavesCleanupToRun`). frp-rs races the whole
//! `connect_and_login` (dial + LoginResp wait) against its `Service::stop`
//! token, so a `SIGTERM` (or admin `/api/stop`) that lands while the client
//! waits for LoginResp ends `run()` promptly instead of waiting out the 10s
//! login timeout.
//!
//! Oracle: the mock accepts the control connection and reads Login but never
//! answers; `request_stop()` after the Login frame arrives must make `run()`
//! return `Ok(())` within ~2s (RED before the race: ~10s, then the
//! `login_fail_exit = true` error exit).

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::FrpMessage;
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn stop_during_login_exits_promptly() {
    common::init_tracing();
    let token = "stop-during-login-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let (login_tx, login_rx) = oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        let _ = login_tx.send(());
        // Never answer LoginResp; hold the connection open until the client
        // drops it on cancellation. A frame read returns Err at EOF/close.
        let _ = tokio::time::timeout(Duration::from_secs(30), stream.read_v1_frame()).await;
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: true,
        tcp_mux: false,
        tls_enable: false,
        heartbeat_interval: 1,
        heartbeat_timeout: 10,
        proxies: vec![],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());

    // Stop only once the client is provably inside the LoginResp wait.
    let stopper = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = login_rx.await;
            client.request_stop();
        })
    };

    let stopped_at = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), client.run())
        .await
        .expect("run() did not exit promptly after a stop during the LoginResp wait")
        .expect("a stop during login is the clean-stop contract (`Ok(())`)");
    assert!(
        stopped_at.elapsed() < Duration::from_secs(2),
        "run() exit was not prompt"
    );

    stopper.await.expect("stopper task panicked");
    mock.abort();
    match mock.await {
        Err(e) if e.is_cancelled() => {}
        other => panic!("mock task ended abnormally: {other:?}"),
    }
}
