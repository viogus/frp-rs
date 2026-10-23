//! frp-rs shutdown during registration — stronger than Go frp v0.71.1, not
//! parity: a stop must abort the `NewProxy` response wait immediately, not
//! wait out `REGISTRATION_RESPONSE_TIMEOUT` (30s at default; 5s overridden
//! here) or the heartbeat watchdog. Go bounds each proxy's registration with
//! its own startErrTimeout in a goroutine and does not cancel that wait on
//! ctx cancel, so extending the stop signal to the registration wait is an
//! frp-rs extension. `register_proxies` races the `Service::stop` token in
//! its response-loop `select!`, sets `ctx.shutdown_flag` and returns
//! `false`, so `run()` takes the normal teardown + clean-stop path.
//!
//! `FRP_REGISTRATION_RESPONSE_TIMEOUT_MS` is process-global and read once
//! (LazyLock), so this test is the only `#[tokio::test]` in this binary, as
//! with `proxy_retry.rs`.
//!
//! Oracle: the mock completes login and reads the client's NewProxy but
//! never answers; after it has seen the NewProxy, `request_stop()` must make
//! `run()` return `Ok(())` within ~2s (RED before the race: ~5s).

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
async fn stop_during_registration_exits_promptly() {
    common::init_tracing();
    const REGISTRATION_TIMEOUT_MS: &str = "5000";
    // Read once at the first registration; must be set before `run()`.
    std::env::set_var(
        "FRP_REGISTRATION_RESPONSE_TIMEOUT_MS",
        REGISTRATION_TIMEOUT_MS,
    );

    let token = "stop-during-registration-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let (new_proxy_tx, new_proxy_rx) = oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        let login_resp = FrpMessage::LoginResp(frp_core::msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("mock-server-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let enc_key = frp_core::encryption::derive_key(token);
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");
        let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("NewProxy timeout")
            .expect("read NewProxy");
        assert!(
            matches!(np, FrpMessage::NewProxy(_)),
            "expected NewProxy, got {np:?}"
        );
        let _ = new_proxy_tx.send(());
        // Never answer the NewProxy; keep reading until the client tears the
        // session down so the registration wait is genuinely outstanding.
        while enc.read_v1_frame().await.is_ok() {}
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        heartbeat_interval: 1,
        // Longer than the test, so the heartbeat watchdog cannot be the
        // thing that ends the wait: only the stop token can.
        heartbeat_timeout: 30,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            // ProxyConfig::default() leaves `enabled` false.
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());

    let stopper = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = new_proxy_rx.await;
            client.request_stop();
        })
    };

    let stopped_at = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), client.run())
        .await
        .expect(
            "run() did not exit promptly after a stop during the registration response wait \
             (registration timeout is 5s; the stop must not wait it out)",
        )
        .expect("a stop during registration is the clean-stop contract (`Ok(())`)");
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
