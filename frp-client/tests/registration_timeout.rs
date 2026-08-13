//! Regression: a server that completes login but never answers NewProxy
//! (stays connected, stays silent) must not leave the client blocked in the
//! registration phase forever. Two bounds apply:
//!
//! - the heartbeat watchdog is armed at login success (before registration),
//!   so a dead-but-connected server is detected within `heartbeat_timeout`;
//! - each registration response read is additionally bounded by
//!   `REGISTRATION_RESPONSE_TIMEOUT`.
//!
//! This test drives the watchdog path with a short heartbeat_timeout and
//! asserts the client reconnects within a bound instead of hanging.
//! (Pre-fix the registration read loop had no timeout at all, pings were not
//! sent until the message loop, and the watchdog was unarmed — the client
//! blocked forever.)

mod common;

use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::FrpMessage;
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn dead_server_during_registration_reconnects_within_heartbeat_timeout() {
    common::init_tracing();
    let token = "registration-timeout-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // Mock server: complete login on the first control connection, read the
    // client's NewProxy, then NEVER answer — and keep the connection open (a
    // dropped conn would make the client exit the registration loop on the
    // read-error path, not the watchdog path under test). On every reconnect,
    // complete login again so each new session settles.
    let (login2_tx, login2_rx) = tokio::sync::oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        // First control connection: login, then silence.
        let (conn, _) = listener.accept().await.expect("first control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("first login timeout")
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
        // Park the first connection silently (no response ever). It ends
        // when the client tears the session down on watchdog reconnect.
        tokio::spawn(async move {
            let _ = enc.read_v1_frame().await;
        });

        // Accept and login-answer ANY number of further reconnects. The
        // client reconnects repeatedly here: this mock never Pongs, so each
        // session dies at the heartbeat watchdog ~3s after login (during
        // registration on the first sessions, from the message loop later)
        // and the client dials again. A mock that handled only two
        // connections would leave the third Login unanswered; a blocked
        // `ctl.login()` cannot be interrupted by request_stop, so the
        // runner's 5s stop timeout would fail the test (flake window:
        // request_stop landing >3s after the second login).
        let mut login2_tx = Some(login2_tx);
        loop {
            let (conn, _) = listener.accept().await.expect("reconnect control conn");
            let mut stream = IoStream::Tcp(conn);
            let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                .await
                .expect("reconnect login timeout")
                .expect("read Login");
            assert!(matches!(login, FrpMessage::Login(_)));
            stream
                .write_v1_frame(&login_resp)
                .await
                .expect("write reconnect LoginResp");
            // Signals the first reconnect; later iterations have no sender
            // left (the test already consumed the receiver).
            if let Some(tx) = login2_tx.take() {
                let _ = tx.send(());
            }
            let mut enc = stream
                .into_encrypted(enc_key)
                .expect("plain test stream is encryptable");
            // Drain until the client closes this connection at stop.
            tokio::spawn(async move { while enc.read_v1_frame().await.is_ok() {} });
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Short heartbeat so the registration-phase watchdog fires quickly:
        // the dead-but-connected server never Pongs, and registration sends
        // no Pings, so the watchdog must reconnect ~3s after login instead
        // of hanging (pre-fix: blocked forever).
        heartbeat_interval: 1,
        heartbeat_timeout: 3,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            // ProxyConfig::default() leaves `enabled` false (only serde
            // defaults it true); the proxy must be active for registration.
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

    // The watchdog must fire and the client reconnect (second login) within
    // a bound well under the pre-fix hang: heartbeat_timeout (3s) + backoff
    // + login round-trip. 15s is generous headroom.
    let reconnected = tokio::time::timeout(Duration::from_secs(15), login2_rx)
        .await
        .expect("client did not reconnect: registration phase hung on a silent server");
    // The mock server signals via oneshot after completing the second login.
    assert!(
        reconnected.is_ok(),
        "mock server failed to complete the second login"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    // The mock task's drain loop ends when the client closes the second
    // connection at stop; detach it explicitly for the let_underscore lint.
    std::mem::drop(mock);
}
