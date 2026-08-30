//! Regression: the message-loop heartbeat watchdog AFTER registration is
//! complete must still fire and reconnect the client when the server goes
//! silent.
//!
//! Coverage gap this closes:
//! - `registration_timeout.rs` exercises the watchdog only during the
//!   REGISTRATION phase (login answered, NewProxy never answered);
//! - `proxy_retry.rs` has the server Pong forever (watchdog never fires);
//! - `ping_pong.rs` disables client heartbeats entirely.
//!
//! Here the session completes Login AND registration (NewProxy answered
//! with NewProxyResp), the message loop is running, and the mock Pongs a
//! few heartbeats to prove liveness — then goes SILENT while keeping the
//! connection open (a dropped conn would exit on the read-error path, not
//! the watchdog path under test). The watchdog must fire
//! `heartbeat_timeout` after the last Pong and the client must dial a NEW
//! Login (reconnect), not hang.
//!
//! Timeline (heartbeat_interval=1s, heartbeat_timeout=3s):
//!   t+0..t+2  message loop pings every 1s, mock Pongs the first 3
//!   t+2       last Pong → watchdog deadline = t+2+3 = t+5
//!   t+5       LoopExit::Reconnect → teardown + phase-1 backoff (≤300ms)
//!   t+~5.4    new Login arrives
//! Two bounds:
//!   - lower: at t+4.2s NO reconnect yet (the Pongs kept the watchdog at
//!     bay — a watchdog that ignored Pongs would have fired at ~t+3 and
//!     dialed again by ~t+3.4);
//!   - upper: a NEW Login within 8s (generous over the ~5.4s nominal).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// The message-loop watchdog after full registration: a silent-but-connected
/// server is detected within heartbeat_timeout of its last Pong and the
/// client reconnects.
#[tokio::test]
async fn silent_server_after_registration_reconnects_within_heartbeat_timeout() {
    common::init_tracing();
    let token = "hb-post-registration-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // Mock server: on EVERY control connection complete login + registration
    // (NewProxy → NewProxyResp) so each session settles into the message
    // loop. On the FIRST connection only, Pong the first 3 client Pings
    // (proving liveness) and then go silent while keeping the connection
    // open. Later connections are drained silently after registration: the
    // watchdog reconnects each ~3s and the mock must keep answering so a
    // client still mid-registration when `request_stop` lands is not left
    // blocked (same pattern as registration_timeout.rs).
    let (login2_tx, login2_rx) = tokio::sync::oneshot::channel::<()>();
    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    let mock = tokio::spawn(async move {
        let login_resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("mock-server-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        let enc_key = frp_core::encryption::derive_key(token);
        let mut first_conn = true;
        let mut login2_tx = Some(login2_tx);
        loop {
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
            let mut enc = stream
                .into_encrypted(enc_key)
                .expect("plain test stream is encryptable");
            // Complete registration on every connection.
            let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
                .await
                .expect("NewProxy timeout")
                .expect("read NewProxy");
            assert!(
                matches!(np, FrpMessage::NewProxy(_)),
                "expected NewProxy, got {np:?}"
            );
            enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: "p1".into(),
                remote_addr: Some("127.0.0.1:8081".into()),
                error: None,
            }))
            .await
            .expect("write NewProxyResp");

            if first_conn {
                first_conn = false;
                // Pong the first 3 Pings (message loop pings at t+0, +1, +2),
                // then go SILENT: keep reading so the connection stays open,
                // but never answer again. The read ends with an error only
                // when the client tears the session down on watchdog
                // reconnect (or at stop).
                let mut ponged = 0;
                loop {
                    match enc.read_v1_frame().await {
                        Ok(FrpMessage::Ping(_)) if ponged < 3 => {
                            enc.write_v1_frame(&FrpMessage::Pong(msg::Pong { error: None }))
                                .await
                                .expect("write Pong");
                            ponged += 1;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            } else {
                // Signals the first reconnect; later iterations have no
                // sender left (the test already consumed the receiver).
                if let Some(tx) = login2_tx.take() {
                    let _ = tx.send(());
                }
                // Drain silently until the client closes this connection at
                // stop.
                tokio::spawn(async move { while enc.read_v1_frame().await.is_ok() {} });
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
        // Short heartbeat: the post-registration watchdog fires ~3s after
        // the last Pong instead of the 90s default.
        heartbeat_interval: 1,
        heartbeat_timeout: 3,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            // ProxyConfig::default() leaves `enabled` false; must be active
            // for registration to complete (the watchdog under test runs in
            // the post-registration message loop).
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

    // Liveness proof: with the first 3 Pings Ponged (through ~t+2), the
    // watchdog cannot fire before ~t+5. At t+4.2 the session must still be
    // up — a watchdog that ignored Pongs would have reconnected by ~t+3.4.
    tokio::time::sleep(Duration::from_millis(4200)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected while the mock was still Ponging: the heartbeat watchdog must not fire on a live session"
    );

    // Then the silence must be detected: a NEW Login arrives within
    // heartbeat_timeout (3s) + backoff + login round-trip ≈ 5.4s nominal;
    // 8s is generous headroom (pre-fix: the message loop would hang on the
    // silent server — registration_timeout.rs only covered the
    // registration-phase watchdog).
    let reconnected = tokio::time::timeout(Duration::from_secs(8), login2_rx)
        .await
        .expect("client did not reconnect: post-registration message loop hung on a silent server");
    assert!(
        reconnected.is_ok(),
        "mock server failed to complete the second login"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    // The mock's accept loop ends when the listener is dropped at runtime
    // shutdown; detach it explicitly for the let_underscore lint.
    std::mem::drop(mock);
}
