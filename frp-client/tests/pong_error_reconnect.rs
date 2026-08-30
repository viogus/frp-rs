//! `Pong{error}` semantics in the message loop: a non-empty error in a
//! server Pong tears the session down and reconnects (Go frp client parity),
//! while with `heartbeat_interval = 0` the client never Pings, so the mock
//! (which only Pongs in response to Pings) can never deliver a Pong{error}
//! and the session must stay up silently.
//!
//! The mock completes login + registration (NewProxy → NewProxyResp) on
//! every control connection so each session settles into the message loop.
//! On the FIRST connection it answers the first client Ping with
//! `Pong{error: "mock server error"}` — the message loop must return
//! `LoopExit::Reconnect` on that, teardown + phase-1 backoff (100-300ms)
//! follow, and a NEW Login arrives. Later connections are Ponged cleanly so
//! the reconnected session stays stable (asserted: exactly one reconnect).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// Mock server: complete login + registration on every connection. On the
/// FIRST connection, answer the first Ping with `Pong{error}` (the client
/// must reconnect); on later connections Pong cleanly to keep the session
/// up. Returns the mock handle, the login counter, and a oneshot that fires
/// when the SECOND Login arrives.
fn spawn_pong_error_server(
    listener: TcpListener,
    token: &str,
) -> (
    JoinHandle<()>,
    Arc<AtomicUsize>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    let (login2_tx, login2_rx) = tokio::sync::oneshot::channel::<()>();
    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-pong-error".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let handle = tokio::spawn(async move {
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
                // Message loop pings at t≈0; answer that Ping with
                // Pong{error} — the client must reconnect on it. Then drain
                // until the client tears the connection down.
                loop {
                    match enc.read_v1_frame().await {
                        Ok(FrpMessage::Ping(_)) => {
                            enc.write_v1_frame(&FrpMessage::Pong(msg::Pong {
                                error: Some("mock server error".into()),
                            }))
                            .await
                            .expect("write Pong error");
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
                // Pong cleanly: the reconnected session must stay stable.
                loop {
                    match enc.read_v1_frame().await {
                        Ok(FrpMessage::Ping(_)) => {
                            let _ = enc
                                .write_v1_frame(&FrpMessage::Pong(msg::Pong { error: None }))
                                .await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }
    });
    (handle, login_count, login2_rx)
}

fn client_cfg(server_port: u16, token: &str, heartbeat_interval: i64) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        heartbeat_interval,
        heartbeat_timeout: 3,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            // ProxyConfig::default() leaves `enabled` false; must be active
            // for registration to complete (the Pong handler under test runs
            // in the post-registration message loop).
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// A `Pong{error}` must tear the session down and reconnect: a NEW Login
/// arrives shortly after the error Pong (nominal ~0.1-0.6s), and the
/// reconnected session stays up (no further logins while the mock Pongs
/// cleanly).
#[tokio::test]
async fn pong_error_triggers_reconnect() {
    common::init_tracing();
    let token = "pong-error-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();
    let (mock, login_count, login2_rx) = spawn_pong_error_server(listener, token);

    let client = Arc::new(
        ClientService::new(client_cfg(server_port, token, 1), None)
            .await
            .unwrap(),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // First Ping is answered with Pong{error} → LoopExit::Reconnect →
    // teardown + phase-1 backoff (100-300ms) → new Login. 8s is generous.
    let reconnected = tokio::time::timeout(Duration::from_secs(8), login2_rx)
        .await
        .expect("client did not reconnect after Pong{error}");
    assert!(
        reconnected.is_ok(),
        "mock server failed to complete the second login"
    );

    // Exactly one reconnect: the second session is Ponged cleanly and must
    // remain established (a client that treats Pong{error} as a ping-reply
    // would keep reconnecting on every Ping).
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        2,
        "client reconnected again on a healthy session"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    std::mem::drop(mock);
}

/// Negative assertion: with `heartbeat_interval = 0` the client sends no
/// Pings, so the mock (which only Pongs in response to Pings) never emits a
/// Pong{error}, and the session must stay up — the Pong-error reconnect
/// path is driven by the heartbeat exchange, not by anything else.
#[tokio::test]
async fn heartbeat_interval_zero_no_ping_no_reconnect() {
    common::init_tracing();
    let token = "pong-error-no-hb-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();
    let (mock, login_count, _login2_rx) = spawn_pong_error_server(listener, token);

    let client = Arc::new(
        ClientService::new(client_cfg(server_port, token, 0), None)
            .await
            .unwrap(),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // With heartbeats off, no Ping is ever sent, the mock never Pongs, and
    // the watchdog is inactive (hb_watchdog_active = false): the session
    // must silently stay up — no reconnect within 5s (at heartbeat_interval
    // = 1 the first Pong{error} would have landed at ~t+0).
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected with heartbeat_interval=0: no Ping was ever sent, so no Pong{{error}} could arrive"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    std::mem::drop(mock);
}
