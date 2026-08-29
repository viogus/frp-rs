//! Registration-phase handover: the heartbeat watchdog armed at login
//! success must carry the session through the REGISTRATION phase. Here the
//! mock reads the client's NewProxy but stalls the NewProxyResp for 4s
//! (heartbeat_timeout = 3s): the watchdog fires ~3s after login, the
//! registration is aborted, and the client reconnects (new Login within a
//! bound) — the stalled response is never the thing that unblocks it.
//!
//! This is the "registration watchdog" leg the round-8 review asked to pin
//! with a mock: registration_timeout.rs stalls the response forever, while
//! this test proves the handover is prompt even when the server would have
//! answered eventually (4s) — the reconnect must come from the watchdog at
//! ~3s, well before any response at 4s. (REGISTRATION_RESPONSE_TIMEOUT
//! defaults to 30s, so the watchdog — not the response timeout — is what
//! fires.)
//!
//! Timeline (heartbeat_interval=1s, heartbeat_timeout=3s):
//!   t+0       login succeeds; watchdog armed (last_pong = login time)
//!   t+0       NewProxy sent; mock stalls the NewProxyResp (sleep 4s)
//!   t+3       watchdog fires (no Pings are sent during registration, so no
//!             Pong can arrive) → registration aborted → teardown
//!   t+3.1-3.3 phase-1 reconnect backoff (100-300ms)
//!   t+~3.3    NEW Login arrives (asserted within 8s)
//! Reconnect handling in the mock completes login + registration and Pongs
//! cleanly so the reconnected session stays stable until request_stop.

mod common;

use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// Mock server: complete login on every control connection. On the FIRST
/// connection read NewProxy and then STALL the NewProxyResp for 4s (the
/// watchdog at 3s beats it; the write afterwards is best-effort — the
/// client has already torn the connection down). On later connections
/// complete registration immediately and Pong Pings cleanly so the
/// reconnected session stays stable.
fn spawn_stalled_registration_server(
    listener: TcpListener,
    token: &str,
) -> (JoinHandle<()>, tokio::sync::oneshot::Receiver<()>) {
    let (login2_tx, login2_rx) = tokio::sync::oneshot::channel::<()>();
    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-stall-reg".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let new_proxy_resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
        proxy_name: "p1".into(),
        remote_addr: Some("127.0.0.1:8081".into()),
        error: None,
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
            stream
                .write_v1_frame(&login_resp)
                .await
                .expect("write LoginResp");
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

            if first_conn {
                first_conn = false;
                // Stall 4s > heartbeat_timeout 3s: the registration-phase
                // watchdog must fire first. The write is best-effort and
                // time-bounded — the client reconnected at ~3.3s, so the
                // socket may already be closed (write error) or the frame
                // may land on a dead conn.
                tokio::time::sleep(Duration::from_secs(4)).await;
                let _ = tokio::time::timeout(
                    Duration::from_millis(500),
                    enc.write_v1_frame(&new_proxy_resp),
                )
                .await;
                // Drain until the client closes this torn-down conn.
                tokio::spawn(async move { while enc.read_v1_frame().await.is_ok() {} });
            } else {
                // Signals the first reconnect; later iterations have no
                // sender left (the test already consumed the receiver).
                if let Some(tx) = login2_tx.take() {
                    let _ = tx.send(());
                }
                enc.write_v1_frame(&new_proxy_resp)
                    .await
                    .expect("write reconnect NewProxyResp");
                // Pong cleanly: the reconnected session must stay stable.
                tokio::spawn(async move {
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
                });
            }
        }
    });
    (handle, login2_rx)
}

fn client_cfg(server_port: u16, token: &str) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Short heartbeat so the registration-phase watchdog fires quickly:
        // the stalled NewProxyResp never comes (4s), and registration sends
        // no Pings, so the watchdog must reconnect ~3s after login.
        heartbeat_interval: 1,
        heartbeat_timeout: 3,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            // ProxyConfig::default() leaves `enabled` false; must be active
            // for registration to be attempted.
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// A NewProxyResp stalled longer than heartbeat_timeout during registration
/// must not hang the client: the registration-phase watchdog reconnects it
/// promptly (new Login within 8s; nominal ~3.3s).
#[tokio::test]
async fn stalled_new_proxy_resp_during_registration_reconnects_via_watchdog() {
    common::init_tracing();
    let token = "registration-handover-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();
    let (mock, login2_rx) = spawn_stalled_registration_server(listener, token);

    let client = Arc::new(
        ClientService::new(client_cfg(server_port, token), None)
            .await
            .unwrap(),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // The watchdog fires at ~login+3s, teardown + phase-1 backoff
    // (100-300ms) → new Login at ~3.3s. 8s is generous over the nominal;
    // a client that hung on the stalled response would never signal.
    let reconnected = tokio::time::timeout(Duration::from_secs(8), login2_rx)
        .await
        .expect("client did not reconnect: the registration-phase watchdog must fire on a stalled NewProxyResp");
    assert!(
        reconnected.is_ok(),
        "mock server failed to complete the reconnected session's login"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    std::mem::drop(mock);
}
