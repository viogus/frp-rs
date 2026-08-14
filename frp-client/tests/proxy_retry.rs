//! Regression: a server that completes login and answers Pongs but NEVER
//! answers NewProxyResp must not leave the client's proxies stuck in
//! WaitStart forever.
//!
//! The flow under test:
//! - initial registration: NewProxy is sent, the server stays silent on it,
//!   and `REGISTRATION_RESPONSE_TIMEOUT` marks the proxy StartErr without
//!   tearing the session down;
//! - the message loop's retry arm re-sends NewProxy (StartErr -> send ->
//!   WaitStart);
//! - a re-sent NewProxy that is again never answered keeps the phase in
//!   WaitStart — only a NewProxyResp error moves it to StartErr, so without
//!   the WaitStart-stuck re-arm a silent-but-ponging server would stop the
//!   retries after that one re-send (pre-fix: exactly 2 NewProxy frames,
//!   forever). Go frp's proxy_wrapper re-arms startErrTimeout while in
//!   waitStart and retries indefinitely; the retry arm mirrors that.
//!
//! Assert the mock receives >= 3 NewProxy frames (initial + two retries).
//! The 30s production cadence is shrunk via the env overrides
//! (`FRP_REGISTRATION_RESPONSE_TIMEOUT_MS` / `FRP_PROXY_RETRY_INTERVAL_MS`)
//! so the test finishes in a couple of seconds instead of ~90s of wall
//! clock, removing CI timer-drift flake.
//!
//! The env vars MUST be set before `Service` is constructed: the cadence is
//! read once into a `LazyLock` at first use (same pattern as
//! `FRP_BRIDGE_BUF_KB`). This file deliberately contains exactly ONE test
//! binary (one `#[tokio::test]`), so the process-global `set_var` + read-once
//! LazyLock cannot be frozen at the 30s default by a sibling test running
//! first. If a second test is ever added here, move the cadence setup into a
//! shared per-binary init that runs before any `Service` is constructed
//! (e.g. `common::init_cadence()` called from every test), or pass the
//! cadence through a `Service` constructor instead of env vars.

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

// Production cadence is 30s per hop. With the env overrides below each hop
// costs 250ms, so the third NewProxy lands at ~750ms; allow 10s.
const TEST_CADENCE_MS: &str = "250";
const ASSERT_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn silent_server_never_answering_newproxy_is_retried_forever() {
    // Shrink the cadence BEFORE constructing the Service (LazyLock read-once).
    std::env::set_var("FRP_REGISTRATION_RESPONSE_TIMEOUT_MS", TEST_CADENCE_MS);
    std::env::set_var("FRP_PROXY_RETRY_INTERVAL_MS", TEST_CADENCE_MS);

    common::init_tracing();
    let token = "proxy-retry-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // Mock server: complete login, then answer every Ping with a Pong so the
    // session survives (the heartbeat watchdog must never fire), but NEVER
    // answer NewProxy. Count the NewProxy frames received across connections
    // (a reconnect would just keep counting).
    let newproxy_count = Arc::new(AtomicUsize::new(0));
    let count = newproxy_count.clone();
    let mock = tokio::spawn(async move {
        let login_resp = FrpMessage::LoginResp(frp_core::msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("mock-server-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        let enc_key = frp_core::encryption::derive_key(token);
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
            // Per-connection frame loop: count NewProxy (deliberately no
            // NewProxyResp), Pong every Ping, leave on EOF (client stop).
            loop {
                let msg = match enc.read_v1_frame().await {
                    Ok(m) => m,
                    Err(_) => break,
                };
                match msg {
                    FrpMessage::NewProxy(_) => {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    FrpMessage::Ping(_) => {
                        enc.write_v1_frame(&FrpMessage::Pong(frp_core::msg::Pong { error: None }))
                            .await
                            .expect("write Pong");
                    }
                    _ => {}
                }
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
        // Heartbeat ON with a long timeout: the client pings every second
        // and this mock Pongs, so the session survives (the watchdog never
        // fires) while the registration retry machinery runs underneath —
        // exactly the "silent server that still Pongs" scenario. (A default
        // heartbeat would instead tear the session down at hb_timeout and
        // reconnect — a different, already-covered path.)
        heartbeat_interval: 1,
        heartbeat_timeout: 120,
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

    // Registration times out after REGISTRATION_RESPONSE_TIMEOUT, and each
    // retry hop costs one PROXY_RETRY_INTERVAL — both shrunk to 250ms here,
    // so the third NewProxy lands at ~750ms. 10s is generous headroom.
    tokio::time::timeout(ASSERT_TIMEOUT, async {
        while newproxy_count.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("NewProxy retries stopped: a proxy stuck in WaitStart is never re-sent");
    let total = newproxy_count.load(Ordering::SeqCst);
    assert!(
        total >= 3,
        "expected at least 3 NewProxy frames (initial + 2 retries), got {total}"
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
