//! Regression: the client must answer an unsolicited server Ping with a
//! Pong on the control connection.
//!
//! Previously inbound Ping fell into the ignored-messages bucket, so a
//! server that probes liveness with Ping would have its own watchdog kill a
//! perfectly healthy control connection.

mod common;

use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn client_answers_server_ping_with_pong() {
    let token = "ping-test-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // No client pings: only the server's Ping is exercised, so the
        // connection must stay healthy without any heartbeat traffic.
        heartbeat_interval: 0,
        proxies: vec![],
        visitors: vec![],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // --- Mock server: complete the login handshake, then send Ping ---
    let (conn, _peer) = listener.accept().await.expect("client did not connect");
    let mut stream = IoStream::Tcp(conn);

    // 1. Login (plaintext V1).
    let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
        .await
        .expect("timeout waiting for client Login")
        .expect("read Login");
    assert!(
        matches!(login, FrpMessage::Login(_)),
        "expected Login, got {login:?}"
    );

    // 2. LoginResp (plaintext).
    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    stream
        .write_v1_frame(&login_resp)
        .await
        .expect("write LoginResp");

    // 3. The client wraps the control stream in AES-128-CFB with
    //    derive_key(token) after LoginResp; wrap our side symmetrically.
    let enc_key = frp_core::encryption::derive_key(token);
    let mut enc = stream.into_encrypted(enc_key);

    // 4. Send Ping; expect a Pong back.
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    enc.write_v1_frame(&ping).await.expect("write Ping");
    let reply = tokio::time::timeout(Duration::from_secs(5), enc.read_v1_frame())
        .await
        .expect("timeout: client did not answer server Ping with Pong")
        .expect("read reply");
    assert!(
        matches!(reply, FrpMessage::Pong(_)),
        "expected Pong, got {reply:?}"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
}
