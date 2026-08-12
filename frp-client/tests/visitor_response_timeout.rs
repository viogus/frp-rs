//! Regression: a visitor must not hang forever waiting for
//! NewVisitorConnResp. The handshake response read is bounded by
//! `dial_server_timeout` (mirroring read_start_work_conn_with_timeout in
//! work_conn.rs); a server that accepts the dial but never answers must
//! close the user connection instead of pinning the visitor task.

mod common;

use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, VisitorConfig};
use frp_core::msg::FrpMessage;
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn stcp_visitor_times_out_waiting_for_response() {
    common::init_tracing();
    let token = "visitor-timeout-token";
    let server_port = allocate_port();
    let visitor_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    // Mock server: complete the control login, accept the visitor's
    // NewVisitorConn, then never answer it.
    let mock = tokio::spawn(async move {
        // Control connection: complete login, then hold it open (a dropped
        // control conn would make the client tear the session down and
        // rebuild the visitor listener mid-test).
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
        let mut enc = stream.into_encrypted(enc_key);
        // Drain client traffic (e.g. the control-channel NewVisitorConn
        // registration message) in a detached task until the connection
        // closes. A one-shot read would complete on the first frame, drop
        // the stream, and close the TCP conn — making the client tear the
        // session down mid-test.
        tokio::spawn(async move { while enc.read_v1_frame().await.is_ok() {} });

        // Visitor connection: read NewVisitorConn, then stay silent.
        let (vconn, _) = listener.accept().await.expect("visitor conn");
        let mut vstream = IoStream::Tcp(vconn);
        let nvc = tokio::time::timeout(Duration::from_secs(10), vstream.read_v1_frame())
            .await
            .expect("visitor NewVisitorConn timeout")
            .expect("read NewVisitorConn");
        assert!(
            matches!(nvc, FrpMessage::NewVisitorConn(_)),
            "expected NewVisitorConn, got {nvc:?}"
        );
        // Never respond. Hold the connection open so the visitor sees a
        // silent peer rather than an EOF.
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        heartbeat_interval: 0,
        // Bounds the NewVisitorConnResp wait: the visitor must give up after
        // ~1s instead of hanging.
        dial_server_timeout: 1,
        proxies: vec![],
        visitors: vec![VisitorConfig {
            name: "sv1".into(),
            visitor_type: "stcp".into(),
            server_name: "srv-proxy".into(),
            secret_key: "sk".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port as i32,
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

    // Wait for the visitor listener to come up, then connect a user.
    let mut user_conn = None;
    for _ in 0..50 {
        if let Ok(c) = tokio::net::TcpStream::connect(("127.0.0.1", visitor_port)).await {
            user_conn = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut user_conn = user_conn.expect("visitor listener did not come up");

    // The visitor dials the mock, sends NewVisitorConn, and must time out
    // waiting for the response (~dial_server_timeout = 1s), closing the
    // user connection instead of hanging forever.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(10), user_conn.read(&mut buf))
        .await
        .expect("user connection not closed: visitor hung waiting for NewVisitorConnResp");
    // Ok(0) = clean EOF, Err = reset — both mean the visitor gave up.
    match read {
        Ok(0) => {}
        Ok(n) => panic!("expected EOF, got {n} bytes"),
        Err(_) => {}
    }

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    // The mock task is still parked (silent server); it dies with the test
    // runtime. Detach it explicitly to satisfy the let_underscore_future lint.
    std::mem::drop(mock);
}
