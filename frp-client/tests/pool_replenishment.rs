//! Work-conn pool replenishment: the client dials a work connection ONLY in
//! response to a server `ReqWorkConn` (Go frp parity — pool_count is
//! declared in Login and the server drives the pool; the client never
//! eagerly spawns). Coverage gap: no test exercised a pool that gets
//! exhausted and replenished.
//!
//! Flow (pool_count=2):
//!   1. mock completes Login (asserting the client declared pool_count=2)
//!      and registration (NewProxy → NewProxyResp);
//!   2. mock sends ReqWorkConn ×2 (simplified from Go frps: one pool
//!      pre-warm right after LoginResp + on-demand requests) → the client
//!      dials exactly 2 work conns;
//!   3. mock CONSUMES one pooled conn: sends StartWorkConn for the proxy
//!      and verifies real data bridges through to the local echo server
//!      and back — the pool is now down to 1;
//!   4. mock sends a third ReqWorkConn → the client dials a THIRD work
//!      conn to replenish (asserted via the message-loop path);
//!   5. no fourth conn without another ReqWorkConn (no unbounded dialing).
//!
//! The initial pool pre-warm ReqWorkConns land during the registration
//! read loop; the replenishment ReqWorkConn lands in the message loop —
//! both `handle_req_work_conn` sites (service.rs) are exercised.
//!
//! Heartbeats are disabled (heartbeat_interval=0): the watchdog must not
//! fire while the mock parks pooled work conns — ponging is orthogonal to
//! pool replenishment.

mod common;

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::{allocate_port, start_echo_server};

#[tokio::test]
async fn exhausted_pool_is_replenished_on_req_work_conn() {
    common::init_tracing();
    let token = "pool-replenishment-token";
    let server_port = allocate_port();
    let echo_port = allocate_port();
    start_echo_server(echo_port);
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);

    let (replenished_tx, replenished_rx) = tokio::sync::oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        // --- Control connection ---
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        match login {
            FrpMessage::Login(l) => assert_eq!(
                l.pool_count,
                Some(2),
                "client must declare pool_count=2 in Login so the server knows how many ReqWorkConns to issue"
            ),
            other => panic!("expected Login, got {other:?}"),
        }
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");

        // Registration: read NewProxy, answer NewProxyResp, and send the
        // pool pre-warm ReqWorkConns (Go frps writes these immediately
        // after LoginResp, before registration responses — the registration
        // read loop handles them).
        let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("NewProxy timeout")
            .expect("read NewProxy");
        assert!(
            matches!(np, FrpMessage::NewProxy(_)),
            "expected NewProxy, got {np:?}"
        );
        enc.write_v1_frame(&FrpMessage::ReqWorkConn(msg::ReqWorkConn {}))
            .await
            .expect("write ReqWorkConn #1");
        enc.write_v1_frame(&FrpMessage::ReqWorkConn(msg::ReqWorkConn {}))
            .await
            .expect("write ReqWorkConn #2");
        enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: "p1".into(),
            remote_addr: Some("127.0.0.1:8081".into()),
            error: None,
        }))
        .await
        .expect("write NewProxyResp");

        // --- Initial pool: exactly 2 work conns dialed ---
        let mut pooled = Vec::new();
        for _ in 0..2 {
            let (wc, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("pool work conn timeout: client did not dial the initial pool")
                .expect("accept work conn");
            let mut wc = IoStream::Tcp(wc);
            let nwc = tokio::time::timeout(Duration::from_secs(10), wc.read_v1_frame())
                .await
                .expect("NewWorkConn timeout")
                .expect("read NewWorkConn");
            match nwc {
                FrpMessage::NewWorkConn(n) => assert_eq!(
                    n.run_id.as_deref(),
                    Some("mock-server-run"),
                    "work conn must carry the run_id from LoginResp"
                ),
                other => panic!("expected NewWorkConn, got {other:?}"),
            }
            pooled.push(wc);
        }

        // --- Consume one pooled conn: assign it to the registered proxy and
        // prove real data bridges through (work conn → client → local echo
        // server → back) ---
        let mut consumed = pooled.pop().expect("pooled conns present");
        consumed
            .write_v1_frame(&FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
                proxy_name: "p1".into(),
                src_addr: None,
                src_port: None,
                dst_addr: None,
                dst_port: None,
                error: None,
                use_encryption: None,
                use_compression: None,
                nat_hole_sid: None,
                nat_hole_visitor_addr: None,
                sk: None,
            })))
            .await
            .expect("write StartWorkConn");
        consumed
            .write_all(b"pool-probe")
            .await
            .expect("write probe");
        let mut echo = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), consumed.read_exact(&mut echo))
            .await
            .expect("echo round-trip timeout: work conn was not bridged to the local service")
            .expect("read echo");
        assert_eq!(
            &echo, b"pool-probe",
            "bridge must relay data to the local service and back"
        );
        drop(consumed); // consumed conn closed server-side; pool is now 1

        // --- Replenish: server asks for a new work conn (message-loop
        // ReqWorkConn path) ---
        enc.write_v1_frame(&FrpMessage::ReqWorkConn(msg::ReqWorkConn {}))
            .await
            .expect("write ReqWorkConn #3");
        let (wc3, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("replenishment work conn timeout: client did not dial a new work conn after ReqWorkConn")
            .expect("accept work conn");
        let mut wc3 = IoStream::Tcp(wc3);
        let nwc = tokio::time::timeout(Duration::from_secs(10), wc3.read_v1_frame())
            .await
            .expect("NewWorkConn #3 timeout")
            .expect("read NewWorkConn");
        match nwc {
            FrpMessage::NewWorkConn(n) => assert_eq!(
                n.run_id.as_deref(),
                Some("mock-server-run"),
                "replenishment work conn must carry the run_id from LoginResp"
            ),
            other => panic!("expected NewWorkConn, got {other:?}"),
        }
        let _ = replenished_tx.send(());

        // --- No unbounded dialing: without another ReqWorkConn no fourth
        // work conn may arrive (the client dials ONLY on ReqWorkConn).
        // NOTE: the client's control conn cannot EOF before this window
        // closes — `enc` is held here until after the assert — so a
        // reconnect dial cannot land inside the window. ---
        let extra = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
        assert!(
            extra.is_err(),
            "client dialed an extra work conn without a ReqWorkConn"
        );

        // Keep the control connection open until the test stops the client
        // (dropping `enc` here would make the client read EOF and reconnect
        // into a dropped listener — noise after the assertions).
        tokio::spawn(async move {
            let _ = enc.read_v1_frame().await;
        });
        // Park the replenished conn (the client's StartWorkConn read times
        // out after the test ends — harmless).
        drop(wc3);
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        pool_count: 2,
        tcp_mux: false,
        tls_enable: false,
        // Heartbeats off: no watchdog can fire while the mock parks the
        // pooled work conns (ponging is orthogonal to pool replenishment).
        heartbeat_interval: 0,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
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

    tokio::time::timeout(Duration::from_secs(10), replenished_rx)
        .await
        .expect("pool was not replenished: no third work conn after the mock consumed one and sent ReqWorkConn")
        .expect("mock server failed to complete the replenishment");
    // The mock runs its 500ms no-fourth-conn window after signaling, then
    // completes on its own; await it so a panic inside the mock (e.g. the
    // unbounded-dialing assert) fails this test instead of vanishing into a
    // detached task.
    tokio::time::timeout(Duration::from_secs(5), mock)
        .await
        .expect("mock server did not finish its no-fourth-conn window")
        .expect("mock server panicked");

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
}
