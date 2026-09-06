//! Client work-conn reject gate (round-11 F2, frp-client/src/work_conn.rs):
//! after the client sends NewWorkConn, the server's answer is a
//! StartWorkConn frame — normally an ASSIGNMENT naming the proxy, but a
//! REJECTION arrives as the same frame with the error field set (round-11
//! F2 made every server reject site write this frame before closing, Go
//! service.go:512-522 parity). The client gates on the error field exactly
//! like Go client/control.go:152 (`startMsg.Error != ""`):
//!   - error Some("reason") → log + close the conn, NEVER dial the local
//!     service (a broken gate would treat the rejection as an assignment
//!     and bridge a conn the server already decided to drop);
//!   - error None or Some("") → NORMAL assignment (the empty-string case
//!     must not be treated as a rejection — `!= ""`, not `!= nil`), the
//!     conn bridges to the local service.
//!
//! The control session must survive both paths: a rejected work conn never
//! kills the client control loop, and later ReqWorkConns are still served
//! by fresh dials.
//!
//! Mock frps drives the whole flow (real frp-rs client service, in-process):
//! Login → LoginResp(run_id "mock-server-run") → NewProxy("p1") answered →
//! ReqWorkConn ×3, each dial answered with a StartWorkConn of the tested
//! shape. Work conns are plaintext (never encrypted); the control stream
//! wraps in AES-128-CFB after LoginResp like the real server.

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

const RUN_ID: &str = "mock-server-run";

#[tokio::test]
async fn rejected_work_conn_closes_without_local_dial_and_empty_error_still_assigns() {
    common::init_tracing();
    let token = "work-conn-reject-gate-token";
    let server_port = allocate_port();
    let echo_port = allocate_port();
    start_echo_server(echo_port);
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some(RUN_ID.into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);

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
                Some(1),
                "client must declare pool_count=1 in Login"
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

        // Registration + pre-warm (mock sends ReqWorkConn #1 before
        // NewProxyResp — the registration read loop handles it).
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
        enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: "p1".into(),
            remote_addr: Some("127.0.0.1:8081".into()),
            error: None,
        }))
        .await
        .expect("write NewProxyResp");

        // --- Work conn #1: REJECTED by the server (error text set). The
        // client must close it without dialing the local service — a
        // bridged conn would stay OPEN (the mock sees no EOF). ---
        let (wc1, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("work conn #1 timeout: client did not dial on ReqWorkConn #1")
            .expect("accept work conn");
        let mut wc1 = IoStream::Tcp(wc1);
        let nwc = tokio::time::timeout(Duration::from_secs(10), wc1.read_v1_frame())
            .await
            .expect("NewWorkConn #1 timeout")
            .expect("read NewWorkConn");
        match nwc {
            FrpMessage::NewWorkConn(n) => assert_eq!(
                n.run_id.as_deref(),
                Some(RUN_ID),
                "work conn must carry the run_id from LoginResp"
            ),
            other => panic!("expected NewWorkConn, got {other:?}"),
        }
        wc1.write_v1_frame(&FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
            proxy_name: "p1".into(),
            src_addr: None,
            src_port: None,
            dst_addr: None,
            dst_port: None,
            error: Some("rejected by mock policy".into()),
            use_encryption: None,
            use_compression: None,
            nat_hole_sid: None,
            nat_hole_visitor_addr: None,
            sk: None,
        })))
        .await
        .expect("write rejecting StartWorkConn");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(3), wc1.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!(
                "rejected work conn must be closed by the client, got {n} bytes instead of EOF"
            ),
            Ok(Err(_)) => {} // RST is also a valid close
            Err(_) => panic!(
                "rejected work conn stayed OPEN: the client treated the rejection as an assignment"
            ),
        }

        // --- Work conn #2: normal assignment (error: None) — the control
        // session survived the rejection above; data must bridge. ---
        enc.write_v1_frame(&FrpMessage::ReqWorkConn(msg::ReqWorkConn {}))
            .await
            .expect("write ReqWorkConn #2");
        let (wc2, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("work conn #2 timeout: client did not dial on ReqWorkConn #2")
            .expect("accept work conn");
        let mut wc2 = IoStream::Tcp(wc2);
        let nwc = tokio::time::timeout(Duration::from_secs(10), wc2.read_v1_frame())
            .await
            .expect("NewWorkConn #2 timeout")
            .expect("read NewWorkConn");
        assert!(
            matches!(nwc, FrpMessage::NewWorkConn(_)),
            "expected NewWorkConn, got {nwc:?}"
        );
        wc2.write_v1_frame(&FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
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
        .expect("write assigning StartWorkConn");
        wc2.write_all(b"probe-ok-1").await.expect("write probe 1");
        let mut echo1 = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), wc2.read_exact(&mut echo1))
            .await
            .expect("echo round-trip #1 timeout: assignment was not bridged to the local service")
            .expect("read echo 1");
        assert_eq!(
            &echo1, b"probe-ok-1",
            "bridge #1 must relay to echo and back"
        );

        // --- Work conn #3: EMPTY error string — Go gates on `!= ""`, so
        // Some("") is an assignment, not a rejection. A gate that flips to
        // "error field present = reject" closes this conn and the probe
        // below never round-trips. ---
        enc.write_v1_frame(&FrpMessage::ReqWorkConn(msg::ReqWorkConn {}))
            .await
            .expect("write ReqWorkConn #3");
        let (wc3, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("work conn #3 timeout: client did not dial on ReqWorkConn #3")
            .expect("accept work conn");
        let mut wc3 = IoStream::Tcp(wc3);
        let nwc = tokio::time::timeout(Duration::from_secs(10), wc3.read_v1_frame())
            .await
            .expect("NewWorkConn #3 timeout")
            .expect("read NewWorkConn");
        assert!(
            matches!(nwc, FrpMessage::NewWorkConn(_)),
            "expected NewWorkConn, got {nwc:?}"
        );
        wc3.write_v1_frame(&FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
            proxy_name: "p1".into(),
            src_addr: None,
            src_port: None,
            dst_addr: None,
            dst_port: None,
            error: Some(String::new()), // "" — assignment, Go `!= ""` gate
            use_encryption: None,
            use_compression: None,
            nat_hole_sid: None,
            nat_hole_visitor_addr: None,
            sk: None,
        })))
        .await
        .expect("write empty-error StartWorkConn");
        wc3.write_all(b"probe-ok-2").await.expect("write probe 2");
        let mut echo2 = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), wc3.read_exact(&mut echo2))
            .await
            .expect("echo round-trip #2 timeout: Some(\"\") error must still assign (Go `!= \"\"` gate)")
            .expect("read echo 2");
        assert_eq!(
            &echo2, b"probe-ok-2",
            "bridge #2 must relay to echo and back"
        );

        // Keep the control connection open until the test stops the client.
        tokio::spawn(async move {
            let _ = enc.read_v1_frame().await;
        });
        drop(wc2);
        drop(wc3);
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        pool_count: 1,
        tcp_mux: false,
        tls_enable: false,
        // Heartbeats off: the watchdog is orthogonal to the reject gate.
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

    // Awaiting the JoinHandle itself (not just a done signal) surfaces the
    // mock's real panic message: a JoinError carries the assertion text,
    // where a bare oneshot drop only says "did not complete".
    tokio::time::timeout(Duration::from_secs(15), mock)
        .await
        .expect("mock server did not complete all three work-conn phases (hung)")
        .expect("mock server panicked");

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
}
