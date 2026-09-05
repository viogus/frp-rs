//! G11 pin (audit round 8): heartbeat wire order — no Ping may leave the
//! client before the server has answered Login, and Pings begin only after
//! registration settles into the message loop.
//!
//! The client arms its heartbeat interval at login success (service.rs "single
//! arm point") but sends Pings only from the message loop, which starts after
//! registration completes. A heartbeat implementation that started ticking
//! earlier (e.g. from the dial) would leak Pings into the pre-LoginResp or
//! registration window and confuse a strict server.
//!
//! Mock timeline (heartbeat_interval = 1s):
//!   t0          client dials and sends Login;
//!   t0..t0+1.6s mock is silent: the client must send NOTHING (no Ping) while
//!               blocked in LoginResp wait — a 1.6s window spans a full
//!               heartbeat period;
//!   t0+1.6s     mock writes LoginResp;
//!               registration (NewProxy -> NewProxyResp) round-trips in ms;
//!   post-reg    the message loop starts; the FIRST frame the client writes
//!               must be a Ping (its heartbeat interval ticks immediately on
//!               first poll), and a second Ping must follow ~1s later.
//!
//! Oracles: (1) no frame in the pre-LoginResp window; (2) the first frame
//! after NewProxyResp is a Ping; (3) a second Ping arrives ~1s after the
//! first; (4) exactly one Login over the whole session.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn no_ping_before_login_resp_pings_begin_after_registration() {
    common::init_tracing();
    let token = "heartbeat-wire-order-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let pong = FrpMessage::Pong(msg::Pong { error: None });

    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    // Signals the mock's post-registration phase completed (Ping cadence
    // verified): the client is heartbeating normally.
    let (pings_ok_tx, pings_ok_rx) = tokio::sync::oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        count.fetch_add(1, Ordering::SeqCst);

        // Oracle 1: before LoginResp the client must send NOTHING. The
        // heartbeat interval is 1s and armed only at login success, so a
        // 1.6s silent window spans a full period: any Ping leaking into it
        // is a wire-order violation. (The Login frame was already read
        // above; the window starts now.) A `timeout` never fires before its
        // deadline — an Err return alone proves the ≥1.6s window held.
        let early = tokio::time::timeout(Duration::from_millis(1600), stream.read_v1_frame()).await;
        match early {
            Err(_) => {}
            Ok(Ok(frame)) => {
                panic!("client sent a frame before LoginResp (wire-order violation): {frame:?}")
            }
            Ok(Err(e)) => panic!("control read failed before LoginResp: {e}"),
        }

        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");

        // Registration round-trip.
        let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
            .await
            .expect("NewProxy timeout")
            .expect("read NewProxy");
        assert!(matches!(np, FrpMessage::NewProxy(_)));
        enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: "p1".into(),
            remote_addr: Some("127.0.0.1:8081".into()),
            error: None,
        }))
        .await
        .expect("write NewProxyResp");

        // Oracles 2-3: the message loop starts at registration completion;
        // the first frame must be a Ping (interval first tick), then a
        // second Ping ~1s later.
        let f1 = tokio::time::timeout(Duration::from_secs(3), enc.read_v1_frame())
            .await
            .expect("no frame after registration")
            .expect("read first post-registration frame");
        assert!(
            matches!(f1, FrpMessage::Ping(_)),
            "first post-registration frame must be a Ping, got {f1:?}"
        );
        let first_ping_at = Instant::now();
        let f2 = tokio::time::timeout(Duration::from_secs(3), enc.read_v1_frame())
            .await
            .expect("no second heartbeat")
            .expect("read second post-registration frame");
        assert!(
            matches!(f2, FrpMessage::Ping(_)),
            "second post-registration frame must be a Ping, got {f2:?}"
        );
        let second_gap = first_ping_at.elapsed();
        assert!(
            second_gap >= Duration::from_millis(500) && second_gap <= Duration::from_millis(1800),
            "heartbeat cadence off: second Ping {}ms after the first (expected ~1000ms)",
            second_gap.as_millis()
        );
        // (A wall-clock lower bound on the first Ping's arrival was dropped
        // as a tautology: it measured after f2 was read, so reg_end.elapsed()
        // ≥ second_gap ≥ 500ms by the assert above — it could never fail.)

        // Cadence verified: answer heartbeats until the test stops the
        // client.
        enc.write_v1_frame(&pong).await.expect("write Pong");
        let _ = pings_ok_tx.send(());
        loop {
            match enc.read_v1_frame().await {
                Ok(FrpMessage::Ping(_)) => {
                    enc.write_v1_frame(&pong).await.expect("write Pong");
                }
                Ok(_) => {}
                Err(_) => break, // client closed at stop
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
        heartbeat_interval: 1,
        heartbeat_timeout: 10,
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

    tokio::time::timeout(Duration::from_secs(8), pings_ok_rx)
        .await
        .expect("mock never verified the post-registration Ping cadence")
        .expect("mock task ended before verifying cadence");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the heartbeat wire-order session"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the whole session"
    );
    // The mock's final drain loop ends when the client closes the
    // connection at stop; detach it explicitly for the let_underscore lint.
    std::mem::drop(mock);
}
