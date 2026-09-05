//! G3 regression (audit round 8): a clean FIN on the control connection
//! (server half-closes after a completed login + registration — no bytes in
//! flight, no error frame) must tear the session down and reconnect: a second
//! Login lands at the server. No RST involved: the mock drains inbound
//! heartbeats, then `shutdown(Write)` (FIN), then keeps reading so any
//! client-side close is orderly.
//!
//! Timeline:
//!   session 1: Login → LoginResp → NewProxy(p1) → NewProxyResp → the mock
//!              drains Pings (Pongs them), then half-closes at ~1.5s;
//!              the client's control read sees EOF → session teardown →
//!              reconnect;
//!   session 2: a second Login lands at the mock within the window; the mock
//!              completes registration and keeps the session alive with
//!              Pongs — a fixed session must NOT reconnect again.
//!
//! Oracles: exactly two Logins (one reconnect, no storm), and the second
//! session stays stable for 3s of heartbeats.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn clean_fin_control_triggers_reconnect() {
    common::init_tracing();
    let token = "g3-clean-fin-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let np_resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
        proxy_name: "p1".into(),
        remote_addr: Some("127.0.0.1:18081".into()),
        error: None,
    });
    let pong = FrpMessage::Pong(msg::Pong { error: None });

    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    // Signals the reconnect session is stable (heartbeating for a while) so
    // the test can stop the client. Notify stores the permit if the waiter
    // registers late, and it is Clone — a oneshot Sender is neither, and each
    // per-conn task needs its own copy.
    let stable = Arc::new(tokio::sync::Notify::new());
    let stable_env = stable.clone();
    let login_resp_env = login_resp.clone();
    let np_resp_env = np_resp.clone();
    let pong_env = pong.clone();
    let mock = tokio::spawn(async move {
        let mut session = 0u32;
        loop {
            let (conn, _) = listener.accept().await.expect("control conn");
            session += 1;
            let my_session = session;
            let count = count.clone();
            let stable_env = stable_env.clone();
            let login_resp = login_resp_env.clone();
            let np_resp = np_resp_env.clone();
            let pong = pong_env.clone();
            tokio::spawn(async move {
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

                let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
                    .await
                    .expect("NewProxy timeout")
                    .expect("read NewProxy");
                assert!(
                    matches!(np, FrpMessage::NewProxy(_)),
                    "session {my_session}: expected NewProxy"
                );
                enc.write_v1_frame(&np_resp)
                    .await
                    .expect("write NewProxyResp");

                if my_session == 1 {
                    // Drain a couple of heartbeats (the client's message
                    // loop starts at registration), then half-close with a
                    // clean FIN: no unread inbound bytes at the mock, so no
                    // RST — the client sees plain EOF.
                    for _ in 0..2 {
                        match tokio::time::timeout(Duration::from_secs(3), enc.read_v1_frame())
                            .await
                        {
                            Ok(Ok(FrpMessage::Ping(_))) => {
                                enc.write_v1_frame(&pong).await.expect("write Pong");
                            }
                            Ok(Ok(_)) => {}
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }
                    // AsyncWrite::shutdown propagates through the cipher
                    // wrapper to the underlying TCP: a clean FIN, no RST.
                    enc.shutdown().await.expect("half-close (FIN)");
                    // Keep reading until the client closes after teardown.
                    let _ = tokio::time::timeout(Duration::from_secs(6), async {
                        while enc.read_v1_frame().await.is_ok() {}
                    })
                    .await;
                } else {
                    // Reconnect session: keep it alive with Pongs; if the
                    // client reconnects a third time the read errors and the
                    // outer accept loop takes the next conn.
                    let mut pings = 0u32;
                    let _ = tokio::time::timeout(Duration::from_secs(6), async {
                        loop {
                            match enc.read_v1_frame().await {
                                Ok(FrpMessage::Ping(_)) => {
                                    enc.write_v1_frame(&pong).await.expect("write Pong");
                                    pings += 1;
                                    if pings >= 2 {
                                        stable_env.notify_one();
                                    }
                                }
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    })
                    .await;
                }
            });
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
            remote_port: 18081,
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

    // Oracle: the clean FIN (at ~1.5s) triggers exactly one reconnect; the
    // second session must stay stable (2+ Pongs served) without a third
    // Login.
    tokio::time::timeout(Duration::from_secs(8), stable.notified())
        .await
        .expect("client never reached a stable reconnect session — clean FIN may not have triggered a reconnect (G3)");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        2,
        "clean FIN must cause exactly one reconnect (saw {} Logins)",
        login_count.load(Ordering::SeqCst)
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        2,
        "client reconnected AGAIN after the stable reconnect session"
    );
    // Mock teardown (round-2 review, audit round 8): the mock is an
    // infinite accept loop, so abort it, then await — a JoinHandle that
    // already panicked reports Panicked even after abort, so any mid-test
    // mock assertion failure fails THIS test instead of vanishing with the
    // runtime at scope end.
    mock.abort();
    match mock.await {
        Err(e) if e.is_cancelled() => {}
        other => panic!("mock task ended abnormally: {other:?}"),
    }
}
