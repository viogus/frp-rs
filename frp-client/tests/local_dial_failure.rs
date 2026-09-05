//! G2 regression (audit round 8): a local-service dial failure after
//! StartWorkConn must close the user connection with a bounded EOF, leave the
//! control session alive, and let subsequent user connections be served via
//! fresh work connections (frp-client/src/work_conn.rs StartWorkConn
//! dial-failure arm).
//!
//! A TCP proxy whose `local_port` points at a dead port (nothing listening —
//! dial → ECONNREFUSED on localhost) exercises exactly that arm on every user
//! connection:
//!   conn1: user dials the remote port → frps StartWorkConn → client dials
//!          dead local port → failure arm closes the work conn → frps closes
//!          the user conn. Oracle: the user read ends (bounded EOF) quickly —
//!          a missing/incorrect arm would leave the user conn parked forever;
//!   conn2, conn3: same bounded EOF via fresh work conns — the failure arm
//!          must not poison the control session or the proxy registration;
//!   whole test: the client `run()` task stays alive (no login_fail_exit /
//!          control-loop exit on a local dial error).

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;

use common::{allocate_port, start_frps, wait_for_port};

#[tokio::test]
async fn local_dial_failure_closes_bounded_and_control_survives() {
    common::init_tracing();
    let token = "g2-local-dial-failure-token";
    let server_port = allocate_port();
    let remote_port = allocate_port();
    // A dead local port: probed free and left unbound. Localhost dial →
    // ECONNREFUSED, deterministically.
    let dead_local_port = allocate_port();

    let _frps = start_frps(server_port, token).await;

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
            local_port: dead_local_port,
            remote_port,
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

    // The proxy is registered when frps listens on the remote port.
    wait_for_port(
        std::net::SocketAddr::from(([127, 0, 0, 1], remote_port)),
        Duration::from_secs(8),
    )
    .await
    .expect("proxy never registered on the remote port");

    for i in 1..=3u32 {
        let mut user = TcpStream::connect(("127.0.0.1", remote_port))
            .await
            .expect("connect to remote port");
        // The user read must end (EOF/error from the frps side once the
        // client's dial-failure arm closed the work conn) — quickly, not a
        // parked read. 4s is a generous bound for the StartWorkConn round
        // trip + dial refusal.
        let started = std::time::Instant::now();
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(4), user.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) => {} // clean EOF — the failure arm did its job
            Ok(Ok(n)) => panic!(
                "conn {i}: expected EOF from the dead local port, got {n} bytes: {:?}",
                &buf[..n]
            ),
            Ok(Err(e)) => panic!("conn {i}: unexpected user-read error: {e}"),
            Err(_) => panic!(
                "conn {i}: user connection PARKED after StartWorkConn to a dead local port — the dial-failure arm never closed it (G2)"
            ),
        }
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "conn {i}: EOF was not bounded"
        );
    }

    // Control session survived all three dial failures: the runner is still
    // alive (a control-loop exit would end run()), and a little idle time
    // passes with no crash while heartbeats flow.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        !runner.is_finished(),
        "client run() exited after local dial failures — the control session must survive (G2)"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
}
