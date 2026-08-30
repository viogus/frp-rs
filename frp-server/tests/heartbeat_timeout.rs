//! Server-side heartbeat-timeout disconnect (control/mod.rs heartbeat
//! watchdog): a client that completes Login and then goes silent must be
//! disconnected at approximately `heartbeat_timeout` — not earlier, and
//! not parked forever. A client that pings periodically must stay up.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

fn heartbeat_cfg(bind_port: u16, timeout_secs: i64) -> ServerConfig {
    let mut cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    // Explicitly set (the completion pass only rewrites 0/default values,
    // and start_test_server forces tcp_mux off, so this survives).
    cfg.transport.heartbeat_timeout = timeout_secs;
    cfg
}

/// A client that completes Login then goes silent: the server must close
/// the control connection at ~heartbeat_timeout (3s): not before ~2.5s
/// (the watchdog must not fire early), closed by ~6s (read returns
/// EOF/error — the connection is released, not parked forever).
#[tokio::test]
async fn test_silent_client_disconnected_at_heartbeat_timeout() {
    let bind_port = allocate_port();
    let cfg = heartbeat_cfg(bind_port, 3);
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let start = Instant::now();
    let (mut enc, resp) = login_with_test_token(addr).await.expect("login");
    assert!(resp.error.is_none(), "login failed: {:?}", resp.error);

    // Go silent: the next control read must fail (EOF/reset) at ~3s.
    let closed = tokio::time::timeout(Duration::from_secs(6), read_msg_v1(&mut enc)).await;
    assert!(
        closed.is_ok(),
        "server did not disconnect the silent control within 6s (heartbeat watchdog dead?)"
    );
    assert!(
        closed.unwrap().is_err(),
        "silent control read returned a message — expected the connection to be closed"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(2500),
        "heartbeat disconnected the client too early: {elapsed:?} (heartbeat_timeout = 3s)"
    );
}

/// A client that pings periodically must outlive heartbeat_timeout: pings
/// every 800ms for ~4s (> 3s), then a final Ping→Pong proves the control
/// is still alive.
#[tokio::test]
async fn test_healthy_client_survives_past_heartbeat_timeout() {
    let bind_port = allocate_port();
    let cfg = heartbeat_cfg(bind_port, 3);
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let (mut enc, resp) = login_with_test_token(addr).await.expect("login");
    assert!(resp.error.is_none(), "login failed: {:?}", resp.error);

    let start = Instant::now();
    for i in 0..5 {
        let ping = FrpMessage::Ping(msg::Ping {
            privilege_key: None,
            timestamp: None,
        });
        write_msg_v1(&mut enc, &ping).await.expect("send ping");
        match read_msg_v1(&mut enc).await.expect("read pong") {
            FrpMessage::Pong(pong) => {
                assert!(
                    pong.error.is_none(),
                    "ping {i} got error pong: {:?}",
                    pong.error
                );
            }
            other => panic!("expected Pong, got type byte {:?}", other.v1_type_byte()),
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    }
    assert!(
        start.elapsed() >= Duration::from_millis(3500),
        "test did not outlive heartbeat_timeout"
    );

    // One final Ping→Pong confirms the control survived past the timeout.
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    write_msg_v1(&mut enc, &ping)
        .await
        .expect("send final ping");
    match read_msg_v1(&mut enc).await.expect("read final pong") {
        FrpMessage::Pong(pong) => assert!(
            pong.error.is_none(),
            "final pong carried an error: {:?}",
            pong.error
        ),
        other => panic!("expected Pong, got type byte {:?}", other.v1_type_byte()),
    }
}
