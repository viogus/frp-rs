//! Initial-login retry cadence (login_fail_exit = false, server rejects
//! every Login): the client must retry with Go frp's exponential schedule —
//! 1s base × 2^attempt with a 10s cap (Go `loopLoginUntilSuccess`,
//! FastBackoffOptions without FastRetryCount, MaxDuration=10s) plus ≤10%
//! jitter. Measured between consecutive Login frame arrivals:
//!
//!   attempt 1 → ~2s   (2000-2200ms incl. jitter)
//!   attempt 2 → ~4s   (4000-4400ms)
//!   attempt 3 → ~8s   (8000-8800ms)
//!   attempt 4 → ~10s  (10s cap: 10000-11000ms, never 16s)
//!
//! The mock records the arrival time of every Login it rejects, so the test
//! asserts the actual 2/4/8/10 cadence rather than any internal helper.
//!
//! Pre-fix (round-8 candidate): a sleep that never hit the cap (or a wrong
//! base) would show up here as interval 3 or 4 outside the expected windows.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// Spawn a mock server that rejects every Login (LoginResp{error}, before
/// any encryption wrap — the client treats it as an auth failure) and
/// records the arrival time of each Login frame. The listener is owned by
/// the task; it ends when the runtime shuts the listener down at stop.
fn spawn_rejecting_server(server_port: u16) -> (JoinHandle<()>, Arc<Mutex<Vec<Instant>>>) {
    let times = Arc::new(Mutex::new(Vec::new()));
    let times2 = times.clone();
    // Bind synchronously: #[tokio::test] is a current-thread runtime, so a
    // listener bound inside the spawned task would not exist yet when the
    // client's first dial lands (same pattern as login_fail_exit.rs).
    let std_listener =
        std::net::TcpListener::bind(("127.0.0.1", server_port)).expect("mock server bind");
    std_listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let listener = tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
    let handle = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.expect("control conn");
            let mut stream = IoStream::Tcp(conn);
            let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                .await
                .expect("login timeout")
                .expect("read Login");
            assert!(matches!(login, FrpMessage::Login(_)));
            times2.lock().unwrap().push(Instant::now());
            stream
                .write_v1_frame(&FrpMessage::LoginResp(msg::LoginResp {
                    version: Some(frp_core::VERSION.into()),
                    run_id: None,
                    error: Some("invalid token".into()),
                    server_additional_auth_scopes: None,
                }))
                .await
                .expect("write LoginResp error");
            // Drain so the connection closes when the client drops it.
            tokio::spawn(async move { while stream.read_v1_frame().await.is_ok() {} });
        }
    });
    (handle, times)
}

fn client_cfg(server_port: u16, token: &str) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // No heartbeats: nothing else can fire during the test windows.
        heartbeat_interval: 0,
        proxies: vec![],
        visitors: vec![],
        ..Default::default()
    }
}

/// The initial-login retry schedule must be 2s, 4s, 8s, then capped at 10s
/// (Go exponential + cap), each with ≤10% jitter. Measured end-to-end on the
/// Login frame arrival times.
#[tokio::test]
async fn initial_login_retries_follow_go_exponential_cap() {
    common::init_tracing();
    let token = "retry-cadence-token";
    let server_port = allocate_port();
    let (mock, times) = spawn_rejecting_server(server_port);

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

    // Wait for 5 Login frames (initial + 4 retries). Worst case ≈ 2+4+8+10
    // = 24s + jitter/overhead; 40s is generous headroom.
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if times.lock().unwrap().len() >= 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("client did not reach 5 login attempts within 40s");

    let ts = times.lock().unwrap().clone();
    let intervals: Vec<u128> = ts
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_millis())
        .collect();
    assert_eq!(intervals.len(), 4, "expected 4 retry intervals");

    // Nominal delays (jitter ≤ +10%): 2000-2200, 4000-4400, 8000-8800,
    // 10000-11000. Windows add ~20-25% upper headroom for slow-CI sleep
    // overruns; the lower bounds are safe (tokio sleeps never finish early).
    assert!(
        (1900..=2600).contains(&intervals[0]),
        "retry 1 interval {}ms, expected ~2s (2000-2200ms + jitter)",
        intervals[0]
    );
    assert!(
        (3800..=5000).contains(&intervals[1]),
        "retry 2 interval {}ms, expected ~4s (4000-4400ms + jitter)",
        intervals[1]
    );
    assert!(
        (7600..=9500).contains(&intervals[2]),
        "retry 3 interval {}ms, expected ~8s (8000-8800ms + jitter)",
        intervals[2]
    );
    assert!(
        (9500..=12500).contains(&intervals[3]),
        "retry 4 interval {}ms, expected the 10s cap (10000-11000ms), NOT 16s",
        intervals[3]
    );

    // The client never succeeds here, so run() only ends on request_stop.
    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");

    std::mem::drop(mock);
}
