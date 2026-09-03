//! Registration-error arms of the frp-client control loop (T9):
//!
//! 1. The registration-batch NewProxyResp arm — a NewProxyResp with
//!    `error: Some(..)` during initial registration moves the proxy to
//!    StartErr WITHOUT tearing the session down (service.rs, the
//!    `register_proxies` response loop);
//! 2. The message-loop NewProxyResp arm — an error answering a RETRY
//!    re-send moves the proxy WaitStart -> StartErr and anchors the
//!    StartErr retry clock (`last_start_err`, Go frp `lastStartErr.Add`);
//! 3. The generic `FrpMessage::Error` arm — a server "Error" frame is
//!    logged and ignored: the session must keep heartbeating and must not
//!    reconnect.
//!
//! proxy_retry.rs covers the SILENT-server path (no response at all). This
//! file covers the explicit-error paths: the mock answers every NewProxy
//! with a NewProxyResp carrying an error (never silence), so both error
//! arms run on every hop, and the observable is that the client keeps
//! re-sending (retry rescheduling) while the ORIGINAL connection stays up.
//!
//! Cadence env vars are shrunk identically in both tests (250ms retry
//! interval). The file-level read-once LazyLock in the client makes the
//! FIRST-constructed Service freeze the values; both tests set the same
//! values before constructing, so interleaving is harmless.

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

const RETRY_MS: &str = "250";
const WAITSTART_MS: &str = "2000";
const ASSERT_TIMEOUT: Duration = Duration::from_secs(10);

/// Mock server state shared with the test: NewProxy frames seen, Pings
/// seen, and accepted connections (a reconnect would increment accepts).
struct MockCounters {
    newproxy: Arc<AtomicUsize>,
    pings: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
}

fn client_config(server_port: u16, token: &str) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
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
    }
}

/// Spawn a mock server: complete login, Pong every Ping, and answer every
/// NewProxy with `responder`. Returns the counters and the mock task (the
/// accept loop ends when the listener is dropped at runtime shutdown).
fn spawn_mock(
    listener: TcpListener,
    token: String,
    counters: &MockCounters,
    responder: impl Fn(&str) -> FrpMessage + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    let newproxy = counters.newproxy.clone();
    let pings = counters.pings.clone();
    let accepts = counters.accepts.clone();
    tokio::spawn(async move {
        let login_resp = FrpMessage::LoginResp(frp_core::msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("mock-server-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        let enc_key = frp_core::encryption::derive_key(&token);
        loop {
            let (conn, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break, // listener closed
            };
            accepts.fetch_add(1, Ordering::SeqCst);
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
            loop {
                let msg = match enc.read_v1_frame().await {
                    Ok(m) => m,
                    Err(_) => break, // client closed the connection
                };
                match msg {
                    FrpMessage::NewProxy(np) => {
                        newproxy.fetch_add(1, Ordering::SeqCst);
                        let resp = responder(&np.proxy_name);
                        enc.write_v1_frame(&resp).await.expect("write NewProxyResp");
                    }
                    FrpMessage::Ping(_) => {
                        pings.fetch_add(1, Ordering::SeqCst);
                        enc.write_v1_frame(&FrpMessage::Pong(frp_core::msg::Pong { error: None }))
                            .await
                            .expect("write Pong");
                    }
                    _ => {}
                }
            }
        }
    })
}

/// Start the client Service + run task. Env cadence must be set BEFORE the
/// first Service construction in the process (LazyLock read-once).
async fn start_client(cfg: ClientConfig) -> (Arc<ClientService>, tokio::task::JoinHandle<()>) {
    let client = Arc::new(ClientService::new(cfg, None).await.unwrap());
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };
    (client, runner)
}

/// T9 arm 1 + 2: every NewProxy (initial registration AND every retry) is
/// answered with an explicit error. The registration-batch arm turns the
/// first error into StartErr; the retry tick re-sends; the message-loop arm
/// turns the re-send's error into StartErr again and re-anchors the retry
/// clock. Observable: >= 3 NewProxy frames arrive (initial + two retries)
/// while the ORIGINAL connection stays up (accepts == 1) and heartbeats
/// keep flowing (pings >= 1) — the errors must never tear the session.
#[tokio::test]
async fn explicit_newproxy_resp_error_drives_starterr_and_retries_on_same_session() {
    std::env::set_var("FRP_PROXY_RETRY_INTERVAL_MS", RETRY_MS);
    std::env::set_var("FRP_WAIT_START_RETRY_TIMEOUT_MS", WAITSTART_MS);

    common::init_tracing();
    let token = "proxy-error-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let counters = MockCounters {
        newproxy: Arc::new(AtomicUsize::new(0)),
        pings: Arc::new(AtomicUsize::new(0)),
        accepts: Arc::new(AtomicUsize::new(0)),
    };
    let mock = spawn_mock(listener, token.into(), &counters, |name| {
        FrpMessage::NewProxyResp(frp_core::msg::NewProxyResp {
            proxy_name: name.to_string(),
            remote_addr: None,
            error: Some("mock rejection: remote port already used".into()),
        })
    });

    let (_client, runner) = start_client(client_config(server_port, token)).await;

    // 10s is generous headroom over the ~0.75s expectation (initial error
    // lands instantly; retry tick 250ms -> re-send -> second error ->
    // anchored 250ms -> third re-send).
    tokio::time::timeout(ASSERT_TIMEOUT, async {
        while counters.newproxy.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("NewProxy retries stopped: an explicit NewProxyResp error does not keep re-sending");
    let total = counters.newproxy.load(Ordering::SeqCst);
    assert!(
        total >= 3,
        "expected >= 3 NewProxy frames (initial + 2 retries after explicit errors), got {total}"
    );

    // The session must have survived every error: exactly one accepted
    // connection and live heartbeats.
    assert_eq!(
        counters.accepts.load(Ordering::SeqCst),
        1,
        "an explicit NewProxyResp error must not tear the session down (no reconnect)"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while counters.pings.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("heartbeats stopped after explicit NewProxyResp errors");

    let client = Arc::clone(&_client);
    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    std::mem::drop(mock);
}

/// T9 arm 3: the generic `FrpMessage::Error` frame (message loop) is logged
/// and ignored. After a SUCCESSFUL registration the mock sends an Error
/// frame; the client must keep the session (no reconnect, accepts == 1) and
/// keep heartbeating (a Ping must arrive AFTER the Error frame was sent).
#[tokio::test]
async fn generic_server_error_frame_is_logged_and_session_survives() {
    std::env::set_var("FRP_PROXY_RETRY_INTERVAL_MS", RETRY_MS);
    std::env::set_var("FRP_WAIT_START_RETRY_TIMEOUT_MS", WAITSTART_MS);

    common::init_tracing();
    let token = "proxy-error-frame-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let counters = MockCounters {
        newproxy: Arc::new(AtomicUsize::new(0)),
        pings: Arc::new(AtomicUsize::new(0)),
        accepts: Arc::new(AtomicUsize::new(0)),
    };
    // First NewProxy succeeds (proxy reaches Running); every subsequent
    // NewProxy is impossible here (no retries on the success path), so the
    // responder only ever sees the initial one.
    let pings = counters.pings.clone();
    let accepts = counters.accepts.clone();
    let newproxy = counters.newproxy.clone();
    let mock = tokio::spawn({
        let listener = listener;
        async move {
            let login_resp = FrpMessage::LoginResp(frp_core::msg::LoginResp {
                version: Some(frp_core::VERSION.into()),
                run_id: Some("mock-server-run".into()),
                error: None,
                server_additional_auth_scopes: None,
            });
            let enc_key = frp_core::encryption::derive_key(token);
            let (conn, _) = listener.accept().await.expect("control conn");
            accepts.fetch_add(1, Ordering::SeqCst);
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
            loop {
                let msg = match enc.read_v1_frame().await {
                    Ok(m) => m,
                    Err(_) => break,
                };
                match msg {
                    FrpMessage::NewProxy(np) => {
                        newproxy.fetch_add(1, Ordering::SeqCst);
                        enc.write_v1_frame(&FrpMessage::NewProxyResp(
                            frp_core::msg::NewProxyResp {
                                proxy_name: np.proxy_name,
                                remote_addr: Some("0.0.0.0:8081".into()),
                                error: None,
                            },
                        ))
                        .await
                        .expect("write NewProxyResp");
                        // Registration done: the session is in the message
                        // loop. Send the generic Error frame once.
                        enc.write_v1_frame(&FrpMessage::Error(frp_core::msg::Error {
                            error: "mock server error: shutting down soon".into(),
                        }))
                        .await
                        .expect("write Error frame");
                    }
                    FrpMessage::Ping(_) => {
                        pings.fetch_add(1, Ordering::SeqCst);
                        enc.write_v1_frame(&FrpMessage::Pong(frp_core::msg::Pong { error: None }))
                            .await
                            .expect("write Pong");
                    }
                    _ => {}
                }
            }
        }
    });

    let (client, runner) = start_client(client_config(server_port, token)).await;

    // The registration must succeed and the Error frame must be harmless:
    // the client keeps heartbeating on the SAME connection. Pings are
    // answered from ~1s in, so wait for >= 1 ping, then assert the
    // connection was never re-established and no second NewProxy was sent
    // (a session restart would re-register).
    tokio::time::timeout(ASSERT_TIMEOUT, async {
        while counters.newproxy.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Give the Error frame time to be processed and a ping cycle to run.
        while counters.pings.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session did not reach steady state (NewProxy registered + first heartbeat)");
    assert_eq!(
        counters.accepts.load(Ordering::SeqCst),
        1,
        "a generic Error frame must not tear the session down (no reconnect)"
    );
    assert_eq!(
        counters.newproxy.load(Ordering::SeqCst),
        1,
        "a generic Error frame must not trigger a re-registration"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    std::mem::drop(mock);
}
