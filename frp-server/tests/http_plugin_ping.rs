//! frps "ping" HTTP-server-plugin operation tests (audit round 10, coverage
//! gap B): the Ping plugin hook (frp-server/src/control/proxy.rs handle_ping)
//! fired for every client Ping when a plugin subscribes to "ping".
//!
//! Go frp v0.70.1 parity pins, mirroring server/control.go handlePing:
//! - the hook runs BEFORE ping auth, with PingContent = the flat Ping msg
//!   plus a `user` object (Go pkg/plugin/server/types.go) and the frp-rs
//!   additive extras run_id/remote_addr;
//! - a plugin rejection answers the client with Pong{error} while the
//!   control connection stays up — and, critically, last_ping is NOT
//!   updated: a client whose pings are all rejected is still disconnected
//!   by the server heartbeat watchdog at ~heartbeat_timeout (Go tolerates a
//!   failed ping but never lets it masquerade as liveness);
//! - a plugin mutation (unchange:false + content) is applied to the typed
//!   Ping BEFORE VerifyPing sees it (Go handleMutableContent order);
//! - ops filtering (plugin/http.rs ops_match) applies to "Ping" like every
//!   other op: an unsubscribed plugin never fires.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, routing::post, Json, Router};
use serde_json::json;

use common::{
    allocate_port, login_with_identity, login_with_test_token, start_test_server, test_auth_cfg,
    TEST_TOKEN,
};
use frp_core::config::{AuthServerConfig, HttpPluginConfig, ServerConfig};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

const REJECT_REASON: &str = "ping denied by policy";

/// Mock plugin state with per-op behavior: every request is recorded in
/// arrival order; an op listed in `reject` is rejected with its reason; an
/// op listed in `mutate` answers unchange:false, echoing the received
/// content with the override keys applied (the Go plugin convention — the
/// server decodes the response content into a FRESH typed struct, so keys
/// the mutation omits are zeroed, never preserved).
#[derive(Default)]
struct MockPluginState {
    requests: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    /// op -> reject reason.
    reject: std::sync::Mutex<HashMap<String, String>>,
    /// op -> mutation override keys (applied on top of the echoed content).
    mutate: std::sync::Mutex<HashMap<String, serde_json::Value>>,
}

type SharedState = Arc<MockPluginState>;

async fn mock_handler(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let op = body["op"].as_str().unwrap_or_default().to_string();
    if !op.is_empty() {
        state
            .requests
            .lock()
            .unwrap()
            .push((op.clone(), body.clone()));
    }
    if let Some(reason) = state.reject.lock().unwrap().get(&op).cloned() {
        return axum::response::IntoResponse::into_response(axum::Json(json!({
            "reject": true,
            "rejectReason": reason,
        })));
    }
    if let Some(overrides) = state.mutate.lock().unwrap().get(&op).cloned() {
        let mut content = body
            .get("content")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if let (Some(c), Some(m)) = (content.as_object_mut(), overrides.as_object()) {
            for (k, v) in m {
                c.insert(k.clone(), v.clone());
            }
        }
        return axum::response::IntoResponse::into_response(axum::Json(json!({
            "reject": false,
            "unchange": false,
            "content": content,
        })));
    }
    axum::response::IntoResponse::into_response(axum::Json(json!({
        "reject": false,
        "unchange": true,
    })))
}

async fn start_mock_plugin(state: SharedState) -> u16 {
    let app = Router::new()
        .route("/handler", post(mock_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    port
}

fn plugin_cfg(port: u16, ops: Vec<&str>) -> HttpPluginConfig {
    HttpPluginConfig {
        name: format!("mock-{port}"),
        addr: format!("http://127.0.0.1:{port}"),
        path: "/handler".to_string(),
        ops: ops.into_iter().map(String::from).collect(),
        timeout: 3,
        enable_control: true,
        tls_verify: true,
    }
}

/// Drive one Ping on an established control connection and return the
/// server's Pong (the observable client-side seam of handle_ping).
async fn ping_pong(
    ctl: &mut IoStream,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
) -> msg::Pong {
    write_msg_v1(
        ctl,
        &FrpMessage::Ping(msg::Ping {
            privilege_key,
            timestamp,
        }),
    )
    .await
    .expect("send Ping");
    match read_msg_v1(ctl).await.expect("read Pong") {
        FrpMessage::Pong(pong) => pong,
        other => panic!("expected Pong, got type byte {:?}", other.v1_type_byte()),
    }
}

/// A plugin subscribed to "ping" receives every client Ping BEFORE ping
/// auth, with Go PingContent shape: the flat Ping msg (privilege_key,
/// timestamp — verbatim from the client) plus the `user` object recorded at
/// login (Go loginUserInfo) and the frp-rs additive extras run_id /
/// remote_addr.
#[tokio::test]
async fn test_plugin_ping_receives_content_with_user_object() {
    let state = Arc::new(MockPluginState::default());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login", "Ping"])],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let mut metas = HashMap::new();
    metas.insert("env".to_string(), "test".to_string());
    let (mut ctl, resp) = login_with_identity(addr, "alice", metas)
        .await
        .expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);
    let run_id = resp.run_id.expect("run_id assigned");

    // Distinctive flat values: whatever the client put in the Ping must
    // reach the plugin verbatim (the hook runs before any auth work).
    let pong = ping_pong(&mut ctl, Some("pk-1".into()), Some(42)).await;
    assert!(
        pong.error.is_none(),
        "accepted ping must get a clean Pong, got: {:?}",
        pong.error
    );
    drop(ctl);

    let requests = state.requests.lock().unwrap();
    let (_, body) = requests
        .iter()
        .find(|(op, _)| op == "Ping")
        .unwrap_or_else(|| panic!("Ping hook must fire; got requests: {requests:?}"));
    // Go wire envelope: op + API version travel in the event body.
    assert_eq!(body["op"], "Ping");
    assert_eq!(body["version"], "0.1.0");
    let content = &body["content"];
    // The `user` object is the login identity recorded for this run_id.
    assert_eq!(
        content["user"]["user"], "alice",
        "user.user must match the control login user"
    );
    assert_eq!(content["user"]["metas"]["env"], "test");
    assert_eq!(
        content["user"]["run_id"], run_id,
        "user.run_id must be the control's run_id"
    );
    assert_eq!(
        content["run_id"], run_id,
        "frp-rs additive top-level run_id must match"
    );
    let remote_addr = content["remote_addr"]
        .as_str()
        .expect("remote_addr must be present");
    assert!(
        remote_addr.starts_with("127.0.0.1:"),
        "remote_addr must be the peer address, got: {remote_addr}"
    );
    // The flat Ping msg fields pass through unmodified.
    assert_eq!(content["privilege_key"], "pk-1");
    assert_eq!(content["timestamp"], 42);
}

/// A plugin that rejects the ping answers the client with Pong{error}
/// (carrying the rejectReason) and the control connection stays up: the
/// very next ping is rejected the same way instead of tearing the session
/// down (Go handlePing tolerates a failed ping).
#[tokio::test]
async fn test_plugin_ping_rejection_answers_pong_error_and_keeps_control() {
    let state = Arc::new(MockPluginState::default());
    state
        .reject
        .lock()
        .unwrap()
        .insert("Ping".to_string(), REJECT_REASON.to_string());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login", "Ping"])],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let (mut ctl, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    for i in 0..2 {
        let pong = ping_pong(&mut ctl, None, None).await;
        assert!(
            pong.error
                .as_deref()
                .is_some_and(|e| e.contains(REJECT_REASON)),
            "ping {i} must be rejected with the plugin reason, got: {:?}",
            pong.error
        );
    }
    drop(ctl);

    // Every ping reached the plugin (rejection is per-ping, never cached).
    let requests = state.requests.lock().unwrap();
    let pings = requests.iter().filter(|(op, _)| op == "Ping").count();
    assert_eq!(pings, 2, "both pings must reach the plugin hook");
}

/// Critical semantic pin (Go server/control.go handlePing parity, comment
/// at control/proxy.rs:463-467): a ping rejected by the plugin must NOT
/// update last_ping. The observable seam is the server heartbeat watchdog:
/// with heartbeat_timeout = 3s, a client whose pings are ALL rejected is
/// still disconnected at ~3s after login — its last_ping stays frozen at
/// login time. (A buggy handler that refreshed last_ping on rejected pings
/// would keep the control alive past the deadline while its client pinged
/// every 800ms — the regression this test pins.)
#[tokio::test]
async fn test_plugin_rejected_ping_does_not_update_last_ping() {
    let state = Arc::new(MockPluginState::default());
    state
        .reject
        .lock()
        .unwrap()
        .insert("Ping".to_string(), REJECT_REASON.to_string());
    let port = start_mock_plugin(state.clone()).await;

    let mut cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login", "Ping"])],
        ..Default::default()
    };
    // Explicitly set (the completion pass only rewrites 0/default values,
    // and start_test_server forces tcp_mux off, so this survives — same
    // pattern as heartbeat_timeout.rs).
    cfg.transport.heartbeat_timeout = 3;
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let (mut ctl, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);
    let start = Instant::now();

    // Heartbeat at ~800ms like a healthy frpc. Every ping is answered with
    // Pong{error} (plugin rejection) while the control is up; once the
    // watchdog fires at ~3s after login (last_ping frozen at login time),
    // the connection drops and the next ping write/read fails.
    let mut rejected = 0u32;
    let mut disconnected_at: Option<Duration> = None;
    for i in 0..9u32 {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
        let ping = FrpMessage::Ping(msg::Ping {
            privilege_key: None,
            timestamp: None,
        });
        if write_msg_v1(&mut ctl, &ping).await.is_err() {
            disconnected_at = Some(start.elapsed());
            break;
        }
        match tokio::time::timeout(Duration::from_secs(3), read_msg_v1(&mut ctl)).await {
            Ok(Ok(FrpMessage::Pong(pong))) => {
                assert!(
                    pong.error
                        .as_deref()
                        .is_some_and(|e| e.contains(REJECT_REASON)),
                    "ping {i} must be plugin-rejected while the control is up, got: {:?}",
                    pong.error
                );
                rejected += 1;
            }
            Ok(Ok(other)) => panic!(
                "expected Pong while the control is up, got type byte {:?}",
                other.v1_type_byte()
            ),
            // EOF/RST from the watchdog's close (or the write above).
            Ok(Err(_)) => {
                disconnected_at = Some(start.elapsed());
                break;
            }
            // A live control answers within ms; a 3s stall means the server
            // wedged — but near the 3s watchdog boundary a slow-arriving
            // close can race the read, so only count it as a disconnect when
            // the watchdog deadline has plausibly passed. 2000ms floor (not
            // 2500): the deadline is measured from `start`, which is taken
            // after the LoginResp round trip, so a >500ms scheduler stall of
            // the login/ack path on a busy CI box shifts the observed
            // disconnect below 3.0s without the watchdog firing early.
            Err(_) => {
                if start.elapsed() >= Duration::from_millis(2000) {
                    disconnected_at = Some(start.elapsed());
                    break;
                }
                panic!(
                    "read of a live control's Pong timed out at {:?}",
                    start.elapsed()
                );
            }
        }
    }

    let elapsed = disconnected_at.expect(
        "server kept the control alive past heartbeat_timeout even though every ping was \
         plugin-rejected — a rejected ping must NOT update last_ping (watchdog should have \
         disconnected at ~3s)",
    );
    assert!(
        rejected >= 2,
        "the client heartbeated and was answered {rejected} times before the watchdog fired \
         — a rejected ping answers Pong{{error}} and does not kill the control"
    );
    assert!(
        elapsed >= Duration::from_millis(2000),
        "watchdog disconnected too early ({elapsed:?}) — last_ping was set at login, so the \
         disconnect must come at ~heartbeat_timeout (3s), not before (floor 2s absorbs login \
         round-trip stalls on a busy CI box)"
    );
    assert!(
        elapsed < Duration::from_millis(8000),
        "watchdog disconnect came late ({elapsed:?}) — the deadline is ~3s after login; a \
         later drop means the disconnect path is delayed. Without this upper bound, a \
         regression delaying the drop past ~9s would false-pass via the read-timeout arm \
         (the loop's last 3s read expires at ~9.4s and is counted as a disconnect)."
    );
    // The plugin saw each rejected ping: rejection is what froze last_ping.
    let requests = state.requests.lock().unwrap();
    let pings = requests.iter().filter(|(op, _)| op == "Ping").count();
    assert!(
        pings as u32 >= rejected,
        "plugin must have seen the rejected pings (got {pings} of {rejected})"
    );
}

/// Go handlePing order pin: the plugin hook runs BEFORE ping auth, and its
/// mutation REPLACES the typed Ping before VerifyPing (Go handleMutableContent
/// — same pattern as the NewWorkConn hook). With "HeartBeats" in
/// additional_auth_scopes, a ping whose privilege_key is WRONG is repaired by
/// a plugin mutation that rewrites key + timestamp to a valid pair: auth must
/// verify the MUTATED ping (a clean Pong proves VerifyPing never saw the
/// original bad key — plugin-before-auth ordering).
#[tokio::test]
async fn test_plugin_ping_mutation_feeds_ping_auth() {
    // A fixed, known-good (token, timestamp) pair the mutation will inject.
    // Distinct from the login's own timestamp (chosen a second earlier).
    let fix_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 1;
    let fix_key = frp_core::auth::generate_token(TEST_TOKEN, fix_ts);

    let state = Arc::new(MockPluginState::default());
    state.mutate.lock().unwrap().insert(
        "Ping".to_string(),
        json!({ "privilege_key": fix_key, "timestamp": fix_ts }),
    );
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: AuthServerConfig {
            additional_auth_scopes: vec!["HeartBeats".into()],
            ..test_auth_cfg()
        },
        http_plugins: vec![plugin_cfg(port, vec!["Login", "Ping"])],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let (mut ctl, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    // A garbage privilege_key that would fail VerifyPing on its own — the
    // plugin's mutation must repair it before auth runs.
    let pong = ping_pong(&mut ctl, Some("wrong-key".into()), Some(7)).await;
    assert!(
        pong.error.is_none(),
        "the plugin-mutated ping must pass auth (hook before VerifyPing), got: {:?}",
        pong.error
    );
    drop(ctl);

    // The hook saw the ORIGINAL bad key: mutation is applied server-side
    // after the notify, never pre-empted by auth.
    let requests = state.requests.lock().unwrap();
    let (_, body) = requests
        .iter()
        .find(|(op, _)| op == "Ping")
        .unwrap_or_else(|| panic!("Ping hook must fire; got requests: {requests:?}"));
    assert_eq!(body["content"]["privilege_key"], "wrong-key");
    assert_eq!(body["content"]["timestamp"], 7);
}

/// ops filtering (plugin/http.rs ops_match, Go IsSupport): a plugin whose
/// ops list omits "ping" must NOT be called for client pings — the ping
/// flows through untouched and gets a clean Pong.
#[tokio::test]
async fn test_plugin_unsubscribed_from_ping_never_fires() {
    let state = Arc::new(MockPluginState::default());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login"])],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let (mut ctl, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    let pong = ping_pong(&mut ctl, None, None).await;
    assert!(
        pong.error.is_none(),
        "an unsubscribed plugin must not affect the ping, got: {:?}",
        pong.error
    );
    drop(ctl);

    let requests = state.requests.lock().unwrap();
    assert!(
        requests.iter().all(|(op, _)| op == "Login"),
        "only the subscribed Login op may fire, got: {requests:?}"
    );
}
