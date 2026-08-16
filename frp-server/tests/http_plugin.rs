//! HTTP server plugin protocol tests (Go frp v0.70.1 compat):
//! - POST {url}?version=0.1.0&op=Login with X-Frp-Reqid header
//! - HTTP 200 required; transport/status errors fail closed (login rejected)
//! - reject:true rejects with rejectReason

mod common;

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use serde_json::json;

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::{HttpPluginConfig, ServerConfig};

/// Mock plugin state: captures the request shape and decides the response.
#[derive(Default)]
struct MockPluginState {
    captured: std::sync::Mutex<Option<serde_json::Value>>,
    reject: bool,
    reject_reason: String,
    status_code: u16,
    /// When true, respond with a non-JSON body (fail-closed check).
    bad_json: bool,
}

type SharedState = Arc<MockPluginState>;

async fn mock_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    query: axum::extract::RawQuery,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    *state.captured.lock().unwrap() = Some(json!({
        "query": query.0,
        "reqid": headers.get("x-frp-reqid").and_then(|v| v.to_str().ok()),
        "body": body,
    }));
    if state.status_code != 0 && state.status_code != 200 {
        return axum::response::Response::builder()
            .status(state.status_code)
            .body(axum::body::Body::from("boom"))
            .unwrap();
    }
    if state.bad_json {
        return axum::response::Response::builder()
            .header("Content-Type", "text/plain")
            .body(axum::body::Body::from("this is not json"))
            .unwrap();
    }
    if state.reject {
        return axum::response::IntoResponse::into_response(axum::Json(json!({
            "reject": true,
            "rejectReason": state.reject_reason,
        })));
    }
    axum::response::IntoResponse::into_response(axum::Json(json!({
        "reject": false,
        "unchange": true
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

fn plugin_cfg(port: u16, ops: Vec<&str>, enable_control: bool) -> HttpPluginConfig {
    HttpPluginConfig {
        name: format!("mock-{port}"),
        addr: format!("http://127.0.0.1:{port}"),
        path: "/handler".to_string(),
        ops: ops.into_iter().map(String::from).collect(),
        timeout: 3,
        enable_control,
        tls_verify: true,
    }
}

/// Login goes through the mock plugin with the Go wire shape and succeeds.
#[tokio::test]
async fn test_plugin_login_wire_format_and_success() {
    let state = Arc::new(MockPluginState::default());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (_provider, resp) = login_with_test_token(addr)
        .await
        .expect("login should succeed");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    let captured = state
        .captured
        .lock()
        .unwrap()
        .clone()
        .expect("plugin called");
    let query = captured["query"].as_str().unwrap_or("");
    assert!(
        query.contains("version=0.1.0") && query.contains("op=Login"),
        "query must carry version=0.1.0&op=Login, got: {query}"
    );
    assert!(
        captured["reqid"].as_str().is_some_and(|r| !r.is_empty()),
        "X-Frp-Reqid header must be set"
    );
    assert_eq!(
        captured["body"]["op"], "Login",
        "body op must be Go-style uppercase"
    );
    assert_eq!(captured["body"]["version"], "0.1.0");
}

/// A rejecting plugin fails the login with its rejectReason.
#[tokio::test]
async fn test_plugin_reject_rejects_login() {
    let state = Arc::new(MockPluginState {
        reject: true,
        reject_reason: "denied by policy".into(),
        ..Default::default()
    });
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["login"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (conn, resp) = login_with_test_token(addr)
        .await
        .expect("login returns a response");
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("denied by policy"),
        "login must be rejected with plugin reason, got: {:?}",
        resp.error
    );
    drop(conn);
}

/// An unreachable plugin fails closed: login is rejected.
#[tokio::test]
async fn test_plugin_unreachable_fails_closed() {
    let dead_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(dead_port, vec!["login"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    let (conn, resp) = login_with_test_token(addr)
        .await
        .expect("login returns a response");
    assert!(
        resp.error.as_deref().unwrap_or("").contains("plugin"),
        "unreachable plugin must fail the login, got: {:?}",
        resp.error
    );
    drop(conn);
}

/// A non-200 status from the plugin fails closed.
#[tokio::test]
async fn test_plugin_non_200_fails_closed() {
    let state = Arc::new(MockPluginState {
        status_code: 500,
        ..Default::default()
    });
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["login"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (conn, resp) = login_with_test_token(addr)
        .await
        .expect("login returns a response");
    assert!(
        resp.error.as_deref().unwrap_or("").contains("error code"),
        "non-200 plugin response must fail the login, got: {:?}",
        resp.error
    );
    drop(conn);
}

/// ops filtering: a plugin subscribed to a different op is not called.
#[tokio::test]
async fn test_plugin_ops_filtering() {
    let state = Arc::new(MockPluginState::default());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["NewProxy"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (_provider, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none());
    // Plugin must NOT have been called for login.
    assert!(
        state.captured.lock().unwrap().is_none(),
        "plugin subscribed to NewProxy must not be called for login"
    );
}

/// A malformed (non-JSON) plugin response fails closed — the operation must
/// be rejected, not silently passed through (Go handleMutableContent parity).
#[tokio::test]
async fn test_plugin_invalid_json_fails_closed() {
    let state = Arc::new(MockPluginState {
        bad_json: true,
        ..Default::default()
    });
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["login"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (conn, resp) = login_with_test_token(addr)
        .await
        .expect("login returns a response");
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("invalid response"),
        "non-JSON plugin response must fail the login, got: {:?}",
        resp.error
    );
    drop(conn);
}
