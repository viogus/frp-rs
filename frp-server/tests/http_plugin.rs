//! HTTP server plugin protocol tests (Go frp v0.70.1 compat):
//! - POST {url}?version=0.1.0&op=Login with X-Frp-Reqid header
//! - HTTP 200 required; transport/status errors fail closed (login rejected)
//! - reject:true rejects with rejectReason

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use serde_json::json;

use common::{
    allocate_port, login_with_identity, login_with_test_token, raw_login_full, start_test_server,
    test_auth_cfg, TEST_TOKEN,
};
use frp_core::config::{HttpPluginConfig, ServerConfig};
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

/// Mock plugin state: captures the request shape and decides the response.
#[derive(Default)]
struct MockPluginState {
    captured: std::sync::Mutex<Option<serde_json::Value>>,
    /// Every request in arrival order: (op, content). The Login and
    /// NewProxy hooks can both fire in one test.
    requests: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    reject: bool,
    reject_reason: String,
    status_code: u16,
    /// When true, respond with a non-JSON body (fail-closed check).
    bad_json: bool,
    /// When Some, respond with `unchange:false` + this content (mutation).
    mutate_response: Option<serde_json::Value>,
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
    if let (Some(op), Some(content)) = (
        body["op"].as_str().map(String::from),
        body.get("content").cloned(),
    ) {
        state.requests.lock().unwrap().push((op, content));
    }
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
    if let Some(mutation) = state.mutate_response.clone() {
        // Real Go plugins echo the received content with their changes:
        // the server decodes the response `content` into a FRESH struct
        // (http.go:78), so fields the plugin omits are zeroed. Echo the
        // request content with the mutation's keys applied on top.
        let mut content = body
            .get("content")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if let (Some(c), Some(m)) = (content.as_object_mut(), mutation.as_object()) {
            for (k, v) in m {
                c.insert(k.clone(), v.clone());
            }
        }
        // unchange:false + content → the server must apply the mutation.
        return axum::response::IntoResponse::into_response(axum::Json(json!({
            "reject": false,
            "unchange": false,
            "content": content,
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

    // Content must carry the full flat Go Login (Go service.go LoginContent
    // = msg.Login + client_address). `user`/`metas` are absent here because
    // raw_login sends None (serde skips, Go omitempty parity).
    let content = &captured["body"]["content"];
    assert_eq!(content["version"], frp_core::VERSION);
    assert_eq!(content["hostname"], "test-host");
    assert!(
        content["os"].as_str().is_some(),
        "os must be present (Go Login always sets it)"
    );
    assert!(
        content["arch"].as_str().is_some(),
        "arch must be present (Go Login always sets it)"
    );
    assert_eq!(content["pool_count"], 1);
    assert!(
        content["timestamp"].as_i64().is_some(),
        "timestamp must be present"
    );
    assert!(
        content["privilege_key"]
            .as_str()
            .is_some_and(|k| !k.is_empty()),
        "privilege_key must be present"
    );
    assert!(
        content["run_id"].as_str().is_some_and(|r| !r.is_empty()),
        "run_id must be present (server assigns it pre-hook)"
    );
    assert!(
        content["client_spec"].is_object(),
        "client_spec must be serialized (Go always emits it, even empty)"
    );
    let client_address = content["client_address"]
        .as_str()
        .expect("client_address must be present");
    assert!(
        client_address.starts_with("127.0.0.1:"),
        "client_address must be the peer address, got: {client_address}"
    );
    assert_eq!(
        content["remote_addr"], content["client_address"],
        "frp-rs keeps remote_addr additive (Go parity: same value)"
    );
    assert!(
        content.get("user").is_none(),
        "Login content has no user object (Go LoginContent is flat)"
    );
    assert!(
        content.get("metas").is_none(),
        "metas omitted when None (Go omitempty parity)"
    );
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

/// ops filtering: a config op Go would never match (unknown name) must
/// silently never fire — the notify filter exact-compares against the
/// fixed Go op set after load-time normalization.
#[tokio::test]
async fn test_plugin_unknown_op_never_fires() {
    let state = Arc::new(MockPluginState::default());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["bogus"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (provider, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);
    drop(provider);
    assert!(
        state.captured.lock().unwrap().is_none(),
        "plugin with an unknown op must never be called"
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

/// Build a NewProxy carrying every field Go frp sends (types.go
/// NewProxyContent = msg.NewProxy + UserInfo). `subdomain` stays None: the
/// test server has no sub_domain_host, and Go rejects a subdomain then too.
fn full_new_proxy(name: &str, remote_port: i32) -> NewProxy {
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Custom".to_string(), "h1".to_string());
    let mut response_headers = std::collections::HashMap::new();
    response_headers.insert("X-Resp".to_string(), "r1".to_string());
    let mut annotations = std::collections::HashMap::new();
    annotations.insert("note".to_string(), "n1".to_string());
    let mut np_metas = std::collections::HashMap::new();
    np_metas.insert("proxy-meta".to_string(), "m1".to_string());
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "tcp".into(),
        use_encryption: Some(true),
        use_compression: Some(true),
        group: Some("g1".into()),
        group_key: Some("gk".into()),
        local_str: Some("127.0.0.1:8080".into()),
        remote_port: Some(remote_port),
        sk: Some("skey".into()),
        custom_domains: Some(vec!["t.example.com".into()]),
        subdomain: None,
        locations: Some(vec!["/".into()]),
        http_user: Some("hu".into()),
        http_pwd: Some("hp".into()),
        host_header_rewrite: Some("rewrite.example.com".into()),
        headers: Some(headers),
        response_headers: Some(response_headers),
        route_by_http_user: Some("rbu".into()),
        allow_users: Some(vec!["bob".into()]),
        bandwidth_limit: Some("1MB".into()),
        bandwidth_limit_mode: Some("client".into()),
        annotations: Some(annotations),
        metas: Some(np_metas),
        multiplexer: Some("yamux".into()),
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }
}

/// Send a NewProxy on an established control and return the NewProxyResp.
async fn send_new_proxy(
    provider: &mut frp_core::transport::IoStream,
    np: NewProxy,
) -> msg::NewProxyResp {
    write_msg_v1(provider, &FrpMessage::NewProxy(Box::new(np)))
        .await
        .expect("send NewProxy");
    match read_msg_v1(provider).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(r) => r,
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }
}

/// The NewProxy hook payload carries the Go `user` object (login identity)
/// plus every flat msg.NewProxy field Go sends (P2 audit fix).
#[tokio::test]
async fn test_plugin_new_proxy_content_user_object_and_fields() {
    let state = Arc::new(MockPluginState::default());
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login", "NewProxy"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    let mut metas = std::collections::HashMap::new();
    metas.insert("env".to_string(), "test".to_string());
    let (mut provider, resp) = login_with_identity(addr, "alice", metas)
        .await
        .expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    let remote_port = allocate_port();
    let resp = send_new_proxy(
        &mut provider,
        full_new_proxy("tcp-test", remote_port as i32),
    )
    .await;
    assert!(resp.error.is_none(), "NewProxy rejected: {:?}", resp.error);
    drop(provider);

    let requests = state.requests.lock().unwrap();
    let (_, content) = requests
        .iter()
        .find(|(op, _)| op == "NewProxy")
        .unwrap_or_else(|| panic!("NewProxy hook must fire; got requests: {requests:?}"));
    // Go UserInfo object: {user, metas, run_id} from the login.
    assert_eq!(content["user"]["user"], "alice");
    assert_eq!(content["user"]["metas"]["env"], "test");
    assert!(
        content["user"]["run_id"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "user.run_id must be present"
    );
    assert_eq!(
        content["user"]["run_id"], content["run_id"],
        "user.run_id must equal the top-level run_id"
    );
    // Every flat msg.NewProxy field Go sends (missing-field audit fix).
    assert_eq!(content["proxy_name"], "tcp-test");
    assert_eq!(content["proxy_type"], "tcp");
    assert_eq!(content["use_encryption"], true);
    assert_eq!(content["use_compression"], true);
    assert_eq!(content["group"], "g1");
    assert_eq!(content["group_key"], "gk");
    assert_eq!(content["local_str"], "127.0.0.1:8080");
    assert_eq!(content["remote_port"], remote_port);
    assert_eq!(content["sk"], "skey");
    assert_eq!(content["custom_domains"][0], "t.example.com");
    assert_eq!(content["locations"][0], "/");
    assert_eq!(content["http_user"], "hu", "Go wire name http_user");
    assert_eq!(content["http_pwd"], "hp", "Go wire name http_pwd");
    assert_eq!(content["host_header_rewrite"], "rewrite.example.com");
    assert_eq!(content["headers"]["X-Custom"], "h1");
    assert_eq!(content["response_headers"]["X-Resp"], "r1");
    assert_eq!(content["route_by_http_user"], "rbu");
    assert_eq!(content["allow_users"][0], "bob");
    assert_eq!(content["bandwidth_limit"], "1MB");
    assert_eq!(content["bandwidth_limit_mode"], "client");
    assert_eq!(content["annotations"]["note"], "n1");
    assert_eq!(content["metas"]["proxy-meta"], "m1");
    assert_eq!(content["multiplexer"], "yamux");
    // Login content stays flat (no user object) — Go LoginContent parity.
    let (_, login_content) = requests
        .iter()
        .find(|(op, _)| op == "Login")
        .expect("Login hook must fire");
    assert!(
        login_content.get("user").is_none_or(|u| u.is_string()),
        "Login content carries the flat user string, never the user object (Go LoginContent parity)"
    );
    assert_eq!(
        login_content["user"], "alice",
        "flat user field must round-trip"
    );
}

/// A plugin returning unchange:false + mutated Login content has its
/// mutation applied BEFORE the server continues (Go service.go ordering):
/// pool_count drives the ReqWorkConn batch, and the mutated metas land in
/// the recorded user object seen by the NewProxy hook.
#[tokio::test]
async fn test_plugin_login_mutation_applied() {
    // Plugin A mutates the Login; plugin B (NewProxy-only) observes the
    // recorded identity after mutation.
    let mutator = Arc::new(MockPluginState {
        mutate_response: Some(json!({
            "pool_count": 3,
            "metas": { "env": "mutated" },
        })),
        ..Default::default()
    });
    let observer = Arc::new(MockPluginState::default());
    let mutator_port = start_mock_plugin(mutator.clone()).await;
    let observer_port = start_mock_plugin(observer.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![
            plugin_cfg(mutator_port, vec!["Login"], true),
            plugin_cfg(observer_port, vec!["NewProxy"], true),
        ],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    let mut metas = std::collections::HashMap::new();
    metas.insert("orig".to_string(), "1".to_string());
    let (mut provider, resp) = login_with_identity(addr, "alice", metas)
        .await
        .expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    // Sent pool_count was 1 (drained by raw_login_full); the mutated
    // pool_count 3 must trigger 2 more ReqWorkConn right after login.
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(3), read_msg_v1(&mut provider)).await {
            Ok(Ok(FrpMessage::ReqWorkConn(_))) => {}
            Ok(Ok(other)) => panic!("expected ReqWorkConn, got {:?}", other.v1_type_byte()),
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => panic!("pool_count mutation not applied: no extra ReqWorkConn arrived"),
        }
    }

    // The NewProxy hook's user object must carry the MUTATED metas.
    let remote_port = allocate_port();
    let resp = send_new_proxy(&mut provider, full_new_proxy("tcp-mut", remote_port as i32)).await;
    assert!(resp.error.is_none(), "NewProxy rejected: {:?}", resp.error);
    drop(provider);

    let requests = observer.requests.lock().unwrap();
    let (_, content) = requests
        .iter()
        .find(|(op, _)| op == "NewProxy")
        .expect("NewProxy hook must fire");
    assert_eq!(
        content["user"]["metas"]["env"], "mutated",
        "user.metas must reflect the plugin-mutated login"
    );
    assert_eq!(content["user"]["user"], "alice");
    assert!(
        content["user"]["metas"].get("orig").is_none(),
        "the original metas key must be replaced by the mutation"
    );
}

/// A plugin returning unchange:false + mutated NewProxy content has its
/// mutation applied BEFORE port allocation/registration (Go control.go
/// ordering): the response names the mutated proxy.
#[tokio::test]
async fn test_plugin_new_proxy_mutation_applied() {
    let state = Arc::new(MockPluginState {
        mutate_response: Some(json!({ "proxy_name": "renamed-tcp" })),
        ..Default::default()
    });
    let port = start_mock_plugin(state.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![plugin_cfg(port, vec!["Login", "NewProxy"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    let (mut provider, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);

    let remote_port = allocate_port();
    let resp = send_new_proxy(
        &mut provider,
        full_new_proxy("orig-tcp", remote_port as i32),
    )
    .await;
    assert_eq!(
        resp.proxy_name, "renamed-tcp",
        "NewProxyResp must carry the plugin-mutated proxy_name"
    );
    assert!(resp.error.is_none(), "NewProxy rejected: {:?}", resp.error);
    drop(provider);
}

/// Mutating plugins chain (Go handleMutableContent, manager.go:79-83):
/// plugin N receives plugin N-1's output, not the original content.
#[tokio::test]
async fn test_plugin_mutations_chain() {
    let first = Arc::new(MockPluginState {
        mutate_response: Some(json!({ "chain_stage": 1 })),
        ..Default::default()
    });
    let second = Arc::new(MockPluginState {
        mutate_response: Some(json!({ "chain_stage": 2 })),
        ..Default::default()
    });
    let first_port = start_mock_plugin(first.clone()).await;
    let second_port = start_mock_plugin(second.clone()).await;

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: allocate_port(),
        auth: test_auth_cfg(),
        http_plugins: vec![
            plugin_cfg(first_port, vec!["Login"], true),
            plugin_cfg(second_port, vec!["Login"], true),
        ],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (provider, resp) = login_with_test_token(addr).await.expect("login succeeds");
    assert!(resp.error.is_none(), "login rejected: {:?}", resp.error);
    drop(provider);

    // The second plugin must have received the FIRST plugin's output
    // (chain_stage:1) — not the original login content.
    let requests = second.requests.lock().unwrap();
    let (_, content) = requests
        .iter()
        .find(|(op, _)| op == "Login")
        .expect("second plugin's Login hook must fire");
    assert_eq!(
        content["chain_stage"], 1,
        "plugin 2 must see plugin 1's mutated content (chaining)"
    );
}

/// Go parity (server/service.go handleConnection): the plugin hook runs
/// BEFORE VerifyLogin (inside RegisterControl) — a failed-auth (bad token)
/// login STILL reaches the plugin. Monitoring/security plugins depend on
/// seeing every login attempt. The plugin's rejection reason surfaces in
/// the LoginResp error, not the token-auth error.
#[tokio::test]
async fn test_plugin_reached_before_auth_on_bad_token() {
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
        http_plugins: vec![plugin_cfg(port, vec!["Login"], true)],
        ..Default::default()
    };
    let bind_port = cfg.bind_port;
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (conn, resp) = raw_login_full(
        addr,
        Some("wrong-privilege-key".into()),
        Some(ts),
        TEST_TOKEN,
        None,
        None,
        Some(1),
    )
    .await
    .expect("login returns a response");
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("denied by policy"),
        "the plugin (not auth) must reject a bad-token login, got: {:?}",
        resp.error
    );
    assert!(
        state.captured.lock().unwrap().is_some(),
        "the Login hook must fire before auth — a failed-auth login still reaches the plugin"
    );
    drop(conn);
}

/// Go parity: VerifyLogin verifies the MUTATED login (`m = &retContent.Login`,
/// service.go:467-473) — a plugin that repairs the privilege_key (and
/// timestamp) turns a bad-token login into a successful one.
#[tokio::test]
async fn test_plugin_mutation_repairs_bad_token() {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let good_key = frp_core::auth::generate_token(TEST_TOKEN, ts);
    let mutator = Arc::new(MockPluginState {
        mutate_response: Some(json!({
            "privilege_key": good_key,
            "timestamp": ts,
        })),
        ..Default::default()
    });
    let port = start_mock_plugin(mutator.clone()).await;

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

    let (conn, resp) = raw_login_full(
        addr,
        Some("wrong-privilege-key".into()),
        Some(ts),
        TEST_TOKEN,
        None,
        None,
        Some(1),
    )
    .await
    .expect("login returns a response");
    assert!(
        resp.error.is_none(),
        "auth must verify the MUTATED login (plugin repaired the token), got: {:?}",
        resp.error
    );
    drop(conn);
}

/// Go parity: the negative pool_count rejection runs in NewControl AFTER
/// VerifyLogin (server/control.go:437), so it sees the MUTATED login — a
/// plugin that repairs pool_count (-1 → 1) lets the login proceed instead
/// of the rejection firing on the pre-mutation value.
#[tokio::test]
async fn test_plugin_mutation_repairs_negative_pool_count() {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token(TEST_TOKEN, ts);
    let mutator = Arc::new(MockPluginState {
        mutate_response: Some(json!({ "pool_count": 1 })),
        ..Default::default()
    });
    let port = start_mock_plugin(mutator.clone()).await;

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

    let (conn, resp) = raw_login_full(addr, Some(key), Some(ts), TEST_TOKEN, None, None, Some(-1))
        .await
        .expect("login returns a response");
    assert!(
        resp.error.is_none(),
        "pool_count must be validated on the MUTATED login (plugin repaired -1), got: {:?}",
        resp.error
    );
    drop(conn);
}
