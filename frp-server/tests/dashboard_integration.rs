use common::FrpsHandle;

mod common;

fn base_config(bind_port: u16, dashboard_port: u16) -> String {
    format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {bind_port}

[auth]
method = "token"
token = "test-token"

[web_server]
addr = "127.0.0.1"
port = {dashboard_port}
user = "admin"
password = "admin"
"#,
        bind_port = bind_port,
        dashboard_port = dashboard_port,
    )
}

fn auth_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

/// GET /healthz returns "ok" without auth
#[tokio::test]
async fn test_dashboard_healthz() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let resp = reqwest::get(&frps.dashboard_url("/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "");
}

/// GET /healthz?probe=readiness returns 200 "ok" on a fresh (non-draining) server.
#[tokio::test]
async fn test_dashboard_healthz_readiness() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let resp = reqwest::get(&frps.dashboard_url("/healthz?probe=readiness"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

/// GET /api/status returns version, uptime, client_count, proxy_count
#[tokio::test]
async fn test_dashboard_status() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/status"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("version").is_some());
    assert!(json.get("uptime_secs").is_some());
    assert_eq!(json["client_count"].as_u64().unwrap(), 0);
    assert_eq!(json["proxy_count"].as_u64().unwrap(), 0);
}

/// GET /api/serverinfo is Go frp compat alias for /api/status
#[tokio::test]
async fn test_dashboard_serverinfo() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/serverinfo"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("version").is_some());
}

/// GET /api/proxies lists proxies (empty on fresh start)
#[tokio::test]
async fn test_dashboard_proxies_list() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/proxies"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let proxies: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(proxies.is_empty()); // No clients connected yet
}

/// GET /api/proxy/{name} returns 404 for unknown proxy
#[tokio::test]
async fn test_dashboard_proxy_detail_not_found() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/proxy/nonexistent"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// GET /api/clients lists connected clients (empty on fresh start)
#[tokio::test]
async fn test_dashboard_clients() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/clients"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let clients: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(clients.is_empty()); // No clients connected yet
}
