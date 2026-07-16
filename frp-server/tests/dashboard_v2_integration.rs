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

/// GET /api/v2/system/info returns version, config (with bind_port), status.
#[tokio::test]
async fn test_v2_system_info() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/system/info"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("version").is_some(), "missing version");
    let config = json.get("config").expect("missing config");
    assert!(config.get("bindPort").is_some(), "missing config.bindPort");
    let status = json.get("status").expect("missing status");
    assert!(
        status.get("clientCounts").is_some(),
        "missing status.clientCounts"
    );
}

/// GET /api/v2/system/info without auth returns 401.
#[tokio::test]
async fn test_v2_system_info_unauthorized() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/system/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// GET /api/v2/clients returns paginated response with empty items array.
#[tokio::test]
async fn test_v2_clients_empty() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/clients"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("items").is_some(), "missing items");
    assert!(
        json["items"].as_array().unwrap().is_empty(),
        "no clients expected"
    );
}

/// GET /api/v2/proxies returns paginated response with empty items array.
#[tokio::test]
async fn test_v2_proxies_empty() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/proxies"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("items").is_some(), "missing items");
    assert!(
        json["items"].as_array().unwrap().is_empty(),
        "no proxies expected"
    );
}

/// POST /api/v2/system/prune?prune_type=offline_proxies returns 200.
#[tokio::test]
async fn test_v2_system_prune() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let url = frps.dashboard_url("/api/v2/system/prune?type=offline_proxies");
    let resp = client
        .post(&url)
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["type"].as_str().unwrap(), "offline_proxies");
    assert!(json.get("cleared").is_some());
    assert!(json.get("total").is_some());
}

/// POST /api/v2/system/prune without prune_type returns 400.
#[tokio::test]
async fn test_v2_system_prune_bad_request() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .post(frps.dashboard_url("/api/v2/system/prune"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// GET /api/v2/proxies/{name} returns 404 for nonexistent proxy.
#[tokio::test]
async fn test_v2_proxy_detail_not_found() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/proxies/nonexistent"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// GET /api/v2/proxies/{name}/traffic returns 404 for nonexistent proxy.
#[tokio::test]
async fn test_v2_proxy_traffic_not_found() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/proxies/nonexistent/traffic"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// GET /api/v2/users returns paginated response.
#[tokio::test]
async fn test_v2_users() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/users"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("items").is_some(), "missing items");
    assert!(
        json["items"].as_array().is_some(),
        "items should be an array"
    );
}

/// GET /api/v2/clients/{key} returns 404 for nonexistent client.
#[tokio::test]
async fn test_v2_client_detail_not_found() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let client = auth_client();
    let resp = client
        .get(frps.dashboard_url("/api/v2/clients/nonexistent"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
