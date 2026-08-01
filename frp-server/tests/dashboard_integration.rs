#![cfg(feature = "dashboard")]
use common::FrpsHandle;

mod common;

fn base_config(bind_port: u16, dashboard_port: u16) -> String {
    format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {bind_port}

[auth]
method = "token"
token = "test-token"

[transport]
tcp_mux = false

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

/// Go compat: the dashboard root (`/`) requires auth.
#[tokio::test]
async fn test_dashboard_root_requires_auth() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    // No credentials → 401.
    let resp = reqwest::get(frps.dashboard_url("/")).await.unwrap();
    assert_eq!(resp.status(), 401, "dashboard root must require auth");

    // With credentials → 200 HTML.
    let resp = auth_client()
        .get(frps.dashboard_url("/"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("<!DOCTYPE html>"));
}

/// Go compat: /debug/pprof is outside auth (placeholder in frp-rs).
#[tokio::test]
async fn test_dashboard_pprof_outside_auth() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let resp = reqwest::get(frps.dashboard_url("/debug/pprof")).await.unwrap();
    assert_eq!(resp.status(), 200, "pprof index is outside auth");
}

/// Offline clients stay listed in /api/clients after disconnect (clients with
/// an explicit clientID are retained).
#[tokio::test]
async fn test_dashboard_offline_clients_listed() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    // Login with an explicit clientID so the registry retains the offline
    // record (raw_login sends client_id: None, which is pruned on disconnect).
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token("test-token", ts);
    let mut io = frp_core::transport::IoStream::Tcp(tokio::net::TcpStream::connect(addr).await.unwrap());
    let login = frp_core::msg::FrpMessage::Login(Box::new(frp_core::msg::Login {
        version: Some("0.69.1".into()),
        hostname: Some("offline-test".into()),
        os: None,
        arch: None,
        user: None,
        run_id: Some("offline-run-1".into()),
        client_id: Some("offline-client-1".into()),
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    frp_core::protocol::write_msg_v1(&mut io, &login).await.unwrap();
    match frp_core::protocol::read_msg_v1(&mut io).await {
        Ok(frp_core::msg::FrpMessage::LoginResp(r)) => {
            assert!(r.error.is_none(), "login rejected: {:?}", r.error);
        }
        Ok(other) => panic!("expected LoginResp, got {:?}", other.v1_type_byte()),
        Err(e) => panic!("login read failed: {e}"),
    }
    // Server wraps in CipherStream after LoginResp; drop the stream to
    // disconnect. (A bare `let _encrypted` binding would live until the end
    // of the test — drop explicitly.)
    let enc_key = frp_core::encryption::derive_key("test-token");
    drop(io.into_encrypted(enc_key));

    // Wait for the server to notice the disconnect (control cleanup).
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let resp = auth_client()
        .get(frps.dashboard_url("/api/clients"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let arr = json.as_array().expect("clients array");
    assert!(
        arr.iter().any(|c| c["clientID"] == "offline-client-1" && c["online"] == false),
        "offline client must remain listed with online=false, got: {json}"
    );
}
