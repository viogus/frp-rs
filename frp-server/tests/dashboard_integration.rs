#![cfg(feature = "dashboard")]
use common::FrpsHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// GET /api/serverinfo serves the Go `model.ServerInfoResp` shape
/// (frp v0.71.0 server/http/model/types.go:21-40): camelCase keys, all
/// non-omitempty keys always present with zero values included, and
/// `allowPortsStr`/`tlsForce` omitted per Go's omitempty tags. The
/// Rust-native payload lives on /api/status (test_dashboard_status).
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
    // Full Go key set, correct camelCase names.
    for key in [
        "version",
        "bindPort",
        "vhostHTTPPort",
        "vhostHTTPSPort",
        "tcpmuxHTTPConnectPort",
        "kcpBindPort",
        "quicBindPort",
        "subdomainHost",
        "maxPoolCount",
        "maxPortsPerClient",
        "heartbeatTimeout",
        "totalTrafficIn",
        "totalTrafficOut",
        "curConns",
        "clientCounts",
        "proxyTypeCount",
    ] {
        assert!(json.get(key).is_some(), "missing Go key {key}");
    }
    // No Rust-native /api/status keys may leak into the Go-shaped payload.
    for key in ["uptime_secs", "client_count", "proxy_count", "pool_hits"] {
        assert!(json.get(key).is_none(), "Rust-native key {key} leaked");
    }
    // Go omitempty on a default server: allowPortsStr empty, tlsForce false.
    assert!(
        json.get("allowPortsStr").is_none(),
        "empty allowPortsStr must be omitted"
    );
    assert!(
        json.get("tlsForce").is_none(),
        "false tlsForce must be omitted"
    );

    // base_config leaves every listener off except bind_port.
    assert_eq!(json["version"].as_str().unwrap(), frp_core::VERSION);
    assert_eq!(json["bindPort"].as_u64().unwrap(), u64::from(bind_port));
    assert_eq!(json["vhostHTTPPort"].as_u64().unwrap(), 0);
    assert_eq!(json["vhostHTTPSPort"].as_u64().unwrap(), 0);
    assert_eq!(json["tcpmuxHTTPConnectPort"].as_u64().unwrap(), 0);
    assert_eq!(json["subdomainHost"].as_str().unwrap(), "");
    // Live state on a fresh server: no clients, no proxies, no traffic.
    assert_eq!(json["clientCounts"].as_u64().unwrap(), 0);
    assert_eq!(json["totalTrafficIn"].as_u64().unwrap(), 0);
    assert_eq!(json["totalTrafficOut"].as_u64().unwrap(), 0);
    assert_eq!(json["curConns"].as_u64().unwrap(), 0);
    assert_eq!(
        json["proxyTypeCount"].as_object().unwrap().len(),
        0,
        "no proxies registered"
    );
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

/// Go compat (`assetsDir`): when `assets_dir` points at a directory with an
/// `index.html`, the dashboard root serves that custom page instead of the
/// built-in one.
#[tokio::test]
async fn test_dashboard_serves_custom_assets_dir() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let dir = tempfile::tempdir().unwrap();
    let custom = "<!DOCTYPE html><html><body>custom-dashboard</body></html>";
    std::fs::write(dir.path().join("index.html"), custom).unwrap();

    let cfg = format!(
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
assetsDir = "{}"
"#,
        dir.path().display()
    );
    let frps = FrpsHandle::start(&cfg).await;

    let resp = auth_client()
        .get(frps.dashboard_url("/"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("custom-dashboard"),
        "expected custom assets_dir page, got: {}",
        &body[..body.len().min(120)]
    );
}

/// Go compat: /debug/pprof is outside auth (placeholder in frp-rs).
#[tokio::test]
async fn test_dashboard_pprof_outside_auth() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;

    let resp = reqwest::get(frps.dashboard_url("/debug/pprof"))
        .await
        .unwrap();
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
    let mut io =
        frp_core::transport::IoStream::Tcp(tokio::net::TcpStream::connect(addr).await.unwrap());
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
    frp_core::protocol::write_msg_v1(&mut io, &login)
        .await
        .unwrap();
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
    drop(
        io.into_encrypted(enc_key)
            .expect("plain test stream is encryptable"),
    );

    // Wait for the server to notice the disconnect (control cleanup).
    // Poll the clients API instead of a fixed sleep: on slow CI the old
    // 1.5s sleep was not always enough.
    let client = auth_client();
    let mut offline_seen = false;
    for _ in 0..50 {
        let resp = client
            .get(frps.dashboard_url("/api/clients"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        let arr = json.as_array().expect("clients array");
        if arr
            .iter()
            .any(|c| c["clientID"] == "offline-client-1" && c["online"] == false)
        {
            offline_seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        offline_seen,
        "offline client never appeared in /api/clients"
    );
}

/// Dashboard proxy-delete paths must honor http-group route ownership (same
/// lifecycle as handle_close_proxy):
/// - deleting the route OWNER while other members remain keeps the shared
///   route alive (remaining members keep serving);
/// - deleting the last member removes the shared route (requests 404).
///
/// Regression for the review finding: the dashboard's single/bulk delete
/// handlers used to unregister the route with the DELETED member's name,
/// which leaked the route (keyed on the owner) or dropped it early (owner
/// deleted first).
#[tokio::test]
async fn test_dashboard_delete_http_group_route_owner_semantics() {
    use frp_core::msg::{self, FrpMessage, NewProxy};
    use frp_core::protocol::{read_msg_v1, write_msg_v1};

    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let vhost_port = common::allocate_port();
    let cfg = format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {bind_port}
vhost_http_port = {vhost_port}

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
        vhost_port = vhost_port,
    );
    let frps = FrpsHandle::start(&cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let vhost: std::net::SocketAddr = format!("127.0.0.1:{vhost_port}").parse().unwrap();
    let client = auth_client();

    fn grp_proxy(name: &str) -> NewProxy {
        NewProxy {
            proxy_name: name.into(),
            proxy_type: "http".into(),
            sk: None,
            use_encryption: None,
            use_compression: None,
            group: Some("webgrp".into()),
            group_key: Some("secret-key".into()),
            local_str: Some("127.0.0.1:8080".into()),
            remote_port: Some(0),
            custom_domains: Some(vec!["app.example.com".into()]),
            subdomain: None,
            locations: None,
            http_user: None,
            http_pwd: None,
            host_header_rewrite: None,
            headers: None,
            response_headers: None,
            route_by_http_user: None,
            allow_users: None,
            bandwidth_limit: None,
            bandwidth_limit_mode: None,
            annotations: None,
            metas: None,
            multiplexer: None,
            virtual_net: None,
            proxy_protocol_version: None,
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        }
    }

    // Register two members: grp-a is the route owner (first).
    let (mut ctl_a, _resp_a) = common::login_with_test_token(addr).await.expect("login A");
    {
        write_msg_v1(
            &mut ctl_a,
            &FrpMessage::NewProxy(Box::new(grp_proxy("grp-a"))),
        )
        .await
        .expect("send NewProxy A");
        match read_msg_v1(&mut ctl_a).await.expect("NewProxyResp A") {
            FrpMessage::NewProxyResp(ref r) => assert!(r.error.is_none(), "{:?}", r.error),
            other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
        }
    }
    let (mut ctl_b, resp_b) = common::login_with_test_token(addr).await.expect("login B");
    let run_id_b_holder = resp_b.run_id.expect("run_id B");
    {
        write_msg_v1(
            &mut ctl_b,
            &FrpMessage::NewProxy(Box::new(grp_proxy("grp-b"))),
        )
        .await
        .expect("send NewProxy B");
        match read_msg_v1(&mut ctl_b).await.expect("NewProxyResp B") {
            FrpMessage::NewProxyResp(ref r) => assert!(r.error.is_none(), "{:?}", r.error),
            other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
        }
    }
    // Dashboard deletes the route OWNER (grp-a) while grp-b remains.
    let resp = client
        .delete(frps.dashboard_url(&format!("/api/store/proxy/{}", "grp-a")))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "owner delete should succeed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // grp-b still serves: pool a work conn and request the vhost domain.
    let mut work = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn");
    write_msg_v1(
        &mut work,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id_b_holder.clone()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    let req = tokio::spawn(async move {
        let mut c = tokio::net::TcpStream::connect(vhost)
            .await
            .expect("vhost connect");
        c.write_all(b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
            .await
            .expect("send");
        let mut buf = Vec::new();
        use tokio::io::AsyncReadExt;
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(3), c.read_to_end(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    });
    // grp-b's work conn receives StartWorkConn + the request head.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while head.len() < 4096 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        if tokio::time::timeout(remaining, work.read_exact(&mut byte))
            .await
            .is_err()
        {
            break;
        }
        head.push(byte[0]);
    }
    assert!(
        !head.is_empty() && head.windows(4).any(|w| w == b"\r\n\r\n"),
        "grp-b should still receive requests after owner deleted, head len={}",
        head.len()
    );
    let body = "member-B";
    work.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len()
        )
        .as_bytes(),
    )
    .await
    .expect("serve");
    let resp_body = req.await.expect("request task");
    assert!(
        resp_body.contains("member-B"),
        "remaining member should serve after owner delete: {resp_body:?}"
    );

    // Bulk-delete the last member (grp-b) -> shared route must be dropped.
    let resp = client
        .delete(frps.dashboard_url("/api/proxies"))
        .basic_auth("admin", Some("admin"))
        .json(&serde_json::json!({ "proxies": ["grp-b"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "bulk delete should succeed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let resp_body = http_get_vhost(vhost, "app.example.com").await;
    assert!(
        resp_body.contains("404"),
        "route should be removed after last member deleted: {resp_body:?}"
    );
}

/// Minimal HTTP GET to the vhost port; returns the raw response text.
async fn http_get_vhost(vhost: std::net::SocketAddr, host: &str) -> String {
    use tokio::io::AsyncReadExt;
    let mut c = tokio::net::TcpStream::connect(vhost)
        .await
        .expect("vhost connect");
    c.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .expect("send");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), c.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}
