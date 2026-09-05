#![cfg(feature = "dashboard")]
use common::FrpsHandle;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
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

    // Poll (R12): the delete handler has responded, but the member removal
    // lands asynchronously across the control path — wait for the proxy to
    // be GONE from the API instead of a fixed sleep (slow CI used to miss
    // the window and round-robin the request into the deleted owner).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        let resp = client
            .get(frps.dashboard_url("/api/proxies/grp-a"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        if resp.status() == 404 {
            break;
        }
        assert_eq!(
            resp.status(),
            200,
            "unexpected status while polling grp-a deletion"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "grp-a never disappeared from /api/proxies"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

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

    // Poll (R12): wait for grp-b to be gone from the API, then assert the
    // route is dead with one request — polling the API first keeps the
    // route check a single deterministic assertion instead of retrying
    // requests into a live-but-draining dispatch.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        let resp = client
            .get(frps.dashboard_url("/api/proxies/grp-b"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        if resp.status() == 404 {
            break;
        }
        assert_eq!(
            resp.status(),
            200,
            "unexpected status while polling grp-b deletion"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "grp-b never disappeared from /api/proxies"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let resp_body = http_get_vhost(vhost, "app.example.com").await;
    assert!(
        resp_body.contains("404"),
        "route should be removed after last member deleted: {resp_body:?}"
    );
}

/// R2: the dashboard proxy-delete paths must honor TCPMUX group route
/// ownership exactly like the http-group sibling above:
/// - deleting the route OWNER while other members remain keeps the shared
///   tcpmux route alive (the remaining member keeps serving CONNECTs);
/// - deleting the last member drops the shared route (CONNECTs get 404).
///
/// This is the dashboard entry point; the in-process CloseProxy e2e in
/// tests/tcpmux_httpconnect.rs pins the same arms through the control
/// path (handle_close_proxy shares the lifecycle code).
#[tokio::test]
async fn test_dashboard_delete_tcpmux_group_route_owner_semantics() {
    use frp_core::msg::{FrpMessage, NewProxy};
    use frp_core::protocol::{read_msg_v1, write_msg_v1};
    use tokio::io::AsyncWriteExt;

    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let tcpmux_port = common::allocate_port();
    let cfg = format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {bind_port}
tcpmux_httpconnect_port = {tcpmux_port}

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
        tcpmux_port = tcpmux_port,
    );
    let frps = FrpsHandle::start(&cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let tcpmux: std::net::SocketAddr = format!("127.0.0.1:{tcpmux_port}").parse().unwrap();
    let client = auth_client();

    fn tgrp_proxy(name: &str) -> NewProxy {
        NewProxy {
            proxy_name: name.into(),
            proxy_type: "tcpmux".into(),
            sk: None,
            use_encryption: None,
            use_compression: None,
            group: Some("tgrp".into()),
            group_key: Some("secret-key".into()),
            local_str: Some("127.0.0.1:8080".into()),
            remote_port: Some(0),
            custom_domains: Some(vec!["tfan.example.com".into()]),
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
            multiplexer: Some("httpconnect".into()),
            virtual_net: None,
            proxy_protocol_version: None,
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        }
    }

    // Register two members: grp-t-a is the route owner (first).
    let (mut ctl_a, resp_a) = common::login_with_test_token(addr).await.expect("login A");
    let run_id_a_holder = resp_a.run_id.expect("run_id A");
    {
        write_msg_v1(
            &mut ctl_a,
            &FrpMessage::NewProxy(Box::new(tgrp_proxy("grp-t-a"))),
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
            &FrpMessage::NewProxy(Box::new(tgrp_proxy("grp-t-b"))),
        )
        .await
        .expect("send NewProxy B");
        match read_msg_v1(&mut ctl_b).await.expect("NewProxyResp B") {
            FrpMessage::NewProxyResp(ref r) => assert!(r.error.is_none(), "{:?}", r.error),
            other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
        }
    }

    let connect_req = b"CONNECT tfan.example.com:22 HTTP/1.1\r\nHost: tfan.example.com:22\r\n\r\n";

    /// CONNECT to the tcpmux port; returns (status_text, stream).
    async fn do_connect(
        tcpmux: std::net::SocketAddr,
        req: &[u8],
    ) -> (String, tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt;
        let mut c = tokio::net::TcpStream::connect(tcpmux)
            .await
            .expect("connect to tcpmux port");
        c.write_all(req).await.expect("send CONNECT");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 128];
        // Stop at the head terminator wherever it appears: rejections now
        // carry Go's NotFoundResponse body (Content-Length + 489-byte HTML
        // page) after the head, so the head does not end the buffer.
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), c.read(&mut chunk))
                .await
                .expect("timeout reading the CONNECT response")
                .expect("read CONNECT response");
            assert!(n > 0, "EOF before the full CONNECT response: {buf:?}");
            buf.extend_from_slice(&chunk[..n]);
        }
        (String::from_utf8_lossy(&buf).into_owned(), c)
    }

    /// Pool a work conn for a run_id and read the StartWorkConn proxy name.
    async fn connect_and_read_member(
        addr: std::net::SocketAddr,
        tcpmux: std::net::SocketAddr,
        run_id: &str,
        req: &[u8],
    ) -> String {
        use frp_core::msg;
        use frp_core::protocol::write_msg_v1;
        let mut work = tokio::net::TcpStream::connect(addr)
            .await
            .expect("work conn");
        write_msg_v1(
            &mut work,
            &FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: Some(run_id.to_string()),
                timestamp: None,
                privilege_key: None,
            }),
        )
        .await
        .expect("send NewWorkConn");
        let (status, client) = do_connect(tcpmux, req).await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "expected 200, got: {status:?}"
        );
        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), read_msg_v1(&mut work))
            .await
            .expect("timeout waiting for StartWorkConn")
            .expect("read StartWorkConn");
        drop(client);
        match msg {
            FrpMessage::StartWorkConn(swc) => {
                assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
                swc.proxy_name
            }
            other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
        }
    }

    // Sanity: both members are live before the delete — round-robin index
    // starts at 0, so the first CONNECT lands on the owner grp-t-a. The work
    // conn must be pooled under the DISPATCHED member's own control (the
    // server pops the pooled conn of the chosen member's run_id), so pool it
    // under run_id A for this round.
    assert_eq!(
        connect_and_read_member(addr, tcpmux, &run_id_a_holder, connect_req).await,
        "grp-t-a",
        "first CONNECT should be served by the route owner"
    );

    // Dashboard deletes the route OWNER (grp-t-a) while grp-t-b remains.
    let resp = client
        .delete(frps.dashboard_url("/api/store/proxy/grp-t-a"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "owner delete should succeed");

    // Poll (R12): wait until the owner is gone from the API.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        let resp = client
            .get(frps.dashboard_url("/api/proxies/grp-t-a"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        if resp.status() == 404 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "grp-t-a never disappeared from /api/proxies"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // grp-t-b still serves CONNECTs on the shared route.
    assert_eq!(
        connect_and_read_member(addr, tcpmux, &run_id_b_holder, connect_req).await,
        "grp-t-b",
        "remaining member must serve after the owner was deleted"
    );

    // Bulk-delete the last member → the shared route must be dropped.
    let resp = client
        .delete(frps.dashboard_url("/api/proxies"))
        .basic_auth("admin", Some("admin"))
        .json(&serde_json::json!({ "proxies": ["grp-t-b"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "bulk delete should succeed");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        let resp = client
            .get(frps.dashboard_url("/api/proxies/grp-t-b"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        if resp.status() == 404 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "grp-t-b never disappeared from /api/proxies"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (status, client) = do_connect(tcpmux, connect_req).await;
    drop(client);
    assert!(
        status.starts_with("HTTP/1.1 404"),
        "route should be removed after the last member was deleted, got: {status:?}"
    );

    drop(ctl_a);
    drop(ctl_b);
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

/// Live-traffic pin (round-9 gap + Go-shape alignment): real bytes through a
/// registered TCP proxy must land on the v1 traffic endpoints in Go's
/// `model.GetProxyTrafficResp` shape — `{name, trafficIn, trafficOut}` with
/// two 7-element per-day arrays, index 0 = today (Go `DateCounter`
/// today-first; same shared daily buffer the v2 history endpoints read), with
/// the Go counter sides (trafficIn = user -> frpc, trafficOut = frpc -> user)
/// and the exact byte counts. Conns counters are NOT part of Go's traffic
/// model (they live on the proxy stats endpoints as curConns), so the old
/// frp-rs scalar shape (bytes_in/bytes_out/current_conns/total_conns) is gone.
#[tokio::test]
async fn test_dashboard_proxy_traffic_live() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let remote_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let client = auth_client();
    let proxy_name = "live-tcp";

    let (mut ctl, resp) = common::login_with_test_token(addr).await.expect("login");
    let run_id = resp.run_id.expect("run_id");
    common::register_tcp_proxy(&mut ctl, proxy_name, remote_port).await;

    // Negative arm: before any traffic, both traffic endpoints report Go's
    // zero shape — name + exactly the keys {name, trafficIn, trafficOut}
    // (no conn/scalar keys) and two 7-entry all-zero day arrays.
    for path in [
        format!("/api/traffic/{proxy_name}"),
        format!("/api/proxy/{proxy_name}/traffic"),
    ] {
        let resp = client
            .get(frps.dashboard_url(&path))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let j: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(j["name"], proxy_name, "fresh proxy {path} name");
        let mut keys: Vec<&str> = j.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["name", "trafficIn", "trafficOut"],
            "fresh proxy {path} must expose exactly Go's GetProxyTrafficResp keys"
        );
        for dir in ["trafficIn", "trafficOut"] {
            let a = j[dir]
                .as_array()
                .unwrap_or_else(|| panic!("{path} {dir} array"));
            assert_eq!(a.len(), 7, "fresh proxy {path} {dir} must be 7 day buckets");
            for (i, v) in a.iter().enumerate() {
                assert_eq!(
                    v.as_u64().unwrap(),
                    0,
                    "fresh proxy {path} {dir}[{i}] must be 0"
                );
            }
        }
    }

    // Pump exact payloads through the live bridge, then poll for the day
    // buckets. The relay records traffic only after both conns close.
    let user_to_work: u64 = 123_457;
    let work_to_user: u64 = 67_891;
    let (user, work) = common::open_tcp_proxy_bridge(addr, remote_port, &mut ctl, &run_id).await;
    common::pump_tcp_bridge(user, work, user_to_work as usize, work_to_user as usize).await;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let traffic: serde_json::Value = loop {
        let resp = client
            .get(frps.dashboard_url(&format!("/api/traffic/{proxy_name}")))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let t: serde_json::Value = resp.json().await.unwrap();
        let sum_in: u64 = t["trafficIn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .sum();
        let sum_out: u64 = t["trafficOut"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .sum();
        if sum_in == user_to_work && sum_out == work_to_user {
            break t;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "traffic counters never reached {user_to_work}/{work_to_user}: {t}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };

    // Direction semantics (Go frp Join(c1=local, c2=userConn)): trafficIn is
    // user -> frpc and trafficOut is frpc -> user. The pump's bytes land in
    // the record day's bucket — index 0 for a same-day pump (today-first
    // arrays, Go DateCounter semantics). The one tolerated drift is a conn
    // close straddling UTC midnight: the rollover shift then moves the
    // earlier close's bytes to index 1 (analogous to the v2 pin's
    // "post-midnight" arm). Buckets 2..7 must stay empty either way.
    assert_eq!(traffic["name"], proxy_name);
    let arr_in = traffic["trafficIn"].as_array().unwrap();
    let arr_out = traffic["trafficOut"].as_array().unwrap();
    assert_eq!(arr_in.len(), 7, "trafficIn must stay 7 day buckets");
    assert_eq!(arr_out.len(), 7, "trafficOut must stay 7 day buckets");
    for (dir, total) in [("trafficIn", user_to_work), ("trafficOut", work_to_user)] {
        let arr = traffic[dir].as_array().unwrap();
        for (i, v) in arr.iter().enumerate().skip(2) {
            assert_eq!(
                v.as_u64().unwrap(),
                0,
                "{dir}[{i}] must be empty beyond the record day: {traffic}"
            );
        }
        let sum: u64 = arr.iter().map(|v| v.as_u64().unwrap()).sum();
        assert_eq!(sum, total, "{dir} bucket sum must equal the pumped bytes");
    }

    // Alias endpoint /api/proxy/{name}/traffic serves the same Go-shaped body.
    let resp = client
        .get(frps.dashboard_url(&format!("/api/proxy/{proxy_name}/traffic")))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap(), traffic);

    // /api/proxies list entry carries the same live counters.
    let resp = client
        .get(frps.dashboard_url("/api/proxies"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = resp.json().await.unwrap();
    let entry = list
        .iter()
        .find(|p| p["name"] == proxy_name)
        .unwrap_or_else(|| panic!("proxy {proxy_name} missing from list: {list:?}"));
    assert_eq!(entry["status"], "online");
    assert_eq!(entry["traffic_in"], user_to_work);
    assert_eq!(entry["traffic_out"], work_to_user);
    assert_eq!(entry["total_conns"], 1);

    // Typed detail embeds the traffic snapshot too.
    let resp = client
        .get(frps.dashboard_url(&format!("/api/proxy/tcp/{proxy_name}")))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    let detail: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(detail["name"], proxy_name);
    // Go model.ProxyInfo parity: the JSON key is "type", not "proxy_type".
    assert_eq!(detail["type"], "tcp");
    assert_eq!(detail["traffic"]["bytes_in"], user_to_work);
    assert_eq!(detail["traffic"]["bytes_out"], work_to_user);
    assert_eq!(detail["traffic"]["total_conns"], 1);
    assert_eq!(detail["traffic"]["current_conns"], 0);
}

/// A NewProxy wire message builder for the server-side proxy type filters.
/// Field set mirrors `common::register_tcp_proxy` plus the type-specific
/// fields (domains for http, sk for stcp).
fn typed_proxy_msg(
    name: &str,
    proxy_type: &str,
    remote_port: Option<u16>,
    custom_domains: Option<Vec<String>>,
    sk: Option<String>,
) -> FrpMessage {
    FrpMessage::NewProxy(Box::new(msg::NewProxy {
        proxy_name: name.into(),
        proxy_type: proxy_type.into(),
        sk,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:1".into()),
        remote_port: remote_port.map(|p| p as i32),
        custom_domains,
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
    }))
}

async fn register_proxy_ok(ctl: &mut frp_core::transport::IoStream, name: &str, msg: FrpMessage) {
    write_msg_v1(ctl, &msg)
        .await
        .unwrap_or_else(|e| panic!("send NewProxy for {name}: {e}"));
    // The server may interleave ReqWorkConn (pool pre-arms, e.g. after a UDP
    // registration) with the NewProxyResp — tolerate and skip them, like a
    // real frpc control loop would.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), read_msg_v1(ctl))
            .await
            .unwrap_or_else(|_| panic!("no NewProxyResp for {name} within 5s"));
        match read.unwrap_or_else(|e| panic!("read NewProxyResp for {name}: {e}")) {
            FrpMessage::NewProxyResp(r) => {
                assert!(r.error.is_none(), "register {name}: {:?}", r.error);
                break;
            }
            FrpMessage::ReqWorkConn(_) => continue,
            other => panic!(
                "expected NewProxyResp for {name}, got type byte {:?}",
                other.v1_type_byte()
            ),
        }
    }
    assert!(
        tokio::time::Instant::now() < deadline,
        "register {name} deadline"
    );
}

/// Per-type proxy listing/detail pins (round-9 gap): /api/proxy/{type},
/// /api/proxy/{type}/{name} and the ?type= filter on /api/proxies with live
/// registrations of several proxy types on the wire.
#[tokio::test]
async fn test_dashboard_proxy_type_and_name_filters() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let vhost_port = common::allocate_port();
    let tcp_port = common::allocate_port();
    let udp_port = common::allocate_port();
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
    let client = auth_client();

    let (mut ctl, _resp) = common::login_with_test_token(addr).await.expect("login");
    // Register order: UDP last. The server pre-arms a pooled work conn after
    // a UDP registration (a ReqWorkConn trails the NewProxyResp); register_proxy_ok
    // tolerates interleaved ReqWorkConn anyway, but this keeps the common case
    // strictly sequential.
    register_proxy_ok(
        &mut ctl,
        "tcp-one",
        typed_proxy_msg("tcp-one", "tcp", Some(tcp_port), None, None),
    )
    .await;
    register_proxy_ok(
        &mut ctl,
        "http-one",
        typed_proxy_msg(
            "http-one",
            "http",
            None,
            Some(vec!["app1.example.com".into()]),
            None,
        ),
    )
    .await;
    register_proxy_ok(
        &mut ctl,
        "stcp-one",
        typed_proxy_msg("stcp-one", "stcp", None, None, Some("sk-1".into())),
    )
    .await;
    register_proxy_ok(
        &mut ctl,
        "udp-one",
        typed_proxy_msg("udp-one", "udp", Some(udp_port), None, None),
    )
    .await;

    let client = &client;
    let frps = &frps;
    let get = |path: &str| {
        let path = path.to_string();
        async move {
            let resp = client
                .get(frps.dashboard_url(&path))
                .basic_auth("admin", Some("admin"))
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            (status, json)
        }
    };

    // Path-param type listing: each type returns exactly its own proxies.
    for (path, ty, expected) in [
        ("/api/proxy/tcp", "tcp", &["tcp-one"][..]),
        ("/api/proxy/udp", "udp", &["udp-one"][..]),
        ("/api/proxy/http", "http", &["http-one"][..]),
        ("/api/proxy/stcp", "stcp", &["stcp-one"][..]),
        // No xtcp/sudp registered — the handler returns an empty array.
        ("/api/proxy/xtcp", "xtcp", &[][..]),
        ("/api/proxy/sudp", "sudp", &[][..]),
    ] {
        let (status, json) = get(path).await;
        assert_eq!(status, 200, "{path} must be 200");
        let names: Vec<&str> = json
            .as_array()
            .expect("list body")
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, expected, "{path} type filter must be exact");
        for p in json.as_array().unwrap() {
            assert_eq!(p["type"], ty, "{path} must only carry {ty} entries");
        }
    }

    // tcpmux IS a valid registered proxy type in Go v0.71.0 (config/v1
    // ProxyTypeTCPMUX, stats keyed on the wire type "tcpmux"), so the v1
    // /api/proxy/tcpmux arm must accept it like the v2 VALID_TYPES does —
    // Go parity is 200; with no tcpmux proxy registered here that is an
    // empty list. (Round-9 alignment: frp-rs v1 previously 404'd tcpmux.)
    let (status, json) = get("/api/proxy/tcpmux").await;
    assert_eq!(status, 200, "v1 type filter must accept tcpmux (Go parity)");
    assert_eq!(
        json.as_array().expect("tcpmux list body").len(),
        0,
        "no tcpmux proxy is registered in this test"
    );
    // Unknown types stay 404 (frp-rs guard — Go v1 returns 200 + empty list
    // for any type string; documented divergence, see handle_proxies_by_type).
    let (status, _) = get("/api/proxy/bogus").await;
    assert_eq!(status, 404, "unknown type must 404");

    // ?type= query filter on /api/proxies.
    let (status, json) = get("/api/proxies").await;
    assert_eq!(status, 200);
    let all: Vec<String> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(all.len(), 4);
    let (_, json) = get("/api/proxies?type=http").await;
    let names: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["http-one"], "?type=http filter must be exact");
    let (_, json) = get("/api/proxies?type=stcp").await;
    let names: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["stcp-one"], "?type=stcp filter must be exact");

    // Typed detail: matching type+name 200, mismatched type 404, alias route.
    let (status, json) = get("/api/proxy/tcp/tcp-one").await;
    assert_eq!(status, 200);
    assert_eq!(json["name"], "tcp-one");
    assert_eq!(json["type"], "tcp", "Go parity: detail key is \"type\"");
    assert_eq!(json["status"], "online");
    assert!(
        json["traffic"].is_object(),
        "detail embeds a traffic snapshot"
    );

    let (status, _) = get("/api/proxy/udp/tcp-one").await;
    assert_eq!(status, 404, "type/name mismatch must 404");
    let (status, _) = get("/api/proxy/tcp/unknown-one").await;
    assert_eq!(status, 404, "unknown proxy must 404");
    // /api/proxies/{name} alias serves the same detail.
    let (status, json2) = get("/api/proxies/tcp-one").await;
    assert_eq!(status, 200);
    assert_eq!(json2, json, "alias detail must match the typed detail");
}
