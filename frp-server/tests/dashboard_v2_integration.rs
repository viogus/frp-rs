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

/// Full server config with tcp_mux disabled: the traffic/pagination pins dial
/// raw (non-yamux) work conns, so the transport must not wrap them.
fn live_config(bind_port: u16, dashboard_port: u16) -> String {
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

/// UTC Y-M-D civil date (Howard Hinnant algorithm) for a Unix timestamp —
/// mirrors the dashboard's `format_date_ymd`, so pins can name the exact
/// history dates the traffic endpoint must report.
fn utc_ymd(ts_secs: i64) -> String {
    let days = ts_secs / 86400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + (era * 400);
    let doy = doe as i64 - (365 * yoe as i64 + yoe as i64 / 4 - yoe as i64 / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Live-traffic pin for the Go-shaped v2 traffic endpoint (round-9 gap):
/// real relayed bytes must produce a Go `V2ProxyTrafficResp` —
/// `{name, unit:"bytes", granularity:"day", history:[{date,trafficIn,
/// trafficOut} x7]}` oldest -> newest, today last, sums byte-exact — and the
/// v2 proxies list must reflect the same day's counters.
#[tokio::test]
async fn test_v2_proxy_traffic_live_go_shape() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let remote_port = common::allocate_port();
    let frps = FrpsHandle::start(&live_config(bind_port, dashboard_port)).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let client = auth_client();
    let proxy_name = "v2-live";

    let (mut ctl, resp) = common::login_with_test_token(addr).await.expect("login");
    let run_id = resp.run_id.expect("run_id");
    common::register_tcp_proxy(&mut ctl, proxy_name, remote_port).await;

    let traffic_url = || frps.dashboard_url(&format!("/api/v2/proxies/{proxy_name}/traffic"));

    // Negative arm: a proxy with no traffic still reports Go's 7 zero points
    // (one per day), not an empty list.
    let resp = client
        .get(traffic_url())
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let zero: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(zero["name"], proxy_name);
    assert_eq!(zero["unit"], "bytes");
    assert_eq!(zero["granularity"], "day");
    let h = zero["history"].as_array().expect("history array");
    assert_eq!(h.len(), 7, "Go V2ProxyTrafficResp: 7 day points");
    for (i, point) in h.iter().enumerate() {
        assert_eq!(point["trafficIn"], 0, "zero point {i} trafficIn");
        assert_eq!(point["trafficOut"], 0, "zero point {i} trafficOut");
        assert!(
            point["date"].as_str().unwrap().len() == 10,
            "date must be YYYY-MM-DD, got {}",
            point["date"]
        );
    }
    // Dates ascend daily and end on today (UTC).
    let today = utc_ymd(now_secs());
    assert_eq!(h[6]["date"], today, "last history point is today");
    for i in 1..7 {
        let prev = utc_ymd(now_secs() - (7 - i) as i64 * 86400);
        assert_eq!(
            h[i - 1]["date"],
            prev,
            "history[{i}] date must be consecutive"
        );
    }

    // Pump exact byte counts through the live bridge, then poll until the
    // totals arrive (the relay records only after both conns close).
    let user_to_work: u64 = 123_457;
    let work_to_user: u64 = 67_891;
    let (user, work) = common::open_tcp_proxy_bridge(addr, remote_port, &mut ctl, &run_id).await;
    common::pump_tcp_bridge(user, work, user_to_work as usize, work_to_user as usize).await;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let live: serde_json::Value = loop {
        let resp = client
            .get(traffic_url())
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        let h = body["history"].as_array().unwrap();
        let sum_in: u64 = h.iter().map(|p| p["trafficIn"].as_u64().unwrap()).sum();
        let sum_out: u64 = h.iter().map(|p| p["trafficOut"].as_u64().unwrap()).sum();
        if sum_in == user_to_work && sum_out == work_to_user {
            break body;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "v2 traffic never reached {user_to_work}/{work_to_user}: {body}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };

    let h = live["history"].as_array().unwrap();
    // Exactly one day carries the pump (the record day's bucket); its sums
    // are the exact byte counts with the Go sides (trafficIn = user -> frpc).
    let nonzero: Vec<(usize, &serde_json::Value)> = h
        .iter()
        .enumerate()
        .filter(|(_, p)| p["trafficIn"].as_u64().unwrap() != 0)
        .collect();
    assert_eq!(
        nonzero.len(),
        1,
        "exactly one day must carry traffic: {live}"
    );
    let (idx, point) = nonzero[0];
    assert_eq!(point["trafficIn"], user_to_work, "user->frpc byte count");
    assert_eq!(point["trafficOut"], work_to_user, "frpc->user byte count");
    let date = point["date"].as_str().unwrap();
    let day_ago = utc_ymd(now_secs() - 86400);
    if date == today {
        assert_eq!(idx, 6, "today's traffic lands in the newest point");
    } else if date == day_ago {
        assert_eq!(idx, 5, "post-midnight snapshot shifts to yesterday");
    } else {
        panic!("traffic landed on unexpected date {date} (idx {idx})");
    }

    // The v2 proxies list entry reflects the same counters (today bucket).
    let list_url = frps.dashboard_url("/api/v2/proxies");
    let resp = client
        .get(&list_url)
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let entry = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == proxy_name)
        .unwrap_or_else(|| panic!("{proxy_name} missing from v2 list: {list}"));
    assert_eq!(entry["status"]["phase"], "online");
    assert_eq!(entry["status"]["curConns"], 0, "bridge ended");
    match entry["status"]["todayTrafficIn"].as_u64().unwrap() {
        v if v == user_to_work => {
            assert_eq!(
                entry["status"]["todayTrafficOut"].as_u64().unwrap(),
                work_to_user,
                "same-day list counters"
            );
        }
        0 => {
            // The midnight rollover case: today's list bucket is empty and
            // the pump sits in yesterday's history point.
            assert_eq!(entry["status"]["todayTrafficOut"], 0);
        }
        other => panic!("unexpected todayTrafficIn {other}: {entry}"),
    }
}

/// Pagination over live proxies (round-9 gap): page/pageSize slices, the
/// total, envelope fields, and the u32::MAX saturating path.
#[tokio::test]
async fn test_v2_proxies_pagination_live() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&live_config(bind_port, dashboard_port)).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let client = auth_client();

    let (mut ctl, _resp) = common::login_with_test_token(addr).await.expect("login");
    for name in ["tcp-a", "tcp-b", "tcp-c", "tcp-d", "tcp-e"] {
        common::register_tcp_proxy(&mut ctl, name, common::allocate_port()).await;
    }

    let client = &client;
    let frps = &frps;
    let page = |p: u32, ps: u32| async move {
        let url = format!("/api/v2/proxies?page={p}&pageSize={ps}");
        let resp = client
            .get(frps.dashboard_url(&url))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        resp.json::<serde_json::Value>().await.unwrap()
    };
    let names = |j: &serde_json::Value| -> Vec<String> {
        j["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    };

    // Envelope + slice shape: Go PageResp {total, page, pageSize, items},
    // sorted by (type, name) — all tcp here, so name ascending.
    let p1 = page(1, 2).await;
    assert_eq!(p1["total"], 5);
    assert_eq!(p1["page"], 1);
    assert_eq!(p1["pageSize"], 2);
    assert_eq!(names(&p1), ["tcp-a", "tcp-b"]);
    let p2 = page(2, 2).await;
    assert_eq!(p2["total"], 5);
    assert_eq!(names(&p2), ["tcp-c", "tcp-d"]);
    let p3 = page(3, 2).await;
    assert_eq!(p3["total"], 5);
    assert_eq!(names(&p3), ["tcp-e"]);
    // Past-the-end page: empty items, total unchanged.
    let p4 = page(4, 2).await;
    assert_eq!(p4["total"], 5);
    assert_eq!(names(&p4), [] as [&str; 0]);
    // Defaults: pageSize alone, page alone.
    let dflt = page(1, 50).await;
    assert_eq!(dflt["total"], 5);
    assert_eq!(names(&dflt).len(), 5);

    // Saturating overflow arm: u32::MAX page must not panic/wrap — the
    // (page-1)*pageSize product saturates and the slice comes back empty.
    let huge = page(u32::MAX, 200).await;
    assert_eq!(huge["page"], u32::MAX, "page must echo even at u32::MAX");
    assert_eq!(huge["total"], 5);
    assert_eq!(names(&huge), [] as [&str; 0]);
}

/// Error arms of the v2 page params (round-9 gap): page < 1, pageSize < 1,
/// pageSize > MAX_PAGE_SIZE, and non-numeric/overflowing params.
#[tokio::test]
async fn test_v2_page_param_errors() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&base_config(bind_port, dashboard_port)).await;
    let client = auth_client();

    let client = &client;
    let frps = &frps;
    let get = |query: &str| {
        let query = query.to_string();
        async move {
            let resp = client
                .get(frps.dashboard_url(&format!("/api/v2/proxies?{query}")))
                .basic_auth("admin", Some("admin"))
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            (status, text)
        }
    };

    let (status, body) = get("page=0").await;
    assert_eq!(status, 400);
    assert_eq!(body, r#"{"error":"page must be a positive integer"}"#);
    let (status, body) = get("pageSize=0").await;
    assert_eq!(status, 400);
    assert_eq!(body, r#"{"error":"pageSize must be a positive integer"}"#);
    let (status, body) = get("pageSize=201").await;
    assert_eq!(status, 400);
    assert_eq!(body, r#"{"error":"pageSize must be between 1 and 200"}"#);
    // Boundary: pageSize == MAX is legal.
    let resp = client
        .get(frps.dashboard_url("/api/v2/proxies?pageSize=200"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // page is validated before pageSize in the Go-order parse.
    let (status, body) = get("page=0&pageSize=0").await;
    assert_eq!(status, 400);
    assert_eq!(body, r#"{"error":"page must be a positive integer"}"#);
    // Non-numeric params fail the u32 Query deserialization (axum rejection:
    // status only, the body is not the JSON error shape).
    let (status, _) = get("page=abc").await;
    assert_eq!(status, 400, "non-numeric page must 400");
    let (status, _) = get("pageSize=abc").await;
    assert_eq!(status, 400, "non-numeric pageSize must 400");
    let (status, _) = get("page=4294967296").await;
    assert_eq!(status, 400, "u32-overflowing page must 400");
}

/// Type/status filters on the v2 proxies list with live registrations.
#[tokio::test]
async fn test_v2_proxies_type_status_filter() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let udp_port = common::allocate_port();
    let frps = FrpsHandle::start(&live_config(bind_port, dashboard_port)).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let client = auth_client();

    let (mut ctl, _resp) = common::login_with_test_token(addr).await.expect("login");
    common::register_tcp_proxy(&mut ctl, "tcp-a", common::allocate_port()).await;
    common::register_tcp_proxy(&mut ctl, "tcp-b", common::allocate_port()).await;
    // A non-tcp registration: build the udp wire message inline.
    {
        use frp_core::msg::{self, FrpMessage};
        use frp_core::protocol::{read_msg_v1, write_msg_v1};
        let np = FrpMessage::NewProxy(Box::new(msg::NewProxy {
            proxy_name: "udp-c".into(),
            proxy_type: "udp".into(),
            sk: None,
            use_encryption: None,
            use_compression: None,
            group: None,
            group_key: None,
            local_str: Some("127.0.0.1:1".into()),
            remote_port: Some(udp_port as i32),
            custom_domains: None,
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
        }));
        write_msg_v1(&mut ctl, &np).await.expect("register udp-c");
        match read_msg_v1(&mut ctl).await.expect("NewProxyResp udp-c") {
            FrpMessage::NewProxyResp(r) => assert!(r.error.is_none(), "{:?}", r.error),
            other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
        }
    }

    let client = &client;
    let frps = &frps;
    let get = |query: &str| {
        let query = query.to_string();
        async move {
            let resp = client
                .get(frps.dashboard_url(&format!("/api/v2/proxies?{query}")))
                .basic_auth("admin", Some("admin"))
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            (status, json)
        }
    };
    let names = |j: &serde_json::Value| -> Vec<String> {
        j["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    };

    let (status, j) = get("type=tcp").await;
    assert_eq!(status, 200);
    assert_eq!(j["total"], 2);
    assert_eq!(names(&j), ["tcp-a", "tcp-b"]);
    for item in j["items"].as_array().unwrap() {
        assert_eq!(item["spec"]["type"], "tcp");
    }
    let (status, j) = get("type=udp").await;
    assert_eq!(status, 200);
    assert_eq!(names(&j), ["udp-c"]);
    // tcpmux is a VALID v2 type (unlike the v1 list, which 404s).
    let (status, j) = get("type=tcpmux").await;
    assert_eq!(status, 200);
    assert_eq!(names(&j), [] as [&str; 0]);
    let (status, j) = get("type=bogus").await;
    assert_eq!(status, 400);
    assert_eq!(
        j["error"],
        "type must be one of tcp, udp, http, https, tcpmux, stcp, xtcp, sudp"
    );

    // Status filter: all live registrations are online.
    let (status, j) = get("status=online").await;
    assert_eq!(status, 200);
    assert_eq!(j["total"], 3);
    for item in j["items"].as_array().unwrap() {
        assert_eq!(item["status"]["phase"], "online");
    }
    let (status, j) = get("status=offline").await;
    assert_eq!(status, 200);
    // frp-rs removes a proxy when its client disconnects — no offline proxy
    // can exist while this control is connected.
    assert_eq!(j["total"], 0);
    let (status, j) = get("status=bogus").await;
    assert_eq!(status, 400);
    assert_eq!(j["error"], "status must be one of all, online, offline");

    // q= substring search over name/type/user/clientID/phase/domains/port.
    let (status, j) = get("q=udp").await;
    assert_eq!(status, 200);
    assert_eq!(names(&j), ["udp-c"]);
}

/// Clients pagination/filter over two live logins with distinct users.
#[tokio::test]
async fn test_v2_clients_pagination_live() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();
    let frps = FrpsHandle::start(&live_config(bind_port, dashboard_port)).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let client = auth_client();

    let (_ctl_a, _) = common::login_with_identity(addr, "alice", Default::default())
        .await
        .expect("login alice");
    let (_ctl_b, _) = common::login_with_identity(addr, "bob", Default::default())
        .await
        .expect("login bob");

    let client = &client;
    let frps = &frps;
    let get = |query: &str| {
        let query = query.to_string();
        async move {
            let resp = client
                .get(frps.dashboard_url(&format!("/api/v2/clients?{query}")))
                .basic_auth("admin", Some("admin"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            resp.json::<serde_json::Value>().await.unwrap()
        }
    };
    let users = |j: &serde_json::Value| -> Vec<String> {
        j["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["user"].as_str().unwrap().to_string())
            .collect()
    };

    let all = get("pageSize=10").await;
    assert_eq!(all["total"], 2);
    assert_eq!(users(&all), ["alice", "bob"], "sorted by user");

    let p1 = get("page=1&pageSize=1").await;
    assert_eq!(p1["total"], 2);
    assert_eq!(users(&p1), ["alice"]);
    let p2 = get("page=2&pageSize=1").await;
    assert_eq!(p2["total"], 2);
    assert_eq!(users(&p2), ["bob"]);

    let by_user = get("user=alice").await;
    assert_eq!(by_user["total"], 1);
    assert_eq!(users(&by_user), ["alice"]);
    let by_user = get("user=nobody").await;
    assert_eq!(by_user["total"], 0);

    let online = get("status=online").await;
    assert_eq!(online["total"], 2);
    for c in online["items"].as_array().unwrap() {
        assert_eq!(c["online"], true);
    }
    let offline = get("status=offline").await;
    assert_eq!(offline["total"], 0, "both clients still connected");
}
