mod common;

use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

use common::{allocate_port, raw_login, raw_login_resp, start_test_server};

// ---------------------------------------------------------------
// Login / Authentication
// ---------------------------------------------------------------

#[tokio::test]
async fn test_login_empty_token_succeeds() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let resp = raw_login_resp(addr, None, None).await.expect("login should succeed");

    assert!(resp.error.is_none(), "expected no error, got: {:?}", resp.error);
    assert!(resp.run_id.is_some(), "expected run_id to be set");
    let run_id = resp.run_id.unwrap();
    assert!(!run_id.is_empty(), "run_id should not be empty");
}

#[tokio::test]
async fn test_login_wrong_token_fails() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: "secret".into(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
        },
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let wrong_key = auth::generate_token("wrong-secret", ts);

    let resp = raw_login_resp(addr, Some(wrong_key), Some(ts))
        .await
        .expect("login should return a response");

    assert!(resp.error.is_some(), "expected auth error, got success");
    assert!(
        resp.error.unwrap().to_lowercase().contains("invalid"),
        "expected 'invalid' in error message"
    );
}

#[tokio::test]
async fn test_login_correct_token_succeeds() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: "secret".into(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
        },
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token("secret", ts);

    let resp = raw_login_resp(addr, Some(key), Some(ts))
        .await
        .expect("login should succeed");

    assert!(resp.error.is_none(), "expected no error, got: {:?}", resp.error);
    assert!(resp.run_id.is_some(), "expected run_id");
}

// ---------------------------------------------------------------
// Ping / Pong heartbeat
// ---------------------------------------------------------------

#[tokio::test]
async fn test_ping_pong_no_auth() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = raw_login(addr, None, None).await.expect("login");

    // Send Ping
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    write_msg_v1(&mut stream, &ping)
        .await
        .expect("send ping");

    // Read Pong
    match read_msg_v1(&mut stream).await.expect("read pong") {
        FrpMessage::Pong(pong) => {
            assert!(pong.error.is_none(), "expected pong without error, got: {:?}", pong.error);
        }
        other => panic!("expected Pong, got type byte: {:?}", other.v1_type_byte()),
    }
}

// ---------------------------------------------------------------
// Proxy registration
// ---------------------------------------------------------------

#[tokio::test]
async fn test_new_proxy_registration_auto_port() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = raw_login(addr, None, None).await.expect("login");

    // Register a TCP proxy with auto-assign port (remote_port = 0)
    let np = FrpMessage::NewProxy(msg::NewProxy {
        proxy_name: "test-tcp".into(),
        proxy_type: "tcp".into(),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9876".into()),
        remote_port: Some(0), // auto-assign
        sk: None,
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
    });
    write_msg_v1(&mut stream, &np).await.expect("send NewProxy");

    match read_msg_v1(&mut stream).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(resp) => {
            assert!(resp.error.is_none(), "expected no error, got: {:?}", resp.error);
            assert!(resp.remote_addr.is_some(), "expected remote_addr");
            let remote_addr = resp.remote_addr.unwrap();
            // remote_addr is something like ":10000" — parse the port
            let assigned_port: u16 = remote_addr
                .trim_start_matches(':')
                .parse()
                .expect("remote_addr should contain a port number");
            assert!(
                assigned_port >= 10000 && assigned_port <= 50000,
                "assigned port {} out of range 10000-50000",
                assigned_port
            );
        }
        other => panic!("expected NewProxyResp, got type byte: {:?}", other.v1_type_byte()),
    }
}

#[tokio::test]
async fn test_new_proxy_duplicate_name_fails() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = raw_login(addr, None, None).await.expect("login");

    let mk_proxy = || FrpMessage::NewProxy(msg::NewProxy {
        proxy_name: "dup-tcp".into(),
        proxy_type: "tcp".into(),
        local_str: Some("127.0.0.1:9876".into()),
        remote_port: Some(0),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        sk: None,
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
    });

    // First registration — should succeed
    write_msg_v1(&mut stream, &mk_proxy()).await.expect("send first NewProxy");
    match read_msg_v1(&mut stream).await.expect("read first NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "first proxy should succeed, got: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Second registration with same name — should fail
    write_msg_v1(&mut stream, &mk_proxy()).await.expect("send second NewProxy");
    match read_msg_v1(&mut stream).await.expect("read second NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_some(),
                "duplicate proxy should fail, got success"
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }
}
