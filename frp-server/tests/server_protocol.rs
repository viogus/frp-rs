mod common;

use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

use common::{allocate_port, raw_login, raw_login_resp, start_test_server};
use frp_core::transport::{DialOptions, IoStream, TransportProtocol, dial_server};
use std::path::PathBuf;

fn test_cert_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("frp-core");
    p.push("tests");
    p.push("certs");
    p
}

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
    let resp = raw_login_resp(addr, None, None, "").await.expect("login should succeed");

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
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
                    oidc_proxy_url: String::new(),
                    additional_auth_scopes: Vec::new(),
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

    let resp = raw_login_resp(addr, Some(wrong_key), Some(ts), "secret")
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
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
                    oidc_proxy_url: String::new(),
                    additional_auth_scopes: Vec::new(),
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

    let resp = raw_login_resp(addr, Some(key), Some(ts), "secret")
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
    let (mut stream, _resp) = raw_login(addr, None, None, "").await.expect("login");

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
    let (mut stream, _resp) = raw_login(addr, None, None, "").await.expect("login");

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
        virtual_net: None,
                    proxy_protocol_version: None,
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
    let (mut stream, _resp) = raw_login(addr, None, None, "").await.expect("login");

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
        virtual_net: None,
                    proxy_protocol_version: None,
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

// ---------------------------------------------------------------
// VHost locations routing
// ---------------------------------------------------------------

#[tokio::test]
async fn test_vhost_location_routing() {
    let port = allocate_port();
    let vhost_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        vhost_http_port: vhost_port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let vhost_addr: std::net::SocketAddr = format!("127.0.0.1:{}", vhost_port).parse().unwrap();

    // Wait for VHost port to be ready
    {
        let start = std::time::Instant::now();
        loop {
            if tokio::net::TcpStream::connect(vhost_addr).await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("VHost port not ready");
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    // Provider logs in and registers HTTP proxy with locations
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "http-loc-test".into(),
        proxy_type: "http".into(),
        custom_domains: Some(vec!["test.local".into()]),
        locations: Some(vec!["/api".into(), "/static".into()]),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9999".into()),
        remote_port: Some(0),
        sk: None,
        subdomain: None,
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
    });
    write_msg_v1(&mut provider, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "HTTP proxy with locations should register: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Provider sends pooled work connection
    let mut work_conn = tokio::net::TcpStream::connect(addr).await.expect("work conn connect");
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id.clone()),
        timestamp: None,
        privilege_key: None,
    });
    write_msg_v1(&mut work_conn, &nwc).await.expect("send NewWorkConn");

    // Connect to VHost HTTP port and send a request matching domain + location
    let mut http_conn = tokio::net::TcpStream::connect(vhost_addr).await.expect("connect to vhost");
    let request = "\
GET /api/users HTTP/1.1\r\n\
Host: test.local\r\n\
Connection: close\r\n\
\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut http_conn, request.as_bytes()).await.expect("send HTTP request");

    // Verify StartWorkConn is received on the work connection
    match read_msg_v1(&mut work_conn).await.expect("read StartWorkConn on work conn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "http-loc-test", "expected http-loc-test, got {}", swc.proxy_name);
            assert!(swc.error.is_none(), "StartWorkConn should not have error: {:?}", swc.error);
        }
        other => {
            panic!("expected StartWorkConn, got type byte: {:?}", other.v1_type_byte());
        }
    }
}

/// VHost location: request with mismatched path should get 404.
#[tokio::test]
async fn test_vhost_location_path_mismatch_404() {
    let port = allocate_port();
    let vhost_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        vhost_http_port: vhost_port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let vhost_addr: std::net::SocketAddr = format!("127.0.0.1:{}", vhost_port).parse().unwrap();

    // Wait for VHost port
    {
        let start = std::time::Instant::now();
        loop {
            if tokio::net::TcpStream::connect(vhost_addr).await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("VHost port not ready");
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    // Provider registers HTTP proxy with locations (only /api)
    let (mut provider, _resp) = raw_login(addr, None, None, "").await.expect("provider login");

    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "http-loc-only".into(),
        proxy_type: "http".into(),
        custom_domains: Some(vec!["test.local".into()]),
        locations: Some(vec!["/api".into()]),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9999".into()),
        remote_port: Some(0),
        sk: None,
        subdomain: None,
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
    });
    write_msg_v1(&mut provider, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "register ok: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Connect to VHost and send request to NON-matching path
    let mut http_conn = tokio::net::TcpStream::connect(vhost_addr).await.expect("connect to vhost");
    let request = "\
GET /other/path HTTP/1.1\r\n\
Host: test.local\r\n\
Connection: close\r\n\
\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut http_conn, request.as_bytes()).await.expect("send HTTP request");

    // Should get 404
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::io::AsyncReadExt::read(&mut http_conn, &mut buf),
    ).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("404"), "expected 404, got: {}", response);
}

// ---------------------------------------------------------------
// WebSocket transport
// ---------------------------------------------------------------

#[tokio::test]
async fn test_login_via_websocket() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: port,
        protocol: TransportProtocol::WebSocket,
        ..Default::default()
    };

    let mut io = dial_server(&opts).await.expect("WS dial");

    // Verify we got a WebSocket stream
    match &io {
        IoStream::WebSocket(_) => {} // expected
        other => panic!("expected IoStream::WebSocket, got: {:?}", other),
    }

    // Send login
    let login = FrpMessage::Login(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-ws-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: None,
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: None,
        
    });
    io.write_v1_frame(&login).await.expect("send login over WS");

    let resp = io.read_v1_frame().await.expect("read LoginResp over WS");
    match resp {
        FrpMessage::LoginResp(r) => {
            assert!(r.error.is_none(), "WS login should succeed, got: {:?}", r.error);
            assert!(r.run_id.is_some(), "expected run_id");
        }
        other => panic!("expected LoginResp, got: {:?}", other.v1_type_byte()),
    }
}

// ---------------------------------------------------------------
// TLS transport
// ---------------------------------------------------------------

#[tokio::test]
async fn test_login_via_tls() {
    let port = allocate_port();
    let cert_dir = test_cert_dir();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        tls_enable: true,
        tls_cert_file: cert_dir.join("server.crt").to_string_lossy().into(),
        tls_key_file: cert_dir.join("server.key").to_string_lossy().into(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    // Connect via TLS using dial_server (trust the CA that signed server cert)
    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: port,
        tls_enable: true,
        tls_server_name: "localhost".into(),
        tls_ca_file: Some(cert_dir.join("ca.crt").to_string_lossy().into()),
        ..Default::default()
    };

    let mut io = dial_server(&opts).await.expect("TLS dial");

    // Verify we got a TLS stream
    match &io {
        IoStream::Tls(_) => {} // expected
        other => panic!("expected IoStream::Tls, got: {:?}", other),
    }

    // Send login
    let login = FrpMessage::Login(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-tls-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: None,
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: None,
        
    });
    io.write_v1_frame(&login).await.expect("send login over TLS");

    let resp = io.read_v1_frame().await.expect("read LoginResp over TLS");
    match resp {
        FrpMessage::LoginResp(r) => {
            assert!(r.error.is_none(), "TLS login should succeed, got: {:?}", r.error);
            assert!(r.run_id.is_some(), "expected run_id");
        }
        other => panic!("expected LoginResp, got: {:?}", other.v1_type_byte()),
    }
}
