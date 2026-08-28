mod common;

use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage, LoginResp, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

use common::{
    allocate_port, login_with_test_token, raw_login_resp, start_test_server, test_auth_cfg,
    TEST_TOKEN,
};
use frp_core::transport::{dial_server, DialOptions, IoStream, TransportProtocol};
use frp_server::service::Service;
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
async fn test_login_empty_token_rejected() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };

    // check_startup() rejects empty-token configurations at server startup.
    // This catches accidental empty-token deployments before they go live.
    let err = match Service::new(cfg, None).await {
        Ok(_) => panic!("Server should reject empty token at startup via check_startup()"),
        Err(e) => e,
    };
    assert!(
        err.contains("security misconfiguration")
            || err.contains("CRITICAL")
            || err.contains("token"),
        "Expected startup rejection with security message, got: {err}"
    );
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
            ..Default::default()
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
    let err = resp.error.unwrap().to_lowercase();
    assert!(
        err.contains("invalid") || err.contains("authentication failed"),
        "expected auth error, got: {err}"
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
            ..Default::default()
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

    assert!(
        resp.error.is_none(),
        "expected no error, got: {:?}",
        resp.error
    );
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
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = login_with_test_token(addr).await.expect("login");

    // Send Ping
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    write_msg_v1(&mut stream, &ping).await.expect("send ping");

    // Read Pong
    match read_msg_v1(&mut stream).await.expect("read pong") {
        FrpMessage::Pong(pong) => {
            assert!(
                pong.error.is_none(),
                "expected pong without error, got: {:?}",
                pong.error
            );
        }
        other => panic!("expected Pong, got type byte: {:?}", other.v1_type_byte()),
    }
}

/// Go frp v0.71.0 parity (server/control.go handlePing): a ping that fails
/// auth — here "HeartBeats" is in additional_auth_scopes and the privilege
/// key is wrong — gets a Pong{Error} but does NOT kill the control
/// connection. The very next message on the same connection (a correctly
/// authenticated ping) must still be answered. The pre-fix behavior
/// (returning Err and tearing the session down) would make the second
/// read/write fail with EOF.
#[tokio::test]
async fn test_ping_auth_failure_keeps_conn_alive() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: TEST_TOKEN.into(),
            additional_auth_scopes: vec!["HeartBeats".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = login_with_test_token(addr).await.expect("login");

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Ping with a WRONG privilege key: must yield Pong{Error} ...
    let bad_key = auth::generate_token("wrong-secret", ts);
    let bad_ping = FrpMessage::Ping(msg::Ping {
        privilege_key: Some(bad_key),
        timestamp: Some(ts),
    });
    write_msg_v1(&mut stream, &bad_ping)
        .await
        .expect("send bad ping");
    match read_msg_v1(&mut stream).await.expect("read error pong") {
        FrpMessage::Pong(pong) => assert!(
            pong.error.is_some(),
            "expected Pong with auth error, got: {:?}",
            pong.error
        ),
        other => panic!("expected Pong, got type byte: {:?}", other.v1_type_byte()),
    }

    // ... but the connection must survive: the next ping with the CORRECT
    // key still gets a clean Pong on the same stream. (Fresh timestamp:
    // reuse could trip replay-protection duplicate detection instead of the
    // survival check this test pins.)
    let good_key = auth::generate_token(TEST_TOKEN, ts + 1);
    let good_ping = FrpMessage::Ping(msg::Ping {
        privilege_key: Some(good_key),
        timestamp: Some(ts + 1),
    });
    write_msg_v1(&mut stream, &good_ping)
        .await
        .expect("send good ping");
    match read_msg_v1(&mut stream).await.expect("read clean pong") {
        FrpMessage::Pong(pong) => assert!(
            pong.error.is_none(),
            "expected clean Pong on surviving conn, got: {:?}",
            pong.error
        ),
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
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = login_with_test_token(addr).await.expect("login");

    // Register a TCP proxy with auto-assign port (remote_port = 0)
    let np = FrpMessage::NewProxy(Box::new(msg::NewProxy {
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
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }));
    write_msg_v1(&mut stream, &np).await.expect("send NewProxy");

    match read_msg_v1(&mut stream).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(resp) => {
            assert!(
                resp.error.is_none(),
                "expected no error, got: {:?}",
                resp.error
            );
            assert!(resp.remote_addr.is_some(), "expected remote_addr");
            let remote_addr = resp.remote_addr.unwrap();
            // remote_addr is "host:port" (e.g. "0.0.0.0:10000") — parse the port
            let assigned_port: u16 = remote_addr
                .rsplit(':')
                .next()
                .expect("remote_addr should contain a port number")
                .parse()
                .expect("remote_addr should contain a valid port number");
            assert!(
                (0..=65535).contains(&assigned_port),
                "assigned port {} out of range 0-65535",
                assigned_port
            );
        }
        other => panic!(
            "expected NewProxyResp, got type byte: {:?}",
            other.v1_type_byte()
        ),
    }
}

#[tokio::test]
async fn test_new_proxy_duplicate_name_fails() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (mut stream, _resp) = login_with_test_token(addr).await.expect("login");

    let mk_proxy = || {
        FrpMessage::NewProxy(Box::new(msg::NewProxy {
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
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        }))
    };

    // First registration — should succeed
    write_msg_v1(&mut stream, &mk_proxy())
        .await
        .expect("send first NewProxy");
    match read_msg_v1(&mut stream)
        .await
        .expect("read first NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "first proxy should succeed, got: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Second registration with same name — should fail
    write_msg_v1(&mut stream, &mk_proxy())
        .await
        .expect("send second NewProxy");
    match read_msg_v1(&mut stream)
        .await
        .expect("read second NewProxyResp")
    {
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
        auth: test_auth_cfg(),
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
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(Box::new(NewProxy {
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
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "HTTP proxy with locations should register: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Provider sends pooled work connection
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id.clone()),
        timestamp: None,
        privilege_key: None,
    });
    write_msg_v1(&mut work_conn, &nwc)
        .await
        .expect("send NewWorkConn");

    // Connect to VHost HTTP port and send a request matching domain + location
    let mut http_conn = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("connect to vhost");
    let request = "\
GET /api/users HTTP/1.1\r\n\
Host: test.local\r\n\
Connection: close\r\n\
\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut http_conn, request.as_bytes())
        .await
        .expect("send HTTP request");

    // Verify StartWorkConn is received on the work connection
    match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn on work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(
                swc.proxy_name, "http-loc-test",
                "expected http-loc-test, got {}",
                swc.proxy_name
            );
            assert!(
                swc.error.is_none(),
                "StartWorkConn should not have error: {:?}",
                swc.error
            );
        }
        other => {
            panic!(
                "expected StartWorkConn, got type byte: {:?}",
                other.v1_type_byte()
            );
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
        auth: test_auth_cfg(),
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
    let (mut provider, _resp) = login_with_test_token(addr).await.expect("provider login");

    let np = FrpMessage::NewProxy(Box::new(NewProxy {
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
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "register ok: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Connect to VHost and send request to NON-matching path
    let mut http_conn = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("connect to vhost");
    let request = "\
GET /other/path HTTP/1.1\r\n\
Host: test.local\r\n\
Connection: close\r\n\
\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut http_conn, request.as_bytes())
        .await
        .expect("send HTTP request");

    // Should get 404
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::io::AsyncReadExt::read(&mut http_conn, &mut buf),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(0);
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
        auth: test_auth_cfg(),
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
    assert_eq!(io.debug_name(), "IoStream::WebSocket");

    // Send login
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token("test-token", ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-ws-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    io.write_v1_frame(&login).await.expect("send login over WS");

    let resp = io.read_v1_frame().await.expect("read LoginResp over WS");
    match resp {
        FrpMessage::LoginResp(r) => {
            assert!(
                r.error.is_none(),
                "WS login should succeed, got: {:?}",
                r.error
            );
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
        auth: test_auth_cfg(),
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
    assert_eq!(io.debug_name(), "IoStream::Tls");

    // Send login
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token("test-token", ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-tls-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    io.write_v1_frame(&login)
        .await
        .expect("send login over TLS");

    let resp = io.read_v1_frame().await.expect("read LoginResp over TLS");
    match resp {
        FrpMessage::LoginResp(r) => {
            assert!(
                r.error.is_none(),
                "TLS login should succeed, got: {:?}",
                r.error
            );
            assert!(r.run_id.is_some(), "expected run_id");
        }
        other => panic!("expected LoginResp, got: {:?}", other.v1_type_byte()),
    }
}

// ---------------------------------------------------------------
// Duplicate run_id supersession
// ---------------------------------------------------------------

/// Like `common::raw_login`, but sends an explicit `run_id` and a
/// MILLISECOND timestamp. The shared helper hardcodes `run_id: None` and
/// second-precision timestamps, both of which the supersession test needs
/// to differ from: the server's ReplayTable deliberately admits a
/// seconds-precision duplicate (Go frpc reconnects within the same second)
/// but rejects an identical millisecond (timestamp, run_id) pair as a
/// replay — so callers must use a DIFFERENT millisecond timestamp for each
/// login with the same run_id.
async fn raw_login_with_run_id(
    addr: std::net::SocketAddr,
    run_id: &str,
    timestamp_ms: i64,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to {}: {}", addr, e).into()))?;

    let key = auth::generate_token(TEST_TOKEN, timestamp_ms);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: Some(run_id.to_string()),
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(timestamp_ms),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));

    let mut io = IoStream::Tcp(stream);
    write_msg_v1(&mut io, &login).await?;

    match read_msg_v1(&mut io).await? {
        FrpMessage::LoginResp(resp) => {
            // Wrap in AES-128-CFB encryption (matches server post-login),
            // exactly as common::raw_login does.
            let enc_key = encryption::derive_key(TEST_TOKEN);
            let mut encrypted = io.into_encrypted(enc_key)?;

            // Drain the pool_count ReqWorkConn messages the server sends
            // immediately after LoginResp (mirrors common::raw_login;
            // pool_count is fixed at 1 above).
            for _ in 0..1 {
                match read_msg_v1(&mut encrypted).await {
                    Ok(FrpMessage::ReqWorkConn(_)) => continue,
                    Ok(_) => break,
                    Err(_) => break,
                }
            }
            Ok((encrypted, resp))
        }
        other => Err(frp_core::Error::Protocol(
            format!(
                "expected LoginResp, got type byte {:?}",
                other.v1_type_byte()
            )
            .into(),
        )),
    }
}

/// Control-plane supersession: a second Login with the same run_id must
/// tear down the first control connection and route that run_id to the new
/// connection (Go frp control.go lifecycle — the old handler receives a
/// Shutdown and its socket is dropped).
#[tokio::test]
async fn test_duplicate_run_id_supersedes_old_control() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // First login with an explicit run_id at millisecond ts.
    let (mut first, resp1) = raw_login_with_run_id(addr, "r1", ts)
        .await
        .expect("first login should succeed");
    assert!(
        resp1.error.is_none(),
        "first login should succeed, got: {:?}",
        resp1.error
    );

    // Second login with the SAME run_id at ts + 1 (fresh auth key for the
    // new timestamp — an identical (ts, run_id) pair would be rejected as
    // a replay, so the timestamp MUST differ). Wrapped in a 10s timeout so
    // a handoff-barrier deadlock fails the test instead of hanging the
    // whole suite.
    let (mut second, resp2) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        raw_login_with_run_id(addr, "r1", ts + 1),
    )
    .await
    .expect("superseding login hung (handoff blocked?)")
    .expect("second login with same run_id should succeed");
    assert!(
        resp2.error.is_none(),
        "second login should succeed, got: {:?}",
        resp2.error
    );

    // The FIRST control connection must be torn down within 5s. Loop on
    // reads: Ok(frame) = stray frame flushed before the close (skip),
    // Err = EOF/reset = teardown. A 5s read timeout elapsing instead
    // means the old control was never superseded.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while read_msg_v1(&mut first).await.is_ok() {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "old control connection was not closed within 5s of the superseding login"
    );

    // The NEW connection must be live: Ping → Pong with no error.
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    write_msg_v1(&mut second, &ping)
        .await
        .expect("send ping on new control");
    match read_msg_v1(&mut second).await.expect("read pong") {
        FrpMessage::Pong(pong) => assert!(
            pong.error.is_none(),
            "expected clean Pong on new control, got: {:?}",
            pong.error
        ),
        other => panic!("expected Pong, got type byte: {:?}", other.v1_type_byte()),
    }
}

/// Supersession after a burst: the old control completes a burst of 200
/// proxy registrations, then the superseding login lands. The old control
/// must still be torn down promptly — the Shutdown/teardown must not hang
/// behind the 200 registered proxies — and the NEW control must be fully
/// functional (NewProxyResp resolves, Ping→Pong clean).
#[tokio::test]
async fn test_duplicate_run_id_supersedes_under_proxy_burst() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let mk_burst_proxy = |i: usize| {
        FrpMessage::NewProxy(Box::new(msg::NewProxy {
            proxy_name: format!("burst-{i}"),
            proxy_type: "tcp".into(),
            local_str: Some("127.0.0.1:9876".into()),
            remote_port: Some(0), // auto-assign
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
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        }))
    };

    // First login with an explicit run_id at millisecond ts.
    let (mut first, resp1) = raw_login_with_run_id(addr, "burst-r1", ts)
        .await
        .expect("first login should succeed");
    assert!(
        resp1.error.is_none(),
        "first login should succeed, got: {:?}",
        resp1.error
    );

    // Burst of proxy registrations on the OLD control.
    for i in 0..200 {
        write_msg_v1(&mut first, &mk_burst_proxy(i))
            .await
            .expect("send NewProxy");
        match read_msg_v1(&mut first).await.expect("read NewProxyResp") {
            FrpMessage::NewProxyResp(r) => {
                assert!(
                    r.error.is_none(),
                    "burst registration {i} failed: {:?}",
                    r.error
                );
            }
            other => panic!(
                "expected NewProxyResp, got type byte {:?}",
                other.v1_type_byte()
            ),
        }
    }

    // Second login with the SAME run_id (fresh timestamp ts + 1). Wrapped
    // in a 10s timeout: the supersession handoff must not be blocked
    // behind the old control's in-flight work.
    let (mut second, resp2) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        raw_login_with_run_id(addr, "burst-r1", ts + 1),
    )
    .await
    .expect("superseding login hung behind the burst (handoff blocked?)")
    .expect("second login with same run_id should succeed");
    assert!(
        resp2.error.is_none(),
        "second login should succeed, got: {:?}",
        resp2.error
    );

    // The OLD control must be torn down within 5s despite the burst.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while read_msg_v1(&mut first).await.is_ok() {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "old control connection was not closed within 5s of the superseding login (under burst)"
    );

    // The NEW control must be fully functional: a fresh registration gets
    // its NewProxyResp.
    write_msg_v1(&mut second, &mk_burst_proxy(999))
        .await
        .expect("send NewProxy on new control");
    match read_msg_v1(&mut second)
        .await
        .expect("read NewProxyResp on new control")
    {
        FrpMessage::NewProxyResp(r) => {
            assert!(
                r.error.is_none(),
                "post-supersession registration failed: {:?}",
                r.error
            );
        }
        other => panic!(
            "expected NewProxyResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }

    // And Ping → Pong with no error.
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    write_msg_v1(&mut second, &ping)
        .await
        .expect("send ping on new control");
    match read_msg_v1(&mut second).await.expect("read pong") {
        FrpMessage::Pong(pong) => assert!(
            pong.error.is_none(),
            "expected clean Pong on new control, got: {:?}",
            pong.error
        ),
        other => panic!("expected Pong, got type byte: {:?}", other.v1_type_byte()),
    }
}
