mod common;

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage, NewProxy, NewWorkConn};
use frp_core::transport::{DialOptions, IoStream};
use frp_core::v2_handshake;
use frp_core::mux;
use frp_server::service::Service;
use common::allocate_port;

/// Full end-to-end V2 protocol test: Rust frps vs Rust frpc (in-process).
///
/// Verifies the V2 wire protocol with tcp_mux (yamux):
/// 1. Client connects, writes V2 magic, wraps in yamux
/// 2. V2 ClientHello/ServerHello handshake on the yamux control stream
/// 3. Login, proxy registration on yamux control stream
/// 4. Work connections over new yamux streams
/// 5. End-to-end echo test through the TCP proxy
///
/// The ordering (yamux BEFORE handshake) matches the Go frp v0.69.1 flow:
/// the server wraps the accepted connection in yamux on detection of V2
/// magic, so the client must do the same before the handshake.
#[tokio::test]
async fn test_v2_tcp_proxy() {
    let bind_port = allocate_port();
    let echo_port = allocate_port();

    // ---- start echo TCP server ----
    let echo_listener =
        tokio::net::TcpListener::bind(format!("127.0.0.1:{echo_port}")).await.unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match echo_listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // ---- start frps (tcp_mux defaults to true in ServerTransportConfig) ----
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        ..Default::default()
    };
    let service = Service::new(cfg, None).await.expect("create service");
    let _server_handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ---- V2 client: dial → yamux → handshake ----
    // dial_server writes V2 magic, returns IoStream::Tcp
    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        v2: true,
        ..Default::default()
    };
    let raw_stream = frp_core::transport::dial_server(&opts)
        .await
        .expect("dial server");

    // Extract TCP stream and wrap in yamux BEFORE handshake.
    // Server wraps in yamux on V2 detection, so client must match.
    let tcp_stream = match raw_stream {
        IoStream::Tcp(s) => s,
        other => panic!(
            "expected IoStream::Tcp after V2 dial, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    let (control_yamux, yamux_session) =
        mux::client_mux(tcp_stream, &mux::TcpMuxConfig::default())
            .await
            .expect("yamux client init");
    let mut control = IoStream::Yamux(control_yamux);

    // V2 ClientHello / ServerHello handshake on the yamux control stream
    v2_handshake::v2_handshake_client(&mut control, "tcp", false, true, false /* with_crypto */)
        .await
        .expect("V2 handshake");

    // ---- Login via V2 on yamux control stream ----
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let login = FrpMessage::Login(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("v2-test-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: Some("yamux".into()),
    });
    control
        .write_v2_frame(&login)
        .await
        .expect("send Login");

    let resp = control.read_v2_frame().await.expect("read LoginResp");
    let run_id = match resp {
        FrpMessage::LoginResp(r) => {
            assert!(
                r.error.is_none(),
                "Login should succeed, got error: {:?}",
                r.error
            );
            r.run_id.expect("run_id should be set")
        }
        other => panic!("expected LoginResp, got v2 type_id: {:?}", other.v2_type_id()),
    };
    println!("V2 login succeeded, run_id: {run_id}");

    // ---- Wrap control stream in AES-128-CFB encryption (matching server post-login) ----
    let enc_key = encryption::derive_key(""); // empty token = no auth
    let mut control = control.into_encrypted(enc_key);

    // ---- Register TCP proxy ----
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "v2-tcp-test".into(),
        proxy_type: "tcp".into(),
        local_str: Some(format!("127.0.0.1:{echo_port}")),
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
    });
    control
        .write_v2_frame(&np)
        .await
        .expect("send NewProxy");

    let proxy_resp = control.read_v2_frame().await.expect("read NewProxyResp");
    let proxy_port: u16 = match proxy_resp {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(
                r.error.is_none(),
                "NewProxy should succeed, got error: {:?}",
                r.error
            );
            let addr = r
                .remote_addr
                .as_ref()
                .expect("remote_addr should be set");
            addr.trim_start_matches(':')
                .parse()
                .expect("remote_addr should contain port")
        }
        other => panic!(
            "expected NewProxyResp, got v2 type_id: {:?}",
            other.v2_type_id()
        ),
    };
    println!("TCP proxy 'v2-tcp-test' registered on port {proxy_port}");

    // ---- Open work connection over new yamux stream ----
    let work_yamux = yamux_session
        .open_stream()
        .await
        .expect("open yamux stream for work conn");

    let mut work_io = IoStream::Yamux(work_yamux);
    let nwc = FrpMessage::NewWorkConn(NewWorkConn {
        run_id: Some(run_id.clone()),
        timestamp: None,
        privilege_key: None,
    });
    work_io
        .write_v2_frame(&nwc)
        .await
        .expect("send NewWorkConn");

    // ---- Connect user to proxy port (triggers StartWorkConn on server) ----
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let mut user = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy port");
    println!("User connected to proxy port {proxy_port}");

    // ---- Read StartWorkConn from work yamux stream ----
    let swc = work_io.read_v2_frame().await.expect("read StartWorkConn");
    match &swc {
        FrpMessage::StartWorkConn(s) => {
            assert!(
                s.error.is_none(),
                "StartWorkConn should not have error, got: {:?}",
                s.error
            );
            assert_eq!(s.proxy_name, "v2-tcp-test");
            println!("Received StartWorkConn for proxy '{}'", s.proxy_name);
        }
        other => panic!(
            "expected StartWorkConn, got v2 type_id: {:?}",
            other.v2_type_id()
        ),
    }

    // ---- Bridge work yamux stream ↔ echo server ----
    let mut work_stream = match work_io {
        IoStream::Yamux(s) => s,
        _ => unreachable!("work_io must be IoStream::Yamux"),
    };
    let mut echo = tokio::net::TcpStream::connect(format!("127.0.0.1:{echo_port}"))
        .await
        .expect("connect to echo server");

    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut work_stream, &mut echo).await;
    });

    // ---- Echo test: write "hello v2", read it back ----
    user.write_all(b"hello v2")
        .await
        .expect("write to proxy");
    println!("Wrote 'hello v2' to proxy port");

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), user.read(&mut buf))
        .await
        .expect("timeout waiting for echo response")
        .expect("read from proxy");

    assert_eq!(
        &buf[..n],
        b"hello v2",
        "echo mismatch: {}",
        String::from_utf8_lossy(&buf[..n])
    );
    println!(
        "Echo test passed: {}",
        String::from_utf8_lossy(&buf[..n])
    );

    // Cleanup
    drop(control);
    echo_task.abort();
}

/// Quick smoke test: V2 login + Ping/Pong on raw TCP (no yamux, no tcp_mux).
/// Verifies that encryption after login works correctly with V2 framing
/// before attempting the more complex end-to-end proxy test.
#[tokio::test]
async fn test_v2_ping_pong_raw_tcp() {
    let bind_port = allocate_port();

    // Start frps WITHOUT tcp_mux (raw TCP + V2 framing)
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let service = Service::new(cfg, None).await.expect("create service");
    let _server_handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Dial with V2
    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        v2: true,
        ..Default::default()
    };
    let mut stream = frp_core::transport::dial_server(&opts)
        .await
        .expect("dial server");

    // V2 handshake on raw TCP (no yamux)
    v2_handshake::v2_handshake_client(&mut stream, "tcp", false, false, false /* with_crypto */)
        .await
        .expect("V2 handshake");

    // Login
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let login = FrpMessage::Login(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("v2-smoke".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: None,
    });
    stream
        .write_v2_frame(&login)
        .await
        .expect("send Login");

    let resp = stream.read_v2_frame().await.expect("read LoginResp");
    match &resp {
        FrpMessage::LoginResp(r) => {
            assert!(
                r.error.is_none(),
                "Login error: {:?}",
                r.error
            );
        }
        other => panic!("expected LoginResp, got {:?}", other.v2_type_id()),
    }
    println!("V2 login OK (raw TCP)");

    // Wrap in encryption
    let enc_key = encryption::derive_key("");
    let mut stream = stream.into_encrypted(enc_key);

    // Ping
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    stream.write_v2_frame(&ping).await.expect("send Ping");
    println!("Ping sent (encrypted)");

    // Pong
    let pong = stream.read_v2_frame().await.expect("read Pong");
    match &pong {
        FrpMessage::Pong(p) => {
            assert!(p.error.is_none(), "Pong error: {:?}", p.error);
            println!("Pong received OK");
        }
        other => panic!("expected Pong, got {:?}", other.v2_type_id()),
    }

    drop(stream);
}

/// V2 Ping/Pong over yamux (tcp_mux=true). Verifies encryption works
/// through the yamux control stream before the full proxy test.
#[tokio::test]
async fn test_v2_ping_pong_yamux() {
    let bind_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        ..Default::default()
    };
    let service = Service::new(cfg, None).await.expect("create service");
    let _server_handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        v2: true,
        ..Default::default()
    };
    let raw_stream = frp_core::transport::dial_server(&opts)
        .await
        .expect("dial server");

    // Wrap in yamux FIRST (matching server)
    let tcp_stream = match raw_stream {
        IoStream::Tcp(s) => s,
        other => panic!("expected IoStream::Tcp, got {:?}", std::mem::discriminant(&other)),
    };
    let (control_yamux, _yamux_session) =
        mux::client_mux(tcp_stream, &mux::TcpMuxConfig::default())
            .await
            .expect("yamux client init");
    let mut control = IoStream::Yamux(control_yamux);

    // V2 handshake on yamux stream
    v2_handshake::v2_handshake_client(&mut control, "tcp", false, true, false /* with_crypto */)
        .await
        .expect("V2 handshake");

    // Login
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let login = FrpMessage::Login(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("v2-yamux".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: Some("yamux".into()),
    });
    control.write_v2_frame(&login).await.expect("send Login");

    let resp = control.read_v2_frame().await.expect("read LoginResp");
    match &resp {
        FrpMessage::LoginResp(r) => {
            assert!(r.error.is_none(), "Login error: {:?}", r.error);
        }
        other => panic!("expected LoginResp, got {:?}", other.v2_type_id()),
    }
    println!("V2 login OK (yamux)");

    // Wrap in encryption
    let enc_key = encryption::derive_key("");
    let mut control = control.into_encrypted(enc_key);

    // Ping
    let ping = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    control.write_v2_frame(&ping).await.expect("send Ping");
    println!("Ping sent (encrypted, yamux)");

    // Pong
    let pong = control.read_v2_frame().await.expect("read Pong");
    match &pong {
        FrpMessage::Pong(p) => {
            assert!(p.error.is_none(), "Pong error: {:?}", p.error);
            println!("Pong received OK (encrypted, yamux)");
        }
        other => panic!("expected Pong, got {:?}", other.v2_type_id()),
    }
}
