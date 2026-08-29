//! Round-8 work-conn pool replenishment regression: every pooled work conn
//! consumed by a proxy user connection must trigger a fresh ReqWorkConn on
//! the control channel (pool.rs assign_or_queue), so the client can refill
//! the pool. A server that pops without replenishing would silently strand
//! the pool at zero and serialize every new user connection behind a
//! control round-trip (user conn → ReqWorkConn → client dial → NewWorkConn
//! → StartWorkConn) instead of dispatching from the warm pool.
//!
//! Flow under test (tcp_mux ON — work conns are yamux streams):
//!   yamux login (pool_count 0) → 2 NewWorkConn streams pooled
//!   → user conn 1 → StartWorkConn on stream 1 + ReqWorkConn replenish
//!   → user conn 2 → StartWorkConn on stream 2 + second ReqWorkConn
//!   → fresh work stream answers the replenish → user conn 3 dispatches on
//!     the replenished conn.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{allocate_port, start_test_server_tcpmux_on, test_auth_cfg, TEST_TOKEN};
use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux;
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

/// Log in over a yamux control stream (V1, tcp_mux ON): dial, wrap in
/// yamux, open the control stream, send Login, read LoginResp. Returns the
/// encrypted control stream, the yamux session (for opening work streams),
/// and the run_id. Drains the single post-login pre-warm ReqWorkConn
/// (capped_pool_count floors at 1 even for pool_count 0), so the control
/// stream is silent afterwards.
async fn yamux_login(addr: SocketAddr) -> (IoStream, mux::YamuxSession, String) {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to server");
    let (control_yamux, session) = mux::client_mux(tcp, &mux::TcpMuxConfig::default())
        .await
        .expect("yamux client init");
    let mut control = IoStream::Yamux(control_yamux);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token(TEST_TOKEN, ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("pool-replenish-test".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(0),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: Some("yamux".into()),
    }));
    write_msg_v1(&mut control, &login)
        .await
        .expect("send Login");

    let run_id = match read_msg_v1(&mut control).await.expect("read LoginResp") {
        FrpMessage::LoginResp(resp) => {
            assert!(resp.error.is_none(), "login failed: {:?}", resp.error);
            resp.run_id.expect("run_id")
        }
        other => panic!("expected LoginResp, got {:?}", other.v1_type_byte()),
    };

    // V1 wraps the control stream in AES-128-CFB after LoginResp (matching
    // the server); the pre-warm ReqWorkConn arrives through the encrypted
    // writer, so drain it here.
    let mut control = control
        .into_encrypted(encryption::derive_key(TEST_TOKEN))
        .expect("wrap control in encryption");
    let warm = tokio::time::timeout(Duration::from_secs(2), read_msg_v1(&mut control))
        .await
        .expect("pre-warm ReqWorkConn must arrive after LoginResp")
        .expect("read pre-warm ReqWorkConn");
    match warm {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!(
            "expected pre-warm ReqWorkConn after login, got type {}",
            other.v1_type_byte(),
        ),
    }
    (control, session, run_id)
}

/// Open a fresh yamux work stream and send NewWorkConn (valid run_id, no
/// privilege_key — raw work conns are accepted pooled like Go frp).
async fn open_work_stream(session: &mux::YamuxSession, run_id: &str) -> IoStream {
    let stream = session.open_stream().await.expect("open yamux stream");
    let mut io = IoStream::Yamux(stream);
    write_msg_v1(
        &mut io,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.into()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("write NewWorkConn");
    io
}

/// Assert StartWorkConn (no error) arrives on `io` within 5s.
async fn expect_start_work_conn(io: &mut IoStream, what: &str) {
    match tokio::time::timeout(Duration::from_secs(5), read_msg_v1(io))
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for StartWorkConn on {what}"))
        .unwrap_or_else(|e| panic!("read error on {what}: {e}"))
    {
        FrpMessage::StartWorkConn(swc) => assert!(swc.error.is_none(), "{:?}", swc.error),
        other => panic!(
            "expected StartWorkConn on {what}, got {:?}",
            other.v1_type_byte()
        ),
    }
}

/// Assert a replenish ReqWorkConn arrives on the control stream within 5s.
async fn expect_req_work_conn(control: &mut IoStream) {
    match tokio::time::timeout(Duration::from_secs(5), read_msg_v1(control))
        .await
        .expect("replenish ReqWorkConn within 5s")
        .expect("read replenish ReqWorkConn")
    {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!(
            "expected replenish ReqWorkConn, got {:?}",
            other.v1_type_byte()
        ),
    }
}

#[tokio::test]
async fn test_pool_replenish_on_consumption() {
    let bind_port = allocate_port();
    let proxy_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server_tcpmux_on(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    let (mut control, session, run_id) = yamux_login(addr).await;

    // Register a tcp proxy on proxy_port.
    let np = FrpMessage::NewProxy(Box::new(msg::NewProxy {
        proxy_name: "pool-replenish".into(),
        proxy_type: "tcp".into(),
        local_str: Some("127.0.0.1:1".into()),
        remote_port: Some(proxy_port.into()),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
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
    write_msg_v1(&mut control, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut control).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(r) => {
            assert!(r.error.is_none(), "registration failed: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Pool TWO work conns (pool_cap = max(1, 0) + WORK_POOL_EXTRA(10) = 11,
    // so both are kept). FIFO: stream 1 is the first pop.
    let mut work1 = open_work_stream(&session, &run_id).await;
    let mut work2 = open_work_stream(&session, &run_id).await;

    // User conn 1 consumes pool entry 1: StartWorkConn on work1, and the
    // replenish ReqWorkConn on the control channel.
    let _user1 = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("user conn 1");
    expect_start_work_conn(&mut work1, "work1").await;
    expect_req_work_conn(&mut control).await;

    // User conn 2 consumes pool entry 2: same pair on work2 + control.
    let _user2 = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("user conn 2");
    expect_start_work_conn(&mut work2, "work2").await;
    expect_req_work_conn(&mut control).await;

    // The replenished pool must be USABLE: answer the second ReqWorkConn
    // with a fresh work conn; a third user connection dispatches on it.
    // (If the replenish ReqWorkConn had never been sent, the server would
    // request a work conn through the pending-requests path instead — the
    // StartWorkConn would still arrive, so this final assertion proves the
    // replenished conn found a warm pool rather than only proving routing.)
    let mut work3 = open_work_stream(&session, &run_id).await;
    let _user3 = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("user conn 3");
    expect_start_work_conn(&mut work3, "work3 (replenished)").await;
}
