//! HTTPS vhost SNI passthrough test.
//!
//! Go frp compat (`pkg/util/vhost/https.go`): frps must NOT terminate TLS for
//! HTTPS vhosts. It reads the ClientHello SNI, routes by SNI, and forwards
//! the original encrypted bytes to the matching frpc HTTPS proxy. This test
//! asserts the backend (work conn) receives the raw TLS bytes.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg, TEST_TOKEN};
use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::{dial_server, DialOptions};

fn test_cert_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("frp-core");
    p.push("tests");
    p.push("certs");
    p
}

/// Build a minimal TLS 1.2 ClientHello with SNI (same construction as the
/// vhost.rs unit tests — byte-exact lengths matter for SNI extraction).
fn client_hello_with_sni(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let name_bytes_len = name.len();

    let sni_ext_data_len: u16 = 1 + 2 + name_bytes_len as u16; // name_type + name_len + name
    let sni_ext_list_len: u16 = sni_ext_data_len; // just one ServerName
    let sni_ext_len: u16 = 2 + sni_ext_list_len; // list_len + list
    let extensions_len: u16 = 4 + sni_ext_len; // ext_type + ext_len + ext_data
                                               // ClientHello body: version(2) + random(32) + sid_len(1) + sid(0)
                                               //   + cs_len(2) + cs_data(2) + cm_len(1) + cm_data(1) + ext_len(2) + ext_data
    let ch_body_len: u16 = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let hs_len: u32 = ch_body_len as u32;
    // record = hs_type(1) + hs_len(3) + ch_body
    let record_len: u16 = 4 + ch_body_len;

    let mut bytes = Vec::new();
    // TLS record header
    bytes.extend_from_slice(&[0x16, 0x03, 0x01]); // content_type + version
    bytes.extend_from_slice(&record_len.to_be_bytes());

    // Handshake header: type(1) + length(3 bytes, uint24)
    bytes.push(0x01); // ClientHello
    bytes.push((hs_len >> 16) as u8);
    bytes.push((hs_len >> 8) as u8);
    bytes.push(hs_len as u8);

    // ClientHello body
    bytes.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    bytes.extend_from_slice(&[0x00u8; 32]); // Random
    bytes.push(0x00); // Session ID: empty
    bytes.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    bytes.extend_from_slice(&[0x01, 0x00]); // compression: null
    bytes.extend_from_slice(&extensions_len.to_be_bytes());

    // SNI extension
    bytes.extend_from_slice(&[0x00, 0x00]); // type = server_name
    bytes.extend_from_slice(&sni_ext_len.to_be_bytes());
    bytes.extend_from_slice(&sni_ext_list_len.to_be_bytes()); // ServerNameList
    bytes.push(0x00); // name_type = host_name
    bytes.extend_from_slice(&(name_bytes_len as u16).to_be_bytes());
    bytes.extend_from_slice(name);

    bytes
}

fn https_group_proxy(name: &str, group: &str, group_key: &str, domain: &str) -> NewProxy {
    let mut np = https_proxy(name, vec![domain.into()]);
    np.group = Some(group.into());
    np.group_key = Some(group_key.into());
    np
}

fn https_proxy(name: &str, domains: Vec<String>) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "https".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:443".into()),
        remote_port: Some(0),
        custom_domains: Some(domains),
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

/// The HTTPS vhost listener routes by SNI and forwards the raw TLS bytes —
/// it must NOT perform a TLS handshake itself.
#[test]
fn test_hello_construction_extracts_sni() {
    let hello = client_hello_with_sni("example.com");
    assert_eq!(hello[0], 0x16, "handshake record type");
    let sni = frp_server::vhost::extract_sni_from_client_hello(&hello);
    assert_eq!(sni.as_deref(), Some("example.com"), "SNI must be extracted");
}

#[tokio::test]
async fn test_https_vhost_sni_passthrough() {
    let bind_port = allocate_port();
    let vhost_https_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_https_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let https_addr: SocketAddr = format!("127.0.0.1:{}", vhost_https_port).parse().unwrap();

    // Provider logs in and registers an HTTPS proxy for example.com.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(Box::new(https_proxy(
        "https-test",
        vec!["example.com".into()],
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "https proxy registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Pool a work connection so the bridge can start immediately.
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");

    // External client sends a TLS ClientHello with SNI example.com.
    let mut client = tokio::net::TcpStream::connect(https_addr)
        .await
        .expect("connect to https vhost port");
    let hello = client_hello_with_sni("example.com");
    client.write_all(&hello).await.expect("send ClientHello");

    // Backend side: StartWorkConn, then the raw TLS bytes (passthrough).
    match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn on work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "https-test");
            assert!(
                swc.error.is_none(),
                "StartWorkConn should not have error: {:?}",
                swc.error
            );
        }
        other => panic!("expected StartWorkConn, got: {:?}", other.v1_type_byte()),
    }

    // Read the forwarded bytes: must start with the TLS record header and
    // contain the raw ClientHello (not decrypted).
    let mut forwarded = Vec::new();
    let mut chunk = [0u8; 512];
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let n = work_conn
                .read(&mut chunk)
                .await
                .expect("read forwarded bytes");
            if n == 0 {
                break;
            }
            forwarded.extend_from_slice(&chunk[..n]);
            if forwarded.len() >= hello.len() {
                break;
            }
        }
    })
    .await
    .expect("timeout waiting for forwarded TLS bytes");

    assert!(
        forwarded.starts_with(&hello),
        "backend must receive the raw ClientHello bytes (SNI passthrough), got prefix: {:?}",
        &forwarded[..forwarded.len().min(16)]
    );

    println!("HTTPS vhost SNI passthrough verified: raw TLS bytes forwarded to backend");
    drop(client);
    drop(provider);
}

/// M11 regression: the main port must NEVER parse the TLS ClientHello (Go
/// parity — Go's main port reads a single 0x17/0x16 byte for TLS detection,
/// pkg/util/net/tls.go; HTTPS proxies are served exclusively on
/// vhost_https_port). The old SNI sniff on the main port hijacked frpc TLS
/// control connections on a route collision: with an https proxy registered
/// under a wildcard domain covering the server hostname, a TLS control
/// login's SNI matched the wildcard route and the connection was diverted to
/// the https backend instead of being accepted as a control connection.
#[tokio::test]
async fn test_tls_control_login_not_hijacked_by_https_wildcard() {
    let bind_port = allocate_port();
    let vhost_https_port = allocate_port();
    let cert_dir = test_cert_dir();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_https_port,
        tls_enable: true,
        tls_cert_file: cert_dir.join("server.crt").to_string_lossy().into(),
        tls_key_file: cert_dir.join("server.key").to_string_lossy().into(),
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    // Provider registers an https proxy under a BARE wildcard: it covers the
    // server hostname ("localhost"/"127.0.0.1"), so the old main-port SNI
    // sniff would have routed the TLS control login's ClientHello here.
    let (mut provider, _resp) = login_with_test_token(addr).await.expect("provider login");
    let np = FrpMessage::NewProxy(Box::new(https_proxy("wildcard-https", vec!["*".into()])));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "wildcard https proxy registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // TLS control login to the MAIN port: must be accepted as a control
    // connection (LoginResp without error), NOT diverted to the https route.
    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        tls_enable: true,
        tls_server_name: "localhost".into(),
        tls_ca_file: Some(cert_dir.join("ca.crt").to_string_lossy().into()),
        ..Default::default()
    };
    let mut io = dial_server(&opts).await.expect("TLS control dial");
    assert_eq!(io.debug_name(), "IoStream::Tls");

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token(TEST_TOKEN, ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("tls-not-hijacked".into()),
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
    match io.read_v1_frame().await.expect("read LoginResp over TLS") {
        FrpMessage::LoginResp(r) => {
            assert!(
                r.error.is_none(),
                "TLS control login must succeed despite the https wildcard route: {:?}",
                r.error
            );
            assert!(r.run_id.is_some(), "expected run_id");
        }
        other => panic!("expected LoginResp, got: {:?}", other.v1_type_byte()),
    }

    drop(io);
    drop(provider);
}

/// HTTPS group SNI fan-out (round-10 kind-keyed registry e2e — GAP4).
/// Two https proxies sharing one group + group_key + custom_domains register
/// on the HTTPS vhost kind; an external TLS client's ClientHello (SNI
/// app.example.com) is dispatched round-robin across the members (Go hands
/// each conn to whichever member accepts first; frp-rs round-robins over the
/// https-kind members). Each dispatch must land on a pooled work conn of ONE
/// member — StartWorkConn names the winner and the raw ClientHello follows.
#[tokio::test]
async fn test_https_group_sni_fan_out_round_robin() {
    let bind_port = allocate_port();
    let vhost_https_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_https_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let https_addr: SocketAddr = format!("127.0.0.1:{vhost_https_port}").parse().unwrap();

    let (mut ctl_a, resp_a) = login_with_test_token(addr).await.expect("login A");
    let run_id_a = resp_a.run_id.expect("run_id A");
    let np = FrpMessage::NewProxy(Box::new(https_group_proxy(
        "grp-a",
        "webgrp",
        "secret-key",
        "app.example.com",
    )));
    write_msg_v1(&mut ctl_a, &np)
        .await
        .expect("send NewProxy A");
    match read_msg_v1(&mut ctl_a).await.expect("NewProxyResp A") {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "first member rejected: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    let (mut ctl_b, resp_b) = login_with_test_token(addr).await.expect("login B");
    let run_id_b = resp_b.run_id.expect("run_id B");
    let np = FrpMessage::NewProxy(Box::new(https_group_proxy(
        "grp-b",
        "webgrp",
        "secret-key",
        "app.example.com",
    )));
    write_msg_v1(&mut ctl_b, &np)
        .await
        .expect("send NewProxy B");
    match read_msg_v1(&mut ctl_b).await.expect("NewProxyResp B") {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "second member rejected: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    let hello = client_hello_with_sni("app.example.com");
    let mut served_a = 0usize;
    let mut served_b = 0usize;
    let mut last_winner: Option<&str> = None;
    for round in 0..4 {
        // The kind-keyed registry round-robins over the members in
        // registration order (choose_endpoint: index fetch_add from 0), so
        // round r dispatches to members[r % 2] = grp-a, grp-b, grp-a, grp-b.
        // Open ONE pooled work conn under the expected member's run_id —
        // the server pops it and StartWorkConn names that member. (The other
        // member's control has no pooled conn and the server would send
        // ReqWorkConn into the void, so only the expected member's conn may
        // exist when the hello arrives.)
        let expected = if round % 2 == 0 { "grp-a" } else { "grp-b" };
        let expected_run_id = if round % 2 == 0 {
            run_id_a.clone()
        } else {
            run_id_b.clone()
        };
        let mut work = tokio::net::TcpStream::connect(addr)
            .await
            .expect("pool work conn");
        write_msg_v1(
            &mut work,
            &FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: Some(expected_run_id),
                timestamp: None,
                privilege_key: None,
            }),
        )
        .await
        .expect("send NewWorkConn");
        let (mut rd, _wr) = work.into_split();

        let mut client = tokio::net::TcpStream::connect(https_addr)
            .await
            .expect("connect to https vhost port");
        client.write_all(&hello).await.expect("send ClientHello");

        // The dispatch must land on THIS conn, naming the expected member.
        let frame = tokio::time::timeout(std::time::Duration::from_secs(4), read_msg_v1(&mut rd))
            .await
            .unwrap_or_else(|_| {
                panic!("round {round}: dispatch to {expected} timed out (no StartWorkConn)")
            })
            .unwrap_or_else(|e| panic!("round {round}: read StartWorkConn errored: {e}"));
        match frame {
            FrpMessage::StartWorkConn(swc) => {
                assert!(
                    swc.error.is_none(),
                    "round {round}: dispatch to {expected} rejected: {:?}",
                    swc.error
                );
                assert_eq!(
                    swc.proxy_name, expected,
                    "round {round}: wheel must dispatch to the next member in registration order"
                );
            }
            other => panic!(
                "round {round}: expected StartWorkConn for {expected}, got type {}",
                other.v1_type_byte()
            ),
        }

        // The dispatched conn carries the raw ClientHello (SNI passthrough).
        let mut forwarded = Vec::new();
        let mut chunk = [0u8; 512];
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let n = rd.read(&mut chunk).await.expect("read forwarded");
                if n == 0 {
                    break;
                }
                forwarded.extend_from_slice(&chunk[..n]);
                if forwarded.len() >= hello.len() {
                    break;
                }
            }
        })
        .await
        .expect("timeout waiting for forwarded TLS bytes");
        assert!(
            forwarded.starts_with(&hello),
            "round {round}: member {expected} must receive the raw ClientHello, got prefix {:?}",
            &forwarded[..forwarded.len().min(16)]
        );

        let winner: &str = if round % 2 == 0 { "A" } else { "B" };
        if winner == "A" {
            served_a += 1;
        } else {
            served_b += 1;
        }
        if let Some(prev) = last_winner {
            assert_ne!(
                prev, winner,
                "round {round}: dispatch must alternate members"
            );
        }
        last_winner = Some(winner);
        drop(client);
    }
    assert!(served_a >= 1, "member A never served: {served_a}");
    assert!(served_b >= 1, "member B never served: {served_b}");
}
