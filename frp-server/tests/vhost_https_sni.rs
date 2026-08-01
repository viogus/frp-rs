//! HTTPS vhost SNI passthrough test.
//!
//! Go frp compat (`pkg/util/vhost/https.go`): frps must NOT terminate TLS for
//! HTTPS vhosts. It reads the ClientHello SNI, routes by SNI, and forwards
//! the original encrypted bytes to the matching frpc HTTPS proxy. This test
//! asserts the backend (work conn) receives the raw TLS bytes.

mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

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
        #[cfg(feature = "vnet")]
        advertise_subnet: None,
        #[cfg(feature = "vnet")]
        vnet_ip: None,
        #[cfg(feature = "vnet")]
        vnet_netmask: None,
        #[cfg(feature = "vnet")]
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
    let https_addr: SocketAddr = format!("127.0.0.1:{}", vhost_https_port)
        .parse()
        .unwrap();

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
            let n = work_conn.read(&mut chunk).await.expect("read forwarded bytes");
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
