//! HTTP vhost backend response-header timeout (504 Gateway Timeout).
//!
//! Go frp v0.70.1's HTTP reverse proxy waits VhostHTTPTimeout (default 60s)
//! for the backend's response headers after the work connection is assigned;
//! on timeout it returns `504 Gateway Timeout` with no body. frp-rs mirrors
//! this on the byte-level bridge: the first read on the work→user direction
//! is bounded by `vhost_http_timeout`, and a timeout writes the 504 line to
//! the client.

mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

fn http_proxy(name: &str, domains: Vec<String>) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "http".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:8080".into()),
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

#[tokio::test]
async fn test_vhost_http_504_on_backend_silence() {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        // Short response-header timeout so the test completes quickly.
        vhost_http_timeout: 1,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let vhost_addr: SocketAddr = format!("127.0.0.1:{}", vhost_port).parse().unwrap();

    // Provider registers an HTTP proxy (no response headers).
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let np = FrpMessage::NewProxy(Box::new(http_proxy(
        "http-504",
        vec!["slow.example.com".into()],
    )));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "registration failed: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Pool a work conn — the backend will accept the forwarded request but
    // never send a response.
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn");
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

    // Client sends a request to the vhost port.
    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: slow.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send request");

    // Backend receives StartWorkConn (with the forwarded head as pre-read).
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "http-504");
            assert!(swc.error.is_none(), "{:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }

    // Backend stays silent — the client must receive a 504 after ~1s.
    let mut resp = vec![0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), client.read(&mut resp))
        .await
        .expect("client should be answered within 3s")
        .expect("read response");
    let resp_text = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_text.starts_with("HTTP/1.1 504"),
        "expected 504, got: {resp_text:?}"
    );
    assert!(
        resp_text.contains("504 Gateway Timeout"),
        "expected Gateway Timeout text: {resp_text:?}"
    );
}
