//! HTTP vhost reverse-proxy behavior tests:
//! - X-Forwarded-For is injected with the client IP (Go httputil.ReverseProxy).
//! - requestHeaders are injected with Set semantics (override same-name).

mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

fn http_proxy(
    name: &str,
    domains: Vec<String>,
    headers: Option<std::collections::HashMap<String, String>>,
) -> NewProxy {
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
        headers,
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
async fn test_vhost_http_injects_xff_and_request_headers() {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let vhost_addr: SocketAddr = format!("127.0.0.1:{}", vhost_port).parse().unwrap();

    // Provider registers an HTTP proxy with requestHeaders.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let np = FrpMessage::NewProxy(Box::new(http_proxy(
        "http-test",
        vec!["app.example.com".into()],
        Some(std::collections::HashMap::from([
            ("X-Injected".to_string(), "from-frps".to_string()),
            ("X-Override".to_string(), "new".to_string()),
        ])),
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

    // Pool a work conn.
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

    // Client sends a request with a same-name header to be overridden.
    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"GET /test HTTP/1.1\r\n\
              Host: app.example.com\r\n\
              X-Override: old\r\n\
              X-Forwarded-For: 10.0.0.1\r\n\
              \r\n",
        )
        .await
        .expect("send request");

    // Backend receives StartWorkConn then the forwarded head.
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "http-test");
            assert!(swc.error.is_none(), "{:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }

    let mut forwarded = Vec::new();
    let mut chunk = [0u8; 1024];
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let n = work_conn.read(&mut chunk).await.expect("read forwarded");
            if n == 0 {
                break;
            }
            forwarded.extend_from_slice(&chunk[..n]);
            if forwarded.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .expect("timeout waiting for forwarded request");

    let text = String::from_utf8_lossy(&forwarded);
    assert!(
        text.contains("X-Injected: from-frps"),
        "configured request header missing: {text}"
    );
    assert!(
        text.contains("X-Override: new"),
        "requestHeaders must override client value: {text}"
    );
    assert!(
        !text.contains("X-Override: old"),
        "client value must be replaced: {text}"
    );
    assert!(
        text.contains("X-Forwarded-For: 10.0.0.1, 127.0.0.1"),
        "XFF must append client IP to existing value: {text}"
    );

    println!("HTTP vhost header injection verified");
    drop(client);
    drop(provider);
}
