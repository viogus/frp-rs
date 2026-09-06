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
    rewrite_host: Option<String>,
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
        host_header_rewrite: rewrite_host,
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
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
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
        None,
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

/// Go parity (pkg/util/vhost/http.go:282-285): a CONNECT request is handed
/// to connectHandler, which writes `req.Write(remote)` RAW — no
/// host_header_rewrite, no X-Forwarded-* injection, no requestHeaders, even
/// when all three are configured on the routed proxy. Auth still gates the
/// route, but a routed CONNECT reaches the backend byte-identical.
#[tokio::test]
async fn test_vhost_http_connect_forwards_raw() {
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

    // Provider registers an HTTP proxy that would rewrite + inject on a
    // normal GET — the CONNECT must bypass all of it.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let np = FrpMessage::NewProxy(Box::new(http_proxy(
        "connect-test",
        vec!["tunnel.example.com".into()],
        Some("backend.internal".into()),
        Some(std::collections::HashMap::from([
            (
                "X-Forwarded-For".to_string(),
                "edge.example.net".to_string(),
            ),
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

    // Client sends a CONNECT with a mismatched Host header — Go routes on
    // the request-line authority alone; the Host header is forwarded
    // verbatim (no rewrite, no injection).
    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"CONNECT tunnel.example.com:443 HTTP/1.1\r\n\
              Host: tunnel.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT");

    // Backend receives StartWorkConn then the raw forwarded head.
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "connect-test");
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
    .expect("timeout waiting for forwarded CONNECT");

    let text = String::from_utf8_lossy(&forwarded);
    assert!(
        text.starts_with("CONNECT tunnel.example.com:443 HTTP/1.1\r\n"),
        "request line must be forwarded verbatim: {text}"
    );
    assert!(
        text.contains("Host: tunnel.example.com\r\n"),
        "original Host must survive (no host_header_rewrite on CONNECT): {text}"
    );
    assert!(
        !text.contains("backend.internal"),
        "host_header_rewrite must not apply to CONNECT: {text}"
    );
    assert!(
        !text.contains("X-Forwarded"),
        "no X-Forwarded-* injection on CONNECT: {text}"
    );
    assert!(
        !text.contains("X-Override"),
        "requestHeaders must not apply to CONNECT: {text}"
    );

    println!("HTTP vhost CONNECT forwarded raw");
    drop(client);
    drop(provider);
}

/// Go parity (server/proxy/http.go:64/114-122): an HTTP reverse-proxy leg
/// reports the user conn's remote address as StartWorkConn src but NIL as
/// dst — Go's vhost CreateConnFn is `GetRealConn(rAddr, nil)`, and Go frpc
/// falls back to 127.0.0.1:0 for the PROXY-protocol destination pair. The
/// pre-round-12 code reported the real vhost accept addr on http-type legs
/// (round-12 audit B1) — every PROXY-header-enabled http backend saw a dst
/// shape Go never produces. TCP-family legs (tcp/https/tcpmux) keep the
/// real server-side local addr; ONLY type=http drops it.
#[tokio::test]
async fn test_vhost_http_start_work_conn_src_without_dst() {
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

    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let mut np = http_proxy("http-no-dst", vec!["dst.example.com".into()], None, None);
    np.proxy_protocol_version = Some("v1".into()); // the dst pair feeds the PROXY header
    write_msg_v1(&mut provider, &FrpMessage::NewProxy(Box::new(np)))
        .await
        .expect("send NewProxy");
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_msg_v1(&mut provider),
    )
    .await
    .expect("timed out waiting for NewProxyResp")
    .expect("read NewProxyResp")
    {
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

    // One client request on the vhost port drives the assignment.
    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: dst.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send request");

    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_msg_v1(&mut work_conn),
    )
    .await
    .expect("timed out waiting for StartWorkConn")
    .expect("read StartWorkConn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "http-no-dst");
            assert!(swc.error.is_none(), "{:?}", swc.error);
            assert_eq!(
                swc.src_addr.as_deref(),
                Some("127.0.0.1"),
                "http leg must report the real client as src (Go http.go:122 rAddr)"
            );
            assert!(
                swc.src_port.is_some_and(|p| p != 0),
                "http leg must report the real client port: {:?}",
                swc.src_port
            );
            assert!(
                swc.dst_addr.is_none() && swc.dst_port.is_none(),
                "http leg must send NO dst pair (Go GetRealConn(rAddr, nil)): {:?}:{:?}",
                swc.dst_addr,
                swc.dst_port
            );
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }

    drop(client);
    drop(work_conn);
    drop(provider);
}
