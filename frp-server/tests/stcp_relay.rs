mod common;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

use common::{allocate_port, raw_login, start_test_server};

/// Full STCP relay test:
/// 1. Provider logs in and registers an STCP proxy with sk
/// 2. Provider sends a pooled work connection (NewWorkConn)
/// 3. Visitor opens a new connection and sends NewVisitorConn with sk
/// 4. Server routes the visitor conn to the provider's control handler
/// 5. Server assigns the pooled work connection (sends StartWorkConn)
#[tokio::test]
async fn test_stcp_visitor_routed_to_provider() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Step 1: Provider logs in ---
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    // --- Step 2: Provider registers STCP proxy ---
    let stcp_sk = "test-stcp-secret-key";
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "stcp-test".into(),
        proxy_type: "stcp".into(),
        sk: Some(stcp_sk.to_string()),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9999".into()),
        remote_port: Some(0),
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
                    #[cfg(feature = "vnet")]
                    advertise_subnet: None,
                    #[cfg(feature = "vnet")]
                    vnet_ip: None,
                    #[cfg(feature = "vnet")]
                    vnet_netmask: None,
                    #[cfg(feature = "vnet")]
                    vnet_mtu: None,
    });
    write_msg_v1(&mut provider, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "STCP proxy registration should succeed: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // --- Step 3: Provider sends pooled work connection ---
    let mut work_conn = tokio::net::TcpStream::connect(addr).await.expect("work conn connect");
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id.clone()),
        timestamp: None,
        privilege_key: None,
    });
    write_msg_v1(&mut work_conn, &nwc).await.expect("send NewWorkConn");
    // The work connection is now pooled by the server

    // --- Step 4: Visitor opens new connection and sends NewVisitorConn ---
    let mut visitor_conn = tokio::net::TcpStream::connect(addr).await.expect("visitor connect");
    let nvc = FrpMessage::NewVisitorConn(msg::NewVisitorConn {
        proxy_name: "stcp-test".into(),
        sign_key: Some(stcp_sk.to_string()),
        timestamp: None,
        run_id: None,
        use_encryption: None,
        use_compression: None,
    });
    write_msg_v1(&mut visitor_conn, &nvc).await.expect("send NewVisitorConn");

    // --- Step 5: Verify server assigned the pooled work connection ---
    // The server should send StartWorkConn on the pooled work connection.
    match read_msg_v1(&mut work_conn).await.expect("read StartWorkConn on work conn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "stcp-test", "StartWorkConn should be for stcp-test");
            assert!(swc.error.is_none(), "StartWorkConn should not have error: {:?}", swc.error);
        }
        other => {
            panic!("expected StartWorkConn, got type byte: {:?} — {:?}", other.v1_type_byte(), other);
        }
    }

    // Cleanup: read from visitor to verify server isn't confused
    // (visitor conn should be bridged — but there's no real local service,
    // so the bridge will close shortly)
    println!("STCP relay routing verified — StartWorkConn received on work connection");
}
