mod common;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};

/// Server-side XTCP message routing test — Go frp v0.69.1 compat flow.
///
/// Verifies that the server correctly routes NatHole messages between
/// visitor (fresh connection) and provider (control + work connection).
/// Uses the Go-compatible flow: pre_check validation, NatHoleSid on
/// work connection, provider STUN response on control connection.
///
/// Flow:
/// 1. Provider logs in, registers XTCP proxy, establishes work conn pool
/// 2. Visitor: pre_check NatHoleVisitor → NatHoleResp(OK) → disconnect
/// 3. Visitor reconnects: full NatHoleVisitor (mapped_addrs, protocol)
/// 4. Server sends NatHoleSid to provider ON WORK CONNECTION
/// 5. Provider reads NatHoleSid from work conn
/// 6. Provider sends NatHoleClient (with STUN addresses) on control conn
/// 7. Server runs analysis → NatHoleResp to visitor (provider's addresses)
/// 8. Server → NatHoleResp to provider (visitor's addresses)
/// 9. Provider → NatHoleReport → server cleans up session
#[tokio::test]
async fn test_xtcp_nat_hole_message_routing() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Step 1: Provider logs in and registers XTCP proxy ---
    let (mut provider_ctl, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let xtcp_sk = "xtcp-test-sk";
    let np = FrpMessage::NewProxy(Box::new(NewProxy {
        proxy_name: "xtcp-test".into(),
        proxy_type: "xtcp".into(),
        sk: Some(xtcp_sk.to_string()),
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
    }));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "XTCP proxy registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }
    println!("Provider registered XTCP proxy (run_id={})", run_id);

    // Establish a work connection and send NewWorkConn so server pools it.
    // The provider KEEPS READING from this work conn to receive NatHoleSid.
    let mut work_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("work conn connect"),
    );
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id.clone()),
        timestamp: None,
        privilege_key: None,
    });
    write_msg_v1(&mut work_conn, &nwc)
        .await
        .expect("send NewWorkConn");
    println!("Provider sent NewWorkConn — work conn pooled by server");

    // Give server time to pool the work connection
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // --- Phase 1: PreCheck ---
    let mut precheck_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor precheck connect"),
    );
    let precheck_msg = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
        transaction_id: format!("precheck-{}", port),
        proxy_name: "xtcp-test".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut precheck_conn, &precheck_msg)
        .await
        .expect("send precheck NatHoleVisitor");

    // PreCheck should return simple NatHoleResp (no sid, no session created)
    match read_msg_v1(&mut precheck_conn)
        .await
        .expect("read precheck NatHoleResp")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "precheck error: {:?}", resp.error);
            assert!(resp.sid.is_none(), "precheck should NOT have sid");
            println!("PreCheck passed — NatHoleResp OK (no sid)");
        }
        other => panic!(
            "expected NatHoleResp for precheck, got: {:?}",
            other.v1_type_byte()
        ),
    }
    drop(precheck_conn);

    // --- Phase 2: Full NatHoleVisitor ---
    let txn_id = format!("full-txn-{}", port);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let sign_key = frp_core::auth::generate_token(xtcp_sk, ts);
    let mut visitor_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor full connect"),
    );
    let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-test".into(),
        pre_check: false,
        protocol: Some("tcp".to_string()),
        sign_key: Some(sign_key),
        timestamp: Some(ts),
        mapped_addrs: Some(vec!["1.2.3.4:5678".to_string(), "1.2.3.4:5680".to_string()]),
        assisted_addrs: Some(vec!["192.168.1.5:5678".to_string()]),
    });
    write_msg_v1(&mut visitor_conn, &nhv)
        .await
        .expect("send full NatHoleVisitor");
    println!("Visitor sent full NatHoleVisitor with mapped_addrs");

    // --- Provider reads StartWorkConn from WORK CONNECTION ---
    // NatHoleSid is embedded in StartWorkConn JSON (Rust frp extension).
    // Go frp sends a separate NatHoleSid frame after; Rust frp embeds it.
    let sid = match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn from work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "xtcp-test");
            println!(
                "Provider received StartWorkConn for proxy '{}'",
                swc.proxy_name
            );
            // NatHoleSid embedded in StartWorkConn
            let s = swc
                .nat_hole_sid
                .clone()
                .expect("StartWorkConn should have nat_hole_sid");
            assert!(!s.is_empty(), "sid should be non-empty");
            println!("Provider received NatHoleSid in StartWorkConn: sid={}", s);
            s
        }
        other => panic!(
            "expected StartWorkConn on work conn, got: {:?}",
            other.v1_type_byte()
        ),
    };

    // --- Provider does "STUN" → sends NatHoleClient on CONTROL conn ---
    let client_msg = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-test".into(),
        sid: Some(sid.clone()),
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec![
            "10.0.0.1:7000".to_string(),
            "10.0.0.1:7002".to_string(),
        ]),
        assisted_addrs: None,
        visitor_addr: None,
    }));
    write_msg_v1(&mut provider_ctl, &client_msg)
        .await
        .expect("send NatHoleClient on control");
    println!("Provider sent NatHoleClient on control with STUN addresses");

    // --- Provider reads NatHoleResp from server on control conn ---
    // Drain any pool-replenish ReqWorkConn messages before the response.
    loop {
        match read_msg_v1(&mut provider_ctl)
            .await
            .expect("read provider control")
        {
            FrpMessage::ReqWorkConn(_) => continue,
            FrpMessage::NatHoleResp(resp) => {
                assert!(
                    resp.error.is_none(),
                    "provider NatHoleResp error: {:?}",
                    resp.error
                );
                assert_eq!(resp.sid.as_deref(), Some(sid.as_str()));
                // Provider should get VISITOR's mapped addresses as candidates
                if let Some(ref candidates) = resp.candidate_addrs {
                    assert!(
                        candidates.iter().any(|a| a.contains("1.2.3.4")),
                        "provider's candidate_addrs should contain visitor addresses, got: {:?}",
                        candidates
                    );
                }
                println!(
                    "Provider received NatHoleResp with visitor addresses: detect_behavior={:?}",
                    resp.detect_behavior
                );
                break;
            }
            other => panic!(
                "expected NatHoleResp on provider control, got: {:?}",
                other.v1_type_byte()
            ),
        }
    }

    // --- Visitor reads NatHoleResp with provider's candidate addresses ---
    match read_msg_v1(&mut visitor_conn)
        .await
        .expect("read NatHoleResp from visitor")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_none(),
                "visitor NatHoleResp error: {:?}",
                resp.error
            );
            let resp_sid = resp.sid.clone();
            assert!(resp_sid.is_some(), "visitor NatHoleResp should have sid");
            // KEY: candidate_addrs should contain PROVIDER's addresses
            if let Some(ref candidates) = resp.candidate_addrs {
                assert!(
                    candidates.iter().any(|a| a.contains("10.0.0.1")),
                    "candidate_addrs should contain provider addresses, got: {:?}",
                    candidates
                );
            } else {
                panic!("NatHoleResp should have candidate_addrs");
            }
            println!(
                "Visitor received NatHoleResp with provider addresses — correct! detect_behavior={:?}",
                resp.detect_behavior
            );
        }
        other => panic!(
            "expected NatHoleResp on visitor, got: {:?}",
            other.v1_type_byte()
        ),
    }

    // --- Provider sends NatHoleReport (hole punch complete) ---
    // Use the sid from the visitor's NatHoleResp
    // (In real flow, provider sends after hole punch succeeds)
    // For this test, we already consumed the provider NatHoleResp above.
    // The session is complete — send report to clean up.
    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
        sid: Some(txn_id.clone()),
        success: None,
    });
    write_msg_v1(&mut provider_ctl, &report)
        .await
        .expect("send NatHoleReport");
    println!("Provider sent NatHoleReport for cleanup");

    // --- Verify: provider control connection still usable after session ---
    let np2 = FrpMessage::NewProxy(Box::new(NewProxy {
        proxy_name: "xtcp-test-2".into(),
        proxy_type: "xtcp".into(),
        sk: Some("another-sk".to_string()),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9998".into()),
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
    }));
    write_msg_v1(&mut provider_ctl, &np2)
        .await
        .expect("send NewProxy after hole punch");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp after hole punch")
    {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "second proxy should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    println!("XTCP Go-compat message routing verified!");
    drop(provider_ctl);
    drop(visitor_conn);
    drop(work_conn);
}

/// Server correctly ignores NatHoleClient with sid=None.
/// The control channel remains usable after the ignored message.
#[tokio::test]
async fn test_xtcp_ignore_nat_hole_client_no_sid() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let (mut provider_ctl, resp) = login_with_test_token(addr).await.expect("login");
    let _run_id = resp.run_id.expect("run_id");

    // Register XTCP proxy
    let np = FrpMessage::NewProxy(Box::new(NewProxy {
        proxy_name: "ignore-no-sid".into(),
        proxy_type: "xtcp".into(),
        sk: Some("ignore-no-sid-sk".to_string()),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:29999".into()),
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
    }));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "reg error: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Send NatHoleClient WITHOUT sid - server should silently drop it
    let bogus = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
        transaction_id: "no-sid-txn".into(),
        proxy_name: "ignore-no-sid".into(),
        sid: None,
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec!["10.0.0.1:9999".to_string()]),
        ..Default::default()
    }));
    write_msg_v1(&mut provider_ctl, &bogus)
        .await
        .expect("send bogus NatHoleClient");

    // Verify control channel is still operational
    let np2 = FrpMessage::NewProxy(Box::new(NewProxy {
        proxy_name: "after-no-sid-2".into(),
        proxy_type: "xtcp".into(),
        sk: Some("after-no-sid-sk-2".to_string()),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:29998".into()),
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
    }));
    write_msg_v1(&mut provider_ctl, &np2)
        .await
        .expect("send NewProxy 2");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("NewProxyResp 2")
    {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "control channel still usable: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    println!("Server correctly ignored NatHoleClient with sid=None");
    drop(provider_ctl);
}
