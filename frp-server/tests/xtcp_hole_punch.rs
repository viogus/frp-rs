mod common;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use common::{allocate_port, raw_login, start_test_server};

/// Server-side XTCP message routing test.
///
/// Verifies that the server correctly routes NatHole messages between
/// visitor (fresh connection) and provider (control connection).
/// Tests the NEW Go frp v0.69.1-compatible flow with address exchange.
///
/// Flow:
/// 1. Provider logs in and registers an XTCP proxy with sk
/// 2. Visitor sends NatHoleVisitor via fresh TCP connection
/// 3. Server sends NatHoleClient notification to provider
/// 4. Provider sends NatHoleClient reply with STUN addresses
/// 5. Server runs NAT analysis, sends NatHoleResp to visitor
///    with provider's addresses as candidate_addrs
/// 6. Provider sends NatHoleSid back (simulating hole punch start)
/// 7. Server forwards NatHoleSid to visitor
/// 8. Provider sends NatHoleReport (hole punch complete)
/// 9. Server forwards NatHoleReport to visitor and cleans up session
#[tokio::test]
async fn test_xtcp_nat_hole_message_routing() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Step 1: Provider logs in and registers XTCP proxy ---
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");

    let xtcp_sk = "xtcp-test-sk";
    let np = FrpMessage::NewProxy(NewProxy {
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
    });
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "XTCP proxy registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // --- Step 2: Visitor sends NatHoleVisitor on fresh connection ---
    let mut visitor_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor connect"),
    );
    let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
        transaction_id: format!("test-txn-{}", port),
        proxy_name: "xtcp-test".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut visitor_conn, &nhv)
        .await
        .expect("send NatHoleVisitor");

    // --- Step 3: Provider reads NatHoleClient notification from server ---
    let (sid, txn_id) = match read_msg_v1(&mut provider)
        .await
        .expect("read NatHoleClient from provider")
    {
        FrpMessage::NatHoleClient(nhc) => {
            assert_eq!(nhc.proxy_name, "xtcp-test");
            assert!(nhc.visitor_addr.is_some(), "should have visitor_addr");
            println!(
                "Provider received NatHoleClient: proxy={}, visitor_addr={}",
                nhc.proxy_name,
                nhc.visitor_addr.as_deref().unwrap_or("none")
            );
            let sid = nhc.sid.clone().unwrap_or_else(|| nhc.transaction_id.clone());
            let txn = nhc.transaction_id.clone();
            (sid, txn)
        }
        other => panic!("expected NatHoleClient, got: {:?}", other.v1_type_byte()),
    };

    // --- Step 4: Provider sends NatHoleClient reply with STUN addresses ---
    // (simulating STUN discovery result)
    let reply = FrpMessage::NatHoleClient(msg::NatHoleClient {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-test".into(),
        sid: Some(sid.clone()),
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec![
            "10.0.0.1:7000".to_string(),
            "10.0.0.1:7002".to_string(),
        ]),
        assisted_addrs: None,
        visitor_addr: Some("127.0.0.1:65411".into()),
    });
    write_msg_v1(&mut provider, &reply)
        .await
        .expect("send NatHoleClient reply");
    println!("Provider sent NatHoleClient reply with STUN addresses for {}", sid);

    // --- Step 5: Visitor reads NatHoleResp with provider's candidate addresses ---
    match read_msg_v1(&mut visitor_conn)
        .await
        .expect("read NatHoleResp from visitor")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "NatHoleResp error: {:?}", resp.error);
            let resp_sid = resp.sid.as_deref().map(|s| s.to_string());
            assert_eq!(resp_sid, Some(sid.clone()));
            // KEY: candidate_addrs should contain PROVIDER's addresses, not visitor's
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
        other => panic!("expected NatHoleResp, got: {:?}", other.v1_type_byte()),
    }

    // --- Step 6: Provider reads NatHoleResp from server ---
    // Server sends NatHoleResp to provider with visitor's addresses as candidates.
    // Provider must consume this before sending further messages.
    match read_msg_v1(&mut provider)
        .await
        .expect("read NatHoleResp from provider")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "provider NatHoleResp error: {:?}", resp.error);
            assert_eq!(resp.sid.as_deref(), Some(sid.as_str()));
            println!(
                "Provider received NatHoleResp with visitor addresses as candidates: {:?}",
                resp.candidate_addrs
            );
        }
        other => panic!("expected NatHoleResp on provider, got: {:?}", other.v1_type_byte()),
    }

    // --- Step 7: Provider sends NatHoleSid (simulating hole punch start) ---
    let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
        sid: Some(sid.clone()),
        provider_addr: None,
    });
    write_msg_v1(&mut provider, &sid_msg)
        .await
        .expect("send NatHoleSid");
    println!("Provider sent NatHoleSid for session {}", sid);

    // --- Step 8: Visitor reads NatHoleSid (forwarded from provider) ---
    let _provider_addr = match read_msg_v1(&mut visitor_conn)
        .await
        .expect("read forwarded msg from visitor")
    {
        FrpMessage::NatHoleSid(sid_resp) => {
            println!("Visitor received NatHoleSid (forwarded)");
            sid_resp.provider_addr
        }
        other => panic!("expected NatHoleSid after NatHoleResp, got: {:?}", other.v1_type_byte()),
    };

    // --- Step 9: Provider sends NatHoleReport (hole punch complete) ---
    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
        sid: Some(sid.clone()),
    });
    write_msg_v1(&mut provider, &report)
        .await
        .expect("send NatHoleReport");
    println!("Provider sent NatHoleReport for session {}", sid);

    // --- Step 10: Visitor reads NatHoleReport ---
    match read_msg_v1(&mut visitor_conn)
        .await
        .expect("read NatHoleReport from visitor")
    {
        FrpMessage::NatHoleReport(report_resp) => {
            assert_eq!(report_resp.sid, Some(sid.clone()));
            println!("Visitor received NatHoleReport — hole punch complete");
        }
        other => panic!("expected NatHoleReport, got: {:?}", other.v1_type_byte()),
    }

    // --- Verify: provider connection still usable after NAT hole session ---
    // Send another NewProxy to confirm connection alive
    let np2 = FrpMessage::NewProxy(NewProxy {
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
    });
    write_msg_v1(&mut provider, &np2)
        .await
        .expect("send NewProxy after hole punch");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp after hole punch") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "second proxy registration should succeed: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    println!("XTCP message routing verified — all messages routed correctly");
    drop(provider);
    drop(visitor_conn);
}
