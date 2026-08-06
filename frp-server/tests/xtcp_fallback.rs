mod common;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NatHoleVisitor, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};

/// Helper: build a minimal `NewProxy` for XTCP with only the required fields set.
fn xtcp_proxy(name: &str, sk: &str, local_str: &str) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "xtcp".into(),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some(local_str.into()),
        remote_port: Some(0),
        sk: Some(sk.into()),
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
    }
}

/// Pre-check against a proxy that was never registered must return an error.
/// Server must not crash.
#[tokio::test]
async fn test_xtcp_precheck_nonexistent_proxy() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Visitor connects (no login -- raw TCP, unencrypted V1 frames)
    let mut conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor connect"),
    );

    let precheck = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: "nonexistent-precheck".into(),
        proxy_name: "ghost-proxy".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut conn, &precheck)
        .await
        .expect("send precheck");

    match read_msg_v1(&mut conn).await.expect("read NatHoleResp") {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_some(),
                "expected error for nonexistent proxy, got: {:?}",
                resp.error
            );
            assert!(
                resp.sid.is_none(),
                "sid must not be set for failed precheck"
            );
        }
        other => panic!(
            "expected NatHoleResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }

    drop(conn);
}

/// Dropping the precheck connection mid-flight must not crash the server.
/// A subsequent precheck for the same proxy must still succeed.
#[tokio::test]
async fn test_xtcp_precheck_disconnect_does_not_crash() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Login as provider and register an XTCP proxy
    let (mut provider_ctl, _resp) = login_with_test_token(addr).await.expect("provider login");

    let np = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-drop-test",
        "drop-test-sk",
        "127.0.0.1:7777",
    )));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // --- Phase 1: send precheck, drop without reading response ---
    {
        let mut conn = IoStream::Tcp(
            tokio::net::TcpStream::connect(addr)
                .await
                .expect("first visitor connect"),
        );
        let precheck = FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: "drop-me".into(),
            proxy_name: "xtcp-drop-test".into(),
            pre_check: true,
            ..Default::default()
        });
        write_msg_v1(&mut conn, &precheck)
            .await
            .expect("send precheck");
        // Drop connection without reading -- server must not crash.
    }

    // Give server time to process the disconnect
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // --- Phase 2: reconnect, precheck again -- must still work ---
    {
        let mut conn2 = IoStream::Tcp(
            tokio::net::TcpStream::connect(addr)
                .await
                .expect("second visitor connect"),
        );
        let precheck2 = FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: "after-drop".into(),
            proxy_name: "xtcp-drop-test".into(),
            pre_check: true,
            ..Default::default()
        });
        write_msg_v1(&mut conn2, &precheck2)
            .await
            .expect("send second precheck");

        match read_msg_v1(&mut conn2)
            .await
            .expect("read second NatHoleResp")
        {
            FrpMessage::NatHoleResp(resp) => {
                assert!(
                    resp.error.is_none(),
                    "second precheck should succeed after drop: {:?}",
                    resp.error
                );
                assert!(resp.sid.is_none(), "precheck must not have sid");
            }
            other => panic!(
                "expected NatHoleResp, got type byte {:?}",
                other.v1_type_byte()
            ),
        }
    }

    drop(provider_ctl);
}

/// Sending NatHoleClient with a nonexistent sid must not break the
/// control channel -- the provider can still register another proxy.
#[tokio::test]
async fn test_xtcp_nat_hole_client_invalid_sid() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Provider logs in and registers an XTCP proxy
    let (mut provider_ctl, _resp) = login_with_test_token(addr).await.expect("provider login");

    let np = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-sid-test",
        "sid-test-sk",
        "127.0.0.1:6666",
    )));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Send NatHoleClient with a sid that does not exist
    let bogus_client = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
        transaction_id: "bogus-txn".into(),
        proxy_name: "xtcp-sid-test".into(),
        sid: Some("deadbeef-nonexistent-sid".into()),
        protocol: Some("tcp".into()),
        mapped_addrs: Some(vec!["9.9.9.9:9999".into()]),
        ..Default::default()
    }));
    write_msg_v1(&mut provider_ctl, &bogus_client)
        .await
        .expect("send NatHoleClient with invalid sid");

    // Control channel must still be usable -- register another proxy
    let np2 = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-sid-test-2",
        "sid-test-sk-2",
        "127.0.0.1:5555",
    )));
    write_msg_v1(&mut provider_ctl, &np2)
        .await
        .expect("send NewProxy after invalid sid");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp after invalid sid")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(
                r.error.is_none(),
                "second proxy should succeed after invalid sid: {:?}",
                r.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    drop(provider_ctl);
}

/// Sending NatHoleClient with sid=None must not break the control channel.
#[tokio::test]
async fn test_xtcp_nat_hole_client_without_sid() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Provider logs in and registers an XTCP proxy
    let (mut provider_ctl, _resp) = login_with_test_token(addr).await.expect("provider login");

    let np = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-nosid-test",
        "nosid-test-sk",
        "127.0.0.1:4444",
    )));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Send NatHoleClient with sid=None
    let no_sid_client = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
        transaction_id: "no-sid-txn".into(),
        proxy_name: "xtcp-nosid-test".into(),
        sid: None,
        protocol: Some("tcp".into()),
        mapped_addrs: Some(vec!["8.8.8.8:8888".into()]),
        ..Default::default()
    }));
    write_msg_v1(&mut provider_ctl, &no_sid_client)
        .await
        .expect("send NatHoleClient without sid");

    // Control channel must still be usable
    let np2 = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-nosid-test-2",
        "nosid-test-sk-2",
        "127.0.0.1:3333",
    )));
    write_msg_v1(&mut provider_ctl, &np2)
        .await
        .expect("send NewProxy after no-sid");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp after no-sid")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(
                r.error.is_none(),
                "second proxy should succeed after nil sid: {:?}",
                r.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    drop(provider_ctl);
}

/// Full message routing flow: provider registers XTCP proxy, work conn
/// established, visitor precheck + full visitor, provider reads
/// StartWorkConn+NatHoleSid from work conn, sends NatHoleClient on
/// control, both sides read NatHoleResp. Provider sends NatHoleReport
/// --> session cleaned up. Then another NatHoleClient with the same sid
/// is silently ignored. Control channel must still work.
#[tokio::test]
async fn test_xtcp_nat_hole_report_cleanup() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Provider login + register XTCP proxy ---
    let (mut provider_ctl, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let xtcp_sk = "cleanup-test-sk";
    let np = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-cleanup",
        xtcp_sk,
        "127.0.0.1:2222",
    )));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // Establish work conn pool
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

    // Give server time to pool the work connection
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // --- PreCheck ---
    let mut precheck_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor precheck connect"),
    );
    let precheck_msg = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: format!("precheck-{}", port),
        proxy_name: "xtcp-cleanup".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut precheck_conn, &precheck_msg)
        .await
        .expect("send precheck");
    match read_msg_v1(&mut precheck_conn)
        .await
        .expect("read precheck NatHoleResp")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "precheck error: {:?}", resp.error);
            assert!(resp.sid.is_none(), "precheck must not have sid");
        }
        other => panic!(
            "expected NatHoleResp for precheck, got: {:?}",
            other.v1_type_byte()
        ),
    }
    drop(precheck_conn);

    // --- Full NatHoleVisitor ---
    let txn_id = format!("cleanup-txn-{}", port);
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
    let nhv = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-cleanup".into(),
        pre_check: false,
        protocol: Some("tcp".to_string()),
        sign_key: Some(sign_key),
        timestamp: Some(ts),
        mapped_addrs: Some(vec!["1.2.3.4:5678".into(), "1.2.3.4:5680".into()]),
        assisted_addrs: Some(vec!["192.168.1.5:5678".into()]),
    });
    write_msg_v1(&mut visitor_conn, &nhv)
        .await
        .expect("send full NatHoleVisitor");

    // --- Provider reads StartWorkConn from work conn ---
    // NatHoleSid embedded in StartWorkConn JSON (Rust frp extension).
    let sid = match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn from work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "xtcp-cleanup");
            // NatHoleSid embedded in StartWorkConn
            let s = swc
                .nat_hole_sid
                .clone()
                .expect("StartWorkConn should have nat_hole_sid");
            assert!(!s.is_empty(), "sid must be non-empty");
            s
        }
        other => panic!(
            "expected StartWorkConn on work conn, got: {:?}",
            other.v1_type_byte()
        ),
    };

    // --- Provider sends NatHoleClient on control ---
    let client_msg = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-cleanup".into(),
        sid: Some(sid.clone()),
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec!["10.0.0.1:7000".into(), "10.0.0.1:7002".into()]),
        assisted_addrs: None,
        visitor_addr: None,
    }));
    write_msg_v1(&mut provider_ctl, &client_msg)
        .await
        .expect("send NatHoleClient on control");

    // --- Provider reads NatHoleResp ---
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
                if let Some(ref candidates) = resp.candidate_addrs {
                    assert!(
                        candidates.iter().any(|a| a.contains("1.2.3.4")),
                        "provider's candidate_addrs should contain visitor addresses"
                    );
                }
                break;
            }
            other => panic!(
                "expected NatHoleResp on provider control, got: {:?}",
                other.v1_type_byte()
            ),
        }
    }

    // --- Visitor reads NatHoleResp ---
    match read_msg_v1(&mut visitor_conn)
        .await
        .expect("read visitor NatHoleResp")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_none(),
                "visitor NatHoleResp error: {:?}",
                resp.error
            );
            assert!(resp.sid.is_some(), "visitor NatHoleResp must have sid");
            if let Some(ref candidates) = resp.candidate_addrs {
                assert!(
                    candidates.iter().any(|a| a.contains("10.0.0.1")),
                    "visitor's candidate_addrs should contain provider addresses"
                );
            }
        }
        other => panic!(
            "expected NatHoleResp on visitor, got: {:?}",
            other.v1_type_byte()
        ),
    }

    // --- Provider sends NatHoleReport --> session cleaned up ---
    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
        sid: Some(sid.clone()),
        success: false,
    });
    write_msg_v1(&mut provider_ctl, &report)
        .await
        .expect("send NatHoleReport");

    // Give server time to process the report and clean up
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // --- Another NatHoleClient with same sid --> silently ignored ---
    let stale_client = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-cleanup".into(),
        sid: Some(sid.clone()),
        protocol: Some("tcp".into()),
        mapped_addrs: Some(vec!["11.11.11.11:1111".into()]),
        assisted_addrs: None,
        visitor_addr: None,
    }));
    write_msg_v1(&mut provider_ctl, &stale_client)
        .await
        .expect("send stale NatHoleClient (should be ignored)");

    // --- Control channel must still work after all this ---
    let np2 = FrpMessage::NewProxy(Box::new(xtcp_proxy(
        "xtcp-cleanup-2",
        "cleanup-sk-2",
        "127.0.0.1:1111",
    )));
    write_msg_v1(&mut provider_ctl, &np2)
        .await
        .expect("send NewProxy after report");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp after report")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(
                r.error.is_none(),
                "second proxy should succeed after cleanup: {:?}",
                r.error
            );
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    drop(provider_ctl);
    drop(visitor_conn);
    drop(work_conn);
}
