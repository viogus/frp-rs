mod common;

use std::net::SocketAddr;
use std::sync::Arc;

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

/// Helper: build a `NewProxy` for XTCP with encryption/compression flags.
fn xtcp_proxy_encrypted(name: &str, sk: &str, local_str: &str) -> NewProxy {
    let mut np = xtcp_proxy(name, sk, local_str);
    np.use_encryption = Some(true);
    np.use_compression = Some(true);
    np
}

/// Run 3 independent XTCP message routing flows concurrently.
///
/// Each session: login → register unique XTCP proxy → work conn →
/// precheck → full NatHoleVisitor → read StartWorkConn+NatHoleSid
/// from work conn.
///
/// All 3 complete without panicking or cross-contamination.
#[tokio::test]
async fn test_xtcp_concurrent_3_sessions() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: Arc<SocketAddr> = Arc::new(format!("127.0.0.1:{}", port).parse().unwrap());

    let mut handles = Vec::new();

    for i in 0..3 {
        let addr = Arc::clone(&addr);
        let handle = tokio::spawn(async move {
            let proxy_name = format!("xtcp-concurrent-{}", i);
            let sk = format!("sk-concurrent-{}", i);
            let txn_id = format!("txn-{}-{}", i, port);

            // --- Login ---
            let (mut provider_ctl, resp) =
                login_with_test_token(*addr).await.expect("provider login");
            let run_id = resp.run_id.expect("provider should get run_id");

            // --- Register XTCP proxy ---
            let np = FrpMessage::NewProxy(xtcp_proxy(
                &proxy_name,
                &sk,
                &format!("127.0.0.1:{}", 9000 + i),
            ));
            write_msg_v1(&mut provider_ctl, &np)
                .await
                .unwrap_or_else(|_| panic!("[{}] send NewProxy", i));
            match read_msg_v1(&mut provider_ctl)
                .await
                .unwrap_or_else(|_| panic!("[{}] read NewProxyResp", i))
            {
                FrpMessage::NewProxyResp(ref r) => {
                    assert!(r.error.is_none(), "[{}] proxy reg error: {:?}", i, r.error);
                }
                other => panic!(
                    "[{}] expected NewProxyResp, got: {:?}",
                    i,
                    other.v1_type_byte()
                ),
            }

            // --- Establish work conn ---
            let mut work_conn = IoStream::Tcp(
                tokio::net::TcpStream::connect(*addr)
                    .await
                    .unwrap_or_else(|_| panic!("[{}] work conn connect", i)),
            );
            let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            });
            write_msg_v1(&mut work_conn, &nwc)
                .await
                .unwrap_or_else(|_| panic!("[{}] send NewWorkConn", i));

            // Give server time to pool the work connection
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            // --- PreCheck ---
            let mut precheck_conn = IoStream::Tcp(
                tokio::net::TcpStream::connect(*addr)
                    .await
                    .unwrap_or_else(|_| panic!("[{}] precheck connect", i)),
            );
            let precheck_msg = FrpMessage::NatHoleVisitor(NatHoleVisitor {
                transaction_id: format!("precheck-{}", txn_id),
                proxy_name: proxy_name.clone(),
                pre_check: true,
                ..Default::default()
            });
            write_msg_v1(&mut precheck_conn, &precheck_msg)
                .await
                .unwrap_or_else(|_| panic!("[{}] send precheck", i));

            match read_msg_v1(&mut precheck_conn)
                .await
                .unwrap_or_else(|_| panic!("[{}] read precheck resp", i))
            {
                FrpMessage::NatHoleResp(resp) => {
                    assert!(
                        resp.error.is_none(),
                        "[{}] precheck error: {:?}",
                        i,
                        resp.error
                    );
                    assert!(resp.sid.is_none(), "[{}] precheck should not have sid", i);
                }
                other => panic!(
                    "[{}] expected NatHoleResp for precheck, got: {:?}",
                    i,
                    other.v1_type_byte()
                ),
            }
            drop(precheck_conn);

            // --- Full NatHoleVisitor ---
            let mut visitor_conn = IoStream::Tcp(
                tokio::net::TcpStream::connect(*addr)
                    .await
                    .unwrap_or_else(|_| panic!("[{}] visitor connect", i)),
            );
            let nhv = FrpMessage::NatHoleVisitor(NatHoleVisitor {
                transaction_id: txn_id.clone(),
                proxy_name: proxy_name.clone(),
                pre_check: false,
                protocol: Some("tcp".to_string()),
                sign_key: None,
                timestamp: None,
                mapped_addrs: Some(vec![format!("1.2.3.{}:{}", i + 1, 5678 + i)]),
                assisted_addrs: None,
            });
            write_msg_v1(&mut visitor_conn, &nhv)
                .await
                .unwrap_or_else(|_| panic!("[{}] send full NatHoleVisitor", i));

            // --- Read StartWorkConn + NatHoleSid from work conn ---
            match read_msg_v1(&mut work_conn)
                .await
                .unwrap_or_else(|_| panic!("[{}] read StartWorkConn from work conn", i))
            {
                FrpMessage::StartWorkConn(swc) => {
                    assert_eq!(
                        swc.proxy_name, proxy_name,
                        "[{}] StartWorkConn proxy_name mismatch",
                        i
                    );
                    // NatHoleSid embedded in StartWorkConn (Rust frp extension).
                    let sid = swc.nat_hole_sid.clone().unwrap_or_else(|| {
                        panic!("[{}] StartWorkConn should have nat_hole_sid", i)
                    });
                    assert!(!sid.is_empty(), "[{}] sid should be non-empty", i);
                }
                other => panic!(
                    "[{}] expected StartWorkConn on work conn, got: {:?}",
                    i,
                    other.v1_type_byte()
                ),
            }

            drop(provider_ctl);
            drop(visitor_conn);
            drop(work_conn);
        });
        handles.push(handle);
    }

    // Wait for all sessions to complete
    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|_| panic!("session {} panicked", i));
    }
}

/// Two providers register separate XTCP proxies on the same server.
/// Visitor for proxy A triggers NatHoleSid delivery — it must arrive
/// on work_conn_A, NOT work_conn_B. No message leakage between providers.
#[tokio::test]
async fn test_xtcp_multiple_providers_same_server() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Provider A: login + register proxy A ---
    let (mut provider_a_ctl, resp_a) = login_with_test_token(addr).await.expect("provider A login");
    let run_id_a = resp_a.run_id.expect("provider A run_id");

    let np_a = FrpMessage::NewProxy(xtcp_proxy("xtcp-prov-a", "sk-prov-a", "127.0.0.1:9001"));
    write_msg_v1(&mut provider_a_ctl, &np_a)
        .await
        .expect("send NewProxy A");
    match read_msg_v1(&mut provider_a_ctl)
        .await
        .expect("read NewProxyResp A")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "proxy A reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp A, got: {:?}", other.v1_type_byte()),
    }

    // Provider A work conn
    let mut work_conn_a = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("work conn A connect"),
    );
    let nwc_a = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id_a.clone()),
        timestamp: None,
        privilege_key: None,
    });
    write_msg_v1(&mut work_conn_a, &nwc_a)
        .await
        .expect("send NewWorkConn A");

    // --- Provider B: login + register proxy B ---
    let (mut provider_b_ctl, resp_b) = login_with_test_token(addr).await.expect("provider B login");
    let run_id_b = resp_b.run_id.expect("provider B run_id");

    let np_b = FrpMessage::NewProxy(xtcp_proxy("xtcp-prov-b", "sk-prov-b", "127.0.0.1:9002"));
    write_msg_v1(&mut provider_b_ctl, &np_b)
        .await
        .expect("send NewProxy B");
    match read_msg_v1(&mut provider_b_ctl)
        .await
        .expect("read NewProxyResp B")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "proxy B reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp B, got: {:?}", other.v1_type_byte()),
    }

    // Provider B work conn
    let mut work_conn_b = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("work conn B connect"),
    );
    let nwc_b = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id_b.clone()),
        timestamp: None,
        privilege_key: None,
    });
    write_msg_v1(&mut work_conn_b, &nwc_b)
        .await
        .expect("send NewWorkConn B");

    // Give server time to pool both work connections
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // --- Visitor for proxy A: precheck ---
    let mut precheck_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor precheck connect"),
    );
    let precheck_msg = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: format!("precheck-a-{}", port),
        proxy_name: "xtcp-prov-a".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut precheck_conn, &precheck_msg)
        .await
        .expect("send precheck A");
    match read_msg_v1(&mut precheck_conn)
        .await
        .expect("read precheck resp A")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "precheck A error: {:?}", resp.error);
            assert!(resp.sid.is_none(), "precheck A should not have sid");
        }
        other => panic!(
            "expected NatHoleResp for precheck A, got: {:?}",
            other.v1_type_byte()
        ),
    }
    drop(precheck_conn);

    // --- Visitor for proxy A: full NatHoleVisitor ---
    let txn_id = format!("full-a-{}", port);
    let mut visitor_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor full connect"),
    );
    let nhv = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-prov-a".into(),
        pre_check: false,
        protocol: Some("tcp".to_string()),
        sign_key: None,
        timestamp: None,
        mapped_addrs: Some(vec!["1.2.3.4:5678".to_string()]),
        assisted_addrs: None,
    });
    write_msg_v1(&mut visitor_conn, &nhv)
        .await
        .expect("send full NatHoleVisitor A");

    // --- NatHoleSid must arrive on work_conn_A, NOT work_conn_B ---
    let sid = match read_msg_v1(&mut work_conn_a)
        .await
        .expect("read StartWorkConn from work_conn_a")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "xtcp-prov-a");
            // NatHoleSid embedded in StartWorkConn (Rust frp extension).
            let s = swc
                .nat_hole_sid
                .clone()
                .expect("StartWorkConn should have nat_hole_sid on A");
            assert!(!s.is_empty());
            s
        }
        other => panic!(
            "expected StartWorkConn on work_conn_a, got: {:?}",
            other.v1_type_byte()
        ),
    };

    // --- Provider A sends NatHoleClient on control ---
    let client_msg = FrpMessage::NatHoleClient(msg::NatHoleClient {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-prov-a".into(),
        sid: Some(sid.clone()),
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec![
            "10.0.0.1:7000".to_string(),
            "10.0.0.1:7002".to_string(),
        ]),
        assisted_addrs: None,
        visitor_addr: None,
    });
    write_msg_v1(&mut provider_a_ctl, &client_msg)
        .await
        .expect("send NatHoleClient A");

    // --- Provider A reads NatHoleResp ---
    match read_msg_v1(&mut provider_a_ctl)
        .await
        .expect("read provider A NatHoleResp")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_none(),
                "provider A NatHoleResp error: {:?}",
                resp.error
            );
            assert_eq!(resp.sid.as_deref(), Some(sid.as_str()));
            if let Some(ref candidates) = resp.candidate_addrs {
                assert!(
                    candidates.iter().any(|a| a.contains("1.2.3.4")),
                    "provider A's candidate_addrs should contain visitor addresses"
                );
            }
        }
        other => panic!(
            "expected NatHoleResp on provider A control, got: {:?}",
            other.v1_type_byte()
        ),
    }

    // --- Visitor reads NatHoleResp for proxy A ---
    match read_msg_v1(&mut visitor_conn)
        .await
        .expect("read visitor NatHoleResp A")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_none(),
                "visitor NatHoleResp A error: {:?}",
                resp.error
            );
            assert!(resp.sid.is_some(), "visitor NatHoleResp A should have sid");
            if let Some(ref candidates) = resp.candidate_addrs {
                assert!(
                    candidates.iter().any(|a| a.contains("10.0.0.1")),
                    "visitor's candidate_addrs should contain provider A addresses"
                );
            }
        }
        other => panic!(
            "expected NatHoleResp on visitor A, got: {:?}",
            other.v1_type_byte()
        ),
    }

    // --- Verify NO message leakage to provider B's work conn ---
    // work_conn_b should NOT receive anything — use a short timeout read.
    // tokio::time::timeout with read_msg_v1 on work_conn_b.
    let leaked = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        read_msg_v1(&mut work_conn_b),
    )
    .await;
    match leaked {
        Ok(Ok(msg)) => {
            panic!(
                "work_conn_B received unexpected message (message leakage!): {:?}",
                msg.v1_type_byte()
            );
        }
        Ok(Err(e)) => {
            // Connection error is acceptable (may have been closed by server)
            // as long as no valid XTCP message was received.
            eprintln!("work_conn_B read error (expected, no leakage): {:?}", e);
        }
        Err(_elapsed) => {
            // Timeout = no message received = correct behavior
            eprintln!("work_conn_B timeout — no message leakage confirmed");
        }
    }

    // --- Provider B's control channel must still be usable ---
    let np_b2 = FrpMessage::NewProxy(xtcp_proxy("xtcp-prov-b-2", "sk-prov-b-2", "127.0.0.1:9003"));
    write_msg_v1(&mut provider_b_ctl, &np_b2)
        .await
        .expect("send NewProxy B2");
    match read_msg_v1(&mut provider_b_ctl)
        .await
        .expect("read NewProxyResp B2")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(
                r.error.is_none(),
                "provider B second proxy should succeed: {:?}",
                r.error
            );
        }
        other => panic!("expected NewProxyResp B2, got: {:?}", other.v1_type_byte()),
    }

    // --- Send NatHoleReport for cleanup ---
    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
        sid: Some(sid.clone()),
    });
    write_msg_v1(&mut provider_a_ctl, &report)
        .await
        .expect("send NatHoleReport A");

    drop(provider_a_ctl);
    drop(provider_b_ctl);
    drop(visitor_conn);
    drop(work_conn_a);
    drop(work_conn_b);
}

/// Register XTCP proxy with encryption and compression flags, then
/// verify those flags propagate through to the StartWorkConn sent
/// on the work connection when a visitor triggers the XTCP flow.
#[tokio::test]
async fn test_xtcp_encrypted_proxy_registration() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Provider login + register XTCP proxy with encryption/compression ---
    let (mut provider_ctl, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("provider should get run_id");

    let np = FrpMessage::NewProxy(xtcp_proxy_encrypted(
        "xtcp-encrypted",
        "encrypted-sk",
        "127.0.0.1:7777",
    ));
    write_msg_v1(&mut provider_ctl, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl)
        .await
        .expect("read NewProxyResp")
    {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "proxy reg error: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // --- Establish work conn ---
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
        proxy_name: "xtcp-encrypted".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut precheck_conn, &precheck_msg)
        .await
        .expect("send precheck");
    match read_msg_v1(&mut precheck_conn)
        .await
        .expect("read precheck resp")
    {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "precheck error: {:?}", resp.error);
            assert!(resp.sid.is_none(), "precheck should not have sid");
        }
        other => panic!(
            "expected NatHoleResp for precheck, got: {:?}",
            other.v1_type_byte()
        ),
    }
    drop(precheck_conn);

    // --- Full NatHoleVisitor to trigger StartWorkConn ---
    let txn_id = format!("enc-txn-{}", port);
    let mut visitor_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("visitor full connect"),
    );
    let nhv = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: txn_id.clone(),
        proxy_name: "xtcp-encrypted".into(),
        pre_check: false,
        protocol: Some("tcp".to_string()),
        sign_key: None,
        timestamp: None,
        mapped_addrs: Some(vec!["5.5.5.5:5555".to_string()]),
        assisted_addrs: None,
    });
    write_msg_v1(&mut visitor_conn, &nhv)
        .await
        .expect("send full NatHoleVisitor");

    // --- Read StartWorkConn from work conn, verify encryption flags ---
    match read_msg_v1(&mut work_conn)
        .await
        .expect("read StartWorkConn from work conn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "xtcp-encrypted");
            assert_eq!(
                swc.use_encryption,
                Some(true),
                "StartWorkConn.use_encryption should be Some(true), got: {:?}",
                swc.use_encryption
            );
            assert_eq!(
                swc.use_compression,
                Some(true),
                "StartWorkConn.use_compression should be Some(true), got: {:?}",
                swc.use_compression
            );

            // NatHoleSid embedded in StartWorkConn (Rust frp extension).
            let sid = swc
                .nat_hole_sid
                .clone()
                .expect("StartWorkConn should have nat_hole_sid");
            assert!(!sid.is_empty(), "sid should be non-empty");
        }
        other => panic!(
            "expected StartWorkConn on work conn, got: {:?}",
            other.v1_type_byte()
        ),
    }

    drop(provider_ctl);
    drop(visitor_conn);
    drop(work_conn);
}
