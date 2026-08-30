//! Round-14 protocol coverage (test-completeness audit).
//!
//! The existing inline tests in `frp-core/src/protocol.rs` round-trip only a
//! Login over the V1 wire path; every other message type is covered only by
//! JSON-level serde tests, which cannot catch a write-path type-byte or
//! framing bug. The read path is also never pinned against malformed
//! payloads (invalid UTF-8, trailing garbage, `null`) — those must yield
//! `Err`, never panic (with `panic = "abort"` a panic is a process abort).

use tokio::io::{AsyncWriteExt, DuplexStream};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{
    read_msg_v1, read_msg_v2, read_v2_magic_or_replay, write_v1_frame, write_v2_frame_raw,
    V2_FRAME_TYPE_MESSAGE, V2_MAGIC_BYTES,
};

fn duplex() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(64 * 1024)
}

/// One fully-populated instance of every FrpMessage variant.
fn all_message_variants() -> Vec<FrpMessage> {
    let mut v = vec![
        FrpMessage::Login(Box::new(msg::Login {
            version: Some("0.71.0".into()),
            hostname: Some("h1".into()),
            os: Some("linux".into()),
            arch: Some("amd64".into()),
            user: Some("u1".into()),
            run_id: Some("r1".into()),
            client_id: Some("c1".into()),
            pool_count: Some(5),
            timestamp: Some(1_721_000_000_123),
            privilege_key: Some("pk".into()),
            metas: Some([("k".to_string(), "v".to_string())].into()),
            client_spec: Some(msg::ClientSpec {
                client_type: Some("frpc".into()),
                always_auth_pass: Some(false),
            }),
            multiplexer: Some("yamux".into()),
        })),
        FrpMessage::LoginResp(msg::LoginResp {
            version: Some("0.71.0".into()),
            run_id: Some("r1".into()),
            error: None,
            server_additional_auth_scopes: Some(vec!["HeartBeats".into()]),
        }),
        FrpMessage::NewProxy(Box::new(msg::NewProxy {
            proxy_name: "alice.web".into(),
            proxy_type: "http".into(),
            use_encryption: Some(true),
            use_compression: Some(false),
            group: Some("web".into()),
            group_key: Some("gkey".into()),
            local_str: Some("10.0.0.1:8080".into()),
            remote_port: Some(7001),
            sk: Some("s3cret".into()),
            custom_domains: Some(vec!["web.example.com".into()]),
            subdomain: Some("web".into()),
            locations: Some(vec!["/".into(), "/api".into()]),
            http_user: Some("admin".into()),
            http_pwd: Some("pw".into()),
            host_header_rewrite: Some("internal.example.com".into()),
            headers: Some([("X-A".to_string(), "1".to_string())].into()),
            response_headers: Some([("X-B".to_string(), "2".to_string())].into()),
            route_by_http_user: Some("alice".into()),
            allow_users: Some(vec!["alice".into(), "bob".into()]),
            bandwidth_limit: Some("2MB".into()),
            bandwidth_limit_mode: Some("server".into()),
            annotations: Some([("owner".to_string(), "ops".to_string())].into()),
            metas: Some([("env".to_string(), "prod".to_string())].into()),
            multiplexer: Some("yamux".into()),
            virtual_net: Some("vn1".into()),
            proxy_protocol_version: Some("v2".into()),
            advertise_subnet: Some("10.0.0.0/8".into()),
            vnet_ip: Some("10.0.0.2".into()),
            vnet_netmask: Some("255.255.0.0".into()),
            vnet_mtu: Some(1400),
        })),
        FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: "p1".into(),
            remote_addr: Some("0.0.0.0:7001".into()),
            error: None,
        }),
        FrpMessage::CloseProxy(msg::CloseProxy {
            proxy_name: "p1".into(),
        }),
        FrpMessage::CloseProxyResp(msg::CloseProxyResp {
            proxy_name: "p1".into(),
        }),
        FrpMessage::Error(msg::Error {
            error: "something failed".into(),
        }),
        FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some("r1".into()),
            timestamp: Some(99),
            privilege_key: Some("pk".into()),
        }),
        FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
        FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
            proxy_name: "tcp1".into(),
            src_addr: Some("1.2.3.4".into()),
            src_port: Some(12345),
            dst_addr: Some("5.6.7.8".into()),
            dst_port: Some(80),
            error: None,
            use_encryption: Some(true),
            use_compression: Some(true),
            nat_hole_sid: Some("sid-1".into()),
            nat_hole_visitor_addr: Some("9.9.9.9:9000".into()),
            sk: Some("s3cret".into()),
        })),
        FrpMessage::Ping(msg::Ping {
            privilege_key: Some("pk".into()),
            timestamp: Some(123),
        }),
        FrpMessage::Pong(msg::Pong {
            error: Some("ok".into()),
        }),
        FrpMessage::NewVisitorConn(msg::NewVisitorConn {
            proxy_name: "stcp1".into(),
            sign_key: Some("sk".into()),
            timestamp: Some(99),
            run_id: Some("r1".into()),
            use_encryption: Some(true),
            use_compression: Some(false),
        }),
        FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
            proxy_name: "stcp1".into(),
            error: None,
        }),
        FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"hello".to_vec(),
            local_addr: Some(msg::UdpAddr {
                ip: "127.0.0.1".into(),
                port: 53001,
                zone: String::new(),
            }),
            remote_addr: Some(msg::UdpAddr {
                ip: "10.0.0.2".into(),
                port: 53,
                zone: "eth0".into(),
            }),
        }),
        FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
            transaction_id: "t1".into(),
            proxy_name: "xtcp1".into(),
            pre_check: true,
            protocol: Some("quic".into()),
            sign_key: Some("sk".into()),
            timestamp: Some(123),
            mapped_addrs: Some(vec!["1.2.3.4:1000".into()]),
            assisted_addrs: Some(vec!["5.6.7.8:2000".into()]),
        }),
        FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
            transaction_id: "t1".into(),
            proxy_name: "xtcp1".into(),
            sid: Some("s1".into()),
            protocol: Some("quic".into()),
            mapped_addrs: Some(vec!["1.2.3.4:1000".into()]),
            assisted_addrs: Some(vec!["5.6.7.8:2000".into()]),
            visitor_addr: Some("9.9.9.9:9000".into()),
        })),
        FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: "t1".into(),
            error: None,
            sid: Some("s1".into()),
            protocol: Some("quic".into()),
            candidate_addrs: Some(vec!["1.2.3.4:1000".into()]),
            assisted_addrs: Some(vec!["5.6.7.8:2000".into()]),
            detect_behavior: Some(msg::NatHoleDetectBehavior {
                mode: 2,
                role: Some("sender".into()),
                ttl: 16,
                send_delay_ms: 20,
                read_timeout_ms: 100,
                send_random_ports: 3,
                listen_random_ports: 3,
                candidate_ports: Some(vec![msg::PortsRange {
                    from: 10000,
                    to: 20000,
                }]),
            }),
        })),
        FrpMessage::NatHoleSid(msg::NatHoleSid {
            transaction_id: Some("t1".into()),
            sid: Some("s1".into()),
            response: true,
            nonce: Some("n1".into()),
        }),
        FrpMessage::NatHoleReport(msg::NatHoleReport {
            sid: Some("s1".into()),
            success: true,
        }),
    ];
    #[cfg(feature = "vnet")]
    v.extend([
        FrpMessage::VnetRouteAdvertise(msg::VnetRouteAdvertise {
            proxy_name: "vnet-adv".into(),
            subnet: "10.0.0.0/8".into(),
            virtual_net: Some("vn1".into()),
        }),
        FrpMessage::VnetRouteRemove(msg::VnetRouteRemove {
            proxy_name: "vnet-rm".into(),
            virtual_net: Some("vn1".into()),
        }),
        FrpMessage::VnetPacket(msg::VnetPacket {
            proxy_name: "vnet-pkt".into(),
            data: "AQID".into(),
        }),
    ]);
    v
}

#[tokio::test]
async fn test_v1_all_message_types_wire_roundtrip() {
    // Every FrpMessage variant must survive write_v1_frame → read_msg_v1
    // with full field fidelity. JSON-level serde tests cannot catch a
    // write-path type-byte mistake or framing error; only the wire
    // round-trip can.
    for msg in all_message_variants() {
        let (mut client, mut server) = duplex();
        write_v1_frame(&mut client, &msg)
            .await
            .unwrap_or_else(|e| panic!("write {msg:?}: {e}"));
        let out = read_msg_v1(&mut server)
            .await
            .unwrap_or_else(|e| panic!("read {msg:?}: {e}"));
        assert_eq!(out, msg, "V1 wire round-trip changed the message");
    }
}

/// Write a raw V1 frame: 1-byte type + 8-byte big-endian length + payload.
async fn write_v1_raw<W: AsyncWriteExt + Unpin>(w: &mut W, ty: u8, payload: &[u8]) {
    let mut header = [0u8; 9];
    header[0] = ty;
    header[1..9].copy_from_slice(&(payload.len() as u64).to_be_bytes());
    w.write_all(&header).await.unwrap();
    w.write_all(payload).await.unwrap();
    w.flush().await.unwrap();
}

#[tokio::test]
async fn test_v1_malformed_payloads_error_not_panic() {
    // (a) invalid UTF-8 in a Login frame — serde_json must fail closed
    let (mut w, mut r) = duplex();
    write_v1_raw(&mut w, msg::TYPE_LOGIN, &[0xFF, 0xFE, 0xFD]).await;
    assert!(
        read_msg_v1(&mut r).await.is_err(),
        "invalid UTF-8 payload must be rejected"
    );

    // (b) trailing garbage after a valid JSON object
    let (mut w, mut r) = duplex();
    write_v1_raw(&mut w, msg::TYPE_LOGIN, br#"{"version":"0.71.0"}"tail"#).await;
    assert!(
        read_msg_v1(&mut r).await.is_err(),
        "trailing bytes after JSON must be rejected"
    );

    // (c) `null` payload — matches no FrpMessage variant
    let (mut w, mut r) = duplex();
    write_v1_raw(&mut w, msg::TYPE_LOGIN, b"null").await;
    assert!(
        read_msg_v1(&mut r).await.is_err(),
        "null payload must be rejected"
    );

    // (d) empty payload
    let (mut w, mut r) = duplex();
    write_v1_raw(&mut w, msg::TYPE_LOGIN, b"").await;
    assert!(
        read_msg_v1(&mut r).await.is_err(),
        "empty payload must be rejected"
    );
}

#[tokio::test]
async fn test_v2_malformed_payloads_error_not_panic() {
    // (a) invalid UTF-8 after the type-id prefix
    let mut payload = Vec::new();
    payload.extend_from_slice(&msg::V2_TYPE_LOGIN.to_be_bytes());
    payload.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
    let (mut w, mut r) = duplex();
    write_v2_frame_raw(&mut w, V2_FRAME_TYPE_MESSAGE, 0, &payload)
        .await
        .unwrap();
    assert!(
        read_msg_v2(&mut r).await.is_err(),
        "invalid UTF-8 payload must be rejected"
    );

    // (b) trailing garbage after a valid JSON object
    let mut payload = Vec::new();
    payload.extend_from_slice(&msg::V2_TYPE_LOGIN.to_be_bytes());
    payload.extend_from_slice(br#"{"version":"0.71.0"}"#);
    payload.extend_from_slice(b"XX");
    let (mut w, mut r) = duplex();
    write_v2_frame_raw(&mut w, V2_FRAME_TYPE_MESSAGE, 0, &payload)
        .await
        .unwrap();
    assert!(
        read_msg_v2(&mut r).await.is_err(),
        "trailing bytes after JSON must be rejected"
    );
}

#[tokio::test]
async fn test_v2_magic_mismatch_replays_bytes_for_v1_fallback() {
    // Exact magic is consumed → Ok(None)
    let (mut w, mut r) = duplex();
    w.write_all(&V2_MAGIC_BYTES).await.unwrap();
    w.flush().await.unwrap();
    let got = read_v2_magic_or_replay(&mut r).await.unwrap();
    assert!(got.is_none(), "matching magic must be consumed");

    // A mismatched prefix (e.g. a TLS first byte 0x16) is returned for
    // replay on the V1/TLS fallback path, byte-for-byte.
    let prefix = b"\x16\x03\x01\x00\x2a\x00\x01";
    let (mut w, mut r) = duplex();
    w.write_all(prefix).await.unwrap();
    w.flush().await.unwrap();
    let got = read_v2_magic_or_replay(&mut r).await.unwrap();
    assert_eq!(got.as_deref(), Some(prefix.as_slice()));

    // EOF before the full magic → Err, not panic.
    let (w, mut r) = duplex();
    drop(w);
    assert!(read_v2_magic_or_replay(&mut r).await.is_err());
}
