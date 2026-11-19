use super::*;

fn roundtrip<T: Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq>(
    val: &T,
    expected_json: &str,
) {
    let json = serde_json::to_string(val).expect("serialize");
    // Verify JSON matches expected (ignoring field ordering)
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse serialized");
    let expected: serde_json::Value = serde_json::from_str(expected_json).expect("parse expected");
    assert_eq!(v, expected, "serialized JSON mismatch");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        &back, val,
        "deserialize must round-trip to the original value"
    );
}

#[test]
fn test_login_roundtrip_minimal() {
    let login = Login {
        version: None,
        hostname: None,
        os: None,
        arch: None,
        user: None,
        run_id: None,
        client_id: None,
        pool_count: None,
        timestamp: None,
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: None,
    };
    roundtrip(&login, r#"{}"#);
}

#[test]
fn test_login_roundtrip_full() {
    let mut metas = std::collections::HashMap::new();
    metas.insert("k".into(), "v".into());
    let login = Login {
        version: Some("0.69.1".into()),
        hostname: Some("testhost".into()),
        os: Some("linux".into()),
        arch: Some("amd64".into()),
        user: Some("admin".into()),
        run_id: Some("abc123".into()),
        client_id: Some("cid1".into()),
        pool_count: Some(5),
        timestamp: Some(1234567890),
        privilege_key: Some("key123".into()),
        metas: Some(metas),
        client_spec: Some(ClientSpec {
            client_type: Some("frpc".into()),
            always_auth_pass: Some(false),
        }),
        multiplexer: Some("yamux".into()),
    };
    // Golden wire format: client_spec serializes as `type` (Go frp
    // ClientSpec JSON key, msg.rs ClientSpec rename) and must come back
    // on deserialization — the roundtrip helper's equality assert pins
    // both directions.
    roundtrip(
        &login,
        r#"{"version":"0.69.1","hostname":"testhost","os":"linux","arch":"amd64","user":"admin","run_id":"abc123","client_id":"cid1","pool_count":5,"timestamp":1234567890,"privilege_key":"key123","metas":{"k":"v"},"client_spec":{"type":"frpc","always_auth_pass":false},"multiplexer":"yamux"}"#,
    );
}

#[test]
fn test_login_resp_roundtrip() {
    let resp = LoginResp {
        version: Some("0.69.1".into()),
        run_id: Some("rid1".into()),
        error: None,
        server_additional_auth_scopes: None,
    };
    roundtrip(&resp, r#"{"version":"0.69.1","run_id":"rid1"}"#);

    let err_resp = LoginResp {
        version: None,
        run_id: None,
        error: Some("auth failed".into()),
        server_additional_auth_scopes: None,
    };
    roundtrip(&err_resp, r#"{"error":"auth failed"}"#);

    let scoped_resp = LoginResp {
        version: Some("0.69.1".into()),
        run_id: Some("rid2".into()),
        error: None,
        server_additional_auth_scopes: Some(vec!["HeartBeats".into(), "NewWorkConns".into()]),
    };
    roundtrip(
        &scoped_resp,
        r#"{"version":"0.69.1","run_id":"rid2","serverAdditionalAuthScopes":["HeartBeats","NewWorkConns"]}"#,
    );
}

#[test]
fn test_new_proxy_roundtrip() {
    let np = NewProxy {
        proxy_name: "http-proxy".into(),
        proxy_type: "tcp".into(),
        use_encryption: Some(true),
        use_compression: Some(false),
        group: Some("web".into()),
        group_key: Some("hash-key".into()),
        local_str: None,
        remote_port: Some(8080),
        sk: None,
        custom_domains: Some(vec!["example.com".into()]),
        subdomain: None,
        locations: Some(vec!["/api".into(), "/admin".into()]),
        http_user: Some("user".into()),
        http_pwd: Some("pass".into()),
        host_header_rewrite: Some("backend.local".into()),
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: Some("1MB".into()),
        bandwidth_limit_mode: Some("client".into()),
        annotations: None,
        metas: None,
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    };
    let json = serde_json::to_string(&np).expect("serialize");
    let back: NewProxy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.proxy_name, "http-proxy");
    assert_eq!(back.use_encryption, Some(true));
    assert_eq!(back.locations.as_ref().unwrap().len(), 2);
    assert_eq!(back.http_user.as_deref(), Some("user"));
    assert_eq!(back.http_pwd.as_deref(), Some("pass"));
    assert_eq!(back.host_header_rewrite.as_deref(), Some("backend.local"));
    assert_eq!(back.bandwidth_limit.as_deref(), Some("1MB"));
    assert_eq!(back.group.as_deref(), Some("web"));
    assert_eq!(
        back, np,
        "deserialize must round-trip to the original value"
    );
}

/// Every NewProxy field must serialize under its snake_case Go wire key.
/// Go frp silently ignores unknown keys — a rename typo on ANY field
/// would break interop without an error, so each key is pinned here.
#[test]
fn test_new_proxy_all_fields_wire_keys() {
    let mut response_headers = std::collections::HashMap::new();
    response_headers.insert("X-Custom".into(), "v1".into());
    let mut annotations = std::collections::HashMap::new();
    annotations.insert("env".into(), "prod".into());
    let mut metas = std::collections::HashMap::new();
    metas.insert("region".into(), "us-east".into());

    let np = NewProxy {
        proxy_name: "all-fields".into(),
        proxy_type: "http".into(),
        use_encryption: Some(true),
        use_compression: Some(true),
        group: Some("g1".into()),
        group_key: Some("gk".into()),
        local_str: Some("127.0.0.1:80".into()),
        remote_port: Some(8080),
        sk: Some("sk1".into()),
        custom_domains: Some(vec!["a.example.com".into(), "b.example.com".into()]),
        subdomain: Some("sub".into()),
        locations: Some(vec!["/api".into(), "/admin".into()]),
        http_user: Some("user".into()),
        http_pwd: Some("pass".into()),
        host_header_rewrite: Some("backend.local".into()),
        headers: None,
        response_headers: Some(response_headers),
        route_by_http_user: Some("alice".into()),
        allow_users: Some(vec!["alice".into(), "bob".into()]),
        bandwidth_limit: Some("1MB".into()),
        bandwidth_limit_mode: Some("client".into()),
        annotations: Some(annotations),
        metas: Some(metas),
        multiplexer: Some("yamux".into()),
        virtual_net: Some("vn1".into()),
        proxy_protocol_version: Some("v2".into()),
        advertise_subnet: Some("10.0.0.0/8".into()),
        vnet_ip: Some("10.0.0.1".into()),
        vnet_netmask: Some("255.0.0.0".into()),
        vnet_mtu: Some(1500),
    };
    let json = serde_json::to_string(&np).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");

    assert_eq!(v["proxy_name"], "all-fields", "proxy_name wire key");
    assert_eq!(v["proxy_type"], "http", "proxy_type wire key");
    assert_eq!(v["use_encryption"], true, "use_encryption wire key");
    assert_eq!(v["use_compression"], true, "use_compression wire key");
    assert_eq!(v["group"], "g1", "group wire key");
    assert_eq!(v["group_key"], "gk", "group_key wire key");
    assert_eq!(v["local_str"], "127.0.0.1:80", "local_str wire key");
    assert_eq!(v["remote_port"], 8080, "remote_port wire key");
    assert_eq!(v["sk"], "sk1", "sk wire key");
    assert_eq!(
        v["custom_domains"][0], "a.example.com",
        "custom_domains wire key"
    );
    assert_eq!(
        v["custom_domains"][1], "b.example.com",
        "custom_domains wire key"
    );
    assert_eq!(v["subdomain"], "sub", "subdomain wire key");
    assert_eq!(v["locations"][0], "/api", "locations wire key");
    assert_eq!(v["locations"][1], "/admin", "locations wire key");
    assert_eq!(v["http_user"], "user", "http_user wire key");
    assert_eq!(v["http_pwd"], "pass", "http_pwd wire key");
    assert_eq!(
        v["host_header_rewrite"], "backend.local",
        "host_header_rewrite wire key"
    );
    assert_eq!(
        v["response_headers"]["X-Custom"], "v1",
        "response_headers wire key"
    );
    assert_eq!(
        v["route_by_http_user"], "alice",
        "route_by_http_user wire key"
    );
    assert_eq!(v["allow_users"][0], "alice", "allow_users wire key");
    assert_eq!(v["allow_users"][1], "bob", "allow_users wire key");
    assert_eq!(v["bandwidth_limit"], "1MB", "bandwidth_limit wire key");
    assert_eq!(
        v["bandwidth_limit_mode"], "client",
        "bandwidth_limit_mode wire key"
    );
    assert_eq!(v["annotations"]["env"], "prod", "annotations wire key");
    assert_eq!(v["metas"]["region"], "us-east", "metas wire key");
    assert_eq!(v["multiplexer"], "yamux", "multiplexer wire key");
    assert_eq!(v["virtual_net"], "vn1", "virtual_net wire key");
    assert_eq!(
        v["proxy_protocol_version"], "v2",
        "proxy_protocol_version wire key"
    );
    assert_eq!(
        v["advertise_subnet"], "10.0.0.0/8",
        "advertise_subnet wire key"
    );
    assert_eq!(v["vnet_ip"], "10.0.0.1", "vnet_ip wire key");
    assert_eq!(v["vnet_netmask"], "255.0.0.0", "vnet_netmask wire key");
    assert_eq!(v["vnet_mtu"], 1500, "vnet_mtu wire key");

    // Deserialization must recover the exact value (a rename typo in
    // either direction would surface here as a mismatch).
    let back: NewProxy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, np);
}

#[test]
fn test_new_proxy_resp_roundtrip() {
    let resp = NewProxyResp {
        proxy_name: "p1".into(),
        remote_addr: Some("0.0.0.0:7001".into()),
        error: None,
    };
    roundtrip(&resp, r#"{"proxy_name":"p1","remote_addr":"0.0.0.0:7001"}"#);
}

#[test]
fn test_close_proxy_roundtrip() {
    roundtrip(
        &CloseProxy {
            proxy_name: "p1".into(),
        },
        r#"{"proxy_name":"p1"}"#,
    );
}

#[test]
fn test_close_proxy_resp_roundtrip() {
    roundtrip(
        &CloseProxyResp {
            proxy_name: "p1".into(),
        },
        r#"{"proxy_name":"p1"}"#,
    );
}

#[test]
fn test_error_msg_roundtrip() {
    roundtrip(
        &Error {
            error: "something broke".into(),
        },
        r#"{"error":"something broke"}"#,
    );
}

#[test]
fn test_new_work_conn_roundtrip() {
    let nwc = NewWorkConn {
        run_id: Some("rid1".into()),
        timestamp: Some(9999),
        privilege_key: Some("priv".into()),
    };
    roundtrip(
        &nwc,
        r#"{"run_id":"rid1","timestamp":9999,"privilege_key":"priv"}"#,
    );
}

#[test]
fn test_req_work_conn_roundtrip() {
    roundtrip(&ReqWorkConn {}, r#"{}"#);
}

#[test]
fn test_start_work_conn_roundtrip() {
    let swc = StartWorkConn {
        proxy_name: "p1".into(),
        src_addr: Some("1.2.3.4".into()),
        src_port: Some(12345),
        dst_addr: None,
        dst_port: None,
        error: None,
        use_encryption: None,
        use_compression: None,
        nat_hole_sid: None,
        nat_hole_visitor_addr: None,
        sk: None,
    };
    roundtrip(
        &swc,
        r#"{"proxy_name":"p1","src_addr":"1.2.3.4","src_port":12345}"#,
    );
}

#[test]
fn test_start_work_conn_reject_frame_omits_empty_proxy_name() {
    // Round-12 B3: a REJECT StartWorkConn (empty proxy_name, error set)
    // must serialize Go-identically — all fields omitempty, so the wire
    // frame is `{"error": ...}` alone (Go msg.go:154-161). Pre-fix the
    // empty proxy_name leaked as `"proxy_name":""`.
    let reject = StartWorkConn {
        proxy_name: String::new(),
        src_addr: None,
        src_port: None,
        dst_addr: None,
        dst_port: None,
        error: Some("work connection pool is full, discarding".into()),
        use_encryption: None,
        use_compression: None,
        nat_hole_sid: None,
        nat_hole_visitor_addr: None,
        sk: None,
    };
    roundtrip(
        &reject,
        r#"{"error":"work connection pool is full, discarding"}"#,
    );
    // A Go reject frame (no proxy_name key) must also DECODE — the
    // `default` on proxy_name.
    let go_frame = serde_json::from_str::<StartWorkConn>(r#"{"error":"no"}"#).unwrap();
    assert_eq!(go_frame.proxy_name, "");
    assert_eq!(go_frame.error.as_deref(), Some("no"));
}

#[test]
fn test_start_work_conn_ports_are_u16() {
    // Round 10 (LOW): Go StartWorkConn ports are uint16 — a hostile frame
    // with -1 or 70000 fails json.Unmarshal in Go. frp-rs used Option<i32>
    // which accepted both; the fields are now Option<u16>, so the same
    // frames fail deserialization here too.
    let bad_neg = r#"{"proxy_name":"p","src_port":-1}"#;
    let bad_big = r#"{"proxy_name":"p","dst_port":70000}"#;
    assert!(serde_json::from_str::<StartWorkConn>(bad_neg).is_err());
    assert!(serde_json::from_str::<StartWorkConn>(bad_big).is_err());
    // In-range values still parse.
    let ok = serde_json::from_str::<StartWorkConn>(
        r#"{"proxy_name":"p","src_port":65535,"dst_port":0}"#,
    )
    .unwrap();
    assert_eq!(ok.src_port, Some(65535));
    assert_eq!(ok.dst_port, Some(0));
}

#[test]
fn test_ping_roundtrip() {
    let ping = Ping {
        privilege_key: Some("pk".into()),
        timestamp: Some(42),
    };
    roundtrip(&ping, r#"{"privilege_key":"pk","timestamp":42}"#);
}

#[test]
fn test_pong_roundtrip() {
    roundtrip(&Pong { error: None }, r#"{}"#);
    roundtrip(
        &Pong {
            error: Some("err".into()),
        },
        r#"{"error":"err"}"#,
    );
}

#[test]
fn test_new_visitor_conn_roundtrip() {
    // Wire shape pin: Go NewVisitorConn bools are `json:",omitempty"`
    // (pkg/msg/msg.go:168-169), so a false flag is OMITTED — the
    // `"use_compression":false` form can never appear from a Go peer.
    // The builder (frp-client proxy.rs `create_visitor_conn_msg`) emits
    // conditional-Some, so this roundtrip pins the Go-emittable shape.
    let nvc = NewVisitorConn {
        proxy_name: "stcp1".into(),
        sign_key: Some("sk".into()),
        timestamp: Some(99),
        run_id: Some("rid".into()),
        use_encryption: Some(true),
        use_compression: None,
    };
    roundtrip(
        &nvc,
        r#"{"proxy_name":"stcp1","sign_key":"sk","timestamp":99,"run_id":"rid","use_encryption":true}"#,
    );
}

#[test]
fn test_new_visitor_conn_resp_roundtrip() {
    roundtrip(
        &NewVisitorConnResp {
            proxy_name: "stcp1".into(),
            error: None,
        },
        r#"{"proxy_name":"stcp1"}"#,
    );
    roundtrip(
        &NewVisitorConnResp {
            proxy_name: "stcp1".into(),
            error: Some("denied".into()),
        },
        r#"{"proxy_name":"stcp1","error":"denied"}"#,
    );
}

#[test]
fn test_udp_packet_base64_roundtrip() {
    let data = vec![0, 1, 2, 255, 100];
    let pkt = UDPPacket {
        content: data.clone(),
        local_addr: Some(UdpAddr {
            ip: "127.0.0.1".into(),
            port: 53,
            zone: String::new(),
        }),
        remote_addr: Some(UdpAddr {
            ip: "10.0.0.1".into(),
            port: 9999,
            zone: String::new(),
        }),
    };
    let json = serde_json::to_string(&pkt).expect("serialize");
    // content field should be base64 encoded
    assert!(json.contains(r#""c":"#), "content field present");
    assert!(json.contains(r#""l":"#), "local_addr present");
    assert!(json.contains(r#""r":"#), "remote_addr present");
    let back: UDPPacket = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.content, data);
    assert_eq!(back.local_addr.as_ref().unwrap().ip, "127.0.0.1");
    assert_eq!(back.local_addr.as_ref().unwrap().port, 53);
    assert_eq!(back.remote_addr.as_ref().unwrap().ip, "10.0.0.1");
    assert_eq!(back.remote_addr.as_ref().unwrap().port, 9999);
}

#[test]
fn test_udp_packet_empty_datagram_go_compat() {
    // Go frp omits "c" (json:"c,omitempty") on empty datagrams and may
    // omit "l"/"r" (nil addrs). All three must deserialize cleanly.
    let json = r#"{}"#;
    let pkt: UDPPacket = serde_json::from_str(json).expect("empty packet");
    assert!(pkt.content.is_empty());
    assert!(pkt.local_addr.is_none());
    assert!(pkt.remote_addr.is_none());

    // And Rust->Go stays byte-identical: empty content is NOT serialized.
    let out = serde_json::to_string(&pkt).expect("serialize");
    assert_eq!(out, r#"{}"#);
}

#[test]
fn test_udp_packet_invalid_base64_rejected() {
    // Garbage in the base64 "c" content must make deserialization return
    // Err — never panic and never silently decode to empty (b64_de maps
    // the decode failure through serde::de::Error::custom).
    let json = r#"{"c":"!!!not-base64!!!","l":{"IP":"127.0.0.1","Port":53,"Zone":""},"r":{"IP":"10.0.0.1","Port":9999,"Zone":""}}"#;
    let result = serde_json::from_str::<UDPPacket>(json);
    assert!(
        result.is_err(),
        "garbage base64 content must fail UDPPacket deserialization"
    );

    // Padding violations are also rejected, not silently tolerated.
    let bad_padding =
        r#"{"c":"aGVsbG8=","r":{"IP":"10.0.0.1","Port":9999,"Zone":""},"featureFlags":["x"]}"#;
    // "aGVsbG8=" is valid; corrupt it: drop the padding.
    let corrupt = bad_padding.replace("aGVsbG8=", "aGVsbG8");
    assert!(
        serde_json::from_str::<UDPPacket>(&corrupt).is_err(),
        "invalid base64 length must fail deserialization"
    );
}

#[test]
fn test_b64_display_byte_exact_with_reference_encoder() {
    // The streaming `Display` encoder (used by `b64_ser` via
    // `collect_str`) must produce byte-identical output to the allocation
    // based reference encoder for every input length — including the
    // 0/1/2-byte remainder arms that carry the `=` padding rules.
    for len in [0usize, 1, 2, 3, 4, 5, 6, 15, 16, 17, 1024] {
        // Deterministic, non-trivial byte pattern covering all 6-bit
        // values (and the full 0..=255 range across the 1024 case).
        let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        assert_eq!(
            B64(&data).to_string(),
            crate::base64::encode(&data),
            "B64 Display mismatch at len {len}"
        );
    }

    // Explicit padding pins (Go base64.StdEncoding rules).
    assert_eq!(B64(b"").to_string(), "");
    assert_eq!(B64(b"f").to_string(), "Zg==");
    assert_eq!(B64(b"fo").to_string(), "Zm8=");
    assert_eq!(B64(b"foo").to_string(), "Zm9v");
    // 0xFF/0xFE remainders exercise the high-bit shifts.
    assert_eq!(B64(&[0xff]).to_string(), "/w==");
    assert_eq!(B64(&[0xff, 0xfe]).to_string(), "//4=");
}

#[test]
fn test_udp_packet_json_wire_form_reused_scratch() {
    // The `c` field wire form must be exactly Go's
    // `base64.StdEncoding.EncodeToString` inside the JSON string, and
    // serializing into a reused scratch buffer must equal `to_string`.
    let mut scratch: Vec<u8> = Vec::new();
    let encoder = |val: &UDPPacket, scratch: &mut Vec<u8>| -> String {
        scratch.clear();
        serde_json::to_writer(&mut *scratch, val).expect("serialize into scratch");
        String::from_utf8(scratch.clone()).expect("utf8 json")
    };

    // Empty content is omitted entirely (Go `json:"c,omitempty"`).
    let empty = UDPPacket {
        content: Vec::new(),
        local_addr: None,
        remote_addr: None,
    };
    assert_eq!(encoder(&empty, &mut scratch), r#"{}"#);
    assert_eq!(
        serde_json::to_string(&empty).expect("to_string"),
        encoder(&empty, &mut scratch),
        "reused-scratch output must equal to_string output"
    );

    // Non-empty content round-trips through the exact base64 text.
    for payload in [&b"h"[..], &b"he"[..], &b"hello"[..], &[0u8, 1, 2, 250][..]] {
        let pkt = UDPPacket {
            content: payload.to_vec(),
            local_addr: None,
            remote_addr: None,
        };
        let json = encoder(&pkt, &mut scratch);
        assert_eq!(
            json,
            format!(r#"{{"c":"{}"}}"#, crate::base64::encode(payload)),
            "wire form for payload {payload:?}"
        );
        let back: UDPPacket = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.content, payload);

        // Repeated serialization into the same buffer must not leak bytes
        // from the previous (longer) message.
        let again = encoder(&pkt, &mut scratch);
        assert_eq!(again, json, "scratch reuse must not retain previous bytes");
    }
}

#[test]
fn test_udp_packet_escaped_base64_string_decodes() {
    // serde_json only takes the borrowed-str fast path when the JSON
    // string has no escapes; an escaped payload arrives via the owned
    // `visit_string` default forwarding into `visit_str`. `=` is `=`,
    // so this decodes to "hello".
    let json = r#"{"c":"aGVsbG8="}"#;
    let pkt: UDPPacket = serde_json::from_str(json).expect("escaped content must decode");
    assert_eq!(pkt.content, b"hello");

    // Escaped-slash form of the same payload (base64 has no `/` here, so
    // use a payload that does: 0xFF encodes to "/w==").
    let json = r#"{"c":"/w=="}"#;
    let pkt: UDPPacket = serde_json::from_str(json).expect("escaped slash must decode");
    assert_eq!(pkt.content, vec![0xff]);
}

#[test]
fn test_nat_hole_report_success_go_compat() {
    // Go frp v0.71.0: Success bool `json:"success,omitempty"` — false is
    // omitted, true is emitted. Rust must serialize byte-identically.
    let ok = NatHoleReport {
        sid: Some("s1".into()),
        success: true,
    };
    assert_eq!(
        serde_json::to_string(&ok).expect("serialize"),
        r#"{"sid":"s1","success":true}"#,
        "success=true must be emitted"
    );

    let fail = NatHoleReport {
        sid: Some("s1".into()),
        success: false,
    };
    assert_eq!(
        serde_json::to_string(&fail).expect("serialize"),
        r#"{"sid":"s1"}"#,
        "success=false must be omitted (Go omitempty parity)"
    );

    // Deserialization accepts both forms.
    let from_true: NatHoleReport =
        serde_json::from_str(r#"{"sid":"s1","success":true}"#).expect("parse");
    assert!(from_true.success);
    let from_false: NatHoleReport =
        serde_json::from_str(r#"{"sid":"s1","success":false}"#).expect("parse");
    assert!(!from_false.success);
    let from_absent: NatHoleReport = serde_json::from_str(r#"{"sid":"s1"}"#).expect("parse");
    assert!(!from_absent.success);
}

#[test]
fn test_nat_hole_visitor_pre_check_go_compat() {
    // Go frp v0.71.0: PreCheck bool `json:"pre_check,omitempty"` — false
    // is omitted, true is emitted.
    let pre = NatHoleVisitor {
        transaction_id: "t1".into(),
        proxy_name: "p1".into(),
        pre_check: true,
        ..NatHoleVisitor::default()
    };
    assert_eq!(
        serde_json::to_string(&pre).expect("serialize"),
        r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":true}"#,
        "pre_check=true must be emitted"
    );

    let full = NatHoleVisitor {
        transaction_id: "t1".into(),
        proxy_name: "p1".into(),
        pre_check: false,
        ..NatHoleVisitor::default()
    };
    assert_eq!(
        serde_json::to_string(&full).expect("serialize"),
        r#"{"transaction_id":"t1","proxy_name":"p1"}"#,
        "pre_check=false must be omitted (Go omitempty parity)"
    );

    // Deserialization accepts both forms.
    let from_true: NatHoleVisitor =
        serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":true}"#)
            .expect("parse");
    assert!(from_true.pre_check);
    let from_false: NatHoleVisitor =
        serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":false}"#)
            .expect("parse");
    assert!(!from_false.pre_check);
    let from_absent: NatHoleVisitor =
        serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1"}"#).expect("parse");
    assert!(!from_absent.pre_check);
}

#[test]
fn test_nat_hole_client_roundtrip() {
    let client = NatHoleClient {
        transaction_id: "t1".into(),
        proxy_name: "xtcp-provider".into(),
        sid: Some("s1".into()),
        protocol: Some("quic".into()),
        mapped_addrs: Some(vec!["1.2.3.4:1000".into(), "5.6.7.8:2000".into()]),
        assisted_addrs: Some(vec!["9.9.9.9:3000".into()]),
        visitor_addr: Some("8.8.8.8:4000".into()),
    };
    roundtrip(
        &client,
        r#"{"transaction_id":"t1","proxy_name":"xtcp-provider","sid":"s1","protocol":"quic","mapped_addrs":["1.2.3.4:1000","5.6.7.8:2000"],"assisted_addrs":["9.9.9.9:3000"],"visitor_addr":"8.8.8.8:4000"}"#,
    );
}

#[test]
fn test_nat_hole_resp_roundtrip() {
    let resp = NatHoleResp {
        transaction_id: "t1".into(),
        error: Some("e1".into()),
        sid: Some("s1".into()),
        protocol: Some("quic".into()),
        candidate_addrs: Some(vec!["1.2.3.4:1000".into()]),
        assisted_addrs: Some(vec!["5.6.7.8:2000".into()]),
        detect_behavior: Some(NatHoleDetectBehavior {
            mode: 3,
            role: Some("sender".into()),
            ttl: 64,
            send_delay_ms: 10,
            // Go wire key is "read_timeout" (rename pins the alias).
            read_timeout_ms: 5000,
            send_random_ports: 4,
            listen_random_ports: 4,
            candidate_ports: Some(vec![PortsRange {
                from: 1000,
                to: 2000,
            }]),
        }),
    };
    roundtrip(
        &resp,
        r#"{"transaction_id":"t1","error":"e1","sid":"s1","protocol":"quic","candidate_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"detect_behavior":{"mode":3,"role":"sender","ttl":64,"send_delay_ms":10,"read_timeout":5000,"send_random_ports":4,"listen_random_ports":4,"candidate_ports":[{"from":1000,"to":2000}]}}"#,
    );
}

#[test]
fn test_nat_hole_sid_roundtrip() {
    // response=true is emitted; response=false is omitted (Go omitempty
    // parity) and defaults back to false on deserialization.
    let sid = NatHoleSid {
        transaction_id: Some("t1".into()),
        sid: Some("s1".into()),
        response: true,
        nonce: Some("n1".into()),
    };
    roundtrip(
        &sid,
        r#"{"transaction_id":"t1","sid":"s1","response":true,"nonce":"n1"}"#,
    );
    let quiet = NatHoleSid {
        transaction_id: Some("t1".into()),
        sid: Some("s1".into()),
        response: false,
        nonce: Some("n1".into()),
    };
    roundtrip(&quiet, r#"{"transaction_id":"t1","sid":"s1","nonce":"n1"}"#);
}

#[test]
fn test_frp_message_v1_type_bytes() {
    // Verify every known type byte maps to the correct variant
    let cases: Vec<(u8, &str)> = vec![
        (TYPE_LOGIN, "Login"),
        (TYPE_LOGIN_RESP, "LoginResp"),
        (TYPE_NEW_PROXY, "NewProxy"),
        (TYPE_NEW_PROXY_RESP, "NewProxyResp"),
        (TYPE_CLOSE_PROXY, "CloseProxy"),
        (TYPE_CLOSE_PROXY_RESP, "CloseProxyResp"),
        (TYPE_NEW_WORK_CONN, "NewWorkConn"),
        (TYPE_REQ_WORK_CONN, "ReqWorkConn"),
        (TYPE_START_WORK_CONN, "StartWorkConn"),
        (TYPE_PING, "Ping"),
        (TYPE_PONG, "Pong"),
        (TYPE_NEW_VISITOR_CONN, "NewVisitorConn"),
        (TYPE_NEW_VISITOR_CONN_RESP, "NewVisitorConnResp"),
        (TYPE_UDP_PACKET, "UDPPacket"),
        (TYPE_NAT_HOLE_VISITOR, "NatHoleVisitor"),
        (TYPE_NAT_HOLE_CLIENT, "NatHoleClient"),
        (TYPE_NAT_HOLE_RESP, "NatHoleResp"),
        (TYPE_NAT_HOLE_SID, "NatHoleSid"),
        (TYPE_NAT_HOLE_REPORT, "NatHoleReport"),
        (TYPE_ERROR, "Error"),
    ];
    for (ty, label) in cases {
        let msg = FrpMessage::from_v1_type_byte(ty)
            .unwrap_or_else(|| panic!("from_v1_type_byte({})", ty));
        assert_eq!(
            msg.v1_type_byte(),
            ty,
            "v1_type_byte roundtrip for {}",
            label
        );
    }
}

#[test]
fn test_frp_message_type_byte_dispatch() {
    // Verify type-byte dispatch (the production deserialization path)
    // Login with multiplexer
    let login_json = r#"{"version":"0.1.0","hostname":"h","multiplexer":"yamux"}"#;
    let login: Login = serde_json::from_str(login_json).expect("deserialize Login struct");
    assert_eq!(login.version.as_deref(), Some("0.1.0"));
    assert_eq!(login.multiplexer.as_deref(), Some("yamux"));

    // Error
    let error_json = r#"{"error":"something failed"}"#;
    let err: Error = serde_json::from_str(error_json).expect("deserialize Error struct");
    assert_eq!(err.error, "something failed");

    // CloseProxyResp
    let cpr_json = r#"{"proxy_name":"my-proxy"}"#;
    let cpr: CloseProxyResp =
        serde_json::from_str(cpr_json).expect("deserialize CloseProxyResp struct");
    assert_eq!(cpr.proxy_name, "my-proxy");
}

#[test]
fn test_unknown_type_byte() {
    assert!(FrpMessage::from_v1_type_byte(0x00).is_none());
    assert!(FrpMessage::from_v1_type_byte(0xFF).is_none());
}

// ---------------------------------------------------------------
// UdpAddr tests — serde JSON format matching Go frp v0.71.0
// ---------------------------------------------------------------

#[test]
fn test_udp_addr_serialize_matches_go_format() {
    // Go's net.UDPAddr has no omitempty on Zone: it is ALWAYS emitted,
    // `"Zone":""` when empty (Go frp v0.71.0 byte-identical output).
    let addr = UdpAddr {
        ip: "127.0.0.1".into(),
        port: 8080,
        zone: String::new(),
    };
    let json = serde_json::to_string(&addr).expect("serialize");
    assert_eq!(
        json, r#"{"IP":"127.0.0.1","Port":8080,"Zone":""}"#,
        "Zone must always be emitted, matching Go net.UDPAddr"
    );

    // Round-trip through deserialization.
    let back: UdpAddr = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.ip, "127.0.0.1");
    assert_eq!(back.port, 8080);
    assert_eq!(back.zone, "");

    // Deserialization from Go-form JSON that includes Zone.
    let go_json = r#"{"IP":"127.0.0.1","Port":8080,"Zone":""}"#;
    let from_go: UdpAddr = serde_json::from_str(go_json).expect("deserialize Go format");
    assert_eq!(from_go.ip, "127.0.0.1");
    assert_eq!(from_go.port, 8080);
    assert_eq!(from_go.zone, "");

    // A non-empty zone also round-trips byte-identically.
    let zoned = UdpAddr {
        ip: "fe80::1".into(),
        port: 8080,
        zone: "eth0".into(),
    };
    let zoned_json = serde_json::to_string(&zoned).expect("serialize");
    assert_eq!(zoned_json, r#"{"IP":"fe80::1","Port":8080,"Zone":"eth0"}"#);
    let from_zoned: UdpAddr = serde_json::from_str(&zoned_json).expect("deserialize");
    assert_eq!(from_zoned.zone, "eth0");
}

#[test]
fn test_udp_addr_deserialize_from_go_format() {
    let json = r#"{"IP":"10.0.0.1","Port":53,"Zone":""}"#;
    let addr: UdpAddr = serde_json::from_str(json).expect("deserialize");
    assert_eq!(addr.ip, "10.0.0.1");
    assert_eq!(addr.port, 53);
    assert_eq!(addr.zone, "");
}

#[test]
fn test_udp_addr_zone_defaults_to_empty() {
    // Go's net.UDPAddr always emits Zone, but hand-written JSON may
    // omit it: the `default` on Zone must fill "" (lenient parse).
    let addr: UdpAddr = serde_json::from_str(r#"{"IP":"1.2.3.4","Port":53}"#).expect("deserialize");
    assert_eq!(addr.ip, "1.2.3.4");
    assert_eq!(addr.port, 53);
    assert_eq!(addr.zone, "", "missing Zone must default to empty");
}

#[test]
fn test_udp_addr_from_string_ipv4() {
    let addr = UdpAddr::from_string("1.2.3.4:5678").expect("should parse IPv4:port");
    assert_eq!(addr.ip, "1.2.3.4");
    assert_eq!(addr.port, 5678);
    assert_eq!(addr.zone, "");
}

#[test]
fn test_udp_addr_from_string_ipv6() {
    let addr = UdpAddr::from_string("[::1]:9090").expect("should parse IPv6:port");
    assert_eq!(addr.ip, "::1");
    assert_eq!(addr.port, 9090);
    assert_eq!(addr.zone, "");
}

#[test]
fn test_udp_addr_from_string_invalid() {
    assert!(UdpAddr::from_string("not-an-address").is_none());
    assert!(UdpAddr::from_string("").is_none());
}

#[test]
fn test_udp_addr_to_string() {
    let addr = UdpAddr {
        ip: "192.168.1.1".into(),
        port: 3000,
        zone: String::new(),
    };
    assert_eq!(addr.to_string(), "192.168.1.1:3000");
}

/// Verify NewProxy fields serialize to Go frp v0.70.0 snake_case wire format.
/// Go frp ignores camelCase keys; this test guards against regression.
#[test]
fn test_new_proxy_wire_format_snake_case() {
    let mut resp_headers = std::collections::HashMap::new();
    resp_headers.insert("X-Custom".into(), "value".into());

    let np = NewProxy {
        proxy_name: "wire-test".into(),
        proxy_type: "http".into(),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: None,
        remote_port: None,
        sk: None,
        custom_domains: None,
        subdomain: None,
        locations: None,
        http_user: Some("alice".into()),
        http_pwd: Some("secret".into()),
        host_header_rewrite: Some("internal.example.com".into()),
        headers: None,
        response_headers: Some(resp_headers),
        route_by_http_user: Some("alice".into()),
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: Some("server".into()),
        annotations: None,
        metas: None,
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: Some("v2".into()),
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    };
    let json = serde_json::to_string(&np).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");

    // Wire keys MUST be snake_case for Go frp v0.70.0 compat.
    assert_eq!(v["http_user"].as_str(), Some("alice"), "http_user wire key");
    assert_eq!(v["http_pwd"].as_str(), Some("secret"), "http_pwd wire key");
    assert_eq!(
        v["host_header_rewrite"].as_str(),
        Some("internal.example.com"),
        "host_header_rewrite wire key"
    );
    assert_eq!(
        v["response_headers"]["X-Custom"].as_str(),
        Some("value"),
        "response_headers wire key"
    );
    assert_eq!(
        v["route_by_http_user"].as_str(),
        Some("alice"),
        "route_by_http_user wire key"
    );
    assert_eq!(
        v["bandwidth_limit_mode"].as_str(),
        Some("server"),
        "bandwidth_limit_mode wire key"
    );
    assert_eq!(
        v["proxy_protocol_version"].as_str(),
        Some("v2"),
        "proxy_protocol_version wire key"
    );

    // camelCase keys MUST NOT appear on the wire.
    assert!(
        v.get("httpUser").is_none(),
        "camelCase httpUser must NOT appear on wire"
    );
    assert!(
        v.get("httpPwd").is_none(),
        "camelCase httpPwd must NOT appear on wire"
    );
    assert!(
        v.get("hostHeaderRewrite").is_none(),
        "camelCase hostHeaderRewrite must NOT appear"
    );
    assert!(
        v.get("responseHeaders").is_none(),
        "camelCase responseHeaders must NOT appear"
    );
    assert!(
        v.get("routeByHTTPUser").is_none(),
        "camelCase routeByHTTPUser must NOT appear"
    );
    assert!(
        v.get("bandwidthLimitMode").is_none(),
        "camelCase bandwidthLimitMode must NOT appear"
    );
    assert!(
        v.get("proxyProtocolVersion").is_none(),
        "camelCase proxyProtocolVersion must NOT appear"
    );

    // Deserialize from Go-format JSON (snake_case only).
    let go_json = r#"{
            "proxy_name": "go-proxy",
            "proxy_type": "http",
            "http_user": "bob",
            "http_pwd": "bobpass",
            "host_header_rewrite": "go.internal",
            "response_headers": {"X-Go": "1"},
            "route_by_http_user": "bob",
            "bandwidth_limit_mode": "client",
            "proxy_protocol_version": "v1"
        }"#;
    let from_go: NewProxy = serde_json::from_str(go_json).expect("deserialize Go format");
    assert_eq!(from_go.proxy_name, "go-proxy");
    assert_eq!(from_go.http_user.as_deref(), Some("bob"));
    assert_eq!(from_go.http_pwd.as_deref(), Some("bobpass"));
    assert_eq!(from_go.host_header_rewrite.as_deref(), Some("go.internal"));
    assert_eq!(
        from_go
            .response_headers
            .as_ref()
            .and_then(|m| m.get("X-Go"))
            .map(|v| v.as_str()),
        Some("1")
    );
    assert_eq!(from_go.route_by_http_user.as_deref(), Some("bob"));
    assert_eq!(from_go.bandwidth_limit_mode.as_deref(), Some("client"));
    assert_eq!(from_go.proxy_protocol_version.as_deref(), Some("v1"));
}

// ---------------------------------------------------------------
// Forward compatibility: unknown fields must be tolerated
// ---------------------------------------------------------------

/// Assert that a JSON literal with an extra unknown key deserializes
/// into `T`. Future Go frp releases will add fields to wire messages;
/// serde ignores unknown fields by default and no struct here uses
/// `deny_unknown_fields` — this pins that property so a refactor
/// adding it is caught by tests instead of silently breaking every Go
/// peer on the wire.
fn accepts<T: serde::de::DeserializeOwned>(json: &str) {
    serde_json::from_str::<T>(json).unwrap_or_else(|e| {
        panic!(
            "expected {} to tolerate unknown fields in {}: {}",
            std::any::type_name::<T>(),
            json,
            e
        )
    });
}

#[test]
fn test_unknown_fields_are_tolerated_go_forward_compat() {
    // Every literal carries a plausible future-Go field
    // ("featureFlags") that no current struct declares, alongside each
    // struct's REAL required fields (Login.client_spec serializes as
    // `client_spec` — verified against the Go v0.71.0 binary).
    accepts::<Login>(
        r#"{"version":"0.71.0","hostname":"h1","os":"linux","arch":"amd64","user":"u1","run_id":"r1","client_id":"c1","pool_count":2,"timestamp":1234567890123,"privilege_key":"pk","metas":{"k":"v"},"client_spec":{"type":"frpc","always_auth_pass":false},"multiplexer":"yamux","featureFlags":["quic-ack"]}"#,
    );
    accepts::<LoginResp>(
        r#"{"version":"0.71.0","run_id":"r1","serverAdditionalAuthScopes":["HeartBeats"],"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NewProxy>(
        r#"{"proxy_name":"p1","proxy_type":"tcp","remote_port":7001,"local_str":"127.0.0.1:80","featureFlags":["quic-ack"]}"#,
    );
    accepts::<NewProxyResp>(
        r#"{"proxy_name":"p1","remote_addr":"0.0.0.0:7001","featureFlags":["quic-ack"]}"#,
    );
    accepts::<CloseProxy>(r#"{"proxy_name":"p1","featureFlags":["quic-ack"]}"#);
    accepts::<CloseProxyResp>(r#"{"proxy_name":"p1","featureFlags":["quic-ack"]}"#);
    #[cfg(feature = "vnet")]
    accepts::<VnetRouteAdvertise>(
        r#"{"proxy_name":"p1","subnet":"10.0.0.0/8","virtual_net":"vn1","featureFlags":["quic-ack"]}"#,
    );
    #[cfg(feature = "vnet")]
    accepts::<VnetPacket>(r#"{"proxy_name":"p1","data":"AQID","featureFlags":["quic-ack"]}"#);
    #[cfg(feature = "vnet")]
    accepts::<VnetRouteRemove>(
        r#"{"proxy_name":"p1","virtual_net":"vn1","featureFlags":["quic-ack"]}"#,
    );
    accepts::<StartWorkConn>(
        r#"{"proxy_name":"p1","src_addr":"1.2.3.4","src_port":12345,"dst_addr":"5.6.7.8","dst_port":80,"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NewWorkConn>(
        r#"{"run_id":"r1","timestamp":123,"privilege_key":"pk","featureFlags":["quic-ack"]}"#,
    );
    accepts::<ReqWorkConn>(r#"{"featureFlags":["quic-ack"]}"#);
    accepts::<Ping>(r#"{"timestamp":123,"privilege_key":"pk","featureFlags":["quic-ack"]}"#);
    accepts::<Pong>(r#"{"error":"ok","featureFlags":["quic-ack"]}"#);
    accepts::<NewVisitorConn>(
        r#"{"proxy_name":"stcp1","sign_key":"sk","timestamp":99,"run_id":"r1","use_encryption":true,"use_compression":false,"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NewVisitorConnResp>(r#"{"proxy_name":"stcp1","featureFlags":["quic-ack"]}"#);
    accepts::<UDPPacket>(
        r#"{"c":"AQID","l":{"IP":"127.0.0.1","Port":53,"Zone":""},"r":{"IP":"10.0.0.1","Port":9999,"Zone":""},"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NatHoleVisitor>(
        r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":true,"protocol":"quic","sign_key":"sk","timestamp":123,"mapped_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NatHoleClient>(
        r#"{"transaction_id":"t1","proxy_name":"p1","sid":"s1","protocol":"quic","mapped_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NatHoleResp>(
        r#"{"transaction_id":"t1","sid":"s1","protocol":"quic","candidate_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"featureFlags":["quic-ack"]}"#,
    );
    accepts::<NatHoleSid>(
        r#"{"transaction_id":"t1","sid":"s1","response":true,"nonce":"n1","featureFlags":["quic-ack"]}"#,
    );
    accepts::<NatHoleReport>(r#"{"sid":"s1","success":true,"featureFlags":["quic-ack"]}"#);
    accepts::<Error>(r#"{"error":"boom","featureFlags":["quic-ack"]}"#);
}

#[test]
fn test_missing_optional_fields_default_to_none() {
    // Go peers emit only the fields they set (omitempty). Absent keys must
    // fill Option fields with None and ints/bools with their serde(default)
    // zeros — parse-OK alone would not catch a lost #[serde(default)].
    let nwc: NewWorkConn = serde_json::from_str(r#"{"run_id":"r1"}"#).unwrap();
    assert_eq!(nwc.run_id, Some("r1".to_string()));
    assert_eq!(nwc.timestamp, None);
    assert_eq!(nwc.privilege_key, None);

    let swc: StartWorkConn = serde_json::from_str(r#"{"proxy_name":"p1"}"#).unwrap();
    assert_eq!(swc.proxy_name, "p1");
    assert_eq!(swc.src_addr, None);
    assert_eq!(swc.src_port, None);
    assert_eq!(swc.dst_addr, None);
    assert_eq!(swc.dst_port, None);
    assert_eq!(swc.error, None);
    assert_eq!(swc.use_encryption, None);
    assert_eq!(swc.use_compression, None);
    assert_eq!(swc.nat_hole_sid, None);
    assert_eq!(swc.nat_hole_visitor_addr, None);
    assert_eq!(swc.sk, None);

    let resp: NewProxyResp = serde_json::from_str(r#"{"proxy_name":"p1"}"#).unwrap();
    assert_eq!(resp.remote_addr, None);
    assert_eq!(resp.error, None);

    let ping: Ping = serde_json::from_str(r#"{}"#).unwrap();
    assert_eq!(ping.privilege_key, None);
    assert_eq!(ping.timestamp, None);

    let nc: NatHoleClient =
        serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1"}"#).unwrap();
    assert_eq!(nc.sid, None);
    assert_eq!(nc.protocol, None);
    assert_eq!(nc.mapped_addrs, None);
    assert_eq!(nc.assisted_addrs, None);
    assert_eq!(nc.visitor_addr, None);

    let sid: NatHoleSid = serde_json::from_str(r#"{"sid":"s1"}"#).unwrap();
    assert_eq!(sid.transaction_id, None);
    assert!(!sid.response);
    assert_eq!(sid.nonce, None);

    // Go omitempty drops zero-valued ints — an empty detect_behavior
    // object must fill every i32 with 0 (field-level #[serde(default)]).
    let nh: NatHoleResp =
        serde_json::from_str(r#"{"transaction_id":"t1","detect_behavior":{}}"#).unwrap();
    let db = nh.detect_behavior.unwrap();
    assert_eq!(
        (
            db.mode,
            db.ttl,
            db.send_delay_ms,
            db.read_timeout_ms,
            db.send_random_ports,
            db.listen_random_ports
        ),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!(db.role, None);
    assert_eq!(db.candidate_ports, None);
}
