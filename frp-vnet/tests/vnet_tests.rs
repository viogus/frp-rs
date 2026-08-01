use frp_vnet::router::RouteTable;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_route_table_integration() {
    let mut rt = RouteTable::new();

    // Register two clients
    rt.insert("client-a", "10.0.0.0/24").unwrap();
    rt.insert("client-b", "10.0.1.0/24").unwrap();

    // Packets for client-a's subnet
    assert_eq!(
        rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))),
        Some("client-a")
    );
    // Packets for client-b's subnet
    assert_eq!(
        rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 99))),
        Some("client-b")
    );
    // Packets for unknown subnet
    assert_eq!(rt.lookup(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), None);
}

#[test]
fn test_route_conflict_rejected() {
    let mut rt = RouteTable::new();
    rt.insert("a", "10.0.0.0/16").unwrap();
    // Same prefix length conflicts
    assert!(rt.insert("b", "10.0.0.0/16").is_err());
    // Different prefix length is allowed (resolved by longest-prefix-match)
    assert!(rt.insert("b", "10.0.0.0/24").is_ok());
}

#[test]
fn test_remove_and_reinsert() {
    let mut rt = RouteTable::new();
    rt.insert("a", "10.0.0.0/24").unwrap();
    rt.remove("a");
    // Now another client can use overlapping range
    assert!(rt.insert("b", "10.0.0.0/16").is_ok());
}

#[test]
fn test_message_serde() {
    let pkt = frp_vnet::msg::VnetPacket {
        proxy_name: "test".into(),
        data: "AAECAwQFBgcICQ==".into(), // base64 for bytes 0x00-0x09
    };
    let json = serde_json::to_string(&pkt).unwrap();
    let parsed: frp_vnet::msg::VnetPacket = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.proxy_name, "test");
    assert_eq!(parsed.data, "AAECAwQFBgcICQ==");
}

#[test]
fn test_route_advertise_serde() {
    let adv = frp_vnet::msg::VnetRouteAdvertise {
        proxy_name: "vnet-office".into(),
        subnet: "10.0.0.0/24".into(),
        virtual_net: Some("corp-net".into()),
    };
    let json = serde_json::to_string(&adv).unwrap();
    let parsed: frp_vnet::msg::VnetRouteAdvertise = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.proxy_name, "vnet-office");
    assert_eq!(parsed.subnet, "10.0.0.0/24");
    assert_eq!(parsed.virtual_net, Some("corp-net".into()));
}

#[test]
fn test_vnet_packet_frp_message_roundtrip() {
    // Verify VnetPacket survives FrpMessage enum roundtrip via V1 protocol dispatch.
    // NOTE: FrpMessage uses #[serde(untagged)] so direct JSON roundtrip is unreliable;
    // the real code path uses deserialize_v1 which dispatches by type byte.
    use frp_core::msg::{self, FrpMessage, VnetPacket};

    let inner = VnetPacket {
        proxy_name: "target".into(),
        data: "dGVzdA==".into(),
    };
    let json_bytes = serde_json::to_vec(&inner).unwrap();

    let back: FrpMessage =
        frp_core::protocol::deserialize_v1(msg::TYPE_VNET_PACKET, &json_bytes).unwrap();

    match back {
        FrpMessage::VnetPacket(ref vp) => {
            assert_eq!(vp.proxy_name, "target");
            assert_eq!(vp.data, "dGVzdA==");
        }
        _ => panic!("wrong variant"),
    }
}
