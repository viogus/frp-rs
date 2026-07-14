//! NAT feature classification for XTCP hole punching.
//! Go frp v0.69.1 compat: pkg/nathole/classify.go

/// NAT type classification.
pub const EASY_NAT: &str = "EasyNAT";
pub const HARD_NAT: &str = "HardNAT";

/// NAT behavior classification.
pub const BEHAVIOR_NO_CHANGE: &str = "BehaviorNoChange";
pub const BEHAVIOR_IP_CHANGED: &str = "BehaviorIPChanged";
pub const BEHAVIOR_PORT_CHANGED: &str = "BehaviorPortChanged";
pub const BEHAVIOR_BOTH_CHANGED: &str = "BehaviorBothChanged";

/// Classified NAT characteristics for a peer.
#[derive(Debug, Clone)]
pub struct NatFeature {
    pub nat_type: String,
    pub behavior: String,
    pub ports_difference: i32,
    pub regular_ports_change: bool,
    pub public_network: bool,
}

/// Split "ip:port" into (ip_str, port) handling IPv4 and bracketed IPv6.
/// Returns error for unbracketed IPv6 (ambiguous with colon separators).
fn split_host_port(addr: &str) -> Result<(&str, i32), String> {
    if addr.starts_with('[') {
        // Bracketed IPv6: [::1]:8080 or [2001:db8::1]:1234
        let close = addr
            .find(']')
            .ok_or_else(|| format!("unclosed bracket in: {}", addr))?;
        let ip = &addr[1..close];
        let port_str = addr
            .get(close + 2..) // skip "]:" — two chars
            .ok_or_else(|| format!("missing port after bracket in: {}", addr))?;
        let port: i32 = port_str
            .parse()
            .map_err(|_| format!("invalid port in: {}", addr))?;
        Ok((ip, port))
    } else {
        // IPv4 or hostname: "1.2.3.4:1234" or "host:port"
        // rsplitn works here because IPv4 has no colons, hostnames conventionally don't
        let colon = addr
            .rfind(':')
            .ok_or_else(|| format!("missing port separator in: {}", addr))?;
        let ip = &addr[..colon];
        let port_str = &addr[colon + 1..];
        let port: i32 = port_str
            .parse()
            .map_err(|_| format!("invalid port in: {}", addr))?;
        Ok((ip, port))
    }
}

/// Classify a peer's NAT type and behavior from its discovered addresses.
///
/// `addresses` — STUN-discovered external addresses (ip:port strings).
/// Handles IPv4 and bracketed IPv6 ([::1]:8080). Unbracketed IPv6
/// addresses are rejected (they are ambiguous with colons as port separators).
/// `local_ips` — known local IPs; if found in addresses, marks public_network.
///
/// Returns error if `addresses.len() <= 1` (need at least 2 for classification).
pub fn classify_nat_feature(
    addresses: &[String],
    local_ips: &[String],
) -> Result<NatFeature, String> {
    if addresses.len() <= 1 {
        return Err("insufficient addresses for NAT classification".into());
    }

    let mut ip_changed = false;
    let mut port_changed = false;
    let mut port_max = 0i32;
    let mut port_min = 65535i32;
    let mut public_network = false;

    // Parse first address as baseline
    let (first_ip, first_port) = split_host_port(&addresses[0])?;
    if !(0..=65535).contains(&first_port) {
        return Err(format!("port out of range (0-65535): {}", addresses[0]));
    }

    port_max = port_max.max(first_port);
    port_min = port_min.min(first_port);

    // Check if any address matches local IPs
    let local_set: std::collections::HashSet<&str> = local_ips.iter().map(|s| s.as_str()).collect();
    if local_set.contains(first_ip) {
        public_network = true;
    }

    for addr in &addresses[1..] {
        let (ip, port) = split_host_port(addr)?;
        if !(0..=65535).contains(&port) {
            return Err(format!("port out of range (0-65535): {}", addr));
        }

        if ip != first_ip {
            ip_changed = true;
        }
        if port != first_port {
            port_changed = true;
        }
        port_max = port_max.max(port);
        port_min = port_min.min(port);

        if local_set.contains(ip) {
            public_network = true;
        }
    }

    let (nat_type, behavior) = if ip_changed && port_changed {
        (HARD_NAT.to_string(), BEHAVIOR_BOTH_CHANGED.to_string())
    } else if ip_changed {
        (HARD_NAT.to_string(), BEHAVIOR_IP_CHANGED.to_string())
    } else if port_changed {
        (HARD_NAT.to_string(), BEHAVIOR_PORT_CHANGED.to_string())
    } else {
        (EASY_NAT.to_string(), BEHAVIOR_NO_CHANGE.to_string())
    };

    let ports_difference = port_max - port_min;
    let regular_ports_change =
        behavior == BEHAVIOR_PORT_CHANGED && (1..=5).contains(&ports_difference);

    Ok(NatFeature {
        nat_type,
        behavior,
        ports_difference,
        regular_ports_change,
        public_network,
    })
}

/// Count NAT feature distribution across a list of features.
/// Returns (easy_count, hard_count, ports_changed_regular_count).
pub fn classify_feature_count(features: &[NatFeature]) -> (i32, i32, i32) {
    let mut easy = 0i32;
    let mut hard = 0i32;
    let mut regular = 0i32;
    for f in features {
        if f.nat_type == EASY_NAT {
            easy += 1;
        } else {
            hard += 1;
            if f.regular_ports_change {
                regular += 1;
            }
        }
    }
    (easy, hard, regular)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_easy_nat_no_change() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.nat_type, EASY_NAT);
        assert_eq!(f.behavior, BEHAVIOR_NO_CHANGE);
        assert!(!f.regular_ports_change);
    }

    #[test]
    fn test_hard_nat_port_changed_regular() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1237".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.nat_type, HARD_NAT);
        assert_eq!(f.behavior, BEHAVIOR_PORT_CHANGED);
        assert_eq!(f.ports_difference, 3);
        assert!(f.regular_ports_change);
    }

    #[test]
    fn test_hard_nat_port_changed_irregular() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:9999".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.nat_type, HARD_NAT);
        assert_eq!(f.behavior, BEHAVIOR_PORT_CHANGED);
        assert!(!f.regular_ports_change);
    }

    #[test]
    fn test_hard_nat_ip_changed() {
        let addrs = vec!["1.2.3.4:1234".into(), "5.6.7.8:1234".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.behavior, BEHAVIOR_IP_CHANGED);
    }

    #[test]
    fn test_hard_nat_both_changed() {
        let addrs = vec!["1.2.3.4:1234".into(), "5.6.7.8:5678".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.behavior, BEHAVIOR_BOTH_CHANGED);
    }

    #[test]
    fn test_public_network_detection() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1235".into()];
        let local = vec!["1.2.3.4".into()];
        let f = classify_nat_feature(&addrs, &local).unwrap();
        assert!(f.public_network);
    }

    #[test]
    fn test_insufficient_addresses() {
        let addrs = vec!["1.2.3.4:1234".into()];
        assert!(classify_nat_feature(&addrs, &[]).is_err());
    }

    #[test]
    fn test_classify_feature_count() {
        let features = vec![
            NatFeature {
                nat_type: EASY_NAT.into(),
                behavior: BEHAVIOR_NO_CHANGE.into(),
                ports_difference: 0,
                regular_ports_change: false,
                public_network: false,
            },
            NatFeature {
                nat_type: HARD_NAT.into(),
                behavior: BEHAVIOR_PORT_CHANGED.into(),
                ports_difference: 3,
                regular_ports_change: true,
                public_network: false,
            },
            NatFeature {
                nat_type: HARD_NAT.into(),
                behavior: BEHAVIOR_BOTH_CHANGED.into(),
                ports_difference: 0,
                regular_ports_change: false,
                public_network: false,
            },
        ];
        let (easy, hard, regular) = classify_feature_count(&features);
        assert_eq!(easy, 1);
        assert_eq!(hard, 2);
        assert_eq!(regular, 1);
    }
}
