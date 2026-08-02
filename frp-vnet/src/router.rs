use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A CIDR routing table mapping subnet strings to target proxy names.
/// Supports longest-prefix-match lookup for IP → proxy_name routing.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    /// Sorted by prefix length descending (longest first) for lookup priority.
    routes: Vec<(Net, String)>,
}

#[derive(Debug, Clone)]
struct Ipv4Net {
    addr: u32,
    prefix_len: u8,
    mask: u32,
}

#[derive(Debug, Clone)]
struct Ipv6Net {
    addr: u128,
    prefix_len: u8,
    mask: u128,
}

#[derive(Debug, Clone)]
enum Net {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Net::V4(net) => write!(f, "{}/{}", Ipv4Addr::from(net.addr), net.prefix_len),
            Net::V6(net) => write!(f, "{}/{}", Ipv6Addr::from(net.addr), net.prefix_len),
        }
    }
}

impl Net {
    fn parse(cidr: &str) -> Option<Self> {
        let (ip_str, len_str) = cidr.split_once('/')?;
        let prefix_len: u8 = len_str.parse().ok()?;
        if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
            if prefix_len > 32 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            Some(Net::V4(Ipv4Net {
                addr: u32::from(addr) & mask,
                prefix_len,
                mask,
            }))
        } else if let Ok(addr) = ip_str.parse::<Ipv6Addr>() {
            if prefix_len > 128 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            Some(Net::V6(Ipv6Net {
                addr: u128::from(addr) & mask,
                prefix_len,
                mask,
            }))
        } else {
            None
        }
    }

    fn family(&self) -> u8 {
        match self {
            Net::V4(_) => 4,
            Net::V6(_) => 6,
        }
    }

    fn prefix_len(&self) -> u8 {
        match self {
            Net::V4(net) => net.prefix_len,
            Net::V6(net) => net.prefix_len,
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Net::V4(net), IpAddr::V4(ip)) => (u32::from(*ip) & net.mask) == net.addr,
            (Net::V6(net), IpAddr::V6(ip)) => (u128::from(*ip) & net.mask) == net.addr,
            _ => false,
        }
    }
}

impl std::fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let a = Ipv4Addr::from(self.addr);
        write!(f, "{}/{}", a, self.prefix_len)
    }
}

#[cfg(test)]
impl Ipv4Net {
    fn parse(cidr: &str) -> Option<Self> {
        let (ip_str, len_str) = cidr.split_once('/')?;
        let addr: Ipv4Addr = ip_str.parse().ok()?;
        let prefix_len: u8 = len_str.parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Some(Ipv4Net {
            addr: u32::from(addr) & mask,
            prefix_len,
            mask,
        })
    }

    fn contains(&self, ip: &Ipv4Addr) -> bool {
        let ip_u32 = u32::from(*ip);
        (ip_u32 & self.mask) == self.addr
    }
}

impl RouteTable {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Insert or update a route. Returns Err if subnet conflicts with an existing route
    /// from a different proxy.
    pub fn insert(&mut self, name: &str, cidr: &str) -> anyhow::Result<()> {
        let net = Net::parse(cidr).ok_or_else(|| anyhow::anyhow!("invalid CIDR: {}", cidr))?;

        // Check for subnet conflict (overlapping with different proxy)
        for (existing, existing_name) in &self.routes {
            if existing_name != name {
                if existing.family() != net.family() {
                    continue;
                }
                // Check overlap: one contains the other's network address.
                // Resolve both sides to IpAddr so the family-specific
                // contains() is used.
                let (existing_ip, net_ip) = match (existing, &net) {
                    (Net::V4(e), Net::V4(n)) => (
                        IpAddr::V4(Ipv4Addr::from(e.addr)),
                        IpAddr::V4(Ipv4Addr::from(n.addr)),
                    ),
                    (Net::V6(e), Net::V6(n)) => (
                        IpAddr::V6(Ipv6Addr::from(e.addr)),
                        IpAddr::V6(Ipv6Addr::from(n.addr)),
                    ),
                    _ => unreachable!("family equality checked above"),
                };
                let overlaps = existing.contains(&net_ip) || net.contains(&existing_ip);
                // Only reject when same prefix length (ambiguous routing).
                // Different-length overlaps are resolved by longest-prefix-match.
                if overlaps && existing.prefix_len() == net.prefix_len() {
                    return Err(anyhow::anyhow!(
                        "subnet {} (for {}) conflicts with existing {} (for {}): same prefix length",
                        net, name, existing, existing_name
                    ));
                }
                if overlaps {
                    tracing::warn!(
                        subnet = %net,
                        proxy = name,
                        existing = %existing,
                        existing_proxy = existing_name,
                        "overlapping subnets with different prefix lengths (resolved by longest-prefix match)"
                    );
                }
            }
        }

        // Remove the previous route for this proxy in the same address family.
        // A proxy may own one IPv4 route and one IPv6 route concurrently.
        self.routes.retain(|(existing, existing_name)| {
            existing_name != name || existing.family() != net.family()
        });

        // Maintain sorted-by-prefix-length-descending order via binary search + insert.
        // O(n) per insertion (shift) vs O(n log n) for full sort.
        let pos = self
            .routes
            .binary_search_by_key(&std::cmp::Reverse(net.prefix_len()), |item| {
                std::cmp::Reverse(item.0.prefix_len())
            })
            .unwrap_or_else(|e| e);
        self.routes.insert(pos, (net, name.to_string()));

        Ok(())
    }

    /// Remove all routes for a proxy.
    pub fn remove(&mut self, name: &str) {
        self.routes.retain(|(_, n)| n != name);
    }

    /// Look up the target proxy name for an IP address. Returns None if no route matches.
    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        for (net, name) in &self.routes {
            if net.contains(ip) {
                return Some(name.as_str());
            }
        }
        None
    }

    /// Return all route entries as (cidr, proxy_name) pairs.
    pub fn list(&self) -> Vec<(String, String)> {
        self.routes
            .iter()
            .map(|(net, name)| (net.to_string(), name.clone()))
            .collect()
    }

    /// Return number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Check if routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Format an IP address as a host-route CIDR: /32 for IPv4, /128 for IPv6.
///
/// Used by the virtual_net visitor plugin to advertise `destinationIP` as a
/// route through the frp vnet controller (Go frp v0.70.1 behavior).
pub fn host_route_cidr(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}/32"),
        std::net::IpAddr::V6(v6) => format!("{v6}/128"),
    }
}

/// Extract the source IP from a raw IPv4/IPv6 packet.
pub fn packet_src_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from([
            packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
            packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21],
            packet[22], packet[23],
        ]))),
        _ => None,
    }
}

/// Extract the destination IP from a raw IPv4/IPv6 packet.
pub fn packet_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from([
            packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30],
            packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37],
            packet[38], packet[39],
        ]))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_route_cidr() {
        assert_eq!(
            host_route_cidr(&std::net::IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1))),
            "100.86.0.1/32"
        );
        assert_eq!(
            host_route_cidr(&"2001:db8::1".parse().unwrap()),
            "2001:db8::1/128"
        );
    }

    #[test]
    fn test_cidr_parse() {
        let net = Ipv4Net::parse("10.0.0.0/24").unwrap();
        assert_eq!(net.addr, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(net.prefix_len, 24);
    }

    #[test]
    fn test_cidr_contains() {
        let net = Ipv4Net::parse("10.0.0.0/24").unwrap();
        assert!(net.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(net.contains(&Ipv4Addr::new(10, 0, 0, 255)));
        assert!(!net.contains(&Ipv4Addr::new(10, 0, 1, 0)));
    }

    #[test]
    fn test_simple_insert_lookup() {
        let mut rt = RouteTable::new();
        rt.insert("vnet-a", "10.0.0.0/24").unwrap();
        assert_eq!(
            rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("vnet-a")
        );
        assert_eq!(rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0))), None);
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut rt = RouteTable::new();
        rt.insert("wide", "10.0.0.0/16").unwrap();
        rt.insert("narrow", "10.0.1.0/24").unwrap();
        // 10.0.1.5 matches both, but /24 is longer
        assert_eq!(
            rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
            Some("narrow")
        );
        // 10.0.2.5 only matches /16
        assert_eq!(
            rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 2, 5))),
            Some("wide")
        );
    }

    #[test]
    fn test_subnet_conflict_rejected() {
        let mut rt = RouteTable::new();
        rt.insert("a", "10.0.0.0/24").unwrap();
        // Same subnet, different proxy name, same prefix length → conflict
        assert!(rt.insert("b", "10.0.0.0/24").is_err());
    }

    #[test]
    fn test_same_name_overlap_allowed() {
        let mut rt = RouteTable::new();
        rt.insert("a", "10.0.0.0/16").unwrap();
        // Same name replaces its own route
        rt.insert("a", "10.0.0.0/24").unwrap();
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut rt = RouteTable::new();
        rt.insert("a", "10.0.0.0/24").unwrap();
        rt.insert("b", "10.0.1.0/24").unwrap();
        rt.remove("a");
        assert_eq!(rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))), None);
        assert_eq!(
            rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
            Some("b")
        );
    }

    #[test]
    fn test_list() {
        let mut rt = RouteTable::new();
        rt.insert("a", "10.0.0.0/24").unwrap();
        let list = rt.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "10.0.0.0/24");
        assert_eq!(list[0].1, "a");
    }

    #[test]
    fn test_ipv6_lookup_and_longest_prefix_match() {
        let mut rt = RouteTable::new();
        rt.insert("wide", "2001:db8::/32").unwrap();
        rt.insert("narrow", "2001:db8:0:1::/64").unwrap();

        let narrow: std::net::IpAddr = "2001:db8:0:1::5".parse().unwrap();
        let wide: std::net::IpAddr = "2001:db8:0:2::5".parse().unwrap();
        let outside: std::net::IpAddr = "2001:db9::1".parse().unwrap();

        assert_eq!(rt.lookup(&narrow), Some("narrow"));
        assert_eq!(rt.lookup(&wide), Some("wide"));
        assert_eq!(rt.lookup(&outside), None);
    }

    #[test]
    fn test_ipv4_and_ipv6_routes_coexist() {
        let mut rt = RouteTable::new();
        rt.insert("a", "10.0.0.0/24").unwrap();
        rt.insert("a", "2001:db8::/64").unwrap();

        assert_eq!(rt.len(), 2);
        assert_eq!(
            rt.lookup(&"10.0.0.5".parse::<std::net::IpAddr>().unwrap()),
            Some("a")
        );
        assert_eq!(
            rt.lookup(&"2001:db8::5".parse::<std::net::IpAddr>().unwrap()),
            Some("a")
        );

        rt.remove("a");
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_ipv6_conflict_only_rejects_same_family_and_prefix() {
        let mut rt = RouteTable::new();
        rt.insert("a", "2001:db8::/64").unwrap();
        // Same family + same prefix length is ambiguous.
        assert!(rt.insert("b", "2001:db8::/64").is_err());
        // Different prefix length is resolved by longest-prefix-match.
        rt.insert("b", "2001:db8::/32").unwrap();
        // Different family with the same prefix length is not a conflict.
        rt.insert("c", "10.0.0.0/24").unwrap();
        assert!(rt.insert("d", "2001:db8::/24").is_ok());
    }

    #[test]
    fn test_ipv6_routes_isolated_per_vnet() {
        let mut rt = RouteTable::new();
        rt.insert("vnet-a", "2001:db8::/64").unwrap();
        rt.insert("vnet-b", "2001:db9::/64").unwrap();
        // Same-family, different vnet → isolated.
        assert_eq!(rt.lookup(&"2001:db8::1".parse().unwrap()), Some("vnet-a"));
        assert_eq!(rt.lookup(&"2001:db9::1".parse().unwrap()), Some("vnet-b"));
        // Outside both vnets → no route.
        assert_eq!(rt.lookup(&"2001:dba::1".parse().unwrap()), None);
        // IPv4 and IPv6 routes coexist without cross-talk.
        rt.insert("vnet-a", "10.0.0.0/8").unwrap();
        assert_eq!(
            rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
            Some("vnet-a")
        );
        assert_eq!(rt.lookup(&"2001:db8::2".parse().unwrap()), Some("vnet-a"));
        // Removing one vnet does not affect the other.
        rt.remove("vnet-b");
        assert_eq!(rt.lookup(&"2001:db9::1".parse().unwrap()), None);
        assert_eq!(rt.lookup(&"2001:db8::1".parse().unwrap()), Some("vnet-a"));
    }
}
