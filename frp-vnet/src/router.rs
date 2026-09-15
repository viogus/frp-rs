use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// A CIDR routing table mapping subnet strings to target proxy names,
/// partitioned by virtual net.
///
/// Isolation semantics (design spec `2026-06-30-virtual-net-design.md`):
/// different virtual nets have isolated routing tables — the same subnet may
/// coexist in two vnets, and lookups are scoped to a single vnet. Within one
/// vnet, two different proxies may not own overlapping subnets with the same
/// prefix length (ambiguous routing); shorter/longer-prefix overlaps are
/// resolved by longest-prefix match.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    /// vnet → routes, each sorted by prefix length descending (longest first)
    /// for lookup priority.
    routes: HashMap<String, Vec<(Net, String)>>,
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
        Self {
            routes: HashMap::new(),
        }
    }

    /// Insert or update a route within `vnet`. Returns Err if the subnet
    /// conflicts with an existing route from a different proxy in the same
    /// virtual net. Routes in different virtual nets never conflict.
    pub fn insert(&mut self, vnet: &str, name: &str, cidr: &str) -> anyhow::Result<()> {
        let net = Net::parse(cidr).ok_or_else(|| anyhow::anyhow!("invalid CIDR: {}", cidr))?;

        let routes = self.routes.entry(vnet.to_string()).or_default();

        // Check for subnet conflict (overlapping with a different proxy in the
        // same virtual net).
        for (existing, existing_name) in routes.iter() {
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
                        "subnet {} (for {}) conflicts with existing {} (for {}) in virtual net {}: same prefix length",
                        net, name, existing, existing_name, vnet
                    ));
                }
                if overlaps {
                    tracing::warn!(
                        vnet,
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
        routes.retain(|(existing, existing_name)| {
            existing_name != name || existing.family() != net.family()
        });

        // Maintain sorted-by-prefix-length-descending order via binary search + insert.
        // O(n) per insertion (shift) vs O(n log n) for full sort.
        let pos = routes
            .binary_search_by_key(&std::cmp::Reverse(net.prefix_len()), |item| {
                std::cmp::Reverse(item.0.prefix_len())
            })
            .unwrap_or_else(|e| e);
        routes.insert(pos, (net, name.to_string()));

        Ok(())
    }

    /// Remove all routes for a proxy within `vnet`. Routes owned by the same
    /// proxy in other virtual nets are untouched.
    pub fn remove(&mut self, vnet: &str, name: &str) {
        let mut empty_vnet = false;
        if let Some(routes) = self.routes.get_mut(vnet) {
            routes.retain(|(_, n)| n != name);
            empty_vnet = routes.is_empty();
        }
        if empty_vnet {
            self.routes.remove(vnet);
        }
    }

    /// Look up the target proxy name for an IP address within `vnet`. Returns
    /// None if no route in that virtual net matches.
    pub fn lookup(&self, vnet: &str, ip: &IpAddr) -> Option<&str> {
        let routes = self.routes.get(vnet)?;
        for (net, name) in routes {
            if net.contains(ip) {
                return Some(name.as_str());
            }
        }
        None
    }

    /// Return all route entries in `vnet` as (cidr, proxy_name) pairs.
    pub fn list(&self, vnet: &str) -> Vec<(String, String)> {
        self.routes
            .get(vnet)
            .into_iter()
            .flatten()
            .map(|(net, name)| (net.to_string(), name.clone()))
            .collect()
    }

    /// Return number of routes across all virtual nets.
    pub fn len(&self) -> usize {
        self.routes.values().map(Vec::len).sum()
    }

    /// Check if routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.values().all(Vec::is_empty)
    }
}

/// A CIDR prefix set precompiled into masked `(network, mask)` pairs.
///
/// [`RouteTable`] re-parses a CIDR string on every `insert`, which is far too
/// expensive for a per-packet path. `RoutePrefixes` is compiled once — at
/// proxy registration — and answers membership tests with one mask + compare
/// per prefix: no parsing, no allocation, no hashing.
///
/// A `RoutePrefixes` is cheap to share behind an `Arc`, so one compiled set
/// can back every packet of every fan-out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePrefixes {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl RoutePrefixes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile a single CIDR (for example `10.0.0.0/24` or `2001:db8::/64`).
    /// Returns `None` when the string is not a valid CIDR — exactly the
    /// inputs [`RouteTable::insert`] rejects.
    pub fn from_cidr(cidr: &str) -> Option<Self> {
        let mut prefixes = Self::new();
        prefixes.insert_cidr(cidr).then_some(prefixes)
    }

    /// Add a CIDR to the set. Returns `false` (leaving the set unchanged) when
    /// the CIDR does not parse, mirroring [`RouteTable::insert`]'s error arm.
    pub fn insert_cidr(&mut self, cidr: &str) -> bool {
        match Net::parse(cidr) {
            Some(Net::V4(net)) => {
                self.v4.push((net.addr, net.mask));
                true
            }
            Some(Net::V6(net)) => {
                self.v6.push((net.addr, net.mask));
                true
            }
            None => false,
        }
    }

    /// Whether `ip` falls inside any prefix of the set.
    ///
    /// Address families are never mixed: an IPv4 address is only tested
    /// against IPv4 prefixes, and vice versa.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(*ip);
                self.v4.iter().any(|(net, mask)| (ip & mask) == *net)
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(*ip);
                self.v6.iter().any(|(net, mask)| (ip & mask) == *net)
            }
        }
    }

    /// Number of compiled prefixes.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// A registered subnet: the CIDR string as configured (kept verbatim for
/// OS route add/remove) plus its precompiled prefix set, shared behind an
/// `Arc` so fanning a packet out to N peers clones a pointer, not a prefix
/// list.
#[derive(Debug, Clone)]
pub struct PrecompiledSubnet {
    cidr: String,
    prefixes: Arc<RoutePrefixes>,
}

impl PrecompiledSubnet {
    /// Precompile `cidr` for the per-packet path.
    ///
    /// A CIDR that does not parse yields an empty prefix set that never
    /// matches — identical to the pre-precompile behavior, where the
    /// per-packet `RouteTable::insert` failed and the route never matched.
    pub fn new(cidr: impl Into<String>) -> Self {
        let cidr = cidr.into();
        let mut prefixes = RoutePrefixes::new();
        prefixes.insert_cidr(&cidr);
        Self {
            cidr,
            prefixes: Arc::new(prefixes),
        }
    }

    /// The CIDR exactly as registered.
    pub fn cidr(&self) -> &str {
        &self.cidr
    }

    /// The precompiled prefix set. Cloning the returned `Arc` is a refcount
    /// bump, not a copy.
    pub fn prefixes(&self) -> &Arc<RoutePrefixes> {
        &self.prefixes
    }

    /// Whether `ip` is inside this subnet.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.prefixes.contains(ip)
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
        rt.insert("", "vnet-a", "10.0.0.0/24").unwrap();
        assert_eq!(
            rt.lookup("", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("vnet-a")
        );
        assert_eq!(rt.lookup("", &IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0))), None);
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut rt = RouteTable::new();
        rt.insert("net", "wide", "10.0.0.0/16").unwrap();
        rt.insert("net", "narrow", "10.0.1.0/24").unwrap();
        // 10.0.1.5 matches both, but /24 is longer
        assert_eq!(
            rt.lookup("net", &IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
            Some("narrow")
        );
        // 10.0.2.5 only matches /16
        assert_eq!(
            rt.lookup("net", &IpAddr::V4(Ipv4Addr::new(10, 0, 2, 5))),
            Some("wide")
        );
    }

    #[test]
    fn test_subnet_conflict_rejected() {
        let mut rt = RouteTable::new();
        rt.insert("net", "a", "10.0.0.0/24").unwrap();
        // Same subnet, different proxy name, same prefix length → conflict
        assert!(rt.insert("net", "b", "10.0.0.0/24").is_err());
    }

    #[test]
    fn test_same_name_overlap_allowed() {
        let mut rt = RouteTable::new();
        rt.insert("net", "a", "10.0.0.0/16").unwrap();
        // Same name replaces its own route
        rt.insert("net", "a", "10.0.0.0/24").unwrap();
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut rt = RouteTable::new();
        rt.insert("net", "a", "10.0.0.0/24").unwrap();
        rt.insert("net", "b", "10.0.1.0/24").unwrap();
        rt.remove("net", "a");
        assert_eq!(
            rt.lookup("net", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            None
        );
        assert_eq!(
            rt.lookup("net", &IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
            Some("b")
        );
    }

    #[test]
    fn test_list() {
        let mut rt = RouteTable::new();
        rt.insert("net", "a", "10.0.0.0/24").unwrap();
        let list = rt.list("net");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "10.0.0.0/24");
        assert_eq!(list[0].1, "a");
    }

    #[test]
    fn test_ipv6_lookup_and_longest_prefix_match() {
        let mut rt = RouteTable::new();
        rt.insert("net", "wide", "2001:db8::/32").unwrap();
        rt.insert("net", "narrow", "2001:db8:0:1::/64").unwrap();

        let narrow: std::net::IpAddr = "2001:db8:0:1::5".parse().unwrap();
        let wide: std::net::IpAddr = "2001:db8:0:2::5".parse().unwrap();
        let outside: std::net::IpAddr = "2001:db9::1".parse().unwrap();

        assert_eq!(rt.lookup("net", &narrow), Some("narrow"));
        assert_eq!(rt.lookup("net", &wide), Some("wide"));
        assert_eq!(rt.lookup("net", &outside), None);
    }

    #[test]
    fn test_ipv4_and_ipv6_routes_coexist() {
        let mut rt = RouteTable::new();
        rt.insert("net", "a", "10.0.0.0/24").unwrap();
        rt.insert("net", "a", "2001:db8::/64").unwrap();

        assert_eq!(rt.len(), 2);
        assert_eq!(
            rt.lookup("net", &"10.0.0.5".parse::<std::net::IpAddr>().unwrap()),
            Some("a")
        );
        assert_eq!(
            rt.lookup("net", &"2001:db8::5".parse::<std::net::IpAddr>().unwrap()),
            Some("a")
        );

        rt.remove("net", "a");
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_ipv6_conflict_only_rejects_same_family_and_prefix() {
        let mut rt = RouteTable::new();
        rt.insert("net", "a", "2001:db8::/64").unwrap();
        // Same family + same prefix length is ambiguous.
        assert!(rt.insert("net", "b", "2001:db8::/64").is_err());
        // Different prefix length is resolved by longest-prefix-match.
        rt.insert("net", "b", "2001:db8::/32").unwrap();
        // Different family with the same prefix length is not a conflict.
        rt.insert("net", "c", "10.0.0.0/24").unwrap();
        assert!(rt.insert("net", "d", "2001:db8::/24").is_ok());
    }

    #[test]
    fn test_same_subnet_different_vnets_coexist() {
        let mut rt = RouteTable::new();
        rt.insert("vnet-a", "a", "10.0.0.0/24").unwrap();
        // The same subnet in a different virtual net is allowed (isolation).
        rt.insert("vnet-b", "b", "10.0.0.0/24").unwrap();
        assert_eq!(rt.len(), 2);
        // Lookup is scoped per vnet: same IP resolves per-vnet.
        assert_eq!(
            rt.lookup("vnet-a", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("a")
        );
        assert_eq!(
            rt.lookup("vnet-b", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("b")
        );
        // A third vnet with no routes resolves nothing.
        assert_eq!(
            rt.lookup("vnet-c", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            None
        );
    }

    #[test]
    fn test_conflict_only_within_same_vnet() {
        let mut rt = RouteTable::new();
        rt.insert("vnet-a", "a", "10.0.0.0/24").unwrap();
        // The same subnet in another vnet does not conflict.
        assert!(rt.insert("vnet-b", "b", "10.0.0.0/24").is_ok());
        // But within vnet-a a second owner of the same subnet is rejected.
        assert!(rt.insert("vnet-a", "c", "10.0.0.0/24").is_err());
    }

    #[test]
    fn test_remove_is_vnet_scoped() {
        let mut rt = RouteTable::new();
        rt.insert("vnet-a", "a", "10.0.0.0/24").unwrap();
        rt.insert("vnet-b", "b", "10.0.0.0/24").unwrap();
        rt.remove("vnet-a", "a");
        assert_eq!(
            rt.lookup("vnet-b", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("b"),
            "removing a route in vnet-a must not affect vnet-b"
        );
        assert_eq!(
            rt.lookup("vnet-a", &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            None
        );
    }

    #[test]
    fn test_large_table_scale_ordering_and_fallback() {
        let mut rt = RouteTable::new();
        // 64 distinct /24 routes in one vnet, plus a /32 host route on top
        // of one of them: 65 routes total.
        for i in 0..64u32 {
            rt.insert("net", &format!("proxy-{i}"), &format!("10.0.{i}.0/24"))
                .unwrap();
        }
        rt.insert("net", "host", "10.0.7.7/32").unwrap();
        assert_eq!(rt.len(), 65);

        // Longest prefix match: the /32 shadows its /24.
        let host_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 7, 7));
        assert_eq!(rt.lookup("net", &host_ip), Some("host"));
        // Other addresses in the same /24 fall back to the /24 route.
        assert_eq!(
            rt.lookup("net", &IpAddr::V4(Ipv4Addr::new(10, 0, 7, 1))),
            Some("proxy-7")
        );
        // Addresses outside the covered space match nothing.
        assert_eq!(
            rt.lookup("net", &IpAddr::V4(Ipv4Addr::new(10, 0, 64, 1))),
            None
        );

        // Routes stay sorted by prefix length descending after 65 inserts.
        let routes = rt.routes.get("net").expect("vnet routes exist");
        assert!(routes
            .windows(2)
            .all(|w| w[0].0.prefix_len() >= w[1].0.prefix_len()));
        assert_eq!(routes[0].0.prefix_len(), 32, "the /32 must sort first");

        // A same-prefix /24 owned by a different proxy still conflicts at
        // scale, and the rejected insert leaves the table untouched.
        assert!(rt.insert("net", "intruder", "10.0.7.0/24").is_err());
        assert_eq!(rt.len(), 65);

        // Deleting the /32 makes lookups fall back to the /24.
        rt.remove("net", "host");
        assert_eq!(rt.len(), 64);
        assert_eq!(rt.lookup("net", &host_ip), Some("proxy-7"));
    }

    /// The precompiled prefix set must answer exactly what the old
    /// per-packet `RouteTable::new() + insert + lookup` chain answered, for
    /// every CIDR/IP combination — including the CIDRs it refuses.
    #[test]
    fn precompiled_lookup_matches_per_packet_route_table() {
        let cidrs = [
            "10.0.0.0/24",
            "10.0.0.0/8",
            "10.0.7.7/32",
            "0.0.0.0/0",
            "192.168.1.0/31",
            "172.16.0.0/12",
            "2001:db8::/64",
            "2001:db8::1/128",
            "::/0",
            "fe80::/10",
            // Unparsable / out-of-range: the reference table refuses these
            // (insert is Err), so the precompiled set must never match.
            "10.0.0.0",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "",
            "not-a-cidr",
            "2001:db8::/129",
        ];
        let ips: Vec<IpAddr> = [
            "10.0.0.1",
            "10.0.7.7",
            "10.1.2.3",
            "11.0.0.1",
            "192.168.1.1",
            "172.31.255.255",
            "0.0.0.1",
            "255.255.255.255",
            "2001:db8::5",
            "2001:db8::1",
            "fe80::1",
            "::1",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        for cidr in cidrs {
            // Reference: the pre-optimization per-packet path.
            let mut rt = RouteTable::new();
            let inserted = rt.insert("", "proxy", cidr).is_ok();
            let compiled = PrecompiledSubnet::new(cidr);

            assert_eq!(
                !compiled.prefixes().is_empty(),
                inserted,
                "compiled emptiness must track insert success for {cidr:?}"
            );
            for ip in &ips {
                let reference = inserted && rt.lookup("", ip) == Some("proxy");
                assert_eq!(
                    compiled.contains(ip),
                    reference,
                    "precompiled contains({ip}) disagreed with the reference for {cidr:?}"
                );
            }
        }
    }

    #[test]
    fn precompiled_subnet_keeps_cidr_verbatim_and_never_matches_invalid() {
        let subnet = PrecompiledSubnet::new("10.0.0.0/24");
        assert_eq!(subnet.cidr(), "10.0.0.0/24");
        assert_eq!(subnet.prefixes().len(), 1);
        assert!(subnet.contains(&"10.0.0.9".parse().unwrap()));
        assert!(!subnet.contains(&"10.0.1.9".parse().unwrap()));
        assert!(
            !subnet.contains(&"2001:db8::1".parse().unwrap()),
            "an IPv6 address must never match an IPv4 subnet"
        );

        // A rejected CIDR keeps the configured string (the OS route removal
        // path needs it) but matches nothing.
        let bogus = PrecompiledSubnet::new("10.0.0.0/33");
        assert_eq!(bogus.cidr(), "10.0.0.0/33");
        assert!(bogus.prefixes().is_empty());
        assert!(!bogus.contains(&"10.0.0.9".parse().unwrap()));
    }

    /// Sharing one compiled subnet across peers must not duplicate the prefix
    /// list: `Arc::clone` is a refcount bump and every clone sees the same
    /// prefixes and the same answers.
    #[test]
    fn precompiled_subnet_arc_is_shared_not_copied() {
        let subnet = PrecompiledSubnet::new("2001:db8::/64");
        let shared = subnet.prefixes().clone();
        assert!(Arc::ptr_eq(subnet.prefixes(), &shared));
        assert_eq!(Arc::strong_count(subnet.prefixes()), 2);

        let clone = subnet.clone();
        assert!(
            Arc::ptr_eq(subnet.prefixes(), clone.prefixes()),
            "cloning a registered subnet must share the compiled prefixes"
        );
        let ip: IpAddr = "2001:db8::7".parse().unwrap();
        assert_eq!(subnet.contains(&ip), clone.contains(&ip));
        assert!(clone.contains(&ip));
    }

    /// Multi-prefix sets: a vnet proxy may own one IPv4 and one IPv6 route,
    /// and `RoutePrefixes` must resolve both without cross-family bleed.
    #[test]
    fn route_prefixes_multi_family_membership() {
        let mut prefixes = RoutePrefixes::new();
        assert!(prefixes.insert_cidr("10.0.0.0/24"));
        assert!(prefixes.insert_cidr("2001:db8::/64"));
        assert!(!prefixes.insert_cidr("garbage"));
        assert_eq!(prefixes.len(), 2);

        assert!(prefixes.contains(&"10.0.0.5".parse().unwrap()));
        assert!(prefixes.contains(&"2001:db8::5".parse().unwrap()));
        assert!(!prefixes.contains(&"10.0.1.5".parse().unwrap()));
        assert!(!prefixes.contains(&"2001:db9::5".parse().unwrap()));

        // A full-coverage /0 set (both families) matches everything.
        let all = RoutePrefixes::from_cidr("0.0.0.0/0").expect("valid CIDR");
        assert!(all.contains(&"8.8.8.8".parse().unwrap()));
        assert!(!all.contains(&"2001:db8::1".parse().unwrap()));
        assert!(RoutePrefixes::from_cidr("nope").is_none());
    }
}
