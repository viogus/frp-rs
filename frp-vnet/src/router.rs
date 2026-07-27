use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A CIDR routing table mapping subnet strings to target proxy names.
/// Supports longest-prefix-match lookup for IP → proxy_name routing.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    /// Sorted by prefix length descending (longest first) for lookup priority.
    routes: Vec<(Ipv4Net, String)>,
    /// Index by proxy_name for fast removal.
    by_name: HashMap<String, Ipv4Net>,
}

#[derive(Debug, Clone)]
struct Ipv4Net {
    addr: u32,
    prefix_len: u8,
    mask: u32,
}

impl std::fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let a = Ipv4Addr::from(self.addr);
        write!(f, "{}/{}", a, self.prefix_len)
    }
}

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
            routes: Vec::new(),
            by_name: HashMap::new(),
        }
    }

    /// Insert or update a route. Returns Err if subnet conflicts with an existing route
    /// from a different proxy.
    pub fn insert(&mut self, name: &str, cidr: &str) -> anyhow::Result<()> {
        let net = Ipv4Net::parse(cidr).ok_or_else(|| anyhow::anyhow!("invalid CIDR: {}", cidr))?;

        // Check for subnet conflict (overlapping with different proxy)
        for (existing, existing_name) in &self.routes {
            if existing_name != name {
                // Check overlap: one contains the other's network address
                let overlaps = existing.contains(&Ipv4Addr::from(net.addr))
                    || net.contains(&Ipv4Addr::from(existing.addr));
                // Only reject when same prefix length (ambiguous routing).
                // Different-length overlaps are resolved by longest-prefix-match.
                if overlaps && existing.prefix_len == net.prefix_len {
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

        // Remove old entry for this proxy if exists
        self.remove(name);

        self.by_name.insert(name.to_string(), net.clone());
        // Maintain sorted-by-prefix-length-descending order via binary search + insert.
        // O(n) per insertion (shift) vs O(n log n) for full sort.
        let pos = self
            .routes
            .binary_search_by_key(&std::cmp::Reverse(net.prefix_len), |item| {
                std::cmp::Reverse(item.0.prefix_len)
            })
            .unwrap_or_else(|e| e);
        self.routes.insert(pos, (net, name.to_string()));

        Ok(())
    }

    /// Remove all routes for a proxy.
    pub fn remove(&mut self, name: &str) {
        self.by_name.remove(name);
        self.routes.retain(|(_, n)| n != name);
    }

    /// Look up the target proxy name for an IP address. Returns None if no route matches.
    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<&str> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(rt.lookup(&Ipv4Addr::new(10, 0, 0, 5)), Some("vnet-a"));
        assert_eq!(rt.lookup(&Ipv4Addr::new(10, 0, 1, 0)), None);
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut rt = RouteTable::new();
        rt.insert("wide", "10.0.0.0/16").unwrap();
        rt.insert("narrow", "10.0.1.0/24").unwrap();
        // 10.0.1.5 matches both, but /24 is longer
        assert_eq!(rt.lookup(&Ipv4Addr::new(10, 0, 1, 5)), Some("narrow"));
        // 10.0.2.5 only matches /16
        assert_eq!(rt.lookup(&Ipv4Addr::new(10, 0, 2, 5)), Some("wide"));
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
        assert_eq!(rt.lookup(&Ipv4Addr::new(10, 0, 0, 5)), None);
        assert_eq!(rt.lookup(&Ipv4Addr::new(10, 0, 1, 5)), Some("b"));
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
}
