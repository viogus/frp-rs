use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::RwLock;

/// A registered proxy on the server side.
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub name: String,
    pub proxy_type: String,
    pub run_id: String,
    pub remote_port: Option<u16>,
    pub sk: Option<String>,
    pub group: Option<String>,
    pub group_key: Option<String>,
    pub local_addr: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
    /// Virtual network for STCP/XTCP isolation.
    pub virtual_net: Option<String>,
    /// Allowed visitor run_ids (STCP/XTCP access control).
    /// Empty = all visitors allowed. Go frp compat: allow_users.
    pub allow_users: Vec<String>,
    /// PROXY protocol version (v1, v2, or empty).
    pub proxy_protocol_version: String,
    /// Response headers to inject into HTTP responses.
    pub response_headers: std::collections::HashMap<String, String>,
    /// Custom domains for HTTP vhost routing.
    pub custom_domains: Vec<String>,
    /// Multiplexer type (e.g., "yamux").
    pub multiplexer: String,
    pub user: String,
}

/// Manages all proxy registrations on the server.
pub struct ProxyManager {
    proxies: RwLock<HashMap<String, ProxyInfo>>,
    by_client: RwLock<HashMap<String, HashMap<String, ProxyInfo>>>,
    /// group name → sorted list of proxy names (for round-robin selection)
    groups: RwLock<HashMap<String, Vec<String>>>,
    /// Per-group round-robin counters. Incremented on each selection.
    group_counters: Mutex<HashMap<String, u64>>,
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(HashMap::new()),
            by_client: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            group_counters: Mutex::new(HashMap::new()),
        }
    }

    /// Non-blocking readiness probe: true if the proxy registry lock is
    /// acquirable right now (not held/deadlocked). Used by /healthz readiness.
    pub fn is_responsive(&self) -> bool {
        self.proxies.try_read().is_ok()
    }

    pub async fn register(&self, run_id: String, info: ProxyInfo) -> Result<(), String> {
        let name = info.name.clone();
        // Register in group index
        if let Some(ref group) = info.group {
            if !group.is_empty() {
                let mut groups = self.groups.write().await;
                groups.entry(group.clone()).or_default().push(name.clone());
            }
        }
        // Check-and-insert atomically under write lock (fixes TOCTOU).
        {
            let mut proxies = self.proxies.write().await;
            if proxies.contains_key(&name) {
                return Err(format!("proxy '{}' already registered", name));
            }
            proxies.insert(name.clone(), info.clone());
        }
        self.by_client
            .write()
            .await
            .entry(run_id)
            .or_default()
            .insert(name, info);
        Ok(())
    }

    pub async fn get(&self, name: &str) -> Option<ProxyInfo> {
        self.proxies.read().await.get(name).cloned()
    }

    pub async fn remove(&self, name: &str) {
        let mut proxies = self.proxies.write().await;
        if let Some(info) = proxies.remove(name) {
            // Clean up group index
            if let Some(ref group) = info.group {
                if !group.is_empty() {
                    let mut groups = self.groups.write().await;
                    if let Some(members) = groups.get_mut(group) {
                        members.retain(|n| n != name);
                        if members.is_empty() {
                            groups.remove(group);
                            // Clean up stale round-robin counter
                            let mut counters = self.group_counters.lock().unwrap();
                            counters.remove(group);
                        }
                    }
                }
            }
            drop(proxies);
            let mut by_client = self.by_client.write().await;
            if let Some(client_proxies) = by_client.get_mut(&info.run_id) {
                client_proxies.remove(name);
            }
        }
    }

    /// Remove all proxies belonging to a disconnected client.
    ///
    /// ## Lock ordering
    ///
    /// The canonical lock acquisition order is:
    ///   1. `self.proxies` (tokio RwLock)
    ///   2. `self.by_client` (tokio RwLock)
    ///   3. `self.groups` (tokio RwLock)
    ///   4. `self.group_counters` (std Mutex)
    ///
    /// When a proxy belongs to a group, we must clean up the group entry.
    /// To avoid deadlock, we **drop** proxies and by_client before acquiring
    /// groups (step 3). After the group cleanup, we **re-acquire** proxies
    /// and by_client to continue iterating. This drop/reacquire is correct
    /// because:
    ///   - `client_proxies.keys()` is an owned Vec (from `by_client.remove`)
    ///     and does not borrow the lock guards.
    ///   - The loop over proxy names iterates the owned keys — no iterator
    ///     invalidation risk from releasing and reacquiring.
    ///   - Other clients may add/remove proxies between the drop and
    ///     reacquire, but only THIS client's proxies are being removed,
    ///     and `by_client.remove(run_id)` already took them out — no other
    ///     task can observe them.
    ///
    /// **Do not** reorder these locks without verifying the full call graph
    /// for cycles. The existing callers acquire in this order; changing it
    /// risks deadlock with `register`, `unregister`, or `select_group_backend`.
    pub async fn remove_client(&self, run_id: &str) {
        let mut proxies = self.proxies.write().await;
        let mut by_client = self.by_client.write().await;
        if let Some(client_proxies) = by_client.remove(run_id) {
            for name in client_proxies.keys() {
                if let Some(info) = proxies.remove(name) {
                    if let Some(ref group) = info.group {
                        if !group.is_empty() {
                            // Drop proxies and by_client to avoid deadlock
                            // when acquiring the groups lock below.
                            // See doc comment above for the full ordering.
                            drop(proxies);
                            drop(by_client);
                            let mut groups = self.groups.write().await;
                            if let Some(members) = groups.get_mut(group) {
                                members.retain(|n| n != name);
                                if members.is_empty() {
                                    groups.remove(group);
                                    // Clean up stale round-robin counter.
                                    // group_counters is a std Mutex (not
                                    // tokio), so it must not be held across
                                    // .await. It is always acquired last.
                                    let mut counters = self.group_counters.lock().unwrap();
                                    counters.remove(group);
                                }
                            }
                            // Re-acquire proxies and by_client for the
                            // remaining loop iterations. Safe because we
                            // iterate over owned keys (see doc comment).
                            proxies = self.proxies.write().await;
                            by_client = self.by_client.write().await;
                        }
                    }
                }
            }
        }
    }

    /// Select a backend from a group for load balancing.
    /// Uses group_key for affinity: same key → same backend (hash-based).
    /// Without group_key, true round-robin selection across group members.
    /// Matches Go frp v0.69.1 group load balancing behavior.
    pub async fn select_group_backend(&self, group: &str, group_key: &str) -> Option<String> {
        let groups = self.groups.read().await;
        let members = groups.get(group)?;
        if members.is_empty() {
            return None;
        }
        if !group_key.is_empty() {
            // Sticky session: hash the key to pick a backend
            let hash = group_key.bytes().fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
            let idx = hash as usize % members.len();
            Some(members[idx].clone())
        } else {
            // True round-robin: increment counter, modulo member count.
            let mut counters = self.group_counters.lock().unwrap();
            let counter = counters.entry(group.to_string()).or_insert(0);
            let idx = (*counter as usize) % members.len();
            *counter += 1;
            Some(members[idx].clone())
        }
    }

    /// Get the group for a proxy, if any.
    pub async fn get_group(&self, name: &str) -> Option<String> {
        self.proxies.read().await.get(name)
            .and_then(|p| p.group.clone())
            .filter(|g| !g.is_empty())
    }

    pub async fn list_client(&self, run_id: &str) -> Vec<ProxyInfo> {
        self.by_client.read().await.get(run_id)
            .map(|proxies| proxies.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List proxy names for a specific client (run_id).
    pub async fn list_client_proxy_names(&self, run_id: &str) -> Vec<String> {
        self.by_client.read().await.get(run_id)
            .map(|proxies| proxies.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn get_run_id(&self, name: &str) -> Option<String> {
        self.proxies.read().await.get(name).map(|p| p.run_id.clone())
    }

    pub async fn list(&self) -> Vec<ProxyInfo> {
        self.proxies.read().await.values().cloned().collect()
    }
}

/// Entry stored in the per-proxy table (simplified — work connections
/// are managed per-client in the control handler).
#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub info: ProxyInfo,
}

/// Allocate a port across multiple ranges.
/// If `port` > 0, try to allocate exactly that port. If already used, return None.
/// If `port` == 0, scan all ranges in order and return the first available port.
pub fn allocate_port_multi(
    used_ports: &mut std::collections::HashSet<u16>,
    port: u16,
    ranges: &[(u16, u16)],
) -> Option<u16> {
    if port > 0 {
        if used_ports.insert(port) {
            return Some(port);
        }
        return None;
    }
    for &(start, end) in ranges {
        for p in start..=end {
            if used_ports.insert(p) {
                return Some(p);
            }
        }
    }
    None
}
