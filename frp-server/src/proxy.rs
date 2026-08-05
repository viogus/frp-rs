use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

/// Maximum consecutive failures before a group backend is marked unhealthy.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Cooldown period after which an unhealthy backend is re-tried.
const HEALTH_COOLDOWN: Duration = Duration::from_secs(30);

/// Health state for a group proxy backend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum HealthState {
    Healthy,
    Unhealthy,
}

/// Per-backend health tracking for group load balancing.
#[derive(Debug, Clone)]
pub(crate) struct GroupMemberHealth {
    pub state: HealthState,
    pub consecutive_failures: u32,
    pub last_failure: Option<Instant>,
}

impl GroupMemberHealth {
    pub fn healthy() -> Self {
        Self {
            state: HealthState::Healthy,
            consecutive_failures: 0,
            last_failure: None,
        }
    }
}

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
    /// Allowed visitor users (STCP/XTCP access control).
    /// Go frp v0.70 compat: empty = owner only, ["*"] = all,
    /// otherwise specific user list.
    pub allow_users: Vec<String>,
    /// PROXY protocol version (v1, v2, or empty).
    pub proxy_protocol_version: String,
    /// Response headers to inject into HTTP responses.
    pub response_headers: std::collections::HashMap<String, String>,
    /// Custom domains for HTTP vhost routing.
    pub custom_domains: Vec<String>,
    /// Per-user routing: extract username from Authorization header and route
    /// to proxy `{route_by_http_user}.{username}` (Go frp compat).
    pub route_by_http_user: String,
    /// Multiplexer type (e.g., "yamux").
    pub multiplexer: String,
    pub bandwidth_limit: String,
    pub bandwidth_limit_mode: String,
    pub user: String,
}

impl ProxyInfo {
    /// Returns the proxy name for use as an `sk_index` key, if this proxy
    /// has a non-empty secret key (STCP/XTCP). Returns `None` when `sk`
    /// is empty/missing.
    ///
    /// The key is `proxy_name` — unique per ProxyManager, so multiple
    /// proxies sharing the same secret key never collide.
    pub fn sk_index_key(&self) -> Option<&str> {
        if self.sk.as_deref().filter(|s| !s.is_empty()).is_some() {
            Some(&self.name)
        } else {
            None
        }
    }
}

/// Manages all proxy registrations on the server.
pub struct ProxyManager {
    proxies: RwLock<HashMap<String, Arc<ProxyInfo>>>,
    by_client: RwLock<HashMap<String, HashMap<String, Arc<ProxyInfo>>>>,
    /// group name → sorted list of proxy names (for round-robin selection)
    groups: RwLock<HashMap<String, Vec<String>>>,
    /// Per-group round-robin counters. Incremented on each selection.
    group_counters: Mutex<HashMap<String, u64>>,
    /// Per-proxy health state for group load balancing.
    /// Keyed by proxy name (same as `proxies` keys).
    group_health: RwLock<HashMap<String, GroupMemberHealth>>,
    /// Fast-path guard: true when `group_health` has ≥1 entries.
    /// Avoids acquiring the `group_health` RwLock on every
    /// `select_group_backend` call when no health tracking is active.
    health_tracking_active: AtomicBool,
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
            group_health: RwLock::new(HashMap::new()),
            health_tracking_active: AtomicBool::new(false),
        }
    }

    /// Non-blocking readiness probe: true if the proxy registry lock is
    /// acquirable right now (not held/deadlocked). Used by /healthz readiness.
    pub fn is_responsive(&self) -> bool {
        self.proxies.try_read().is_ok()
    }

    pub async fn register(&self, run_id: String, info: ProxyInfo) -> Result<(), String> {
        let name = info.name.clone();
        let group = info.group.clone();
        let info = Arc::new(info);
        // Check-and-insert atomically under write lock (fixes TOCTOU).
        // Must check BEFORE updating group index — if registration fails
        // due to name conflict, the group index must not be polluted with
        // a proxy name that belongs to a different (already-registered) proxy.
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
            .insert(name.clone(), info);
        // Register in group index only after successful insertion.
        if let Some(ref group) = group {
            if !group.is_empty() {
                let mut groups = self.groups.write().await;
                groups.entry(group.clone()).or_default().push(name);
            }
        }
        Ok(())
    }

    pub async fn get(&self, name: &str) -> Option<Arc<ProxyInfo>> {
        self.proxies.read().await.get(name).cloned()
    }

    /// Remove a proxy, returning `true` if it was actually present and removed.
    ///
    /// Callers that maintain derived counters (e.g. the SNI-sniff gate
    /// `https_proxy_count`) must only update them when this returns `true`:
    /// removal paths can race (dashboard delete vs CloseProxy vs client
    /// disconnect) and both may observe the proxy before either removes it.
    pub async fn remove(&self, name: &str) -> bool {
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
                            let mut counters = self
                                .group_counters
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            counters.remove(group);
                        }
                    }
                }
            }
            // Clean up health tracking for this proxy
            {
                let mut health = self.group_health.write().await;
                health.remove(name);
                if health.is_empty() {
                    self.health_tracking_active.store(false, Ordering::Release);
                }
            }
            drop(proxies);
            let mut by_client = self.by_client.write().await;
            if let Some(client_proxies) = by_client.get_mut(&info.run_id) {
                client_proxies.remove(name);
            }
            true
        } else {
            false
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
                                    let mut counters = self
                                        .group_counters
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
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

    /// Report a successful connection to a backend, resetting its health.
    pub async fn report_backend_success(&self, name: &str) {
        let mut health = self.group_health.write().await;
        if let Some(entry) = health.get_mut(name) {
            entry.consecutive_failures = 0;
            entry.state = HealthState::Healthy;
            entry.last_failure = None;
        }
    }

    /// Report a connection failure to a backend. After `MAX_CONSECUTIVE_FAILURES`
    /// (3), the backend is marked `Unhealthy`. It recovers after `HEALTH_COOLDOWN`
    /// (30s) or on the next successful connection via `report_backend_success`.
    pub async fn report_backend_failure(&self, name: &str) {
        self.health_tracking_active.store(true, Ordering::Release);
        let mut health = self.group_health.write().await;
        let entry = health
            .entry(name.to_string())
            .or_insert_with(GroupMemberHealth::healthy);
        entry.consecutive_failures += 1;
        entry.last_failure = Some(Instant::now());
        if entry.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            tracing::warn!(
                proxy_name = %name,
                failures = entry.consecutive_failures,
                "Group backend '{}' marked unhealthy after {} consecutive failures",
                name,
                entry.consecutive_failures,
            );
            entry.state = HealthState::Unhealthy;
        }
    }

    /// Remove health tracking for a proxy (called on proxy removal).
    pub async fn remove_backend_health(&self, name: &str) {
        let mut health = self.group_health.write().await;
        health.remove(name);
        if health.is_empty() {
            self.health_tracking_active.store(false, Ordering::Release);
        }
    }

    /// Select a backend from a group for load balancing.
    /// Skips backends marked unhealthy (unless all backends are unhealthy).
    /// Uses group_key for affinity: same key → same backend (hash-based).
    /// Without group_key, true round-robin selection across healthy members.
    /// Matches Go frp v0.69.1 group load balancing behavior.
    pub async fn select_group_backend(&self, group: &str, group_key: &str) -> Option<String> {
        let groups = self.groups.read().await;
        let members = groups.get(group)?;
        if members.is_empty() {
            return None;
        }

        // Fast path: no health tracking entries → skip RwLock and Vec alloc.
        if !self.health_tracking_active.load(Ordering::Acquire) {
            return if !group_key.is_empty() {
                let hash = group_key
                    .bytes()
                    .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
                Some(members[hash as usize % members.len()].clone())
            } else {
                let mut counters = self
                    .group_counters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let counter = counters.entry(group.to_string()).or_insert(0);
                let idx = (*counter as usize) % members.len();
                *counter += 1;
                Some(members[idx].clone())
            };
        }

        // Filter out unhealthy members, but only if at least one is healthy.
        // If all members are unhealthy, fall through to allow best-effort routing.
        let health = self.group_health.read().await;
        let now = Instant::now();
        let healthy_indices: Vec<usize> = members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| {
                match health.get(m) {
                    Some(h) if h.state == HealthState::Unhealthy => {
                        // Check if cooldown has expired → recover automatically
                        if let Some(t) = h.last_failure {
                            if now.duration_since(t) >= HEALTH_COOLDOWN {
                                Some(i)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    _ => Some(i), // No health entry or Healthy
                }
            })
            .collect();
        drop(health);

        // Use the healthy indices list; if empty, fall back to all members
        let pool_indices: &[usize] = if healthy_indices.is_empty() {
            // All members are unhealthy or none filtered — use full member list
            &(0..members.len()).collect::<Vec<_>>()
        } else {
            &healthy_indices
        };

        if pool_indices.is_empty() {
            return None;
        }

        if !group_key.is_empty() {
            // Sticky session: hash the key to pick a backend
            let hash = group_key
                .bytes()
                .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
            let idx = pool_indices[hash as usize % pool_indices.len()];
            Some(members[idx].clone())
        } else {
            // True round-robin: increment counter, modulo pool count.
            let mut counters = self
                .group_counters
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let counter = counters.entry(group.to_string()).or_insert(0);
            let idx = pool_indices[(*counter as usize) % pool_indices.len()];
            *counter += 1;
            Some(members[idx].clone())
        }
    }

    /// Get the group for a proxy, if any.
    pub async fn get_group(&self, name: &str) -> Option<String> {
        self.proxies
            .read()
            .await
            .get(name)
            .and_then(|p| p.group.clone())
            .filter(|g| !g.is_empty())
    }

    /// Number of members in a group. Returns 0 if group doesn't exist.
    pub async fn group_len(&self, group: &str) -> usize {
        self.groups
            .read()
            .await
            .get(group)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Check if a group has any members.
    pub async fn group_exists(&self, group: &str) -> bool {
        self.group_len(group).await > 0
    }

    pub async fn list_client(&self, run_id: &str) -> Vec<Arc<ProxyInfo>> {
        self.by_client
            .read()
            .await
            .get(run_id)
            .map(|proxies| proxies.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List proxy names for a specific client (run_id).
    pub async fn list_client_proxy_names(&self, run_id: &str) -> Vec<String> {
        self.by_client
            .read()
            .await
            .get(run_id)
            .map(|proxies| proxies.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn get_run_id(&self, name: &str) -> Option<String> {
        self.proxies
            .read()
            .await
            .get(name)
            .map(|p| p.run_id.clone())
    }

    /// Select a backend from a group and return both the backend name and its run_id.
    /// Returns `None` if the group has no suitable backends.
    pub async fn select_group_backend_with_run_id(
        &self,
        group: &str,
        group_key: &str,
    ) -> Option<(String, String)> {
        let backend = self.select_group_backend(group, group_key).await?;
        let run_id = self.get_run_id(&backend).await.unwrap_or_default();
        Some((backend, run_id))
    }

    pub async fn list(&self) -> Vec<Arc<ProxyInfo>> {
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
/// If `port` > 0, try to allocate exactly that port. If already used or
/// not bindable at the OS level, return None.
/// If `port` == 0, scan all ranges in order and return the first available
/// port that is both not in `used_ports` and not bound by another process
/// on the system.
///
/// The `bind_addr` parameter specifies the IP address to use for the OS-level
/// TCP bind probe, matching Go frp's `Manager.isPortAvailable` behavior.
pub fn allocate_port_multi(
    used_ports: &mut std::collections::HashSet<u16>,
    port: u16,
    ranges: &[frp_core::config::PortsRange],
    bind_addr: &str,
) -> Option<u16> {
    let bind_addr = if bind_addr.is_empty() {
        "0.0.0.0"
    } else {
        bind_addr
    };

    if port > 0 {
        if used_ports.contains(&port) {
            return None;
        }
        // When allow_ports ranges are configured, an explicit port must fall
        // within at least one range (Go frp compat: Manager.Acquire checks
        // freePorts which is populated from allowPorts ranges). Without this
        // check, a client could bypass the port restriction by specifying a
        // port outside the configured ranges.
        if !ranges.is_empty() && !ranges.iter().any(|r| r.contains(port)) {
            tracing::debug!(
                port = %port,
                ranges = ?ranges,
                "Explicit port {port} is not within any configured allow_ports range",
            );
            return None;
        }
        if is_port_bindable(bind_addr, port) {
            used_ports.insert(port);
            return Some(port);
        }
        return None;
    }
    for r in ranges {
        for p in r.iter() {
            if used_ports.contains(&p) {
                continue;
            }
            if is_port_bindable(bind_addr, p) {
                used_ports.insert(p);
                return Some(p);
            }
        }
    }
    tracing::warn!(
        ranges = ?ranges,
        "Port exhaustion: no available ports in configured allow_ports ranges",
    );
    None
}

/// Check whether a port is available at the OS level by attempting a TCP bind.
/// Immediately drops the listener if successful (just a probe).
/// Matches Go frp's `Manager.isPortAvailable` behavior.
pub fn is_tcp_port_bindable(bind_addr: &str, port: u16) -> bool {
    is_port_bindable(bind_addr, port)
}

fn is_port_bindable(bind_addr: &str, port: u16) -> bool {
    let addr = frp_core::format_socket_addr(bind_addr, port);
    match std::net::TcpListener::bind(&addr) {
        Ok(listener) => {
            // Probe succeeded — port is available. Drop immediately.
            drop(listener);
            true
        }
        Err(e) => {
            tracing::debug!(
                port = %port,
                bind_addr = %bind_addr,
                error = %e,
                "Port {port} on bind address '{bind_addr}' is not available at OS level: {e}",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_port_multi_explicit_unavailable() {
        // A port already in used_ports should be rejected immediately
        let mut used = std::collections::HashSet::new();
        used.insert(8080);
        assert_eq!(
            allocate_port_multi(&mut used, 8080, &[], "0.0.0.0"),
            None,
            "port already in used_ports must return None"
        );
    }

    #[test]
    fn test_allocate_port_multi_explicit_not_in_ranges() {
        // An explicit port outside the configured allow_ports ranges must be rejected
        // (Go frp compat: Manager.Acquire checks freePorts which is populated from allowPorts).
        let mut used = std::collections::HashSet::new();
        let ranges = [frp_core::config::PortsRange {
            start: 10000,
            end: 20000,
            single: 0,
        }];
        assert_eq!(
            allocate_port_multi(&mut used, 8080, &ranges, "127.0.0.1"),
            None,
            "explicit port outside allow_ports ranges must return None"
        );
    }

    #[test]
    fn test_allocate_port_multi_explicit_in_ranges() {
        // An explicit port within a configured allow_ports range must be accepted
        let mut used = std::collections::HashSet::new();
        let ranges = [
            frp_core::config::PortsRange {
                start: 10000,
                end: 20000,
                single: 0,
            },
            frp_core::config::PortsRange {
                start: 30000,
                end: 40000,
                single: 0,
            },
        ];
        let result = allocate_port_multi(&mut used, 35000, &ranges, "127.0.0.1");
        assert_eq!(
            result,
            Some(35000),
            "explicit port within allow_ports range must be accepted"
        );
        // Verify it's now in used_ports
        assert!(
            used.contains(&35000),
            "allocated port must be in used_ports"
        );
    }

    #[test]
    fn test_allocate_port_multi_explicit_empty_ranges_always_allowed() {
        // When ranges is empty (no allow_ports configured), all ports are allowed
        let mut used = std::collections::HashSet::new();
        let result = allocate_port_multi(&mut used, 51993, &[], "127.0.0.1");
        // Should succeed if port is bindable
        assert!(
            result.is_some(),
            "port should be allocatable with empty ranges"
        );
        assert_eq!(result, Some(51993));
    }

    #[test]
    fn test_allocate_port_multi_explicit_available() {
        // Allocate a port that's not in used_ports and verify it succeeds.
        // "0.0.0.0" with port 0 is invalid, so use a specific port that's
        // very likely available (above the ephemeral range).
        let mut used = std::collections::HashSet::new();
        let result = allocate_port_multi(&mut used, 51999, &[], "127.0.0.1");
        assert_eq!(
            result,
            Some(51999),
            "port not in used_ports must be allocatable"
        );
        // Second allocation of same port should fail
        assert_eq!(
            allocate_port_multi(&mut used, 51999, &[], "127.0.0.1"),
            None,
            "same port cannot be allocated twice"
        );
    }

    #[test]
    fn test_allocate_port_multi_range_scan() {
        let mut used = std::collections::HashSet::new();
        // Pre-fill one port in the range
        used.insert(62002);
        let ranges = [frp_core::config::PortsRange {
            start: 62001,
            end: 62005,
            single: 0,
        }];
        // Should skip 62001 (bindable), then 62002 (in set), then
        // find 62003 (bindable).
        let result = allocate_port_multi(&mut used, 0, &ranges, "127.0.0.1");
        assert!(result.is_some(), "should allocate a port from the range");
        let p = result.unwrap();
        assert!((62001..=62005).contains(&p), "port must be in range");
        assert_ne!(p, 62002, "should not allocate port already in used_ports");
    }

    #[test]
    fn test_allocate_port_multi_empty_ranges() {
        let mut used = std::collections::HashSet::new();
        assert_eq!(
            allocate_port_multi(&mut used, 0, &[], "0.0.0.0"),
            None,
            "empty ranges should return None"
        );
    }

    #[test]
    fn test_allocate_port_multi_explicit_port_zero() {
        // port=0 should scan ranges, not allocate port 0
        let mut used = std::collections::HashSet::new();
        let result = allocate_port_multi(
            &mut used,
            0,
            &[frp_core::config::PortsRange {
                start: 51990,
                end: 51990,
                single: 0,
            }],
            "127.0.0.1",
        );
        assert_eq!(result, Some(51990), "explicit port 0 should scan ranges");
    }

    #[test]
    fn test_allocate_port_multi_empty_bind_addr_defaults() {
        let mut used = std::collections::HashSet::new();
        let result = allocate_port_multi(&mut used, 51991, &[], "");
        // Empty bind_addr defaults to 0.0.0.0 — should work on any machine
        assert_eq!(result, Some(51991), "empty bind_addr defaults to 0.0.0.0");
    }

    #[test]
    fn test_is_port_bindable_free_port() {
        assert!(
            is_port_bindable("127.0.0.1", 51992),
            "free port should be bindable"
        );
    }

    #[test]
    fn test_is_port_bindable_bound_port() {
        // Bind a port, then check it's not bindable
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            !is_port_bindable("127.0.0.1", port),
            "bound port should not be bindable"
        );
        // Drop the listener to avoid test pollution
        drop(listener);
    }
}
