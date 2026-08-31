use dashmap::DashMap;
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
    /// Control generation that registered this proxy. Lets a disconnect
    /// sweep (`unregister_control`) skip proxies registered by a
    /// superseding control for the same run_id (audit finding 3).
    /// 0 = legacy/unknown generation (tests, manual registration).
    pub control_id: u64,
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
    /// Negotiated UDPPacket codec of the registering control (`"binary-v1"`
    /// or empty, Go frp v0.71.0). The SUDP message bridge uses this as the
    /// provider-segment codec when the visitor segment uses a different
    /// packet encoding.
    pub udp_packet_codec: String,
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
    /// Per-proxy user-connection cap (audit D2-2): a Semaphore of size
    /// `max_conns_per_proxy` when configured (>0); None = unlimited (Go
    /// default). Permits are held for the user conn's full lifetime (they
    /// live in `PendingRequest` and drop when the bridge ends), bounding
    /// per-proxy connection floods that would otherwise grow
    /// `pending_requests` + fds without limit.
    pub user_conn_sem: Option<Arc<tokio::sync::Semaphore>>,
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
    /// Sharded lock-free map (dashmap): per-proxy lookups on every
    /// NewWorkConn dispatch no longer contend on one global read lock.
    proxies: DashMap<String, Arc<ProxyInfo>>,
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
            proxies: DashMap::new(),
            by_client: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            group_counters: Mutex::new(HashMap::new()),
            group_health: RwLock::new(HashMap::new()),
            health_tracking_active: AtomicBool::new(false),
        }
    }

    /// Readiness probe. With the DashMap migration the registry has no global
    /// lock that could deadlock, so the legacy `try_read().is_ok()` probe is
    /// replaced by a constant `true` — the registry is always accessible.
    pub fn is_responsive(&self) -> bool {
        true
    }

    pub async fn register(&self, run_id: String, info: ProxyInfo) -> Result<(), String> {
        self.register_inner(run_id, info, false).await.map(|_| ())
    }

    /// Register a proxy, replacing an older control generation's entry for
    /// the same name and returning the entry that was replaced.
    ///
    /// The plain `register` rejects a name conflict. This variant allows
    /// ONE exception: the superseding control of the same run_id (strictly
    /// newer, non-zero control_id) re-registering a name its older
    /// generation still holds after a handoff-barrier timeout. The
    /// replaced entry is handed back so the caller can free the old
    /// control's port mark exactly once (audit-fix: residual port-mark
    /// leak on barrier-timeout supersession). control_id 0 (legacy
    /// callers) is never replaced, and a different run_id never replaces.
    pub async fn register_or_replace(
        &self,
        run_id: String,
        info: ProxyInfo,
    ) -> Result<Option<Arc<ProxyInfo>>, String> {
        self.register_inner(run_id, info, true).await
    }

    async fn register_inner(
        &self,
        run_id: String,
        info: ProxyInfo,
        replace: bool,
    ) -> Result<Option<Arc<ProxyInfo>>, String> {
        let name = info.name.clone();
        let group = info.group.clone();
        let info = Arc::new(info);
        // Check-and-insert atomically on the DashMap entry (fixes TOCTOU).
        // Must check BEFORE updating group index — if registration fails
        // due to name conflict, the group index must not be polluted with
        // a proxy name that belongs to a different (already-registered) proxy.
        // The entry guard is not Send and is dropped before the .await below.
        let replaced: Option<Arc<ProxyInfo>> = match self.proxies.entry(name.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let old = entry.get().clone();
                // Supersession takeover is only allowed when the SAME run_id
                // re-registers under a strictly newer control generation.
                let qualified = old.run_id == run_id
                    && old.control_id != 0
                    && info.control_id != 0
                    && old.control_id < info.control_id;
                if !replace || !qualified {
                    return Err(format!("proxy '{}' already registered", name));
                }
                entry.insert(info.clone());
                Some(old)
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(info.clone());
                None
            }
        };
        // Group index migration: a replaced entry moving to a different
        // group must leave its old group (cleaning up the group and its
        // round-robin counter when empty, mirroring remove()). A
        // replacement staying in the same group keeps its membership.
        if let Some(ref old) = replaced {
            if let Some(ref old_group) = old.group {
                if !old_group.is_empty() && old.group != group {
                    let mut groups = self.groups.write().await;
                    if let Some(members) = groups.get_mut(old_group) {
                        members.retain(|n| n != &name);
                        if members.is_empty() {
                            groups.remove(old_group);
                            // Clean up stale round-robin counter
                            let mut counters = self
                                .group_counters
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            counters.remove(old_group);
                        }
                    }
                }
            }
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
                let members = groups.entry(group.clone()).or_default();
                // A replacement staying in the same group is already a
                // member; re-pushing would double-count it.
                if !members.contains(&name) {
                    members.push(name);
                }
            }
        }
        Ok(replaced)
    }

    pub async fn get(&self, name: &str) -> Option<Arc<ProxyInfo>> {
        self.proxies.get(name).map(|r| r.value().clone())
    }

    /// Number of live proxies registered by one client (run_id).
    ///
    /// Backs the Rust-only `max_proxies_per_client` cap. Counts the
    /// `by_client` index, which is the same source the register path writes
    /// under the exclusive lock, so the count reflects the current registry
    /// state. Callers gate on `cap > 0` before consulting this.
    pub async fn client_proxy_count(&self, run_id: &str) -> usize {
        self.by_client
            .read()
            .await
            .get(run_id)
            .map(|proxies| proxies.len())
            .unwrap_or(0)
    }

    /// Hot-update server-side runtime settings for a live proxy without
    /// re-registering it or reloading the frpc side.
    ///
    /// Only bandwidth limits are server-side hot-applicable in frp-rs: they
    /// are read by the bridge path on every newly established connection, so
    /// an update takes effect for subsequent work-conns. Fields that depend
    /// on the frpc-side provider (local_addr, remote_port, custom_domains,
    /// use_encryption, ...) are deliberately NOT changed here — callers must
    /// reject those with a "requires frpc reload" error.
    ///
    /// Implementation: the stored `Arc<ProxyInfo>` is swapped for a
    /// cloned-and-modified one under the registry write lock. New work-conn
    /// requests that re-fetch the proxy from this manager observe the new
    /// settings; bridges already in flight keep their original limits.
    ///
    /// Returns Err if no proxy with `name` is registered.
    pub async fn update_runtime(
        &self,
        name: &str,
        bandwidth_limit: Option<String>,
        bandwidth_limit_mode: Option<String>,
    ) -> Result<(), String> {
        // Validate before taking the lock: a rejected update must never
        // observe a partially-applied state, and the write lock is held for
        // as short a time as possible.
        if let Some(bl) = &bandwidth_limit {
            if !bl.is_empty() && frp_core::config::parse_bandwidth_limit(bl).is_none() {
                return Err(format!(
                    "invalid bandwidthLimit '{bl}' (e.g. 1MB, 2KB, 1GB)"
                ));
            }
        }
        if let Some(m) = &bandwidth_limit_mode {
            if !matches!(m.as_str(), "server" | "client" | "") {
                return Err(
                    "bandwidthLimitMode must be one of server, client, or empty".to_string()
                );
            }
        }
        // Read-modify-write is atomic inside the DashMap entry guard:
        // `None` keeps the current value, so concurrent PUTs updating
        // disjoint fields do not clobber each other. The guard is not Send
        // and is dropped before the .await below.
        let updated = match self.proxies.get_mut(name) {
            Some(mut entry) => {
                let mut changed = (**entry).clone();
                if let Some(v) = bandwidth_limit {
                    changed.bandwidth_limit = v;
                }
                if let Some(v) = bandwidth_limit_mode {
                    changed.bandwidth_limit_mode = v;
                }
                let updated = Arc::new(changed);
                *entry = updated.clone();
                updated
            }
            None => return Err(format!("proxy '{name}' not found")),
        };
        // The DashMap entry guard was dropped above; a concurrent remove()
        // may have deleted the proxy in between. Re-check the registry
        // before syncing by_client so a removed proxy cannot be resurrected
        // as a phantom by_client entry (audit finding 7).
        if !self.proxies.contains_key(name) {
            return Err(format!("proxy '{name}' not found"));
        }
        // Keep the by_client index (run_id → name → info) in sync so
        // list_client / per-client iteration see the same updated record.
        // Use entry().or_default() like register() so a missing run_id key
        // (teardown race) cannot silently drop the sync.
        self.by_client
            .write()
            .await
            .entry(updated.run_id.clone())
            .or_default()
            .insert(name.to_string(), updated);
        Ok(())
    }

    /// Remove a proxy, returning `true` if it was actually present and removed.
    ///
    /// Callers that maintain derived counters (e.g. the SNI-sniff gate
    /// `https_proxy_count`) must only update them when this returns `true`:
    /// removal paths can race (dashboard delete vs CloseProxy vs client
    /// disconnect) and both may observe the proxy before either removes it.
    pub async fn remove(&self, name: &str) -> bool {
        // DashMap::remove is synchronous and releases the shard guard on
        // return; no guard is held across the .await calls below.
        let info = self.proxies.remove(name).map(|(_, v)| v);
        if let Some(info) = info {
            self.cleanup_removed(name, info).await;
            true
        } else {
            false
        }
    }

    /// Generation-guarded removal: remove only when the entry still belongs
    /// to `control_id` (round-7 audit MEDIUM — the stale-control reaper's
    /// get-then-remove could destroy a superseding control's fresh
    /// registration that landed between the check and the removal).
    /// Returns the removed entry, or None when the name is absent or owned
    /// by a different generation. `control_id == 0` entries (legacy callers,
    /// no owning control) are always removable, mirroring the reaper's old
    /// sweep semantics.
    pub async fn remove_if_control_id(
        &self,
        name: &str,
        control_id: u64,
    ) -> Option<Arc<ProxyInfo>> {
        let info = self
            .proxies
            .remove_if(name, |_, info| {
                info.control_id == 0 || info.control_id == control_id
            })
            .map(|(_, v)| v);
        if let Some(info) = info {
            self.cleanup_removed(name, info.clone()).await;
            Some(info)
        } else {
            None
        }
    }

    /// Index cleanup after a proxy entry was removed from `proxies`.
    async fn cleanup_removed(&self, name: &str, info: Arc<ProxyInfo>) {
        // A concurrent register() may have re-inserted a proxy under the
        // same name between our remove and the index cleanup below
        // (register() only touches `proxies` first, then the indexes).
        // Re-check the registry: if the name is live again, its fresh
        // indexes must not be deleted — doing so would leave the new
        // registration unreachable by group selection and list_client
        // (audit finding 6).
        if self.proxies.contains_key(name) {
            return;
        }
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
        let mut by_client = self.by_client.write().await;
        if let Some(client_proxies) = by_client.get_mut(&info.run_id) {
            client_proxies.remove(name);
        }
    }

    /// Remove all proxies belonging to a disconnected client.
    ///
    /// ## Lock ordering
    ///
    /// `proxies` is a sharded DashMap, so it no longer participates in the
    /// global tokio-lock ordering. The remaining canonical order is:
    ///   1. `self.by_client` (tokio RwLock)
    ///   2. `self.groups` (tokio RwLock)
    ///   3. `self.group_counters` (std Mutex)
    ///
    /// The by_client entry is removed first (taking proxies out of
    /// visibility), then the DashMap sweep via `retain` runs synchronously,
    /// and finally group + health indexes are cleaned up. Each lock is held
    /// one at a time and never across the other's acquisition, so no
    /// drop/reacquire dance is needed.
    ///
    /// **Do not** reorder these locks without verifying the full call graph
    /// for cycles. The existing callers acquire in this order; changing it
    /// risks deadlock with `register`, `unregister`, or `select_group_backend`.
    pub async fn remove_client(&self, run_id: &str) {
        let mut by_client = self.by_client.write().await;
        let client_proxies = by_client.remove(run_id);
        drop(by_client);
        if let Some(client_proxies) = client_proxies {
            // Collect owned (name, group) pairs first: DashMap guards are
            // not Send and must not be held across .await.
            let removed: Vec<(String, Option<String>)> = client_proxies
                .values()
                .map(|p| (p.name.clone(), p.group.clone()))
                .collect();
            // Remove every proxy belonging to this client in one sweep.
            // DashMap supports retain; shard locks are held only for the
            // synchronous callback (no .await inside).
            self.proxies.retain(|_, v| v.run_id != run_id);
            // Group index cleanup. The by_client entry is already gone and
            // the DashMap sweep is done, so each group lock acquisition is
            // short and non-nested.
            for (name, group) in &removed {
                if let Some(ref group) = group {
                    if !group.is_empty() {
                        let mut groups = self.groups.write().await;
                        if let Some(members) = groups.get_mut(group) {
                            members.retain(|n| n != name);
                            if members.is_empty() {
                                groups.remove(group);
                                // Clean up stale round-robin counter.
                                // group_counters is a std Mutex (not tokio),
                                // so it must not be held across .await. It is
                                // always acquired last.
                                let mut counters = self
                                    .group_counters
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                counters.remove(group);
                            }
                        }
                    }
                }
            }
            // Clean up health tracking for the removed proxies.
            {
                let mut health = self.group_health.write().await;
                for (name, _) in &removed {
                    health.remove(name);
                }
                if health.is_empty() {
                    self.health_tracking_active.store(false, Ordering::Release);
                }
            }
            // A concurrent register() for this run_id may have raced the
            // sweep: its proxy can end up removed from `proxies` while its
            // by_client entry survives (or vice versa — register() writes
            // by_client after `proxies`, so the interleaving is possible).
            // Re-sync by_client so it only references proxies that are still
            // in the registry — a phantom by_client entry would otherwise
            // surface a removed proxy to list_client (audit finding 9).
            {
                let mut by_client = self.by_client.write().await;
                by_client.retain(|_, proxies| {
                    proxies.retain(|name, _| self.proxies.contains_key(name));
                    !proxies.is_empty()
                });
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
            .get(name)
            .and_then(|r| r.value().group.clone())
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
        self.proxies.get(name).map(|r| r.value().run_id.clone())
    }

    /// Select a backend from a group and return both the backend name and its run_id.
    /// Returns `None` if the group has no suitable backends.
    ///
    /// Cheap guard for the removal race (audit fix): a backend can be
    /// unregistered between the group-member read and the run_id lookup
    /// (client disconnect mid-selection), which would otherwise yield an
    /// empty run_id and drop the user conn instead of falling back. Retry
    /// once so the next member is picked; a backend that is still stale on
    /// the second pass is genuinely gone and `None` lets the caller fall
    /// back to the originating proxy.
    pub async fn select_group_backend_with_run_id(
        &self,
        group: &str,
        group_key: &str,
    ) -> Option<(String, String)> {
        for _ in 0..2 {
            let backend = self.select_group_backend(group, group_key).await?;
            if let Some(run_id) = self.get_run_id(&backend).await {
                return Some((backend, run_id));
            }
            // Backend vanished between the group read and the run_id lookup;
            // loop to pick another member (round-robin advances, group_key
            // affinity re-picks — both bounded by the second pass).
        }
        None
    }

    pub async fn list(&self) -> Vec<Arc<ProxyInfo>> {
        self.proxies.iter().map(|r| r.value().clone()).collect()
    }
}

/// Entry stored in the per-proxy table (simplified — work connections
/// are managed per-client in the control handler).
#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub info: ProxyInfo,
}

/// Collect up to `limit` candidate TCP ports without probing the OS:
/// explicit `port` (with allow_ports range validation) or free ports from
/// `ranges`. This is the lock-fast portion of allocation — the blocking
/// `TcpListener::bind` probe must happen outside any shared lock (see
/// [`allocate_port_multi`]).
pub fn pick_tcp_port_candidates(
    used_ports: &std::collections::HashSet<u16>,
    port: u16,
    ranges: &[frp_core::config::PortsRange],
    limit: usize,
) -> Vec<u16> {
    if port > 0 {
        if used_ports.contains(&port) {
            return Vec::new();
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
            return Vec::new();
        }
        return vec![port];
    }
    let mut out = Vec::new();
    for r in ranges {
        for p in r.iter() {
            if !used_ports.contains(&p) {
                out.push(p);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
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
///
/// NOTE: the OS bind probe runs while `used_ports` is mutably borrowed. Hot
/// registration paths (proxy_ops) should prefer the lock-free three-phase
/// pattern: pick candidates under a read lock, probe outside any lock, then
/// commit under a short write lock.
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

    for candidate in pick_tcp_port_candidates(used_ports, port, ranges, u16::MAX as usize) {
        if is_port_bindable(bind_addr, candidate) {
            used_ports.insert(candidate);
            return Some(candidate);
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
    is_port_bindable_at(bind_addr, port, &addr)
}

/// Async port-bindability probe. Offloads the synchronous `TcpListener::bind`
/// to a blocking thread so a registration burst can't stall the worker thread
/// that owns the accept loop (audit r3/server#1). Falls back to `false` if the
/// blocking pool is shutting down.
pub async fn is_tcp_port_bindable_async(bind_addr: &str, port: u16) -> bool {
    let bind_addr = bind_addr.to_owned();
    let addr = frp_core::format_socket_addr(&bind_addr, port);
    tokio::task::spawn_blocking(move || is_port_bindable_at(&bind_addr, port, &addr))
        .await
        .unwrap_or(false)
}

fn is_port_bindable_at(bind_addr: &str, port: u16, addr: &str) -> bool {
    match std::net::TcpListener::bind(addr) {
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
        let result = allocate_port_multi(&mut used, 24013, &[], "127.0.0.1");
        // Should succeed if port is bindable
        assert!(
            result.is_some(),
            "port should be allocatable with empty ranges"
        );
        assert_eq!(result, Some(24013));
    }

    #[test]
    fn test_allocate_port_multi_explicit_available() {
        // Allocate a port that's not in used_ports and verify it succeeds.
        // "0.0.0.0" with port 0 is invalid, so use a specific port that's
        // very likely available. All the fixed ports in this test module live
        // in the 24000 block: below the Linux ephemeral port range
        // (32768-60999) so a concurrent test binding port 0 can never be
        // handed one of them (CI regression: 51990 was inside the ephemeral
        // range and randomly collided with a parallel test's `:0` bind).
        let mut used = std::collections::HashSet::new();
        let result = allocate_port_multi(&mut used, 24019, &[], "127.0.0.1");
        assert_eq!(
            result,
            Some(24019),
            "port not in used_ports must be allocatable"
        );
        // Second allocation of same port should fail
        assert_eq!(
            allocate_port_multi(&mut used, 24019, &[], "127.0.0.1"),
            None,
            "same port cannot be allocated twice"
        );
    }

    #[test]
    fn test_allocate_port_multi_range_scan() {
        let mut used = std::collections::HashSet::new();
        // Pre-fill one port in the range
        used.insert(24002);
        let ranges = [frp_core::config::PortsRange {
            start: 24001,
            end: 24005,
            single: 0,
        }];
        // Should skip 24001 (bindable), then 24002 (in set), then
        // find 24003 (bindable).
        let result = allocate_port_multi(&mut used, 0, &ranges, "127.0.0.1");
        assert!(result.is_some(), "should allocate a port from the range");
        let p = result.unwrap();
        assert!((24001..=24005).contains(&p), "port must be in range");
        assert_ne!(p, 24002, "should not allocate port already in used_ports");
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
                start: 24010,
                end: 24010,
                single: 0,
            }],
            "127.0.0.1",
        );
        assert_eq!(result, Some(24010), "explicit port 0 should scan ranges");
    }

    #[test]
    fn test_allocate_port_multi_empty_bind_addr_defaults() {
        let mut used = std::collections::HashSet::new();
        let result = allocate_port_multi(&mut used, 24011, &[], "");
        // Empty bind_addr defaults to 0.0.0.0 — should work on any machine
        assert_eq!(result, Some(24011), "empty bind_addr defaults to 0.0.0.0");
    }

    #[test]
    fn test_is_port_bindable_free_port() {
        assert!(
            is_port_bindable("127.0.0.1", 24012),
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

    fn test_proxy_info(name: &str, run_id: &str, group: Option<String>) -> ProxyInfo {
        ProxyInfo {
            name: name.to_string(),
            proxy_type: "tcp".into(),
            run_id: run_id.to_string(),
            control_id: 1,
            remote_port: Some(24000),
            sk: None,
            group,
            group_key: None,
            local_addr: Some("127.0.0.1:8080".into()),
            use_encryption: false,
            use_compression: false,
            virtual_net: None,
            allow_users: Vec::new(),
            proxy_protocol_version: String::new(),
            response_headers: std::collections::HashMap::new(),
            custom_domains: Vec::new(),
            route_by_http_user: String::new(),
            multiplexer: String::new(),
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
            udp_packet_codec: String::new(),
            user: String::new(),
            user_conn_sem: None,
        }
    }

    /// A backend removed between the group read and the run_id lookup (the
    /// remove() race window: `proxies` is swept before `groups`) must not
    /// yield a selection with an empty run_id — the cheap guard retries and
    /// then returns None so the caller falls back to the originating proxy.
    #[tokio::test]
    async fn select_group_backend_with_run_id_never_returns_empty_run_id() {
        let mgr = ProxyManager::new();
        mgr.register(
            "run-1".into(),
            test_proxy_info("a", "run-1", Some("g".into())),
        )
        .await
        .expect("register a");
        mgr.register(
            "run-1".into(),
            test_proxy_info("b", "run-1", Some("g".into())),
        )
        .await
        .expect("register b");

        // Normal selection returns a live backend with its run_id.
        let sel = mgr
            .select_group_backend_with_run_id("g", "")
            .await
            .expect("group must select");
        assert!(
            !sel.1.is_empty(),
            "live backend must carry a non-empty run_id: {sel:?}"
        );

        // Simulate the race-window state directly (test module has access):
        // all members are still listed in the group index but gone from the
        // proxies map — exactly what remove() leaves between its two sweeps.
        mgr.proxies.remove("a");
        mgr.proxies.remove("b");
        let sel = mgr.select_group_backend_with_run_id("g", "").await;
        assert!(
            sel.is_none(),
            "stale members must not yield Some((_, empty run_id)): {sel:?}"
        );
    }
}
