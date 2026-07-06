//! Client registry — thread-safe tracking of connected frpc instances.
//!
//! Port of Go frp v0.69.1 `server/registry/registry.go`.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Metadata about a connected frpc instance.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Composite key: `{user}.{clientID}` (runID fallback when raw_client_id is empty).
    pub key: String,
    /// Authenticated user (from auth).
    pub user: String,
    /// Explicit client ID from config, or empty string.
    pub raw_client_id: String,
    /// Unique run ID for this connection.
    pub run_id: String,
    /// Client hostname.
    pub hostname: String,
    /// Remote IP address.
    pub ip: String,
    /// frp version reported by client.
    pub version: String,
    /// Wire protocol in use ("v1" or "v2").
    pub wire_protocol: String,
    /// When this client first connected (across reconnects).
    pub first_connected_at: Instant,
    /// When this client last connected.
    pub last_connected_at: Instant,
    /// When this client disconnected (None if currently online).
    pub disconnected_at: Option<Instant>,
    /// Whether this client is currently online.
    pub online: bool,
}

impl ClientInfo {
    /// Resolved client identifier: `raw_client_id` if set, otherwise `run_id`.
    pub fn client_id(&self) -> &str {
        if self.raw_client_id.is_empty() {
            &self.run_id
        } else {
            &self.raw_client_id
        }
    }
}

/// Thread-safe registry of connected frpc clients.
///
/// Keyed by `{user}.{clientID}` with a secondary `run_id → key` index
/// for efficient disconnect handling.
///
/// Entries without an explicit `raw_client_id` are removed on disconnect
/// to avoid accumulating stale offline records.
pub struct ClientRegistry {
    clients: RwLock<HashMap<String, ClientInfo>>,
    run_index: RwLock<HashMap<String, String>>,
}

impl ClientRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            run_index: RwLock::new(HashMap::new()),
        }
    }

    /// Register or update client metadata.
    ///
    /// Returns `(key, conflict)` where `conflict=true` means an online client
    /// with the same key but different run_id already exists.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &self,
        user: &str,
        raw_client_id: &str,
        run_id: &str,
        hostname: &str,
        version: &str,
        remote_addr: &str,
        wire_protocol: &str,
    ) -> (String, bool) {
        if run_id.is_empty() {
            return (String::new(), false);
        }

        let effective_id = if raw_client_id.is_empty() {
            run_id
        } else {
            raw_client_id
        };
        let key = compose_client_key(user, effective_id);
        let enforce_unique = !raw_client_id.is_empty();

        let now = Instant::now();

        let mut clients = self.clients.write().unwrap();
        let mut run_index = self.run_index.write().unwrap();

        // Conflict check under write lock (atomic with registration, matching Go)
        if enforce_unique {
            if let Some(info) = clients.get(&key) {
                if info.online && !info.run_id.is_empty() && info.run_id != run_id {
                    return (key, true);
                }
            }
        }

        let info = clients.entry(key.clone()).or_insert_with(|| ClientInfo {
            key: key.clone(),
            user: user.to_string(),
            raw_client_id: String::new(),
            run_id: String::new(),
            hostname: String::new(),
            ip: String::new(),
            version: String::new(),
            wire_protocol: String::new(),
            first_connected_at: now,
            last_connected_at: now,
            disconnected_at: None,
            online: false,
        });

        // If reconnecting with a new run_id, remove old run_index entry
        if !info.run_id.is_empty() && info.run_id != run_id {
            run_index.remove(&info.run_id);
        }

        // first_connected_at is set by or_insert_with for new entries;
        // keep the original value for reconnecting clients.
        info.raw_client_id = raw_client_id.to_string();
        info.run_id = run_id.to_string();
        info.hostname = hostname.to_string();
        info.ip = remote_addr.to_string();
        info.version = version.to_string();
        info.wire_protocol = wire_protocol.to_string();
        info.last_connected_at = now;
        info.disconnected_at = None;
        info.online = true;

        run_index.insert(run_id.to_string(), key.clone());
        (key, false)
    }

    /// Mark a client as offline by its run_id.
    ///
    /// If the client has no `raw_client_id`, the entry is removed entirely.
    /// Otherwise, the entry persists with `online=false` and `disconnected_at` set.
    pub fn mark_offline_by_run_id(&self, run_id: &str) {
        let mut run_index = self.run_index.write().unwrap();
        let key = match run_index.remove(run_id) {
            Some(k) => k,
            None => return,
        };
        drop(run_index);

        let mut clients = self.clients.write().unwrap();
        if let Some(info) = clients.get_mut(&key) {
            if info.run_id == run_id {
                if info.raw_client_id.is_empty() {
                    clients.remove(&key);
                } else {
                    info.run_id = String::new();
                    info.online = false;
                    info.disconnected_at = Some(Instant::now());
                }
            }
        }
    }

    /// Return a snapshot of all known clients.
    pub fn list(&self) -> Vec<ClientInfo> {
        let clients = self.clients.read().unwrap();
        clients.values().cloned().collect()
    }

    /// Look up a client by its composite key.
    pub fn get_by_key(&self, key: &str) -> Option<ClientInfo> {
        let clients = self.clients.read().unwrap();
        clients.get(key).cloned()
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a composite key from user and client identifier.
///
/// Returns `{user}.{id}` when both are non-empty, or whichever is non-empty.
fn compose_client_key(user: &str, id: &str) -> String {
    match (user.is_empty(), id.is_empty()) {
        (true, _) => id.to_string(),
        (_, true) => user.to_string(),
        (false, false) => format!("{user}.{id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_registry() -> ClientRegistry {
        ClientRegistry::new()
    }

    fn register_test_client(r: &ClientRegistry, user: &str, raw_id: &str, run_id: &str) -> (String, bool) {
        r.register(user, raw_id, run_id, "testhost", "0.69.1", "1.2.3.4:5678", "v1")
    }

    #[test]
    fn test_register_new() {
        let r = mk_registry();
        let (key, conflict) = register_test_client(&r, "user1", "clientA", "run-001");
        assert!(!conflict);
        assert_eq!(key, "user1.clientA");

        let info = r.get_by_key("user1.clientA").unwrap();
        assert!(info.online);
        assert_eq!(info.run_id, "run-001");
        assert_eq!(info.client_id(), "clientA");
    }

    #[test]
    fn test_register_conflict() {
        let r = mk_registry();
        register_test_client(&r, "u", "c1", "run-1");
        let (_key, conflict) = register_test_client(&r, "u", "c1", "run-2");
        assert!(conflict);
    }

    #[test]
    fn test_register_no_conflict_after_offline() {
        let r = mk_registry();
        register_test_client(&r, "u", "c1", "run-1");
        r.mark_offline_by_run_id("run-1");
        let (_key, conflict) = register_test_client(&r, "u", "c1", "run-2");
        assert!(!conflict);
    }

    #[test]
    fn test_mark_offline_removes_no_raw_id() {
        let r = mk_registry();
        register_test_client(&r, "u", "", "run-x");
        r.mark_offline_by_run_id("run-x");
        assert!(r.get_by_key("u.run-x").is_none());
    }

    #[test]
    fn test_mark_offline_preserves_with_raw_id() {
        let r = mk_registry();
        register_test_client(&r, "u", "c1", "run-y");
        r.mark_offline_by_run_id("run-y");
        let info = r.get_by_key("u.c1").unwrap();
        assert!(!info.online);
        assert!(info.run_id.is_empty());
        assert!(info.disconnected_at.is_some());
    }

    #[test]
    fn test_list_snapshot() {
        let r = mk_registry();
        register_test_client(&r, "a", "x", "r1");
        register_test_client(&r, "b", "y", "r2");
        let snapshot = r.list();
        assert_eq!(snapshot.len(), 2);
    }

    #[test]
    fn test_get_by_key_missing() {
        let r = mk_registry();
        assert!(r.get_by_key("nonexistent").is_none());
    }

    #[test]
    fn test_compose_client_key() {
        assert_eq!(compose_client_key("user", "id"), "user.id");
        assert_eq!(compose_client_key("user", ""), "user");
        assert_eq!(compose_client_key("", "id"), "id");
        assert_eq!(compose_client_key("", ""), "");
    }

    #[test]
    fn test_client_id_fallback() {
        let info = ClientInfo {
            key: "k".into(),
            user: "u".into(),
            raw_client_id: "".into(),
            run_id: "run-123".into(),
            hostname: "h".into(),
            ip: "1.2.3.4".into(),
            version: "0.69.1".into(),
            wire_protocol: "v1".into(),
            first_connected_at: Instant::now(),
            last_connected_at: Instant::now(),
            disconnected_at: None,
            online: true,
        };
        assert_eq!(info.client_id(), "run-123");
    }
}
