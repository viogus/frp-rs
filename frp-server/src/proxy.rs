use std::collections::HashMap;
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
}

/// Manages all proxy registrations on the server.
pub struct ProxyManager {
    proxies: RwLock<HashMap<String, ProxyInfo>>,
    by_client: RwLock<HashMap<String, HashMap<String, ProxyInfo>>>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(HashMap::new()),
            by_client: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(&self, run_id: String, info: ProxyInfo) -> Result<(), String> {
        let name = info.name.clone();
        {
            let proxies = self.proxies.read().await;
            if proxies.contains_key(&name) {
                return Err(format!("proxy '{}' already registered", name));
            }
        }
        self.proxies.write().await.insert(name.clone(), info.clone());
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
        // Lock proxies first, then by_client — consistent order with remove_client
        let mut proxies = self.proxies.write().await;
        if let Some(info) = proxies.remove(name) {
            // Drop proxies lock before acquiring by_client to avoid holding both
            drop(proxies);
            let mut by_client = self.by_client.write().await;
            if let Some(client_proxies) = by_client.get_mut(&info.run_id) {
                client_proxies.remove(name);
            }
        }
    }

    pub async fn remove_client(&self, run_id: &str) {
        // Lock proxies first, then by_client — consistent order with remove
        let mut proxies = self.proxies.write().await;
        let mut by_client = self.by_client.write().await;
        if let Some(client_proxies) = by_client.remove(run_id) {
            for name in client_proxies.keys() {
                proxies.remove(name);
            }
        }
    }

    pub async fn list_client(&self, run_id: &str) -> Vec<ProxyInfo> {
        self.by_client.read().await.get(run_id)
            .map(|proxies| proxies.values().cloned().collect())
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

/// Allocate a port for a proxy, auto-assigning if port is 0.
/// Iterates over all configured ranges. Kept for backward compat.
#[allow(dead_code)]
pub fn allocate_port(
    used_ports: &mut std::collections::HashSet<u16>,
    port: u16,
    max_attempts: u16,
    base_port: u16,
) -> Option<u16> {
    allocate_port_multi(used_ports, port, &[(base_port, base_port.saturating_add(max_attempts).saturating_sub(1))])
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
