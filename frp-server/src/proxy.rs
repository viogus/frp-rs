use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::net::TcpStream;
use tracing::{info, warn, error, debug};

use frp_core::transport::IoStream;

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
        let mut proxies = self.proxies.write().await;
        if let Some(info) = proxies.remove(name) {
            let mut by_client = self.by_client.write().await;
            if let Some(client_proxies) = by_client.get_mut(&info.run_id) {
                client_proxies.remove(name);
            }
        }
    }

    pub async fn remove_client(&self, run_id: &str) {
        let mut by_client = self.by_client.write().await;
        if let Some(proxies) = by_client.remove(run_id) {
            let mut all_proxies = self.proxies.write().await;
            for name in proxies.keys() {
                all_proxies.remove(name);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn list(&self) -> Vec<ProxyInfo> {
        self.proxies.read().await.values().cloned().collect()
    }
}

/// Data associated with a registered proxy for work connection handling.
#[derive(Clone)]
pub struct ProxyEntry {
    pub info: ProxyInfo,
    pub work_conn_tx: mpsc::UnboundedSender<IoStream>,
}

/// Bridge a user connection and a work connection for a proxy.
pub async fn proxy_pair(
    mut user_conn: TcpStream,
    proxy_name: String,
    proxy_table: Arc<RwLock<HashMap<String, ProxyEntry>>>,
) {
    let work_conn = {
        let table = proxy_table.read().await;
        table.get(&proxy_name).and_then(|entry| {
            entry.work_conn_tx.try_recv().ok()
        })
    };

    match work_conn {
        Some(mut wc) => {
            match &mut wc {
                IoStream::Tcp(ws) => {
                    debug!("Bridging user conn to work conn for proxy: {}", proxy_name);
                    if let Err(e) = tokio::io::copy_bidirectional(&mut user_conn, ws).await {
                        error!("Proxy pair error for {}: {}", proxy_name, e);
                    }
                }
                IoStream::WebSocket(_ws) => {
                    warn!("WebSocket work connection bridging not implemented yet");
                }
            }
            info!("Proxy pair completed for: {}", proxy_name);
        }
        None => {
            warn!("No work connection available for proxy: {}", proxy_name);
        }
    }
}

/// Allocate a port for a proxy, auto-assigning if port is 0.
pub fn allocate_port(
    used_ports: &mut std::collections::HashSet<u16>,
    port: u16,
    max_attempts: u16,
    base_port: u16,
) -> Option<u16> {
    if port > 0 {
        if used_ports.insert(port) {
            return Some(port);
        }
        return None;
    }
    for p in base_port..base_port + max_attempts {
        if used_ports.insert(p) {
            return Some(p);
        }
    }
    None
}
