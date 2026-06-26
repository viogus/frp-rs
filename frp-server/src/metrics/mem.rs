//! Mem backend — in-memory metrics store that powers the dashboard API.
//! Mirrors Go frp's pkg/metrics/mem/server.go + pkg/metrics/mem/types.go.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

use super::types::{ProxyCounters, ProxyStats, ServerStats};
use super::ServerMetrics;

/// Mem backend key: (proxy_name, proxy_type) tuple.
type ProxyKey = (String, String);

pub struct MemBackend {
    client_count: AtomicI64,
    proxies: RwLock<HashMap<ProxyKey, Arc<ProxyCounters>>>,
}

impl MemBackend {
    pub fn new() -> Self {
        Self {
            client_count: AtomicI64::new(0),
            proxies: RwLock::new(HashMap::new()),
        }
    }

    /// Snapshot of all server-level stats for the dashboard API.
    pub fn server_stats(&self) -> ServerStats {
        let proxies = self.proxies.read().unwrap();
        let proxy_count = proxies.len() as i64;
        let mut connection_count: i64 = 0;
        let mut traffic_in: u64 = 0;
        let mut traffic_out: u64 = 0;
        for c in proxies.values() {
            connection_count += c.connections.load(Ordering::Relaxed);
            traffic_in += c.traffic_in.load(Ordering::Relaxed);
            traffic_out += c.traffic_out.load(Ordering::Relaxed);
        }
        ServerStats {
            client_count: self.client_count.load(Ordering::Relaxed),
            proxy_count,
            connection_count,
            traffic_in,
            traffic_out,
        }
    }

    /// List of all proxy stats for the dashboard /api/proxies endpoint.
    pub fn proxy_stats_list(&self) -> Vec<ProxyStats> {
        self.proxies
            .read()
            .unwrap()
            .values()
            .map(|c| c.snapshot())
            .collect()
    }

    /// Remove a proxy's counters (when proxy is closed).
    pub fn remove_proxy(&self, name: &str, proxy_type: &str) {
        self.proxies.write().unwrap().remove(&(name.to_string(), proxy_type.to_string()));
    }

    /// Remove all proxies belonging to a client (when client disconnects).
    /// Not yet plumbed — Go frp doesn't have per-client tracking in mem backend either.
    pub fn client_count_value(&self) -> i64 {
        self.client_count.load(Ordering::Relaxed)
    }
}

impl ServerMetrics for MemBackend {
    fn new_client(&self) {
        self.client_count.fetch_add(1, Ordering::Relaxed);
    }

    fn close_client(&self) {
        self.client_count.fetch_sub(1, Ordering::Relaxed);
    }

    fn new_proxy(&self, name: &str, proxy_type: &str) {
        let key = (name.to_string(), proxy_type.to_string());
        let mut proxies = self.proxies.write().unwrap();
        proxies.entry(key).or_insert_with(|| {
            Arc::new(ProxyCounters::new(name.to_string(), proxy_type.to_string()))
        });
    }

    fn close_proxy(&self, name: &str, proxy_type: &str) {
        self.remove_proxy(name, proxy_type);
    }

    fn open_connection(&self, name: &str, proxy_type: &str) {
        let key = (name.to_string(), proxy_type.to_string());
        let proxies = self.proxies.read().unwrap();
        if let Some(c) = proxies.get(&key) {
            c.connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn close_connection(&self, name: &str, proxy_type: &str) {
        let key = (name.to_string(), proxy_type.to_string());
        let proxies = self.proxies.read().unwrap();
        if let Some(c) = proxies.get(&key) {
            c.connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn add_traffic_in(&self, name: &str, proxy_type: &str, bytes: u64) {
        let key = (name.to_string(), proxy_type.to_string());
        let proxies = self.proxies.read().unwrap();
        if let Some(c) = proxies.get(&key) {
            c.traffic_in.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn add_traffic_out(&self, name: &str, proxy_type: &str, bytes: u64) {
        let key = (name.to_string(), proxy_type.to_string());
        let proxies = self.proxies.read().unwrap();
        if let Some(c) = proxies.get(&key) {
            c.traffic_out.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

impl Default for MemBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn test_new_and_close_client() {
        let m = MemBackend::new();
        assert_eq!(m.server_stats().client_count, 0);
        m.new_client();
        assert_eq!(m.server_stats().client_count, 1);
        m.new_client();
        assert_eq!(m.server_stats().client_count, 2);
        m.close_client();
        assert_eq!(m.server_stats().client_count, 1);
    }

    #[test]
    fn test_new_and_close_proxy() {
        let m = MemBackend::new();
        m.new_proxy("web", "tcp");
        assert_eq!(m.server_stats().proxy_count, 1);
        m.new_proxy("ssh", "tcp");
        assert_eq!(m.server_stats().proxy_count, 2);
        // duplicate should be idempotent
        m.new_proxy("web", "tcp");
        assert_eq!(m.server_stats().proxy_count, 2);
        m.close_proxy("web", "tcp");
        assert_eq!(m.server_stats().proxy_count, 1);
    }

    #[test]
    fn test_connection_open_close() {
        let m = MemBackend::new();
        m.new_proxy("web", "tcp");
        m.open_connection("web", "tcp");
        m.open_connection("web", "tcp");
        assert_eq!(m.server_stats().connection_count, 2);
        m.close_connection("web", "tcp");
        assert_eq!(m.server_stats().connection_count, 1);
    }

    #[test]
    fn test_traffic_counting() {
        let m = MemBackend::new();
        m.new_proxy("web", "tcp");
        m.add_traffic_in("web", "tcp", 100);
        m.add_traffic_in("web", "tcp", 50);
        m.add_traffic_out("web", "tcp", 200);
        assert_eq!(m.server_stats().traffic_in, 150);
        assert_eq!(m.server_stats().traffic_out, 200);
    }

    #[test]
    fn test_proxy_stats_list() {
        let m = MemBackend::new();
        m.new_proxy("web", "tcp");
        m.new_proxy("ssh", "tcp");
        m.add_traffic_in("web", "tcp", 10);
        let list = m.proxy_stats_list();
        assert_eq!(list.len(), 2);
        let web = list.iter().find(|p| p.name == "web").unwrap();
        assert_eq!(web.proxy_type, "tcp");
        assert_eq!(web.traffic_in, 10);
    }

    #[test]
    fn test_concurrent_traffic() {
        let m = Arc::new(MemBackend::new());
        m.new_proxy("test", "tcp");

        let barrier = Arc::new(Barrier::new(16));
        let mut handles = vec![];
        for _ in 0..16 {
            let m = m.clone();
            let b = barrier.clone();
            handles.push(thread::spawn(move || {
                b.wait();
                for _ in 0..1000 {
                    m.add_traffic_in("test", "tcp", 1);
                    m.add_traffic_out("test", "tcp", 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.server_stats().traffic_in, 16000);
        assert_eq!(m.server_stats().traffic_out, 16000);
    }
}
