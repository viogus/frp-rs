//! Metrics module — mirrors Go frp's pkg/metrics/ architecture.
//!
//! `ServerMetrics` trait with aggregate dispatcher fans out to:
//! - `mem` backend: in-memory store, powers the dashboard API
//! - `prom` backend: Prometheus metrics registry, powers the /metrics endpoint

pub mod types;

pub mod mem;

pub mod prom;

use std::sync::{Arc, RwLock};

/// Metrics interface — mirrors Go frp's pkg/metrics/metrics.go `ServerMetrics`.
pub trait ServerMetrics: Send + Sync {
    fn new_client(&self);
    fn close_client(&self);
    fn new_proxy(&self, name: &str, proxy_type: &str);
    fn close_proxy(&self, name: &str, proxy_type: &str);
    fn open_connection(&self, name: &str, proxy_type: &str);
    fn close_connection(&self, name: &str, proxy_type: &str);
    fn add_traffic_in(&self, name: &str, proxy_type: &str, bytes: u64);
    fn add_traffic_out(&self, name: &str, proxy_type: &str, bytes: u64);
}

/// Aggregate dispatcher — fans out every call to all registered backends.
/// Mirrors Go frp's pkg/metrics/aggregate/server.go.
pub struct ServerMetricsAggregate {
    backends: RwLock<Vec<Arc<dyn ServerMetrics>>>,
    mem_backend: Arc<mem::MemBackend>,
}

impl ServerMetricsAggregate {
    pub fn new() -> Self {
        let mem = Arc::new(mem::MemBackend::new());
        Self {
            backends: RwLock::new(vec![mem.clone() as Arc<dyn ServerMetrics>]),
            mem_backend: mem,
        }
    }

    pub fn add_backend(&self, backend: Arc<dyn ServerMetrics>) {
        self.backends.write().unwrap().push(backend);
    }

    /// Access the in-memory backend for dashboard queries.
    pub fn mem_backend(&self) -> &Arc<mem::MemBackend> {
        &self.mem_backend
    }

    /// Number of registered backends.
    pub fn backend_count(&self) -> usize {
        self.backends.read().unwrap().len()
    }
}

impl ServerMetrics for ServerMetricsAggregate {
    fn new_client(&self) {
        for b in self.backends.read().unwrap().iter() {
            b.new_client();
        }
    }

    fn close_client(&self) {
        for b in self.backends.read().unwrap().iter() {
            b.close_client();
        }
    }

    fn new_proxy(&self, name: &str, proxy_type: &str) {
        for b in self.backends.read().unwrap().iter() {
            b.new_proxy(name, proxy_type);
        }
    }

    fn close_proxy(&self, name: &str, proxy_type: &str) {
        for b in self.backends.read().unwrap().iter() {
            b.close_proxy(name, proxy_type);
        }
    }

    fn open_connection(&self, name: &str, proxy_type: &str) {
        for b in self.backends.read().unwrap().iter() {
            b.open_connection(name, proxy_type);
        }
    }

    fn close_connection(&self, name: &str, proxy_type: &str) {
        for b in self.backends.read().unwrap().iter() {
            b.close_connection(name, proxy_type);
        }
    }

    fn add_traffic_in(&self, name: &str, proxy_type: &str, bytes: u64) {
        for b in self.backends.read().unwrap().iter() {
            b.add_traffic_in(name, proxy_type, bytes);
        }
    }

    fn add_traffic_out(&self, name: &str, proxy_type: &str, bytes: u64) {
        for b in self.backends.read().unwrap().iter() {
            b.add_traffic_out(name, proxy_type, bytes);
        }
    }
}

impl Default for ServerMetricsAggregate {
    fn default() -> Self {
        Self::new()
    }
}

