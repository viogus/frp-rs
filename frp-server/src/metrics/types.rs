//! Shared types for metrics — mirrors Go frp's pkg/metrics/mem/types.go

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Snapshot of a proxy's current statistics.
#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub name: String,
    pub proxy_type: String,
    pub traffic_in: u64,
    pub traffic_out: u64,
    pub connections: i64,
}

/// Aggregate server-level statistics for the dashboard API.
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    pub client_count: i64,
    pub proxy_count: i64,
    pub connection_count: i64,
    pub traffic_in: u64,
    pub traffic_out: u64,
}

/// Per-proxy in-memory counters, used by the mem backend.
pub(crate) struct ProxyCounters {
    pub name: String,
    pub proxy_type: String,
    pub traffic_in: AtomicU64,
    pub traffic_out: AtomicU64,
    pub connections: AtomicI64,
    #[allow(dead_code)]
    pub created: Instant,
}

impl ProxyCounters {
    pub fn new(name: String, proxy_type: String) -> Self {
        Self {
            name,
            proxy_type,
            traffic_in: AtomicU64::new(0),
            traffic_out: AtomicU64::new(0),
            connections: AtomicI64::new(0),
            created: Instant::now(),
        }
    }

    pub fn snapshot(&self) -> ProxyStats {
        ProxyStats {
            name: self.name.clone(),
            proxy_type: self.proxy_type.clone(),
            traffic_in: self.traffic_in.load(Ordering::Relaxed),
            traffic_out: self.traffic_out.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
        }
    }
}
