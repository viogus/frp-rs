use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Per-proxy traffic counters using atomics for lock-free reads.
#[derive(Debug)]
pub struct ProxyMetrics {
    pub name: String,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub current_conns: AtomicI64,
    pub total_conns: AtomicU64,
}

impl ProxyMetrics {
    pub fn new(name: String) -> Self {
        Self {
            name,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            current_conns: AtomicI64::new(0),
            total_conns: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            current_conns: self.current_conns.load(Ordering::Relaxed),
            total_conns: self.total_conns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub current_conns: i64,
    pub total_conns: u64,
}

#[derive(Debug, Default)]
pub struct ProxyMetricsRegistry {
    metrics: RwLock<HashMap<String, Arc<ProxyMetrics>>>,
}

impl ProxyMetricsRegistry {
    pub fn new() -> Self {
        Self { metrics: RwLock::new(HashMap::new()) }
    }

    pub async fn get_or_create(&self, name: &str) -> Arc<ProxyMetrics> {
        let mut map = self.metrics.write().await;
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(ProxyMetrics::new(name.to_string())))
            .clone()
    }

    pub async fn get(&self, name: &str) -> Option<Arc<ProxyMetrics>> {
        self.metrics.read().await.get(name).cloned()
    }

    pub async fn remove(&self, name: &str) {
        self.metrics.write().await.remove(name);
    }
}

/// Connection guard: +1 current_conns + total_conns on creation,
/// -1 current_conns on drop.
pub struct ConnGuard {
    metrics: Arc<ProxyMetrics>,
}

impl ConnGuard {
    pub fn new(metrics: Arc<ProxyMetrics>) -> Self {
        metrics.current_conns.fetch_add(1, Ordering::Relaxed);
        metrics.total_conns.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_counts() {
        let m = ProxyMetrics::new("t".into());
        m.bytes_in.fetch_add(100, Ordering::Relaxed);
        m.bytes_out.fetch_add(200, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.bytes_in, 100);
        assert_eq!(s.bytes_out, 200);
    }

    #[tokio::test]
    async fn test_registry_reuses_metrics() {
        let reg = ProxyMetricsRegistry::new();
        let m1 = reg.get_or_create("p1").await;
        m1.bytes_in.fetch_add(10, Ordering::Relaxed);
        let m2 = reg.get_or_create("p1").await;
        assert_eq!(m2.snapshot().bytes_in, 10);
    }

    #[tokio::test]
    async fn test_registry_remove() {
        let reg = ProxyMetricsRegistry::new();
        reg.get_or_create("p1").await;
        assert!(reg.get("p1").await.is_some());
        reg.remove("p1").await;
        assert!(reg.get("p1").await.is_none());
    }

    #[test]
    fn test_conn_guard_lifecycle() {
        let m = Arc::new(ProxyMetrics::new("g".into()));
        assert_eq!(m.snapshot().current_conns, 0);
        {
            let _g = ConnGuard::new(m.clone());
            assert_eq!(m.snapshot().current_conns, 1);
            assert_eq!(m.snapshot().total_conns, 1);
        }
        assert_eq!(m.snapshot().current_conns, 0);
        assert_eq!(m.snapshot().total_conns, 1);
    }
}
