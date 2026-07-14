use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::sync::Mutex;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Per-proxy traffic counters using atomics for lock-free reads.
pub struct ProxyMetrics {
    pub name: String,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub current_conns: AtomicI64,
    pub total_conns: AtomicU64,
    /// Per-day rolling traffic history (index 0 = today, 6 = 6 days ago).
    pub daily: TrafficHistory,
}

impl std::fmt::Debug for ProxyMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyMetrics")
            .field("name", &self.name)
            .field("bytes_in", &self.bytes_in)
            .field("bytes_out", &self.bytes_out)
            .field("current_conns", &self.current_conns)
            .field("total_conns", &self.total_conns)
            .finish_non_exhaustive()
    }
}

impl ProxyMetrics {
    pub fn new(name: String) -> Self {
        Self {
            name,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            current_conns: AtomicI64::new(0),
            total_conns: AtomicU64::new(0),
            daily: TrafficHistory::new(),
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

    /// Record traffic delta. Updates atomic counters and per-day history.
    pub fn record_traffic(&self, delta_in: u64, delta_out: u64) {
        self.bytes_in.fetch_add(delta_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(delta_out, Ordering::Relaxed);
        self.daily.record(delta_in, delta_out);
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MetricsSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub current_conns: i64,
    pub total_conns: u64,
}

// ── 7-day rolling traffic history ────────────────────────────────────

/// Per-day traffic ring buffer. Index 0 = today, 6 = 6 days ago.
/// Rotates automatically on day change. Go frp v0.70.0 compat.
pub struct TrafficHistory {
    state: Mutex<TrafficState>,
}

struct TrafficState {
    traffic_in: [u64; 7],
    traffic_out: [u64; 7],
    last_day: u32,
}

impl Default for TrafficHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficHistory {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(TrafficState {
                traffic_in: [0; 7],
                traffic_out: [0; 7],
                last_day: days_since_epoch(),
            }),
        }
    }

    pub fn record(&self, delta_in: u64, delta_out: u64) {
        let today = days_since_epoch();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if today != s.last_day {
            let shift = (today.wrapping_sub(s.last_day) as usize).min(7);
            for i in (shift..7).rev() {
                s.traffic_in[i] = s.traffic_in[i - shift];
                s.traffic_out[i] = s.traffic_out[i - shift];
            }
            for i in 0..shift {
                s.traffic_in[i] = 0;
                s.traffic_out[i] = 0;
            }
            s.last_day = today;
        }
        s.traffic_in[0] = s.traffic_in[0].saturating_add(delta_in);
        s.traffic_out[0] = s.traffic_out[0].saturating_add(delta_out);
    }

    /// Return (traffic_in[7], traffic_out[7]) where index 0 = today.
    pub fn snapshot(&self) -> ([u64; 7], [u64; 7]) {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (s.traffic_in, s.traffic_out)
    }
}

fn days_since_epoch() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as u32)
        .unwrap_or(0)
}

// ── Registry ─────────────────────────────────────────────────────────

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
        m.record_traffic(100, 200);
        let s = m.snapshot();
        assert_eq!(s.bytes_in, 100);
        assert_eq!(s.bytes_out, 200);
    }

    #[tokio::test]
    async fn test_registry_reuses_metrics() {
        let reg = ProxyMetricsRegistry::new();
        let m1 = reg.get_or_create("p1").await;
        m1.record_traffic(10, 0);
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

    #[test]
    fn test_traffic_history_initial() {
        let h = TrafficHistory::new();
        let (tin, tout) = h.snapshot();
        assert_eq!(tin, [0; 7]);
        assert_eq!(tout, [0; 7]);
    }

    #[test]
    fn test_traffic_history_record_today() {
        let h = TrafficHistory::new();
        h.record(100, 200);
        let (tin, tout) = h.snapshot();
        assert_eq!(tin[0], 100);
        assert_eq!(tout[0], 200);
        assert_eq!(tin[1], 0);
    }

    #[test]
    fn test_traffic_history_accumulates() {
        let h = TrafficHistory::new();
        h.record(10, 20);
        h.record(30, 40);
        let (tin, tout) = h.snapshot();
        assert_eq!(tin[0], 40);
        assert_eq!(tout[0], 60);
    }
}
