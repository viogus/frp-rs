use std::sync::atomic::Ordering;
use frp_core::metrics::{ProxyMetricsRegistry, ConnGuard};

#[tokio::test]
async fn test_metrics_snapshot_after_counting() {
    let reg = ProxyMetricsRegistry::new();
    let m = reg.get_or_create("ssh").await;
    m.bytes_in.fetch_add(1024, Ordering::Relaxed);
    m.bytes_out.fetch_add(512, Ordering::Relaxed);
    {
        let _g = ConnGuard::new(m.clone());
        assert_eq!(m.snapshot().current_conns, 1);
        assert_eq!(m.snapshot().total_conns, 1);
    }
    let snap = m.snapshot();
    assert_eq!(snap.bytes_in, 1024);
    assert_eq!(snap.bytes_out, 512);
    assert_eq!(snap.current_conns, 0);
    assert_eq!(snap.total_conns, 1);
}

#[tokio::test]
async fn test_registry_multiple_proxies_independent() {
    let reg = ProxyMetricsRegistry::new();
    reg.get_or_create("p1").await;
    reg.get_or_create("p2").await;
    assert!(reg.get("p1").await.is_some());
    assert!(reg.get("p2").await.is_some());
    reg.remove("p1").await;
    assert!(reg.get("p1").await.is_none());
    assert!(reg.get("p2").await.is_some());
}

#[tokio::test]
async fn test_registry_remove_nonexistent_no_panic() {
    let reg = ProxyMetricsRegistry::new();
    reg.remove("no_such_proxy").await; // should not panic
}

#[test]
fn test_metrics_snapshot_defaults_zero() {
    let m = frp_core::metrics::ProxyMetrics::new("test".into());
    let s = m.snapshot();
    assert_eq!(s.bytes_in, 0);
    assert_eq!(s.bytes_out, 0);
    assert_eq!(s.current_conns, 0);
    assert_eq!(s.total_conns, 0);
}
