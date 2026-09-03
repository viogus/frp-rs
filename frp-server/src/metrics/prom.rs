//! Prometheus metrics — mirrors Go frp v0.69.1 metric names exactly.
//! Rendered from live AppState + ProxyMetricsRegistry data on each /metrics scrape.
//! Same data source as the dashboard API (single metrics system).

use prometheus::{Encoder, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::LazyLock;

use crate::service::AppState;

/// Registry holding all 6 frp_server metrics.
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// --- 6 metrics matching Go frp v0.69.1 ---

/// frp_server_client_counts — current number of connected clients.
static CLIENT_COUNTS: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new(
        "frp_server_client_counts",
        "current client counts",
    ))
    .expect("metric definition must be valid")
});

/// frp_server_proxy_counts — current proxy count, labeled by type.
static PROXY_COUNTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new("frp_server_proxy_counts", "current proxy counts"),
        &["type"],
    )
    .expect("metric definition must be valid")
});

/// frp_server_proxy_counts_detailed — current proxy count, labeled by type and name.
static PROXY_COUNTS_DETAILED: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new("frp_server_proxy_counts_detailed", "current proxy counts"),
        &["type", "name"],
    )
    .expect("metric definition must be valid")
});

/// frp_server_connection_counts — current connection count per proxy.
static CONNECTION_COUNTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new("frp_server_connection_counts", "current connection counts"),
        &["name", "type"],
    )
    .expect("metric definition must be valid")
});

/// frp_server_traffic_in — total inbound traffic bytes per proxy (counter).
static TRAFFIC_IN: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new("frp_server_traffic_in", "total inbound traffic"),
        &["name", "type"],
    )
    .expect("metric definition must be valid")
});

/// frp_server_traffic_out — total outbound traffic bytes per proxy (counter).
static TRAFFIC_OUT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new("frp_server_traffic_out", "total outbound traffic"),
        &["name", "type"],
    )
    .expect("metric definition must be valid")
});

/// Traffic delta key: (proxy_name, proxy_type).
type TrafficKey = (String, String);
/// (bytes_in, bytes_out) cumulative pair.
type TrafficPair = (u64, u64);

/// Last-reported cumulative traffic per `(proxy_name, proxy_type)`.
/// Used to compute per-scrape deltas so Prometheus counters accumulate
/// monotonically (rate() in PromQL requires counters to never decrease).
///
/// Uses `tokio::sync::Mutex` because the guard must be held across `.await`
/// points inside `sync_from_state` — `std::sync::MutexGuard` is `!Send`
/// and would make the async future non-`Send`, breaking the axum handler.
static LAST_TRAFFIC: LazyLock<tokio::sync::Mutex<HashMap<TrafficKey, TrafficPair>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

// --- Pool metrics (new in frp-rs, no Go frp equivalent) ---

/// frp_server_pool_hits_total — lifetime work connection pool hits.
static POOL_HITS: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new(
        "frp_server_pool_hits_total",
        "lifetime work conn pool hits",
    ))
    .expect("metric definition must be valid")
});

/// frp_server_pool_misses_total — lifetime pool misses (pool empty, ReqWorkConn sent).
static POOL_MISSES: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new(
        "frp_server_pool_misses_total",
        "lifetime pool misses",
    ))
    .expect("metric definition must be valid")
});

/// frp_server_pool_drops_total — lifetime pool drops (pool full, conn discarded).
static POOL_DROPS: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new(
        "frp_server_pool_drops_total",
        "lifetime pool drops",
    ))
    .expect("metric definition must be valid")
});

/// frp_server_pool_size — current number of idle work connections across all clients.
static POOL_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new("frp_server_pool_size", "current idle work conns"))
        .expect("metric definition must be valid")
});

/// frp_server_pool_pending_requests — current pending requests waiting for work conns.
static POOL_PENDING: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new(
        "frp_server_pool_pending_requests",
        "current pending requests",
    ))
    .expect("metric definition must be valid")
});

/// Register all 11 metrics with the registry. Called once at startup.
/// Idempotent — safe to call multiple times (subsequent calls are no-ops).
pub fn register_all() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        REGISTRY.register(Box::new(CLIENT_COUNTS.clone())).ok();
        REGISTRY.register(Box::new(PROXY_COUNTS.clone())).ok();
        REGISTRY
            .register(Box::new(PROXY_COUNTS_DETAILED.clone()))
            .ok();
        REGISTRY.register(Box::new(CONNECTION_COUNTS.clone())).ok();
        REGISTRY.register(Box::new(TRAFFIC_IN.clone())).ok();
        REGISTRY.register(Box::new(TRAFFIC_OUT.clone())).ok();
        REGISTRY.register(Box::new(POOL_HITS.clone())).ok();
        REGISTRY.register(Box::new(POOL_MISSES.clone())).ok();
        REGISTRY.register(Box::new(POOL_DROPS.clone())).ok();
        REGISTRY.register(Box::new(POOL_SIZE.clone())).ok();
        REGISTRY.register(Box::new(POOL_PENDING.clone())).ok();
    });
}

/// Sync prometheus gauges from live AppState data.
/// Called on each /metrics scrape to refresh gauge values from the
/// single source of truth (ProxyMetricsRegistry + proxy_manager).
pub async fn sync_from_state(state: &AppState) {
    use std::collections::HashMap;

    // Client counts — from active control connections
    let client_count = state.run_id_to_ctl_tx.len() as i64;
    CLIENT_COUNTS.set(client_count);

    // Reset gauge-based label metrics before rebuilding.
    // Traffic counters are NOT reset — we compute per-scrape deltas to
    // preserve Prometheus counter monotonicity (rate() requires it).
    PROXY_COUNTS.reset();
    PROXY_COUNTS_DETAILED.reset();
    CONNECTION_COUNTS.reset();

    let proxies = state.proxy_manager.list().await;
    let mut type_counts: HashMap<String, i64> = HashMap::new();
    let mut last_traffic = LAST_TRAFFIC.lock().await;

    for p in &proxies {
        *type_counts.entry(p.proxy_type.clone()).or_default() += 1;

        let snap = state
            .proxy_metrics
            .get(&p.name)
            .await
            .map(|m| m.snapshot())
            .unwrap_or_else(|| frp_core::metrics::MetricsSnapshot {
                bytes_in: 0,
                bytes_out: 0,
                current_conns: 0,
                total_conns: 0,
            });

        let pt = &p.proxy_type;
        let pn = &p.name;

        PROXY_COUNTS_DETAILED.with_label_values(&[pt, pn]).set(1);
        CONNECTION_COUNTS
            .with_label_values(&[pn, pt])
            .set(snap.current_conns);

        // Delta-tracking: compute bytes since last scrape and inc_by(delta).
        // The original reset+inc_by(cumulative) gave correct point-in-time
        // values but broke Prometheus counter monotonicity — counters would
        // drop to 0 between scrapes, making rate() return garbage.
        let key = (pn.clone(), pt.clone());
        let (prev_in, prev_out) = last_traffic.remove(&key).unwrap_or((0, 0));
        let delta_in = snap.bytes_in.saturating_sub(prev_in);
        let delta_out = snap.bytes_out.saturating_sub(prev_out);
        if delta_in > 0 {
            TRAFFIC_IN.with_label_values(&[pn, pt]).inc_by(delta_in);
        }
        if delta_out > 0 {
            TRAFFIC_OUT.with_label_values(&[pn, pt]).inc_by(delta_out);
        }
        // Store cumulative values for the next scrape's delta calculation.
        if snap.bytes_in > 0 || snap.bytes_out > 0 {
            last_traffic.insert(key, (snap.bytes_in, snap.bytes_out));
        }
    }
    // Proxies absent from this scrape leave no trace: their baselines were
    // dropped at the removal sites (prom::proxy_removed, called alongside
    // ProxyMetricsRegistry::remove), so a same-name re-register computes
    // deltas from zero instead of stalling against the pre-removal total.

    for (pt, count) in &type_counts {
        PROXY_COUNTS.with_label_values(&[pt]).set(*count);
    }

    // Pool metrics — aggregate from AppState counters + per-client PoolStats
    POOL_HITS.set(i64::try_from(state.pool.hits.load(Ordering::Relaxed)).unwrap_or(i64::MAX));
    POOL_MISSES.set(i64::try_from(state.pool.misses.load(Ordering::Relaxed)).unwrap_or(i64::MAX));
    POOL_DROPS.set(i64::try_from(state.pool.drops.load(Ordering::Relaxed)).unwrap_or(i64::MAX));

    let total_pool_size: i64 = state
        .run_id_to_ctl_tx
        .iter()
        .map(|ctl| ctl.pool_stats.pool_size.load(Ordering::Relaxed))
        .sum();
    POOL_SIZE.set(total_pool_size);

    let total_pending: i64 = state
        .run_id_to_ctl_tx
        .iter()
        .map(|ctl| ctl.pool_stats.pending_requests.load(Ordering::Relaxed))
        .sum();
    POOL_PENDING.set(total_pending);
}

/// Render Prometheus text format from the frp registry.
/// Used by the axum /metrics handler.
pub fn render_metrics_text() -> String {
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    match encoder.encode(&metric_families, &mut buf) {
        Ok(()) => String::from_utf8_lossy(&buf).to_string(),
        Err(e) => {
            tracing::error!(error = %e, "Prometheus text encoding failed");
            String::new()
        }
    }
}

/// Drop the per-scrape delta baseline(s) for a removed proxy. Called at the
/// proxy-removal sites alongside `ProxyMetricsRegistry::remove`.
///
/// E1 scope (verified against Go frp v0.71.0): the traffic COUNTER label
/// children are intentionally KEPT — Go never deletes label values
/// (`CloseProxy` only `Dec()`s the gauges, metrics/server.go RemoveProxy), so
/// a same-name re-register (the normal client-reconnect path) must CONTINUE
/// the cumulative counter rather than restart it at 0; deleting the child
/// here would drop the Prometheus series on every reconnect. The stale
/// `LAST_TRAFFIC` baseline is the actual defect: after a proxy is removed and
/// re-registered under the same name, the old baseline suppresses deltas
/// until the new registration's cumulative bytes overtake the pre-removal
/// total — undercounting every byte the new registration carries.
pub async fn proxy_removed(name: &str) {
    LAST_TRAFFIC
        .lock()
        .await
        .retain(|(proxy_name, _), _| proxy_name != name);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The metric statics (REGISTRY / PROXY_COUNTS* / TRAFFIC* /
    /// LAST_TRAFFIC) are process-global, so tests that sync and render
    /// concurrently would reset or observe each other's label children
    /// (sync_from_state resets the gauge vecs on every scrape). Serialize
    /// every test in this module behind one lock.
    static PROM_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
        LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[tokio::test]
    async fn test_all_metrics_registered() {
        let _guard = PROM_TEST_LOCK.lock().await;
        register_all();
        // Verify that register_all() is idempotent (doesn't panic on second call).
        register_all();
        // Verify at least the text render works.
        let text = render_metrics_text();
        assert!(!text.is_empty(), "metrics text should not be empty");
    }

    #[tokio::test]
    async fn test_render_text_format() {
        let _guard = PROM_TEST_LOCK.lock().await;
        register_all();
        // Touch a gauge label so it appears in render output
        PROXY_COUNTS.with_label_values(&["__fmt_test"]).set(1);
        PROXY_COUNTS_DETAILED
            .with_label_values(&["__fmt_test", "__fmt_proxy"])
            .set(1);
        TRAFFIC_IN
            .with_label_values(&["__fmt_proxy", "__fmt_test"])
            .inc_by(0);
        TRAFFIC_OUT
            .with_label_values(&["__fmt_proxy", "__fmt_test"])
            .inc_by(0);
        CONNECTION_COUNTS
            .with_label_values(&["__fmt_proxy", "__fmt_test"])
            .set(0);
        let text = render_metrics_text();
        // HEADER line present for gauge (always renders)
        assert!(text.contains("TYPE frp_server_client_counts gauge"));
        assert!(text.contains("TYPE frp_server_traffic_in counter"));
        // Pool metrics should appear even without touching them (they're plain IntGauges)
        assert!(text.contains("frp_server_pool_hits_total"));
        assert!(text.contains("frp_server_pool_misses_total"));
        assert!(text.contains("frp_server_pool_drops_total"));
        assert!(text.contains("frp_server_pool_size"));
        assert!(text.contains("frp_server_pool_pending_requests"));
        // Cleanup
        PROXY_COUNTS.reset();
        PROXY_COUNTS_DETAILED.reset();
        TRAFFIC_IN.reset();
        TRAFFIC_OUT.reset();
        CONNECTION_COUNTS.reset();
    }

    use crate::control::proxy_ops::unregister_generation_tests::{proxy_info, test_state};

    /// Fabricate an AppState with one registered `tcp` proxy carrying
    /// `in`/`out` cumulative bytes in its metrics registry entry.
    async fn state_with_proxy(
        name: &str,
        bytes_in: u64,
        bytes_out: u64,
    ) -> std::sync::Arc<AppState> {
        let state = test_state();
        state
            .proxy_manager
            .register("run-1".into(), proxy_info(name, "tcp", "run-1", None, 1))
            .await
            .expect("register proxy");
        let m = state.proxy_metrics.get_or_create(name).await;
        m.record_traffic(bytes_in, bytes_out);
        state
    }

    /// T6: the /metrics data path — sync_from_state over a real AppState
    /// (proxy_manager + ProxyMetricsRegistry) must populate the gauges and
    /// feed the traffic counters the per-scrape deltas (monotonic totals in
    /// the rendered text). None of the pre-existing prom tests exercised
    /// sync_from_state; the delta logic was only hand-replayed.
    #[tokio::test]
    async fn test_sync_from_state_delta_and_render() {
        let _guard = PROM_TEST_LOCK.lock().await;
        register_all();
        let state = test_state();
        // Empty state: gauges render zeroed.
        sync_from_state(&state).await;
        let text = render_metrics_text();
        assert!(
            text.contains("frp_server_client_counts 0"),
            "client gauge should render after an empty sync"
        );

        // Scrape 1: cumulative (100, 50) → deltas (100, 50).
        let pname = "t6-sync-p1";
        let state = state_with_proxy(pname, 100, 50).await;
        sync_from_state(&state).await;
        let text = render_metrics_text();
        assert!(
            text.contains(&format!(
                "frp_server_traffic_in{{name=\"{pname}\",type=\"tcp\"}} 100"
            )),
            "scrape 1 traffic_in missing from render:\n{text}"
        );
        assert!(
            text.contains(&format!(
                "frp_server_traffic_out{{name=\"{pname}\",type=\"tcp\"}} 50"
            )),
            "scrape 1 traffic_out missing from render:\n{text}"
        );
        // TextEncoder sorts label names alphabetically: {name=...,type=...}
        // even though the vec declares ["type", "name"].
        assert!(
            text.contains(&format!(
                "frp_server_proxy_counts_detailed{{name=\"{pname}\",type=\"tcp\"}} 1"
            )),
            "detailed gauge missing from render:\n{text}"
        );
        assert!(
            text.contains("frp_server_proxy_counts{type=\"tcp\"} 1"),
            "type gauge missing from render:\n{text}"
        );

        // Scrape 2: cumulative grows to (250, 120) → deltas (150, 70); the
        // rendered counters must be the cumulative totals (monotonic).
        state
            .proxy_metrics
            .get_or_create(pname)
            .await
            .record_traffic(150, 70);
        sync_from_state(&state).await;
        let text = render_metrics_text();
        assert!(
            text.contains(&format!(
                "frp_server_traffic_in{{name=\"{pname}\",type=\"tcp\"}} 250"
            )),
            "scrape 2 traffic_in must accumulate to the cumulative total:\n{text}"
        );
        assert!(
            text.contains(&format!(
                "frp_server_traffic_out{{name=\"{pname}\",type=\"tcp\"}} 120"
            )),
            "scrape 2 traffic_out must accumulate to the cumulative total:\n{text}"
        );

        // Cleanup this test's registry + baseline so parallel tests are not
        // affected by the shared statics.
        state.proxy_manager.remove(pname).await;
        state.proxy_metrics.remove(pname).await;
        proxy_removed(pname).await;
    }

    /// E1: after a proxy is removed and re-registered under the same name
    /// (the normal client-reconnect path), the traffic counters must
    /// CONTINUE accumulating — the delta machinery must not stall against
    /// the pre-removal baseline. The removal sites call `proxy_removed` to
    /// drop the stale baseline; the counter children themselves are kept
    /// (Go v0.71.0 never deletes label values — CloseProxy only Dec()s the
    /// gauges), so re-registration continues the same series.
    #[tokio::test]
    async fn test_sync_re_registered_proxy_continues_counter() {
        let _guard = PROM_TEST_LOCK.lock().await;
        register_all();
        let pname = "t6-e1-rereg";
        // Registration #1: cumulative 100 → rendered 100.
        let state = state_with_proxy(pname, 100, 0).await;
        sync_from_state(&state).await;
        let text = render_metrics_text();
        assert!(
            text.contains(&format!(
                "frp_server_traffic_in{{name=\"{pname}\",type=\"tcp\"}} 100"
            )),
            "registration #1 traffic must render:\n{text}"
        );

        // Proxy removed (mirrors the hook sequence at the CloseProxy /
        // control-sweep / dashboard-delete / prune removal sites).
        state.proxy_manager.remove(pname).await;
        state.proxy_metrics.remove(pname).await;
        proxy_removed(pname).await;

        // Registration #2 (same name, fresh registry entry): cumulative 40
        // from zero. With the stale baseline dropped, the delta is 40 and
        // the counter continues to 140 — without `proxy_removed` the stale
        // baseline (100) suppresses the delta and the counter stalls at 100.
        let state = state_with_proxy(pname, 40, 0).await;
        sync_from_state(&state).await;
        let text = render_metrics_text();
        assert!(
            text.contains(&format!(
                "frp_server_traffic_in{{name=\"{pname}\",type=\"tcp\"}} 140"
            )),
            "re-registered proxy must CONTINUE the cumulative counter (stale \
             baseline suppressed the delta?):\n{text}"
        );

        state.proxy_manager.remove(pname).await;
        state.proxy_metrics.remove(pname).await;
        proxy_removed(pname).await;
    }

    #[tokio::test]
    async fn test_delta_tracking_no_reset() {
        let _guard = PROM_TEST_LOCK.lock().await;
        register_all();

        // Simulate two sequential scrapes:
        // Scrape 1: cumulative in=100, out=50 → delta in=100, out=50
        // Scrape 2: cumulative in=250, out=120 → delta in=150, out=70
        // After both scrapes, counter should be 100+150=250 in, 50+70=120 out
        {
            let mut lt = LAST_TRAFFIC.lock().await;
            // Scrape 1: first visit → no previous record, delta = cumulative
            let key = ("delta_test".to_string(), "tcp".to_string());
            let (prev_in, prev_out) = lt.remove(&key).unwrap_or((0, 0));
            assert_eq!((prev_in, prev_out), (0, 0));
            let delta_in = 100u64.saturating_sub(prev_in);
            let delta_out = 50u64.saturating_sub(prev_out);
            assert_eq!((delta_in, delta_out), (100, 50));
            lt.insert(key.clone(), (100, 50));
        }
        // Scrape 2: cumulative increased
        {
            let mut lt = LAST_TRAFFIC.lock().await;
            let key = ("delta_test".to_string(), "tcp".to_string());
            let (prev_in, prev_out) = lt.remove(&key).unwrap_or((0, 0));
            assert_eq!((prev_in, prev_out), (100, 50));
            let delta_in = 250u64.saturating_sub(prev_in);
            let delta_out = 120u64.saturating_sub(prev_out);
            assert_eq!((delta_in, delta_out), (150, 70));
            lt.insert(key, (250, 120));
        }

        // Cleanup
        LAST_TRAFFIC.lock().await.clear();
    }
}
