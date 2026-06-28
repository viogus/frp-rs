//! Prometheus metrics — mirrors Go frp v0.69.1 metric names exactly.
//! Rendered from live AppState + ProxyMetricsRegistry data on each /metrics scrape.
//! Same data source as the dashboard API (single metrics system).

use prometheus::{Encoder, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};
use std::sync::LazyLock;

use crate::service::AppState;

/// Registry holding all 6 frp_server metrics.
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// --- 6 metrics matching Go frp v0.69.1 ---

/// frp_server_client_counts — current number of connected clients.
static CLIENT_COUNTS: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new("frp_server_client_counts", "current client counts"))
        .expect("metric definition must be valid")
});

/// frp_server_proxy_counts — current proxy count, labeled by type.
static PROXY_COUNTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(Opts::new("frp_server_proxy_counts", "current proxy counts"), &["type"])
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

/// frp_server_traffic_in — total inbound traffic bytes per proxy.
static TRAFFIC_IN: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new("frp_server_traffic_in", "total inbound traffic"),
        &["name", "type"],
    )
    .expect("metric definition must be valid")
});

/// frp_server_traffic_out — total outbound traffic bytes per proxy.
static TRAFFIC_OUT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new("frp_server_traffic_out", "total outbound traffic"),
        &["name", "type"],
    )
    .expect("metric definition must be valid")
});

/// Register all 6 metrics with the registry. Called once at startup.
/// Idempotent — safe to call multiple times (subsequent calls are no-ops).
pub fn register_all() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        REGISTRY.register(Box::new(CLIENT_COUNTS.clone())).ok();
        REGISTRY.register(Box::new(PROXY_COUNTS.clone())).ok();
        REGISTRY.register(Box::new(PROXY_COUNTS_DETAILED.clone())).ok();
        REGISTRY.register(Box::new(CONNECTION_COUNTS.clone())).ok();
        REGISTRY.register(Box::new(TRAFFIC_IN.clone())).ok();
        REGISTRY.register(Box::new(TRAFFIC_OUT.clone())).ok();
    });
}

/// Sync prometheus gauges from live AppState data.
/// Called on each /metrics scrape to refresh gauge values from the
/// single source of truth (ProxyMetricsRegistry + proxy_manager).
pub async fn sync_from_state(state: &AppState) {
    use std::collections::HashMap;

    // Client counts — from active control connections
    let client_count = state.run_id_to_ctl_tx.read().await.len() as i64;
    CLIENT_COUNTS.set(client_count);

    // Reset all label-based metrics before rebuilding
    PROXY_COUNTS.reset();
    PROXY_COUNTS_DETAILED.reset();
    CONNECTION_COUNTS.reset();
    TRAFFIC_IN.reset();
    TRAFFIC_OUT.reset();

    let proxies = state.proxy_manager.list().await;
    let mut type_counts: HashMap<String, i64> = HashMap::new();

    for p in &proxies {
        *type_counts.entry(p.proxy_type.clone()).or_default() += 1;

        let snap = state.proxy_metrics.get(&p.name).await
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
        CONNECTION_COUNTS.with_label_values(&[pn, pt]).set(snap.current_conns);
        TRAFFIC_IN.with_label_values(&[pn, pt]).set(snap.bytes_in as i64);
        TRAFFIC_OUT.with_label_values(&[pn, pt]).set(snap.bytes_out as i64);
    }

    for (pt, count) in &type_counts {
        PROXY_COUNTS.with_label_values(&[pt]).set(*count);
    }
}

/// Render Prometheus text format from the frp registry.
/// Used by the axum /metrics handler.
pub fn render_metrics_text() -> String {
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    encoder
        .encode(&metric_families, &mut buf)
        .map(|_| String::from_utf8_lossy(&buf).to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_metrics_registered() {
        register_all();
        // Verify that register_all() is idempotent (doesn't panic on second call).
        register_all();
        // Verify at least the text render works.
        let text = render_metrics_text();
        assert!(!text.is_empty(), "metrics text should not be empty");
    }

    #[test]
    fn test_render_text_format() {
        register_all();
        // Touch a gauge label so it appears in render output
        PROXY_COUNTS.with_label_values(&["__fmt_test"]).set(1);
        PROXY_COUNTS_DETAILED.with_label_values(&["__fmt_test", "__fmt_proxy"]).set(1);
        TRAFFIC_IN.with_label_values(&["__fmt_proxy", "__fmt_test"]).set(0);
        TRAFFIC_OUT.with_label_values(&["__fmt_proxy", "__fmt_test"]).set(0);
        CONNECTION_COUNTS.with_label_values(&["__fmt_proxy", "__fmt_test"]).set(0);
        let text = render_metrics_text();
        // HEADER line present for gauge (always renders)
        assert!(text.contains("TYPE frp_server_client_counts gauge"));
        assert!(text.contains("TYPE frp_server_traffic_in gauge"));
        // Cleanup
        PROXY_COUNTS.reset();
        PROXY_COUNTS_DETAILED.reset();
        TRAFFIC_IN.reset();
        TRAFFIC_OUT.reset();
        CONNECTION_COUNTS.reset();
    }
}
