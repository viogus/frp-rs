//! Prometheus backend — registers 6 metrics matching Go frp v0.69.1 exactly.
//! Mirrors Go frp's pkg/metrics/prometheus/server.go.

use prometheus::{
    Encoder, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};

use super::ServerMetrics;

lazy_static::lazy_static! {
    /// Registry holding all 6 frp_server metrics.
    static ref REGISTRY: Registry = Registry::new();

    // --- 6 metrics matching Go frp v0.69.1 ---

    /// frp_server_client_counts — current number of connected clients.
    static ref CLIENT_COUNTS: IntGauge =
        IntGauge::with_opts(Opts::new("frp_server_client_counts", "current client counts"))
            .expect("metric definition must be valid");

    /// frp_server_proxy_counts — current proxy count, labeled by type.
    static ref PROXY_COUNTS: IntGaugeVec =
        IntGaugeVec::new(Opts::new("frp_server_proxy_counts", "current proxy counts"), &["type"])
            .expect("metric definition must be valid");

    /// frp_server_proxy_counts_detailed — current proxy count, labeled by type and name.
    static ref PROXY_COUNTS_DETAILED: IntGaugeVec =
        IntGaugeVec::new(
            Opts::new("frp_server_proxy_counts_detailed", "current proxy counts"),
            &["type", "name"],
        )
        .expect("metric definition must be valid");

    /// frp_server_connection_counts — current connection count per proxy.
    static ref CONNECTION_COUNTS: IntGaugeVec =
        IntGaugeVec::new(
            Opts::new("frp_server_connection_counts", "current connection counts"),
            &["name", "type"],
        )
        .expect("metric definition must be valid");

    /// frp_server_traffic_in — total inbound traffic bytes per proxy.
    static ref TRAFFIC_IN: IntCounterVec =
        IntCounterVec::new(
            Opts::new("frp_server_traffic_in", "total inbound traffic"),
            &["name", "type"],
        )
        .expect("metric definition must be valid");

    /// frp_server_traffic_out — total outbound traffic bytes per proxy.
    static ref TRAFFIC_OUT: IntCounterVec =
        IntCounterVec::new(
            Opts::new("frp_server_traffic_out", "total outbound traffic"),
            &["name", "type"],
        )
        .expect("metric definition must be valid");
}

/// Register all 6 metrics with the registry. Called once at startup.
/// Idempotent — safe to call multiple times (subsequent calls are no-ops).
pub fn register_all() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        REGISTRY
            .register(Box::new(CLIENT_COUNTS.clone()))
            .expect("frp_server_client_counts must register once");
        REGISTRY
            .register(Box::new(PROXY_COUNTS.clone()))
            .expect("frp_server_proxy_counts must register once");
        REGISTRY
            .register(Box::new(PROXY_COUNTS_DETAILED.clone()))
            .expect("frp_server_proxy_counts_detailed must register once");
        REGISTRY
            .register(Box::new(CONNECTION_COUNTS.clone()))
            .expect("frp_server_connection_counts must register once");
        REGISTRY
            .register(Box::new(TRAFFIC_IN.clone()))
            .expect("frp_server_traffic_in must register once");
        REGISTRY
            .register(Box::new(TRAFFIC_OUT.clone()))
            .expect("frp_server_traffic_out must register once");
    });
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

/// Prometheus backend for the aggregate dispatcher.
#[derive(Clone, Default)]
pub struct PromBackend;

impl PromBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ServerMetrics for PromBackend {
    fn new_client(&self) {
        CLIENT_COUNTS.inc();
    }

    fn close_client(&self) {
        CLIENT_COUNTS.dec();
    }

    fn new_proxy(&self, name: &str, proxy_type: &str) {
        PROXY_COUNTS.with_label_values(&[proxy_type]).inc();
        PROXY_COUNTS_DETAILED
            .with_label_values(&[proxy_type, name])
            .inc();
    }

    fn close_proxy(&self, name: &str, proxy_type: &str) {
        PROXY_COUNTS.with_label_values(&[proxy_type]).dec();
        PROXY_COUNTS_DETAILED
            .with_label_values(&[proxy_type, name])
            .dec();
    }

    fn open_connection(&self, name: &str, proxy_type: &str) {
        CONNECTION_COUNTS
            .with_label_values(&[name, proxy_type])
            .inc();
    }

    fn close_connection(&self, name: &str, proxy_type: &str) {
        CONNECTION_COUNTS
            .with_label_values(&[name, proxy_type])
            .dec();
    }

    fn add_traffic_in(&self, name: &str, proxy_type: &str, bytes: u64) {
        TRAFFIC_IN
            .with_label_values(&[name, proxy_type])
            .inc_by(bytes);
    }

    fn add_traffic_out(&self, name: &str, proxy_type: &str, bytes: u64) {
        TRAFFIC_OUT
            .with_label_values(&[name, proxy_type])
            .inc_by(bytes);
    }
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
        // Touch a counter label so it appears in render output
        // (CounterVec without labels is omitted by prometheus crate).
        // Use unique proxy name to avoid cross-test pollution.
        let b = PromBackend::new();
        b.new_proxy("__fmt_test", "__fmt");
        b.add_traffic_in("__fmt_test", "__fmt", 0);
        b.add_traffic_out("__fmt_test", "__fmt", 0);
        let text = render_metrics_text();
        // HEADER line present for gauge (always renders)
        assert!(text.contains("TYPE frp_server_client_counts gauge"));
        // Counter renders now that label values exist
        assert!(text.contains("TYPE frp_server_traffic_in counter"));
        // Cleanup
        b.close_proxy("__fmt_test", "__fmt");
    }

    #[test]
    fn test_prom_backend_client_counts() {
        register_all();
        let b = PromBackend::new();
        b.new_client();
        b.new_client();
        assert_eq!(CLIENT_COUNTS.get(), 2);
        b.close_client();
        assert_eq!(CLIENT_COUNTS.get(), 1);
    }

    #[test]
    fn test_prom_backend_proxy_counts() {
        register_all();
        let b = PromBackend::new();
        // Use unique type names to avoid cross-test pollution
        b.new_proxy("web", "__pc_tcp");
        b.new_proxy("ssh", "__pc_tcp");
        b.new_proxy("api", "__pc_http");
        assert_eq!(PROXY_COUNTS.with_label_values(&["__pc_tcp"]).get(), 2);
        assert_eq!(PROXY_COUNTS.with_label_values(&["__pc_http"]).get(), 1);
        b.close_proxy("web", "__pc_tcp");
        assert_eq!(PROXY_COUNTS.with_label_values(&["__pc_tcp"]).get(), 1);
    }

    #[test]
    fn test_prom_backend_traffic() {
        register_all();
        let b = PromBackend::new();
        // Use unique type to avoid cross-test pollution
        b.add_traffic_in("traffic_web", "__traffic", 1024);
        b.add_traffic_out("traffic_web", "__traffic", 512);
        assert_eq!(TRAFFIC_IN.with_label_values(&["traffic_web", "__traffic"]).get(), 1024);
        assert_eq!(TRAFFIC_OUT.with_label_values(&["traffic_web", "__traffic"]).get(), 512);
    }
}
