//! Metrics module — single unified metrics system.
//!
//! `frp_core::metrics::ProxyMetricsRegistry` is the single source of truth
//! for per-proxy traffic and connection counters. Both the dashboard API
//! and the Prometheus /metrics endpoint read from the same data.
//!
//! The `prom` module renders Prometheus text format on each scrape by
//! syncing gauge values from the live AppState + ProxyMetricsRegistry.

pub mod prom;
