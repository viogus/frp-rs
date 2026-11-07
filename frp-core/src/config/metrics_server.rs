//! Go frp v0.72.0 `metricsServer` configuration (frps and frpc).
//!
//! Go's listener is a separate HTTP endpoint for health checks, metrics and
//! (opt-in) profiling, deliberately distinct from the dashboard/admin API so a
//! monitoring sidecar can reach `/healthz` and `/metrics` without dashboard
//! credentials: `pkg/config/v1/common.go:76-93` and
//! `pkg/util/http/metrics_server.go`.
//!
//! This module is the *config surface* shared by both binaries. The listener
//! itself lives in `frp-server/src/metrics_server.rs` (behind the `dashboard`
//! feature, which is the build tier that already carries the HTTP server and
//! the Prometheus registry) and `frp-client/src/metrics_server.rs` (behind
//! `admin`, its axum tier); a build without that tier accepts the section and
//! warns that the port is not served, the same way the other reader-gated
//! listener ports behave.

use serde::{Deserialize, Serialize};

fn default_metrics_server_addr() -> String {
    // Go: `MetricsServerConfig.Complete()` → `util.EmptyOr(Addr, "127.0.0.1")`
    // (`pkg/config/v1/common.go:91-93`). Monitoring defaults to loopback.
    "127.0.0.1".to_string()
}

/// Go frp v0.72.0 `metricsServer` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsServerConfig {
    /// Listen address. Default `127.0.0.1` (Go's `Complete()`).
    #[serde(default = "default_metrics_server_addr")]
    pub addr: String,
    /// Listen port. `0` disables the listener (Go: "disables the listener when
    /// set to 0").
    #[serde(default)]
    pub port: u16,
    /// Basic-auth user for `/metrics` and the profiling routes. `/healthz`
    /// stays anonymous (Go: "health checks remain anonymous").
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    /// Enable the profiling routes. frp-rs answers them with the same
    /// "Go-style pprof is not available" placeholders the dashboard uses: Go's
    /// pprof serves goroutine/heap profiles that have no Rust equivalent. A
    /// recorded divergence, not a silent no-op — the routes exist and answer.
    #[serde(default, alias = "pprofEnable")]
    pub pprof_enable: bool,
    /// TLS for this listener. Go models it as `*TLSConfig`: **presence** of the
    /// block enables TLS and then requires both files, so `tls = {}` is a
    /// config error rather than a silent plaintext listener.
    #[serde(default)]
    pub tls: Option<MetricsServerTlsConfig>,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            addr: default_metrics_server_addr(),
            port: 0,
            user: String::new(),
            password: String::new(),
            pprof_enable: false,
            tls: None,
        }
    }
}

/// Go frp v0.72.0 `metricsServer.tls` (a `*TLSConfig` in Go; the client-only
/// `useSystemCa` field is rejected by validation rather than dropped).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsServerTlsConfig {
    #[serde(default, alias = "certFile")]
    pub cert_file: String,
    #[serde(default, alias = "keyFile")]
    pub key_file: String,
    /// Accepted so the key is not silently swallowed; validation rejects it
    /// with Go's message (`pkg/config/v1/validation/common.go:44-46`).
    #[serde(default, alias = "useSystemCa")]
    pub use_system_ca: bool,
    /// Accepted for parity, **inert** — exactly as in Go: `newServer`
    /// (`pkg/util/http/server.go:61`) builds the listener's `tls.Config` from
    /// `CertFile`/`KeyFile` only, so a `trustedCaFile` here does not enable
    /// client-certificate verification on the metrics listener (that switch is
    /// the *transport* server's, `pkg/transport/tls.go:120-129`).
    #[serde(default, alias = "trustedCaFile")]
    pub trusted_ca_file: String,
    /// Accepted for parity, **inert** for the same reason: Go never sets
    /// `tls.Config.ServerName` on this listener, and a server-side `ServerName`
    /// has no effect in `crypto/tls` anyway.
    #[serde(default, alias = "serverName")]
    pub server_name: String,
}
