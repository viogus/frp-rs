//! Go frp v0.72.0 `metricsServer` on the client: a listener for health checks,
//! metrics and (opt-in) profiling, kept separate from the admin API so a
//! monitoring sidecar needs neither admin credentials nor admin routes
//! (`pkg/util/http/metrics_server.go`).
//!
//! Build tier: behind the `admin` feature, the client's axum tier. A build
//! without it accepts the `[metricsServer]` section and warns that the port is
//! not served.
//!
//! Divergence, recorded: Go's frpc `metricsServer` exports **Go runtime**
//! metrics (`go_goroutines`, `go_memstats_*`, `process_*`). Rust has no
//! equivalent instrumentation, so `/metrics` here exposes the honest subset —
//! build info plus whatever the process can report without a metrics
//! dependency (`process_start_time_seconds`, `process_resident_memory_bytes`
//! where the OS exposes it). The pprof routes answer with the same placeholders
//! the server side and the dashboard use.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{http::StatusCode, Router};
use frp_core::admin_auth::apply_admin_auth;
use frp_core::config::MetricsServerConfig;
use tokio_util::sync::CancellationToken;

use crate::admin::TlsListener;

/// Unix seconds at first use — the process start time, captured lazily so it
/// does not need a global initialised before `main`.
fn process_start_time_seconds() -> u64 {
    use std::sync::LazyLock;
    use std::time::{SystemTime, UNIX_EPOCH};
    static START: LazyLock<u64> = LazyLock::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    *START
}

/// Resident set size in bytes, where the OS exposes it without a dependency.
fn resident_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/statm: field 2 is the resident page count.
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// `GET /healthz` — anonymous, like Go's (`health checks remain anonymous`).
async fn healthz() -> &'static str {
    "ok"
}

/// `GET /metrics` — Prometheus text exposition of the subset frp-rs can report.
async fn metrics(State(_state): State<Arc<()>>) -> String {
    let mut out = String::new();
    out.push_str("# HELP frpc_build_info Build information for this frpc.\n");
    out.push_str("# TYPE frpc_build_info gauge\n");
    out.push_str(&format!(
        "frpc_build_info{{version=\"{}\"}} 1\n",
        frp_core::VERSION
    ));
    out.push_str("# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n");
    out.push_str("# TYPE process_start_time_seconds gauge\n");
    out.push_str(&format!(
        "process_start_time_seconds {}\n",
        process_start_time_seconds()
    ));
    if let Some(rss) = resident_memory_bytes() {
        out.push_str("# HELP process_resident_memory_bytes Resident memory size in bytes.\n");
        out.push_str("# TYPE process_resident_memory_bytes gauge\n");
        out.push_str(&format!("process_resident_memory_bytes {rss}\n"));
    }
    out
}

async fn pprof_index() -> (StatusCode, &'static str) {
    (
        StatusCode::OK,
        "frp-rs does not expose Go-style pprof endpoints.",
    )
}

async fn pprof() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "pprof profiles are not available in frp-rs",
    )
}

/// Run the client metrics listener until `shutdown` fires.
pub async fn run(
    cfg: &MetricsServerConfig,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let authed = Router::new()
        .route("/metrics", get(metrics))
        .route("/debug/pprof", get(pprof_index))
        .route("/debug/pprof/{*path}", get(pprof))
        .with_state(Arc::new(()));
    let authed = apply_admin_auth(authed, &cfg.user, &cfg.password);
    let app = Router::new().route("/healthz", get(healthz)).merge(authed);

    let bind_addr = format!("{}:{}", cfg.addr, cfg.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    if !cfg.tls.cert_file.is_empty() {
        #[cfg(feature = "tls")]
        {
            let acceptor = frp_core::transport::build_tls_acceptor(
                &cfg.tls.cert_file,
                &cfg.tls.key_file,
                None,
            )?;
            tracing::info!(addr = %bind_addr, "frpc metrics server listening on {} (TLS)", bind_addr);
            axum::serve(TlsListener::new(listener, acceptor), app)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await?;
        }
        #[cfg(not(feature = "tls"))]
        {
            tracing::error!("TLS feature not enabled; cannot serve metricsServer with TLS");
            return Err("TLS feature not enabled".into());
        }
    } else {
        tracing::info!(addr = %bind_addr, "frpc metrics server listening on {}", bind_addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await?;
    }
    Ok(())
}
