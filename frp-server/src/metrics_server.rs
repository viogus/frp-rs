//! Go frp v0.72.0 `metricsServer`: a listener dedicated to health checks,
//! metrics and (opt-in) profiling, deliberately separate from the dashboard so a
//! monitoring sidecar can reach `/healthz` and `/metrics` without dashboard
//! access (`pkg/util/http/metrics_server.go`).
//!
//! Build tier: this lives behind the `dashboard` feature, which is the tier that
//! already carries axum and the Prometheus registry. A build without it accepts
//! the `[metricsServer]` section and warns that the port is not served (the same
//! contract the other reader-gated listener ports have); Go has no such tier.
//!
//! Divergences, both recorded: `/metrics` here is the same six Go-aligned frps
//! metrics the dashboard serves (Go's `metricsServer` renders them without
//! `enablePrometheus`, and so does this listener), and the pprof routes answer
//! with the dashboard's "Go-style pprof is not available" placeholders — Go's
//! pprof serves goroutine/heap profiles with no Rust equivalent.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{http::StatusCode, Router};
use frp_core::admin_auth::apply_admin_auth;
use frp_core::config::MetricsServerConfig;
use tokio_util::sync::CancellationToken;

use crate::dashboard::{NoDelayListener, TlsListener};
use crate::service::AppState;

/// `GET /healthz` — anonymous by design: Go keeps health checks reachable
/// without credentials so an orchestrator probe needs no secrets.
async fn healthz() -> &'static str {
    "ok"
}

/// `GET /metrics` — the same live renderer the dashboard uses (sync from state,
/// then Prometheus text).
async fn metrics(State(state): State<Arc<AppState>>) -> String {
    crate::metrics::prom::sync_from_state(&state).await;
    crate::metrics::prom::render_metrics_text()
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

/// Run the listener until `shutdown` fires.
pub async fn run(
    cfg: &MetricsServerConfig,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = format!("{}:{}", cfg.addr, cfg.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    run_with_listener(cfg, state, shutdown, listener).await
}

/// [`run`] on an already-bound listener: the tests bind `127.0.0.1:0` so they
/// can assert the routes without racing for a fixed port.
pub async fn run_with_listener(
    cfg: &MetricsServerConfig,
    state: Arc<AppState>,
    shutdown: CancellationToken,
    listener: tokio::net::TcpListener,
) -> Result<(), Box<dyn std::error::Error>> {
    // Go's frps `metricsServer` serves the business metrics without
    // `enablePrometheus`; `register_all` is a `Once`, so this is idempotent with
    // the dashboard's own registration.
    crate::metrics::prom::register_all();
    let authed = Router::new()
        .route("/metrics", get(metrics))
        .route("/debug/pprof", get(pprof_index))
        .route("/debug/pprof/{*path}", get(pprof))
        .with_state(state);
    // Go's auth middleware wraps `/metrics` and the profiling routes only;
    // `/healthz` is mounted outside it, exactly as in `NewMetricsServer`.
    let authed = apply_admin_auth(authed, &cfg.user, &cfg.password);
    let app = Router::new().route("/healthz", get(healthz)).merge(authed);

    let bind_addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("{}:{}", cfg.addr, cfg.port));

    if !cfg.tls.cert_file.is_empty() {
        #[cfg(feature = "tls")]
        {
            let acceptor = frp_core::transport::build_tls_acceptor(
                &cfg.tls.cert_file,
                &cfg.tls.key_file,
                None,
            )?;
            tracing::info!(addr = %bind_addr, "Metrics server listening on {} (TLS)", bind_addr);
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
        tracing::info!(addr = %bind_addr, "Metrics server listening on {}", bind_addr);
        axum::serve(NoDelayListener { inner: listener }, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::proxy_ops::unregister_generation_tests::test_state;

    /// Raw HTTP/1.1 GET: the metrics listener must not need a client crate.
    async fn get(addr: std::net::SocketAddr, path: &str, auth: Option<&str>) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let auth_header = match auth {
            Some(creds) => format!("Authorization: Basic {creds}\r\n"),
            None => String::new(),
        };
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth_header}\r\n"
        );
        conn.write_all(req.as_bytes()).await.expect("write");
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.expect("read");
        let text = String::from_utf8_lossy(&out).to_string();
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    fn b64_creds() -> String {
        // "monitor:s3cret" → standard base64 (the frp_core encoder).
        frp_core::base64::encode(b"monitor:s3cret")
    }

    /// Go's `NewMetricsServer` contract: `/healthz` anonymous, `/metrics` and
    /// the profiling routes behind the configured basic auth.
    #[tokio::test]
    async fn healthz_is_anonymous_and_metrics_requires_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = MetricsServerConfig {
            addr: "127.0.0.1".to_string(),
            port: addr.port(),
            user: "monitor".to_string(),
            password: "s3cret".to_string(),
            pprof_enable: true,
            ..Default::default()
        };
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                // The listener is cancelled below; an error here is a test
                // failure surfaced by the request assertions.
                let _ = run_with_listener(&cfg, test_state(), shutdown, listener).await;
            }
        });

        let (status, body) = get(addr, "/healthz", None).await;
        assert_eq!(status, 200, "healthz must be anonymous: {body}");

        let (status, _) = get(addr, "/metrics", None).await;
        assert_eq!(status, 401, "metrics must require auth");

        let (status, body) = get(addr, "/metrics", Some(&b64_creds())).await;
        assert_eq!(status, 200, "authenticated metrics: {body}");
        assert!(
            body.contains("frp_server_client_counts"),
            "the Go-aligned metrics must render: {body}"
        );

        // `/debug/pprof` is the index (200): the dashboard's documented
        // divergence is "pprof exists, Go profiles do not".
        let (status, body) = get(addr, "/debug/pprof", Some(&b64_creds())).await;
        assert_eq!(status, 200, "pprof index placeholder: {body}");
        assert!(body.contains("does not expose Go-style pprof"));
        let (status, _) = get(addr, "/debug/pprof/heap", Some(&b64_creds())).await;
        assert_eq!(status, 501, "pprof profiles answer 501");

        shutdown.cancel();
        let _ = handle.await;
    }
}
