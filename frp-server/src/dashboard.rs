use std::sync::Arc;
use axum::{Router, Json, extract::{State, Path}, response::Html, routing::get};
use serde::Serialize;
use crate::service::AppState;
use frp_core::admin_auth::apply_admin_auth;
use frp_core::metrics::MetricsSnapshot;

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    uptime_secs: u64,
    client_count: usize,
    proxy_count: usize,
}

#[derive(Serialize)]
struct ProxyEntry {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    status: String,
    remote_port: Option<u16>,
    local_addr: Option<String>,
    traffic_in: u64,
    traffic_out: u64,
}

#[derive(Serialize)]
struct ProxyDetail {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    status: String,
    run_id: Option<String>,
    remote_port: Option<u16>,
    local_addr: Option<String>,
    use_encryption: bool,
    use_compression: bool,
    custom_domains: Vec<String>,
    multiplexer: String,
    group: String,
    traffic: MetricsSnapshot,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct ClientEntry {
    run_id: String,
    client_addr: Option<String>,
    online: bool,
    login_time_secs: u64,
    proxy_count: usize,
    proxies: Vec<String>,
}

#[derive(Serialize)]
struct ClientDetail {
    run_id: String,
    client_addr: Option<String>,
    online: bool,
    login_time_secs: u64,
    proxy_count: usize,
    proxies: Vec<ProxyEntry>,
}

// --- Handlers ---

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let uptime = state.dashboard_start.elapsed().as_secs();
    let client_count = state.run_id_to_ctl_tx.read().await.len();
    let proxies = state.proxy_manager.list().await;
    Json(StatusResponse {
        version: frp_core::VERSION.to_string(),
        uptime_secs: uptime,
        client_count,
        proxy_count: proxies.len(),
    })
}

async fn handle_proxies(State(state): State<Arc<AppState>>) -> Json<Vec<ProxyEntry>> {
    let proxies = state.proxy_manager.list().await;
    let mut entries = Vec::new();
    for p in &proxies {
        let online = state.run_id_to_ctl_tx.read().await.contains_key(&p.run_id);
        let traffic = state.proxy_metrics.get(&p.name).await
            .map(|m| m.snapshot())
            .unwrap_or_else(|| MetricsSnapshot {
                bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
            });
        entries.push(ProxyEntry {
            name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            status: if online { "online".into() } else { "offline".into() },
            remote_port: p.remote_port,
            local_addr: p.local_addr.clone(),
            traffic_in: traffic.bytes_in,
            traffic_out: traffic.bytes_out,
        });
    }
    Json(entries)
}

async fn handle_proxy_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy_manager.get(&name).await
        .ok_or_else(|| (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: "proxy not found".into() }),
        ))?;

    let online = state.run_id_to_ctl_tx.read().await.contains_key(&proxy.run_id);
    let traffic = state.proxy_metrics.get(&name).await
        .map(|m| m.snapshot())
        .unwrap_or_else(|| MetricsSnapshot {
            bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
        });

    Ok(Json(ProxyDetail {
        name: proxy.name.clone(),
        proxy_type: proxy.proxy_type.clone(),
        status: if online { "online".into() } else { "offline".into() },
        run_id: Some(proxy.run_id.clone()),
        remote_port: proxy.remote_port,
        local_addr: proxy.local_addr.clone(),
        use_encryption: proxy.use_encryption,
        use_compression: proxy.use_compression,
        custom_domains: Vec::new(),
        multiplexer: String::new(),
        group: proxy.group.unwrap_or_default(),
        traffic,
    }))
}

async fn handle_proxy_traffic(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<MetricsSnapshot>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    // Verify proxy exists
    let _proxy = state.proxy_manager.get(&name).await
        .ok_or_else(|| (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: "proxy not found".into() }),
        ))?;

    let traffic = state.proxy_metrics.get(&name).await
        .map(|m| m.snapshot())
        .unwrap_or_else(|| MetricsSnapshot {
            bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
        });

    Ok(Json(traffic))
}

async fn handle_clients(State(state): State<Arc<AppState>>) -> Json<Vec<ClientEntry>> {
    let map = state.run_id_to_ctl_tx.read().await;
    let mut clients = Vec::new();
    for (run_id, ctl) in map.iter() {
        let proxies = state.proxy_manager.list_client_proxy_names(run_id).await;
        clients.push(ClientEntry {
            run_id: run_id.clone(),
            client_addr: ctl.client_addr.map(|a| a.to_string()),
            online: true,
            login_time_secs: ctl.login_time.elapsed().as_secs(),
            proxy_count: proxies.len(),
            proxies,
        });
    }
    Json(clients)
}

async fn handle_client_detail(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<ClientDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let ctl = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    }.ok_or_else(|| (
        axum::http::StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: "client not found".into() }),
    ))?;

    let proxy_infos = state.proxy_manager.list_client(&run_id).await;
    let mut proxies = Vec::new();
    for p in &proxy_infos {
        let traffic = state.proxy_metrics.get(&p.name).await
            .map(|m| m.snapshot())
            .unwrap_or_else(|| MetricsSnapshot {
                bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
            });
        proxies.push(ProxyEntry {
            name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            status: "online".into(),
            remote_port: p.remote_port,
            local_addr: p.local_addr.clone(),
            traffic_in: traffic.bytes_in,
            traffic_out: traffic.bytes_out,
        });
    }

    Ok(Json(ClientDetail {
        run_id: run_id.clone(),
        client_addr: ctl.client_addr.map(|a| a.to_string()),
        online: true,
        login_time_secs: ctl.login_time.elapsed().as_secs(),
        proxy_count: proxies.len(),
        proxies,
    }))
}

async fn handle_root() -> Html<String> {
    Html(include_str!("dashboard.html").replace("{version}", frp_core::VERSION))
}

async fn handle_healthz() -> &'static str {
    "ok"
}

pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // API routes (auth-protected)
    let api_routes = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/proxies", get(handle_proxies))
        .route("/api/proxy/:name", get(handle_proxy_detail))
        .route("/api/proxy/:name/traffic", get(handle_proxy_traffic))
        .route("/api/clients", get(handle_clients))
        .route("/api/clients/:run_id", get(handle_client_detail));

    let api_routes = apply_admin_auth(api_routes, &auth_user, &auth_password);

    // /metrics is public (Prometheus scrapers don't use Basic Auth).
    // Syncs gauge values from the live ProxyMetricsRegistry on each scrape.
    let state_for_metrics = state.clone();
    let metrics_route = Router::new()
        .route("/metrics", get(move || {
            let state = state_for_metrics.clone();
            async move {
                crate::metrics::prom::sync_from_state(&state).await;
                crate::metrics::prom::render_metrics_text()
            }
        }));

    let app = Router::new()
        .route("/", get(handle_root))
        .route("/healthz", get(handle_healthz))
        .merge(api_routes)
        .merge(metrics_route)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
