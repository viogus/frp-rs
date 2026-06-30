use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use axum::{Router, Json, extract::{State, Path, Query, ws::{WebSocketUpgrade, WebSocket, Message}}, response::Html, routing::{get, delete}};
use axum::http::StatusCode;
use serde::{Serialize, Deserialize};
use crate::service::AppState;
use frp_core::admin_auth::apply_admin_auth;
use frp_core::metrics::MetricsSnapshot;

// --- Local TlsListener (moved from frp-core to avoid axum in core) ---

#[cfg(feature = "tls")]
use std::io;
#[cfg(feature = "tls")]
use tokio::net::TcpListener;
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tokio_rustls::server::TlsAcceptor;

/// TLS listener wrapper implementing axum's Listener trait.
/// Used by dashboard and admin API servers to accept TLS connections.
#[cfg(feature = "tls")]
struct TlsListener {
    inner: TcpListener,
    acceptor: Arc<std::sync::RwLock<Option<TlsAcceptor>>>,
}

#[cfg(feature = "tls")]
impl TlsListener {
    fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self {
            inner,
            acceptor: Arc::new(std::sync::RwLock::new(Some(acceptor))),
        }
    }
}

#[cfg(feature = "tls")]
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "TLS listener accept error: {}", e);
                    continue;
                }
            };
            let tls_acceptor = self
                .acceptor
                .read()
                .unwrap()
                .clone()
                .expect("TLS acceptor not initialized");
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, addr),
                Err(e) => {
                    tracing::warn!(addr = %addr, error = %e, "TLS handshake error from {}: {}", addr, e);
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

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
    total_conns: u64,
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

#[derive(Deserialize, Default)]
struct ProxiesQuery {
    #[serde(rename = "type", default)]
    proxy_type: String,
}

#[derive(Deserialize)]
struct DeleteProxiesBody {
    #[serde(default)]
    proxies: Vec<String>,
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

/// GET /api/serverinfo — Go frp compat alias for /api/status.
async fn handle_serverinfo(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
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

/// GET /api/proxies — list all proxies, optional ?type= filter.
async fn handle_proxies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ProxiesQuery>,
) -> Json<Vec<ProxyEntry>> {
    let proxies = state.proxy_manager.list().await;
    let filter_type = query.proxy_type;
    let mut entries = Vec::new();
    for p in &proxies {
        if !filter_type.is_empty() && p.proxy_type != filter_type {
            continue;
        }
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
            total_conns: traffic.total_conns,
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

/// GET /api/proxies/{name} — Go frp compat alias for /api/proxy/{name}.
async fn handle_proxy_by_name(
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
            total_conns: traffic.total_conns,
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

#[derive(Deserialize)]
struct HealthzQuery {
    /// Probe type: "liveness" (default) or "readiness".
    #[serde(default)]
    probe: Option<String>,
}

async fn handle_healthz(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HealthzQuery>,
) -> (StatusCode, &'static str) {
    match query.probe.as_deref() {
        Some("readiness") => {
            // Verify internal state structures are accessible (not deadlocked).
            let used_ok = state.used_ports.try_read().is_ok();
            let ctl_ok = state.run_id_to_ctl_tx.try_read().is_ok();
            if used_ok && ctl_ok {
                (StatusCode::OK, "ok")
            } else {
                tracing::warn!(
                    used_ports = %used_ok,
                    ctl_map = %ctl_ok,
                    "Readiness check failed: used_ports={} ctl_map={}",
                    used_ok,
                    ctl_ok
                );
                (StatusCode::SERVICE_UNAVAILABLE, "not ready")
            }
        }
        _ => {
            // Liveness: process is alive, always ok.
            (StatusCode::OK, "ok")
        }
    }
}

// --- Store API ---

#[derive(Deserialize)]
struct StoreProxyConfig {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    #[serde(default)]
    remote_port: Option<u16>,
    #[serde(default)]
    custom_domains: Vec<String>,
    #[serde(default)]
    local_addr: String,
    #[serde(default)]
    group: String,
}

/// GET /api/store/proxies — list all active proxies with extended config.
async fn handle_store_proxies(State(state): State<Arc<AppState>>) -> Json<Vec<serde_json::Value>> {
    let proxies = state.proxy_manager.list().await;
    let result: Vec<serde_json::Value> = proxies.iter().map(|p| {
        serde_json::json!({
            "name": p.name,
            "type": p.proxy_type,
            "run_id": p.run_id,
            "remote_port": p.remote_port,
            "local_addr": p.local_addr,
            "use_encryption": p.use_encryption,
            "use_compression": p.use_compression,
            "group": p.group,
        })
    }).collect();
    Json(result)
}

/// POST /api/store/proxies — stash a proxy config in memory.
async fn handle_store_proxy_create(
    State(state): State<Arc<AppState>>,
    Json(config): Json<StoreProxyConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if config.name.is_empty() || config.proxy_type.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "name and type are required".into()
        })));
    }
    let exists = state.proxy_manager.get(&config.name).await.is_some();
    if exists {
        return Err((StatusCode::CONFLICT, Json(ErrorResponse {
            error: "proxy already exists".into()
        })));
    }
    let name = config.name.clone();
    {
        let mut store = state.proxy_config_store.write().await;
        if store.contains_key(&config.name) {
            return Err((StatusCode::CONFLICT, Json(ErrorResponse {
                error: "proxy config already in store".into()
            })));
        }
        let (local_ip, local_port) = if config.local_addr.is_empty() {
            (String::new(), 0u16)
        } else if let Some((ip, port_str)) = config.local_addr.rsplit_once(':') {
            (ip.to_string(), port_str.parse::<u16>().unwrap_or(0))
        } else {
            (config.local_addr.clone(), 0u16)
        };
        store.insert(config.name.clone(), frp_core::config::ProxyConfig {
            name: config.name.clone(),
            proxy_type: config.proxy_type.clone(),
            remote_port: config.remote_port.unwrap_or(0),
            local_ip,
            local_port,
            custom_domains: config.custom_domains.clone(),
            group: config.group.clone(),
            ..Default::default()
        });
    } // write lock released before persist

    // Persist to disk
    if let Some(ref p) = state.store_path {
        let snapshot = state.proxy_config_store.read().await.clone();
        crate::store::save_store(p, &snapshot);
    }

    Ok(Json(serde_json::json!({"status": "created", "name": name})))
}

/// DELETE /api/store/proxy/:name — remove a proxy (cleans up server-side state).
async fn handle_store_proxy_delete(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy_manager.get(&name).await
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "proxy not found".into()
        })))?;

    // Clean up port
    if let Some(port) = proxy.remote_port {
        state.used_ports.write().await.remove(&port);
    }
    // Clean up sk_index
    if let Some(ref sk) = proxy.sk {
        if !sk.is_empty() {
            state.sk_index.write().await.remove(sk);
        }
    }
    // Clean up VHost and TCPMux routes
    state.vhost_manager.unregister(&name).await;
    state.tcpmux_manager.unregister(&name).await;
    state.proxy_metrics.remove(&name).await;
    state.proxy_manager.remove(&name).await;
    // Remove from store if present
    state.proxy_config_store.write().await.remove(&name);

    // Persist to disk
    if let Some(ref p) = state.store_path {
        let snapshot = state.proxy_config_store.read().await.clone();
        crate::store::save_store(p, &snapshot);
    }

    Ok(Json(serde_json::json!({"status": "deleted", "name": name})))
}

/// DELETE /api/proxies — bulk delete proxies. Go frp compat.
/// Body: {"proxies": ["name1", "name2"]}
async fn handle_proxies_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteProxiesBody>,
) -> Json<serde_json::Value> {
    let mut deleted = Vec::new();
    for name in &body.proxies {
        if let Some(proxy) = state.proxy_manager.get(name).await {
            if let Some(port) = proxy.remote_port {
                state.used_ports.write().await.remove(&port);
            }
            if let Some(ref sk) = proxy.sk {
                if !sk.is_empty() {
                    state.sk_index.write().await.remove(sk);
                }
            }
            state.vhost_manager.unregister(name).await;
            state.tcpmux_manager.unregister(name).await;
            state.proxy_metrics.remove(name).await;
            state.proxy_manager.remove(name).await;
            state.proxy_config_store.write().await.remove(name);
            deleted.push(name.clone());
        }
    }
    // Persist to disk
    if let Some(ref p) = state.store_path {
        let snapshot = state.proxy_config_store.read().await.clone();
        crate::store::save_store(p, &snapshot);
    }
    Json(serde_json::json!({
        "deleted": deleted.len(),
        "proxies": deleted,
    }))
}

// --- WebSocket event stream ---

/// Upgrade handler for GET /api/events.
/// Auth is handled by the `apply_admin_auth` middleware on the router —
/// this handler only runs when the Authorization header is valid.
async fn handle_events(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.event_tx.subscribe();
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        let json = serde_json::to_string(&ev).unwrap_or_default();
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!(
                            skipped = n,
                            "WebSocket event stream lagged, skipped {} events",
                            n
                        );
                        // Continue — rx.recv() recovers after lagged
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "WebSocket recv error");
                        break;
                    }
                    _ => {} // Ignore text/binary/ping/pong — axum auto-pongs
                }
            }
        }
    }
}

/// Background task that periodically emits traffic snapshots to
/// WebSocket subscribers. Runs every 1 second, skips when no
/// subscribers are connected, and only emits when metrics change.
async fn run_traffic_events(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Track last-emitted values per proxy to avoid redundant events
    let mut last_values: HashMap<String, MetricsSnapshot> = HashMap::new();

    loop {
        interval.tick().await;

        // Skip work entirely when no WebSocket clients are listening
        if state.event_tx.receiver_count() == 0 {
            continue;
        }

        let proxies = state.proxy_manager.list().await;
        for proxy in &proxies {
            if let Some(metrics) = state.proxy_metrics.get(&proxy.name).await {
                let snap = metrics.snapshot();
                let changed = last_values
                    .get(&proxy.name)
                    .map(|prev| {
                        prev.bytes_in != snap.bytes_in
                            || prev.bytes_out != snap.bytes_out
                            || prev.current_conns != snap.current_conns
                    })
                    .unwrap_or(true);

                if changed {
                    last_values.insert(proxy.name.clone(), snap.clone());
                    let _ = state.event_tx.send(crate::event::ServerEvent::Traffic {
                        proxy_name: proxy.name.clone(),
                        bytes_in: snap.bytes_in,
                        bytes_out: snap.bytes_out,
                        current_conns: snap.current_conns,
                    });
                }
            }
        }
    }
}

// --- Dashboard runner ---

pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
    enable_prometheus: bool,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // API routes (auth-protected)
    let api_routes = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/serverinfo", get(handle_serverinfo))
        .route("/api/proxies", get(handle_proxies).delete(handle_proxies_delete))
        .route("/api/proxies/{name}", get(handle_proxy_by_name))
        .route("/api/proxy/{name}", get(handle_proxy_detail))
        .route("/api/proxy/{name}/traffic", get(handle_proxy_traffic))
        .route("/api/clients", get(handle_clients))
        .route("/api/clients/{run_id}", get(handle_client_detail))
        .route("/api/store/proxies", get(handle_store_proxies).post(handle_store_proxy_create))
        .route("/api/store/proxy/{name}", delete(handle_store_proxy_delete))
        .route("/api/events", get(handle_events));

    let api_routes = apply_admin_auth(api_routes, &auth_user, &auth_password);

    // /metrics: gated behind enable_prometheus (Go frp compat).
    // Returns 404 when disabled. When dashboard auth is configured,
    // /metrics also requires Basic auth.
    let state_for_metrics = state.clone();
    let metrics_route = Router::new()
        .route("/metrics", get(move || {
            let state = state_for_metrics.clone();
            async move {
                crate::metrics::prom::sync_from_state(&state).await;
                crate::metrics::prom::render_metrics_text()
            }
        }));
    let metrics_route = apply_admin_auth(metrics_route, &auth_user, &auth_password);

    let mut app = Router::new()
        .route("/", get(handle_root))
        .route("/healthz", get(handle_healthz))
        .merge(api_routes);
    if enable_prometheus {
        app = app.merge(metrics_route);
    }
    // Spawn periodic traffic event broadcaster for WebSocket subscribers.
    // Clone state before it's moved into .with_state().
    let traffic_state = state.clone();
    tokio::spawn(async move {
        run_traffic_events(traffic_state).await;
    });

    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    match (tls_cert_file, tls_key_file) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            #[cfg(feature = "tls")]
            {
                let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
                tracing::info!(addr = %addr, "Dashboard listening on {} (TLS)", addr);
                let tls_listener = TlsListener::new(listener, acceptor);
                axum::serve(tls_listener, app).await?;
            }
            #[cfg(not(feature = "tls"))]
            {
                tracing::error!("TLS feature not enabled; cannot serve dashboard with TLS");
                return Err("TLS feature not enabled".into());
            }
        }
        _ => {
            tracing::info!(addr = %addr, "Dashboard listening on {}", addr);
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
