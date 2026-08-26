#[cfg(feature = "tls")]
use crate::lock::RwLockExt;
use crate::service::{AppState, InternalMsg};
use axum::http::StatusCode;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::HeaderValue,
    middleware,
    middleware::Next,
    response::Html,
    routing::{delete, get},
    Json, Router,
};
use frp_core::admin_auth::apply_admin_auth;
use frp_core::metrics::MetricsSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;

/// Build a 404 Not Found response tuple with the given error message.
fn not_found(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: msg.into() }),
    )
}

/// Map an axum `JsonRejection` to a status code. A missing or wrong
/// Content-Type is 415 (axum's `MissingJsonContentType`); everything else
/// (malformed body, size overflow, …) is 422 (audit-fix: JsonBody
/// rejection semantics drift — missing/wrong Content-Type yielded 422
/// instead of axum's 415).
fn json_rejection_status(err: &axum::extract::rejection::JsonRejection) -> StatusCode {
    match err {
        axum::extract::rejection::JsonRejection::MissingJsonContentType(_) => {
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        }
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

/// JSON body extractor that maps malformed bodies to a generic 422 instead
/// of axum's default `JsonRejection` body — the default embeds the internal
/// type path (e.g. `frp_server::dashboard::StoreProxyConfig`), leaking
/// implementation detail to API clients. The rejection body here is a plain
/// `{"error": "invalid JSON body"}`. A missing or wrong Content-Type is
/// rejected with 415 (generic body too, matching axum's 415 semantics).
struct JsonBody<T>(T);

impl<S, T> axum::extract::FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(err) => {
                tracing::debug!(error = %err, "Dashboard: rejecting request with invalid JSON body");
                let status = json_rejection_status(&err);
                Err((
                    status,
                    Json(ErrorResponse {
                        error: "invalid JSON body".into(),
                    }),
                ))
            }
        }
    }
}

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

/// Minimum interval between per-connection TLS handshake error warnings on
/// the dashboard/admin listener. A client that repeatedly fails the
/// handshake (e.g. a scanner probing the port) must not flood the log; the
/// first failure in each window is enough to signal a problem.
#[cfg(feature = "tls")]
const TLS_HANDSHAKE_WARN_MIN_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(feature = "tls")]
static LAST_TLS_HANDSHAKE_WARN: AtomicU64 = AtomicU64::new(0);

/// Warn about a failed TLS handshake at most once per
/// [`TLS_HANDSHAKE_WARN_MIN_INTERVAL`]: the first failure in each window is
/// logged, the rest are suppressed.
#[cfg(feature = "tls")]
fn warn_tls_handshake_rate_limited(addr: std::net::SocketAddr, error: &std::io::Error) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_TLS_HANDSHAKE_WARN.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < TLS_HANDSHAKE_WARN_MIN_INTERVAL.as_secs() {
        return;
    }
    if LAST_TLS_HANDSHAKE_WARN
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        // Another connection already logged within this window.
        return;
    }
    tracing::warn!(addr = %addr, error = %error, "TLS handshake error from {}: {}", addr, error);
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
            let tls_acceptor = match self.acceptor.read_ok().clone() {
                Some(acceptor) => acceptor,
                None => {
                    tracing::warn!("TLS acceptor not initialized, skipping connection");
                    continue;
                }
            };
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, addr),
                Err(e) => {
                    warn_tls_handshake_rate_limited(addr, &e);
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
    pool_hits: u64,
    pool_misses: u64,
    pool_drops: u64,
    pool_size: i64,
    pool_pending: i64,
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
    /// Composite key `{user}.{clientID}` (Go ClientInfoResp.key).
    key: String,
    user: String,
    #[serde(rename = "clientID", skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(rename = "runID")]
    run_id: String,
    version: String,
    #[serde(rename = "wireProtocol")]
    wire_protocol: String,
    hostname: String,
    #[serde(rename = "clientIP")]
    client_ip: String,
    online: bool,
    /// Go compat: first/last/disconnected timestamps as Unix seconds.
    #[serde(rename = "firstConnectedAt")]
    first_connected_at: u64,
    #[serde(rename = "lastConnectedAt")]
    last_connected_at: u64,
    #[serde(rename = "disconnectedAt", skip_serializing_if = "Option::is_none")]
    disconnected_at: Option<u64>,
    /// Proxy count for online clients (0 for offline).
    #[serde(rename = "proxyCount")]
    proxy_count: usize,
    proxies: Vec<String>,
    #[serde(rename = "poolSize")]
    pool_size: i64,
    #[serde(rename = "pendingRequests")]
    pending_requests: i64,
}

#[derive(Serialize)]
struct ClientDetail {
    run_id: String,
    client_addr: Option<String>,
    online: bool,
    login_time_secs: u64,
    proxy_count: usize,
    proxies: Vec<ProxyEntry>,
    pool_size: i64,
    pending_requests: i64,
}

// --- Handlers ---

/// Build the shared status payload for `/api/status` and its Go-frp-compat
/// alias `/api/serverinfo`.
async fn build_status_response(state: &Arc<AppState>) -> StatusResponse {
    let uptime = state.dashboard_start.elapsed().as_secs();
    let client_count = state.run_id_to_ctl_tx.len();
    let proxies = state.proxy_manager.list().await;

    let (total_pool_size, total_pending) =
        state
            .run_id_to_ctl_tx
            .iter()
            .fold((0i64, 0i64), |(s, p), ctl| {
                (
                    s + ctl.pool_stats.pool_size.load(Ordering::Relaxed),
                    p + ctl.pool_stats.pending_requests.load(Ordering::Relaxed),
                )
            });

    StatusResponse {
        version: frp_core::VERSION.to_string(),
        uptime_secs: uptime,
        client_count,
        proxy_count: proxies.len(),
        pool_hits: state.pool.hits.load(Ordering::Relaxed),
        pool_misses: state.pool.misses.load(Ordering::Relaxed),
        pool_drops: state.pool.drops.load(Ordering::Relaxed),
        pool_size: total_pool_size,
        pool_pending: total_pending,
    }
}

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(build_status_response(&state).await)
}

/// GET /api/serverinfo — Go frp compat alias for /api/status.
async fn handle_serverinfo(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(build_status_response(&state).await)
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
        let online = state.run_id_to_ctl_tx.contains_key(&p.run_id);
        let traffic = state
            .proxy_metrics
            .get(&p.name)
            .await
            .map(|m| m.snapshot())
            .unwrap_or_default();
        entries.push(ProxyEntry {
            name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            status: if online {
                "online".into()
            } else {
                "offline".into()
            },
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
    let proxy = state
        .proxy_manager
        .get(&name)
        .await
        .ok_or_else(|| not_found("proxy not found"))?;

    let online = state.run_id_to_ctl_tx.contains_key(&proxy.run_id);
    let traffic = state
        .proxy_metrics
        .get(&name)
        .await
        .map(|m| m.snapshot())
        .unwrap_or_default();

    Ok(Json(ProxyDetail {
        name: proxy.name.clone(),
        proxy_type: proxy.proxy_type.clone(),
        status: if online {
            "online".into()
        } else {
            "offline".into()
        },
        run_id: Some(proxy.run_id.clone()),
        remote_port: proxy.remote_port,
        local_addr: proxy.local_addr.clone(),
        use_encryption: proxy.use_encryption,
        use_compression: proxy.use_compression,
        custom_domains: proxy.custom_domains.clone(),
        multiplexer: proxy.multiplexer.clone(),
        group: proxy.group.clone().unwrap_or_default(),
        traffic,
    }))
}

async fn handle_proxy_traffic(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<MetricsSnapshot>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    // Verify proxy exists
    let _proxy = state
        .proxy_manager
        .get(&name)
        .await
        .ok_or_else(|| not_found("proxy not found"))?;

    let traffic = state
        .proxy_metrics
        .get(&name)
        .await
        .map(|m| m.snapshot())
        .unwrap_or_default();

    Ok(Json(traffic))
}

/// GET /api/proxy/{type} — list proxies filtered by type (path-param variant of ?type=).
async fn handle_proxies_by_type(
    State(state): State<Arc<AppState>>,
    Path(proxy_type): Path<String>,
) -> Result<Json<Vec<ProxyEntry>>, StatusCode> {
    // Validate proxy type — reject unknown types with 404
    let valid_types = ["tcp", "udp", "http", "https", "stcp", "xtcp", "sudp"];
    if !valid_types.contains(&proxy_type.as_str()) {
        return Err(StatusCode::NOT_FOUND);
    }
    let proxies = state.proxy_manager.list().await;
    let mut entries = Vec::new();
    for p in &proxies {
        if p.proxy_type != proxy_type {
            continue;
        }
        let online = state.run_id_to_ctl_tx.contains_key(&p.run_id);
        let traffic = state
            .proxy_metrics
            .get(&p.name)
            .await
            .map(|m| m.snapshot())
            .unwrap_or_default();
        entries.push(ProxyEntry {
            name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            status: if online {
                "online".into()
            } else {
                "offline".into()
            },
            remote_port: p.remote_port,
            local_addr: p.local_addr.clone(),
            traffic_in: traffic.bytes_in,
            traffic_out: traffic.bytes_out,
            total_conns: traffic.total_conns,
        });
    }
    Ok(Json(entries))
}

/// GET /api/proxy/{type}/{name} — proxy detail with type verification.
async fn handle_proxy_by_type_name(
    State(state): State<Arc<AppState>>,
    Path((proxy_type, name)): Path<(String, String)>,
) -> Result<Json<ProxyDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let proxy = state
        .proxy_manager
        .get(&name)
        .await
        .ok_or_else(|| not_found("proxy not found"))?;

    if proxy.proxy_type != proxy_type {
        return Err(not_found("proxy type mismatch"));
    }

    let online = state.run_id_to_ctl_tx.contains_key(&proxy.run_id);
    let traffic = state
        .proxy_metrics
        .get(&name)
        .await
        .map(|m| m.snapshot())
        .unwrap_or_default();

    Ok(Json(ProxyDetail {
        name: proxy.name.clone(),
        proxy_type: proxy.proxy_type.clone(),
        status: if online {
            "online".into()
        } else {
            "offline".into()
        },
        run_id: Some(proxy.run_id.clone()),
        remote_port: proxy.remote_port,
        local_addr: proxy.local_addr.clone(),
        use_encryption: proxy.use_encryption,
        use_compression: proxy.use_compression,
        custom_domains: proxy.custom_domains.clone(),
        multiplexer: proxy.multiplexer.clone(),
        group: proxy.group.clone().unwrap_or_default(),
        traffic,
    }))
}

/// GET /api/proxies/{name} — Go frp compat alias for /api/proxy/{type}/{name}.
async fn handle_proxy_by_name(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    handle_proxy_detail(State(state), Path(name)).await
}

async fn handle_clients(State(state): State<Arc<AppState>>) -> Json<Vec<ClientEntry>> {
    // Go compat: /api/clients lists the registry (online AND offline clients,
    // with a pruning policy), not just the live control connections.
    let registry = state.client_registry.list();
    let mut clients = Vec::with_capacity(registry.len());
    for info in registry {
        let ctl = if info.run_id.is_empty() {
            None
        } else {
            state.run_id_to_ctl_tx.get(&info.run_id).map(|c| c.clone())
        };
        let (proxies, pool_size, pending) = match ctl {
            Some(ctl) => {
                let names = state
                    .proxy_manager
                    .list_client_proxy_names(&info.run_id)
                    .await;
                (
                    names,
                    ctl.pool_stats.pool_size.load(Ordering::Relaxed),
                    ctl.pool_stats.pending_requests.load(Ordering::Relaxed),
                )
            }
            None => (Vec::new(), 0, 0),
        };
        clients.push(ClientEntry {
            key: info.key.clone(),
            user: info.user.clone(),
            client_id: if info.raw_client_id.is_empty() {
                None
            } else {
                Some(info.raw_client_id.clone())
            },
            run_id: info.run_id.clone(),
            version: info.version.clone(),
            wire_protocol: info.wire_protocol.clone(),
            hostname: info.hostname.clone(),
            client_ip: info.ip.clone(),
            online: info.online,
            first_connected_at: info.first_connected_at_unix,
            last_connected_at: info.last_connected_at_unix,
            disconnected_at: info.disconnected_at_unix,
            proxy_count: proxies.len(),
            proxies,
            pool_size,
            pending_requests: pending,
        });
    }
    Json(clients)
}

async fn handle_client_detail(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<ClientDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let ctl = state
        .run_id_to_ctl_tx
        .get(&run_id)
        .map(|c| c.clone())
        .ok_or_else(|| not_found("client not found"))?;

    let proxy_infos = state.proxy_manager.list_client(&run_id).await;
    let mut proxies = Vec::new();
    for p in &proxy_infos {
        let traffic = state
            .proxy_metrics
            .get(&p.name)
            .await
            .map(|m| m.snapshot())
            .unwrap_or_default();
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
        pool_size: ctl.pool_stats.pool_size.load(Ordering::Relaxed),
        pending_requests: ctl.pool_stats.pending_requests.load(Ordering::Relaxed),
    }))
}

/// Dashboard root page. When `assets_dir` is configured, serve the
/// `index.html` from that directory (Go frp `assetsDir` compat: custom
/// dashboard HTML), falling back to the built-in page if the file is
/// missing or unreadable.
/// Load the dashboard root page. The custom `assets_dir/index.html` (Go
/// frp `assetsDir` compat) is read once at startup and cached — Go loads
/// its assets at startup too, and this keeps per-request file IO + warn
/// spam out of the hot path.
fn load_dashboard_page(assets_dir: &str) -> String {
    let builtin = || include_str!("dashboard.html").replace("{version}", frp_core::VERSION);
    if assets_dir.is_empty() {
        return builtin();
    }
    let path = std::path::Path::new(assets_dir).join("index.html");
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            tracing::info!(path = %path.display(), "dashboard: serving custom index.html from assets_dir");
            content.replace("{version}", frp_core::VERSION)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %path.display(),
                "dashboard: assets_dir index.html not found, using built-in page"
            );
            builtin()
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "dashboard: failed to read assets_dir index.html, using built-in page"
            );
            builtin()
        }
    }
}

async fn handle_root(page: &str) -> Html<String> {
    Html(page.to_string())
}

/// Go compat: `/debug/pprof` index. frp-rs has no Go-style pprof endpoints;
/// return a minimal page so tooling probing the route gets a sane response.
async fn handle_pprof_index() -> Html<&'static str> {
    Html("<html><body><h1>pprof</h1><p>frp-rs does not expose Go-style pprof endpoints.</p></body></html>")
}

/// Go compat: `/debug/pprof/*` placeholder (outside auth, like Go).
async fn handle_pprof() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_FOUND,
        "pprof profiles are not available in frp-rs",
    )
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
            // A draining server is definitionally not-ready: stop routing
            // new traffic while existing connections finish.
            if state.shutdown_token.is_cancelled() {
                return (StatusCode::SERVICE_UNAVAILABLE, "draining");
            }
            // Verify internal state structures are accessible (not deadlocked).
            let used_ok = state.used_ports.try_read().is_ok();
            let used_udp_ok = state.used_udp_ports.try_read().is_ok();
            // `run_id_to_ctl_tx` is a DashMap (sharded locks) — there is no
            // single global lock to probe, so the lock-contention check is
            // dropped.
            let proxy_ok = state.proxy_manager.is_responsive();
            if used_ok && used_udp_ok && proxy_ok {
                (StatusCode::OK, "ok")
            } else {
                tracing::warn!(
                    used_ports = %used_ok,
                    used_udp_ports = %used_udp_ok,
                    proxy_manager = %proxy_ok,
                    "Readiness check failed: used_ports={} used_udp_ports={} proxy_manager={}",
                    used_ok,
                    used_udp_ok,
                    proxy_ok
                );
                (StatusCode::SERVICE_UNAVAILABLE, "not ready")
            }
        }
        _ => {
            // Liveness (no probe param, or probe=liveness): process is alive.
            // Return empty body per Go frp compat.
            (StatusCode::OK, "")
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
    let result: Vec<serde_json::Value> = proxies
        .iter()
        .map(|p| {
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
        })
        .collect();
    Json(result)
}

/// POST /api/store/proxies — stash a proxy config in memory.
async fn handle_store_proxy_create(
    State(state): State<Arc<AppState>>,
    JsonBody(config): JsonBody<StoreProxyConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if config.name.is_empty() || config.proxy_type.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "name and type are required".into(),
            }),
        ));
    }
    let exists = state.proxy_manager.get(&config.name).await.is_some();
    if exists {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "proxy already exists".into(),
            }),
        ));
    }
    let name = config.name.clone();
    {
        let mut store = state.proxy_config_store.write().await;
        if store.contains_key(&config.name) {
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "proxy config already in store".into(),
                }),
            ));
        }
        let (local_ip, local_port) = if config.local_addr.is_empty() {
            (String::new(), 0u16)
        } else if let Some((ip, port_str)) = config.local_addr.rsplit_once(':') {
            (ip.to_string(), port_str.parse::<u16>().unwrap_or(0))
        } else {
            (config.local_addr.clone(), 0u16)
        };
        store.insert(
            config.name.clone(),
            frp_core::config::ProxyConfig {
                name: config.name.clone(),
                proxy_type: config.proxy_type.clone(),
                remote_port: config.remote_port.unwrap_or(0),
                local_ip,
                local_port,
                custom_domains: config.custom_domains.clone(),
                group: config.group.clone(),
                ..Default::default()
            },
        );
    } // write lock released before persist

    // Persist to disk
    if let Some(ref p) = state.store_path {
        let snapshot = state.proxy_config_store.read().await.clone();
        crate::store::save_store(p, &snapshot);
    }

    Ok(Json(serde_json::json!({"status": "created", "name": name})))
}

/// Clean up server-side port allocation for a deleted proxy, mirroring the
/// client CloseProxy path (`control/proxy.rs`): TCP group ports are only
/// released for the last group member (the shared listener still owns the
/// port otherwise), the group listener is stopped for the final member, and
/// the per-client port count is decremented. The dashboard delete paths used
/// to skip all three — leaking port quota (`max_ports_per_client`) and
/// leaving zombie group listeners holding ports until frps restarts.
async fn cleanup_deleted_proxy_port(state: &Arc<AppState>, proxy: &crate::proxy::ProxyInfo) {
    let is_tcp_group =
        proxy.proxy_type == "tcp" && proxy.group.as_deref().filter(|g| !g.is_empty()).is_some();
    let group_name = proxy.group.clone().unwrap_or_default();
    let last_group_member = is_tcp_group && state.proxy_manager.group_len(&group_name).await <= 1;
    if let Some(port) = proxy.remote_port {
        if proxy.proxy_type == "udp" || proxy.proxy_type == "sudp" {
            // SUDP proxies can share one server port (frp-rs extension):
            // only release the mark when no OTHER live udp/sudp proxy still
            // holds the bound socket — otherwise the next SUDP registration's
            // OS bind probe fails with EADDRINUSE (audit finding 2, mirroring
            // handle_close_proxy). The deleted proxy is still in the registry
            // here, so it is excluded from the owner count.
            crate::control::release_udp_port_with_owner_check(state, port, &proxy.name).await;
        } else if !is_tcp_group || last_group_member {
            state.used_ports.write().await.remove(&port);
        }
        // Decrement per-client port count (matching Go frp's portsUsedNum).
        // Only proxies that actually consumed a port were counted (audit
        // finding 1 symmetry): http/https/tcpmux/stcp/xtcp delete with
        // remote_port Some(0) and must not decrement — repeated deletes of
        // non-consuming proxies would drive the shared budget counter down
        // while live tcp/udp proxies still consume ports, letting the
        // max_ports_per_client gate undercount.
        if matches!(proxy.proxy_type.as_str(), "tcp" | "udp" | "sudp") && port > 0 {
            let run_id = &proxy.run_id;
            let mut port_counts = state.client_ports_used.write().await;
            if let Some(count) = port_counts.get_mut(run_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    port_counts.remove(run_id);
                }
            }
        }
    }
    // Stop the shared TCP group listener when the last member closes so it
    // doesn't linger as a zombie holding the group port.
    if last_group_member {
        state.tcp_group_ctl.remove_group(&group_name).await;
    }
}

/// DELETE /api/store/proxy/:name — remove a proxy (cleans up server-side state
/// and notifies the client via CloseProxy so it stops forwarding).
async fn handle_store_proxy_delete(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    tracing::warn!(proxy_name = %name, "Dashboard: single proxy delete");
    let proxy = state
        .proxy_manager
        .get(&name)
        .await
        .ok_or_else(|| not_found("proxy not found"))?;

    let run_id = proxy.run_id.clone();

    // Clean up port (TCP/UDP manager, TCP group last-member semantics and
    // per-client port quota — same lifecycle as the client CloseProxy path).
    cleanup_deleted_proxy_port(&state, &proxy).await;
    // Clean up sk_index (indexed by proxy_name)
    if let Some(key) = proxy.sk_index_key() {
        state.xtcp.sk_index.remove(key);
    }
    // Clean up VHost and TCPMux routes. HTTP/HTTPS group members share one
    // route: remove from the group first, drop the route with the OWNER's
    // name when the group empties (same lifecycle as handle_close_proxy).
    if (proxy.proxy_type == "http" || proxy.proxy_type == "https")
        && proxy.group.as_deref().filter(|g| !g.is_empty()).is_some()
    {
        if let Some(owner) = state
            .http_group_ctl
            .unregister_member(proxy.group.as_deref().unwrap_or_default(), &proxy.name)
            .await
        {
            state.vhost_manager.unregister(&owner).await;
        }
    } else {
        state.vhost_manager.unregister(&name).await;
    }
    state.tcpmux_manager.unregister(&name).await;
    state.proxy_metrics.remove(&name).await;
    // Decrement the SNI-sniff gate count only when the proxy was actually
    // removed — the client CloseProxy path races this handler and both may
    // observe the proxy before either removes it. A double decrement would
    // leave https_proxy_count at 0 while https proxies still exist, silently
    // disabling SNI sniff (HTTPS vhost routing) until the next lifecycle
    // event.
    if state.proxy_manager.remove(&name).await && proxy.proxy_type == "https" {
        state.dec_https_proxy_count();
    }
    // Remove from store if present
    state.proxy_config_store.write().await.remove(&name);

    // Persist to disk
    if let Some(ref p) = state.store_path {
        let snapshot = state.proxy_config_store.read().await.clone();
        crate::store::save_store(p, &snapshot);
    }

    // Notify the client to close the proxy on its side (Go frp compat).
    if let Some(ctl_tx) = state.run_id_to_ctl_tx.get(&run_id).map(|c| c.clone()) {
        let _ = ctl_tx
            .tx
            .try_send(InternalMsg::WriteCloseProxy {
                proxy_name: name.clone(),
            })
            .ok();
    }

    Ok(Json(serde_json::json!({"status": "deleted", "name": name})))
}

/// DELETE /api/proxies — bulk delete proxies. Go frp compat.
/// Body: {"proxies": ["name1", "name2"]}
async fn handle_proxies_delete(
    State(state): State<Arc<AppState>>,
    JsonBody(body): JsonBody<DeleteProxiesBody>,
) -> Json<serde_json::Value> {
    tracing::warn!(count = body.proxies.len(), names = ?body.proxies, "Dashboard: bulk proxy delete");
    let mut deleted = Vec::new();
    for name in &body.proxies {
        if let Some(proxy) = state.proxy_manager.get(name).await {
            // Clean up port (TCP/UDP manager, TCP group last-member semantics
            // and per-client port quota — same lifecycle as CloseProxy).
            cleanup_deleted_proxy_port(&state, &proxy).await;
            if let Some(key) = proxy.sk_index_key() {
                state.xtcp.sk_index.remove(key);
            }
            if (proxy.proxy_type == "http" || proxy.proxy_type == "https")
                && proxy.group.as_deref().filter(|g| !g.is_empty()).is_some()
            {
                if let Some(owner) = state
                    .http_group_ctl
                    .unregister_member(proxy.group.as_deref().unwrap_or_default(), &proxy.name)
                    .await
                {
                    state.vhost_manager.unregister(&owner).await;
                }
            } else {
                state.vhost_manager.unregister(name).await;
            }
            state.tcpmux_manager.unregister(name).await;
            state.proxy_metrics.remove(name).await;
            // Decrement the SNI-sniff gate count only when the proxy was
            // actually removed — CloseProxy / client disconnect race this
            // bulk delete, and a double decrement would leave
            // https_proxy_count at 0 while https proxies still exist.
            if state.proxy_manager.remove(name).await && proxy.proxy_type == "https" {
                state.dec_https_proxy_count();
            }
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

/// Maximum number of concurrent WebSocket subscribers on `/api/events`.
/// Caps per-process connection and task accumulation: the event feed is a
/// best-effort broadcast, so excess connections are rejected outright.
const MAX_WS_SUBSCRIBERS: usize = 64;

/// Process-wide semaphore capping concurrent `/api/events` WebSocket
/// connections. One permit is held for the lifetime of each connection
/// (dropped when the socket closes) so a single client cannot accumulate
/// unbounded connections.
fn ws_conn_semaphore() -> Arc<tokio::sync::Semaphore> {
    static SEM: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_WS_SUBSCRIBERS)));
    SEM.clone()
}

/// Try to acquire a WebSocket subscriber permit, rejecting with 429 when the
/// concurrent-subscriber cap is reached.
fn try_acquire_ws_permit(
    sem: &Arc<tokio::sync::Semaphore>,
) -> Result<OwnedSemaphorePermit, (StatusCode, Json<ErrorResponse>)> {
    sem.clone().try_acquire_owned().map_err(|_| {
        tracing::warn!(
            limit = MAX_WS_SUBSCRIBERS,
            "Dashboard: WebSocket subscriber limit reached, rejecting /api/events upgrade"
        );
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "too many WebSocket connections".into(),
            }),
        )
    })
}

/// Upgrade handler for GET /api/events.
/// Auth is handled by the `apply_admin_auth` middleware on the router —
/// this handler only runs when the Authorization header is valid.
async fn handle_events(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> Result<impl axum::response::IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let sem = ws_conn_semaphore();
    let permit = try_acquire_ws_permit(&sem)?;
    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state, permit)))
}

/// `_permit` is the RAII guard that caps concurrent subscribers: it is held
/// for the full connection lifetime and dropped when the socket closes.
async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>, _permit: OwnedSemaphorePermit) {
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
                        tracing::warn!(
                            skipped = n,
                            "WebSocket event stream lagged, {} events skipped — client should re-sync via REST API",
                            n
                        );
                        // Send synthetic error so client knows state may be stale
                        let resync = crate::event::ServerEvent::Error {
                            message: format!(
                                "event stream lagged: {} events skipped — re-sync via GET /api/proxies and /api/clients",
                                n
                            ),
                            context: None,
                        };
                        let json = serde_json::to_string(&resync).unwrap_or_default();
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
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

        emit_traffic_events_tick(&state, &state.event_tx, &mut last_values).await;
    }
}

/// Emit one round of traffic events: drop `last_values` entries for proxies
/// that are no longer registered, then send events for proxies whose metrics
/// changed since the last round. Dropping stale entries keeps `last_values`
/// bounded by the set of live proxies instead of growing without bound
/// across proxy churn (create/delete cycles).
async fn emit_traffic_events_tick(
    state: &AppState,
    event_tx: &tokio::sync::broadcast::Sender<crate::event::ServerEvent>,
    last_values: &mut HashMap<String, MetricsSnapshot>,
) {
    let proxies = state.proxy_manager.list().await;
    let live: std::collections::HashSet<&str> = proxies.iter().map(|p| p.name.as_str()).collect();
    last_values.retain(|name, _| live.contains(name.as_str()));

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
                let _ = event_tx.send(crate::event::ServerEvent::Traffic {
                    proxy_name: proxy.name.clone(),
                    bytes_in: snap.bytes_in,
                    bytes_out: snap.bytes_out,
                    current_conns: snap.current_conns,
                });
            }
        }
    }
}

/// Security headers middleware: adds common HTTP security headers to every
/// dashboard response. Applied as axum middleware so handler return types
/// are unaffected — no test breakage from response type mismatches.
async fn add_security_headers(req: axum::extract::Request, next: Next) -> axum::response::Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}

// ─────────────────────────────────────────────────────────────────────────
// Dashboard API v2 — Go frp v0.70.0 parity.
//
// Routes (registered in `run_dashboard`):
//   GET  /api/v2/system/info
//   POST /api/v2/system/prune
//   GET  /api/v2/users
//   GET  /api/v2/clients
//   GET  /api/v2/clients/{key}
//   GET  /api/v2/proxies
//   GET  /api/v2/proxies/{name}
//   GET  /api/v2/proxies/{name}/traffic
//   GET  /api/v2/config                (audit-specified; not in Go frp)
//   PUT  /api/v2/proxy/{name}/update   (audit-specified; not in Go frp)
//
// Field names, pagination, filtering, sorting and prune semantics follow
// Go frp v0.70.0 `server/http/controller_v2.go` + `server/http/model/v2.go`.
// The `/api/v2/config` and `/api/v2/proxy/{name}/update` endpoints do NOT
// exist in Go frp (v0.70.0 or dev); they follow audit-specified paths and
// reuse the Go V2 response shapes — see the handler doc comments.
//
// NOTE: a pre-existing `dashboard_v2.rs` module carried an earlier, less
// accurate v2 implementation; it was removed in the same commit that added
// this in-place module. This module is the authoritative v2 implementation.
mod v2 {
    use super::*;
    use axum::routing::{post, put};
    use std::time::SystemTime;

    const DEFAULT_PAGE: u32 = 1;
    const DEFAULT_PAGE_SIZE: u32 = 50;
    const MAX_PAGE_SIZE: u32 = 200;
    const TRAFFIC_DAYS: usize = 7;

    const VALID_TYPES: &[&str] = &[
        "tcp", "udp", "http", "https", "tcpmux", "stcp", "xtcp", "sudp",
    ];

    // ── Response models ──

    #[derive(Serialize)]
    struct PageResp<T: Serialize> {
        total: usize,
        page: u32,
        #[serde(rename = "pageSize")]
        page_size: u32,
        items: Vec<T>,
    }

    #[derive(Serialize, Debug)]
    struct V2Error {
        error: String,
    }

    fn err(s: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<V2Error>) {
        (s, Json(V2Error { error: msg.into() }))
    }

    /// V2 variant of `JsonBody`: same rejection semantics — 415 on a
    /// missing/wrong Content-Type, generic 422 on a malformed body — but
    /// rejects with the V2 error shape `{error}` instead of the V1
    /// `ErrorResponse` (audit-fix: v2 endpoints returned the V1 shape on
    /// malformed JSON).
    struct V2JsonBody<T>(T);

    impl<S, T> axum::extract::FromRequest<S> for V2JsonBody<T>
    where
        S: Send + Sync,
        T: serde::de::DeserializeOwned,
    {
        type Rejection = (StatusCode, Json<V2Error>);

        async fn from_request(
            req: axum::extract::Request,
            state: &S,
        ) -> Result<Self, Self::Rejection> {
            match Json::<T>::from_request(req, state).await {
                Ok(Json(value)) => Ok(V2JsonBody(value)),
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        "Dashboard V2: rejecting request with invalid JSON body"
                    );
                    Err((
                        json_rejection_status(&err),
                        Json(V2Error {
                            error: "invalid JSON body".into(),
                        }),
                    ))
                }
            }
        }
    }

    /// Go `model.V2SystemInfoConfigResp`.
    #[derive(Serialize)]
    struct SystemInfoConfig {
        #[serde(rename = "bindPort")]
        bind_port: u16,
        #[serde(rename = "vhostHTTPPort")]
        vhost_http_port: u16,
        #[serde(rename = "vhostHTTPSPort")]
        vhost_https_port: u16,
        #[serde(rename = "tcpmuxHTTPConnectPort")]
        tcpmux_httpconnect_port: u16,
        #[cfg(feature = "kcp")]
        #[serde(rename = "kcpBindPort")]
        kcp_bind_port: u16,
        #[cfg(feature = "quic")]
        #[serde(rename = "quicBindPort")]
        quic_bind_port: u16,
        #[serde(rename = "subdomainHost")]
        subdomain_host: String,
        #[serde(rename = "maxPoolCount")]
        max_pool_count: i64,
        #[serde(rename = "maxPortsPerClient")]
        max_ports_per_client: i64,
        #[serde(rename = "heartbeatTimeout")]
        heartbeat_timeout: i64,
        #[serde(rename = "allowPortsStr")]
        allow_ports_str: String,
        #[serde(rename = "tlsForce")]
        tls_force: bool,
    }

    /// Go `model.V2SystemInfoStatusResp`.
    #[derive(Serialize)]
    struct SystemInfoStatus {
        #[serde(rename = "totalTrafficIn")]
        total_traffic_in: i64,
        #[serde(rename = "totalTrafficOut")]
        total_traffic_out: i64,
        #[serde(rename = "curConns")]
        cur_conns: i64,
        #[serde(rename = "clientCounts")]
        client_counts: i64,
        #[serde(rename = "proxyTypeCount")]
        proxy_type_counts: HashMap<String, i64>,
    }

    /// Go `model.V2SystemInfoResp`.
    #[derive(Serialize)]
    struct SystemInfoResp {
        version: String,
        config: SystemInfoConfig,
        status: SystemInfoStatus,
    }

    /// Go `model.V2SystemPruneResp`.
    #[derive(Serialize)]
    struct SystemPruneResp {
        #[serde(rename = "type")]
        prune_type: String,
        cleared: usize,
        total: usize,
    }

    /// Sanitized server configuration for `GET /api/v2/config`.
    ///
    /// NOTE: Go frp v0.70.0 (and dev) have no `/api/v2/config` endpoint —
    /// verified against `server/api_router.go`. This shape follows the
    /// audit-specified fields using Go v1 config camelCase JSON names. Secret
    /// material (auth token, dashboard password) is deliberately excluded.
    ///
    /// Data-source limits in frp-rs: the `AppState` keeps a
    /// `ServerConfigSnapshot` plus the runtime dashboard settings, but does
    /// not retain the full `ServerConfig` (bind_addr, auth sub-options,
    /// log config). Fields with no source are omitted and documented here.
    #[derive(Serialize)]
    struct ConfigResp {
        version: String,
        /// frp-rs proxy/listen bind address (`proxyBindAddr`, falls back to
        /// `bind_addr` at startup); the raw `bind_addr` is not retained in
        /// AppState.
        #[serde(rename = "bindAddr")]
        bind_addr: String,
        #[serde(rename = "bindPort")]
        bind_port: u16,
        #[serde(rename = "vhostHTTPPort")]
        vhost_http_port: u16,
        #[serde(rename = "vhostHTTPSPort")]
        vhost_https_port: u16,
        #[serde(rename = "subdomainHost")]
        subdomain_host: String,
        #[serde(rename = "maxPortsPerClient")]
        max_ports_per_client: i64,
        #[serde(rename = "heartbeatTimeout")]
        heartbeat_timeout: i64,
        #[serde(rename = "allowPortsStr")]
        allow_ports_str: String,
        #[serde(rename = "tlsForce")]
        tls_force: bool,
        dashboard: DashboardConfigResp,
        /// Auth method only — the token/credentials are never returned.
        auth: AuthConfigResp,
    }

    /// Go `model.V2SystemInfoConfigResp`-style dashboard section (sanitized:
    /// password omitted).
    #[derive(Serialize)]
    struct DashboardConfigResp {
        addr: String,
        port: u16,
        user: String,
        #[serde(rename = "enablePrometheus")]
        enable_prometheus: bool,
    }

    /// Sanitized auth section: only the method name is exposed.
    #[derive(Serialize)]
    struct AuthConfigResp {
        method: String,
    }

    /// Go `model.V2UserResp`.
    #[derive(Serialize)]
    struct UserResp {
        user: String,
        #[serde(rename = "clientCount")]
        client_count: usize,
        #[serde(rename = "proxyCount")]
        proxy_count: usize,
    }

    /// Go `model.ClientInfoResp` (used for both client list and detail).
    #[derive(Serialize)]
    struct ClientEntry {
        key: String,
        user: String,
        #[serde(rename = "clientID")]
        client_id: String,
        #[serde(rename = "runID")]
        run_id: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        version: String,
        #[serde(rename = "wireProtocol", skip_serializing_if = "String::is_empty")]
        wire_protocol: String,
        hostname: String,
        #[serde(rename = "clientIP", skip_serializing_if = "String::is_empty")]
        client_ip: String,
        #[serde(rename = "firstConnectedAt")]
        first_connected_at: i64,
        #[serde(rename = "lastConnectedAt")]
        last_connected_at: i64,
        #[serde(rename = "disconnectedAt", skip_serializing_if = "is_zero")]
        disconnected_at: i64,
        online: bool,
    }

    impl ClientEntry {
        /// Go `buildClientInfoResp`.
        fn from_info(info: &crate::registry::ClientInfo) -> Self {
            Self {
                key: info.key.clone(),
                user: info.user.clone(),
                client_id: info.client_id().to_string(),
                run_id: info.run_id.clone(),
                version: info.version.clone(),
                wire_protocol: info.wire_protocol.clone(),
                hostname: info.hostname.clone(),
                client_ip: info.ip.clone(),
                first_connected_at: info.first_connected_at_unix as i64,
                last_connected_at: info.last_connected_at_unix as i64,
                disconnected_at: info.disconnected_at_unix.unwrap_or(0) as i64,
                online: info.online,
            }
        }
    }

    /// Go `model.V2ClientDetailResp`: flattened ClientInfoResp + status.
    #[derive(Serialize)]
    struct ClientDetailResp {
        #[serde(flatten)]
        info: ClientEntry,
        status: ClientStatus,
    }

    /// Go `model.V2ClientStatusResp`.
    #[derive(Serialize)]
    struct ClientStatus {
        phase: String,
        #[serde(rename = "curConns")]
        cur_conns: i64,
        #[serde(rename = "proxyCount")]
        proxy_count: i64,
    }

    /// Go `model.V2ProxyResp`.
    #[derive(Serialize)]
    struct ProxyResp {
        name: String,
        user: String,
        #[serde(rename = "clientID")]
        client_id: String,
        spec: ProxySpec,
        status: ProxyStatus,
    }

    /// Go `model.V2ProxySpec`.
    #[derive(Serialize, Default)]
    struct ProxySpec {
        #[serde(rename = "type")]
        proxy_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcp: Option<TcpUdpSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        udp: Option<TcpUdpSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        http: Option<HttpSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        https: Option<HttpsSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcpmux: Option<TcpMuxSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stcp: Option<BaseOnlySpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sudp: Option<BaseOnlySpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        xtcp: Option<BaseOnlySpec>,
    }

    /// Go `model.V2ProxyBaseSpec`. `transport` is always present; `loadBalancer`
    /// always present (empty group allowed) to match Go's non-omitempty fields.
    /// `annotations`/`metadatas` are omitted because frp-rs `ProxyInfo` has no
    /// corresponding data.
    #[derive(Serialize)]
    struct ProxyBaseSpec {
        transport: Option<ProxyTransport>,
        #[serde(rename = "loadBalancer")]
        load_balancer: Option<LoadBalancer>,
    }

    /// Go `model.V2ProxyTransportSpec`.
    #[derive(Serialize)]
    struct ProxyTransport {
        #[serde(rename = "useEncryption")]
        use_encryption: bool,
        #[serde(rename = "useCompression")]
        use_compression: bool,
        #[serde(rename = "bandwidthLimit")]
        bandwidth_limit: String,
        #[serde(rename = "bandwidthLimitMode")]
        bandwidth_limit_mode: String,
    }

    /// Go `model.V2ProxyLoadBalancerSpec`.
    #[derive(Serialize)]
    struct LoadBalancer {
        group: String,
    }

    /// Go `model.V2TCPProxySpec` / `V2UDPProxySpec`.
    #[derive(Serialize)]
    struct TcpUdpSpec {
        #[serde(flatten)]
        base: ProxyBaseSpec,
        #[serde(rename = "remotePort", skip_serializing_if = "Option::is_none")]
        remote_port: Option<u16>,
    }

    /// Go `model.V2HTTPProxySpec`.
    #[derive(Serialize)]
    struct HttpSpec {
        #[serde(flatten)]
        base: ProxyBaseSpec,
        #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
        custom_domains: Vec<String>,
        #[serde(skip_serializing_if = "String::is_empty")]
        subdomain: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        locations: Vec<String>,
        #[serde(rename = "hostHeaderRewrite", skip_serializing_if = "String::is_empty")]
        host_header_rewrite: String,
    }

    /// Go `model.V2HTTPSProxySpec`.
    #[derive(Serialize)]
    struct HttpsSpec {
        #[serde(flatten)]
        base: ProxyBaseSpec,
        #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
        custom_domains: Vec<String>,
        #[serde(skip_serializing_if = "String::is_empty")]
        subdomain: String,
    }

    /// Go `model.V2TCPMuxProxySpec`.
    #[derive(Serialize)]
    struct TcpMuxSpec {
        #[serde(flatten)]
        base: ProxyBaseSpec,
        #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
        custom_domains: Vec<String>,
        #[serde(skip_serializing_if = "String::is_empty")]
        subdomain: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        multiplexer: String,
        #[serde(rename = "routeByHTTPUser", skip_serializing_if = "String::is_empty")]
        route_by_http_user: String,
    }

    /// Go `model.V2STCPProxySpec` / `V2SUDPProxySpec` / `V2XTCPProxySpec`.
    #[derive(Serialize)]
    struct BaseOnlySpec {
        #[serde(flatten)]
        base: ProxyBaseSpec,
    }

    /// Go `model.V2ProxyStatusResp`.
    #[derive(Serialize)]
    struct ProxyStatus {
        phase: String,
        #[serde(rename = "todayTrafficIn")]
        today_traffic_in: u64,
        #[serde(rename = "todayTrafficOut")]
        today_traffic_out: u64,
        #[serde(rename = "curConns")]
        cur_conns: i64,
        #[serde(rename = "lastStartAt", skip_serializing_if = "is_zero")]
        last_start_at: i64,
        #[serde(rename = "lastCloseAt", skip_serializing_if = "is_zero")]
        last_close_at: i64,
    }

    /// Go `model.V2ProxyTrafficResp`.
    #[derive(Serialize)]
    struct ProxyTrafficResp {
        name: String,
        unit: String,
        granularity: String,
        history: Vec<TrafficPoint>,
    }

    /// Go `model.V2ProxyTrafficPointResp`.
    #[derive(Serialize)]
    struct TrafficPoint {
        date: String,
        #[serde(rename = "trafficIn")]
        traffic_in: i64,
        #[serde(rename = "trafficOut")]
        traffic_out: i64,
    }

    fn is_zero(v: &i64) -> bool {
        *v == 0
    }

    // ── Query params ──

    #[derive(Deserialize, Default)]
    struct UserQuery {
        page: Option<u32>,
        #[serde(rename = "pageSize")]
        page_size: Option<u32>,
        q: Option<String>,
    }

    #[derive(Deserialize, Default)]
    struct ClientQuery {
        page: Option<u32>,
        #[serde(rename = "pageSize")]
        page_size: Option<u32>,
        status: Option<String>,
        user: Option<String>,
        #[serde(rename = "clientID")]
        client_id: Option<String>,
        #[serde(rename = "runID")]
        run_id: Option<String>,
        q: Option<String>,
    }

    #[derive(Deserialize, Default)]
    struct ProxyQuery {
        page: Option<u32>,
        #[serde(rename = "pageSize")]
        page_size: Option<u32>,
        status: Option<String>,
        #[serde(rename = "type")]
        proxy_type: Option<String>,
        user: Option<String>,
        #[serde(rename = "clientID")]
        client_id: Option<String>,
        q: Option<String>,
    }

    #[derive(Deserialize, Default)]
    struct PruneQuery {
        #[serde(rename = "type")]
        prune_type: Option<String>,
    }

    /// Request body for `PUT /api/v2/proxy/{name}/update`.
    ///
    /// Only the server-side hot-applicable fields are honoured
    /// (`bandwidthLimit` / `bandwidthLimitMode`). The remaining fields are
    /// declared so that supplying them yields an explicit 400 ("requires frpc
    /// reload") instead of being silently ignored.
    #[derive(Deserialize, Default)]
    struct UpdateProxyRequest {
        /// Bandwidth limit (Go frp format, e.g. "1MB"). Hot-applied: enforced
        /// on subsequently established bridges.
        #[serde(rename = "bandwidthLimit")]
        bandwidth_limit: Option<String>,
        /// "server", "client" or "". Only "server" makes the server enforce
        /// the limit (Go frp semantics).
        #[serde(rename = "bandwidthLimitMode")]
        bandwidth_limit_mode: Option<String>,
        // ── Provider-dependent fields (rejected with 400) ──
        #[serde(rename = "localIP")]
        local_ip: Option<String>,
        #[serde(rename = "localPort")]
        local_port: Option<u16>,
        #[serde(rename = "remotePort")]
        remote_port: Option<u16>,
        #[serde(rename = "customDomains")]
        custom_domains: Option<Vec<String>>,
        #[serde(rename = "useEncryption")]
        use_encryption: Option<bool>,
        #[serde(rename = "useCompression")]
        use_compression: Option<bool>,
    }

    // ── Pagination / filtering helpers ──

    /// Go `parseV2PageParams` / `parseV2PositiveInt`.
    fn parse_page(
        p: Option<u32>,
        ps: Option<u32>,
    ) -> Result<(u32, u32), (StatusCode, Json<V2Error>)> {
        let page = match p {
            Some(v) if v >= 1 => v,
            Some(_) => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "page must be a positive integer",
                ));
            }
            None => DEFAULT_PAGE,
        };
        let size = match ps {
            Some(v) if v >= 1 => v,
            Some(_) => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "pageSize must be a positive integer",
                ));
            }
            None => DEFAULT_PAGE_SIZE,
        };
        if size > MAX_PAGE_SIZE {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!("pageSize must be between 1 and {MAX_PAGE_SIZE}"),
            ));
        }
        Ok((page, size))
    }

    /// Go `buildV2PageResp` / `paginateV2Items`.
    /// Resolve a proxy's owning client identifier the way Go v0.70.0 does:
    /// the client's configured clientID if set, otherwise its run_id.
    fn resolved_client_id(state: &Arc<AppState>, run_id: &str) -> String {
        state
            .client_registry
            .get_by_run_id(run_id)
            .map(|i| i.client_id().to_string())
            .unwrap_or_else(|| run_id.to_string())
    }

    fn paginate<T: Serialize>(mut items: Vec<T>, page: u32, page_size: u32) -> PageResp<T> {
        let total = items.len();
        let start = ((page as usize).saturating_sub(1)).saturating_mul(page_size as usize);
        let items = if start >= total {
            Vec::new()
        } else {
            let end = (start + page_size as usize).min(total);
            items.drain(start..end).collect()
        };
        PageResp {
            total,
            page,
            page_size,
            items,
        }
    }

    /// Go `matchV2StatusFilter`.
    fn match_status(online: bool, filter: &str) -> bool {
        match filter {
            "" | "all" => true,
            "online" => online,
            "offline" => !online,
            _ => true,
        }
    }

    /// Case-insensitive substring search over a set of values (Go `containsV2Query`).
    fn contains_query(q: &str, values: &[String]) -> bool {
        let q = q.to_lowercase();
        values.iter().any(|v| v.to_lowercase().contains(&q))
    }

    fn validate_type(t: &str) -> Result<(), (StatusCode, Json<V2Error>)> {
        if t.is_empty() || VALID_TYPES.contains(&t) {
            Ok(())
        } else {
            Err(err(
                StatusCode::BAD_REQUEST,
                "type must be one of tcp, udp, http, https, tcpmux, stcp, xtcp, sudp",
            ))
        }
    }

    fn validate_status(s: &str) -> Result<(), (StatusCode, Json<V2Error>)> {
        match s {
            "" | "all" | "online" | "offline" => Ok(()),
            _ => Err(err(
                StatusCode::BAD_REQUEST,
                "status must be one of all, online, offline",
            )),
        }
    }

    /// Percent-decode a URL-encoded path segment (Go `decodeV2PathParam`).
    fn percent_decode_path(s: &str) -> Result<String, (StatusCode, Json<V2Error>)> {
        let mut out = String::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if i + 2 < bytes.len() => {
                    let hi = hex_nibble(bytes[i + 1]);
                    let lo = hex_nibble(bytes[i + 2]);
                    if let (Some(h), Some(l)) = (hi, lo) {
                        out.push((h << 4 | l) as char);
                        i += 3;
                    } else {
                        return Err(err(StatusCode::BAD_REQUEST, "invalid percent-encoding"));
                    }
                }
                b'+' => {
                    out.push(' ');
                    i += 1;
                }
                b => {
                    out.push(b as char);
                    i += 1;
                }
            }
        }
        Ok(out)
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'A'..=b'F' => Some(b - b'A' + 10),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }

    /// Format a Unix timestamp (seconds) as YYYY-MM-DD.
    /// Civil-from-days algorithm (http://howardhinnant.github.io/date_algorithms.html).
    fn format_date_ymd(ts_secs: i64) -> String {
        if ts_secs <= 0 {
            return String::new();
        }
        let days = ts_secs / 86400;
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u32; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = (yoe as i64) + (era * 400);
        let doy = doe as i64 - (365 * yoe as i64 + yoe as i64 / 4 - yoe as i64 / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{:04}-{:02}-{:02}", y, m, d)
    }

    /// Go `buildV2ProxyBaseSpec` (transport always present, loadBalancer always
    /// present — Go has no `omitempty` on those).
    fn proxy_base_spec(info: &crate::proxy::ProxyInfo) -> ProxyBaseSpec {
        ProxyBaseSpec {
            transport: Some(ProxyTransport {
                use_encryption: info.use_encryption,
                use_compression: info.use_compression,
                bandwidth_limit: info.bandwidth_limit.clone(),
                bandwidth_limit_mode: info.bandwidth_limit_mode.clone(),
            }),
            load_balancer: Some(LoadBalancer {
                group: info.group.clone().unwrap_or_default(),
            }),
        }
    }

    /// Go `buildV2ProxySpec`.
    fn proxy_spec(info: &crate::proxy::ProxyInfo) -> ProxySpec {
        match info.proxy_type.as_str() {
            "tcp" => ProxySpec {
                proxy_type: "tcp".into(),
                tcp: Some(TcpUdpSpec {
                    base: proxy_base_spec(info),
                    remote_port: info.remote_port,
                }),
                ..Default::default()
            },
            "udp" => ProxySpec {
                proxy_type: "udp".into(),
                udp: Some(TcpUdpSpec {
                    base: proxy_base_spec(info),
                    remote_port: info.remote_port,
                }),
                ..Default::default()
            },
            "http" => ProxySpec {
                proxy_type: "http".into(),
                http: Some(HttpSpec {
                    base: proxy_base_spec(info),
                    custom_domains: info.custom_domains.clone(),
                    subdomain: String::new(),
                    locations: Vec::new(),
                    host_header_rewrite: String::new(),
                }),
                ..Default::default()
            },
            "https" => ProxySpec {
                proxy_type: "https".into(),
                https: Some(HttpsSpec {
                    base: proxy_base_spec(info),
                    custom_domains: info.custom_domains.clone(),
                    subdomain: String::new(),
                }),
                ..Default::default()
            },
            "tcpmux" => ProxySpec {
                proxy_type: "tcpmux".into(),
                tcpmux: Some(TcpMuxSpec {
                    base: proxy_base_spec(info),
                    custom_domains: info.custom_domains.clone(),
                    subdomain: String::new(),
                    multiplexer: info.multiplexer.clone(),
                    route_by_http_user: info.route_by_http_user.clone(),
                }),
                ..Default::default()
            },
            "stcp" => ProxySpec {
                proxy_type: "stcp".into(),
                stcp: Some(BaseOnlySpec {
                    base: proxy_base_spec(info),
                }),
                ..Default::default()
            },
            "sudp" => ProxySpec {
                proxy_type: "sudp".into(),
                sudp: Some(BaseOnlySpec {
                    base: proxy_base_spec(info),
                }),
                ..Default::default()
            },
            "xtcp" => ProxySpec {
                proxy_type: "xtcp".into(),
                xtcp: Some(BaseOnlySpec {
                    base: proxy_base_spec(info),
                }),
                ..Default::default()
            },
            other => ProxySpec {
                proxy_type: other.to_string(),
                ..Default::default()
            },
        }
    }

    // ── Handlers ──

    /// GET /api/v2/config — sanitized server configuration.
    ///
    /// No secrets are returned: the auth section carries only the method name
    /// and the dashboard section omits the password.
    async fn handle_v2_config(
        State(state): State<Arc<AppState>>,
        dashboard_addr: String,
        auth_user: String,
        enable_prometheus: bool,
    ) -> Json<ConfigResp> {
        let snap = &state.server_config_snapshot;
        // std::sync::RwLock (poison-tolerant read) — no await needed.
        let method = state
            .reloadable
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .auth_cfg
            .method
            .clone();
        let method = match method {
            frp_core::auth::AuthMethod::Token => "token",
            #[cfg(feature = "oidc")]
            frp_core::auth::AuthMethod::Oidc => "oidc",
        }
        .to_string();

        let (dash_addr, dash_port) = dashboard_addr
            .rsplit_once(':')
            .map(|(a, p)| (a.to_string(), p.parse().unwrap_or(0)))
            .unwrap_or_else(|| (dashboard_addr.clone(), 0));

        Json(ConfigResp {
            version: frp_core::VERSION.to_string(),
            bind_addr: state.proxy_bind_addr.clone(),
            bind_port: snap.bind_port,
            vhost_http_port: snap.vhost_http_port,
            vhost_https_port: snap.vhost_https_port,
            subdomain_host: snap.subdomain_host.clone(),
            max_ports_per_client: snap.max_ports_per_client,
            heartbeat_timeout: snap.heartbeat_timeout,
            allow_ports_str: snap.allow_ports_str.clone(),
            tls_force: snap.tls_force,
            dashboard: DashboardConfigResp {
                addr: dash_addr,
                port: dash_port,
                user: auth_user,
                enable_prometheus,
            },
            auth: AuthConfigResp { method },
        })
    }

    /// PUT /api/v2/proxy/{name}/update — hot-update a live proxy's
    /// server-side runtime settings.
    ///
    /// Path note: Go frp v0.70.0 (and dev) have NO proxy-update endpoint —
    /// verified against `server/api_router.go`, whose v2 proxy routes use the
    /// plural `/api/v2/proxies/{name}`. This handler follows the
    /// audit-specified path `/api/v2/proxy/{name}/update` (singular `proxy`,
    /// PUT) and returns the updated proxy detail in the Go `V2ProxyResp`
    /// shape. Route ambiguity between `/api/v2/proxies` (plural) and this
    /// route is avoided because the update path is a distinct suffix.
    ///
    /// Semantics: only server-side hot-applicable fields are honoured
    /// (bandwidth limits, enforced on subsequently established bridges).
    /// Fields that depend on the frpc-side provider (local_ip/local_port,
    /// remote_port, custom_domains, use_encryption/use_compression) are
    /// rejected with 400 and an explanation that an frpc config change +
    /// reload is required.
    async fn handle_proxy_update(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
        V2JsonBody(req): V2JsonBody<UpdateProxyRequest>,
    ) -> Result<Json<ProxyResp>, (StatusCode, Json<V2Error>)> {
        let name = percent_decode_path(&name)?;

        let provider_field = req.local_ip.is_some()
            || req.local_port.is_some()
            || req.remote_port.is_some()
            || req.custom_domains.is_some()
            || req.use_encryption.is_some()
            || req.use_compression.is_some();
        // Note: provider-field and empty-body checks run BEFORE the 404
        // pre-check below, so an update against an unknown proxy with
        // provider fields yields 400 (shape error) rather than 404 — a
        // deliberate asymmetry from the bandwidth-validation path.
        if provider_field {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "localIP/localPort/remotePort/customDomains/useEncryption/useCompression \
                 depend on the frpc-side provider and cannot be hot-applied on the server; \
                 update the frpc config and reload instead",
            ));
        }
        if req.bandwidth_limit.is_none() && req.bandwidth_limit_mode.is_none() {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "no updatable fields provided (supported: bandwidthLimit, bandwidthLimitMode)",
            ));
        }

        // 404 on unknown proxy first, so a validation error from
        // update_runtime (400) is never masked as not-found.
        if state.proxy_manager.get(&name).await.is_none() {
            return Err(err(StatusCode::NOT_FOUND, "no proxy info found"));
        }
        // Pass the raw Options straight through: update_runtime fills the
        // gaps from the current record inside its write lock, making the
        // read-modify-write atomic across concurrent PUTs.
        state
            .proxy_manager
            .update_runtime(
                &name,
                req.bandwidth_limit.clone(),
                req.bandwidth_limit_mode.clone(),
            )
            .await
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;

        let updated = state
            .proxy_manager
            .get(&name)
            .await
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no proxy info found"))?;
        Ok(Json(build_proxy_resp(&state, &updated).await))
    }

    /// GET /api/v2/system/info — Go `APIV2SystemInfo`.
    async fn handle_system_info(State(state): State<Arc<AppState>>) -> Json<SystemInfoResp> {
        let snap = &state.server_config_snapshot;
        let client_counts = state.run_id_to_ctl_tx.len() as i64;

        let proxies = state.proxy_manager.list().await;
        let mut proxy_type_counts: HashMap<String, i64> = HashMap::new();
        let mut total_traffic_in: i64 = 0;
        let mut total_traffic_out: i64 = 0;
        let mut cur_conns: i64 = 0;
        for p in &proxies {
            *proxy_type_counts.entry(p.proxy_type.clone()).or_insert(0) += 1;
            if let Some(m) = state.proxy_metrics.get(&p.name).await {
                let (tin, tout) = m.daily.snapshot();
                // Go ServerStats: TotalTrafficIn/Out are TodayCount().
                total_traffic_in += tin[0] as i64;
                total_traffic_out += tout[0] as i64;
                cur_conns += m.snapshot().current_conns;
            }
        }

        let config = SystemInfoConfig {
            bind_port: snap.bind_port,
            vhost_http_port: snap.vhost_http_port,
            vhost_https_port: snap.vhost_https_port,
            tcpmux_httpconnect_port: snap.tcpmux_httpconnect_port,
            #[cfg(feature = "kcp")]
            kcp_bind_port: snap.kcp_bind_port,
            #[cfg(feature = "quic")]
            quic_bind_port: snap.quic_bind_port,
            subdomain_host: snap.subdomain_host.clone(),
            max_pool_count: snap.max_pool_count,
            max_ports_per_client: snap.max_ports_per_client,
            heartbeat_timeout: snap.heartbeat_timeout,
            allow_ports_str: snap.allow_ports_str.clone(),
            tls_force: snap.tls_force,
        };

        Json(SystemInfoResp {
            version: frp_core::VERSION.to_string(),
            config,
            status: SystemInfoStatus {
                total_traffic_in,
                total_traffic_out,
                cur_conns,
                client_counts,
                proxy_type_counts,
            },
        })
    }

    /// POST /api/v2/system/prune — Go `APIV2SystemPrune`.
    async fn handle_system_prune(
        State(state): State<Arc<AppState>>,
        Query(q): Query<PruneQuery>,
    ) -> Result<Json<SystemPruneResp>, (StatusCode, Json<V2Error>)> {
        let prune_type = q.prune_type.clone().unwrap_or_default();
        if prune_type.is_empty() {
            return Err(err(StatusCode::BAD_REQUEST, "type is required"));
        }
        if prune_type != "offline_proxies" {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "type must be one of offline_proxies",
            ));
        }
        let (cleared, total) = prune_offline_stats(&state).await;
        Ok(Json(SystemPruneResp {
            prune_type,
            cleared,
            total,
        }))
    }

    /// GET /api/v2/users — Go `APIV2UserList`.
    async fn handle_users(
        State(state): State<Arc<AppState>>,
        Query(q): Query<UserQuery>,
    ) -> Result<Json<PageResp<UserResp>>, (StatusCode, Json<V2Error>)> {
        let (page, size) = parse_page(q.page, q.page_size)?;

        // Go: iterate client registry (online AND offline) for clientCount,
        // then proxy stats for proxyCount.
        let registry = state.client_registry.list();
        let proxies = state.proxy_manager.list().await;
        let mut user_map: HashMap<String, UserResp> = HashMap::new();
        for info in &registry {
            let user = info.user.clone();
            let e = user_map.entry(user.clone()).or_insert_with(|| UserResp {
                user: user.clone(),
                client_count: 0,
                proxy_count: 0,
            });
            e.client_count += 1;
        }
        for p in &proxies {
            let user = p.user.clone();
            let e = user_map.entry(user.clone()).or_insert_with(|| UserResp {
                user: user.clone(),
                client_count: 0,
                proxy_count: 0,
            });
            e.proxy_count += 1;
        }

        let mut items: Vec<UserResp> = user_map.into_values().collect();
        items.sort_by(|a, b| a.user.cmp(&b.user));
        if let Some(ref search) = q.q {
            let s = search.to_lowercase();
            items.retain(|u| u.user.to_lowercase().contains(&s));
        }
        Ok(Json(paginate(items, page, size)))
    }

    /// GET /api/v2/clients — Go `APIV2ClientList`.
    async fn handle_clients(
        State(state): State<Arc<AppState>>,
        Query(q): Query<ClientQuery>,
    ) -> Result<Json<PageResp<ClientEntry>>, (StatusCode, Json<V2Error>)> {
        let (page, size) = parse_page(q.page, q.page_size)?;
        validate_status(q.status.as_deref().unwrap_or(""))?;

        let mut items = Vec::new();
        for info in state.client_registry.list() {
            if let Some(ref u) = q.user {
                if !u.is_empty() && info.user != u.as_str() {
                    continue;
                }
            }
            if let Some(ref cid) = q.client_id {
                if !cid.is_empty() && info.client_id() != cid.as_str() {
                    continue;
                }
            }
            if let Some(ref rid) = q.run_id {
                if !rid.is_empty() && info.run_id != rid.as_str() {
                    continue;
                }
            }
            if !match_status(info.online, q.status.as_deref().unwrap_or("")) {
                continue;
            }
            let entry = ClientEntry::from_info(&info);
            if let Some(ref search) = q.q {
                let hay = [
                    entry.key.clone(),
                    entry.user.clone(),
                    entry.client_id.clone(),
                    entry.run_id.clone(),
                    entry.version.clone(),
                    entry.wire_protocol.clone(),
                    entry.hostname.clone(),
                    entry.client_ip.clone(),
                ];
                if !contains_query(search, &hay) {
                    continue;
                }
            }
            items.push(entry);
        }

        // Go: sort by (User, ClientID, Key).
        items.sort_by(|a, b| {
            a.user
                .cmp(&b.user)
                .then_with(|| a.client_id.cmp(&b.client_id))
                .then_with(|| a.key.cmp(&b.key))
        });
        Ok(Json(paginate(items, page, size)))
    }

    /// GET /api/v2/clients/{key} — Go `APIV2ClientDetail`.
    async fn handle_client_detail(
        State(state): State<Arc<AppState>>,
        Path(key): Path<String>,
    ) -> Result<Json<ClientDetailResp>, (StatusCode, Json<V2Error>)> {
        let key = percent_decode_path(&key)?;

        // Go looks up by composite key `{user}.{clientID}`. As a frp-rs
        // compatibility extension we also accept a bare run_id.
        let info = state
            .client_registry
            .get_by_key(&key)
            .or_else(|| {
                state
                    .client_registry
                    .list()
                    .into_iter()
                    .find(|i| i.run_id == key)
            })
            .ok_or_else(|| err(StatusCode::NOT_FOUND, format!("client {key} not found")))?;

        let (cur_conns, proxy_count) = if info.online && !info.run_id.is_empty() {
            let proxies = state.proxy_manager.list_client(&info.run_id).await;
            let mut cur_conns = 0i64;
            for p in &proxies {
                if let Some(m) = state.proxy_metrics.get(&p.name).await {
                    cur_conns += m.snapshot().current_conns;
                }
            }
            (cur_conns, proxies.len() as i64)
        } else {
            // Offline clients: frp-rs removes a client's proxies and their
            // stats on disconnect (data-model difference vs Go, which keeps
            // residual stats until pruning), so counts are 0.
            (0, 0)
        };

        Ok(Json(ClientDetailResp {
            info: ClientEntry::from_info(&info),
            status: ClientStatus {
                phase: if info.online { "online" } else { "offline" }.into(),
                cur_conns,
                proxy_count,
            },
        }))
    }

    /// GET /api/v2/proxies — Go `APIV2ProxyList`.
    async fn handle_proxies(
        State(state): State<Arc<AppState>>,
        Query(q): Query<ProxyQuery>,
    ) -> Result<Json<PageResp<ProxyResp>>, (StatusCode, Json<V2Error>)> {
        let (page, size) = parse_page(q.page, q.page_size)?;
        validate_status(q.status.as_deref().unwrap_or(""))?;
        validate_type(q.proxy_type.as_deref().unwrap_or(""))?;

        let all = state.proxy_manager.list().await;
        let mut items = Vec::new();
        for p in &all {
            if let Some(ref pt) = q.proxy_type {
                if p.proxy_type != pt.as_str() {
                    continue;
                }
            }
            let online = state.run_id_to_ctl_tx.contains_key(&p.run_id);
            if !match_status(online, q.status.as_deref().unwrap_or("")) {
                continue;
            }
            if let Some(ref u) = q.user {
                if !u.is_empty() && p.user != u.as_str() {
                    continue;
                }
            }
            if let Some(ref cid) = q.client_id {
                if !cid.is_empty() && cid != resolved_client_id(&state, &p.run_id).as_str() {
                    continue;
                }
            }

            let spec = proxy_spec(p);
            let (today_in, today_out, cur_conns) = state
                .proxy_metrics
                .get(&p.name)
                .await
                .map(|m| {
                    let s = m.snapshot();
                    let (tin, tout) = m.daily.snapshot();
                    (tin[0], tout[0], s.current_conns)
                })
                .unwrap_or((0, 0, 0));

            let resp = ProxyResp {
                name: p.name.clone(),
                user: p.user.clone(),
                client_id: resolved_client_id(&state, &p.run_id),
                spec,
                status: ProxyStatus {
                    phase: if online { "online" } else { "offline" }.into(),
                    today_traffic_in: today_in,
                    today_traffic_out: today_out,
                    cur_conns,
                    last_start_at: 0,
                    last_close_at: 0,
                },
            };

            // Go matchV2ProxyQuery: name, type, user, clientID, state, plus
            // remotePort (tcp/udp) and customDomains/subdomain (http/https/tcpmux).
            if let Some(ref search) = q.q {
                let mut hay = vec![
                    resp.name.clone(),
                    resp.spec.proxy_type.clone(),
                    resp.user.clone(),
                    resp.client_id.clone(),
                    resp.status.phase.clone(),
                ];
                hay.extend(p.custom_domains.iter().cloned());
                if let Some(port) = p.remote_port {
                    hay.push(port.to_string());
                }
                if !contains_query(search, &hay) {
                    continue;
                }
            }

            items.push(resp);
        }

        // Go: sort by (Spec.Type, Name).
        items.sort_by(|a, b| {
            a.spec
                .proxy_type
                .cmp(&b.spec.proxy_type)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(Json(paginate(items, page, size)))
    }

    /// Go `buildV2ProxyResp` — build the detail response for a proxy.
    async fn build_proxy_resp(state: &Arc<AppState>, p: &crate::proxy::ProxyInfo) -> ProxyResp {
        let online = state.run_id_to_ctl_tx.contains_key(&p.run_id);
        let (today_in, today_out, cur_conns) = state
            .proxy_metrics
            .get(&p.name)
            .await
            .map(|m| {
                let s = m.snapshot();
                let (tin, tout) = m.daily.snapshot();
                (tin[0], tout[0], s.current_conns)
            })
            .unwrap_or((0, 0, 0));

        ProxyResp {
            name: p.name.clone(),
            user: p.user.clone(),
            client_id: resolved_client_id(state, &p.run_id),
            spec: proxy_spec(p),
            status: ProxyStatus {
                phase: if online { "online" } else { "offline" }.into(),
                today_traffic_in: today_in,
                today_traffic_out: today_out,
                cur_conns,
                last_start_at: 0,
                last_close_at: 0,
            },
        }
    }

    /// GET /api/v2/proxies/{name} — Go `APIV2ProxyDetail`.
    async fn handle_proxy_detail(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
    ) -> Result<Json<ProxyResp>, (StatusCode, Json<V2Error>)> {
        let name = percent_decode_path(&name)?;

        let p = state
            .proxy_manager
            .get(&name)
            .await
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no proxy info found"))?;

        Ok(Json(build_proxy_resp(&state, &p).await))
    }

    /// GET /api/v2/proxies/{name}/traffic — Go `APIV2ProxyTraffic`.
    async fn handle_proxy_traffic(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
    ) -> Result<Json<ProxyTrafficResp>, (StatusCode, Json<V2Error>)> {
        let name = percent_decode_path(&name)?;

        let p = state
            .proxy_manager
            .get(&name)
            .await
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no proxy info found"))?;

        let history = if let Some(m) = state.proxy_metrics.get(&p.name).await {
            let (tin, tout) = m.daily.snapshot();
            let today_secs = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            // Go buildV2ProxyTrafficResp: iterate age from oldest (6) to today
            // (0), so history is oldest → newest.
            (0..TRAFFIC_DAYS)
                .map(|i| {
                    let age = (TRAFFIC_DAYS - 1 - i) as i64;
                    TrafficPoint {
                        date: format_date_ymd(today_secs - age * 86400),
                        traffic_in: tin[age as usize] as i64,
                        traffic_out: tout[age as usize] as i64,
                    }
                })
                .collect()
        } else {
            // Go parity: a proxy without metrics still reports 7 zero points
            // (one per day), not an empty list.
            let today_secs = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            (0..TRAFFIC_DAYS)
                .map(|i| {
                    let age = (TRAFFIC_DAYS - 1 - i) as i64;
                    TrafficPoint {
                        date: format_date_ymd(today_secs - age * 86400),
                        traffic_in: 0,
                        traffic_out: 0,
                    }
                })
                .collect()
        };

        Ok(Json(ProxyTrafficResp {
            name: p.name.clone(),
            unit: "bytes".into(),
            granularity: "day".into(),
            history,
        }))
    }

    // ── Prune (shared with the periodic background task) ──

    /// Prune statistics for offline proxies.
    ///
    /// Go frp v0.70.0 `mem.StatsCollector.PruneOfflineProxies()` clears the
    /// *stats records* of proxies that are currently offline; it does not
    /// touch live proxy registrations. frp-rs removes a proxy's metrics when
    /// it closes, so this is a defensive sweep of any residual stats for
    /// proxies whose client is no longer connected.
    ///
    /// Returns `(cleared, total)` mirroring Go's response shape.
    pub(super) async fn prune_offline_stats(state: &Arc<AppState>) -> (usize, usize) {
        let all = state.proxy_manager.list().await;
        let total = all.len();
        let mut cleared = 0usize;
        for p in &all {
            if !state.run_id_to_ctl_tx.contains_key(&p.run_id) {
                state.proxy_metrics.remove(&p.name).await;
                cleared += 1;
            }
        }
        (cleared, total)
    }

    // ── Route registration ──

    /// Register v2 API routes (Go frp v0.70.0 compat + audit-specified
    /// `/api/v2/config` and `/api/v2/proxy/{name}/update`).
    ///
    /// `dashboard_addr` / `auth_user` are the configured `[webServer]`
    /// listen address and user, injected into `GET /api/v2/config` (they are
    /// not stored in `AppState`).
    pub(super) fn v2_routes(
        dashboard_addr: String,
        auth_user: String,
        enable_prometheus: bool,
    ) -> Router<Arc<AppState>> {
        let config_handler = {
            let addr = dashboard_addr.clone();
            let user = auth_user.clone();
            move |State(state): State<Arc<AppState>>| {
                handle_v2_config(State(state), addr.clone(), user.clone(), enable_prometheus)
            }
        };
        Router::new()
            .route("/api/v2/system/info", get(handle_system_info))
            .route("/api/v2/system/prune", post(handle_system_prune))
            .route("/api/v2/users", get(handle_users))
            .route("/api/v2/clients", get(handle_clients))
            .route("/api/v2/clients/{key}", get(handle_client_detail))
            .route("/api/v2/proxies", get(handle_proxies))
            .route("/api/v2/proxies/{name}", get(handle_proxy_detail))
            .route("/api/v2/proxies/{name}/traffic", get(handle_proxy_traffic))
            // Audit-specified endpoints (not present in Go frp; see the
            // handler doc comments for shape notes).
            .route("/api/v2/config", get(config_handler))
            .route("/api/v2/proxy/{name}/update", put(handle_proxy_update))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use axum::extract::FromRequest as _;

        fn test_state() -> Arc<AppState> {
            let cfg = frp_core::config::ServerConfig::default();
            Arc::new(AppState::new(
                frp_core::auth::AuthConfig::with_token("test-token"),
                "127.0.0.1".into(),
                frp_core::encryption::derive_key("test-token"),
                vec![frp_core::config::PortsRange {
                    start: 1,
                    end: u16::MAX,
                    single: 0,
                }],
                String::new(),
                true,
                30,
                7200,
                0,
                0,
                90,
                1500,
                false,
                None,
                0,
                60,
                10,
                false,
                String::new(),
                Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
                0,
                0,
                168,
                true,
                0,
                0,
                frp_core::config::ServerConfigSnapshot::from_config(&cfg),
            ))
        }

        fn proxy_info(name: &str, proxy_type: &str) -> crate::proxy::ProxyInfo {
            crate::proxy::ProxyInfo {
                name: name.into(),
                proxy_type: proxy_type.into(),
                run_id: "run-1".into(),
                control_id: 0,
                remote_port: Some(10001),
                sk: None,
                group: None,
                group_key: None,
                local_addr: Some("127.0.0.1:80".into()),
                use_encryption: false,
                use_compression: false,
                virtual_net: None,
                allow_users: Vec::new(),
                proxy_protocol_version: String::new(),
                response_headers: HashMap::new(),
                custom_domains: Vec::new(),
                route_by_http_user: String::new(),
                multiplexer: String::new(),
                bandwidth_limit: String::new(),
                bandwidth_limit_mode: String::new(),
                user: String::new(),
                user_conn_sem: None,
                udp_packet_codec: String::new(),
            }
        }

        /// Serialize a handler response to JSON for leak assertions.
        fn to_json<T: Serialize>(v: &T) -> serde_json::Value {
            serde_json::to_value(v).unwrap()
        }

        /// Unwrap the `Err` side of a handler result, panicking on success
        /// (avoids a `Debug` bound on the `Ok` type for `expect_err`).
        fn expect_err<T, E>(r: Result<T, E>, msg: &str) -> E {
            match r {
                Err(e) => e,
                Ok(_) => panic!("{msg}"),
            }
        }

        #[tokio::test]
        async fn test_v2_config_is_sanitized() {
            let state = test_state();
            let resp = handle_v2_config(
                State(state.clone()),
                "127.0.0.1:7500".to_string(),
                "admin".to_string(),
                true,
            )
            .await;
            assert_eq!(resp.bind_port, 7000, "default bind port");
            assert_eq!(resp.version, frp_core::VERSION);
            assert_eq!(resp.dashboard.port, 7500);
            assert_eq!(resp.dashboard.user, "admin");
            assert!(resp.dashboard.enable_prometheus);
            assert_eq!(resp.auth.method, "token");

            // Secret material must never be present in the serialized config.
            let json = to_json(&resp.0);
            let s = serde_json::to_string(&json).unwrap().to_lowercase();
            assert!(!s.contains("test-token"), "auth token leaked: {s}");
            assert!(
                !s.contains("\"token\":"),
                "token field must not be serialized"
            );
            assert!(
                !s.contains("password"),
                "dashboard password field must not be serialized"
            );
        }

        #[tokio::test]
        async fn test_proxy_update_applies_bandwidth_limit() {
            let state = test_state();
            state
                .proxy_manager
                .register("run-1".into(), proxy_info("p1", "tcp"))
                .await
                .unwrap();

            let req = UpdateProxyRequest {
                bandwidth_limit: Some("2MB".into()),
                bandwidth_limit_mode: Some("server".into()),
                ..Default::default()
            };
            let result =
                handle_proxy_update(State(state.clone()), Path("p1".into()), V2JsonBody(req)).await;
            let resp = result.expect("update should succeed");
            assert_eq!(
                resp.0
                    .spec
                    .tcp
                    .as_ref()
                    .unwrap()
                    .base
                    .transport
                    .as_ref()
                    .unwrap()
                    .bandwidth_limit,
                "2MB"
            );
            assert_eq!(
                resp.0
                    .spec
                    .tcp
                    .as_ref()
                    .unwrap()
                    .base
                    .transport
                    .as_ref()
                    .unwrap()
                    .bandwidth_limit_mode,
                "server"
            );

            // The stored record must reflect the new value (hot-applied to
            // subsequently established bridges).
            let stored = state.proxy_manager.get("p1").await.unwrap();
            assert_eq!(stored.bandwidth_limit, "2MB");
            assert_eq!(stored.bandwidth_limit_mode, "server");

            // The by_client index must be in sync (list_client sees the new
            // record, not the pre-update clone).
            let clients = state.proxy_manager.list_client("run-1").await;
            let client_proxy = clients
                .into_iter()
                .find(|p| p.name == "p1")
                .expect("p1 present in by_client index");
            assert_eq!(client_proxy.bandwidth_limit, "2MB");
            assert_eq!(client_proxy.bandwidth_limit_mode, "server");
        }

        #[tokio::test]
        async fn test_proxy_update_rejects_provider_dependent_fields() {
            let state = test_state();
            state
                .proxy_manager
                .register("run-1".into(), proxy_info("p1", "tcp"))
                .await
                .unwrap();

            let req = UpdateProxyRequest {
                local_port: Some(8080),
                ..Default::default()
            };
            let (status, json) = expect_err(
                handle_proxy_update(State(state.clone()), Path("p1".into()), V2JsonBody(req)).await,
                "provider-dependent fields must be rejected",
            );
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(
                json.0.error.contains("frpc"),
                "error should mention frpc reload, got: {}",
                json.0.error
            );

            // Nothing changed.
            let stored = state.proxy_manager.get("p1").await.unwrap();
            assert!(stored.bandwidth_limit.is_empty());
        }

        #[tokio::test]
        async fn test_proxy_update_rejects_invalid_bandwidth() {
            let state = test_state();
            state
                .proxy_manager
                .register("run-1".into(), proxy_info("p1", "tcp"))
                .await
                .unwrap();

            let req = UpdateProxyRequest {
                bandwidth_limit: Some("not-a-limit".into()),
                ..Default::default()
            };
            let (status, _) = expect_err(
                handle_proxy_update(State(state.clone()), Path("p1".into()), V2JsonBody(req)).await,
                "invalid bandwidth limit must be rejected",
            );
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_proxy_update_unknown_proxy_returns_not_found() {
            let state = test_state();
            let req = UpdateProxyRequest {
                bandwidth_limit: Some("1MB".into()),
                ..Default::default()
            };
            let (status, _) = expect_err(
                handle_proxy_update(State(state), Path("missing".into()), V2JsonBody(req)).await,
                "unknown proxy must 404",
            );
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_proxy_update_empty_body_rejected() {
            let state = test_state();
            state
                .proxy_manager
                .register("run-1".into(), proxy_info("p1", "tcp"))
                .await
                .unwrap();
            let (status, _) = expect_err(
                handle_proxy_update(
                    State(state),
                    Path("p1".into()),
                    V2JsonBody(UpdateProxyRequest::default()),
                )
                .await,
                "empty update body must be rejected",
            );
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_ws_subscriber_cap_rejects_when_exhausted() {
            // Regression: concurrent /api/events WebSocket connections are
            // capped; once the semaphore is exhausted, further upgrades are
            // rejected with 429 instead of accumulating unboundedly.
            let sem = Arc::new(tokio::sync::Semaphore::new(1));
            let Ok(permit) = try_acquire_ws_permit(&sem) else {
                panic!("first subscriber must acquire a permit");
            };
            let (status, _) = expect_err(
                try_acquire_ws_permit(&sem),
                "cap must reject the second concurrent subscriber",
            );
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            drop(permit);
            if try_acquire_ws_permit(&sem).is_err() {
                panic!("permit released → acquisition succeeds again");
            }
        }

        #[tokio::test]
        async fn test_traffic_events_sweeps_stale_last_values() {
            // Regression: last_values must not grow without bound across
            // proxy churn — entries for proxies that are no longer
            // registered are dropped each tick.
            let state = test_state();
            state
                .proxy_manager
                .register("run-1".into(), proxy_info("p1", "tcp"))
                .await
                .unwrap();
            let metrics = state.proxy_metrics.get_or_create("p1").await;
            metrics.record_traffic(100, 200);

            let (event_tx, mut rx) = tokio::sync::broadcast::channel(64);
            let mut last_values = HashMap::new();
            last_values.insert("gone".into(), MetricsSnapshot::default());
            last_values.insert("p1".into(), MetricsSnapshot::default());

            emit_traffic_events_tick(&state, &event_tx, &mut last_values).await;

            assert!(
                !last_values.contains_key("gone"),
                "stale proxy entry must be swept from last_values"
            );
            let p1 = last_values.get("p1").expect("p1 is tracked");
            assert_eq!(p1.bytes_in, 100);
            assert_eq!(p1.bytes_out, 200);

            let ev = rx.try_recv().expect("changed traffic emits an event");
            match ev {
                crate::event::ServerEvent::Traffic {
                    proxy_name,
                    bytes_in,
                    bytes_out,
                    ..
                } => {
                    assert_eq!(proxy_name, "p1");
                    assert_eq!(bytes_in, 100);
                    assert_eq!(bytes_out, 200);
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_json_body_malformed_returns_generic_422() {
            // Regression: a malformed JSON body must yield a generic 422 that
            // does not leak internal type paths (axum's default rejection
            // embeds e.g. `frp_server::dashboard::StoreProxyConfig`).
            let state = test_state();
            let req = axum::http::Request::builder()
                .method("POST")
                .uri("/api/store/proxies")
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{\"name\": 123"))
                .unwrap();
            let (status, json) = expect_err(
                JsonBody::<StoreProxyConfig>::from_request(req, &state).await,
                "malformed JSON must be rejected",
            );
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(json.0.error, "invalid JSON body");
            assert!(
                !json.0.error.contains("StoreProxyConfig"),
                "rejection must not leak internal type paths"
            );
        }

        #[tokio::test]
        async fn test_json_body_missing_content_type_returns_415() {
            // Audit-fix regression: a request without a JSON Content-Type
            // must be rejected with 415 (axum's MissingJsonContentType), not
            // 422 — and with the same generic, non-leaking body.
            let state = test_state();
            let req = axum::http::Request::builder()
                .method("POST")
                .uri("/api/store/proxies")
                .body(axum::body::Body::from("{\"name\":\"p1\"}"))
                .unwrap();
            let (status, json) = expect_err(
                JsonBody::<StoreProxyConfig>::from_request(req, &state).await,
                "missing content type must be rejected",
            );
            assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(json.0.error, "invalid JSON body");
            assert!(
                !json.0.error.contains("StoreProxyConfig"),
                "rejection must not leak internal type paths"
            );
        }

        #[tokio::test]
        async fn test_json_body_wrong_content_type_returns_415() {
            // Audit-fix regression: a wrong Content-Type is a
            // MissingJsonContentType rejection in axum → 415, not 422.
            let state = test_state();
            let req = axum::http::Request::builder()
                .method("POST")
                .uri("/api/store/proxies")
                .header("content-type", "text/plain")
                .body(axum::body::Body::from("{\"name\":\"p1\"}"))
                .unwrap();
            let (status, json) = expect_err(
                JsonBody::<StoreProxyConfig>::from_request(req, &state).await,
                "wrong content type must be rejected",
            );
            assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(json.0.error, "invalid JSON body");
        }

        #[tokio::test]
        async fn test_v2_json_body_malformed_returns_v2_422() {
            // Audit-fix regression: v2 endpoints must reject malformed JSON
            // with 422 and the V2 error shape ({error}), not the V1
            // ErrorResponse shape.
            let state = test_state();
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v2/proxies/p1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{\"bandwidthLimit\": \"2MB"))
                .unwrap();
            let (status, json) = expect_err(
                V2JsonBody::<UpdateProxyRequest>::from_request(req, &state).await,
                "malformed JSON must be rejected",
            );
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(json.0.error, "invalid JSON body");
        }

        #[tokio::test]
        async fn test_v2_json_body_missing_content_type_returns_415() {
            // Audit-fix regression: the V2 extractor maps a missing
            // Content-Type to 415 like the V1 one.
            let state = test_state();
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v2/proxies/p1")
                .body(axum::body::Body::from("{\"bandwidthLimit\":\"2MB\"}"))
                .unwrap();
            let (status, json) = expect_err(
                V2JsonBody::<UpdateProxyRequest>::from_request(req, &state).await,
                "missing content type must be rejected",
            );
            assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(json.0.error, "invalid JSON body");
        }
    }
}

// --- Dashboard runner ---

/// Start the dashboard web server (V1 + V2 API, metrics, UI).
#[allow(clippy::too_many_arguments)]
pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
    enable_prometheus: bool,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
    assets_dir: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // API routes (auth-protected)
    let api_routes = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/serverinfo", get(handle_serverinfo))
        .route(
            "/api/proxies",
            get(handle_proxies).delete(handle_proxies_delete),
        )
        .route("/api/proxies/{name}", get(handle_proxy_by_name))
        .route("/api/proxy/{type}", get(handle_proxies_by_type))
        .route("/api/proxy/{type}/{name}", get(handle_proxy_by_type_name))
        .route("/api/proxy/{name}/traffic", get(handle_proxy_traffic))
        .route("/api/traffic/{name}", get(handle_proxy_traffic))
        .route("/api/clients", get(handle_clients))
        .route("/api/clients/{run_id}", get(handle_client_detail))
        .route(
            "/api/store/proxies",
            get(handle_store_proxies).post(handle_store_proxy_create),
        )
        .route("/api/store/proxy/{name}", delete(handle_store_proxy_delete))
        .route("/api/events", get(handle_events))
        // v2 API (Go frp v0.70.0 compat): paginated, filterable, searchable endpoints
        .merge(v2::v2_routes(
            addr.clone(),
            auth_user.clone(),
            enable_prometheus,
        ));

    let api_routes = apply_admin_auth(api_routes, &auth_user, &auth_password);

    // /metrics: gated behind enable_prometheus (Go frp compat).
    // Returns 404 when disabled. When dashboard auth is configured,
    // /metrics also requires Basic auth.
    let state_for_metrics = state.clone();
    let metrics_route = Router::new().route(
        "/metrics",
        get(move || {
            let state = state_for_metrics.clone();
            async move {
                crate::metrics::prom::sync_from_state(&state).await;
                crate::metrics::prom::render_metrics_text()
            }
        }),
    );
    let metrics_route = apply_admin_auth(metrics_route, &auth_user, &auth_password);

    let mut app = Router::new()
        // Go compat (server.go:125-129): /healthz and /debug/pprof are
        // OUTSIDE auth; / and /static are inside (api_router.go).
        .route("/healthz", get(handle_healthz))
        .route("/debug/pprof", get(handle_pprof_index))
        .route("/debug/pprof/{*path}", get(handle_pprof))
        .merge(api_routes);
    if enable_prometheus {
        app = app.merge(metrics_route);
    }
    // Dashboard root (and any future /static assets) require auth, matching
    // Go: the web UI is only reachable with the configured credentials.
    let root_handler = {
        // Read the custom page once at startup (Go loads assetsDir at
        // startup too); the handler serves the cached string.
        let page = load_dashboard_page(&assets_dir);
        move || {
            let page = page.clone();
            async move { handle_root(&page).await }
        }
    };
    let protected = Router::new().route("/", get(root_handler));
    let protected = apply_admin_auth(protected, &auth_user, &auth_password);
    app = app.merge(protected);
    // Spawn periodic traffic event broadcaster for WebSocket subscribers.
    // Clone state before it's moved into .with_state().
    let traffic_state = state.clone();
    tokio::spawn(async move {
        run_traffic_events(traffic_state).await;
    });

    // Background task: periodically prune stats for offline proxies.
    // Go frp v0.70.0 runs this sweep every 12h
    // (server/metrics/mem/server.go runUntil → clearUselessInfo(7*24h)).
    let prune_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let (cleared, total) = v2::prune_offline_stats(&prune_state).await;
            if cleared > 0 {
                tracing::debug!(
                    cleared = cleared,
                    total = total,
                    "Dashboard: pruned stats for offline proxies"
                );
            }
        }
    });

    // Apply security headers middleware (P2-2). Uses axum::middleware::from_fn
    // so it operates on Response, not handler return types — won't break tests.
    let app = app.layer(middleware::from_fn(add_security_headers));

    let app = app.with_state(state);

    // Security: when no admin auth is configured, force binding to localhost
    // to prevent unauthenticated access to the dashboard and /metrics endpoint.
    let bind_addr = if auth_user.is_empty() || auth_password.is_empty() {
        let localhost_addr = format!("127.0.0.1:{}", addr.rsplit(':').next().unwrap_or("7500"));
        tracing::warn!(
            original = %addr,
            bind = %localhost_addr,
            "Dashboard: no admin auth configured — binding to {} (localhost only) to prevent unauthenticated public access. Set [webServer].user and [webServer].password to expose on a public interface.",
            localhost_addr
        );
        localhost_addr
    } else {
        addr.clone()
    };

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    match (tls_cert_file, tls_key_file) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            #[cfg(feature = "tls")]
            {
                let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
                tracing::info!(addr = %bind_addr, "Dashboard listening on {} (TLS)", bind_addr);
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
            tracing::info!(addr = %bind_addr, "Dashboard listening on {}", bind_addr);
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod cleanup_deleted_proxy_port_tests {
    use super::*;
    use crate::control::proxy_ops::unregister_generation_tests::{proxy_info, test_state};

    /// Finding-1 symmetry (review round 1): deleting a proxy that never
    /// consumed a port (http/https/tcpmux/stcp/xtcp register with
    /// remote_port Some(0)) must not decrement client_ports_used — the
    /// increment side is gated on `tcp|udp|sudp && port > 0`, so the
    /// dashboard delete must mirror it. Before the fix, repeated deletes of
    /// non-consuming proxies drove the shared budget counter down while live
    /// tcp/udp proxies still consumed ports, letting the max_ports_per_client
    /// gate undercount.
    #[tokio::test]
    async fn delete_non_port_consuming_proxy_keeps_client_count() {
        let state = test_state();
        // A tcp proxy consumes a port, so it is counted once.
        let tcp = proxy_info("p-tcp", "tcp", "run-1", Some(6000), 1);
        state
            .proxy_manager
            .register("run-1".to_string(), tcp.clone())
            .await
            .unwrap();
        state
            .client_ports_used
            .write()
            .await
            .insert("run-1".to_string(), 1);

        // Deleting an http proxy (remote_port Some(0)) must not decrement.
        let http = proxy_info("p-http", "http", "run-1", Some(0), 1);
        cleanup_deleted_proxy_port(&state, &http).await;
        assert_eq!(
            state.client_ports_used.read().await.get("run-1"),
            Some(&1),
            "deleting a non-port-consuming proxy must not touch the budget count"
        );

        // Deleting the tcp proxy returns the counter to zero and removes it.
        cleanup_deleted_proxy_port(&state, &tcp).await;
        assert!(
            state.client_ports_used.read().await.get("run-1").is_none(),
            "deleting the last port-consuming proxy must clear the count"
        );
    }

    /// Finding-2 symmetry (review round 1): deleting one SUDP proxy of a
    /// pair sharing a port must keep the port mark (the sibling still holds
    /// the bound socket — an early release makes the next SUDP
    /// registration's bind probe fail EADDRINUSE); deleting the last owner
    /// frees it.
    #[tokio::test]
    async fn delete_sudp_proxy_keeps_shared_port_mark_until_last_owner() {
        let state = test_state();
        let p1 = proxy_info("p-sudp1", "sudp", "run-1", Some(7000), 1);
        let p2 = proxy_info("p-sudp2", "sudp", "run-1", Some(7000), 1);
        state
            .proxy_manager
            .register("run-1".to_string(), p1.clone())
            .await
            .unwrap();
        state
            .proxy_manager
            .register("run-1".to_string(), p2.clone())
            .await
            .unwrap();
        state.used_udp_ports.write().await.insert(7000);

        cleanup_deleted_proxy_port(&state, &p1).await;
        assert!(
            state.used_udp_ports.read().await.contains(&7000),
            "shared SUDP mark must survive while a sibling holds the socket"
        );

        // Mirror the handler's full sequence: cleanup runs while the deleted
        // proxy is still registered, then the proxy is removed (the owner
        // check must no longer see it).
        assert!(state.proxy_manager.remove("p-sudp1").await);
        cleanup_deleted_proxy_port(&state, &p2).await;
        assert!(
            !state.used_udp_ports.read().await.contains(&7000),
            "last SUDP owner delete must release the mark"
        );
    }
}
