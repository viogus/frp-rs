#![cfg(feature = "admin")]

use axum::{
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{header, StatusCode},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

use frp_core::admin_auth::apply_admin_auth;
use frp_core::config::{ProxyConfig, VisitorConfig};
use frp_core::metrics::ProxyMetricsRegistry;

use crate::proxy_runtime::{ProxyRuntimeInfo, ReloadRequest};
use crate::store::{StoreError, StoreSource};

// --- Types ---

#[derive(Serialize)]
struct ProxyStatusEntry {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    status: String,
    local_addr: String,
    remote_addr: String,
    plugin: String,
    err: String,
}

#[derive(Clone)]
pub struct AdminState {
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
    pub proxies: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    pub reload_tx: mpsc::Sender<ReloadRequest>,
    pub stop_tx: mpsc::Sender<()>,
    pub config_path: Option<String>,
    /// Optional file-backed store. When present, `/api/store/*` routes are
    /// registered and CRUD operations trigger a reload after persisting.
    pub store: Option<Arc<StoreSource>>,
}

#[derive(Deserialize)]
struct ReloadBody {
    strict_config: Option<bool>,
}

// --- Handlers ---

/// Escape special characters in a Prometheus label value.
/// Per the exposition format spec, backslash, double-quote, and newline
/// must be escaped with a backslash.
fn prometheus_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

async fn handle_metrics(State(state): State<AdminState>) -> String {
    let proxies = state.proxies.read().await;
    let mut traffic_in = String::new();
    let mut traffic_out = String::new();
    let mut conn_counts = String::new();
    let mut current_conns = String::new();

    for (name, info) in proxies.iter() {
        if let Some(m) = state.proxy_metrics.get(name).await {
            let s = m.snapshot();
            let labels = format!(
                "{{name=\"{}\",type=\"{}\"}}",
                prometheus_escape(name),
                prometheus_escape(&info.proxy_type),
            );
            traffic_in.push_str(&format!("frp_client_traffic_in{} {}\n", labels, s.bytes_in));
            traffic_out.push_str(&format!(
                "frp_client_traffic_out{} {}\n",
                labels, s.bytes_out
            ));
            conn_counts.push_str(&format!(
                "frp_client_connection_counts{} {}\n",
                labels, s.total_conns
            ));
            current_conns.push_str(&format!(
                "frp_client_current_conns{} {}\n",
                labels, s.current_conns
            ));
        }
    }

    let mut out = String::new();
    out.push_str("# HELP frp_client_traffic_in Total inbound traffic bytes per proxy\n");
    out.push_str("# TYPE frp_client_traffic_in gauge\n");
    out.push_str(&traffic_in);
    out.push_str("# HELP frp_client_traffic_out Total outbound traffic bytes per proxy\n");
    out.push_str("# TYPE frp_client_traffic_out gauge\n");
    out.push_str(&traffic_out);
    out.push_str("# HELP frp_client_connection_counts Total connections per proxy\n");
    out.push_str("# TYPE frp_client_connection_counts gauge\n");
    out.push_str(&conn_counts);
    out.push_str("# HELP frp_client_current_conns Current active connections per proxy\n");
    out.push_str("# TYPE frp_client_current_conns gauge\n");
    out.push_str(&current_conns);
    out.push_str("# EOF\n");
    out
}

async fn handle_status(State(state): State<AdminState>) -> Json<serde_json::Value> {
    let proxies = state.proxies.read().await;
    let mut by_type: HashMap<String, Vec<ProxyStatusEntry>> = HashMap::new();

    for (name, info) in proxies.iter() {
        let status = if !info.err.is_empty() {
            "error"
        } else {
            "online"
        };
        let entry = ProxyStatusEntry {
            name: name.clone(),
            proxy_type: info.proxy_type.clone(),
            status: status.into(),
            local_addr: info.local_addr.clone(),
            remote_addr: info.remote_addr.clone(),
            plugin: info.plugin.clone(),
            err: info.err.clone(),
        };
        by_type
            .entry(info.proxy_type.clone())
            .or_default()
            .push(entry);
    }

    // Ensure all known types appear even if empty (Go frp compat)
    for ty in &[
        "tcp", "http", "https", "stcp", "xtcp", "sudp", "udp", "tcpmux",
    ] {
        by_type.entry(ty.to_string()).or_default();
    }

    Json(serde_json::to_value(by_type).unwrap_or_default())
}

async fn handle_reload(
    State(state): State<AdminState>,
    Json(body): Json<ReloadBody>,
) -> Result<String, (StatusCode, String)> {
    let strict = body.strict_config.unwrap_or(false);
    reload_and_wait(&state, strict).await
}

/// Send a reload request to the service run loop and wait for the result.
async fn reload_and_wait(state: &AdminState, strict: bool) -> Result<String, (StatusCode, String)> {
    let (tx, rx) = oneshot::channel();
    let req = ReloadRequest { strict, reply: tx };
    state.reload_tx.send(req).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reload channel closed".into(),
        )
    })?;
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(Ok(summary))) => Ok(summary),
        Ok(Ok(Err(e))) => Err((StatusCode::BAD_REQUEST, e)),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "reload handler disconnected".into(),
        )),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "reload timed out".into())),
    }
}

fn store_to_http_error(err: StoreError) -> (StatusCode, String) {
    match err {
        StoreError::InvalidArgument(msg) => (StatusCode::BAD_REQUEST, msg),
        StoreError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        StoreError::Conflict(msg) => (StatusCode::CONFLICT, msg),
        StoreError::Persist(msg) | StoreError::Load(msg) => {
            (StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
    }
}

fn store_or_error(state: &AdminState) -> Result<Arc<StoreSource>, (StatusCode, String)> {
    state
        .store
        .clone()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "store API is disabled".to_string()))
}

fn proxy_to_json(proxy: &ProxyConfig) -> Result<serde_json::Value, (StatusCode, String)> {
    serde_json::to_value(proxy).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize proxy: {e}"),
        )
    })
}

fn visitor_to_json(visitor: &VisitorConfig) -> Result<serde_json::Value, (StatusCode, String)> {
    serde_json::to_value(visitor).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize visitor: {e}"),
        )
    })
}

async fn handle_list_store_proxies(
    State(state): State<AdminState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = store_or_error(&state)?;
    let proxies: Vec<serde_json::Value> = store
        .all_proxies()
        .iter()
        .map(proxy_to_json)
        .collect::<Result<_, _>>()?;
    Ok(Json(serde_json::json!({ "proxies": proxies })))
}

async fn handle_get_store_proxy(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "proxy name is required".into()));
    }
    let store = store_or_error(&state)?;
    let proxy = store
        .get_proxy(&name)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("proxy {name:?} not found")))?;
    Ok(Json(proxy_to_json(&proxy)?))
}

async fn handle_create_store_proxy(
    State(state): State<AdminState>,
    Json(proxy): Json<ProxyConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = store_or_error(&state)?;
    let created = store.add_proxy(proxy).map_err(store_to_http_error)?;
    reload_and_wait(&state, false).await?;
    Ok(Json(proxy_to_json(&created)?))
}

async fn handle_update_store_proxy(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
    Json(proxy): Json<ProxyConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "proxy name is required".into()));
    }
    if name != proxy.name {
        return Err((
            StatusCode::BAD_REQUEST,
            "proxy name in URL must match name in body".into(),
        ));
    }
    let store = store_or_error(&state)?;
    let updated = store.update_proxy(proxy).map_err(store_to_http_error)?;
    reload_and_wait(&state, false).await?;
    Ok(Json(proxy_to_json(&updated)?))
}

async fn handle_delete_store_proxy(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "proxy name is required".into()));
    }
    let store = store_or_error(&state)?;
    store.remove_proxy(&name).map_err(store_to_http_error)?;
    reload_and_wait(&state, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_list_store_visitors(
    State(state): State<AdminState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = store_or_error(&state)?;
    let visitors: Vec<serde_json::Value> = store
        .all_visitors()
        .iter()
        .map(visitor_to_json)
        .collect::<Result<_, _>>()?;
    Ok(Json(serde_json::json!({ "visitors": visitors })))
}

async fn handle_get_store_visitor(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "visitor name is required".into()));
    }
    let store = store_or_error(&state)?;
    let visitor = store
        .get_visitor(&name)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("visitor {name:?} not found")))?;
    Ok(Json(visitor_to_json(&visitor)?))
}

async fn handle_create_store_visitor(
    State(state): State<AdminState>,
    Json(visitor): Json<VisitorConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = store_or_error(&state)?;
    let created = store.add_visitor(visitor).map_err(store_to_http_error)?;
    reload_and_wait(&state, false).await?;
    Ok(Json(visitor_to_json(&created)?))
}

async fn handle_update_store_visitor(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
    Json(visitor): Json<VisitorConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "visitor name is required".into()));
    }
    if name != visitor.name {
        return Err((
            StatusCode::BAD_REQUEST,
            "visitor name in URL must match name in body".into(),
        ));
    }
    let store = store_or_error(&state)?;
    let updated = store.update_visitor(visitor).map_err(store_to_http_error)?;
    reload_and_wait(&state, false).await?;
    Ok(Json(visitor_to_json(&updated)?))
}

async fn handle_delete_store_visitor(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "visitor name is required".into()));
    }
    let store = store_or_error(&state)?;
    store.remove_visitor(&name).map_err(store_to_http_error)?;
    reload_and_wait(&state, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_stop(State(state): State<AdminState>) -> &'static str {
    let _ = state.stop_tx.try_send(());
    "stop success"
}

async fn handle_get_config(
    State(state): State<AdminState>,
) -> Result<String, (StatusCode, String)> {
    let path = state
        .config_path
        .as_ref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no config file path stored".into()))?;
    let raw = std::fs::read_to_string(path).map_err(|e| {
        tracing::error!(path = %path, error = %e, "Failed to read config file: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to read config file".into(),
        )
    })?;

    // Parse and redact sensitive fields before returning
    let value: toml::Value = toml::from_str(&raw).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid TOML syntax: {e}"),
        )
    })?;
    let redacted = redact_sensitive(value);
    toml::to_string(&redacted).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize config: {e}"),
        )
    })
}

async fn handle_put_config(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Result<&'static str, (StatusCode, String)> {
    // Validate content type — only accept TOML
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.contains("application/toml")
        && !content_type.contains("text/x-toml")
        && !content_type.contains("text/plain")
    {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/toml, text/x-toml, or text/plain".into(),
        ));
    }

    let path = state
        .config_path
        .as_ref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no config file path stored".into()))?;

    // Validate TOML before writing — don't overwrite with invalid config
    let _ = frp_core::config::load_client_config_from_str(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid config: {e}")))?;

    std::fs::write(path, &body).map_err(|e| {
        tracing::error!(path = %path, error = %e, "Failed to write config file: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to write config file".into(),
        )
    })?;
    // Trigger reload after config update
    reload_and_wait(&state, true)
        .await
        .map(|_| "update success")
}

// --- Local TlsListener (moved from frp-core to avoid axum in core) ---

#[cfg(feature = "tls")]
use std::io;
#[cfg(feature = "tls")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "tls")]
use tokio_rustls::server::TlsAcceptor;

/// TLS listener wrapper implementing axum's Listener trait.
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

// --- Server ---

pub async fn run_admin_server(
    addr: String,
    state: AdminState,
    auth_user: String,
    auth_password: String,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/metrics", get(handle_metrics))
        .route("/api/reload", axum::routing::post(handle_reload))
        .route("/api/stop", axum::routing::post(handle_stop))
        .route(
            "/api/config",
            get(handle_get_config)
                .put(handle_put_config)
                .layer(DefaultBodyLimit::max(1024 * 1024)),
        );

    let app = if state.store.is_some() {
        app.route(
            "/api/store/proxies",
            get(handle_list_store_proxies).post(handle_create_store_proxy),
        )
        .route(
            "/api/store/proxies/{name}",
            get(handle_get_store_proxy)
                .put(handle_update_store_proxy)
                .delete(handle_delete_store_proxy),
        )
        .route(
            "/api/store/visitors",
            get(handle_list_store_visitors).post(handle_create_store_visitor),
        )
        .route(
            "/api/store/visitors/{name}",
            get(handle_get_store_visitor)
                .put(handle_update_store_visitor)
                .delete(handle_delete_store_visitor),
        )
    } else {
        app
    };

    let app = apply_admin_auth(app, &auth_user, &auth_password);
    let app = app.with_state(state);

    // Security: always bind to localhost by default, even when auth is configured.
    // The admin API exposes config with tokens, reload, and stop — binding to
    // 0.0.0.0/:: by accident is a serious exposure. Only bind to non-loopback
    // addresses when the user explicitly configured admin_addr to one.
    let default_port = addr.rsplit(':').next().unwrap_or("7400");
    let localhost_addr = format!("127.0.0.1:{}", default_port);

    let bind_addr = if addr.starts_with("127.0.0.1:")
        || addr.starts_with("::1")
        || addr.starts_with("localhost:")
    {
        // Loopback explicitly configured — use as-is.
        addr.clone()
    } else if !addr.starts_with("0.0.0.0:") && !addr.starts_with("[::]:") && !addr.starts_with("::")
    {
        // Non-loopback, non-wildcard address explicitly configured — use as-is.
        addr.clone()
    } else {
        // Wildcard (0.0.0.0 or [::]) or unspecified — force localhost.
        if auth_user.is_empty() || auth_password.is_empty() {
            tracing::warn!(
                original = %addr,
                bind = %localhost_addr,
                "frpc admin: no admin auth configured — binding to {} (localhost only) to prevent unauthenticated public access. Set admin_user and admin_password.",
                localhost_addr
            );
        } else {
            tracing::warn!(
                original = %addr,
                bind = %localhost_addr,
                "frpc admin: binding to {} (localhost only). Set admin_addr to an explicit non-loopback address to bind externally.",
                localhost_addr
            );
        }
        localhost_addr
    };

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    #[cfg(feature = "tls")]
    match (tls_cert_file, tls_key_file) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
            tracing::info!(addr = %bind_addr, "frpc admin server listening on {} (TLS)", bind_addr);
            let tls_listener = TlsListener::new(listener, acceptor);
            axum::serve(tls_listener, app).await?;
        }
        _ => {
            tracing::info!(addr = %bind_addr, "frpc admin server listening on {}", bind_addr);
            axum::serve(listener, app).await?;
        }
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = (&tls_cert_file, &tls_key_file);
        tracing::info!(addr = %bind_addr, "frpc admin server listening on {}", bind_addr);
        axum::serve(listener, app).await?;
    }
    Ok(())
}

// --- Helpers ---

/// Sensitive keys that should be redacted from config responses.
const SENSITIVE_KEYS: &[&str] = &[
    "token",
    "auth_token",
    "privilege_token",
    "http_pwd",
    "http_password",
    "sk",
    "group_key",
    "oidc_client_secret",
    "user",
    "password",
];

/// Recursively redact sensitive values in TOML, returning a copy with
/// sensitive string values replaced by "***".
fn redact_sensitive(value: toml::Value) -> toml::Value {
    match value {
        toml::Value::Table(table) => {
            let mut redacted = toml::map::Map::new();
            for (key, val) in table {
                let redacted_val = if SENSITIVE_KEYS.contains(&key.as_str()) {
                    redact_value(val)
                } else {
                    redact_sensitive(val)
                };
                redacted.insert(key, redacted_val);
            }
            toml::Value::Table(redacted)
        }
        toml::Value::Array(arr) => {
            toml::Value::Array(arr.into_iter().map(redact_sensitive).collect())
        }
        other => other,
    }
}

/// Replace a sensitive value with "***".
fn redact_value(value: toml::Value) -> toml::Value {
    match value {
        toml::Value::String(_) => toml::Value::String("***".into()),
        _ => toml::Value::String("***".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    fn test_state() -> (AdminState, mpsc::Receiver<ReloadRequest>) {
        let path =
            std::env::temp_dir().join(format!("frpc_admin_store_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(StoreSource::new(&path).unwrap());
        let (reload_tx, reload_rx) = mpsc::channel(16);
        let (stop_tx, _stop_rx) = mpsc::channel(1);
        let state = AdminState {
            proxy_metrics: Arc::new(frp_core::metrics::ProxyMetricsRegistry::new()),
            proxies: Arc::new(RwLock::new(HashMap::new())),
            reload_tx,
            stop_tx,
            config_path: None,
            store: Some(store),
        };
        (state, reload_rx)
    }

    fn test_app(state: AdminState) -> Router {
        Router::new()
            .route(
                "/api/store/proxies",
                get(handle_list_store_proxies).post(handle_create_store_proxy),
            )
            .route(
                "/api/store/proxies/{name}",
                get(handle_get_store_proxy)
                    .put(handle_update_store_proxy)
                    .delete(handle_delete_store_proxy),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn store_proxy_crud_round_trip() {
        let (state, mut reload_rx) = test_state();
        // The service run loop is not running in this test; answer reload
        // requests so the handlers can complete.
        tokio::spawn(async move {
            while let Some(req) = reload_rx.recv().await {
                let _ = req
                    .reply
                    .send(Ok("reload success: no changes detected".into()));
            }
        });
        let app = test_app(state);

        let create_body = serde_json::json!({
            "name": "store-proxy",
            "type": "tcp",
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "remote_port": 9090
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/store/proxies")
                    .header("content-type", "application/json")
                    .body(Body::from(create_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(created["name"], "store-proxy");
        assert_eq!(created["remote_port"], 9090);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/store/proxies/store-proxy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let fetched: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(fetched["local_port"], 8080);

        let update_body = serde_json::json!({
            "name": "store-proxy",
            "type": "tcp",
            "local_ip": "127.0.0.1",
            "local_port": 8081,
            "remote_port": 9091
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/store/proxies/store-proxy")
                    .header("content-type", "application/json")
                    .body(Body::from(update_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/store/proxies/store-proxy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/store/proxies/store-proxy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let path =
            std::env::temp_dir().join(format!("frpc_admin_store_{}.json", std::process::id()));
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
        let _ = std::fs::remove_file(path);
    }
}
