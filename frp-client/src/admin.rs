use std::sync::Arc;
use std::collections::HashMap;
use axum::{
    Router, Json,
    extract::{State, Query},
    routing::get,
    http::StatusCode,
};
use serde::Serialize;
use tokio::sync::{mpsc, RwLock, oneshot};

use frp_core::metrics::ProxyMetricsRegistry;
use frp_core::admin_auth::apply_admin_auth;

// Re-export for service.rs
#[derive(Debug, Clone)]
pub struct ProxyRuntimeInfo {
    pub local_addr: String,
    pub proxy_type: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub bandwidth_limit: u64,
    pub bandwidth_limit_mode: String,
}

// --- Types ---

pub struct ReloadRequest {
    pub strict: bool,
    pub reply: oneshot::Sender<Result<String, String>>,
}

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
    pub reload_tx: mpsc::UnboundedSender<ReloadRequest>,
    pub stop_tx: mpsc::UnboundedSender<()>,
    pub config_path: Option<String>,
}

// --- Handlers ---

async fn handle_status(State(state): State<AdminState>) -> Json<serde_json::Value> {
    let proxies = state.proxies.read().await;
    let mut by_type: HashMap<String, Vec<ProxyStatusEntry>> = HashMap::new();

    for (name, info) in proxies.iter() {
        let entry = ProxyStatusEntry {
            name: name.clone(),
            proxy_type: info.proxy_type.clone(),
            status: "online".into(),
            local_addr: info.local_addr.clone(),
            remote_addr: String::new(),
            plugin: String::new(),
            err: String::new(),
        };
        by_type.entry(info.proxy_type.clone()).or_default().push(entry);
    }

    // Ensure all known types appear even if empty (Go frp compat)
    for ty in &["tcp", "http", "https", "stcp", "xtcp", "sudp", "udp", "tcpmux"] {
        by_type.entry(ty.to_string()).or_default();
    }

    Json(serde_json::to_value(by_type).unwrap_or_default())
}

async fn handle_reload(
    State(state): State<AdminState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<String, (StatusCode, String)> {
    let strict = params.get("strictConfig").map(|v| v == "true").unwrap_or(false);
    let (tx, rx) = oneshot::channel();
    let req = ReloadRequest { strict, reply: tx };
    state.reload_tx.send(req).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "reload channel closed".into())
    })?;
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(Ok(summary))) => Ok(summary),
        Ok(Ok(Err(e))) => Err((StatusCode::BAD_REQUEST, e)),
        Ok(Err(_)) => Err((StatusCode::INTERNAL_SERVER_ERROR, "reload handler disconnected".into())),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "reload timed out".into())),
    }
}

async fn handle_stop(State(state): State<AdminState>) -> &'static str {
    let _ = state.stop_tx.send(());
    "stop success"
}

async fn handle_get_config(State(state): State<AdminState>) -> Result<String, (StatusCode, String)> {
    let path = state.config_path.as_ref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no config file path stored".into()))?;
    let raw = std::fs::read_to_string(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("read config: {e}")))?;

    // Parse and redact sensitive fields before returning
    let value: toml::Value = toml::from_str(&raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("parse config: {e}")))?;
    let redacted = redact_sensitive(value);
    toml::to_string(&redacted)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize config: {e}")))
}

async fn handle_put_config(
    State(state): State<AdminState>,
    body: String,
) -> Result<&'static str, (StatusCode, String)> {
    let path = state.config_path.as_ref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no config file path stored".into()))?;

    // Validate TOML before writing — don't overwrite with invalid config
    let _ = frp_core::config::load_client_config_from_str(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid config: {e}")))?;

    std::fs::write(path, &body)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("write config: {e}")))?;
    // Trigger reload after config update
    let (tx, rx) = oneshot::channel();
    let req = ReloadRequest { strict: false, reply: tx };
    state.reload_tx.send(req).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "reload channel closed".into())
    })?;
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(_)) => Ok("update success"),
        Ok(Err(e)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "reload timed out".into())),
    }
}

// --- Server ---

pub async fn run_admin_server(
    addr: String,
    state: AdminState,
    auth_user: String,
    auth_password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/reload", get(handle_reload))
        .route("/api/stop", axum::routing::post(handle_stop))
        .route("/api/config", get(handle_get_config).put(handle_put_config));

    let app = apply_admin_auth(app, &auth_user, &auth_password);
    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("frpc admin server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

// --- Helpers ---

/// Sensitive keys that should be redacted from config responses.
const SENSITIVE_KEYS: &[&str] = &[
    "token", "privilege_token",
    "http_pwd", "http_password",
    "sk", "group_key",
    "oidc_client_secret",
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
