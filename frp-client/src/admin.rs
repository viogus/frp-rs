#![cfg(feature = "admin")]

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, RawQuery, State},
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
    /// Go frp compat: "store" when the proxy comes from the file-backed
    /// store (client/http/model status source field).
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
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
    /// frp-rs's CLI sends the camelCase spelling (`strictConfig`,
    /// `frpc/src/main.rs run_reload`); the documented JSON form and the tests
    /// use snake_case. Accept both so the CLI's flag is not silently ignored.
    #[serde(alias = "strictConfig")]
    strict_config: Option<bool>,
}

/// Go's `net/url` default maximum URL query parameter count.
///
/// `parseQuery` (`net/url/url.go:1019-1020` in go1.25.12 — the line numbers
/// drift between Go releases, `:979-980` in the go1.27.1 toolchain installed
/// here) opens with
/// `if !urlParamsWithinMax(strings.Count(query, "&") + 1) { return Values{}, err }`,
/// where `defaultMaxParams = 10000` (`:1001` in go1.25.12, `:961` in go1.27.1)
/// and `urlParamsWithinMax(n) = n <= defaultMaxParams` (`:1003` in go1.25.12,
/// `:963` in go1.27.1) — the limit is
/// **inclusive** and the count is `&`s + 1 (so an empty query is one
/// parameter). `URL.Query()` discards the returned error together with the
/// empty `Values`, so an over-limit query leaves `Get("strictConfig")` at `""`
/// — a non-strict reload.
///
/// Measured on the shipped Go frp v0.71.0 binary with `?strictConfig=true`
/// plus N `&`: N=9999 (10000 parameters) -> 400 strict, N=10000 (10001
/// parameters) -> 200 non-strict. frp-rs had no guard, so it was strict for
/// both.
///
/// Precision: this guard is present in **go1.25.12**, the toolchain that built
/// the shipped v0.71.0 binary, and **absent in go1.25.0** — it is a 1.25.x
/// backport, not a 1.25.0 feature (two successful fetches of
/// `net/url/url.go`: 0 hits for `defaultMaxParams` on go1.25.0, 2 on
/// go1.25.12). It is also GODEBUG-gated: `urlmaxqueryparams`
/// (`:998` in go1.25.12, `:958` in go1.27.1) can raise the limit, or set it
/// to `0` for unlimited. The parity target is therefore the shipped binary's
/// default, not "Go in general".
const GO_DEFAULT_MAX_PARAMS: usize = 10000;

/// Go's strict-mode query channel, reimplemented the way Go reads it.
///
/// `client/http/controller.go` (commit 4a23aa18) calls
/// `r.URL.Query().Get("strictConfig")`. `URL.Query()` runs `url.ParseQuery`
/// and **discards** its error; `parseQuery` drops only the pair it could not
/// unescape and keeps the rest, and `Values.Get` returns the **first** value
/// of a repeated key. Parsing the raw string here keeps those rules explicit:
///
/// * `?strictConfig=true&strictConfig=false` -> `"true"` (first wins). This is
///   the observed defect: deserializing into a struct made axum's `Query`
///   reject the repeated field with serde's `duplicate_field` error, so the
///   handler never ran and the request answered 400 where Go reloads.
/// * `?strictConfig=%zz` -> the pair is skipped, so the parameter is *absent*.
///   For a **body-less** request that is the same non-strict answer the old
///   extractor gave (`form_urlencoded` left the invalid escape literal, which
///   `ParseBool` then rejected), so the parser is not a fix there — it
///   replaces reliance on that incidental leniency with Go's documented rules,
///   pinned against real `net/url` below. With a **JSON body** it *is* a
///   behaviour change: the parameter is now absent, so the body fallback
///   applies and `{"strict_config": true}` can select strict mode, whereas the
///   old extractor kept the key present and ignored the body.
///
/// ## `#` in the request target (known divergence, not fixable here)
///
/// Go parses request URIs with `viaRequest=true`, which never splits a
/// fragment (`net/url/url.go`: the only cut is `strings.Cut(rest, "?")`), so a
/// `#` stays inside `RawQuery`. Both manifestations differ from frp-rs:
///
/// * `GET /api/reload?strictConfig=true#strictConfig=false` — Go's value is
///   `true#strictConfig=false`, which `ParseBool` rejects, so Go reloads
///   **non-strict (200)**; frp-rs's fragment is dropped, so it reads
///   `strictConfig=true` and is **strict (400)**.
/// * `GET /api/reload#x?strictConfig=true` — Go's path is `/api/reload#x`,
///   which matches no route (**404**); frp-rs's fragment is dropped and the
///   request reloads (**200**).
///
/// This is unrecoverable at this layer: `RawQuery` comes from `http::Uri`,
/// whose parser truncates the target at the first `#`
/// (`http-1.5.0/src/uri/path.rs:28-29`:
/// `if let Some(i) = fragment { src.truncate(i as usize); }`), and that
/// truncation happens inside hyper's request-line parsing, before any frp-rs
/// code runs. Recovering the raw target would mean replacing the HTTP stack.
/// Both manifestations are pinned as documented divergences in
/// `frp-client/tests/reload_malformed_config.rs` and described for users in
/// `docs/deployment.md`.
///
/// Returns the first `strictConfig` value, or `None` when no pair carries it.
fn first_strict_config_param(raw_query: Option<&str>) -> Option<String> {
    let raw = raw_query?;
    // Go's parameter-count guard, before any pair is looked at: `parseQuery`
    // returns early with its error and leaves `Values` EMPTY, and `URL.Query()`
    // discards that error, so *every* parameter -- including `strictConfig` --
    // is absent. `None` follows the same "parameter absent" path as the `%zz`
    // case below, so the frp-rs JSON-body extension still applies when a body
    // is present (Go reads no body at all, so the body channel is a frp-rs
    // extension either way).
    if raw.matches('&').count() + 1 > GO_DEFAULT_MAX_PARAMS {
        return None;
    }
    for segment in raw.split('&') {
        // Go: an empty segment is skipped; a segment containing ';' is a
        // parse error since Go 1.17, so the pair is dropped.
        if segment.is_empty() || segment.contains(';') {
            continue;
        }
        let (key, value) = match segment.split_once('=') {
            Some((k, v)) => (k, v),
            None => (segment, ""),
        };
        let (Ok(key), Ok(value)) = (query_unescape(key), query_unescape(value)) else {
            continue;
        };
        if key == "strictConfig" {
            return Some(value);
        }
    }
    None
}

/// Go `url.QueryUnescape`: `+` -> space, `%XX` -> byte, and an invalid escape
/// is an error (the caller drops that pair). Go does not validate UTF-8 here;
/// the result is only ever compared against the ASCII `ParseBool` set, so a
/// lossy decode of invalid bytes cannot change the strict decision.
fn query_unescape(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(());
                }
                let hi = hex_digit(bytes[i + 1]).ok_or(())?;
                let lo = hex_digit(bytes[i + 2]).ok_or(())?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Mirror Go's `strconv.ParseBool` accept set (https://pkg.go.dev/strconv#ParseBool)
/// with the error handling Go's `Reload` handler applies: it discards the parse
/// error (`strictConfigMode, _ = strconv.ParseBool(strictStr)`,
/// `client/http/controller.go` at commit 4a23aa18), so an unrecognised value --
/// including the empty string an absent/empty parameter yields -- is `false`,
/// never a 400. Only `1 t T TRUE true True` select strict mode.
fn parse_strict_config(s: &str) -> bool {
    matches!(s, "1" | "t" | "T" | "TRUE" | "true" | "True")
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
        let source = match &state.store {
            Some(store) if store.get_proxy(name).is_some() => Some("store".to_string()),
            _ => None,
        };
        let entry = ProxyStatusEntry {
            name: name.clone(),
            proxy_type: info.proxy_type.clone(),
            status: status.into(),
            local_addr: info.local_addr.clone(),
            remote_addr: info.remote_addr.clone(),
            plugin: info.plugin.clone(),
            err: info.err.clone(),
            source,
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
    RawQuery(raw_query): RawQuery,
    body: Bytes,
) -> Result<String, (StatusCode, String)> {
    // Read the optional body FIRST, whichever method was used: a body that is
    // present but not well-formed JSON must be a 400 on every method. Go reads
    // no body at all (`ctx.Body()` is never called by `Reload`); the body is a
    // frp-rs extension kept for frpc's own CLI (`frpc/src/main.rs run_reload`).
    let body_strict = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<ReloadBody>(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?
            .strict_config
    };

    // Precedence: an explicit `?strictConfig=...` wins over the JSON body.
    // Go's handler only ever reads the query (`client/http/controller.go` at
    // commit 4a23aa18), so the query is the Go-faithful source when the two
    // disagree; the CLI sends the body and no query, so in practice the
    // channels never conflict. With neither present the reload is non-strict,
    // matching Go's absent/empty parameter. The raw string goes through
    // `first_strict_config_param` so a repeated parameter takes the first
    // value and a malformed escape drops only its own pair -- both like Go.
    let strict = match first_strict_config_param(raw_query.as_deref()) {
        Some(v) => parse_strict_config(&v),
        None => body_strict.unwrap_or(false),
    };
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
    let value = serde_json::to_value(proxy).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize proxy: {e}"),
        )
    })?;
    Ok(redact_json_sensitive(value))
}

fn visitor_to_json(visitor: &VisitorConfig) -> Result<serde_json::Value, (StatusCode, String)> {
    let value = serde_json::to_value(visitor).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize visitor: {e}"),
        )
    })?;
    Ok(redact_json_sensitive(value))
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

/// Go frp compat: GET /api/proxy/{name}/config — returns the proxy config
/// from the file-backed store when present, else from the config file.
async fn handle_get_proxy_config(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "proxy name is required".into()));
    }
    if let Some(store) = &state.store {
        if let Some(proxy) = store.get_proxy(&name) {
            return Ok(Json(proxy_to_json(&proxy)?));
        }
    }
    let cfg = config_from_file(&state)?;
    if let Some(p) = cfg.proxies.iter().find(|p| p.name == name) {
        return Ok(Json(proxy_to_json(p)?));
    }
    Err((StatusCode::NOT_FOUND, format!("proxy {name:?} not found")))
}

/// Go frp compat: GET /api/visitor/{name}/config.
async fn handle_get_visitor_config(
    State(state): State<AdminState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "visitor name is required".into()));
    }
    if let Some(store) = &state.store {
        if let Some(visitor) = store.get_visitor(&name) {
            return Ok(Json(visitor_to_json(&visitor)?));
        }
    }
    let cfg = config_from_file(&state)?;
    if let Some(v) = cfg.visitors.iter().find(|v| v.name == name) {
        return Ok(Json(visitor_to_json(v)?));
    }
    Err((StatusCode::NOT_FOUND, format!("visitor {name:?} not found")))
}

/// Load the client config from the stored config path.
fn config_from_file(
    state: &AdminState,
) -> Result<frp_core::config::ClientConfig, (StatusCode, String)> {
    let path = state
        .config_path
        .as_ref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no config file path stored".into()))?;
    frp_core::config::load_client_config(path, false).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load config: {e}"),
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

    // Atomic write: write to a temp file in the same directory then rename,
    // so a crash mid-write cannot leave the config file truncated/corrupted
    // (plain fs::write would truncate in place first).
    let tmp_path = {
        let mut tmp = std::path::Path::new(path).as_os_str().to_os_string();
        tmp.push(".admin.tmp");
        std::path::PathBuf::from(tmp)
    };
    std::fs::write(&tmp_path, &body).map_err(|e| {
        tracing::error!(path = %tmp_path.display(), error = %e, "Failed to write config temp file: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to write config file".into(),
        )
    })?;
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        tracing::error!(path = %path, error = %e, "Failed to atomically replace config file: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to write config file".into(),
        ));
    }
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
                .unwrap_or_else(|e| e.into_inner())
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

/// Explicit HEAD handler for every admin `GET` route.
///
/// axum serves HEAD through the `get` handler
/// (`axum-0.8.9/src/routing/method_routing.rs:1157-1158`:
/// `call!(req, HEAD, head); call!(req, HEAD, get);`), so without this, HEAD on
/// an admin GET route runs the GET handler. Go's admin router matches methods
/// exactly and answers `405` for every registered GET route — the shipped
/// v0.71.0 binary was measured 405 on `HEAD /api/status`, `HEAD /api/reload`,
/// `HEAD /api/config`, `HEAD /api/proxy/{name}/config` and
/// `HEAD /api/visitor/{name}/config` (with existing names; GET on those two
/// routes is 200 on both).
///
/// The `/api/reload` case is not cosmetic: the GET handler *reloads the
/// config*, so a HEAD there was a real, unrequested side effect, and with
/// `?strictConfig=true` the reload is strict. Measured on the pre-change tree:
/// with a config that strict mode rejects (the tests' unknown-key oracle) the
/// HEAD answered **400**; with a valid config the strict reload succeeded and
/// it answered **200**. Go answers 405 either way.
async fn handle_head_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

/// The frpc admin route table.
///
/// Split out of [`run_admin_server`] so tests can drive the same route table
/// the server serves, including the per-route HEAD handlers below.
/// `store_enabled` mirrors `state.store.is_some()`.
///
/// Every route that registers `get(...)` also registers
/// `.head(handle_head_not_allowed)`. An *unconditional* HEAD-rejection layer
/// was rejected on measurement, not on the axum docs (`Router::layer` is often
/// read as applying only to existing routes, which does not mean unmatched
/// paths skip it — measured, they do not):
///
/// * such a layer OUTERMOST (before auth) answers 405 for
///   `HEAD /api/nonexistent`, where Go answers 404 — a new divergence;
/// * such a layer INNERMOST (inside the auth layer) lets auth win on a matched
///   path, so an unauthenticated `HEAD /api/reload` would be 401 — the very
///   divergence such a layer was meant to avoid. Go answers 405 with *and*
///   without credentials: its router resolves path+method before auth
///   (measured: `HEAD /api/reload` 405 both ways, `HEAD /api/nonexistent` 404
///   both ways, while an unauthenticated `GET /api/reload` is 401).
///
/// Per-route `.head(...)` introduces no new divergence: it changes only HEAD
/// on a *registered* admin GET route (405 instead of 200/400/...) and, for a
/// request the auth layer admits (valid credentials, or no auth configured),
/// keeps axum's natural 404 for an unknown path, matching Go.
///
/// Residual, pre-existing and NOT changed here: frp-rs applies the auth
/// middleware to the whole router before the method router runs, so an
/// *unauthenticated* HEAD on a registered route is still 401 where Go is 405
/// (measured on both with `webServer.user`/`password` set); an unauthenticated
/// request to an unknown path is likewise 401 here where Go is 404, for GET as
/// well as HEAD. Those requests are already 401 today.
///
/// Matching Go on those cells is reachable, and was measured, but is NOT
/// adopted here — and not because the `HEAD` cell is unmatchable. An earlier
/// review round built `.route_layer(auth)` (which on its own fixes the two
/// unknown-path cells, because middleware added that way runs only when a route
/// matches — axum `axum-0.8.9/src/docs/routing/route_layer.md`) plus a
/// *route-aware* outermost HEAD layer. A later adversarial review measured a
/// per-handler construction C instead, which reaches Go's `HEAD` cell with
/// **no** route introspection and no path list: auth on the registered GET/POST
/// handlers, the existing unauthenticated `handle_head_not_allowed` left on
/// each route's `.head(...)`, and an auth-wrapped `Router::fallback`. C answers
/// 405 for an unauthenticated HEAD on a registered route while keeping
/// unmatched paths at 401. It is not adopted because:
///
/// 1. C makes auth opt-in per route: a route added later without the wrapper is
///    unauthenticated by default, whereas the single outer layer authenticates
///    every route, present and future, by default. Closing that fail-open
///    foot-gun (a wrapping helper plus a test that every registered route
///    answers 401 unauthenticated) is the first requirement of any future fix.
/// 2. The unknown-path 401 is deliberate and permanent: authenticating only
///    matched routes (`route_layer`, or C's fallback left off) would answer 404
///    there and reveal which paths and methods exist. Reviewer 2 measured the
///    sharper form: an unauthenticated `GET /api/store/proxies` answers 401 when
///    the store is enabled and 404 when it is not, disclosing *configuration
///    state*, not merely path existence. This repo already deviates from Go for
///    security elsewhere: a wildcard/unspecified `web_server.addr` is forced to
///    `127.0.0.1` regardless of auth, and an explicit non-loopback address is
///    honoured only when auth is set.
/// 3. A *blanket* switch of `apply_admin_auth` to `route_layer` is out of scope:
///    the helper is shared (`frp-core/src/admin_auth.rs:36`), called from this
///    file and from `frp-server/src/dashboard.rs:3656/3672/3696`, so it would
///    change the frps dashboard too. C is admin-local and leaves the helper and
///    the dashboard alone.
///
/// The rule is applied uniformly to `/api/metrics` and the `/api/store/*`
/// routes too. `/api/metrics` is the genuinely frp-rs-only one: Go v0.71.0's
/// client admin has no such route at all (404 for GET and HEAD — measured), so
/// no Go parity is claimed for it. The `/api/store/*` routes are **not**
/// frp-rs-only: Go ships the same paths and, with `store.path` set, matches this
/// tree after the change — HEAD 405 and OPTIONS 405 on all four, and GET 200 on
/// the two collection routes with 404 on the two `{name}` routes while the store
/// is empty (measured on both). Before the change `main` forwarded HEAD to the
/// GET handler, so with an empty store HEAD answered 200 on the two collection
/// routes and 404 on the two `{name}` routes (measured 200/404/200/404); all
/// four now answer 405, so this change also repairs them. Only the
/// request/response *payload shape* is frp-rs-specific, as `docs/deployment.md`
/// states. POST is unchanged: `frpc/src/main.rs:630-631` sends `POST` with a
/// JSON body (`admin_post_json`), and the comment on the `/api/reload` route
/// documents POST as a deliberate frp-rs extension.
/// `OPTIONS /api/reload` is already 405 on both, and `POST`/`HEAD /api/stop`
/// already agree; only HEAD changes.
fn admin_router(store_enabled: bool) -> Router<AdminState> {
    let app = Router::new()
        .route(
            "/api/status",
            get(handle_status).head(handle_head_not_allowed),
        )
        .route(
            "/api/metrics",
            get(handle_metrics).head(handle_head_not_allowed),
        )
        // Go frp compat: GET /api/reload (Go uses GET; keep POST too).
        .route(
            "/api/reload",
            get(handle_reload)
                .post(handle_reload)
                .head(handle_head_not_allowed),
        )
        .route("/api/stop", axum::routing::post(handle_stop))
        .route(
            "/api/proxy/{name}/config",
            get(handle_get_proxy_config).head(handle_head_not_allowed),
        )
        .route(
            "/api/visitor/{name}/config",
            get(handle_get_visitor_config).head(handle_head_not_allowed),
        )
        .route(
            "/api/config",
            get(handle_get_config)
                .put(handle_put_config)
                .head(handle_head_not_allowed)
                .layer(DefaultBodyLimit::max(1024 * 1024)),
        );

    // Store CRUD uses the Rust-native typed JSON body (full ProxyConfig /
    // VisitorConfig objects). Go frp's admin API registers the same paths and
    // its method behaviour matches this tree (GET 200 on the collections,
    // 404 on `{name}` while empty, HEAD/OPTIONS 405 -- measured), but it uses
    // nested typed blocks (`ProxyDefinition` with tcp/udp/stcp...), so the
    // request/response *payload shape* is frp-rs-specific and is not
    // wire-compatible with a Go admin client.
    if store_enabled {
        app.route(
            "/api/store/proxies",
            get(handle_list_store_proxies)
                .post(handle_create_store_proxy)
                .head(handle_head_not_allowed),
        )
        .route(
            "/api/store/proxies/{name}",
            get(handle_get_store_proxy)
                .put(handle_update_store_proxy)
                .delete(handle_delete_store_proxy)
                .head(handle_head_not_allowed),
        )
        .route(
            "/api/store/visitors",
            get(handle_list_store_visitors)
                .post(handle_create_store_visitor)
                .head(handle_head_not_allowed),
        )
        .route(
            "/api/store/visitors/{name}",
            get(handle_get_store_visitor)
                .put(handle_update_store_visitor)
                .delete(handle_delete_store_visitor)
                .head(handle_head_not_allowed),
        )
    } else {
        app
    }
}

pub async fn run_admin_server(
    addr: String,
    state: AdminState,
    auth_user: String,
    auth_password: String,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = admin_router(state.store.is_some());

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
        // Non-loopback, non-wildcard address explicitly configured. Allow it
        // ONLY when admin auth is configured — without auth, every API
        // endpoint (/api/config read incl. token, PUT config, /api/stop,
        // store CRUD) is open to anyone who can reach the address. Force
        // loopback instead so the exposure cannot happen by misconfiguration.
        if auth_user.is_empty() || auth_password.is_empty() {
            tracing::error!(
                original = %addr,
                bind = %localhost_addr,
                "frpc admin: no admin auth configured — refusing to bind admin API to non-loopback address {}; binding {} (localhost only). Set admin_user and admin_password to bind externally.",
                addr,
                localhost_addr
            );
            localhost_addr
        } else {
            addr.clone()
        }
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
///
/// Includes the camelCase serde aliases (audit finding M10): /api/config
/// serves the raw file parsed as TOML, preserving the user's original key
/// spelling — a Go-style config (`secretKey = ...`, `httpPwd = ...`,
/// `groupKey = ...`, `oidcClientSecret = ...`, `passwd = ...`) used to
/// round-trip its secrets unredacted. Each alias below mirrors a real
/// `#[serde(alias = ...)]` on a credential-bearing field in
/// ProxyConfig/PluginConfig/AuthConfig.
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
    "secret_key",
    // camelCase Go-style spellings (serde aliases of the fields above).
    "secretKey",
    "httpUser",
    "httpPwd",
    "httpPassword",
    "groupKey",
    "oidcClientSecret",
    "passwd",
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

/// Recursively redact sensitive values in JSON (mirror of [`redact_sensitive`]
/// for the serde_json side). Used by the `/api/.../config` and store JSON
/// endpoints so proxy/visitor secrets (`sk`, `http_pwd`, `group_key`,
/// `secret_key`) never leak over the admin API.
fn redact_json_sensitive(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, val) in map {
                let redacted_val = if SENSITIVE_KEYS.contains(&key.as_str()) {
                    serde_json::Value::String("***".into())
                } else {
                    redact_json_sensitive(val)
                };
                redacted.insert(key, redacted_val);
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(redact_json_sensitive).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    #[test]
    fn redact_sensitive_toml_covers_camelcase_go_spellings() {
        // M10 pin: /api/config serves the raw config file preserving the
        // user's key spelling — Go-style camelCase keys must redact like
        // their snake_case twins. Build the TOML through the same
        // parse→redact→serialize path as handle_get_config.
        let raw = r#"
serverAddr = "127.0.0.1"
serverPort = 7000
auth.token = "auth-secret-token"
oidcClientSecret = "oidc-secret"

[[proxies]]
name = "web"
type = "http"
localPort = 8080
secretKey = "stcp-secret"
httpUser = "alice"
httpPwd = "http-secret"
httpPassword = "http-secret-2"
groupKey = "grp-secret"

[[proxies]]
name = "plug"
type = "tcp"
localPort = 8081
[proxies.plugin]
type = "socks5"
user = "socks-user"
passwd = "socks-pass"
"#;
        let value: toml::Value = toml::from_str(raw).unwrap();
        let redacted = redact_sensitive(value);
        let out = toml::to_string(&redacted).unwrap();
        for secret in [
            "auth-secret-token",
            "oidc-secret",
            "stcp-secret",
            "http-secret",
            "http-secret-2",
            "grp-secret",
            "socks-pass",
        ] {
            assert!(
                !out.contains(secret),
                "camelCase/alias secret leaked into redacted config: {secret}"
            );
        }
        // The username is masked too ("user" key), but the plaintext must
        // never survive in any form — check no raw value round-tripped.
        assert!(!out.contains("socks-user"));
        // Non-secret camelCase keys must survive redaction intact.
        assert!(out.contains("serverAddr"));
        assert!(out.contains("localPort"));
    }

    #[test]
    fn parse_strict_config_matches_strconv_parse_bool() {
        // Go's full accept set: `1 t T TRUE true True` -> true,
        // `0 f F FALSE false False` -> false.
        for s in ["1", "t", "T", "TRUE", "true", "True"] {
            assert!(parse_strict_config(s), "ParseBool({s:?}) must be true");
        }
        for s in ["0", "f", "F", "FALSE", "false", "False"] {
            assert!(!parse_strict_config(s), "ParseBool({s:?}) must be false");
        }
        // Everything else is a ParseBool error; Go discards it, so the reload
        // stays non-strict and still answers 200 (never 400).
        for s in ["", "yes", "no", "garbage", "2", "TRue", " true", "true "] {
            assert!(
                !parse_strict_config(s),
                "ParseBool({s:?}) errors -> discarded -> false"
            );
        }
    }

    #[test]
    fn first_strict_config_param_matches_go_url_query() {
        // Cases cross-checked against real Go (`net/url.ParseQuery` +
        // `Values.Get` + `strconv.ParseBool`): the parse error Go discards is
        // reproduced here so the endpoint keeps Go's rules explicitly rather
        // than relying on `form_urlencoded`'s incidental leniency.
        let cases: &[(&str, Option<&str>)] = &[
            // Values.Get takes the first value; order decides, not truthiness.
            ("strictConfig=true&strictConfig=false", Some("true")),
            ("strictConfig=false&strictConfig=true", Some("false")),
            // An un-unescapable pair is dropped, so the parameter is absent
            // (Go: ParseQuery error discarded -> Get("") -> non-strict 200).
            ("strictConfig=%zz", None),
            ("%zz=1&strictConfig=true", Some("true")),
            ("strictConfig=%zz&strictConfig=true", Some("true")),
            ("strictConfig=a;b", None),
            // A bare key is the empty value, not an absent parameter.
            ("strictConfig", Some("")),
            ("strictConfig=", Some("")),
            ("other=1", None),
            ("", None),
            // `+` decodes to space and `%XX` to its byte, as Go does; neither
            // is a ParseBool true spelling.
            ("strictConfig=+%74rue", Some(" true")),
            ("strictConfig=%74rue", Some("true")),
            ("strictConfig=%ff", Some("\u{FFFD}")),
        ];
        for (query, want) in cases {
            let got = first_strict_config_param(Some(query));
            assert_eq!(got.as_deref(), *want, "Go url.Query() on {query:?}");
        }
        assert_eq!(first_strict_config_param(None), None);
        // The %ff value decodes lossily but ParseBool still rejects it.
        assert!(!parse_strict_config(
            &first_strict_config_param(Some("strictConfig=%ff")).unwrap()
        ));
    }

    #[test]
    fn first_strict_config_param_mirrors_go_max_param_guard() {
        // Go `parseQuery` (`net/url/url.go:1019-1020` in go1.25.12 — line
        // numbers drift between Go releases, `:979-980` in go1.27.1):
        //   if !urlParamsWithinMax(strings.Count(query, "&") + 1) { return err }
        // with `defaultMaxParams = 10000` (`:1001` in go1.25.12) and
        // `urlParamsWithinMax(n) = n <= 10000`. The count is `&`s + 1 and the
        // limit is INCLUSIVE, so 9999 `&` (10000 parameters) parses and
        // 10000 `&` (10001) does not.
        // Cross-checked on the shipped Go frp v0.71.0 binary:
        // `?strictConfig=true` + 9999 `&` -> 400 strict; + 10000 `&` -> 200
        // non-strict.
        let at_limit = format!("strictConfig=true{}", "&".repeat(9999));
        assert_eq!(
            first_strict_config_param(Some(&at_limit)).as_deref(),
            Some("true"),
            "10000 parameters is within Go's inclusive limit"
        );
        let over_limit = format!("strictConfig=true{}", "&".repeat(10000));
        assert_eq!(
            first_strict_config_param(Some(&over_limit)),
            None,
            "10001 parameters exceeds Go's limit -> empty Values -> absent"
        );
        // The guard runs before any pair is parsed, so a well-formed
        // `strictConfig` later in an over-limit query is still invisible.
        let over_limit_late = format!("junk{}&strictConfig=true", "&".repeat(10000));
        assert_eq!(first_strict_config_param(Some(&over_limit_late)), None);
        // A trailing empty segment keeps the parameter count at the boundary:
        // 9999 `&` total is still exactly 10000 parameters.
        let at_limit_trailing = format!("strictConfig=true{}&", "&".repeat(9998));
        assert_eq!(
            first_strict_config_param(Some(&at_limit_trailing)).as_deref(),
            Some("true")
        );
    }

    #[tokio::test]
    async fn reload_duplicate_strict_config_takes_first_like_go() {
        // The defect this pins: `Query<ReloadQuery>` (a struct) made axum
        // reject `?strictConfig=a&strictConfig=b` with serde's
        // `duplicate_field` error -> 400 *before* the handler, while Go's
        // `url.Values.Get` reads the first value and reloads. Drive the real
        // handler so the assertion is about HTTP status, not just the helper.
        let (state, mut reload_rx) = test_state();
        let (seen_tx, mut seen_rx) = mpsc::channel::<bool>(8);
        tokio::spawn(async move {
            while let Some(req) = reload_rx.recv().await {
                let _ = seen_tx.send(req.strict).await;
                let _ = req.reply.send(Ok("reload success".into()));
            }
        });
        // Drive the real route table rather than a copy of it, so a change to
        // `admin_router` cannot leave this test exercising a hand-rolled
        // subset.
        let app = admin_router(true).with_state(state);

        // First value wins: true -> strict, even though false follows.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reload?strictConfig=true&strictConfig=false")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "duplicate parameter must not 400 (Go reloads with the first value)"
        );
        assert_eq!(seen_rx.recv().await, Some(true));

        // Order decides, not truthiness: false first -> non-strict.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reload?strictConfig=false&strictConfig=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(seen_rx.recv().await, Some(false));

        // A garbage first value is ParseBool's error case -> non-strict 200,
        // even when a later duplicate says true.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reload?strictConfig=garbage&strictConfig=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(seen_rx.recv().await, Some(false));

        // Go discards ParseQuery's error and keeps the pairs it could
        // unescape: a malformed escape drops only its own pair. These are
        // Go-parity pins, not regression pins -- the old `Query` extractor
        // answered 200 here too (`form_urlencoded` is infallible and lossy);
        // only the repeated-field cases above were a genuine base 400.
        for uri in [
            "/api/reload?strictConfig=%zz",
            "/api/reload?strictConfig=a;b",
        ] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri} must not 400");
            assert_eq!(seen_rx.recv().await, Some(false), "{uri}");
        }
        // A malformed pair elsewhere does not hide a well-formed one.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reload?foo=%zz&strictConfig=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(seen_rx.recv().await, Some(true));

        // A bare key (no `=`) is the empty value -> ParseBool error ->
        // non-strict, not a missing parameter and not a 400.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reload?strictConfig")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(seen_rx.recv().await, Some(false));

        // A pair dropped for a malformed escape makes the parameter *absent*,
        // so the JSON body fallback applies: `%zz` + body true selects strict.
        // This is the second, body-dependent behaviour change — the old
        // extractor kept the key present with the literal "%zz" (-> false) and
        // the body was ignored. Pinned here so the drop is discriminating.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/reload?strictConfig=%zz")
                    .body(Body::from(r#"{"strict_config": true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            seen_rx.recv().await,
            Some(true),
            "a dropped query pair must let the JSON body select strict"
        );
    }

    #[tokio::test]
    async fn reload_over_max_params_flips_strict_decision_like_go() {
        // Handler-level proof that the parameter-count guard changes the
        // DECISION, not just the helper's return value: the fake reload
        // channel reports the `strict` flag the run loop would have received.
        let (state, mut reload_rx) = test_state();
        let (seen_tx, mut seen_rx) = mpsc::channel::<bool>(8);
        tokio::spawn(async move {
            while let Some(req) = reload_rx.recv().await {
                let _ = seen_tx.send(req.strict).await;
                let _ = req.reply.send(Ok("reload success".into()));
            }
        });
        let app = admin_router(true).with_state(state);

        // 9999 `&` = 10000 parameters: within Go's inclusive limit -> the
        // parameter is read -> strict.
        let uri = format!("/api/reload?strictConfig=true{}", "&".repeat(9999));
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            seen_rx.recv().await,
            Some(true),
            "10000 parameters is within Go's limit, so ?strictConfig=true is read"
        );

        // 10000 `&` = 10001 parameters: Go's guard trips and the discarded
        // error leaves `Values` empty -> parameter absent -> non-strict.
        let uri = format!("/api/reload?strictConfig=true{}", "&".repeat(10000));
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            seen_rx.recv().await,
            Some(false),
            "10001 parameters must trip the guard and reload non-strict"
        );

        // Guard-absent is the same path as the dropped `%zz` pair, so the
        // frp-rs JSON-body extension still applies when a body is present:
        // over-limit query + body true selects strict. (Go reads no body at
        // all, so the body channel is a frp-rs extension either way.)
        let uri = format!("/api/reload?strictConfig=true{}", "&".repeat(10000));
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&uri)
                    .body(Body::from(r#"{"strict_config": true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            seen_rx.recv().await,
            Some(true),
            "an over-limit query is absent, so the JSON body fallback applies"
        );
    }

    #[tokio::test]
    async fn head_on_registered_admin_get_routes_is_405_without_running_the_handler() {
        // axum serves HEAD through the `get` handler
        // (`axum-0.8.9/src/routing/method_routing.rs:1157-1158`), so this
        // drives the REAL route table (`admin_router`) to prove every GET
        // route registers an explicit `.head(...)`.
        //
        // The path list below is hand-maintained: axum 0.8.9 exposes no route
        // introspection (only `has_routes() -> bool`), so a route added to
        // `admin_router` must be added here too. The integration test
        // `admin_head_is_405_and_never_runs_a_get_handler` probes the
        // corresponding live-server routes.
        //
        // No reload-forwarding task is spawned for the HEAD phase on purpose:
        // `reload_rx` stays owned here, and its sender is still alive (`app`
        // holds `reload_tx`), so `TryRecvError::Empty` is the only way the
        // channel can report "nothing was enqueued" — asserting the variant
        // distinguishes that from `Disconnected`.
        let (state, mut reload_rx) = test_state();
        let app = admin_router(true).with_state(state);

        // HEAD on every registered GET route -> 405.
        for path in [
            "/api/status",
            "/api/metrics",
            "/api/reload",
            "/api/reload?strictConfig=true",
            "/api/proxy/p1/config",
            "/api/visitor/v1/config",
            "/api/config",
            "/api/store/proxies",
            "/api/store/proxies/p1",
            "/api/store/visitors",
            "/api/store/visitors/v1",
        ] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::HEAD)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "HEAD {path} must be 405 (never the GET handler)"
            );
        }

        // The proof that the /api/reload GET handler did not run and that the
        // strict query was never even evaluated: no reload request was
        // enqueued. A handler run would have queued one and then waited on the
        // reply oneshot. The explicit `Empty` variant matters — `is_err()` is
        // also true for `Disconnected`, which would prove nothing.
        assert!(
            matches!(reload_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "HEAD /api/reload must not enqueue a reload request (channel must be \
             Empty, not Disconnected)"
        );

        // An unknown path keeps axum's natural 404, matching Go — this is why
        // a blanket router-level HEAD layer was not used.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/api/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Now answer reload requests so the controls can complete.
        let (seen_tx, mut seen_rx) = mpsc::channel::<bool>(8);
        tokio::spawn(async move {
            while let Some(req) = reload_rx.recv().await {
                let _ = seen_tx.send(req.strict).await;
                let _ = req.reply.send(Ok("reload success".into()));
            }
        });

        // GET controls: the routes really are live (not vacuous).
        for path in ["/api/status", "/api/metrics"] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "GET {path} control");
        }

        // POST support is untouched (frpc's CLI sends POST + JSON body).
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/reload")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "POST /api/reload control");
        assert_eq!(seen_rx.recv().await, Some(false));
    }

    #[test]
    fn reload_body_accepts_both_strict_spellings() {
        let snake: ReloadBody = serde_json::from_str(r#"{"strict_config": true}"#).unwrap();
        assert_eq!(snake.strict_config, Some(true));
        // frpc's CLI sends this spelling (frpc/src/main.rs run_reload).
        let camel: ReloadBody = serde_json::from_str(r#"{"strictConfig": true}"#).unwrap();
        assert_eq!(camel.strict_config, Some(true));
        let empty: ReloadBody = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.strict_config, None);
        assert!(serde_json::from_str::<ReloadBody>("{oops").is_err());
    }

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
        // The real route table (store routes included, since `test_state` has a
        // store) rather than a hand-rolled subset.
        admin_router(true).with_state(state)
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

    #[test]
    fn proxy_and_visitor_json_redact_secrets() {
        use frp_core::config::{ProxyConfig, VisitorConfig};
        // A TCP proxy with secret_key/http_pwd/sk set.
        let proxy: ProxyConfig = serde_json::from_value(serde_json::json!({
            "name": "p",
            "type": "stcp",
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "sk": "secret-key-abc",
            "http_pwd": "pw-xyz",
            "group_key": "grp-key"
        }))
        .unwrap();
        let pj = proxy_to_json(&proxy).unwrap();
        assert_eq!(pj["sk"], "***", "proxy sk must be redacted");
        assert_eq!(pj["http_pwd"], "***", "proxy http_pwd must be redacted");
        assert_eq!(pj["group_key"], "***", "proxy group_key must be redacted");
        let pj_str = pj.to_string();
        assert!(
            !pj_str.contains("secret-key-abc") && !pj_str.contains("pw-xyz"),
            "proxy secrets leaked into config JSON: {pj_str}"
        );

        // A visitor with secret_key set.
        let visitor: VisitorConfig = serde_json::from_value(serde_json::json!({
            "name": "v",
            "type": "xtcp",
            "server_name": "s",
            "secret_key": "visitor-secret-key"
        }))
        .unwrap();
        let vj = visitor_to_json(&visitor).unwrap();
        assert_eq!(
            vj["secret_key"], "***",
            "visitor secret_key must be redacted"
        );
        let vj_str = vj.to_string();
        assert!(
            !vj_str.contains("visitor-secret-key"),
            "visitor secret leaked into config JSON: {vj_str}"
        );
    }
}
