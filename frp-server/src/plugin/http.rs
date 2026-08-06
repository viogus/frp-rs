use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;
use http::HeaderValue;
use serde::Deserialize;
use serde::Serialize;

use frp_core::config::HttpPluginConfig;

/// Go frp v0.70.1 compat: pkg/plugin/server API version.
const PLUGIN_API_VERSION: &str = "0.1.0";

/// Map Rust snake_case op names to the Go wire names (pkg/plugin/server/manager.go).
/// Unknown ops pass through unchanged.
fn go_op_name(op: &str) -> String {
    match op {
        "login" => "Login".to_string(),
        "new_proxy" => "NewProxy".to_string(),
        "close_proxy" => "CloseProxy".to_string(),
        "ping" => "Ping".to_string(),
        "new_work_conn" => "NewWorkConn".to_string(),
        "new_user_conn" => "NewUserConn".to_string(),
        // Unknown ops pass through unchanged (call sites use a fixed set).
        other => other.to_string(),
    }
}

/// JSON payload sent to plugin servers on lifecycle events (Go wire shape:
/// `{"version":"0.1.0","op":"Login","content":{...}}`).
#[derive(Serialize)]
struct PluginEvent {
    version: &'static str,
    op: String,
    content: serde_json::Value,
}

/// Expected JSON response from a plugin server (Go `Response`):
/// `{"reject":false,"unchange":true,"rejectReason":"","content":{...}}`.
#[derive(Deserialize, Default)]
struct PluginResponse {
    /// When true, reject the operation.
    #[serde(default)]
    reject: bool,
    /// Human-readable reason for rejection (Go: rejectReason).
    #[serde(default, alias = "rejectReason", alias = "reject_reason")]
    reject_reason: String,
    /// When false, the plugin replaced `content` (mutation).
    #[serde(default)]
    unchange: bool,
    /// Mutated content (Go: `content`).
    #[serde(default)]
    content: serde_json::Value,
}

/// Manages a collection of HTTP plugin servers.
///
/// On lifecycle events (login, new_proxy, close_proxy), notifies
/// matching plugins via HTTP POST. Plugins with `enable_control: true`
/// can approve or reject operations.
pub struct HttpPluginManager {
    plugins: Arc<Vec<PluginDef>>,
}

struct PluginDef {
    cfg: HttpPluginConfig,
    /// HTTP client honoring the plugin's TLS verify setting
    /// (Go http.go: InsecureSkipVerify: !options.TLSVerify).
    client: frp_core::http_client::HttpClient,
}

impl HttpPluginManager {
    /// Create a new manager from plugin configs.
    pub fn new(configs: Vec<HttpPluginConfig>) -> Self {
        // Per-plugin timeout is enforced by tokio::time::timeout below.
        // No client-level timeout — the tokio wrapper covers connect + full
        // request lifecycle and respects per-plugin timeout config.
        let client = frp_core::http_client::HttpClientBuilder::new()
            .build()
            .unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to build default HTTP plugin client: {e}. \
                     HTTP plugin notifications will be unavailable."
                );
                // Build a client that will fail every request (no valid TLS).
                // Using skip-verify here would silently downgrade security.
                frp_core::http_client::HttpClientBuilder::new()
                    .build()
                    .expect("HTTP plugin client retry")
            });
        let plugins = configs
            .into_iter()
            .map(|cfg| {
                let client = if cfg.url.starts_with("https://") && !cfg.tls_verify {
                    // Go compat: tlsVerify=false → InsecureSkipVerify.
                    frp_core::http_client::HttpClientBuilder::new()
                        .tls_skip_verify(true)
                        .build()
                        .unwrap_or_else(|e| {
                            tracing::warn!(
                                plugin_name = %cfg.name,
                                error = %e,
                                "Failed to build insecure HTTP plugin client, falling back to default"
                            );
                            client.clone()
                        })
                } else {
                    client.clone()
                };
                PluginDef { cfg, client }
            })
            .collect();
        Self {
            plugins: Arc::new(plugins),
        }
    }

    /// True when no plugins are configured (the default). Hot paths (login,
    /// work conn, user conn) skip building the notify payload and the notify
    /// loop entirely when this is true.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Notify all plugins about an event.
    ///
    /// Go frp v0.70.1 compat (`pkg/plugin/server/http.go` + `manager.go`):
    /// - POST `{url}?version=0.1.0&op=Login` with an `X-Frp-Reqid` header.
    /// - HTTP 200 is required; any transport/status error fails closed
    ///   (the operation is rejected, matching Go handleMutableContent).
    /// - `reject:true` rejects with `rejectReason`; `unchange:false` returns
    ///   the mutated content as `Ok(Some(value))`.
    ///
    /// Returns `Err(reason)` on rejection or plugin failure (fail-closed),
    /// `Ok(Some(mutated))` when a plugin mutated the content, else `Ok(None)`.
    pub async fn notify(
        &self,
        op: &str,
        content: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, String> {
        let go_op = go_op_name(op);
        let mut mutated: Option<serde_json::Value> = None;
        for plugin in self.plugins.iter() {
            // Filter by ops list if non-empty (case-insensitive so Rust-style
            // lowercase "login" matches Go-style "Login").
            if !plugin.cfg.ops.is_empty()
                && !plugin.cfg.ops.iter().any(|o| o.eq_ignore_ascii_case(op))
            {
                continue;
            }

            let event = PluginEvent {
                version: PLUGIN_API_VERSION,
                op: go_op.clone(),
                content: content.clone(),
            };
            let timeout = Duration::from_secs(plugin.cfg.timeout.max(1));

            let body = match serde_json::to_string(&event) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(plugin_name = %plugin.cfg.name, error = %e, "Server plugin '{}' JSON serialize error: {}", plugin.cfg.name, e);
                    return Err(format!(
                        "send {op} request to plugin [{}] error: {e}",
                        plugin.cfg.name
                    ));
                }
            };

            // Go http.go do(): POST {url}?version=0.1.0&op=Login with X-Frp-Reqid.
            let reqid = uuid::Uuid::new_v4().to_string();
            let url = format!(
                "{}?version={}&op={}",
                plugin.cfg.url, PLUGIN_API_VERSION, go_op
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-Frp-Reqid",
                HeaderValue::from_str(&reqid).map_err(|e| format!("invalid reqid header: {e}"))?,
            );
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            let result = tokio::time::timeout(
                timeout,
                plugin.client.post_with_headers(&url, headers, body),
            )
            .await;

            let resp = match result {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    tracing::warn!(
                        plugin_name = %plugin.cfg.name, op = %op, error = %e,
                        "Server plugin '{}' HTTP error for op '{}': {}",
                        plugin.cfg.name, op, e
                    );
                    // Fail closed: plugin unreachable ⇒ reject the operation.
                    return Err(format!(
                        "send {op} request to plugin [{}] error",
                        plugin.cfg.name
                    ));
                }
                Err(_) => {
                    tracing::warn!(
                        plugin_name = %plugin.cfg.name, op = %op,
                        "Server plugin '{}' timeout for op '{}'",
                        plugin.cfg.name, op
                    );
                    return Err(format!(
                        "send {op} request to plugin [{}] timeout",
                        plugin.cfg.name
                    ));
                }
            };

            // Go http.go: non-200 status is a hard error (fail-closed).
            if !resp.status().is_success() {
                let status = resp.status();
                tracing::warn!(
                    plugin_name = %plugin.cfg.name, op = %op, status = %status,
                    "Server plugin '{}' returned HTTP {} for op '{}'",
                    plugin.cfg.name, status, op
                );
                return Err(format!(
                    "send {op} request to plugin [{}] error code: {status}",
                    plugin.cfg.name
                ));
            }

            let resp_text = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(plugin_name = %plugin.cfg.name, error = %e, "Server plugin '{}' read response error: {}", plugin.cfg.name, e);
                    return Err(format!(
                        "send {op} request to plugin [{}] read response error",
                        plugin.cfg.name
                    ));
                }
            };
            // Fail closed on malformed plugin responses (Go handleMutableContent
            // treats a JSON decode error as a plugin failure). A non-JSON body
            // must not silently pass the operation through.
            let pr: PluginResponse = match serde_json::from_str(&resp_text) {
                Ok(pr) => pr,
                Err(e) => {
                    tracing::warn!(
                        plugin_name = %plugin.cfg.name,
                        op = %op,
                        error = %e,
                        "Server plugin '{}' returned invalid JSON for op '{}': {}",
                        plugin.cfg.name,
                        op,
                        e
                    );
                    return Err(format!(
                        "send {op} request to plugin [{}] invalid response",
                        plugin.cfg.name
                    ));
                }
            };

            if pr.reject {
                let reason = if pr.reject_reason.is_empty() {
                    "rejected by plugin".to_string()
                } else {
                    pr.reject_reason.clone()
                };
                tracing::warn!(
                    plugin_name = %plugin.cfg.name, op = %op, reason = %reason,
                    "Server plugin '{}' rejected op '{}': {}",
                    plugin.cfg.name, op, reason
                );
                return Err(reason);
            }
            if !pr.unchange && !pr.content.is_null() {
                mutated = Some(pr.content);
            }
        }
        Ok(mutated)
    }
}
