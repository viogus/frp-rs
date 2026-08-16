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
/// Join an HTTP plugin addr + path into a base URL, forgiving style:
/// - trailing '/' on addr is trimmed (the `http://` scheme is preserved);
/// - a path without a leading '/' gets one (so host:port + handler never
///   becomes host:porthandler or host:port//handler);
/// - a missing scheme defaults to http://.
fn join_plugin_base(addr: &str, path: &str) -> String {
    let addr = addr.trim_end_matches('/');
    let base = if path.is_empty() {
        addr.to_string()
    } else if path.starts_with('/') {
        format!("{addr}{path}")
    } else {
        format!("{addr}/{path}")
    };
    if base.starts_with("http://") || base.starts_with("https://") {
        base
    } else {
        format!("http://{base}")
    }
}

/// can approve or reject operations.
pub struct HttpPluginManager {
    plugins: Arc<Vec<PluginDef>>,
}

struct PluginDef {
    cfg: HttpPluginConfig,
    /// HTTP client honoring the plugin's TLS verify setting
    /// (Go http.go: InsecureSkipVerify: !options.TLSVerify).
    /// `None` when the client could not be built at all — the plugin is then
    /// skipped on every notify (logged at debug) instead of panicking.
    client: Option<frp_core::http_client::HttpClient>,
}

impl HttpPluginManager {
    /// Create a new manager from plugin configs.
    pub fn new(configs: Vec<HttpPluginConfig>) -> Self {
        // Per-plugin timeout is enforced by tokio::time::timeout below.
        // No client-level timeout — the tokio wrapper covers connect + full
        // request lifecycle and respects per-plugin timeout config.
        let client = match frp_core::http_client::HttpClientBuilder::new().build() {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::error!(
                    "Failed to build default HTTP plugin client: {e}. \
                     HTTP plugin notifications will be unavailable."
                );
                // Degrade instead of panicking: leave the client as None and
                // skip every plugin notification (logged at debug on notify).
                None
            }
        };
        let plugins = configs
            .into_iter()
            .map(|cfg| {
                let base = join_plugin_base(&cfg.addr, &cfg.path);
                let client = if base.starts_with("https://") && !cfg.tls_verify {
                    // Go compat: tlsVerify=false → InsecureSkipVerify.
                    match frp_core::http_client::HttpClientBuilder::new()
                        .tls_skip_verify(true)
                        .build()
                    {
                        Ok(c) => Some(c),
                        Err(e) => {
                            tracing::warn!(
                                plugin_name = %cfg.name,
                                error = %e,
                                "Failed to build insecure HTTP plugin client, falling back to default"
                            );
                            client.clone()
                        }
                    }
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
            // Forgiving join (join_plugin_base): trims a trailing '/' from
            // addr (never the http:// scheme), adds a leading '/' to a bare
            // path, and defaults a missing scheme to http://.
            let reqid = uuid::Uuid::new_v4().to_string();
            let url = format!(
                "{}?version={}&op={}",
                join_plugin_base(&plugin.cfg.addr, &plugin.cfg.path),
                PLUGIN_API_VERSION,
                go_op
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-Frp-Reqid",
                HeaderValue::from_str(&reqid).map_err(|e| format!("invalid reqid header: {e}"))?,
            );
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            // Client is None (initial build failed): skip this plugin's
            // notify — it would fail for every request anyway. Never panic.
            let Some(client) = &plugin.client else {
                tracing::debug!(
                    plugin_name = %plugin.cfg.name, op = %op,
                    "HTTP plugin client unavailable, skipping plugin '{}' for op '{}'",
                    plugin.cfg.name, op
                );
                continue;
            };
            let result =
                tokio::time::timeout(timeout, client.post_with_headers(&url, headers, body)).await;

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

#[cfg(test)]
mod tests {
    use super::join_plugin_base;

    #[test]
    fn test_join_plugin_base_variants() {
        // Canonical Go form: addr + path with leading slash.
        assert_eq!(
            join_plugin_base("http://127.0.0.1:4000", "/handler"),
            "http://127.0.0.1:4000/handler"
        );
        // Trailing slash on addr must not double the separator.
        assert_eq!(
            join_plugin_base("http://127.0.0.1:4000/", "/handler"),
            "http://127.0.0.1:4000/handler"
        );
        // Bare path without leading slash gets one (no host:porthandler).
        assert_eq!(
            join_plugin_base("http://127.0.0.1:4000", "handler"),
            "http://127.0.0.1:4000/handler"
        );
        // addr trailing slash + bare path: single separator.
        assert_eq!(
            join_plugin_base("http://127.0.0.1:4000/", "handler"),
            "http://127.0.0.1:4000/handler"
        );
        // Missing scheme defaults to http://.
        assert_eq!(
            join_plugin_base("127.0.0.1:4000", ""),
            "http://127.0.0.1:4000"
        );
        // Empty path keeps addr as-is.
        assert_eq!(
            join_plugin_base("http://127.0.0.1:4000/handler", ""),
            "http://127.0.0.1:4000/handler"
        );
    }
}
