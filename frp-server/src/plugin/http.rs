use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

use frp_core::config::HttpPluginConfig;

/// JSON payload sent to plugin servers on lifecycle events.
#[derive(Serialize)]
struct PluginEvent<'a> {
    op: &'a str,
    content: serde_json::Value,
}

/// Expected JSON response from a plugin server.
#[derive(Deserialize, Default)]
struct PluginResponse {
    /// When true, reject the operation.
    #[serde(default)]
    reject: bool,
    /// Human-readable reason for rejection.
    #[serde(default)]
    reject_reason: String,
}

/// Manages a collection of HTTP plugin servers.
///
/// On lifecycle events (login, new_proxy, close_proxy), notifies
/// matching plugins via HTTP POST. Plugins with `enable_control: true`
/// can approve or reject operations.
pub struct HttpPluginManager {
    plugins: Arc<Vec<PluginDef>>,
    client: reqwest::Client,
}

struct PluginDef {
    cfg: HttpPluginConfig,
}

impl HttpPluginManager {
    /// Create a new manager from plugin configs.
    pub fn new(configs: Vec<HttpPluginConfig>) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        let plugins = configs.into_iter().map(|cfg| PluginDef { cfg }).collect();
        Self { plugins: Arc::new(plugins), client }
    }

    /// Notify all plugins about an event.
    ///
    /// Returns `Ok(())` if no plugin rejects the event. Returns
    /// `Err(reason)` if any control-enabled plugin rejects.
    pub async fn notify(
        &self,
        op: &str,
        content: serde_json::Value,
    ) -> Result<(), String> {
        for plugin in self.plugins.iter() {
            // Filter by ops list if non-empty
            if !plugin.cfg.ops.is_empty()
                && !plugin.cfg.ops.iter().any(|o| o == op)
            {
                continue;
            }

            let event = PluginEvent { op, content: content.clone() };
            let timeout = Duration::from_secs(plugin.cfg.timeout.max(1));

            match tokio::time::timeout(timeout, self.client
                .post(&plugin.cfg.url)
                .json(&event)
                .send()
            ).await {
                Ok(Ok(resp)) => {
                    if plugin.cfg.enable_control {
                        if let Ok(pr) = resp.json::<PluginResponse>().await {
                            if pr.reject {
                                let reason = if pr.reject_reason.is_empty() {
                                    "rejected by plugin".to_string()
                                } else {
                                    pr.reject_reason.clone()
                                };
                                tracing::warn!(
                                    "Server plugin '{}' rejected op '{}': {}",
                                    plugin.cfg.name, op, reason
                                );
                                return Err(reason);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        "Server plugin '{}' HTTP error for op '{}': {}",
                        plugin.cfg.name, op, e
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        "Server plugin '{}' timeout for op '{}'",
                        plugin.cfg.name, op
                    );
                }
            }
        }
        Ok(())
    }
}
