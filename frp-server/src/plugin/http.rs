use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;
use http::HeaderValue;
use serde::Deserialize;
use serde::Serialize;

use frp_core::config::HttpPluginConfig;

use super::UserInfo;

/// Go frp v0.70.1 compat: pkg/plugin/server API version.
const PLUGIN_API_VERSION: &str = "0.1.0";

/// Map an op spelling to the Go wire name (pkg/plugin/server/manager.go).
/// Both the call-site snake_case ("login") and the config-file Go name
/// ("Login") normalize to the exact Go name; config ops are passed through
/// this at load time (HttpPluginManager::new) so the notify filter can
/// exact-compare. Unknown ops pass through unchanged (Go has a fixed op
/// set — an unknown config op never fires).
fn go_op_name(op: &str) -> String {
    match op {
        "login" | "Login" => "Login".to_string(),
        "new_proxy" | "NewProxy" => "NewProxy".to_string(),
        "close_proxy" | "CloseProxy" => "CloseProxy".to_string(),
        "ping" | "Ping" => "Ping".to_string(),
        "new_work_conn" | "NewWorkConn" => "NewWorkConn".to_string(),
        "new_user_conn" | "NewUserConn" => "NewUserConn".to_string(),
        // Unknown ops pass through unchanged (call sites use a fixed set).
        other => other.to_string(),
    }
}

/// Whether `cfg_ops` (already normalized to Go names at load) includes
/// `go_op`. Exact compare only — Go `IsSupport` is `slices.Contains`
/// against the Go op name (case-sensitive): a config op spelled "login" or
/// "new_proxy" fires because load-time normalization mapped it to the Go
/// name, never because the comparison is lenient.
fn ops_match(cfg_ops: &[String], go_op: &str) -> bool {
    cfg_ops.iter().any(|o| o == go_op)
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
/// On lifecycle events (login, new_proxy, close_proxy, ping,
/// new_work_conn, new_user_conn), notifies matching plugins via HTTP POST
/// and applies their reject/approve verdict — any transport error,
/// timeout, non-200 status, or malformed response fails the operation
/// closed (Go handleMutableContent parity: a plugin outage must not
/// silently pass operations through).
///
/// Timeout deviation from Go: every plugin call is bounded by the
/// per-plugin `timeout` (default 5s, config default_plugin_timeout). Go
/// frp v0.71.0 uses a bare `http.Client{}` with NO timeout and waits
/// indefinitely; frp-rs fail-closes after the timeout — deliberately
/// safer.
///
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
    /// Per-run_id client identity for the `user` object in plugin payloads
    /// (Go loginUserInfo). Populated at login from the (possibly
    /// plugin-mutated) Login, consulted by the NewProxy/CloseProxy/Ping/
    /// NewWorkConn/NewUserConn hooks, dropped at control unregister — the
    /// map is bounded by live controls.
    ///
    /// Values carry the recording control's generation (`control_id`):
    /// `remove_user` is remove-if-match, so a stale control's cleanup can
    /// only drop an entry still holding ITS control_id, never a superseding
    /// control's fresh record.
    users: std::sync::RwLock<std::collections::HashMap<String, (u64, UserInfo)>>,
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
            .map(|mut cfg| {
                // Go matches config ops EXACTLY against the Go op names
                // (slices.Contains) — a config op spelled "login" or
                // "new_proxy" never fires on Go. Normalize the Rust-style
                // spellings to the Go names at load so both styles fire;
                // the notify filter then exact-compares (unknown ops stay
                // as-is and never fire, matching Go's fixed op set).
                cfg.ops = cfg.ops.iter().map(|o| go_op_name(o)).collect();
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
            users: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// True when no plugins are configured (the default). Hot paths (login,
    /// work conn, user conn) skip building the notify payload and the notify
    /// loop entirely when this is true.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Record the (possibly plugin-mutated) login identity for later hooks'
    /// `user` object (Go `ctl.loginUserInfo()`). Called once per control at
    /// login, storing the control's own generation alongside the identity;
    /// the entry is removed by `remove_user` at control unregister.
    pub fn record_login_user(&self, run_id: &str, control_id: u64, user: &UserInfo) {
        self.users
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(run_id.to_string(), (control_id, user.clone()));
    }

    /// The recorded client identity for `run_id`, or default when unknown
    /// (no login recorded — e.g. legacy test setups).
    pub fn user_info(&self, run_id: &str) -> Option<UserInfo> {
        self.users
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(run_id)
            .map(|(_, user)| user.clone())
    }

    /// Drop the identity entry when a control unregisters, bounding the map
    /// to live controls. Generation-exact: the entry is removed only when it
    /// still belongs to `control_id`, so a stale control's cleanup can never
    /// delete a superseding control's fresh record — the caller's
    /// generation guard is now defense in depth, not the sole guard.
    pub fn remove_user(&self, run_id: &str, control_id: u64) {
        let mut users = self
            .users
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if users
            .get(run_id)
            .is_some_and(|(stored, _)| *stored == control_id)
        {
            users.remove(run_id);
        }
    }

    /// Notify all plugins about an event.
    ///
    /// Go frp v0.70.1 compat (`pkg/plugin/server/http.go` + `manager.go`):
    /// - POST `{url}?version=0.1.0&op=Login` with an `X-Frp-Reqid` header.
    /// - HTTP 200 is required; any transport/status error fails closed
    ///   (the operation is rejected, matching Go handleMutableContent).
    /// - `reject:true` rejects with `rejectReason`; `unchange:false` returns
    ///   the mutated content as `Ok(Some(value))`.
    /// - Mutations chain (Go manager.go:79-83): each plugin receives the
    ///   previous plugin's output, and `Ok(Some(..))` carries the last
    ///   mutator's content.
    ///
    /// Returns `Err(reason)` on rejection or plugin failure (fail-closed),
    /// `Ok(Some(mutated))` when a plugin mutated the content, else `Ok(None)`.
    pub async fn notify(
        &self,
        op: &str,
        content: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, String> {
        let go_op = go_op_name(op);
        // Go handleMutableContent (manager.go:79-83) reassigns `content`
        // after every unchange:false plugin, so plugin N receives plugin
        // N-1's output — NOT the original. `cur` is the content each
        // plugin sees; a mutation replaces it for the next plugin in the
        // list, and the final value is what the caller applies to the
        // typed message.
        let mut cur = content;
        let mut mutated: Option<serde_json::Value> = None;
        for plugin in self.plugins.iter() {
            // Filter by ops list if non-empty. Config ops were normalized
            // to the Go names at load (HttpPluginManager::new), so this is
            // an exact compare — Go parity: a config op Go would reject
            // (lowercase, snake_case, unknown) never fires here either.
            if !plugin.cfg.ops.is_empty() && !ops_match(&plugin.cfg.ops, &go_op) {
                continue;
            }

            let event = PluginEvent {
                version: PLUGIN_API_VERSION,
                op: go_op.clone(),
                content: cur.clone(),
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
            if !pr.unchange {
                // Go http.go:78 pre-sets `res.Content = reflect.New(T)`, so
                // an ABSENT `content` key leaves the zero-value *T — the
                // mutation zeroes the typed struct ("" / nil / 0), which
                // frp-rs mirrors with an empty-object mutation below. An
                // EXPLICIT `"content": null` differs in Go: json.Unmarshal
                // nil-fills that interface, and handleMutableContent's
                // `content = retContent.(*T)` (manager.go:99-102) then
                // PANICS on the nil — panicking by design ("Buggy Plugin
                // implementations still panic here, by design"). frp-rs maps
                // explicit-null to the same empty-object zero-fill as absent:
                // strictly more graceful than Go's panic and still
                // fail-closed — Login's all-Option fields → auth fails on
                // the missing privilege_key/timestamp, and NewProxy fails
                // closed on the missing proxy_name. Deliberate deviation,
                // not parity.
                cur = if pr.content.is_null() {
                    serde_json::Value::Object(serde_json::Map::new())
                } else {
                    pr.content
                };
                mutated = Some(cur.clone());
            }
        }
        Ok(mutated)
    }
}

#[cfg(test)]
mod tests {
    use super::{go_op_name, join_plugin_base, ops_match};
    use crate::plugin::HttpPluginManager;

    fn user(run_id: &str, name: &str) -> super::UserInfo {
        super::UserInfo {
            user: name.to_string(),
            metas: std::collections::HashMap::new(),
            run_id: run_id.to_string(),
        }
    }

    /// Generation-exact removal (audit-fix): `remove_user` must be a no-op
    /// when the entry belongs to a different control_id (a stale cleanup
    /// after a same-run_id re-login) and must remove only for the matching
    /// generation.
    #[test]
    fn remove_user_is_generation_exact() {
        let m = HttpPluginManager::new(vec![]);
        m.record_login_user("run-1", 7, &user("run-1", "fresh"));

        // A stale control's cleanup (generation 3) must not delete
        // generation 7's record.
        m.remove_user("run-1", 3);
        assert_eq!(
            m.user_info("run-1").map(|u| u.user),
            Some("fresh".to_string()),
            "stale remove_user must not delete a fresh control's record"
        );

        // The matching generation's cleanup removes it.
        m.remove_user("run-1", 7);
        assert!(
            m.user_info("run-1").is_none(),
            "matching remove_user must drop the record"
        );

        // A subsequent stale remove stays a no-op (no entry, no panic).
        m.remove_user("run-1", 3);
        assert!(m.user_info("run-1").is_none());
    }

    #[test]
    fn test_go_op_name_normalizes_both_styles() {
        // Call-site snake_case and config-file Go names both normalize to
        // the exact Go wire name.
        assert_eq!(go_op_name("login"), "Login");
        assert_eq!(go_op_name("Login"), "Login");
        assert_eq!(go_op_name("new_proxy"), "NewProxy");
        assert_eq!(go_op_name("NewProxy"), "NewProxy");
        assert_eq!(go_op_name("close_proxy"), "CloseProxy");
        assert_eq!(go_op_name("ping"), "Ping");
        assert_eq!(go_op_name("new_work_conn"), "NewWorkConn");
        assert_eq!(go_op_name("new_user_conn"), "NewUserConn");
        // Unknown ops pass through unchanged.
        assert_eq!(go_op_name("bogus"), "bogus");
    }

    #[test]
    fn test_ops_filter_is_exact_after_normalization() {
        // snake_case config ops are normalized at load and fire.
        let snake: Vec<String> = ["new_proxy", "login"].into_iter().map(go_op_name).collect();
        assert!(
            ops_match(&snake, "NewProxy"),
            "normalized snake_case must fire"
        );
        assert!(ops_match(&snake, "Login"), "normalized lowercase must fire");
        assert!(!ops_match(&snake, "Ping"), "unsubscribed op must not fire");

        // CamelCase (Go-style) config ops fire as-is.
        let camel: Vec<String> = ["NewProxy"].into_iter().map(go_op_name).collect();
        assert!(ops_match(&camel, "NewProxy"), "CamelCase op must fire");

        // An unknown config op is normalized to itself and exact-compares:
        // it can never match a fixed Go op name, so it silently never fires.
        let unknown: Vec<String> = ["bogus"].into_iter().map(go_op_name).collect();
        assert!(
            !ops_match(&unknown, "Login"),
            "unknown op must silently not fire"
        );

        // A raw lowercase op the loader never normalized must NOT match —
        // the filter is exact; load-time normalization is what makes
        // lowercase config ops fire (Go parity for everything else).
        let raw: Vec<String> = vec!["login".into()];
        assert!(!ops_match(&raw, "Login"), "unnormalized op must not match");
    }

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
