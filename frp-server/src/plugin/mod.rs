use serde::Serialize;

#[cfg(feature = "http-proxy")]
mod http;
#[cfg(feature = "http-proxy")]
pub use http::HttpPluginManager;

#[cfg(not(feature = "http-proxy"))]
/// Stub plugin manager that always allows operations.
pub struct HttpPluginManager;

#[cfg(not(feature = "http-proxy"))]
impl HttpPluginManager {
    pub fn new(_configs: Vec<frp_core::config::HttpPluginConfig>) -> Self {
        Self
    }
    /// Stub: no plugins are ever configured in this build.
    pub fn is_empty(&self) -> bool {
        true
    }
    pub async fn notify(
        &self,
        _op: &str,
        _content: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, String> {
        Ok(None)
    }
    /// Stub: no-op (no plugins, so no hook ever reads the identity).
    pub fn record_login_user(&self, _run_id: &str, _user: &UserInfo) {}
    pub fn user_info(&self, _run_id: &str) -> Option<UserInfo> {
        None
    }
    pub fn remove_user(&self, _run_id: &str) {}
}

/// Go frp v0.71.0 `plugin.UserInfo` (pkg/plugin/server/types.go): the
/// client identity attached to the `user` object of the NewProxy,
/// CloseProxy, Ping, NewWorkConn, and NewUserConn plugin payloads
/// (Go `ctl.loginUserInfo()` = LoginMsg.User/Metas + runID).
///
/// Populated from the (possibly plugin-mutated) Login at control setup
/// (`login.rs`) and keyed by run_id on the plugin manager; dropped when
/// the control unregisters (`proxy_ops.rs::unregister_control`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct UserInfo {
    pub user: String,
    pub metas: std::collections::HashMap<String, String>,
    pub run_id: String,
}

/// Apply a plugin's mutated content (`unchange:false` + `content`) over
/// the current message, mirroring Go's `handleMutableContent`
/// (pkg/plugin/server/manager.go:75-96): a plugin that returns
/// `unchange:false` replaces the typed struct, and the operation proceeds
/// with the mutated message.
///
/// Merge semantics: keys present in the mutation replace the current
/// values; absent keys keep them (Go plugins echo the full received
/// content with their changes — a partial response works too). Keys the
/// typed message does not know (`user`, `client_address`, frp-rs extras)
/// are ignored by the typed deserialization (serde default), so the
/// plugin-only fields Go adds survive the round-trip harmlessly.
///
/// Returns `Err` (never panics) when the merged content does not
/// deserialize into `T`; callers fail closed on that error.
pub(crate) fn apply_plugin_mutation<T>(current: &T, mutated: serde_json::Value) -> Result<T, String>
where
    T: Serialize + serde::de::DeserializeOwned,
{
    let mut base = serde_json::to_value(current)
        .map_err(|e| format!("failed to serialize current content: {e}"))?;
    if let (Some(obj), serde_json::Value::Object(mutated_obj)) = (base.as_object_mut(), mutated) {
        for (key, value) in mutated_obj {
            obj.insert(key, value);
        }
    }
    serde_json::from_value(base).map_err(|e| format!("invalid plugin content mutation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::apply_plugin_mutation;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct TestMsg {
        name: String,
        count: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
    }

    #[test]
    fn mutation_replaces_present_keys_keeps_absent() {
        let current = TestMsg {
            name: "a".into(),
            count: 1,
            extra: Some("keep".into()),
        };
        let mutated = serde_json::json!({ "count": 7 });
        let out = apply_plugin_mutation(&current, mutated).expect("valid mutation");
        assert_eq!(out.name, "a", "absent key must keep the current value");
        assert_eq!(out.count, 7, "present key must replace the current value");
        assert_eq!(out.extra.as_deref(), Some("keep"));
    }

    #[test]
    fn mutation_ignores_plugin_only_keys() {
        let current = TestMsg {
            name: "a".into(),
            count: 1,
            extra: None,
        };
        // Go plugins echo content with the plugin-only `user` object and
        // frp-rs extras (`remote_addr`, `run_id`) — the typed message must
        // ignore them, not fail.
        let mutated = serde_json::json!({
            "name": "b",
            "user": { "user": "alice", "metas": {}, "run_id": "r1" },
            "remote_addr": "127.0.0.1:1",
            "run_id": "r1",
        });
        let out = apply_plugin_mutation(&current, mutated).expect("valid mutation");
        assert_eq!(out.name, "b");
        assert_eq!(out.count, 1);
    }

    #[test]
    fn mutation_with_wrong_types_fails_closed() {
        let current = TestMsg {
            name: "a".into(),
            count: 1,
            extra: None,
        };
        let mutated = serde_json::json!({ "count": "not-a-number" });
        let err = apply_plugin_mutation(&current, mutated).expect_err("must fail");
        assert!(
            err.contains("invalid plugin content mutation"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mutation_full_replacement_echo_works() {
        let current = TestMsg {
            name: "a".into(),
            count: 1,
            extra: Some("x".into()),
        };
        // A Go-style plugin echoes the full received content with changes.
        let mutated = serde_json::json!({
            "name": "echoed",
            "count": 1,
            "extra": "x",
        });
        let out = apply_plugin_mutation(&current, mutated).expect("valid mutation");
        assert_eq!(out.name, "echoed");
        assert_eq!(out.count, 1);
        assert_eq!(out.extra.as_deref(), Some("x"));
    }
}
