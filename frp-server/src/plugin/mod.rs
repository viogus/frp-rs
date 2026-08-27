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

/// Apply a plugin's mutated content (`unchange:false` + `content`) to the
/// typed message, mirroring Go's `handleMutableContent`
/// (pkg/plugin/server/manager.go:75-96): a plugin that returns
/// `unchange:false` replaces the typed struct, and the operation proceeds
/// with the mutated message.
///
/// Go semantics (http.go:78): the response `content` is decoded into a
/// FRESH zero-value struct (`reflect.New` + `json.Unmarshal`) — absent
/// fields take Go's zero value ("" / nil / 0); they do NOT keep the
/// current value. `serde_json::from_value::<T>` matches: absent fields
/// take T's serde defaults (Option fields → None, Go nil/"" parity), so a
/// plugin that clears a field by omitting it actually clears it. `current`
/// is deliberately NOT merged into the mutation — Go plugins echo the full
/// received content with their changes; what they omit is zeroed, not
/// preserved. Keys the typed message does not know (`user`,
/// `client_address`, frp-rs extras) are ignored by the typed
/// deserialization, so plugin-only fields survive the round-trip
/// harmlessly.
///
/// Required non-Option fields absent from the mutation (e.g.
/// `msg::NewProxy`'s `proxy_name`/`proxy_type`) fail closed here — Go
/// would zero them and reject the proxy downstream at registration; same
/// net rejection, explicit error.
///
/// Returns `Err` (never panics) when the mutated content does not
/// deserialize into `T`; callers fail closed on that error.
pub(crate) fn apply_plugin_mutation<T>(
    _current: &T,
    mutated: serde_json::Value,
) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(mutated).map_err(|e| format!("invalid plugin content mutation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::apply_plugin_mutation;

    /// Models msg::Login (all optional fields — absent → None) plus one
    /// required field like msg::NewProxy's proxy_name (absent → fail
    /// closed).
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct TestMsg {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
    }

    #[test]
    fn mutation_zeroes_absent_option_fields() {
        // Go http.go:78: the response content is decoded into a FRESH
        // zero-value struct — a field the plugin omits takes Go's zero
        // value, it does NOT keep the current value.
        let current = TestMsg {
            name: "a".into(),
            count: Some(1),
            extra: Some("keep".into()),
        };
        let mutated = serde_json::json!({ "name": "b" });
        let out = apply_plugin_mutation(&current, mutated).expect("valid mutation");
        assert_eq!(out.name, "b");
        assert_eq!(
            out.count, None,
            "absent field must be zeroed (Go parity), not kept"
        );
        assert_eq!(
            out.extra, None,
            "absent field must be zeroed (Go parity), not kept"
        );
    }

    #[test]
    fn mutation_ignores_plugin_only_keys() {
        let current = TestMsg {
            name: "a".into(),
            count: Some(1),
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
        assert_eq!(
            out.count, None,
            "absent optional fields are zeroed, not kept"
        );
    }

    #[test]
    fn mutation_with_wrong_types_fails_closed() {
        let current = TestMsg {
            name: "a".into(),
            count: Some(1),
            extra: None,
        };
        let mutated = serde_json::json!({ "name": "a", "count": "not-a-number" });
        let err = apply_plugin_mutation(&current, mutated).expect_err("must fail");
        assert!(
            err.contains("invalid plugin content mutation"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mutation_omitting_required_field_fails_closed() {
        // msg::NewProxy's proxy_name/proxy_type are required (non-Option):
        // a mutation omitting them cannot deserialize. Go would zero them
        // and reject the proxy downstream at registration; frp-rs fails
        // closed at deserialize with an explicit plugin error.
        let current = TestMsg {
            name: "a".into(),
            count: Some(1),
            extra: None,
        };
        let mutated = serde_json::json!({ "count": 7 });
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
            count: Some(1),
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
        assert_eq!(out.count, Some(1));
        assert_eq!(out.extra.as_deref(), Some("x"));
    }
}
