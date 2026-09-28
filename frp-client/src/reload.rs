use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

use frp_core::config::{AuthClientConfig, ClientConfig, ProxyConfig, VisitorConfig};

use crate::proxy_runtime::ProxyRuntimeInfo;

/// Fields of `[auth]` a reload can change, as `(name, changed)` pairs.
///
/// **The completeness of this list is enforced by the compiler, not by the
/// list.** The two `let AuthClientConfig { … }` statements below destructure
/// every field with **no `..`**, so adding a field to [`AuthClientConfig`] makes
/// this function fail to compile (E0027: pattern does not mention the field)
/// until the new field is added to the destructure — and the destructure is
/// immediately next to the `vec![]` that must also gain an entry. A plain
/// `vec![("auth.token", old.token != new.token), …]` of named reads does *not*
/// have that property: measured by the second reviewer on the earlier shape,
/// adding a probe field to the struct and its `Default` left
/// `cargo check -p frp-client` green and
/// `auth_reload_refusal_covers_every_auth_field` passing, i.e. a reload changing
/// that field would have been silently accepted as `no changes detected` — the
/// exact bug class this function exists to close, reintroduced by the next
/// `[auth]` field.
fn auth_field_changes(old: &AuthClientConfig, new: &AuthClientConfig) -> Vec<(&'static str, bool)> {
    let AuthClientConfig {
        method: old_method,
        token: old_token,
        token_source: old_token_source,
        oidc_client_id: old_oidc_client_id,
        oidc_client_secret: old_oidc_client_secret,
        oidc_audience: old_oidc_audience,
        oidc_token_endpoint: old_oidc_token_endpoint,
        oidc_scope: old_oidc_scope,
        oidc_issuer: old_oidc_issuer,
        additional_endpoint_params: old_additional_endpoint_params,
        oidc_token_source: old_oidc_token_source,
        oidc_tls_trusted_ca_file: old_oidc_tls_trusted_ca_file,
        oidc_tls_insecure_skip_verify: old_oidc_tls_insecure_skip_verify,
        oidc_proxy_url: old_oidc_proxy_url,
        additional_auth_scopes: old_additional_auth_scopes,
        authentication_timeout: old_authentication_timeout,
        token_auth_timeout: old_token_auth_timeout,
    } = old;
    let AuthClientConfig {
        method: new_method,
        token: new_token,
        token_source: new_token_source,
        oidc_client_id: new_oidc_client_id,
        oidc_client_secret: new_oidc_client_secret,
        oidc_audience: new_oidc_audience,
        oidc_token_endpoint: new_oidc_token_endpoint,
        oidc_scope: new_oidc_scope,
        oidc_issuer: new_oidc_issuer,
        additional_endpoint_params: new_additional_endpoint_params,
        oidc_token_source: new_oidc_token_source,
        oidc_tls_trusted_ca_file: new_oidc_tls_trusted_ca_file,
        oidc_tls_insecure_skip_verify: new_oidc_tls_insecure_skip_verify,
        oidc_proxy_url: new_oidc_proxy_url,
        additional_auth_scopes: new_additional_auth_scopes,
        authentication_timeout: new_authentication_timeout,
        token_auth_timeout: new_token_auth_timeout,
    } = new;
    vec![
        (
            "auth.method",
            // Compare through the one policy, not the raw string: an absent
            // method and `method = ""` are both "token" after
            // `complete_auth_method` (Go's `util.EmptyOr`), so a reload that
            // only *spells out* the default must not be reported as auth change.
            {
                let mut o = old_method.clone();
                let mut n = new_method.clone();
                frp_core::auth::complete_auth_method(&mut o);
                frp_core::auth::complete_auth_method(&mut n);
                o != n
            },
        ),
        ("auth.token", old_token != new_token),
        (
            "auth.tokenSource",
            // `ValueSource` is not `PartialEq`; `Debug` is its deterministic
            // shape and is the same mechanism `config_snapshot` above uses for
            // the map fields it cannot compare field-wise.
            format!("{:?}", old_token_source) != format!("{:?}", new_token_source),
        ),
        (
            "auth.oidc.clientID",
            old_oidc_client_id != new_oidc_client_id,
        ),
        (
            "auth.oidc.clientSecret",
            old_oidc_client_secret != new_oidc_client_secret,
        ),
        ("auth.oidc.audience", old_oidc_audience != new_oidc_audience),
        (
            "auth.oidc.tokenEndpointURL",
            old_oidc_token_endpoint != new_oidc_token_endpoint,
        ),
        ("auth.oidc.scope", old_oidc_scope != new_oidc_scope),
        ("auth.oidc.issuer", old_oidc_issuer != new_oidc_issuer),
        (
            "auth.oidc.additionalEndpointParams",
            old_additional_endpoint_params != new_additional_endpoint_params,
        ),
        (
            "auth.oidc.tokenSource",
            format!("{:?}", old_oidc_token_source) != format!("{:?}", new_oidc_token_source),
        ),
        (
            "auth.oidc.tlsTrustedCAFile",
            old_oidc_tls_trusted_ca_file != new_oidc_tls_trusted_ca_file,
        ),
        (
            "auth.oidc.tlsInsecureSkipVerify",
            old_oidc_tls_insecure_skip_verify != new_oidc_tls_insecure_skip_verify,
        ),
        (
            "auth.oidc.proxyURL",
            old_oidc_proxy_url != new_oidc_proxy_url,
        ),
        (
            "auth.additionalAuthScopes",
            old_additional_auth_scopes != new_additional_auth_scopes,
        ),
        (
            "auth.authenticationTimeout",
            old_authentication_timeout != new_authentication_timeout,
        ),
        (
            "auth.tokenAuthTimeout",
            old_token_auth_timeout != new_token_auth_timeout,
        ),
    ]
}

/// Why a reload that changes `[auth]` is refused, or `None` when it does not.
///
/// **Decision: refuse** (naming the changed field), rather than re-derive.
/// Reasons, in order of weight:
///
/// 1. Auth is **startup-only in this process**: `Service::auth_cfg` and
///    `Service::encryption_key` are built once in
///    `Service::with_unsafe_features` and are not behind an `RwLock`, and the
///    OIDC client is a plain `Option<Arc<OidcClient>>`. Re-deriving would mean
///    swapping the verifier and the bridge cipher key under a live control
///    connection. `encryption_key` is copied **by value** into the control
///    reader/writer when the session is established, so a mid-flight swap
///    would not reach the live connection and would leave the two ends of the
///    bridge disagreeing about the cipher.
/// 2. Go has the same shape: `frpc`'s reload re-reads **proxies and visitors
///    only** — `client/service.go:494-525` (`reloadConfigFromSourcesLocked` →
///    `UpdateAllConfigurer`), `client/control.go:294` — and the auth setter
///    built at startup is never rebuilt.
/// 3. Reporting success while nothing about auth changed is the bug this
///    closes (`TODO.md`, "The client's admin-triggered reload never re-derives
///    auth"): `frpc-tiny reload` printed `reload success: reload success: no
///    changes detected` and logged nothing about auth at all.
///
/// Refusing (rather than applying the proxy diff and merely reporting the auth
/// change) keeps `Service::cfg` — what the admin API's `/api/config` and
/// `frpc status` report — equal to the config the process is actually running.
/// Storing the new `[auth]` there would make the reported method disagree with
/// the live verifier.
///
/// `old` must be the config captured **before** the reload writes anything.
/// `reload_from_sources` calls this immediately after loading, while `Self::cfg`
/// still holds the startup value; nothing else ever writes `cfg.auth` (only
/// `cfg.proxies`/`cfg.visitors` are replaced), so that value stays the running
/// one for the process's lifetime.
///
/// # What is compared, and the one deliberate over-refusal
///
/// The comparison is on the **`[auth]` section as written**, after nothing but
/// the `auth.method` fill (`complete_auth_method`, so `method = ""` equals
/// `method = "token"`). It is *not* a comparison of the "effective" auth, and it
/// deliberately over-refuses in one shape: adding an `[auth]` section that
/// happens to match the effective auth of a client whose `[auth]` was absent is
/// reported as `[auth] section added` and refused. That is not an oversight:
///
/// * `None` and `Some(AuthClientConfig::default())` are **not** equivalent here.
///   With `[auth]` absent the token comes from the deprecated flat top-level
///   `token`; with `[auth]` present a non-empty `auth.token` **wins** over it
///   (`frp_core::config::validate_client_config`), so the same-looking pair can
///   resolve different tokens. Deciding equivalence would mean modelling that
///   precedence here, which this function cannot see — it receives only the two
///   optional sections.
/// * The two directions are not symmetric in cost. Over-refusing costs a restart
///   on a config that would have been a no-op; under-refusing silently accepts
///   an auth change — the bug this function exists to close.
///
/// Pinned as deliberate by `auth_reload_refusal_treats_the_section_as_written`
/// so a future reader does not "fix" it into an equivalence check.
pub(crate) fn auth_reload_refusal(
    old: Option<&AuthClientConfig>,
    new: Option<&AuthClientConfig>,
) -> Option<String> {
    let changed: Vec<&str> = match (old, new) {
        (None, None) => Vec::new(),
        (Some(o), Some(n)) => auth_field_changes(o, n)
            .into_iter()
            .filter_map(|(name, changed)| changed.then_some(name))
            .collect(),
        // Adding or deleting the whole section is a change too.
        (None, Some(_)) => vec!["[auth] section added"],
        (Some(_), None) => vec!["[auth] section removed"],
    };
    if changed.is_empty() {
        return None;
    }
    // Field names only, never values: `auth.token`/`clientSecret` are secrets and
    // this text is echoed through the admin API and the CLI.
    Some(format!(
        "{}. auth is read once at startup and applying it needs a new control \
         session with new credentials — restart frpc to apply",
        changed.join(", ")
    ))
}

/// Build a config snapshot string for reload change detection.
/// Includes all fields that matter for proxy registration and plugin config.
/// Deterministic map serialization for snapshot equality. std HashMap's
/// Debug output iterates in per-instance random order, so two config
/// objects with identical content would serialize differently and false-diff
/// on EVERY reload (re-registering every proxy on each SIGUSR1). BTreeMap
/// iterates in key order; serde_json serialization is therefore stable.
fn sorted_map(m: &std::collections::HashMap<String, String>) -> String {
    let sorted: std::collections::BTreeMap<&String, &String> = m.iter().collect();
    serde_json::to_string(&sorted).unwrap_or_default()
}

pub(crate) fn config_snapshot(p: &ProxyConfig) -> String {
    // Sort and serialize key fields deterministically.
    // Hash secrets for change detection — never include plaintext secrets in
    // the snapshot (same policy as `sk`; change detection only needs the
    // hash to differ when the value differs).
    let hash_secret = |s: &str| -> String {
        if s.is_empty() {
            String::new()
        } else {
            frp_core::auth::generate_token(s, 0)
        }
    };
    let mut fields: Vec<(&str, String)> = vec![
        ("type", p.proxy_type.clone()),
        ("local_ip", p.local_ip.clone()),
        ("local_port", p.local_port.to_string()),
        ("remote_port", p.remote_port.to_string()),
        ("use_encryption", p.use_encryption.to_string()),
        ("use_compression", p.use_compression.to_string()),
        ("sk", hash_secret(&p.sk)),
        ("custom_domains", format!("{:?}", p.custom_domains)),
        ("subdomain", p.subdomain.clone()),
        ("http_user", p.http_user.clone()),
        ("http_pwd", hash_secret(&p.http_pwd)),
        ("host_header_rewrite", p.host_header_rewrite.clone()),
        ("locations", format!("{:?}", p.locations)),
        ("bandwidth_limit", p.bandwidth_limit.clone()),
        ("bandwidth_limit_mode", p.bandwidth_limit_mode.clone()),
        ("group", p.group.clone()),
        ("group_key", hash_secret(&p.group_key)),
        ("multiplexer", p.multiplexer.clone()),
        ("proxy_protocol_version", p.proxy_protocol_version.clone()),
        ("vnet_ip", p.vnet_ip.clone()),
        ("vnet_netmask", p.vnet_netmask.clone()),
        ("vnet_mtu", p.vnet_mtu.to_string()),
        ("advertise_subnet", p.advertise_subnet.clone()),
        ("virtual_net", p.virtual_net.clone()),
        // Round 6 (MEDIUM C1): health_check_* fields — a reload that only
        // changes health parameters (e.g. interval/max_failed) must not
        // hit the "no changes detected" early return and skip the health
        // restart. health_check_http_headers included (reload restarts
        // the health task on any health-field diff).
        ("health_check_type", p.health_check_type.clone()),
        ("health_check_url", p.health_check_url.clone()),
        (
            "health_check_http_headers",
            format!("{:?}", p.health_check_http_headers),
        ),
        (
            "health_check_interval_seconds",
            p.health_check_interval_seconds.to_string(),
        ),
        (
            "health_check_timeout_seconds",
            p.health_check_timeout_seconds.to_string(),
        ),
        (
            "health_check_max_failed",
            p.health_check_max_failed.to_string(),
        ),
        // Round-19 audit M7: all NewProxy-wire fields must be covered or a
        // reload that only edits them (headers, route_by_http_user, ...)
        // silently no-ops — the proxy is never re-registered with the server.
        // `enabled` is included for defense even though try_reload retains
        // enabled-only proxies before diffing (a disabled proxy is dropped
        // from the list and surfaces as removed); if a future path diffs
        // unfiltered lists it must not slip through.
        ("headers", sorted_map(&p.headers)),
        ("response_headers", sorted_map(&p.response_headers)),
        ("route_by_http_user", p.route_by_http_user.clone()),
        ("allow_users", format!("{:?}", p.allow_users)),
        ("annotations", sorted_map(&p.annotations)),
        ("metas", sorted_map(&p.metas)),
        ("http_password", hash_secret(&p.http_password)),
        ("enabled", p.enabled.to_string()),
        (
            "disable_assisted_addrs",
            p.disable_assisted_addrs.to_string(),
        ),
    ];

    // Plugin fields — needed for detecting plugin config changes during reload
    if let Some(ref pl) = p.plugin {
        fields.push(("plugin.type", pl.plugin_type.clone()));
        fields.push(("plugin.http_user", pl.http_user.clone()));
        fields.push(("plugin.http_password", hash_secret(&pl.http_password)));
        fields.push(("plugin.local_addr", pl.local_addr.clone()));
        fields.push(("plugin.local_path", pl.local_path.clone()));
        fields.push(("plugin.strip_prefix", pl.strip_prefix.clone()));
        fields.push(("plugin.host_header_rewrite", pl.host_header_rewrite.clone()));
        fields.push(("plugin.username", pl.username.clone()));
        fields.push(("plugin.password", hash_secret(&pl.password)));
        fields.push(("plugin.crt_file", pl.crt_file.clone()));
        fields.push(("plugin.key_file", pl.key_file.clone()));
        fields.push(("plugin.server_name", pl.server_name.clone()));
        fields.push(("plugin.secret_key", hash_secret(&pl.secret_key)));
        fields.push(("plugin.bind_addr", pl.bind_addr.clone()));
        fields.push(("plugin.bind_port", pl.bind_port.to_string()));
    } else {
        fields.push(("plugin.type", "(none)".to_string()));
    }

    fields.sort_by(|a, b| a.0.cmp(b.0));
    let parts: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.join("|")
}

/// Result of diffing old vs new proxy configurations.
/// The caller (try_reload) uses this to restart plugins,
/// send protocol messages, and update proxy_info_map.
#[derive(Debug)]
pub(crate) struct ReloadDelta {
    pub summary: String,
    pub removed: Vec<String>,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    /// Visitors removed/added/changed by this reload. Visitor listeners are
    /// session-scoped, so a non-empty set forces a clean session restart.
    pub visitor_removed: Vec<String>,
    pub visitor_added: Vec<String>,
    pub visitor_changed: Vec<String>,
    pub new_config: ClientConfig,
}

/// Compute the diff between the current proxy set and a freshly loaded config.
///
/// Does NOT send protocol messages or update proxy_info_map — the caller
/// (`Service::try_reload`) handles plugin restarts, message sending, and
/// state updates so it can use the correct plugin bound addresses.
pub(crate) async fn do_reload(
    proxy_info_map: &Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    old_visitors: &[VisitorConfig],
    new_cfg: ClientConfig,
    user: &str,
) -> Result<ReloadDelta, String> {
    // Diff old vs new proxy names
    let old_names: HashSet<String> = {
        proxy_info_map
            .read()
            .await
            .keys()
            .map(|k| {
                if user.is_empty() {
                    k.clone()
                } else {
                    let prefix = format!("{}.", user);
                    k.strip_prefix(&prefix).unwrap_or(k).to_string()
                }
            })
            .collect()
    };
    let new_names: HashSet<String> = new_cfg.proxies.iter().map(|p| p.name.clone()).collect();

    let removed: Vec<String> = old_names.difference(&new_names).cloned().collect();
    let added: Vec<String> = new_names.difference(&old_names).cloned().collect();

    // Detect changed proxies: same name, different config
    let common: HashSet<&String> = old_names.intersection(&new_names).collect();
    let mut changed: Vec<String> = Vec::new();
    {
        let map = proxy_info_map.read().await;
        for name in &common {
            let map_key = if user.is_empty() {
                (*name).clone()
            } else {
                format!("{}.{}", user, name)
            };
            if let (Some(old_info), Some(new_p)) = (
                map.get(&map_key),
                new_cfg.proxies.iter().find(|p| &p.name == *name),
            ) {
                let new_snapshot = config_snapshot(new_p);
                if old_info.config_snapshot != new_snapshot {
                    changed.push((*name).clone());
                }
            }
        }
    }

    // Diff visitors (Go frp compat: reload also applies visitor changes).
    let old_visitor_names: HashSet<String> = old_visitors.iter().map(|v| v.name.clone()).collect();
    let new_visitor_names: HashSet<String> =
        new_cfg.visitors.iter().map(|v| v.name.clone()).collect();
    let visitor_removed: Vec<String> = old_visitor_names
        .difference(&new_visitor_names)
        .cloned()
        .collect();
    let visitor_added: Vec<String> = new_visitor_names
        .difference(&old_visitor_names)
        .cloned()
        .collect();

    if removed.is_empty()
        && added.is_empty()
        && changed.is_empty()
        && visitor_removed.is_empty()
        && visitor_added.is_empty()
    {
        return Ok(ReloadDelta {
            summary: "reload success: no changes detected".into(),
            removed,
            added,
            changed,
            visitor_removed,
            visitor_added,
            visitor_changed: Vec::new(),
            new_config: new_cfg,
        });
    }

    // Detect changed visitors (same name, different config).
    let visitor_changed: Vec<String> = new_cfg
        .visitors
        .iter()
        .filter(|v| {
            old_visitors
                .iter()
                .any(|old| old.name == v.name && *old != **v)
        })
        .map(|v| v.name.clone())
        .collect();

    let summary = format!(
        "reload: +{} added, ~{} changed, -{} removed, visitors +{}/-{}",
        added.len(),
        changed.len(),
        removed.len(),
        visitor_added.len(),
        visitor_removed.len()
    );
    tracing::info!(added = %added.len(), changed = %changed.len(), removed = %removed.len(),
        visitor_added = %visitor_added.len(), visitor_removed = %visitor_removed.len(),
        "Config diff: +{} added, ~{} changed, -{} removed, visitors +{}/-{}",
        added.len(), changed.len(), removed.len(),
        visitor_added.len(), visitor_removed.len());

    Ok(ReloadDelta {
        summary,
        removed,
        added,
        changed,
        visitor_removed,
        visitor_added,
        visitor_changed,
        new_config: new_cfg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_runtime::{ProxyPhase, ProxyRuntimeInfo};

    fn wire_proxy_info(local_addr: &str) -> ProxyRuntimeInfo {
        ProxyRuntimeInfo {
            local_addr: local_addr.into(),
            proxy_type: "tcp".into(),
            use_encryption: false,
            use_compression: false,
            sk: String::new(),
            bandwidth_limit: 0,
            bandwidth_limit_mode: String::new(),
            bandwidth_limiter: None,
            proxy_protocol_version: String::new(),
            plugin: String::new(),
            remote_addr: String::new(),
            err: String::new(),
            config_snapshot: String::new(),
            phase: ProxyPhase::Running,
        }
    }

    fn proxy(name: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.into(),
            ..Default::default()
        }
    }

    /// When the reload changes `user`, strip_prefix with the NEW user fails
    /// against the old wire keys, so `removed` carries the full OLD wire
    /// names. try_reload resolves those against proxy_info_map before any
    /// keyed removal (close_wire_name_for_reload); this test pins the diff
    /// contract that resolution relies on. Rebuilding the removal keys with
    /// wire_proxy_name(&new_user, name) would double-prefix and miss
    /// (stale proxy_info_map/health entries survive the reload).
    #[tokio::test]
    async fn user_change_puts_full_wire_names_in_removed() {
        let map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        map.write()
            .await
            .insert("old_user.p1".into(), wire_proxy_info("127.0.0.1:8000"));
        map.write()
            .await
            .insert("old_user.p2".into(), wire_proxy_info("127.0.0.1:8001"));

        let new_cfg = ClientConfig {
            user: "new_user".into(),
            proxies: vec![proxy("p1"), proxy("p2"), proxy("p3")],
            ..Default::default()
        };

        let delta = do_reload(&map, &[], new_cfg, "new_user").await.unwrap();
        let mut removed = delta.removed;
        removed.sort();
        assert_eq!(removed, vec!["old_user.p1", "old_user.p2"]);
        // All bare names are re-added (registered under the new user).
        let mut added = delta.added;
        added.sort();
        assert_eq!(added, vec!["p1", "p2", "p3"]);
    }

    /// Without a user change, map keys strip cleanly and `removed`/`added`
    /// carry bare names (the common case for wire_proxy_name-based keying).
    #[tokio::test]
    async fn unchanged_user_keeps_bare_names() {
        let map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        map.write()
            .await
            .insert("user.p1".into(), wire_proxy_info("127.0.0.1:8000"));

        let new_cfg = ClientConfig {
            user: "user".into(),
            proxies: vec![proxy("p2")],
            ..Default::default()
        };

        let delta = do_reload(&map, &[], new_cfg, "user").await.unwrap();
        assert_eq!(delta.removed, vec!["p1"]);
        assert_eq!(delta.added, vec!["p2"]);
    }

    /// Round-19 audit M7 pin: the snapshot must cover every NewProxy-wire
    /// field. Editing ONLY one of these in the config file and reloading
    /// (SIGUSR1) must not silently no-op — do_reload's changed detection is
    /// the snapshot, and try_reload only re-registers (sends NewProxy) and
    /// restarts plugins for proxies whose snapshot differs.
    #[test]
    fn config_snapshot_covers_all_newproxy_wire_fields() {
        fn differs(mut c: ProxyConfig, mutate: impl FnOnce(&mut ProxyConfig)) -> bool {
            let base = config_snapshot(&c);
            mutate(&mut c);
            base != config_snapshot(&c)
        }
        let p = || proxy("p");
        assert!(differs(p(), |c| {
            c.headers.insert("h".into(), "1".into());
        }));
        assert!(differs(p(), |c| {
            c.response_headers.insert("r".into(), "2".into());
        }));
        assert!(differs(p(), |c| c.route_by_http_user = "alice".into()));
        assert!(differs(p(), |c| c.allow_users = vec!["alice".into()]));
        assert!(differs(p(), |c| {
            c.annotations.insert("a".into(), "b".into());
        }));
        assert!(differs(p(), |c| {
            c.metas.insert("m".into(), "n".into());
        }));
        assert!(differs(p(), |c| c.http_password = "secret".into()));
        // ProxyConfig::default() leaves enabled=false (default_true applies at
        // deserialization), so flip it ON to prove the field participates.
        assert!(differs(p(), |c| c.enabled = true));
        assert!(differs(p(), |c| c.disable_assisted_addrs = true));
        // And a proxy with none of them set still snapshots.
        assert!(!config_snapshot(&p()).is_empty());
    }

    /// Round-19 audit M7 pin: map-typed fields must snapshot in key order,
    /// not std HashMap's per-instance random iteration order — two config
    /// objects with identical content (differing only in map insertion
    /// order) must produce identical snapshots, or an untouched proxy would
    /// false-diff and re-register on every reload.
    #[test]
    fn config_snapshot_is_order_independent_for_maps() {
        let mut a = proxy("p");
        let mut b = proxy("p");
        for (k, v) in [("a", "1"), ("z", "2"), ("m", "3")] {
            a.headers.insert(k.into(), v.into());
            b.headers.insert(k.into(), v.into());
        }
        // Reverse b's insertion order (std HashMap iteration differs per
        // instance, so without sorting this would false-diff).
        let keys: Vec<String> = b.headers.keys().cloned().collect();
        for k in keys.iter().rev() {
            let v = b.headers.remove(k).unwrap();
            b.headers.insert(k.clone(), v);
        }
        assert_eq!(a.headers.len(), b.headers.len());
        assert_eq!(config_snapshot(&a), config_snapshot(&b));
        // Same content, freshly parsed object → same snapshot.
        let mut c = proxy("p");
        c.headers.insert("m".into(), "3".into());
        c.headers.insert("a".into(), "1".into());
        c.headers.insert("z".into(), "2".into());
        assert_eq!(config_snapshot(&a), config_snapshot(&c));
    }

    // -----------------------------------------------------------------
    // auth_reload_refusal — the client's reload decision for `[auth]`.
    // -----------------------------------------------------------------

    fn auth(method: &str, token: &str) -> AuthClientConfig {
        AuthClientConfig {
            method: method.into(),
            token: token.into(),
            ..Default::default()
        }
    }

    /// The no-change case, including the one that must NOT be reported: a
    /// config whose method is absent (`""`) vs one that spells out the default
    /// (`"token"`) are the same running auth after completion.
    #[test]
    fn auth_reload_refusal_is_none_when_auth_is_unchanged() {
        assert!(auth_reload_refusal(None, None).is_none());
        assert!(
            auth_reload_refusal(Some(&auth("token", "t")), Some(&auth("token", "t"))).is_none()
        );
        // `method = ""` (the absent key) and `method = "token"` are the same
        // value after `complete_auth_method`, so this must not refuse.
        assert!(auth_reload_refusal(Some(&auth("", "t")), Some(&auth("token", "t"))).is_none());
        assert!(auth_reload_refusal(Some(&auth("token", "t")), Some(&auth("", "t"))).is_none());
    }

    /// The refusal names the changed field and never its value. `auth.token` is
    /// a secret and this text is echoed to the admin API and the CLI.
    #[test]
    fn auth_reload_refusal_names_fields_not_values() {
        let r = auth_reload_refusal(Some(&auth("token", "t")), Some(&auth("oidc", "t")))
            .expect("a method change must be refused");
        assert!(r.starts_with("auth.method"), "got {r:?}");
        assert!(r.contains("restart frpc"), "got {r:?}");

        // Distinctive values so a leak is unambiguous: the field name
        // `auth.token` contains "token", so a substring check on a short
        // secret cannot discriminate.
        let r = auth_reload_refusal(
            Some(&auth("token", "SECRET-OLD-TOKEN")),
            Some(&auth("token", "SECRET-NEW-TOKEN")),
        )
        .expect("a token change must be refused");
        assert!(r.starts_with("auth.token"), "got {r:?}");
        assert!(
            !r.contains("SECRET-OLD-TOKEN") && !r.contains("SECRET-NEW-TOKEN"),
            "the message leaked a token value: {r:?}"
        );
    }

    /// Adding or removing the whole section is a change too.
    #[test]
    fn auth_reload_refusal_covers_the_whole_section() {
        assert!(auth_reload_refusal(None, Some(&auth("token", "t")))
            .expect("added")
            .starts_with("[auth] section added"));
        assert!(auth_reload_refusal(Some(&auth("token", "t")), None)
            .expect("removed")
            .starts_with("[auth] section removed"));
    }

    /// The deliberate over-refusal, pinned so it is not "fixed" into an
    /// equivalence check by a later reader (see the function's
    /// "What is compared" section for why `None` and `Some(default)` are not
    /// interchangeable).
    #[test]
    fn auth_reload_refusal_treats_the_section_as_written() {
        // A section that is byte-for-byte the `Default` impl still counts as
        // "added" against an absent one.
        let default_auth = AuthClientConfig::default();
        assert!(auth_reload_refusal(None, Some(&default_auth))
            .expect("None -> Some(default) is deliberately refused")
            .starts_with("[auth] section added"));
        // The same in the other direction.
        assert!(auth_reload_refusal(Some(&default_auth), None)
            .expect("Some(default) -> None is deliberately refused")
            .starts_with("[auth] section removed"));
        // And the method fill still applies inside a present pair, so this is
        // not "any textual difference": only the field values matter.
        let mut empty_method = default_auth.clone();
        empty_method.method = String::new();
        assert!(auth_reload_refusal(Some(&empty_method), Some(&default_auth)).is_none());
    }

    /// Every field of the client `[auth]` section participates. If a field is
    /// missing from `auth_field_changes`, its arm here stays `None` and this
    /// fails — that is the point of listing one mutation per field.
    #[test]
    fn auth_reload_refusal_covers_every_auth_field() {
        // Alias, not an inline type: clippy::type_complexity.
        type Mutator = Box<dyn Fn(&mut AuthClientConfig)>;
        let base = auth("oidc", "t");
        let cases: Vec<(&str, Mutator)> = vec![
            (
                "auth.method",
                Box::new(|a: &mut AuthClientConfig| a.method = "token".into()),
            ),
            (
                "auth.token",
                Box::new(|a: &mut AuthClientConfig| a.token = "u".into()),
            ),
            (
                "auth.tokenSource",
                Box::new(|a: &mut AuthClientConfig| {
                    a.token_source = Some(frp_core::config::ValueSource {
                        source_type: "file".into(),
                        file: Some(frp_core::config::FileSource { path: "/x".into() }),
                        exec: None,
                    })
                }),
            ),
            (
                "auth.oidc.clientID",
                Box::new(|a: &mut AuthClientConfig| a.oidc_client_id = "id".into()),
            ),
            (
                "auth.oidc.clientSecret",
                Box::new(|a: &mut AuthClientConfig| a.oidc_client_secret = "s".into()),
            ),
            (
                "auth.oidc.audience",
                Box::new(|a: &mut AuthClientConfig| a.oidc_audience = "aud".into()),
            ),
            (
                "auth.oidc.tokenEndpointURL",
                Box::new(|a: &mut AuthClientConfig| a.oidc_token_endpoint = "http://x".into()),
            ),
            (
                "auth.oidc.scope",
                Box::new(|a: &mut AuthClientConfig| a.oidc_scope = "openid".into()),
            ),
            (
                "auth.oidc.issuer",
                Box::new(|a: &mut AuthClientConfig| a.oidc_issuer = "http://i".into()),
            ),
            (
                "auth.oidc.additionalEndpointParams",
                Box::new(|a: &mut AuthClientConfig| {
                    a.additional_endpoint_params.insert("k".into(), "v".into());
                }),
            ),
            (
                "auth.oidc.tokenSource",
                Box::new(|a: &mut AuthClientConfig| {
                    a.oidc_token_source = Some(frp_core::config::ValueSource {
                        source_type: "file".into(),
                        file: Some(frp_core::config::FileSource { path: "/y".into() }),
                        exec: None,
                    })
                }),
            ),
            (
                "auth.oidc.tlsTrustedCAFile",
                Box::new(|a: &mut AuthClientConfig| a.oidc_tls_trusted_ca_file = "/ca".into()),
            ),
            (
                "auth.oidc.tlsInsecureSkipVerify",
                Box::new(|a: &mut AuthClientConfig| a.oidc_tls_insecure_skip_verify = true),
            ),
            (
                "auth.oidc.proxyURL",
                Box::new(|a: &mut AuthClientConfig| a.oidc_proxy_url = "http://p".into()),
            ),
            (
                "auth.additionalAuthScopes",
                Box::new(|a: &mut AuthClientConfig| {
                    a.additional_auth_scopes = vec!["HeartBeats".into()]
                }),
            ),
            (
                "auth.authenticationTimeout",
                Box::new(|a: &mut AuthClientConfig| a.authentication_timeout = 12),
            ),
            (
                "auth.tokenAuthTimeout",
                Box::new(|a: &mut AuthClientConfig| a.token_auth_timeout = false),
            ),
        ];
        // A fingerprint, not an enforcement. What the compiler enforces is the
        // *destructure* in `auth_field_changes` (a new struct field fails that
        // function to compile); this literal cannot see the struct, so it only
        // makes a missing row in the table below visible. If you add a field,
        // the destructure forces you to touch `auth_field_changes`, and this
        // count forces you to decide whether this table needs a row for it too.
        assert_eq!(
            cases.len(),
            17,
            "this table has one case per AuthClientConfig field today; if you \
             added a field, add its case here and move this literal with it"
        );
        for (field, mutate) in cases {
            let mut new = base.clone();
            mutate(&mut new);
            let r = auth_reload_refusal(Some(&base), Some(&new))
                .unwrap_or_else(|| panic!("changing {field} must be refused"));
            assert!(
                r.contains(field),
                "changing {field} must name it; got {r:?}"
            );
        }
    }
}
