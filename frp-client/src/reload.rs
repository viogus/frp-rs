use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use crate::proxy_runtime::ProxyRuntimeInfo;

/// Build a config snapshot string for reload change detection.
/// Includes all fields that matter for proxy registration and plugin config.
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
}
