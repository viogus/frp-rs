use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

use crate::proxy_runtime::ProxyRuntimeInfo;

/// Build a config snapshot string for reload change detection.
/// Includes all fields that matter for proxy registration and plugin config.
#[allow(clippy::vec_init_then_push)]
pub(crate) fn config_snapshot(p: &ProxyConfig) -> String {
    // Sort and serialize key fields deterministically
    let mut fields: Vec<(&str, String)> = Vec::new();
    fields.push(("type", p.proxy_type.clone()));
    fields.push(("local_ip", p.local_ip.clone()));
    fields.push(("local_port", p.local_port.to_string()));
    fields.push(("remote_port", p.remote_port.to_string()));
    fields.push(("use_encryption", p.use_encryption.to_string()));
    fields.push(("use_compression", p.use_compression.to_string()));
    // Hash sk for change detection — never include plaintext secret in snapshot.
    let sk_hash = if p.sk.is_empty() {
        String::new()
    } else {
        frp_core::auth::generate_token(&p.sk, 0)
    };
    fields.push(("sk", sk_hash));
    fields.push(("custom_domains", format!("{:?}", p.custom_domains)));
    fields.push(("subdomain", p.subdomain.clone()));
    fields.push(("http_user", p.http_user.clone()));
    fields.push(("http_pwd", p.http_pwd.clone()));
    fields.push(("host_header_rewrite", p.host_header_rewrite.clone()));
    fields.push(("locations", format!("{:?}", p.locations)));
    fields.push(("bandwidth_limit", p.bandwidth_limit.clone()));
    fields.push(("bandwidth_limit_mode", p.bandwidth_limit_mode.clone()));
    fields.push(("group", p.group.clone()));
    fields.push(("group_key", p.group_key.clone()));
    fields.push(("multiplexer", p.multiplexer.clone()));
    fields.push(("proxy_protocol_version", p.proxy_protocol_version.clone()));
    fields.push(("vnet_ip", p.vnet_ip.clone()));
    fields.push(("vnet_netmask", p.vnet_netmask.clone()));
    fields.push(("vnet_mtu", p.vnet_mtu.to_string()));
    fields.push(("advertise_subnet", p.advertise_subnet.clone()));
    fields.push(("virtual_net", p.virtual_net.clone()));

    // Plugin fields — needed for detecting plugin config changes during reload
    if let Some(ref pl) = p.plugin {
        fields.push(("plugin.type", pl.plugin_type.clone()));
        fields.push(("plugin.http_user", pl.http_user.clone()));
        fields.push(("plugin.http_password", pl.http_password.clone()));
        fields.push(("plugin.local_addr", pl.local_addr.clone()));
        fields.push(("plugin.local_path", pl.local_path.clone()));
        fields.push(("plugin.strip_prefix", pl.strip_prefix.clone()));
        fields.push(("plugin.host_header_rewrite", pl.host_header_rewrite.clone()));
        fields.push(("plugin.username", pl.username.clone()));
        fields.push(("plugin.password", pl.password.clone()));
        fields.push(("plugin.crt_file", pl.crt_file.clone()));
        fields.push(("plugin.key_file", pl.key_file.clone()));
        fields.push(("plugin.server_name", pl.server_name.clone()));
        fields.push(("plugin.secret_key", pl.secret_key.clone()));
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
