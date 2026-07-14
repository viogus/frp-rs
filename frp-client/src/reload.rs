use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

use frp_core::config::{ClientConfig, ProxyConfig};

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
    pub new_config: ClientConfig,
}

/// Compute the diff between the current proxy set and a freshly loaded config.
///
/// Does NOT send protocol messages or update proxy_info_map — the caller
/// (`Service::try_reload`) handles plugin restarts, message sending, and
/// state updates so it can use the correct plugin bound addresses.
pub(crate) async fn do_reload(
    proxy_info_map: &Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    config_path: &str,
    strict: bool,
) -> Result<ReloadDelta, String> {
    let new_cfg: ClientConfig = frp_core::config::load_client_config(config_path, strict)
        .map_err(|e| format!("failed to load config: {e}"))?;

    // Diff old vs new proxy names
    let old_names: HashSet<String> = { proxy_info_map.read().await.keys().cloned().collect() };
    let new_names: HashSet<String> = new_cfg.proxies.iter().map(|p| p.name.clone()).collect();

    let removed: Vec<String> = old_names.difference(&new_names).cloned().collect();
    let added: Vec<String> = new_names.difference(&old_names).cloned().collect();

    // Detect changed proxies: same name, different config
    let common: HashSet<&String> = old_names.intersection(&new_names).collect();
    let mut changed: Vec<String> = Vec::new();
    {
        let map = proxy_info_map.read().await;
        for name in &common {
            if let (Some(old_info), Some(new_p)) = (
                map.get(*name),
                new_cfg.proxies.iter().find(|p| &p.name == *name),
            ) {
                let new_snapshot = config_snapshot(new_p);
                if old_info.config_snapshot != new_snapshot {
                    changed.push((*name).clone());
                }
            }
        }
    }

    if strict && (!removed.is_empty() || !added.is_empty() || !changed.is_empty()) {
        let mut parts: Vec<String> = Vec::new();
        if !removed.is_empty() {
            parts.push(format!("removed: {:?}", removed));
        }
        if !added.is_empty() {
            parts.push(format!("added: {:?}", added));
        }
        if !changed.is_empty() {
            parts.push(format!("changed: {:?}", changed));
        }
        return Err(format!("config changed — {}", parts.join("; ")));
    }

    if removed.is_empty() && added.is_empty() && changed.is_empty() {
        return Ok(ReloadDelta {
            summary: "reload success: no changes detected".into(),
            removed,
            added,
            changed,
            new_config: new_cfg,
        });
    }

    let summary = format!(
        "reload: +{} added, ~{} changed, -{} removed",
        added.len(),
        changed.len(),
        removed.len()
    );
    tracing::info!(added = %added.len(), changed = %changed.len(), removed = %removed.len(),
        "Config diff: +{} added, ~{} changed, -{} removed",
        added.len(), changed.len(), removed.len());

    Ok(ReloadDelta {
        summary,
        removed,
        added,
        changed,
        new_config: new_cfg,
    })
}
