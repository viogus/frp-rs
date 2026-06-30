use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::{Mutex, RwLock};
use tracing;

use frp_core::config::{ClientConfig, ProxyConfig};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg;

use crate::admin::ProxyRuntimeInfo;

/// Build a config snapshot string for reload change detection.
/// Includes all fields that matter for proxy registration.
pub(crate) fn config_snapshot(p: &ProxyConfig) -> String {
    // Sort and serialize key fields deterministically
    let mut fields: Vec<(&str, String)> = Vec::new();
    fields.push(("type", p.proxy_type.clone()));
    fields.push(("local_ip", p.local_ip.clone()));
    fields.push(("local_port", p.local_port.to_string()));
    fields.push(("remote_port", p.remote_port.to_string()));
    fields.push(("use_encryption", p.use_encryption.to_string()));
    fields.push(("use_compression", p.use_compression.to_string()));
    fields.push(("sk", p.sk.clone()));
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
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let parts: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.join("|")
}

/// Reload configuration from file. Used by admin API.
///
/// Sends NewProxy for added proxies and CloseProxy for removed proxies
/// over the control connection. Responses are handled asynchronously by
/// the message loop. Plugin-based proxies log a warning (plugin restart
/// requires a full frpc restart).
pub(crate) async fn do_reload(
    proxy_info_map: &Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    v2: bool,
    config_path: &str,
    strict: bool,
    writer: &Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>,
) -> Result<String, String> {
    let new_cfg: ClientConfig = frp_core::config::load_client_config(config_path, strict)
        .map_err(|e| format!("failed to load config: {e}"))?;

    // Diff old vs new proxy names
    let old_names: HashSet<String> = {
        proxy_info_map.read().await.keys().cloned().collect()
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
            if let (Some(old_info), Some(new_p)) = (map.get(*name), new_cfg.proxies.iter().find(|p| &p.name == *name)) {
                let new_snapshot = config_snapshot(new_p);
                if old_info.config_snapshot != new_snapshot {
                    changed.push((*name).clone());
                }
            }
        }
    }

    if strict && (!removed.is_empty() || !added.is_empty() || !changed.is_empty()) {
        let mut parts: Vec<String> = Vec::new();
        if !removed.is_empty() { parts.push(format!("removed: {:?}", removed)); }
        if !added.is_empty() { parts.push(format!("added: {:?}", added)); }
        if !changed.is_empty() { parts.push(format!("changed: {:?}", changed)); }
        return Err(format!("config changed — {}", parts.join("; ")));
    }

    if removed.is_empty() && added.is_empty() && changed.is_empty() {
        return Ok("reload success: no changes detected".into());
    }

    let mut changes: Vec<String> = Vec::new();
    let mut w = writer.lock().await;

    // Send CloseProxy for removed proxies (fire-and-forget; CloseProxyResp
    // is handled by the message loop)
    for name in &removed {
        let close = FrpMessage::CloseProxy(msg::CloseProxy {
            proxy_name: name.clone(),
        });
        write_msg(&mut *w, &close, v2).await
            .map_err(|e| format!("send CloseProxy for '{name}': {e}"))?;
        changes.push(format!("proxy '{name}' removed"));
        tracing::info!("Reload: sent CloseProxy for '{name}'");
    }

    // Send CloseProxy + NewProxy for changed proxies
    for name in &changed {
        if let Some(p) = new_cfg.proxies.iter().find(|p| &p.name == name) {
            if p.plugin.is_some() {
                tracing::warn!(
                    "Reload: proxy '{name}' has a plugin — plugin restart requires full frpc restart"
                );
            }
            let close = FrpMessage::CloseProxy(msg::CloseProxy {
                proxy_name: name.clone(),
            });
            write_msg(&mut *w, &close, v2).await
                .map_err(|e| format!("send CloseProxy for changed '{name}': {e}"))?;
            let local_addr = format!("{}:{}", p.local_ip, p.local_port);
            let np = crate::proxy::create_new_proxy_msg(p, &local_addr);
            write_msg(&mut *w, &np, v2).await
                .map_err(|e| format!("send NewProxy for changed '{name}': {e}"))?;
            changes.push(format!("proxy '{name}' updated"));
            tracing::info!("Reload: sent CloseProxy+NewProxy for changed '{name}'");
        }
    }

    // Send NewProxy for added proxies (fire-and-forget; NewProxyResp
    // is handled by the message loop)
    for name in &added {
        if let Some(p) = new_cfg.proxies.iter().find(|p| &p.name == name) {
            if p.plugin.is_some() {
                tracing::warn!(
                    "Reload: proxy '{name}' has a plugin — plugin restart requires full frpc restart"
                );
            }
            let local_addr = format!("{}:{}", p.local_ip, p.local_port);
            let np = crate::proxy::create_new_proxy_msg(p, &local_addr);
            write_msg(&mut *w, &np, v2).await
                .map_err(|e| format!("send NewProxy for '{name}': {e}"))?;
            changes.push(format!("proxy '{name}' added"));
            tracing::info!("Reload: sent NewProxy for '{name}'");
        }
    }
    drop(w);

    // Update the shared proxy_info_map so admin API and work conn lookups
    // reflect the new proxy set.
    {
        let mut map = proxy_info_map.write().await;
        for name in &removed {
            map.remove(name);
        }
        for name in changed.iter().chain(added.iter()) {
            if let Some(p) = new_cfg.proxies.iter().find(|p| &p.name == name) {
                let bw_limit = frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
                let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                let plugin_type = p.plugin.as_ref()
                    .map(|pl| pl.plugin_type.clone())
                    .unwrap_or_default();
                let snapshot = config_snapshot(p);
                map.insert(name.clone(), ProxyRuntimeInfo {
                    local_addr,
                    proxy_type: p.proxy_type.clone(),
                    use_encryption: p.use_encryption,
                    use_compression: p.use_compression,
                    sk: p.sk.clone(),
                    bandwidth_limit: bw_limit,
                    bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
                    proxy_protocol_version: p.proxy_protocol_version.clone(),
                    plugin: plugin_type,
                    remote_addr: String::new(),
                    err: String::new(),
                    config_snapshot: snapshot,
                });
            }
        }
    }

    let summary = changes.join("; ");
    tracing::info!("Config reload summary: {}", summary);
    Ok(format!("reload success: {summary}"))
}
