use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, instrument, warn};

use frp_core::format_socket_addr;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg;
use frp_core::transport::IoStream;

use crate::lock::RwLockExt;
use crate::proxy::{allocate_port_multi, ProxyInfo};
use crate::service::{AppState, InternalMsg};

/// Returns full detail when detailed_errors is enabled, otherwise generic message.
pub(crate) fn err_msg(detailed: bool, detail: String, generic: &str) -> String {
    if detailed {
        detail
    } else {
        generic.to_string()
    }
}

/// Protocol-aware write helper: dispatches to V1 or V2 framing via
/// `frp_core::protocol::write_msg`, logging errors (connection likely dead).
async fn write_resp(writer: &mut (impl AsyncWriteExt + Unpin), msg: &FrpMessage, v2: bool) {
    if let Err(e) = write_msg(writer, msg, v2).await {
        warn!(error = %e, "Failed to write response: {e}");
    }
}

/// Build and send a `NewProxyResp` rejecting a proxy with `error`.
async fn reject_new_proxy(
    writer: &mut (impl AsyncWriteExt + Unpin),
    proxy_name: &str,
    error: String,
    v2: bool,
) {
    let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
        proxy_name: proxy_name.to_string(),
        remote_addr: None,
        error: Some(error),
    });
    write_resp(writer, &resp, v2).await;
}

/// Check whether a UDP port is available at the OS level by attempting a bind.
/// Immediately drops the socket if successful (just a probe).
/// Matches Go frp's `Manager.isPortAvailable` for UDP netType.
fn is_udp_port_bindable(bind_addr: &str, port: u16) -> bool {
    let addr = frp_core::format_socket_addr(bind_addr, port);
    match std::net::UdpSocket::bind(&addr) {
        Ok(socket) => {
            drop(socket);
            true
        }
        Err(e) => {
            tracing::debug!(
                port = %port,
                bind_addr = %bind_addr,
                error = %e,
                "UDP port {port} on '{bind_addr}' is not available at OS level: {e}",
            );
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod unregister_generation_tests {
    use super::*;

    fn test_state() -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
            frp_core::auth::AuthConfig::with_token("test-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("test-token"),
            vec![frp_core::config::PortsRange { start: 1, end: u16::MAX, single: 0 }],
            String::new(),
            true,
            30,
            7200,
            90,
            1500,
            false,
            None,
            0,
            60,
            10,
            false,
            String::new(),
            Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
            0,
            168,
            true,
            0,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    async fn insert_control(state: &Arc<AppState>, run_id: &str, control_id: u64) {
        let _rx = insert_control_rx(state, run_id, control_id).await;
    }

    async fn insert_control_rx(
        state: &Arc<AppState>,
        run_id: &str,
        control_id: u64,
    ) -> mpsc::Receiver<InternalMsg> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let mut map = state.run_id_to_ctl_tx.write().await;
        map.insert(
            run_id.to_string(),
            crate::state::ControlTx {
                tx,
                client_addr: None,
                login_time: std::time::Instant::now(),
                login_time_unix: 0,
                pool_stats: Arc::new(crate::state::PoolStats::default()),
                user: String::new(),
                control_id,
            },
        );
        rx
    }

    #[tokio::test]
    async fn stale_failure_cannot_unregister_superseding_control() {
        let state = test_state();
        insert_control(&state, "run-1", 7).await;

        // An older failing control (generation 3) must not delete the
        // replacement's routing entry.
        unregister_control(&state, "run-1", 3, false).await;
        assert!(state.run_id_to_ctl_tx.read().await.contains_key("run-1"));

        // The replacement itself may still clean up its own generation.
        unregister_control(&state, "run-1", 7, false).await;
        assert!(!state.run_id_to_ctl_tx.read().await.contains_key("run-1"));
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn unregister_control_removes_run_id_vnet_routes_and_broadcasts_remove() {
        let state = test_state();
        let mut peer_rx = insert_control_rx(&state, "run-b", 2).await;
        insert_control(&state, "run-a", 1).await;
        {
            let mut routes = state.vnet_routes.write().await;
            routes.insert(
                ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
                ("run-a".to_string(), "proxy-a".to_string()),
            );
            routes.insert(
                ("vnet-a".to_string(), "2001:db8::/64".to_string()),
                ("run-a".to_string(), "visitor-v6".to_string()),
            );
            routes.insert(
                ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
                ("run-b".to_string(), "proxy-b".to_string()),
            );
        }

        unregister_control(&state, "run-a", 1, false).await;

        let routes = state.vnet_routes.read().await;
        assert!(routes.iter().all(|(_, (run_id, _))| run_id != "run-a"));
        assert!(routes.contains_key(&("vnet-b".to_string(), "10.1.0.0/24".to_string())));
        drop(routes);

        let mut removes = Vec::new();
        for _ in 0..2 {
            match peer_rx.recv().await {
                Some(InternalMsg::VnetRouteRemoveForward { msg }) => removes.push(msg),
                other => panic!("expected forwarded remove, got {:?}", other),
            }
        }
        assert!(removes
            .iter()
            .any(|m| { m.proxy_name == "proxy-a" && m.virtual_net.as_deref() == Some("vnet-a") }));
        assert!(removes.iter().any(|m| {
            m.proxy_name == "visitor-v6" && m.virtual_net.as_deref() == Some("vnet-a")
        }));
    }
}

/// Pure validation of NewProxy fields. Returns Ok(()) or an error message.
/// Checks port range, proxy_name length/control chars, custom_domains length,
/// and subdomain length. Extracted from the async state machine to reduce
/// the number of `.await` points in `handle_new_proxy`.
#[inline(never)]
fn validate_new_proxy(np: &msg::NewProxy) -> Result<(), String> {
    let raw_port = np.remote_port.unwrap_or(0);
    if raw_port < 0 || raw_port > u16::MAX as i32 {
        return Err(format!(
            "remote_port {} out of valid range (0-65535)",
            raw_port
        ));
    }
    if np.proxy_name.len() > 255 {
        return Err("proxy_name exceeds 255 characters".into());
    }
    if np
        .proxy_name
        .contains(|c: char| c.is_control() && c != '\n' && c != '\r')
    {
        return Err("proxy_name contains invalid control characters".into());
    }
    if let Some(ref domains) = np.custom_domains {
        for domain in domains {
            if domain.len() > 253 {
                return Err(format!(
                    "custom_domain '{}' exceeds 253 characters (RFC 1035 FQDN limit)",
                    domain
                ));
            }
        }
    }
    if let Some(ref subdomain) = np.subdomain {
        if subdomain.len() > 63 {
            return Err(format!(
                "subdomain '{}' exceeds 63 characters (RFC 1035 label limit)",
                subdomain
            ));
        }
    }
    Ok(())
}

/// Register a new proxy and start listening on its assigned port.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(state, writer, internal_tx, listener_handles, udp_sockets, udp_local_to_proxy), fields(proxy_name = %np.proxy_name, proxy_type = %np.proxy_type, run_id = %run_id))]
pub(crate) async fn handle_new_proxy(
    np: msg::NewProxy,
    run_id: &str,
    state: &Arc<AppState>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    internal_tx: &mpsc::Sender<InternalMsg>,
    listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    udp_local_to_proxy: &mut std::collections::HashMap<String, String>,
    v2: bool,
) {
    if let Err(e) = validate_new_proxy(&np) {
        reject_new_proxy(writer, &np.proxy_name, e, v2).await;
        return;
    }
    let remote_port = np.remote_port.unwrap_or(0) as u16;

    // Server plugin: new_proxy hook (before port allocation).
    // Control-enabled plugins can reject the proxy registration.
    let np_content = serde_json::json!({
        "proxy_name": np.proxy_name,
        "proxy_type": np.proxy_type,
        "remote_port": remote_port,
        "custom_domains": np.custom_domains,
        "run_id": run_id,
    });
    if let Err(reason) = state.plugin_manager.notify("new_proxy", np_content).await {
        // Emit WebSocket event for dashboard subscribers
        #[cfg(feature = "dashboard")]
        {
            let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                message: format!(
                    "Plugin 'new_proxy' rejected proxy '{}': {}",
                    np.proxy_name, reason
                ),
                context: Some("new_proxy".into()),
            });
        }
        reject_new_proxy(writer, &np.proxy_name, reason, v2).await;
        return;
    }

    // Go frp compat: only TCP/UDP proxies consume ports. HTTP/HTTPS/TCPMux
    // share the vhost/tcpmux listeners; STCP/XTCP have no remote port.
    let consumes_port = matches!(np.proxy_type.as_str(), "tcp" | "udp" | "sudp");

    // Check per-client port limit (matching Go frp's GetUsedPortsNum logic).
    // Count actual used ports, not proxy names, and add 1 for this new proxy.
    if consumes_port && state.max_ports_per_client > 0 {
        let used = state
            .client_ports_used
            .read()
            .await
            .get(run_id)
            .copied()
            .unwrap_or(0);
        if used + 1 > state.max_ports_per_client {
            reject_new_proxy(
                writer,
                &np.proxy_name,
                format!(
                    "maximum number of ports ({}) reached for this client",
                    state.max_ports_per_client
                ),
                v2,
            )
            .await;
            return;
        }
    }

    let is_sudp = np.proxy_type == "sudp";
    let is_tcp_group =
        np.proxy_type == "tcp" && np.group.as_deref().filter(|g| !g.is_empty()).is_some();

    // TCP group proxy: try to join an existing group first.
    // Go frp dev compat: group members share a single port with round-robin dispatch.
    let mut tcp_group_created = false;
    if is_tcp_group {
        let group_name = np.group.as_deref().unwrap_or("");
        let group_key = np.group_key.as_deref().unwrap_or("");
        if let Some(group_port) = state
            .tcp_group_ctl
            .get_group_port(group_name, group_key, remote_port, &state.proxy_bind_addr)
            .await
        {
            info!(
                proxy_name = %np.proxy_name,
                group = %group_name,
                port = %group_port,
                "TCP proxy '{}' joining existing group '{}' on port {}",
                np.proxy_name, group_name, group_port,
            );
            // Group exists — reuse its port and skip port allocation.
            // The shared group listener handles connection dispatch.
            // We still create ProxyInfo with the group's port so users
            // connect to the correct port, but no new listener is spawned.
            let mut ports = state.used_ports.write().await;
            ports.insert(group_port);
            let allocated_port = Some(group_port);
            // Jump to proxy registration, skipping listener creation below.
            handle_tcp_group_member_registration(
                state,
                run_id,
                writer,
                np,
                remote_port,
                internal_tx,
                listener_handles,
                udp_sockets,
                udp_local_to_proxy,
                v2,
                allocated_port,
                false,
            )
            .await;
            return;
        }
        // No existing group — will create one with a new shared listener.
        tcp_group_created = true;
    }

    // When sudp_port is configured, force all SUDP proxies to use that port
    let remote_port = if is_sudp && state.sudp_port > 0 {
        if remote_port > 0 && remote_port != state.sudp_port {
            info!(proxy_name = %np.proxy_name, remote_port = %remote_port, sudp_port = %state.sudp_port, "SUDP proxy '{}': overriding remote_port {} → {} (sudp_port config)",
                np.proxy_name, remote_port, state.sudp_port);
        }
        state.sudp_port
    } else {
        remote_port
    };
    // Separate port managers for TCP and UDP (Go frp compat).
    // TCP port 8080 can coexist with UDP port 8080.
    let is_udp_type = np.proxy_type == "udp" || np.proxy_type == "sudp";
    let allocated_port = if !consumes_port {
        // http/https/tcpmux/stcp/xtcp: no allowPorts consumption. Keep the
        // configured remote_port (usually 0) for display only.
        Some(remote_port)
    } else if is_udp_type {
        // UDP/SuDP port allocation: no TCP bind probe (UdpSocket::bind handles
        // OS-level validation later). Use dedicated used_udp_ports tracking
        // separate from TCP used_ports (Go frp compat).
        let mut ports = state.used_udp_ports.write().await;
        if remote_port > 0 {
            if ports.contains(&remote_port) {
                // Port already used by another UDP proxy. SUDP allows sharing,
                // pure UDP does not.
                if is_sudp {
                    Some(remote_port)
                } else {
                    None
                }
            } else {
                // OS-level UDP bind probe before marking as used (Go frp compat:
                // Manager.isPortAvailable does net.ListenUDP for UDP netType).
                if !is_udp_port_bindable(&state.proxy_bind_addr, remote_port) {
                    None
                } else {
                    ports.insert(remote_port);
                    Some(remote_port)
                }
            }
        } else {
            // 24h reservation: re-registration with the same proxy name reuses
            // its previous port when still free (Go ports.Manager.Acquire).
            let mut found = None;
            {
                let mut reservations = state.port_reservations.write().await;
                // Lazy cleanup (Go cleanReservedPortsWorker): drop expired
                // entries so the map does not grow without bound.
                if let Some(&(res_port, true, reserved_at)) =
                    reservations.get(&np.proxy_name)
                {
                    if reserved_at.elapsed() >= std::time::Duration::from_secs(24 * 3600) {
                        reservations.remove(&np.proxy_name);
                    } else if !ports.contains(&res_port)
                        && is_udp_port_bindable(&state.proxy_bind_addr, res_port)
                    {
                        ports.insert(res_port);
                        found = Some(res_port);
                    }
                }
            }
            if found.is_none() {
                // Auto-assign: scan allow_ports ranges for first available UDP
                // port with OS-level bind probe (Go frp compat).
                let allow_ports = state.reloadable.read_ok().allow_ports.clone();
                drop(ports); // Release write lock before re-acquiring
                let mut ports = state.used_udp_ports.write().await;
                for r in allow_ports.iter() {
                    for p in r.iter() {
                        if !ports.contains(&p) && is_udp_port_bindable(&state.proxy_bind_addr, p) {
                            ports.insert(p);
                            found = Some(p);
                            break;
                        }
                    }
                    if found.is_some() {
                        break;
                    }
                }
                if found.is_none() {
                    tracing::warn!(
                        ranges = ?allow_ports,
                        "UDP port exhaustion: no available ports in configured allow_ports ranges",
                    );
                }
            }
            found
        }
    } else {
        // TCP-type proxy (tcp): use TCP port manager with OS-level bind probe.
        let mut ports = state.used_ports.write().await;
        if remote_port == 0 {
            // 24h reservation by proxy name (Go ports.Manager.Acquire).
            let mut allocated = None;
            {
                let mut reservations = state.port_reservations.write().await;
                // Lazy cleanup (Go cleanReservedPortsWorker): drop expired
                // entries so the map does not grow without bound.
                if let Some(&(res_port, false, reserved_at)) =
                    reservations.get(&np.proxy_name)
                {
                    if reserved_at.elapsed() >= std::time::Duration::from_secs(24 * 3600) {
                        reservations.remove(&np.proxy_name);
                    } else if !ports.contains(&res_port)
                        && crate::proxy::is_tcp_port_bindable(
                            &state.proxy_bind_addr,
                            res_port,
                        )
                    {
                        ports.insert(res_port);
                        allocated = Some(res_port);
                    }
                }
            }
            if allocated.is_none() {
                allocated = allocate_port_multi(
                    &mut ports,
                    0,
                    &state.reloadable.read_ok().allow_ports,
                    &state.proxy_bind_addr,
                );
            }
            allocated
        } else {
            allocate_port_multi(
                &mut ports,
                remote_port,
                &state.reloadable.read_ok().allow_ports,
                &state.proxy_bind_addr,
            )
        }
    };

    match allocated_port {
        Some(port) => {
            let virtual_net = np.virtual_net.clone().filter(|v| !v.is_empty());
            let info = ProxyInfo {
                name: np.proxy_name.clone(),
                proxy_type: np.proxy_type.clone(),
                run_id: run_id.to_string(),
                remote_port: Some(port),
                sk: np.sk.clone(),
                group: np.group.clone(),
                group_key: np.group_key.clone(),
                local_addr: np.local_str.clone(),
                use_encryption: np.use_encryption.unwrap_or(false),
                use_compression: np.use_compression.unwrap_or(false),
                virtual_net: virtual_net.clone(),
                allow_users: np.allow_users.clone().unwrap_or_default(),
                proxy_protocol_version: np.proxy_protocol_version.clone().unwrap_or_default(),
                response_headers: np.response_headers.clone().unwrap_or_default(),
                custom_domains: np.custom_domains.clone().unwrap_or_default(),
                route_by_http_user: np.route_by_http_user.clone().unwrap_or_default(),
                multiplexer: np.multiplexer.clone().unwrap_or_default(),
                bandwidth_limit: np.bandwidth_limit.clone().unwrap_or_default(),
                bandwidth_limit_mode: np.bandwidth_limit_mode.clone().unwrap_or_default(),
                user: state
                    .run_id_to_ctl_tx
                    .read()
                    .await
                    .get(run_id)
                    .map(|c| c.user.clone())
                    .unwrap_or_default(),
            };

            // Go frp compat: proxy.Run() calls startVisitorListener() BEFORE
            // proxyManager.Add(). Insert sk_index before proxy_manager.register()
            // so that STCP/XTCP visitors that arrive during the registration
            // window can find the proxy via sk_index fallback.
            let needs_sk_index = (np.proxy_type == "stcp" || np.proxy_type == "xtcp")
                && np.sk.as_deref().filter(|s| !s.is_empty()).is_some();
            if needs_sk_index {
                let raw = np.sk.clone().unwrap_or_default();
                let vn = np.virtual_net.as_deref().unwrap_or("");
                state
                    .xtcp
                    .sk_index
                    .write()
                    .await
                    .insert(np.proxy_name.clone(), raw);
                info!(proxy_name = %np.proxy_name, vn = %vn, "STCP/XTCP sk_index registered for '{}'{}",
                    np.proxy_name,
                    if vn.is_empty() { String::new() } else { format!(" (virtual_net: {vn})") });
            }

            if let Err(e) = state
                .proxy_manager
                .register(run_id.to_string(), info.clone())
                .await
            {
                // Cleanup sk_index on registration failure
                if needs_sk_index {
                    state.xtcp.sk_index.write().await.remove(&np.proxy_name);
                }
                state.used_ports.write().await.remove(&port);
                // For UDP proxies, also clean up used_udp_ports. The port
                // was allocated from the TCP set by the TCP group path
                // (TCP group proxies are always TCP, not UDP).
                if is_udp_type {
                    state.used_udp_ports.write().await.remove(&port);
                }
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    err_msg(
                        state.detailed_errors_to_client,
                        e,
                        "proxy registration conflict",
                    ),
                    v2,
                )
                .await;
                return;
            }

            // Track port usage per client (matching Go frp's portsUsedNum).
            state
                .client_ports_used
                .write()
                .await
                .entry(run_id.to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);

            #[cfg(feature = "vnet")]
            if np.proxy_type == "vnet" {
                if let Some(ref subnet) = np.advertise_subnet {
                    if !subnet.is_empty() {
                        let vn = np.virtual_net.clone().unwrap_or_default();
                        let key = (vn, subnet.clone());
                        let mut routes = state.vnet_routes.write().await;
                        routes.insert(key, (run_id.to_string(), np.proxy_name.clone()));
                        info!(
                            proxy_name = %np.proxy_name,
                            subnet = %subnet,
                            "vnet route registered: {} → {}",
                            subnet, np.proxy_name
                        );
                    }
                }
            }

            // Register HTTP proxies with VhostManager
            if np.proxy_type == "http" {
                let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

                // Subdomain routing: {subdomain}.{sub_domain_host}
                if let Some(ref subdomain) = np.subdomain {
                    if !subdomain.is_empty() {
                        let sub_host = &state.sub_domain_host;
                        if !sub_host.is_empty() {
                            let full_domain = format!("{}.{}", subdomain, sub_host);
                            info!(full_domain = %full_domain, proxy_name = %np.proxy_name, "Subdomain route: {} → {}", full_domain, np.proxy_name);
                            if !domains.contains(&full_domain) {
                                domains.push(full_domain);
                            }
                        }
                    }
                }

                let locations: Vec<String> = np.locations.clone().unwrap_or_default();

                // Always register HTTP proxies with VHost manager.
                // If both domains and locations are empty, register with empty
                // strings as catch-all routes (matches any host/path).
                let mut locations = locations;
                if domains.is_empty() && locations.is_empty() {
                    domains.push(String::new()); // catch-all domain
                    locations.push(String::new()); // catch-all path
                }
                let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
                let http_user = np.http_user.as_deref().unwrap_or("");
                let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                let rubu = np.route_by_http_user.as_deref().unwrap_or("");
                let headers: Vec<(String, String)> = np
                    .headers
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if let Err(conflict) = state
                    .vhost_manager
                    .register(
                        &np.proxy_name,
                        &domains,
                        &locations,
                        run_id,
                        hhr,
                        http_user,
                        http_pwd,
                        rubu,
                        &headers,
                    )
                    .await
                {
                    // Roll back previous registrations.
                    state.used_ports.write().await.remove(&port);
                    state
                        .client_ports_used
                        .write()
                        .await
                        .entry(run_id.to_string())
                        .and_modify(|c| *c = c.saturating_sub(1));
                    state.proxy_manager.remove(&np.proxy_name).await;
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        err_msg(
                            state.detailed_errors_to_client,
                            conflict.to_string(),
                            "vhost route config conflict",
                        ),
                        v2,
                    )
                    .await;
                    return;
                }
                info!(proxy_name = %np.proxy_name, domains = ?domains, locations = ?locations, hhr = ?hhr, "VHost routes registered for '{}': domains={:?}, locations={:?}, rewrite={:?}",
                    np.proxy_name, domains, locations, hhr);
            }

            // Register HTTPS proxies with VhostManager for SNI routing.
            // Routes by domain only (no path/location) — SNI hostname
            // from the TLS ClientHello determines the route.
            if np.proxy_type == "https" {
                let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

                // Subdomain routing
                if let Some(ref subdomain) = np.subdomain {
                    if !subdomain.is_empty() {
                        let sub_host = &state.sub_domain_host;
                        if !sub_host.is_empty() {
                            let full_domain = format!("{}.{}", subdomain, sub_host);
                            if !domains.contains(&full_domain) {
                                domains.push(full_domain);
                            }
                        }
                    }
                }

                if domains.is_empty() {
                    warn!(proxy_name = %np.proxy_name, "HTTPS proxy '{}' has no custom_domains — SNI routing won't work", np.proxy_name);
                }

                let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
                let http_user = np.http_user.as_deref().unwrap_or("");
                let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                let rubu = np.route_by_http_user.as_deref().unwrap_or("");
                let headers: Vec<(String, String)> = np
                    .headers
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if let Err(conflict) = state
                    .vhost_manager
                    .register(
                        &np.proxy_name,
                        &domains,
                        &[], // no locations for HTTPS SNI routing
                        run_id,
                        hhr,
                        http_user,
                        http_pwd,
                        rubu,
                        &headers,
                    )
                    .await
                {
                    // Roll back previous registrations.
                    state.used_ports.write().await.remove(&port);
                    state
                        .client_ports_used
                        .write()
                        .await
                        .entry(run_id.to_string())
                        .and_modify(|c| *c = c.saturating_sub(1));
                    state.proxy_manager.remove(&np.proxy_name).await;
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        err_msg(
                            state.detailed_errors_to_client,
                            conflict.to_string(),
                            "vhost route config conflict",
                        ),
                        v2,
                    )
                    .await;
                    return;
                }
                info!(
                    proxy_name = %np.proxy_name, domains = ?domains, "VHost SNI routes registered for HTTPS proxy '{}': domains={:?}",
                    np.proxy_name, domains
                );
            }

            // Register TCPMux proxies with TcpMuxManager (domain-based CONNECT routing).
            // Follows the same pattern as VHost HTTP registration.
            if np.proxy_type == "tcpmux" {
                let domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();
                if domains.is_empty() {
                    // TCPMux requires at least one domain for routing
                    state.used_ports.write().await.remove(&port);
                    state
                        .client_ports_used
                        .write()
                        .await
                        .entry(run_id.to_string())
                        .and_modify(|c| *c = c.saturating_sub(1));
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        "tcpmux proxy requires custom_domains".into(),
                        v2,
                    )
                    .await;
                    state.proxy_manager.remove(&np.proxy_name).await;
                    return;
                }
                let http_user = np.http_user.as_deref().unwrap_or("");
                let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                state
                    .tcpmux_manager
                    .register(
                        &np.proxy_name,
                        &domains,
                        run_id,
                        http_user,
                        http_pwd,
                        &np.headers
                            .clone()
                            .unwrap_or_default()
                            .into_iter()
                            .collect::<Vec<(String, String)>>(),
                    )
                    .await;
                info!(
                    proxy_name = %np.proxy_name, domains = ?domains, "TCPMux routes registered for '{}': domains={:?}",
                    np.proxy_name, domains
                );
            }

            // Start the appropriate listener for this proxy type.
            // STCP/XTCP/TCPMux use NAT hole punching or shared ports — no listener port needed.
            let pn = np.proxy_name.clone();
            let itx = internal_tx.clone();
            let bind_addr = state.proxy_bind_addr.clone();

            let is_nat_hole =
                np.proxy_type == "stcp" || np.proxy_type == "xtcp" || np.proxy_type == "tcpmux";

            // Collect oneshot senders for UDP work-conn tasks so we can signal
            // them after NewProxyResp has been written (avoiding the race where
            // client receives ReqWorkConn before proxy registration completes).
            let mut udp_resp_signals: Vec<oneshot::Sender<()>> = Vec::new();

            if np.proxy_type == "udp" || np.proxy_type == "sudp" {
                let is_sudp = np.proxy_type == "sudp";
                let addr = format_socket_addr(&bind_addr, port);
                let bind_result = UdpSocket::bind(&addr).await;
                // For SUDP with an already-bound shared port, bind may fail with
                // EADDRINUSE — that's expected, reuse existing socket for this port.
                let socket = match bind_result {
                    Ok(s) => std::sync::Arc::new(s),
                    Err(e) if is_sudp => {
                        // Try to find an existing socket on this port
                        let found = udp_sockets.iter().find_map(|(_, sock)| {
                            sock.local_addr()
                                .ok()
                                .filter(|a| a.port() == port)
                                .map(|_| sock.clone())
                        });
                        match found {
                            Some(sock) => {
                                info!(proxy_name = %np.proxy_name, port = %port, "SUDP proxy '{}' sharing port {} (reusing existing socket)", np.proxy_name, port);
                                sock
                            }
                            None => {
                                tracing::error!(port = %port, error = %e, "SUDP port {} bind failed (no existing socket to share): {}", port, e);
                                // Roll back port tracking: remove from used_udp_ports
                                // (safe even if port was pre-existing — the bind failure
                                // means it's unusable).
                                state.used_udp_ports.write().await.remove(&port);
                                state
                                    .client_ports_used
                                    .write()
                                    .await
                                    .entry(run_id.to_string())
                                    .and_modify(|c| *c = c.saturating_sub(1));
                                state.proxy_manager.remove(&np.proxy_name).await;
                                reject_new_proxy(
                                    writer,
                                    &np.proxy_name,
                                    err_msg(
                                        state.detailed_errors_to_client,
                                        format!("SUDP bind failed: {e}"),
                                        "SUDP bind failed",
                                    ),
                                    v2,
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(port = %port, error = %e, "Failed to bind UDP port {}: {}", port, e);
                        state.used_udp_ports.write().await.remove(&port);
                        state
                            .client_ports_used
                            .write()
                            .await
                            .entry(run_id.to_string())
                            .and_modify(|c| *c = c.saturating_sub(1));
                        state.proxy_manager.remove(&np.proxy_name).await;
                        reject_new_proxy(
                            writer,
                            &np.proxy_name,
                            err_msg(
                                state.detailed_errors_to_client,
                                format!("UDP bind failed: {e}"),
                                "UDP bind failed",
                            ),
                            v2,
                        )
                        .await;
                        return;
                    }
                };
                udp_sockets.insert(np.proxy_name.clone(), socket);
                // Build reverse lookup: local_addr → proxy_name for routing UDPPacket responses
                if let Some(ref local_str) = np.local_str {
                    if !local_str.is_empty() {
                        udp_local_to_proxy.insert(local_str.clone(), np.proxy_name.clone());
                    }
                }
                // For SUDP sharing existing socket, don't spawn duplicate listener
                let should_spawn = !is_sudp
                    || !udp_sockets.iter().any(|(n, _)| {
                        n != &np.proxy_name && {
                            udp_sockets
                                .get(n)
                                .and_then(|s| s.local_addr().ok())
                                .is_some_and(|a| a.port() == port)
                        }
                    });
                if should_spawn {
                    // Go frp v0.69.1 compat: UDP data flows over work connections,
                    // not the control connection. Request a work conn from the client.
                    // Use oneshot channel to ensure NewProxyResp is written BEFORE
                    // ReqWorkConn, avoiding race where client receives ReqWorkConn
                    // before proxy registration completes.
                    let pn_clone = np.proxy_name.clone();
                    let itx_clone = itx.clone();
                    let (tx, rx) = oneshot::channel();
                    udp_resp_signals.push(tx);
                    tokio::spawn(async move {
                        let _ = rx.await; // Wait until NewProxyResp is written
                                          // send().await: backpressure is correct — silently
                                          // dropping UdpNeedsWorkConn would permanently break
                                          // the UDP proxy (no work connection = no data flow).
                        let _ = itx_clone
                            .send(InternalMsg::UdpNeedsWorkConn {
                                proxy_name: pn_clone,
                            })
                            .await;
                    });
                }
                info!(is_sudp = %is_sudp, proxy_name = %np.proxy_name, port = %port, "{} proxy '{}' listening on port {}", if is_sudp { "SUDP" } else { "UDP" }, np.proxy_name, port);
            } else if is_nat_hole {
                info!(proxy_type = %np.proxy_type, proxy_name = %np.proxy_name, "{} proxy '{}' registered (no listener, NAT hole punch)", np.proxy_type, np.proxy_name);
            } else if tcp_group_created {
                // TCP group first member: create a shared group listener
                // that dispatches connections via round-robin (Go frp dev compat).
                // NOT a per-proxy listener — groups share one port.
                let group_name = np.group.clone().unwrap_or_default();
                let group_key = np.group_key.clone().unwrap_or_default();
                info!(
                    proxy_name = %np.proxy_name,
                    group = %group_name,
                    port = %port,
                    "TCP proxy '{}' creating shared group listener for '{}' on port {}",
                    np.proxy_name, group_name, port,
                );
                let cancel_token = tokio_util::sync::CancellationToken::new();
                let ct = cancel_token.clone();
                let st = state.clone();
                let gn = group_name.clone();
                let ba = bind_addr.clone();
                let handle = tokio::spawn(async move {
                    tcp_group_listener(ba, port, gn, st, ct).await;
                });
                if let Err(e) = state
                    .tcp_group_ctl
                    .create_group(
                        &group_name,
                        &group_key,
                        port,
                        &bind_addr,
                        handle,
                        cancel_token,
                    )
                    .await
                {
                    warn!(
                        proxy_name = %np.proxy_name,
                        group = %group_name,
                        error = %e,
                        "Failed to register TCP group '{}': {}",
                        group_name, e,
                    );
                }
            } else if np.proxy_type == "tcp" {
                // Only TCP proxies bind a per-proxy listener. HTTP/HTTPS use
                // the shared vhost listener, TCPMux the shared tcpmux
                // listener, and STCP/XTCP have no remote port.
                let handle = tokio::spawn(async move {
                    listen_and_proxy(bind_addr, port, pn, itx).await;
                });
                listener_handles.insert(np.proxy_name.clone(), handle);
            } else {
                info!(
                    proxy_type = %np.proxy_type,
                    proxy_name = %np.proxy_name,
                    port = %port,
                    "{} proxy '{}' registered (shared listener, port {})",
                    np.proxy_type,
                    np.proxy_name,
                    port
                );
            }

            info!(proxy_name = %np.proxy_name, port = %port, run_id = %run_id, "Proxy '{}' registered on port {} (run_id: {})", np.proxy_name, port, run_id);

            // Emit WebSocket event for dashboard subscribers
            #[cfg(feature = "dashboard")]
            {
                let _ = state.event_tx.send(crate::event::ServerEvent::ProxyUp {
                    proxy_name: np.proxy_name.clone(),
                    proxy_type: np.proxy_type.clone(),
                    run_id: run_id.to_string(),
                    remote_port: Some(port),
                });
            }

            let remote_addr_str = format!("{}:{}", state.proxy_bind_addr, port);
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_addr: Some(remote_addr_str),
                error: None,
            });
            write_resp(writer, &resp, v2).await;

            // Signal UDP work-conn tasks that NewProxyResp has been written.
            // This ensures ReqWorkConn is never sent to the client before the
            // proxy registration response, preventing a race in the Go frp
            // v0.69.1 compatibility path.
            for tx in udp_resp_signals.drain(..) {
                let _ = tx.send(());
            }
        }
        None => {
            warn!(proxy_name = %np.proxy_name, "No available port for proxy '{}'", np.proxy_name);
            reject_new_proxy(writer, &np.proxy_name, "no available port".into(), v2).await;
        }
    }
}

/// Listen on a proxy port and forward incoming connections to the control handler.
#[instrument(skip(internal_tx), fields(proxy_name = %proxy_name, port = %port))]
pub(crate) async fn listen_and_proxy(
    bind_addr: String,
    port: u16,
    proxy_name: String,
    internal_tx: mpsc::Sender<InternalMsg>,
) {
    let addr = format_socket_addr(&bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!(addr = %addr, proxy_name = %proxy_name, "Proxy listener started on {} for '{}'", addr, proxy_name);
            l
        }
        Err(e) => {
            tracing::error!(port = %port, error = %e, "Failed to bind proxy port {}: {}", port, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((user_conn, _addr)) => {
                frp_core::transport::set_nodelay(&user_conn);
                match internal_tx.try_send(InternalMsg::ProxyUserConn {
                    proxy_name: proxy_name.clone(),
                    user_conn: IoStream::Tcp(user_conn),
                    pre_read: vec![],
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Channel is temporarily full — drop this connection
                        // and continue accepting. Do NOT stop the listener.
                        tracing::debug!(
                            proxy_name = %proxy_name,
                            "Proxy listener backpressure, dropping user connection for '{}'",
                            proxy_name
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!(proxy_name = %proxy_name, "Control handler gone, stopping proxy listener for '{}'", proxy_name);
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::error!(port = %port, error = %e, "Accept error on proxy port {}: {}", port, e);
                break;
            }
        }
    }
}

/// Remove a control's routing/registry/OIDC state.
///
/// `control_id` is the removing control's own generation. The `run_id` map
/// entry is only removed when it still belongs to that generation (or when
/// `control_id` is 0 for legacy callers that do not track generations), so a
/// slow post-login failure can never delete a superseding control's entry.
/// `skip_ctl_unregister` is used by the supersession path where the new
/// handler has already installed its replacement `ControlTx`.
pub(crate) async fn unregister_control(
    state: &Arc<AppState>,
    run_id: &str,
    control_id: u64,
    skip_ctl_unregister: bool,
) {
    let removed_control_id = if !skip_ctl_unregister {
        let current_control_id = {
            let map = state.run_id_to_ctl_tx.read().await;
            map.get(run_id).map(|c| c.control_id).unwrap_or(0)
        };
        if control_id != 0 && current_control_id != control_id {
            None
        } else {
            let mut map = state.run_id_to_ctl_tx.write().await;
            map.remove(run_id);
            // Mark the client offline in the registry, generation-aware.
            state
                .client_registry
                .mark_offline_by_run_id_and_control_id(run_id, current_control_id);
            Some(current_control_id)
        }
    } else {
        None
    };
    // Release allocated ports and clean up sk/vhost entries for this client
    let proxies = state.proxy_manager.list_client(run_id).await;
    // TCP port cleanup
    let mut ports = state.used_ports.write().await;
    for p in &proxies {
        if let Some(port) = p.remote_port {
            // For TCP group proxies, only release the port if this is the last
            // member of the group. Otherwise the shared group listener still
            // needs the port.
            let is_tcp_group =
                p.proxy_type == "tcp" && p.group.as_deref().filter(|g| !g.is_empty()).is_some();
            if is_tcp_group {
                // Check if the group still has other members
                let group_name = p.group.as_deref().unwrap_or("");
                if state.proxy_manager.group_len(group_name).await <= 1 {
                    ports.remove(&port);
                    if port > 0 {
                        state
                            .port_reservations
                            .write()
                            .await
                            .insert(p.name.clone(), (port, false, std::time::Instant::now()));
                    }
                    // Stop the shared group listener
                    state.tcp_group_ctl.remove_group(group_name).await;
                }
            } else if p.proxy_type != "udp" && p.proxy_type != "sudp" {
                ports.remove(&port);
                if port > 0 {
                    state
                        .port_reservations
                        .write()
                        .await
                        .insert(p.name.clone(), (port, false, std::time::Instant::now()));
                }
            }
        }
        // Clean up STCP sk_index (indexed by proxy_name — exact match, no
        // risk of removing another proxy's entry even when keys are shared)
        if let Some(key) = p.sk_index_key() {
            state.xtcp.sk_index.write().await.remove(key);
        }
    }
    drop(ports);
    // UDP port cleanup (Go frp compat: separate port manager for UDP)
    let mut udp_ports = state.used_udp_ports.write().await;
    for p in &proxies {
        if let Some(port) = p.remote_port {
            if p.proxy_type == "udp" || p.proxy_type == "sudp" {
                // For SUDP, only release the port if no other SUDP proxy uses it
                if p.proxy_type == "sudp" {
                    let count = proxies
                        .iter()
                        .filter(|op| {
                            op.proxy_type == "sudp"
                                && op.remote_port == Some(port)
                                && op.name != p.name
                        })
                        .count();
                    if count == 0 {
                        udp_ports.remove(&port);
                        if port > 0 {
                            state
                                .port_reservations
                                .write()
                                .await
                                .insert(p.name.clone(), (port, true, std::time::Instant::now()));
                        }
                    }
                } else {
                    udp_ports.remove(&port);
                    if port > 0 {
                        state
                            .port_reservations
                            .write()
                            .await
                            .insert(p.name.clone(), (port, true, std::time::Instant::now()));
                    }
                }
            }
        }
    }
    drop(udp_ports);
    // Clear per-client port usage tracking (matching Go frp's portsUsedNum cleanup).
    state.client_ports_used.write().await.remove(run_id);
    // VHost unregister outside port lock to avoid holding it across awaits
    for p in &proxies {
        state.vhost_manager.unregister(&p.name).await;
        state.tcpmux_manager.unregister(&p.name).await;
        state.proxy_metrics.remove(&p.name).await;
    }
    #[cfg(feature = "vnet")]
    state.remove_run_id_vnet_routes(run_id).await;
    // Clean up OIDC subject mapping for this client.
    // Map key is run_id; remove it directly rather than scanning values
    // (which are OIDC subject strings, not proxy names — retain would
    // never match and entries would leak unboundedly).
    {
        let mut subjects = state.oidc.subjects.write().await;
        if let Some(control_id) = removed_control_id {
            if subjects
                .get(run_id)
                .is_some_and(|(_, generation)| *generation == control_id)
            {
                subjects.remove(run_id);
            }
        }
    }
}

// ---- TCP group shared listener ----

/// Shared TCP group listener: accepts connections on the group's shared port
/// and dispatches them to group members via round-robin (`select_group_backend`).
/// Stops when the group has no members or the cancel token is triggered.
#[instrument(skip(state, cancel_token), fields(group = %group_name, port = %port))]
async fn tcp_group_listener(
    bind_addr: String,
    port: u16,
    group_name: String,
    state: Arc<AppState>,
    cancel_token: tokio_util::sync::CancellationToken,
) {
    let addr = format_socket_addr(&bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!(
                addr = %addr,
                group = %group_name,
                "TCP group '{}' shared listener started on {}",
                group_name, addr,
            );
            l
        }
        Err(e) => {
            tracing::error!(
                port = %port,
                group = %group_name,
                error = %e,
                "Failed to bind TCP group port {} for '{}': {}",
                port, group_name, e,
            );
            return;
        }
    };

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!(group = %group_name, "TCP group '{}' shared listener cancelled", group_name);
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((conn, _addr)) => {
                        frp_core::transport::set_nodelay(&conn);
                        // Check if group still has members before dispatching
                        if state.proxy_manager.group_len(&group_name).await == 0 {
                            info!(group = %group_name, "TCP group '{}' has no members, stopping listener", group_name);
                            break;
                        }
                        // Select a backend via round-robin (Go frp dev compat).
                        // group_key is empty here — the shared listener uses simple
                        // round-robin across ALL group members regardless of key.
                        // The key-based affinity is maintained per-proxy via the
                        // existing handle_proxy_user_conn group dispatch in pool.rs.
                        if let Some((backend, backend_run_id)) = state
                            .proxy_manager
                            .select_group_backend_with_run_id(&group_name, "")
                            .await
                        {
                            let ctl_tx = {
                                let map = state.run_id_to_ctl_tx.read().await;
                                map.get(&backend_run_id).map(|c| c.tx.clone())
                            };
                            if let Some(tx) = ctl_tx {
                                if let Err(e) = tx.try_send(InternalMsg::ProxyUserConn {
                                    proxy_name: backend,
                                    user_conn: frp_core::transport::IoStream::Tcp(conn),
                                    pre_read: vec![],
                                }) {
                                    debug!(
                                        group = %group_name,
                                        error = %e,
                                        "Failed to dispatch connection from group '{}': {}",
                                        group_name, e,
                                    );
                                }
                            } else {
                                debug!(
                                    group = %group_name,
                                    backend = %backend,
                                    "Group '{}' backend '{}' has no active control handler",
                                    group_name, backend,
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            port = %port,
                            group = %group_name,
                            error = %e,
                            "TCP group '{}' accept error on port {}: {}",
                            group_name, port, e,
                        );
                        break;
                    }
                }
            }
        }
    }
}

/// Register a proxy as a member of an existing TCP group.
/// This function is used when a TCP proxy joins a group that already
/// has a shared listener. It registers the proxy with ProxyManager
/// (so select_group_backend can route connections to it) but does NOT
/// create a new listener — the shared group listener handles dispatch.
///
/// Returns early (via `return` from `handle_new_proxy`) after registration,
/// skipping the normal listener creation path.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_group_member_registration(
    state: &Arc<AppState>,
    run_id: &str,
    writer: &mut (impl AsyncWriteExt + Unpin),
    np: msg::NewProxy,
    _remote_port: u16,
    _internal_tx: &mpsc::Sender<InternalMsg>,
    _listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    _udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    _udp_local_to_proxy: &mut std::collections::HashMap<String, String>,
    v2: bool,
    allocated_port: Option<u16>,
    _tcp_group_created: bool,
) {
    let port = match allocated_port {
        Some(p) => p,
        None => {
            reject_new_proxy(
                writer,
                &np.proxy_name,
                "no available port (TCP group)".into(),
                v2,
            )
            .await;
            return;
        }
    };

    let virtual_net = np.virtual_net.clone().filter(|v| !v.is_empty());
    let info = ProxyInfo {
        name: np.proxy_name.clone(),
        proxy_type: np.proxy_type.clone(),
        run_id: run_id.to_string(),
        remote_port: Some(port),
        sk: np.sk.clone(),
        group: np.group.clone(),
        group_key: np.group_key.clone(),
        local_addr: np.local_str.clone(),
        use_encryption: np.use_encryption.unwrap_or(false),
        use_compression: np.use_compression.unwrap_or(false),
        virtual_net: virtual_net.clone(),
        allow_users: np.allow_users.clone().unwrap_or_default(),
        proxy_protocol_version: np.proxy_protocol_version.clone().unwrap_or_default(),
        response_headers: np.response_headers.clone().unwrap_or_default(),
        custom_domains: np.custom_domains.clone().unwrap_or_default(),
        route_by_http_user: np.route_by_http_user.clone().unwrap_or_default(),
        multiplexer: np.multiplexer.clone().unwrap_or_default(),
        bandwidth_limit: np.bandwidth_limit.clone().unwrap_or_default(),
        bandwidth_limit_mode: np.bandwidth_limit_mode.clone().unwrap_or_default(),
        user: state
            .run_id_to_ctl_tx
            .read()
            .await
            .get(run_id)
            .map(|c| c.user.clone())
            .unwrap_or_default(),
    };

    if let Err(e) = state
        .proxy_manager
        .register(run_id.to_string(), info.clone())
        .await
    {
        state.used_ports.write().await.remove(&port);
        reject_new_proxy(
            writer,
            &np.proxy_name,
            err_msg(
                state.detailed_errors_to_client,
                e,
                "proxy registration conflict (TCP group)",
            ),
            v2,
        )
        .await;
        return;
    }

    // Emit dashboard event
    #[cfg(feature = "dashboard")]
    {
        let _ = state.event_tx.send(crate::event::ServerEvent::ProxyUp {
            proxy_name: np.proxy_name.clone(),
            proxy_type: np.proxy_type.clone(),
            run_id: run_id.to_string(),
            remote_port: Some(port),
        });
    }

    info!(
        proxy_name = %np.proxy_name,
        port = %port,
        group = ?np.group,
        "TCP proxy '{}' joined group '{}' on port {} (shared listener)",
        np.proxy_name,
        np.group.as_deref().unwrap_or(""),
        port,
    );

    let remote_addr_str = format!(":{}", port);
    let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
        proxy_name: np.proxy_name.clone(),
        remote_addr: Some(remote_addr_str),
        error: None,
    });
    write_resp(writer, &resp, v2).await;
}
