use std::sync::atomic::Ordering;
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
use crate::proxy::ProxyInfo;
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

/// Allocate the remote port for a new proxy (Go frp `ports.Manager` compat):
/// SUDP override, per-client reservations with 24h expiry, allow-ports range
/// scans, and OS-level bind probes. Extracted from `handle_new_proxy`'s
/// state machine — no `.await`-free parts remain in the parent.
#[inline(never)]
async fn allocate_proxy_port(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    consumes_port: bool,
    is_udp_type: bool,
    is_sudp: bool,
    mut remote_port: u16,
) -> Option<u16> {
    // When sudp_port is configured, force all SUDP proxies to use that port
    if is_sudp && state.sudp_port > 0 {
        if remote_port > 0 && remote_port != state.sudp_port {
            info!(proxy_name = %np.proxy_name, remote_port = %remote_port, sudp_port = %state.sudp_port, "SUDP proxy '{}': overriding remote_port {} → {} (sudp_port config)",
                np.proxy_name, remote_port, state.sudp_port);
        }
        remote_port = state.sudp_port;
    }
    // Separate port managers for TCP and UDP (Go frp compat).
    // TCP port 8080 can coexist with UDP port 8080.
    if !consumes_port {
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
                if let Some(&(res_port, true, reserved_at)) = reservations.get(&np.proxy_name) {
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
        // TCP-type proxy (tcp): three-phase port allocation. The blocking OS
        // `TcpListener::bind` probe used to run while holding
        // `used_ports.write()` — serializing every TCP proxy registration
        // behind socket-bind latency. Now: pick a candidate under a brief
        // read lock, probe bindability OUTSIDE any lock, then commit under a
        // short write lock (re-checking to close the TOCTOU window).
        let allow_ports = state.reloadable.read_ok().allow_ports.clone();
        let candidate = if remote_port == 0 {
            // 24h reservation by proxy name (Go ports.Manager.Acquire).
            let res_candidate = {
                let mut reservations = state.port_reservations.write().await;
                // Lazy cleanup (Go cleanReservedPortsWorker): drop expired
                // entries so the map does not grow without bound.
                if let Some(&(res_port, false, reserved_at)) = reservations.get(&np.proxy_name) {
                    if reserved_at.elapsed() >= std::time::Duration::from_secs(24 * 3600) {
                        reservations.remove(&np.proxy_name);
                        None
                    } else {
                        Some(res_port)
                    }
                } else {
                    None
                }
            };
            // Check used_ports OUTSIDE the reservations write lock. Holding
            // port_reservations across a used_ports acquisition inverts the
            // lock order vs unregister_control (used_ports.write() →
            // port_reservations.write()) and deadlocks both on
            // reconnect-during-cleanup. The commit phase below re-checks
            // under used_ports.write(), closing the small race this opens.
            let res_candidate = match res_candidate {
                Some(res_port) => {
                    let used = state.used_ports.read().await;
                    if used.contains(&res_port) {
                        None
                    } else {
                        Some(res_port)
                    }
                }
                None => None,
            };
            // Probe bindability OUTSIDE the reservations write lock: the
            // blocking std::net::TcpListener::bind must not serialize
            // reservation lookups (audit D3-6).
            let res_candidate = match res_candidate {
                Some(p) if !crate::proxy::is_tcp_port_bindable(&state.proxy_bind_addr, p) => None,
                other => other,
            };
            match res_candidate {
                Some(p) => Some(p),
                None => {
                    // Collect candidates under a brief read lock, then probe
                    // each one OUTSIDE the lock (the blocking bind probe must
                    // not serialize registrations). `find` continues past
                    // occupied ports, matching the old in-lock scan.
                    let candidates = {
                        let used = state.used_ports.read().await;
                        crate::proxy::pick_tcp_port_candidates(&used, 0, &allow_ports, 4096)
                    };
                    candidates
                        .into_iter()
                        .find(|p| crate::proxy::is_tcp_port_bindable(&state.proxy_bind_addr, *p))
                }
            }
        } else {
            let candidates = {
                let used = state.used_ports.read().await;
                crate::proxy::pick_tcp_port_candidates(&used, remote_port, &allow_ports, 4096)
            };
            candidates
                .into_iter()
                .find(|p| crate::proxy::is_tcp_port_bindable(&state.proxy_bind_addr, *p))
        };
        // Commit under write lock; re-check to close the race with a
        // concurrent registration. On conflict (TOCTOU: two registrations
        // probed the same candidate), retry once inside the lock with the
        // next free candidate — the old in-lock scan would have continued
        // to the next available port instead of failing the registration.
        match candidate {
            Some(p) => {
                let mut ports = state.used_ports.write().await;
                if ports.contains(&p) {
                    tracing::debug!(
                        port = %p,
                        "Port {p} taken by a concurrent registration during allocation, retrying in-lock",
                    );
                    let retry = {
                        let used = &*ports;
                        crate::proxy::pick_tcp_port_candidates(used, 0, &allow_ports, 64)
                            .into_iter()
                            .find(|c| {
                                !ports.contains(c)
                                    && crate::proxy::is_tcp_port_bindable(
                                        &state.proxy_bind_addr,
                                        *c,
                                    )
                            })
                    };
                    match retry {
                        Some(p2) => {
                            ports.insert(p2);
                            Some(p2)
                        }
                        None => {
                            tracing::warn!(
                                ranges = ?allow_ports,
                                "Port exhaustion after allocation race: no available ports",
                            );
                            None
                        }
                    }
                } else {
                    ports.insert(p);
                    Some(p)
                }
            }
            None => None,
        }
    }
}

/// Build the `ProxyInfo` for a registered proxy. Shared by
/// `handle_new_proxy` and `handle_tcp_group_member_registration`.
#[inline(never)]
async fn build_proxy_info(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    control_id: u64,
    port: u16,
) -> ProxyInfo {
    let virtual_net = np.virtual_net.clone().filter(|v| !v.is_empty());
    ProxyInfo {
        name: np.proxy_name.clone(),
        proxy_type: np.proxy_type.clone(),
        run_id: run_id.to_string(),
        // Registration generation (audit finding 3): a disconnect sweep
        // skips proxies registered by a superseding control.
        control_id,
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
            .get(run_id)
            .map(|c| c.user.clone())
            .unwrap_or_default(),
        user_conn_sem: (state.max_conns_per_proxy > 0).then(|| {
            Arc::new(tokio::sync::Semaphore::new(
                state.max_conns_per_proxy as usize,
            ))
        }),
    }
}

/// Register the STCP/XTCP secret-key index before proxy registration
/// (visitor-before-provider race, Go frp `startVisitorListener` compat).
/// Returns whether an index entry was inserted.
#[inline(never)]
async fn register_sk_index(state: &Arc<AppState>, np: &msg::NewProxy) -> bool {
    let needs_sk_index =
        (np.proxy_type == "stcp" || np.proxy_type == "xtcp" || np.proxy_type == "sudp")
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
        info!(proxy_name = %np.proxy_name, vn = %vn, "STCP/XTCP/SUDP sk_index registered for '{}'{}",
            np.proxy_name,
            if vn.is_empty() { String::new() } else { format!(" (virtual_net: {vn})") });
    }
    needs_sk_index
}

/// Roll back a failed registration after a `proxy_manager.register` error:
/// remove the sk-index entry (if any) and release the port from whichever
/// port set it was allocated from.
#[inline(never)]
async fn rollback_port_allocation(
    state: &Arc<AppState>,
    proxy_name: &str,
    port: u16,
    is_udp_type: bool,
    needs_sk_index: bool,
) {
    if needs_sk_index {
        state.xtcp.sk_index.write().await.remove(proxy_name);
    }
    state.used_ports.write().await.remove(&port);
    // For UDP proxies, also clean up used_udp_ports. The port
    // was allocated from the TCP set by the TCP group path
    // (TCP group proxies are always TCP, not UDP).
    // SUDP proxies share one server port across run_ids: only release the
    // UDP-port mark if no OTHER live udp/sudp proxy still occupies it.
    // Exclude nothing here: this rollback runs after a *failed* register,
    // so we are not in the registry — and if the failure was a same-name
    // conflict, the live proxy holding the port must count as an owner.
    if is_udp_type
        && !udp_port_has_other_owner(state, port, &std::collections::HashSet::new()).await
    {
        state.used_udp_ports.write().await.remove(&port);
    }
}

/// True if a live UDP/SUDP proxy not in `exclude` still holds `port`.
///
/// SUDP proxies can share a single server UDP port (the frp-rs shared-port
/// extension) across proxies and run_ids, so UDP-port bookkeeping must not
/// be torn down while another owner remains. `exclude` is the set of names
/// being removed *by this caller*: during teardown the proxies being
/// deleted are still in the registry, so they must not count as owners.
async fn udp_port_has_other_owner(
    state: &Arc<AppState>,
    port: u16,
    exclude: &std::collections::HashSet<String>,
) -> bool {
    state.proxy_manager.list().await.into_iter().any(|info| {
        info.remote_port == Some(port)
            && (info.proxy_type == "udp" || info.proxy_type == "sudp")
            && !exclude.contains(&info.name)
    })
}

/// Release a UDP port mark when no OTHER live udp/sudp proxy still holds
/// it, returning whether the port was released.
///
/// SUDP proxies can share one server port (frp-rs extension); closing one
/// proxy must not free the mark while a sibling still owns the bound
/// socket — otherwise the next SUDP registration's OS bind probe fails
/// with EADDRINUSE even though the shared socket is alive (audit finding
/// 2). The closing proxy itself is still in the registry when callers
/// invoke this, so it is excluded from the owner count.
pub(crate) async fn release_udp_port_with_owner_check(
    state: &Arc<AppState>,
    port: u16,
    closing_proxy: &str,
) -> bool {
    let mut exclude = std::collections::HashSet::new();
    exclude.insert(closing_proxy.to_string());
    if udp_port_has_other_owner(state, port, &exclude).await {
        return false;
    }
    state.used_udp_ports.write().await.remove(&port);
    true
}

/// Roll back a vhost route conflict: release the port and decrement the
/// per-client port count. Callers keep their own `proxy_manager.remove`
/// and error-response ordering.
///
/// Both actions only apply when the failing proxy actually consumed a
/// port: http/https/tcpmux proxies register with remote port 0 and never
/// incremented `client_ports_used` (audit finding 8), so rolling back
/// must not remove another proxy's port mark or under-count the client.
#[inline(never)]
async fn rollback_vhost_conflict(
    state: &Arc<AppState>,
    run_id: &str,
    port: u16,
    consumes_port: bool,
) {
    if !consumes_port {
        return;
    }
    state.used_ports.write().await.remove(&port);
    state
        .client_ports_used
        .write()
        .await
        .entry(run_id.to_string())
        .and_modify(|c| *c = c.saturating_sub(1));
}

/// Roll back a failed UDP/SuDP bind: release the UDP port, decrement the
/// per-client port count, and drop the proxy registration.
#[inline(never)]
async fn rollback_udp_bind_failure(
    state: &Arc<AppState>,
    run_id: &str,
    port: u16,
    proxy_name: &str,
) {
    state.used_udp_ports.write().await.remove(&port);
    state
        .client_ports_used
        .write()
        .await
        .entry(run_id.to_string())
        .and_modify(|c| *c = c.saturating_sub(1));
    state.proxy_manager.remove(proxy_name).await;
}

/// Roll back a failed TCP bind: release the TCP port, decrement the
/// per-client port count, and drop the proxy registration. Mirrors
/// `rollback_udp_bind_failure` — TCP proxies register no sk_index or
/// vhost/tcpmux routes, so this covers everything a TCP proxy registered
/// before `setup_proxy_listeners` ran (audit finding 4).
#[inline(never)]
async fn rollback_tcp_bind_failure(
    state: &Arc<AppState>,
    run_id: &str,
    port: u16,
    proxy_name: &str,
) {
    state.used_ports.write().await.remove(&port);
    state
        .client_ports_used
        .write()
        .await
        .entry(run_id.to_string())
        .and_modify(|c| *c = c.saturating_sub(1));
    state.proxy_manager.remove(proxy_name).await;
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
    // Reject ALL control characters (including CR/LF, which previously slipped
    // through) — proxy_name flows into vhost keys, sk_index, logs, dashboard
    // events and wire messages.
    if np.proxy_name.contains(|c: char| c.is_control()) {
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
            // Character whitelist + structure: only DNS-ish names are
            // routable vhost keys. Reject wildcards (`*` catch-all would let
            // a tenant hijack every host on a shared vhost deployment),
            // whitespace, CR/LF, and empty labels.
            if domain.is_empty()
                || !domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                || domain.starts_with('.')
                || domain.ends_with('.')
                || domain.contains("..")
                || domain.contains('*')
                || domain.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(format!(
                    "custom_domain '{}' contains invalid characters or structure (letters, digits, '.', '-', '_' only; no wildcards)",
                    domain
                ));
            }
        }
    }
    if let Some(ref subdomain) = np.subdomain {
        // Single DNS label: letters/digits/'-', no '.', not starting/ending
        // with '-'. Without this, a subdomain containing '.' could register
        // arbitrary-depth names under the vhost root (Go frp applies the same
        // RFC 1123 label rules).
        let valid = !subdomain.is_empty()
            && subdomain.len() <= 63
            && subdomain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !subdomain.starts_with('-')
            && !subdomain.ends_with('-');
        if !valid {
            return Err(format!(
                "subdomain '{}' is not a valid RFC 1123 DNS label (letters, digits, '-'; no leading/trailing '-' or '.')",
                subdomain
            ));
        }
    }
    Ok(())
}

/// Register HTTP vhost routes for an http proxy (domains + locations,
/// subdomain expansion, catch-all fallback). On route conflict, rolls back
/// the registration, rejects the proxy, and returns `false` — the caller
/// must abort. Extracted from `handle_new_proxy`'s state machine.
#[inline(never)]
async fn register_http_vhost(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    port: u16,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
) -> bool {
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
    let headers: Vec<(String, String)> =
        np.headers.clone().unwrap_or_default().into_iter().collect();
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
        // Roll back previous registrations. http proxies never consume a
        // port (remote port 0), so the rollback is a no-op — kept for
        // symmetry with the general conflict path (audit finding 8).
        rollback_vhost_conflict(state, run_id, port, false).await;
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
        return false;
    }
    info!(proxy_name = %np.proxy_name, domains = ?domains, locations = ?locations, hhr = ?hhr, "VHost routes registered for '{}': domains={:?}, locations={:?}, rewrite={:?}",
        np.proxy_name, domains, locations, hhr);
    true
}

/// Register HTTPS vhost routes for an https proxy (SNI routing, subdomain
/// expansion) and enable the SNI-sniff gate in the accept loop. On route
/// conflict, rolls back the registration, rejects the proxy, and returns
/// `false` — the caller must abort. Extracted from `handle_new_proxy`'s
/// state machine.
#[inline(never)]
async fn register_https_vhost(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    port: u16,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
) -> bool {
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
    let headers: Vec<(String, String)> =
        np.headers.clone().unwrap_or_default().into_iter().collect();
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
        // Roll back previous registrations. https proxies never consume a
        // port (remote port 0), so the rollback is a no-op — kept for
        // symmetry with the general conflict path (audit finding 8).
        rollback_vhost_conflict(state, run_id, port, false).await;
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
        return false;
    }
    // Enable the SNI-sniff gate in the accept loop: at least one
    // HTTPS proxy can be routed via ClientHello SNI. Decremented
    // on unregister/close (unregister_control, handle_close_proxy,
    // dashboard proxy delete).
    state.https_proxy_count.fetch_add(1, Ordering::Relaxed);
    info!(
        proxy_name = %np.proxy_name, domains = ?domains, "VHost SNI routes registered for HTTPS proxy '{}': domains={:?}",
        np.proxy_name, domains
    );
    true
}

/// Set up the per-proxy listener for a newly registered proxy: UDP/SuDP
/// socket bind with work-conn requesters, TCP group shared listener, or
/// per-proxy TCP listener. Returns the oneshot senders that must be fired
/// after NewProxyResp is written (they gate ReqWorkConn on the response),
/// or `Err(())` if the proxy was already rejected (bind failure) and the
/// caller must abort. Extracted from `handle_new_proxy`'s state machine.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
async fn setup_proxy_listeners(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    port: u16,
    bind_addr: &str,
    itx: &mpsc::Sender<InternalMsg>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
    tcp_group_created: bool,
) -> Result<Vec<oneshot::Sender<()>>, ()> {
    let is_nat_hole =
        np.proxy_type == "stcp" || np.proxy_type == "xtcp" || np.proxy_type == "tcpmux";
    let pn = np.proxy_name.clone();
    let itx = itx.clone();
    let bind_addr = bind_addr.to_string();

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
        let socket: Option<std::sync::Arc<UdpSocket>> = match bind_result {
            Ok(s) => Some(std::sync::Arc::new(s)),
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
                        Some(sock)
                    }
                    None => {
                        // Go frp v0.70.1 has NO server-side UDP port for SUDP
                        // (visitor model only); the shared server port is a
                        // frp-rs extension. A bind failure (e.g. privileged
                        // port scan colliding with another proxy) must NOT
                        // fail registration — the visitor tunnel still works.
                        // Log and continue without a server socket.
                        warn!(proxy_name = %np.proxy_name, port = %port, error = %e,
                            "SUDP proxy '{}': shared server port {} unavailable; registering visitor-only (Go frp semantics)",
                            np.proxy_name, port);
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(port = %port, error = %e, "Failed to bind UDP port {}: {}", port, e);
                rollback_udp_bind_failure(state, run_id, port, &np.proxy_name).await;
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
                return Err(());
            }
        };
        if let Some(ref socket) = socket {
            udp_sockets.insert(np.proxy_name.clone(), socket.clone());
        }
        // For SUDP sharing existing socket, don't spawn duplicate listener.
        // Also skip when the shared port could not be bound (visitor-only).
        let should_spawn = socket.is_some()
            && (!is_sudp
                || !udp_sockets.iter().any(|(n, _)| {
                    n != &np.proxy_name && {
                        udp_sockets
                            .get(n)
                            .and_then(|s| s.local_addr().ok())
                            .is_some_and(|a| a.port() == port)
                    }
                }));
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
        if socket.is_none() {
            // Shared server port could not be bound — visitor-only SUDP
            // (Go frp semantics). The proxy is fully registered; only the
            // frp-rs shared-port extension is unavailable.
            info!(is_sudp = %is_sudp, proxy_name = %np.proxy_name, port = %port,
                "SUDP proxy '{}' registered (visitor-only, no shared server port {})",
                np.proxy_name, port);
        } else {
            info!(is_sudp = %is_sudp, proxy_name = %np.proxy_name, port = %port, "{} proxy '{}' listening on port {}", if is_sudp { "SUDP" } else { "UDP" }, np.proxy_name, port);
        }
    } else if is_nat_hole {
        info!(proxy_type = %np.proxy_type, proxy_name = %np.proxy_name, "{} proxy '{}' registered (no listener, NAT hole punch)", np.proxy_type, np.proxy_name);
    } else if tcp_group_created {
        // TCP group first member: create a shared group listener
        // that dispatches connections via round-robin (Go frp dev compat).
        // NOT a per-proxy listener — groups share one port. The listener
        // is bound synchronously so a bind failure rejects the proxy
        // instead of leaving a registered-but-dead group holding the port
        // (audit finding 4; mirrors the UDP/TCP bind rollback paths).
        let group_name = np.group.clone().unwrap_or_default();
        let group_key = np.group_key.clone().unwrap_or_default();
        let addr = format_socket_addr(&bind_addr, port);
        let listener = match bind_proxy_listener(&bind_addr, port, &np.proxy_name).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port = %port, error = %e, "Failed to bind TCP group port {} for '{}': {}", port, np.proxy_name, e);
                rollback_tcp_bind_failure(state, run_id, port, &np.proxy_name).await;
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    err_msg(
                        state.detailed_errors_to_client,
                        format!("TCP group bind failed: {e}"),
                        "TCP group bind failed",
                    ),
                    v2,
                )
                .await;
                return Err(());
            }
        };
        info!(
            proxy_name = %np.proxy_name,
            group = %group_name,
            port = %port,
            addr = %addr,
            "TCP proxy '{}' creating shared group listener for '{}' on port {}",
            np.proxy_name, group_name, port,
        );
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let ct = cancel_token.clone();
        let st = state.clone();
        let gn = group_name.clone();
        let handle = tokio::spawn(async move {
            tcp_group_listener(listener, port, gn, st, ct).await;
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
        //
        // Bind synchronously BEFORE the NewProxyResp is written: a bind
        // failure (TOCTOU race with the allocation-time probe) must reject
        // the proxy instead of leaving a registered-but-dead proxy holding
        // the port (audit finding 4; mirrors the UDP bind rollback path).
        let addr = format_socket_addr(&bind_addr, port);
        let listener = match bind_proxy_listener(&bind_addr, port, &np.proxy_name).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port = %port, error = %e, "Failed to bind proxy port {}: {}", port, e);
                rollback_tcp_bind_failure(state, run_id, port, &np.proxy_name).await;
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    err_msg(
                        state.detailed_errors_to_client,
                        format!("TCP bind failed: {e}"),
                        "TCP bind failed",
                    ),
                    v2,
                )
                .await;
                return Err(());
            }
        };
        info!(addr = %addr, proxy_name = %np.proxy_name, "Proxy listener started on {} for '{}'", addr, np.proxy_name);
        let tcp_keepalive = state.tcp_keepalive;
        let handle = tokio::spawn(async move {
            listen_and_proxy(listener, port, pn, itx, tcp_keepalive).await;
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
    Ok(udp_resp_signals)
}

/// Register a new proxy and start listening on its assigned port.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(state, writer, internal_tx, listener_handles, udp_sockets), fields(proxy_name = %np.proxy_name, proxy_type = %np.proxy_type, run_id = %run_id))]
pub(crate) async fn handle_new_proxy(
    np: msg::NewProxy,
    run_id: &str,
    control_id: u64,
    state: &Arc<AppState>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    internal_tx: &mpsc::Sender<InternalMsg>,
    listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
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
    // NOTE (review): benign TOCTOU — a concurrent deregistration can remove
    // the group between our port insert (below) and the callee's
    // failure-path removal; the stale reservation is lazily cleaned by the
    // 24h expiry sweep, so no correctness issue.
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
            // Scope the write lock: the callee below takes `used_ports.write()`
            // again (on register failure it removes the port), and tokio's
            // RwLock is NOT reentrant — holding `ports` here would
            // self-deadlock the control select loop (audit D3-1).
            let allocated_port = {
                let mut ports = state.used_ports.write().await;
                ports.insert(group_port);
                Some(group_port)
            };
            // Jump to proxy registration, skipping listener creation below.
            handle_tcp_group_member_registration(
                state,
                run_id,
                control_id,
                writer,
                np,
                remote_port,
                internal_tx,
                listener_handles,
                udp_sockets,
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

    // Separate port managers for TCP and UDP (Go frp compat).
    // TCP port 8080 can coexist with UDP port 8080.
    let is_udp_type = np.proxy_type == "udp" || np.proxy_type == "sudp";
    let allocated_port =
        allocate_proxy_port(state, &np, consumes_port, is_udp_type, is_sudp, remote_port).await;

    match allocated_port {
        Some(port) => {
            let info = build_proxy_info(state, &np, run_id, control_id, port).await;

            // Go frp compat: proxy.Run() calls startVisitorListener() BEFORE
            // proxyManager.Add(). Insert sk_index before proxy_manager.register()
            // so that STCP/XTCP visitors that arrive during the registration
            // window can find the proxy via sk_index fallback.
            let needs_sk_index = register_sk_index(state, &np).await;

            if let Err(e) = state
                .proxy_manager
                .register(run_id.to_string(), info.clone())
                .await
            {
                // Cleanup sk_index on registration failure
                rollback_port_allocation(state, &np.proxy_name, port, is_udp_type, needs_sk_index)
                    .await;
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
            // Only proxies that actually consume a port are counted:
            // stcp/xtcp/http/https/tcpmux register with remote port 0 and
            // would otherwise inflate the count the max_ports_per_client
            // gate checks (audit finding 1).
            if consumes_port && port > 0 {
                state
                    .client_ports_used
                    .write()
                    .await
                    .entry(run_id.to_string())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
            }

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
            if np.proxy_type == "http"
                && !register_http_vhost(state, &np, run_id, port, writer, v2).await
            {
                return;
            }

            // Register HTTPS proxies with VhostManager for SNI routing.
            // Routes by domain only (no path/location) — SNI hostname
            // from the TLS ClientHello determines the route.
            if np.proxy_type == "https"
                && !register_https_vhost(state, &np, run_id, port, writer, v2).await
            {
                return;
            }

            // Register TCPMux proxies with TcpMuxManager (domain-based CONNECT routing).
            // Follows the same pattern as VHost HTTP registration: a route
            // conflict rejects the proxy instead of silently overwriting the
            // live sibling's route (audit finding 5).
            if np.proxy_type == "tcpmux" {
                let domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();
                if domains.is_empty() {
                    // TCPMux requires at least one domain for routing
                    rollback_vhost_conflict(state, run_id, port, false).await;
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
                if let Err(conflict) = state
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
                    .await
                {
                    // Roll back previous registrations (mirror
                    // register_http_vhost). tcpmux proxies never consume a
                    // port, so the rollback is a no-op (audit finding 8).
                    rollback_vhost_conflict(state, run_id, port, false).await;
                    state.proxy_manager.remove(&np.proxy_name).await;
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        err_msg(
                            state.detailed_errors_to_client,
                            conflict,
                            "tcpmux route config conflict",
                        ),
                        v2,
                    )
                    .await;
                    return;
                }
                info!(
                    proxy_name = %np.proxy_name, domains = ?domains, "TCPMux routes registered for '{}': domains={:?}",
                    np.proxy_name, domains
                );
            }

            let mut udp_resp_signals = match setup_proxy_listeners(
                state,
                &np,
                run_id,
                port,
                &state.proxy_bind_addr,
                internal_tx,
                udp_sockets,
                listener_handles,
                writer,
                v2,
                tcp_group_created,
            )
            .await
            {
                Ok(signals) => signals,
                Err(()) => return,
            };

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

/// Bind a proxy listener on `bind_addr:port`, retrying briefly on
/// EADDRINUSE: on supersession the old handler's `abort()` schedules
/// cancellation but does not wait for the socket to be released, and the
/// retry lets the new handler win the bind instead of failing once
/// (audit round 5, MEDIUM 4.2). Callers bind synchronously so a bind
/// failure rejects the proxy before the success response is written
/// (audit finding 4).
async fn bind_proxy_listener(
    bind_addr: &str,
    port: u16,
    proxy_name: &str,
) -> Result<TcpListener, std::io::Error> {
    let addr = format_socket_addr(bind_addr, port);
    for attempt in 0..3 {
        match TcpListener::bind(&addr).await {
            Ok(l) => return Ok(l),
            Err(e) if attempt < 2 && e.kind() == std::io::ErrorKind::AddrInUse => {
                warn!(addr = %addr, proxy_name = %proxy_name, attempt = attempt + 1,
                    "Proxy port {} for '{}' busy (EADDRINUSE), retrying (attempt {})", port, proxy_name, attempt + 1);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e),
        }
    }
    // Unreachable: the final (third) failed bind returns via the catch-all
    // arm above; kept so the loop's Result type checks.
    Err(std::io::Error::other(
        "proxy listener bind failed after retries",
    ))
}

/// Accept loop for an already-bound proxy listener: forward incoming
/// connections to the control handler. The bind happens synchronously in
/// `setup_proxy_listeners` (audit finding 4) — this function only accepts.
#[instrument(skip(listener, internal_tx), fields(proxy_name = %proxy_name, port = %port))]
pub(crate) async fn listen_and_proxy(
    listener: TcpListener,
    port: u16,
    proxy_name: String,
    internal_tx: mpsc::Sender<InternalMsg>,
    tcp_keepalive: i64,
) {
    loop {
        match listener.accept().await {
            Ok((user_conn, _addr)) => {
                frp_core::transport::set_nodelay(&user_conn);
                if tcp_keepalive > 0 {
                    frp_core::transport::set_keepalive(&user_conn, tcp_keepalive as u64);
                }
                // send().await: backpressure is correct — the control channel
                // (cap 1024) can fill under a burst of user connections; Go frp
                // blocks here and lets the TCP backlog absorb the burst. This
                // accept loop is single-task, so stalling it only pauses this
                // proxy's accepts. A closed channel means the control handler
                // is gone — stop the listener.
                if let Err(e) = internal_tx
                    .send(InternalMsg::ProxyUserConn {
                        proxy_name: proxy_name.clone(),
                        user_conn: IoStream::Tcp(user_conn),
                        pre_read: vec![],
                    })
                    .await
                {
                    warn!(proxy_name = %proxy_name, error = %e, "Control handler gone, stopping proxy listener for '{}'", proxy_name);
                    break;
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
        let current_control_id = state
            .run_id_to_ctl_tx
            .get(run_id)
            .map(|c| c.control_id)
            .unwrap_or(0);
        if control_id != 0 && current_control_id != control_id {
            None
        } else {
            state.run_id_to_ctl_tx.remove(run_id);
            // Mark the client offline in the registry, generation-aware.
            state
                .client_registry
                .mark_offline_by_run_id_and_control_id(run_id, current_control_id);
            Some(current_control_id)
        }
    } else {
        None
    };
    // Release allocated ports and clean up sk/vhost entries for this client.
    // In the normal handoff path the old handler's cleanup finishes before
    // the new login proceeds (barrier), so everything is safe. If the 10s
    // handoff-barrier timeout fires (old handler stuck), the new control may
    // have already re-registered proxies for the same run_id — the filter
    // below skips any proxy registered by a newer control generation, so a
    // delayed cleanup can never tear down the superseding control's fresh
    // proxies (audit finding 3).
    let proxies: Vec<_> = state
        .proxy_manager
        .list_client(run_id)
        .await
        .into_iter()
        // Skip proxies registered by a NEWER control generation. control_id
        // == 0 (legacy callers) sweeps everything.
        .filter(|p| control_id == 0 || p.control_id <= control_id)
        .collect();
    // TODO(audit-fix): residual port-mark leak on barrier-timeout
    // supersession. When the 10s handoff barrier times out and the
    // superseding control has already re-registered the same proxy names,
    // those names are skipped here (newer control_id) — but the OLD
    // control's original port marks in used_ports/used_udp_ports are never
    // released, and nothing prunes used_ports (the 24h pruner only touches
    // port_reservations). Real fix: have proxy_manager.register() return
    // the ProxyInfo it replaced so the superseding login can free the old
    // control's different port (same note at control/proxy.rs skip path).
    // TCP port cleanup. Phase 1 (no locks held): decide what to release.
    // group_len is queried here — NOT while holding used_ports — and the
    // port_reservations inserts / remove_group / sk_index calls run after
    // the used_ports guard is dropped (phase 3). Holding used_ports across
    // those inverts the lock order vs allocate_proxy_port
    // (port_reservations → used_ports) and deadlocks both on
    // reconnect-during-cleanup. The observed group_len is re-checked in
    // phase 3 before remove_group, so a concurrent member join between the
    // phases cannot leave a live group without its shared listener.
    let mut ports_to_remove: Vec<u16> = Vec::new();
    let mut reservations: Vec<(String, u16)> = Vec::new();
    // (group name, member count observed in phase 1) — the count is
    // re-checked in phase 3 before remove_group.
    let mut groups_to_remove: Vec<(String, usize)> = Vec::new();
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
                let group_len = state.proxy_manager.group_len(group_name).await;
                if group_len <= 1 {
                    ports_to_remove.push(port);
                    if port > 0 {
                        reservations.push((p.name.clone(), port));
                    }
                    groups_to_remove.push((group_name.to_string(), group_len));
                }
            } else if p.proxy_type != "udp" && p.proxy_type != "sudp" {
                ports_to_remove.push(port);
                if port > 0 {
                    reservations.push((p.name.clone(), port));
                }
            }
        }
    }
    // Phase 2: remove the ports under the used_ports write lock only.
    {
        let mut ports = state.used_ports.write().await;
        for port in ports_to_remove {
            ports.remove(&port);
        }
    }
    // Phase 3: cross-lock mutations WITHOUT holding used_ports.
    for (name, port) in &reservations {
        state
            .port_reservations
            .write()
            .await
            .insert(name.clone(), (*port, false, std::time::Instant::now()));
    }
    for (group_name, len_at_phase1) in &groups_to_remove {
        // Re-check before stopping the shared listener: a concurrent member
        // join can land between the phase-1 group_len decision above and this
        // point (register() pushes to the group index under its own lock).
        // remove_group would then kill the listener out from under a live
        // group — a dead group with a live member. Skip teardown when the
        // member count changed from what phase 1 observed. The port mark was
        // already freed in phase 2 either way, but the listener's OS bind
        // keeps the port from being re-allocated until the group empties.
        if state.proxy_manager.group_len(group_name).await == *len_at_phase1 {
            // Stop the shared group listener
            state.tcp_group_ctl.remove_group(group_name).await;
        }
    }
    // Clean up STCP sk_index (indexed by proxy_name — exact match, no
    // risk of removing another proxy's entry even when keys are shared)
    for p in &proxies {
        if let Some(key) = p.sk_index_key() {
            state.xtcp.sk_index.write().await.remove(key);
        }
    }
    // UDP port cleanup (Go frp compat: separate port manager for UDP)
    // SUDP proxies can share one server port across run_ids: a port is
    // released only when no OTHER live udp/sudp proxy still occupies it.
    // Query the registry BEFORE taking the UDP-port lock (avoids awaiting a
    // different lock while holding it).
    // The whole batch being removed counts as "not owners": the proxies are
    // still in the registry during teardown, so same-batch SUDP proxies
    // sharing one port must not be treated as live owners of each other.
    let removing: std::collections::HashSet<String> =
        proxies.iter().map(|p| p.name.clone()).collect();
    let mut udp_port_shared: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    for p in &proxies {
        if p.proxy_type == "sudp" {
            if let Some(port) = p.remote_port {
                udp_port_shared.insert(
                    p.name.clone(),
                    udp_port_has_other_owner(state, port, &removing).await,
                );
            }
        }
    }
    let mut udp_ports = state.used_udp_ports.write().await;
    for p in &proxies {
        if let Some(port) = p.remote_port {
            if p.proxy_type == "udp" || p.proxy_type == "sudp" {
                // For SUDP, only release the port if no other live proxy
                // (any run_id) still shares it.
                if p.proxy_type == "sudp" && udp_port_shared.get(&p.name).copied().unwrap_or(false)
                {
                    continue;
                }
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
    drop(udp_ports);
    // Clear per-client port usage tracking (matching Go frp's portsUsedNum
    // cleanup). Decrement by the number of port-consuming proxies actually
    // removed: the per-run_id counter is shared with a superseding control's
    // registrations, so a wholesale remove would clear its counts too
    // (audit finding 3).
    let consumed: usize = proxies
        .iter()
        .filter(|p| {
            matches!(p.proxy_type.as_str(), "tcp" | "udp" | "sudp")
                && p.remote_port.is_some_and(|port| port > 0)
        })
        .count();
    if consumed > 0 {
        let mut port_counts = state.client_ports_used.write().await;
        if let Some(count) = port_counts.get_mut(run_id) {
            *count = count.saturating_sub(consumed as u64);
            if *count == 0 {
                port_counts.remove(run_id);
            }
        }
    }
    // VHost unregister outside port lock to avoid holding it across awaits
    //
    // NOTE: the SNI-sniff gate count (https_proxy_count) is NOT decremented
    // here. This function only cleans up routing/ports — the actual
    // proxy_manager.remove() calls happen in the caller (control::cleanup),
    // and the decrement must be gated on remove()'s result so a racing
    // dashboard delete can never double-decrement (see control/proxy.rs).
    for p in &proxies {
        state.vhost_manager.unregister(&p.name).await;
        state.tcpmux_manager.unregister(&p.name).await;
        state.proxy_metrics.remove(&p.name).await;
    }
    #[cfg(feature = "vnet")]
    {
        // Remove vnet routes for the proxies being swept (control_id
        // filtered) so a superseding control's vnet routes survive the old
        // control's cleanup (audit finding 3).
        for p in &proxies {
            if p.proxy_type == "vnet" {
                state
                    .remove_proxy_vnet_routes_and_broadcast(run_id, &p.name)
                    .await;
            }
        }
    }
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
/// The listener is bound synchronously by the caller (audit finding 4), so a
/// bind failure rejects the first group member instead of leaving a
/// registered-but-dead group.
#[instrument(skip(listener, state, cancel_token), fields(group = %group_name, port = %port))]
async fn tcp_group_listener(
    listener: TcpListener,
    port: u16,
    group_name: String,
    state: Arc<AppState>,
    cancel_token: tokio_util::sync::CancellationToken,
) {
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
                        if state.tcp_keepalive > 0 {
                            frp_core::transport::set_keepalive(&conn, state.tcp_keepalive as u64);
                        }
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
                            let ctl_tx = state
                                .run_id_to_ctl_tx
                                .get(&backend_run_id)
                                .map(|c| c.tx.clone());
                            if let Some(tx) = ctl_tx {
                                // send().await: same backpressure rationale as
                                // listen_and_proxy — the group accept loop
                                // stalls until the backend control handler
                                // drains, letting the kernel backlog absorb
                                // bursts. A closed channel means the backend
                                // control is gone; the connection is dropped.
                                if let Err(e) = tx
                                    .send(InternalMsg::ProxyUserConn {
                                        proxy_name: backend,
                                        user_conn: frp_core::transport::IoStream::Tcp(conn),
                                        pre_read: vec![],
                                    })
                                    .await
                                {
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
    control_id: u64,
    writer: &mut (impl AsyncWriteExt + Unpin),
    np: msg::NewProxy,
    _remote_port: u16,
    _internal_tx: &mpsc::Sender<InternalMsg>,
    _listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    _udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
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

    let info = build_proxy_info(state, &np, run_id, control_id, port).await;

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

    // Track port usage per client (matching Go frp's portsUsedNum — each
    // group member counts against the client's port budget, keeping the
    // count in sync with handle_close_proxy's decrement and
    // unregister_control's per-proxy decrement; audit finding 1).
    state
        .client_ports_used
        .write()
        .await
        .entry(run_id.to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);

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

// ---- Port reservation periodic cleanup ----

/// Pure sweep of 24h-expired port reservations; extracted from
/// [`AppState::prune_expired_reservations`] for testability. Returns the
/// number of expired entries removed.
fn prune_expired_reservations_inner(
    reservations: &mut crate::state::PortReservationMap,
    now: std::time::Instant,
) -> usize {
    let before = reservations.len();
    reservations.retain(|_, &mut (_, _, reserved_at)| {
        now.duration_since(reserved_at) < std::time::Duration::from_secs(24 * 3600)
    });
    before - reservations.len()
}

impl AppState {
    /// Prune port reservations whose 24h expiry has passed (Go frp
    /// `cleanReservedPortsWorker`). Reservations are otherwise only reclaimed
    /// lazily when a proxy re-registers under the same name, so a churned fleet
    /// would accumulate stale entries that block port reuse — and let a name be
    /// squatted to hold a port reservation indefinitely. The server loop calls
    /// this on an interval via [`AppState::spawn_port_reservation_pruner`].
    ///
    /// Returns the number of expired entries removed.
    pub async fn prune_expired_reservations(&self) -> usize {
        let now = std::time::Instant::now();
        prune_expired_reservations_inner(&mut *self.port_reservations.write().await, now)
    }

    /// Spawn the periodic port-reservation pruner: sweeps expired 24h
    /// reservations every 60 seconds, stopping when `shutdown_token` is
    /// cancelled. Call once from the server lifecycle (e.g. alongside the NAT
    /// hole cleanup task in `Service::run`).
    pub fn spawn_port_reservation_pruner(
        self: Arc<Self>,
        shutdown_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Skip the first tick (fires immediately), matching the TLS
            // hot-reload task, so the first sweep runs one full interval after
            // startup.
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let removed = self.prune_expired_reservations().await;
                        if removed > 0 {
                            debug!(removed = %removed, "Port reservation pruner removed {} expired entries", removed);
                        }
                    }
                    _ = shutdown_token.cancelled() => {
                        debug!("Port reservation pruner: shutdown requested, stopping");
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
pub(crate) mod unregister_generation_tests {
    use super::*;
    use std::time::{Duration, Instant};

    pub(crate) fn test_state() -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
            frp_core::auth::AuthConfig::with_token("test-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("test-token"),
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
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
        state.run_id_to_ctl_tx.insert(
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

    pub(crate) fn proxy_info(
        name: &str,
        proxy_type: &str,
        run_id: &str,
        remote_port: Option<u16>,
        control_id: u64,
    ) -> ProxyInfo {
        ProxyInfo {
            name: name.into(),
            proxy_type: proxy_type.into(),
            run_id: run_id.into(),
            control_id,
            remote_port,
            sk: None,
            group: None,
            group_key: None,
            local_addr: Some("127.0.0.1:8080".to_string()),
            use_encryption: false,
            use_compression: false,
            virtual_net: None,
            allow_users: Vec::new(),
            proxy_protocol_version: String::new(),
            response_headers: std::collections::HashMap::new(),
            custom_domains: Vec::new(),
            route_by_http_user: String::new(),
            multiplexer: String::new(),
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
            user: String::new(),
            user_conn_sem: None,
        }
    }

    /// A minimal `msg::NewProxy` for registration tests. All optional fields
    /// start None so each test only sets what its path needs.
    fn new_proxy(proxy_name: &str, proxy_type: &str) -> msg::NewProxy {
        msg::NewProxy {
            proxy_name: proxy_name.to_string(),
            proxy_type: proxy_type.to_string(),
            use_encryption: None,
            use_compression: None,
            group: None,
            group_key: None,
            local_str: None,
            remote_port: None,
            sk: None,
            custom_domains: None,
            subdomain: None,
            locations: None,
            http_user: None,
            http_pwd: None,
            host_header_rewrite: None,
            headers: None,
            response_headers: None,
            route_by_http_user: None,
            allow_users: None,
            bandwidth_limit: None,
            bandwidth_limit_mode: None,
            annotations: None,
            metas: None,
            multiplexer: None,
            virtual_net: None,
            proxy_protocol_version: None,
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        }
    }

    #[tokio::test]
    async fn stale_failure_cannot_unregister_superseding_control() {
        let state = test_state();
        insert_control(&state, "run-1", 7).await;

        // An older failing control (generation 3) must not delete the
        // replacement's routing entry.
        unregister_control(&state, "run-1", 3, false).await;
        assert!(state.run_id_to_ctl_tx.contains_key("run-1"));

        // The replacement itself may still clean up its own generation.
        unregister_control(&state, "run-1", 7, false).await;
        assert!(!state.run_id_to_ctl_tx.contains_key("run-1"));
    }

    /// Regression test for the used_ports ↔ port_reservations lock-order
    /// inversion (audit Task 1). `unregister_control` used to hold
    /// `used_ports.write()` while acquiring `port_reservations.write()`,
    /// while `allocate_proxy_port` held `port_reservations.write()` while
    /// acquiring `used_ports.read()` — the reconnect-during-cleanup
    /// interleaving below deadlocked both, wedging the whole service.
    ///
    /// Deterministic staging (single-threaded test runtime): the test holds
    /// `port_reservations.write()` and spawns the allocator first, then the
    /// cleanup, so both queue on `port_reservations` in FIFO order. The
    /// cleanup grabs `used_ports.write()` and parks on `port_reservations`
    /// behind the allocator; releasing the test's guard grants the
    /// allocator, which (old order) parks on `used_ports.read()` while still
    /// holding `port_reservations` — a guaranteed ABBA deadlock. With the
    /// fix the allocator drops `port_reservations` before touching
    /// `used_ports`, so the cleanup proceeds and both complete.
    #[tokio::test]
    async fn concurrent_register_unregister_no_lock_order_deadlock() {
        let state = test_state();
        insert_control(&state, "run-1", 1).await;

        // A live TCP proxy for run-1 so the cleanup exercises the TCP port
        // release path.
        state
            .proxy_manager
            .register(
                "run-1".to_string(),
                proxy_info("p1", "tcp", "run-1", Some(49901), 0),
            )
            .await
            .expect("register p1");

        // Fresh (non-expired) 24h reservation for the allocating proxy.
        state
            .port_reservations
            .write()
            .await
            .insert("reg-test".to_string(), (49902, false, Instant::now()));

        // Stage the interleaving. Allocator first: it queues as a writer on
        // port_reservations (held by the test) and parks without acquiring
        // anything else.
        let held_reservations = state.port_reservations.write().await;
        let alloc = tokio::spawn({
            let state = state.clone();
            async move {
                let np = msg::NewProxy {
                    proxy_name: "reg-test".to_string(),
                    proxy_type: "tcp".to_string(),
                    use_encryption: None,
                    use_compression: None,
                    group: None,
                    group_key: None,
                    local_str: None,
                    remote_port: None,
                    sk: None,
                    custom_domains: None,
                    subdomain: None,
                    locations: None,
                    http_user: None,
                    http_pwd: None,
                    host_header_rewrite: None,
                    headers: None,
                    response_headers: None,
                    route_by_http_user: None,
                    allow_users: None,
                    bandwidth_limit: None,
                    bandwidth_limit_mode: None,
                    annotations: None,
                    metas: None,
                    multiplexer: None,
                    virtual_net: None,
                    proxy_protocol_version: None,
                    advertise_subnet: None,
                    vnet_ip: None,
                    vnet_netmask: None,
                    vnet_mtu: None,
                };
                allocate_proxy_port(&state, &np, true, false, false, 0).await
            }
        });
        tokio::task::yield_now().await;
        // Cleanup second: it must acquire used_ports.write() (free) and park
        // on port_reservations behind the allocator. Staging check: the
        // cleanup removes the run_id entry before its first park, and every
        // await between that removal and the port_reservations park is
        // uncontended (cannot pend), so a removed entry means it is parked
        // on port_reservations. (Pre-fix it was parked there while still
        // holding used_ports.write().)
        let unreg = tokio::spawn({
            let state = state.clone();
            async move { unregister_control(&state, "run-1", 1, false).await }
        });
        tokio::task::yield_now().await;
        assert!(
            !state.run_id_to_ctl_tx.contains_key("run-1"),
            "cleanup should have run and parked on port_reservations"
        );

        // Release the reservations lock: the allocator is granted first
        // (FIFO). With the old lock order both tasks now wait on each other
        // forever; with the fix both complete.
        drop(held_reservations);
        tokio::time::timeout(Duration::from_secs(5), alloc)
            .await
            .expect("allocator hung: lock-order deadlock")
            .expect("allocator task panicked");
        tokio::time::timeout(Duration::from_secs(5), unreg)
            .await
            .expect("cleanup hung: lock-order deadlock")
            .expect("cleanup task panicked");
        // End-state: the cleanup released the live proxy's port and recorded
        // the 24h reservation for it.
        assert!(!state.used_ports.read().await.contains(&49901));
        assert!(state
            .port_reservations
            .read()
            .await
            .get("p1")
            .is_some_and(|&(port, is_udp, _)| port == 49901 && !is_udp));
    }

    #[tokio::test]
    async fn unregister_group_len_recheck_keeps_listener_on_concurrent_join() {
        let state = test_state();
        insert_control(&state, "run-1", 1).await;

        // A live TCP group proxy for run-1: only member of group "grp".
        let mut g1 = proxy_info("g1", "tcp", "run-1", Some(49911), 1);
        g1.group = Some("grp".to_string());
        g1.group_key = Some("grp-key".to_string());
        state
            .proxy_manager
            .register("run-1".to_string(), g1)
            .await
            .expect("register g1");
        assert_eq!(state.proxy_manager.group_len("grp").await, 1);

        // The shared group listener exists (normally created by the NewProxy
        // handler for the first member).
        let cancel_token = tokio_util::sync::CancellationToken::new();
        state
            .tcp_group_ctl
            .create_group(
                "grp",
                "grp-key",
                49911,
                "0.0.0.0",
                tokio::spawn(async {}),
                cancel_token.clone(),
            )
            .await
            .expect("create group");

        // Stage the interleaving: hold port_reservations so the cleanup parks
        // at its phase-3 reservation insert — AFTER the phase-1 group_len
        // decision but BEFORE the phase-3 remove_group re-check. Every await
        // before that park (list_client, group_len, used_ports) is
        // uncontended, so a removed run_id entry means the task is parked
        // there with the phase-1 group_len already observed.
        let held_reservations = state.port_reservations.write().await;
        let unreg = tokio::spawn({
            let state = state.clone();
            async move { unregister_control(&state, "run-1", 1, false).await }
        });
        tokio::task::yield_now().await;
        assert!(
            !state.run_id_to_ctl_tx.contains_key("run-1"),
            "cleanup should have passed phase 1 and parked on port_reservations"
        );

        // A concurrent group-member join lands between phase 1 and phase 3.
        let mut g2 = proxy_info("g2", "tcp", "run-2", Some(49911), 2);
        g2.group = Some("grp".to_string());
        g2.group_key = Some("grp-key".to_string());
        state
            .proxy_manager
            .register("run-2".to_string(), g2)
            .await
            .expect("register g2");
        assert_eq!(state.proxy_manager.group_len("grp").await, 2);

        // Let the cleanup proceed: its phase-3 re-check must notice the
        // joined member and skip remove_group, keeping the shared listener
        // alive for the remaining live member.
        drop(held_reservations);
        tokio::time::timeout(Duration::from_secs(5), unreg)
            .await
            .expect("cleanup hung")
            .expect("cleanup task panicked");

        // The group listener survives with its live member.
        assert!(
            state.tcp_group_ctl.group_exists("grp").await,
            "shared group listener must survive a concurrent member join"
        );
        assert!(!cancel_token.is_cancelled());
        assert_eq!(state.proxy_manager.group_len("grp").await, 2);
        assert!(state.proxy_manager.get("g2").await.is_some());
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn unregister_control_removes_run_id_vnet_routes_and_broadcasts_remove() {
        let state = test_state();
        let mut peer_rx = insert_control_rx(&state, "run-b", 2).await;
        insert_control(&state, "run-a", 1).await;
        // The sweep removes vnet routes per proxy (audit finding 3), so the
        // proxies owning the routes must be registered under the removing
        // control's generation.
        state
            .proxy_manager
            .register(
                "run-a".to_string(),
                proxy_info("proxy-a", "vnet", "run-a", Some(0), 1),
            )
            .await
            .expect("register proxy-a");
        state
            .proxy_manager
            .register(
                "run-a".to_string(),
                proxy_info("visitor-v6", "vnet", "run-a", Some(0), 1),
            )
            .await
            .expect("register visitor-v6");
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
            // run-b also participates in vnet-a, so it is a peer of run-a's
            // vnet-a routes and must receive the broadcast removes below.
            routes.insert(
                ("vnet-a".to_string(), "10.99.0.0/24".to_string()),
                ("run-b".to_string(), "proxy-b-vnet-a".to_string()),
            );
        }

        unregister_control(&state, "run-a", 1, false).await;

        let routes = state.vnet_routes.read().await;
        assert!(routes.iter().all(|(_, (run_id, _))| run_id != "run-a"));
        assert!(routes.contains_key(&("vnet-b".to_string(), "10.1.0.0/24".to_string())));
        assert!(routes.contains_key(&("vnet-a".to_string(), "10.99.0.0/24".to_string())));
        drop(routes);

        let mut removes = Vec::new();
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(5), peer_rx.recv()).await {
                Ok(Some(InternalMsg::VnetRouteRemoveForward { msg })) => removes.push(msg),
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

    #[test]
    fn prune_removes_expired_keeps_fresh() {
        let now = Instant::now();
        let mut map = crate::state::PortReservationMap::new();
        map.insert(
            "fresh".to_string(),
            (8080, true, now - Duration::from_secs(3600)),
        );
        map.insert(
            "expired".to_string(),
            (8081, false, now - Duration::from_secs(25 * 3600)),
        );

        assert_eq!(prune_expired_reservations_inner(&mut map, now), 1);
        assert!(map.contains_key("fresh"));
        assert!(!map.contains_key("expired"));
    }

    #[test]
    fn prune_empty_map_is_noop() {
        let now = Instant::now();
        let mut map = crate::state::PortReservationMap::new();
        assert_eq!(prune_expired_reservations_inner(&mut map, now), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn prune_boundary_just_under_24h_is_kept() {
        // Strictly-less-than semantics: a reservation younger than 24h is
        // kept. (An exactly-24h boundary is not testable with Instant —
        // `now - 24h` then `now.duration_since(..)` includes nanosecond
        // overhead, so it would nondeterministically count as expired.)
        let now = Instant::now();
        let mut map = crate::state::PortReservationMap::new();
        map.insert(
            "boundary".to_string(),
            (8082, true, now - Duration::from_secs(24 * 3600 - 1)),
        );

        assert_eq!(prune_expired_reservations_inner(&mut map, now), 0);
        assert!(map.contains_key("boundary"));
    }

    /// Audit finding 1 regression: `client_ports_used` must only count
    /// proxies that actually consume a port (tcp/udp/sudp with a real
    /// remote port). stcp/xtcp/http/https/tcpmux register with remote port
    /// 0 and previously inflated the count the `max_ports_per_client` gate
    /// checks.
    #[tokio::test]
    async fn client_ports_used_counts_only_port_consuming_proxies() {
        let state = test_state();
        insert_control(&state, "run-1", 1).await;
        let (itx, _rx) = mpsc::channel(8);
        let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
            std::collections::HashMap::new();
        let mut udp_sockets: std::collections::HashMap<
            String,
            std::sync::Arc<tokio::net::UdpSocket>,
        > = std::collections::HashMap::new();

        // tcp proxy → counted.
        let mut np = new_proxy("p1", "tcp");
        np.remote_port = Some(24021);
        let mut writer = Vec::new();
        handle_new_proxy(
            np,
            "run-1",
            1,
            &state,
            &mut writer,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert_eq!(
            *state.client_ports_used.read().await.get("run-1").unwrap(),
            1,
            "tcp proxy must count against the client port budget"
        );

        // http proxy (remote port 0) → must NOT inflate the count.
        let mut np = new_proxy("p2", "http");
        np.custom_domains = Some(vec!["example.com".to_string()]);
        let mut writer = Vec::new();
        handle_new_proxy(
            np,
            "run-1",
            1,
            &state,
            &mut writer,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert_eq!(
            *state.client_ports_used.read().await.get("run-1").unwrap(),
            1,
            "http proxy (remote port 0) must not inflate the port count"
        );

        // stcp proxy (no remote port) → must NOT inflate the count.
        let mut np = new_proxy("p3", "stcp");
        np.sk = Some("secret".to_string());
        let mut writer = Vec::new();
        handle_new_proxy(
            np,
            "run-1",
            1,
            &state,
            &mut writer,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert_eq!(
            *state.client_ports_used.read().await.get("run-1").unwrap(),
            1,
            "stcp proxy (no remote port) must not inflate the port count"
        );

        // Second tcp proxy → 2.
        let mut np = new_proxy("p4", "tcp");
        np.remote_port = Some(24022);
        let mut writer = Vec::new();
        handle_new_proxy(
            np,
            "run-1",
            1,
            &state,
            &mut writer,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert_eq!(
            *state.client_ports_used.read().await.get("run-1").unwrap(),
            2,
            "two tcp proxies must count 2"
        );

        // Disconnect cleanup decrements by the count of port-consuming
        // proxies it actually removes (finding 3 symmetry): entry cleared.
        unregister_control(&state, "run-1", 1, false).await;
        assert!(
            state.client_ports_used.read().await.get("run-1").is_none(),
            "cleanup must remove the per-client port count"
        );
    }

    /// Audit finding 2 regression: closing one SUDP proxy must not release
    /// the shared UDP port while another live SUDP proxy still holds it.
    #[tokio::test]
    async fn sudp_shared_port_released_only_when_last_owner() {
        let state = test_state();
        state.used_udp_ports.write().await.insert(24023);
        state
            .proxy_manager
            .register(
                "run-1".to_string(),
                proxy_info("s1", "sudp", "run-1", Some(24023), 1),
            )
            .await
            .expect("register s1");
        state
            .proxy_manager
            .register(
                "run-1".to_string(),
                proxy_info("s2", "sudp", "run-1", Some(24023), 1),
            )
            .await
            .expect("register s2");

        // Closing s1 while s2 still holds the port must NOT release it.
        // Mirrors handle_close_proxy: the owner check runs while the closing
        // proxy is still in the registry; the registry removal happens after.
        assert!(
            !release_udp_port_with_owner_check(&state, 24023, "s1").await,
            "shared port must stay allocated while s2 is live"
        );
        assert!(
            state.used_udp_ports.read().await.contains(&24023),
            "port must remain marked while a sibling SUDP proxy holds it"
        );
        state.proxy_manager.remove("s1").await;

        // Closing the last owner releases it.
        assert!(
            release_udp_port_with_owner_check(&state, 24023, "s2").await,
            "last SUDP owner must release the port"
        );
        assert!(
            !state.used_udp_ports.read().await.contains(&24023),
            "port must be released after the last owner closes"
        );
        state.proxy_manager.remove("s2").await;

        // Closing a proxy that never existed is a no-op release.
        assert!(
            release_udp_port_with_owner_check(&state, 24023, "ghost").await,
            "no live owner means the port is free to release"
        );
    }

    /// Audit finding 3 regression: when the 10s handoff barrier times out,
    /// the old control's sweep must skip proxies registered by the
    /// superseding control — it must only tear down its own generation.
    #[tokio::test]
    async fn unregister_control_generation_filter_skips_newer_proxies() {
        let state = test_state();
        // The superseding control (generation 2) owns the run_id entry.
        insert_control(&state, "run-1", 2).await;
        // Old control's proxy (generation 1) + new control's proxy (2).
        state
            .proxy_manager
            .register(
                "run-1".to_string(),
                proxy_info("old-proxy", "tcp", "run-1", Some(24024), 1),
            )
            .await
            .expect("register old-proxy");
        state
            .proxy_manager
            .register(
                "run-1".to_string(),
                proxy_info("new-proxy", "tcp", "run-1", Some(24025), 2),
            )
            .await
            .expect("register new-proxy");
        {
            let mut ports = state.used_ports.write().await;
            ports.insert(24024);
            ports.insert(24025);
        }
        state
            .client_ports_used
            .write()
            .await
            .insert("run-1".to_string(), 2);

        // Old control (generation 1) sweeps: only its own proxy's port is
        // released; the new control's proxy and counts survive.
        unregister_control(&state, "run-1", 1, false).await;
        assert!(
            !state.used_ports.read().await.contains(&24024),
            "old control's port must be released"
        );
        assert!(
            state.used_ports.read().await.contains(&24025),
            "superseding control's port must survive the old sweep"
        );
        assert_eq!(
            *state.client_ports_used.read().await.get("run-1").unwrap(),
            1,
            "only the old control's count may be decremented"
        );
        assert!(
            state.run_id_to_ctl_tx.contains_key("run-1"),
            "superseding control's routing entry must survive"
        );

        // The superseding control's own cleanup sweeps everything.
        unregister_control(&state, "run-1", 2, false).await;
        assert!(
            !state.used_ports.read().await.contains(&24025),
            "superseding control must release its own port on disconnect"
        );
        assert!(
            state.client_ports_used.read().await.get("run-1").is_none(),
            "per-client count must be cleared when the last control leaves"
        );
    }

    /// Audit finding 5 regression: a tcpmux proxy claiming a domain already
    /// routed by a live proxy is rejected — the sibling's route survives.
    #[tokio::test]
    async fn tcpmux_route_conflict_rejects_new_proxy() {
        let state = test_state();
        insert_control(&state, "run-1", 1).await;
        let (itx, _rx) = mpsc::channel(8);
        let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
            std::collections::HashMap::new();
        let mut udp_sockets: std::collections::HashMap<
            String,
            std::sync::Arc<tokio::net::UdpSocket>,
        > = std::collections::HashMap::new();

        let mut np1 = new_proxy("mux-a", "tcpmux");
        np1.custom_domains = Some(vec!["a.example.com".to_string()]);
        let mut writer1 = Vec::new();
        handle_new_proxy(
            np1,
            "run-1",
            1,
            &state,
            &mut writer1,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert!(
            state.proxy_manager.get("mux-a").await.is_some(),
            "first tcpmux proxy must register"
        );
        assert!(state
            .tcpmux_manager
            .lookup("a.example.com")
            .await
            .is_some_and(|r| r.proxy_name == "mux-a"));

        // Second proxy claims the same domain → must be rejected and rolled
        // back, with an error response naming the conflict.
        let mut np2 = new_proxy("mux-b", "tcpmux");
        np2.custom_domains = Some(vec!["a.example.com".to_string()]);
        let mut writer2 = Vec::new();
        handle_new_proxy(
            np2,
            "run-1",
            1,
            &state,
            &mut writer2,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert!(
            state.proxy_manager.get("mux-b").await.is_none(),
            "conflicting tcpmux proxy must be rolled back"
        );
        assert!(
            String::from_utf8_lossy(&writer2).contains("conflict"),
            "rejection response must surface the route conflict"
        );
        assert!(
            state
                .tcpmux_manager
                .lookup("a.example.com")
                .await
                .is_some_and(|r| r.proxy_name == "mux-a"),
            "live sibling's route must survive the rejected registration"
        );

        // tcpmux proxies never consume a port → no client port count.
        assert!(
            state.client_ports_used.read().await.get("run-1").is_none(),
            "tcpmux proxies must not count against the client port budget"
        );
    }
}
