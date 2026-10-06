//! Proxy-registry entry construction and per-entry rollback bookkeeping.
//!
//! Split out of `proxy_ops/mod.rs`; the parent re-imports every item, so
//! `proxy_ops::build_proxy_info`, `proxy_ops::register_sk_index`,
//! `proxy_ops::rollback_port_allocation`,
//! `proxy_ops::rollback_vhost_conflict`,
//! `proxy_ops::rollback_udp_bind_failure`,
//! `proxy_ops::rollback_tcp_bind_failure`, `proxy_ops::register_proxy_entry`
//! and `proxy_ops::remove_proxy_and_release_client_counts` keep their existing
//! paths and visibility.
//!
//! `remove_proxy_and_release_client_counts` is the one `pub(crate)` item here;
//! its callers live outside this module: `handle_store_proxy_delete` and
//! `handle_proxies_delete` in `frp-server/src/dashboard.rs` (base lines 1227
//! and 1312, plus the tests at base lines 3836-3921), `handle_close_proxy` in
//! `frp-server/src/control/proxy.rs` (base line 220), and the `pub(crate) use`
//! re-export in `frp-server/src/control/mod.rs` (base line 32).
//!
//! Call sites of the rest: `build_proxy_info` is called by
//! `register_proxy_entry` here and by `handle_tcp_group_member_registration` in
//! `frp-server/src/control/proxy_ops/tcp_group.rs` (base line 221);
//! `rollback_vhost_conflict` by `handle_new_proxy` in `proxy_ops/mod.rs` (base
//! lines 1659-1958) and by `register_http_vhost`/`register_https_vhost` in
//! `frp-server/src/control/proxy_ops/vhost.rs` (base lines 44-473);
//! `rollback_udp_bind_failure` and `rollback_tcp_bind_failure` by
//! `setup_proxy_listeners` in `proxy_ops/mod.rs` (base lines 954 and
//! 1073-1171), and `rollback_tcp_bind_failure` also by
//! `bind_tcp_proxy_with_retry` in `proxy_ops/mod.rs` (base lines 2142 and
//! 2170); `register_proxy_entry` by `handle_new_proxy` in `proxy_ops/mod.rs`
//! (base line 1552) and by `bind_tcp_proxy_with_retry` (base line 2189);
//! `register_sk_index` and `rollback_port_allocation` only by
//! `register_proxy_entry` here.

use std::sync::Arc;

use tracing::info;

use frp_core::msg;

use crate::proxy::ProxyInfo;
use crate::service::AppState;

use super::{free_replaced_port, proxy_consumes_client_port, udp_port_has_other_owner};

/// Build the `ProxyInfo` for a registered proxy. Shared by
/// `handle_new_proxy` and `handle_tcp_group_member_registration`.
#[inline(never)]
pub(super) async fn build_proxy_info(
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
        // Per-proxy SHARED bandwidth limiter, created ONCE at registration
        // (Go frp v0.71.0: NewProxy builds a single `*rate.Limiter` when
        // mode == "server" — proxy.go:536-540; "both" is the frp-rs
        // extension — both sides limit). Empty mode normalizes to "client"
        // (Go EmptyOr), which the client side handles. One bucket covers
        // both directions and all concurrent connections; bridges clone
        // this Arc instead of building per-connection limiters (F1/F2).
        bandwidth_limiter: {
            let bw_rate = np
                .bandwidth_limit
                .as_deref()
                .filter(|bl| !bl.is_empty())
                .and_then(frp_core::config::parse_bandwidth_limit)
                .unwrap_or(0);
            frp_core::bandwidth::server_side_limiter(
                bw_rate,
                np.bandwidth_limit_mode.as_deref().unwrap_or(""),
            )
        },
        user: state
            .run_id_to_ctl_tx
            .get(run_id)
            .map(|c| c.user.clone())
            .unwrap_or_default(),
        // Provider-segment UDPPacket codec (Go frp v0.71.0): inherited from
        // the registering control's negotiated ServerHello codec. The SUDP
        // message bridge compares this against the visitor segment's codec.
        udp_packet_codec: state
            .run_id_to_ctl_tx
            .get(run_id)
            .map(|c| c.udp_packet_codec.clone())
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
///
/// Sync (DashMap insert — no await needed): the caller invokes this BEFORE
/// `proxy_manager.register()` so a visitor arriving in the registration
/// window finds the entry via the `sk_index` fallback.
#[inline(never)]
pub(super) fn register_sk_index(state: &Arc<AppState>, np: &msg::NewProxy) -> bool {
    let needs_sk_index =
        (np.proxy_type == "stcp" || np.proxy_type == "xtcp" || np.proxy_type == "sudp")
            && np.sk.as_deref().filter(|s| !s.is_empty()).is_some();
    if needs_sk_index {
        let raw = np.sk.clone().unwrap_or_default();
        let vn = np.virtual_net.as_deref().unwrap_or("");
        state.xtcp.sk_index.insert(np.proxy_name.clone(), raw);
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
pub(super) async fn rollback_port_allocation(
    state: &Arc<AppState>,
    proxy_name: &str,
    port: u16,
    is_udp_type: bool,
    needs_sk_index: bool,
) {
    if needs_sk_index {
        state.xtcp.sk_index.remove(proxy_name);
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

/// Remove a proxy from the registry and, when THIS call actually performed
/// the removal, release the derived counters the entry owned: the
/// SNI-sniff gate count (`https_proxy_count`, an https entry) and the
/// per-client port-budget slot (`client_ports_used` for tcp/udp/sudp
/// entries). Returns whether the removal happened here.
///
/// Removal paths race — the dashboard delete API, the client CloseProxy
/// handler and control-disconnect cleanup can all observe the same proxy
/// before any of them removes it. Counters are released only by the path
/// whose `remove()` returned true: the loser re-releasing them would
/// double-decrement (S4) — `client_ports_used` drifts below the live
/// proxy count and `max_ports_per_client` admits one extra proxy per
/// double-release, and `https_proxy_count` would hit 0 while https
/// proxies still exist, silently disabling SNI sniff.
pub(crate) async fn remove_proxy_and_release_client_counts(
    state: &Arc<AppState>,
    info: &ProxyInfo,
) -> bool {
    if !state.proxy_manager.remove(&info.name).await {
        return false;
    }
    if info.proxy_type == "https" {
        state.dec_https_proxy_count();
    }
    if proxy_consumes_client_port(info) {
        let mut port_counts = state.client_ports_used.write().await;
        if let Some(count) = port_counts.get_mut(&info.run_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                port_counts.remove(&info.run_id);
            }
        }
    }
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
pub(super) async fn rollback_vhost_conflict(
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
pub(super) async fn rollback_udp_bind_failure(
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
pub(super) async fn rollback_tcp_bind_failure(
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

/// Register `np` under `run_id` and attach the per-client port bookkeeping
/// for `port` (sk_index, registry entry with `remote_port`, replaced-entry
/// cleanup, per-client port count).
///
/// Shared by `handle_new_proxy` and the TCP auto-assign bind retry
/// (`bind_tcp_proxy_with_retry`), which re-registers a proxy on a fresh
/// port after the first bind lost the auto-assigned port to another
/// process — re-entering this same path keeps every structure that holds
/// the port (ProxyInfo `remote_port`, `used_ports`, `client_ports_used`)
/// consistent.
///
/// Returns `Err(message)` when registration failed (the port mark and
/// sk_index entry were already rolled back); the caller writes the
/// rejection response.
#[inline(never)]
pub(super) async fn register_proxy_entry(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    control_id: u64,
    port: u16,
    is_udp_type: bool,
) -> Result<(), String> {
    let info = build_proxy_info(state, np, run_id, control_id, port).await;

    // Go frp compat: proxy.Run() calls startVisitorListener() BEFORE
    // proxyManager.Add(). Insert sk_index before proxy_manager.register()
    // so that STCP/XTCP visitors that arrive during the registration
    // window can find the proxy via sk_index fallback.
    let needs_sk_index = register_sk_index(state, np);

    // Supersession takeover: when the 10s handoff-barrier timeout
    // fires, the superseding control may re-register a name the old
    // control still holds. Port-consuming types (tcp/udp/sudp/
    // stcp/xtcp/vnet) take over via register_or_replace — the
    // replaced entry's port mark is freed below, exactly once
    // (audit-fix: residual port-mark leak on barrier-timeout
    // supersession). http/https/tcpmux keep the conflict-reject
    // behavior: their vhost/tcpmux routes are owned by the old
    // control's registration and cannot be taken over mid-flight
    // (a replace-then-rollback would orphan the old routes).
    let replaced = {
        let replaceable = matches!(
            np.proxy_type.as_str(),
            "tcp" | "udp" | "sudp" | "stcp" | "xtcp" | "vnet"
        );
        let register_result = if replaceable {
            state
                .proxy_manager
                .register_or_replace(run_id.to_string(), info.clone())
                .await
        } else {
            state
                .proxy_manager
                .register(run_id.to_string(), info.clone())
                .await
                .map(|_| None)
        };
        match register_result {
            Ok(r) => r,
            Err(e) => {
                // Cleanup sk_index on registration failure
                rollback_port_allocation(state, &np.proxy_name, port, is_udp_type, needs_sk_index)
                    .await;
                return Err(e);
            }
        }
    };

    // A replaced entry's per-client port count and port mark are
    // released here: the old control's sweep will skip the name
    // (newer control_id) and never decrement either.
    if let Some(old) = replaced {
        if (old.proxy_type == "tcp" || old.proxy_type == "udp" || old.proxy_type == "sudp")
            && old.remote_port.is_some_and(|p| p > 0)
        {
            let mut port_counts = state.client_ports_used.write().await;
            if let Some(count) = port_counts.get_mut(run_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    port_counts.remove(run_id);
                }
            }
        }
        free_replaced_port(state, &old, port).await;
    }

    // Track port usage per client (matching Go frp's portsUsedNum).
    // Only proxies that actually consume a port are counted:
    // stcp/xtcp/http/https/tcpmux register with remote port 0 and
    // would otherwise inflate the count the max_ports_per_client
    // gate checks (audit finding 1).
    if matches!(np.proxy_type.as_str(), "tcp" | "udp" | "sudp") && port > 0 {
        state
            .client_ports_used
            .write()
            .await
            .entry(run_id.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }
    Ok(())
}
