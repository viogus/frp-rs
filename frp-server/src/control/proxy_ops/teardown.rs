//! Control teardown: release a disconnecting control's ports, routes, sk/vhost/
//! registry state and OIDC/plugin identity.
//!
//! Split out of `proxy_ops/mod.rs` as a pure text move; the parent re-exports
//! `unregister_control` so its `crate::control::proxy_ops::unregister_control`
//! callers keep resolving unchanged.
//!
//! Lock order: `used_ports` is dropped before the phase-3 `port_reservations`
//! mutations below, so the two port maps are never held at the same time —
//! the rule the plan records as `used_ports → port_reservations`.

use std::sync::Arc;

use crate::service::AppState;
use crate::state::ControlTx;

use super::{proxy_consumes_client_port, udp_port_has_other_owner};

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
    sweep: bool,
) {
    let removed_control_id = if !skip_ctl_unregister {
        // Atomic generation-guarded removal: remove_if compares control_id
        // inside the shard lock, so a fresh re-login's insert can never land
        // between a check and the removal (the previous get-then-remove
        // TOCTOU — in the disconnect+reconnect path it could delete the
        // fresh ControlTx entry, and then its fresh user record via
        // remove_user below). The entry is removed only when it still holds
        // THIS control's control_id; control_id == 0 (legacy callers that
        // do not track generations) sweeps unconditionally. remove_user
        // below fires only when the removal actually matched (i.e. the
        // returned value held this control's id), so a superseding
        // control's fresh entry and user record are never touched.
        // remove_user itself is now generation-exact too (the users map
        // stores (control_id, UserInfo); the entry check happens inside
        // remove_user, under its write lock), so even a remove that landed
        // between a re-login's insert+record could not delete the fresh
        // record — the gate below is belt-and-suspenders.
        let removed: Option<(String, ControlTx)> = if control_id == 0 {
            state.run_id_to_ctl_tx.remove(run_id)
        } else {
            state
                .run_id_to_ctl_tx
                .remove_if(run_id, |_, cur| cur.control_id == control_id)
        };
        match removed {
            Some((_, removed)) => {
                // Mark the client offline in the registry, generation-aware.
                state
                    .client_registry
                    .mark_offline_by_run_id_and_control_id(run_id, removed.control_id);
                Some(removed.control_id)
            }
            None => None,
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

    // Clean up OIDC subject mapping for this client.
    // Map key is run_id; remove it directly rather than scanning values
    // (which are OIDC subject strings, not proxy names — retain would
    // never match and entries would leak unboundedly). Generation-guarded,
    // so this is safe to run in sweep-free mode too.
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

    // Drop this control's plugin user-info entry (bounds the manager's
    // identity store to live controls). Fired only when the run_id_to_ctl_tx
    // removal actually matched this control (`removed_control_id`), and the
    // entry removal is itself generation-exact (`remove_user` drops the
    // entry only when it still holds the removing control_id), so on
    // supersession the old control's cleanup can never remove the new
    // control's freshly recorded identity — even if a same-run_id re-login
    // lands between the remove_if above and this call.
    if let Some(control_id) = removed_control_id {
        state.plugin_manager.remove_user(run_id, control_id);
    }

    // Sweep-free mode: the duplicate-login conflict path in login.rs calls
    // this with sweep=false because ITS control_id (assigned from the
    // monotonic counter) is HIGHER than the live control's — the generation
    // filter above would let the live control's older proxies through and
    // tear down their ports/vhost routes/sk_index (audit-fix: the
    // duplicate-login conflict path swept the live control's routes). That
    // path only wants the run_id entry removal and the OIDC subject cleanup
    // below; the sweep must not run.
    if !sweep {
        return;
    }

    // Port-mark ownership on supersession: if the superseding control
    // re-registered one of these names (barrier-timeout path), the registry
    // entry now belongs to the newer control generation and is skipped by
    // the filter above. Its port mark was freed exactly once by the
    // replacement path — proxy_manager.register_or_replace returns the
    // replaced entry and handle_new_proxy's free_replaced_port releases the
    // old mark when it differs from the new port, reserving it for the
    // standard 24h window. Nothing leaks here and this sweep never touches
    // the superseding control's marks (audit-fix: residual port-mark leak
    // on barrier-timeout supersession; same note at control/proxy.rs skip
    // path).
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
        // Ownership re-check (mirrors the sk_index/vhost/tcpmux loops
        // below): the snapshot is taken BEFORE this loop runs, so a
        // superseding control that re-registered this name between the
        // snapshot and phase 1 must not lose its port mark — the
        // replacement path (handle_new_proxy → register_or_replace →
        // free_replaced_port) already freed the old mark exactly once, so
        // phase 2 must not free it again (a third-party proxy may have
        // re-allocated the freed port in the meantime), and the count
        // decrement below must not run twice for the same name
        // (audit-fix: sweep port marks vs same-name re-registration).
        if p.control_id != 0
            && state
                .proxy_manager
                .get(&p.name)
                .await
                .is_some_and(|cur| cur.control_id > p.control_id)
        {
            continue;
        }
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
    // risk of removing another proxy's entry even when keys are shared).
    // Ownership re-check: the snapshot above is taken BEFORE this loop
    // runs, so a superseding control that re-registered the same name
    // between snapshot and sweep must not lose its sk_index entry —
    // mirror the tcpmux ownership guard below (audit-fix: sweep snapshot
    // vs same-name re-registration).
    for p in &proxies {
        if p.control_id != 0
            && state
                .proxy_manager
                .get(&p.name)
                .await
                .is_some_and(|cur| cur.control_id > p.control_id)
        {
            continue;
        }
        if let Some(key) = p.sk_index_key() {
            state.xtcp.sk_index.remove(key);
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
    let mut consumed: usize = 0;
    for p in &proxies {
        // Ownership re-check (same rationale as phase 1): the replacement
        // path already decremented the per-client count for the old entry
        // and incremented for the new registration (net zero), so a sweep
        // decrement for a replaced name would undercount the client's port
        // budget by 1 (audit-fix: double-decrement on supersession).
        if p.control_id != 0
            && state
                .proxy_manager
                .get(&p.name)
                .await
                .is_some_and(|cur| cur.control_id > p.control_id)
        {
            continue;
        }
        if proxy_consumes_client_port(p) {
            consumed += 1;
        }
    }
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
        // Ownership re-check (mirrors the tcpmux pattern): the snapshot was
        // taken before this loop, so a superseding control that
        // re-registered the same name between snapshot and sweep must not
        // lose its vhost/tcpmux routes or metrics (audit-fix: sweep
        // snapshot vs same-name re-registration). http/https/tcpmux cannot
        // be replaced via register_or_replace today, so this guards against
        // future route takeover paths too.
        if p.control_id != 0
            && state
                .proxy_manager
                .get(&p.name)
                .await
                .is_some_and(|cur| cur.control_id > p.control_id)
        {
            continue;
        }
        // HTTP/HTTPS group members share one vhost route: remove from the
        // group first; only drop the route when the group empties (Go
        // HTTPGroup.UnRegister). Non-group proxies drop their own route.
        let is_http_group = (p.proxy_type == "http" || p.proxy_type == "https")
            && p.group.as_deref().filter(|g| !g.is_empty()).is_some();
        if is_http_group {
            let gname = p.group.as_deref().unwrap_or_default();
            // unregister_member returns the route OWNER (first member) when
            // the group empties — the shared route is keyed on that name, so
            // unregistering with a later member's name would leak it.
            let kind_https = p.proxy_type == "https";
            if let Some(owner) = state
                .http_group_ctl
                .unregister_member(gname, &p.name, kind_https)
                .await
            {
                state.vhost_manager.unregister(&owner).await;
            }
        } else {
            state.vhost_manager.unregister(&p.name).await;
        }
        // TCPMux group members share one route (owned by the FIRST member):
        // remove from the group first; only drop the route when the group
        // empties — the owner's name keys it, so unregistering with a later
        // member's name would leak it (M2, mirrors the HTTP group branch).
        let is_tcpmux_group =
            p.proxy_type == "tcpmux" && p.group.as_deref().filter(|g| !g.is_empty()).is_some();
        if is_tcpmux_group {
            let gname = p.group.as_deref().unwrap_or_default();
            if let Some(owner) = state
                .tcpmux_group_ctl
                .unregister_member(gname, &p.name)
                .await
            {
                state.tcpmux_manager.unregister(&owner).await;
            }
        } else {
            state.tcpmux_manager.unregister(&p.name).await;
        }
        state.proxy_metrics.remove(&p.name).await;
        #[cfg(feature = "dashboard")]
        crate::metrics::prom::proxy_removed(&p.name).await;
    }
    #[cfg(feature = "vnet")]
    {
        // Remove vnet routes for the proxies being swept (control_id
        // filtered) so a superseding control's vnet routes survive the old
        // control's cleanup (audit finding 3). Ownership re-check: a
        // superseding control that re-registered the name between the
        // snapshot and this loop must keep its routes (audit-fix: sweep
        // snapshot vs same-name re-registration).
        for p in &proxies {
            if p.control_id != 0
                && state
                    .proxy_manager
                    .get(&p.name)
                    .await
                    .is_some_and(|cur| cur.control_id > p.control_id)
            {
                continue;
            }
            if p.proxy_type == "vnet" {
                state
                    .remove_proxy_vnet_routes_and_broadcast(run_id, &p.name)
                    .await;
            }
        }
    }
}
