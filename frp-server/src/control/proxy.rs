//! Proxy lifecycle, ping, and cleanup handlers for the control connection
//! select! loop, plus the post-loop cleanup routine.

use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use frp_core::msg::{self, FrpMessage};

use super::proxy_ops;
use super::{write_ctl_msg, ControlContext, ControlState};

// ── FrpMessage handlers ────────────────────────────────────────────

/// Register a new proxy and start listening on its assigned port.
pub(crate) async fn handle_new_proxy<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    np: msg::NewProxy,
) -> Result<(), ()> {
    info!(proxy_name = %np.proxy_name, "NewProxy: received NewProxy for {}", np.proxy_name);
    let is_udp_proxy = np.proxy_type == "udp" || np.proxy_type == "sudp";
    // np is moved into the callee — capture the name for the
    // post-registration token insert below.
    let proxy_name = np.proxy_name.clone();
    let registered = proxy_ops::handle_new_proxy(
        np,
        &ctx.run_id,
        ctx.control_id,
        &ctx.state,
        writer,
        &ctx.internal_tx,
        &mut ctl.listener_handles,
        &mut ctl.udp_sockets,
        ctx.v2,
    )
    .await;
    // Per-proxy UDP bridge cancellation (low finding 5): each UDP/SUDP
    // proxy gets a child token of the control's udp_cancel so
    // handle_close_proxy can cancel a wedged per-proxy bridge without
    // waiting for control teardown. Inserted ONLY after registration
    // succeeded — a rejected duplicate NewProxy ("already registered")
    // must not replace the live token without cancelling it, which would
    // sever the cancel link to a running wedged bridge (it would then
    // linger until control teardown). A failed registration leaves no
    // token behind at all.
    if registered && is_udp_proxy {
        ctl.udp_cancels
            .insert(proxy_name, ctl.udp_cancel.child_token());
    }
    Ok(())
}

/// Close a proxy and release its resources (port, sk_index, vhost, metrics, listener).
pub(crate) async fn handle_close_proxy<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    _writer: &mut W,
    cp: msg::CloseProxy,
) -> Result<(), ()> {
    // Verify the proxy belongs to this client
    let owner_run_id = ctx.state.proxy_manager.get_run_id(&cp.proxy_name).await;
    if owner_run_id.as_ref() != Some(&ctx.run_id) {
        warn!(
            proxy_name = %cp.proxy_name,
            run_id = %ctx.run_id,
            owner = ?owner_run_id,
            "CloseProxy rejected: proxy belongs to different client"
        );
        return Ok(());
    }
    let info = ctx.state.proxy_manager.get(&cp.proxy_name).await;
    // TCP group proxies share one port + a shared listener across members
    // (Go frp dev compat). When the last member closes, the shared listener
    // must be stopped too — otherwise it outlives the group as a zombie still
    // holding the port. Mirror the lifecycle in `unregister_control`
    // (proxy_ops.rs): only release the group port and stop the listener for
    // the final member.
    let is_tcp_group = info.as_ref().is_some_and(|i| {
        i.proxy_type == "tcp" && i.group.as_deref().filter(|g| !g.is_empty()).is_some()
    });
    // HTTP/HTTPS group member (Go frp v0.71.0 HTTPGroup): shares one vhost
    // route with the other members — close removes it from the group and
    // only drops the route when the group empties.
    let is_http_group_member = info.as_ref().is_some_and(|i| {
        (i.proxy_type == "http" || i.proxy_type == "https")
            && i.group.as_deref().filter(|g| !g.is_empty()).is_some()
    });
    // TCPMux group member (Go frp v0.71.0 TCPMuxGroup): shares one tcpmux
    // route with the other members — close removes it from the group and
    // only drops the shared route (owned by the FIRST member) when the
    // group empties. Mirrors the HTTP group lifecycle (M2 audit fix: the
    // previous unconditional route unregister would delete the shared
    // route while sibling members were still live).
    let is_tcpmux_group_member = info.as_ref().is_some_and(|i| {
        i.proxy_type == "tcpmux" && i.group.as_deref().filter(|g| !g.is_empty()).is_some()
    });
    let group_name = info
        .as_ref()
        .and_then(|i| i.group.clone())
        .unwrap_or_default();
    // M5: the "last member" decision for the shared group port + listener is
    // made AFTER remove() below — two concurrent close paths (a second
    // CloseProxy, or a dashboard delete racing this handler) would both
    // snapshot group_len before either removal and both skip, orphaning the
    // group listener and its port mark. The post-removal count is the true
    // residual. Capture the member's remote port here.
    let tcp_group_port = info.as_ref().and_then(|i| {
        (i.proxy_type == "tcp" && i.group.as_deref().filter(|g| !g.is_empty()).is_some())
            .then_some(i.remote_port)
            .flatten()
    });
    // The derived counters this proxy owns (https SNI-sniff gate count,
    // per-client port-budget slot) are released by
    // `remove_proxy_and_release_client_counts` after remove() succeeds
    // below (S4) — the helper derives both from this pre-removal snapshot,
    // so `info` is only borrowed (not consumed) by the cleanup block above
    // and stays available for the removal call.
    if let Some(info) = info.as_ref() {
        if let Some(port) = info.remote_port {
            // Clean up the appropriate port manager (TCP or UDP — Go frp compat).
            // For a TCP group member that is not the last member, the shared
            // group listener still owns the port — leave it allocated.
            if info.proxy_type == "udp" || info.proxy_type == "sudp" {
                // SUDP proxies can share one server port across proxies
                // (frp-rs extension): only release the port mark when no
                // OTHER live udp/sudp proxy still holds the bound socket —
                // otherwise the next SUDP registration's OS bind probe
                // fails with EADDRINUSE while the shared socket is alive
                // (audit finding 2). The closing proxy itself is still in
                // the registry here, so it is excluded from the owner count.
                proxy_ops::release_udp_port_with_owner_check(&ctx.state, port, &cp.proxy_name)
                    .await;
            } else if !is_tcp_group {
                ctx.state.used_ports.write().await.remove(&port);
                // TCP group ports are released with the shared listener for
                // the FINAL member only — see the post-remove block below
                // (M5 race-safe ordering).
            }
            // The per-client port-count decrement is NOT here: the slot is
            // released by `remove_proxy_and_release_client_counts` after
            // remove() succeeds below (S4 — a racing dashboard delete must
            // not double-decrement).
        }
        // Clean up STCP sk_index (indexed by proxy_name)
        if let Some(key) = info.sk_index_key() {
            ctx.state.xtcp.sk_index.remove(key);
        }
        // Clean up VHost routes — HTTP/HTTPS group members share one route:
        // remove the member from the group first; only drop the shared
        // route when the group becomes empty (Go HTTPGroup.UnRegister).
        if is_http_group_member {
            let fresh = ctx.state.proxy_manager.get(&cp.proxy_name).await;
            let kind_https = fresh.as_ref().is_some_and(|i| i.proxy_type == "https");
            let gname = fresh.and_then(|i| i.group.clone()).unwrap_or_default();
            if let Some(owner) = ctx
                .state
                .http_group_ctl
                .unregister_member(&gname, &cp.proxy_name, kind_https)
                .await
            {
                // The shared route is keyed on the FIRST member's name; the
                // group just emptied, so drop it with the owner's name.
                ctx.state.vhost_manager.unregister(&owner).await;
            }
        } else {
            ctx.state.vhost_manager.unregister(&cp.proxy_name).await;
        }
        // Clean up tcpmux domain routes: without this a CloseProxy of a
        // tcpmux proxy leaves its domains (and wildcard_count) registered
        // until control disconnect — a reload-rename (CloseProxy A then
        // NewProxy B with A's domain) would be rejected with "tcpmux route
        // conflict". Mirrors the unregister_control sweep (proxy_ops.rs)
        // and dashboard delete path; no-op for non-tcpmux proxies.
        //
        // TCPMux group members: remove from the group first; the shared
        // route is keyed on the FIRST member's name, so drop it with the
        // owner only when the group empties (M2).
        if is_tcpmux_group_member {
            let fresh = ctx.state.proxy_manager.get(&cp.proxy_name).await;
            let gname = fresh.and_then(|i| i.group.clone()).unwrap_or_default();
            if let Some(owner) = ctx
                .state
                .tcpmux_group_ctl
                .unregister_member(&gname, &cp.proxy_name)
                .await
            {
                ctx.state.tcpmux_manager.unregister(&owner).await;
            }
        } else {
            ctx.state.tcpmux_manager.unregister(&cp.proxy_name).await;
        }
        ctx.state.proxy_metrics.remove(&cp.proxy_name).await;
        #[cfg(feature = "dashboard")]
        crate::metrics::prom::proxy_removed(&cp.proxy_name).await;
        #[cfg(feature = "vnet")]
        {
            ctx.state
                .remove_proxy_vnet_routes_and_broadcast(&ctx.run_id, &cp.proxy_name)
                .await;
        }
    }
    // Stop the listener task
    if let Some(handle) = ctl.listener_handles.remove(&cp.proxy_name) {
        handle.abort();
    }
    // Remove the proxy from the registry and release the counters it owns
    // (https SNI-sniff gate count, per-client port-budget slot) ONLY when
    // this call actually performed the removal. The dashboard delete path
    // races this handler — both observe the proxy before either removes it
    // — and a double release would decrement client_ports_used twice (S4:
    // the budget drifts below the live count and max_ports_per_client
    // admits extra proxies) and leave https_proxy_count at 0 while https
    // proxies still exist, silently disabling SNI sniff (HTTPS vhost
    // routing). Gating on remove()'s result makes exactly one path
    // release; the port marks and shared group-listener teardown below are
    // idempotent and run on every path (as before).
    match info {
        Some(i) => {
            proxy_ops::remove_proxy_and_release_client_counts(&ctx.state, &i).await;
        }
        None => {
            // `info` was None only if the proxy vanished between the
            // ownership check and the fetch — remove() by name then reports
            // false and releases nothing (there was nothing to release).
            ctx.state.proxy_manager.remove(&cp.proxy_name).await;
        }
    }
    // Stop the shared TCP group listener when the last member closes so it
    // doesn't linger as a zombie holding the group port (remove_group cancels
    // the listener's token — same shutdown signal as `unregister_control`).
    // M5: the membership check runs AFTER remove() above — concurrent close
    // paths (a second CloseProxy, or a dashboard delete racing this handler)
    // would both snapshot group_len before either removal and both skip,
    // orphaning the listener + port mark. The post-removal count is the true
    // residual; remove_group is idempotent, and the member's port mark is
    // released here with the listener (non-group TCP ports are released
    // above). A member re-registering between the check and the cancel
    // re-creates the group listener on registration — self-healing.
    if is_tcp_group && ctx.state.proxy_manager.group_len(&group_name).await == 0 {
        if let Some(port) = tcp_group_port {
            ctx.state.used_ports.write().await.remove(&port);
        }
        ctx.state.tcp_group_ctl.remove_group(&group_name).await;
        info!(
            proxy_name = %cp.proxy_name,
            group = %group_name,
            "TCP group '{}' shared listener stopped after last member '{}' closed",
            group_name, cp.proxy_name
        );
    }
    // Drop this proxy's UDP socket from ctl (Go frp closeUDP parity). The
    // bridge task may still hold a clone via its spawned Arc; the socket is
    // fully closed once that task exits.
    ctl.udp_sockets.remove(&cp.proxy_name);
    // Cancel this proxy's UDP bridge task (low finding 5): without this, a
    // wedged bridge (half-open work conn) only exits at control teardown
    // via udp_cancel. The token is a child of udp_cancel, so cleanup's
    // udp_cancel.cancel() still covers it — double-cancel is idempotent.
    if let Some(cancel) = ctl.udp_cancels.remove(&cp.proxy_name) {
        cancel.cancel();
    }
    info!(proxy_name = %cp.proxy_name, "Proxy closed: {}", cp.proxy_name);
    // Emit WebSocket event for dashboard subscribers
    #[cfg(feature = "dashboard")]
    {
        let _ = ctx
            .state
            .event_tx
            .send(crate::event::ServerEvent::ProxyDown {
                proxy_name: cp.proxy_name.clone(),
                run_id: ctx.run_id.clone(),
            });
    }
    // Server plugin: close_proxy hook (fire-and-forget — Go closeProxy
    // spawns a goroutine for the notify, and Go discards the returned
    // content here too: manager.go CloseProxy is notify-only). Payload is
    // Go's CloseProxyContent: `user` object + proxy_name; `run_id` stays
    // as a frp-rs extra (additive).
    let plugin_state = ctx.state.clone();
    let pn = cp.proxy_name.clone();
    let rid = ctx.run_id.clone();
    let user_info = ctx
        .state
        .plugin_manager
        .user_info(&ctx.run_id)
        .unwrap_or_default();
    tokio::spawn(async move {
        let _ = plugin_state
            .plugin_manager
            .notify(
                "close_proxy",
                serde_json::json!({
                    "user": user_info,
                    "proxy_name": pn,
                    "run_id": rid,
                }),
            )
            .await;
    });
    // Note: Go frp does not send CloseProxyResp (type 7/19 is
    // Rust-only). frp-rs client handles both CloseProxy
    // and CloseProxyResp identically and already cleans up
    // health_cancels immediately after sending CloseProxy,
    // so no response is needed here.
    Ok(())
}

/// Write a CloseProxy message to the client via its control channel.
/// Called from the dashboard delete API to notify the client to shut
/// down its proxy listener and local resources.
pub(crate) async fn handle_write_close_proxy<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: String,
) {
    debug!(
        proxy_name = %proxy_name,
        "Writing CloseProxy to client via control channel for {}",
        proxy_name
    );
    let msg = FrpMessage::CloseProxy(msg::CloseProxy { proxy_name });
    if let Err(e) = write_ctl_msg(writer, &msg, ctx.v2).await {
        warn!(
            error = %e,
            "Failed to write CloseProxy to client: {}",
            e
        );
    }
}

/// Handle a Ping from the frpc client: validate auth, update last_ping, send Pong.
pub(crate) async fn handle_ping<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    ping_msg: msg::Ping,
) -> Result<(), ()> {
    // Go parity (server/control.go handlePing): the Ping plugin hook runs
    // BEFORE ping auth verification. A plugin may reject the ping (Pong
    // with an error, lastPing NOT updated — the control stays up, Go
    // tolerates a failed ping) or mutate it (the mutation feeds
    // VerifyPing below).
    let mut ping_msg = ping_msg;
    if !ctx.state.plugin_manager.is_empty() {
        // Go pkg/plugin/server/types.go PingContent: `user` object + the
        // flat Ping msg (privilege_key, timestamp); `run_id`/`remote_addr`
        // stay as frp-rs extras (additive).
        let user_info = ctx
            .state
            .plugin_manager
            .user_info(&ctx.run_id)
            .unwrap_or_default();
        let mut ping_content = match serde_json::to_value(&ping_msg) {
            Ok(v) => v,
            Err(e) => {
                warn!(peer = ?ctx.peer, error = %e, "Ping plugin content serialize error for {:?}: {}", ctx.peer, e);
                let pong = FrpMessage::Pong(msg::Pong {
                    error: Some(proxy_ops::err_msg(
                        ctx.state.detailed_errors_to_client,
                        format!("server plugin ping content error: {e}"),
                        "invalid ping",
                    )),
                });
                let _ = write_ctl_msg(writer, &pong, ctx.v2).await;
                return Ok(());
            }
        };
        if let Some(obj) = ping_content.as_object_mut() {
            obj.insert(
                "user".into(),
                serde_json::to_value(&user_info).unwrap_or_default(),
            );
            obj.insert("run_id".into(), serde_json::json!(ctx.run_id));
            obj.insert(
                "remote_addr".into(),
                serde_json::json!(ctx.peer.map(|a| a.to_string()).unwrap_or_default()),
            );
        }
        match ctx.state.plugin_manager.notify("ping", ping_content).await {
            Err(reason) => {
                warn!(peer = ?ctx.peer, reason = %reason, "Ping rejected by server plugin from {:?}: {}", ctx.peer, reason);
                let pong = FrpMessage::Pong(msg::Pong {
                    error: Some(proxy_ops::err_msg(
                        ctx.state.detailed_errors_to_client,
                        reason,
                        "invalid ping",
                    )),
                });
                let _ = write_ctl_msg(writer, &pong, ctx.v2).await;
                return Ok(());
            }
            Ok(Some(mutated)) => {
                // Go handleMutableContent: the plugin's returned content
                // replaces the typed Ping before VerifyPing. Fail closed on
                // invalid content.
                match crate::plugin::apply_plugin_mutation(&ping_msg, mutated) {
                    Ok(m) => ping_msg = m,
                    Err(e) => {
                        warn!(peer = ?ctx.peer, error = %e, "Ping plugin returned invalid content from {:?}: {}", ctx.peer, e);
                        let pong = FrpMessage::Pong(msg::Pong {
                            error: Some(proxy_ops::err_msg(
                                ctx.state.detailed_errors_to_client,
                                e,
                                "invalid ping",
                            )),
                        });
                        let _ = write_ctl_msg(writer, &pong, ctx.v2).await;
                        return Ok(());
                    }
                }
            }
            Ok(None) => {}
        }
    }
    // Validate ping auth (Go frp v0.69.1 compat).
    // Only validate when "HeartBeats" is in additional_auth_scopes.
    let requires_ping_auth = ctx
        .reloadable
        .additional_auth_scopes
        .iter()
        .any(|s| s == "HeartBeats");
    let ping_auth_result = if !requires_ping_auth {
        Ok(())
    } else if let Some(ref verifier) = ctx.state.oidc.verifier {
        let expected_sub = ctx
            .state
            .oidc
            .subjects
            .read()
            .await
            .get(&ctx.run_id)
            .map(|(subject, _)| subject.clone())
            .unwrap_or_default();
        verifier
            .verify_ping(
                ping_msg.privilege_key.as_deref().unwrap_or(""),
                &expected_sub,
            )
            .await
    } else {
        ctx.reloadable.auth_cfg.resolve_token().and_then(|token| {
            ctx.reloadable
                .auth_cfg
                .validate_login_with_token(
                    &token,
                    ping_msg.privilege_key.as_deref(),
                    ping_msg.timestamp,
                )
                .map(|_| ())
        })
    };
    if let Err(e) = ping_auth_result {
        warn!(peer = ?ctx.peer, error = %e, "Ping auth failed from {:?}: {}", ctx.peer, e);
        let pong = FrpMessage::Pong(msg::Pong {
            error: Some(proxy_ops::err_msg(
                ctx.state.detailed_errors_to_client,
                e,
                "ping authentication failed",
            )),
        });
        let _ = write_ctl_msg(writer, &pong, ctx.v2).await;
        // Go frp v0.71.0 parity (server/control.go handlePing): an invalid
        // ping gets a Pong{Error} and the handler returns nil — the control
        // connection stays up and lastPing is NOT updated. Go tolerates a
        // failed ping so a transient clock-skew/plugin auth failure survives
        // to the next ping instead of reconnect-storming.
        return Ok(());
    }
    ctl.last_ping = tokio::time::Instant::now();
    let pong = FrpMessage::Pong(msg::Pong { error: None });
    if let Err(e) = write_ctl_msg(writer, &pong, ctx.v2).await {
        warn!(error = %e, "Failed to send pong: {}", e);
        return Err(());
    }
    debug!(peer = ?ctx.peer, "Ping from {:?}", ctx.peer);
    Ok(())
}

// ── Post-loop cleanup ──────────────────────────────────────────────

/// Drain all listener handles, emit dashboard events, unregister control,
/// and remove the client from the proxy manager. Called once after the
/// main select! loop exits.
///
/// ## Supersession safety
///
/// During supersession (client reconnects with the same run_id), the NEW
/// handler may have already registered proxies before the OLD handler's
/// cleanup runs. We capture proxy names at the start and only remove
/// those specific proxies, preventing the old handler from deleting the
/// new handler's proxies.
pub(crate) async fn cleanup<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    _writer: &mut W,
) {
    // Capture proxy names belonging to this client BEFORE any cleanup.
    // During supersession, the new handler may have already registered
    // proxies under the same run_id — we must only remove proxies that
    // existed when THIS handler started shutting down.
    let proxy_names: Vec<String> = ctx
        .state
        .proxy_manager
        .list_client_proxy_names(&ctx.run_id)
        .await;

    for (_, handle) in ctl.listener_handles.drain() {
        handle.abort();
    }
    // Cancel UDP bridge tasks: they hold a clone of the proxy's UdpSocket and
    // block on the work conn read / socket recv. On supersession or disconnect
    // the work conn can stay half-open forever, so without this they'd hang
    // and keep the socket + task memory alive (Go frp v0.70.1 fix parity).
    // Dropping the sockets from ctl releases this control's Arc; the bridge
    // task's Arc is released when it observes the cancellation and exits.
    ctl.udp_cancel.cancel();
    ctl.udp_sockets.clear();
    // Cancel TCP/WS/KCP work-conn bridge tasks (HIGH finding): each bridge
    // holds the user conn + work conn and copies until one side dies. The
    // work conn is owned by this control, so on disconnect/supersession it
    // stays half-open forever and every reconnect with active tunnels leaked
    // 1 task + 2 fds. The bridges select on this token alongside the
    // server-global shutdown token (which still covers graceful shutdown).
    ctl.bridge_cancel.cancel();
    // Per-proxy UDP bridge tokens are children of udp_cancel — already
    // cancelled by the line above; drop the map.
    ctl.udp_cancels.clear();
    // Emit ProxyDown for all proxies owned by this client (before removing them)
    #[cfg(feature = "dashboard")]
    {
        for pn in &proxy_names {
            let _ = ctx
                .state
                .event_tx
                .send(crate::event::ServerEvent::ProxyDown {
                    proxy_name: pn.clone(),
                    run_id: ctx.run_id.clone(),
                });
        }
    }
    // Emit ClientDisconnected
    #[cfg(feature = "dashboard")]
    {
        let _ = ctx
            .state
            .event_tx
            .send(crate::event::ServerEvent::ClientDisconnected {
                run_id: ctx.run_id.clone(),
            });
    }
    proxy_ops::unregister_control(
        &ctx.state,
        &ctx.run_id,
        ctx.control_id,
        ctl.shutting_down,
        true,
    )
    .await;
    // Remove only the proxies that existed at cleanup start.
    // Do NOT use remove_client() — it removes ALL proxies for this run_id,
    // which in supersession would delete the new handler's proxies.
    for name in &proxy_names {
        // Generation-guarded removal: `remove_if_control_id` removes only
        // when the entry still belongs to this control generation (or has
        // no owner), closing the get-then-remove window where a same-name
        // newer-generation re-registration landing between the pre-check
        // and the removal would be torn down (audit finding 3 — same
        // generation filter as unregister_control and the round-7 reaper).
        if let Some(removed) = ctx
            .state
            .proxy_manager
            .remove_if_control_id(name, ctx.control_id)
            .await
        {
            // Port-mark ownership on supersession: a skipped proxy's
            // ORIGINAL port mark was freed exactly once by the superseding
            // login's registration — register_or_replace returned the
            // replaced entry and free_replaced_port (proxy_ops.rs) released
            // the old mark when it differed from the new port. Nothing
            // leaks here (audit-fix: residual port-mark leak on
            // barrier-timeout supersession; same note in proxy_ops.rs
            // unregister_control).
            //
            // Decrement the SNI-sniff gate count only when the removed
            // entry is an https proxy — the removed entry is the source of
            // truth (a racing dashboard delete may have removed it first,
            // and a double decrement would leave https_proxy_count at 0
            // while https proxies still exist, silently disabling SNI
            // sniff).
            if removed.proxy_type == "https" {
                ctx.state.dec_https_proxy_count();
            }
        }
    }
    info!(run_id = %ctx.run_id, "Control connection {} removed", ctx.run_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Low finding 5: handle_close_proxy must cancel the per-proxy UDP
    /// bridge token so a wedged bridge (half-open work conn) exits
    /// immediately instead of lingering until control teardown.
    ///
    /// A full wedged-bridge task is not staged here: the bridge
    /// (assign_udp_work_conn/run_udp_work_conn in pool.rs) selects on the
    /// token it is handed, and the child-of-udp_cancel wiring means
    /// teardown cancellation is identical to what a live bridge observes
    /// on control disconnect — so the deterministic unit-level contract is
    /// "close cancels the token and drops it from the map".
    #[tokio::test]
    async fn close_proxy_cancels_per_proxy_udp_bridge_token() {
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        let info = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "u1",
            "udp",
            "run-1",
            Some(24000),
            1,
        );
        state
            .proxy_manager
            .register("run-1".into(), info)
            .await
            .expect("register udp proxy");

        let (_, run_mu_guard) = state.get_run_mu("run-1");
        let (internal_tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = ControlContext {
            state: Arc::clone(&state),
            pool_stats: Arc::new(crate::state::PoolStats::default()),
            reloadable: state
                .reloadable
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            v2: false,
            run_id: "run-1".to_string(),
            control_id: 1,
            pool_cap: 10,
            internal_tx,
            peer: None,
            authenticated_user: String::new(),
            udp_packet_codec: String::new(),
            _run_mu_guard: run_mu_guard,
        };
        let mut ctl = ControlState {
            shutting_down: false,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            udp_cancels: HashMap::new(),
            bridge_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool: std::collections::VecDeque::new(),
            pending_requests: std::collections::VecDeque::new(),
            pending_udp: std::collections::VecDeque::new(),
            pending_nat_hole_sids: std::collections::VecDeque::new(),
            listener_handles: HashMap::new(),
            udp_sockets: HashMap::new(),
            last_ping: tokio::time::Instant::now(),
            superseded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        // Simulate the handle_new_proxy registration: per-proxy child token.
        let token = ctl.udp_cancel.child_token();
        ctl.udp_cancels.insert("u1".to_string(), token.clone());
        assert!(!token.is_cancelled(), "token starts live");

        let mut writer = Vec::new();
        let res = handle_close_proxy(
            &mut ctx,
            &mut ctl,
            &mut writer,
            msg::CloseProxy {
                proxy_name: "u1".to_string(),
            },
        )
        .await;
        assert!(res.is_ok());
        assert!(
            token.is_cancelled(),
            "close_proxy must cancel the per-proxy UDP bridge token"
        );
        assert!(
            ctl.udp_cancels.is_empty(),
            "cancelled token must be removed from the map"
        );
    }

    /// HIGH finding: cleanup (control disconnect / supersession) must cancel
    /// the work-conn bridge token so TCP/WS/KCP bridges spawned by
    /// `assign_work_to_proxy` exit instead of copying forever over a
    /// half-open work conn (1 task + 2 fds leaked per reconnect with active
    /// tunnels). The bridge-task side is covered e2e by bridge.rs
    /// `bridge_cancel_terminates_half_open_tcp_bridge`; this pins the
    /// cleanup wiring: teardown cancels the token.
    #[tokio::test]
    async fn cleanup_cancels_work_conn_bridge_token() {
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        let (_, run_mu_guard) = state.get_run_mu("run-1");
        let (internal_tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = ControlContext {
            state: Arc::clone(&state),
            pool_stats: Arc::new(crate::state::PoolStats::default()),
            reloadable: state
                .reloadable
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            v2: false,
            run_id: "run-1".to_string(),
            control_id: 1,
            pool_cap: 10,
            internal_tx,
            peer: None,
            authenticated_user: String::new(),
            udp_packet_codec: String::new(),
            _run_mu_guard: run_mu_guard,
        };
        let mut ctl = ControlState {
            shutting_down: false,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            udp_cancels: HashMap::new(),
            bridge_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool: std::collections::VecDeque::new(),
            pending_requests: std::collections::VecDeque::new(),
            pending_udp: std::collections::VecDeque::new(),
            pending_nat_hole_sids: std::collections::VecDeque::new(),
            listener_handles: HashMap::new(),
            udp_sockets: HashMap::new(),
            last_ping: tokio::time::Instant::now(),
            superseded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let bridge_token = ctl.bridge_cancel.clone();
        assert!(!bridge_token.is_cancelled(), "token starts live");

        let mut writer = Vec::new();
        cleanup(&mut ctx, &mut ctl, &mut writer).await;

        assert!(
            bridge_token.is_cancelled(),
            "cleanup must cancel the work-conn bridge token"
        );
    }

    /// Round-8 finding: cleanup's per-proxy removal must be generation-
    /// guarded (`remove_if_control_id`). A proxy that a NEWER control
    /// generation re-registered between the name snapshot and the removal
    /// loop must survive the old handler's cleanup — the old get-then-remove
    /// window could tear down the fresh registration. Mirrors the round-7
    /// reaper pattern (service.rs).
    #[tokio::test]
    async fn cleanup_removes_own_generation_proxy_and_decrements_https() {
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        state
            .proxy_manager
            .register(
                "run-1".into(),
                crate::control::proxy_ops::unregister_generation_tests::proxy_info(
                    "p1",
                    "https",
                    "run-1",
                    Some(24001),
                    1,
                ),
            )
            .await
            .expect("register https proxy");
        state
            .https_proxy_count
            .store(1, std::sync::atomic::Ordering::Relaxed);

        let (_, run_mu_guard) = state.get_run_mu("run-1");
        let (internal_tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = ControlContext {
            state: Arc::clone(&state),
            pool_stats: Arc::new(crate::state::PoolStats::default()),
            reloadable: state
                .reloadable
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            v2: false,
            run_id: "run-1".to_string(),
            control_id: 1,
            pool_cap: 10,
            internal_tx,
            peer: None,
            authenticated_user: String::new(),
            udp_packet_codec: String::new(),
            _run_mu_guard: run_mu_guard,
        };
        let mut ctl = ControlState {
            shutting_down: false,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            udp_cancels: HashMap::new(),
            bridge_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool: std::collections::VecDeque::new(),
            pending_requests: std::collections::VecDeque::new(),
            pending_udp: std::collections::VecDeque::new(),
            pending_nat_hole_sids: std::collections::VecDeque::new(),
            listener_handles: HashMap::new(),
            udp_sockets: HashMap::new(),
            last_ping: tokio::time::Instant::now(),
            superseded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        let mut writer = Vec::new();
        cleanup(&mut ctx, &mut ctl, &mut writer).await;

        assert!(
            state.proxy_manager.get("p1").await.is_none(),
            "own-generation https proxy must be removed by cleanup"
        );
        assert_eq!(
            state
                .https_proxy_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "removing an https proxy must decrement the SNI-sniff gate count"
        );
    }

    /// Round-8 finding (supersession arm): the same-name proxy re-registered
    /// by a NEWER generation (control_id 2, via register_or_replace) must
    /// survive the OLD generation's cleanup, and the https count must NOT
    /// be decremented for the surviving entry.
    #[tokio::test]
    async fn cleanup_skips_newer_generation_proxy_without_https_decrement() {
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        state
            .proxy_manager
            .register(
                "run-1".into(),
                crate::control::proxy_ops::unregister_generation_tests::proxy_info(
                    "p1",
                    "https",
                    "run-1",
                    Some(24001),
                    1,
                ),
            )
            .await
            .expect("register old-generation https proxy");
        // The superseding login's registration replaces the old entry.
        state
            .proxy_manager
            .register_or_replace(
                "run-1".into(),
                crate::control::proxy_ops::unregister_generation_tests::proxy_info(
                    "p1",
                    "https",
                    "run-1",
                    Some(24002),
                    2,
                ),
            )
            .await
            .expect("register_or_replace newer-generation proxy");
        // Both generations' registrations are https (proxy_ops increments
        // once per registration in production).
        state
            .https_proxy_count
            .store(2, std::sync::atomic::Ordering::Relaxed);

        let (_, run_mu_guard) = state.get_run_mu("run-1");
        let (internal_tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = ControlContext {
            state: Arc::clone(&state),
            pool_stats: Arc::new(crate::state::PoolStats::default()),
            reloadable: state
                .reloadable
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            v2: false,
            run_id: "run-1".to_string(),
            control_id: 1,
            pool_cap: 10,
            internal_tx,
            peer: None,
            authenticated_user: String::new(),
            udp_packet_codec: String::new(),
            _run_mu_guard: run_mu_guard,
        };
        let mut ctl = ControlState {
            shutting_down: false,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            udp_cancels: HashMap::new(),
            bridge_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool: std::collections::VecDeque::new(),
            pending_requests: std::collections::VecDeque::new(),
            pending_udp: std::collections::VecDeque::new(),
            pending_nat_hole_sids: std::collections::VecDeque::new(),
            listener_handles: HashMap::new(),
            udp_sockets: HashMap::new(),
            last_ping: tokio::time::Instant::now(),
            superseded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        let mut writer = Vec::new();
        cleanup(&mut ctx, &mut ctl, &mut writer).await;

        let survivor = state.proxy_manager.get("p1").await;
        assert!(
            survivor.is_some_and(|i| i.control_id == 2),
            "newer-generation proxy must survive the old generation's cleanup"
        );
        assert_eq!(
            state
                .https_proxy_count
                .load(std::sync::atomic::Ordering::Relaxed),
            2,
            "the surviving newer-generation https proxy must not decrement the count"
        );
    }
}
