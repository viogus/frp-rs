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
    info!(proxy_name = %np.proxy_name, "KCP TLS: received NewProxy for {}", np.proxy_name);
    proxy_ops::handle_new_proxy(
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
    let group_name = info
        .as_ref()
        .and_then(|i| i.group.clone())
        .unwrap_or_default();
    let last_group_member =
        is_tcp_group && ctx.state.proxy_manager.group_len(&group_name).await <= 1;
    let is_https = if let Some(info) = info {
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
            } else if !is_tcp_group || last_group_member {
                ctx.state.used_ports.write().await.remove(&port);
            }
            // Decrement per-client port count (matching Go frp's portsUsedNum).
            // Only proxies that actually consumed a port were counted
            // (audit finding 1 symmetry): stcp/xtcp/http/https/tcpmux close
            // with remote_port Some(0) and must not decrement.
            if matches!(info.proxy_type.as_str(), "tcp" | "udp" | "sudp") && port > 0 {
                let mut port_counts = ctx.state.client_ports_used.write().await;
                if let Some(count) = port_counts.get_mut(&ctx.run_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        port_counts.remove(&ctx.run_id);
                    }
                }
            }
        }
        // Clean up STCP sk_index (indexed by proxy_name)
        if let Some(key) = info.sk_index_key() {
            ctx.state.xtcp.sk_index.write().await.remove(key);
        }
        // Clean up VHost routes
        ctx.state.vhost_manager.unregister(&cp.proxy_name).await;
        ctx.state.proxy_metrics.remove(&cp.proxy_name).await;
        #[cfg(feature = "vnet")]
        {
            ctx.state
                .remove_proxy_vnet_routes_and_broadcast(&ctx.run_id, &cp.proxy_name)
                .await;
        }
        info.proxy_type == "https"
    } else {
        false
    };
    // Stop the listener task
    if let Some(handle) = ctl.listener_handles.remove(&cp.proxy_name) {
        handle.abort();
    }
    // Decrement the SNI-sniff gate count only when the proxy was actually
    // removed. The dashboard delete path races this handler — both observe
    // the proxy before either removes it, and a double decrement would leave
    // https_proxy_count at 0 while https proxies still exist, silently
    // disabling SNI sniff (HTTPS vhost routing) until the next lifecycle
    // event. Gating on remove()'s result makes exactly one path decrement.
    if ctx.state.proxy_manager.remove(&cp.proxy_name).await && is_https {
        ctx.state.dec_https_proxy_count();
    }
    // Stop the shared TCP group listener when the last member closes so it
    // doesn't linger as a zombie holding the group port (remove_group cancels
    // the listener's token — same shutdown signal as `unregister_control`).
    if last_group_member {
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
    // Server plugin: close_proxy hook (fire-and-forget)
    let plugin_state = ctx.state.clone();
    let pn = cp.proxy_name.clone();
    let rid = ctx.run_id.clone();
    tokio::spawn(async move {
        let _ = plugin_state
            .plugin_manager
            .notify(
                "close_proxy",
                serde_json::json!({ "proxy_name": pn, "run_id": rid }),
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
        return Err(());
    }
    ctl.last_ping = tokio::time::Instant::now();
    // Fire ping plugin hook (fire-and-forget — don't block control loop)
    let ping_content = serde_json::json!({
        "run_id": ctx.run_id,
        "remote_addr": ctx.peer.map(|a| a.to_string()).unwrap_or_default(),
        "timestamp": ping_msg.timestamp,
    });
    let plugin_mgr = ctx.state.plugin_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = plugin_mgr.notify("ping", ping_content).await {
            debug!(error = %e, "Ping plugin hook failed");
        }
    });
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
    proxy_ops::unregister_control(&ctx.state, &ctx.run_id, ctx.control_id, ctl.shutting_down).await;
    // Remove only the proxies that existed at cleanup start.
    // Do NOT use remove_client() — it removes ALL proxies for this run_id,
    // which in supersession would delete the new handler's proxies.
    for name in &proxy_names {
        // Skip proxies registered by a newer control generation: when the
        // 10s handoff barrier times out, the superseding control may have
        // registered proxies before this cleanup captured its snapshot, and
        // the snapshot-then-remove loop must not tear them down (audit
        // finding 3 — same generation filter as unregister_control).
        if ctx
            .state
            .proxy_manager
            .get(name)
            .await
            .is_some_and(|i| i.control_id != 0 && i.control_id > ctx.control_id)
        {
            continue;
        }
        // Decrement the SNI-sniff gate count only when the proxy was
        // actually removed here — a racing dashboard delete may have removed
        // it first, and a double decrement would leave https_proxy_count at 0
        // while https proxies still exist, silently disabling SNI sniff.
        let is_https = ctx
            .state
            .proxy_manager
            .get(name)
            .await
            .is_some_and(|i| i.proxy_type == "https");
        if ctx.state.proxy_manager.remove(name).await && is_https {
            ctx.state.dec_https_proxy_count();
        }
    }
    info!(run_id = %ctx.run_id, "Control connection {} removed", ctx.run_id);
}
