//! Proxy lifecycle, ping, and UDP packet handlers for the control connection
//! select! loop, plus the post-loop cleanup routine.

use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};

use super::proxy_ops;
use super::{write_ctl_msg, ControlContext, ControlState};

// ── FrpMessage handlers ────────────────────────────────────────────

/// Forward a UDP packet from the frpc client through the proxy's UDP socket.
/// Handles decrypt/decompress, local-addr→proxy-name caching, and bidirectional NAT.
pub(crate) async fn handle_udp_packet<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    _writer: &mut W,
    up: msg::UDPPacket,
) -> Result<(), ()> {
    debug!(byte_count = %up.content.len(), remote_addr = ?up.remote_addr, "UDPPacket from client: {} bytes to {:?}", up.content.len(), up.remote_addr);
    // Forward via the proxy's UDP socket (bidirectional NAT, Go frp compat).
    let local_addr_str = up
        .local_addr
        .as_ref()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let proxy_name = ctl.udp_local_to_proxy.get(&local_addr_str).cloned();
    // Cache local_addr → proxy_name mapping from incoming packets
    if !local_addr_str.is_empty() && !ctl.udp_local_to_proxy.contains_key(&local_addr_str) {
        let fallback_pn = proxy_name
            .clone()
            .or_else(|| {
                let first = ctl.udp_sockets.keys().next().cloned();
                if first.is_some() {
                    tracing::debug!(
                        local_addr = %local_addr_str,
                        "UDP packet local_addr→proxy_name not cached, falling back to first available socket"
                    );
                }
                first
            });
        if let Some(ref pn) = fallback_pn {
            ctl.udp_local_to_proxy
                .insert(local_addr_str.clone(), pn.clone());
        }
    }
    // Decrypt/decompress if the proxy requires it. Move the content in (no
    // clone); decrypt/decompress replace it with a fresh Vec when they succeed.
    let orig_len = up.content.len();
    let mut payload = up.content;
    if let Some(ref pn) = proxy_name {
        // Cached flags (per-control, ControlState) avoid a per-packet
        // proxy_manager.get() (async RwLock). Never hold the cache lock
        // across an .await: probe, then fill on miss.
        let cached = ctl.udp_proxy_flags.get(pn.as_str()).copied();
        let flags = match cached {
            Some(f) => f,
            None => match ctx.state.proxy_manager.get(pn.as_str()).await {
                Some(info) => {
                    let f = (info.use_encryption, info.use_compression);
                    ctl.udp_proxy_flags.insert(pn.clone(), f);
                    f
                }
                // Proxy not (yet) registered: don't cache, so a later packet
                // after registration picks up the real flags.
                None => (false, false),
            },
        };
        if flags.0 {
            if let Ok(decrypted) = encryption::decrypt(&payload, &ctx.reloadable.encryption_key) {
                payload = decrypted;
            }
        }
        if flags.1 {
            if let Ok(decompressed) = encryption::decompress(&payload) {
                payload = decompressed;
            }
        }
    }
    let sock_opt = proxy_name
        .as_ref()
        .and_then(|pn| ctl.udp_sockets.get(pn.as_str()))
        .or_else(|| ctl.udp_sockets.iter().next().map(|(_, s)| s));
    if let Some(sock) = sock_opt {
        let sock = sock.clone();
        let content = payload;
        if let Some(ref remote) = up.remote_addr {
            let remote_str = remote.to_string();
            tokio::spawn(async move {
                let _ = sock.send_to(&content, &remote_str).await;
            });
        }
    } else {
        warn!(
            byte_count = orig_len,
            "No UDP socket for proxy, dropping {} bytes", orig_len
        );
    }
    Ok(())
}

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
        &ctx.state,
        writer,
        &ctx.internal_tx,
        &mut ctl.listener_handles,
        &mut ctl.udp_sockets,
        &mut ctl.udp_local_to_proxy,
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
    if let Some(info) = ctx.state.proxy_manager.get(&cp.proxy_name).await {
        if let Some(port) = info.remote_port {
            // Clean up the appropriate port manager (TCP or UDP — Go frp compat).
            if info.proxy_type == "udp" || info.proxy_type == "sudp" {
                ctx.state.used_udp_ports.write().await.remove(&port);
            } else {
                ctx.state.used_ports.write().await.remove(&port);
            }
            // Decrement per-client port count (matching Go frp's portsUsedNum).
            let mut port_counts = ctx.state.client_ports_used.write().await;
            if let Some(count) = port_counts.get_mut(&ctx.run_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    port_counts.remove(&ctx.run_id);
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
    }
    // Stop the listener task
    if let Some(handle) = ctl.listener_handles.remove(&cp.proxy_name) {
        handle.abort();
    }
    ctx.state.proxy_manager.remove(&cp.proxy_name).await;
    // Drop cached UDP encryption/compression flags for this proxy so a later
    // re-registration with different flags picks up the new values.
    ctl.udp_proxy_flags.remove(&cp.proxy_name);
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
        ctx.state.proxy_manager.remove(name).await;
        ctl.udp_proxy_flags.remove(name);
    }
    info!(run_id = %ctx.run_id, "Control connection {} removed", ctx.run_id);
}
