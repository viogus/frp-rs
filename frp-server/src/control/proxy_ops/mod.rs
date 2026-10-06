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
use crate::state::{ControlTx, GroupPortQuery};

mod validate;
use validate::{duplicate_domain, validate_new_proxy};

mod vhost;
use vhost::{register_http_vhost, register_https_vhost};

mod tcp_group;
use tcp_group::{handle_tcp_group_member_registration, tcp_group_listener};

mod registry;
pub(crate) use registry::remove_proxy_and_release_client_counts;
use registry::{
    build_proxy_info, register_proxy_entry, rollback_tcp_bind_failure, rollback_udp_bind_failure,
    rollback_vhost_conflict,
};

mod ports;
#[cfg(test)]
use ports::prune_expired_reservations_inner;
pub(crate) use ports::release_udp_port_with_owner_check;
use ports::{
    allocate_proxy_port, free_replaced_port, proxy_consumes_client_port, udp_port_has_other_owner,
};

/// Returns full detail when detailed_errors is enabled, otherwise generic message.
/// Build a NewProxyResp error text, mirroring Go
/// `util.GenerateResponseErrorString(summary, err, detailed)` (pkg/util/
/// util/util.go:113-118): detailed mode sends the full error, non-detailed
/// sends the summary.
///
/// Documented divergence (R1 review, round 10): Go ALWAYS passes the fixed
/// summary "new proxy [<name>] error" (server/control.go:757) for every
/// registration failure, so in non-detailed mode a Go client learns nothing
/// beyond the proxy name. frp-rs deliberately uses per-class summaries
/// ("group params invalid", "vhost route config conflict", …) — strictly
/// more informative for frp-rs clients, and `detailed_errors_to_client`
/// defaults to true on both sides, so the common path carries the exact Go
/// error text either way. Keep per-arm summaries consistent: each arm
/// should name its own failure class, never mask a sibling's.
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

/// Set up the per-proxy listener for a newly registered proxy: UDP/SuDP
/// socket bind with work-conn requesters, TCP group shared listener, or
/// per-proxy TCP listener. Returns the oneshot senders that must be fired
/// after NewProxyResp is written (they gate ReqWorkConn on the response)
/// plus the FINAL port, or `Err(())` if the proxy was already rejected
/// (bind failure) and the caller must abort. The final port can differ
/// from the requested `port` for TCP proxies: an auto-assigned port stolen
/// by another process between the allocation probe and the bind triggers
/// an internal re-allocation retry (`bind_tcp_proxy_with_retry`) — the
/// caller's NewProxyResp / dashboard event must use the returned port.
/// Extracted from `handle_new_proxy`'s state machine.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
async fn setup_proxy_listeners(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    control_id: u64,
    port: u16,
    bind_addr: &str,
    itx: &mpsc::Sender<InternalMsg>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
    tcp_group_created: bool,
) -> Result<(Vec<oneshot::Sender<()>>, u16), ()> {
    let is_nat_hole =
        np.proxy_type == "stcp" || np.proxy_type == "xtcp" || np.proxy_type == "tcpmux";
    let pn = np.proxy_name.clone();
    let itx = itx.clone();
    let bind_addr = bind_addr.to_string();
    // Mutable: the per-proxy TCP branch may re-allocate on an auto-assign
    // bind race, moving the proxy to a fresh port.
    let mut port = port;

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
                                  // send() fails only when the internal channel is
                                  // closed (control handler gone); log at debug.
                if let Err(e) = itx_clone
                    .send(InternalMsg::UdpNeedsWorkConn {
                        proxy_name: pn_clone.clone(),
                    })
                    .await
                {
                    debug!(proxy_name = %pn_clone, error = %e, "UdpNeedsWorkConn send failed: {}", e);
                }
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
                // EADDRINUSE surviving the 3×100ms retries: a sibling member
                // may have created the group (and bound its shared listener)
                // while this registration was in flight. Rolling back would
                // reject the first member for a transient collision — the
                // join fallback below re-checks the group and registers as
                // a member instead (audit-fix: group-create bind failure
                // rejected the first member). Per-proxy TCP listeners keep
                // the reject behavior: their port is exclusive.
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    // This member's DECLARED port decides the join, not the
                    // port this attempt happened to bind (auto-assign
                    // resolves 0 to a concrete number the sibling may not
                    // share). Go compares declared-vs-declared (tcp.go).
                    let declared_port = np.remote_port.unwrap_or(0) as u16;
                    match state
                        .tcp_group_ctl
                        .get_group_port(&group_name, &group_key, declared_port, &bind_addr)
                        .await
                    {
                        GroupPortQuery::Matched(join_port) => {
                            // The group exists and matches this member's
                            // declared group/key/port — join it on the
                            // GROUP's real port (auto-assign groups resolve
                            // to a real port this member never bound).
                            // Roll back the create-path registration (port
                            // mark + registry entry + count), then
                            // re-register via the member path, which writes
                            // the NewProxyResp itself and marks the group's
                            // real port.
                            tracing::warn!(
                                port = %port,
                                join_port = %join_port,
                                group = %group_name,
                                proxy_name = %np.proxy_name,
                                "TCP group port {port} bind raced a sibling group create for '{}' — joining existing group on port {join_port}",
                                np.proxy_name,
                            );
                            rollback_tcp_bind_failure(state, run_id, port, &np.proxy_name).await;
                            state.used_ports.write().await.insert(join_port);
                            handle_tcp_group_member_registration(
                                state,
                                run_id,
                                control_id,
                                writer,
                                np.clone(),
                                declared_port,
                                &itx,
                                listener_handles,
                                udp_sockets,
                                v2,
                                Some(join_port),
                                tcp_group_created,
                            )
                            .await;
                            return Err(());
                        }
                        GroupPortQuery::Mismatch(err_text) => {
                            // Group exists but with different params — Go
                            // rejects with the specific text (F5), not a
                            // generic bind error.
                            tracing::warn!(
                                port = %port,
                                group = %group_name,
                                proxy_name = %np.proxy_name,
                                "TCP group port {port} bind raced a sibling group create with mismatched params for '{}' — rejecting",
                                np.proxy_name,
                            );
                            rollback_tcp_bind_failure(state, run_id, port, &np.proxy_name).await;
                            reject_new_proxy(writer, &np.proxy_name, err_text.to_string(), v2)
                                .await;
                            return Err(());
                        }
                        GroupPortQuery::NotFound => {}
                    }
                }
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
        let abort_handle = handle.abort_handle();
        // The group stores the member's DECLARED remote port separately
        // from the bound one: Go keeps `tg.port` (declared, 0 for
        // auto-assign) alongside `realPort`, and later members must declare
        // the SAME number — an explicit port can never join an auto-assign
        // group even if the values coincide.
        let declared_port = np.remote_port.unwrap_or(0) as u16;
        let create_result = state
            .tcp_group_ctl
            .create_group(
                &group_name,
                &group_key,
                port,
                declared_port,
                &bind_addr,
                handle,
                cancel_token,
            )
            .await;
        if let Err(e) = create_result {
            // A racing member created the group between the NotFound probe
            // and here. Go's `TCPGroupCtl.Listen` retries on `errGroupStale`
            // and then validates params; mirror that: abort the redundant
            // listener we just bound, roll back the create-path
            // registration, and re-query — Matched → join, else reject with
            // the Go error text (F5 review finding: the old code logged
            // warn-only and left the proxy registered on its own port,
            // splitting the group across two listeners).
            abort_handle.abort();
            rollback_tcp_bind_failure(state, run_id, port, &np.proxy_name).await;
            // Declared-vs-declared join probe (Go tcp.go: an explicit port
            // cannot join an auto-assign group even if the numbers agree).
            let declared_port = np.remote_port.unwrap_or(0) as u16;
            match state
                .tcp_group_ctl
                .get_group_port(&group_name, &group_key, declared_port, &bind_addr)
                .await
            {
                GroupPortQuery::Matched(join_port) => {
                    tracing::warn!(
                        proxy_name = %np.proxy_name,
                        group = %group_name,
                        error = %e,
                        "TCP group '{}' created concurrently for '{}' — joining on port {}",
                        group_name, np.proxy_name, join_port,
                    );
                    state.used_ports.write().await.insert(join_port);
                    handle_tcp_group_member_registration(
                        state,
                        run_id,
                        control_id,
                        writer,
                        np.clone(),
                        np.remote_port.unwrap_or(0) as u16,
                        &itx,
                        listener_handles,
                        udp_sockets,
                        v2,
                        Some(join_port),
                        tcp_group_created,
                    )
                    .await;
                }
                GroupPortQuery::Mismatch(err_text) => {
                    reject_new_proxy(writer, &np.proxy_name, err_text.to_string(), v2).await;
                }
                GroupPortQuery::NotFound => {
                    // Group vanished between create failure and re-query —
                    // reject; the client's next attempt re-creates it.
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        err_msg(
                            state.detailed_errors_to_client,
                            format!("TCP group registration failed: {e}"),
                            "TCP group registration failed",
                        ),
                        v2,
                    )
                    .await;
                }
            }
            return Err(());
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
        let listener = match bind_tcp_proxy_with_retry(
            state, np, run_id, control_id, &mut port, &bind_addr, writer, v2,
        )
        .await
        {
            Ok(l) => l,
            Err(()) => return Err(()),
        };
        let addr = format_socket_addr(&bind_addr, port);
        info!(addr = %addr, proxy_name = %np.proxy_name, "Proxy listener started on {} for '{}'", addr, np.proxy_name);
        let tcp_keepalive = state.tcp_keepalive;
        // Capture this proxy's user-conn semaphore for the accept loop
        // (M5 mirror). The registry entry was inserted by
        // register_proxy_entry before this spawn; a listener outliving its
        // proxy keeps a clone of the Arc, so caps stay enforced even as the
        // registry entry is removed.
        let user_conn_sem = state
            .proxy_manager
            .get(&pn)
            .await
            .and_then(|p| p.user_conn_sem.clone());
        let handle = tokio::spawn(async move {
            listen_and_proxy(listener, port, pn, itx, tcp_keepalive, user_conn_sem).await;
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
    Ok((udp_resp_signals, port))
}

/// Register a new proxy and start listening on its assigned port.
/// Returns `true` when the proxy was fully registered (listener up, success
/// response written), `false` when it was rejected at any stage — the caller
/// uses this to attach per-proxy side state only to successful
/// registrations (a rejected duplicate must not replace the live side state
/// of a running proxy).
#[allow(clippy::too_many_arguments)]
#[instrument(skip(state, writer, internal_tx, listener_handles, udp_sockets), fields(proxy_name = %np.proxy_name, proxy_type = %np.proxy_type, run_id = %run_id))]
pub(crate) async fn handle_new_proxy(
    mut np: msg::NewProxy,
    run_id: &str,
    control_id: u64,
    state: &Arc<AppState>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    internal_tx: &mpsc::Sender<InternalMsg>,
    listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    v2: bool,
) -> bool {
    // Server plugin: new_proxy hook — Go ordering (server/control.go
    // handleNewProxy): the plugin runs BEFORE validation and port
    // allocation, and a plugin's mutated content feeds registration.
    if !state.plugin_manager.is_empty() {
        // Go pkg/plugin/server/types.go NewProxyContent: the full flat
        // NewProxy msg plus a `user` object (loginUserInfo). Serializing
        // the struct guarantees every Go field is present with Go wire
        // names; `run_id` stays as a frp-rs extra (additive).
        let user_info = state.plugin_manager.user_info(run_id).unwrap_or_default();
        let mut np_content = match serde_json::to_value(&np) {
            Ok(v) => v,
            Err(e) => {
                warn!(proxy_name = %np.proxy_name, error = %e, "Server plugin new_proxy content serialize error for '{}': {}", np.proxy_name, e);
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    format!("server plugin new_proxy content error: {e}"),
                    v2,
                )
                .await;
                return false;
            }
        };
        if let Some(obj) = np_content.as_object_mut() {
            obj.insert(
                "user".into(),
                serde_json::to_value(&user_info).unwrap_or_default(),
            );
            obj.insert("run_id".into(), serde_json::json!(run_id));
        }
        match state.plugin_manager.notify("new_proxy", np_content).await {
            Err(reason) => {
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
                return false;
            }
            Ok(Some(mutated)) => {
                // Go handleMutableContent (manager.go:75-96): a plugin with
                // unchange:false replaces the typed NewProxy before
                // registration. Fail closed on invalid content.
                match crate::plugin::apply_plugin_mutation(&np, mutated) {
                    Ok(m) => np = m,
                    Err(e) => {
                        warn!(proxy_name = %np.proxy_name, error = %e, "NewProxy plugin returned invalid content for '{}': {}", np.proxy_name, e);
                        #[cfg(feature = "dashboard")]
                        {
                            let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                                message: format!(
                                    "Plugin 'new_proxy' invalid mutation for proxy '{}': {}",
                                    np.proxy_name, e
                                ),
                                context: Some("new_proxy".into()),
                            });
                        }
                        reject_new_proxy(writer, &np.proxy_name, e, v2).await;
                        return false;
                    }
                }
            }
            Ok(None) => {}
        }
    }

    // Go parity ordering: validation runs on the post-plugin message (Go's
    // RegisterProxy validates after the plugin hook), so a plugin can fix
    // an otherwise-invalid proxy exactly as in Go.
    if let Err(e) = validate_new_proxy(&np, &state.sub_domain_host) {
        reject_new_proxy(writer, &np.proxy_name, e, v2).await;
        return false;
    }
    let remote_port = np.remote_port.unwrap_or(0) as u16;

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
            return false;
        }
    }

    // Per-client proxy-count cap (Rust-only opt-in; Go frp has no such
    // limit). Bound how many proxies one authenticated client can hold —
    // each registration carries config + runtime info + routing entries,
    // so an unbounded count lets a client drive server memory growth.
    // Default 0 = unlimited. Same benign TOCTOU as the port gate: register
    // is the only writer of `by_client`, so a concurrent burst can overshoot
    // by a couple of entries at most.
    if state.max_proxies_per_client > 0 {
        let used = state.proxy_manager.client_proxy_count(run_id).await;
        if used + 1 > state.max_proxies_per_client as usize {
            reject_new_proxy(
                writer,
                &np.proxy_name,
                format!(
                    "maximum number of proxies ({}) reached for this client",
                    state.max_proxies_per_client
                ),
                v2,
            )
            .await;
            return false;
        }
    }

    // Per-proxy route-claiming domain cap (Rust-only opt-in; Go frp has no
    // such limit). One HTTP/HTTPS/tcpmux proxy with a huge
    // custom_domains/locations list would grow the shared vhost/tcpmux
    // routing tables (and per-request conflict-check cost) in a SINGLE
    // register call — the per-client proxy cap does not bound that, since it
    // is one proxy. Estimate = custom_domains + (subdomain ? 1 : 0) +
    // locations, an upper bound on the route entries this NewProxy adds.
    // Pairs with `max_proxies_per_client` to bound total routes.
    let max_route_domains = state.server_config_snapshot.max_custom_domains_per_proxy;
    if max_route_domains > 0 && matches!(np.proxy_type.as_str(), "http" | "https" | "tcpmux") {
        let estimate = np.custom_domains.as_ref().map(|d| d.len()).unwrap_or(0)
            + usize::from(np.subdomain.as_deref().filter(|s| !s.is_empty()).is_some())
            + np.locations.as_ref().map(|l| l.len()).unwrap_or(0);
        // `as i64` is safe: the estimate is bounded by the message's
        // serialized size — a single V1/V2 frame is capped at 10 KiB/256
        // KiB of JSON, so the count of list entries is far below i64::MAX
        // (round-18 review; the cap itself is clamped to 2^20 upstream).
        if estimate as i64 > max_route_domains {
            reject_new_proxy(
                writer,
                &np.proxy_name,
                format!(
                    "proxy '{}' declares {} route-claiming domain(s)/location(s), exceeding the configured maximum of {max_route_domains}",
                    np.proxy_name, estimate,
                ),
                v2,
            )
            .await;
            return false;
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
        // Go frp parity (server/group/tcp.go `TCPGroup.Listen`): the first
        // member creates the group; later members are validated — addr
        // (ErrGroupParamsInvalid), port (ErrGroupDifferentPort), group_key
        // (ErrGroupAuthFailed) — and REJECTED on mismatch with the Go error
        // text (F5 review finding: old code conflated mismatch with
        // missing-group and silently fell through to group-create, so a
        // mismatched member could end up registered on its own port).
        match state
            .tcp_group_ctl
            .get_group_port(group_name, group_key, remote_port, &state.proxy_bind_addr)
            .await
        {
            GroupPortQuery::Matched(group_port) => {
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
                // TCP group member path: the callee completed its own
                // registration (or rejection) — never udp/sudp.
                return true;
            }
            GroupPortQuery::NotFound => {
                // No existing group — will create one with a new shared listener.
                tcp_group_created = true;
            }
            GroupPortQuery::Mismatch(err_text) => {
                reject_new_proxy(writer, &np.proxy_name, err_text.to_string(), v2).await;
                return false;
            }
        }
    }

    // Separate port managers for TCP and UDP (Go frp compat).
    // TCP port 8080 can coexist with UDP port 8080.
    let is_udp_type = np.proxy_type == "udp" || np.proxy_type == "sudp";
    let allocated_port =
        allocate_proxy_port(state, &np, consumes_port, is_udp_type, is_sudp, remote_port).await;

    match allocated_port {
        Ok(mut port) => {
            // Registration via the shared helper: the TCP auto-assign bind
            // retry (`bind_tcp_proxy_with_retry`) re-enters it on a fresh
            // port when the first bind lost the auto-assigned port to
            // another process, so the ProxyInfo remote_port, used_ports
            // mark and per-client count all move together.
            if let Err(e) =
                register_proxy_entry(state, &np, run_id, control_id, port, is_udp_type).await
            {
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
                return false;
            }

            #[cfg(feature = "vnet")]
            if np.proxy_type == "vnet" {
                if let Some(ref subnet) = np.advertise_subnet {
                    if !subnet.is_empty() {
                        let vn = np.virtual_net.clone().unwrap_or_default();
                        // Guard the route insert exactly like the
                        // VnetRouteAdvertise path (audit finding 5): the
                        // old insert was unconditional — no hijack-prefix
                        // rejection, no per-client cap, no liveness-gated
                        // owner-conflict refusal — and silently overwrote
                        // a live owner's (virtual_net, subnet) route,
                        // redirecting the displaced proxy's visitor
                        // packets here (VnetRoutes::visitor_route_target).
                        // The registering proxy itself IS the membership
                        // (proxy_type == "vnet" in `vn`), so no
                        // membership check applies on this path.
                        let mut rejection: Option<String> = None;
                        {
                            let mut routes = state.vnet_routes.write().await;
                            let key = (vn.clone(), subnet.clone());
                            if super::nathole::is_route_hijack_prefix(subnet) {
                                // Defense-in-depth (hijack-prefix MED):
                                // reject default / near-default prefixes
                                // before they reach peers' kernel routing
                                // tables. A vnet proxy whose advertise
                                // subnet would inject a default-route
                                // equivalent must not register at all.
                                rejection = Some(format!(
                                    "vnet proxy '{}' rejected: advertise subnet '{subnet}' is a hijack prefix (default /0 or its /1 split)",
                                    np.proxy_name
                                ));
                            } else {
                                // Route-count cap (round 10 HIGH): reject
                                // new keys once this run_id owns the cap.
                                // Re-registering an already-owned key stays
                                // allowed (normal update — reload keeps the
                                // run_id). Mirror the advertise path.
                                if !routes.contains_key(&key) {
                                    // O(1) precomputed count (index on
                                    // `VnetRoutes`), not a table scan.
                                    let owned = routes.run_route_count(run_id);
                                    if owned >= super::nathole::MAX_VNET_ROUTES_PER_CLIENT {
                                        rejection = Some(format!(
                                            "vnet proxy '{}' rejected: per-client route cap ({}) reached",
                                            np.proxy_name,
                                            super::nathole::MAX_VNET_ROUTES_PER_CLIENT
                                        ));
                                    }
                                }
                                if rejection.is_none() {
                                    if let Some((owner_run_id, owner_proxy)) = routes.get(&key) {
                                        if owner_run_id != run_id {
                                            // Liveness check mirrors the
                                            // advertise path: a route is
                                            // only "owned" while its
                                            // owner's control connection is
                                            // alive. A dead owner (crashed
                                            // client that restarted with a
                                            // fresh run_id) must not block
                                            // reclaiming its stale route.
                                            let owner_alive = state
                                                .run_id_to_ctl_tx
                                                .contains_key(owner_run_id.as_str());
                                            if owner_alive {
                                                rejection = Some(format!(
                                                    "vnet proxy '{}' rejected: subnet '{subnet}' in virtual_net '{vn}' already owned by live run_id {owner_run_id} (proxy '{owner_proxy}')",
                                                    np.proxy_name
                                                ));
                                            } else {
                                                warn!(
                                                    proxy_name = %np.proxy_name,
                                                    virtual_net = %vn,
                                                    subnet = %subnet,
                                                    owner_run_id = %owner_run_id,
                                                    owner_proxy = %owner_proxy,
                                                    "vnet proxy route: taking over subnet from dead run_id"
                                                );
                                            }
                                        }
                                    }
                                }
                                if rejection.is_none() {
                                    routes.insert(key, (run_id.to_string(), np.proxy_name.clone()));
                                }
                            }
                        }
                        if let Some(rejection) = rejection {
                            // Roll back the proxy registration done above
                            // (mirror the vhost/tcpmux conflict rejections).
                            // vnet proxies never consume a port, so the
                            // port rollback is a no-op.
                            rollback_vhost_conflict(state, run_id, port, false).await;
                            state.proxy_manager.remove(&np.proxy_name).await;
                            reject_new_proxy(
                                writer,
                                &np.proxy_name,
                                err_msg(
                                    state.detailed_errors_to_client,
                                    rejection,
                                    "vnet route config conflict",
                                ),
                                v2,
                            )
                            .await;
                            return false;
                        }
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
                return false;
            }

            // Register HTTPS proxies with VhostManager for SNI routing.
            // Routes by domain only (no path/location) — SNI hostname
            // from the TLS ClientHello determines the route.
            if np.proxy_type == "https"
                && !register_https_vhost(state, &np, run_id, port, writer, v2).await
            {
                return false;
            }

            // Register TCPMux proxies with TcpMuxManager (domain-based CONNECT routing).
            // Follows the same pattern as VHost HTTP registration: a route
            // conflict rejects the proxy instead of silently overwriting the
            // live sibling's route (audit finding 5).
            if np.proxy_type == "tcpmux" {
                // Go frp v0.71.0 parity (server/proxy/tcpmux.go `Run()`):
                // only the httpconnect multiplexer is valid — anything else
                // rejects with `unknown multiplexer [%s]`. frp-rs accepts ""
                // as a lenient default (documented divergence: Go rejects
                // "", but existing frp-rs configs omit the field and the
                // client only ever sends httpconnect).
                let multiplexer = np.multiplexer.as_deref().unwrap_or("");
                if !multiplexer.is_empty() && multiplexer != "httpconnect" {
                    rollback_vhost_conflict(state, run_id, port, false).await;
                    state.proxy_manager.remove(&np.proxy_name).await;
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        format!("unknown multiplexer [{}]", multiplexer),
                        v2,
                    )
                    .await;
                    return false;
                }
                let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

                // Subdomain routing: {subdomain}.{sub_domain_host} — Go
                // frp v0.71.0 TCPMuxProxy::httpConnectRun routes
                // buildDomains(CustomDomains, SubDomain), so a
                // subdomain-only tcpmux proxy is valid (frpc sends
                // subdomain for tcpmux). Go's
                // validateDomainConfigForServer REJECTS a subdomain when
                // SubDomainHost is unset — the HTTP/HTTPS paths mirror
                // this accept/reject decision (C1).
                if let Some(ref subdomain) = np.subdomain {
                    if !subdomain.is_empty() {
                        let sub_host = &state.sub_domain_host;
                        if sub_host.is_empty() {
                            rollback_vhost_conflict(state, run_id, port, false).await;
                            reject_new_proxy(
                                writer,
                                &np.proxy_name,
                                "subdomain is not supported because this feature is not enabled in server".into(),
                                v2,
                            )
                            .await;
                            state.proxy_manager.remove(&np.proxy_name).await;
                            return false;
                        }
                        let full_domain = format!("{}.{}", subdomain, sub_host);
                        info!(full_domain = %full_domain, proxy_name = %np.proxy_name, "Subdomain route: {} → {}", full_domain, np.proxy_name);
                        // No dedup (Go buildDomains parity): a subdomain
                        // expansion colliding with a custom_domains entry is
                        // a duplicate domain — rejected below by the
                        // duplicate-domain gate (Go: the second Muxer.Listen
                        // → Routers.Add hits exist() and rejects).
                        domains.push(full_domain);
                    }
                }

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
                    return false;
                }
                // Go buildDomains parity (server/proxy/proxy.go:218-229):
                // empty custom_domains entries are SKIPPED (`if d != ""`),
                // so custom_domains=["",""] yields zero domains and the
                // proxy is ACCEPTED (Muxer.Listen never runs, listens
                // nothing). Filter before the duplicate gate so ["",""]
                // can't trip it; the register below with an empty list is a
                // no-op. The len(customDomains)==0 gate above stays on the
                // raw list (Go checks it before buildDomains).
                let domains: Vec<String> = domains.into_iter().filter(|d| !d.is_empty()).collect();
                // Go frp v0.71.0 parity (tcpmux.go httpConnectRun →
                // httpConnectListen → Muxer.Listen → Routers.Add): buildDomains
                // does no dedup, so a duplicate domain within one proxy's own
                // list (duplicate custom_domains entry, subdomain expansion
                // colliding with a custom_domains entry, or a case-only
                // variant — Add lowercases before exist()) repeats the
                // (domain, "", routeByHTTPUser) triple and the second Add
                // REJECTS the whole registration. The tcpmux manager's
                // per-(domain, routeByHTTPUser) HashMap insert is idempotent
                // for same-proxy re-registration, so the reject happens here.
                if let Some(dup) = duplicate_domain(&domains) {
                    rollback_vhost_conflict(state, run_id, port, false).await;
                    state.proxy_manager.remove(&np.proxy_name).await;
                    reject_new_proxy(
                        writer,
                        &np.proxy_name,
                        err_msg(
                            state.detailed_errors_to_client,
                            format!(
                                "tcpmux proxy custom_domains contains duplicate domain '{}'",
                                dup
                            ),
                            "tcpmux route config conflict",
                        ),
                        v2,
                    )
                    .await;
                    return false;
                }
                let http_user = np.http_user.as_deref().unwrap_or("");
                let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                let headers: Vec<(String, String)> =
                    np.headers.clone().unwrap_or_default().into_iter().collect();

                // TCPMux load-balancing group (Go frp v0.71.0
                // group.TCPMuxGroupController + server/proxy/tcpmux.go
                // httpConnectListen): when LoadBalancer.Group is set the
                // Listen goes through the group controller — the FIRST
                // member creates the group and registers the shared muxer
                // route; later members are validated against it (params
                // equal → "group params invalid" ErrGroupParamsInvalid,
                // group_key equal → "group auth failed" ErrGroupAuthFailed,
                // both verbatim, Go check order) and join the fan-out.
                // M2 audit fix: second members were previously rejected as
                // plain route conflicts, silently disabling the documented
                // multi-client load-balanced tcpmux feature.
                //
                // Go's TCPMuxGroup stores ONE (domain, rubu, user, pwd) per
                // group name — a same-group proxy whose second domain
                // differs from the first member's is rejected with
                // ErrGroupParamsInvalid. Mirrored up front like the HTTP
                // group path ("http group proxies must configure exactly
                // one custom_domain and one location"), instead of failing
                // mid-registration.
                let group_name = np.group.as_deref().unwrap_or("");
                if !group_name.is_empty() {
                    if domains.len() != 1 {
                        rollback_vhost_conflict(state, run_id, port, false).await;
                        state.proxy_manager.remove(&np.proxy_name).await;
                        reject_new_proxy(
                            writer,
                            &np.proxy_name,
                            err_msg(
                                state.detailed_errors_to_client,
                                "tcpmux group proxies must configure exactly one custom_domain (Go frp TCPMuxGroup semantics)".into(),
                                "tcpmux group params invalid",
                            ),
                            v2,
                        )
                        .await;
                        return false;
                    }
                    let domain = &domains[0];
                    match state
                        .tcpmux_group_ctl
                        .register_member(
                            group_name,
                            np.group_key.as_deref().unwrap_or(""),
                            domain,
                            np.route_by_http_user.as_deref().unwrap_or(""),
                            http_user,
                            http_pwd,
                            &np.proxy_name,
                        )
                        .await
                    {
                        Ok((_group, is_first)) => {
                            // Only the first member registers the shared
                            // tcpmux route (tagged with the group name);
                            // later members just joined the member list.
                            if is_first {
                                if let Err(conflict) = state
                                    .tcpmux_manager
                                    .register(
                                        &np.proxy_name,
                                        &domains,
                                        run_id,
                                        http_user,
                                        http_pwd,
                                        // Round 6 (A2): route_by_http_user is
                                        // the second tcpmux routing dimension
                                        // (Go RouteConfig) — CONNECT lookups
                                        // match the request user's bucket
                                        // first.
                                        np.route_by_http_user.as_deref().unwrap_or(""),
                                        &headers,
                                        group_name,
                                    )
                                    .await
                                {
                                    state
                                        .tcpmux_group_ctl
                                        .unregister_member(group_name, &np.proxy_name)
                                        .await;
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
                                    return false;
                                }
                            }
                        }
                        Err(e) => {
                            // e is the verbatim Go rejection ("group params
                            // invalid" / "group auth failed").
                            rollback_vhost_conflict(state, run_id, port, false).await;
                            state.proxy_manager.remove(&np.proxy_name).await;
                            reject_new_proxy(
                                writer,
                                &np.proxy_name,
                                err_msg(
                                    state.detailed_errors_to_client,
                                    e,
                                    "tcpmux group registration failed",
                                ),
                                v2,
                            )
                            .await;
                            return false;
                        }
                    }
                    info!(
                        proxy_name = %np.proxy_name, group = %group_name, domain = %domain,
                        rubu = %np.route_by_http_user.as_deref().unwrap_or(""),
                        "TCPMux proxy '{}' registered in group '{}' (route {})",
                        np.proxy_name, group_name, domain
                    );
                } else if let Err(conflict) = state
                    .tcpmux_manager
                    .register(
                        &np.proxy_name,
                        &domains,
                        run_id,
                        http_user,
                        http_pwd,
                        // Round 6 (A2): route_by_http_user is the second
                        // tcpmux routing dimension (Go RouteConfig) — CONNECT
                        // lookups match the request user's bucket first.
                        np.route_by_http_user.as_deref().unwrap_or(""),
                        &headers,
                        "",
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
                    return false;
                }
                if group_name.is_empty() {
                    info!(
                        proxy_name = %np.proxy_name, domains = ?domains, "TCPMux routes registered for '{}': domains={:?}",
                        np.proxy_name, domains
                    );
                }
            }

            let mut udp_resp_signals = match setup_proxy_listeners(
                state,
                &np,
                run_id,
                control_id,
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
                // The TCP auto-assign bind retry may have moved the proxy
                // to a fresh port — everything below (log, dashboard event,
                // NewProxyResp remote_addr) must use the final port.
                Ok((signals, final_port)) => {
                    port = final_port;
                    signals
                }
                Err(()) => return false,
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

            // remote_addr is ":port" (Go frp parity — Go's NewProxyResp
            // uses fmt.Sprintf(":%d", ...) and the client treats it as an
            // opaque string; the TCP group path below already sends this
            // form). No Rust-side consumer parses the host prefix — the
            // frpc stores it opaquely for status display, and tests parse
            // the port with rsplit(':').
            let remote_addr_str = format!(":{}", port);
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
            // Success — all failure paths above returned false.
            return true;
        }
        Err(pe) => {
            // P8: the rejection carries the Go-mapped reason (ports.go:22-27)
            // instead of collapsing every failure into "no available port".
            warn!(proxy_name = %np.proxy_name, reason = %pe.client_text(), "Port allocation failed for proxy '{}': {}", np.proxy_name, pe.client_text());
            reject_new_proxy(writer, &np.proxy_name, pe.client_text(), v2).await;
            return false;
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

/// Total bind attempts for a TCP proxy with an AUTO-ASSIGNED remote port
/// (remote_port == 0) before the retry gives up: 1 initial + 7 re-allocations.
/// The cross-instance port-steal race is rare; 8 fresh ports is far beyond
/// any realistic collision window, and each attempt carries a bounded cost
/// (`bind_proxy_listener` retries 3×100ms on EADDRINUSE).
const TCP_AUTO_BIND_MAX_ATTEMPTS: u32 = 8;

/// Bind the per-proxy TCP listener for `np` at `*port`, retrying with a
/// freshly allocated port when the bind fails with EADDRINUSE on an
/// AUTO-ASSIGNED port (remote_port == 0). On success `*port` holds the
/// final (possibly re-allocated) port.
///
/// Why this exists: three-phase TCP allocation probes the OS OUTSIDE
/// `used_ports`, so a second frps instance (or any other process) can bind
/// the same candidate in the window between the probe and our own bind —
/// the bind then fails with EADDRINUSE even though the port was
/// "allocated". Two parallel frps instances on one host collide this way
/// on every proxy they auto-assign. The retry rolls the failed
/// registration back (`rollback_tcp_bind_failure`), clears the 24h
/// reservation keyed by the proxy name (it would hand back the SAME stolen
/// port on re-allocation), re-runs `allocate_proxy_port` with
/// remote_port == 0, and re-registers via `register_proxy_entry` so the
/// ProxyInfo `remote_port`, `used_ports` mark and per-client count all
/// move to the fresh port together.
///
/// Explicit ports (remote_port > 0) keep the immediate reject-on-AddrInUse
/// behavior (Go parity: Go's port manager is per-process and never faces
/// this cross-instance race, and a requested-port conflict is a client
/// config error — Go rejects it at registration). On exhaustion or a
/// non-retryable error the failed registration is rolled back and the
/// rejection response written; the caller aborts (`Err(())`).
#[allow(clippy::too_many_arguments)]
async fn bind_tcp_proxy_with_retry(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    control_id: u64,
    port: &mut u16,
    bind_addr: &str,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
) -> Result<TcpListener, ()> {
    let auto_assign = np.remote_port.unwrap_or(0) == 0;
    let mut attempts: u32 = 0;
    loop {
        match bind_proxy_listener(bind_addr, *port, &np.proxy_name).await {
            Ok(l) => return Ok(l),
            Err(e) => {
                let retryable = auto_assign
                    && e.kind() == std::io::ErrorKind::AddrInUse
                    && attempts + 1 < TCP_AUTO_BIND_MAX_ATTEMPTS;
                if !retryable {
                    // Plain reject path (explicit-port conflicts, and
                    // auto-assign exhaustion): roll the registration back
                    // (port mark, per-client count, registry entry) and
                    // reject — unchanged behavior.
                    tracing::error!(port = %*port, error = %e, "Failed to bind proxy port {}: {}", *port, e);
                    rollback_tcp_bind_failure(state, run_id, *port, &np.proxy_name).await;
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
                attempts += 1;
                // The port was stolen between the allocation probe and this
                // bind (cross-instance collision). Roll the failed
                // registration back, clear the 24h reservation (it would
                // otherwise hand back the SAME stolen port), re-allocate,
                // and re-register on the fresh port.
                tracing::warn!(
                    port = %*port,
                    proxy_name = %np.proxy_name,
                    attempt = attempts,
                    error = %e,
                    "Auto-assigned proxy port {} for '{}' was stolen between allocation and bind — re-allocating (attempt {}/{})",
                    *port, np.proxy_name, attempts, TCP_AUTO_BIND_MAX_ATTEMPTS,
                );
                rollback_tcp_bind_failure(state, run_id, *port, &np.proxy_name).await;
                state.port_reservations.write().await.remove(&np.proxy_name);
                // P8: this re-allocation is always auto-assign, so the
                // Go-mapped reason is NoAvailable in practice — but the
                // reject text comes from the error, not a hardcoded string.
                let p = match allocate_proxy_port(state, np, true, false, false, 0).await {
                    Ok(p) => p,
                    Err(pe) => {
                        tracing::warn!(
                            proxy_name = %np.proxy_name,
                            reason = %pe.client_text(),
                            "No available port for proxy '{}' after auto-assign bind retry: {}",
                            np.proxy_name,
                            pe.client_text(),
                        );
                        reject_new_proxy(writer, &np.proxy_name, pe.client_text(), v2).await;
                        return Err(());
                    }
                };
                if let Err(e) = register_proxy_entry(state, np, run_id, control_id, p, false).await
                {
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
                    return Err(());
                }
                *port = p;
            }
        }
    }
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
    user_conn_sem: Option<Arc<tokio::sync::Semaphore>>,
) {
    loop {
        match listener.accept().await {
            Ok((user_conn, _addr)) => {
                frp_core::transport::set_nodelay(&user_conn);
                if tcp_keepalive > 0 {
                    frp_core::transport::set_keepalive(&user_conn, tcp_keepalive as u64);
                }
                // Acquire the proxy's user-conn permit BEFORE the send (M5
                // mirror of the group path). Without this, a flood of user
                // conns to an at-cap proxy queues raw sockets (each holding
                // an fd) in the 1024-slot internal channel ahead of the
                // handler-side permit check — starving the control's other
                // internal traffic. The permit crosses the message boundary
                // and the handler consumes it instead of re-acquiring (no
                // double-count). No semaphore = unlimited — send with None.
                let user_conn_permit = match &user_conn_sem {
                    Some(sem) => match sem.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            debug!(
                                proxy_name = %proxy_name,
                                "Proxy '{}' at user-conn cap, dropping connection",
                                proxy_name,
                            );
                            continue;
                        }
                    },
                    None => None,
                };
                // send().await: backpressure is correct — the control channel
                // (cap 1024) can fill under a burst of user connections; Go frp
                // blocks here and lets the TCP backlog absorb the burst. This
                // accept loop is single-task, so stalling it only pauses this
                // proxy's accepts. Bounded (same pattern as dispatch.rs
                // visitor/NewWorkConn sends): a control handler that stops
                // draining must not pin this task + fd forever — after
                // CTL_SEND_TIMEOUT the user conn drops (the kernel backlog
                // absorbs the burst; the peer retries). A closed channel
                // means the control handler is gone — stop the listener.
                match tokio::time::timeout(
                    crate::state::CTL_SEND_TIMEOUT,
                    internal_tx.send(InternalMsg::ProxyUserConn {
                        proxy_name: proxy_name.clone(),
                        user_conn: IoStream::Tcp(user_conn),
                        pre_read: vec![],
                        user_conn_permit,
                        // Local sender — no group selection was done.
                        group_selected: false,
                        // Raw TCP listener — never an HTTP request.
                        request_is_connect: false,
                    }),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        warn!(proxy_name = %proxy_name, "Control handler gone, stopping proxy listener for '{}'", proxy_name);
                        break;
                    }
                    Err(_elapsed) => {
                        warn!(proxy_name = %proxy_name, "User-conn dispatch for proxy '{}' timed out; dropping connection", proxy_name);
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

#[cfg(test)]
pub(crate) mod unregister_generation_tests;

#[cfg(test)]
#[path = "validate/subdomain_conflict_tests.rs"]
mod subdomain_conflict_tests;

#[cfg(test)]
mod tcp_auto_bind_retry_tests;
