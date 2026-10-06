//! TCP group shared listener and member registration.
//!
//! Split out of `proxy_ops/mod.rs`. The parent re-imports both helpers
//! privately, so `proxy_ops::tcp_group_listener` /
//! `proxy_ops::handle_tcp_group_member_registration` keep their paths and
//! private visibility for every existing caller. The only callers are inside
//! `mod.rs` — `setup_proxy_listeners` (base lines 1072, 1137, 1186) and
//! `handle_new_proxy` (base line 1505).

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, instrument};

use frp_core::msg::{self, FrpMessage};

use crate::service::{AppState, InternalMsg};

use super::{build_proxy_info, err_msg, free_replaced_port, reject_new_proxy, write_resp};

/// Shared TCP group listener: accepts connections on the group's shared port
/// and dispatches them to group members via round-robin (`select_group_backend`).
/// Stops when the group has no members or the cancel token is triggered.
/// The listener is bound synchronously by the caller (audit finding 4), so a
/// bind failure rejects the first group member instead of leaving a
/// registered-but-dead group.
#[instrument(skip(listener, state, cancel_token), fields(group = %group_name, port = %port))]
pub(super) async fn tcp_group_listener(
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
                            // Audit M5 mirror: acquire the backend's
                            // user-conn permit BEFORE the send. Without
                            // this, a flood of group conns to an at-cap/slow
                            // backend queues raw sockets (each holding an
                            // fd) in the shared 1024-slot internal channel
                            // ahead of the backend's own permit check —
                            // starving that control's other internal
                            // traffic. The permit crosses the message
                            // boundary and the backend handler consumes it
                            // instead of re-acquiring (no double-count). A
                            // backend without a semaphore is unlimited —
                            // send with None. At-cap → drop the conn here
                            // (the permit never existed; nothing to leak).
                            let forwarded_permit = match state
                                .proxy_manager
                                .get(&backend)
                                .await
                            {
                                Some(p) => match p.user_conn_sem.clone() {
                                    Some(sem) => match sem.try_acquire_owned() {
                                        Ok(permit) => Some(permit),
                                        Err(_) => {
                                            debug!(
                                                group = %group_name,
                                                proxy_name = %backend,
                                                "Group backend '{}' at user-conn cap, dropping connection from group '{}'",
                                                backend, group_name,
                                            );
                                            continue;
                                        }
                                    },
                                    None => None,
                                },
                                // Backend vanished mid-forward — carry no
                                // permit; the send will surface the closed
                                // channel.
                                None => None,
                            };
                            let ctl_tx = state
                                .run_id_to_ctl_tx
                                .get(&backend_run_id)
                                .map(|c| c.tx.clone());
                            if let Some(tx) = ctl_tx {
                                // send().await: same backpressure rationale as
                                // listen_and_proxy — the group accept loop
                                // stalls until the backend control handler
                                // drains, letting the kernel backlog absorb
                                // bursts. Bounded (same pattern as dispatch.rs
                                // visitor/NewWorkConn sends): a backend
                                // control that stops draining must not pin
                                // this task + fd forever — after
                                // CTL_SEND_TIMEOUT the conn (and its
                                // forwarded permit) drops, returning the
                                // permit to the semaphore — nothing leaks. A
                                // closed channel means the backend control is
                                // gone; the message (with its permit) is
                                // dropped the same way.
                                match tokio::time::timeout(
                                    crate::state::CTL_SEND_TIMEOUT,
                                    tx.send(InternalMsg::ProxyUserConn {
                                        proxy_name: backend,
                                        user_conn: frp_core::transport::IoStream::Tcp(conn),
                                        pre_read: vec![],
                                        user_conn_permit: forwarded_permit,
                                        // Backend already selected here —
                                        // the receiving handler must route
                                        // directly, not re-run group
                                        // selection (would bounce the conn
                                        // between members forever).
                                        group_selected: true,
                                        // Raw TCP group member — never an
                                        // HTTP request.
                                        request_is_connect: false,
                                    }),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => {
                                        debug!(
                                            group = %group_name,
                                            error = %e,
                                            "Failed to dispatch connection from group '{}': {}",
                                            group_name, e,
                                        );
                                    }
                                    Err(_elapsed) => {
                                        debug!(
                                            group = %group_name,
                                            "Failed to dispatch connection from group '{}': backend control send timed out",
                                            group_name,
                                        );
                                    }
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
pub(super) async fn handle_tcp_group_member_registration(
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

    // Supersession takeover: a same-name re-registration by a newer control
    // generation of the same run_id replaces the old entry; the old port
    // mark and per-client count are freed here exactly once — the old
    // control's sweep skips the name and would never release them
    // (audit-fix: residual port-mark leak on barrier-timeout supersession).
    let replaced = match state
        .proxy_manager
        .register_or_replace(run_id.to_string(), info.clone())
        .await
    {
        Ok(r) => r,
        Err(e) => {
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
    };
    if let Some(old) = replaced {
        if old.remote_port.is_some_and(|p| p > 0) {
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
