//! Per-proxy listener setup and the accept loop.
//!
//! `setup_proxy_listeners` chooses the listener shape for a newly registered
//! proxy (UDP/SuDP socket, TCP-group shared listener, or per-proxy TCP
//! listener), and `listen_and_proxy` runs the per-proxy accept loop. Split out
//! of `proxy_ops/mod.rs` as a pure text move; the parent imports
//! `setup_proxy_listeners`, and the `#[cfg(test)]` sibling suite imports
//! `listen_and_proxy`.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, instrument, warn};

use frp_core::format_socket_addr;
use frp_core::msg;
use frp_core::transport::IoStream;

use crate::service::{AppState, InternalMsg};
use crate::state::GroupPortQuery;

use super::ports::allocate_proxy_port;
use super::registry::{register_proxy_entry, rollback_tcp_bind_failure, rollback_udp_bind_failure};
use super::tcp_group::{handle_tcp_group_member_registration, tcp_group_listener};
use super::{err_msg, reject_new_proxy};

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
pub(super) async fn setup_proxy_listeners(
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
