use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{info, instrument, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg;

use crate::lock::RwLockExt;
use crate::proxy::ProxyInfo;
use crate::service::{AppState, InternalMsg};
use crate::state::GroupPortQuery;

mod validate;
use validate::validate_new_proxy;

mod vhost;
use vhost::{register_http_vhost, register_https_vhost};

mod tcpmux;
use tcpmux::register_tcpmux_proxy;

mod tcp_group;
use tcp_group::handle_tcp_group_member_registration;

mod registry;
pub(crate) use registry::remove_proxy_and_release_client_counts;
use registry::{build_proxy_info, register_proxy_entry, rollback_vhost_conflict};

mod ports;
#[cfg(test)]
use ports::prune_expired_reservations_inner;
pub(crate) use ports::release_udp_port_with_owner_check;
use ports::{
    allocate_proxy_port, free_replaced_port, proxy_consumes_client_port, udp_port_has_other_owner,
};

mod listener;
#[cfg(test)]
use listener::listen_and_proxy;
use listener::setup_proxy_listeners;

mod teardown;
pub(crate) use teardown::unregister_control;

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
            if np.proxy_type == "tcpmux"
                && !register_tcpmux_proxy(state, &np, run_id, port, writer, v2).await
            {
                return false;
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

#[cfg(test)]
pub(crate) mod unregister_generation_tests;

#[cfg(test)]
#[path = "validate/subdomain_conflict_tests.rs"]
mod subdomain_conflict_tests;

#[cfg(test)]
mod tcp_auto_bind_retry_tests;
