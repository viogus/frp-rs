//! Port allocation, reservation release and the periodic reservation pruner.
//!
//! Split out of `proxy_ops/mod.rs` as a pure text move; the parent re-imports
//! the items its own code and its child modules still resolve through
//! `proxy_ops::`/`super::`, so no path or visibility changes.

use std::sync::Arc;

use frp_core::msg;
use tracing::{debug, info};

use crate::service::AppState;

use super::{is_udp_port_bindable, ProxyInfo, RwLockExt};

/// First candidate whose OS-level bind probe succeeds, each probed off the
/// executor via `spawn_blocking` (audit r3/server#1 — the sync bind must not
/// run on a worker thread during a registration burst).
async fn first_bindable(bind_addr: &str, candidates: impl IntoIterator<Item = u16>) -> Option<u16> {
    for p in candidates {
        if crate::proxy::is_tcp_port_bindable_async(bind_addr, p).await {
            return Some(p);
        }
    }
    None
}

/// Why a proxy port could not be allocated, mirroring Go frp v0.71.0's four
/// distinct errors — server/ports/ports.go:22-27:
///
/// ```go
/// var (
///     ErrPortAlreadyUsed = errors.New("port already used")
///     ErrPortNotAllowed  = errors.New("port not allowed")
///     ErrPortUnAvailable = errors.New("port unavailable")
///     ErrNoAvailablePort = errors.New("no available port")
/// )
/// ```
///
/// Go's `Manager.Acquire` (ports.go:110-144) maps every failure branch to
/// exactly one of these, and the text travels verbatim to the client's
/// NewProxyResp error. Rust used to collapse the distinct failures into a
/// single "no available port" (P8): an explicit port inside the allow
/// ranges that fails the OS bind probe → [`PortError::UnAvailable`]
/// (ports.go:130-136 — in `freePorts` but `isPortAvailable` failed); an
/// explicit port outside the ranges → [`PortError::AlreadyUsed`] when
/// `usedPorts` already holds it, else [`PortError::NotAllowed`]
/// (ports.go:137-142); random auto-assign exhaustion →
/// [`PortError::NoAvailable`] (ports.go:125-127).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortError {
    /// Explicit port already marked used by another live proxy (Go
    /// `usedPorts` hit).
    AlreadyUsed,
    /// Explicit port outside every configured allow_ports range.
    NotAllowed,
    /// Port passed the allow checks but the OS-level bind probe failed
    /// (bound by another process / privileged port / OS family restriction).
    UnAvailable,
    /// Auto-assign (remote_port == 0) exhausted every candidate.
    NoAvailable,
}

impl PortError {
    /// Go frp v0.71.0 client-visible rejection text —
    /// server/ports/ports.go:23-26, verbatim.
    pub(crate) fn client_text(&self) -> String {
        match self {
            PortError::AlreadyUsed => "port already used",
            PortError::NotAllowed => "port not allowed",
            PortError::UnAvailable => "port unavailable",
            PortError::NoAvailable => "no available port",
        }
        .to_string()
    }
}

/// Allocate the remote port for a new proxy (Go frp `ports.Manager` compat):
/// SUDP override, per-client reservations with 24h expiry, allow-ports range
/// scans, and OS-level bind probes. Extracted from `handle_new_proxy`'s
/// state machine — no `.await`-free parts remain in the parent.
///
/// Returns [`PortError`] with the Go-mapped failure reason (see its doc for
/// the branch mapping).
#[inline(never)]
pub(super) async fn allocate_proxy_port(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    consumes_port: bool,
    is_udp_type: bool,
    is_sudp: bool,
    mut remote_port: u16,
) -> Result<u16, PortError> {
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
        Ok(remote_port)
    } else if is_udp_type {
        // UDP/SuDP port allocation: no TCP bind probe (UdpSocket::bind handles
        // OS-level validation later). Use dedicated used_udp_ports tracking
        // separate from TCP used_ports (Go frp compat).
        let mut ports = state.used_udp_ports.write().await;
        if remote_port > 0 {
            if ports.contains(&remote_port) {
                // Port already used by another UDP proxy. SUDP allows sharing,
                // pure UDP does not — Go ErrPortAlreadyUsed for the pure case
                // (the `usedPorts` hit at ports.go:138-140).
                if is_sudp {
                    Ok(remote_port)
                } else {
                    Err(PortError::AlreadyUsed)
                }
            } else if !is_udp_port_bindable(&state.proxy_bind_addr, remote_port) {
                // OS-level UDP bind probe failed (Go frp compat:
                // Manager.isPortAvailable does net.ListenUDP for UDP
                // netType) — an in-range explicit port that cannot bind is
                // Go ErrPortUnAvailable (ports.go:130-136), NOT exhaustion.
                Err(PortError::UnAvailable)
            } else {
                ports.insert(remote_port);
                Ok(remote_port)
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
            found.ok_or(PortError::NoAvailable)
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
            // bind probe must not serialize reservation lookups (audit D3-6).
            // Probe runs off the executor (audit r3/server#1).
            let res_candidate = match res_candidate {
                Some(p) => {
                    if !crate::proxy::is_tcp_port_bindable_async(&state.proxy_bind_addr, p).await {
                        None
                    } else {
                        Some(p)
                    }
                }
                other => other,
            };
            match res_candidate {
                Some(p) => Some(p),
                None => {
                    // Collect candidates under a brief read lock, then probe
                    // each one OUTSIDE the lock (the bind probe must not
                    // serialize registrations). Continues past occupied
                    // ports, matching the old in-lock scan.
                    let candidates = {
                        let used = state.used_ports.read().await;
                        crate::proxy::pick_tcp_port_candidates(&used, 0, &allow_ports, 4096)
                    };
                    first_bindable(&state.proxy_bind_addr, candidates).await
                }
            }
        } else {
            // P8: classify an explicit port's failure BEFORE probing. The
            // candidate picker collapses "already used" and "outside the
            // allow ranges" into one empty vec, and an in-range probe
            // failure looked identical to auto-assign exhaustion — every
            // reject then read "no available port". Go distinguishes them
            // (ports.go:137-142): a used explicit port → ErrPortAlreadyUsed;
            // a port outside every allow range → ErrPortNotAllowed.
            let (used, allowed) = {
                let used_ports = state.used_ports.read().await;
                let allowed =
                    allow_ports.is_empty() || allow_ports.iter().any(|r| r.contains(remote_port));
                (used_ports.contains(&remote_port), allowed)
            };
            if used {
                return Err(PortError::AlreadyUsed);
            }
            if !allowed {
                return Err(PortError::NotAllowed);
            }
            // In-range, unmarked: the single candidate's OS probe decides
            // between success and Go ErrPortUnAvailable (ports.go:130-136 —
            // in `freePorts` but `isPortAvailable` failed) — an explicit
            // port another process holds is NOT exhaustion.
            match first_bindable(&state.proxy_bind_addr, std::iter::once(remote_port)).await {
                Some(p) => Some(p),
                None => return Err(PortError::UnAvailable),
            }
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
                        first_bindable(
                            &state.proxy_bind_addr,
                            crate::proxy::pick_tcp_port_candidates(used, 0, &allow_ports, 64)
                                .into_iter()
                                .filter(|c| !ports.contains(c)),
                        )
                        .await
                    };
                    match retry {
                        Some(p2) => {
                            ports.insert(p2);
                            Ok(p2)
                        }
                        None => {
                            tracing::warn!(
                                ranges = ?allow_ports,
                                "Port exhaustion after allocation race: no available ports",
                            );
                            Err(PortError::NoAvailable)
                        }
                    }
                } else {
                    ports.insert(p);
                    Ok(p)
                }
            }
            // Auto-assign (remote_port == 0) exhausted every candidate —
            // Go ErrNoAvailablePort (ports.go:125-127). An explicit port
            // never reaches here: its probe failure returned UnAvailable.
            None => Err(PortError::NoAvailable),
        }
    }
}

/// True if a live UDP/SUDP proxy not in `exclude` still holds `port`.
///
/// SUDP proxies can share a single server UDP port (the frp-rs shared-port
/// extension) across proxies and run_ids, so UDP-port bookkeeping must not
/// be torn down while another owner remains. `exclude` is the set of names
/// being removed *by this caller*: during teardown the proxies being
/// deleted are still in the registry, so they must not count as owners.
pub(super) async fn udp_port_has_other_owner(
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

/// Free the port mark of a registry entry that a superseding control's
/// re-registration just replaced (see `ProxyManager::register_or_replace`).
///
/// The old control's own sweep will skip the name (newer control_id) and
/// nothing else would ever release the mark — used_ports is never pruned
/// (the 24h pruner only touches port_reservations) — so the replacement is
/// the only place that still knows the old port and must free it exactly
/// once here. Rules mirror the sweep's port cleanup:
/// - same port as the new registration: no-op (the mark now belongs to the
///   new control's proxy — e.g. SUDP sharing the old port);
/// - TCP group member: keep the mark while the old group still has other
///   members (their shared listener owns the port); stop the group
///   listener and free the mark when the group emptied;
/// - SUDP: free only when no other live udp/sudp proxy still holds the
///   port (shared-port ownership, `udp_port_has_other_owner`);
/// - otherwise: remove the mark from used_ports / used_udp_ports.
///
/// The freed port is reserved under the old proxy's name for the standard
/// 24h window, matching what the sweep's normal cleanup path would have
/// created — the old control's sweep never runs for this name.
pub(super) async fn free_replaced_port(state: &Arc<AppState>, old: &Arc<ProxyInfo>, new_port: u16) {
    let Some(port) = old.remote_port.filter(|p| *p > 0) else {
        return;
    };
    if port == new_port {
        // The new registration shares the old port (SUDP) — the mark is
        // now the new control's, not a leak.
        return;
    }
    let is_udp_type = old.proxy_type == "udp" || old.proxy_type == "sudp";
    if old.proxy_type == "tcp" && old.group.as_deref().filter(|g| !g.is_empty()).is_some() {
        // TCP group member: the shared group listener owns the port. Keep
        // the mark while other members remain; stop the listener and free
        // the mark when the group emptied. NOTE: unlike the sweep's
        // `group_len <= 1` check (which counts the member being removed,
        // still in the registry), the replacement already migrated the old
        // entry out of the group index — a count of 1 here means a sibling
        // still owns the shared port.
        let group_name = old.group.as_deref().unwrap_or("");
        if state.proxy_manager.group_len(group_name).await == 0 {
            state.used_ports.write().await.remove(&port);
            state
                .port_reservations
                .write()
                .await
                .insert(old.name.clone(), (port, false, std::time::Instant::now()));
            // Re-check group_len immediately before tearing down the
            // shared listener (mirrors the sweep's phase-3 re-check): a
            // concurrent member join can land between the observation
            // above and this point (register() pushes to the group index
            // under its own lock). remove_group would then cancel the
            // listener out from under the newly joined member, which
            // registered against the shared listener without creating one
            // of its own — a dead group with a live member. The port mark
            // was already freed either way, but the listener's OS bind
            // keeps the port from being re-allocated until the group
            // empties. The TOCTOU cannot be fully closed (a join landing
            // after this re-check) — best-effort, same as the sweep.
            if state.proxy_manager.group_len(group_name).await == 0 {
                state.tcp_group_ctl.remove_group(group_name).await;
            }
        }
        return;
    }
    if is_udp_type {
        if !udp_port_has_other_owner(state, port, &std::collections::HashSet::new()).await {
            state.used_udp_ports.write().await.remove(&port);
            state
                .port_reservations
                .write()
                .await
                .insert(old.name.clone(), (port, true, std::time::Instant::now()));
        }
        return;
    }
    state.used_ports.write().await.remove(&port);
    state
        .port_reservations
        .write()
        .await
        .insert(old.name.clone(), (port, false, std::time::Instant::now()));
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

/// Whether a registered proxy consumed a per-client port-budget slot —
/// the exact mirror of the registration increments (register_proxy_entry
/// and the TCP group member path): only tcp/udp/sudp proxies with a real
/// remote port count against `max_ports_per_client`. stcp/xtcp/http/
/// https/tcpmux register with remote_port Some(0) and must never release
/// a slot (audit finding 1 symmetry). Shared by the release helper below
/// and the unregister_control sweep.
pub(super) fn proxy_consumes_client_port(info: &ProxyInfo) -> bool {
    matches!(info.proxy_type.as_str(), "tcp" | "udp" | "sudp")
        && info.remote_port.is_some_and(|p| p > 0)
}

// ---- Port reservation periodic cleanup ----

/// Pure sweep of 24h-expired port reservations; extracted from
/// [`AppState::prune_expired_reservations`] for testability. Returns the
/// number of expired entries removed.
pub(super) fn prune_expired_reservations_inner(
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
