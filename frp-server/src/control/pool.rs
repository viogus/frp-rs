//! Work connection pool lifecycle management.
//!
//! Handles NewWorkConn, VisitorConn, ProxyUserConn, and UDP work connection
//! InternalMsg dispatch, pool assignment, and XTCP NatHoleSid delivery.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use crate::proxy::ProxyInfo;
use crate::service::InternalMsg;

use super::bridge;
use super::{write_ctl_msg, ControlContext, ControlState};

// ---- Constants ----

/// Default max age of a pending request when no user_conn_timeout configured.
const DEFAULT_PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Return the pending request timeout from the configured user_conn_timeout (seconds),
/// or the 10s default when the configured value is 0 (unset).
#[inline]
pub(super) fn pending_request_timeout(user_conn_timeout_secs: u64) -> Duration {
    if user_conn_timeout_secs > 0 {
        Duration::from_secs(user_conn_timeout_secs)
    } else {
        DEFAULT_PENDING_REQUEST_TIMEOUT
    }
}

/// Expire stale pending NatHoleSid entries from the front of the queue.
/// Returns the number of entries removed.
///
/// Shared by the control loop-top expiry (control/mod.rs) and the
/// delivery-time expiry in `handle_new_work_conn`. Without the loop-top
/// arm, entries only expired when a work conn arrived — a provider that
/// never delivers work conns let the queue grow unbounded (each entry
/// otherwise only expired inside `handle_new_work_conn`).
pub(crate) fn expire_pending_nat_hole_sids(
    pending: &mut VecDeque<(String, String, Instant)>,
    timeout: Duration,
) -> usize {
    let mut expired = 0;
    while let Some((sid, _pn, ts)) = pending.pop_front() {
        if ts.elapsed() >= timeout {
            expired += 1;
            debug!(sid = %sid, timeout = ?timeout, "Pending NatHoleSid {} timed out after {:?}", sid, timeout);
        } else {
            pending.push_front((sid, _pn, ts));
            break;
        }
    }
    expired
}

/// Max work connections to pool beyond what the client requested (Go frp: poolCount + 10).
pub(crate) const WORK_POOL_EXTRA: usize = 10;

/// Absolute server-side ceiling on a client's requested pool count when
/// `max_pool_count` is unset (0). Without it the client-controlled
/// `pool_count` would make the server hold an unbounded number of pooled
/// work-conn fds (audit fix). Generous next to Go frp's default
/// `maxPoolCount = 5`; Go's own hard cap is effectively the same resource
/// question left to the operator, so this only bounds the unconfigured case.
pub(crate) const WORK_POOL_ABS_CEILING: usize = 512;

// ---- Types ----

/// A pooled work connection. (Idle expiry was removed 2026-08-09 — audit
/// D2-3: `idle_timeout` is never configured and Go frp parity keeps pooled
/// conns alive until control disconnect, so `pooled_at` was dead.)
pub(crate) struct PoolEntry {
    pub(crate) conn: IoStream,
}

/// A pending request from a proxy listener waiting for a work connection.
///
/// The metadata below (local_addr/bandwidth limits via `proxy_info`) is
/// snapshotted when the request is enqueued; a config reload in the
/// enqueue→bridge window bridges to the stale backend. Self-limiting (the
/// bridge is one-shot) and narrow (one work-conn round trip), so no refresh
/// is done.
pub(crate) struct PendingRequest {
    pub(crate) proxy_name: String,
    pub(crate) user_conn: IoStream,
    pub(crate) pre_read: Vec<u8>,
    pub(crate) use_encryption: bool,
    pub(crate) use_compression: bool,
    /// Visitor-segment encryption (Go 三段式第 1 段): set from the visitor's
    /// NewVisitorConn use_encryption flag. When true, `run_work_bridge` wraps
    /// the visitor conn with `derive_key(proxy.sk)` before the provider-segment
    /// bridge (token encryption or plaintext). `use_encryption` above stays the
    /// provider-segment (work conn) flag from the proxy config.
    pub(crate) visitor_use_encryption: bool,
    /// Visitor-segment compression (Go 三段式第 1 段): set from the visitor's
    /// NewVisitorConn use_compression flag. When true, `run_work_bridge` wraps
    /// the visitor conn in a Snappy stream (inside the CFB layer when
    /// visitor-segment encryption is also on — snappy inner, CFB outer).
    pub(crate) visitor_use_compression: bool,
    /// Wire protocol of the visitor's connection (V2 frame detection). The
    /// SUDP message bridge needs it (with `visitor_udp_packet_codec`) to
    /// detect a mixed packet encoding between the visitor and provider
    /// segments (Go frp v0.71.0 `isMixedSUDPPacketEncoding`).
    pub(crate) visitor_v2: bool,
    /// Visitor-segment UDPPacket codec (`"binary-v1"` or empty). Inherited
    /// from the provider control's negotiated codec for V2 visitor
    /// connections; empty for V1 visitors (JSON) — Go frp v0.71.0
    /// `admitVisitorByRunID` semantics.
    pub(crate) visitor_udp_packet_codec: String,
    pub(crate) created_at: Instant,
    /// Per-proxy user-conn cap permit (audit D2-2). Held for the connection's
    /// full lifetime: dropped when this request is bridged and completes, or
    /// when the pending entry is expired/cleaned. None = unlimited.
    /// Never read directly — its `Drop` releases the semaphore permit, which
    /// is the entire point.
    #[allow(dead_code)]
    pub(crate) user_conn_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// Proxy metadata fetched once by the dispatcher. `assign_work_to_proxy`
    /// reads local_addr/remote_port/bandwidth_limit/etc. from it instead of
    /// re-acquiring the proxy-map RwLock per user connection.
    pub(crate) proxy_info: Option<Arc<ProxyInfo>>,
}

// ---- Helpers ----

/// Assign `req` to a pooled work connection if one is available (pool hit),
/// otherwise record a miss, send `ReqWorkConn`, and queue the request.
/// Returns `Err(())` if the `ReqWorkConn` write failed — caller must break.
pub(crate) async fn assign_or_queue<W>(
    work_pool: &mut VecDeque<PoolEntry>,
    pending_requests: &mut VecDeque<PendingRequest>,
    ctx: &ControlContext,
    writer: &mut W,
    req: PendingRequest,
) -> Result<(), ()>
where
    W: AsyncWriteExt + Unpin,
{
    if let Some(entry) = work_pool.pop_front() {
        ctx.state.pool.hits.fetch_add(1, Ordering::Relaxed);
        ctx.pool_stats
            .pool_size
            .store(work_pool.len() as i64, Ordering::Relaxed);
        // Proactive replenish: tell client to send replacement work conn.
        // Matches Go frp v0.70 GetWorkConn which always sends ReqWorkConn
        // after consuming from the pool channel (server/control.go:264).
        if let Err(e) = write_ctl_msg(
            writer,
            &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
            ctx.v2,
        )
        .await
        {
            warn!(error = %e, "Failed to send ReqWorkConn for pool replenish: {}", e);
            return Err(());
        }
        match bridge::assign_work_to_proxy(
            entry.conn,
            req,
            ctx.reloadable.encryption_key,
            ctx.state.clone(),
            ctx.v2,
        )
        .await
        {
            Ok(()) => {}
            // Dead pooled work conn: the client closed it after pooling and
            // StartWorkConn could not be written. The replenish ReqWorkConn
            // above is already on the wire, so retry once by re-enqueueing —
            // the replacement conn will pick this request up instead of
            // failing the user connection (audit fix).
            Err(req) => {
                warn!(proxy_name = %req.proxy_name, "Pooled work conn died before StartWorkConn; re-enqueueing request for replacement");
                pending_requests.push_back(req);
                ctx.pool_stats
                    .pending_requests
                    .store(pending_requests.len() as i64, Ordering::Relaxed);
            }
        }
    } else {
        ctx.state.pool.misses.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = write_ctl_msg(
            writer,
            &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
            ctx.v2,
        )
        .await
        {
            warn!(error = %e, "Failed to send ReqWorkConn: {}", e);
            return Err(());
        }
        pending_requests.push_back(req);
        // Bounded queue (audit round 5, MEDIUM): within the 10s expiry window
        // a burst of user connections with no work conns available can pile
        // up live sockets; cap the queue and evict the oldest entry instead.
        // Dropping the socket closes the user's connection (HTTP-style
        // backpressure) rather than holding the fd until expiry.
        const MAX_PENDING_REQUESTS: usize = 256;
        if pending_requests.len() > MAX_PENDING_REQUESTS {
            tracing::warn!(
                pending = %pending_requests.len(),
                "pending_requests queue full (>{MAX_PENDING_REQUESTS}), dropping oldest"
            );
            pending_requests.pop_front();
        }
        ctx.pool_stats
            .pending_requests
            .store(pending_requests.len() as i64, Ordering::Relaxed);
    }
    Ok(())
}

/// Parameters for a NAT hole-punched StartWorkConn message.
pub(crate) struct NatHoleWorkConnParams<'a> {
    pub proxy_name: &'a str,
    pub use_enc: bool,
    pub use_comp: bool,
    pub sk: Option<&'a str>,
    pub sid: &'a str,
    pub v2: bool,
    pub context: &'a str,
}

/// Write StartWorkConn with embedded `nat_hole_sid` + a separate NatHoleSid
/// frame for Go frpc compat. Go frp ignores unknown JSON fields, so the
/// standalone frame is needed for XTCP notification recognition.
///
/// NOTE: Go frp v0.70.1 server only writes NatHoleSid on the work connection
/// (no StartWorkConn). See /tmp/frp-source/server/proxy/xtcp.go:88-92.
/// The Rust frpc currently expects StartWorkConn first (work_conn.rs:310),
/// so Go frps → Rust frpc XTCP is NOT compatible for the provider side.
/// Rust frps sends both StartWorkConn (Rust frpc compat) + NatHoleSid
/// (Go frpc compat) to support both.
pub(crate) async fn write_start_work_conn_with_nat_hole_sid<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    params: &NatHoleWorkConnParams<'_>,
) {
    let swc = FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: params.proxy_name.to_string(),
        src_addr: None,
        src_port: None,
        dst_addr: None,
        dst_port: None,
        error: None,
        use_encryption: if params.use_enc { Some(true) } else { None },
        use_compression: if params.use_comp { Some(true) } else { None },
        nat_hole_sid: Some(params.sid.to_string()),
        nat_hole_visitor_addr: None,
        sk: params.sk.map(|s| s.to_string()),
    }));
    if let Err(e) = write_ctl_msg(writer, &swc, params.v2).await {
        warn!(error = %e, "Failed to send StartWorkConn with NatHoleSid{}: {}", params.context, e);
    } else {
        debug!(sid = %params.sid, "Sent StartWorkConn with embedded NatHoleSid {} to provider{}", params.sid, params.context);
        // Standalone NatHoleSid V1 frame for Go frpc compat.
        let nhs = FrpMessage::NatHoleSid(msg::NatHoleSid {
            sid: Some(params.sid.to_string()),
            ..Default::default()
        });
        if let Err(e) = write_ctl_msg(writer, &nhs, params.v2).await {
            debug!(error = %e, "Failed to send separate NatHoleSid frame (non-fatal): {}", e);
        }
    }
}

// ---- InternalMsg Handlers ----

/// Handle a new work connection arriving for this control session.
///
/// Priority order: (1) deliver pending NatHoleSid, (2) assign to waiting UDP
/// proxy, (3) assign to oldest pending TCP request, (4) pool if below cap,
/// (5) drop if pool is full.
pub(crate) async fn handle_new_work_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    _writer: &mut W,
    mut stream: IoStream,
) -> Result<(), ()> {
    debug!(run_id = %ctx.run_id, "Got work conn for run_id {}", ctx.run_id);
    // Expire stale pending NatHoleSid entries first (shared helper — the
    // control loop-top also expires them so the queue cannot grow while no
    // work conns arrive).
    expire_pending_nat_hole_sids(
        &mut ctl.pending_nat_hole_sids,
        pending_request_timeout(ctx.state.user_conn_timeout),
    );
    // Check NatHoleSid delivery first (Go frp XTCP compat).
    // Pending sids take priority — they unblock waiting visitors.
    if let Some((sid, proxy_name, _ts)) = ctl.pending_nat_hole_sids.pop_front() {
        debug!(sid = %sid, proxy_name = %proxy_name, "Delivering pending NatHoleSid {} for {} to provider", sid, proxy_name);
        // Look up proxy flags for StartWorkConn (encryption/compression propagation)
        let (use_enc, use_comp, sk) = ctx
            .state
            .proxy_manager
            .get(&proxy_name)
            .await
            .map(|p| (p.use_encryption, p.use_compression, p.sk.clone()))
            .unwrap_or((false, false, None));
        write_start_work_conn_with_nat_hole_sid(
            &mut stream,
            &NatHoleWorkConnParams {
                proxy_name: &proxy_name,
                use_enc,
                use_comp,
                sk: sk.as_deref(),
                sid: &sid,
                v2: ctx.v2,
                context: " (pending)",
            },
        )
        .await;
        // Work conn consumed for XTCP notification — drop it.
    } else {
        // Expire stale pending UDP requests first
        while let Some((pn, ts)) = ctl.pending_udp.pop_front() {
            if ts.elapsed() > pending_request_timeout(ctx.state.user_conn_timeout) {
                debug!(proxy_name = %pn, "Pending UDP work conn for '{}' timed out", pn);
            } else {
                ctl.pending_udp.push_front((pn, ts));
                break;
            }
        }
        // Check if a UDP proxy needs this work connection
        if let Some((proxy_name, _)) = ctl.pending_udp.pop_front() {
            info!(proxy_name = %proxy_name, "Assigning work conn to UDP proxy '{}'", proxy_name);
            let info = ctx.state.proxy_manager.get(&proxy_name).await;
            let local_addr = info
                .as_ref()
                .and_then(|info| info.local_addr.clone())
                .and_then(|s| msg::UdpAddr::from_string(&s));
            let udp_use_enc = info.as_ref().is_some_and(|i| i.use_encryption);
            // UDP bandwidth limiting: parsed from the proxy's
            // bandwidthLimit/bandwidthLimitMode (server mode applies a
            // two-direction limiter). Empty/unset stays unlimited — a
            // limiter is only created when the operator explicitly
            // configures a rate.
            let (bw_rate, bw_mode) = info
                .as_ref()
                .map(|i| {
                    bridge::parse_bandwidth_config(
                        if i.bandwidth_limit.is_empty() {
                            None
                        } else {
                            Some(i.bandwidth_limit.as_str())
                        },
                        Some(i.bandwidth_limit_mode.as_str()),
                    )
                })
                .unwrap_or((0, String::new()));
            bridge::assign_udp_work_conn(
                stream,
                &proxy_name,
                &ctl.udp_sockets,
                local_addr,
                udp_use_enc,
                ctx.reloadable.encryption_key,
                ctx.v2,
                ctx.state.udp_packet_size,
                bw_rate,
                bw_mode,
                // Per-proxy cancel token (low finding 5): a wedged bridge
                // exits when the proxy closes (handle_close_proxy cancels
                // it) instead of lingering until control teardown. Falls
                // back to the shared control token when the proxy never
                // registered one (cleanup path).
                ctl.udp_cancels
                    .get(&proxy_name)
                    .cloned()
                    .unwrap_or_else(|| ctl.udp_cancel.clone()),
                // Negotiated UDP packet codec from the V2 handshake
                // (Go frp v0.71.0 binary-v1 or empty JSON fallback).
                ctx.udp_packet_codec.clone(),
            )
            .await;
        } else {
            // Drain expired TCP requests
            while let Some(req) = ctl.pending_requests.front() {
                if req.created_at.elapsed() > pending_request_timeout(ctx.state.user_conn_timeout) {
                    ctl.pending_requests.pop_front();
                    ctx.pool_stats
                        .pending_requests
                        .store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                } else {
                    break;
                }
            }
            if let Some(req) = ctl.pending_requests.pop_front() {
                ctx.state.pool.hits.fetch_add(1, Ordering::Relaxed);
                ctx.pool_stats
                    .pending_requests
                    .store(ctl.pending_requests.len() as i64, Ordering::Relaxed);
                ctx.pool_stats
                    .pool_size
                    .store(ctl.work_pool.len() as i64, Ordering::Relaxed);
                let enc_key = ctx.reloadable.encryption_key;
                match bridge::assign_work_to_proxy(stream, req, enc_key, ctx.state.clone(), ctx.v2)
                    .await
                {
                    Ok(()) => {}
                    // A freshly delivered work conn died at StartWorkConn —
                    // the client is likely gone too, so dropping the request
                    // (closing its user conn) is correct; no re-enqueue
                    // without a new ReqWorkConn on the wire.
                    Err(req) => {
                        warn!(proxy_name = %req.proxy_name, "Fresh work conn died before StartWorkConn; dropping request");
                    }
                }
            } else if ctl.work_pool.len() < ctx.pool_cap {
                ctl.work_pool.push_back(PoolEntry { conn: stream });
                ctx.pool_stats
                    .pool_size
                    .store(ctl.work_pool.len() as i64, Ordering::Relaxed);
                debug!(run_id = %ctx.run_id, pool_size = %ctl.work_pool.len(), pool_cap = %ctx.pool_cap, "Work conn pooled for {} (pool size: {}/{})", ctx.run_id, ctl.work_pool.len(), ctx.pool_cap);
            } else {
                ctx.state.pool.drops.fetch_add(1, Ordering::Relaxed);
                debug!(run_id = %ctx.run_id, pool_size = %ctl.work_pool.len(), pool_cap = %ctx.pool_cap, "Work pool full for {} ({}/{}), dropping work conn", ctx.run_id, ctl.work_pool.len(), ctx.pool_cap);
            }
        }
    }
    Ok(())
}

/// Handle a visitor connection for STCP (secret TCP) proxy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_visitor_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: String,
    visitor_conn: IoStream,
    visitor_use_encryption: bool,
    visitor_use_compression: bool,
    visitor_v2: bool,
    visitor_udp_packet_codec: String,
) -> Result<(), ()> {
    // NewUserConn plugin hook — control-enabled plugins can reject.
    // Skip payload construction when no plugins are configured (the
    // default) — every user conn used to build a full json! Value
    // just for the notify loop.
    if !ctx.state.plugin_manager.is_empty() {
        let user_content = serde_json::json!({
            "proxy_name": proxy_name,
            "run_id": ctx.run_id,
        });
        if let Err(reason) = ctx
            .state
            .plugin_manager
            .notify("new_user_conn", user_content)
            .await
        {
            debug!(proxy_name = %proxy_name, reason = %reason, "NewUserConn plugin hook rejected (VisitorConn): {}", reason);
            return Ok(());
        }
    }
    debug!(proxy_name = %proxy_name, run_id = %ctx.run_id, "STCP visitor conn for proxy {} on run_id {}", proxy_name, ctx.run_id);
    // Fetch proxy metadata once and carry it in the request — the bridge
    // reads it from here instead of re-locking the proxy map.
    let proxy_info = ctx.state.proxy_manager.get(&proxy_name).await;
    let (enc, comp) = proxy_info
        .as_ref()
        .map(|p| (p.use_encryption, p.use_compression))
        .unwrap_or((false, false));
    // Visitor-segment UDPPacket codec was determined at accept time (Go
    // frp v0.71.0 admitVisitorByRunID) and carried in the InternalMsg.
    assign_or_queue(
        &mut ctl.work_pool,
        &mut ctl.pending_requests,
        ctx,
        writer,
        PendingRequest {
            proxy_name,
            user_conn: visitor_conn,
            pre_read: Vec::new(),
            use_encryption: enc,
            use_compression: comp,
            visitor_use_encryption,
            visitor_use_compression,
            visitor_v2,
            visitor_udp_packet_codec,
            created_at: Instant::now(),
            // STCP/XTCP visitors are not bounded by the provider's
            // user-conn cap (Go semantics: visitor conns are peer-initiated
            // and already gated by sk auth).
            user_conn_permit: None,
            proxy_info,
        },
    )
    .await
}

/// Handle a user connection arriving for a proxy.
///
/// Includes plugin hook, group load balancing with cross-run_id forwarding,
/// and pool assignment.
///
/// `forwarded_permit` is the user-conn cap permit acquired by a FORWARDER
/// (group-LB cross-run_id path, audit M5) and carried inside
/// `InternalMsg::ProxyUserConn`. When `Some`, it is consumed directly — the
/// backend must NOT re-acquire (the forwarder already counted this
/// connection against the backend's cap). When `None` (local sends from
/// vhost/tcpmux/proxy listeners, or an unlimited backend), the permit is
/// acquired here as usual.
///
/// `group_selected` is set by forwarders that already chose the backend (the
/// TCP group shared listener and the M5 cross-run_id forwarder). When `true`,
/// group re-selection is SKIPPED and the conn routes directly to the named
/// `proxy_name` — re-selecting an already-selected conn bounces it between
/// group members forever (manager-level round-robin counter) when the group
/// spans run_ids without a group_key, pinning both controls and never
/// bridging the conn.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_proxy_user_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: String,
    user_conn: IoStream,
    pre_read: Vec<u8>,
    forwarded_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    group_selected: bool,
) -> Result<(), ()> {
    // NewUserConn plugin hook — control-enabled plugins can reject.
    // Skip payload construction when no plugins are configured (the
    // default) — every user conn used to build a full json! Value
    // just for the notify loop.
    if !ctx.state.plugin_manager.is_empty() {
        let user_content = serde_json::json!({
            "proxy_name": proxy_name,
            "run_id": ctx.run_id,
        });
        if let Err(reason) = ctx
            .state
            .plugin_manager
            .notify("new_user_conn", user_content)
            .await
        {
            debug!(proxy_name = %proxy_name, reason = %reason, "NewUserConn plugin hook rejected (ProxyUserConn): {}", reason);
            return Ok(());
        }
    }
    debug!(proxy_name = %proxy_name, run_id = %ctx.run_id, "User conn for proxy {} on run_id {}", proxy_name, ctx.run_id);
    // Group load balancing: if proxy belongs to a group,
    // select a backend (possibly on a different run_id). The fetched
    // metadata is retained and carried into the pending request when the
    // backend is this same proxy, so the bridge never re-locks the map.
    let (target_proxy, target_run_id, orig_info) = {
        let p = ctx.state.proxy_manager.get(&proxy_name).await;
        if group_selected {
            // The forwarder (TCP group shared listener / M5 cross-run_id
            // path) already selected this backend and routed the message
            // to its run_id. Re-running selection here would bounce the
            // conn between members forever — the shared round-robin
            // counter makes every hop pick the next member, so a
            // 2+-member cross-run_id group without group_key never
            // settles (pre-existing livelock fix). Route directly.
            (proxy_name.clone(), ctx.run_id.clone(), p)
        } else {
            // Group LB applies ONLY to TCP groups (shared listener
            // dispatch). HTTP/HTTPS group members are selected by the vhost
            // router (Go HTTPGroup.chooseEndpoint) before the conn reaches
            // here — the incoming proxy_name already IS the chosen member,
            // so re-running selection would bounce the conn between
            // members (and the vhost route stays on the first member's
            // control, which is not necessarily the selected member's).
            let group = p
                .as_ref()
                .filter(|p| p.proxy_type == "tcp")
                .and_then(|p| p.group.clone())
                .filter(|g| !g.is_empty());
            let group_key = p
                .as_ref()
                .and_then(|p| p.group_key.clone())
                .unwrap_or_default();
            if let Some(ref group_name) = group {
                if let Some((backend, backend_run_id)) = ctx
                    .state
                    .proxy_manager
                    .select_group_backend_with_run_id(group_name, &group_key)
                    .await
                {
                    info!(proxy_name = %proxy_name, backend = %backend, backend_run_id = %backend_run_id, "Group LB: {} -> backend {} (run_id {})", proxy_name, backend, backend_run_id);
                    (backend, backend_run_id, p)
                } else {
                    (proxy_name.clone(), ctx.run_id.clone(), p)
                }
            } else {
                (proxy_name.clone(), ctx.run_id.clone(), p)
            }
        }
    };
    // If backend is on a different run_id, forward to that handler
    if target_run_id != ctx.run_id {
        // Audit M5: acquire the BACKEND's user-conn permit BEFORE the
        // try_send. Without this, a flood of group-LB conns to an at-cap/
        // slow backend queues raw sockets (each holding an fd) in the
        // shared 1024-slot internal_rx channel before the backend's own
        // permit check rejects them — starving that control's other
        // internal traffic. The permit crosses the message boundary and
        // the backend handler consumes it instead of re-acquiring
        // (no double-count: forwarded permit replaces the re-acquire).
        // A backend without a semaphore is unlimited — forward with
        // permit None. A backend at cap is dropped here, mirroring the
        // local path's behavior.
        //
        // Window: the backend may unregister (control closed, reload)
        // between the `get()` above and the `try_send` below. The permit
        // then rides a `ProxyUserConn` for a dead proxy; the receiving
        // handler's control loop is shutting down, so the permit is
        // dropped (returning to the semaphore) once that control's
        // shutdown drains the channel — bounded and self-releasing, and
        // the proxy_manager `get()` returning `None` already covers the
        // common unregister-before-get case. No leak either way.
        let forwarded_permit = match ctx.state.proxy_manager.get(&target_proxy).await {
            Some(p) => match p.user_conn_sem.clone() {
                Some(sem) => match sem.try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        debug!(proxy_name = %target_proxy, "Group backend '{}' at user-conn cap, dropping connection", target_proxy);
                        return Ok(());
                    }
                },
                None => None,
            },
            // Backend vanished mid-forward — carry no permit; try_send
            // will surface the closed channel.
            None => None,
        };
        let ctl_tx = ctx
            .state
            .run_id_to_ctl_tx
            .get(&target_run_id)
            .map(|v| v.clone());
        if let Some(ctl) = ctl_tx {
            match ctl.tx.try_send(InternalMsg::ProxyUserConn {
                proxy_name: target_proxy.clone(),
                user_conn,
                pre_read,
                // On TrySendError the message (with its permit) is dropped
                // with the error — the permit returns to the backend's
                // semaphore, so nothing leaks on Full/Closed.
                user_conn_permit: forwarded_permit,
                // Backend already selected here — the receiving handler
                // must route directly, not re-run group selection (would
                // bounce the conn between members forever).
                group_selected: true,
            }) {
                Ok(()) => {
                    // Reset health on successful dispatch
                    ctx.state
                        .proxy_manager
                        .report_backend_success(&target_proxy)
                        .await;
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Backend handler is overloaded, not unhealthy — do NOT count
                    // channel-full as a backend failure (would cause premature
                    // health degradation under high load).
                    debug!(target_run_id = %target_run_id, "Group backend channel full (overloaded), dropping connection");
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    ctx.state
                        .proxy_manager
                        .report_backend_failure(&target_proxy)
                        .await;
                    debug!(target_run_id = %target_run_id, "Group backend handler closed, dropping connection");
                    return Ok(());
                }
            }
        } else {
            ctx.state
                .proxy_manager
                .report_backend_failure(&target_proxy)
                .await;
            warn!(target_run_id = %target_run_id, target_proxy = %target_proxy, "Group backend run_id {} not found for proxy {}", target_run_id, target_proxy);
            return Ok(());
        }
    }
    // Fetch the backend's metadata once (reusing the group-selection fetch
    // when the backend is the same proxy) and carry it in the request.
    let proxy_info = if target_proxy == proxy_name {
        orig_info
    } else {
        ctx.state.proxy_manager.get(&target_proxy).await
    };
    let (enc, comp) = proxy_info
        .as_ref()
        .map(|p| (p.use_encryption, p.use_compression))
        .unwrap_or((false, false));
    // Per-proxy user-conn cap (audit D2-2): acquire the permit before
    // enqueueing so a flood cannot grow pending_requests + fds unbounded.
    // The permit lives in the PendingRequest and drops when the bridge
    // ends (or the pending entry expires), covering the conn's lifetime.
    // 0 = unlimited (Go frp default; no equivalent option upstream).
    // A forwarded permit (audit M5, cross-run_id group-LB path) is
    // consumed as-is — the forwarder already counted this conn against
    // the backend's cap, so re-acquiring would double-count and fail
    // spuriously at cap.
    let user_conn_permit = match forwarded_permit {
        Some(permit) => Some(permit),
        None => match proxy_info.as_ref().and_then(|p| p.user_conn_sem.clone()) {
            Some(sem) => match sem.try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    debug!(proxy_name = %target_proxy, "Proxy '{}' at user-conn cap, dropping connection", target_proxy);
                    return Ok(());
                }
            },
            None => None,
        },
    };
    assign_or_queue(
        &mut ctl.work_pool,
        &mut ctl.pending_requests,
        ctx,
        writer,
        PendingRequest {
            proxy_name: target_proxy,
            user_conn,
            pre_read,
            use_encryption: enc,
            use_compression: comp,
            // Group load-balancing forwards a provider-side user conn (not a
            // visitor conn), so visitor-segment encryption/compression never
            // apply here.
            visitor_use_encryption: false,
            visitor_use_compression: false,
            // Group forwarder carries a provider-side conn — not a visitor
            // conn — so visitor wire protocol/codec never apply here.
            visitor_v2: false,
            visitor_udp_packet_codec: String::new(),
            created_at: Instant::now(),
            user_conn_permit,
            proxy_info,
        },
    )
    .await
}

/// Handle a UDP proxy requesting a work connection.
pub(crate) async fn handle_udp_work_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: String,
) -> Result<(), ()> {
    debug!(proxy_name = %proxy_name, "UDP proxy '{}' needs work connection", proxy_name);
    if let Err(e) = write_ctl_msg(
        writer,
        &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
        ctx.v2,
    )
    .await
    {
        warn!(error = %e, "Failed to send ReqWorkConn for UDP: {}", e);
        return Err(());
    }
    ctl.pending_udp.push_back((proxy_name, Instant::now()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use frp_core::transport::Transport;

    /// Work transport whose writes fail deterministically — a pooled conn
    /// the client closed after pooling.
    struct BrokenWorkTransport;

    impl tokio::io::AsyncRead for BrokenWorkTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for BrokenWorkTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected writer failure",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Transport for BrokenWorkTransport {
        fn debug_name(&self) -> &'static str {
            "BrokenWorkTransport"
        }
    }

    fn broken_io() -> IoStream {
        IoStream::from(Box::new(BrokenWorkTransport) as Box<dyn Transport>)
    }

    fn test_state() -> Arc<crate::state::AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(crate::state::AppState::new(
            frp_core::auth::AuthConfig::with_token("test-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("test-token"),
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
            String::new(),
            true,
            30,
            7200,
            90,
            1500,
            false,
            None,
            0,
            60,
            10,
            false,
            String::new(),
            Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
            0,
            0,
            168,
            true,
            0,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    fn test_context(
        state: &Arc<crate::state::AppState>,
        run_id: &str,
    ) -> (ControlContext, ControlState) {
        let (_, run_mu_guard) = state.get_run_mu(run_id);
        let (internal_tx, _internal_rx) = mpsc::channel(16);
        let ctx = ControlContext {
            state: Arc::clone(state),
            pool_stats: Arc::new(crate::state::PoolStats::default()),
            reloadable: state
                .reloadable
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            v2: false,
            run_id: run_id.to_string(),
            control_id: 1,
            pool_cap: 10,
            internal_tx,
            peer: None,
            authenticated_user: String::new(),
            udp_packet_codec: String::new(),
            _run_mu_guard: run_mu_guard,
        };
        let ctl = ControlState {
            shutting_down: false,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            udp_cancels: HashMap::new(),
            work_pool: VecDeque::new(),
            pending_requests: VecDeque::new(),
            pending_udp: VecDeque::new(),
            pending_nat_hole_sids: VecDeque::new(),
            listener_handles: HashMap::new(),
            udp_sockets: HashMap::new(),
            last_ping: Instant::now(),
        };
        (ctx, ctl)
    }

    fn test_req(proxy_name: &str) -> PendingRequest {
        PendingRequest {
            proxy_name: proxy_name.to_string(),
            user_conn: broken_io(),
            pre_read: Vec::new(),
            use_encryption: false,
            use_compression: false,
            visitor_use_encryption: false,
            visitor_use_compression: false,
            visitor_v2: false,
            visitor_udp_packet_codec: String::new(),
            created_at: Instant::now(),
            user_conn_permit: None,
            proxy_info: None,
        }
    }

    /// A pooled work conn that dies at StartWorkConn must re-enqueue the
    /// request (the replenish ReqWorkConn is already on the wire) instead
    /// of failing the user connection (audit fix).
    #[tokio::test]
    async fn dead_pooled_conn_reenqueues_request() {
        let state = test_state();
        let (ctx, mut ctl) = test_context(&state, "run-1");
        ctl.work_pool.push_back(PoolEntry { conn: broken_io() });
        let mut writer = Vec::new();

        let res = assign_or_queue(
            &mut ctl.work_pool,
            &mut ctl.pending_requests,
            &ctx,
            &mut writer,
            test_req("p1"),
        )
        .await;
        assert!(res.is_ok(), "assign_or_queue must not fail the control");

        // The dead conn was consumed and the request re-enqueued for the
        // replacement work conn.
        assert!(ctl.work_pool.is_empty(), "dead conn consumed");
        assert_eq!(ctl.pending_requests.len(), 1, "request must be re-enqueued");
        assert_eq!(ctl.pending_requests[0].proxy_name, "p1");
        // Replenish ReqWorkConn was written to the control channel.
        assert!(!writer.is_empty(), "ReqWorkConn replenish must be written");
    }

    /// Register a control channel for a run_id and hand back the receiver so
    /// tests can assert what (if anything) the forwarder sent to the backend.
    async fn insert_control_rx(
        state: &Arc<crate::state::AppState>,
        run_id: &str,
        control_id: u64,
    ) -> mpsc::Receiver<crate::state::InternalMsg> {
        let (tx, rx) = mpsc::channel(8);
        state.run_id_to_ctl_tx.insert(
            run_id.to_string(),
            crate::state::ControlTx {
                tx,
                client_addr: None,
                login_time: std::time::Instant::now(),
                login_time_unix: 0,
                pool_stats: Arc::new(crate::state::PoolStats::default()),
                user: String::new(),
                control_id,
                udp_packet_codec: String::new(),
                wire_v2: false,
            },
        );
        rx
    }

    /// Low finding 1: stale pending NatHoleSid entries must expire from the
    /// queue front (the loop-top expiry arm in control/mod.rs), not linger
    /// until a work conn happens to arrive.
    #[test]
    fn expire_pending_nat_hole_sids_removes_stale_keeps_fresh() {
        let mut pending = VecDeque::new();
        pending.push_back((
            "sid-stale-1".to_string(),
            "p1".to_string(),
            Instant::now() - Duration::from_secs(120),
        ));
        pending.push_back((
            "sid-stale-2".to_string(),
            "p2".to_string(),
            Instant::now() - Duration::from_secs(90),
        ));
        pending.push_back(("sid-fresh".to_string(), "p3".to_string(), Instant::now()));
        let removed = expire_pending_nat_hole_sids(&mut pending, Duration::from_secs(60));
        assert_eq!(removed, 2, "two stale entries must expire");
        assert_eq!(pending.len(), 1, "fresh entry must survive");
        assert_eq!(pending[0].0, "sid-fresh");
    }

    /// Audit M5: a group-LB cross-run_id forward to an at-cap backend must
    /// drop the connection AT THE FORWARDER (acquiring the backend's permit
    /// fails first) — the raw socket must never be queued into the backend's
    /// internal channel, which would starve that control's other traffic.
    #[tokio::test]
    async fn cross_run_id_forward_drops_conn_when_backend_at_cap() {
        let state = test_state();
        // Register g2 (run-2) FIRST so the group round-robin counter (0)
        // picks it as the backend for the first user conn.
        let mut info_g2 = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "g2",
            "tcp",
            "run-2",
            Some(24002),
            2,
        );
        info_g2.group = Some("grp".to_string());
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        // Hold the single permit: g2 is at cap, one conn in flight.
        let _held = sem
            .clone()
            .try_acquire_owned()
            .expect("hold the only permit");
        info_g2.user_conn_sem = Some(sem.clone());
        state
            .proxy_manager
            .register("run-2".into(), info_g2)
            .await
            .expect("register g2");
        // g1 (run-1) joins AFTER g2 → group members [g2, g1].
        let mut info_g1 = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "g1",
            "tcp",
            "run-1",
            Some(24001),
            1,
        );
        info_g1.group = Some("grp".to_string());
        state
            .proxy_manager
            .register("run-1".into(), info_g1)
            .await
            .expect("register g1");

        let mut rx_run2 = insert_control_rx(&state, "run-2", 2).await;
        let (mut ctx, mut ctl) = test_context(&state, "run-1");
        let mut writer = Vec::new();

        let res = handle_proxy_user_conn(
            &mut ctx,
            &mut ctl,
            &mut writer,
            "g1".to_string(),
            broken_io(),
            Vec::new(),
            None,
            // Local conn, no prior group selection — selection runs here.
            false,
        )
        .await;
        assert!(
            res.is_ok(),
            "dropping at the forwarder must not fail the control"
        );
        assert!(
            rx_run2.try_recv().is_err(),
            "at-cap backend conn must be dropped at the forwarder, not queued into the backend channel"
        );
        assert_eq!(sem.available_permits(), 0, "permit must not leak");
        assert!(ctl.pending_requests.is_empty());
    }

    /// Audit M5 positive path: the forwarder acquires the BACKEND's permit
    /// and ships it inside the message; the backend consumes it without
    /// re-acquiring (no double-count — a re-acquire would fail spuriously
    /// at cap).
    #[tokio::test]
    async fn cross_run_id_forward_carries_permit_backend_consumes_it() {
        let state = test_state();
        // g1 registered FIRST → members [g1, g2]. group_key "a" hashes to
        // index 1 → BOTH controls deterministically select g2, so the
        // forwarded conn terminates at the backend (no re-forward loop).
        let mut info_g1 = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "g1",
            "tcp",
            "run-1",
            Some(24001),
            1,
        );
        info_g1.group = Some("grp".to_string());
        info_g1.group_key = Some("a".to_string());
        state
            .proxy_manager
            .register("run-1".into(), info_g1)
            .await
            .expect("register g1");
        let mut info_g2 = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "g2",
            "tcp",
            "run-2",
            Some(24002),
            2,
        );
        info_g2.group = Some("grp".to_string());
        info_g2.group_key = Some("a".to_string());
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        info_g2.user_conn_sem = Some(sem.clone());
        state
            .proxy_manager
            .register("run-2".into(), info_g2)
            .await
            .expect("register g2");

        let mut rx_run2 = insert_control_rx(&state, "run-2", 2).await;
        let (mut ctx_fwd, mut ctl_fwd) = test_context(&state, "run-1");
        let mut writer_fwd = Vec::new();

        let res = handle_proxy_user_conn(
            &mut ctx_fwd,
            &mut ctl_fwd,
            &mut writer_fwd,
            "g1".to_string(),
            broken_io(),
            Vec::new(),
            None,
            // Local conn, no prior group selection — selection runs here.
            false,
        )
        .await;
        assert!(res.is_ok());

        // Forwarder acquired the backend's permit and shipped it in the
        // message: available is 0 and the message carries it.
        let msg = rx_run2
            .recv()
            .await
            .expect("forwarded conn must reach the backend");
        let crate::state::InternalMsg::ProxyUserConn {
            proxy_name,
            user_conn,
            pre_read,
            user_conn_permit,
            group_selected,
        } = msg
        else {
            panic!("unexpected internal message: {msg:?}");
        };
        assert_eq!(proxy_name, "g2");
        assert!(
            group_selected,
            "forwarder must mark the message as group-selected"
        );
        assert!(
            user_conn_permit.is_some(),
            "forwarder must carry the backend's permit in the message"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "permit held by the in-flight forwarded message"
        );

        // Backend consumes the carried permit WITHOUT re-acquiring: the
        // request is queued (not dropped at cap) with the permit inside it.
        let (mut ctx_bk, mut ctl_bk) = test_context(&state, "run-2");
        let mut writer_bk = Vec::new();
        let res = handle_proxy_user_conn(
            &mut ctx_bk,
            &mut ctl_bk,
            &mut writer_bk,
            proxy_name,
            user_conn,
            pre_read,
            user_conn_permit,
            // The message was forwarded with group_selected — the backend
            // routes directly to the named proxy.
            true,
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(
            ctl_bk.pending_requests.len(),
            1,
            "backend must accept the conn — consuming the carried permit, not re-acquiring"
        );
        assert!(
            ctl_bk.pending_requests[0].user_conn_permit.is_some(),
            "permit must live inside the pending request"
        );
        assert_eq!(sem.available_permits(), 0, "permit moved, not leaked");
    }

    /// Pre-existing finding 2: a conn forwarded with group_selected=true
    /// (TCP group shared listener / M5 forwarder) must NOT be re-selected by
    /// the receiving backend handler. With a 2-member cross-run_id group
    /// WITHOUT group_key, re-selection bounces the conn between members
    /// forever — the manager-level round-robin counter makes every hop pick
    /// the next member, so the conn never settles (CPU livelock on both
    /// controls, never bridged). Same-run_id groups and group_key-sticky
    /// paths terminate fine; only the no-key cross-run_id case bounces.
    #[tokio::test]
    async fn group_forwarded_conn_does_not_bounce_without_group_key() {
        let state = test_state();
        // g1 registered FIRST → members [g1, g2]. NO group_key: the group
        // listener's first round-robin selection (counter 0) picks g1.
        let mut info_g1 = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "g1",
            "tcp",
            "run-1",
            Some(24001),
            1,
        );
        info_g1.group = Some("grp".to_string());
        state
            .proxy_manager
            .register("run-1".into(), info_g1)
            .await
            .expect("register g1");
        let mut info_g2 = crate::control::proxy_ops::unregister_generation_tests::proxy_info(
            "g2",
            "tcp",
            "run-2",
            Some(24002),
            2,
        );
        info_g2.group = Some("grp".to_string());
        state
            .proxy_manager
            .register("run-2".into(), info_g2)
            .await
            .expect("register g2");

        // run-2's control channel receives anything the handlers forward.
        let mut rx_run2 = insert_control_rx(&state, "run-2", 2).await;
        let (mut ctx_fwd, mut ctl_fwd) = test_context(&state, "run-1");
        let mut writer_fwd = Vec::new();

        // Simulate the group listener's FIRST selection (counter 0 → g1,
        // advancing the shared round-robin counter to 1). Without this the
        // counter would sit at 0 and even a re-selection would re-pick g1 —
        // the bounce needs the counter to have advanced past g1.
        let (first_backend, first_run_id) = state
            .proxy_manager
            .select_group_backend_with_run_id("grp", "")
            .await
            .expect("group has members");
        assert_eq!(
            (first_backend.as_str(), first_run_id.as_str()),
            ("g1", "run-1"),
            "first round-robin selection must pick g1"
        );

        // Conn 1: the group listener selected g1 (run-1) and forwarded with
        // group_selected=true. The handler must route DIRECTLY to g1 — a
        // re-selection would advance the shared counter, pick g2, and bounce
        // the conn into run-2's channel.
        let res = handle_proxy_user_conn(
            &mut ctx_fwd,
            &mut ctl_fwd,
            &mut writer_fwd,
            "g1".to_string(),
            broken_io(),
            Vec::new(),
            None,
            true,
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(
            ctl_fwd.pending_requests.len(),
            1,
            "group-selected conn must be queued at the named backend (g1), not re-selected"
        );
        assert!(
            rx_run2.try_recv().is_err(),
            "group-selected conn must not bounce to the other member (run-2)"
        );

        // Conn 2: the listener's counter advanced, so it selected g2
        // (run-2) and forwarded there with group_selected=true. It must
        // stay at run-2 — not bounce back to run-1.
        let (mut ctx_bk, mut ctl_bk) = test_context(&state, "run-2");
        let mut writer_bk = Vec::new();
        let res = handle_proxy_user_conn(
            &mut ctx_bk,
            &mut ctl_bk,
            &mut writer_bk,
            "g2".to_string(),
            broken_io(),
            Vec::new(),
            None,
            true,
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(
            ctl_bk.pending_requests.len(),
            1,
            "group-selected conn must stay at the named backend (g2)"
        );
        // Nothing bounced: run-1 kept its conn and run-2 kept its own.
        assert_eq!(ctl_fwd.pending_requests.len(), 1, "no conn left run-1");
        assert!(
            rx_run2.try_recv().is_err(),
            "run-2 must not forward anything onward either"
        );
    }
}
