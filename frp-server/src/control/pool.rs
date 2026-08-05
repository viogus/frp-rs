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

/// Max work connections to pool beyond what the client requested (Go frp: poolCount + 10).
pub(crate) const WORK_POOL_EXTRA: usize = 10;

// ---- Types ----

/// A pooled work connection with its pool-entry timestamp for idle expiry.
pub(crate) struct PoolEntry {
    pub(crate) conn: IoStream,
    pub(crate) pooled_at: Instant,
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
    pub(crate) created_at: Instant,
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
        bridge::assign_work_to_proxy(
            entry.conn,
            req,
            ctx.reloadable.encryption_key,
            ctx.state.clone(),
            ctx.v2,
        )
        .await;
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
    // Expire stale pending NatHoleSid entries first.
    while let Some((sid, _pn, ts)) = ctl.pending_nat_hole_sids.pop_front() {
        if ts.elapsed() > pending_request_timeout(ctx.state.user_conn_timeout) {
            debug!(sid = %sid, "Pending NatHoleSid {} timed out", sid);
        } else {
            ctl.pending_nat_hole_sids.push_front((sid, _pn, ts));
            break;
        }
    }
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
            let local_addr = ctx
                .state
                .proxy_manager
                .get(&proxy_name)
                .await
                .and_then(|info| info.local_addr.clone())
                .and_then(|s| msg::UdpAddr::from_string(&s));
            bridge::assign_udp_work_conn(
                stream,
                &proxy_name,
                &ctl.udp_sockets,
                local_addr,
                ctx.v2,
                ctx.state.udp_packet_size,
                ctl.udp_cancel.clone(),
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
                bridge::assign_work_to_proxy(stream, req, enc_key, ctx.state.clone(), ctx.v2).await;
            } else if ctl.work_pool.len() < ctx.pool_cap {
                ctl.work_pool.push_back(PoolEntry {
                    conn: stream,
                    pooled_at: Instant::now(),
                });
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
pub(crate) async fn handle_visitor_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: String,
    visitor_conn: IoStream,
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
            created_at: Instant::now(),
            proxy_info,
        },
    )
    .await
}

/// Handle a user connection arriving for a proxy.
///
/// Includes plugin hook, group load balancing with cross-run_id forwarding,
/// and pool assignment.
pub(crate) async fn handle_proxy_user_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: String,
    user_conn: IoStream,
    pre_read: Vec<u8>,
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
        let group = p
            .as_ref()
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
    };
    // If backend is on a different run_id, forward to that handler
    if target_run_id != ctx.run_id {
        let ctl_tx = {
            let map = ctx.state.run_id_to_ctl_tx.read().await;
            map.get(&target_run_id).cloned()
        };
        if let Some(ctl) = ctl_tx {
            match ctl.tx.try_send(InternalMsg::ProxyUserConn {
                proxy_name: target_proxy.clone(),
                user_conn,
                pre_read,
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
            created_at: Instant::now(),
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
