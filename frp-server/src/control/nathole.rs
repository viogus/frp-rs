//! XTCP NAT hole punch handlers for the control connection select! loop.
//!
//! Handles InternalMsg forwarding (WriteNatHoleSid/Resp/Report, NatHoleSidOnWorkConn,
//! VnetPacketForward) and FrpMessage dispatch (NatHoleClient, NatHoleSid, NatHoleResp,
//! NatHoleReport, NatHoleVisitor, NewVisitorConn) plus VNet route management.

use std::sync::atomic::Ordering;
#[cfg(any(feature = "vnet", test))]
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use frp_core::msg::{self, FrpMessage};

use crate::lock::RwLockExt;
use crate::nathole::NAT_HOLE_TIMEOUT;
use crate::service::InternalMsg;

use super::pool;
use super::{write_ctl_msg, ControlContext, ControlState};

// ── InternalMsg handlers ────────────────────────────────────────────

/// Write NatHoleSid to the visitor via the control channel.
pub(crate) async fn handle_write_sid<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    sid: String,
) {
    debug!(sid = %sid, "Writing NatHoleSid to visitor via control channel for {}", sid);
    let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
        sid: Some(sid),
        ..Default::default()
    });
    if let Err(e) = write_ctl_msg(writer, &forward, ctx.v2).await {
        warn!(error = %e, "Failed to write NatHoleSid to visitor: {}", e);
    }
}

/// Write NatHoleResp to the visitor via the control channel.
pub(crate) async fn handle_write_resp<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    resp: msg::NatHoleResp,
) {
    debug!(transaction_id = %resp.transaction_id, "Writing NatHoleResp to visitor via control channel for {}", resp.transaction_id);
    let forward = FrpMessage::NatHoleResp(Box::new(resp));
    if let Err(e) = write_ctl_msg(writer, &forward, ctx.v2).await {
        warn!(error = %e, "Failed to write NatHoleResp to visitor: {}", e);
    }
}

/// Write NatHoleReport to the visitor via the control channel.
pub(crate) async fn handle_write_report<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    sid: String,
) {
    debug!(sid = %sid, "Writing NatHoleReport to visitor via control channel for {}", sid);
    let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
        sid: Some(sid),
        success: false,
    });
    if let Err(e) = write_ctl_msg(writer, &forward, ctx.v2).await {
        warn!(error = %e, "Failed to write NatHoleReport to visitor: {}", e);
    }
}

/// Handle NatHoleSidOnWorkConn: deliver a NatHoleSid to the provider on a
/// pooled work connection, or queue + ReqWorkConn if pool is empty.
pub(crate) async fn handle_sid_on_work_conn<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    sid: String,
    proxy_name: String,
) -> Result<(), ()> {
    debug!(sid = %sid, proxy_name = %proxy_name, "Sending NatHoleSid {} for proxy {} to provider on work conn", sid, proxy_name);
    if let Some(entry) = ctl.work_pool.pop_front() {
        let mut work_conn = entry.conn;
        ctx.state.pool.hits.fetch_add(1, Ordering::Relaxed);
        ctx.pool_stats
            .pool_size
            .store(ctl.work_pool.len() as i64, Ordering::Relaxed);
        // Look up proxy flags for StartWorkConn (encryption/compression propagation)
        let (use_enc, use_comp, sk) = ctx
            .state
            .proxy_manager
            .get(&proxy_name)
            .await
            .map(|p| (p.use_encryption, p.use_compression, p.sk.clone()))
            .unwrap_or((false, false, None));
        pool::write_start_work_conn_with_nat_hole_sid(
            &mut work_conn,
            &pool::NatHoleWorkConnParams {
                proxy_name: &proxy_name,
                use_enc,
                use_comp,
                sk: sk.as_deref(),
                sid: &sid,
                v2: ctx.v2,
                context: " on work conn",
            },
        )
        .await;
        // Replenish the work connection pool: after consuming a pooled
        // work conn, tell the client to send a replacement.
        // Matches Go frp v0.70 GetWorkConn behavior (server/control.go:264).
        if let Err(e) = write_ctl_msg(
            writer,
            &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
            ctx.v2,
        )
        .await
        {
            warn!(error = %e, "Failed to send ReqWorkConn for NatHoleSid pool replenish: {}", e);
        }
        // Connection consumed — Go frp doesn't reuse after NatHoleSid.
        drop(work_conn);
    } else {
        ctx.state.pool.misses.fetch_add(1, Ordering::Relaxed);
        // No pooled work conn — request one, queue sid.
        debug!(sid = %sid, "No pooled work conn for NatHoleSid {}, requesting via ReqWorkConn", sid);
        if let Err(e) = write_ctl_msg(
            writer,
            &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
            ctx.v2,
        )
        .await
        {
            warn!(error = %e, "Failed to send ReqWorkConn for NatHoleSid: {}", e);
        }
        ctl.pending_nat_hole_sids
            .push_back((sid, proxy_name, Instant::now()));
    }
    Ok(())
}

/// Forward a VNet packet to the client via the control channel.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_packet_forward<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    proxy_name: Arc<str>,
    data: Arc<str>,
) {
    let pkt = FrpMessage::VnetPacket(msg::VnetPacket {
        proxy_name: proxy_name.to_string(),
        data: data.to_string(),
    });
    if let Err(e) = write_ctl_msg(writer, &pkt, ctx.v2).await {
        warn!(error = %e, "Failed to forward VnetPacket: {}", e);
    }
}

/// Forward a VNet route advertisement to the client via the control channel.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_route_advertise_forward<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    adv: msg::VnetRouteAdvertise,
) {
    let forward = FrpMessage::VnetRouteAdvertise(adv);
    if let Err(e) = write_ctl_msg(writer, &forward, ctx.v2).await {
        warn!(error = %e, "Failed to forward VnetRouteAdvertise: {}", e);
    }
}

/// Forward a VNet route removal to the client via the control channel.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_route_remove_forward<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    rem: msg::VnetRouteRemove,
) {
    let forward = FrpMessage::VnetRouteRemove(rem);
    if let Err(e) = write_ctl_msg(writer, &forward, ctx.v2).await {
        warn!(error = %e, "Failed to forward VnetRouteRemove: {}", e);
    }
}

// ── FrpMessage handlers ─────────────────────────────────────────────

/// Handle NatHoleClient from the provider: forward to NAT hole coordinator.
pub(crate) async fn handle_nat_hole_client(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    client_msg: msg::NatHoleClient,
) {
    debug!(
        transaction_id = %client_msg.transaction_id,
        mapped_addrs = ?client_msg.mapped_addrs,
        "Received NatHoleClient from provider: txn={}, addrs={:?}",
        client_msg.transaction_id, client_msg.mapped_addrs
    );
    ctx.state.xtcp.nat_hole.handle_client(client_msg).await;
}

/// Handle NatHoleSid from the provider: relay the SID to the visitor.
pub(crate) async fn handle_nat_hole_sid(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    sid_msg: msg::NatHoleSid,
) {
    debug!(sid = ?sid_msg.sid, "Received NatHoleSid from provider: {:?}", sid_msg.sid);
    if let Some(ref sid) = sid_msg.sid {
        // Try control-channel path first (Go frp compat).
        if ctx.state.xtcp.nat_hole.forward_sid_via_ctl(sid).await {
            debug!(sid = %sid, "Forwarded NatHoleSid via control channel for {}", sid);
        } else if let Some(mut accept_writer) = ctx.state.xtcp.nat_hole.take_writer(sid).await {
            // Fallback: accept-loop writer path
            let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                sid: Some(sid.clone()),
                ..Default::default()
            });
            if write_ctl_msg(&mut accept_writer, &forward, ctx.v2)
                .await
                .is_ok()
            {
                debug!(sid = %sid, "Forwarded NatHoleSid to visitor for session {}", sid);
            } else {
                warn!(sid = %sid, "Failed to write NatHoleSid to visitor for session {}", sid);
            }
            ctx.state
                .xtcp
                .nat_hole
                .return_writer(sid, accept_writer)
                .await;
        } else {
            warn!(sid = %sid, "NatHoleSid for unknown session {}", sid);
        }
    }
}

/// Handle NatHoleResp from the provider: relay to visitor.
pub(crate) async fn handle_nat_hole_resp(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    resp_msg: msg::NatHoleResp,
) {
    debug!(transaction_id = %resp_msg.transaction_id, error = ?resp_msg.error, candidate_addrs = ?resp_msg.candidate_addrs, "Received NatHoleResp from provider: txn={}, error={:?}, candidates={:?}",
        resp_msg.transaction_id, resp_msg.error, resp_msg.candidate_addrs);
    // Relay provider's NAT hole response to visitor.
    // Go frp XTCP compat: visitor needs provider's candidate addresses
    // for TCP simultaneous open.
    let tid = &resp_msg.transaction_id;
    // Try accept-writer path first (cheap: take_writer takes &str, no clones needed).
    // A session has either a writer OR a ctl_tx (never both), so the order
    // doesn't change behavior — exactly one path will succeed.
    if let Some(mut accept_writer) = ctx.state.xtcp.nat_hole.take_writer(tid).await {
        let forward = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: tid.clone(),
            error: resp_msg.error.clone(),
            sid: resp_msg.sid.clone(),
            protocol: resp_msg.protocol.clone(),
            candidate_addrs: resp_msg.candidate_addrs.clone(),
            assisted_addrs: resp_msg.assisted_addrs.clone(),
            detect_behavior: resp_msg.detect_behavior.clone(),
        }));
        let _ = write_ctl_msg(&mut accept_writer, &forward, ctx.v2).await;
        ctx.state
            .xtcp
            .nat_hole
            .return_writer(tid, accept_writer)
            .await;
    } else if ctx
        .state
        .xtcp
        .nat_hole
        .forward_nat_hole_resp_via_ctl(
            tid,
            resp_msg.error.clone(),
            resp_msg.sid.clone(),
            resp_msg.protocol.clone(),
            resp_msg.candidate_addrs.clone(),
            resp_msg.assisted_addrs.clone(),
            resp_msg.detect_behavior.clone(),
        )
        .await
    {
        debug!(tid = %tid, "Forwarded NatHoleResp via control channel for {}", tid);
    } else {
        warn!(tid = %tid, "NatHoleResp for unknown session {}", tid);
    }
    // Signal the session so handle_nat_hole_visitor wakes up.
    // Go frp v0.69.1 sends NatHoleResp (type 'm') from provider
    // with its discovered addresses. We store them as if they
    // arrived via NatHoleClient so the accept-loop path can
    // build the combined NatHoleResp for both sides.
    ctx.state
        .xtcp
        .nat_hole
        .handle_client(msg::NatHoleClient {
            sid: resp_msg.sid.clone().or_else(|| Some(tid.clone())),
            transaction_id: tid.clone(),
            proxy_name: String::new(),
            protocol: resp_msg.protocol.clone(),
            mapped_addrs: resp_msg.candidate_addrs.clone(),
            assisted_addrs: resp_msg.assisted_addrs.clone(),
            visitor_addr: None,
        })
        .await;
}

/// Handle NatHoleReport from the provider: forward to visitor + complete session.
pub(crate) async fn handle_nat_hole_report(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    report_msg: msg::NatHoleReport,
) {
    debug!(sid = ?report_msg.sid, "Received NatHoleReport from provider: {:?}", report_msg.sid);
    if let Some(ref sid) = report_msg.sid {
        // Try control-channel path first (Go frp compat).
        if !ctx.state.xtcp.nat_hole.forward_report_via_ctl(sid).await {
            // Fallback: accept-loop writer path
            if let Some(mut accept_writer) = ctx.state.xtcp.nat_hole.take_writer(sid).await {
                let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
                    sid: Some(sid.clone()),
                    success: report_msg.success,
                });
                let _ = write_ctl_msg(&mut accept_writer, &forward, ctx.v2).await;
            }
        }
        ctx.state.xtcp.nat_hole.complete(sid).await;
    }
}

/// Handle NewVisitorConn on the control channel: visitor registration with auth.
pub(crate) async fn handle_new_visitor_conn<W: AsyncWriteExt + Unpin>(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    nvc: msg::NewVisitorConn,
    login_user: &str,
) {
    debug!(proxy_name = %nvc.proxy_name, "NewVisitorConn on control channel: proxy='{}'", nvc.proxy_name);
    // Visitor registration on the control connection.
    // Rust frpc sends NewVisitorConn on control before sending
    // NatHoleVisitor for XTCP hole punching. Go frps v0.69.1
    // responds with ReqWorkConn but we send NewVisitorConnResp
    // with no error — the visitor just needs acknowledgment.
    let sign_key = nvc.sign_key.unwrap_or_default();
    let timestamp = nvc.timestamp.unwrap_or(0);

    // Validate timestamp freshness (replay attack prevention).
    let auth_timeout = ctx
        .state
        .reloadable
        .read_ok()
        .auth_cfg
        .authentication_timeout;
    let ts_fresh = frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout);

    // Validate proxy exists and sign_key matches.
    // Uses constant-time comparison (verify_token) instead of
    // plain string == to prevent timing side-channel attacks.
    let ok = if let Some(proxy_info) = ctx.state.proxy_manager.get(&nvc.proxy_name).await {
        // allow_users check on control channel: match Path A
        // (accept loop) semantics. Empty = owner-only (Go frp compat);
        // if both owner and visitor have no user (empty string),
        // they are the same identity and access is allowed.
        let user_ok = crate::handlers::visitor_user_allowed(
            login_user,
            &proxy_info.user,
            &proxy_info.allow_users,
        );
        if !user_ok {
            warn!(proxy_name = %nvc.proxy_name, "NewVisitorConn on ctl: user denied for proxy '{}'", nvc.proxy_name);
            false
        } else if let Some(ref sk) = proxy_info.sk {
            if sk.is_empty() {
                true // No sk — allow without auth
            } else if ts_fresh.is_err() {
                warn!(proxy_name = %nvc.proxy_name, "NewVisitorConn on ctl: timestamp stale for proxy '{}'", nvc.proxy_name);
                false
            } else {
                frp_core::auth::verify_token(sk, timestamp, &sign_key)
            }
        } else {
            true // No sk configured
        }
    } else {
        // Without ProxyInfo the owner/allow_users policy is unknown. A shared
        // secret alone is not an authenticated user identity, so fail closed.
        false
    };

    if ok {
        info!(proxy_name = %nvc.proxy_name, "Visitor '{}' registered on control channel for proxy '{}'",
            nvc.proxy_name, nvc.proxy_name);
        // Go frps v0.69.1 compat: respond with ReqWorkConn.
        // Rust frpc control.rs register_visitor() treats
        // ReqWorkConn as success (just like Go frps does).
        let rwc = FrpMessage::ReqWorkConn(msg::ReqWorkConn {});
        let _ = write_ctl_msg(writer, &rwc, ctx.v2).await;
    } else {
        warn!(proxy_name = %nvc.proxy_name, "NewVisitorConn auth failed on control channel for proxy '{}'",
            nvc.proxy_name);
        let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
            proxy_name: nvc.proxy_name.clone(),
            error: Some("auth failed".into()),
        });
        let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
    }
}

/// Handle NatHoleVisitor on the control channel: full auth + session creation
/// + spawn NAT analysis task.
#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_nat_hole_visitor_on_ctl<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    _ctl: &mut ControlState,
    writer: &mut W,
    nhv: msg::NatHoleVisitor,
    login_user: &str,
) -> Result<(), ()> {
    debug!(proxy_name = %nhv.proxy_name, transaction_id = %nhv.transaction_id, "NatHoleVisitor on control channel: proxy='{}', txn='{}'",
        nhv.proxy_name, nhv.transaction_id);
    let transaction_id = nhv.transaction_id.clone();
    let proxy_name = nhv.proxy_name.clone();

    // Validate proxy exists and capture info for auth
    let proxy_info = match ctx.state.proxy_manager.get(&proxy_name).await {
        Some(info) => info,
        None => {
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("proxy not found".into()),
                ..Default::default()
            }));
            let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
            return Ok(());
        }
    };

    // --- Auth: verify visitor is authorized to access this proxy ---
    // Go frp v0.70 allowUsers semantics:
    //   - Empty: only the proxy owner can be a visitor
    //   - ["*"]: all authenticated users
    //   - Specific list: only those users
    // Auth is enforced BEFORE pre_check response so Go frp's
    // pre_check permission model is preserved.

    if !crate::handlers::visitor_user_allowed(login_user, &proxy_info.user, &proxy_info.allow_users)
    {
        let error = if proxy_info.allow_users.is_empty() {
            let owner = &proxy_info.user;
            warn!(proxy_name = %proxy_name, user = %login_user, owner = %owner, "NatHoleVisitor: user '{}' not proxy owner '{}' for proxy '{}'", login_user, owner, proxy_name);
            "access denied: owner only"
        } else {
            warn!(proxy_name = %proxy_name, user = %login_user, "NatHoleVisitor: user '{}' not in allow_users for proxy '{}'", login_user, proxy_name);
            "access denied"
        };
        let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: Some(error.into()),
            ..Default::default()
        }));
        let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
        return Ok(());
    }

    // Go frp v0.70 pre_check compat: validate proxy and permissions,
    // return OK without sign_key/timestamp auth or creating a session.
    // Must be BEFORE the sign_key block — precheck skips shared-secret auth.
    // Go frp controller.go only checks m.PreCheck with no extra conditions.
    if nhv.pre_check {
        debug!(proxy_name = %proxy_name, user = %login_user, "NatHoleVisitor pre_check on ctl channel: proxy='{}' OK", proxy_name);
        let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            ..Default::default()
        }));
        let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
        return Ok(());
    }

    // Verify sign_key if the proxy has a shared secret.
    // Uses constant-time comparison (verify_token) and timestamp
    // freshness check to prevent timing side-channel and replay attacks.
    let sign_key = nhv.sign_key.as_deref().unwrap_or("");
    let timestamp = nhv.timestamp.unwrap_or(0);
    if let Some(ref sk) = proxy_info.sk {
        if !sk.is_empty() {
            if sign_key.is_empty() {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: missing sign_key for protected proxy '{}'", proxy_name);
                let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                    transaction_id: transaction_id.clone(),
                    error: Some("auth required".into()),
                    ..Default::default()
                }));
                let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
                return Ok(());
            }
            // Validate timestamp freshness (replay attack prevention).
            let auth_timeout = ctx
                .state
                .reloadable
                .read_ok()
                .auth_cfg
                .authentication_timeout;
            if let Err(freshness_err) =
                frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout)
            {
                warn!(proxy_name = %proxy_name, error = %freshness_err, "NatHoleVisitor on ctl: timestamp stale for proxy '{}'", proxy_name);
                let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                    transaction_id: transaction_id.clone(),
                    error: Some(freshness_err),
                    ..Default::default()
                }));
                let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
                return Ok(());
            }
            if !frp_core::auth::verify_token(sk, timestamp, sign_key) {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor auth failed on ctl for proxy '{}'", proxy_name);
                let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                    transaction_id: transaction_id.clone(),
                    error: Some("auth failed".into()),
                    ..Default::default()
                }));
                let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
                return Ok(());
            }
            debug!(proxy_name = %proxy_name, "NatHoleVisitor auth OK (constant-time) on ctl for proxy '{}'", proxy_name);
        }
    }

    // Look up provider run_id and control channel
    let provider_run_id = match ctx.state.proxy_manager.get_run_id(&proxy_name).await {
        Some(id) => id,
        None => {
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider offline".into()),
                ..Default::default()
            }));
            let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
            return Ok(());
        }
    };

    let provider_ctl = {
        let map = ctx.state.run_id_to_ctl_tx.read().await;
        map.get(&provider_run_id).cloned()
    };
    let provider_ctl = match provider_ctl {
        Some(ctl) => ctl,
        None => {
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider disconnected".into()),
                ..Default::default()
            }));
            let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
            return Ok(());
        }
    };

    // Create session via control-channel path
    let (session, report_rx) = match ctx
        .state
        .xtcp
        .nat_hole
        .create_session_with_ctl(
            transaction_id.clone(),
            proxy_name.clone(),
            nhv.clone(),
            ctx.internal_tx.clone(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "NatHole session creation failed: {}", e);
            return Ok(());
        }
    };

    // Set up notify channel BEFORE sending to provider
    let notify_rx = {
        let mut guard = session.notify_ch.lock().await;
        let (tx, rx) = oneshot::channel();
        *guard = Some(tx);
        rx
    };

    // Send NatHoleSid to provider ON A WORK CONNECTION (Go frp compat).
    if provider_ctl
        .tx
        .try_send(InternalMsg::NatHoleSidOnWorkConn {
            sid: transaction_id.clone(),
            proxy_name: proxy_name.clone(),
        })
        .is_err()
    {
        warn!(provider_run_id = %provider_run_id, "Provider for run_id {} has gone away", provider_run_id);
        ctx.state.xtcp.nat_hole.remove(&transaction_id).await;
        return Ok(());
    }

    // Spawn task for full Go-compat analysis flow.
    // Waits for provider's NatHoleClient on control, runs NAT analysis,
    // and sends NatHoleResp to both sides.
    let nat_hole = ctx.state.xtcp.nat_hole.clone();
    let visitor_tx = ctx.internal_tx.clone();
    let provider_tx = provider_ctl.tx.clone();
    let tid = transaction_id.clone();
    let visitor_msg = nhv.clone();
    let _proxy = proxy_name.clone();
    tokio::spawn(async move {
        // Wait for provider's NatHoleClient with STUN addresses
        let client_received =
            tokio::time::timeout(Duration::from_secs(NAT_HOLE_TIMEOUT), notify_rx).await;

        if client_received.is_err() {
            warn!(tid = %tid, "NatHole ctl session {}: timeout waiting for provider", tid);
            nat_hole.remove(&tid).await;
            return;
        }

        let client_msg_opt = {
            let session_ref = nat_hole.sessions.read().await;
            if let Some(s) = session_ref.get(&tid) {
                s.client_msg.lock().await.take()
            } else {
                None
            }
        };
        let client_msg = match client_msg_opt {
            Some(m) => m,
            None => {
                warn!(tid = %tid, "NatHole ctl session {}: no client msg", tid);
                nat_hole.remove(&tid).await;
                return;
            }
        };

        let client_mapped = client_msg.mapped_addrs.unwrap_or_default();
        let client_assisted = client_msg.assisted_addrs.unwrap_or_default();
        let visitor_mapped = visitor_msg.mapped_addrs.unwrap_or_default();
        let visitor_assisted = visitor_msg.assisted_addrs.unwrap_or_default();

        // Classify NAT features
        use crate::nathole::classify;
        use crate::nathole::controller as nathole_ctrl;
        let visitor_local_ips = classify::parse_ips(&visitor_assisted);
        let client_local_ips = classify::parse_ips(&client_assisted);
        debug!(
            tid = %tid,
            v_mapped = ?visitor_mapped,
            v_assisted = ?visitor_assisted,
            c_mapped = ?client_mapped,
            "XTCP: classify inputs"
        );
        let v_feature = classify::classify_nat_feature(&visitor_mapped, &visitor_local_ips).ok();
        let c_feature = classify::classify_nat_feature(&client_mapped, &client_local_ips).ok();
        debug!(tid = %tid, v_feature = ?v_feature, c_feature = ?c_feature, "XTCP: classify results");

        // Run analysis and build responses
        let analysis_index;
        let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
            let key = nathole_ctrl::gen_analysis_key(cf, vf, &client_mapped, &visitor_mapped);
            {
                let sessions = nat_hole.sessions.read().await;
                if let Some(s) = sessions.get(&tid) {
                    *s.analysis_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.clone());
                }
            }
            let (mode, index, c_behavior, v_behavior) =
                nat_hole.analyzer.get_recommend_behaviors(&key, cf, vf);
            analysis_index = Some(index);

            let extra_timeout =
                if c_behavior.listen_random_ports > 0 || v_behavior.listen_random_ports > 0 {
                    30000
                } else {
                    0
                };
            let timeout_ms =
                c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000 + extra_timeout;
            let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
            let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;

            let v_resp =
                nathole_ctrl::build_nat_hole_response(nathole_ctrl::NatHoleResponseParams {
                    transaction_id: tid.clone(),
                    sid: tid.clone(),
                    protocol: visitor_msg.protocol.clone(),
                    mode,
                    candidate_addrs: client_mapped.clone(),
                    assisted_addrs: client_assisted.clone(),
                    behavior: v_behavior,
                    read_timeout_ms: v_read_timeout,
                    ports_difference: cf.ports_difference,
                });
            // Use visitor's protocol in c_resp so the provider
            // knows which transport to use (Go frp compat:
            // provider reads NatHoleResp.protocol to decide
            // KCP vs TCP). If empty, Go falls back to TCP
            // which is incompatible with visitor's KCP.
            let protocol_for_provider = visitor_msg
                .protocol
                .clone()
                .or_else(|| client_msg.protocol.clone());
            let c_resp =
                nathole_ctrl::build_nat_hole_response(nathole_ctrl::NatHoleResponseParams {
                    transaction_id: client_msg.transaction_id.clone(),
                    sid: tid.clone(),
                    protocol: protocol_for_provider,
                    mode,
                    candidate_addrs: visitor_mapped.clone(),
                    assisted_addrs: visitor_assisted.clone(),
                    behavior: c_behavior,
                    read_timeout_ms: c_read_timeout,
                    ports_difference: vf.ports_difference,
                });
            (v_resp, Some(c_resp))
        } else {
            analysis_index = None;
            let v_resp = msg::NatHoleResp {
                transaction_id: tid.clone(),
                error: None,
                sid: Some(tid.clone()),
                protocol: visitor_msg.protocol.clone(),
                candidate_addrs: if client_mapped.is_empty() {
                    None
                } else {
                    Some(client_mapped)
                },
                assisted_addrs: if client_assisted.is_empty() {
                    None
                } else {
                    Some(client_assisted)
                },
                ..Default::default()
            };
            let protocol_for_provider2 = visitor_msg
                .protocol
                .clone()
                .or_else(|| client_msg.protocol.clone());
            let c_resp = msg::NatHoleResp {
                transaction_id: client_msg.transaction_id.clone(),
                error: None,
                sid: Some(tid.clone()),
                protocol: protocol_for_provider2,
                candidate_addrs: if visitor_mapped.is_empty() {
                    None
                } else {
                    Some(visitor_mapped)
                },
                assisted_addrs: if visitor_assisted.is_empty() {
                    None
                } else {
                    Some(visitor_assisted)
                },
                ..Default::default()
            };
            (v_resp, Some(c_resp))
        };

        // Store v_resp, NAT features, and selected_index on
        // session for analyzer feedback in handle_report
        // (C15, C16). The accept-loop path stores these in
        // handlers.rs; the Go frp compat control-path did not,
        // so report_success always used index=0 with no features.
        {
            let sessions = nat_hole.sessions.read().await;
            if let Some(s) = sessions.get(&tid) {
                *s.v_resp.lock().await = Some(v_resp.clone());
                *s.selected_index.lock().await = analysis_index;
                if let Some(ref vf) = v_feature {
                    *s.v_nat_feature.lock().await = Some(vf.clone());
                }
                if let Some(ref cf) = c_feature {
                    *s.c_nat_feature.lock().await = Some(cf.clone());
                }
            }
        }

        // Go frp dev compat: if the visitor has the "sender" role, wait 1s
        // before sending NatHoleResp. This gives the sender time to complete
        // STUN and start sending detect messages before the receiver gets
        // the response and starts detecting. Without this delay, hole punch
        // may fail in certain NAT configurations.
        if v_resp
            .detect_behavior
            .as_ref()
            .is_some_and(|db| db.role.as_deref() == Some("sender"))
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Send NatHoleResp to visitor via control channel.
        // send().await: backpressure is correct — silently
        // dropping NatHoleResp would permanently hang the
        // visitor (protocol-critical message).
        if let Err(e) = visitor_tx
            .send(InternalMsg::WriteNatHoleResp {
                transaction_id: v_resp.transaction_id.clone(),
                error: v_resp.error.clone(),
                sid: v_resp.sid.clone(),
                protocol: v_resp.protocol.clone(),
                candidate_addrs: v_resp.candidate_addrs.clone(),
                assisted_addrs: v_resp.assisted_addrs.clone(),
                detect_behavior: v_resp.detect_behavior.clone(),
            })
            .await
        {
            warn!(error = %e, "failed to send NatHoleResp to visitor via control channel");
        }

        // Go frp dev compat: if the provider has the "sender" role, wait 1s
        // before sending NatHoleResp (see comment above for rationale).
        if let Some(ref cr) = c_resp {
            if cr
                .detect_behavior
                .as_ref()
                .is_some_and(|db| db.role.as_deref() == Some("sender"))
            {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        // Send NatHoleResp to provider via control channel
        if let Some(ref cr) = c_resp {
            if let Err(e) = provider_tx
                .send(InternalMsg::WriteNatHoleResp {
                    transaction_id: cr.transaction_id.clone(),
                    error: cr.error.clone(),
                    sid: cr.sid.clone(),
                    protocol: cr.protocol.clone(),
                    candidate_addrs: cr.candidate_addrs.clone(),
                    assisted_addrs: cr.assisted_addrs.clone(),
                    detect_behavior: cr.detect_behavior.clone(),
                })
                .await
            {
                warn!(error = %e, "failed to send NatHoleResp to provider via control channel");
            }
        }

        // Wait for report.
        // Go frp v0.69.1 compat: sleep ReadTimeoutMs + 30000ms after sending
        // NatHoleResp to keep the session alive for hole-punch completion and
        // NatHoleReport. Use a dynamic timeout from the provider's detect_behavior.
        let wait_ms = c_resp
            .as_ref()
            .and_then(|cr| cr.detect_behavior.as_ref())
            .map(|db| (db.read_timeout_ms.max(0) as u64) + 30000)
            .unwrap_or(30000);
        match tokio::time::timeout(Duration::from_millis(wait_ms), report_rx).await {
            Ok(Ok(_)) => debug!(tid = %tid, "NatHole ctl session {}: completed", tid),
            Ok(Err(_)) | Err(_) => {
                debug!(tid = %tid, "NatHole ctl session {}: cleanup", tid);
                nat_hole.remove(&tid).await;
            }
        }
    });

    Ok(())
}

// ── VNet FrpMessage handlers ────────────────────────────────────────

/// Store a VNet route advertisement.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_route_advertise(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    adv: msg::VnetRouteAdvertise,
) {
    let vn = adv.virtual_net.clone().unwrap_or_default();
    let key = (vn.clone(), adv.subnet.clone());
    ctx.state
        .vnet_routes
        .write()
        .await
        .insert(key, (ctx.run_id.clone(), adv.proxy_name.clone()));
    info!(
        proxy_name = %adv.proxy_name,
        subnet = %adv.subnet,
        "vnet route advertised: {} → {}",
        adv.subnet, adv.proxy_name
    );
    ctx.state
        .broadcast_vnet_route_advertise(&ctx.run_id, &adv)
        .await;
}

/// Look up target proxy and forward a VNet packet via internal message.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_packet(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    pkt: msg::VnetPacket,
) {
    // Isolation: the packet's source run_id must be in the target route's
    // virtual net, otherwise drop it (different virtual nets are isolated).
    if !ctx
        .state
        .vnet_packet_source_allowed(&ctx.run_id, &pkt.proxy_name)
        .await
    {
        debug!(
            run_id = %ctx.run_id,
            proxy_name = %pkt.proxy_name,
            "vnet packet dropped: source run_id is not in the target route's virtual net"
        );
        return;
    }
    // Look up the target control connection and forward the packet.
    //
    // Proxy path: `proxy_manager.get` returns an `Arc<ProxyInfo>` whose run_id
    // we borrow directly (no String clone) to index `run_id_to_ctl_tx`. If the
    // same client owns a registered proxy it handles the packet locally and
    // does not need a control-conn echo. Visitor path: not a proxy, so resolve
    // virtual_net visitor routes advertised over the control connection
    // (visitor name → advertising client) and deliver the packet back to that
    // client's control connection. The resolution is scoped to virtual nets
    // the source participates in, so it agrees with the isolation check above
    // — a same-named visitor in a different vnet is never chosen.
    if let Some(target_info) = ctx.state.proxy_manager.get(&pkt.proxy_name).await {
        if target_info.run_id != ctx.run_id {
            if let Some(ctl_tx) = ctx
                .state
                .run_id_to_ctl_tx
                .read()
                .await
                .get(&target_info.run_id)
            {
                let _ = ctl_tx.tx.try_send(InternalMsg::VnetPacketForward {
                    proxy_name: Arc::from(pkt.proxy_name.as_str()),
                    data: Arc::from(pkt.data.as_str()),
                });
            }
        }
    } else {
        let routes = ctx.state.vnet_routes.read().await;
        if let Some(target_run_id) =
            vnet_visitor_route_target_run_id(&routes, &ctx.run_id, &pkt.proxy_name)
        {
            if let Some(ctl_tx) = ctx.state.run_id_to_ctl_tx.read().await.get(&target_run_id) {
                let _ = ctl_tx.tx.try_send(InternalMsg::VnetPacketForward {
                    proxy_name: Arc::from(pkt.proxy_name.as_str()),
                    data: Arc::from(pkt.data.as_str()),
                });
            }
        }
    }
}

/// Remove a VNet route.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_route_remove(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    rem: msg::VnetRouteRemove,
) {
    let vn = rem.virtual_net.clone().unwrap_or_default();
    let removed = {
        let mut routes = ctx.state.vnet_routes.write().await;
        // Only the run_id that advertised the route may remove it. A stale or
        // replayed remove from an older control must not clobber a newer one.
        let existed = routes.iter().any(|((vn_k, _), (run_id, name))| {
            run_id == &ctx.run_id && vn_k == &vn && name == &rem.proxy_name
        });
        routes.retain(|(vn_k, _), (run_id, name)| {
            !(run_id == &ctx.run_id && vn_k == &vn && name == &rem.proxy_name)
        });
        existed
    };
    if !removed {
        debug!(
            proxy_name = %rem.proxy_name,
            "vnet route remove ignored: no matching route for this run_id"
        );
        return;
    }
    info!(proxy_name = %rem.proxy_name, "vnet route removed: {}", rem.proxy_name);
    ctx.state
        .broadcast_vnet_route_remove(&ctx.run_id, &rem)
        .await;
}

/// Resolve the run_id that advertised `proxy_name` as a virtual_net visitor
/// route reachable from `source_run_id`. Returns `None` when no such route
/// exists. The candidate route must live in a virtual net the source
/// participates in (the source owns at least one route in that vnet) — this
/// mirrors `vnet_packet_source_allowed` so the isolation check and the actual
/// target resolution can never disagree. Same-named visitors in other virtual
/// nets are invisible to the source.
#[cfg(feature = "vnet")]
fn vnet_visitor_route_target_run_id(
    routes: &std::collections::HashMap<(String, String), (String, String)>,
    source_run_id: &str,
    proxy_name: &str,
) -> Option<String> {
    // Pick deterministically: collect every qualifying candidate (the source
    // owns a route in the candidate's vnet) and take the lexicographically
    // smallest vnet. HashMap iteration order is process-dependent, so a plain
    // `.find()` would make the choice nondeterministic when the source
    // participates in several vnets that each advertise a same-named visitor.
    routes
        .iter()
        .filter(|((vn, _), (_, name))| {
            name == proxy_name
                && routes
                    .iter()
                    .any(|((vn2, _), (rid2, _))| vn2 == vn && rid2 == source_run_id)
        })
        .map(|((vn, _), (run_id, _))| (vn.clone(), run_id.clone()))
        .min()
        .map(|(_, run_id)| run_id)
}

#[cfg(test)]
mod identity_binding_tests {
    #[test]
    fn oidc_keeps_claimed_user_a_even_when_subject_is_b() {
        let identity = super::super::login::authenticated_user(Some("A"), Some("B"));
        assert_eq!(identity, "A");
        assert!(crate::handlers::visitor_user_allowed(
            &identity,
            "A",
            &["A".to_string()]
        ));
        assert!(crate::handlers::visitor_user_allowed(&identity, "A", &[]));
    }

    #[test]
    fn oidc_does_not_substitute_subject_a_for_claimed_user_b() {
        let identity = super::super::login::authenticated_user(Some("B"), Some("A"));
        assert_eq!(identity, "B");
        assert!(!crate::handlers::visitor_user_allowed(
            &identity,
            "owner",
            &["A".to_string()]
        ));
    }

    #[test]
    fn oidc_without_claimed_user_keeps_empty_go_identity() {
        let identity = super::super::login::authenticated_user(None, Some("A"));
        assert_eq!(identity, "");
        assert!(crate::handlers::visitor_user_allowed(&identity, "", &[]));
        assert!(!crate::handlers::visitor_user_allowed(
            &identity,
            "owner",
            &[]
        ));
    }

    #[test]
    fn token_auth_preserves_claimed_user_compatibility() {
        let identity = super::super::login::authenticated_user(Some("A"), None);
        assert_eq!(identity, "A");
        assert!(crate::handlers::visitor_user_allowed(&identity, "A", &[]));
        assert!(crate::handlers::visitor_user_allowed(
            &identity,
            "owner",
            &["A".to_string()]
        ));
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn vnet_visitor_route_resolves_advertising_run_id() {
        use std::collections::HashMap;

        let mut routes = HashMap::new();
        routes.insert(
            (String::new(), "10.0.0.1/32".to_string()),
            ("run-a".to_string(), "vnet-visitor".to_string()),
        );
        routes.insert(
            (String::new(), "10.0.0.0/24".to_string()),
            ("run-b".to_string(), "vnet-proxy-b".to_string()),
        );

        // The source owns a route in the default vnet, so same-vnet visitors
        // resolve; the target route itself counts as the source's membership.
        assert_eq!(
            super::vnet_visitor_route_target_run_id(&routes, "run-a", "vnet-visitor"),
            Some("run-a".to_string())
        );
        // Route advertisements from regular vnet proxies also appear in the
        // table; proxy_manager remains the primary resolver for those names.
        assert_eq!(
            super::vnet_visitor_route_target_run_id(&routes, "run-b", "vnet-proxy-b"),
            Some("run-b".to_string())
        );
        // A source with no route in the visitor's vnet cannot resolve it.
        assert_eq!(
            super::vnet_visitor_route_target_run_id(&routes, "run-z", "vnet-visitor"),
            None
        );
        assert_eq!(
            super::vnet_visitor_route_target_run_id(&routes, "run-a", "missing"),
            None
        );
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn vnet_visitor_route_same_name_other_vnet_not_resolved() {
        use std::collections::HashMap;

        let mut routes = HashMap::new();
        // Same visitor name in two virtual nets, advertised by two run_ids.
        routes.insert(
            ("vnet-a".to_string(), "10.0.0.1/32".to_string()),
            ("run-a".to_string(), "visitor".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.0.0.1/32".to_string()),
            ("run-b".to_string(), "visitor".to_string()),
        );
        // run-c participates only in vnet-a.
        routes.insert(
            ("vnet-a".to_string(), "10.99.0.0/24".to_string()),
            ("run-c".to_string(), "peer-c".to_string()),
        );

        // run-c must resolve the vnet-a visitor (run-a), never the vnet-b one.
        assert_eq!(
            super::vnet_visitor_route_target_run_id(&routes, "run-c", "visitor"),
            Some("run-a".to_string())
        );
        // A client with no route in either vnet cannot resolve it at all.
        assert_eq!(
            super::vnet_visitor_route_target_run_id(&routes, "run-z", "visitor"),
            None
        );
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn vnet_visitor_route_deterministic_when_source_in_multiple_vnets() {
        use std::collections::HashMap;

        let mut routes = HashMap::new();
        // Same visitor name in two virtual nets, advertised by two run_ids.
        routes.insert(
            ("vnet-a".to_string(), "10.0.0.1/32".to_string()),
            ("run-a".to_string(), "visitor".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.0.0.1/32".to_string()),
            ("run-b".to_string(), "visitor".to_string()),
        );
        // run-c participates in both vnets, so both visitors are reachable.
        routes.insert(
            ("vnet-a".to_string(), "10.99.0.0/24".to_string()),
            ("run-c".to_string(), "peer-a".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.99.0.0/24".to_string()),
            ("run-c".to_string(), "peer-b".to_string()),
        );

        // Both candidates qualify; the result must not depend on HashMap
        // iteration order. The lexicographically smallest vnet wins
        // ("vnet-a" < "vnet-b" → run-a). Repeatedly asserting the same value
        // guards the determinism guarantee.
        for _ in 0..25 {
            assert_eq!(
                super::vnet_visitor_route_target_run_id(&routes, "run-c", "visitor"),
                Some("run-a".to_string())
            );
        }
    }
}

#[cfg(all(test, feature = "vnet"))]
mod vnet_route_tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Arc;
    use std::time::Instant as StdInstant;

    use tokio::sync::mpsc;
    use tokio::time::{Duration, Instant};

    use frp_core::msg::{self, FrpMessage};
    use frp_core::protocol::read_msg_v1;

    use crate::control::{ControlContext, ControlState};
    use crate::state::{AppState, ControlTx, InternalMsg, PoolStats};

    fn test_state() -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
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
            168,
            true,
            0,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    async fn insert_control(state: &Arc<AppState>, run_id: &str) -> mpsc::Receiver<InternalMsg> {
        let (tx, rx) = mpsc::channel(16);
        let mut map = state.run_id_to_ctl_tx.write().await;
        map.insert(
            run_id.to_string(),
            ControlTx {
                tx,
                client_addr: None,
                login_time: StdInstant::now(),
                login_time_unix: 0,
                pool_stats: Arc::new(PoolStats::default()),
                user: String::new(),
                control_id: 1,
            },
        );
        rx
    }

    fn test_context(state: &Arc<AppState>, run_id: &str) -> (ControlContext, ControlState) {
        let (_, run_mu_guard) = state.get_run_mu(run_id);
        let (internal_tx, _internal_rx) = mpsc::channel(16);
        let ctx = ControlContext {
            state: Arc::clone(state),
            pool_stats: Arc::new(PoolStats::default()),
            reloadable: state.reloadable.read().unwrap().clone(),
            v2: false,
            run_id: run_id.to_string(),
            control_id: 1,
            pool_cap: 0,
            internal_tx,
            peer: None,
            authenticated_user: String::new(),
            _run_mu_guard: run_mu_guard,
        };
        let ctl = ControlState {
            shutting_down: false,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool: VecDeque::new(),
            pending_requests: VecDeque::new(),
            pending_udp: VecDeque::new(),
            pending_nat_hole_sids: VecDeque::new(),
            listener_handles: HashMap::new(),
            udp_sockets: HashMap::new(),
            udp_local_to_proxy: HashMap::new(),
            udp_proxy_flags: HashMap::new(),
            last_ping: Instant::now(),
        };
        (ctx, ctl)
    }

    fn assert_advertise_eq(actual: &msg::VnetRouteAdvertise, expected: &msg::VnetRouteAdvertise) {
        assert_eq!(actual.proxy_name, expected.proxy_name);
        assert_eq!(actual.subnet, expected.subnet);
        assert_eq!(actual.virtual_net, expected.virtual_net);
    }

    fn assert_remove_eq(actual: &msg::VnetRouteRemove, expected: &msg::VnetRouteRemove) {
        assert_eq!(actual.proxy_name, expected.proxy_name);
        assert_eq!(actual.virtual_net, expected.virtual_net);
    }

    #[tokio::test]
    async fn advertise_is_recorded_and_forwarded_to_other_online_clients() {
        let state = test_state();
        let mut sender_rx = insert_control(&state, "run-a").await;
        let mut peer_rx = insert_control(&state, "run-b").await;
        let (ctx, mut ctl) = test_context(&state, "run-a");
        let adv = msg::VnetRouteAdvertise {
            proxy_name: "vnet-visitor".to_string(),
            subnet: "2001:db8::1/128".to_string(),
            virtual_net: Some("vnet-a".to_string()),
        };

        // Pre-seed run-b with a vnet-a route so the broadcast filter (which
        // only forwards to controls that have a route in the same virtual
        // net) considers run-b a peer; otherwise peer_rx would block forever.
        {
            let mut routes = state.vnet_routes.write().await;
            routes.insert(
                ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
                ("run-b".to_string(), "peer-b".to_string()),
            );
        }

        super::handle_vnet_route_advertise(&ctx, &mut ctl, &mut tokio::io::sink(), adv.clone())
            .await;

        let routes = state.vnet_routes.read().await;
        assert_eq!(
            routes.get(&("vnet-a".to_string(), "2001:db8::1/128".to_string())),
            Some(&("run-a".to_string(), "vnet-visitor".to_string()))
        );
        drop(routes);

        match tokio::time::timeout(Duration::from_secs(5), peer_rx.recv()).await {
            Ok(Some(InternalMsg::VnetRouteAdvertiseForward { msg })) => {
                assert_advertise_eq(&msg, &adv);
            }
            other => panic!("expected forwarded advertise, got {:?}", other),
        }
        assert!(sender_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn route_remove_is_forwarded_to_other_online_clients() {
        let state = test_state();
        let mut sender_rx = insert_control(&state, "run-a").await;
        let mut peer_rx = insert_control(&state, "run-b").await;
        let (ctx, mut ctl) = test_context(&state, "run-a");
        {
            let mut routes = state.vnet_routes.write().await;
            routes.insert(
                ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
                ("run-a".to_string(), "vnet-visitor".to_string()),
            );
            routes.insert(
                ("vnet-a".to_string(), "2001:db8::/64".to_string()),
                ("run-a".to_string(), "vnet-visitor".to_string()),
            );
            routes.insert(
                ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
                ("run-b".to_string(), "peer-proxy".to_string()),
            );
            // Same proxy name advertised by a different run_id must survive
            // run-a's remove (run_id-guarded deletion).
            routes.insert(
                ("vnet-a".to_string(), "10.2.0.0/24".to_string()),
                ("run-b".to_string(), "vnet-visitor".to_string()),
            );
        }
        let rem = msg::VnetRouteRemove {
            proxy_name: "vnet-visitor".to_string(),
            virtual_net: Some("vnet-a".to_string()),
        };

        super::handle_vnet_route_remove(&ctx, &mut ctl, &mut tokio::io::sink(), rem.clone()).await;

        let routes = state.vnet_routes.read().await;
        assert!(routes.iter().all(|((vn, _), (rid, name))| {
            !(vn == "vnet-a" && rid == "run-a" && name == "vnet-visitor")
        }));
        assert!(routes.contains_key(&("vnet-b".to_string(), "10.1.0.0/24".to_string())));
        assert!(
            routes.contains_key(&("vnet-a".to_string(), "10.2.0.0/24".to_string())),
            "run-b's same-named route must not be removed by run-a"
        );
        drop(routes);

        match tokio::time::timeout(Duration::from_secs(5), peer_rx.recv()).await {
            Ok(Some(InternalMsg::VnetRouteRemoveForward { msg })) => {
                assert_remove_eq(&msg, &rem);
            }
            other => panic!("expected forwarded remove, got {:?}", other),
        }
        assert!(sender_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatch_writes_forwarded_route_messages_to_client_writer() {
        let state = test_state();
        let (mut ctx, mut ctl) = test_context(&state, "run-b");
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let adv = msg::VnetRouteAdvertise {
            proxy_name: "vnet-visitor".to_string(),
            subnet: "2001:db8::1/128".to_string(),
            virtual_net: Some("vnet-a".to_string()),
        };

        crate::control::dispatch::dispatch_internal(
            &mut ctx,
            &mut ctl,
            &mut writer,
            InternalMsg::VnetRouteAdvertiseForward { msg: adv.clone() },
        )
        .await
        .unwrap();
        match read_msg_v1(&mut reader).await.unwrap() {
            FrpMessage::VnetRouteAdvertise(forwarded) => assert_advertise_eq(&forwarded, &adv),
            other => panic!("expected advertise frame, got {:?}", other),
        }

        let rem = msg::VnetRouteRemove {
            proxy_name: "vnet-visitor".to_string(),
            virtual_net: Some("vnet-a".to_string()),
        };
        crate::control::dispatch::dispatch_internal(
            &mut ctx,
            &mut ctl,
            &mut writer,
            InternalMsg::VnetRouteRemoveForward { msg: rem.clone() },
        )
        .await
        .unwrap();
        match read_msg_v1(&mut reader).await.unwrap() {
            FrpMessage::VnetRouteRemove(forwarded) => assert_remove_eq(&forwarded, &rem),
            other => panic!("expected remove frame, got {:?}", other),
        }
    }
}
