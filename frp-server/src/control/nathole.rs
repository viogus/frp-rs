//! XTCP NAT hole punch handlers for the control connection select! loop.
//!
//! Handles InternalMsg forwarding (WriteNatHoleSid/Resp/Report, NatHoleSidOnWorkConn,
//! VnetPacketForward) and FrpMessage dispatch (NatHoleClient, NatHoleSid, NatHoleResp,
//! NatHoleReport, NatHoleVisitor, NewVisitorConn) plus VNet route management.

use std::sync::atomic::Ordering;
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
    provider_addr: Option<String>,
) {
    debug!(sid = %sid, "Writing NatHoleSid to visitor via control channel for {}", sid);
    let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
        sid: Some(sid),
        provider_addr,
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
    let forward = FrpMessage::NatHoleReport(msg::NatHoleReport { sid: Some(sid) });
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
    proxy_name: String,
    data: String,
) {
    let pkt = FrpMessage::VnetPacket(msg::VnetPacket { proxy_name, data });
    if let Err(e) = write_ctl_msg(writer, &pkt, ctx.v2).await {
        warn!(error = %e, "Failed to forward VnetPacket: {}", e);
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
        let provider_addr = ctx.peer.as_ref().map(|a| a.to_string());
        // Try control-channel path first (Go frp compat).
        if ctx
            .state
            .xtcp
            .nat_hole
            .forward_sid_via_ctl(sid, provider_addr.clone())
            .await
        {
            debug!(sid = %sid, "Forwarded NatHoleSid via control channel for {}", sid);
        } else if let Some(mut accept_writer) = ctx.state.xtcp.nat_hole.take_writer(sid).await {
            // Fallback: accept-loop writer path
            let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                sid: Some(sid.clone()),
                provider_addr,
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
    // Try control-channel path first.
    if ctx
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
        )
        .await
    {
        debug!(tid = %tid, "Forwarded NatHoleResp via control channel for {}", tid);
    } else if let Some(mut accept_writer) = ctx.state.xtcp.nat_hole.take_writer(tid).await {
        let forward = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: tid.clone(),
            error: resp_msg.error.clone(),
            sid: resp_msg.sid.clone(),
            protocol: resp_msg.protocol.clone(),
            candidate_addrs: resp_msg.candidate_addrs.clone(),
            assisted_addrs: resp_msg.assisted_addrs.clone(),
            ..Default::default()
        }));
        let _ = write_ctl_msg(&mut accept_writer, &forward, ctx.v2).await;
        ctx.state
            .xtcp
            .nat_hole
            .return_writer(tid, accept_writer)
            .await;
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
        let user_ok = if proxy_info.allow_users.is_empty() {
            login_user == proxy_info.user
        } else if proxy_info.allow_users.iter().any(|u| u == "*") {
            true
        } else {
            proxy_info.allow_users.iter().any(|u| u == login_user)
        };
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
        // Race: NewVisitorConn may arrive before proxy_manager
        // registration completes. Fall back to sk_index
        // (populated after successful registration).
        if ts_fresh.is_err() {
            false
        } else {
            let sk_map = ctx.state.xtcp.sk_index.read().await;
            sk_map
                .get(&nvc.proxy_name)
                .is_some_and(|sk_raw| frp_core::auth::verify_token(sk_raw, timestamp, &sign_key))
        }
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

    if proxy_info.allow_users.is_empty() {
        // Empty = proxy owner only (Go frp compat).
        // When both owner and visitor have no user set
        // (default empty string), they are the same
        // identity and access is allowed.
        let owner = &proxy_info.user;
        if login_user != *owner {
            warn!(proxy_name = %proxy_name, user = %login_user, owner = %owner, "NatHoleVisitor: user '{}' not proxy owner '{}' for proxy '{}'", login_user, owner, proxy_name);
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("access denied: owner only".into()),
                ..Default::default()
            }));
            let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
            return Ok(());
        }
    } else if proxy_info.allow_users.iter().any(|u| u == "*") {
        // Wildcard — any authenticated user
    } else if !proxy_info.allow_users.iter().any(|u| u == login_user) {
        warn!(proxy_name = %proxy_name, user = %login_user, "NatHoleVisitor: user '{}' not in allow_users for proxy '{}'", login_user, proxy_name);
        let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: Some("access denied".into()),
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

    // Go frp v0.70 pre_check compat: after auth, return OK without
    // creating a session or notifying the provider.
    if nhv.pre_check && nhv.mapped_addrs.is_none() {
        debug!(proxy_name = %proxy_name, user = %login_user, "NatHoleVisitor pre_check on ctl channel: proxy='{}' OK", proxy_name);
        let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            ..Default::default()
        }));
        let _ = write_ctl_msg(writer, &resp, ctx.v2).await;
        return Ok(());
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
        let v_feature = classify::classify_nat_feature(&visitor_mapped, &[]).ok();
        let c_feature = classify::classify_nat_feature(&client_mapped, &[]).ok();

        // Run analysis and build responses
        let analysis_index;
        let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
            let key = nathole_ctrl::gen_analysis_key(cf, vf);
            let (mode, index, c_behavior, v_behavior) =
                nat_hole.analyzer.get_recommend_behaviors(&key, cf, vf);
            analysis_index = Some(index);

            let timeout_ms = c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000;
            let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
            let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;

            let v_resp = nathole_ctrl::build_nat_hole_response(
                &tid,
                &tid,
                visitor_msg.protocol.clone(),
                mode,
                client_mapped.clone(),
                client_assisted.clone(),
                v_behavior,
                v_read_timeout,
                cf.ports_difference,
            );
            // Use visitor's protocol in c_resp so the provider
            // knows which transport to use (Go frp compat:
            // provider reads NatHoleResp.protocol to decide
            // KCP vs TCP). If empty, Go falls back to TCP
            // which is incompatible with visitor's KCP.
            let protocol_for_provider = visitor_msg
                .protocol
                .clone()
                .or_else(|| client_msg.protocol.clone());
            let c_resp = nathole_ctrl::build_nat_hole_response(
                &client_msg.transaction_id,
                &tid,
                protocol_for_provider,
                mode,
                visitor_mapped.clone(),
                visitor_assisted.clone(),
                c_behavior,
                c_read_timeout,
                vf.ports_difference,
            );
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
            })
            .await
        {
            warn!(error = %e, "failed to send NatHoleResp to visitor via control channel");
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
                })
                .await
            {
                warn!(error = %e, "failed to send NatHoleResp to provider via control channel");
            }
        }

        // Wait for report
        match tokio::time::timeout(Duration::from_secs(30), report_rx).await {
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
}

/// Look up target proxy and forward a VNet packet via internal message.
#[cfg(feature = "vnet")]
pub(crate) async fn handle_vnet_packet(
    ctx: &ControlContext,
    _ctl: &mut ControlState,
    _writer: &mut (impl AsyncWriteExt + Unpin),
    pkt: msg::VnetPacket,
) {
    if let Some(target_info) = ctx.state.proxy_manager.get(&pkt.proxy_name).await {
        let target_run_id = target_info.run_id.clone();
        if target_run_id == ctx.run_id {
            // Same client — no forwarding needed (client handles locally)
            debug!(proxy_name = %pkt.proxy_name, "vnet packet target is self, skipping forward");
        } else if let Some(ctl_tx) = ctx.state.run_id_to_ctl_tx.read().await.get(&target_run_id) {
            let _ = ctl_tx.tx.try_send(InternalMsg::VnetPacketForward {
                proxy_name: pkt.proxy_name.clone(),
                data: pkt.data.clone(),
            });
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
    let mut routes = ctx.state.vnet_routes.write().await;
    routes.retain(|(vn_k, _), (_, name)| !(vn_k == &vn && name == &rem.proxy_name));
    info!(proxy_name = %rem.proxy_name, "vnet route removed: {}", rem.proxy_name);
}
