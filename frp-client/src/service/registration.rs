//! Registration-phase plumbing: `register_proxies` (Phase 4 of one
//! connection attempt) and the two-stage persisted frame reader it drives.
//!
//! Split out of `frp-client/src/service.rs` by the P2 S2 seam as a pure move
//! (every moved line byte-identical). The one non-mechanical edit is the
//! `pub(super)` on `register_proxies`: a private method declared in a child
//! module is not visible to the parent `service` module or to its sibling
//! `service::tests`, which both call it (E0624), and `pub(super)` is the
//! minimum that makes it visible to exactly those callers. This module is a
//! *child* of `service`, which is what lets the `impl Service` block below
//! reach the parent's private fields and methods; it is deployed as a child
//! module rather than a flat sibling for exactly that reason (see the P2
//! layout note in `docs/refactor-large-modules.md`).
//!
//! The registration response loop in `register_proxies` is one
//! cancellation-sensitive `tokio::select!` state machine (the F10 two-stage
//! read exists so a liveness timer never discards bytes of an in-progress
//! frame); it contains no `tokio::spawn` and no `unsafe`, and the move
//! changes no ordering inside it.

use super::*;

/// A validated frame header of an in-flight registration response (F10).
///
/// The V1 header (9 bytes: 1 type byte + 8-byte BE length) and the V2 header
/// (8 bytes: 2-byte frame type + 2-byte flags + 4-byte BE payload length) are
/// validated exactly like `frp_core::protocol` read_msg_v1/read_msg_v2 +
/// read_v2_frame_header do, so the two-stage split below is wire-identical to
/// the whole-frame readers it replaces.
struct RegFrameHdr {
    v2: bool,
    /// V1 ASCII type byte (V2 message type IDs live in the payload's 2-byte
    /// prefix and are only known after the payload read).
    v1_type: u8,
    payload_len: usize,
}

/// In-flight stage of the persisted registration-response frame read (F10).
///
/// The registration phase's liveness timers are semantic ("the server has
/// not answered within the bound") and must never discard bytes of an
/// in-progress frame, so the frame read is split into two stages the loop
/// polls across select iterations. A stage future lives in this enum (owned
/// by the loop), borrows nothing from the loop, and locks the control
/// stream (Arc<Mutex<IoStream>> clone) only inside its own poll — the exact
/// S3 persisted-read pattern of the message loop:
///   - [`RegReadStage::Header`] — the frame-header read_exact. Before it
///     completes at most 8 bytes can be consumed, so the visitor-grace drain
///     may still cancel it: a never-acking server (Go frps v0.70.1 never
///     acks control-channel NewVisitorConn) has consumed 0 bytes and the
///     drain stays byte-clean. (A server dribbling a partial header and
///     stalling loses ≤8 bytes on cancel — the pre-fix code had the same
///     loss on every timer fire, degrading to message-loop garbage →
///     reconnect.)
///   - [`RegReadStage::Payload`] — spawned only after the header committed
///     (8/9 bytes consumed). A committed frame is never cancelled by the
///     visitor-grace drain; it completes and registers normally even when
///     the server splits it across the grace boundary. It is bounded only by
///     REGISTRATION_RESPONSE_TIMEOUT and the heartbeat watchdog.
enum RegReadStage {
    Header(Pin<Box<dyn Future<Output = Result<RegFrameHdr, frp_core::Error>> + Send>>),
    Payload(Pin<Box<dyn Future<Output = Result<FrpMessage, frp_core::Error>> + Send>>),
}

/// Result of a completed read stage: a header (spawn the payload stage) or a
/// full message (dispatch it).
enum RegStageDone {
    Header(RegFrameHdr),
    Message(FrpMessage),
}

/// What the registration response loop's per-iteration liveness timer does
/// when it fires (F10). The timer never cancels a committed payload read.
#[derive(Clone, Copy)]
enum RegTimerKind {
    /// Proxies pending: no completed frame within REGISTRATION_RESPONSE_TIMEOUT.
    /// The pending proxies are marked StartErr (the message-loop retry
    /// re-registers them) and a header-stage read is cancelled (≤8 bytes
    /// consumed). A committed payload stage cannot be cancelled — dropping
    /// it would lose the consumed header — so the session aborts for a clean
    /// reconnect (the pre-fix code misaligned the stream here and limped
    /// into the message loop, which reconnected anyway).
    ProxyResponse,
    /// Visitors only, grace window open: the 2s visitor-grace bound. On fire
    /// the window closes (visitor_grace_elapsed); a header stage is cancelled
    /// so the assumed-registered drain can run, while a committed payload
    /// stage is left to complete (F10).
    VisitorGrace,
    /// Visitors only, grace window closed, committed payload in flight:
    /// REGISTRATION_RESPONSE_TIMEOUT. The server committed a frame and then
    /// stalled — abort for a clean reconnect.
    CommittedPayload,
    /// Nothing pending; a straggler frame read in flight (a response for
    /// requests already drained by a ProxyResponse fire):
    /// REGISTRATION_RESPONSE_TIMEOUT. A header-stage straggler is cancelled
    /// (≤8 bytes); a committed one aborts.
    StrayFrame,
}

/// F10: stage 1 of 2 — read + validate a registration-response frame header
/// (V1: 9 bytes; V2: 8 bytes). Cancel-safe for the visitor-grace drain: at
/// most 8 bytes can be consumed before completion.
fn reg_frame_header_read(
    ctl: &Arc<Mutex<IoStream>>,
    v2: bool,
) -> Pin<Box<dyn Future<Output = Result<RegFrameHdr, frp_core::Error>> + Send>> {
    let ctl = ctl.clone();
    Box::pin(async move {
        use tokio::io::AsyncReadExt;
        let mut guard = ctl.lock().await;
        let mut header = [0u8; 9];
        guard
            .read_exact(&mut header[..if v2 { 8 } else { 9 }])
            .await
            .map_err(|e| {
                frp_core::Error::Protocol(format!("read registration frame header: {e}").into())
            })?;
        if v2 {
            // Mirror frp_core::protocol::read_v2_frame_header + read_msg_v2's
            // type/length gates: flags must be 0, the frame type must be
            // Message (16), and the payload must carry at least the 2-byte
            // message type ID prefix within the 64 KiB cap.
            let frame_type = u16::from_be_bytes([header[0], header[1]]);
            let flags = u16::from_be_bytes([header[2], header[3]]);
            let payload_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            if flags != 0 {
                return Err(frp_core::Error::Protocol(
                    format!("unsupported V2 registration frame flags: {flags}").into(),
                ));
            }
            if frame_type != frp_core::protocol::V2_FRAME_TYPE_MESSAGE {
                return Err(frp_core::Error::Protocol(
                    format!(
                        "unexpected V2 registration frame type: {frame_type}, expected {} (Message)",
                        frp_core::protocol::V2_FRAME_TYPE_MESSAGE
                    )
                    .into(),
                ));
            }
            if payload_len < 2 {
                return Err(frp_core::Error::Protocol(
                    "V2 registration frame payload too short".into(),
                ));
            }
            if payload_len > frp_core::protocol::V2_MAX_FRAME_PAYLOAD {
                return Err(frp_core::Error::Protocol(
                    format!(
                        "V2 registration frame payload too large: {payload_len} (max: {})",
                        frp_core::protocol::V2_MAX_FRAME_PAYLOAD
                    )
                    .into(),
                ));
            }
            Ok(RegFrameHdr {
                v2: true,
                v1_type: 0,
                payload_len: payload_len as usize,
            })
        } else {
            let payload_len = u64::from_be_bytes([
                header[1], header[2], header[3], header[4], header[5], header[6], header[7],
                header[8],
            ]);
            if payload_len > frp_core::protocol::V1_MAX_MSG_LENGTH as u64 {
                return Err(frp_core::Error::Protocol(
                    format!(
                        "invalid V1 registration frame length: {payload_len} (max: {})",
                        frp_core::protocol::V1_MAX_MSG_LENGTH
                    )
                    .into(),
                ));
            }
            Ok(RegFrameHdr {
                v2: false,
                v1_type: header[0],
                payload_len: payload_len as usize,
            })
        }
    })
}

/// F10: stage 2 of 2 — read the payload of a frame whose header already
/// committed (V1: JSON; V2: 2-byte type ID prefix + JSON) and deserialize
/// it. Spawned only after the header read completed, so this future is never
/// cancelled by the visitor-grace drain.
fn reg_frame_payload_read(
    ctl: &Arc<Mutex<IoStream>>,
    hdr: RegFrameHdr,
) -> Pin<Box<dyn Future<Output = Result<FrpMessage, frp_core::Error>> + Send>> {
    let ctl = ctl.clone();
    Box::pin(async move {
        use tokio::io::AsyncReadExt;
        let mut guard = ctl.lock().await;
        let mut payload = vec![0u8; hdr.payload_len];
        guard.read_exact(&mut payload).await.map_err(|e| {
            frp_core::Error::Protocol(format!("read registration frame payload: {e}").into())
        })?;
        if hdr.v2 {
            let type_id = u16::from_be_bytes([payload[0], payload[1]]);
            frp_core::protocol::deserialize_v2(type_id, &payload[2..])
        } else {
            frp_core::protocol::deserialize_v1(hdr.v1_type, &payload)
        }
    })
}

impl Service {
    /// Phase 4 of one connection attempt: pipelined NewProxy/NewVisitorConn
    /// writes (all frames first, then the responses in a single read loop),
    /// the registration response read loop (2s visitor grace +
    /// REGISTRATION_RESPONSE_TIMEOUT + heartbeat watchdog races), vnet TUN
    /// opens, and the StartErr drain for still-pending proxies/visitors.
    ///
    /// Returns false when the registration phase aborted (a write/read
    /// error, the heartbeat watchdog, or too many unexpected messages): the
    /// caller then skips the session continuation (writer task, visitor
    /// listeners, message loop) and goes straight to teardown + reconnect —
    /// the same path a message-loop heartbeat timeout takes. Registration
    /// errors do NOT abort the session itself; the message loop's 30s retry
    /// re-registers StartErr proxies (login_fail_exit only governs login).
    pub(super) async fn register_proxies(
        &self,
        ctx: &mut SessionCtx,
        cfg_local: &ClientConfig,
        proxies: &[frp_core::config::ProxyConfig],
        pool_count: i32,
    ) -> bool {
        // Register proxies using IoStream directly (supports TCP and TLS).
        // Pipelined: write ALL NewProxy frames first, then collect the
        // responses in a single read loop — N proxies no longer cost N
        // sequential network round-trips (Go frpc registers each proxy in
        // its own goroutine, so Go frps may answer out of order; each
        // response is matched to its proxy by wire proxy_name). ReqWorkConn
        // frames arriving in this window (pool pre-warm, or a user conn
        // hitting the server mid-registration) are handled here instead of
        // dropped: skipping them left the pool empty after login and let
        // the server's work-conn wait stall for up to 10s.
        for (idx, p) in proxies.iter().enumerate() {
            // Go frp v0.71.0: a health-checked proxy is NOT registered until
            // its FIRST successful probe (proxy_wrapper health=1 → CheckFailed
            // → no NewProxy). The health monitor's first Recover event
            // registers it. Non-health proxies — and health-configured plugin
            // proxies, whose local_port == 0 makes the Go monitor gate
            // (HealthCheck.Type != "" && LocalPort > 0) fail — register
            // immediately below.
            if health_check_monitored(p) {
                debug!(name = %p.name, "Skipping initial registration of health-checked proxy '{}' (registers on first healthy probe)", p.name);
                continue;
            }
            let local_addr = self
                .proxy_info_map
                .read()
                .await
                .get(&wire_proxy_name(&cfg_local.user, &p.name))
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let np = crate::proxy::create_new_proxy_msg(p, &local_addr, &cfg_local.user);
            debug!(
                name = %p.name,
                proxy_type = %p.proxy_type,
                remote_port = p.remote_port,
                encrypted = p.use_encryption,
                compressed = p.use_compression,
                "NewProxy message prepared"
            );
            info!(name = %p.name, proxy_type = %p.proxy_type, remote_port = %p.remote_port, local_addr = %local_addr,
                "Registering proxy '{}' type={} remote_port={} local={}",
                p.name, p.proxy_type, p.remote_port, local_addr);
            let wire_name = wire_proxy_name(&cfg_local.user, &p.name);
            let write_result = if ctx.v2 {
                ctx.control_stream
                    .as_mut()
                    .expect("control_stream available before split")
                    .write_v2_frame(&np)
                    .await
            } else {
                ctx.control_stream
                    .as_mut()
                    .expect("control_stream available before split")
                    .write_v1_frame(&np)
                    .await
            };
            if let Err(e) = write_result {
                // A failed write leaves the stream state undefined; record
                // the failure, mark the proxy failed, and skip the response
                // phase entirely (responses for the unwritten requests may
                // never arrive — see `ctx.write_failed`/`aborted` below).
                ctx.write_failed = true;
                warn!(proxy_name = %p.name, error = %e, "Failed to register proxy '{}': {}", p.name, e);
                let mut map = self.proxy_info_map.write().await;
                if let Some(info) = map.get_mut(&wire_name) {
                    info.err = e.to_string();
                    info.phase = ProxyPhase::StartErr(e.to_string());
                }
                continue;
            }
            ctx.pending_proxies.push((wire_name, idx));
        }

        // Register STCP/XTCP visitors on the control connection.
        // Go frps v0.69.1 requires visitor registration before NatHoleVisitor
        // can be sent on the control connection (otherwise: "auth failed").
        // Pipelined like the proxies: write all NewVisitorConn frames, then
        // resolve them in the shared read loop below.
        let session_visitors_cfg = self.cfg.read().await.visitors.clone();
        let session_visitors: Vec<&frp_core::config::VisitorConfig> = session_visitors_cfg
            .iter()
            .filter(|v| v.enabled && v.bind_port != 0)
            .collect();
        for (idx, v) in session_visitors.iter().enumerate() {
            let nvc = crate::proxy::create_visitor_conn_msg(
                &v.server_name,
                &v.secret_key,
                v.use_encryption,
                v.use_compression,
                Some(v.server_user.as_str()).filter(|s| !s.is_empty()),
                Some(cfg_local.user.as_str()).filter(|s| !s.is_empty()),
                Some(ctx.run_id.as_str()).filter(|s| !s.is_empty()),
            );
            debug!(
                server_name = %v.server_name,
                encrypted = v.use_encryption,
                compressed = v.use_compression,
                "NewVisitorConn message prepared"
            );
            info!(visitor_name = %v.name, proxy_name = %v.server_name, "Registering visitor '{}' for proxy '{}'", v.name, v.server_name);
            let wire_name = crate::proxy::visitor_wire_name(
                Some(v.server_user.as_str()).filter(|s| !s.is_empty()),
                Some(cfg_local.user.as_str()).filter(|s| !s.is_empty()),
                &v.server_name,
            );
            let write_result = if ctx.v2 {
                ctx.control_stream
                    .as_mut()
                    .expect("control_stream available before split")
                    .write_v2_frame(&nvc)
                    .await
            } else {
                ctx.control_stream
                    .as_mut()
                    .expect("control_stream available before split")
                    .write_v1_frame(&nvc)
                    .await
            };
            if let Err(e) = write_result {
                ctx.write_failed = true;
                warn!(visitor_name = %v.name, error = %e, "Failed to register visitor '{}': {}", v.name, e);
                continue;
            }
            ctx.pending_visitors.push((wire_name, idx));
        }

        // Collect responses. NewProxyResp/NewVisitorConnResp are matched to
        // their request by wire proxy_name — the server answers
        // synchronously in request order, but matching by name keeps this
        // robust regardless of response order. ReqWorkConn spawns a work
        // connection (pool pre-warm — written by the server immediately
        // after LoginResp, BEFORE any registration response — a
        // NewVisitorConn success ack, or an on-demand user conn that
        // arrived while the client was still registering).
        let mut aborted = ctx.write_failed;
        let mut unexpected = 0u32;
        // F10 (audit round 8): the visitor-grace drain has run. Set once the
        // 2s grace window passes with no completed visitor frame; the
        // assumed-registered drain then runs at the next loop top where no
        // read stage is in flight.
        let mut visitor_grace_elapsed = false;

        // The registration response phase owns the control stream behind a
        // mutex: the persisted two-stage read futures ([`RegReadStage`]) lock
        // it inside their own polls, so this loop never borrows the stream
        // directly and a timer arm winning mid-frame can never drop consumed
        // bytes (F10). The block runs only when at least one request is
        // pending; otherwise the stream stays in `ctx.control_stream`
        // untouched and this phase is a no-op.
        if !ctx.pending_proxies.is_empty() || !ctx.pending_visitors.is_empty() {
            let ctl =
                Arc::new(Mutex::new(ctx.control_stream.take().expect(
                    "control_stream available before registration response phase",
                )));
            let mut read_stage: Option<RegReadStage> = None;

            loop {
                // Aborted (read error, heartbeat watchdog, or a committed
                // payload stage stalled past its bound): the stream stays in
                // `ctl` and is dropped with this scope, so the session cannot
                // continue on a possibly-misaligned stream; the tail of this
                // phase marks the still-pending requests failed.
                if aborted {
                    break;
                }
                // Visitor-grace drain: Go frp v0.70.1 never acks
                // control-channel NewVisitorConn — its stcp/xtcp visitors
                // register per user connection when the connection arrives,
                // not at startup. A pure-visitor client must therefore not
                // wait forever for a visitor ack the server will never send.
                // Once every proxy response is in, give the remaining visitor
                // acks a 2s grace period — our server writes its ack in the
                // same control iteration as the pool conns (ms under load,
                // ~200x headroom) — then assume the un-acked visitors
                // registered (Go frps semantics) and stop reading. Any frames
                // the server still writes afterwards are handled by the
                // session's main read loop. The drain advertises vnet routes,
                // which needs the stream, so it runs only when no read stage
                // can hold the lock; a stage in flight here is necessarily a
                // committed payload (grace cancels only header stages), and
                // the drain runs at the next loop top once it completes.
                if visitor_grace_elapsed
                    && read_stage.is_none()
                    && ctx.pending_proxies.is_empty()
                    && !ctx.pending_visitors.is_empty()
                {
                    while !ctx.pending_visitors.is_empty() {
                        let (_, idx) = ctx.pending_visitors.remove(0);
                        let v = session_visitors[idx];
                        info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}' (no registration response — assumed registered)", v.name, v.server_name);
                        #[cfg(feature = "vnet")]
                        advertise_vnet_visitor_route(&mut *ctl.lock().await, ctx.v2, v).await;
                    }
                    break;
                }
                // Normal completion: every pending request resolved and no
                // frame is mid-flight.
                if ctx.pending_proxies.is_empty()
                    && ctx.pending_visitors.is_empty()
                    && read_stage.is_none()
                {
                    break;
                }
                // Start a fresh frame (header stage) whenever requests are
                // pending and no read is in flight.
                if read_stage.is_none()
                    && (!ctx.pending_proxies.is_empty() || !ctx.pending_visitors.is_empty())
                {
                    read_stage = Some(RegReadStage::Header(reg_frame_header_read(&ctl, ctx.v2)));
                }
                // Heartbeat watchdog during registration: `last_pong` was
                // armed at login success, and no Ping is sent during
                // registration (pings start with the message loop), so no
                // Pong can arrive — the deadline starts as the full
                // hb_timeout from login, and is re-armed on every
                // registration response below (a response proves the server
                // is alive, so a server answering NewProxy steadily — even
                // when many proxies total more than hb_timeout — must not be
                // torn down mid-registration). A server that stays connected
                // but never answers is therefore detected within
                // heartbeat_timeout of its last response (Go frp's heartbeat
                // timer also runs continuously while its proxies register in
                // goroutines). With the heartbeat disabled
                // (hb_watchdog_active false) the watchdog must never fire:
                // sleep for ~136 years so both branches share the same Sleep
                // type, leaving the per-read deadlines below as the bound.
                let watchdog = tokio::time::sleep(if ctx.hb_watchdog_active {
                    ctx.hb_timeout_dur.saturating_sub(ctx.last_pong.elapsed())
                } else {
                    Duration::from_secs(u32::MAX as u64)
                });
                tokio::pin!(watchdog);
                // Per-iteration liveness timer, chosen from the pending state
                // (each bound restarts per iteration — i.e. after every
                // completed frame — exactly like the pre-fix per-branch
                // arms): a proxy batch waits REGISTRATION_RESPONSE_TIMEOUT
                // for each response; a pure-visitor registration runs the 2s
                // grace window (see the drain above); a committed payload or
                // a straggler frame is bounded by
                // REGISTRATION_RESPONSE_TIMEOUT. On fire the timer NEVER
                // cancels a committed payload stage (F10) — its handling
                // below only ever cancels header stages.
                let (timer_dur, timer_kind) = if !ctx.pending_proxies.is_empty() {
                    (*REGISTRATION_RESPONSE_TIMEOUT, RegTimerKind::ProxyResponse)
                } else if !ctx.pending_visitors.is_empty() {
                    if visitor_grace_elapsed {
                        (
                            *REGISTRATION_RESPONSE_TIMEOUT,
                            RegTimerKind::CommittedPayload,
                        )
                    } else {
                        (Duration::from_millis(2000), RegTimerKind::VisitorGrace)
                    }
                } else {
                    (*REGISTRATION_RESPONSE_TIMEOUT, RegTimerKind::StrayFrame)
                };
                let timer = tokio::time::sleep(timer_dur);
                tokio::pin!(timer);
                let mut timer_fired = false;
                let mut watchdog_fired = false;
                let mut resp_msg: Option<FrpMessage> = None;
                tokio::select! {
                    // Poll whichever stage is in flight. The stage future
                    // lives in `read_stage`; this branch holds only a borrow
                    // of it, so when a competing arm wins mid-read the
                    // select drops the branch, not the future — the bytes
                    // consumed so far survive until the frame completes
                    // (F10, the S3 persisted-read pattern).
                    out = async {
                        match read_stage.as_mut().expect("a registration read stage is in flight") {
                            RegReadStage::Header(f) => match f.as_mut().await {
                                Ok(hdr) => Ok(RegStageDone::Header(hdr)),
                                Err(e) => Err(e),
                            },
                            RegReadStage::Payload(f) => match f.as_mut().await {
                                Ok(m) => Ok(RegStageDone::Message(m)),
                                Err(e) => Err(e),
                            },
                        }
                    } => match out {
                        Ok(RegStageDone::Header(hdr)) => {
                            // Header committed — the frame is no longer
                            // cancellable by the grace drain. Continue the
                            // read as the payload stage.
                            read_stage = Some(RegReadStage::Payload(reg_frame_payload_read(
                                &ctl, hdr,
                            )));
                        }
                        Ok(RegStageDone::Message(m)) => {
                            read_stage = None;
                            resp_msg = Some(m);
                        }
                        Err(e) => {
                            warn!(error = %e, "Registration response read failed: {}", e);
                            aborted = true;
                        }
                    },
                    _ = &mut timer => timer_fired = true,
                    _ = &mut watchdog => watchdog_fired = true,
                }
                if watchdog_fired {
                    warn!(timeout = %ctx.hb_timeout, "Heartbeat timeout ({}s) during registration, reconnecting...", ctx.hb_timeout);
                    aborted = true;
                    // Break the registration loop: `aborted` skips the
                    // session continuation (writer task, visitor
                    // listeners, message loop) below and the session
                    // goes straight to teardown + reconnect — same
                    // path a message-loop heartbeat timeout takes.
                    break;
                }
                if timer_fired {
                    // Apply the timer's semantics now that the select has
                    // returned and dropped every branch future, so
                    // `read_stage` is free to mutate.
                    match timer_kind {
                        RegTimerKind::ProxyResponse => {
                            // The server never answered the pending
                            // requests. Mark them StartErr with a
                            // clear message and drop them from the
                            // pending set so the registration phase
                            // finishes; the message loop's retry then
                            // re-registers them (their phase is
                            // StartErr) while the session keeps
                            // running. A header-stage read is cancelled
                            // (at most 8 bytes consumed — a silent server
                            // consumed 0); a committed payload stage
                            // cannot be cancelled without losing its
                            // consumed header, so the session aborts for
                            // a clean reconnect.
                            let msg = format!(
                                "registration timed out (no response within {}s)",
                                REGISTRATION_RESPONSE_TIMEOUT.as_millis() as f64 / 1000.0
                            );
                            warn!(
                                proxies = %ctx.pending_proxies.len(),
                                timeout_ms = REGISTRATION_RESPONSE_TIMEOUT.as_millis(),
                                "Registration response timeout; marking {} pending proxies as failed",
                                ctx.pending_proxies.len()
                            );
                            for (wire_name, _) in ctx.pending_proxies.drain(..) {
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&wire_name) {
                                    info.err = msg.clone();
                                    info.phase = ProxyPhase::StartErr(msg.clone());
                                }
                            }
                            match read_stage {
                                Some(RegReadStage::Header(_)) => read_stage = None,
                                Some(RegReadStage::Payload(_)) => {
                                    warn!(
                                        "Registration response timeout while a response frame was mid-flight; aborting the session for a clean reconnect"
                                    );
                                    aborted = true;
                                }
                                None => {}
                            }
                        }
                        RegTimerKind::VisitorGrace => {
                            // The grace window closed without a completed
                            // visitor frame. Cancel only a header-stage read
                            // (at most 8 bytes consumed — a never-acking
                            // server consumed 0), so the assumed-registered
                            // drain can run; a committed payload stage keeps
                            // reading (F10: a visitor ack split across the
                            // grace boundary must complete, not lose its
                            // consumed header to this arm).
                            visitor_grace_elapsed = true;
                            if let Some(RegReadStage::Header(_)) = read_stage {
                                read_stage = None;
                            }
                        }
                        RegTimerKind::CommittedPayload | RegTimerKind::StrayFrame => {
                            // A frame the server committed (header consumed)
                            // has stalled past its bound, or a straggler
                            // header never completed. Cancel a header stage
                            // (≤8 bytes consumed); a committed payload means
                            // the stream is misaligned from here on — abort
                            // for a clean reconnect.
                            match read_stage {
                                Some(RegReadStage::Header(_)) => read_stage = None,
                                Some(RegReadStage::Payload(_)) => {
                                    warn!(
                                        "Registration response frame stalled mid-payload; aborting the session for a clean reconnect"
                                    );
                                    aborted = true;
                                }
                                None => {}
                            }
                        }
                    }
                }
                if aborted {
                    break;
                }
                if let Some(resp_msg) = resp_msg {
                    match resp_msg {
                        FrpMessage::NewProxyResp(resp) => {
                            ctx.seen_registration_response = true;
                            // The server answered — it is provably alive, so the
                            // registration watchdog restarts from here instead of
                            // counting from login (a slow-but-steady registration
                            // must not be torn down).
                            ctx.last_pong = Instant::now();
                            // Match by wire proxy_name: responses may arrive in any
                            // order relative to the requests they answer.
                            let Some(pos) = ctx
                                .pending_proxies
                                .iter()
                                .position(|(name, _)| *name == resp.proxy_name)
                            else {
                                unexpected += 1;
                                warn!(proxy_name = %resp.proxy_name, "NewProxyResp for proxy not in this registration batch");
                                continue;
                            };
                            let (_, idx) = ctx.pending_proxies.swap_remove(pos);
                            let p = &proxies[idx];
                            if let Some(err) = resp.error {
                                warn!(proxy_name = %p.name, error = %err, "Failed to register proxy '{}': {}", p.name, err);
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) =
                                    map.get_mut(&wire_proxy_name(&cfg_local.user, &p.name))
                                {
                                    info.err = err.clone();
                                    info.phase = ProxyPhase::StartErr(err);
                                }
                            } else {
                                let remote = resp
                                    .remote_addr
                                    .unwrap_or_else(|| format!("0.0.0.0:{}", p.remote_port));
                                info!(proxy_name = %p.name, remote = %remote, "Proxy '{}' registered on remote port {}", p.name, remote);
                                // Update runtime info for admin API
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) =
                                    map.get_mut(&wire_proxy_name(&cfg_local.user, &p.name))
                                {
                                    info.remote_addr = remote;
                                    info.err.clear();
                                    info.phase = ProxyPhase::Running;
                                }

                                #[cfg(feature = "vnet")]
                                if vnet_tun_params(p, &cfg_local.virtual_net.address).is_some() {
                                    if let Err(e) = self.open_vnet_tun_for_proxy(p, cfg_local).await
                                    {
                                        warn!(proxy_name = %p.name, error = %e, "TUN open/register failed (need root/CAP_NET_ADMIN?)");
                                    }
                                }
                            }
                        }
                        FrpMessage::NewVisitorConnResp(resp) => {
                            ctx.seen_registration_response = true;
                            // Same liveness proof as NewProxyResp: any server
                            // response during registration re-arms the watchdog.
                            ctx.last_pong = Instant::now();
                            let Some(pos) = ctx
                                .pending_visitors
                                .iter()
                                .position(|(name, _)| *name == resp.proxy_name)
                            else {
                                unexpected += 1;
                                // Defensive: an out-of-batch response is almost
                                // always a REJECTED visitor whose earlier
                                // ReqWorkConn ack was misattributed (e.g. a pool
                                // pre-warm conn consumed as its success signal),
                                // leaving the failure unnamed and discarded here.
                                // Resolve the wire name against the configured
                                // visitor list and surface the error so a future
                                // ordering change cannot silently swallow an auth
                                // failure.
                                let configured = session_visitors.iter().find(|v| {
                                    crate::proxy::visitor_wire_name(
                                        Some(v.server_user.as_str()).filter(|s| !s.is_empty()),
                                        Some(cfg_local.user.as_str()).filter(|s| !s.is_empty()),
                                        &v.server_name,
                                    ) == resp.proxy_name
                                });
                                match configured {
                                    Some(v) => {
                                        warn!(visitor_name = %v.name, proxy_name = %resp.proxy_name, error = ?resp.error, "NewVisitorConnResp for visitor '{}' (wire '{}') not in this registration batch: {:?}", v.name, resp.proxy_name, resp.error)
                                    }
                                    None => {
                                        warn!(proxy_name = %resp.proxy_name, "NewVisitorConnResp for visitor not in this registration batch")
                                    }
                                }
                                continue;
                            };
                            let (_, idx) = ctx.pending_visitors.swap_remove(pos);
                            let v = session_visitors[idx];
                            if let Some(err) = resp.error {
                                warn!(visitor_name = %v.name, error = %err, "Failed to register visitor '{}': {}", v.name, err);
                            } else {
                                info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}'", v.name, v.server_name);
                                // Virtual-net visitors advertise their destination IP
                                // as a host route instead of binding a local listener.
                                #[cfg(feature = "vnet")]
                                advertise_vnet_visitor_route(&mut *ctl.lock().await, ctx.v2, v)
                                    .await;
                            }
                        }
                        FrpMessage::ReqWorkConn(_) => {
                            self.handle_req_work_conn(ctx);
                            // Go frps v0.69.1 acks a successful NewVisitorConn on
                            // the control channel with an anonymous ReqWorkConn
                            // (no proxy_name; failures get a named
                            // NewVisitorConnResp{error}). While visitors are
                            // still pending, attribute the ack to the oldest one
                            // (FIFO — the server answers registrations in request
                            // order, so acks arrive in visitor order).
                            //
                            // The server writes its pool pre-warm ReqWorkConns
                            // immediately after LoginResp, BEFORE it processes any
                            // registration frame, so they always precede every
                            // NewProxyResp/NewVisitorConnResp on the wire. An
                            // anonymous ReqWorkConn can therefore only be a
                            // visitor success ack once a registration response has
                            // been seen. (With no proxies there is no NewProxyResp
                            // to mark the pool's end; the client's own pool_count
                            // bounds it instead — the server never sends more pool
                            // conns than the client asked for.) Without this gate
                            // the pool conns were FIFO-attributed to the oldest
                            // pending visitors, marking them registered (and
                            // advertising vnet routes) before the server had even
                            // seen their NewVisitorConn — a rejected visitor's
                            // real response then hit the out-of-batch branch above
                            // and was silently discarded.
                            let pool_conns_done = ctx.seen_registration_response
                                || (ctx.pending_proxies.is_empty()
                                    && ctx.req_work_conns_seen >= pool_count.max(1) as usize);
                            if pool_conns_done && !ctx.pending_visitors.is_empty() {
                                let (_, idx) = ctx.pending_visitors.remove(0);
                                let v = session_visitors[idx];
                                info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}' (Go frps compat: ReqWorkConn after NewVisitorConn)", v.name, v.server_name);
                                #[cfg(feature = "vnet")]
                                advertise_vnet_visitor_route(&mut *ctl.lock().await, ctx.v2, v)
                                    .await;
                            }
                            ctx.req_work_conns_seen += 1;
                        }
                        other => {
                            unexpected += 1;
                            warn!(
                                type_byte = other.v1_type_byte(),
                                "Unexpected message during registration"
                            );
                        }
                    }
                }
                if unexpected >= 100 {
                    warn!("Registration aborted: too many unexpected messages");
                    aborted = true;
                }
            }
            if !aborted {
                // Hand the stream back for the session continuation (phase 5's
                // split). Every non-aborted exit has `read_stage == None` (the
                // drain and completion exits require it; the timer exits only
                // cancel header stages), so this scope is the sole Arc holder.
                ctx.control_stream = Some(
                Arc::try_unwrap(ctl)
                    .expect("only the registration loop holds the control stream when the phase completes")
                    .into_inner(),
            );
            }
        }

        // Any request still pending here never got an answer (write
        // failure, read error, or too many unexpected frames). Mark the
        // proxies failed and log the unresolved visitors; the session
        // continues — registration errors do not abort the client
        // (login_fail_exit only governs the login phase).
        if !ctx.pending_proxies.is_empty() || !ctx.pending_visitors.is_empty() {
            warn!(proxies = %ctx.pending_proxies.len(), visitors = %ctx.pending_visitors.len(), "Registration aborted; marking still-pending proxies/visitors as failed");
            for (wire_name, _) in ctx.pending_proxies.drain(..) {
                let mut map = self.proxy_info_map.write().await;
                if let Some(info) = map.get_mut(&wire_name) {
                    info.err = "registration aborted (no response)".to_string();
                    info.phase =
                        ProxyPhase::StartErr("registration aborted (no response)".to_string());
                }
            }
            for (_, idx) in ctx.pending_visitors.drain(..) {
                let v = session_visitors[idx];
                warn!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registration unresolved", v.name);
            }
        }

        !aborted
    }
}
