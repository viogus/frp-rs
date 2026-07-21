//! Login authentication for control connections.
//!
//! Handles OIDC verification, token-based auth, PBKDF2 key derivation,
//! duplicate `run_id` shutdown, encryption setup, and per-client state
//! initialisation.

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, Interval};
use tracing::{debug, info, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;

use crate::lock::RwLockExt;
use crate::state::{AppState, ControlTx, InternalMsg, PoolStats};

use super::pool::{PendingRequest, PoolEntry, WORK_POOL_EXTRA};
use super::proxy_ops::{err_msg, unregister_control};
use super::{write_ctl_msg, ControlContext, ControlState};

/// Authenticate a new control connection and set up per-client state.
/// On success returns all state needed by the main select! loop.
/// On failure sends LoginResp with an error and returns `Err(())`.
/// When `internal` is true and the login's ClientSpec.AlwaysAuthPass is set,
/// authentication is bypassed (Go frp SSH gateway compat).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authenticate<S>(
    mut stream: S,
    login: &msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    internal: bool,
) -> Result<
    (
        ControlContext,
        ControlState,
        mpsc::Sender<InternalMsg>,
        mpsc::Receiver<InternalMsg>,
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
        Option<IncomingStreams>,
        Interval,
    ),
    (),
>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // --- Login throttle: max 5 failed attempts per 60s per IP ---
    // For transports with a peer address (TCP), use the real IP.
    // For transports without SocketAddr (TLS/WS/KCP/QUIC), hash the
    // privilege_key into a synthetic IP to prevent brute-force attacks
    // on the login endpoint. This ensures all login paths are throttled.
    let throttle_key = match peer {
        Some(ref peer_addr) => *peer_addr,
        None => {
            let key = login.privilege_key.as_deref().unwrap_or("");
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            let hash = hasher.finish();
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(
                    (hash >> 24) as u8,
                    (hash >> 16) as u8,
                    (hash >> 8) as u8,
                    hash as u8,
                ),
                0,
            ))
        }
    };
    if !state.check_login_throttle(throttle_key).await {
        warn!(peer = ?peer, "Login throttle: too many failed attempts from {:?}", peer);
        return Err(());
    }

    // --- Authenticate ---
    // Internal connections (SSH gateway) with AlwaysAuthPass bypass all auth.
    let is_auth_bypass = internal
        && login
            .client_spec
            .as_ref()
            .and_then(|cs| cs.always_auth_pass)
            .unwrap_or(false);
    if is_auth_bypass {
        info!(
            peer = ?peer,
            run_id = ?login.run_id,
            "Internal connection with AlwaysAuthPass, bypassing authentication",
        );
    }

    let oidc_subject: Option<String> = if is_auth_bypass {
        None
    } else if let Some(ref verifier) = state.oidc.verifier {
        let token = login.privilege_key.as_deref().unwrap_or("");
        match verifier.verify_login(token).await {
            Ok(oidc_token) => {
                info!(subject = %oidc_token.subject, "OIDC login verified: subject={}", oidc_token.subject);
                Some(oidc_token.subject)
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "OIDC auth failed for {:?}: {}", peer, e);
                // Login throttle slot was reserved atomically in check_login_throttle above.
                let (_, mut writer) = tokio::io::split(stream);
                let resp = FrpMessage::LoginResp(msg::LoginResp {
                    version: Some(frp_core::VERSION.into()),
                    run_id: None,
                    error: Some(err_msg(
                        state.detailed_errors_to_client,
                        format!("OIDC authentication failed: {e}"),
                        "OIDC authentication failed",
                    )),
                    server_additional_auth_scopes: None,
                });
                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                return Err(());
            }
        }
    } else {
        let auth_cfg = state.reloadable.read_ok().auth_cfg.clone();
        if let Err(e) = auth_cfg.validate_login(login.privilege_key.as_deref(), login.timestamp) {
            warn!(peer = ?peer, error = %e, "Authentication failed for {:?}: {}", peer, e);
            // Login throttle slot was reserved atomically in check_login_throttle above.
            // Emit WebSocket event for dashboard subscribers
            #[cfg(feature = "dashboard")]
            {
                let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                    message: format!("Authentication failed for {:?}", peer),
                    context: Some("login".into()),
                });
            }
            let (_, mut writer) = tokio::io::split(stream);
            let resp = FrpMessage::LoginResp(msg::LoginResp {
                version: Some(frp_core::VERSION.into()),
                run_id: None,
                error: Some(err_msg(
                    state.detailed_errors_to_client,
                    e,
                    "token authentication failed",
                )),
                server_additional_auth_scopes: None,
            });
            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
            return Err(());
        }

        // --- Replay protection: timestamp freshness + duplicate detection ---
        if auth_cfg.token_auth_timeout && auth_cfg.authentication_timeout > 0 {
            if let Some(ts) = login.timestamp {
                if let Err(e) = frp_core::auth::validate_timestamp_freshness(
                    ts,
                    auth_cfg.authentication_timeout,
                ) {
                    warn!(peer = ?peer, error = %e, "Login timestamp outside acceptable window: {}", e);
                    let (_, mut writer) = tokio::io::split(stream);
                    let resp = FrpMessage::LoginResp(msg::LoginResp {
                        version: Some(frp_core::VERSION.into()),
                        run_id: None,
                        error: Some(e),
                        server_additional_auth_scopes: None,
                    });
                    let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                    return Err(());
                }
                // Use client-provided run_id for duplicate detection.
                // When the client doesn't send one (old/Rust clients or tests),
                // generate a unique UUID so concurrent logins within the same
                // second don't collide. Replay protection is weaker without
                // a client-provided run_id (attacker could replay within the
                // timestamp freshness window), but the login throttle and
                // timestamp freshness check provide layered defense.
                let run_id_for_check = login
                    .run_id
                    .clone()
                    .filter(|id| !id.is_empty())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let mut used = state.used_timestamps.lock().await;
                let entry = used.entry(ts).or_default();
                if !entry.insert(run_id_for_check.clone()) {
                    warn!(
                        peer = ?peer, run_id = %run_id_for_check, ts = %ts,
                        "Replay attack detected: duplicate (run_id, timestamp) pair for run_id={} ts={}",
                        run_id_for_check, ts,
                    );
                    let (_, mut writer) = tokio::io::split(stream);
                    let resp = FrpMessage::LoginResp(msg::LoginResp {
                        version: Some(frp_core::VERSION.into()),
                        run_id: None,
                        error: Some("replay attack detected: duplicate timestamp".into()),
                        server_additional_auth_scopes: None,
                    });
                    let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                    return Err(());
                }
                // Clean old entries: split_off (O(log n)) is faster than a full
                // retain scan (O(n)) and avoids holding the lock for a linear scan.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let threshold = now - auth_cfg.authentication_timeout;
                let kept = used.split_off(&threshold);
                *used = kept;
            }
        }

        None
    };

    let reloadable = state.reloadable.read_ok().clone();

    let run_id = login
        .run_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!(peer = ?peer, run_id = %run_id, "Client {:?} logged in with run_id: {}", peer, run_id);

    // Store OIDC subject for ping/NWC verification
    if let Some(ref sub) = oidc_subject {
        state
            .oidc
            .subjects
            .write()
            .await
            .insert(run_id.clone(), sub.clone());
    }

    // --- Server plugin: login hook ---
    let login_content = serde_json::json!({
        "version": login.version,
        "hostname": login.hostname,
        "os": login.os,
        "user": login.user,
        "run_id": run_id,
        "remote_addr": peer.map(|a| a.to_string()),
        "metas": login.metas,
    });
    if let Err(reason) = state.plugin_manager.notify("login", login_content).await {
        warn!(run_id = %run_id, reason = %reason, "Login for run_id {} rejected by server plugin: {}", run_id, reason);
        let (_, mut writer) = tokio::io::split(stream);
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: None,
            error: Some(reason),
            server_additional_auth_scopes: None,
        });
        let _ = write_ctl_msg(&mut writer, &resp, v2).await;
        // Clean up OIDC subject inserted before login validation.
        if oidc_subject.is_some() {
            state.oidc.subjects.write().await.remove(&run_id);
        }
        return Err(());
    }

    // --- Set up internal channel ---
    let (internal_tx, internal_rx) = mpsc::channel::<InternalMsg>(1024);
    let pool_stats = Arc::new(PoolStats::default());

    // ── Control Manager: Admit phase ──────────────────────────────────
    // Assign a monotonically increasing control_id to distinguish this
    // control generation from any previous one with the same run_id.
    let control_id = state.control_id_counter.fetch_add(1, Ordering::SeqCst);

    // Acquire per-runID mutex to serialize lifecycle transitions.
    // This prevents two concurrent logins for the same run_id from racing.
    let run_mu = state.get_run_mu(&run_id);
    let run_guard = run_mu.lock().await;

    // Check for existing control and set up handoff barrier.
    // The new handler waits for the old handler's cleanup to complete
    // before proceeding (Go frp dev control.go lifecycle).
    let handoff_barrier: Option<oneshot::Receiver<()>> = {
        let map = state.run_id_to_ctl_tx.read().await;
        if let Some(old_ctl) = map.get(&run_id) {
            warn!(run_id = %run_id, "Duplicate run_id {}: shutting down old control handler for replacement", run_id);
            let (tx, rx) = oneshot::channel();
            match old_ctl.tx.try_send(InternalMsg::Shutdown { done: tx }) {
                Ok(()) => Some(rx),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(run_id = %run_id, "Old control handler already shut down");
                    None
                }
                Err(mpsc::error::TrySendError::Full(shutdown_msg)) => {
                    debug!(run_id = %run_id, "Old control handler channel full; sending async");
                    let old_tx = old_ctl.tx.clone();
                    tokio::spawn(async move {
                        let _ = old_tx.send(shutdown_msg).await;
                    });
                    Some(rx)
                }
            }
        } else {
            None
        }
    };

    // Insert new ControlTx while holding run_mu.
    {
        let mut map = state.run_id_to_ctl_tx.write().await;
        map.insert(
            run_id.clone(),
            ControlTx {
                tx: internal_tx.clone(),
                client_addr: peer,
                login_time: std::time::Instant::now(),
                login_time_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                pool_stats: pool_stats.clone(),
                user: login.user.clone().unwrap_or_default(),
                control_id,
            },
        );
    }

    // Wait for handoff barrier. RunMu is released during this wait so the
    // old handler's cleanup (which may need to acquire run_mu via Remove)
    // does not deadlock. This matches Go frp dev's WaitForHandoff() which
    // is called outside the per-runID serialization lock.
    if let Some(barrier) = handoff_barrier {
        info!(run_id = %run_id, "Waiting for old control handler shutdown...");
        let _ = barrier.await;
        info!(run_id = %run_id, "Old control handler shutdown complete");
    }

    // ── Activate phase: register in ClientRegistry ──────────────────
    let peer_str = peer.map(|a| a.to_string()).unwrap_or_default();
    let wire_protocol = if v2 { "v2" } else { "v1" };
    let (_registry_key, conflict) = state.client_registry.register_with_control_id(
        login.user.as_deref().unwrap_or(""),
        login.client_id.as_deref().unwrap_or(""),
        &run_id,
        login.hostname.as_deref().unwrap_or(""),
        login.version.as_deref().unwrap_or(""),
        &peer_str,
        wire_protocol,
        control_id,
    );
    if conflict {
        warn!(
            run_id = %run_id,
            "Client already online with same user/client_id — rejecting activation"
        );
        let (_, mut writer) = tokio::io::split(stream);
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: None,
            error: Some("client already online".into()),
            server_additional_auth_scopes: None,
        });
        let _ = write_ctl_msg(&mut writer, &resp, v2).await;
        unregister_control(&state, &run_id, false).await;
        // Clean up OIDC subject
        if oidc_subject.is_some() {
            state.oidc.subjects.write().await.remove(&run_id);
        }
        return Err(());
    }

    // ── CompleteLogin phase: write LoginResp within run_mu ──────────
    let additional_auth_scopes = reloadable.additional_auth_scopes.clone();
    let resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some(run_id.clone()),
        error: None,
        server_additional_auth_scopes: if additional_auth_scopes.is_empty() {
            None
        } else {
            Some(additional_auth_scopes)
        },
    });
    // Hex-dump the raw LoginResp V1 frame for Go compat debugging
    let type_byte = resp.v1_type_byte();
    let payload = serde_json::to_vec(&resp).unwrap_or_default();
    let frame_len = 9 + payload.len();
    info!(
        peer = ?peer, run_id = %run_id,
        type_byte = format_args!("{:#04x}", type_byte),
        payload_len = payload.len(),
        payload_text = %String::from_utf8_lossy(&payload),
        "LoginResp V1 frame: type={:#04x} len={} frame_total={} json={}",
        type_byte, payload.len(), frame_len,
        String::from_utf8_lossy(&payload),
    );
    if let Err(e) = write_ctl_msg(&mut stream, &resp, v2).await {
        warn!(peer = ?peer, error = %e, "Failed to send login response to {:?}: {}", peer, e);
        unregister_control(&state, &run_id, false).await;
        // Clean up registry entry
        state
            .client_registry
            .mark_offline_by_run_id_and_control_id(&run_id, control_id);
        // Clean up OIDC subject
        if oidc_subject.is_some() {
            state.oidc.subjects.write().await.remove(&run_id);
        }
        return Err(());
    }
    // Flush TLS stream to ensure LoginResp reaches KCP before we wrap in CipherStream
    if let Err(e) = stream.flush().await {
        warn!(peer = ?peer, error = %e, "Failed to flush after LoginResp: {}", e);
    }
    info!(peer = ?peer, run_id = %run_id, "LoginResp sent to {:?}, flushed", peer);

    // Release run_mu after completeLogin succeeds.
    // The control handler's main loop runs without the per-runID lock,
    // allowing the next superseding login to proceed via Add/Activate again.
    drop(run_guard);

    // Emit WebSocket event for dashboard subscribers
    #[cfg(feature = "dashboard")]
    {
        let _ = state
            .event_tx
            .send(crate::event::ServerEvent::ClientConnected {
                run_id: run_id.clone(),
                client_addr: peer.map(|a| a.to_string()),
            });
    }

    // --- Wrap in encryption (matches client after login) ---
    // V2 with AEAD crypto: wrap stream in AEAD here, AFTER LoginResp sent
    // (matching Go frp flow: ClientHello/ServerHello + Login/LoginResp in
    // plaintext, then AEAD for all subsequent messages).
    // V1 or V2 without AEAD: wrap in AES-128-CFB (CipherStream) for backward compat.
    let (reader, mut writer): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) = if let (true, Some(ctx)) = (v2, crypto_ctx.as_ref()) {
        let token = reloadable.auth_cfg.token.clone();
        match frp_core::crypto::derive_aead_control_keys(
            token.as_bytes(),
            ctx.algorithm,
            &ctx.transcript_hash,
        ) {
            Ok((read_key, write_key)) => {
                // derive_aead_control_keys returns (client_to_server, server_to_client).
                // Server reads from client → client_to_server (= read_key).
                // Server writes to client → server_to_client (= write_key).
                match frp_core::crypto::AeadStream::new(
                    Box::new(stream),
                    ctx.algorithm,
                    &read_key,
                    &write_key,
                ) {
                    Ok(aead) => {
                        let (r, w) = tokio::io::split(aead);
                        (Box::new(r), Box::new(w))
                    }
                    Err(e) => {
                        warn!(peer = ?peer, error = %e, "Failed to create AEAD stream for {:?}: {}", peer, e);
                        unregister_control(&state, &run_id, false).await;
                        return Err(());
                    }
                }
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to derive AEAD keys for {:?}: {}", peer, e);
                unregister_control(&state, &run_id, false).await;
                return Err(());
            }
        }
    } else {
        // V1 or plain V2: ALWAYS wrap in AES-128-CFB after LoginResp.
        // Go frp v0.69.1 always encrypts the control connection after login
        // (both frps service.go:460 and frpc control_session.go:219 call
        // NewCryptoReadWriter unconditionally — no config flag gates it).
        // The use_encryption config flag controls proxy bridge (data plane)
        // encryption, not control plane encryption.
        info!(peer = ?peer, run_id = %run_id, "Wrapping control stream in CipherStream (AES-128-CFB)");
        let enc_key = encryption::derive_key(&reloadable.auth_cfg.token);
        let cipher = frp_core::cipher_stream::CipherStream::new(Box::new(stream), enc_key);
        // ReqWorkConn pre-warming is done AFTER the if/else block below,
        // so BOTH V1 and V2+AEAD paths benefit from pre-warmed work conns.
        let (r, w) = tokio::io::split(cipher);
        (Box::new(r), Box::new(w))
    };

    // --- ReqWorkConn pre-warming (BOTH V1 and V2+AEAD paths) ---
    // Go frps service.go:496 ctl.Start() sends ReqWorkConn immediately
    // after LoginResp. For V1 this was previously done inside the
    // CipherStream block (before split); for V2+AEAD it was missing.
    // Sending ReqWorkConn now, after encryption setup (split), ensures
    // both protocols benefit from pre-warmed work connections.
    {
        let max_pool = state.server_config_snapshot.max_pool_count;
        let raw_pool = login.pool_count.unwrap_or(1).max(1) as i64;
        let pool_count = if max_pool > 0 {
            raw_pool.min(max_pool)
        } else {
            raw_pool
        } as usize;
        info!(peer = ?peer, pool_count = pool_count, max_pool_count = max_pool, "Sending ReqWorkConn x{} through encrypted stream", pool_count);
        for i in 0..pool_count {
            // writer is already the encrypted write half (CipherStream or AeadStream).
            if let Err(e) = write_ctl_msg(
                &mut writer,
                &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
                v2,
            )
            .await
            {
                warn!(peer = ?peer, error = %e, i = i, "Failed to send ReqWorkConn #{}/{}: {}", i, pool_count, e);
                // Non-fatal — the pool will be replenished on demand.
                break;
            }
        }
    }

    // --- Per-client state ---
    let max_pool = state.server_config_snapshot.max_pool_count;
    let raw_pool = login.pool_count.unwrap_or(1).max(0) as i64;
    let capped_pool = if max_pool > 0 {
        raw_pool.min(max_pool)
    } else {
        raw_pool
    } as usize;
    let pool_cap = capped_pool + WORK_POOL_EXTRA;
    let work_pool: VecDeque<PoolEntry> = VecDeque::new();
    let pending_requests: VecDeque<PendingRequest> = VecDeque::new();
    let pending_udp: VecDeque<(String, Instant)> = VecDeque::new();
    let pending_nat_hole_sids: VecDeque<(String, String, Instant)> = VecDeque::new();
    // TCP/HTTP/STCP listener handles. UDP listeners are managed via the work-connection
    // mechanism (UdpNeedsWorkConn → ReqWorkConn → assign_udp_work_conn).
    let listener_handles: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let udp_sockets: HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> = HashMap::new();
    // Reverse mapping: local_addr → proxy_name for routing UDPPacket responses
    let udp_local_to_proxy: HashMap<String, String> = HashMap::new();
    let shutting_down = false;
    let last_ping = Instant::now();
    // Ping interval: max 10s to stay well within Go frpc's heartbeat timeout
    let ping_interval = Duration::from_secs(10);
    let mut ping_tick = tokio::time::interval(ping_interval);
    // Defer first ping to ping_interval from now (Go frpc heartbeat timeout is 90s)
    ping_tick.reset();
    ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    Ok((
        ControlContext {
            state: state.clone(),
            pool_stats: pool_stats.clone(),
            reloadable,
            v2,
            run_id,
            pool_cap,
            internal_tx: internal_tx.clone(),
            peer,
        },
        ControlState {
            shutting_down,
            shutdown_done: None,
            work_pool,
            pending_requests,
            pending_udp,
            pending_nat_hole_sids,
            listener_handles,
            udp_sockets,
            udp_local_to_proxy,
            last_ping,
        },
        internal_tx,
        internal_rx,
        reader,
        writer,
        incoming,
        ping_tick,
    ))
}
