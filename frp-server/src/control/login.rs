//! Login authentication for control connections.
//!
//! Handles OIDC verification, token-based auth, PBKDF2 key derivation,
//! duplicate `run_id` shutdown, encryption setup, and per-client state
//! initialisation.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;

use crate::lock::RwLockExt;
use crate::state::{AppState, ControlTx, InternalMsg, PoolStats};

use super::pool::{PendingRequest, PoolEntry, WORK_POOL_ABS_CEILING, WORK_POOL_EXTRA};
use super::proxy_ops::{err_msg, unregister_control};
use super::{write_ctl_msg, ControlContext, ControlState};

/// Identity used for authorization decisions.
///
/// Go frp never rewrites `LoginMsg.User` when OIDC is enabled: the claimed
/// user drives proxy ownership and visitor `allow_users` checks, while the
/// verified JWT subject is used only for NewWorkConn/Ping verification.
pub(crate) fn authenticated_user(
    claimed_user: Option<&str>,
    _oidc_subject: Option<&str>,
) -> String {
    claimed_user.unwrap_or_default().to_string()
}

/// Clamp the client's requested pool_count against the server-side
/// `max_pool_count`, and against the absolute ceiling `WORK_POOL_ABS_CEILING`
/// when `max_pool_count` is unset (0) — the client must not be able to make
/// the server pool an unbounded number of work conns (audit fix). Go frp
/// treats poolCount < 1 as 1.
fn capped_pool_count(pool_count: Option<i32>, max_pool_count: i64) -> usize {
    let raw = pool_count.unwrap_or(1).max(1) as i64;
    let capped = if max_pool_count > 0 {
        raw.min(max_pool_count)
    } else {
        raw.min(WORK_POOL_ABS_CEILING as i64)
    };
    capped.max(1) as usize
}

async fn remove_oidc_subject_generation(state: &AppState, run_id: &str, control_id: u64) {
    let mut subjects = state.oidc.subjects.write().await;
    if subjects
        .get(run_id)
        .is_some_and(|(_, generation)| *generation == control_id)
    {
        subjects.remove(run_id);
    }
}

async fn flush_login_response_and_signal<W>(
    stream: &mut W,
    auth_success: Option<oneshot::Sender<()>>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    stream.flush().await?;
    if let Some(auth_success) = auth_success {
        let _ = auth_success.send(());
    }
    Ok(())
}

/// Write a LoginResp error frame and drop the stream.
///
/// Every auth-failure path in `authenticate` sends the same shape of
/// LoginResp (version + error, no run_id) and then returns `Err(())`.
/// Extracted into its own function so the login state machine contains
/// one copy of the message construction + write instead of six.
#[inline(never)]
async fn send_login_error(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    error: String,
    v2: bool,
) {
    let (_, mut writer) = tokio::io::split(stream);
    let resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: None,
        error: Some(error),
        server_additional_auth_scopes: None,
    });
    let _ = write_ctl_msg(&mut writer, &resp, v2).await;
}

/// Verify login credentials and run timestamp replay protection.
///
/// On success returns the verified OIDC subject (if any) together with the
/// still-open stream for the caller's post-auth phases. On failure sends a
/// LoginResp error (consuming the stream) and returns `Err(())`.
///
/// Extracted from `authenticate` so the large login future is split into
/// two smaller state machines (auth phase + setup phase).
#[inline(never)]
async fn verify_login_auth(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: &Arc<AppState>,
    peer: Option<SocketAddr>,
    v2: bool,
    internal: bool,
) -> Result<
    (
        Option<String>,
        Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    ),
    (),
> {
    // --- Authenticate ---
    // Internal connections (SSH gateway) with AlwaysAuthPass bypass all auth.
    // always_auth_pass is Option<Option<bool>>: outer Option is ClientSpec presence
    // (Go clients never send ClientSpec; only internal/Rust connections do).
    // Inner Option<bool> defaults to false. Only Some(Some(true)) triggers bypass.
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
                if oidc_token.subject.trim().is_empty() {
                    warn!(peer = ?peer, "OIDC auth failed: subject claim is empty");
                    return Err(());
                }
                // jti replay protection: same jti + same subject is allowed
                // (frpc reconnects reuse the cached token); same jti +
                // different subject is rejected as a cross-identity replay.
                if let Err(e) = verifier.check_replay(
                    oidc_token.jti.as_deref(),
                    &oidc_token.subject,
                    oidc_token.expiry,
                ) {
                    warn!(peer = ?peer, error = %e, "OIDC login rejected: {}", e);
                    send_login_error(
                        stream,
                        err_msg(
                            state.detailed_errors_to_client,
                            "OIDC authentication failed".to_string(),
                            "OIDC authentication failed",
                        ),
                        v2,
                    )
                    .await;
                    return Err(());
                }
                info!(subject = %oidc_token.subject, "OIDC login verified: subject={}", oidc_token.subject);
                Some(oidc_token.subject)
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "OIDC auth failed for {:?}: {}", peer, e);
                send_login_error(
                    stream,
                    err_msg(
                        state.detailed_errors_to_client,
                        "OIDC authentication failed".to_string(),
                        "OIDC authentication failed",
                    ),
                    v2,
                )
                .await;
                return Err(());
            }
        }
    } else {
        let auth_cfg = state.reloadable.read_ok().auth_cfg.clone();
        let login_auth = auth_cfg.resolve_token().and_then(|token| {
            auth_cfg.validate_login_with_token(
                &token,
                login.privilege_key.as_deref(),
                login.timestamp,
            )
        });
        if let Err(e) = login_auth {
            warn!(peer = ?peer, error = %e, "Authentication failed for {:?}: {}", peer, e);
            // Rate-limit failed logins per IP (Go frp LoginThrottle parity).
            // Only failures consume a slot — successful logins are not counted.
            let throttled = match peer {
                Some(addr) => !state.check_login_throttle(addr).await,
                None => false, // no peer address → cannot throttle
            };
            if throttled {
                warn!(peer = ?peer, "Login throttled for {:?} (too many failed attempts)", peer);
                send_login_error(
                    stream,
                    err_msg(
                        state.detailed_errors_to_client,
                        "login throttled: too many failed attempts".to_string(),
                        "login throttled",
                    ),
                    v2,
                )
                .await;
                return Err(());
            }
            // Emit WebSocket event for dashboard subscribers
            #[cfg(feature = "dashboard")]
            {
                let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                    message: format!("Authentication failed for {:?}", peer),
                    context: Some("login".into()),
                });
            }
            send_login_error(
                stream,
                err_msg(
                    state.detailed_errors_to_client,
                    e,
                    "token authentication failed",
                ),
                v2,
            )
            .await;
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
                    send_login_error(stream, e, v2).await;
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
                // Bound the per-timestamp duplicate-detection set: a single
                // timestamp key must not grow without bound. An attacker that
                // can pass token auth can otherwise inject unique run_ids
                // within one second and grow this map indefinitely
                // (token-reachable OOM). Legitimate clients hitting the cap
                // are rejected for this second and retry on the next timestamp.
                const MAX_ENTRIES_PER_TIMESTAMP: usize = 100;
                // Prune FIRST (both precisions): keys are milliseconds (frpc)
                // or seconds (Go frpc). With seconds-only pruning, ms keys
                // (~1.75e12) would never be < the seconds threshold and the
                // table would grow unbounded. Running the prune before the
                // cap check also means a full table drains stale entries and
                // reopens — the cap check itself must never become a
                // permanent login lockout.
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                let timeout_ms = auth_cfg.authentication_timeout.saturating_mul(1000);
                let threshold_ms = now_ms.saturating_sub(timeout_ms);
                let threshold_s = (now_ms / 1000).saturating_sub(auth_cfg.authentication_timeout);
                // Keys < 1e12 are seconds-precision (Go frpc); >= 1e12 are ms.
                const MS_EPOCH: i64 = 1_000_000_000_000;
                used.retain(|k, _| {
                    if *k >= MS_EPOCH {
                        *k >= threshold_ms
                    } else {
                        *k >= threshold_s
                    }
                });
                // Global bound on the whole table (defense-in-depth): with a
                // large authenticationTimeout the per-second cap alone allows
                // ~2*timeout*100 entries. If the table is STILL full after
                // pruning (sustained attack), degrade to freshness-only
                // duplicate detection (matching Go frps, which has no
                // duplicate table) instead of rejecting every login — a
                // reject-here would lock out all legitimate clients until
                // frps restarts.
                const MAX_TOTAL_REPLAY_ENTRIES: usize = 100_000;
                let total: usize = used.values().map(|s| s.len()).sum();
                if total >= MAX_TOTAL_REPLAY_ENTRIES {
                    warn!(
                        peer = ?peer,
                        "Login: replay-detection table full ({} entries, cap {}); degraded to freshness-only duplicate detection",
                        total, MAX_TOTAL_REPLAY_ENTRIES,
                    );
                } else {
                    let entry = used.entry(ts).or_default();
                    if entry.len() >= MAX_ENTRIES_PER_TIMESTAMP {
                        warn!(
                            peer = ?peer, ts = ts,
                            "Login rejected: too many unique run_ids for timestamp {} (cap {})",
                            ts, MAX_ENTRIES_PER_TIMESTAMP,
                        );
                        send_login_error(
                            stream,
                            "login rejected: too many login attempts for this timestamp".into(),
                            v2,
                        )
                        .await;
                        return Err(());
                    }
                    if !entry.insert(run_id_for_check.clone()) {
                        // Duplicate (run_id, ts). Rust frpc sends
                        // MILLISECONDS keys — a genuine replay reuses an
                        // identical ms stamp, so reject. Go frpc reuses its
                        // run_id and sends SECONDS keys: a reconnect landing
                        // in the same wall-clock second collides with the
                        // previous login and is indistinguishable from a
                        // replay; admit it (the freshness window still
                        // bounds real replays).
                        if ts < MS_EPOCH {
                            debug!(
                                peer = ?peer, run_id = %run_id_for_check, ts = %ts,
                                "Login: duplicate seconds-precision (run_id, ts) — treating as same-second Go frpc reconnect"
                            );
                        } else {
                            warn!(
                                peer = ?peer, run_id = %run_id_for_check, ts = %ts,
                                "Replay attack detected: duplicate (run_id, timestamp) pair for run_id={} ts={}",
                                run_id_for_check, ts,
                            );
                            send_login_error(
                                stream,
                                "replay attack detected: duplicate timestamp".into(),
                                v2,
                            )
                            .await;
                            return Err(());
                        }
                    }
                }
            }
        }

        None
    };

    Ok((oidc_subject, stream))
}

/// Authenticate a new control connection and set up per-client state.
/// On success returns all state needed by the main select! loop.
/// On failure sends LoginResp with an error and returns `Err(())`.
/// When `internal` is true and the login's ClientSpec.AlwaysAuthPass is set,
/// authentication is bypassed (Go frp SSH gateway compat).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(crate) async fn authenticate(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    internal: bool,
    auth_success: Option<oneshot::Sender<()>>,
) -> Result<
    (
        ControlContext,
        ControlState,
        mpsc::Sender<InternalMsg>,
        mpsc::Receiver<InternalMsg>,
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
        Option<IncomingStreams>,
    ),
    (),
> {
    // Login throttle removed — it counted both successful and failed attempts,
    // causing legitimate reconnects to be throttled after 5 connections in 60s
    // per IP. Brute-force protection is still provided by auth failure logging
    // and the reconnect backoff on the client side.

    // --- Authenticate ---
    // Split into its own state machine (OIDC/token verification + timestamp
    // replay protection) so this function and the auth phase are each much
    // smaller than the previous single 45 KiB future.
    //
    // The auth future is polled through a `dyn Future` vtable: `#[inline(never)]`
    // does not stop LLVM from inlining an async fn's poll into its single
    // caller, which would merge the two state machines back into one giant
    // function. One vtable call per connection is irrelevant (auth runs once).
    type AuthFuture<'a> = dyn Future<
            Output = Result<
                (
                    Option<String>,
                    Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
                ),
                (),
            >,
        > + Send
        + 'a;
    let auth_fut: Pin<Box<AuthFuture<'_>>> =
        Box::pin(verify_login_auth(stream, login, &state, peer, v2, internal));
    let (oidc_subject, mut stream) = auth_fut.await?;

    let reloadable = state.reloadable.read_ok().clone();
    let authenticated_user = authenticated_user(login.user.as_deref(), oidc_subject.as_deref());

    let run_id = login
        .run_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!(peer = ?peer, run_id = %run_id, "Client {:?} logged in with run_id: {}", peer, run_id);

    // --- Server plugin: login hook ---
    // Skip payload construction entirely when no plugins are configured
    // (the default) — json! builds a full Value on every login otherwise.
    if !state.plugin_manager.is_empty() {
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
            send_login_error(stream, reason, v2).await;
            return Err(());
        }
    }

    // --- Set up internal channel ---
    let (internal_tx, internal_rx) = mpsc::channel::<InternalMsg>(1024);
    let pool_stats = Arc::new(PoolStats::default());

    // ── Control Manager: Admit phase ──────────────────────────────────
    // Assign a monotonically increasing control_id to distinguish this
    // control generation from any previous one with the same run_id.
    let control_id = state.control_id_counter.fetch_add(1, Ordering::SeqCst);

    if let Some(ref subject) = oidc_subject {
        state
            .oidc
            .subjects
            .write()
            .await
            .insert(run_id.clone(), (subject.clone(), control_id));
    }

    // Acquire per-runID mutex to serialize lifecycle transitions.
    // This prevents two concurrent logins for the same run_id from racing.
    let (run_mu, run_mu_guard) = state.get_run_mu(&run_id);
    let run_guard = run_mu.lock().await;

    // Check for existing control and set up handoff barrier.
    // The new handler waits for the old handler's cleanup to complete
    // before proceeding (Go frp dev control.go lifecycle).
    let handoff_barrier: Option<oneshot::Receiver<()>> = {
        if let Some(old_ctl) = state.run_id_to_ctl_tx.get(&run_id).map(|c| c.clone()) {
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
    state.run_id_to_ctl_tx.insert(
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
            // Proxy ownership/access control must use the verified OIDC
            // subject. Proxy names and registry keys above intentionally
            // retain the claimed user for Go wire compatibility.
            user: authenticated_user.clone(),
            control_id,
        },
    );

    // Release run_mu before waiting for the handoff barrier — the old
    // handler's cleanup may need to acquire run_mu (via unregister_control
    // or future code paths). This matches Go frp dev's WaitForHandoff()
    // which is called outside the per-runID serialization lock.
    drop(run_guard);

    if let Some(barrier) = handoff_barrier {
        info!(run_id = %run_id, "Waiting for old control handler shutdown...");
        // Defense-in-depth timeout: if the old handler exits via a client
        // read error before consuming the queued Shutdown, its `done` may
        // never be signaled. Cleanup is idempotent and control_id-guarded
        // (unregister_control skips entries owned by a newer control), so
        // proceeding after the timeout is safe — never block reconnects.
        let _ = tokio::time::timeout(Duration::from_secs(10), barrier).await;
        info!(run_id = %run_id, "Old control handler shutdown complete");
    }

    // Re-acquire run_mu for the Activate and CompleteLogin phases.
    // This matches Go frp dev's Activate (which re-enters the ControlManager
    // serialization lock after WaitForHandoff returns).
    let run_guard = run_mu.lock().await;

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
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: None,
            error: Some("client already online".into()),
            server_additional_auth_scopes: None,
        });
        let _ = write_ctl_msg(&mut stream, &resp, v2).await;
        // TODO(audit-fix): the duplicate-login conflict path sweeps the LIVE
        // control's routes. unregister_control runs with THIS login's control
        // id — assigned from the monotonically increasing counter (see above),
        // so it is HIGHER than the live control's — and its generation filter
        // (p.control_id <= control_id) lets the live control's older proxies
        // through, tearing down its port marks, vhost routes, and sk_index
        // entries. The conflict path should arguably not sweep at all: only
        // the generation-guarded run_id_to_ctl_tx removal (already done above
        // the sweep) and the OIDC-subject cleanup below are wanted. Do not
        // call unregister_control here until it gains a sweep-free mode.
        unregister_control(&state, &run_id, control_id, false).await;
        // Clean up OIDC subject
        if oidc_subject.is_some() {
            remove_oidc_subject_generation(&state, &run_id, control_id).await;
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
    // Hex-dump the raw LoginResp frame for Go compat debugging.
    // debug-level only: re-serializing the frame purely for logging cost
    // an allocation + utf8_lossy on every login at the default INFO level.
    if tracing::enabled!(tracing::Level::DEBUG) {
        let type_byte = resp.v1_type_byte();
        let payload = serde_json::to_vec(&resp).unwrap_or_default();
        let frame_len = 9 + payload.len();
        let proto_label = if v2 { "V2" } else { "V1" };
        debug!(
            peer = ?peer, run_id = %run_id,
            type_byte = format_args!("{:#04x}", type_byte),
            payload_len = payload.len(),
            payload_text = %String::from_utf8_lossy(&payload),
            "LoginResp {} frame: type={:#04x} len={} frame_total={} json={}",
            proto_label, type_byte, payload.len(), frame_len,
            String::from_utf8_lossy(&payload),
        );
    }
    // Go frp compat: write LoginResp with 5-second deadline
    let resp_send = tokio::time::timeout(
        Duration::from_secs(5),
        write_ctl_msg(&mut stream, &resp, v2),
    );
    if let Err(e) = match resp_send.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => {
            warn!(peer = ?peer, "LoginResp write timed out after 5s for {:?}", peer);
            Err(frp_core::Error::Protocol(
                "LoginResp write timed out".into(),
            ))
        }
    } {
        warn!(peer = ?peer, error = %e, "Failed to send login response to {:?}: {}", peer, e);
        unregister_control(&state, &run_id, control_id, false).await;
        // Clean up registry entry
        state
            .client_registry
            .mark_offline_by_run_id_and_control_id(&run_id, control_id);
        // Clean up OIDC subject
        if oidc_subject.is_some() {
            remove_oidc_subject_generation(&state, &run_id, control_id).await;
        }
        return Err(());
    }
    // Flush TLS stream to ensure LoginResp reaches KCP before we wrap in CipherStream
    if let Err(e) = flush_login_response_and_signal(&mut *stream, auth_success).await {
        warn!(peer = ?peer, error = %e, "Failed to flush after LoginResp: {}", e);
        unregister_control(&state, &run_id, control_id, false).await;
        state
            .client_registry
            .mark_offline_by_run_id_and_control_id(&run_id, control_id);
        if oidc_subject.is_some() {
            remove_oidc_subject_generation(&state, &run_id, control_id).await;
        }
        return Err(());
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
                    stream,
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
                        unregister_control(&state, &run_id, control_id, false).await;
                        return Err(());
                    }
                }
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to derive AEAD keys for {:?}: {}", peer, e);
                unregister_control(&state, &run_id, control_id, false).await;
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
        //
        // Security note: when V2 is negotiated without AEAD (plain V2 path)
        // and tls_enable is false, this CFB wrapping serves as an encryption
        // safety net for the control connection. Without it, a plain V2
        // control channel over raw TCP would transmit all control messages
        // (including auth tokens in Login) in cleartext. The CFB cipher
        // derives its key from the auth token, so an attacker must already
        // know the token to decrypt. For production, prefer AEAD-negotiated
        // V2 or TLS to avoid potential CFB weaknesses (malleability, lack of
        // integrity protection).
        info!(peer = ?peer, run_id = %run_id, "Wrapping control stream in CipherStream (AES-128-CFB)");
        let enc_key = encryption::derive_key(&reloadable.auth_cfg.token);
        let cipher = frp_core::cipher_stream::CipherStream::new(stream, enc_key);
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
        let pool_count = capped_pool_count(login.pool_count, max_pool);
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
    let pool_cap = capped_pool_count(
        login.pool_count,
        state.server_config_snapshot.max_pool_count,
    ) + WORK_POOL_EXTRA;
    let work_pool: VecDeque<PoolEntry> = VecDeque::new();
    let pending_requests: VecDeque<PendingRequest> = VecDeque::new();
    let pending_udp: VecDeque<(String, Instant)> = VecDeque::new();
    let pending_nat_hole_sids: VecDeque<(String, String, Instant)> = VecDeque::new();
    // TCP/HTTP/STCP listener handles. UDP listeners are managed via the work-connection
    // mechanism (UdpNeedsWorkConn → ReqWorkConn → assign_udp_work_conn).
    let listener_handles: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let udp_sockets: HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> = HashMap::new();
    let shutting_down = false;
    let last_ping = Instant::now();

    Ok((
        ControlContext {
            state: state.clone(),
            pool_stats: pool_stats.clone(),
            reloadable,
            v2,
            run_id,
            control_id,
            pool_cap,
            internal_tx: internal_tx.clone(),
            peer,
            authenticated_user,
            _run_mu_guard: run_mu_guard,
        },
        ControlState {
            shutting_down,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool,
            pending_requests,
            pending_udp,
            pending_nat_hole_sids,
            listener_handles,
            udp_sockets,
            last_ping,
        },
        internal_tx,
        internal_rx,
        reader,
        writer,
        incoming,
    ))
}
#[cfg(test)]
mod auth_signal_tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::AsyncWrite;

    use super::flush_login_response_and_signal;

    fn test_state() -> Arc<crate::state::AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(crate::state::AppState::new(
            frp_core::auth::AuthConfig::with_token("expected-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("expected-token"),
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

    struct FlushWriter {
        fail_flush: bool,
    }

    impl AsyncWrite for FlushWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fail_flush {
                Poll::Ready(Err(io::Error::other("injected flush failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn successful_flush_signals_before_blocked_prewarm_work() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut writer = FlushWriter { fail_flush: false };

        let task = tokio::spawn(async move {
            flush_login_response_and_signal(&mut writer, Some(tx))
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        tokio::time::timeout(std::time::Duration::from_millis(100), rx)
            .await
            .expect("auth signal must not wait for prewarm")
            .expect("successful flush must signal");
        task.abort();
    }

    #[tokio::test]
    async fn flush_failure_returns_error_without_auth_signal() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut writer = FlushWriter { fail_flush: true };

        assert!(flush_login_response_and_signal(&mut writer, Some(tx))
            .await
            .is_err());
        assert!(
            rx.await.is_err(),
            "flush failure must drop the unsent signal"
        );
    }

    #[tokio::test]
    async fn bad_token_returns_without_auth_signal() {
        let (server, mut client) = tokio::io::duplex(4096);
        let drain = tokio::spawn(async move {
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut client, &mut Vec::new()).await;
        });
        let login = frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: None,
            client_id: None,
            pool_count: None,
            timestamp: None,
            privilege_key: Some("bad-token".into()),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let result = super::authenticate(
            Box::new(server),
            &login,
            test_state(),
            Some("127.0.0.1:12345".parse().unwrap()),
            None,
            false,
            None,
            false,
            Some(tx),
        )
        .await;

        assert!(result.is_err());
        assert!(rx.await.is_err(), "bad token must drop the unsent signal");
        drain.abort();
    }
}

#[cfg(test)]
mod pool_count_tests {
    use super::capped_pool_count;
    use crate::control::pool::WORK_POOL_ABS_CEILING;

    #[test]
    fn unset_max_pool_count_clamps_to_absolute_ceiling() {
        // max_pool_count = 0 (unset): the client's pool_count must not be
        // able to make the server pool unbounded work conns (audit fix).
        assert_eq!(capped_pool_count(Some(100_000), 0), WORK_POOL_ABS_CEILING);
        assert_eq!(capped_pool_count(Some(65_000), 0), WORK_POOL_ABS_CEILING);
        // Below the ceiling: honored as requested.
        assert_eq!(capped_pool_count(Some(5), 0), 5);
        assert_eq!(capped_pool_count(None, 0), 1);
        // Go frp treats poolCount < 1 as 1.
        assert_eq!(capped_pool_count(Some(0), 0), 1);
    }

    #[test]
    fn configured_max_pool_count_wins() {
        assert_eq!(capped_pool_count(Some(100_000), 50), 50);
        assert_eq!(capped_pool_count(Some(5), 50), 5);
        assert_eq!(capped_pool_count(None, 50), 1);
        // The configured cap still applies above the absolute ceiling.
        assert_eq!(capped_pool_count(Some(100_000), 10_000), 10_000);
    }
}
