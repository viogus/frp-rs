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

/// Upper bound for the supersession Shutdown send when the old control's
/// internal channel is full (round-7 audit LOW). A draining control frees a
/// slot within this window; a wedged one costs at most this delay per
/// reconnect — bounded, so no parked-task accumulation.
const SUPERSESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
use tracing::{debug, info, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;

use crate::lock::RwLockExt;
use crate::state::{AppState, ControlTx, InternalMsg, PoolStats, ReplayCheck};

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

pub(crate) async fn remove_oidc_subject_generation(
    state: &AppState,
    run_id: &str,
    control_id: u64,
) {
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
    // Go frp compat: reject-path LoginResp writes carry the same 5-second
    // deadline as the success path (audit H4). This helper is the single
    // choke point for every reject path, so the deadline covers them all.
    // The error frame is best-effort — on timeout the stream drops with it.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        write_ctl_msg(&mut writer, &resp, v2),
    )
    .await;
}

/// Consume a per-IP login-throttle slot for a FAILED auth attempt and
/// return the throttled LoginResp message when the IP has exceeded its
/// window quota (`None` → the attempt proceeds to the normal error
/// response).
///
/// Deliberate frp-rs hardening (NOT Go frp parity — Go frp v0.71.0 has
/// no login throttle in its source): only failures consume a slot — this
/// helper is invoked on failure paths only, so successful logins are
/// never counted and legitimate reconnects are never throttled (except
/// a same-ms run_id replay from a sub-tick reconnect, which counts as
/// a failure like any other replay). An IP is
/// rejected for the 60s window after the 5th failure (per-IP fixed 60s
/// window anchored at the first counted failure, capped table with a
/// coarse overflow bucket).
async fn throttled_login_error(state: &AppState, peer: Option<SocketAddr>) -> Option<String> {
    let throttled = match peer {
        Some(addr) => !state.check_login_throttle(addr).await,
        None => false, // no peer address → cannot throttle
    };
    if !throttled {
        return None;
    }
    warn!(
        peer = ?peer,
        "Login throttled for {:?} (too many failed attempts)",
        peer
    );
    Some(err_msg(
        state.detailed_errors_to_client,
        "login throttled: too many failed attempts".to_string(),
        "login throttled",
    ))
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

    // The pre-auth throttle gate lives in `authenticate`, BEFORE the plugin
    // hook (see there — a throttled IP must not trigger plugin HTTP calls
    // either). The failure paths below still consume a slot via
    // `throttled_login_error`.

    let oidc_subject: Option<String> = if is_auth_bypass {
        None
    } else if let Some(ref verifier) = state.oidc.verifier {
        let token = login.privilege_key.as_deref().unwrap_or("");
        match verifier.verify_login(token).await {
            Ok(oidc_token) => {
                if oidc_token.subject.trim().is_empty() {
                    warn!(peer = ?peer, "OIDC auth failed: subject claim is empty");
                    // Rate-limit failed logins per IP (F1): the OIDC path
                    // must not be exempt from the login throttle, and the
                    // client needs a LoginResp error rather than a silent
                    // hang.
                    if let Some(msg) = throttled_login_error(state, peer).await {
                        send_login_error(stream, msg, v2).await;
                        return Err(());
                    }
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
                // jti replay protection: same jti + same subject is allowed
                // (frpc reconnects reuse the cached token); same jti +
                // different subject is rejected as a cross-identity replay.
                if let Err(e) = verifier.check_replay(
                    oidc_token.jti.as_deref(),
                    &oidc_token.subject,
                    oidc_token.expiry,
                ) {
                    warn!(peer = ?peer, error = %e, "OIDC login rejected: {}", e);
                    // Rate-limit failed logins per IP — the OIDC path must
                    // not be exempt from the login throttle (F1).
                    if let Some(msg) = throttled_login_error(state, peer).await {
                        send_login_error(stream, msg, v2).await;
                        return Err(());
                    }
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
                // Rate-limit failed logins per IP (F1): the OIDC path must
                // not be exempt from the login throttle — an
                // unauthenticated attacker can otherwise send forged JWTs
                // at any rate, each costing a signature verification (+ a
                // JWKS refresh retry, itself cooldown-gated in the
                // verifier).
                if let Some(msg) = throttled_login_error(state, peer).await {
                    send_login_error(stream, msg, v2).await;
                    return Err(());
                }
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
            // Rate-limit failed logins per IP (deliberate frp-rs hardening
            // — Go frp v0.71.0 has no login throttle). Only failures
            // consume a slot — successful logins are not counted.
            if let Some(msg) = throttled_login_error(state, peer).await {
                send_login_error(stream, msg, v2).await;
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

        // The negative pool_count rejection now lives in `authenticate`,
        // AFTER the plugin hook and auth — Go NewControl parity, validated
        // against the MUTATED login (control.go:437).

        // --- Validate run_id (Go frp v0.71.0 ValidateRunID) ---
        // Go 0.71.0 server/service.go rejects a client-supplied run id that is
        // empty, longer than 64 bytes, or contains non-printable characters
        // before it enters routing tables / logs / dashboards. frp-rs
        // normalizes a missing run_id to a generated UUID below, but a
        // client-supplied oversized or control-character run_id must be
        // rejected to match Go behavior (and to keep log lines and map keys
        // well-formed). Rust Strings are always valid UTF-8, so only the
        // length and printable-character checks apply.
        if let Some(rid) = login.run_id.as_deref() {
            if !rid.is_empty() && (rid.len() > 64 || rid.chars().any(|c| c.is_control())) {
                warn!(peer = ?peer, run_id_len = %rid.len(), "Login rejected: invalid run_id (max 64 printable bytes)");
                send_login_error(
                    stream,
                    "invalid run id: must be at most 64 printable bytes".into(),
                    v2,
                )
                .await;
                return Err(());
            }
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
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                let mut used = state.used_timestamps.lock().await;
                // Prune FIRST (both precisions): keys are milliseconds (frpc)
                // or seconds (Go frpc). A leading-key drain (BTreeMap is
                // ordered by timestamp, so expired keys are always the
                // smallest) is O(expired keys) per login instead of a
                // full-map scan; the total is tracked incrementally (F4).
                // Running the prune before the record also means a full table
                // drains stale entries and reopens — the caps themselves
                // never become a permanent login lockout.
                let pruned = used.prune_expired(now_ms, auth_cfg.authentication_timeout);
                if pruned > 0 {
                    debug!(
                        peer = ?peer, pruned = pruned,
                        "Login: pruned {} expired entries from the replay-detection table",
                        pruned,
                    );
                }
                // Record the (run_id, ts) pair. Neither memory cap rejects a
                // login: the per-timestamp cap evicts the oldest run_id, the
                // global cap evicts whole oldest keys (F3/F4) — only an
                // identical ms-precision (run_id, ts) replay is rejected.
                // The decision is produced under the lock, but the rejection
                // write happens AFTER dropping it: send_login_error awaits a
                // network write, which must not hold the shared
                // used_timestamps lock (a slow/blocked peer would stall every
                // concurrent login).
                let reject_replay = match used.record(ts, &run_id_for_check) {
                    ReplayCheck::Admitted => None,
                    ReplayCheck::DuplicateSecondsPrecision => {
                        // Duplicate (run_id, ts). Go frpc reuses its run_id
                        // and sends SECONDS keys: a reconnect landing in the
                        // same wall-clock second collides with the previous
                        // login and is indistinguishable from a replay; admit
                        // it (the freshness window still bounds real replays).
                        debug!(
                            peer = ?peer, run_id = %run_id_for_check, ts = %ts,
                            "Login: duplicate seconds-precision (run_id, ts) — treating as same-second Go frpc reconnect"
                        );
                        None
                    }
                    ReplayCheck::Replay => {
                        // Rust frpc sends MILLISECONDS keys — a genuine
                        // replay reuses an identical ms stamp, so reject.
                        warn!(
                            peer = ?peer, run_id = %run_id_for_check, ts = %ts,
                            "Replay attack detected: duplicate (run_id, timestamp) pair for run_id={} ts={}",
                            run_id_for_check, ts,
                        );
                        Some("replay attack detected: duplicate timestamp".to_string())
                    }
                };
                drop(used);
                if let Some(error) = reject_replay {
                    // Replay rejections consume a throttle slot like any
                    // other failure: without this, an attacker replaying
                    // captured (ts, md5, run_id) triples could retry
                    // freely — each rejection was uncounted — and never
                    // advance toward the throttle that caps their later
                    // guess attempts.
                    let throttled = throttled_login_error(state, peer).await;
                    send_login_error(stream, throttled.unwrap_or(error), v2).await;
                    return Err(());
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
    // Login throttle: FAIL-ONLY rate limiting (deliberate frp-rs hardening
    // — Go frp v0.71.0 has no login throttle).
    // `check_login_throttle` is invoked on authentication failure below and
    // counts only failed attempts — successful logins never consume a slot,
    // so legitimate reconnects are never throttled. A throttled IP is
    // rejected for the 60s window after the 5th failure (per-IP fixed 60s
    // window anchored at the first counted failure, capped table with a
    // coarse overflow bucket).

    // --- Throttle gate FIRST (frp-rs DoS protection — no Go equivalent) ---
    // Round 6 (MEDIUM B5): reject an already-throttled IP BEFORE any work —
    // before auth AND before the server plugin hook, so a brute-force flood
    // of bad tokens pays neither MD5 / OIDC JWT verify CPU per attempt nor
    // triggers plugin HTTP round-trips (the plugin can be a remote service).
    // Pure check (no slot consumed): the failure paths below still consume
    // a slot via `throttled_login_error`, so a successful login never
    // counts and window semantics are unchanged. Skipped for internal
    // AlwaysAuthPass (bypass paths never throttle).
    let is_auth_bypass = internal
        && login
            .client_spec
            .as_ref()
            .and_then(|cs| cs.always_auth_pass)
            .unwrap_or(false);
    if !is_auth_bypass && state.is_login_throttled(peer).await {
        warn!(
            peer = ?peer,
            "Login rejected pre-auth: IP already throttled",
        );
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

    // Effective run_id: computed up-front (pre-plugin) so the Login hook
    // payload can carry it — a client that omits run_id still appears as
    // the assigned UUID (the value registration actually uses).
    let run_id = login
        .run_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // --- Server plugin: login hook (Go parity: BEFORE auth verify) ---
    // Go frp v0.71.0 server/service.go handleConnection: the plugin hook
    // runs FIRST, and on success the mutated login (`m = &retContent.Login`)
    // is what RegisterControl consumes — VerifyLogin (token OR OIDC) runs
    // inside RegisterControl, and the negative pool_count check runs inside
    // NewControl, both AFTER the plugin. Consequences (Go parity): failed-
    // auth logins STILL reach plugins (monitoring/security plugins depend
    // on it), plugin mutations of auth fields (privilege_key / timestamp /
    // pool_count / user) are honored, and a plugin can repair or reject a
    // negative pool_count before it is validated.
    let mut login = login.clone();
    // Skip payload construction entirely when no plugins are configured
    // (the default) — json! builds a full Value on every login otherwise.
    if !state.plugin_manager.is_empty() {
        // Go pkg/plugin/server/types.go LoginContent: the full flat Login
        // msg plus `client_address` (the peer address). Serializing the
        // struct guarantees every Go field is present with Go wire names;
        // `remote_addr` stays as a frp-rs extra (additive).
        let mut login_content = match serde_json::to_value(&login) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Server plugin login content serialize error: {}", e);
                send_login_error(
                    stream,
                    format!("server plugin login content error: {e}"),
                    v2,
                )
                .await;
                return Err(());
            }
        };
        if let Some(obj) = login_content.as_object_mut() {
            let peer_str = peer.map(|a| a.to_string()).unwrap_or_default();
            obj.insert("client_address".into(), serde_json::json!(peer_str));
            obj.insert("remote_addr".into(), serde_json::json!(peer_str));
            // Go always serializes client_spec (omitempty is a no-op on
            // structs); emit {} when unset for exact payload parity.
            let client_spec = match &login.client_spec {
                Some(spec) => serde_json::to_value(spec).unwrap_or_default(),
                None => serde_json::json!({}),
            };
            obj.insert("client_spec".into(), client_spec);
            // Effective run_id: a client that omits it still appears as the
            // assigned UUID (the value registration actually uses), so the
            // plugin payload always matches Go's (Go frpc always sends one).
            if login.run_id.is_none() {
                obj.insert("run_id".into(), serde_json::json!(run_id));
            }
        }
        match state.plugin_manager.notify("login", login_content).await {
            Err(reason) => {
                warn!(run_id = %run_id, reason = %reason, "Login for run_id {} rejected by server plugin: {}", run_id, reason);
                send_login_error(stream, reason, v2).await;
                return Err(());
            }
            Ok(Some(mutated)) => {
                // Go handleMutableContent (manager.go:75-96): a plugin with
                // unchange:false replaces the typed Login. Fail closed on
                // invalid content — a malformed mutation must not silently
                // pass through.
                match crate::plugin::apply_plugin_mutation(&login, mutated) {
                    Ok(m) => login = m,
                    Err(e) => {
                        warn!(run_id = %run_id, error = %e, "Login plugin returned invalid content for run_id {}: {}", run_id, e);
                        send_login_error(stream, e, v2).await;
                        return Err(());
                    }
                }
            }
            Ok(None) => {}
        }
    }

    // --- Authenticate on the MUTATED login ---
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
    let auth_fut: Pin<Box<AuthFuture<'_>>> = Box::pin(verify_login_auth(
        stream, &login, &state, peer, v2, internal,
    ));
    let (oidc_subject, mut stream) = auth_fut.await?;

    // --- Reject negative pool_count (Go frp v0.71.0 fix; NewControl parity) ---
    // Go rejects a negative pool_count in NewControl (server/control.go:437),
    // AFTER RegisterControl's VerifyLogin — so the check runs on the
    // MUTATED login: a plugin mutation can repair a negative value, and a
    // negative value introduced by a mutation is rejected here. frp-rs
    // previously clamped to 1 (no panic), but reject to match Go behavior.
    if let Some(pc) = login.pool_count {
        if pc < 0 {
            warn!(peer = ?peer, pool_count = %pc, "Login rejected: negative pool_count {}", pc);
            send_login_error(
                stream,
                format!("invalid pool count {pc}: must be non-negative"),
                v2,
            )
            .await;
            return Err(());
        }
    }

    let reloadable = state.reloadable.read_ok().clone();
    let authenticated_user = authenticated_user(login.user.as_deref(), oidc_subject.as_deref());
    info!(peer = ?peer, run_id = %run_id, "Client {:?} logged in with run_id: {}", peer, run_id);

    // Record the (possibly plugin-mutated) client identity for the `user`
    // object of later plugin hooks (Go loginUserInfo: LoginMsg.User/Metas
    // + runID).
    if !state.plugin_manager.is_empty() {
        state.plugin_manager.record_login_user(
            &run_id,
            &crate::plugin::UserInfo {
                user: login.user.clone().unwrap_or_default(),
                metas: login.metas.clone().unwrap_or_default(),
                run_id: run_id.clone(),
            },
        );
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
                    // A wedged old control (dead-slow peer that never drains
                    // its internal channel) would make `old_tx.send(...).await`
                    // hang forever, accumulating one parked task per reconnect
                    // — hence the try_send fast paths above. But a channel
                    // that is full yet DRAINING (busy control briefly blocked
                    // on read_msg while 1024 VisitorConns queue) was left
                    // unsuperseded by a plain drop: its registrations, pending
                    // queues, and bridges linger until the socket dies
                    // (round-7 audit LOW). Park with a bounded timeout
                    // instead: a draining control frees a slot and receives
                    // the Shutdown; a wedged one costs at most
                    // SUPERSESSION_SHUTDOWN_TIMEOUT. The wait is bounded per
                    // reconnect, so no task accumulation. On timeout or close
                    // the message drops and its `done` oneshot sender drops
                    // with it, so the handoff barrier below resolves
                    // immediately (Err) and the new login is never blocked.
                    // The control loop's post-exit drain (control/mod.rs)
                    // covers the delivered-but-undispatched case; a dropped
                    // Shutdown needs no drain, and cleanup's generation guard
                    // (unregister_control skips entries owned by a newer
                    // control) protects this control's fresh entry.
                    debug!(run_id = %run_id, "Old control handler channel full; bounded wait for a slot");
                    if tokio::time::timeout(
                        SUPERSESSION_SHUTDOWN_TIMEOUT,
                        old_ctl.tx.send(shutdown_msg),
                    )
                    .await
                    .is_err()
                    {
                        debug!(run_id = %run_id, "Old control handler channel still full; Shutdown dropped after {SUPERSESSION_SHUTDOWN_TIMEOUT:?}");
                        // Round-7 review finding: dropping the Shutdown left
                        // the old control alive until its socket died or the
                        // heartbeat fired (up to 90s), with stale
                        // registrations + same-name re-registration conflicts
                        // in the window. The flag the old handler checks at
                        // its loop top makes it exit as soon as it is free —
                        // eventual supersession without a parked task.
                        old_ctl
                            .superseded
                            .store(true, std::sync::atomic::Ordering::Release);
                    }
                    Some(rx)
                }
            }
        } else {
            None
        }
    };

    // Insert new ControlTx while holding run_mu.
    // Negotiated UDPPacket codec flows into the session registry so SUDP
    // visitor routing can inherit it (Go frp v0.71.0 admitVisitorByRunID).
    let udp_packet_codec = crypto_ctx
        .as_ref()
        .map(|c| c.udp_packet_codec.clone())
        .unwrap_or_default();
    // Shared supersession flag (round-7 review finding): a later login with
    // the same run_id sets it when it cannot deliver its Shutdown through a
    // full channel; the old handler's loop-top check sees it.
    let superseded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
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
            // Negotiated UDPPacket codec (Go frp v0.71.0 sessionCtx).
            udp_packet_codec: udp_packet_codec.clone(),
            // Wire protocol of this control (Go v0.71.0 work/visitor conn
            // wire-protocol enforcement).
            wire_v2: v2,
            superseded: superseded.clone(),
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
        // Go frp compat: same 5-second deadline as the success-path
        // LoginResp write (audit H4) — a wedged client must not pin this
        // login task + fd + semaphore permit while it holds run_mu.
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            write_ctl_msg(&mut stream, &resp, v2),
        )
        .await;
        // Sweep-free unregister. NOTE: on THIS path a full sweep would be
        // vacuous anyway — register_with_control_id only reports conflict
        // when the existing entry's run_id DIFFERS (registry.rs), and the
        // sweep is run_id-scoped, so it could never list the live control's
        // proxies. sweep=false is still required for the login FAILURE
        // paths below (LoginResp write / flush failures, which can happen
        // after the 10s handoff-barrier timeout): there THIS login's
        // control_id (assigned from the monotonically increasing counter,
        // see above) is HIGHER than the older live control's, so a full
        // sweep's generation filter (p.control_id <= control_id) would let
        // the older control's proxies through and tear down its port marks,
        // vhost routes, and sk_index entries while that control may still
        // be running (audit-fix: the barrier-timeout login failure path
        // swept the live control's routes). sweep=false keeps only the
        // generation-guarded run_id_to_ctl_tx removal and OIDC-subject
        // cleanup — this login registered no proxies, so nothing of its own
        // is left behind.
        unregister_control(&state, &run_id, control_id, false, false).await;
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
        unregister_control(&state, &run_id, control_id, false, false).await;
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
        unregister_control(&state, &run_id, control_id, false, false).await;
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
                        unregister_control(&state, &run_id, control_id, false, false).await;
                        return Err(());
                    }
                }
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to derive AEAD keys for {:?}: {}", peer, e);
                unregister_control(&state, &run_id, control_id, false, false).await;
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
    let udp_cancels: HashMap<String, tokio_util::sync::CancellationToken> = HashMap::new();
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
            // Go frp v0.71.0: the negotiated UDPPacket codec flows from the
            // V2 ServerHello (via CryptoContext) into the session context so
            // UDP/SUDP data planes can pick the packet codec.
            udp_packet_codec: crypto_ctx
                .as_ref()
                .map(|c| c.udp_packet_codec.clone())
                .unwrap_or_default(),
            _run_mu_guard: run_mu_guard,
        },
        ControlState {
            shutting_down,
            shutdown_done: None,
            udp_cancel: tokio_util::sync::CancellationToken::new(),
            udp_cancels,
            bridge_cancel: tokio_util::sync::CancellationToken::new(),
            work_pool,
            pending_requests,
            pending_udp,
            pending_nat_hole_sids,
            listener_handles,
            udp_sockets,
            last_ping,
            superseded,
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
            0,
            0,
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
mod send_login_error_deadline_tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite};

    use super::send_login_error;

    /// Stream whose read/write never complete — simulates a wedged-but-alive
    /// client the LoginResp error frame cannot be delivered to.
    struct StalledStream;

    impl AsyncRead for StalledStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for StalledStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    /// Audit H4 regression: send_login_error (the single choke point for
    /// every reject-path LoginResp) must carry the same 5-second deadline as
    /// the success path. A stalled client must not pin the login task + fd +
    /// permit forever. Paused time keeps the test instant.
    #[tokio::test(start_paused = true)]
    async fn send_login_error_bounded_by_5s_deadline() {
        let stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin> = Box::new(StalledStream);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_login_error(stream, "rejected".into(), false),
        )
        .await;
        assert!(
            result.is_ok(),
            "send_login_error must complete at the 5s deadline, got {result:?}"
        );
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

#[cfg(test)]
#[cfg(feature = "oidc")]
mod oidc_throttle_tests {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    use super::authenticate;
    use crate::state::AppState;

    /// Minimal OIDC discovery + JWKS mock on 127.0.0.1, plain HTTP, so an
    /// `OidcVerifier` can be built without external network access. Returns
    /// the issuer URL and a stop signal for the serving thread.
    fn oidc_mock_server() -> (String, std::sync::mpsc::Sender<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock OIDC server");
        let addr = listener.local_addr().expect("mock OIDC address");
        let issuer = format!("http://{addr}");
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "oct",
                "kid": "k1",
                "k": frp_core::base64::encode(b"mock-jwks-secret"),
            }]
        })
        .to_string();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 8192];
                        let n = Read::read(&mut stream, &mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        let path = req.split_whitespace().nth(1).unwrap_or("/");
                        let (status, body) = if path.contains(".well-known/openid-configuration") {
                            let jwks_uri = format!("http://{addr}/jwks");
                            (200, format!(r#"{{"jwks_uri":"{jwks_uri}"}}"#))
                        } else if path == "/jwks" {
                            (200, jwks.clone())
                        } else {
                            (404, String::new())
                        };
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = Write::write_all(&mut stream, resp.as_bytes());
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        (issuer, stop_tx)
    }

    /// Read one V1 LoginResp frame from the client side of the duplex and
    /// return its error field (empty when the login succeeded).
    async fn read_login_resp_error(client: &mut tokio::io::DuplexStream) -> String {
        let mut header = [0u8; 9];
        client
            .read_exact(&mut header)
            .await
            .expect("read frame header");
        let len = u64::from_be_bytes(header[1..9].try_into().unwrap()) as usize;
        assert!(len < 4096, "implausible frame length {len}");
        let mut payload = vec![0u8; len];
        client
            .read_exact(&mut payload)
            .await
            .expect("read frame payload");
        // Deserialize the bare LoginResp struct directly. The untagged
        // `FrpMessage` enum cannot be used here: `ReqWorkConn {}` (a
        // zero-field struct) matches ANY JSON object in untagged serde
        // matching, so even a genuine LoginResp payload would parse as
        // ReqWorkConn. Production wire decoding is unaffected — V1
        // dispatch (deserialize_v1) selects by type byte first.
        let resp: frp_core::msg::LoginResp =
            serde_json::from_slice(&payload).expect("parse LoginResp");
        resp.error.unwrap_or_default()
    }

    fn state_with_oidc(verifier: frp_core::auth::OidcVerifier) -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
            frp_core::auth::AuthConfig::with_token("unused-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("unused-token"),
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
            String::new(),
            true,
            30,
            7200,
            0,
            0,
            90,
            1500,
            false,
            Some(Arc::new(verifier)),
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

    #[tokio::test]
    async fn oidc_failures_consume_login_throttle_slots() {
        // F1: the OIDC branch of `verify_login_auth` must be subject to the
        // per-IP login throttle like the token branch. An unauthenticated
        // attacker sending forged JWTs (valid kid, garbage signature) must
        // be throttled after 5 failed attempts instead of getting an
        // unbounded per-IP failure rate.
        let (issuer, _stop) = oidc_mock_server();
        let verifier = frp_core::auth::OidcVerifier::new(
            issuer,
            "test-audience".into(),
            false, // skip_expiry
            false, // skip_issuer
            false, // skip_nbf
            false, // skip_audience
            Vec::new(),
            None,
            None,
        )
        .await
        .expect("OidcVerifier against mock");
        let state = state_with_oidc(verifier);

        // Forged JWT: valid kid, signature that fails against the mock
        // JWKS key → OIDC verification fails on every attempt (and the
        // in-verifier JWKS refresh cooldown prevents outbound fetches
        // beyond the first).
        let forged = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::HS256,
                kid: Some("k1".into()),
                ..jsonwebtoken::Header::default()
            },
            &serde_json::json!({"sub": "attacker", "exp": 4_102_444_800_u64}),
            &jsonwebtoken::EncodingKey::from_secret(b"attacker-secret"),
        )
        .expect("encode forged JWT");

        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = || frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: None,
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(forged.clone()),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };

        // Attempts 1..=5 fail auth (each consuming a throttle slot);
        // attempt 6 must be rejected with the throttled message.
        for attempt in 1..=6u32 {
            let (server, mut client) = tokio::io::duplex(4096);
            let result = authenticate(
                Box::new(server),
                &login(),
                state.clone(),
                Some(peer),
                None,
                false,
                None,
                false,
                None,
            )
            .await;
            assert!(result.is_err(), "attempt {attempt} must be rejected");
            let error = read_login_resp_error(&mut client).await;
            if attempt <= 5 {
                assert!(
                    error.contains("OIDC authentication failed"),
                    "attempt {attempt} must fail auth, got: {error}"
                );
            } else {
                assert!(
                    error.contains("throttled"),
                    "6th attempt must be throttled, got: {error}"
                );
            }
        }
    }
}
