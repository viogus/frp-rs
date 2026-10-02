//! Login credential verification, split by auth method.
//!
//! Token, OIDC, and timestamp-replay verification, moved out of the parent
//! `login` module (P5 seam: split `authenticate` by auth method, never by
//! reordering). `verify_login_auth` keeps the original dispatch order —
//! AlwaysAuthPass bypass, then OIDC when a verifier is installed, then token —
//! and each arm is a plain move of the arm it came from. The rejection that
//! must not hold the replay lock (`drop(used)` before `send_login_error`)
//! stays inside `check_token_replay`.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{debug, info, warn};

use frp_core::auth::{AuthConfig, OidcVerifier};
use frp_core::msg;

use crate::control::proxy_ops::err_msg;
use crate::lock::RwLockExt;
use crate::state::{AppState, ReplayCheck};

use super::send_login_error;
use super::throttle::throttled_login_error;

/// Verify login credentials and run timestamp replay protection.
///
/// On success returns the verified OIDC subject (if any) together with the
/// still-open stream for the caller's post-auth phases. On failure sends a
/// LoginResp error (consuming the stream) and returns `Err(())`.
///
/// Extracted from `authenticate` so the large login future is split into
/// two smaller state machines (auth phase + setup phase).
///
/// `throttle_keyed` marks whether the peer's source IP may key the per-IP
/// login throttle (audit E1/S1): TCP/TLS/WS/QUIC logins carry a real,
/// non-spoofable source → true. KCP logins are exempt (false) — their
/// "peer IP" is a spoofable UDP datagram source. See `AppState::login_throttle`
/// docs in state.rs for the full rationale.
#[inline(never)]
pub(super) async fn verify_login_auth(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: &Arc<AppState>,
    peer: Option<SocketAddr>,
    v2: bool,
    internal: bool,
    throttle_keyed: bool,
) -> Result<
    (
        Option<String>,
        Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    ),
    (),
> {
    // --- Authenticate ---
    // Internal connections (SSH gateway) with AlwaysAuthPass bypass all auth.
    // always_auth_pass is Option<Option<bool>>: the outer Option is ClientSpec
    // presence — Go's Login.ClientSpec is a VALUE struct with omitempty, which
    // is a no-op on structs, so Go ALWAYS emits `"client_spec":{"type":"",
    // "always_auth_pass":false}` (msg.go:89); the inner Option is the
    // always_auth_pass bool itself, default false. The bypass is gated on
    // `internal`, so only the SSH-gateway connection (which sets
    // Some(Some(true))) triggers it — a regular frpc's always-emitted
    // {"always_auth_pass": false} never bypasses.
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

    // Effective per-IP throttle key. `throttle_keyed=false` (KCP-sourced
    // logins — spoofable UDP source, see state.rs login_throttle docs)
    // disables the per-IP throttle entirely: failure paths below consume no
    // throttle slot (the pre-auth gate lives in `authenticate`). Socket-
    // layer KCP session caps (32/IP/10s, 256/10s global —
    // frp-core/src/kcp/socket.rs) remain the KCP attempt bound.
    let throttle_peer = if throttle_keyed { peer } else { None };

    // The pre-auth throttle gate lives in `authenticate`, BEFORE the plugin
    // hook (see there — a throttled IP must not trigger plugin HTTP calls
    // either). The failure paths below still consume a slot via
    // `throttled_login_error`.

    // Which credential validates this login is decided by **the verifier's
    // presence**, not by `auth_cfg.method`:
    //
    //   `state.oidc.verifier.is_some()`  ⟺  the process was started with
    //   `auth.method = "oidc"`
    //
    // The verifier is built once, in `Service::with_unsafe_features`, from the
    // startup method, and construction *fails* rather than starting without
    // one (`Cannot start frps with OIDC auth: …`). `Service::reload` then
    // never installs a `method` the verifier was not built for: the `AuthConfig`
    // it puts live is the running one with only `auth.token` /
    // `auth.tokenSource` / `auth.additionalAuthScopes` replaced, and
    // `auth.method` (like every other `[auth]` field) is only *reported* as
    // restart-required (`frp-server/src/service.rs`,
    // `note_auth_restart_changes`). So the two spellings of the dispatch — this
    // one and `auth_cfg.method == Oidc` — cannot disagree, and the other two
    // OIDC entry points key off the same field for the same reason
    // (`frp-server/src/handlers/dispatch.rs`,
    // `frp-server/src/control/proxy.rs`).
    //
    // If that invariant were ever broken (a hand-built state with
    // `method == Oidc` and no verifier), the `else` branch below runs the
    // **token** path, and `AuthConfig::validate_login_with_token` answers
    // `OIDC auth requires server-side verifier (not configured)` — it fails
    // closed, it does not accept a token under an OIDC-labelled config. Pinned
    // by
    // `frp-server/tests/server_reload_auth.rs::token_login_fails_closed_if_the_method_says_oidc_without_a_verifier`.

    if is_auth_bypass {
        Ok((None, stream))
    } else if let Some(ref verifier) = state.oidc.verifier {
        verify_oidc_login(stream, login, state, peer, v2, throttle_peer, verifier).await
    } else {
        verify_token_login(stream, login, state, peer, v2, throttle_peer).await
    }
}

/// OIDC arm of `verify_login_auth` (moved verbatim).
async fn verify_oidc_login(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: &Arc<AppState>,
    peer: Option<SocketAddr>,
    v2: bool,
    throttle_peer: Option<SocketAddr>,
    verifier: &Arc<OidcVerifier>,
) -> Result<
    (
        Option<String>,
        Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    ),
    (),
> {
    let token = login.privilege_key.as_deref().unwrap_or("");
    // S2: jti replay pre-check runs BEFORE the expensive verify_login
    // (JWKS fetch on a stale cache + signature verify). Claims are
    // extracted from the JWT payload segment without crypto; a replayed
    // token (same jti, different subject) is rejected with an O(1)
    // table hit. The pre-check never records — only fully verified
    // tokens populate the table, so an unauthenticated flood cannot
    // poison it or evict live entries. Malformed payloads skip the
    // pre-check and fall through to verify_login, which reports the
    // authoritative error.
    if let Ok((jti, subject, _exp)) = verifier.extract_claims_unverified(token) {
        if verifier.check_replay_pending(jti.as_deref(), &subject) {
            warn!(
                peer = ?peer,
                "OIDC login rejected: JWT jti reused with a different subject (replay suspected)"
            );
            if let Some(msg) = throttled_login_error(state, throttle_peer).await {
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
    let oidc_subject: Option<String> = match verifier.verify_login(token).await {
        Ok(oidc_token) => {
            if oidc_token.subject.trim().is_empty() {
                warn!(peer = ?peer, "OIDC auth failed: subject claim is empty");
                // Rate-limit failed logins per IP (F1): the OIDC path
                // must not be exempt from the login throttle, and the
                // client needs a LoginResp error rather than a silent
                // hang.
                if let Some(msg) = throttled_login_error(state, throttle_peer).await {
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
                if let Some(msg) = throttled_login_error(state, throttle_peer).await {
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
            // E3/C2: Go frp logs no OIDC subject on login — demoted from
            // info to debug (per-login PII in the info stream).
            debug!(subject = %oidc_token.subject, "OIDC login verified: subject={}", oidc_token.subject);
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
            if let Some(msg) = throttled_login_error(state, throttle_peer).await {
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
    };
    Ok((oidc_subject, stream))
}

/// Token arm of `verify_login_auth` (moved verbatim).
async fn verify_token_login(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: &Arc<AppState>,
    peer: Option<SocketAddr>,
    v2: bool,
    throttle_peer: Option<SocketAddr>,
) -> Result<
    (
        Option<String>,
        Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    ),
    (),
> {
    let auth_cfg = state.reloadable.read_ok().auth_cfg.clone();
    let login_auth = auth_cfg.resolve_token().and_then(|token| {
        auth_cfg.validate_login_with_token(&token, login.privilege_key.as_deref(), login.timestamp)
    });
    if let Err(e) = login_auth {
        warn!(peer = ?peer, error = %e, "Authentication failed for {:?}: {}", peer, e);
        // Rate-limit failed logins per IP (deliberate frp-rs hardening
        // — Go frp v0.71.0 has no login throttle). Only failures
        // consume a slot — successful logins are not counted.
        if let Some(msg) = throttled_login_error(state, throttle_peer).await {
            send_login_error(stream, msg, v2).await;
            return Err(());
        }
        // Emit WebSocket event for dashboard subscribers
        #[cfg(feature = "dashboard")]
        {
            let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                message: format!("Authentication failed for {:?}: {}", peer, e),
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

    let stream =
        check_token_replay(stream, login, state, peer, v2, throttle_peer, &auth_cfg).await?;
    Ok((None, stream))
}

/// Timestamp freshness + duplicate detection (moved verbatim).
async fn check_token_replay(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: &Arc<AppState>,
    peer: Option<SocketAddr>,
    v2: bool,
    throttle_peer: Option<SocketAddr>,
    auth_cfg: &AuthConfig,
) -> Result<Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>, ()> {
    // --- Replay protection: timestamp freshness + duplicate detection ---
    if auth_cfg.token_auth_timeout && auth_cfg.authentication_timeout > 0 {
        if let Some(ts) = login.timestamp {
            if let Err(e) =
                frp_core::auth::validate_timestamp_freshness(ts, auth_cfg.authentication_timeout)
            {
                warn!(peer = ?peer, error = %e, "Login timestamp outside acceptable window: {}", e);
                // Freshness rejections consume a throttle slot like every
                // other pre-auth failure (finding 6b): an attacker
                // replaying captured (ts, md5) pairs with a stale clock
                // would otherwise fail here forever without ever
                // advancing toward the per-IP throttle.
                let throttled = throttled_login_error(state, throttle_peer).await;
                send_login_error(stream, throttled.unwrap_or(e), v2).await;
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
                let throttled = throttled_login_error(state, throttle_peer).await;
                send_login_error(stream, throttled.unwrap_or(error), v2).await;
                return Err(());
            }
        }
    }
    Ok(stream)
}
