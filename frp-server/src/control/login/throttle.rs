//! Login-throttle helpers for the authentication path.
//!
//! `throttled_login_error` (consume a per-IP slot on a failed attempt) and
//! `pre_auth_throttle_gate` (reject an already-throttled peer before any
//! auth or plugin work) moved out of the parent `login` module (P5 seam:
//! split `authenticate` by auth method, never by reordering).

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::warn;

use frp_core::msg;

use crate::control::proxy_ops::err_msg;
use crate::state::AppState;

use super::send_login_error;

/// Consume a per-IP login-throttle slot for a FAILED auth attempt and
/// return the throttled LoginResp message when the IP has exceeded its
/// window quota (`None` → the attempt proceeds to the normal error
/// response).
///
/// The caller passes `throttle_peer` — the peer address only when the
/// transport's source IP is a trusted throttle key (see
/// `AppState::login_throttle` docs): TCP/TLS/WS/QUIC pass the real peer;
/// KCP passes `None` (spoofable UDP source — exempt, E1/S1), which also
/// means a KCP-sourced failure can never trip the pre-auth gate.
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
pub(super) async fn throttled_login_error(
    state: &AppState,
    peer: Option<SocketAddr>,
) -> Option<String> {
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

/// Pre-auth throttle gate: reject an already-throttled peer before the
/// plugin hook and before any auth work (moved verbatim out of
/// `authenticate`). Pure check — it consumes no slot; the failure paths
/// consume slots via `throttled_login_error`.
pub(super) async fn pre_auth_throttle_gate(
    stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>,
    login: &msg::Login,
    state: &Arc<AppState>,
    peer: Option<SocketAddr>,
    throttle_peer: Option<SocketAddr>,
    v2: bool,
    internal: bool,
) -> Result<Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin>, ()> {
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
    if !is_auth_bypass && state.is_login_throttled(throttle_peer).await {
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
    Ok(stream)
}
