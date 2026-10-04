//! Login authentication for control connections.
//!
//! Handles OIDC verification, token-based auth, PBKDF2 key derivation,
//! duplicate `run_id` shutdown, encryption setup, and per-client state
//! initialisation.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
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
use crate::state::{AppState, ControlTx, InternalMsg, PoolStats};

use super::pool::{PendingRequest, PoolEntry, WORK_POOL_EXTRA};
use super::proxy_ops::unregister_control;
use super::{write_ctl_msg, ControlContext, ControlState};

// The login authentication path, split by auth method (P5 seam). These are
// child modules of this file rather than `mod.rs` children, matching the
// landed `service.rs` + `service/listeners.rs` seam. Their `tracing` events
// report target `frp_server::control::login::auth` / `::throttle` instead of
// `frp_server::control::login`; `RUST_LOG` target matching is a prefix
// comparison, so `RUST_LOG=frp_server::control=debug` still enables them.
mod auth;
mod throttle;

/// Counts raw wire bytes consumed from the underlying stream — CFB IV,
/// AEAD frame headers, ciphertext: everything read before any decryption.
///
/// Fed to the control-loop stall reaper (S1, round-17 security review): the
/// reaper's `ProgressRead` sits ABOVE the cipher and only sees decrypted
/// bytes, so a peer that sends exactly the 16-byte CFB IV and then goes
/// silent (while ponging yamux keepalives to keep the session alive)
/// delivers zero decrypted bytes — `mark_progress` would never fire and the
/// task + fd + conn_semaphore permit + run_id registration would stay pinned
/// forever (~512 such connections exhaust every permit). Wrapping the raw
/// stream below the cipher makes the IV (and AEAD frame headers) count as
/// "a frame has started", so the fixed-anchor reap arm closes the stall.
/// Pure wire counting — semantics of the anchor (first byte of the frame,
/// not a per-byte extension) are unchanged.
struct CountingIoStream<S> {
    inner: S,
    raw: Arc<AtomicU64>,
}

impl<S> CountingIoStream<S> {
    fn new(inner: S, raw: Arc<AtomicU64>) -> Self {
        Self { inner, raw }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingIoStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let consumed = buf.filled().len() - filled_before;
        if consumed > 0 {
            self.raw.fetch_add(consumed as u64, Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingIoStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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
/// `max_pool_count`. An unset (0) `max_pool_count` is the Go default 5
/// (Go `util.EmptyOr` parity, pkg/config/v1/server.go:186 — Go has no
/// "uncapped" mode; a negative value was already rejected in
/// `authenticate` with the Go control.go:440 error). Go clamps with a
/// MIN-ONLY `min(PoolCount, MaxPoolCount)` (server/control.go:446): a
/// client asking for poolCount 0 gets 0 prewarmed work conns (the pool is
/// replenished on demand), never floored to 1. `None` (absent — the
/// client did not declare a poolCount) means 1, the frp client default.
fn capped_pool_count(pool_count: Option<i32>, max_pool_count: i64) -> usize {
    // Absent pool_count → the frp default 1. A negative value is rejected
    // in `authenticate` before this runs; the `.max(0)` below is a
    // defensive guard so an upstream regression can never turn into a
    // giant usize loop bound.
    let raw = pool_count.unwrap_or(1).max(0) as i64;
    // Negative max_pool_count is rejected at login before this runs; only
    // 0 (→ Go default 5) and positive values reach the min.
    let max = if max_pool_count > 0 {
        max_pool_count
    } else {
        5
    };
    raw.min(max) as usize
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

/// Go `unicode.IsPrint` parity for run_id validation (Go name.go
/// validateIdentifier → IsPrint). Printable = graphic runes
/// (categories L/M/N/P/S plus Zs). Go's Latin-1 fast path: any rune
/// ≤ 0xFF that is not a space (U+0020) is NOT spacing (Zs), so U+00A0
/// (non-breaking space) is rejected; the space U+0020 stays printable.
/// U+00AD (soft hyphen, Cf), U+2028/U+2029 (Zl/Zp) are not graphic and
/// not printable. Rust `is_whitespace()` includes Zl/Zp — excluded
/// explicitly below. `is_control()` covers Cc (Go IsControl) but not
/// Cf, which is why U+00AD gets its own case.
///
/// The >Latin-1 fallback accepts everything that is neither Cc nor
/// White_Space (Rust std has no IsPrint/IsGraphic methods): the graphic
/// categories L/M/N/P/S that Go admits — plus, as a known negligible
/// fail-open edge, Cf format characters (e.g. ZWJ U+200D), unassigned
/// (Cn) and private-use (Co) runes that Go IsPrint rejects. Run ids are
/// UUIDs in practice, so the gap is unreachable for real clients.
fn is_printable_run_id_char(c: char) -> bool {
    match c {
        // U+0020 is the only printable Latin-1 spacing rune.
        ' ' => true,
        // Latin-1 fast path: every other rune ≤ 0xFF that is not a
        // graphic category (e.g. U+00A0 Zs, U+00AD Cf) is unprintable.
        '\u{00A0}' | '\u{00AD}' => false,
        // Go IsControl covers Cc; also covers the C0 range already.
        c if c.is_control() => false,
        // Latin-1 graphic runes are printable (Go's isPrintLatin1).
        c if (c as u32) <= 0xFF => true,
        // Above Latin-1: Go unicode.IsPrint admits every graphic rune —
        // L/M/N/P/S (IsGraphic) minus Cc, Cf and White_Space, with
        // U+0020 the sole spacing rune (IsPrint is IsGraphic minus
        // IsControl/IsSpace/IsFormat). `!is_control() && !is_whitespace()`
        // matches that for every graphic category and keeps Zs above
        // Latin-1 (U+1680, U+2000-U+200A, U+202F, U+205F, U+3000) and
        // Zl/Zp rejected via White_Space (round-8 finding — the old Zs
        // clause failed open for U+3000 and friends). The only
        // divergences vs Go are the fail-open Cf/Cn/Co edge noted in the
        // doc comment. Round-15 finding: the previous is_alphanumeric
        // fallback fail-closed on P/S/M, rejecting Go-accepted runes
        // like U+2010 (Pd) and U+2192 (Sm).
        c => !c.is_control() && !c.is_whitespace(),
    }
}

/// Authenticate a new control connection and set up per-client state.
/// On success returns all state needed by the main select! loop.
/// On failure sends LoginResp with an error and returns `Err(())`.
/// When `internal` is true and the login's ClientSpec.AlwaysAuthPass is set,
/// authentication is bypassed (Go frp SSH gateway compat).
///
/// `throttle_keyed` marks whether the peer's source IP may key the per-IP
/// login throttle (audit E1/S1): true for TCP/TLS/WS/QUIC (real,
/// non-spoofable sources), false for KCP-sourced logins (spoofable UDP
/// source — see `AppState::login_throttle` docs in state.rs).
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
    throttle_keyed: bool,
) -> Result<
    (
        ControlContext,
        ControlState,
        mpsc::Sender<InternalMsg>,
        mpsc::Receiver<InternalMsg>,
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
        Option<IncomingStreams>,
        Arc<AtomicU64>,
    ),
    (),
> {
    // Raw wire-byte counter (S1): wrapped below the cipher in both
    // encryption branches so the stall reaper sees IV/frame-header bytes.
    let raw = Arc::new(AtomicU64::new(0));
    // Effective per-IP throttle key. `throttle_keyed=false` (KCP-sourced
    // logins — the peer IP is a spoofable UDP datagram source, session
    // created from the FIRST datagram, no handshake round-trip) disables
    // the per-IP login throttle entirely: no slot consumption on any
    // failure path and no pre-auth gate. 5 spoofed wrong-token logins
    // would otherwise hard-lock the victim IP's REAL frpc logins for the
    // 60 s window, refreshable at ~5 spoofed logins/min indefinitely —
    // the throttle (Rust-only hardening; Go frp has none) becomes a
    // targeted lockout primitive. KCP attempt volume stays bounded at the
    // socket layer: 32 sessions/IP/10s + 256/10s global session-create
    // caps (frp-core/src/kcp/socket.rs).
    let throttle_peer = if throttle_keyed { peer } else { None };
    // Login throttle: FAIL-ONLY rate limiting (deliberate frp-rs hardening
    // — Go frp v0.71.0 has no login throttle).
    // `check_login_throttle` is invoked on authentication failure below and
    // counts only failed attempts — successful logins never consume a slot,
    // so legitimate reconnects are never throttled. A throttled IP is
    // rejected for the 60s window after the 5th failure (per-IP fixed 60s
    // window anchored at the first counted failure, capped table with a
    // coarse overflow bucket).

    let stream =
        throttle::pre_auth_throttle_gate(stream, login, &state, peer, throttle_peer, v2, internal)
            .await?;

    // Effective run_id: computed up-front (pre-plugin) so the Login hook
    // payload can carry it — a client that omits run_id still appears as
    // the assigned UUID (the value registration actually uses).
    // NOTE: plugin mutations of run_id are deliberately NOT honored for
    // BOOKKEEPING — run_id_to_ctl_tx, the plugin users map, client
    // registry, and OIDC subjects all key off this pre-plugin value
    // (honoring a mutated run_id would desync them). The login replay
    // table is the exception: verify_login_auth derives run_id_for_check
    // from the MUTATED login, so a plugin-mutated run_id DOES change the
    // replay key — Go parity (Go uses the mutated `m` throughout
    // RegisterControl, including the ctlsByRunID key). Echo-style
    // plugins preserve run_id, so the split is invisible in practice;
    // pathological plugins get the pre-plugin value in the bookkeeping
    // maps and the mutated value in the replay table.
    // An empty client-supplied run_id normalizes to a generated UUID just
    // like an absent one (Go server/service.go:789-791: `RunID == ""` →
    // util.RandID(), BEFORE ValidateRunID). `Some("")` must never flow into
    // routing tables / logs / the LoginResp as the key "".
    let run_id = login
        .run_id
        .clone()
        .filter(|id| !id.is_empty())
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
                // Consume a throttle slot: this is a pre-auth failure (round
                // 6 B5 DoS gate) — without it an attacker could trigger
                // plugin HTTP round-trips at any rate.
                if let Some(msg) = throttle::throttled_login_error(&state, throttle_peer).await {
                    send_login_error(stream, msg, v2).await;
                    return Err(());
                }
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
                // Consume a throttle slot: a plugin that rejects on
                // attacker-controlled fields (user, metas) must not get
                // unbounded pre-auth HTTP calls per IP (round-6 B5 DoS gate).
                if let Some(msg) = throttle::throttled_login_error(&state, throttle_peer).await {
                    send_login_error(stream, msg, v2).await;
                    return Err(());
                }
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
                        // Consume a throttle slot: a pre-auth failure must
                        // not be exempt from the login throttle (round-6 B5
                        // DoS gate — the plugin hook runs BEFORE auth).
                        if let Some(msg) =
                            throttle::throttled_login_error(&state, throttle_peer).await
                        {
                            send_login_error(stream, msg, v2).await;
                            return Err(());
                        }
                        send_login_error(stream, e, v2).await;
                        return Err(());
                    }
                }
            }
            Ok(None) => {}
        }
    }

    // --- Validate run_id (Go frp v0.71.0 RegisterControl + ValidateRunID) ---
    // Go server/service.go:789-791 FIRST normalizes an empty run id to a
    // generated UUID (util.RandID), THEN validates — on ALL auth paths
    // (token AND OIDC), before VerifyLogin — so only a NON-EMPTY,
    // oversized (>64 BYTES, Go len()), or non-printable run id is rejected,
    // before any auth work or before it enters routing tables / logs /
    // dashboards (an OIDC-path control-char run_id would otherwise reach
    // `info!(run_id = %run_id)` log lines). Go plugin order: login hook →
    // RegisterControl (normalize + validate) → VerifyLogin, so the check
    // runs on the MUTATED login (a plugin mutation can repair an invalid
    // run_id). Rust Strings are always valid UTF-8, so the UTF-8 check is
    // automatic; length and printable-rune checks apply (Go name.go:
    // validateIdentifier). None (absent) still normalizes to a generated
    // UUID below (as does Some("")).
    if let Some(rid) = login.run_id.as_deref() {
        if rid.is_empty() {
            // Go server/service.go:789-791 parity: an empty run id means a
            // NEW client — normalize it to a generated UUID BEFORE
            // validation (Go does this in RegisterControl, after the plugin
            // hook, on the mutated login). ValidateRunID rejects "", so Go
            // never lets an empty run id reach routing tables / logs; the
            // pre-plugin `run_id` above already keyed bookkeeping on a UUID
            // for the same reason, and this keeps the MUTATED login in
            // sync with the bookkeeping value (the replay table in
            // verify_login_auth derives from this field).
            login.run_id = Some(uuid::Uuid::new_v4().to_string());
        } else if rid.len() > 64 || !rid.chars().all(is_printable_run_id_char) {
            warn!(peer = ?peer, run_id_len = %rid.len(), "Login rejected: invalid run_id (max 64 printable bytes)");
            // Consume a throttle slot: like every other pre-auth failure
            // path, an IP flooding invalid run_ids must advance the per-IP
            // counter toward the 60s throttle window instead of an
            // unbounded failure rate (round-8 finding — the old path
            // returned before `throttled_login_error`, so the pre-auth
            // gate never armed).
            if let Some(msg) = throttle::throttled_login_error(&state, throttle_peer).await {
                send_login_error(stream, msg, v2).await;
                return Err(());
            }
            send_login_error(
                stream,
                "invalid run id: must be at most 64 printable bytes".into(),
                v2,
            )
            .await;
            return Err(());
        }
    }

    // --- Cap client_id (audit round-8 F12) ---
    // client_id flows verbatim into the registry composite key
    // ({user}.{client_id}), dashboard rows, and log lines — with a VALID
    // auth token a hostile client could push megabytes of it past the run_id
    // 64-byte cap (which does not cover it). Reject pre-auth at 256 bytes
    // with throttle-slot consumption like every other pre-auth rejection
    // (an oversized-client_id flood must advance the per-IP window, not
    // race it). Empty/absent stays legal: the registry keys on run_id then.
    // Deliberate divergence: Go frp validates clientID nowhere (control.go
    // only checks the already-online conflict; the registry keys on the raw
    // string) — an oversized client_id that Go accepts is rejected here.
    // Same fail-fast treatment as the negative-poolCount config check.
    if let Some(cid) = login.client_id.as_deref() {
        if cid.len() > 256 {
            warn!(
                peer = ?peer,
                client_id_len = %cid.len(),
                "Login rejected: client_id too long (max 256 bytes)"
            );
            if let Some(msg) = throttle::throttled_login_error(&state, throttle_peer).await {
                send_login_error(stream, msg, v2).await;
                return Err(());
            }
            send_login_error(
                stream,
                "invalid client id: must be at most 256 bytes".into(),
                v2,
            )
            .await;
            return Err(());
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
    let auth_fut: Pin<Box<AuthFuture<'_>>> = Box::pin(auth::verify_login_auth(
        stream,
        &login,
        &state,
        peer,
        v2,
        internal,
        throttle_keyed,
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

    // Server-side negative max_pool_count: Go NewControl parity
    // (server/control.go:440-445) — the check runs immediately after the
    // client poolCount check and rejects the login with the Go error text.
    // Go's Complete() only EmptyOrs 0 → 5 and leaves negatives to fail
    // every login; frp-rs used to treat a negative like 0 (uncapped, 512
    // ceiling) instead of surfacing the operator config error.
    let max_pool = state.server_config_snapshot.max_pool_count;
    if max_pool < 0 {
        warn!(peer = ?peer, max_pool_count = %max_pool, "Login rejected: negative server max_pool_count {}", max_pool);
        send_login_error(
            stream,
            format!("invalid max pool count {max_pool}: must be non-negative"),
            v2,
        )
        .await;
        return Err(());
    }

    let reloadable = state.reloadable.read_ok().clone();
    let authenticated_user = authenticated_user(login.user.as_deref(), oidc_subject.as_deref());
    info!(peer = ?peer, run_id = %run_id, "Client {:?} logged in with run_id: {}", peer, run_id);

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

    // Record the (possibly plugin-mutated) client identity for the `user`
    // object of later plugin hooks (Go loginUserInfo: LoginMsg.User/Metas
    // + runID). Deliberately AFTER the run_id_to_ctl_tx insert (audit
    // finding): the record carries this control's own control_id, so
    // remove_user is generation-exact — it removes an entry only when it
    // still holds the removing control's control_id (remove-if-match inside
    // the users-map write lock). A stale control's cleanup can therefore
    // never delete the fresh record of a control that re-logged in with the
    // same run_id, even when it lands between the re-login's insert and its
    // own removal step (the residual window in unregister_control: its
    // atomic remove_if drops the old ctl_tx entry, and remove_user then ran
    // on the run_id alone). The caller-side guards — the stale-control
    // reaper's run_mu hold across its re-check + remove_user, and
    // unregister_control firing remove_user only when its run_id_to_ctl_tx
    // removal actually matched this control's control_id (a single atomic
    // remove_if) — remain as defense in depth. Recording here, in the same
    // run_mu critical section, makes the record strictly follow the insert
    // (no await between): a guard whose check runs before the insert cannot
    // find the fresh record yet; one that runs after it sees the fresh
    // generation and skips.
    if !state.plugin_manager.is_empty() {
        state.plugin_manager.record_login_user(
            &run_id,
            control_id,
            &crate::plugin::UserInfo {
                user: login.user.clone().unwrap_or_default(),
                metas: login.metas.clone().unwrap_or_default(),
                run_id: run_id.clone(),
            },
        );
    }

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
                    Box::new(CountingIoStream::new(stream, raw.clone())),
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
        // Audit B2: OS-RNG failure (IV generation) tears the control down
        // like the AEAD arm above instead of aborting the process.
        let cipher = match frp_core::cipher_stream::CipherStream::new(
            CountingIoStream::new(stream, raw.clone()),
            enc_key,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to create CipherStream for {:?}: {}", peer, e);
                unregister_control(&state, &run_id, control_id, false, false).await;
                return Err(());
            }
        };
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
        raw,
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
            None,
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
            true,
        )
        .await;

        assert!(result.is_err());
        assert!(rx.await.is_err(), "bad token must drop the unsent signal");
        drain.abort();
    }

    /// Read one V1 LoginResp frame from the client side of the duplex and
    /// return its error field (empty when the login succeeded). Local copy
    /// of the helper in oidc_throttle_tests (sibling test modules cannot
    /// share private items).
    async fn read_login_resp_error(client: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
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
        let resp: frp_core::msg::LoginResp =
            serde_json::from_slice(&payload).expect("parse LoginResp");
        resp.error.unwrap_or_default()
    }

    #[tokio::test]
    async fn invalid_run_ids_consume_login_throttle_slots() {
        // Round-8 finding: the invalid-run_id rejection (oversized /
        // non-printable) must consume a per-IP throttle slot like every
        // other pre-auth failure path. An attacker flooding invalid run_ids
        // must hit the 60s throttle window instead of an unbounded failure
        // rate — the old path returned before `throttled_login_error`, so
        // the pre-auth gate never armed. Mirrors the replay×throttle and
        // OIDC slot-consumption patterns: attempts 1..=5 reject the run id,
        // attempt 6 is pre-auth-throttled.
        let state = test_state();
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
            // 65 bytes > the 64-byte Go len() cap — rejected before auth.
            run_id: Some("x".repeat(65)),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("expected-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        for attempt in 1..=6u32 {
            let (server, mut client) = tokio::io::duplex(4096);
            let result = super::authenticate(
                Box::new(server),
                &login(),
                state.clone(),
                Some(peer),
                None,
                false,
                None,
                false,
                None,
                true,
            )
            .await;
            assert!(result.is_err(), "attempt {attempt} must be rejected");
            let error = read_login_resp_error(&mut client).await;
            if attempt <= 5 {
                assert!(
                    error.contains("invalid run id"),
                    "attempt {attempt} must reject the run id, got: {error}"
                );
            } else {
                assert!(
                    error.contains("throttled"),
                    "6th attempt must be throttled, got: {error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn kcp_sourced_logins_exempt_from_per_ip_login_throttle() {
        // E1/S1 (audit round 9): the per-IP login throttle keys on the peer
        // IP for every transport, but a KCP peer IP is a spoofable UDP
        // datagram source — the session is created from the FIRST datagram
        // (sn=0, no ACK round-trip), so a full V1 wrong-token Login can be
        // delivered from a spoofed source. 5 spoofed failures inside the
        // anchored 60s window would hard-lock the victim IP's real frpc
        // logins, refreshable at ~5 spoofed logins/min indefinitely — the
        // throttle (Rust-only hardening; Go frp has none) becomes a
        // 5-packet/min targeted lockout primitive. KCP-sourced logins
        // therefore run with throttle_keyed=false: they must neither
        // consume per-IP throttle slots nor trip the pre-auth gate (KCP
        // attempt volume stays bounded at the socket layer — 32 sessions/
        // IP/10s, 256/10s global, frp-core/src/kcp/socket.rs).
        //
        // Both arms of the matrix:
        //  - throttle_keyed=false (KCP): 6 consecutive failed logins from
        //    one IP → NONE throttled (every attempt gets the auth error).
        //  - throttle_keyed=true (TCP/WS/QUIC): 5 failures consume slots;
        //    the 6th attempt is rejected pre-auth as throttled (existing
        //    keyed behavior, pinned here for contrast).
        let state = test_state();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let bad_login = |run_tag: &str| frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some(format!("kcp-throttle-{run_tag}")),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("wrong-secret", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let kcp_peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        // KCP arm: exempt — none of the 6 failures may be throttled.
        for attempt in 1..=6u32 {
            let (server, mut client) = tokio::io::duplex(4096);
            let result = super::authenticate(
                Box::new(server),
                &bad_login(&format!("kcp-{attempt}")),
                state.clone(),
                Some(kcp_peer),
                None,
                false,
                None,
                false,
                None,
                false, // throttle_keyed=false: KCP transport (spoofable UDP src)
            )
            .await;
            assert!(result.is_err(), "KCP attempt {attempt} must be rejected");
            let error = read_login_resp_error(&mut client).await;
            assert!(
                !error.contains("throttled"),
                "KCP-sourced attempt {attempt} must never be throttled, got: {error}"
            );
            assert!(
                !error.is_empty(),
                "KCP-sourced attempt {attempt} must fail auth"
            );
        }
        // TCP arm (mirror): keyed — the 6th attempt IS pre-auth-throttled.
        let tcp_peer: std::net::SocketAddr = "127.0.0.2:12345".parse().unwrap();
        for attempt in 1..=6u32 {
            let (server, mut client) = tokio::io::duplex(4096);
            let result = super::authenticate(
                Box::new(server),
                &bad_login(&format!("tcp-{attempt}")),
                state.clone(),
                Some(tcp_peer),
                None,
                false,
                None,
                false,
                None,
                true, // throttle_keyed=true: TCP/WS/QUIC (real source IP)
            )
            .await;
            assert!(result.is_err(), "TCP attempt {attempt} must be rejected");
            let error = read_login_resp_error(&mut client).await;
            if attempt <= 5 {
                assert!(
                    !error.contains("throttled"),
                    "TCP attempt {attempt} must fail auth (not throttle), got: {error}"
                );
            } else {
                assert!(
                    error.contains("throttled"),
                    "TCP 6th attempt must be throttled, got: {error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn detailed_login_resp_token_mismatch_matches_go_literal() {
        // E2/C3 (audit round 9): Go frp's detailed_errors_to_client=true
        // puts err.Error() verbatim in LoginResp.error; its VerifyLogin
        // (pkg/auth/token.go:66) returns the literal
        // "token in login doesn't match token from configuration".
        // test_state() below runs detailed_errors_to_client=true, so the
        // wire text must byte-match Go's literal.
        let state = test_state();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("e2-go-literal".into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("wrong-secret", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let (server, mut client) = tokio::io::duplex(4096);
        let result = super::authenticate(
            Box::new(server),
            &login,
            state,
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_err(), "wrong token must be rejected");
        let error = read_login_resp_error(&mut client).await;
        assert_eq!(
            error, "token in login doesn't match token from configuration",
            "detailed-mode LoginResp.error must byte-match Go pkg/auth/token.go:66"
        );
    }

    #[test]
    fn run_id_printable_chars_match_go_unicode_is_print() {
        // Round-8 finding: Go unicode.IsPrint admits U+0020 as the only
        // spacing rune, so Zs above Latin-1 must be rejected (the old
        // whitespace clause failed open for these).
        for c in [
            '\u{1680}', '\u{2000}', '\u{200A}', '\u{202F}', '\u{205F}', '\u{3000}',
        ] {
            assert!(
                !super::is_printable_run_id_char(c),
                "Zs rune U+{:04X} must be rejected (Go IsPrint admits only U+0020)",
                c as u32
            );
        }
        // U+0020 and Latin-1 fast path stay printable; control runes stay
        // rejected.
        assert!(super::is_printable_run_id_char(' '));
        assert!(super::is_printable_run_id_char('a'));
        assert!(super::is_printable_run_id_char('Z'));
        assert!(super::is_printable_run_id_char('0'));
        assert!(super::is_printable_run_id_char('-'));
        assert!(super::is_printable_run_id_char('\u{4E2D}'));
        assert!(!super::is_printable_run_id_char('\u{00A0}'));
        assert!(!super::is_printable_run_id_char('\u{00AD}'));
        assert!(!super::is_printable_run_id_char('\u{0000}'));
        assert!(!super::is_printable_run_id_char('\u{2028}'));
        assert!(!super::is_printable_run_id_char('\u{2029}'));
        // Round-15 finding: the old is_alphanumeric fallback fail-closed on
        // Go-admitted graphic categories — punctuation (Pd), symbols (Sm)
        // and combining marks (Mn) above Latin-1 must be printable.
        assert!(
            super::is_printable_run_id_char('\u{2010}'),
            "Pd U+2010 must be printable (Go IsPrint admits P)"
        );
        assert!(
            super::is_printable_run_id_char('\u{2192}'),
            "Sm U+2192 must be printable (Go IsPrint admits S)"
        );
        assert!(
            super::is_printable_run_id_char('\u{0301}'),
            "Mn U+0301 must be printable (Go IsPrint admits M)"
        );
        // Documented fail-open edge: Cf format chars (ZWJ) pass the
        // std-only probe but Go IsPrint rejects them — pinned here so a
        // future Cf exclusion is a deliberate change.
        assert!(
            super::is_printable_run_id_char('\u{200D}'),
            "Cf U+200D accepted (documented divergence from Go IsPrint)"
        );
    }

    #[tokio::test]
    async fn zero_pool_count_prewarms_no_req_work_conn() {
        // F3: Go clamps the pool count with `min(PoolCount, MaxPoolCount)`
        // (server/control.go:446) — no lower floor — and the worker()
        // prewarm loop (control.go:690) sends exactly `poolCount`
        // ReqWorkConns. The old `.max(1)` floor made pool_count = 0 prewarm
        // one work conn where a Go server prewarms none (the pool is
        // replenished on demand via ReqWorkConn when a proxy needs one).
        // Drive a successful login with pool_count = Some(0) and assert the
        // wire carries LoginResp followed by silence, not a ReqWorkConn.
        use tokio::io::AsyncReadExt;
        let state = test_state();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("zero-pool-run-id".into()),
            client_id: None,
            pool_count: Some(0),
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("expected-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let (server, mut client) = tokio::io::duplex(4096);
        let result = super::authenticate(
            Box::new(server),
            &login,
            state,
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_ok(), "valid login must authenticate");

        // LoginResp first — success (empty error field).
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login must succeed, got: {error}");

        // Then silence. pool_count = 0 must prewarm ZERO ReqWorkConns; the
        // prewarm loop runs inside authenticate before it returns, so any
        // frame is already buffered here and the read would complete.
        let mut header = [0u8; 9];
        let next = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.read_exact(&mut header),
        )
        .await;
        assert!(
            next.is_err(),
            "pool_count = 0 must not prewarm work conns (Go control.go:446 min-only clamp)"
        );
    }

    #[tokio::test]
    async fn oversized_client_id_rejected_at_login() {
        // F12 (audit round 8): the client-supplied client_id is never
        // validated and flows verbatim into the registry composite key
        // ({user}.{clientID}), dashboard rows, and log lines. A hostile
        // client can push an arbitrarily long client_id (megabytes) with a
        // VALID auth token — the run_id 64-byte cap (Go parity) does not
        // cover it. Cap it pre-auth like run_id (with throttle-slot
        // consumption) at 256 bytes with an explicit login error.
        let state = test_state();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("valid-run-id".into()),
            // 10k chars — valid token, valid run_id, absurd client_id.
            client_id: Some("x".repeat(10_000)),
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("expected-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let (server, mut client) = tokio::io::duplex(64 * 1024);
        let result = super::authenticate(
            Box::new(server),
            &login,
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(
            result.is_err(),
            "an oversized client_id must be rejected before auth"
        );
        let error = read_login_resp_error(&mut client).await;
        assert!(
            error.contains("client id"),
            "rejection must name the client id cap, got: {error}"
        );
        // And a sane-length client_id still logs in.
        let login = frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some("valid-run-id-2".into()),
            client_id: Some("frpc-host-1".into()),
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(frp_core::auth::generate_token("expected-token", ts)),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        let (server, mut client) = tokio::io::duplex(4096);
        let result = super::authenticate(
            Box::new(server),
            &login,
            state,
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_ok(), "a sane client_id must still authenticate");
        let error = read_login_resp_error(&mut client).await;
        assert!(error.is_empty(), "login must succeed, got: {error}");
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

    #[test]
    fn unset_max_pool_count_uses_go_empty_or_default() {
        // max_pool_count = 0 (unset): Go util.EmptyOr parity
        // (pkg/config/v1/server.go:186) — unset is the Go default 5, NOT
        // uncapped. The old "0 = no server cap" (512 absolute ceiling)
        // pooled up to 512 work conns per client where a Go server pools 5.
        assert_eq!(capped_pool_count(Some(100_000), 0), 5);
        assert_eq!(capped_pool_count(Some(65_000), 0), 5);
        // Below the default: honored as requested.
        assert_eq!(capped_pool_count(Some(5), 0), 5);
        assert_eq!(capped_pool_count(None, 0), 1);
        // No floor: Go control.go:446 `min(PoolCount, MaxPoolCount)` clamps
        // only the upper side (a negative value is rejected at login before
        // this runs), so poolCount 0 must prewarm ZERO work conns.
        assert_eq!(capped_pool_count(Some(0), 0), 0);
    }

    #[test]
    fn configured_max_pool_count_wins() {
        assert_eq!(capped_pool_count(Some(100_000), 50), 50);
        assert_eq!(capped_pool_count(Some(5), 50), 5);
        assert_eq!(capped_pool_count(None, 50), 1);
        // An explicitly configured cap above 5 is honored (Go same — the
        // EmptyOr default only applies to unset).
        assert_eq!(capped_pool_count(Some(100_000), 10_000), 10_000);
        // Explicit cap, requested 0: min(0, 50) = 0, no floor.
        assert_eq!(capped_pool_count(Some(0), 50), 0);
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

    /// How long the mock waits for one accepted client's complete request head.
    ///
    /// The accepted socket's mode is **platform-defined**, and it decides which
    /// of the pre-fix failures a given host could see. On macOS, `accept()` on a
    /// `set_nonblocking(true)` listener yields a **non-blocking** stream
    /// (measured on this host, rustc 1.98.1: the first `read` with nothing sent
    /// returns `Err(WouldBlock, os error 35)`), so a single `read` returned 0
    /// bytes whenever the accept beat the client's write. That
    /// **accept-before-bytes race is macOS-only**: on Linux the accepted stream
    /// is **blocking** (measured in a `rust:1.98.1-slim` container on kernel
    /// 6.8.0/Ubuntu 24.04: a 500 ms `SO_RCVTIMEO` was waited out in 515 ms, and a
    /// pre-fix-style single read with no mode change returned the full request
    /// 304.7 ms after a client that slept 300 ms before writing).
    ///
    /// The pre-fix `unwrap_or(0)` had **two further failures that are not
    /// platform-specific**, so this wait is not a Linux no-op. (1) An EOF makes
    /// `read` return `Ok(0)`, which `unwrap_or(0)` cannot distinguish from
    /// `WouldBlock`: a client that connects and half-closes before sending gives
    /// `n=0` → the `/` fallback → 404 on **both** platforms (measured: 3.833 µs
    /// on macOS, 1.625 µs on Linux). (2) A head split across writes mis-routes,
    /// because the single read returns only the prefix (measured on Linux). The
    /// elapsed figures are shape- and host-dependent, so they are named with their
    /// shape: with the first write ~200 ms after the accept, `n=16`,
    /// `path="/.well-known"` → 404 in ~208 ms, while an immediate first write
    /// gives the same `n=16` and the same mis-route in single-digit microseconds
    /// to ~1.6 ms depending on host and run — reviewer samples: 10-run medians
    /// 7.583 µs macOS / 5.917 µs Linux, a 20-trial spread of 2–1576 µs, and
    /// one-off figures of 192.08 µs and 1.635 ms). Every `ci.yml` job is
    /// `ubuntu-latest`, so the *race* cannot flake CI — but those EOF and split
    /// shapes could still 404 there. What this wait does not do is depend on the
    /// inherited mode — it clears `O_NONBLOCK` explicitly — so it is correct on
    /// both. Bounded so a client that connects and never sends cannot hold the
    /// serving thread.
    ///
    /// What this does **not** cover: the stop channel is read only at the top of
    /// the accept loop, so a stop sent while the thread is inside this wait is
    /// not observed until the wait ends — up to the deadline later (measured by
    /// review: stop observed after 1.357 s macOS / 1.386 s Linux of a 1500 ms
    /// read). A **dropped** sender is not a stop at all: `try_recv()` returns
    /// `Err(Disconnected)`, for which `is_ok()` is false (measured), so the mock
    /// keeps serving after `_stop` is dropped — only an explicit `send(())`
    /// breaks the loop. That explicit stop *is* pinned
    /// (`mock_idp_stops_serving_after_the_stop_signal`). The bound is on the
    /// client's stall, not on stop latency; the mock's threads are
    /// process-lifetime test scaffolding and no caller blocks on one, so the gap
    /// is recorded rather than bounded.
    ///
    /// The shipped 5 s value is pinned by value
    /// (`mock_default_request_head_deadline_is_pinned`); its **end-to-end effect
    /// is deliberately not exercised** — that would cost 5 s per run — while the
    /// deadline *mechanism* is pinned by the 200 ms override test.
    const MOCK_REQUEST_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Upper bound on the request head the mock buffers before giving up.
    const MOCK_REQUEST_HEAD_MAX: usize = 8192;

    /// Why [`read_request_head`] stopped before a complete request head arrived.
    ///
    /// Rendered into the 500 body and stderr, so a request the mock never
    /// received can never be mistaken for the `/` → 404 unknown-path route.
    #[derive(Debug)]
    enum RequestHeadError {
        /// The peer closed the socket before sending the head terminator.
        Eof,
        /// No complete head arrived before the deadline.
        TimedOut(std::time::Duration),
        /// The head exceeded [`MOCK_REQUEST_HEAD_MAX`] with no terminator.
        TooLarge(usize),
        /// The socket itself failed.
        Io(std::io::Error),
    }

    impl std::fmt::Display for RequestHeadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Eof => write!(
                    f,
                    "client closed the socket before sending a complete request head"
                ),
                Self::TimedOut(d) => write!(f, "no complete request head within {d:?}"),
                Self::TooLarge(n) => {
                    write!(f, "request head exceeded {n} bytes without CRLFCRLF")
                }
                Self::Io(e) => write!(f, "socket error: {e}"),
            }
        }
    }

    /// Read exactly one HTTP request head — through its `\r\n\r\n` terminator —
    /// from `stream`, waiting at most `timeout` in total.
    ///
    /// The accepted socket is switched to **blocking** explicitly (its inherited
    /// mode is platform-defined: non-blocking on macOS, blocking on Linux — both
    /// measured) and given an `SO_RCVTIMEO` no larger than the remaining budget,
    /// so the wait is bounded by the OS rather than by a poll loop. Short reads
    /// are accumulated because the head — the `\r\n\r\n` terminator included —
    /// may be split across segments. The returned head ends at the terminator:
    /// bytes that arrived **in the same read** past it are consumed and
    /// discarded (they cannot be pushed back), so the mock still serves exactly
    /// one request per accepted socket. The remaining budget can be
    /// sub-millisecond, and it is passed as-is rather than floored to zero —
    /// `set_read_timeout(Some(Duration::ZERO))` is an error ("cannot set a 0
    /// duration timeout", measured), while a sub-millisecond value returns
    /// promptly (measured: `1ns` → `WouldBlock` after 17.9 µs, `500µs` →
    /// 633.8 µs) instead of waiting forever.
    fn read_request_head(
        stream: &mut std::net::TcpStream,
        timeout: std::time::Duration,
    ) -> Result<String, RequestHeadError> {
        stream
            .set_nonblocking(false)
            .map_err(RequestHeadError::Io)?;
        let deadline = std::time::Instant::now() + timeout;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RequestHeadError::TimedOut(timeout));
            }
            stream
                .set_read_timeout(Some(remaining))
                .map_err(RequestHeadError::Io)?;
            match Read::read(stream, &mut chunk) {
                Ok(0) => return Err(RequestHeadError::Eof),
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.truncate(end + 4);
                        return Ok(String::from_utf8_lossy(&buf).into_owned());
                    }
                    if buf.len() >= MOCK_REQUEST_HEAD_MAX {
                        return Err(RequestHeadError::TooLarge(MOCK_REQUEST_HEAD_MAX));
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(RequestHeadError::TimedOut(timeout));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(RequestHeadError::Io(e)),
            }
        }
    }

    /// What [`oidc_mock_server`] and [`oidc_mock_server_with_timeout`] hand back:
    /// the serving thread's stop signal **plus** the request-head deadline that
    /// call was actually built with.
    ///
    /// It derefs to the stop [`std::sync::mpsc::Sender`], so every existing
    /// `let (issuer, _stop) = …` / `stop.send(())` call site is unchanged; the
    /// extra field is what lets
    /// `mock_default_ctor_delegates_the_pinned_deadline` observe the delegation
    /// `oidc_mock_server() → oidc_mock_server_with_timeout(MOCK_REQUEST_HEAD_TIMEOUT)`
    /// without waiting out the shipped 5 s.
    pub(super) struct MockServerHandle {
        stop: std::sync::mpsc::Sender<()>,
        request_head_timeout: std::time::Duration,
    }

    impl MockServerHandle {
        /// The deadline this mock's serving thread reads a request head with.
        fn request_head_timeout(&self) -> std::time::Duration {
            self.request_head_timeout
        }
    }

    impl std::ops::Deref for MockServerHandle {
        type Target = std::sync::mpsc::Sender<()>;

        fn deref(&self) -> &Self::Target {
            &self.stop
        }
    }

    /// Minimal OIDC discovery + JWKS mock on 127.0.0.1, plain HTTP, so an
    /// `OidcVerifier` can be built without external network access. Returns
    /// the issuer URL and a handle carrying the serving thread's stop signal and
    /// the request-head deadline it was built with.
    pub(super) fn oidc_mock_server() -> (String, MockServerHandle) {
        oidc_mock_server_with_timeout(MOCK_REQUEST_HEAD_TIMEOUT)
    }

    /// `oidc_mock_server` with the request-head deadline overridden, so the
    /// bounded wait and its explicit failure can be pinned without a 5-second
    /// test.
    fn oidc_mock_server_with_timeout(
        request_timeout: std::time::Duration,
    ) -> (String, MockServerHandle) {
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
                    Ok((mut stream, _)) => match read_request_head(&mut stream, request_timeout) {
                        Ok(req) => {
                            let path = req.split_whitespace().nth(1).unwrap_or("/");
                            let (status, body) =
                                if path.contains(".well-known/openid-configuration") {
                                    let jwks_uri = format!("http://{addr}/jwks");
                                    (200, format!(r#"{{"jwks_uri":"{jwks_uri}"}}"#))
                                } else if path == "/jwks" {
                                    (200, jwks.clone())
                                } else {
                                    (404, String::new())
                                };
                            // Connection: close — the mock serves exactly ONE
                            // request per accepted socket (the socket is dropped
                            // at the end of this arm). Without the header, the
                            // HTTP/1.1 keep-alive default makes hyper's client
                            // pool the discovery connection and route the JWKS
                            // fetch into the abandoned socket → flaky
                            // "client error (SendRequest)".
                            let resp = format!(
                                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = Write::write_all(&mut stream, resp.as_bytes());
                        }
                        Err(err) => {
                            // A request head that never arrived must NOT fall
                            // through to the `/` route: a silent `404 OK` is
                            // indistinguishable from a genuinely unknown path,
                            // which is exactly how the accept-before-bytes race
                            // used to present. Say what happened on the wire (so
                            // the client's own error names it) and on stderr.
                            let body = format!("oidc mock: {err}");
                            let resp = format!(
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = Write::write_all(&mut stream, resp.as_bytes());
                            eprintln!("oidc_mock_server: {err}");
                        }
                    },
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        (
            issuer,
            MockServerHandle {
                stop: stop_tx,
                request_head_timeout: request_timeout,
            },
        )
    }

    /// Deterministic regression pin for the accept-before-request-bytes race.
    ///
    /// The mock used to `read` **once** from the accepted socket
    /// (`Read::read(&mut stream, &mut buf).unwrap_or(0)`). On macOS that socket
    /// inherits the listener's non-blocking mode (measured on this host, rustc
    /// 1.98.1: `accept()` on a `set_nonblocking(true)` listener yields a stream
    /// whose first `read` with no data returns `Err(WouldBlock, os error 35)`),
    /// so a client that connected and only then wrote made the accept fire
    /// first, the read return `WouldBlock` → `unwrap_or(0)` → 0 bytes → the `/`
    /// fallback → `HTTP/1.1 404 OK`. A client-side sleep of a few milliseconds
    /// is enough (measured: the 5 ms iteration already fails on `d1be6675`), so
    /// on macOS this is a **deterministic** red on the pre-fix mock — no CPU
    /// load is involved. `delay_ms = 0` is the control: it passes both before
    /// and after, so a failure here isolates the *delayed* request, not "the
    /// mock is broken".
    ///
    /// **This pin is a macOS regression pin only.** On Linux the accepted stream
    /// is blocking (measured with the same rustc in a container: a pre-fix-style
    /// single read returned the full request 304.7 ms after a client that slept
    /// 300 ms), so on the `ubuntu-latest` CI lanes the pre-fix code already
    /// passed this scenario — green-before, and the test guards nothing there.
    /// What guards the new logic on every platform are the helper-level pins
    /// below, which force the accepted side non-blocking themselves.
    #[test]
    fn mock_idp_serves_a_request_that_arrives_after_accept() {
        let (issuer, _stop) = oidc_mock_server();
        let addr = issuer.strip_prefix("http://").expect("issuer host");
        for delay_ms in [0u64, 5, 20, 50] {
            for rep in 0..2 {
                let mut stream = std::net::TcpStream::connect(addr).expect("connect mock");
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                Write::write_all(
                    &mut stream,
                    format!(
                        "GET /.well-known/openid-configuration HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .expect("send discovery request");
                let mut resp = String::new();
                let _ = Read::read_to_string(&mut stream, &mut resp);
                let first = resp.lines().next().unwrap_or("");
                assert!(
                    first.contains(" 200 "),
                    "delay {delay_ms}ms rep {rep}: mock answered {first:?} to a valid request; full response: {resp:?}"
                );
                assert!(
                    resp.contains(&format!("http://{addr}/jwks")),
                    "delay {delay_ms}ms rep {rep}: discovery body must name the mock's jwks_uri; got: {resp:?}"
                );
            }
        }
    }

    /// A listener/client pair whose *accepted* side is forced non-blocking —
    /// the mode `accept()` inherits from the mock's non-blocking listener on
    /// this host, reproduced here explicitly so the pin does not depend on that
    /// inheritance.
    fn nonblocking_accepted_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind scratch listener");
        let addr = listener.local_addr().expect("scratch address");
        let client = std::net::TcpStream::connect(addr).expect("connect scratch listener");
        let (server, _) = listener.accept().expect("accept scratch connection");
        server
            .set_nonblocking(true)
            .expect("force accepted side non-blocking");
        (server, client)
    }

    /// The reader itself must wait for a request that arrives *after* the accept
    /// on a non-blocking accepted socket — the exact interleaving the pre-fix
    /// mock got wrong. The 150 ms writer delay is what makes this deterministic:
    /// a reader that returns on the first `WouldBlock` fails here regardless of
    /// scheduling, and the elapsed-time floor proves it actually waited rather
    /// than getting lucky.
    #[test]
    fn read_request_head_waits_for_a_request_that_arrives_after_accept() {
        let (mut server, mut client) = nonblocking_accepted_pair();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            Write::write_all(
                &mut client,
                b"GET /.well-known/openid-configuration HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .expect("write delayed request head");
        });
        let started = std::time::Instant::now();
        let head = read_request_head(&mut server, std::time::Duration::from_secs(5))
            .expect("a request that arrives after accept must still be read");
        let waited = started.elapsed();
        writer.join().expect("writer thread did not panic");
        assert!(
            head.starts_with("GET /.well-known/openid-configuration HTTP/1.1"),
            "head must be the full request line, got {head:?}"
        );
        assert!(
            waited >= std::time::Duration::from_millis(100),
            "reader returned before the client wrote (waited {waited:?})"
        );
    }

    /// The wait is **bounded**: a client that connects and never sends must not
    /// hang the reader, and the failure must be a named timeout rather than a
    /// silent empty head. Elapsed time is measured, not assumed.
    #[test]
    fn read_request_head_times_out_on_a_client_that_never_sends() {
        let (mut server, _client) = nonblocking_accepted_pair();
        let started = std::time::Instant::now();
        let err = read_request_head(&mut server, std::time::Duration::from_millis(200))
            .expect_err("a silent client must time out");
        let waited = started.elapsed();
        assert!(
            matches!(err, RequestHeadError::TimedOut(_)),
            "expected TimedOut, got {err:?}"
        );
        assert!(
            waited >= std::time::Duration::from_millis(150),
            "gave up before the deadline (waited {waited:?})"
        );
        assert!(
            waited < std::time::Duration::from_secs(5),
            "the deadline is not bounded (waited {waited:?})"
        );
    }

    /// A budget that is **already expired** is a named `TimedOut(0ns)`, not an OS
    /// error: the `remaining.is_zero()` guard is the only thing keeping the
    /// `set_read_timeout(Some(ZERO))` below from being reached, and that call fails
    /// with `Io(InvalidInput "cannot set a 0 duration timeout")` (measured). No
    /// clock control and no socket timing — the deadline is expired the moment it
    /// is computed — so the mutant a round-3 review listed as needing "a read that
    /// lands exactly on the expired budget, a controlled clock, not a socket" is
    /// in fact a direct call away.
    #[test]
    fn read_request_head_reports_a_zero_budget_as_a_named_timeout() {
        let (mut server, _client) = nonblocking_accepted_pair();
        let err = read_request_head(&mut server, std::time::Duration::ZERO)
            .expect_err("an expired budget cannot return a head");
        assert!(
            matches!(err, RequestHeadError::TimedOut(d) if d.is_zero()),
            "a zero budget must be a named TimedOut(0ns), got {err:?}"
        );
    }

    /// A client that connects and closes before sending anything is an **EOF**,
    /// not a stall: `Ok(0)` must become the named `Eof` promptly. This is the
    /// third failure the pre-fix `unwrap_or(0)` hid, and unlike the
    /// accept-before-bytes race it is **not** platform-specific — an EOF gives
    /// `n=0` on macOS and Linux alike (measured: 3.833 µs / 1.625 µs), which the
    /// old code could not distinguish from `WouldBlock`. The mutant this pin is
    /// written against is `Ok(0) => continue`, which leaves all six other pins
    /// green and turns this fast, named EOF into a busy-wait to the deadline.
    #[test]
    fn read_request_head_reports_eof_when_the_client_closes_before_sending() {
        let (mut server, client) = nonblocking_accepted_pair();
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close the client");
        let started = std::time::Instant::now();
        let err = read_request_head(&mut server, std::time::Duration::from_secs(2))
            .expect_err("EOF must be reported, not turned into an empty head");
        let waited = started.elapsed();
        assert!(
            matches!(err, RequestHeadError::Eof),
            "expected Eof, got {err:?}"
        );
        assert!(
            waited < std::time::Duration::from_millis(500),
            "EOF must fail fast, not wait out the deadline (waited {waited:?})"
        );
    }

    /// The reader must **accumulate across reads**: an HTTP head can arrive in
    /// more than one segment. Two split points are covered, the second cutting
    /// the `\r\n\r\n` terminator itself in half — so an implementation that
    /// reads once, or that searches only the newly-read chunk for the
    /// terminator, fails here (both are mutants this pin is written against:
    /// the first returns a truncated head, the second never finds the terminator
    /// and times out).
    ///
    /// The 250 ms gap between the two writes is what makes them separate reads:
    /// the reader is already blocked in `read` when the first chunk lands, so it
    /// is woken immediately, and the second chunk arrives ~250 ms later. The
    /// residual is scheduler starvation of this thread for the whole gap, which
    /// no assertion can exclude on a shipped test host.
    #[test]
    fn read_request_head_accumulates_a_head_split_across_reads() {
        let cases: [(&[u8], &[u8]); 2] = [
            // Split at the request-line / header boundary.
            (
                b"GET /.well-known/openid-configuration HTTP/1.1\r\n",
                b"Host: x\r\nConnection: close\r\n\r\n",
            ),
            // Split INSIDE the terminator: the 4-byte window must span two reads.
            (
                b"GET /.well-known/openid-configuration HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r",
                b"\n",
            ),
        ];
        for (case, (first, second)) in cases.into_iter().enumerate() {
            let (mut server, mut client) = nonblocking_accepted_pair();
            let writer = std::thread::spawn(move || {
                Write::write_all(&mut client, first).expect("write first chunk");
                std::thread::sleep(std::time::Duration::from_millis(250));
                Write::write_all(&mut client, second).expect("write second chunk");
            });
            let head = read_request_head(&mut server, std::time::Duration::from_secs(5))
                .unwrap_or_else(|e| {
                    panic!("case {case}: a split head must still be read, got {e}")
                });
            writer.join().expect("writer thread did not panic");
            let mut expected = first.to_vec();
            expected.extend_from_slice(second);
            assert_eq!(
                head.as_bytes(),
                expected.as_slice(),
                "case {case}: the returned head must be both chunks concatenated"
            );
        }
    }

    /// The buffered head is bounded: a stream that never sends the terminator and
    /// exceeds [`MOCK_REQUEST_HEAD_MAX`] must fail with `TooLarge` **fast**,
    /// instead of waiting out the deadline or growing without bound (deleting the
    /// guard is the mutant this pin is written against; it turns this case into a
    /// 5 s `TimedOut`).
    #[test]
    fn read_request_head_rejects_an_over_max_head_without_a_terminator() {
        let (mut server, mut client) = nonblocking_accepted_pair();
        let writer = std::thread::spawn(move || {
            // The reader stops reading once the cap is exceeded, so bound this
            // write rather than ever blocking the writer thread forever.
            client
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("bound writer");
            // No CRLFCRLF anywhere: more than the cap, in one write.
            let blob = vec![b'a'; MOCK_REQUEST_HEAD_MAX + 512];
            let _ = Write::write_all(&mut client, &blob);
        });
        let started = std::time::Instant::now();
        let err = read_request_head(&mut server, std::time::Duration::from_secs(5))
            .expect_err("an over-max head must be rejected");
        let waited = started.elapsed();
        writer.join().expect("writer thread did not panic");
        assert!(
            matches!(err, RequestHeadError::TooLarge(n) if n == MOCK_REQUEST_HEAD_MAX),
            "expected TooLarge({MOCK_REQUEST_HEAD_MAX}), got {err:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(5),
            "TooLarge must fail fast rather than wait out the deadline (waited {waited:?})"
        );
    }

    /// The returned head ends **at** the terminator: bytes that arrive in the same
    /// read past it are consumed and discarded, not appended. The target is the
    /// `buf.truncate(end + 4)` mutant, which would return the pipelined tail as
    /// part of the head. Routing (`req.split_whitespace().nth(1)`) yields `/jwks`
    /// either way — the pipelined `GET` is a third token, not the second — so the
    /// equality assertion below is the entire catch, not a path difference.
    #[test]
    fn read_request_head_stops_at_the_terminator() {
        let (mut server, mut client) = nonblocking_accepted_pair();
        let writer = std::thread::spawn(move || {
            // Head plus a pipelined-looking second request, in ONE write.
            let _ = Write::write_all(
                &mut client,
                b"GET /jwks HTTP/1.1\r\nHost: x\r\n\r\nGET /second HTTP/1.1\r\n\r\n",
            );
        });
        let head = read_request_head(&mut server, std::time::Duration::from_secs(2))
            .expect("a complete head must be returned");
        writer.join().expect("writer thread did not panic");
        assert_eq!(
            head, "GET /jwks HTTP/1.1\r\nHost: x\r\n\r\n",
            "the head must stop at the first CRLFCRLF, not include what follows it"
        );
    }

    /// The **shipped** deadline is the one a stalled client in the suite meets;
    /// every other test overrides it, so without this the constant could be raised
    /// to 60 s with the whole suite green (a round-3 review mutant). Pinned by
    /// value — see the constant's doc for why the end-to-end effect is not
    /// exercised, and `mock_default_ctor_delegates_the_pinned_deadline` below for
    /// the half this value pin cannot see.
    #[test]
    fn mock_default_request_head_deadline_is_pinned() {
        assert_eq!(
            MOCK_REQUEST_HEAD_TIMEOUT,
            std::time::Duration::from_secs(5),
            "the shipped mock deadline changed: a stalled client now holds the \
             serving thread for {MOCK_REQUEST_HEAD_TIMEOUT:?}. If deliberate, \
             update the ledger's 5 s figures and this pin together."
        );
    }

    /// The **delegation** `oidc_mock_server() → oidc_mock_server_with_timeout(MOCK_REQUEST_HEAD_TIMEOUT)`,
    /// which the value pin above cannot see: it asserts only that the constant is
    /// 5 s, so wiring the call to `Duration::from_secs(60)` — a round-3 review
    /// mutant (`M_delegation_60s`) — left the whole `oidc` suite green, because
    /// every other test either sends at once or overrides the deadline
    /// explicitly.
    ///
    /// The returned handle carries the deadline its serving thread actually reads
    /// with, so this costs nothing and does **not** wait out the shipped 5 s.
    #[test]
    fn mock_default_ctor_delegates_the_pinned_deadline() {
        let (issuer, handle) = oidc_mock_server();
        assert_eq!(
            handle.request_head_timeout(),
            MOCK_REQUEST_HEAD_TIMEOUT,
            "oidc_mock_server() must pass the shipped MOCK_REQUEST_HEAD_TIMEOUT to \
             oidc_mock_server_with_timeout; wiring it to any other value leaves every \
             record-counting oidc test green (round-3 mutant M_delegation_60s). \
             issuer={issuer}"
        );
    }

    /// [`MockServerHandle::request_head_timeout`] reports the **stored** field,
    /// not a constant — the half the default-ctor pin above cannot see.
    ///
    /// `mock_default_ctor_delegates_the_pinned_deadline` calls the accessor once
    /// and compares it to `MOCK_REQUEST_HEAD_TIMEOUT`, so an accessor that
    /// ignores `self.request_head_timeout` and returns the constant keeps every
    /// other `oidc` test green — measured: on the pre-pin tree all 19 `oidc`
    /// tests stayed green with the accessor body replaced by
    /// `MOCK_REQUEST_HEAD_TIMEOUT` (there are 20 at this head, this pin
    /// included; TODO.md:8553 (b)).
    /// Three **distinct** overrides keep that mutant red three times over: a
    /// distilled accessor can return at most one of the three values, so
    /// `125 ms`, `60 s` or `31.337 ms` fails whichever value it happened to pick.
    /// They are also all different from the 5 s constant, so a body that returns
    /// `MOCK_REQUEST_HEAD_TIMEOUT` fails all three — and, because they are the
    /// same values the assertions use, the test is its own control.
    ///
    /// The third override is deliberately **sub-100 ms and non-round**. A body
    /// that special-cases a round threshold ("`< 100 ms` → the constant, else the
    /// stored field") is right for `125 ms` and `60 s` alone and was measured
    /// green against the two-value loop; so is a body that hardcodes exactly the
    /// two originally pinned values. Both die on `31.337 ms`.
    /// No sleeping: the handle is produced by `oidc_mock_server_with_timeout`
    /// without waiting out any of the deadlines.
    #[test]
    fn mock_handle_reports_the_override_it_was_built_with() {
        // Not a shipped constant and not a round number an accessor could
        // special-case: below any plausible threshold, and small enough that the
        // mock never waits it out (the handle is built without a connection).
        let third = std::time::Duration::from_micros(31_337);
        for override_timeout in [
            std::time::Duration::from_millis(125),
            std::time::Duration::from_secs(60),
            third,
        ] {
            assert_ne!(
                override_timeout, MOCK_REQUEST_HEAD_TIMEOUT,
                "each override must differ from the shipped constant, or the accessor \
                 could return either one and stay green"
            );
            let (issuer, handle) = oidc_mock_server_with_timeout(override_timeout);
            assert_eq!(
                handle.request_head_timeout(),
                override_timeout,
                "request_head_timeout() must return the stored deadline the handle was \
                 built with ({override_timeout:?}), not a constant: a distilled accessor \
                 returning MOCK_REQUEST_HEAD_TIMEOUT ({MOCK_REQUEST_HEAD_TIMEOUT:?}) or a \
                 different override's value is invisible to \
                 mock_default_ctor_delegates_the_pinned_deadline, whose only comparison is \
                 against the shipped constant. issuer={issuer}"
            );
        }
    }

    /// End to end: a client that connects and never sends gets an explicit
    /// `500` naming the cause — never the `/` route's silent `404 OK` — and the
    /// mock's serving thread stays usable for the next connection.
    #[test]
    fn mock_idp_answers_an_explicit_error_when_no_request_line_arrives() {
        let (issuer, _stop) = oidc_mock_server_with_timeout(std::time::Duration::from_millis(200));
        let addr = issuer.strip_prefix("http://").expect("issuer host");
        let mut silent = std::net::TcpStream::connect(addr).expect("connect mock");
        let started = std::time::Instant::now();
        let mut resp = String::new();
        let _ = Read::read_to_string(&mut silent, &mut resp);
        let waited = started.elapsed();
        let first = resp.lines().next().unwrap_or("");
        assert!(
            first.contains(" 500 "),
            "a missing request head must be an explicit 500, got {first:?} (full: {resp:?})"
        );
        assert!(
            !first.contains(" 404 "),
            "a missing request head must not be a silent 404: {first:?}"
        );
        assert!(
            resp.contains("no complete request head"),
            "the 500 body must name the cause, got {resp:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(5),
            "the mock did not bound its wait (waited {waited:?})"
        );
        // The accept loop survived the failure: the next connection is served.
        let mut client = std::net::TcpStream::connect(addr).expect("reconnect mock");
        Write::write_all(
            &mut client,
            format!("GET /.well-known/openid-configuration HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("send follow-up request");
        let mut after = String::new();
        let _ = Read::read_to_string(&mut client, &mut after);
        assert!(
            after.lines().next().unwrap_or("").contains(" 200 "),
            "the mock must keep serving after an expired wait, got {after:?}"
        );
    }

    /// End to end, and **red on the pre-fix mock on both platforms**: a client
    /// that connects and half-closes before sending anything made the old single
    /// `read` return `Ok(0)`, which `unwrap_or(0)` mapped to 0 bytes → the `/`
    /// route → `404 OK` (measured shapes: `n=0` → 404 on macOS *and* Linux, so
    /// this is not the macOS-only accept race). It must be an explicit error
    /// naming the closed socket.
    #[test]
    fn mock_idp_answers_an_explicit_error_when_the_client_closes_before_sending() {
        let (issuer, _stop) = oidc_mock_server_with_timeout(std::time::Duration::from_millis(500));
        let addr = issuer.strip_prefix("http://").expect("issuer host");
        let mut stream = std::net::TcpStream::connect(addr).expect("connect mock");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close before sending");
        let started = std::time::Instant::now();
        let mut resp = String::new();
        let _ = Read::read_to_string(&mut stream, &mut resp);
        let waited = started.elapsed();
        let first = resp.lines().next().unwrap_or("");
        assert!(
            first.contains(" 500 "),
            "a closed client must be an explicit 500, got {first:?} (full: {resp:?})"
        );
        assert!(
            !first.contains(" 404 "),
            "a closed client must not be a silent 404: {first:?}"
        );
        assert!(
            resp.contains("closed the socket"),
            "the 500 body must name the EOF, got {resp:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(2),
            "EOF must not wait out the deadline (waited {waited:?})"
        );
    }

    /// `send(())` really does stop the accept loop: after the signal the listener
    /// must go away, so a later connection is refused. The target is the
    /// `M_ignore_stop` mutant (dropping the `break` in
    /// `if stop_rx.try_recv().is_ok()`), which leaves every other `oidc` test
    /// green — including the doc sentence that says only an explicit `send(())`
    /// breaks the loop.
    #[test]
    fn mock_idp_stops_serving_after_the_stop_signal() {
        let (issuer, stop) = oidc_mock_server();
        let addr = issuer
            .strip_prefix("http://")
            .expect("issuer host")
            .to_string();
        // Prove the loop is alive first, so a refusal below cannot be a mock that
        // never started.
        let mut stream = std::net::TcpStream::connect(&addr).expect("connect mock");
        Write::write_all(
            &mut stream,
            format!("GET /.well-known/openid-configuration HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("send discovery request");
        let mut resp = String::new();
        let _ = Read::read_to_string(&mut stream, &mut resp);
        assert!(
            resp.lines().next().unwrap_or("").contains(" 200 "),
            "the mock must serve before the stop, got {resp:?}"
        );

        stop.send(()).expect("send stop signal");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut refused = false;
        while std::time::Instant::now() < deadline {
            match std::net::TcpStream::connect(&addr) {
                // Drop it at once so a connection that lands just before the
                // break cannot stall the loop in a request-head wait.
                Ok(probe) => {
                    drop(probe);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => {
                    refused = true;
                    break;
                }
            }
        }
        assert!(
            refused,
            "the mock kept accepting connections after send(()): the accept loop did not terminate"
        );
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

    pub(super) fn state_with_oidc(verifier: frp_core::auth::OidcVerifier) -> Arc<AppState> {
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
            None,
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
                true,
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

    #[tokio::test]
    async fn oidc_replay_seeded_jti_rejected_at_login() {
        // S2 pin: a jti already recorded for ANOTHER subject is rejected at
        // login even when the token is VALIDLY SIGNED (it would pass
        // verify_login) — the pre-verify replay check
        // (extract_claims_unverified + check_replay_pending) fires before
        // verify_login, so a cross-identity replay of a stolen token is
        // refused with an O(1) table hit instead of a JWKS fetch +
        // signature verify. (The post-verify check would also reject; the
        // pre-verify ordering is pinned structurally by code placement and
        // by the frp-core unit tests.)
        let (issuer, _stop) = oidc_mock_server();
        let verifier = frp_core::auth::OidcVerifier::new(
            issuer.clone(),
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
        // Seed the replay state the way a verified login for ANOTHER
        // subject would: j1 → mallory.
        verifier
            .check_replay(Some("j1"), "mallory", 4_102_444_800)
            .expect("seed jti");
        let state = state_with_oidc(verifier);

        // VALIDLY SIGNED token (kid k1 = the mock JWKS key) for alice
        // reusing j1 — a cross-identity replay.
        let valid_token = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::HS256,
                kid: Some("k1".into()),
                ..jsonwebtoken::Header::default()
            },
            &serde_json::json!({
                "sub": "alice",
                "exp": 4_102_444_800_u64,
                "jti": "j1",
                "iss": issuer,
                "aud": "test-audience",
            }),
            &jsonwebtoken::EncodingKey::from_secret(b"mock-jwks-secret"),
        )
        .expect("encode valid JWT");

        let peer: std::net::SocketAddr = "127.0.0.1:12346".parse().unwrap();
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
            privilege_key: Some(valid_token.clone()),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        for attempt in 1..=3u32 {
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
                true,
            )
            .await;
            assert!(result.is_err(), "attempt {attempt} must be rejected");
            let error = read_login_resp_error(&mut client).await;
            assert!(
                error.contains("OIDC authentication failed"),
                "attempt {attempt} must fail auth, got: {error}"
            );
        }
    }

    #[tokio::test]
    async fn oidc_path_rejects_invalid_run_id() {
        // L4 regression: run_id validation must run BEFORE the auth branch
        // (Go service.go:795 ValidateRunID before VerifyLogin), so the OIDC
        // path rejects oversized / non-printable run ids too — previously
        // the validation only ran in the token branch and an OIDC login
        // with a 65-byte run_id sailed through into routing tables and
        // logs. EMPTY run ids are NOT rejected: Go service.go:789-790
        // normalizes an empty run id to util.RandID() before validating.
        // A VALID OIDC JWT is used everywhere so the rejection is provably
        // run_id-driven, and a control case with a valid run_id proves the
        // JWT itself authenticates.
        let (issuer, _stop) = oidc_mock_server();
        let issuer_url = issuer.clone();
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

        let valid_jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::HS256,
                kid: Some("k1".into()),
                ..jsonwebtoken::Header::default()
            },
            &serde_json::json!({
                "sub": "l4-oidc-user",
                "exp": 4_102_444_800_u64,
                "iss": issuer_url,
                "aud": "test-audience",
            }),
            &jsonwebtoken::EncodingKey::from_secret(b"mock-jwks-secret"),
        )
        .expect("encode valid OIDC JWT");

        let peer: std::net::SocketAddr = "127.0.0.2:12345".parse().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login_with = |run_id: Option<String>| frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id,
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(valid_jwt.clone()),
            metas: None,
            client_spec: None,
            multiplexer: None,
        };

        // (a) 65 bytes > Go's 64-byte cap.
        let (server, mut client) = tokio::io::duplex(4096);
        let result = authenticate(
            Box::new(server),
            &login_with(Some("a".repeat(65))),
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_err(), "oversized run_id must be rejected");
        let error = read_login_resp_error(&mut client).await;
        assert!(
            error.contains("invalid run id"),
            "oversized run_id must be rejected on the OIDC path, got: {error}"
        );

        // (b) U+00A0 (non-breaking space) is not printable (Go IsPrint).
        let (server, mut client) = tokio::io::duplex(4096);
        let result = authenticate(
            Box::new(server),
            &login_with(Some("\u{00A0}run".into())),
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_err(), "U+00A0 run_id must be rejected");
        let error = read_login_resp_error(&mut client).await;
        assert!(
            error.contains("invalid run id"),
            "U+00A0 run_id must be rejected on the OIDC path, got: {error}"
        );

        // (c) Empty client-supplied run_id (Some("")) is normalized to a
        // generated UUID, NOT rejected (Go service.go:789-790 runs
        // util.RandID() before ValidateRunID — ValidateRunID never sees
        // the empty string, so "run id cannot be empty" is unreachable).
        let (server, _client) = tokio::io::duplex(4096);
        let result = authenticate(
            Box::new(server),
            &login_with(Some(String::new())),
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(
            result.is_ok(),
            "empty run_id must normalize to a generated id, not be rejected (Go service.go:789-790)"
        );

        // (d) Control: valid printable run_id + the same valid JWT must
        // authenticate — proves (a)-(b) rejections are run_id-driven.
        let (server, _client) = tokio::io::duplex(4096);
        let result = authenticate(
            Box::new(server),
            &login_with(Some("l4-ok-run-id".into())),
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_ok(), "valid run_id + valid JWT must authenticate");
    }
}

/// PR #454 login auth-method split: ordering pins (`TODO.md:10441`).
///
/// Each test below reds under the specific reordering it names. The two
/// gate-order mutants (the throttle gate moved after the plugin hook, and
/// after run_id validation) are already caught by
/// `frp-server/tests/http_plugin.rs::test_plugin_reject_consumes_login_throttle_slots`
/// — it pins the plugin-invocation count, and the gate sits before the plugin
/// hook in the correct order, so either move lets the throttled attempt
/// reach the plugin and reds — so no duplicate test is added here.
#[cfg(test)]
mod login_order_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{authenticate, send_login_error};

    const TOKEN: &str = "login-order-token";

    /// State with the token replay window ENABLED: `AuthConfig::with_token`
    /// leaves `authentication_timeout` at 0, which makes `check_token_replay`
    /// a no-op.
    fn state_with_replay() -> Arc<crate::state::AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        let mut auth = frp_core::auth::AuthConfig::with_token(TOKEN);
        auth.authentication_timeout = 90;
        Arc::new(crate::state::AppState::new(
            auth,
            "127.0.0.1".into(),
            frp_core::encryption::derive_key(TOKEN),
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
            String::new(),
            true,
            30,
            None,
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
            0,
            168,
            true,
            0,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn login_msg(run_id: &str, ts: i64, privilege_key: String) -> frp_core::msg::Login {
        frp_core::msg::Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: Some(run_id.into()),
            client_id: None,
            pool_count: None,
            timestamp: Some(ts),
            privilege_key: Some(privilege_key),
            metas: None,
            client_spec: None,
            multiplexer: None,
        }
    }

    /// Read one V1 LoginResp frame from the client side of a duplex and
    /// return its error field (local copy — sibling test modules cannot share
    /// private items).
    async fn read_login_resp_error(client: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
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
        let resp: frp_core::msg::LoginResp =
            serde_json::from_slice(&payload).expect("parse LoginResp");
        resp.error.unwrap_or_default()
    }

    /// PR #454 invariant 3: run_id validation runs BEFORE the auth phase.
    /// The LoginResp text is identical in the reordered shape (the invalid
    /// run_id branch emits the same literal in both orders), so this pins the
    /// ORDER through the replay table: with a VALID credential the auth phase
    /// records the `(ts, run_id)` pair in `used_timestamps`; if validation
    /// moved after `auth_fut.await?` that counter becomes 1.
    ///
    /// Mutant: move the `if let Some(rid) = login.run_id.as_deref()` block
    /// after `let (oidc_subject, mut stream) = auth_fut.await?;`.
    #[tokio::test]
    async fn run_id_validation_short_circuits_the_auth_phase() {
        let state = state_with_replay();
        let peer: std::net::SocketAddr = "127.0.0.7:12345".parse().unwrap();
        let ts = now_ms();
        let oversized = "r".repeat(65);
        let login = login_msg(&oversized, ts, frp_core::auth::generate_token(TOKEN, ts));
        let (server, mut client) = tokio::io::duplex(4096);

        let result = authenticate(
            Box::new(server),
            &login,
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(result.is_err(), "an oversized run_id must be rejected");
        assert_eq!(
            read_login_resp_error(&mut client).await,
            "invalid run id: must be at most 64 printable bytes"
        );
        assert_eq!(
            state.used_timestamps.lock().await.total(),
            0,
            "run_id validation must reject BEFORE the auth phase records the login in the replay table"
        );
    }

    /// PR #454 invariant 4: `verify_login_auth` short-circuits on
    /// `is_auth_bypass` BEFORE dispatching to the OIDC verifier
    /// (`frp-server/src/control/login/auth.rs:121-126`). An internal
    /// connection carrying `always_auth_pass` must bypass even when an OIDC
    /// verifier is configured and its privilege_key is not a JWT.
    ///
    /// Mutant: swap the two arms so the `state.oidc.verifier` dispatch
    /// precedes the bypass — this internal login is then pushed into JWT
    /// verification and rejected.
    #[cfg(feature = "oidc")]
    #[tokio::test]
    async fn oidc_dispatch_does_not_preempt_the_auth_bypass_short_circuit() {
        use super::oidc_throttle_tests::{oidc_mock_server, state_with_oidc};

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
        let peer: std::net::SocketAddr = "127.0.0.8:12345".parse().unwrap();
        let ts = now_ms();
        let mut login = login_msg("bypass-run-id", ts, "not-a-jwt".into());
        login.client_spec = Some(frp_core::msg::ClientSpec {
            client_type: Some("ssh-tunnel".into()),
            always_auth_pass: Some(true),
        });
        let (server, _client) = tokio::io::duplex(65536);
        let result = authenticate(
            Box::new(server),
            &login,
            state,
            Some(peer),
            None,
            false,
            None,
            true, // internal
            None,
            true,
        )
        .await;
        assert!(
            result.is_ok(),
            "an internal always_auth_pass login must bypass the configured OIDC verifier"
        );
    }

    /// `TODO.md:10441` Done-when: "`throttled_login_error`'s LoginResp message
    /// text asserted like the gate's in `frp-server/tests/login_replay_throttle.rs`".
    /// The gate's copy of the literal is asserted end-to-end there; this pins
    /// the OTHER producer (`frp-server/src/control/login/throttle.rs:58`),
    /// reached from the plugin / run_id / auth failure paths.
    /// `pre_auth_throttle_gate` shares `check_login_throttle`'s predicate and
    /// always runs first on a new connection, so on a single sequential
    /// connection this producer is unreachable; the direct call below uses
    /// the same state and peer and pushes the returned string through the
    /// real `send_login_error` wire path.
    ///
    /// Mutant: reword the literal at `throttle.rs:58` — this test reds while
    /// the gate-path integration assertions stay green.
    #[tokio::test]
    async fn throttled_login_error_message_reaches_the_login_resp() {
        let state = state_with_replay();
        let peer: std::net::SocketAddr = "127.0.0.9:12345".parse().unwrap();
        for _ in 0..5 {
            assert!(
                state.check_login_throttle(peer).await,
                "the first five attempts are admitted"
            );
        }
        let msg = super::throttle::throttled_login_error(&state, Some(peer))
            .await
            .expect("the sixth attempt must be throttled");
        assert_eq!(msg, "login throttled: too many failed attempts");

        let (server, mut client) = tokio::io::duplex(4096);
        send_login_error(Box::new(server), msg, false).await;
        assert_eq!(
            read_login_resp_error(&mut client).await,
            "login throttled: too many failed attempts",
            "throttled_login_error's message must be the LoginResp error text"
        );
    }

    /// Like `StalledStream` in `send_login_error_deadline_tests`, but signals
    /// the first `poll_write` so the test knows the reject write has been
    /// ENTERED without relying on a timer.
    struct SignalingStalledStream {
        reached: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl tokio::io::AsyncRead for SignalingStalledStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for SignalingStalledStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if let Some(tx) = self.reached.take() {
                let _ = tx.send(());
            }
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// PR #454 invariant 5: the replay-table guard is released (`drop(used)`,
    /// `frp-server/src/control/login/auth.rs:414`) BEFORE the
    /// replay-rejection `send_login_error` (`auth.rs:415-428`).
    /// `used_timestamps` is one tokio Mutex shared by every login, so holding
    /// it across the reject write stalls unrelated logins for up to the 5s
    /// reject-path deadline.
    ///
    /// Mutant: move `drop(used)` after the `send_login_error(...).await` in
    /// the replay branch — task A then holds the lock for its full stall and
    /// task B times out.
    #[tokio::test]
    async fn replay_rejection_releases_the_replay_lock_before_writing() {
        let state = state_with_replay();
        let peer: std::net::SocketAddr = "127.0.0.10:12345".parse().unwrap();
        let ts = now_ms();
        let login = login_msg(
            "lock-release-run-id",
            ts,
            frp_core::auth::generate_token(TOKEN, ts),
        );

        // Admit the pair once on a live stream so the next send is a genuine
        // duplicate-second replay.
        let (server, _client) = tokio::io::duplex(4096);
        let first = authenticate(
            Box::new(server),
            &login,
            state.clone(),
            Some(peer),
            None,
            false,
            None,
            false,
            None,
            true,
        )
        .await;
        assert!(first.is_ok(), "the admitting login must succeed");
        assert_eq!(state.used_timestamps.lock().await.total(), 1);

        // A: the replay, on a stream whose write never completes. The signal
        // fires once A has entered `send_login_error`'s write.
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let state_a = state.clone();
        let login_a = login.clone();
        let stalled = tokio::spawn(async move {
            let stream: Box<dyn frp_core::cipher_stream::AsyncReadWriteUnpin> =
                Box::new(SignalingStalledStream {
                    reached: Some(reached_tx),
                });
            let _ = authenticate(
                stream,
                &login_a,
                state_a,
                Some(peer),
                None,
                false,
                None,
                false,
                None,
                true,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(5), reached_rx)
            .await
            .expect("the replay reject write must be entered within 5s")
            .expect("the write-entered signal must be delivered");

        // B: an unrelated fresh login on another connection must not block on
        // the replay lock while A's reject write is in flight.
        let ts_b = now_ms() + 1_000;
        let login_b = login_msg(
            "lock-release-run-id-b",
            ts_b,
            frp_core::auth::generate_token(TOKEN, ts_b),
        );
        let (server_b, _client_b) = tokio::io::duplex(4096);
        let b = tokio::time::timeout(
            Duration::from_secs(2),
            authenticate(
                Box::new(server_b),
                &login_b,
                state.clone(),
                Some(peer),
                None,
                false,
                None,
                false,
                None,
                true,
            ),
        )
        .await;
        stalled.abort();
        assert!(
            b.is_ok(),
            "a concurrent login must not block on the replay lock while a reject write is in flight"
        );
        assert!(
            b.unwrap().is_ok(),
            "the concurrent login must still succeed"
        );
    }
}
