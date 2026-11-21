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
    let resp: frp_core::msg::LoginResp = serde_json::from_slice(&payload).expect("parse LoginResp");
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

/// `TODO.md:11472` Done-when: "`throttled_login_error`'s LoginResp message
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
/// Mutant: reword the literal at `frp-server/src/control/login/throttle.rs:58` — this test reds while
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
/// replay-rejection `send_login_error` (`frp-server/src/control/login/auth.rs:415-428`).
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
