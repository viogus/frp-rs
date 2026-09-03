//! Login replay × throttle interaction (login.rs). Replaying a captured
//! Login frame — identical ms-precision timestamp + run_id + token — must
//! be rejected by the ReplayTable, and every rejection must consume a
//! per-IP login-throttle slot: after 5 failures (login.rs
//! `throttled_login_error` → `check_login_throttle` cap) the IP is
//! rejected pre-auth (`is_login_throttled`), even with a fresh timestamp.

mod common;

use std::net::SocketAddr;

use common::{allocate_port, start_test_server, test_auth_cfg, TEST_TOKEN};
use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

/// Open one TCP connection and send the byte-identical Login frame (the
/// same ms-precision timestamp, run_id, and MD5(token+ts) key). Returns
/// the LoginResp error string, if any.
async fn replay_login_once(addr: SocketAddr, run_id: &str, ts: i64) -> Option<String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to server");
    let mut io = IoStream::Tcp(tcp);

    let key = auth::generate_token(TEST_TOKEN, ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("replay-test".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: Some(run_id.into()),
        client_id: None,
        pool_count: Some(0),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    write_msg_v1(&mut io, &login).await.expect("send Login");

    match read_msg_v1(&mut io).await.expect("read LoginResp") {
        FrpMessage::LoginResp(resp) => resp.error,
        other => panic!(
            "expected LoginResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

/// Attempt 1 with a fresh (run_id, ms timestamp) pair is admitted. The
/// same frame replayed 5 times is rejected as a replay attack, and each
/// rejection consumes a throttle slot (5 = the per-IP cap). The 6th
/// replay — and even a replay with a FRESH timestamp — is then rejected
/// by the pre-auth throttle gate.
#[tokio::test]
async fn test_replayed_login_consumes_throttle_slots_then_throttles() {
    let bind_port = allocate_port();
    // NOTE: `test_auth_cfg()` keeps AuthServerConfig's default
    // authentication_timeout = 0 (Go parity: replay protection OFF), which
    // skips the replay table entirely — the server-level default of 90s is
    // what enables it, so set it explicitly here.
    let mut auth = test_auth_cfg();
    auth.authentication_timeout = 90;
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // 1: fresh pair → admitted (successful logins never count).
    let err = replay_login_once(addr, "replay-target", ts).await;
    assert!(
        err.is_none(),
        "first login with fresh timestamp must succeed: {err:?}"
    );

    // 2-6: the identical frame is a replay attack; each rejection must
    // consume a throttle slot, reaching the 5-failure per-IP cap.
    for attempt in 0..5 {
        let err = replay_login_once(addr, "replay-target", ts).await;
        assert_eq!(
            err.as_deref(),
            Some("replay attack detected: duplicate timestamp"),
            "replay attempt {}: expected replay rejection, got: {err:?}",
            attempt + 2,
        );
    }

    // 7: over the cap → the pre-auth throttle gate rejects, even though
    // the frame is still the same valid-login replay.
    let err = replay_login_once(addr, "replay-target", ts).await;
    assert_eq!(
        err.as_deref(),
        Some("login throttled: too many failed attempts"),
        "expected pre-auth throttle rejection, got: {err:?}",
    );

    // 8: a fresh timestamp does not reset the window — the IP is
    // throttled for the remaining 60s regardless of replay status.
    let err = replay_login_once(addr, "replay-target", ts + 1).await;
    assert_eq!(
        err.as_deref(),
        Some("login throttled: too many failed attempts"),
        "fresh-timestamp login must still be throttled inside the 60s window, got: {err:?}",
    );
}

/// R9: stale-timestamp logins are rejected with the freshness error AND
/// consume per-IP throttle slots. login.rs runs the freshness check before
/// the replay table (Go VerifyLogin order), so a flood of captured
/// (ts, md5) pairs with a stale clock must still advance the per-IP
/// failure counter — after 5 stale rejections the IP is throttled
/// pre-auth and even a FRESH-timestamp login is refused for the rest of
/// the 60s window.
#[tokio::test]
async fn test_stale_timestamp_logins_consume_throttle_slots_then_throttle_fresh() {
    let bind_port = allocate_port();
    let mut auth = test_auth_cfg();
    auth.authentication_timeout = 90;
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // 1: a FRESH (run_id, ts) pair succeeds (successes never count against
    // the throttle).
    let err = replay_login_once(addr, "stale-ts-target", now_ms).await;
    assert!(err.is_none(), "fresh-timestamp login must succeed: {err:?}");

    // 2-6: five stale-timestamp logins (2 minutes in the past — outside the
    // 90s freshness window). Each is rejected with the freshness error and
    // consumes one of the 5 per-IP throttle slots.
    let stale_ts = now_ms - 120_000;
    for attempt in 0..5 {
        let err = replay_login_once(addr, "stale-ts-target", stale_ts - attempt).await;
        assert_eq!(
            err.as_deref(),
            Some("timestamp outside acceptable window"),
            "stale login attempt {}: expected freshness rejection, got: {err:?}",
            attempt + 2,
        );
    }

    // 7: over the cap → pre-auth throttle rejects (throttled_login_error
    // supersedes the freshness error once the IP is throttled).
    let err = replay_login_once(addr, "stale-ts-target", stale_ts - 100).await;
    assert_eq!(
        err.as_deref(),
        Some("login throttled: too many failed attempts"),
        "expected pre-auth throttle rejection, got: {err:?}",
    );

    // 8: even a FRESH timestamp is refused — the throttle gate sits in
    // front of the freshness/replay checks.
    let err = replay_login_once(addr, "stale-ts-target", now_ms + 1).await;
    assert_eq!(
        err.as_deref(),
        Some("login throttled: too many failed attempts"),
        "fresh-timestamp login must still be throttled inside the 60s window, got: {err:?}",
    );
}
