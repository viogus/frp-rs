//! Round-8 login validation regressions (Go frp v0.71.0 parity):
//!
//! 1. An EMPTY run_id (`Some("")`) is normalized to a generated UUID, NOT
//!    rejected — Go server/service.go:789-791 does `if loginMsg.RunID == "" {
//!    loginMsg.RunID, err = util.RandID() }` BEFORE ValidateRunID, and the
//!    normalized value is what routing tables / LoginResp / the replay table
//!    use. A subsequent NewWorkConn carrying the echoed run_id must be
//!    accepted (proving the normalized id is what the control handler
//!    registered).
//! 2. A NON-EMPTY invalid run_id — control characters or > 64 bytes — is
//!    rejected (Go name.go validateIdentifier: unicode.IsPrint + MaxRunID
//!    length 64).
//! 3. A negative pool_count is rejected (Go server/control.go:437
//!    NewControl), and the rejection must NOT consume a login-throttle
//!    slot: five negative-pool_count failures followed by a valid login
//!    still succeeds. If the rejections consumed slots, the sixth attempt
//!    would be refused pre-auth ("login throttled").

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{allocate_port, start_test_server, test_auth_cfg, TEST_TOKEN};
use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage, LoginResp};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use tokio::io::AsyncReadExt;

/// Raw V1 login with a caller-supplied run_id and pool_count (raw_login_full
/// hardcodes run_id: None). Fresh timestamp + privilege_key per call, so
/// repeated attempts never collide in the replay table. The returned stream
/// is NOT yet wrapped in CipherStream — the caller wraps it only when the
/// login succeeded (the server wraps after a successful LoginResp).
async fn raw_login_custom(
    addr: SocketAddr,
    run_id: Option<String>,
    pool_count: Option<i32>,
) -> (IoStream, LoginResp) {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to server");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token(TEST_TOKEN, ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("run-id-test".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id,
        client_id: None,
        pool_count,
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    let mut io = IoStream::Tcp(stream);
    write_msg_v1(&mut io, &login).await.expect("send Login");
    match read_msg_v1(&mut io).await.expect("read LoginResp") {
        FrpMessage::LoginResp(resp) => (io, resp),
        other => panic!("expected LoginResp, got {:?}", other.v1_type_byte()),
    }
}

#[tokio::test]
async fn test_empty_run_id_normalized_to_uuid_and_usable() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    // `Some("")` must be treated exactly like an absent run_id: normalized
    // to a generated UUID, not rejected.
    let (io, resp) = raw_login_custom(addr, Some(String::new()), Some(1)).await;
    assert!(
        resp.error.is_none(),
        "empty run_id must be normalized, not rejected: {:?}",
        resp.error
    );
    let run_id = resp.run_id.expect("LoginResp must carry a run_id");
    assert_eq!(
        run_id.len(),
        36,
        "normalized run_id must be a UUID: {run_id}"
    );

    // The server wraps the control stream in AES-128-CFB after LoginResp;
    // pool_count 1 pre-warms exactly one ReqWorkConn through it.
    let mut control = io
        .into_encrypted(encryption::derive_key(TEST_TOKEN))
        .expect("wrap control in encryption");
    match tokio::time::timeout(Duration::from_secs(2), read_msg_v1(&mut control))
        .await
        .expect("pre-warm ReqWorkConn within 2s")
        .expect("read pre-warm ReqWorkConn")
    {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!(
            "expected pre-warm ReqWorkConn, got {:?}",
            other.v1_type_byte()
        ),
    }

    // The NORMALIZED run_id must be what the control handler registered:
    // a raw NewWorkConn carrying it is accepted (pooled → connection stays
    // open), not dropped as unknown-run_id.
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("dial work conn");
    let (mut rd, mut wr) = stream.into_split();
    write_msg_v1(
        &mut wr,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    let mut buf = [0u8; 64];
    let kept = tokio::time::timeout(Duration::from_millis(300), rd.read(&mut buf)).await;
    assert!(
        kept.is_err(),
        "NewWorkConn with normalized run_id must be pooled, not dropped"
    );
}

#[tokio::test]
async fn test_nonempty_invalid_run_id_rejected() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    // Control character (Go unicode.IsPrint rejects \x01) …
    let (_io, resp) = raw_login_custom(addr, Some("bad\x01run_id".into()), None).await;
    assert!(
        resp.error.is_some(),
        "control-character run_id must be rejected"
    );

    // … and > 64 bytes (Go MaxRunID length 64) are both rejected.
    let (_io, resp) = raw_login_custom(addr, Some("x".repeat(65)), None).await;
    assert!(resp.error.is_some(), "65-byte run_id must be rejected");
}

/// Five negative-pool_count logins must each be rejected WITHOUT consuming
/// a login-throttle slot (the rejection happens after auth, and the
/// round-8 fix keeps it off the throttled_login_error path): the sixth,
/// valid login from the same IP must still succeed. If the rejections had
/// counted as failures, the pre-auth throttle gate would refuse attempt 6
/// outright.
#[tokio::test]
async fn test_negative_pool_count_rejected_without_throttle_slot() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    for i in 0..5 {
        let (_io, resp) = raw_login_custom(addr, None, Some(-1)).await;
        assert!(
            resp.error.is_some(),
            "attempt {i}: negative pool_count must be rejected, got: {:?}",
            resp.error
        );
    }

    // Same IP, valid login: must NOT be throttled.
    let (io, resp) = raw_login_custom(addr, None, Some(1)).await;
    assert!(
        resp.error.is_none(),
        "valid login after 5 negative-pool_count rejections must not be throttled: {:?}",
        resp.error
    );
    let _ = io
        .into_encrypted(encryption::derive_key(TEST_TOKEN))
        .expect("wrap control in encryption");
}
