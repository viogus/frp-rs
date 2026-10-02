use super::*;
use tokio::io::AsyncReadExt;

struct TestSshClient;

impl russh::client::Handler for TestSshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn test_state(max_connections: usize) -> Arc<AppState> {
    let cfg = frp_core::config::ServerConfig::default();
    Arc::new(AppState::new(
        frp_core::auth::AuthConfig::with_token("test-token"),
        "127.0.0.1".into(),
        frp_core::encryption::derive_key("test-token"),
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
        max_connections,
        0,
        frp_core::config::ServerConfigSnapshot::from_config(&cfg),
    ))
}

fn pre_auth_session() -> (
    SshSession,
    tokio::sync::watch::Receiver<bool>,
    Arc<std::sync::Mutex<Option<String>>>,
) {
    let (auth_tx, auth_rx) = tokio::sync::watch::channel(false);
    let run_id = Arc::new(std::sync::Mutex::new(None));
    let session = SshSession::new(
        "test-token".into(),
        Vec::new(),
        test_state(1),
        "127.0.0.1:2200".parse().unwrap(),
        auth_tx,
        run_id.clone(),
        tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
        tokio_util::sync::CancellationToken::new(),
    );
    (session, auth_rx, run_id)
}

async fn start_test_ssh_listener(
    auth_deadline: std::time::Duration,
) -> (
    std::net::SocketAddr,
    Arc<AppState>,
    tokio::task::JoinHandle<()>,
) {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let state = test_state(1);
    let mut rng = rand::rng();
    let host_key =
        russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
    let listener = SshListener {
        bind_addr: addr.ip().to_string(),
        bind_port: addr.port(),
        server_token: "test-token".into(),
        state: state.clone(),
        host_key,
        authorized_keys: Vec::new(),
        auth_deadline,
        ssh_session_idle_timeout: 0,
    };
    let task = tokio::spawn(async move {
        listener.run().await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, state, task)
}

#[test]
fn test_pre_auth_session_has_no_internal_control_resources() {
    let (session, auth_rx, run_id) = pre_auth_session();

    assert!(session.run_id.is_empty());
    assert!(session.frame_tx.is_none());
    assert!(!session.authenticated);
    assert!(run_id.lock().unwrap_or_else(|e| e.into_inner()).is_none());
    assert!(!*auth_rx.borrow());
}

#[tokio::test]
async fn test_valid_password_authentication_still_succeeds_without_pre_auth_control() {
    let (mut session, _auth_rx, _run_id) = pre_auth_session();

    let result = session.auth_password("v0", "test-token").await.unwrap();

    assert!(matches!(result, Auth::Accept));
    assert!(session.run_id.is_empty());
    assert!(session.frame_tx.is_none());
}

#[tokio::test]
async fn test_password_failures_throttle_per_ip() {
    // S1 pin: SSH gateway password failures consume the per-IP login
    // throttle slots (mirror of login.rs `throttled_login_error`) — a
    // brute-forcing IP is cut off after the 5th wrong password, and the
    // success path never consumes a slot (legit sessions are never
    // throttled). Go frp has no SSH-gateway auth throttle; this is the
    // same deliberate frp-rs hardening as the login throttle.
    let (mut session, _auth_rx, _run_id) = pre_auth_session();
    let addr = session.peer_addr;
    let state = session.state.clone();
    for _ in 0..5 {
        let result = session.auth_password("v0", "wrong").await.unwrap();
        assert!(matches!(result, Auth::Reject { .. }));
    }
    assert!(
        !state.check_login_throttle(addr).await,
        "6th attempt from the same IP must be throttled"
    );
    // Round-11 GAP-1 pin: the throttle must DENY, not merely return
    // false from the table. The 6th wrong password on this session is
    // cut off with an Err (russh treats a handler error as fatal for
    // the session — the connection dies) instead of a fresh Reject
    // round-trip. Pre-fix this returned Ok(Reject) again: the
    // check_login_throttle bool was discarded at the call site.
    let result = session.auth_password("v0", "wrong").await;
    assert!(
        result.is_err(),
        "6th wrong password must end the session with Err, got: {result:?}"
    );
    // A FRESH connection from the same IP within the window is denied
    // without a USERAUTH_FAILURE round-trip (same state table, shared
    // below). Round-12 pin (audit A1): the deny is now a FAIL-CLOSED
    // pre-auth gate (login.rs:680 `is_login_throttled` parity) that
    // runs BEFORE the constant-time compare — an armed IP's guess is
    // never evaluated, and even a CORRECT password from an armed IP is
    // denied for the window. Round-11's deny ran only on the mismatch
    // branch (after the compare): fail-open meant the throttle never
    // stopped online guessing of the actual password (1 evaluated guess
    // per fresh conn) and skipped the russh 3s rejection pacing, so the
    // 6th+ guess was FASTER than the pre-fix paced rejects.
    let (auth_tx2, _auth_rx2) = tokio::sync::watch::channel(false);
    let run_id2 = Arc::new(std::sync::Mutex::new(None));
    let mut fresh = SshSession::new(
        "test-token".into(),
        Vec::new(),
        state.clone(),
        addr,
        auth_tx2,
        run_id2,
        tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
        tokio_util::sync::CancellationToken::new(),
    );
    let result = fresh.auth_password("v0", "wrong").await;
    assert!(
        result.is_err(),
        "fresh session from a throttled IP must be cut off, got: {result:?}"
    );
    // Fail-closed pin: the pre-gate denies BEFORE the credential
    // compare, so the CORRECT password from an armed IP inside the
    // window is also cut off (no guess evaluated, no accept). RED on
    // round-11 code: the mismatch-branch-only deny let this Accept.
    let (auth_tx3, _auth_rx3) = tokio::sync::watch::channel(false);
    let run_id3 = Arc::new(std::sync::Mutex::new(None));
    let mut fresh_correct = SshSession::new(
        "test-token".into(),
        Vec::new(),
        state.clone(),
        addr,
        auth_tx3,
        run_id3,
        tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
        tokio_util::sync::CancellationToken::new(),
    );
    let result = fresh_correct.auth_password("v0", "test-token").await;
    assert!(
        result.is_err(),
        "correct password from an armed IP must be denied by the pre-gate, got: {result:?}"
    );
    // Other IPs are unaffected.
    assert!(
        state
            .check_login_throttle(std::net::SocketAddr::from(([127, 0, 0, 2], 1)))
            .await,
        "a different IP must not be throttled"
    );
    // The success path consumes no slot.
    let (mut s2, _a2, _r2) = pre_auth_session();
    let addr2 = s2.peer_addr;
    let state2 = s2.state.clone();
    let result = s2.auth_password("v0", "test-token").await.unwrap();
    assert!(matches!(result, Auth::Accept));
    assert!(
        state2.check_login_throttle(addr2).await,
        "successful auth must not consume a throttle slot"
    );
}

#[tokio::test]
async fn test_pubkey_and_none_rejections_do_not_consume_throttle_slots() {
    // D5 pin: only PASSWORD failures consume per-IP throttle slots.
    // `auth_publickey` / `auth_none` return Reject without calling
    // `check_login_throttle`, so a client that probes with pubkey or
    // "none" methods cannot arm the window against the password path
    // (or the shared frpc-login table) — and 5 pubkey/none rejections
    // from one IP leave a subsequent password attempt fully allowed.
    let (mut session, _auth_rx, _run_id) = pre_auth_session();
    let addr = session.peer_addr;
    let state = session.state.clone();

    // 5 publickey rejections (key not in the empty authorized_keys).
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let pubkey = key.public_key().clone();
    for i in 0..5 {
        let result = session.auth_publickey("v0", &pubkey).await.unwrap();
        assert!(
            matches!(result, Auth::Reject { .. }),
            "pubkey rejection {i} must reject (key not authorized)"
        );
    }
    assert!(
        state.check_login_throttle(addr).await,
        "5 pubkey rejections must not arm the password throttle window"
    );

    // 5 "none" rejections (token configured → auth_none rejects).
    let mut s2 = session;
    for i in 0..5 {
        let result = s2.auth_none("v0").await.unwrap();
        assert!(
            matches!(result, Auth::Reject { .. }),
            "none rejection {i} must reject (token configured)"
        );
    }
    assert!(
        state.check_login_throttle(addr).await,
        "5 none rejections must not arm the password throttle window"
    );

    // And a password attempt from the same IP is still fully allowed.
    let result = s2.auth_password("v0", "test-token").await.unwrap();
    assert!(matches!(result, Auth::Accept));
}

#[tokio::test]
async fn test_auth_none_rejected_when_token_is_set() {
    // Regression: auth_none must NOT accept when server_token is
    // configured even if authorized_keys is empty — otherwise any
    // SSH client can bypass token auth (OpenSSH sends "none" first).
    let (mut session, _auth_rx, _run_id) = pre_auth_session();
    let result = session.auth_none("v0").await.unwrap();
    assert!(matches!(result, Auth::Reject { .. }));
}

#[tokio::test]
async fn test_auth_none_accepted_when_no_auth_configured() {
    let (auth_tx, _auth_rx) = tokio::sync::watch::channel(false);
    let run_id_arc = Arc::new(std::sync::Mutex::new(None));
    let mut session = SshSession::new(
        String::new(), // empty token
        Vec::new(),    // empty authorized_keys
        test_state(1),
        "127.0.0.1:2200".parse().unwrap(),
        auth_tx,
        run_id_arc,
        tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
        tokio_util::sync::CancellationToken::new(),
    );
    let result = session.auth_none("v0").await.unwrap();
    assert!(matches!(result, Auth::Accept));
}

#[tokio::test]
async fn test_auth_none_rejected_when_only_keys_configured() {
    // When authorized_keys is set but token is empty, auth_none must
    // still reject — client must use pubkey auth, not anonymous.
    let (auth_tx, _auth_rx) = tokio::sync::watch::channel(false);
    let run_id_arc = Arc::new(std::sync::Mutex::new(None));
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let pubkey = key.public_key().clone();
    let mut session = SshSession::new(
        String::new(),
        vec![pubkey],
        test_state(1),
        "127.0.0.1:2200".parse().unwrap(),
        auth_tx,
        run_id_arc,
        tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
        tokio_util::sync::CancellationToken::new(),
    );
    let result = session.auth_none("v0").await.unwrap();
    assert!(matches!(result, Auth::Reject { .. }));
}

/// Round-11 GAP5: the authorized_keys parser is a pure fn with an
/// externally visible contract (a hostile or hand-edited file must not
/// crash the gateway, and only valid keys may enter the allow-list).
/// This was inline in SshListener::new with zero unit coverage; the
/// shapes below pin the extraction.
#[test]
fn test_parse_authorized_keys_shapes() {
    use russh::keys::PublicKeyBase64;

    let key1 =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let key2 =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let k1_b64 = key1.public_key().public_key_base64();
    let k2_b64 = key2.public_key().public_key_base64();
    let expected1 = russh::keys::parse_public_key_base64(&k1_b64).unwrap();
    let expected2 = russh::keys::parse_public_key_base64(&k2_b64).unwrap();

    // (a) valid line with comment; (b) blank + # comment skipped;
    // (c) indented key lines parse (trim).
    let parsed = parse_authorized_keys(&format!(
        "ssh-ed25519 {k1_b64} user@host\n\n  # comment\n   \nssh-ed25519 {k2_b64}\n"
    ));
    assert_eq!(parsed, vec![expected1.clone(), expected2.clone()]);
    assert_eq!(parsed[0].algorithm(), russh::keys::Algorithm::Ed25519);

    // (d) type-only line (no base64) is dropped;
    // (e) garbage base64 is dropped, neighbors survive.
    let parsed = parse_authorized_keys(&format!(
        "ssh-ed25519\nssh-rsa NOT-BASE64!!\nssh-ed25519 {k1_b64}\n"
    ));
    assert_eq!(parsed, vec![expected1.clone()]);

    // (f) a wrong type field does not invalidate a decodable key
    // (the blob itself carries the type; see the fn doc).
    let parsed = parse_authorized_keys(&format!("ssh-rsa {k2_b64} comment\n"));
    assert_eq!(parsed, vec![expected2.clone()]);

    // (g) empty body / comment-only body parse to nothing.
    assert!(parse_authorized_keys("").is_empty());
    assert!(parse_authorized_keys("# only comments\n\n").is_empty());

    // (h) OpenSSH option-prefixed lines parse (round-12 A2: the old
    // parts[1]-as-base64 reader dropped every options line — a
    // migrated stock authorized_keys uses options everywhere). Covers
    // bare options, quoted values with embedded spaces/commas, and
    // option lists that swallow several tokens.
    let parsed = parse_authorized_keys(&format!(
        "restrict,command=\"echo hi\",from=\"1.2.3.4, 5.6.7.8\" ssh-ed25519 {k1_b64} u@h\n\
             no-port-forwarding ssh-ed25519 {k2_b64}\n"
    ));
    assert_eq!(parsed, vec![expected1.clone(), expected2.clone()]);

    // (i) certificate entries are dropped whole (frp-rs has no CA trust
    // store — see the fn doc) even when the blob decodes — the cert
    // anchor + a raw key blob is the (f)-style trap: the old parser
    // accepted the embedded raw key with zero CA validation; neighbor
    // lines survive.
    let parsed = parse_authorized_keys(&format!(
        "ssh-ed25519-cert-v01@openssh.com {k1_b64}\n\
             ssh-ed25519 {k2_b64}\n"
    ));
    assert_eq!(parsed, vec![expected2]);

    // (j) options lines whose key material does not decode are dropped
    // (the malformed line, not the file — per-line-drop divergence).
    let parsed = parse_authorized_keys(&format!(
        "restrict,from=\"9.9.9.9\" ssh-ed25519 NOT-BASE64!!\n\
             ssh-ed25519 {k1_b64}\n"
    ));
    assert_eq!(parsed, vec![expected1]);
}

/// Round-13: the quote-aware tokenizer's `\`-escape arm (an escaped
/// quote inside a quoted option value must NOT close the quote) has no
/// direct coverage — a hand-edited file like
/// `command="echo \"hi\"" ssh-ed25519 ...` must still yield the key.
#[test]
fn test_parse_authorized_key_line_backslash_escaped_quotes() {
    use russh::keys::PublicKeyBase64;

    let key1 =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let k1_b64 = key1.public_key().public_key_base64();
    let expected1 = russh::keys::parse_public_key_base64(&k1_b64).unwrap();
    let key2 =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let k2_b64 = key2.public_key().public_key_base64();

    // `\"` inside a quoted option value: the tokenizer must not close
    // the quote at the escaped `"`, so the keytype+blob pair stays
    // reachable. The SECOND line is the discriminating shape: a real
    // key material pair sits inside an unterminated quote — the
    // quote-aware parser drops the whole line, while a naive
    // whitespace tokenizer would surface it. Exactly key1 must parse.
    let parsed = parse_authorized_keys(&format!(
        "restrict,command=\"echo \\\"hi\\\"\",from=\"a b\" ssh-ed25519 {k1_b64} u@h\n\
             command=\"unterminated quote swallows ssh-ed25519 {k2_b64} u@h\n"
    ));
    assert_eq!(
        parsed,
        vec![expected1],
        "escaped quotes must not split the option token, and key material \
             inside an unterminated quote must stay dropped (got {} keys)",
        parsed.len()
    );
}

#[test]
fn test_authentication_resource_initialization_is_idempotent() {
    let (mut session, auth_rx, _run_id) = pre_auth_session();

    assert!(session.begin_authentication());
    assert!(*auth_rx.borrow());
    assert!(!session.begin_authentication());
}

#[test]
fn test_authentication_cannot_begin_after_deadline() {
    let (mut session, _auth_rx, _run_id) = pre_auth_session();
    session.auth_deadline = tokio::time::Instant::now();

    assert!(!session.begin_authentication());
    assert!(!session.authenticated);
}

#[test]
fn test_ssh_connection_permit_is_bounded_and_released() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().unwrap();
    assert!(semaphore.clone().try_acquire_owned().is_err());
    drop(permit);
    assert!(semaphore.try_acquire_owned().is_ok());
}

#[tokio::test]
async fn test_hard_close_wakes_blocked_transport_and_confirms_drop() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(tokio::net::TcpStream::connect(addr));
    let (server_stream, _) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap().unwrap();
    let (mut stream, closer) = CloseableSshStream::new(server_stream);
    let blocked = tokio::spawn(async move {
        let mut byte = [0u8; 1];
        stream.read(&mut byte).await
    });

    closer.close();

    tokio::time::timeout(std::time::Duration::from_secs(1), closer.wait_dropped())
        .await
        .expect("hard-close must make the transport owner drop its stream");
    assert!(blocked.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_drop_notification_is_sticky_when_drop_precedes_wait() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(tokio::net::TcpStream::connect(addr));
    let (server_stream, _) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap().unwrap();
    let (stream, closer) = CloseableSshStream::new(server_stream);
    drop(stream);

    tokio::time::timeout(std::time::Duration::from_millis(10), closer.wait_dropped())
        .await
        .expect("drop notification must remain observable after an early drop");
}

#[tokio::test]
async fn test_pending_disconnect_still_forces_io_close_and_finishes_chain() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(tokio::net::TcpStream::connect(addr));
    let (server_stream, _) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap().unwrap();
    let (mut stream, closer) = CloseableSshStream::new(server_stream);
    let mut session_task = tokio::spawn(async move {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        Ok::<(), anyhow::Error>(())
    });

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        terminate_ssh_session(
            std::future::pending(),
            &mut session_task,
            &closer,
            std::time::Duration::from_millis(10),
        ),
    )
    .await
    .expect("a stuck disconnect sender must not stall termination");

    assert!(closer.0.dropped.is_cancelled());
    assert!(session_task.is_finished());
}

#[tokio::test]
async fn test_real_unauthenticated_connection_times_out_without_control_and_releases_permit() {
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_millis(500)).await;
    let client = russh::client::connect(
        Arc::new(russh::client::Config::default()),
        addr,
        TestSshClient,
    )
    .await
    .expect("SSH key exchange should complete before the auth deadline");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !client.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("post-KEX unauthenticated SSH connection must close at deadline");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(state.run_id_to_ctl_tx.is_empty());
    listener_task.abort();
}

#[tokio::test]
async fn test_real_password_authentication_creates_one_control_and_releases_permit() {
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
    let client_config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect(client_config, addr, TestSshClient)
        .await
        .unwrap();

    let auth = client
        .authenticate_password("v0", "test-token")
        .await
        .unwrap();
    assert!(auth.success());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.run_id_to_ctl_tx.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.run_id_to_ctl_tx.len(), 1);
    assert_eq!(
        state.conn_semaphore.as_ref().unwrap().available_permits(),
        0
    );

    client
        .disconnect(russh::Disconnect::ByApplication, "test complete", "")
        .await
        .unwrap();
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    listener_task.abort();
}

/// Authenticate a russh client against the test SSH listener.
async fn auth_test_client(addr: std::net::SocketAddr) -> russh::client::Handle<TestSshClient> {
    let client_config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect(client_config, addr, TestSshClient)
        .await
        .unwrap();
    let auth = client
        .authenticate_password("v0", "test-token")
        .await
        .unwrap();
    assert!(auth.success());
    client
}

#[tokio::test]
async fn test_exec_parse_error_written_to_client_then_close() {
    // P10 + P6: an exec parse error must reach the SSH client as text,
    // then the session closes (Go writeToClient + close). Returning Err
    // from exec_request would drop the text — the write is queued via
    // Handle::data and flushed only after exec_request returns Ok.
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
    let client = auth_test_client(addr).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel.exec(true, "tcp --bogus_flag value").await.unwrap();
    let mut reader = channel.make_reader();
    let mut text = String::new();
    use tokio::io::AsyncReadExt;
    // The session disconnects after the text, so the read ends at EOF.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_to_string(&mut text),
    )
    .await;
    assert!(
        text.contains("unknown flag: --bogus_flag"),
        "parse error must be written to the client, got: {text:?}"
    );
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    listener_task.abort();
}

#[tokio::test]
async fn test_exec_empty_payload_answers_usage() {
    // Round-16 pin: a truly EMPTY exec payload is answered instantly
    // with the usage text, then the connection closes — the documented
    // frp-rs divergence (see exec_request). Go v0.71.0 never parses an
    // empty payload: its addr+payload wait loop breaks only on
    // extraPayload != "" (server.go:253), so the session stalls the
    // full 3s window and dies with the server-side "get addr and extra
    // payload timeout" (server.go:251) — no client text at all.
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
    let client = auth_test_client(addr).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel.exec(true, "").await.unwrap();
    let mut reader = channel.make_reader();
    let mut text = String::new();
    use tokio::io::AsyncReadExt;
    // The session disconnects after the text, so the read ends at EOF.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_to_string(&mut text),
    )
    .await;
    assert!(
        text.contains("Usage:"),
        "the empty command must yield the usage text, got: {text:?}"
    );
    assert!(
        text.contains("ssh ... <proxy_type> [flags]"),
        "usage must show the gateway command shape, got: {text:?}"
    );
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    listener_task.abort();
}

#[tokio::test]
async fn test_exec_success_writes_banner_and_keeps_session_open() {
    // P6: a successful registration writes the Go createSuccessInfo
    // banner ("Ctrl+C to quit") to the client and KEEPS the session
    // open — the tunnel serves until the client leaves. (The old code
    // wrote nothing and returned immediately.)
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
    let client = auth_test_client(addr).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .exec(true, "tcp --proxy_name e2e-web --remote_port 0")
        .await
        .unwrap();
    let mut reader = channel.make_reader();
    let mut got = String::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    use tokio::io::AsyncReadExt;
    loop {
        if got.contains("RemoteAddress: :") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "banner not received within 5s, got so far: {got:?}"
        );
        let n = tokio::time::timeout(std::time::Duration::from_millis(500), reader.read(&mut buf))
            .await
            .expect("reading the exec channel must not stall")
            .unwrap();
        if n == 0 {
            panic!("exec channel closed before the banner arrived; got: {got:?}");
        }
        got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
    }
    assert!(
        got.contains("\nfrp (via SSH) (Ctrl+C to quit)\n"),
        "{got:?}"
    );
    assert!(got.contains("User: v0\n"), "{got:?}");
    assert!(got.contains("ProxyName: e2e-web\n"), "{got:?}");
    assert!(got.contains("Type: tcp\n"), "{got:?}");

    // The session stays open after the banner (no server disconnect).
    assert!(
        !client.is_closed(),
        "session must stay open after the banner"
    );
    // Dropping the Handle does not close the connection — russh keeps
    // the client task until an explicit disconnect (the integration-test
    // idiom). Without it the server session never ends and the
    // conn_semaphore permit below is never released.
    client
        .disconnect(russh::Disconnect::ByApplication, "test complete", "")
        .await
        .ok();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    listener_task.abort();
}

#[tokio::test]
async fn test_control_exit_terminates_session_and_releases_permit() {
    // Regression (M6): when the SSH virtual control handler exits — the
    // server's heartbeat-timeout cleanup kills it because the SSH
    // virtual client never sends Ping — the russh session must be torn
    // down deterministically. Before the fix the session stayed open,
    // holding the SSH fd + conn_semaphore permit and silently dropping
    // every later -R tcpip-forward work conn. Here the shutdown token
    // drives the control handler down the same exit path (break ->
    // cleanup) as a heartbeat timeout.
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
    let client_config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect(client_config, addr, TestSshClient)
        .await
        .unwrap();

    let auth = client
        .authenticate_password("v0", "test-token")
        .await
        .unwrap();
    assert!(auth.success());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.run_id_to_ctl_tx.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.run_id_to_ctl_tx.len(), 1);
    assert_eq!(
        state.conn_semaphore.as_ref().unwrap().available_permits(),
        0
    );

    // Kill the control handler the same way a heartbeat timeout does.
    state.shutdown_token.cancel();

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !client.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("SSH session must be terminated when the control handler exits");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(state.run_id_to_ctl_tx.is_empty());
    listener_task.abort();
}

#[tokio::test]
async fn test_real_authentication_just_before_deadline_wins_race() {
    let (addr, state, listener_task) =
        start_test_ssh_listener(std::time::Duration::from_millis(800)).await;
    let mut client = russh::client::connect(
        Arc::new(russh::client::Config::default()),
        addr,
        TestSshClient,
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    let auth = client
        .authenticate_password("v0", "test-token")
        .await
        .unwrap();

    assert!(auth.success());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.run_id_to_ctl_tx.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client
        .disconnect(russh::Disconnect::ByApplication, "test complete", "")
        .await
        .unwrap();
    listener_task.abort();
}

#[test]
fn test_parse_ssh_args_tcp() {
    let args = parse_ssh_args(r#"tcp --proxy_name "web" --remote_port 9090"#).unwrap();
    assert_eq!(args.proxy_type, "tcp");
    assert_eq!(args.proxy_name, "web");
    assert_eq!(args.remote_port, 9090);
}

#[test]
fn test_parse_ssh_args_http() {
    let args =
        parse_ssh_args(r#"http --proxy_name "blog" --custom_domain "a.example.com,b.example.com""#)
            .unwrap();
    assert_eq!(args.proxy_type, "http");
    assert_eq!(args.proxy_name, "blog");
    assert_eq!(args.custom_domains, vec!["a.example.com", "b.example.com"]);
}

#[test]
fn test_parse_ssh_args_repeated_list_flags_accumulate() {
    // F3: pflag stringSliceValue.Set APPENDS after the first occurrence
    // (string_slice.go changed flag) — a repeated list flag accumulates
    // in Go, it does not replace. Only the SINGULAR custom_domain is
    // registered in Go (pkg/config/flags.go:126); every separator mix of
    // that one registration (-d, --custom_domain, --custom-domain) is
    // the same flag via WordSepNormalizeFunc, so interleaved repeats
    // accumulate together. The plural --custom_domains is NOT registered
    // (normalizes to custom-domains ≠ custom-domain) and is pinned as an
    // unknown flag in test_parse_ssh_args_plural_spelling_rejected.
    let args = parse_ssh_args("http -d a.com -d b.com --custom_domain c.com").unwrap();
    assert_eq!(args.custom_domains, vec!["a.com", "b.com", "c.com"]);
    let args = parse_ssh_args("http --custom_domain x.com --custom-domain y.com -d z.com").unwrap();
    assert_eq!(args.custom_domains, vec!["x.com", "y.com", "z.com"]);
    let args = parse_ssh_args("http --locations /a --locations /b").unwrap();
    assert_eq!(args.locations, vec!["/a", "/b"]);
    // allow_users is the same pflag stringSlice type and already
    // accumulated.
    let args = parse_ssh_args("stcp --allow_users alice --allow_users bob").unwrap();
    assert_eq!(args.allow_users, vec!["alice", "bob"]);
}

#[test]
fn test_parse_ssh_args_plural_spelling_rejected() {
    // Round-16 audit: Go SSH mode registers the SINGULAR --custom_domain
    // only (pkg/config/flags.go:126). frp's WordSepNormalizeFunc folds
    // `_` → `-` on the TYPED name, so --custom_domains looks up
    // `custom-domains` against the registered `custom-domain` and misses
    // — Go answers `unknown flag: --custom_domains`, echoing the typed
    // (pre-normalization) token (pflag flag.go:978). frp-rs has no
    // plural table entry, so the same gate fires on EVERY proxy type
    // (there is no registration to gate per-type), with the same typed
    // echo for both separators.
    for (cmd, expected) in [
        // Domain types reject the plural too — Go never registered it.
        (
            "http --custom_domains a.com",
            "unknown flag: --custom_domains",
        ),
        (
            "https --custom_domains a.com",
            "unknown flag: --custom_domains",
        ),
        (
            "tcpmux --custom_domains a.com",
            "unknown flag: --custom_domains",
        ),
        (
            "tcp --custom_domains a.com",
            "unknown flag: --custom_domains",
        ),
        // The dash-folded plural is equally unknown (custom-domains ≠
        // custom-domain).
        (
            "http --custom-domains a.com",
            "unknown flag: --custom-domains",
        ),
        (
            "tcp --custom-domains a.com",
            "unknown flag: --custom-domains",
        ),
    ] {
        let err = parse_ssh_args(cmd).unwrap_err();
        assert_eq!(err, expected, "cmd {cmd:?}");
    }
    // The singular (any separator mix) still parses on domain types.
    let ok = parse_ssh_args("http --custom-domain a.com --custom_domain b.com").unwrap();
    assert_eq!(ok.custom_domains, vec!["a.com", "b.com"]);
}

#[test]
fn test_parse_ssh_args_unknown_type() {
    // FIX 4: Go-verbatim error (pkg/ssh/server.go:275-276), support
    // types in Go's order.
    let err = parse_ssh_args("smtp --proxy_name test").unwrap_err();
    assert_eq!(
        err,
        "invalid proxy type: smtp, support types: [tcp http https tcpmux stcp]"
    );
}

#[test]
fn test_parse_ssh_args_type_token_exact_match_no_case_folding() {
    // FIX 4: the type token matches Go's exact Contains after TrimSpace
    // — NO to_lowercase fold, so any case variant is rejected with the
    // verbatim Go text (old code folded "TCP" to "tcp" and accepted).
    for cmd in ["TCP", "Tcp", "Stcp --proxy_name x", "HTTP"] {
        let err = parse_ssh_args(cmd).unwrap_err();
        assert_eq!(
            err,
            format!(
                "invalid proxy type: {}, support types: [tcp http https tcpmux stcp]",
                cmd.split_whitespace().next().unwrap()
            ),
            "cmd {cmd:?}"
        );
    }
    // Quoted-token acceptance is a documented frp-rs EXTENSION, not
    // parity: shell_split strips the quote characters before the match,
    // so `"stcp "` trims to "stcp". Go splits the payload on literal
    // spaces with no quote processing (server.go:267 strings.Split), so
    // args[0] would be `"stcp` — quote characters included — and the
    // support-types check would REJECT it with the verbatim text above
    // (`invalid proxy type: "stcp, ...`). No command Go frps accepts is
    // misparsed; only commands Go rejects outright are accepted here.
    let args = parse_ssh_args("\"stcp \" --sk x").unwrap();
    assert_eq!(args.proxy_type, "stcp");
    assert_eq!(args.sk, "x");
    // The support-types list order is Go's
    // [tcp http https tcpmux stcp] — stcp AFTER tcpmux.
    assert_eq!(
        VALID_PROXY_TYPES,
        &["tcp", "http", "https", "tcpmux", "stcp"]
    );
}

#[test]
fn test_parse_ssh_args_missing_name_gets_default_ssh_tunnel_name() {
    // Go parity: an SSH-mode proxy without --proxy_name registers under
    // `sshtunnel-{type}-{8 lowercase hex}` (pkg/ssh server.go), not the
    // empty string.
    let args = parse_ssh_args("tcp --remote_port 9090").unwrap();
    assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
    let suffix = &args.proxy_name["sshtunnel-tcp-".len()..];
    assert_eq!(suffix.len(), 8);
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "random suffix must be 8 lowercase hex chars, got: {suffix}"
    );
}

#[test]
fn test_parse_ssh_args_default_name_per_type_and_explicit_override() {
    for (cmd, prefix) in [
        ("http --custom_domain a.example.com", "sshtunnel-http-"),
        ("stcp", "sshtunnel-stcp-"),
        ("tcpmux", "sshtunnel-tcpmux-"),
    ] {
        let args = parse_ssh_args(cmd).unwrap();
        assert!(
            args.proxy_name.starts_with(prefix),
            "cmd {cmd:?} → {}",
            args.proxy_name
        );
    }
    // Explicit names still win (including the --proxy_name=value form).
    let args = parse_ssh_args("tcp --proxy_name=web").unwrap();
    assert_eq!(args.proxy_name, "web");
    // And an explicitly empty name falls back to the default.
    let args = parse_ssh_args("tcp --proxy_name=").unwrap();
    assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
}

#[test]
fn test_parse_ssh_args_stcp() {
    let args = parse_ssh_args(r#"stcp --proxy_name "secret" --sk "mysecret""#).unwrap();
    assert_eq!(args.proxy_type, "stcp");
    assert_eq!(args.sk, "mysecret");
}

#[test]
fn test_parse_ssh_args_tcpmux() {
    let args = parse_ssh_args(r#"tcpmux --proxy_name "mux" --multiplexer "httpconnect""#).unwrap();
    assert_eq!(args.proxy_type, "tcpmux");
    assert_eq!(args.multiplexer, "httpconnect");
}

#[test]
fn test_parse_ssh_args_go_spellings_accepted() {
    // FIX 2a: Go's SSH-mode spellings (pkg/config/flags.go) parse and
    // map onto the same fields as the frp-rs spellings.
    // --sd (Go) == --subdomain (frp-rs extension), domain types.
    let a = parse_ssh_args("http --sd foo --proxy_name h").unwrap();
    assert_eq!(a.subdomain, "foo");
    let b = parse_ssh_args("https --sd foo --custom_domain a.com").unwrap();
    assert_eq!(b.subdomain, "foo");
    assert_eq!(b.custom_domains, vec!["a.com"]);
    let c = parse_ssh_args("tcpmux --sd foo --mux httpconnect").unwrap();
    assert_eq!(c.subdomain, "foo");
    assert_eq!(c.multiplexer, "httpconnect");
    // --mux (Go) == --multiplexer (frp-rs extension).
    let d = parse_ssh_args("tcpmux --multiplexer httpconnect").unwrap();
    let e = parse_ssh_args("tcpmux --mux httpconnect").unwrap();
    assert_eq!(d.multiplexer, e.multiplexer);
    // http-only Go flags.
    let f = parse_ssh_args(
        "http --locations /a,/b --http_user u --http_pwd p --host_header_rewrite hh",
    )
    .unwrap();
    assert_eq!(f.locations, vec!["/a", "/b"]);
    assert_eq!(f.http_user, "u");
    assert_eq!(f.http_pwd, "p");
    assert_eq!(f.host_header_rewrite, "hh");
    // tcpmux takes http_user/http_pwd but NOT host_header_rewrite.
    let g = parse_ssh_args("tcpmux --http_user u --http_pwd p").unwrap();
    assert_eq!(g.http_user, "u");
    assert_eq!(g.http_pwd, "p");
    // stcp Go flags: --sk + --allow_users.
    let h = parse_ssh_args("stcp --sk mysecret --allow_users alice,bob").unwrap();
    assert_eq!(h.sk, "mysecret");
    assert_eq!(h.allow_users, vec!["alice", "bob"]);
    // Dash-form of the Go flag names works (pflag normalization).
    let i = parse_ssh_args("http --custom-domain a.com").unwrap();
    assert_eq!(i.custom_domains, vec!["a.com"]);
    let j = parse_ssh_args("stcp --allow-users alice").unwrap();
    assert_eq!(j.allow_users, vec!["alice"]);
    // metadatas/annotations on ANY type (Go base flags).
    let k = parse_ssh_args("tcp --metadatas k1=v1 --annotations a1=b1").unwrap();
    assert_eq!(k.metadatas, vec![("k1".into(), "v1".into())]);
    assert_eq!(k.annotations, vec![("a1".into(), "b1".into())]);
}

#[test]
fn test_parse_ssh_args_user_token_client_id_flags() {
    // FIX 2a: Go persistent client-common flags (pkg/ssh/server.go
    // RegisterClientCommonConfigFlags) parse on every proxy type.
    let a = parse_ssh_args(
        "tcp --proxy_name p1 --user alice --token sekrit --client-id abc-123 --remote_port 9090",
    )
    .unwrap();
    assert_eq!(a.user, "alice");
    assert_eq!(a.token, "sekrit");
    assert_eq!(a.client_id, "abc-123");
    // Shorthands -u / -t (all cluster forms) parse to the same args.
    for cmd in [
        "tcp --proxy_name p1 -u alice -t sekrit --client_id abc-123 -r 9090",
        "tcp --proxy_name p1 -u=alice -t=sekrit --client_id=abc-123 -r=9090",
        "tcp --proxy_name p1 -ualice -tsekrit --client_id abc-123 -r9090",
    ] {
        let args = parse_ssh_args(cmd).unwrap_or_else(|e| panic!("cmd {cmd:?}: {e}"));
        assert_eq!(args, a, "cmd {cmd:?}");
    }
    // --client_id (underscore) and --client-id (Go's registered dash
    // name) are the same flag via separator folding.
    let e = parse_ssh_args("stcp --client_id c1 --sk s").unwrap();
    assert_eq!(e.client_id, "c1");
    let f = parse_ssh_args("stcp --client-id c1 --sk s").unwrap();
    assert_eq!(f.client_id, "c1");
    // Values flow into the parsed args; their consumption at the
    // virtual-client login level is documented in exec_request (the
    // control Login predates the exec payload).
}

#[test]
fn test_parse_ssh_args_per_type_gates_reject_go_flags_on_other_types() {
    // FIX 2c: Go registers type-specific flags only for their types; on
    // any other type the flag errors exactly like an unknown one
    // (pflag unknown-flag arm — Go never registered it for this type).
    let cases = [
        // (cmd, expected error)
        ("tcp --sk s", "unknown flag: --sk"),   // stcp-only
        ("tcp --sd foo", "unknown flag: --sd"), // domain types only
        ("tcp --custom_domain a.com", "unknown flag: --custom_domain"),
        ("tcp --mux httpconnect", "unknown flag: --mux"),
        ("tcp --allow_users alice", "unknown flag: --allow_users"),
        ("tcp --metadatas k=v", ""), // metadatas: ALL types — no error
        ("tcp --user u", ""),        // persistent: ALL types
        ("http --remote_port 9090", "unknown flag: --remote_port"), // tcp-only
        ("https --sk s", "unknown flag: --sk"),
        ("https --http_user u", "unknown flag: --http_user"), // http/tcpmux
        ("https --http_pwd p", "unknown flag: --http_pwd"),
        ("https --locations /a", "unknown flag: --locations"), // http-only
        (
            "https --host_header_rewrite h",
            "unknown flag: --host_header_rewrite",
        ),
        (
            "tcpmux --host_header_rewrite h",
            "unknown flag: --host_header_rewrite",
        ),
        ("tcpmux --locations /a", "unknown flag: --locations"),
        ("tcpmux --sk s", "unknown flag: --sk"),
        ("stcp --sd foo", "unknown flag: --sd"),
        (
            "stcp --custom_domain a.com",
            "unknown flag: --custom_domain",
        ),
        ("stcp --mux m", "unknown flag: --mux"),
        ("stcp --remote_port 1", "unknown flag: --remote_port"),
        ("stcp --http_pwd p", "unknown flag: --http_pwd"),
        // The gate is keyed on the TYPED spelling (unknown-flag echo).
        // The plural --custom_domains has NO registration anywhere —
        // Go registers only the singular custom_domain (flags.go:126) —
        // so it is unknown on domain types AND non-domain types alike
        // (pinned in test_parse_ssh_args_plural_spelling_rejected).
        (
            "tcp --custom_domains a.com",
            "unknown flag: --custom_domains",
        ),
    ];
    for (cmd, expected) in cases {
        if expected.is_empty() {
            parse_ssh_args(cmd).unwrap_or_else(|e| panic!("cmd {cmd:?} must parse: {e}"));
        } else {
            let err = parse_ssh_args(cmd).unwrap_err();
            assert_eq!(err, expected, "cmd {cmd:?}");
        }
    }
    // Shorthand gates report pflag's unknown-shorthand text.
    let err = parse_ssh_args("http -r 9090").unwrap_err();
    assert_eq!(err, "unknown shorthand flag: 'r' in -r");
    let err = parse_ssh_args("tcp -d a.com").unwrap_err();
    assert_eq!(err, "unknown shorthand flag: 'd' in -d");
    let err = parse_ssh_args("stcp -r 1").unwrap_err();
    assert_eq!(err, "unknown shorthand flag: 'r' in -r");
    let err = parse_ssh_args("http -r").unwrap_err();
    assert_eq!(err, "unknown shorthand flag: 'r' in -r");
    // ...while the registered shorthands still work on their types.
    parse_ssh_args("tcp -r 9090 -n web").unwrap();
    parse_ssh_args("http -d a.com").unwrap();
    parse_ssh_args("tcpmux -d a.com").unwrap();
    parse_ssh_args("stcp -n s1").unwrap();
}

#[test]
fn test_parse_ssh_args_bandwidth_flags_rejected_like_go() {
    // FIX 2: Go SSH mode does not register bandwidth_* (flags.go gates
    // them behind !options.sshMode) — frp-rs rejects them identically
    // instead of accepting a setting Go would drop.
    let err = parse_ssh_args("tcp --bandwidth_limit 1MB").unwrap_err();
    assert_eq!(err, "unknown flag: --bandwidth_limit");
    let err = parse_ssh_args("tcp --bandwidth_limit_mode client").unwrap_err();
    assert_eq!(err, "unknown flag: --bandwidth_limit_mode");
}

#[test]
fn test_parse_ssh_args_metadatas_annotations_kv_semantics() {
    // FIX 2a: pflag StringToString semantics — comma-separated k=v
    // pairs; repeated occurrences ACCUMULATE; later same-key pairs win;
    // a value with exactly one '=' keeps its commas (Go's single-pair
    // arm); a pair without '=' is the pflag error text.
    let args = parse_ssh_args("tcp --metadatas k1=v1,k2=v2").unwrap();
    assert_eq!(
        args.metadatas,
        vec![("k1".into(), "v1".into()), ("k2".into(), "v2".into())]
    );
    // Accumulation + last-wins on repeat.
    let args = parse_ssh_args("tcp --metadatas k1=v1 --metadatas k2=v2,k1=v1b").unwrap();
    assert_eq!(
        args.metadatas,
        vec![("k1".into(), "v1b".into()), ("k2".into(), "v2".into())]
    );
    // Exactly one '=' → the whole value is one pair (commas are value).
    let args = parse_ssh_args("tcp --metadatas k=v,w").unwrap();
    assert_eq!(args.metadatas, vec![("k".into(), "v,w".into())]);
    // Multi-'=' values: first '=' splits the pair.
    let args = parse_ssh_args("tcp --metadatas k=v=w").unwrap();
    assert_eq!(args.metadatas, vec![("k".into(), "v=w".into())]);
    // Missing '=' → pflag error text, carried through the flag wrapper.
    let err = parse_ssh_args("tcp --metadatas novalue").unwrap_err();
    assert_eq!(
        err,
        "invalid argument \"novalue\" for \"--metadatas\" flag: novalue must be formatted as key=value"
    );
    // A pair without '=' inside a multi-pair value errors on that pair
    // (a single-'=' value like "a=b,broken" is ONE legal pair whose
    // value is "b,broken" — Go's n==1 arm, pinned above).
    let err = parse_ssh_args("tcp --annotations a=b,c=d,broken").unwrap_err();
    assert_eq!(
        err,
        "invalid argument \"a=b,c=d,broken\" for \"--annotations\" flag: broken must be formatted as key=value"
    );
    // Go accepts the single-'=' comma value as one pair; so does frp-rs.
    let ok = parse_ssh_args("tcp --annotations a=b,broken").unwrap();
    assert_eq!(ok.annotations, vec![("a".into(), "b,broken".into())]);
    // annotations accumulate independently of metadatas.
    let args = parse_ssh_args("tcp --annotations a=1 --metadatas m=2 --annotations a=3").unwrap();
    assert_eq!(args.annotations, vec![("a".into(), "3".into())]);
    assert_eq!(args.metadatas, vec![("m".into(), "2".into())]);
}

#[test]
fn test_build_v1_frame_carries_metas_annotations_allow_users() {
    // FIX 2a wire check: the accumulated k=v pairs and the allow_users
    // list reach the NewProxy frame (msg wire keys metas/annotations/
    // allow_users, Go msg.go parity); bandwidth fields are gone.
    let args = parse_ssh_args(
        "stcp --proxy_name sec --sk x --allow_users alice,bob \
             --metadatas k1=v1 --annotations a1=b1,a2=b2",
    )
    .unwrap();
    let frame = build_v1_frame_from_args(&args, 0).unwrap();
    let payload = &frame[9..];
    let v: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(v["metas"]["k1"], "v1");
    assert_eq!(v["annotations"]["a1"], "b1");
    assert_eq!(v["annotations"]["a2"], "b2");
    assert_eq!(v["allow_users"], serde_json::json!(["alice", "bob"]));
    assert!(v.get("bandwidth_limit").is_none());
    assert!(v.get("bandwidth_limit_mode").is_none());
    // None when no pairs were parsed — the wire fields stay absent.
    let args = parse_ssh_args("tcp --proxy_name plain --remote_port 1").unwrap();
    let frame = build_v1_frame_from_args(&args, 1).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&frame[9..]).unwrap();
    assert!(v.get("metas").is_none());
    assert!(v.get("annotations").is_none());
    assert!(v.get("allow_users").is_none());
}

#[test]
fn test_parse_ssh_args_empty() {
    // Round-16 note: this is NOT Go parity for the empty input — a truly
    // empty exec payload never reaches Go's parse. Go's addr+payload
    // wait loop breaks only when extraPayload != "" (server.go:253), so
    // an empty payload stalls the full 3s window and the session dies
    // server-side with "get addr and extra payload timeout"
    // (server.go:251) — no client text. frp-rs's exec handler answers
    // the empty (post-trim) payload with the usage text (documented
    // divergence, pinned e2e by test_exec_empty_payload_answers_usage)
    // before parse_ssh_args is ever called.
    //
    // parse_ssh_args("") itself is therefore reachable only by direct
    // call: shell_split yields no parts, the type defaults to "", and
    // the support-types check answers the blank-type text — the SAME
    // text a whitespace-only payload gets through Go's genuine parse
    // path (payload != "" → strings.Split → args[0] == "" →
    // server.go:267-277), pinned for whitespace-only in
    // test_parse_ssh_args_empty_or_blank_command_is_error. Kept here as
    // the parse-level invariant: a truly empty direct call must not
    // panic and must land on the identical arm.
    let err = parse_ssh_args("").unwrap_err();
    assert_eq!(
        err,
        "invalid proxy type: , support types: [tcp http https tcpmux stcp]"
    );
}

#[test]
fn test_shell_split_simple() {
    let tokens = shell_split("tcp --proxy_name web --remote_port 9090");
    assert_eq!(
        tokens,
        vec!["tcp", "--proxy_name", "web", "--remote_port", "9090"]
    );
}

#[test]
fn test_shell_split_quoted() {
    let tokens = shell_split(r#"tcp --proxy_name "my web""#);
    assert_eq!(tokens, vec!["tcp", "--proxy_name", "my web"]);
}

#[test]
fn test_shell_split_multiple_spaces() {
    let tokens = shell_split("tcp   --proxy_name   web   --remote_port   9090");
    assert_eq!(
        tokens,
        vec!["tcp", "--proxy_name", "web", "--remote_port", "9090"]
    );
}

#[test]
fn test_shell_split_empty_quoted() {
    // Empty quoted strings are dropped (current.is_empty() guard).
    // This is acceptable — proxy names are never empty in practice.
    let tokens = shell_split(r#"tcp --proxy_name """#);
    assert_eq!(tokens, vec!["tcp", "--proxy_name"]);
}

#[test]
fn test_exec_request_log_summary_redacts_secrets() {
    const SK: &str = "S3KR-sk-value";
    const GROUP_KEY: &str = "S3KR-group-key-value";
    const HTTP_PWD: &str = "S3KR-http-pwd-value";
    let args = ParsedProxyArgs {
        proxy_type: "tcp".into(),
        proxy_name: "web".into(),
        remote_port: 9090,
        local_ip: "127.0.0.1".into(),
        local_port: 8080,
        custom_domains: Vec::new(),
        subdomain: String::new(),
        sk: SK.into(),
        multiplexer: String::new(),
        use_encryption: true,
        use_compression: true,
        group: String::new(),
        group_key: GROUP_KEY.into(),
        http_user: String::new(),
        http_pwd: HTTP_PWD.into(),
        host_header_rewrite: String::new(),
        locations: Vec::new(),
        metadatas: Vec::new(),
        annotations: Vec::new(),
        allow_users: Vec::new(),
        user: String::new(),
        token: String::new(),
        client_id: String::new(),
    };

    let summary = exec_request_log_summary(&args);
    assert!(summary.contains("type=tcp"));
    assert!(summary.contains("name=web"));
    assert!(summary.contains("remote_port=9090"));
    assert!(summary.contains("encryption=true"));
    assert!(summary.contains("compression=true"));
    for secret in [SK, GROUP_KEY, HTTP_PWD] {
        assert!(
            !summary.contains(secret),
            "secret leaked into exec_request log summary: {summary}"
        );
    }
}

// ── Malformed exec input hardening (Go frp v0.70.1: SSH gateway panic fix) ──
// Go frp v0.70.1 fixed a panic when handling malformed exec requests
// (pkg/ssh gateway indexing into an empty fields() slice). frp-rs parses
// the SSH remote command in parse_ssh_args; every case below must be
// tolerated without panicking (no unwrap, no index out of bounds) and
// either rejected with an error or defaulted as documented.

#[test]
fn test_parse_ssh_args_truncated_flags_no_panic() {
    // F2: a value-requiring flag at the very END of the command errors
    // with pflag's needs-argument text echoing the typed token
    // (pflag/flag.go:996) — Go rejects a truncated command the same way
    // (--sk is stcp-only, so the arm is exercised on the type Go
    // registers it for).
    let err = parse_ssh_args("stcp --proxy_name web --sk").unwrap_err();
    assert_eq!(err, "flag needs an argument: --sk");

    // A run of value-requiring flags with no values: each flag before
    // the last is followed by a FLAG-LIKE token (tolerated, deliberate
    // divergence — Go would consume it as the value); only the
    // end-of-command flag errors.
    let err = parse_ssh_args("stcp --sk --allow_users").unwrap_err();
    assert_eq!(err, "flag needs an argument: --allow_users");
    let err = parse_ssh_args("http --http_pwd --locations --sd").unwrap_err();
    assert_eq!(err, "flag needs an argument: --sd");

    // Flag immediately after the type, nothing else.
    let err = parse_ssh_args("tcp --proxy_name").unwrap_err();
    assert_eq!(err, "flag needs an argument: --proxy_name");

    // The flag-like-next-token tolerance itself still parses when the
    // command is complete: --sk leaves its default instead of eating
    // "--allow_users" as its value (Go would register sk="--allow_users"
    // and never apply the alice list).
    let args = parse_ssh_args("stcp --sk --allow_users alice").unwrap();
    assert!(args.sk.is_empty());
    assert_eq!(args.allow_users, vec!["alice"]);
}

#[test]
fn test_parse_ssh_args_invalid_ports_rejected() {
    // P10: Go parity — a value that fails to parse is an error written
    // to the SSH client, not a silent fallback to 0/auto-assign (which
    // could hand out an unintended random port).
    for bad in [
        "abc",
        "-1",
        "65536",
        "999999999",
        "3.14",
        "0x10",
        "12a34",
        "18446744073709551616", // overflows u64, let alone u16
    ] {
        let cmd = format!("tcp --proxy_name web --remote_port {bad}");
        let err = parse_ssh_args(&cmd).unwrap_err();
        // Go quotes the dash-folded registered spelling: pflag's
        // WordSepNormalizeFunc (`_` → `-`, config/flags.go:30-36, set
        // in pkg/ssh/server.go) rewrites flag.Name at AddFlag time, so
        // the Set error shows "-r, --remote-port" (empirically probed
        // against pflag v1.0.5).
        let expected = format!("invalid argument \"{bad}\" for \"-r, --remote-port\" flag");
        assert!(
            err.contains(&expected),
            "cmd {cmd:?} must be rejected with {expected:?}, got: {err}"
        );
    }
    // An explicitly empty value is rejected too (Go runs strconv on it).
    let err = parse_ssh_args("tcp --remote_port=").unwrap_err();
    assert!(
        err.contains("invalid argument \"\" for \"-r, --remote-port\" flag"),
        "got: {err}"
    );
    // A truncated flag at the end of the command errors with pflag's
    // needs-argument text (F2, flag.go:996), pinned by
    // test_parse_ssh_args_truncated_flags_no_panic.
    let err = parse_ssh_args("tcp --proxy_name web --remote_port").unwrap_err();
    assert_eq!(err, "flag needs an argument: --remote_port");
}

#[test]
fn test_parse_ssh_args_invalid_local_port_rejected() {
    let err = parse_ssh_args("tcp --proxy_name web --local_port not-a-port").unwrap_err();
    assert!(
        err.contains("invalid argument \"not-a-port\" for \"--local_port\" flag"),
        "got: {err}"
    );
}

#[test]
fn test_parse_ssh_args_empty_or_blank_command_is_error() {
    // F1: WHITESPACE-ONLY commands produce Go's blank type-token error
    // (server.go:267-277). These payloads are non-empty, so Go's
    // gateway wait loop hands them to strings.Split; args[0] is an
    // empty field (or trims to ""), and the support-types check answers
    // the verbatim blank-type text. shell_split yields no parts, so the
    // type defaults to "" exactly like Go's split result.
    for cmd in ["   ", "\t", " \n "] {
        let err = parse_ssh_args(cmd).unwrap_err();
        assert_eq!(
            err, "invalid proxy type: , support types: [tcp http https tcpmux stcp]",
            "cmd {cmd:?} should be rejected, got: {err}"
        );
    }
    // A truly EMPTY payload is deliberately NOT in the loop: it is not a
    // Go-parity input. Go never parses it (wait loop requires
    // extraPayload != "", server.go:253 → 3s timeout, no client text),
    // and frp-rs's exec handler intercepts it with the usage text
    // (documented divergence). The parse-level blank-type text for a
    // direct-call "" is pinned separately in test_parse_ssh_args_empty.
}

#[test]
fn test_parse_ssh_args_unterminated_quote_no_panic() {
    // Unterminated double quote: shell_split keeps the remainder as one
    // token and the parse loop skips the unknown positional.
    let args = parse_ssh_args(r#"tcp --proxy_name "web --remote_port 9090"#).unwrap();
    assert_eq!(args.proxy_type, "tcp");
    assert_eq!(args.remote_port, 0);
}

#[test]
fn test_parse_ssh_args_excessive_whitespace_no_panic() {
    let args =
        parse_ssh_args("   tcp      --proxy_name    web     --remote_port       9090   ").unwrap();
    assert_eq!(args.proxy_type, "tcp");
    assert_eq!(args.proxy_name, "web");
    assert_eq!(args.remote_port, 9090);
}

#[test]
fn test_parse_ssh_args_very_long_argument_no_panic() {
    let long = "x".repeat(1_000_000);
    let cmd = format!("tcp --proxy_name {long} --remote_port 9090");
    let args = parse_ssh_args(&cmd).unwrap();
    assert_eq!(args.proxy_name.len(), 1_000_000);
    assert_eq!(args.remote_port, 9090);
}

#[test]
fn test_parse_ssh_args_unknown_flag_rejected() {
    // P10: unknown flags are rejected with pflag's text instead of being
    // silently skipped — a typo'd flag used to register a proxy missing
    // that setting, with no error anywhere.
    let err = parse_ssh_args("tcp --bogus_flag value --proxy_name web").unwrap_err();
    assert_eq!(err, "unknown flag: --bogus_flag");
    // Dash-form unknowns keep their raw spelling in the message.
    let err = parse_ssh_args("tcp --bogus-flag value").unwrap_err();
    assert_eq!(err, "unknown flag: --bogus-flag");
}

#[test]
fn test_parse_ssh_args_unknown_shorthand_rejected() {
    let err = parse_ssh_args("tcp -x").unwrap_err();
    assert_eq!(err, "unknown shorthand flag: 'x' in -x");
    // pflag reports the full remaining cluster, unknown char included
    // (parseSingleShortArg: `in -%s` gets the unconsumed shorthands).
    let err = parse_ssh_args("tcp -xn").unwrap_err();
    assert_eq!(err, "unknown shorthand flag: 'x' in -xn");
}

#[test]
fn test_parse_ssh_args_flag_equals_value_forms() {
    let args = parse_ssh_args("tcp --proxy_name=web --remote_port=9090").unwrap();
    assert_eq!(args.proxy_name, "web");
    assert_eq!(args.remote_port, 9090);
    // --custom_domain is domain-type-scoped (singular registration,
    // flags.go:126), so the `=` form is pinned on http.
    let args = parse_ssh_args("http --custom_domain=a.com,b.com").unwrap();
    assert_eq!(args.custom_domains, vec!["a.com", "b.com"]);
    let args =
        parse_ssh_args("http --proxy_name=blog --use_encryption=true --subdomain=sub").unwrap();
    assert!(args.use_encryption);
    assert_eq!(args.subdomain, "sub");
    // The Go --custom_domain registration works in the `=` form too.
    let args = parse_ssh_args("http --custom_domain=a.example.com").unwrap();
    assert_eq!(args.custom_domains, vec!["a.example.com"]);
}

#[test]
fn test_parse_ssh_args_dash_underscore_equivalence() {
    // pflag WordSepNormalizeFunc intent: --proxy_name and --proxy-name
    // are the same flag.
    let a = parse_ssh_args("tcp --proxy_name web --remote_port 9090").unwrap();
    let b = parse_ssh_args("tcp --proxy-name web --remote-port 9090").unwrap();
    assert_eq!(a, b);
    // The dash+`=` form is the same flag too (a includes --remote_port,
    // so the comparison parse must too).
    let c = parse_ssh_args("tcp --proxy-name=web --remote-port=9090").unwrap();
    assert_eq!(c, a);
}

#[test]
fn test_parse_ssh_args_shorthand_forms() {
    // pflag shorthand value forms: `-n web`, `-n=web`, `-nweb`.
    let a = parse_ssh_args("tcp -n web -r 9090").unwrap();
    assert_eq!(a.proxy_name, "web");
    assert_eq!(a.remote_port, 9090);
    let b = parse_ssh_args("tcp -n=web -r=9090").unwrap();
    assert_eq!(b, a);
    let c = parse_ssh_args("tcp -nweb -r9090").unwrap();
    assert_eq!(c, a);
    // -d maps to custom_domains (Go shorthand).
    let d = parse_ssh_args("http -d a.com,b.com").unwrap();
    assert_eq!(d.custom_domains, vec!["a.com", "b.com"]);
    // Round-16: the BARE `-x=` shape is a documented-class divergence.
    // pflag treats `=` as an inline separator only when the cluster is
    // longer than flag+`=` (parseSingleShortArg flag.go:1041-1044), so
    // a Go `-n=` never splits: the literal "=" falls through to the
    // -farg arm and becomes the VALUE (proxy_name "="). frp-rs splits
    // and yields "" — which then falls back to the generated default
    // name, matching what the long form `--proxy_name=` produces in
    // BOTH implementations (see parse_short_flags). Every longer
    // cluster (-n=x) agrees in both.
    let e = parse_ssh_args("tcp -n=").unwrap();
    assert!(
        e.proxy_name.starts_with("sshtunnel-tcp-"),
        "-n= yields the empty name in frp-rs → default, got: {}",
        e.proxy_name
    );
    // F2: a bare value-taking shorthand at the end of the command
    // errors with pflag's short needs-argument text (flag.go:1058 —
    // `%q` quotes the shorthand, `-%s` echoes the typed cluster).
    let err = parse_ssh_args("tcp -r").unwrap_err();
    assert_eq!(err, "flag needs an argument: 'r' in -r");
}

#[test]
fn test_parse_ssh_args_help_returns_usage() {
    // Go frp prints the command usage to the SSH client on ErrHelp
    // (--help / -h) and closes — the frp-rs equivalent returns the usage
    // text as the parse error.
    for cmd in [
        "tcp --help",
        "tcp -h",
        "http --proxy_name web --help",
        "stcp -h",
    ] {
        let err = parse_ssh_args(cmd).unwrap_err();
        assert!(
            err.contains("Usage:"),
            "cmd {cmd:?} must yield usage text, got: {err}"
        );
        assert!(err.contains("--proxy_name"), "cmd {cmd:?}");
    }
}

#[test]
fn test_parse_ssh_args_bad_flag_syntax_rejected() {
    // pflag "bad flag syntax": a flag name starting with '-' or '=' is a
    // syntax error (`---x` names "-x"); a bare `--` is the terminator,
    // not an error (asserted in test_parse_ssh_args_double_dash...).
    for tok in ["---x", "--=x"] {
        let err = parse_ssh_args(&format!("tcp {tok}")).unwrap_err();
        assert_eq!(err, format!("bad flag syntax: {tok}"), "token {tok:?}");
    }
}

#[test]
fn test_parse_ssh_args_double_dash_terminates_flags() {
    // pflag `--`: everything after it is positional and ignored. A bare
    // trailing `--` is legal (Go pflag terminates, no "bad flag syntax").
    let args = parse_ssh_args("tcp --proxy_name web -- --remote_port 9090").unwrap();
    assert_eq!(args.proxy_name, "web");
    assert_eq!(args.remote_port, 0);
    let args = parse_ssh_args("tcp --").unwrap();
    assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
}

#[test]
fn test_parse_ssh_args_boolean_flags_bare_true_and_parse_bool_set() {
    // FIX 3: a bare bool flag (no `=`) applies true (Go pflag
    // NoOptDefVal="true") and NEVER consumes the next token.
    let args = parse_ssh_args("tcp --use_encryption --remote_port 9090").unwrap();
    assert!(args.use_encryption);
    assert_eq!(
        args.remote_port, 9090,
        "the next token is not the bool's value"
    );
    let args = parse_ssh_args("http --proxy_name blog --use_compression --sd foo").unwrap();
    assert!(args.use_compression);
    assert_eq!(args.subdomain, "foo");
    // A following non-flag token is an ignored positional, exactly like
    // Go (a bool with NoOptDefVal never reads the next arg): the bool
    // stays TRUE even for "--use_encryption false".
    let args = parse_ssh_args("tcp --use_encryption false").unwrap();
    assert!(args.use_encryption);
    // Explicit = forms: full strconv.ParseBool value set
    // (1,t,T,TRUE,true,True → true; 0,f,F,FALSE,false,False → false).
    for v in ["1", "t", "T", "TRUE", "true", "True"] {
        let args = parse_ssh_args(&format!("tcp --use_encryption={v}")).unwrap();
        assert!(args.use_encryption, "value {v:?} must parse as true");
    }
    for v in ["0", "f", "F", "FALSE", "false", "False"] {
        let args = parse_ssh_args(&format!("tcp --use_encryption={v}")).unwrap();
        assert!(!args.use_encryption, "value {v:?} must parse as false");
    }
    // Garbage → the parser error path with Go's verbatim strconv text
    // (both the `=` form and the pflag empty-value form).
    for v in ["v", "yes", "2", "Truee"] {
        let err = parse_ssh_args(&format!("tcp --use_encryption={v}")).unwrap_err();
        let expected = format!(
            "invalid argument \"{v}\" for \"--use_encryption\" flag: \
                 strconv.ParseBool: parsing \"{v}\": invalid syntax"
        );
        assert_eq!(err, expected, "value {v:?}");
    }
    // A quoted value containing whitespace parses as one value (and
    // fails ParseBool like Go).
    let err = parse_ssh_args(r#"tcp --use_encryption=" true""#).unwrap_err();
    assert_eq!(
        err,
        "invalid argument \" true\" for \"--use_encryption\" flag: \
             strconv.ParseBool: parsing \" true\": invalid syntax"
    );
    let err = parse_ssh_args("tcp --use_encryption=").unwrap_err();
    assert_eq!(
        err,
        "invalid argument \"\" for \"--use_encryption\" flag: \
             strconv.ParseBool: parsing \"\": invalid syntax"
    );
    // use_compression errors identically with its own flag name.
    let err = parse_ssh_args("tcp --use_compression=maybe").unwrap_err();
    assert_eq!(
        err,
        "invalid argument \"maybe\" for \"--use_compression\" flag: \
             strconv.ParseBool: parsing \"maybe\": invalid syntax"
    );
}

#[test]
fn test_parse_ssh_args_truncated_boolean_and_list_flags() {
    // A bare bool applies true; value-requiring flags followed by a
    // FLAG-LIKE token stay at their defaults (deliberate frp-rs
    // divergence — Go would consume the next flag token as the value;
    // see parse_long_flag for the chained-shape bounds of that
    // divergence), and the end-of-command flag errors with pflag's
    // needs-argument text (F2) instead of silently defaulting.
    let err = parse_ssh_args(
        "http --proxy_name blog --use_encryption --custom_domain --locations --group",
    )
    .unwrap_err();
    assert_eq!(err, "flag needs an argument: --group");
    // The same chain minus the end-of-command flag parses: the bool
    // applies, the flag-like-truncated list stays empty, and the final
    // flag gets its real value.
    let args =
        parse_ssh_args("http --proxy_name blog --use_encryption --custom_domain --locations /a")
            .unwrap();
    assert!(args.use_encryption);
    assert!(args.custom_domains.is_empty());
    assert_eq!(args.locations, vec!["/a"]);
}

#[test]
fn build_v1_frame_rejects_oversized_proxy_config() {
    // Audit finding 6e: a giant custom_domains entry (attacker's own
    // `ssh -R` command line, bounded only by the ~32 KiB SSH channel
    // window) used to build a >10 KiB V1 frame by hand, bypassing
    // write_v1_frame's length check and killing the SSH user's own
    // virtual control on read_v1_frame's "invalid V1 msg length".
    let long_domain = format!("{}.example.com", "x".repeat(20_000));
    let args = parse_ssh_args(&format!(
        "http --proxy_name h --custom_domain {long_domain}"
    ))
    .expect("parse oversized domain");
    let err = build_v1_frame_from_args(&args, 0)
        .expect_err("oversized proxy config must be rejected before framing");
    assert!(
        err.to_string().contains("too large"),
        "unexpected error: {err}"
    );

    // Control: a normal frame still builds and carries the V1 header
    // (type byte + declared payload length must match the frame size).
    let small = parse_ssh_args("tcp --proxy_name web --remote_port 9090").expect("parse small");
    let frame = build_v1_frame_from_args(&small, 9090).expect("small frame builds");
    assert_eq!(frame[0], frp_core::msg::TYPE_NEW_PROXY);
    let declared = i64::from_be_bytes(frame[1..9].try_into().expect("9-byte header")) as usize;
    assert!(declared <= frp_core::protocol::V1_MAX_MSG_LENGTH as usize);
    assert_eq!(frame.len(), 9 + declared);
}
