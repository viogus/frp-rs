//! The NewWorkConn token path end-to-end: a real server `ReqWorkConn` on a
//! session whose OIDC token source is an `exec` command must make the client
//! dial a work connection whose `NewWorkConn` carries the RAW token from that
//! source — not a cached md5 key, and not nothing at all.
//!
//! `TODO.md:10358` residue: the OIDC NewWorkConn path was pinned only at the
//! `spawn_work_conn` seam (`frp-client/src/work_conn.rs:1500`,
//! `oidc_token_source_fills_new_work_conn_privilege_key` builds its own
//! `WorkConnConfig`), so `handle_req_work_conn`
//! (`frp-client/src/service.rs:931`) — the only production call site that
//! constructs that config — was off-path: dropping
//! `oidc_client: self.oidc_client.clone()`,
//! `client_auth_scopes: ctx.client_scopes.clone()`, or
//! `server_auth_scopes: ctx.server_scopes.clone()` there left every lane green.
//!
//! These tests drive the real path end to end: a mock frps completes an OIDC
//! Login, sends `ReqWorkConn` over the encrypted control stream, accepts the
//! work connection the client dials, and reads its `NewWorkConn`. The two
//! tests exercise the two halves of `scope_requires_auth`'s OR
//! (`frp-client/src/work_conn.rs:261`) — the scope can arrive from the client
//! config (`additional_auth_scopes`) or from the server's LoginResp
//! (`server_additional_auth_scopes`, read at `frp-client/src/service/session.rs:624`
//! and threaded through `SessionCtx.server_scopes`) — so emptying EITHER
//! threading in `handle_req_work_conn` reds exactly one of them.
//!
//! The `exec` command appends one line per invocation, so the invocation count
//! is also asserted (login + work conn = 2): the privilege key must come from
//! the source, not from a value cached at login.

#![cfg(all(unix, feature = "oidc"))]

mod common;

use std::time::Duration;

use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::{AuthClientConfig, ClientConfig, ExecSource, ValueSource};
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;
use frp_core::unsafe_features::{UnsafeFeatures, TOKEN_SOURCE_EXEC};

use common::{allocate_port, init_tracing};

/// The raw token every `exec` invocation prints — the value the OIDC setters
/// put in `privilege_key` (Go's `pkg/auth/oidc.go`).
const TOKEN: &str = "req-work-conn-oidc-token";
/// The run_id the mock returns in LoginResp; the work conn must echo it.
const RUN_ID: &str = "mock-server-run";
/// The scope either side can advertise to require NewWorkConn auth.
const NEW_WORK_CONNS: &str = "NewWorkConns";

/// One appended line per invocation (the invocation counter) plus the token on
/// stdout.
const EXEC_SCRIPT: &str = "\
printf 'exec\\n' >> \"$1\"\n\
printf '%s' \"$2\"\n";

/// Number of times the OIDC exec token source has run so far.
fn exec_invocations(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// `sh script log token` — the OIDC `auth.oidc.tokenSource` exec source.
fn oidc_config(server_port: u16, script: &str, log: &str, client_scopes: &[&str]) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        // No static token: the OIDC exec source is the only credential.
        token: String::new(),
        auth: Some(AuthClientConfig {
            method: "oidc".into(),
            oidc_client_id: "req-work-conn-oidc-client".into(),
            // With a token source, OidcClient::new skips endpoint
            // discovery/JWKS entirely (frp-core/src/auth.rs:1333-1336), so no
            // identity provider is needed.
            oidc_token_source: Some(ValueSource {
                source_type: "exec".into(),
                file: None,
                exec: Some(ExecSource {
                    command: "sh".into(),
                    args: vec![script.into(), log.into(), TOKEN.into()],
                    env: vec![],
                }),
            }),
            additional_auth_scopes: client_scopes.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        }),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Heartbeats off: pings are orthogonal here and would add exec runs.
        heartbeat_interval: 0,
        proxies: vec![],
        ..Default::default()
    }
}

/// Assert the `NewWorkConn` the client dialed carries the OIDC token and no
/// timestamp, and that the exec source produced it.
fn assert_oidc_new_work_conn(nwc: &msg::NewWorkConn, invocations: usize) {
    assert_eq!(
        nwc.run_id.as_deref(),
        Some(RUN_ID),
        "NewWorkConn must carry the run_id from LoginResp"
    );
    assert_eq!(
        nwc.privilege_key.as_deref(),
        Some(TOKEN),
        "NewWorkConn must carry the RAW token from the exec source (Go OIDC \
         setNewWorkConn sets only PrivilegeKey, frp-core/src/auth.rs:1530)"
    );
    assert!(
        nwc.timestamp.is_none(),
        "Go frp's OIDC NewWorkConn setter leaves Timestamp unset; a Some(ts) \
         means the token branch ran (oidc_client was not threaded)"
    );
    assert_eq!(
        invocations, 2,
        "the exec source must run once for Login and once for NewWorkConn"
    );
}

/// Drive exactly one real `ReqWorkConn` against a mock frps and return the
/// `NewWorkConn` the client sent plus the exec-source invocation count.
async fn drive_one_req_work_conn(
    client_scopes: &[&str],
    server_scopes: Option<Vec<String>>,
) -> (msg::NewWorkConn, usize) {
    init_tracing();
    let dir = tempfile::tempdir().expect("tempdir");
    let script_path = dir.path().join("oidc-token-exec.sh");
    let log_path = dir.path().join("oidc-exec-invocations.txt");
    std::fs::write(&script_path, EXEC_SCRIPT).expect("write exec script");
    std::fs::write(&log_path, "").expect("create exec invocation log");
    let script_str = script_path.to_str().unwrap().to_owned();
    let log_str = log_path.to_str().unwrap().to_owned();

    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some(RUN_ID.into()),
        error: None,
        server_additional_auth_scopes: server_scopes,
    });
    // The OIDC config carries no `auth.token`, so the control-stream key is
    // derive_key("") (session.rs:631).
    let enc_key = frp_core::encryption::derive_key("");

    let mock = tokio::spawn(async move {
        // --- Control connection: OIDC Login ---
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("Login timeout")
            .expect("read Login");
        match login {
            FrpMessage::Login(l) => {
                assert_eq!(
                    l.privilege_key.as_deref(),
                    Some(TOKEN),
                    "the OIDC Login must carry the exec-source token"
                );
                // The control layer stamps the Login timestamp BEFORE the
                // OIDC setter runs (`frp-client/src/control.rs:350`), and
                // `set_login` preserves it — so a timestamp here is expected;
                // only the token proves the OIDC source ran.
                assert!(
                    l.timestamp.is_some(),
                    "the control layer must stamp the Login timestamp"
                );
            }
            other => panic!("expected Login, got {other:?}"),
        }
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");

        // --- Message loop: ask for one work conn ---
        enc.write_v1_frame(&FrpMessage::ReqWorkConn(msg::ReqWorkConn {}))
            .await
            .expect("write ReqWorkConn");

        // --- The client dials a work conn against the SAME listener ---
        let (wc, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("work conn timeout: handle_req_work_conn did not dial after ReqWorkConn")
            .expect("accept work conn");
        let mut wc = IoStream::Tcp(wc);
        let nwc = tokio::time::timeout(Duration::from_secs(10), wc.read_v1_frame())
            .await
            .expect("NewWorkConn timeout")
            .expect("read NewWorkConn");
        let nwc = match nwc {
            FrpMessage::NewWorkConn(n) => n,
            other => panic!("expected NewWorkConn, got {other:?}"),
        };

        // Answer so the client's work-conn task ends cleanly instead of
        // waiting out its StartWorkConn timeout (the count is already fixed at
        // this point: set_new_work_conn ran while the frame was written).
        wc.write_v1_frame(&FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
            proxy_name: "p1".into(),
            src_addr: None,
            src_port: None,
            dst_addr: None,
            dst_port: None,
            error: None,
            use_encryption: None,
            use_compression: None,
            nat_hole_sid: None,
            nat_hole_visitor_addr: None,
            sk: None,
        })))
        .await
        .expect("write StartWorkConn");

        (nwc, exec_invocations(&log_path))
    });

    let cfg = oidc_config(server_port, &script_str, &log_str, client_scopes);
    let client =
        ClientService::with_unsafe_features(cfg, None, UnsafeFeatures::new(&[TOKEN_SOURCE_EXEC]))
            .await
            .expect(
                "client construction must accept an exec auth.oidc.tokenSource under \
         the TokenSourceExec allowlist",
            );
    let runner = tokio::spawn(async move {
        let _ = client.run().await;
    });

    let (nwc, invocations) = tokio::time::timeout(Duration::from_secs(30), mock)
        .await
        .expect("mock never observed the work conn")
        .expect("mock task panicked");

    runner.abort();
    (nwc, invocations)
}

/// The client config advertises `NewWorkConns`, the server advertises nothing:
/// `handle_req_work_conn` must thread `ctx.client_scopes` into the work conn.
#[tokio::test]
async fn req_work_conn_uses_client_declared_scope() {
    let (nwc, invocations) = drive_one_req_work_conn(&[NEW_WORK_CONNS], None).await;
    assert_oidc_new_work_conn(&nwc, invocations);
}

/// The server advertises `NewWorkConns` in LoginResp, the client config
/// advertises nothing: `handle_req_work_conn` must thread `ctx.server_scopes`.
#[tokio::test]
async fn req_work_conn_uses_server_advertised_scope() {
    let (nwc, invocations) =
        drive_one_req_work_conn(&[], Some(vec![NEW_WORK_CONNS.to_string()])).await;
    assert_oidc_new_work_conn(&nwc, invocations);
}
