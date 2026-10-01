//! Regression: `frpc` must execute an `auth.tokenSource` `exec` command
//! **once per client service**, exactly like Go frp — not a second time when it
<<<<<<< HEAD
//! builds the login (`TODO.md:8415`: "Rust frpc runs the `auth.tokenSource`
=======
//! builds the login (`TODO.md:8388`: "Rust frpc runs the `auth.tokenSource`
>>>>>>> 198ddfc8 (docs(records): apply the #450 review findings and re-derive the shifted TODO.md cites)
//! `exec` command twice per successful login where Go runs it once").
//!
//! Measured on the base commit `9b2acefb` against a live frps with this same
//! config/command: the exec log held two lines while the client logged in
//! once. Go frp v0.71.0 held one. With the fix, two logins and three reloads
//! leave exactly one line.
//!
//! Go's shape, which this pins: `client/service.go:168`
//! `authRuntime, err := auth.BuildClientAuth(&options.Common.Auth)` resolves
//! the `tokenSource` once inside `NewService`; `client/service.go:201` stores
//! it as `s.auth`, and the reconnect loop hands that same runtime to every
//! login (`client/service.go:316 auth: svr.auth`). `pkg/auth/token.go`'s
//! `SetLogin`/`SetPing`/`SetNewWorkConn` only call
//! `util.GetAuthKey(auth.token, ts)` on the cached string — the source is
//! never resolved a second time.
//!
//! The count is observed the way the original report observed it: the command
//! has a side effect (append one line to `$FRP_TOKENS_SOURCE_LOG`) and the
//! test counts the lines. That measures executions, not resolutions of a
//! cached value, which is why it is decisive against "it only *looks* like
//! two reads" readings.
//!
//! Two connections are driven against the mock: the first logs in once and the
//! control stream then dies, the second is the client's automatic reconnect.
//! Go resolves once per client service (inside `NewService`), so the second
//! login must not re-execute the command either — the same `auth_cfg` snapshot
//! is reused. (One `Service` per config file: `--config-dir` builds one service
//! per file and so executes once per file, matching Go's `runMultipleClients`,
//! `cmd/frpc/sub/root.go:87`.)
//!
//! The reload arm is driven through the real reload path
//! (`Service::request_reload()` → `try_reload` → `reload_from_sources`) from a
//! config **file**, and it adds **zero** executions:
//!
//! * an accepted reload (same `[auth]`, a proxy added or moved) never rebuilds
//!   `Service::auth_cfg`, so `auth.tokenSource` is not resolved again;
//! * a reload that changes `[auth]` is refused before anything is applied by
//!   `reload::auth_reload_refusal` (`frp-client/src/service.rs:4511-4514`,
//!   `frp-client/src/reload.rs:30`/`:86`), so it cannot re-read either.
//!
//! Order matters: **the refused reload is last and its file is never rewritten
//! after the request**. A `request_reload()` carries a reply oneshot that the
//! signal path drops, so the test cannot wait for an ack; if the refused config
//! were later overwritten, a stalled reload loop could read the *later* file
//! when it processed the request and be legitimately accepted, and the refusal
//! arm would pass vacuously. Leaving the refused file in place removes that
//! write-before-process race entirely. The refused file also adds a proxy
//! (`reload-probe-denied`), so a broken refusal is observable on the wire, not
//! only in the exec count; the 1s quiet read only bounds how long the test
//! watches for that frame.
#![cfg(unix)]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use frp_client::service::Service as ClientService;
use frp_core::config::load_client_config;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;
use frp_core::unsafe_features::{UnsafeFeatures, TOKEN_SOURCE_EXEC};
use tokio::net::TcpListener;

use common::allocate_port;

const TOKEN: &str = "token-source-single-exec";
/// Proxy added/moved by the accepted reloads.
const PROBE: &str = "reload-probe";
/// Proxy that exists only in the reload file whose `[auth]` changed. It must
/// never reach the wire — not in the refused reload, and not afterwards.
const PROBE_DENIED: &str = "reload-probe-denied";

/// The exec command's side effect is the measurement: one appended line per
/// execution. Its stdout is the resolved token.
const EXEC_SCRIPT: &str =
    "printf 'exec\\n' >> \"$FRP_TOKENS_SOURCE_LOG\"\nprintf '%s' 'token-source-single-exec'\n";

/// How long the control stream must stay free of proxy frames after a refused
/// reload. The reload path reads the file and diffs it in-process, so a
/// processed refusal is quiet long before this elapses (the in-tree
/// `reload_malformed_config.rs` uses 400 ms for the same purpose). The refused
/// config is the last file written, so this window bounds only how long the
/// test watches for a broken refusal — it does not have to cover a race with a
/// later write.
const REFUSAL_QUIET_WINDOW: Duration = Duration::from_secs(1);

/// The `[auth]` body that configures the exec token source (the shape the
/// client starts with, and the one restored for the last reload).
fn exec_auth_body(script: &str, log: &str) -> String {
    format!(
        "method = \"token\"\n\n\
         [auth.tokenSource]\ntype = \"exec\"\n\n\
         [auth.tokenSource.exec]\ncommand = \"sh\"\nargs = [\"{script}\"]\n\
         env = [{{ name = \"FRP_TOKENS_SOURCE_LOG\", value = \"{log}\" }}]\n"
    )
}

/// A *different* source: any change here is what `auth_reload_refusal` must
/// refuse.
fn file_auth_body(path: &str) -> String {
    format!(
        "method = \"token\"\n\n\
         [auth.tokenSource]\ntype = \"file\"\n\n\
         [auth.tokenSource.file]\npath = \"{path}\"\n"
    )
}

/// Write the frpc config the client loads (and later re-loads). `auth_body` is
/// the raw body of `[auth]`; `probes` are `(name, remotePort)` pairs. Written
/// in the Go-dialect spelling the loader normalizes (`[transport] tcpMux`,
/// `heartbeatInterval`). No token key appears anywhere: the token comes from
/// `auth.tokenSource`, and the loader refuses `auth.token` + `auth.tokenSource`
/// together (`frp-core/src/config/loader.rs:1048-1050`).
fn write_config(path: &Path, server_port: u16, auth_body: &str, probes: &[(&str, u16)]) {
    let mut body = format!(
        "serverAddr = \"127.0.0.1\"\n\
         serverPort = {server_port}\n\
         loginFailExit = false\n\
         tls_enable = false\n\
         \n\
         [transport]\n\
         tcpMux = false\n\
         heartbeatInterval = -1\n\
         \n\
         [auth]\n\
         {auth_body}\n"
    );
    for (name, remote_port) in probes {
        body.push_str(&format!(
            "\n[[proxies]]\nname = \"{name}\"\ntype = \"tcp\"\nlocalIp = \"127.0.0.1\"\n\
             localPort = {}\nremotePort = {remote_port}\n",
            allocate_port()
        ));
    }
    std::fs::write(path, body).expect("write frpc config");
}

/// One completed login handshake: the privilege key the client sent plus the
/// post-`LoginResp` encrypted control stream (kept open by the caller when it
/// wants to read later frames).
struct LoginSession {
    privilege_key: String,
    timestamp: i64,
    stream: IoStream,
}

/// Serve one login on `listener`, complete the handshake the way the real
/// server does (LoginResp in the clear, everything after it AES-128-CFB keyed
/// by the resolved token — derived at `frp-client/src/service.rs:1797` and
/// applied at `:1802-1803` via `stream.into_encrypted(enc_key)`).
async fn serve_one_login(listener: &TcpListener, token: &str) -> LoginSession {
    let (conn, _peer) = listener.accept().await.expect("client did not connect");
    let mut stream = IoStream::Tcp(conn);

    let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
        .await
        .expect("timeout waiting for client Login")
        .expect("read Login");
    let (privilege_key, timestamp) = match login {
        FrpMessage::Login(m) => (
            m.privilege_key
                .clone()
                .expect("Login must carry a privilege_key when auth.tokenSource resolves"),
            m.timestamp.expect("Login must carry a timestamp"),
        ),
        other => panic!("expected Login, got {other:?}"),
    };

    stream
        .write_v1_frame(&FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("token-source-single-exec-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        }))
        .await
        .expect("write LoginResp");

    // The client wraps the control stream after LoginResp; wrap our side with
    // the same key so later frames decode. Dropping this closes the
    // connection, which is what drives the reconnect.
    let enc_key = frp_core::encryption::derive_key(token);
    let stream = stream
        .into_encrypted(enc_key)
        .expect("plain test stream is encryptable");

    LoginSession {
        privilege_key,
        timestamp,
        stream,
    }
}

/// Read control frames until the `NewProxy` for `want` arrives, panicking on
/// any frame naming `forbidden` (a proxy only present in a refused reload).
/// `CloseProxy` frames for other names are the ordinary remove/add pair of a
/// changed proxy and are ignored.
async fn read_until_new_proxy(stream: &mut IoStream, want: &str, forbidden: &str) -> msg::NewProxy {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(15), stream.read_v1_frame())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for NewProxy({want})"))
            .expect("read control frame while waiting for NewProxy");
        match frame {
            FrpMessage::NewProxy(p) => {
                assert_ne!(
                    p.proxy_name, forbidden,
                    "a reload refused by auth_reload_refusal was applied: {p:?}"
                );
                if p.proxy_name == want {
                    return *p;
                }
            }
            FrpMessage::CloseProxy(c) => {
                assert_ne!(
                    c.proxy_name, forbidden,
                    "a reload refused by auth_reload_refusal was applied: {c:?}"
                );
            }
            // Heartbeats are disabled in this config; anything else is noise
            // for this assertion.
            _ => {}
        }
    }
}

/// Assert the control stream stays free of proxy frames for `window`: the
/// reload that changed `[auth]` must have been refused before it was applied.
/// A proxy frame here means the refusal did not happen (or did not happen
/// before the next reload's file was written), which is exactly the failure
/// mode this arm has to catch — the racy alternative to "refused" is
/// "applied".
async fn assert_no_proxy_frames(stream: &mut IoStream, window: Duration, why: &str) {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, stream.read_v1_frame()).await {
            Err(_elapsed) => return,
            Ok(Err(e)) => {
                panic!("control stream failed while waiting for a refused reload: {e} ({why})")
            }
            Ok(Ok(FrpMessage::NewProxy(p))) => {
                panic!(
                    "reload that changed auth.tokenSource was applied: NewProxy({}) ({why})",
                    p.proxy_name
                )
            }
            Ok(Ok(FrpMessage::CloseProxy(c))) => {
                panic!(
                    "reload that changed auth.tokenSource was applied: CloseProxy({}) ({why})",
                    c.proxy_name
                )
            }
            Ok(Ok(_)) => {}
        }
    }
}

fn read_exec_log(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The login key the client must have sent is `md5(token + timestamp)`, the
/// same `util.GetAuthKey` Go uses (`pkg/util/util.go`). Asserting it proves the
/// one execution that *did* happen was the one the login used — a count of 1
/// alone could also mean the source never resolved and login silently used an
/// empty token.
fn expected_login_key(timestamp: i64) -> String {
    frp_core::auth::generate_token(TOKEN, timestamp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_token_source_runs_once_across_logins_and_reloads() {
    common::init_tracing();
    let dir = tempfile::tempdir().expect("tempdir");
    let script_path = dir.path().join("token-exec.sh");
    std::fs::write(&script_path, EXEC_SCRIPT).expect("write exec script");
    let log_path = dir.path().join("exec-count.txt");
    let denied_token_path = dir.path().join("denied-token");
    std::fs::write(&denied_token_path, "denied\n").expect("write denied-token file");
    let script_str = script_path.to_str().unwrap().to_owned();
    let log_str = log_path.to_str().unwrap().to_owned();
    let denied_str = denied_token_path.to_str().unwrap().to_owned();

    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port))
        .await
        .expect("bind mock server");

    // The config is a real file: the reload arm re-loads this same path.
    let cfg_path = dir.path().join("frpc.toml");
    write_config(
        &cfg_path,
        server_port,
        &exec_auth_body(&script_str, &log_str),
        &[],
    );
    let cfg_str = cfg_path.to_str().unwrap().to_owned();
    let cfg = load_client_config(&cfg_str, false).expect("load frpc config");
    assert!(
        cfg.auth
            .as_ref()
            .and_then(|a| a.token_source.as_ref())
            .is_some(),
        "the config file must be what configures auth.tokenSource"
    );

    let client = Arc::new(
        ClientService::with_unsafe_features(
            cfg,
            Some(cfg_str),
            UnsafeFeatures::new(&[TOKEN_SOURCE_EXEC]),
        )
        .await
        .expect("Service construction must resolve the exec token source once"),
    );

    // Exactly one execution has happened by now — construction — and the
    // snapshot it produced is the token the login must use.
    let after_construction = read_exec_log(&log_str);
    assert_eq!(
        after_construction.len(),
        1,
        "Service construction must execute the source exactly once, saw {after_construction:?}"
    );

    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // Login #1, then drop the control stream so the client reconnects.
    let login1 = serve_one_login(&listener, TOKEN).await;
    assert_eq!(
        login1.privilege_key,
        expected_login_key(login1.timestamp),
        "login #1 must be keyed with the construction-time token snapshot"
    );
    drop(login1.stream);

    // Login #2 is the client's automatic reconnect (~ms of fast backoff, see
    // frp-client/src/backoff.rs). Go reuses one auth runtime per process, so
    // this must not execute the source again.
    let login2 = serve_one_login(&listener, TOKEN).await;
    assert_eq!(
        login2.privilege_key,
        expected_login_key(login2.timestamp),
        "the reconnecting login must reuse the same startup snapshot"
    );
    let mut control = login2.stream;

    let after_two_logins = read_exec_log(&log_str);
    assert_eq!(
        after_two_logins.len(),
        1,
        "the exec token source must run once per client service (Go frp \
         client/service.go:168 + :316 resolve it once and cache it), but two \
         logins produced {} executions: {after_two_logins:?}. A second line \
         here is the double read this regression pins: the client stored the \
         ValueSource in AuthConfig.token_source and resolve_token() \
         re-executed it when building the login.",
        after_two_logins.len()
    );

    // ---- reload arm ----------------------------------------------------
    // R1: accepted — same [auth], one proxy added. The NewProxy frame is a
    // hard sync: the reload was applied.
    let probe_port = allocate_port();
    write_config(
        &cfg_path,
        server_port,
        &exec_auth_body(&script_str, &log_str),
        &[(PROBE, probe_port)],
    );
    client.request_reload();
    let added = read_until_new_proxy(&mut control, PROBE, PROBE_DENIED).await;
    assert_eq!(
        added.remote_port,
        Some(probe_port as i32),
        "the accepted reload must register {PROBE} at {probe_port}"
    );
    let after_accepted_reload = read_exec_log(&log_str);
    assert_eq!(
        after_accepted_reload.len(),
        1,
        "an accepted reload must not re-execute auth.tokenSource, saw {after_accepted_reload:?}"
    );

    // R2: accepted — same [auth], PROBE moved to a new port. Proves the
    // accepted path handles a changed proxy (CloseProxy + NewProxy) as well as
    // an added one, and still adds no execution.
    let probe_port_moved = allocate_port();
    write_config(
        &cfg_path,
        server_port,
        &exec_auth_body(&script_str, &log_str),
        &[(PROBE, probe_port_moved)],
    );
    client.request_reload();
    let moved = read_until_new_proxy(&mut control, PROBE, PROBE_DENIED).await;
    assert_eq!(
        moved.remote_port,
        Some(probe_port_moved as i32),
        "the second accepted reload must move {PROBE} to {probe_port_moved}"
    );
    let after_moved_reload = read_exec_log(&log_str);
    assert_eq!(
        after_moved_reload.len(),
        1,
        "a reload that changes a proxy must not re-execute auth.tokenSource, saw {after_moved_reload:?}"
    );

    // R3: REFUSED, deliberately last — the file swaps auth.tokenSource
    // (exec -> file) *and* adds a proxy, so a broken refusal is observable on
    // the wire, not only in the exec count. No later reload rewrites this
    // file, so the loop reads exactly this content when it processes the
    // request: the refutation of "it was accepted" cannot be confused with a
    // later file's legitimate acceptance.
    let denied_port = allocate_port();
    write_config(
        &cfg_path,
        server_port,
        &file_auth_body(&denied_str),
        &[(PROBE, probe_port_moved), (PROBE_DENIED, denied_port)],
    );
    client.request_reload();
    assert_no_proxy_frames(
        &mut control,
        REFUSAL_QUIET_WINDOW,
        "a reload that changes auth.tokenSource must be refused before it is applied",
    )
    .await;

    let after_reloads = read_exec_log(&log_str);
    assert_eq!(
        after_reloads.len(),
        1,
        "the reload path must add zero auth.tokenSource executions (accepted \
         reloads never rebuild Service::auth_cfg, refused ones never apply), \
         saw {after_reloads:?}"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");

    let calls = read_exec_log(&log_str);
    assert_eq!(
        calls.len(),
        1,
        "auth.tokenSource must be executed once per client service across \
         logins and reloads (Go frp client/service.go:168 + :316), but ran {} \
         times: {calls:?}",
        calls.len()
    );

    // Guard the guard: an empty/failed source would also produce one line, so
    // require the line to be the literal the command emits.
    assert_eq!(calls[0], "exec", "unexpected exec-log content: {calls:?}");
}
