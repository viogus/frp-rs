//! The **client's SIGUSR1 reload** still delivers the
//! `[web_server.tls] enable` diagnostic.
//!
//! **Why this file exists.** The fix moved the record out of the loader and into
//! the binaries, because on the `-c` startup path the loader runs before
//! `init_logging` and a `tracing::warn` there reached no subscriber. The reload
//! is a *different* in-process load — it runs long after `init_logging`, so a
//! silent loader means the record is simply **lost** on that path. Measured on
//! the base binary with real binaries (`frpc -c`, live session, SIGUSR1): the
//! reload window added **1** record; on the reviewed tree it added **0**
//! (`/tmp/enable-warn-probe/out2-{before,after}.txt`, probe
//! `/tmp/enable-warn-probe/run-probe2.sh`, rows `frpc-c-reload` /
//! `frpc-c-reload-common`). `enable` has no field, so the reload summary cannot
//! report it either — the record was the only signal the reload gave about it.
//! The reload site (`Service::reload_from_sources`) now calls the
//! presence-returning loader and emits the record itself, once per reload.
//!
//! **Why in-process rather than a spawn test.** The client only processes a
//! reload request inside a live session, and this crate's test harness already
//! runs a **real** `frp_server::service::Service` in-process
//! (`common::start_frps`) — so the whole path is exercised without a second
//! binary, in the lane that builds one anyway. The `frpc` binary's own record is
//! pinned by `frpc/tests/warn_delivery.rs`; the config-file spelling that needs
//! `[common]` flattening is pinned there and in
//! `frp-core/tests/web_server_tls_enable_warning.rs`. This file's shape is
//! `[common.web_server.tls] enable` — the spelling the first round silently lost
//! — driven through the real reload.
//!
//! **One test per process, and a global subscriber.** The capture must be
//! **global**, not thread-scoped: the reload runs on a tokio worker thread, so a
//! `set_default` guard on the test thread would never see it (the flake the
//! `frp-core` sibling documents). This target therefore holds exactly one test and
//! installs its subscriber with `try_init()`, whose failure is an assertion
//! rather than a silent `.ok()`.
//!
//! **What it does not cover.** The wiring from a real `SIGUSR1` to
//! `request_reload()` (that is `frpc/src/main.rs`; the probe exercises it end to
//! end with the real binary and a real `kill -USR1`), the server's reload
//! (`frps/tests/warn_delivery.rs::a_sigusr1_reload_delivers_the_warning_again`),
//! and the exact log line: this file asserts the clause this crate's
//! `web_server_tls_enable_reader()` answer produced, while the full text of all
//! three clauses is pinned by `frp-core/tests/web_server_tls_enable_warning.rs`.
//! It is the only target that pins the **no-TLS** clause in the crate that emits
//! it (`frp-client --no-default-features --features admin`).

mod common;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use frp_client::service::Service as ClientService;
use frp_core::config::load_client_config;

use common::{allocate_port, start_echo_server, start_frps, wait_for_port};

/// The key, as the message names it.
const KEY: &str = "web_server.tls.enable";
/// The marker unique to the **dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`).
const DASHBOARD_CLAUSE: &str = "plaintext HTTP";
/// The marker unique to the **no-dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`). The texts share their
/// whole first half, so `KEY` is in all of them and cannot tell them apart.
const NO_DASHBOARD_CLAUSE: &str = "no dashboard support";
/// The marker unique to the **no-TLS-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_TLS`) — the `admin`-without-`tls`
/// shape, which compiles an admin server but no acceptor for it. This is the
/// clause the `--no-default-features --features admin` lane exists to pin; the
/// three markers are pairwise disjoint.
const NO_TLS_CLAUSE: &str = "no TLS support";
const TOKEN: &str = "reload-warning-token";
/// How long the reload may take to emit the record.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn captured(sink: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(sink.lock().unwrap().clone()).unwrap()
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The clause the reloaded record must carry — decided by **this crate's**
/// build, not by a literal argument. `Service::reload_from_sources`
/// (`frp-client/src/service.rs:4458`) passes
/// `frp_client::web_server_tls_enable_reader()`, which answers from this crate's
/// own `admin` and `tls` features; a site that hardcodes any of the three
/// answers still compiles and still emits one `KEY` record, so only a
/// `cfg!`-keyed assertion can see what this build answered. CI exercises all
/// three answers, one per lane: `-p frp-client --features admin` (admin + tls →
/// the dashboard clause), `-p frp-client --no-default-features --all-targets`
/// (neither → the no-dashboard clause) and `-p frp-client --no-default-features
/// --features admin` (admin without tls → the no-TLS clause).
fn assert_clause_matches_this_build(tag: &str, logged: &str) {
    // The same question `WebServerTlsEnableReader::from_features` asks, in the
    // same order: `admin` decides whether this build compiles a server at all,
    // and `tls` whether that server can accept HTTPS.
    let (expected, absent) = match (cfg!(feature = "admin"), cfg!(feature = "tls")) {
        (true, true) => (DASHBOARD_CLAUSE, [NO_DASHBOARD_CLAUSE, NO_TLS_CLAUSE]),
        (true, false) => (NO_TLS_CLAUSE, [DASHBOARD_CLAUSE, NO_DASHBOARD_CLAUSE]),
        (false, _) => (NO_DASHBOARD_CLAUSE, [DASHBOARD_CLAUSE, NO_TLS_CLAUSE]),
    };
    assert!(
        logged.contains(expected),
        "{tag}: the record must carry this build's clause ({expected:?})\n--- captured ---\n{logged}"
    );
    for other in absent {
        assert!(
            !logged.contains(other),
            "{tag}: the record must not carry another build's clause ({other:?})\n--- captured ---\n{logged}"
        );
    }
}

/// A valid client config with one tcp proxy, whose dashboard TLS section is
/// written under `[common]` — the spelling `normalize_client_config` flattens
/// onto the top level before `normalize_web_server_section` removes it.
fn write_config(path: &std::path::Path, server_port: u16, echo_port: u16, remote_port: u16) {
    std::fs::write(
        path,
        format!(
            r#"serverAddr = "127.0.0.1"
serverPort = {server_port}
loginFailExit = false
token = "{TOKEN}"

[transport]
tcpMux = false

[common.web_server.tls]
enable = true

[[proxies]]
name = "main"
type = "tcp"
localIp = "127.0.0.1"
localPort = {echo_port}
remotePort = {remote_port}
"#
        ),
    )
    .expect("write config");
}

#[tokio::test]
async fn a_client_reload_delivers_the_web_server_tls_enable_warning() {
    let sink = Arc::new(Mutex::new(Vec::new()));
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_writer({
            let sink = sink.clone();
            move || CapturedLogs(sink.clone())
        })
        .try_init()
        .expect("this target holds one test, so the capturing subscriber must install");

    // A real in-process frps and a real echo backend, so the client reaches a
    // live session — the reload request is only processed there.
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let remote_port = allocate_port();
    let _echo = start_echo_server(echo_port);
    let _server = start_frps(server_port, TOKEN).await;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("in-process frps ready");

    // Drop-guarded scratch dir (`tempfile`, this crate's dev-dependency — the
    // same guard six sibling targets in `frp-client/tests` use). A raw
    // `std::env::temp_dir().join(...)` path leaked the directory on **every
    // failure**, which is exactly when the test is re-run most; measured by the
    // reviewing round as `pass = +0 / fail = +1 leaked $TMPDIR/frp-reload-warning-<pid>`.
    let dir = tempfile::tempdir().expect("create temp dir");
    let cfg_path = dir.path().join("frpc.toml");
    write_config(&cfg_path, server_port, echo_port, remote_port);

    // The startup load is the *loader* path (deliberately silent); the reload is
    // the in-process path that has a sink. So the capture starts empty here.
    let cfg = load_client_config(cfg_path.to_str().unwrap(), false).expect("load initial config");
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path.to_string_lossy().into()))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };
    let remote_addr: std::net::SocketAddr = format!("127.0.0.1:{remote_port}").parse().unwrap();
    wait_for_port(remote_addr, Duration::from_secs(15))
        .await
        .expect("initial proxy port ready");
    assert_eq!(
        occurrences(&captured(&sink), KEY),
        0,
        "the startup load must not emit it (that is the binaries' job, and this \
         test's client is constructed without one): {}",
        captured(&sink)
    );

    // Drive the reload the SIGUSR1 handler drives.
    client.request_reload();
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    while Instant::now() < deadline {
        if captured(&sink).contains(KEY) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let logged = captured(&sink);
    assert_eq!(
        occurrences(&logged, KEY),
        1,
        "the reload must emit exactly one record for the `[common]` spelling\n--- captured ---\n{logged}"
    );
    assert!(
        logged.contains("has no effect"),
        "the record is the `[web_server.tls] enable` diagnostic, not an unrelated \
         mention of the key\n--- captured ---\n{logged}"
    );
    assert_clause_matches_this_build("client reload", &logged);

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    // No explicit cleanup: `dir` removes itself on drop, including while an
    // assertion above unwinds.
}
