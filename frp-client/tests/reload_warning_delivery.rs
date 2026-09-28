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
//! and the message text (pinned by
//! `frp-core/tests/web_server_tls_enable_warning.rs`).

mod common;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use frp_client::service::Service as ClientService;
use frp_core::config::load_client_config;

use common::{allocate_port, start_echo_server, start_frps, wait_for_port};

/// The key, as the message names it.
const KEY: &str = "web_server.tls.enable";
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

    let dir = std::env::temp_dir().join(format!("frp-reload-warning-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
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

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    let _ = std::fs::remove_dir_all(&dir);
}
