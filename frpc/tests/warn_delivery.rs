//! The client half of `frps/tests/warn_delivery.rs`: the
//! `[web_server.tls] enable` diagnostic a **`frpc` user** actually sees, on both
//! config paths and for both the top-level and the `[common]` spelling, with
//! stdout and stderr captured separately.
//!
//! **The defect these pin.** `normalize_web_server_section` (shared by the
//! server and client normalizers — `ClientConfig.web_server` is the same
//! `WebServerConfig`) accepts the key, removes it because nothing reads it, and
//! used to warn from *inside the loader*. On the `-c` path the loader runs
//! **before** `init_logging` (the single-config branch of `frpc/src/main.rs`:
//! `load_client_config_with_presence`, then `init_logging` — deliberate Go-parity
//! ordering, because Go installs its logger only after a successful load,
//! `cmd/frpc/sub/root.go:191`), so the record reached no subscriber:
//!
//! | shape | base | reviewed | now |
//! |---|---|---|---|
//! | `frpc -c <cfg>` with `[web_server.tls] enable` | **0** | 1 | 1 |
//! | `frpc --config-dir <dir>` | 1 | 1 | 1 |
//! | `[common.web_server.tls] enable`, `-c` | 0 | **0** | 1 |
//! | `[common.web_server.tls] enable`, `--config-dir` | 1 | **0** | 1 |
//! | `[web_server]` + `[webServer.tls] enable` (mixed) | 0 | 0 | **1** |
//! | `frpc -c` with no `enable` key | 0 | 0 | 0 |
//! | `frpc verify -c <cfg>` (logger installed before the load) | 1 | 1 | 1 |
//! | **SIGUSR1 reload** delta (`frpc -c`, live session) | +1 | **0** | +1 |
//!
//! Every row is stdout; stderr carried 0. Counts are
//! `grep -o web_server\.tls\.enable | wc -l` over separately captured streams:
//! `/tmp/enable-warn-probe/out/{before,after}.txt` (first round),
//! `/tmp/enable-warn-probe/out2-{before,after,after2}.txt` (this round, via
//! `run-probe2.sh`), `/tmp/enable-warn-probe/out/before-extra.txt` for `verify`.
//! The Go-parity ordering itself was **not** moved — only the emission.
//!
//! The `[common]` spelling is the invisible path the first round created: the
//! flag detector read the raw value *before* `normalize_*_config` flattens
//! `[common]` onto the top level, so the key still reached the removal site but
//! the flag was never set, and the record was lost on exactly the paths where the
//! base binary delivered it (`--config-dir`).
//!
//! **Why the child stays up.** `[web_server] port` is a free port and
//! `login_fail_exit = false`, so `frpc` retries the (deliberately absent) server
//! instead of exiting; the startup line and the warning are both emitted before
//! the first connect attempt, so the ordering does not matter — the retry just
//! keeps the child alive until the guard reaps it.
//!
//! **Falsification (measured).** With
//! `FRPC_BIN=/tmp/enable-warn-probe/before/frpc` (the pre-change binary) the
//! plain `-c` test fails `stdout: 0` and `--config-dir` passes; with
//! `FRPC_BIN=/tmp/enable-warn-probe/after/frpc` (the reviewed binary) the
//! `[common]` test fails while the plain ones pass.
//!
//! **What these tests assert, and what they do not.** Real binary, real config
//! file, the two streams captured separately, the **number of records per
//! stream**, and that the binary reached its post-`init_logging` startup line.
//! They do **not** pin the message text, the exact log line, or the position of
//! the record; the text is pinned by
//! `frp-core/tests/web_server_tls_enable_warning.rs`.
//!
//! **What it does not cover.** `frps` (the sibling file
//! `frps/tests/warn_delivery.rs`, which also pins the server's SIGUSR1 reload
//! and the `includes` spelling), the `frpc verify` row and the **client** reload
//! row above (measured by probe; the client reload needs a live session, so it is
//! pinned in-process by `frp-client/tests/reload_warning_delivery.rs`), the admin
//! server's actual HTTP/HTTPS behaviour, and other sinks.
//!
//! Bounded: every wait has a deadline, every child is killed and reaped by
//! [`ChildGuard::drop`] even on panic, and each test picks its own ports from the
//! ephemeral range (never 7000 — held on this host by macOS Control Center).
//! Counts are read **before** any signal.
//!
//! Gated on `full` for the same reason as `admin_cli.rs`: the `frpc` bin carries
//! `required-features = ["full"]`, so without the gate this file would not
//! compile in the no-default-features lanes CI runs (`cargo test -p frpc
//! --no-default-features`).
#![cfg(feature = "full")]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The binary under test: the one `cargo test -p frpc` built for this target.
/// `FRPC_BIN` overrides it, which is how the pre-change falsification runs.
const BIN: &str = env!("CARGO_BIN_EXE_frpc");
/// How long a shape may take from spawn to its startup line being visible.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a killed child may take to disappear before the guard gives up.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Settle time after the startup line, so every record `init_logging` gates has
/// been written before the streams are read. Counts are taken BEFORE any signal.
const SETTLE: Duration = Duration::from_millis(500);
/// A substring of the first record `frpc` emits **after** `init_logging`, so
/// seeing it proves the load succeeded and a subscriber exists.
const STARTUP_MARKER: &str = "frpc (Rust) v";
/// The key, as the message names it.
const KEY: &str = "web_server.tls.enable";
/// The marker unique to the **dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`): the only words a build with no admin
/// server must never print.
const DASHBOARD_CLAUSE: &str = "plaintext HTTP";
/// The marker unique to the **no-dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`). The two clauses share
/// their whole first half, so `KEY` above is in both and cannot tell them apart.
const NO_DASHBOARD_CLAUSE: &str = "no dashboard support";
/// The **server-side** flat `tls_enable` diagnostic. It must never appear in
/// `frpc`: `ClientConfig::tls_enable` is live (it decides whether the control
/// connection is encrypted — `frp-client/src/control.rs`), so the "no effect"
/// claim would be false. These tests are the client half's negative control; the
/// `frps` half is `frps/tests/warn_delivery.rs`.
const SERVER_KEY: &str = "tls_enable has no effect on the server";
/// How long `frpc verify` may take to exit before the test kills it.
const EXIT_TIMEOUT: Duration = Duration::from_secs(20);

fn bin() -> String {
    std::env::var("FRPC_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as `admin_cli.rs`: no
/// `tempfile` dev-dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frpc-warn-delivery-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write config");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free port from the ephemeral range, deduplicated inside this process.
/// Same documented residual race as `frps/tests/log_completion.rs::free_port`.
fn free_port() -> u16 {
    loop {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);
        if used_ports().lock().unwrap().insert(port) {
            return port;
        }
    }
}

fn used_ports() -> &'static Mutex<std::collections::HashSet<u16>> {
    static USED: std::sync::OnceLock<Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    USED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Kills and reaps the child on every exit path, including a panicking
/// assertion — a leaked `frpc` holds a port and keeps retrying its server.
struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => break,
            }
        }
        let _ = self.child.wait();
    }
}

/// A spawned `frpc` whose stdout and stderr are drained by reader threads (a
/// full pipe can never block the child) and snapshotted **before** any signal.
struct Spawned {
    _guard: ChildGuard,
    stdout_buf: Arc<Mutex<String>>,
    stderr_buf: Arc<Mutex<String>>,
    stdout: String,
    stderr: String,
}

impl Spawned {
    fn run(dir: &TempDir, argv: &[&str]) -> Self {
        let child = Command::new(bin())
            .args(argv)
            .current_dir(&dir.0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn frpc");
        let mut spawned = Self::from_child(child);
        spawned.wait_for_marker();
        std::thread::sleep(SETTLE);
        spawned.snapshot();
        spawned
    }

    fn wait_for_marker(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if self.peek_stdout().contains(STARTUP_MARKER)
                || self.peek_stderr().contains(STARTUP_MARKER)
            {
                return;
            }
            if let Ok(Some(status)) = self._guard.child.try_wait() {
                panic!(
                    "frpc exited ({status}) before its startup line\n--- stdout ({} B) ---\n{}\n\
                     --- stderr ({} B) ---\n{}",
                    self.peek_stdout().len(),
                    self.peek_stdout(),
                    self.peek_stderr().len(),
                    self.peek_stderr(),
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "frpc never logged {STARTUP_MARKER:?} within {READY_TIMEOUT:?}\n\
                     --- stdout ({} B) ---\n{}\n--- stderr ({} B) ---\n{}",
                    self.peek_stdout().len(),
                    self.peek_stdout(),
                    self.peek_stderr().len(),
                    self.peek_stderr(),
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn from_child(mut child: Child) -> Self {
        let out = Arc::new(Mutex::new(String::new()));
        let err = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take().expect("child stdout"), out.clone());
        drain(child.stderr.take().expect("child stderr"), err.clone());
        Self {
            _guard: ChildGuard { child },
            stdout_buf: out,
            stderr_buf: err,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Freeze what the reader threads have collected so far, before any signal.
    fn snapshot(&mut self) {
        self.stdout = self.peek_stdout();
        self.stderr = self.peek_stderr();
    }

    fn peek_stdout(&self) -> String {
        self.stdout_buf.lock().unwrap().clone()
    }

    fn peek_stderr(&self) -> String {
        self.stderr_buf.lock().unwrap().clone()
    }

    fn stdout(&self) -> String {
        if self.stdout.is_empty() {
            self.peek_stdout()
        } else {
            self.stdout.clone()
        }
    }

    fn stderr(&self) -> String {
        if self.stderr.is_empty() {
            self.peek_stderr()
        } else {
            self.stderr.clone()
        }
    }
}

/// Read a child's pipe to EOF on its own thread, appending into `sink`.
fn drain<R: Read + Send + 'static>(mut pipe: R, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    });
}

/// Which spelling of the nested TLS section the config uses. All three named
/// spellings set the flag — `MixedSections` writes the camelCase `[webServer.tls]`
/// beside a snake_case `[web_server]`, and the two sections merge per key — and
/// `None` is the control.
#[derive(Clone, Copy)]
enum Section {
    Nested,
    CommonNested,
    MixedSections,
    None,
}

/// `server_port` points at nothing (a fresh ephemeral port); `login_fail_exit =
/// false` keeps the retrying child alive. The dashboard section is there because
/// it is what the warning is about.
fn frpc_config(server_port: u16, admin_port: u16, section: Section) -> String {
    let head = format!(
        "server_addr = \"127.0.0.1\"\nserver_port = {server_port}\nlogin_fail_exit = false\n"
    );
    match section {
        Section::Nested => format!(
            "{head}[web_server]\naddr = \"127.0.0.1\"\nport = {admin_port}\n\
             [web_server.tls]\nenable = true\n"
        ),
        Section::CommonNested => format!(
            "{head}[common.web_server]\naddr = \"127.0.0.1\"\nport = {admin_port}\n\
             [common.web_server.tls]\nenable = true\n"
        ),
        Section::MixedSections => format!(
            "{head}[web_server]\naddr = \"127.0.0.1\"\nport = {admin_port}\n\
             [webServer.tls]\nenable = true\n"
        ),
        Section::None => {
            format!("{head}[web_server]\naddr = \"127.0.0.1\"\nport = {admin_port}\n")
        }
    }
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The shared assertion: one record on **stdout**, none on **stderr**, the
/// binary really did start, and the record carries the clause **this build**
/// answers with.
fn assert_one_warning_on_stdout(tag: &str, spawned: &Spawned) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(STARTUP_MARKER),
        "{tag}: no startup line, so this shape never reached `init_logging`\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(
        occurrences(&out, KEY),
        1,
        "{tag}: expected exactly 1 `{KEY}` record on stdout (console sink)\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(
        occurrences(&err, KEY),
        0,
        "{tag}: the console sink is stdout; stderr must carry none\n--- stderr ---\n{err}"
    );
    assert_clause_matches_this_build(tag, spawned);
}

/// The clause the emitted record must carry — decided by **this build**, not by
/// a literal argument.
///
/// Both variants open with the same `web_server.tls.enable has no effect: …`, so
/// the count assertions above pass either way: a `frpc/src/main.rs` call site
/// (or `frp-client/src/service.rs:4457`) that hardcodes the other answer still
/// compiles and still emits one `KEY` record. `frp-core`'s own dispatch test
/// passes `has_dashboard` as an argument, so only this `cfg!`-keyed assertion on
/// the captured stdout can see what the binary answered.
///
/// Keyed on **`admin`**, the client's own word (`frp-client`'s `admin` feature,
/// which `frpc` forwards) — not on `dashboard`, which `frpc` does not have. The
/// plain `cargo test -p frpc` lane runs with `admin` off, so the no-dashboard
/// direction is pinned there without a new lane.
fn assert_clause_matches_this_build(tag: &str, spawned: &Spawned) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    if cfg!(feature = "admin") {
        assert!(
            out.contains(DASHBOARD_CLAUSE),
            "{tag}: a build that compiles the admin server must keep the dashboard clause \
             ({DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
        );
        assert!(
            !out.contains(NO_DASHBOARD_CLAUSE),
            "{tag}: a build that compiles the admin server must not claim it has no dashboard \
             support ({NO_DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
        );
    } else {
        assert!(
            out.contains(NO_DASHBOARD_CLAUSE),
            "{tag}: a build with no admin server must name its own build fact rather than the \
             dashboard's ({NO_DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
        );
        assert!(
            !out.contains(DASHBOARD_CLAUSE),
            "{tag}: a build with no admin server must not describe the dashboard's TLS \
             ({DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
        );
    }
}

#[test]
fn web_server_tls_enable_warning_reaches_a_dash_c_user() {
    let dir = TempDir::new("dashc");
    let cfg = frpc_config(free_port(), free_port(), Section::Nested);
    let path = dir.write("frpc.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout("frpc -c", &spawned);
}

#[test]
fn web_server_tls_enable_warning_reaches_a_config_dir_user() {
    let dir = TempDir::new("cfgdir");
    let cfg = frpc_config(free_port(), free_port(), Section::Nested);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frpc.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);
    assert_one_warning_on_stdout("frpc --config-dir", &spawned);
}

/// The `[common]` spelling: the same shape `frps` pins, on the client's own
/// config path. `normalize_client_config` flattens `[common]` onto the top level
/// with `or_insert` before `normalize_web_server_section` runs, so the key does
/// reach the removal site — and the detector has to mirror the flatten or the
/// record is lost, exactly as it was on the reviewed tree (measured 0 on
/// `--config-dir`, where the base binary emitted 1).
#[test]
fn web_server_tls_enable_warning_reaches_a_dash_c_user_with_the_common_spelling() {
    let dir = TempDir::new("dashc-common");
    let cfg = frpc_config(free_port(), free_port(), Section::CommonNested);
    let path = dir.write("frpc.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout("frpc -c ([common] spelling)", &spawned);
}

#[test]
fn web_server_tls_enable_warning_reaches_a_config_dir_user_with_the_common_spelling() {
    let dir = TempDir::new("cfgdir-common");
    let cfg = frpc_config(free_port(), free_port(), Section::CommonNested);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frpc.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);
    assert_one_warning_on_stdout("frpc --config-dir ([common] spelling)", &spawned);
}

/// Negative control: without the key there is no record on either stream, so the
/// warning is presence-driven and not an unconditional startup line.
#[test]
fn no_warning_for_a_config_without_the_key() {
    let dir = TempDir::new("nokey");
    let cfg = frpc_config(free_port(), free_port(), Section::None);
    let path = dir.write("frpc.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(STARTUP_MARKER),
        "no startup line\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(occurrences(&out, KEY), 0, "stdout:\n{out}");
    assert_eq!(occurrences(&err, KEY), 0, "stderr:\n{err}");
}

/// The mixed-sections shape warns: `[webServer]` and `[web_server]` are the same
/// section, merged per key, so the camelCase `[webServer.tls]` table reaches the
/// removal site and the client emits the record like any other nested spelling.
/// (Before the merge a top-level `[web_server]` discarded the whole `[webServer]`
/// table and this test pinned the silence, with the detector mirroring the
/// discard so it would not report a dropped key. It now mirrors the merge — it
/// must neither claim a dropped key nor miss a kept one.)
#[test]
fn warning_when_the_camelcase_tls_table_is_merged_into_the_snake_section() {
    let dir = TempDir::new("mixed");
    let cfg = frpc_config(free_port(), free_port(), Section::MixedSections);
    let path = dir.write("frpc.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(STARTUP_MARKER),
        "no startup line\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(
        occurrences(&out, KEY),
        1,
        "exactly one record on the console sink\n--- stdout ---\n{out}"
    );
    assert_eq!(occurrences(&err, KEY), 0, "stderr:\n{err}");
    assert_clause_matches_this_build("frpc -c (mixed sections)", &spawned);
}

/// The client writes the **same flat key name** the server warning is about, but
/// here it is live — so the server message must not appear. This is what keeps a
/// future "call the new warn from every `warn_inert_web_server_tls_enable` site"
/// edit from shipping a false claim on the client.
#[test]
fn no_server_tls_enable_warning_in_frpc_where_the_field_is_live() {
    let dir = TempDir::new("srv-key-live");
    let cfg = format!(
        "server_addr = \"127.0.0.1\"\nserver_port = {}\nlogin_fail_exit = false\n\
         tls_enable = false\n",
        free_port()
    );
    let path = dir.write("frpc.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(STARTUP_MARKER),
        "no startup line\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(
        occurrences(&out, SERVER_KEY),
        0,
        "the server-side message must never appear in frpc\n--- stdout ---\n{out}"
    );
    assert_eq!(occurrences(&err, SERVER_KEY), 0, "stderr:\n{err}");
}

/// `frpc verify` installs its console logger **before** the load and therefore
/// *does* reach the dashboard diagnostic — but the server `tls_enable` message
/// must still be absent, because that path loads a `ClientConfig`.
#[test]
fn frpc_verify_says_nothing_about_the_server_tls_enable_key() {
    let dir = TempDir::new("srv-key-verify");
    let cfg = format!(
        "server_addr = \"127.0.0.1\"\nserver_port = {}\ntls_enable = false\n",
        free_port()
    );
    let path = dir.write("frpc.toml", &cfg);

    let mut child = Command::new(bin())
        .args(["verify", "-c", path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frpc verify");
    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        match child.try_wait().expect("try_wait frpc verify") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("frpc verify did not exit within {EXIT_TIMEOUT:?}");
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let out = child
        .wait_with_output()
        .expect("collect frpc verify output");
    let status = out.status;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        status.success(),
        "verify must succeed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        occurrences(&stdout, SERVER_KEY),
        0,
        "frpc verify must not claim the client field is inert\n--- stdout ---\n{stdout}"
    );
    assert_eq!(occurrences(&stderr, SERVER_KEY), 0, "stderr:\n{stderr}");
}
