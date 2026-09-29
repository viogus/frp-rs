//! The admin config **GET**'s inert-`enable` delivery, pinned against the **real**
//! `frpc` binary — including the wiring the in-process test cannot reach.
//!
//! **What this pins that `frp-client/src/admin.rs` cannot.** The unit test there
//! (`admin_config_get_warns_once_per_state_change`) drives `config_from_file` and
//! `seed_web_server_tls_enable_seen` directly, so it pins the cell protocol and
//! the seed mapping — but not the one line in `spawn_admin_server`
//! (`frp-client/src/service.rs`) that puts the seed into the cell. Reverting that
//! line to round 2's `AtomicU8::new(0)` leaves all 11 of its tests green while the
//! shipped behaviour regresses (`seed` mutant M3b): the first GET then baselines
//! silently and a hand-edit that adds `[web_server.tls] enable` after startup is
//! **lost** (0 records). This target spawns the real binary, drives the real HTTP
//! route, and reds on that mutant.
//!
//! | case | startup | hand-edit | GETs | records |
//! |---|---|---|---|---|
//! | `hand_edit_after_startup_is_reported` | no `enable` | add `enable` | 1 | **1** |
//! | `startup_record_is_not_repeated_by_a_get` | has `enable` | — | 3 | **1** (startup only) |
//! | `seed_reads_the_file_non_strictly` | no `enable` + an unknown field, `--strict-config=false` | add `enable` | 1 | **1** |
//!
//! **The strict-flag row.** `seed_web_server_tls_enable_seen` loads with
//! `strict = false`, deliberately: the admin GET itself
//! (`config_from_file` → `load_client_config_with_presence(path, false)`) and the
//! service **reload** (`load_client_config(&path, false)`) both read the file
//! non-strictly, and the seed is standing in for the record that load already
//! emitted. Parsing strictly would make the seed fail on a file the runtime
//! accepts (any unknown field, under `--strict-config=false`), leaving
//! `NO_BASELINE` — and then the first GET baselines silently and a later add is
//! lost. The third row is that file: with the flag flipped to `true` the seed
//! fails, the GET adds **0**, and this test is red.
//!
//! **What this models.** A real `frpc` (built by `cargo test -p frpc --features
//! admin` for this target), a real config file, the real admin route
//! (`GET /api/proxy/main/config` — the handler loads the config *before* it
//! answers 404, so the 404 is not a problem), stdout and stderr captured
//! separately, a per-case free admin port, and a hand-edit made while the child
//! runs. No `frps` is needed: the admin server starts in `Service::run`
//! independently of the control connection, and `login_fail_exit = false` keeps
//! the child alive against a deliberately absent server.
//!
//! **What it does not cover.** The message text (pinned by
//! `frp-core/tests/web_server_tls_enable_warning.rs`), the PUT path's cell reset
//! (in-process, `admin_config_get_warns_once_per_state_change`), the admin API's
//! routing/auth/status codes (`frpc/tests/admin_cli.rs`), and the seed's
//! failure mode (asserted in-process). It also does not pin the *cadence* of any
//! particular poller beyond "three GETs add nothing".
//!
//! Bounded: every wait has a deadline, every child is killed and reaped by
//! [`ChildGuard::drop`] even on panic, and each test picks its own ports from the
//! ephemeral range. Record counts are polled to a deadline (stdout is a pipe;
//! a line can land a few milliseconds after the request that caused it).
//!
//! Gated on `full` (the `frpc` bin carries `required-features = ["full"]`) and
//! `admin` (the route only exists when the feature compiles it in).
#![cfg(all(feature = "full", feature = "admin"))]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The binary under test: the one `cargo test -p frpc --features admin` built for
/// this target. `FRPC_BIN` overrides it, which is how the mutant runs are made.
const BIN: &str = env!("CARGO_BIN_EXE_frpc");
/// A substring of the first record `frpc` emits **after** `init_logging`, so
/// seeing it proves the load succeeded and a subscriber exists.
const STARTUP_MARKER: &str = "frpc (Rust) v";
/// Emitted once the admin listener is bound; the GETs must wait for it.
const ADMIN_MARKER: &str = "frpc admin server listening";
/// The inert-key record the tests count.
const KEY: &str = "web_server.tls.enable has no effect";
/// How long a shape may take from spawn to a marker being visible.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a killed child may take to disappear before the guard gives up.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Settle time after a marker or a GET, so the record it gates has been written.
const SETTLE: Duration = Duration::from_millis(500);
/// How long a record count may lag the request that caused it. Records appear in
/// milliseconds; this only stops a *failing* assertion from waiting out
/// [`READY_TIMEOUT`].
const COUNT_TIMEOUT: Duration = Duration::from_secs(5);

fn bin() -> String {
    std::env::var("FRPC_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as
/// `frpc/tests/warn_delivery.rs`: no `tempfile` dev-dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("frpc-admin-get-{tag}-{}-{n}", std::process::id()));
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

/// A spawned `frpc` whose stdout and stderr are drained by reader threads (a full
/// pipe can never block the child).
struct Spawned {
    _guard: ChildGuard,
    stdout_buf: Arc<Mutex<String>>,
    stderr_buf: Arc<Mutex<String>>,
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
        spawned.wait_for(STARTUP_MARKER);
        spawned.wait_for(ADMIN_MARKER);
        std::thread::sleep(SETTLE);
        spawned
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
        }
    }

    /// Wait until `marker` appears on either stream, or panic with both.
    fn wait_for(&mut self, marker: &str) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let out = self.peek_stdout();
            let err = self.peek_stderr();
            if out.contains(marker) || err.contains(marker) {
                return;
            }
            if let Ok(Some(status)) = self._guard.child.try_wait() {
                panic!(
                    "frpc exited ({status}) before {marker:?}\n--- stdout ({} B) ---\n{out}\n\
                     --- stderr ({} B) ---\n{err}",
                    out.len(),
                    err.len(),
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "frpc never logged {marker:?} within {READY_TIMEOUT:?}\n\
                     --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{err}",
                    out.len(),
                    err.len(),
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn peek_stdout(&self) -> String {
        self.stdout_buf.lock().unwrap().clone()
    }

    fn peek_stderr(&self) -> String {
        self.stderr_buf.lock().unwrap().clone()
    }

    fn records(&self) -> usize {
        self.peek_stdout().matches(KEY).count()
    }

    /// Poll until at least `want` records are visible (a piped line can land a
    /// few milliseconds after the request that caused it), then assert exactly
    /// `want` on **both** streams' totals. `want` never changes under a mutant,
    /// so a wrong count can only fail — the poll just removes the timing flake.
    fn assert_records(&self, want: usize, tag: &str) {
        let deadline = Instant::now() + COUNT_TIMEOUT;
        while self.records() < want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = self.peek_stdout();
        let err = self.peek_stderr();
        assert_eq!(
            self.records(),
            want,
            "{tag}: expected {want} {KEY:?} record(s) on stdout\n--- stdout ---\n{out}\n\
             --- stderr ---\n{err}"
        );
        assert_eq!(
            err.matches(KEY).count(),
            0,
            "{tag}: the console sink is stdout; stderr must carry none\n--- stderr ---\n{err}"
        );
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

/// One admin config **GET**, hand-rolled so the test needs no HTTP client
/// dependency. The handler runs `config_from_file` before it can answer, so the
/// 404 for the absent `main` proxy still exercises the load; the response body is
/// read to EOF so the request is complete before the caller counts records.
fn admin_get(port: u16, tag: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("{tag}: connect to the admin port {port}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    stream
        .write_all(b"GET /api/proxy/main/config HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap_or_else(|e| panic!("{tag}: write the GET: {e}"));
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .unwrap_or_else(|e| panic!("{tag}: read the response: {e}"));
    response
}

/// A `frpc` config that starts the admin server and stays up against an absent
/// server (`server_port = 1`, refused; `login_fail_exit = false`). `extra` is
/// appended verbatim after `[web_server]`.
fn frpc_config(admin_port: u16, extra: &str) -> String {
    format!(
        "server_addr = \"127.0.0.1\"\nserver_port = 1\ntoken = \"t\"\n\
         login_fail_exit = false\n[web_server]\naddr = \"127.0.0.1\"\nport = {admin_port}\n{extra}"
    )
}

/// The key's section, as a config fragment.
const ENABLE: &str = "[web_server.tls]\nenable = true\n";

/// The headline behaviour change of the seeding round: a hand-edit that **adds**
/// `[web_server.tls] enable` after the admin server has started is reported by
/// the next admin config GET.
///
/// The file has no key at startup, so nothing is emitted at load and the seed
/// records `ABSENT`; the edit is therefore a real state change and the GET emits
/// **1**. With the seed wiring reverted to `AtomicU8::new(0)` the first GET
/// baselines silently and the total is **0** — the regression this target exists
/// to catch.
///
/// **What this does not cover.** A hand-edit made in the window **before** the
/// admin server starts: that one is still baselined, because the seed reads the
/// file at spawn; the window is named in the seed's and `AdminState`'s docs.
#[test]
fn hand_edit_after_startup_is_reported() {
    let dir = TempDir::new("hand-edit");
    let admin_port = free_port();
    let cfg = dir.write("frpc.toml", &frpc_config(admin_port, ""));
    let child = Spawned::run(&dir, &["-c", cfg.to_str().unwrap()]);
    assert_eq!(
        child.records(),
        0,
        "no key at startup, so no startup record"
    );

    // The hand-edit: add the key while the child runs, then poll once.
    std::fs::write(&cfg, frpc_config(admin_port, ENABLE)).expect("hand-edit the config");
    let response = admin_get(admin_port, "hand-edit");
    assert!(
        response.contains("HTTP/1."),
        "the admin route must answer, got {response:?}"
    );

    child.assert_records(1, "one GET after a hand-edit");
    assert!(
        child.peek_stderr().is_empty() || !child.peek_stderr().contains(KEY),
        "stderr must stay clean"
    );
}

/// The no-duplicate control: a file that **had** the key at startup emits the
/// startup record, and three admin config GETs add **nothing**.
///
/// This is what the seed buys in the other direction — the cell already holds
/// `WRITTEN`, so the polls are not state changes. (It is a control rather than a
/// mutant-catcher: a `NO_BASELINE` cell also ends at one record, because its
/// first GET baselines silently. `hand_edit_after_startup_is_reported` is the row
/// that distinguishes the two.)
#[test]
fn startup_record_is_not_repeated_by_a_get() {
    let dir = TempDir::new("no-dup");
    let admin_port = free_port();
    let cfg = dir.write("frpc.toml", &frpc_config(admin_port, ENABLE));
    let child = Spawned::run(&dir, &["-c", cfg.to_str().unwrap()]);
    child.assert_records(1, "the startup record");

    for i in 0..3 {
        let response = admin_get(admin_port, "no-dup");
        assert!(response.contains("HTTP/1."), "GET {i} must answer");
    }
    child.assert_records(1, "three GETs over an unchanged file");
}

/// The seed reads the file **non-strictly**, like the admin GET and the service
/// reload it stands in for.
///
/// The config carries an unknown field, so the runtime is started with
/// `--strict-config=false`; the seed must still read it (strict parsing would
/// fail, leave `NO_BASELINE`, and silently baseline the hand-edit below). With
/// the flag flipped to `true` this test is red: 0 records instead of 1.
///
/// **What this does not cover.** The seed's `strict = true` failure mode itself
/// (asserted in-process by `admin_config_get_warns_once_per_state_change`'s
/// `NO_BASELINE` case), and the `-c` default (strict) — this row deliberately
/// measures the non-strict runtime.
#[test]
fn seed_reads_the_file_non_strictly() {
    let dir = TempDir::new("non-strict");
    let admin_port = free_port();
    // An unknown top-level field: accepted by the runtime only because the run
    // is non-strict, and enough to make a strict seed fail.
    let cfg = dir.write(
        "frpc.toml",
        &format!(
            "unknown_top_level_field = 1\n{}",
            frpc_config(admin_port, "")
        ),
    );
    let child = Spawned::run(
        &dir,
        &["--strict-config=false", "-c", cfg.to_str().unwrap()],
    );
    assert_eq!(child.records(), 0, "no key at startup");

    std::fs::write(
        &cfg,
        format!(
            "unknown_top_level_field = 1\n{}",
            frpc_config(admin_port, ENABLE)
        ),
    )
    .expect("hand-edit the config");
    let response = admin_get(admin_port, "non-strict");
    assert!(response.contains("HTTP/1."), "the route must answer");

    child.assert_records(1, "the seed must have read the non-strict file");
}
