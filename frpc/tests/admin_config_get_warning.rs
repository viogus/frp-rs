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
//! | `seed_resolves_spellings_only_the_loader_does` (a/b) | `[common]` / `includes` spelling | — | 3 | **1** (startup only) |
//! | the same test's (c) | key in `admin-node.toml`, a key-less `frpc.toml` in the cwd | — | 3 | **1** (startup only) |
//! | the same test's (d) | key-less `admin-node.toml` (`-c`), a keyed `frpc.toml` in the cwd | add `enable` to the `-c` file | 1 | **1** |
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
//! **failure-mode mapping** — that a missing path yields `NO_BASELINE` rather
//! than `ABSENT` is asserted in-process by that same test's two
//! `seed_web_server_tls_enable_seen(…) == WS_TLS_ENABLE_NO_BASELINE` cases
//! (`None`, then a path that does not exist). Under a `.unwrap_or(ABSENT)` mutant
//! **this** target stays green while the in-process one reds on the `None` case
//! (`frp-client/src/admin.rs:2044`), so the missing-path case is never reached;
//! either way the mapping is caught in-process, not here — this target only ever
//! exercises readable files. It also does not pin the *cadence* of any
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
/// The marker unique to the **dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`); this target only compiles when
/// `admin` is on, so this is the clause it must carry.
const DASHBOARD_CLAUSE: &str = "plaintext HTTP";
/// The marker unique to the **no-dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`) — the one an admin build
/// must never print. All three texts share `KEY` above, so `KEY` cannot tell them
/// apart on its own.
const NO_DASHBOARD_CLAUSE: &str = "no dashboard support";
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
        assert_clause_is_the_dashboard_one(tag, &out);
    }
}

/// The clause the emitted record must carry in **this** target.
///
/// The file compiles only when `admin` is on (`#![cfg(all(feature = "full",
/// feature = "admin"))]`), so the build under test can serve HTTPS (`full`
/// forwards `frp-client/default`, which includes `tls`) and answers "a web server
/// with a TLS acceptor exists", and a record that says otherwise means a call
/// site answered wrongly. The call sites this file reaches are `frpc/src/main.rs:606`
/// (the `-c` startup load) and `frp-client/src/admin.rs:771` (the admin config-GET
/// handler runs `config_from_file`); it never drives the reload, so
/// `frp-client/src/service.rs:4458` is not visible here — that site is pinned by
/// `frp-client/tests/reload_warning_delivery.rs`. `KEY` is the shared prefix of
/// all three texts and cannot tell them apart; these markers are the whole
/// assertion. Every test in this file reaches it through [`assert_records`];
/// measured before the three-way reader landed, hardcoding a reached site's
/// answer to the no-dashboard one reds **2 of the 4** (`test result: FAILED. 2
/// passed; 2 failed`) — the startup rows witness `:604`, the hand-edit rows
/// witness `:771`.
fn assert_clause_is_the_dashboard_one(tag: &str, out: &str) {
    assert!(
        out.contains(DASHBOARD_CLAUSE),
        "{tag}: an admin build's record must keep the dashboard clause \
         ({DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
    );
    assert!(
        !out.contains(NO_DASHBOARD_CLAUSE),
        "{tag}: an admin build's record must not claim it has no dashboard support \
         ({NO_DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
    );
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

/// A proxy whose `local_port` is distinctive, so a GET body proves **which**
/// file answered: only the `-c` file of sub-case (d) declares it, while the cwd
/// file there holds no proxies at all.
const MAIN_PROXY: &str =
    "\n[[proxies]]\nname = \"main\"\ntype = \"tcp\"\nlocalPort = 45999\nremotePort = 45999\n";

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

/// The seed reads the file with the **loader**, not with a raw top-level parse of
/// the TOML.
///
/// That distinction is invisible to the rows above: a seed that only looked at
/// `web_server.tls.enable` / `webServer.tls.enable` **at the top level** passes
/// them all, while the shipped seed resolves both shapes here — the key sits
/// under `[common]`, in either spelling, or in an `includes` file. Neither shape
/// reaches a raw top-level parse: `process_includes` deep-merges the include
/// (`frp-core/src/config/normalize.rs:600`) and the presence detector
/// (`ConfigPresence::web_server_tls_enable_set_in`) reads the value **before**
/// `normalize` (`frp-core/src/config/normalize.rs:621`), with its own "top level
/// first, `[common]` second" fallback per spelling
/// (`frp-core/src/config/loader.rs:427-429`). The per-key section merge
/// (`merge_section_into`) runs inside `normalize`, so it is not what the flag
/// consults — the merge has its own frp-core pin. Measured on the shipped binary
/// before this row existed: both shapes emit **1** record at 0 GETs and still
/// **1** after 3.
///
/// Each sub-case asserts the no-duplicate property: the file wrote the key (so
/// the startup load emits one record — asserted first, which is also what proves
/// the shape reached the loader), then three admin GETs add **nothing**. A
/// raw-parse seed records `ABSENT`, so the first GET sees a state change and
/// emits a second record, and the total is 2 — red.
///
/// **What this does not cover.** The presence detector's own spelling matrix
/// (pinned in `frp-core/tests/web_server_tls_enable_warning.rs`, which measures
/// each `[common]`/cross-spelling row directly, and by
/// `common_and_includes_spellings_set_the_flag`). Sub-cases (c) and (d) pin the
/// **path** the seed reads rather than a default filename, in both directions:
/// (c) starts the child with a non-default filename carrying the key while a
/// `frpc.toml` **without** the key sits in its working directory, and (d) starts
/// it with a key-less `-c` file while the working directory's `frpc.toml` **has**
/// the key, then adds the key to the `-c` file: the `-c` argument must win, so
/// that edit is a real state change and the GET emits **1**. (d) is the row a
/// "prefer `./frpc.toml` only when that file sets the key" seed reds (it would
/// have baselined `WRITTEN` and emitted **0**); (c) cannot see that seed, because
/// there the cwd file does not set the key.
#[test]
fn seed_resolves_spellings_only_the_loader_does() {
    // (a) `[common.webServer.tls] enable` beside a top-level `[web_server]`: the
    //     two spellings are different keys, so the flatten keeps `webServer` and
    //     the presence detector finds its `tls` through the `[common]` fallback —
    //     read before `normalize`, so the per-key merge is not what keeps it.
    let dir = TempDir::new("loader-common");
    let admin_port = free_port();
    let cfg = dir.write(
        "frpc.toml",
        &frpc_config(admin_port, "[common.webServer.tls]\nenable = true\n"),
    );
    let child = Spawned::run(&dir, &["-c", cfg.to_str().unwrap()]);
    child.assert_records(1, "(a) the startup record for the [common] spelling");
    for _ in 0..3 {
        let response = admin_get(admin_port, "(a) common spelling");
        assert!(response.contains("HTTP/1."), "the route must answer");
    }
    child.assert_records(1, "(a) three GETs over the [common] spelling");

    // (b) The same key in an `includes` file, which `process_includes`
    //     deep-merges before the detector runs.
    let dir = TempDir::new("loader-includes");
    let admin_port = free_port();
    let cfg = dir.write(
        "frpc.toml",
        &format!("includes = [\"inc.toml\"]\n{}", frpc_config(admin_port, "")),
    );
    dir.write("inc.toml", "[common.webServer.tls]\nenable = true\n");
    let child = Spawned::run(&dir, &["-c", cfg.to_str().unwrap()]);
    child.assert_records(1, "(b) the startup record for the includes spelling");
    for _ in 0..3 {
        let response = admin_get(admin_port, "(b) includes spelling");
        assert!(response.contains("HTTP/1."), "the route must answer");
    }
    child.assert_records(1, "(b) three GETs over the includes spelling");

    // (c) The seed must read the path it was handed, not a default filename: the
    //     child is started with `-c admin-node.toml` (carrying the key) while its
    //     working directory holds a `frpc.toml` **without** the key. A seed that
    //     read `./frpc.toml` instead would record `ABSENT`, and the first GET would
    //     then report the key as a state change — a second record. (A default-name
    //     read of an *absent* `frpc.toml` is not caught here: `NO_BASELINE`
    //     baselines silently on the first GET, so the counts would match.)
    let dir = TempDir::new("loader-argument");
    let admin_port = free_port();
    dir.write("frpc.toml", &frpc_config(admin_port, ""));
    let cfg = dir.write("admin-node.toml", &frpc_config(admin_port, ENABLE));
    let child = Spawned::run(&dir, &["-c", cfg.to_str().unwrap()]);
    child.assert_records(1, "(c) the startup record for a non-default filename");
    for _ in 0..3 {
        let response = admin_get(admin_port, "(c) non-default filename");
        assert!(response.contains("HTTP/1."), "the route must answer");
    }
    child.assert_records(1, "(c) three GETs over a non-default filename");

    // (d) The same precedence in the other direction: the `-c` file
    //     (`admin-node.toml`) is **key-less**, while the working directory holds a
    //     `frpc.toml` **with** the key. The `-c` argument must still win, so the
    //     startup load emits nothing and the seed records `ABSENT` — which makes
    //     adding the key to the `-c` file a real state change, so the next GET
    //     emits **1** (a GET warns only when the file *becomes* written; see
    //     `config_from_file`). A seed that preferred an *existing* keyed
    //     `./frpc.toml` would record `WRITTEN`, and the same edit would then emit
    //     **0** — red. Sub-case (c) catches only the plain "always prefer
    //     `./frpc.toml`" seed (its keyed `-c` file makes that seed emit a second
    //     record, 2 vs 1); this row is what catches the narrower "prefer the cwd
    //     file only when it sets the key" fallback, which (c) cannot see because
    //     there the cwd file does *not* set the key.
    //
    //     The `-c` file also declares the only `main` proxy (distinctive
    //     `local_port = 45999`); the cwd file declares none. So the GET body, not
    //     just the record count, says which file answered: a load that preferred
    //     the proxy-less cwd file still emits the same single record, but answers
    //     `404 proxy "main" not found` instead of describing the proxy.
    let dir = TempDir::new("loader-precedence");
    let admin_port = free_port();
    dir.write("frpc.toml", &frpc_config(admin_port, ENABLE));
    let cfg = dir.write("admin-node.toml", &frpc_config(admin_port, MAIN_PROXY));
    let child = Spawned::run(&dir, &["-c", cfg.to_str().unwrap()]);
    assert_eq!(
        child.records(),
        0,
        "(d) the `-c` file has no key at startup, so no record — a load that read \
         the keyed ./frpc.toml instead would have emitted one"
    );

    // The hand-edit lands in the `-c` file, not in the cwd one, so only a seed
    // that actually read the `-c` file sees the change. It keeps the proxy.
    std::fs::write(
        &cfg,
        frpc_config(admin_port, &format!("{MAIN_PROXY}{ENABLE}")),
    )
    .expect("hand-edit the -c file");
    let response = admin_get(admin_port, "(d) precedence");
    assert!(
        response.contains("HTTP/1."),
        "the admin route must answer, got {response:?}"
    );
    child.assert_records(1, "(d) one GET after the `-c` file gains the key");
    // Provenance, not just the count: `main` exists only in the `-c` file, so a
    // body describing it can only have come from there.
    assert!(
        response.contains("\"local_port\":45999"),
        "(d) the GET body must describe the `main` proxy declared in the `-c` file \
         — a load that read the proxy-less cwd ./frpc.toml answers 404 instead\n\
         --- response ---\n{response}"
    );
}
