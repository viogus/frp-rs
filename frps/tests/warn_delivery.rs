//! The `[web_server.tls] enable` diagnostic a **`frps` user** actually sees:
//! bounded spawn tests against the real binary, on both config paths and across
//! a **SIGUSR1 reload**, with stdout and stderr captured separately.
//!
//! **The defect these pin.** `normalize_web_server_section` accepts the key
//! (a deliberate divergence — Go's `TLSConfig` has no `Enable` field, so
//! `frps verify` refuses it with `json: unknown field "enable"`, measured with
//! `/private/tmp/frp_0.71.0_darwin_arm64/frps`), removes it because nothing
//! reads it, and used to warn from *inside the loader*. On the `-c` path the
//! loader runs **before** `init_logging` (the single-config branch of
//! `frps/src/main.rs`: `load_server_config_uncompleted_with_presence`, then
//! `init_logging` — a deliberate Go-parity ordering, because Go installs its
//! logger only after a successful load, `cmd/frps/root.go:112`), so the record
//! reached no subscriber. The fix
//! carries the fact out of the loader on `ConfigPresence` and emits it at every
//! **in-process load site that has a sink**: both startup paths, and the SIGUSR1
//! reload (`Service::reload`).
//!
//! Measured with the v0.71.0 debug binaries, stdout and stderr captured
//! separately, occurrence counts (`grep -o web_server\.tls\.enable | wc -l`),
//! probe `/tmp/enable-warn-probe/run-probe2.sh`, rows
//! `/tmp/enable-warn-probe/out2-{before,after,after2}.txt` (`after` = the
//! reviewed tree, `after2` = this one):
//!
//! | shape | base | reviewed | now |
//! |---|---|---|---|
//! | `frps -c <cfg>` | 0 | 1 | 1 |
//! | `frps --config-dir <dir>` | 1 | 1 | 1 |
//! | `[common.web_server.tls] enable`, `-c` | 0 | **0** | 1 |
//! | `[common.web_server.tls] enable`, `--config-dir` | 1 | **0** | 1 |
//! | `[common.webServer.tls] enable`, `-c` | 0 | 0 | 1 |
//! | inline `common = { … tls = { enable = true } }`, `-c` | 0 | 0 | 1 |
//! | the same in an `includes` file (`--config-dir`) | 1 | **0** | 1 |
//! | `[web_server]` + `[webServer.tls] enable` (mixed) | 0 | 0 | **1** |
//! | no `enable` key | 0 | 0 | 0 |
//! | **SIGUSR1 reload** delta on `-c` | +1 | **0** | +1 |
//!
//! Every row above is stdout; stderr carried 0 in all of them. The `[common]`
//! rows were the invisible path the first round created — the detector read the
//! raw value *before* the `[common]` flatten, so the key reached the removal site
//! but never the flag — and the reload row is the user-visible path that was
//! lost when the loader went silent.
//!
//! **What these tests assert, and what they do not.** Real binary, real config
//! file, the two streams captured separately, and the **number of records per
//! stream** — plus the order-independent fact that the process reached its
//! post-`init_logging` startup line. They do **not** pin the message text, the
//! exact log line, or the position of the record relative to other records; the
//! text is pinned by `frp-core/tests/web_server_tls_enable_warning.rs`.
//!
//! **Falsification (measured).** Run with
//! `FRPS_BIN=/tmp/enable-warn-probe/before/frps` (the pre-change binary): the
//! plain `-c` test fails `left: 0, right: 1` while `--config-dir` passes. Run
//! with `FRPS_BIN=/tmp/enable-warn-probe/after/frps` (the reviewed binary): the
//! `[common]` and reload tests fail, which is what this round fixes
//! (`/tmp/enable-warn-probe/out2-after-frozen.txt`).
//!
//! Bounded: every wait has a deadline, every child is killed and reaped by
//! [`ChildGuard::drop`] even on panic, each test picks its own port from the
//! ephemeral range (never 7000 — held on this host by macOS Control Center), and
//! the counts are read **before** any signal so no shutdown record can be
//! mistaken for a second warning.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The binary under test: the one `cargo test -p frps` built for this target.
/// `FRPS_BIN` overrides it, which is how the falsification runs work.
const BIN: &str = env!("CARGO_BIN_EXE_frps");
/// How long a shape may take from spawn to its startup line being visible.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the SIGUSR1 handler may take to come up after the startup line.
///
/// Unix-only, like the lane it serves: `frps`'s SIGUSR1 handling (and the
/// `--config-dir` reload fan-out built on it) lives behind `#[cfg(unix)]`, so
/// every test and helper below that drives it carries the same gate rather than
/// compiling on a non-unix target and failing there. `SETTLE`, by contrast, is
/// used by the plain startup path and stays ungated.
#[cfg(unix)]
const RELOAD_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the reload may take to log its summary after SIGUSR1.
#[cfg(unix)]
const RELOAD_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a killed child may take to disappear before the guard gives up.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Settle time after a marker, so every record `init_logging` gates has been
/// written before the streams are read. Counts are taken BEFORE any signal.
const SETTLE: Duration = Duration::from_millis(600);
/// A substring of the first record `frps` emits **after** `init_logging`, so
/// seeing it proves the load succeeded and a subscriber exists. Without it, an
/// empty warning count would be indistinguishable from "the binary never ran".
const STARTUP_MARKER: &str = "frps (Rust) v";
/// The SIGUSR1 task's own progress witness. Gated on registration completing:
/// the handler is installed *before* the services are spawned (so an early
/// signal cannot kill the process), but this line is only printed once every
/// spawned task has registered, so a signal sent after it reaches a fully
/// populated registry. Unix-only (see `RELOAD_READY_TIMEOUT`).
#[cfg(unix)]
const SIGNAL_READY_MARKER: &str = "SIGUSR1 reload ready";
/// The server's reload summary line (`frps/src/main.rs`). Unix-only.
#[cfg(unix)]
const RELOAD_MARKER: &str = "SIGUSR1:";
/// The key, as the message names it.
const KEY: &str = "web_server.tls.enable";
/// The marker unique to the **dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`): the only words a build with no
/// dashboard must never print.
const DASHBOARD_CLAUSE: &str = "plaintext HTTP";
/// The marker unique to the **no-dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`). The three texts share
/// their whole first half, so `KEY` above is in all of them and cannot tell them
/// apart; these three markers are pairwise disjoint.
const NO_DASHBOARD_CLAUSE: &str = "no dashboard support";
/// The marker unique to the **no-TLS-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_TLS`). Unreachable from this binary —
/// see `assert_clause_matches_this_build` — so it is used only as a negative
/// control.
const NO_TLS_CLAUSE: &str = "no TLS support";
/// The **second** diagnostic this file now pins: the flat server `tls_enable` is
/// inert too (`TODO.md` item), and it warns from the same three sites. Kept as a
/// substring of `SERVER_TLS_ENABLE_INERT_WARNING` so a count of it cannot match
/// the dashboard message, and vice versa.
const SERVER_KEY: &str = "tls_enable has no effect on the server";

fn bin() -> String {
    std::env::var("FRPS_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as
/// `frps/tests/log_completion.rs`: no `tempfile` dev-dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frps-warn-delivery-{tag}-{}-{n}",
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

/// A free port from the ephemeral range, deduplicated inside this process. Same
/// documented residual race as `frps/tests/log_completion.rs::free_port`: a
/// concurrent process can take the port between the probe's drop and the child's
/// bind, which fails loudly (the startup line never arrives, with the child's own
/// stderr in the panic message) rather than being papered over.
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
/// assertion — a leaked `frps` holds a port and has produced false measurements
/// in this repository.
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

/// A spawned `frps` whose stdout and stderr are drained by reader threads (a
/// full pipe can never block the child) and snapshotted at each point the test
/// wants a count. The child stays alive until this value is dropped, which kills
/// and reaps it.
struct Spawned {
    _guard: ChildGuard,
    stdout_buf: Arc<Mutex<String>>,
    stderr_buf: Arc<Mutex<String>>,
    stdout: String,
    stderr: String,
}

impl Spawned {
    /// Spawn `frps` with `argv` from `dir`, wait (bounded) for
    /// [`STARTUP_MARKER`] on either stream, settle, and snapshot both streams.
    fn run(dir: &TempDir, argv: &[&str]) -> Self {
        let child = Command::new(bin())
            .args(argv)
            .current_dir(&dir.0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn frps");
        let mut spawned = Self::from_child(child);
        spawned.wait_for_marker(STARTUP_MARKER, READY_TIMEOUT);
        std::thread::sleep(SETTLE);
        spawned.snapshot();
        spawned
    }

    /// Spawn `frps` with `argv` and extra `env` vars from `dir`, wait (bounded)
    /// for [`STARTUP_MARKER`], and snapshot — but **without** [`SETTLE`].
    ///
    /// The registration-order pin needs the window right after the startup line
    /// left open: it signals as soon as [`SIGNAL_READY_MARKER`] appears, so a
    /// fixed settle would hide the race it exists to catch. Unix-only, like the
    /// signal it is built to drive.
    #[cfg(unix)]
    fn spawn(dir: &TempDir, argv: &[&str], envs: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(bin());
        cmd.args(argv)
            .current_dir(&dir.0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let child = cmd.spawn().expect("spawn frps");
        let mut spawned = Self::from_child(child);
        spawned.wait_for_marker(STARTUP_MARKER, READY_TIMEOUT);
        spawned.snapshot();
        spawned
    }

    /// Send `SIGUSR1`, wait (bounded) for the reload summary, settle, and
    /// re-snapshot. Returns `true` when the summary line was seen; the counts
    /// the caller reads afterwards are the post-reload ones.
    #[cfg(unix)]
    fn sigusr1_and_reload(&mut self) -> bool {
        // The handler prints this once installed; a signal sent earlier can be
        // lost, which would look exactly like the defect under test.
        self.wait_for_marker(SIGNAL_READY_MARKER, RELOAD_READY_TIMEOUT);
        let pid = self._guard.child.id();
        let status = Command::new("kill")
            .args(["-USR1", &pid.to_string()])
            .status()
            .expect("run kill -USR1");
        assert!(status.success(), "kill -USR1 {pid} failed: {status}");
        let seen = self.wait_for_marker_or_timeout(RELOAD_MARKER, RELOAD_TIMEOUT);
        std::thread::sleep(SETTLE);
        self.snapshot();
        seen
    }

    /// Send `SIGUSR1` and wait until the reload-summary count has grown by
    /// `expect_extra`, then settle, snapshot and return the **total** count.
    ///
    /// The count-based sibling of [`Self::sigusr1_and_reload`]: with two
    /// services one signal prints two summaries, and a presence wait would
    /// return on the *previous* signal's line instead of the new ones.
    #[cfg(unix)]
    fn sigusr1_and_wait_for_reloads(&mut self, expect_extra: usize) -> usize {
        self.wait_for_marker(SIGNAL_READY_MARKER, RELOAD_READY_TIMEOUT);
        let before = occurrences(&self.peek_streams(), RELOAD_MARKER);
        let pid = self._guard.child.id();
        let status = Command::new("kill")
            .args(["-USR1", &pid.to_string()])
            .status()
            .expect("run kill -USR1");
        assert!(status.success(), "kill -USR1 {pid} failed: {status}");
        let deadline = Instant::now() + RELOAD_TIMEOUT;
        while occurrences(&self.peek_streams(), RELOAD_MARKER) < before + expect_extra
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(25));
        }
        std::thread::sleep(SETTLE);
        self.snapshot();
        occurrences(&self.streams(), RELOAD_MARKER)
    }

    /// Both streams concatenated: the reload summaries are `tracing` records,
    /// and this file counts other markers on stdout alone — counting both keeps
    /// this helper independent of which stream `tracing` is wired to.
    #[cfg(unix)]
    fn peek_streams(&self) -> String {
        format!("{}{}", self.peek_stdout(), self.peek_stderr())
    }

    /// The frozen snapshot of both streams. Unix-only, like its only readers:
    /// the SIGUSR1 fan-out pins that count summaries.
    #[cfg(unix)]
    fn streams(&self) -> String {
        format!("{}{}", self.stdout(), self.stderr())
    }

    /// Wait until either stream carries `marker`.
    fn wait_for_marker(&mut self, marker: &str, timeout: Duration) {
        assert!(
            self.wait_for_marker_or_timeout(marker, timeout),
            "frps never logged {marker:?} within {timeout:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.peek_stdout(),
            self.peek_stderr(),
        );
    }

    fn wait_for_marker_or_timeout(&mut self, marker: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.peek_stdout().contains(marker) || self.peek_stderr().contains(marker) {
                return true;
            }
            if let Ok(Some(status)) = self._guard.child.try_wait() {
                panic!(
                    "frps exited ({status}) before {marker:?}\n--- stdout ({} B) ---\n{}\n\
                     --- stderr ({} B) ---\n{}",
                    self.peek_stdout().len(),
                    self.peek_stdout(),
                    self.peek_stderr().len(),
                    self.peek_stderr(),
                );
            }
            if Instant::now() >= deadline {
                return false;
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

    /// `true` while the child is still running. `Ok(None)` is the only
    /// still-running answer; an already-exited child is reaped here and an OS
    /// error means the child is gone too.
    #[cfg(unix)]
    fn is_alive(&mut self) -> bool {
        matches!(self._guard.child.try_wait(), Ok(None))
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

/// Which spelling of the nested TLS section the config uses. The first three all
/// set the flag — `MixedSections` writes the camelCase `[webServer.tls]` beside a
/// snake_case `[web_server]`, and the two sections merge per key — and `None` is
/// the control.
#[derive(Clone, Copy)]
enum Section {
    Nested,
    CommonNested,
    MixedSections,
    None,
}

/// `bind_port` is the only field a `frps` config needs to start; the dashboard
/// section is there because it is what the warning is about.
fn frps_config(bind_port: u16, dashboard_port: u16, section: Section) -> String {
    match section {
        Section::Nested => format!(
            "bind_port = {bind_port}\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\n\
             port = {dashboard_port}\n[web_server.tls]\nenable = true\n"
        ),
        Section::CommonNested => format!(
            "bind_port = {bind_port}\ntoken = \"t\"\n[common.web_server]\naddr = \"127.0.0.1\"\n\
             port = {dashboard_port}\n[common.web_server.tls]\nenable = true\n"
        ),
        Section::MixedSections => format!(
            "bind_port = {bind_port}\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\n\
             port = {dashboard_port}\n[webServer.tls]\nenable = true\n"
        ),
        Section::None => format!(
            "bind_port = {bind_port}\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\n\
             port = {dashboard_port}\n"
        ),
    }
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The shared assertion: one record on **stdout**, none on **stderr**, the
/// binary really did start, and the record is byte-for-byte this build's message
/// — the count plus the clause is not enough, because all three variants share
/// their first half (`web_server.tls.enable has no effect: …`), so an appended
/// clause at the emit site leaves both green.
fn assert_one_warning_on_stdout(tag: &str, spawned: &Spawned) {
    assert_one_warning_on_stdout_for(tag, spawned, KEY);
    assert_web_server_tls_enable_records_are_exactly_the_message(tag, &spawned.stdout(), 1);
    assert_clause_matches_this_build(tag, spawned);
}

/// The clause the emitted record must carry — decided by **this build**, not by
/// a literal argument.
///
/// All three variants share their whole first half (`web_server.tls.enable has no
/// effect: …`), so every count assertion in this file passes for any of them: a
/// call site that hardcodes another answer still compiles, still emits exactly one
/// `KEY` record, and still satisfies `frp-core`'s own dispatch test — that one
/// passes the caller's answer as an argument, so it never sees a real build's
/// answer. Only an assertion on the captured stdout can, and that is what binds
/// `frps/src/main.rs:245`/`:469` (and the reload site,
/// `frp-server/src/service.rs:2333`) to the build under test. The lane that runs
/// this file **without** `--features dashboard` is what makes the no-dashboard
/// direction observable.
///
/// The **no-TLS** clause is unreachable from this binary's lanes: `dashboard`
/// decides the first question, and every lane that runs this file links
/// `frp-server/default`, which includes `tls`. A build with the dashboard on but
/// `tls` off is only linted (`cargo clippy -p frp-server --no-default-features
/// --features dashboard --all-targets`), never run. The negative control below
/// holds that in every combination in which this file is exercised.
fn assert_clause_matches_this_build(tag: &str, spawned: &Spawned) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        !out.contains(NO_TLS_CLAUSE),
        "{tag}: this binary's lanes always link frp-server's `tls` feature, so it must never emit \
         the no-TLS clause ({NO_TLS_CLAUSE:?})\n--- stdout ---\n{out}"
    );
    if cfg!(feature = "dashboard") {
        assert!(
            out.contains(DASHBOARD_CLAUSE),
            "{tag}: a build that compiles a dashboard must keep the dashboard clause \
             ({DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
        );
        assert!(
            !out.contains(NO_DASHBOARD_CLAUSE),
            "{tag}: a build that compiles a dashboard must not claim it has no dashboard \
             support ({NO_DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
        );
    } else {
        assert!(
            out.contains(NO_DASHBOARD_CLAUSE),
            "{tag}: a build with no dashboard must name its own build fact rather than the \
             dashboard's ({NO_DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
        );
        assert!(
            !out.contains(DASHBOARD_CLAUSE),
            "{tag}: a build with no dashboard must not describe the dashboard's TLS \
             ({DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
        );
    }
}

/// [`assert_one_warning_on_stdout`] for an arbitrary key, so the flat server
/// `tls_enable` diagnostic can reuse the same checks instead of a second copy
/// that could drift from them.
fn assert_one_warning_on_stdout_for(tag: &str, spawned: &Spawned, key: &str) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(STARTUP_MARKER),
        "{tag}: no startup line, so this shape never reached `init_logging`\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(
        occurrences(&out, key),
        1,
        "{tag}: expected exactly 1 `{key}` record on stdout (console sink)\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(
        occurrences(&err, key),
        0,
        "{tag}: the console sink is stdout; stderr must carry none\n--- stderr ---\n{err}"
    );
}

// ── Byte pinning for the flat server `tls_enable` record ─────────────────────
//
// The `frp-core` captures pin their emitted record byte-for-byte
// (`assert_record_is_exactly_the_message`, `frp-core/tests/common/mod.rs`), but
// this file's `SERVER_KEY` captures only **counted** it. Appending a clause at
// the emit site (`frp-core/src/config/loader.rs`,
// `tracing::warn!("{} but honestly", SERVER_TLS_ENABLE_INERT_WARNING.as_str())`)
// therefore left `cargo test -p frps --test warn_delivery` green while the
// `frp-core` lane reddened — the server-visible line could drift unnoticed.
//
// The helpers below are a **local port** of that pin. The shared helper cannot
// be `use`d from here: an integration test reaches another crate's public
// library surface, not its `tests/` tree, and nothing outside both crates can
// hold the single copy without adding a dependency (banned by the repo's
// dependency policy). Keep this copy in step with
// `frp-core/tests/common/mod.rs`; the only difference is how the record is
// obtained — one **line of the spawned binary's stdout**, which also carries a
// timestamp, rather than a single-record in-process capture.

/// The `tracing` target of the server `tls_enable` emit site
/// (`frp-core/src/config/loader.rs`, `warn_inert_server_tls_enable`) — the
/// module path `tracing::warn!` records there. Identical for this binary's
/// console sink and for `frp-core`'s own captures.
const WARNING_TARGET: &str = "frp_core::config::loader";

/// Drop well-formed ANSI SGR sequences (`ESC [ <digits and ';'> m`) from a
/// captured record, copying every other byte through unchanged. Port of the
/// helper of the same name in `frp-core/tests/common/mod.rs`; needed here
/// because `frps` turns colour **on** by default (`--disable-log-color` is what
/// turns it off, `frp-core/src/logging.rs::resolve_ansi`), so the console
/// sink's level and target carry SGR even when stdout is a pipe.
fn strip_sgr(record: &str) -> String {
    let bytes = record.as_bytes();
    let mut out = String::with_capacity(record.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'[') {
            let mut j = i + 2;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b';') {
                j += 1;
            }
            if bytes.get(j) == Some(&b'm') {
                i = j + 1;
                continue;
            }
        }
        let ch = record[i..]
            .chars()
            .next()
            .expect("i stays on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The emitted record must be the one-line `tracing` prefix followed by `want`
/// and **nothing else** but an optional trailing newline. Port of
/// `assert_record_is_exactly_the_message` (`frp-core/tests/common/mod.rs`), with
/// the same four rejections:
///
/// * the message appears zero or twice, or is a different message;
/// * bytes appended after the message — the `"{} but honestly"` mutant this
///   file was missing;
/// * a literal injected between the target and the message;
/// * the target rewritten to a longer key that ends in the expected one
///   (`target: "evil {target}"`), or prefixed with whitespace
///   (`target: " {target}"`), which leaves extra bytes in the level field.
///
/// Unlike the `frp-core` captures, the record here carries a `tracing_subscriber`
/// timestamp before the level. That field is validated and stripped first, and
/// the level is then compared with the shared helper's **untrimmed**
/// `assert_eq!(level, " WARN")`; the previous `level.contains("WARN")` passed
/// both rewrites above.
fn assert_record_is_exactly_the_message(tag: &str, record: &str, want: &str, target: &str) {
    let clean = strip_sgr(record);
    assert!(
        clean.contains(want),
        "{tag}: the record must carry the message; got raw record: {record:?}"
    );
    assert_eq!(
        clean.match_indices(want).count(),
        1,
        "{tag}: the message must appear exactly once in the record; got raw record: {record:?}"
    );
    let at = clean.find(want).expect("checked just above");
    let prefix = &clean[..at];
    let tail = &clean[at + want.len()..];
    assert!(
        tail.is_empty() || tail == "\n",
        "{tag}: the emit site appended bytes after the message (only a trailing newline is \
         allowed); got tail: {tail:?} from raw record: {record:?}"
    );
    let anchor = format!(" {target}: ");
    assert_eq!(
        prefix.matches(&anchor).count(),
        1,
        "{tag}: the tracing prefix must carry the target `{target}: ` exactly once (SGR stripped); \
         got prefix: {prefix:?} from raw record: {record:?}"
    );
    assert!(
        prefix.ends_with(&anchor),
        "{tag}: the emit site inserted bytes between the tracing prefix and the message; the \
         prefix must end with {anchor:?} (SGR stripped), got prefix: {prefix:?} from raw record: \
         {record:?}"
    );
    let mut fields = prefix[..prefix.len() - anchor.len()].splitn(2, ' ');
    let stamp = fields.next().expect("prefix is non-empty");
    let level = fields.next().unwrap_or("");
    assert!(
        is_tracing_timestamp(stamp),
        "{tag}: the record must begin with the `tracing_subscriber` timestamp, which is the only \
         field this port strips before comparing the level; got: {stamp:?} from raw record: \
         {record:?}"
    );
    assert_eq!(
        level, " WARN",
        "{tag}: only the tracing level may precede the target, and it must be exactly `\" WARN\"` \
         (compared untrimmed, as the shared helper does); got level: {level:?} from raw record: \
         {record:?}"
    );
}

/// Is `field` a `tracing_subscriber` timestamp? The default `SystemTime` timer
/// prints `YYYY-MM-DDTHH:MM:SS[.fraction]Z`. The `frp-core` lane has no
/// timestamp to validate (it captures one in-process record), so this port
/// checks the field it strips rather than letting a rewritten prefix smuggle
/// bytes past the level comparison above.
fn is_tracing_timestamp(field: &str) -> bool {
    let Some(body) = field.strip_suffix('Z') else {
        return false;
    };
    let (secs, frac) = match body.split_once('.') {
        Some((secs, frac)) => (secs, Some(frac)),
        None => (body, None),
    };
    if secs.len() != 19 {
        return false;
    }
    let bytes = secs.as_bytes();
    if !(bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':')
    {
        return false;
    }
    if !secs
        .bytes()
        .enumerate()
        .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit())
    {
        return false;
    }
    match frac {
        None => true,
        Some(frac) => {
            !frac.is_empty() && frac.len() <= 9 && frac.bytes().all(|c| c.is_ascii_digit())
        }
    }
}

/// Slice every occurrence of `want` out of an SGR-stripped capture as the record
/// the emit site produced: the whole line from its start through its terminating
/// newline, **plus any further newlines the emit appended**, so a bare extra
/// newline lands in the record and the helper's `tail == "\n"` guard stays live.
/// `clean.lines()` cannot express that — it drops the terminator — and it
/// silently discards an appended non-record line. The second half of each pair
/// is what follows the record, so the caller can require a fresh record (or the
/// end of the capture) there.
fn records_containing<'a>(clean: &'a str, want: &str) -> Vec<(&'a str, &'a str)> {
    let mut found = Vec::new();
    let mut search = 0;
    while let Some(offset) = clean[search..].find(want) {
        let at = search + offset;
        let start = clean[..at].rfind('\n').map_or(0, |i| i + 1);
        let line_end = clean[at..].find('\n').map_or(clean.len(), |i| at + i);
        let mut end = line_end;
        while end < clean.len() && clean.as_bytes()[end] == b'\n' {
            end += 1;
        }
        found.push((&clean[start..end], &clean[end..]));
        search = end.max(at + want.len());
    }
    found
}

/// Does `rest` — the text after a record — begin a fresh `tracing_subscriber`
/// record? A `warn!("{}\nEXTRA", …)` mutant appends a following line that is not
/// one, so this is the "no following line" half of the shared helper's
/// `tail.is_empty() || tail == "\n"` guard, made reachable for a line-oriented
/// capture.
fn starts_a_fresh_tracing_record(rest: &str) -> bool {
    let Some((stamp, after)) = rest.split_once(' ') else {
        return false;
    };
    is_tracing_timestamp(stamp)
        && ["ERROR ", " WARN ", " INFO ", "DEBUG ", "TRACE "]
            .iter()
            .any(|level| after.starts_with(level))
}

/// Byte-pin every stdout record carrying `want`: there must be exactly
/// `expected` of them, each must be the message with the one-line `tracing`
/// prefix, and nothing may follow a record but a fresh record or the end of the
/// capture.
fn assert_records_are_exactly_the_message(tag: &str, out: &str, want: &str, expected: usize) {
    let clean = strip_sgr(out);
    let records = records_containing(&clean, want);
    assert_eq!(
        records.len(),
        expected,
        "{tag}: expected {expected} record(s) carrying `{want}`, found {}\n--- stdout ---\n{out}",
        records.len()
    );
    for (i, (record, rest)) in records.iter().enumerate() {
        assert_record_is_exactly_the_message(
            &format!("{tag} (record {} of {expected})", i + 1),
            record,
            want,
            WARNING_TARGET,
        );
        assert!(
            rest.is_empty() || starts_a_fresh_tracing_record(rest),
            "{tag} (record {} of {expected}): the emit site appended a following line — the bytes \
             after the record must begin a fresh tracing record or end the capture; got {:?}",
            i + 1,
            rest.chars().take(120).collect::<String>()
        );
    }
}

/// Byte-pin every stdout line carrying the server `tls_enable` message: there
/// must be exactly `expected` of them, and each must be the message with the
/// one-line `tracing` prefix and no other bytes.
///
/// `expected` mirrors the caller's occurrence count, so this **can stand in
/// for** the count-only assertion rather than being a second, independently
/// driftable check: the wrapper below uses it that way, and the reload test
/// asserts the same count through both so the "one per load" intent stays
/// explicit.
fn assert_server_tls_enable_records_are_exactly_the_message(tag: &str, out: &str, expected: usize) {
    assert_records_are_exactly_the_message(
        tag,
        out,
        frp_core::config::SERVER_TLS_ENABLE_INERT_WARNING.as_str(),
        expected,
    );
}

/// [`assert_server_tls_enable_records_are_exactly_the_message`] for the dashboard
/// `web_server.tls.enable` diagnostic. The expected text is the clause **this
/// build** answers with, selected exactly as [`assert_clause_matches_this_build`]
/// selects it, so a build whose reader answers the other way is pinned to the
/// other message instead of passing on the clause the three variants share.
fn assert_web_server_tls_enable_records_are_exactly_the_message(
    tag: &str,
    out: &str,
    expected: usize,
) {
    let want = if cfg!(feature = "dashboard") {
        frp_core::config::WEB_SERVER_TLS_ENABLE_INERT_WARNING
    } else {
        frp_core::config::WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD
    };
    assert_records_are_exactly_the_message(tag, out, want, expected);
}

/// [`assert_one_warning_on_stdout_for`] for the flat server `tls_enable`
/// diagnostic: exactly one record, and its bytes are pinned to the message.
fn assert_one_server_tls_enable_warning(tag: &str, spawned: &Spawned) {
    assert_one_warning_on_stdout_for(tag, spawned, SERVER_KEY);
    assert_server_tls_enable_records_are_exactly_the_message(tag, &spawned.stdout(), 1);
}

/// The shared "no record at all" assertion, with the startup line still there so
/// the silence is a decision and not a failed run. The byte-pin runs with
/// `expected = 0` so the silence is stated in the same terms as the presence
/// rows: no variant of this build's message, anywhere in the capture.
fn assert_no_warning(tag: &str, spawned: &Spawned) {
    assert_no_warning_for(tag, spawned, KEY);
    assert_web_server_tls_enable_records_are_exactly_the_message(tag, &spawned.stdout(), 0);
}

/// [`assert_no_warning`] for an arbitrary key.
fn assert_no_warning_for(tag: &str, spawned: &Spawned, key: &str) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(STARTUP_MARKER),
        "{tag}: no startup line\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
    );
    assert_eq!(occurrences(&out, key), 0, "{tag}: stdout:\n{out}");
    assert_eq!(occurrences(&err, key), 0, "{tag}: stderr:\n{err}");
}

/// A `frps` config that writes the **flat** server `tls_enable` (the frp-rs-only
/// field), or the legacy `[transport.tls]` shapes that *synthesize* it.
#[derive(Clone, Copy)]
enum ServerTls {
    /// `tls_enable = true` — written, inert, warns.
    WrittenTrue,
    /// `tls_enable = false` — written, inert, warns the same way.
    WrittenFalse,
    /// `[common] tls_enable = true` — written, reached through the flatten.
    CommonWritten,
    /// `[transport.tls] force = true` — synthesizes `tls_enable = true` plus the
    /// real switch `tls_only`; **not** written, so it must stay silent.
    SynthesizedForce,
}

fn frps_config_server_tls(bind_port: u16, shape: ServerTls) -> String {
    let head = format!("bind_port = {bind_port}\ntoken = \"t\"\n");
    match shape {
        ServerTls::WrittenTrue => format!("{head}tls_enable = true\n"),
        ServerTls::WrittenFalse => format!("{head}tls_enable = false\n"),
        ServerTls::CommonWritten => format!("{head}[common]\ntls_enable = true\n"),
        ServerTls::SynthesizedForce => format!("{head}[transport.tls]\nforce = true\n"),
    }
}

#[test]
fn web_server_tls_enable_warning_reaches_a_dash_c_user() {
    let dir = TempDir::new("dashc");
    let port = free_port();
    let cfg = frps_config(port, free_port(), Section::Nested);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout("frps -c", &spawned);

    // Liveness oracle for the same shape: the pre-change binary **did** bind, so
    // "it warned nothing" is the defect, not "it died". A regression that stops
    // the listener coming up must fail here. (A plain TCP connect that is closed
    // immediately appends a `Failed to detect connection type … early eof`
    // record — never the warning — and this runs after the snapshot.)
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "nothing accepted a TCP connection on 127.0.0.1:{port} within {READY_TIMEOUT:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn web_server_tls_enable_warning_reaches_a_config_dir_user() {
    let dir = TempDir::new("cfgdir");
    let cfg = frps_config(free_port(), free_port(), Section::Nested);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frps.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);
    assert_one_warning_on_stdout("frps --config-dir", &spawned);
}

/// The `[common]` spelling: `[common]` is flattened onto the top level before the
/// hoist, so the key reaches the same removal site. The detector has to mirror
/// that flatten, or this path is silent — which is exactly what the first round
/// shipped (measured 0 on `--config-dir`, where the base binary emitted 1).
#[test]
fn web_server_tls_enable_warning_reaches_a_dash_c_user_with_the_common_spelling() {
    let dir = TempDir::new("dashc-common");
    let cfg = frps_config(free_port(), free_port(), Section::CommonNested);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout("frps -c ([common] spelling)", &spawned);
}

#[test]
fn web_server_tls_enable_warning_reaches_a_config_dir_user_with_the_common_spelling() {
    let dir = TempDir::new("cfgdir-common");
    let cfg = frps_config(free_port(), free_port(), Section::CommonNested);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frps.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);
    assert_one_warning_on_stdout("frps --config-dir ([common] spelling)", &spawned);
}

/// The `--config-dir` lane installs the **same** SIGUSR1 handler as `-c`, so the
/// signal reloads every service built from the directory instead of killing the
/// process. The defect this pins was a hard exit: on the base binary a
/// `--config-dir` process that had logged its startup line died on `SIGUSR1`
/// with `unix_wait_status(158)` (`128+30`, shell message "User defined signal
/// 1: 30") and logged no summary.
///
/// The config is left **unchanged** across the signal, so the summary's wording
/// (`config reloaded: no changes detected`) is not what is asserted — only that
/// a summary arrived, i.e. that `Service::reload` ran on a process that is still
/// alive afterwards.
#[cfg(unix)]
#[test]
fn a_config_dir_process_survives_sigusr1_and_reloads() {
    let dir = TempDir::new("cfgdir-reload");
    let cfg = frps_config(free_port(), free_port(), Section::Nested);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frps.toml"), &cfg).expect("write config");
    let mut spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);

    assert!(
        spawned.sigusr1_and_reload(),
        "the --config-dir reload never logged {RELOAD_MARKER:?}\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert!(
        spawned.is_alive(),
        "frps --config-dir must survive SIGUSR1, not take its default disposition\n\
         --- stdout ---\n{}",
        spawned.stdout()
    );
}

/// The fan-out pin: one `--config-dir` holding **two** config files, one
/// signal — two reload summaries, and two more on the next signal. A regression
/// that reloaded only `svcs.first()` (or dropped a registry entry) leaves the
/// single-file test above green, so the count is the guard here. Reviewer 1
/// measured the same shape by hand with two and three services
/// (`summaries=2` after one signal, `4` after two; `3`/`6` with three) and the
/// wording is byte-identical to `-c` (`SIGUSR1: config reloaded: no changes
/// detected`), which the single-config pins already assert.
#[cfg(unix)]
#[test]
fn a_config_dir_sigusr1_reloads_every_service() {
    let dir = TempDir::new("cfgdir-fanout");
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    // Distinct ports per service — the default config binds each file's own
    // `bindPort`, and two files sharing one port would fail one of them at
    // startup rather than test the fan-out.
    for name in ["a.toml", "b.toml"] {
        let cfg = frps_config(free_port(), free_port(), Section::Nested);
        std::fs::write(sub.join(name), &cfg).expect("write config");
    }
    let mut spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);

    let after_one = spawned.sigusr1_and_wait_for_reloads(2);
    assert_eq!(
        after_one,
        2,
        "one signal must reload both services (two summary lines), not just the first\n\
         --- stdout ---\n{}",
        spawned.stdout()
    );
    let after_two = spawned.sigusr1_and_wait_for_reloads(2);
    assert_eq!(
        after_two,
        4,
        "a second signal must reload both again (four summaries total)\n\
         --- stdout ---\n{}",
        spawned.stdout()
    );
    assert!(
        spawned.is_alive(),
        "frps --config-dir must survive repeated SIGUSR1\n--- stdout ---\n{}",
        spawned.stdout()
    );
}

/// The registry must not keep counting a **dead** task: one file's task panics
/// (the debug-only `FRPS_CFGDIR_TEST_PANIC` hook, which panics *after* the task
/// registered) while the other three serve, and a later SIGUSR1 must report
/// `3 of 3`, not `4 of 4`.
///
/// The removal used to live in `Service::run`'s error arm
/// (`frps/src/main.rs`), which a panicking task never reaches — it unwinds past
/// it — so the dead service stayed registered and the fan-out line counted it
/// (`reloaded 4 of 4`, measured by reviewer 1). Registration now arms a drop
/// guard (`DirRegistryEntry`) and unwinding runs it.
///
/// The signal is re-sent in a bounded loop because the panic hook runs *before*
/// unwinding: a signal racing the unwind could still see the dead entry. Every
/// later signal sees the fix and the mutant never does, so the loop is the
/// deterministic form — it cannot pass without the guard and cannot flake with
/// it.
#[cfg(unix)]
#[test]
fn a_config_dir_sigusr1_does_not_count_a_panicking_service() {
    const FILES: usize = 4;
    const LIVE: usize = FILES - 1;
    let dir = TempDir::new("cfgdir-panic-fanout");
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    let mut doomed = PathBuf::new();
    for name in ["a.toml", "b.toml", "c.toml", "d.toml"] {
        let path = sub.join(name);
        let cfg = frps_config(free_port(), free_port(), Section::Nested);
        std::fs::write(&path, &cfg).expect("write config");
        if name == "d.toml" {
            doomed = path;
        }
    }
    let mut spawned = Spawned::spawn(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        &[("FRPS_CFGDIR_TEST_PANIC", doomed.to_str().unwrap())],
    );

    let fan_out = format!("SIGUSR1 fan-out: reloaded {LIVE} of {LIVE} services");
    let mut seen = false;
    for _ in 0..10 {
        if spawned.sigusr1_and_reload() && spawned.streams().contains(&fan_out) {
            seen = true;
            break;
        }
    }
    assert!(
        seen,
        "a panicking task must leave the registry, so the fan-out line must be \
         {fan_out:?} (never `4 of 4`) within ten signals\n--- stdout ---\n{}\n\
         --- stderr ---\n{}",
        spawned.stdout(),
        spawned.stderr(),
    );
}

/// The registration-order pin. `SIGUSR1` is installed **before** the services
/// are spawned — that is what keeps an early signal from killing the process —
/// but the "reload ready" line must not be printed until every spawned task has
/// pushed itself into the registry, or a signal sent right after it reloads
/// only the registered subset. The measured window (delay 0: `12` files →
/// `10/12` summaries once in four runs, `40` files → `39/40` twice in four;
/// clean at `0.3 s`) is exactly that subset.
///
/// The debug-only `FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS` hook holds the
/// pre-registration window open deterministically: each task sleeps after
/// construction and before registering, so with the barrier in place the ready
/// marker cannot appear for ~1.2 s, and the fan-out line must name **every**
/// file. Without the barrier the marker appears at once, the signal lands on an
/// empty registry, and the count collapses to `0` — which is what this asserts
/// against. The `> 800 ms` lower bound is the same gate seen from the timing
/// side; slowness only widens it, so it cannot flake.
#[cfg(unix)]
#[test]
fn a_config_dir_sigusr1_immediately_after_the_ready_marker_reloads_everything() {
    const FILES: usize = 4;
    const DELAY_MS: &str = "1200";
    let dir = TempDir::new("cfgdir-prereg");
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    for name in ["a.toml", "b.toml", "c.toml", "d.toml"] {
        let cfg = frps_config(free_port(), free_port(), Section::Nested);
        std::fs::write(sub.join(name), &cfg).expect("write config");
    }
    let mut spawned = Spawned::spawn(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        &[("FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS", DELAY_MS)],
    );

    let start = Instant::now();
    spawned.wait_for_marker(SIGNAL_READY_MARKER, RELOAD_READY_TIMEOUT);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(800),
        "the ready marker must be gated on registration completing: every task was \
         still sleeping its {DELAY_MS} ms pre-registration delay when the marker \
         appeared after only {elapsed:?}\n--- stdout ---\n{}",
        spawned.stdout()
    );

    let total = spawned.sigusr1_and_wait_for_reloads(FILES);
    assert_eq!(
        total,
        FILES,
        "a signal sent immediately after the ready marker must reload all {FILES} \
         services, not the registered subset\n--- stdout ---\n{}",
        spawned.stdout()
    );
    let fan_out = format!("SIGUSR1 fan-out: reloaded {FILES} of {FILES} services");
    assert!(
        spawned.streams().contains(&fan_out),
        "the reload must report the full fan-out ({fan_out:?})\n--- stdout ---\n{}",
        spawned.stdout()
    );
}

/// The file set is fixed at startup, and this pins that as deliberate: the
/// directory is read **once** (`collect_config_files`) and the registry only
/// ever holds the files that constructed at startup.
///
/// Three legs, one signal each: a file added after startup is never loaded; a
/// file whose construction failed is never retried; a file removed on disk
/// keeps its service running (its reload now fails loudly, exactly the measured
/// `SIGUSR1 reload: Failed to reload config: <path>: failed to read config file:
/// No such file or directory (os error 2)`) while its listener still accepts.
/// `c.toml` has no `[auth].token`, so it fails construction and is the
/// never-retried leg. Option B — rescan and retry on every signal — would make
/// all three assertions move; the code comment above the read in
/// `frps/src/main.rs` states the choice.
#[cfg(unix)]
#[test]
fn a_config_dir_reload_keeps_the_startup_file_set() {
    let dir = TempDir::new("cfgdir-fileset");
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    let port_a = free_port();
    std::fs::write(
        sub.join("a.toml"),
        frps_config(port_a, free_port(), Section::Nested),
    )
    .expect("write a.toml");
    std::fs::write(
        sub.join("b.toml"),
        frps_config(free_port(), free_port(), Section::Nested),
    )
    .expect("write b.toml");
    // Construction failure: no `[auth].token`. Never becomes a service.
    std::fs::write(
        sub.join("c.toml"),
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {}\n", free_port()),
    )
    .expect("write c.toml");
    let mut spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);

    let first = spawned.sigusr1_and_wait_for_reloads(2);
    assert_eq!(
        first,
        2,
        "only the two files that constructed at startup are in the registry — \
         c.toml failed construction and is never served\n--- stdout ---\n{}",
        spawned.stdout()
    );

    std::fs::write(
        sub.join("d.toml"),
        frps_config(free_port(), free_port(), Section::Nested),
    )
    .expect("write d.toml");
    let second = spawned.sigusr1_and_wait_for_reloads(2);
    assert_eq!(
        second,
        4,
        "a file added after startup is never loaded: the reload re-reads the \
         startup set, not the directory\n--- stdout ---\n{}",
        spawned.stdout()
    );

    std::fs::remove_file(sub.join("a.toml")).expect("remove a.toml");
    let third = spawned.sigusr1_and_wait_for_reloads(1);
    assert_eq!(
        third,
        5,
        "a.toml was removed on disk: its service keeps running but its reload now \
         fails (no summary), while b.toml still reloads — one more summary only\n\
         --- stdout ---\n{}",
        spawned.stdout()
    );
    assert!(
        spawned.streams().contains("No such file or directory"),
        "the removed file's reload must fail loudly, not silently\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert!(
        spawned.is_alive(),
        "the process must keep serving after a file disappears\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert!(
        TcpStream::connect(("127.0.0.1", port_a)).is_ok(),
        "the removed file's listener must still be accepting on {port_a}\n--- stdout ---\n{}",
        spawned.stdout()
    );
}

/// The reload is an in-process load with the sink already installed, so it gets
/// its **own** record — one per load, on top of the one the startup emitted. The
/// loader cannot supply it (it is silent on every path), so the reload site
/// emits it; without that, the base binary's record (measured +1 in the reload
/// window) is lost, and `enable` has no field for the reload summary to report.
#[cfg(unix)]
#[test]
fn a_sigusr1_reload_delivers_the_warning_again() {
    let dir = TempDir::new("reload");
    let cfg = frps_config(free_port(), free_port(), Section::CommonNested);
    let path = dir.write("frps.toml", &cfg);
    let mut spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_eq!(
        occurrences(&spawned.stdout(), KEY),
        1,
        "startup: one record\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert_web_server_tls_enable_records_are_exactly_the_message(
        "frps reload (startup)",
        &spawned.stdout(),
        1,
    );

    assert!(
        spawned.sigusr1_and_reload(),
        "the reload never logged {RELOAD_MARKER:?}\n--- stdout ---\n{}",
        spawned.stdout()
    );
    let out = spawned.stdout();
    assert_eq!(
        occurrences(&out, KEY),
        2,
        "startup + reload = exactly 2 records, one per load\n--- stdout ---\n{out}"
    );
    assert_eq!(occurrences(&spawned.stderr(), KEY), 0);
    assert_web_server_tls_enable_records_are_exactly_the_message(
        "frps reload (startup + reload)",
        &out,
        2,
    );
    assert_clause_matches_this_build("frps reload", &spawned);
}

/// Negative control: without the key there is no record on either stream, so the
/// warning is presence-driven and not an unconditional startup line.
#[test]
fn no_warning_for_a_config_without_the_key() {
    let dir = TempDir::new("nokey");
    let cfg = frps_config(free_port(), free_port(), Section::None);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_no_warning("frps -c (no key)", &spawned);
}

/// The mixed-sections shape **does** warn: `[webServer]` and `[web_server]` are
/// the same section, merged per key, so the camelCase `[webServer.tls]` table
/// reaches the removal site and the key is delivered like any other nested
/// spelling. (Before the merge, a top-level `[web_server]` discarded the whole
/// `[webServer]` table — nested `tls` included — and this test pinned the
/// silence; the detector mirrored the discard on purpose, because reporting a
/// key the loader dropped would have been a false claim. The detector now
/// mirrors the per-key merge, which is the invariant: it must neither claim a
/// dropped key nor miss a kept one.)
#[test]
fn warning_when_the_camelcase_tls_table_is_merged_into_the_snake_section() {
    let dir = TempDir::new("mixed");
    let cfg = frps_config(free_port(), free_port(), Section::MixedSections);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout("frps -c (mixed sections)", &spawned);
}

// ---------------------------------------------------------------------------
// The flat server `tls_enable` diagnostic.
//
// Distinct key, distinct field, and a distinct failure mode from the dashboard
// message above: `ServerConfig::tls_enable` is parsed but read by nothing, so a
// user who writes it gets no effect and — before this round — no signal either.
// The same three sink-bearing server paths emit it: `frps -c`, `frps
// --config-dir`, and `Service::reload`. `frps verify` stays silent (no
// subscriber). No `frpc` site emits it: those load `ClientConfig`, where
// `tls_enable` is live.
//
// The negative control is not "no key" but "a key the user did **not** write":
// the legacy `[transport.tls]` section synthesizes `tls_enable = true`, and
// warning there would be a false claim about a Go-shaped input the user wrote.
// ---------------------------------------------------------------------------

/// Written `tls_enable = true`, `-c`: one record on stdout, and **zero**
/// occurrences of the dashboard key, so the two diagnostics cannot be confused.
#[test]
fn server_tls_enable_warning_reaches_a_dash_c_user() {
    let dir = TempDir::new("srv-dashc");
    let port = free_port();
    let cfg = frps_config_server_tls(port, ServerTls::WrittenTrue);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_server_tls_enable_warning("frps -c (tls_enable = true)", &spawned);
    assert_eq!(
        occurrences(&spawned.stdout(), KEY),
        0,
        "the dashboard key was not written, so its diagnostic must not fire\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert_web_server_tls_enable_records_are_exactly_the_message(
        "frps -c (dashboard key not written)",
        &spawned.stdout(),
        0,
    );
}

/// The same key reached through the `[common]` flatten, on both startup paths.
#[test]
fn server_tls_enable_warning_reaches_a_config_dir_user_with_the_common_spelling() {
    let dir = TempDir::new("srv-cfgdir-common");
    let cfg = frps_config_server_tls(free_port(), ServerTls::CommonWritten);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frps.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);
    assert_one_server_tls_enable_warning("frps --config-dir ([common] tls_enable)", &spawned);

    let dir = TempDir::new("srv-dashc-common");
    let cfg = frps_config_server_tls(free_port(), ServerTls::CommonWritten);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_server_tls_enable_warning("frps -c ([common] tls_enable)", &spawned);
}

/// `tls_enable = false` is just as inert as `true`, and just as likely to be
/// believed — a value gate would hide exactly this case.
#[test]
fn server_tls_enable_warning_reaches_a_dash_c_user_for_a_written_false() {
    let dir = TempDir::new("srv-false");
    let cfg = frps_config_server_tls(free_port(), ServerTls::WrittenFalse);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_server_tls_enable_warning("frps -c (tls_enable = false)", &spawned);
}

/// Negative control: `[transport.tls] force = true` **synthesizes**
/// `tls_enable = true` inside the normalizer. The user never wrote the flat key,
/// so the warning must not fire — even though the field ends up `true`.
#[test]
fn no_server_tls_enable_warning_when_it_was_synthesized_from_transport_tls() {
    let dir = TempDir::new("srv-synth");
    let cfg = frps_config_server_tls(free_port(), ServerTls::SynthesizedForce);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_no_warning_for("frps -c (synthesized)", &spawned, SERVER_KEY);
    assert_eq!(
        occurrences(&spawned.stdout(), KEY),
        0,
        "no dashboard key either\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert_web_server_tls_enable_records_are_exactly_the_message(
        "frps -c (synthesized tls_enable)",
        &spawned.stdout(),
        0,
    );
}

/// The reload is a second in-process load with the sink already installed, so it
/// adds its own record: startup 1, reload 2. One per load.
#[cfg(unix)]
#[test]
fn a_sigusr1_reload_delivers_the_server_tls_enable_warning_again() {
    let dir = TempDir::new("srv-reload");
    let cfg = frps_config_server_tls(free_port(), ServerTls::WrittenTrue);
    let path = dir.write("frps.toml", &cfg);
    let mut spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_eq!(
        occurrences(&spawned.stdout(), SERVER_KEY),
        1,
        "startup: one record\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert_server_tls_enable_records_are_exactly_the_message(
        "startup (tls_enable = true)",
        &spawned.stdout(),
        1,
    );

    assert!(
        spawned.sigusr1_and_reload(),
        "the reload never logged {RELOAD_MARKER:?}\n--- stdout ---\n{}",
        spawned.stdout()
    );
    let out = spawned.stdout();
    assert_eq!(
        occurrences(&out, SERVER_KEY),
        2,
        "startup + reload = exactly 2 records, one per load\n--- stdout ---\n{out}"
    );
    assert_server_tls_enable_records_are_exactly_the_message(
        "startup + SIGUSR1 reload (tls_enable = true)",
        &out,
        2,
    );
    assert_eq!(occurrences(&spawned.stderr(), SERVER_KEY), 0);
}
