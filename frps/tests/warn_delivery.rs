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
//! post-`init_logging` startup line. The count is exact in both directions:
//! `assert_records_are_exactly_the_message` pins the **total** `tracing` record
//! count of the capture (the expected warnings plus a measured boot baseline),
//! so a record emitted beyond the counted ones — appended after the warning or
//! emitted ahead of it — reds, and every counted record is byte-pinned to the
//! message. What is **not** pinned is the text of the other (boot) records, only
//! their number; the warning's own text is pinned here and in
//! `frp-core/tests/web_server_tls_enable_warning.rs`.
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
//!
//! [`drain`] distinguishes a read error from EOF, as the sibling
//! `frpc/tests/warn_delivery.rs` one does: `Ok(0)` ends the capture,
//! `ErrorKind::Interrupted` retries, and any other error is recorded so the
//! readers can refuse to treat the truncated buffer as final. The shape differs
//! — `frpc` joins its readers after the child exits, while this harness reads
//! the pipes of a **live** child, so the error is parked instead of joined —
//! and [`mod drain_tests`] pins both the recording and the refusal directly,
//! because no `frps` pipe in these tests ever fails.

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
/// [`Spawned::wait_for_capture_convergence`] uses it as the **quiet period**:
/// the capture is frozen once its record count has held still this long.
const SETTLE: Duration = Duration::from_millis(600);
/// How long `records_emitted_after_the_snapshot_never_reach_the_capture` watches
/// the live buffer after the freeze, sized to cover the adversarial's `+3 s`
/// duplicate. One row, not every row: see that test's docs.
const LATE_WINDOW: Duration = Duration::from_millis(3500);
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

/// How many `tracing` records a running `frps` emits on stdout **beside** the
/// diagnostic a row counts, at the moment [`Spawned::run`] snapshots it: the
/// baseline the total-record pin in [`assert_records_are_exactly_the_message`]
/// adds to its expected count.
///
/// Measured (not derived) from this harness — not from a short-lived probe: the
/// debug binary started with each test's own config, its stdout read to the
/// point [`Spawned::run`] freezes it, and the `tracing` records listed. The
/// count depends on **two** things, which is why the accessors below are
/// functions rather than one constant:
///
/// * the config's **shape** — a config that writes `[web_server]` (every
///   `frps_config` shape) gets three dashboard records in a build that compiles
///   the feature (`Dashboard web UI starting on …`, `Dashboard: no admin auth
///   configured …`, `Dashboard listening on …`); one that does not (every
///   `frps_config_server_tls` shape) gets none. The seven shared records are
///   `frps (Rust) v0.71.0 starting...`, `no existing store file, starting
///   fresh`, `frps starting on …`, `No TLS cert files configured —
///   auto-generating …`, `SIGUSR1 reload ready`, `TLS enabled with
///   auto-generated …`, `frps listener started on …`; the warning a row counts
///   is one more (first on `-c`; on `--config-dir` second, after the `starting 1
///   services from config directory` line that replaces nothing).
/// * the **features compiled in** — `profiling` adds one record (the SIGUSR2
///   handler's `SIGUSR2 profiling ready (pid=…)`, `frps/src/main.rs`), so every
///   shape is one higher under `--all-features`.
///
/// This is a boot baseline, not an invariant of the product: a change to the
/// startup log set moves it, and the count assertion reds with the actual total
/// and both addends in the message. That is the point — the set was previously
/// uncounted, so an emit-site mutant that appended a **second well-formed
/// `warn!`** left the whole lane green.
const BOOT_RECORDS_BASE: usize = 7;
/// The extra records a build that compiles `profiling` emits: the SIGUSR2
/// handler's ready record (measured once per process, in every shape).
#[cfg(feature = "profiling")]
const PROFILING_EXTRA: usize = 1;
#[cfg(not(feature = "profiling"))]
const PROFILING_EXTRA: usize = 0;
/// The extra records a config that writes `[web_server]` gets from a build that
/// compiles the dashboard.
#[cfg(feature = "dashboard")]
const DASHBOARD_EXTRA: usize = 3;
#[cfg(not(feature = "dashboard"))]
const DASHBOARD_EXTRA: usize = 0;
/// The records a SIGUSR1 reload adds on the single-config `-c` path when the
/// config is unchanged: `main.rs` logs `SIGUSR1: config reloaded: no changes
/// detected`. The re-emitted diagnostic a reload row counts is its own extra
/// `want`, so it is not in here. Measured with the same harness run (the flat
/// lane: its capture totals 8 before the signal and 9 after).
const RELOAD_EXTRA_RECORDS: usize = 1;

/// The `-c` boot baseline for tests whose config writes **no** `[web_server]`
/// section (`frps_config_server_tls` shapes).
fn boot_records_no_dashboard() -> usize {
    BOOT_RECORDS_BASE + PROFILING_EXTRA
}

/// The `-c` boot baseline for tests whose config writes `[web_server]`: the
/// shape's three dashboard records when the feature is compiled in, plus the
/// profiling record when that one is. The two are independent, so this is the
/// sum, not a choice.
fn boot_records_with_dashboard() -> usize {
    BOOT_RECORDS_BASE + DASHBOARD_EXTRA + PROFILING_EXTRA
}

/// The record count a complete capture of this shape must reach, for
/// [`Spawned::run`] to know it can freeze: the boot records plus the warning the
/// shape is going to emit. `web` picks the dashboard-configured shape (which has
/// the three dashboard records when the feature is on) over the plain one;
/// `warning` is false only for the spawn shape that reads the streams live. A
/// `web` shape names a non-zero `web_server.port`, so it also owes the
/// reader-gated port record in a build without `dashboard`.
fn capture_floor(warning: bool, web: bool) -> usize {
    if !warning {
        return 0;
    }
    if web {
        boot_records_with_dashboard() + 1 + want_web_server_port_records()
    } else {
        boot_records_flat_tls_enable() + 1
    }
}

/// [`boot_records_with_dashboard`] for the `--config-dir` startup path, which
/// has **one record fewer** under `--all-features`: the config-directory branch
/// in `frps/src/main.rs` runs its services under its **own** SIGUSR1 handler —
/// it does emit `SIGUSR1 reload ready` — but it returns before the shared
/// `-c`-path block installs the SIGUSR2 task, so the `profiling` feature's
/// `SIGUSR2 profiling ready (pid=…)` record is the one this path never emits.
/// Measured: 11 records for this shape under `--all-features` versus 12 for the
/// same shape on `-c`.
fn boot_records_with_dashboard_config_dir() -> usize {
    BOOT_RECORDS_BASE + DASHBOARD_EXTRA
}

/// [`boot_records_flat_tls_enable`] for the `--config-dir` startup path (no
/// profiling record — see [`boot_records_with_dashboard_config_dir`]).
fn boot_records_flat_tls_enable_config_dir() -> usize {
    BOOT_RECORDS_BASE
}

/// [`capture_floor`] for the `--config-dir` startup paths. The `web` shape owes
/// the same reader-gated port record as its `-c` twin.
fn capture_floor_config_dir(web: bool) -> usize {
    if web {
        boot_records_with_dashboard_config_dir() + 1 + want_web_server_port_records()
    } else {
        boot_records_flat_tls_enable_config_dir() + 1
    }
}

/// The baseline for a `-c` row whose counted warning is the **flat**
/// `tls_enable` diagnostic: the no-dashboard shape (no `[web_server]` is
/// written), whose warning is the flat one. The one row that counts the **web**
/// diagnostic while the flat one is present (a written `tls_enable` with no
/// `web_server.tls.enable`) adds 1 itself, because for it the flat warning is a
/// sibling, not the `want`.
fn boot_records_flat_tls_enable() -> usize {
    boot_records_no_dashboard()
}

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
///
/// A reader that ends on a **read error** rather than EOF leaves the capture
/// truncated, so every reader below checks that slot and panics instead of
/// handing back what was read — see [`drain`].
struct Spawned {
    _guard: ChildGuard,
    stdout_buf: Arc<Mutex<String>>,
    stderr_buf: Arc<Mutex<String>>,
    stdout_failed: Arc<Mutex<Option<std::io::Error>>>,
    stderr_failed: Arc<Mutex<Option<std::io::Error>>>,
    /// The record count [`Spawned::run`] waits for before freezing: see
    /// [`spawn_floor`].
    boot_floor: usize,
    stdout: String,
    stderr: String,
}

impl Spawned {
    /// Spawn `frps` with `argv` from `dir`, wait (bounded) for
    /// [`STARTUP_MARKER`] on either stream, settle, and snapshot both streams.
    fn run(dir: &TempDir, argv: &[&str], boot_floor: usize) -> Self {
        let child = Command::new(bin())
            .args(argv)
            .current_dir(&dir.0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn frps");
        let mut spawned = Self::from_child(child, boot_floor);
        spawned.wait_for_marker(STARTUP_MARKER, READY_TIMEOUT);
        spawned.wait_for_capture_convergence();
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
        // Floor 0: this lane reads both streams **live** while the registry
        // settles, so it must not wait for a count (and its panic record is not
        // part of any count assertion anyway).
        let mut spawned = Self::from_child(child, 0);
        spawned.wait_for_marker(STARTUP_MARKER, READY_TIMEOUT);
        // Deliberately **no** convergence wait: this lane is timing-sensitive
        // (it measures how long the ready marker took to appear), so it
        // snapshots the moment the marker does. Floor 0 already tells
        // [`Spawned::wait_for_capture_convergence`] the same thing.
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

    fn from_child(mut child: Child, boot_floor: usize) -> Self {
        let out = Arc::new(Mutex::new(String::new()));
        let err = Arc::new(Mutex::new(String::new()));
        let out_failed = Arc::new(Mutex::new(None));
        let err_failed = Arc::new(Mutex::new(None));
        drain(
            child.stdout.take().expect("child stdout"),
            out.clone(),
            out_failed.clone(),
        );
        drain(
            child.stderr.take().expect("child stderr"),
            err.clone(),
            err_failed.clone(),
        );
        Self {
            _guard: ChildGuard { child },
            stdout_buf: out,
            stderr_buf: err,
            stdout_failed: out_failed,
            stderr_failed: err_failed,
            boot_floor,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Wait, bounded, until the capture has **stopped growing**: the record
    /// count is at least [`Spawned::boot_floor`] and has been unchanged for
    /// [`SETTLE`]. This replaces a fixed sleep, which was not enough under
    /// `--all-features`: the `profiling` task's SIGUSR2 record is emitted from a
    /// spawned task and could land after a fixed deadline, so the same shape
    /// sometimes had one record more than its pin.
    ///
    /// A floor that is never reached is a **mis-specified floor**, not a slow
    /// child, and it is fatal: exiting here on the deadline would silently turn
    /// the row's window into the 15 s deadline — the capture would still freeze,
    /// but no longer at convergence — which is exactly the silent widening the
    /// review found at three call sites. The panic names the floor, the count
    /// and `capture_floor`, so the fix is mechanical.
    fn wait_for_capture_convergence(&mut self) {
        if self.boot_floor == 0 {
            // The live-read shape declares "no floor": settle, do not poll.
            std::thread::sleep(SETTLE);
            return;
        }
        let deadline = Instant::now() + READY_TIMEOUT;
        let mut last = 0usize;
        let mut stable_since: Option<Instant> = None;
        loop {
            let count = tracing_record_starts(&strip_sgr(&self.peek_streams())).len();
            if count != last {
                last = count;
                stable_since = Some(Instant::now());
            } else if count >= self.boot_floor
                && stable_since.is_some_and(|t| t.elapsed() >= SETTLE)
            {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "the capture never reached its floor: {} record(s) after {READY_TIMEOUT:?}, \
                     floor {} — `capture_floor(...)` at this row's `Spawned::run` names a shape \
                     this config does not produce. Fix the floor; do not widen the window.\n\
                     --- stdout ---\n{}",
                    count,
                    self.boot_floor,
                    self.peek_stdout()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Freeze what the reader threads have collected so far, before any signal.
    fn snapshot(&mut self) {
        self.assert_drains_are_healthy();
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

    /// Neither reader thread has **recorded a read error** (see [`drain`]); a
    /// thread that ended at EOF recorded none, and one still running has not
    /// failed yet. What this cannot see is EOF itself: the threads are not
    /// joined (they cannot be, the child is alive), so a *silent* truncation
    /// would pass here — but [`drain`] never truncates silently, because every
    /// non-EOF error is recorded and every other return is a successful read.
    fn assert_drains_are_healthy(&self) {
        check_drain_errors(
            self.stdout_failed.lock().unwrap().as_ref(),
            self.stderr_failed.lock().unwrap().as_ref(),
        );
    }

    fn peek_stdout(&self) -> String {
        self.assert_drains_are_healthy();
        self.stdout_buf.lock().unwrap().clone()
    }

    fn peek_stderr(&self) -> String {
        self.assert_drains_are_healthy();
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

/// Read a child's pipe on its own thread, appending into `sink` until EOF.
///
/// Only `Ok(0)` is EOF. `ErrorKind::Interrupted` is a signal, not an end, so it
/// retries; any other read error is recorded in `failed` and ends the thread.
/// The old loop (`Ok(0) | Err(_) => break`) could not tell the two apart, so a
/// pipe that failed for another reason truncated the capture and looked
/// exactly like a quiet stream — on the rows that assert silence that would
/// hide a warning emitted before the error.
///
/// The error is parked in a shared slot rather than returned from a joinable
/// thread (the `frpc` shape) because this harness reads the pipes while the
/// child is **still running**: joining here would block before the write end is
/// closed. The three readers below check the slot instead, so a truncated
/// capture is never consulted as final. [`drain_failed_before_eof`] owns the
/// message and the teeth ([`mod drain_tests`]).
fn drain<R: Read + Send + 'static>(
    mut pipe: R,
    sink: Arc<Mutex<String>>,
    failed: Arc<Mutex<Option<std::io::Error>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => sink
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    *failed.lock().unwrap() = Some(e);
                    return;
                }
            }
        }
    })
}

/// The assertion a reader thread's recorded error produces: the capture is
/// **truncated**, not final, and the test must red rather than read the partial
/// buffer. A free function so [`mod drain_tests`] can drive it directly.
fn drain_failed_before_eof(stream: &str, err: &std::io::Error) -> ! {
    panic!(
        "the {stream} reader failed before EOF ({err}) — the capture is truncated, not final, \
         and asserting on it would read a partial stream as a quiet one"
    )
}

/// Red before the first stream with a recorded read error is read as final.
/// Free of `Spawned` so [`mod drain_tests`] drives the assertion itself.
fn check_drain_errors(stdout: Option<&std::io::Error>, stderr: Option<&std::io::Error>) {
    if let Some(err) = stdout {
        drain_failed_before_eof("stdout", err);
    }
    if let Some(err) = stderr {
        drain_failed_before_eof("stderr", err);
    }
}

/// Teeth for [`drain`]'s error handling. The old loop (`Ok(0) | Err(_) => break`)
/// cannot be reached through a real child: an `frps` pipe reaches EOF, so
/// nothing in the spawned-binary tests distinguishes "EOF" from "a read error".
/// These drive the reader and the assertion directly with the failing shape the
/// previous loop disclosed, so removing the distinction reds *here* rather than
/// silently weakening a silence row — the same shape as `frpc`'s `mod
/// drain_tests`, adapted because this harness cannot join its readers.
#[cfg(test)]
mod drain_tests {
    use super::{check_drain_errors, drain};
    use std::io::{self, Read};
    use std::sync::{Arc, Mutex};

    /// Run one [`drain`] to completion and hand back what it recorded: the
    /// bytes, the error slot, and the assertion the readers would run.
    fn run<R: Read + Send + 'static>(pipe: R) -> (String, Option<io::Error>) {
        let sink = Arc::new(Mutex::new(String::new()));
        let failed = Arc::new(Mutex::new(None));
        drain(pipe, sink.clone(), failed.clone())
            .join()
            .expect("drain thread panicked");
        let text = sink.lock().unwrap().clone();
        let err = failed.lock().unwrap().take();
        (text, err)
    }

    /// [`Read`] that hands out one record and then fails — a pipe error, not EOF.
    struct RecordThenError {
        data: &'static [u8],
        sent: bool,
    }

    impl Read for RecordThenError {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.sent {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe failed"));
            }
            self.sent = true;
            let n = self.data.len().min(buf.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }
    }

    /// [`Read`] that raises `EINTR` once, then yields a record and EOF.
    struct InterruptedOnce {
        state: u8,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.state {
                0 => {
                    self.state = 1;
                    Err(io::Error::new(io::ErrorKind::Interrupted, "EINTR"))
                }
                1 => {
                    self.state = 2;
                    buf[..5].copy_from_slice(b"kept\n");
                    Ok(5)
                }
                _ => Ok(0),
            }
        }
    }

    /// The bytes read before the error are kept, and the error is **recorded**,
    /// so a reader never mistakes the truncated capture for the final one.
    #[test]
    fn a_read_error_is_recorded_and_not_read_as_eof() {
        let (text, err) = run(RecordThenError {
            data: b"partial record\n",
            sent: false,
        });
        assert_eq!(
            text, "partial record\n",
            "bytes read before the error are still captured"
        );
        let err = err.expect("a non-EOF read error must be recorded, not folded into EOF");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// ...and the recorded error is what makes a capture unusable: the readers'
    /// assertion must red on it, with the stream name and the cause.
    #[test]
    #[should_panic(expected = "the stdout reader failed before EOF")]
    fn a_recorded_read_error_is_fatal_to_the_capture() {
        let (_text, err) = run(RecordThenError {
            data: b"partial record\n",
            sent: false,
        });
        check_drain_errors(err.as_ref(), None);
    }

    /// The **stderr** half of the same assertion: deleting it must red here,
    /// not stay green because every call above passes `None` for stderr.
    #[test]
    #[should_panic(expected = "the stderr reader failed before EOF")]
    fn a_recorded_stderr_read_error_is_fatal_to_the_capture() {
        let (_text, err) = run(RecordThenError {
            data: b"partial record\n",
            sent: false,
        });
        check_drain_errors(None, err.as_ref());
    }

    /// A clean capture passes that same assertion.
    #[test]
    fn a_clean_eof_capture_is_usable() {
        let (text, err) = run(io::Cursor::new(b"one record\n".to_vec()));
        assert!(err.is_none(), "plain EOF records no error; got {err:?}");
        assert_eq!(text, "one record\n");
        check_drain_errors(None, None);
    }

    /// `EINTR` is a signal, not a failure, and not the end of the capture.
    #[test]
    fn interrupted_is_retried_and_does_not_end_the_capture() {
        let (text, err) = run(InterruptedOnce { state: 0 });
        assert!(
            err.is_none(),
            "EINTR is a signal, not a failure; got {err:?}"
        );
        assert_eq!(text, "kept\n");
    }
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
    assert_one_warning_on_stdout_with_boot(tag, spawned, boot_records_with_dashboard());
}

/// [`assert_one_warning_on_stdout`] for the `--config-dir` startup path, whose
/// boot is one record shorter under `profiling` (see
/// [`boot_records_with_dashboard_config_dir`]).
fn assert_one_warning_on_stdout_from_config_dir(tag: &str, spawned: &Spawned) {
    assert_one_warning_on_stdout_with_boot(tag, spawned, boot_records_with_dashboard_config_dir());
}

/// `boot` is this shape's boot baseline ([`boot_records_with_dashboard`] or its
/// `--config-dir` twin). The reader-gated `web_server.port` record is added on
/// top: every `[web_server]` fixture this file builds names a **non-zero**
/// port, so a build without `dashboard` owes exactly one record for it beside
/// the `tls_enable` one (TODO.md item 1). The term is zero in the dashboard
/// lane, where the same port is honoured and the build must stay silent.
fn assert_one_warning_on_stdout_with_boot(tag: &str, spawned: &Spawned, boot: usize) {
    assert_one_warning_on_stdout_for(tag, spawned, KEY);
    assert_web_server_tls_enable_records_are_exactly_the_message(
        tag,
        &spawned.stdout(),
        1,
        boot + want_web_server_port_records(),
    );
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
/// the two `frps/src/main.rs` emit sites (`:1078` on the `-c` path, `:625` on the
/// `--config-dir` path) and the reload site `frp-server/src/service.rs:1568` to the
/// build under test. The lane that runs this file **without** `--features dashboard`
/// is what makes the no-dashboard direction observable.
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

/// The starts of every `tracing` record in an SGR-stripped capture: a line that
/// begins with an RFC 3339 timestamp, a space and a level — the same shape
/// [`is_tracing_timestamp`] validates in the helper above. A line that merely
/// *contains* a timestamp (a log message quoting one, say) does not begin with
/// one, so it is not a record.
fn tracing_record_starts(clean: &str) -> Vec<usize> {
    /// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` is at least this long; the fraction
    /// widens the stamp leftwards from the `Z`, so this is the widest start.
    const STAMP: usize = 27;
    let mut found = Vec::new();
    let mut search = 0;
    while let Some(offset) = clean[search..].find('Z') {
        let at = search + offset;
        if at + 1 >= STAMP {
            let start = at + 1 - STAMP;
            if clean.as_bytes().get(at + 1) == Some(&b' ')
                && is_tracing_timestamp(&clean[start..=at])
            {
                found.push(start);
                search = at + 1;
                continue;
            }
        }
        search = at + 1;
    }
    found
}

/// How many `tracing` records in `out` carry `want`, by the same extraction
/// [`assert_records_are_exactly_the_message`] uses. Exposed for the tests that
/// must count a **live** buffer rather than a frozen one.
fn records_carrying(out: &str, want: &str) -> usize {
    records_containing(&strip_sgr(out), want).len()
}

/// The byte offset at which the capture's **first** `tracing` record starts.
/// `Some(0)` means the capture begins with a record; `None` means it carries no
/// record at all. Used to reject bytes printed ahead of the first record.
fn first_record_start(clean: &str) -> Option<usize> {
    tracing_record_starts(clean).into_iter().next()
}

/// Byte-pin every record carrying `want` **and pin the total record count**:
/// there must be exactly `expected` records carrying `want`, the capture must
/// hold exactly `expected + others` records in total (`others` is the caller's
/// measured boot baseline, see [`boot_records_no_dashboard()`]), each matching record
/// must be the message with the one-line `tracing` prefix, nothing may precede
/// the first record (so bytes printed ahead of it cannot hide there), and
/// nothing may follow a record but a fresh record or the end of the capture.
///
/// The count is the half that makes an emit-site mutant appending a **second
/// well-formed `warn!`** red: byte-pinning the records it is handed cannot see a
/// record it was not handed, and the orphan-line guard below accepts a fresh
/// record. It also covers a record emitted *before* the warning — the other
/// direction the helper was blind to — because that shifts the total by one too.
///
/// The residual the count shares with the baseline: a capture in which a record
/// was **swapped** for a record that is not `want` (a second boot line, say)
/// keeps `expected + others` and stays green. That shape is indistinguishable
/// from the honest boot output by construction — the boot lines are not pinned,
/// only counted — and it is not the shape this closes. The window is also this
/// snapshot: a record emitted **after** `Spawned::run` froze the buffers is not
/// in the capture at all. Both limits are pinned by the tests named in
/// `frps/tests/warn_delivery.rs::mod record_count_tests` and by
/// `records_emitted_after_the_snapshot_never_reach_the_capture`.
fn assert_records_are_exactly_the_message(
    tag: &str,
    out: &str,
    want: &str,
    expected: usize,
    others: usize,
) {
    let clean = strip_sgr(out);
    let records = records_containing(&clean, want);
    assert_eq!(
        records.len(),
        expected,
        "{tag}: expected {expected} record(s) carrying `{want}`, found {}\n--- stdout ---\n{out}",
        records.len()
    );
    // Nothing may precede the first record: `records_containing` starts each
    // record at the previous newline, so raw bytes printed ahead of the warning
    // would otherwise be part of no record and examined by nobody.
    if let Some(start) = first_record_start(&clean) {
        assert_eq!(
            start,
            0,
            "{tag}: {} byte(s) precede the capture's first `tracing` record — the emit site printed \
             them ahead of any record: {:?}",
            start,
            clean[..start].chars().take(120).collect::<String>()
        );
    }
    let total = tracing_record_starts(&clean).len();
    assert_eq!(
        total,
        expected + others,
        "{tag}: the capture must hold exactly {} `tracing` record(s) — {expected} carrying `{want}` \
         and the {others} this shape emits besides it; found {total}. A record emitted beyond \
         those (an appended well-formed `warn!`, or one ahead of the warning) reds here.\n\
         --- stdout ---\n{out}",
        expected + others
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

/// Byte-pin every stdout record carrying the server `tls_enable` message: there
/// must be exactly `expected` of them, `others` records beside them, and
/// each must be the message with the one-line `tracing` prefix and no other
/// bytes.
///
/// `expected` mirrors the caller's occurrence count, so this **can stand in
/// for** the count-only assertion rather than being a second, independently
/// driftable check: the wrapper below uses it that way, and the reload test
/// asserts the same count through both so the "one per load" intent stays
/// explicit.
fn assert_server_tls_enable_records_are_exactly_the_message(
    tag: &str,
    out: &str,
    expected: usize,
    others: usize,
) {
    assert_records_are_exactly_the_message(
        tag,
        out,
        frp_core::config::SERVER_TLS_ENABLE_INERT_WARNING.as_str(),
        expected,
        others,
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
    others: usize,
) {
    let want = if cfg!(feature = "dashboard") {
        frp_core::config::WEB_SERVER_TLS_ENABLE_INERT_WARNING
    } else {
        frp_core::config::WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD
    };
    assert_records_are_exactly_the_message(tag, out, want, expected, others);
}

/// [`assert_one_warning_on_stdout_for`] for the flat server `tls_enable`
/// diagnostic: exactly one record, and its bytes are pinned to the message.
fn assert_one_server_tls_enable_warning(tag: &str, spawned: &Spawned, boot: usize) {
    assert_one_server_tls_enable_warning_with_boot(tag, spawned, boot);
}

/// [`assert_one_server_tls_enable_warning`] for the `--config-dir` startup path.
fn assert_one_server_tls_enable_warning_from_config_dir(tag: &str, spawned: &Spawned) {
    assert_one_server_tls_enable_warning_with_boot(
        tag,
        spawned,
        boot_records_flat_tls_enable_config_dir(),
    );
}

fn assert_one_server_tls_enable_warning_with_boot(tag: &str, spawned: &Spawned, boot: usize) {
    assert_one_warning_on_stdout_for(tag, spawned, SERVER_KEY);
    assert_server_tls_enable_records_are_exactly_the_message(tag, &spawned.stdout(), 1, boot);
}

/// The shared "no record at all" assertion, with the startup line still there so
/// the silence is a decision and not a failed run. The byte-pin runs with
/// `expected = 0` so the silence is stated in the same terms as the presence
/// rows: no variant of this build's message, anywhere in the capture.
/// [`assert_no_warning`] pins the `web_server.tls.enable` silence, so its
/// `others` baseline is the shape's boot plus the reader-gated `web_server.port`
/// record the same config owes in a build without `dashboard` (the negative
/// control's config writes a non-zero port, it just omits the `tls` table).
fn assert_no_warning(tag: &str, spawned: &Spawned, boot: usize) {
    assert_no_warning_for(tag, spawned, KEY);
    assert_web_server_tls_enable_records_are_exactly_the_message(
        tag,
        &spawned.stdout(),
        0,
        boot + want_web_server_port_records(),
    );
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

/// Teeth for the two properties [`assert_records_are_exactly_the_message`] gained
/// over the H2 batch: the capture must hold exactly `expected + others` records,
/// so a **second well-formed `warn!`** appended at the emit site — the mutant the
/// record byte-pin could not see, because it byte-pins the records it is handed —
/// reds, and so does a record emitted **ahead** of the warning.
///
/// These drive the assertion directly on synthetic captures instead of mutating
/// the product: a real emit-site mutant would also red `frp-core`'s captures and
/// has to be reverted, while the count is what this file owns. The honest-fixed
/// captures below are the same shape the binary writes (SGR, timestamp, level,
/// target, message, newline), so the three tests are green on the unmutated
/// shapes and red only on the two mutated ones.
#[cfg(test)]
mod record_count_tests {
    use super::assert_records_are_exactly_the_message;

    /// One synthetic diagnostic, SGR and all, as the console sink writes it.
    fn diagnostic(message: &str) -> String {
        format!(
            "\u{1b}[2m2026-10-01T18:50:19.791487Z\u{1b}[0m \u{1b}[33m WARN\u{1b}[0m \
             \u{1b}[2mfrp_core::config::loader\u{1b}[0m\u{1b}[2m:\u{1b}[0m {message}\n"
        )
    }

    /// A synthetic boot record with the same skeleton as the real ones.
    fn boot(level: &str, body: &str) -> String {
        format!(
            "\u{1b}[2m2026-10-01T18:50:19.791644Z\u{1b}[0m \u{1b}[32m {level}\u{1b}[0m \
             \u{1b}[2mfrps\u{1b}[0m\u{1b}[2m:\u{1b}[0m {body}\n"
        )
    }

    const WANT: &str = "the warning this row counts";

    /// The honest shape: one warning, two boot records. Green.
    #[test]
    fn the_honest_capture_stays_green() {
        let capture = format!(
            "{}{}{}",
            diagnostic(WANT),
            boot("INFO", "starting..."),
            boot("INFO", "listening")
        );
        assert_records_are_exactly_the_message("honest", &capture, WANT, 1, 2);
    }

    /// Raw non-record bytes printed **ahead** of the first record red too: the
    /// count alone cannot see them (the record they precede is still there and
    /// exact), which is the M7 shape the adversarial found.
    #[test]
    #[should_panic(expected = "byte(s) precede the capture's first `tracing` record")]
    fn raw_bytes_before_the_first_record_red() {
        let capture = format!("junk before any record\n{}", diagnostic(WANT));
        assert_records_are_exactly_the_message("junk-prefix", &capture, WANT, 1, 0);
    }

    /// ...and the honest shape with a record first stays green — any record,
    /// not only the counted one, satisfies "the capture begins with a record".
    #[test]
    fn a_capture_that_begins_with_a_record_is_green() {
        let capture = format!("{}{}", boot("INFO", "starting..."), diagnostic(WANT));
        assert_records_are_exactly_the_message("record-first", &capture, WANT, 1, 1);
    }

    /// The mutant the item names: the emit site appends a **second well-formed
    /// record**. Every record it hands the byte-pin is still exact, so only the
    /// count can see it.
    #[test]
    #[should_panic(expected = "must hold exactly 3")]
    fn an_appended_well_formed_record_reds_the_count() {
        let capture = format!(
            "{}{}{}{}",
            diagnostic(WANT),
            boot("INFO", "starting..."),
            boot("INFO", "listening"),
            diagnostic("a second, well-formed warning record")
        );
        assert_records_are_exactly_the_message("appended", &capture, WANT, 1, 2);
    }

    /// The other blind direction: a well-formed record emitted **before** the
    /// warning, which `records_containing` never looked at.
    #[test]
    #[should_panic(expected = "must hold exactly 3")]
    fn a_record_ahead_of_the_warning_reds_the_count() {
        let capture = format!(
            "{}{}{}{}",
            diagnostic("a record ahead of the warning"),
            diagnostic(WANT),
            boot("INFO", "starting..."),
            boot("INFO", "listening")
        );
        assert_records_are_exactly_the_message("prefixed", &capture, WANT, 1, 2);
    }
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
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, true),
    );
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
    let spawned = Spawned::run(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        capture_floor_config_dir(true),
    );
    assert_one_warning_on_stdout_from_config_dir("frps --config-dir", &spawned);
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
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, true),
    );
    assert_one_warning_on_stdout("frps -c ([common] spelling)", &spawned);
}

#[test]
fn web_server_tls_enable_warning_reaches_a_config_dir_user_with_the_common_spelling() {
    let dir = TempDir::new("cfgdir-common");
    let cfg = frps_config(free_port(), free_port(), Section::CommonNested);
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frps.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        capture_floor_config_dir(true),
    );
    assert_one_warning_on_stdout_from_config_dir("frps --config-dir ([common] spelling)", &spawned);
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
    let mut spawned = Spawned::run(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        capture_floor_config_dir(true),
    );

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
    let mut spawned = Spawned::run(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        capture_floor_config_dir(true),
    );

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
///
/// The deliberate panic is the `debug_assertions`-only `FRPS_CFGDIR_TEST_PANIC`
/// hook, so the release profile compiles it out and the service never panics
/// there: this test is `#[ignore]`d in release rather than assert a fan-out
/// shape the shipped binary cannot produce. The `warn_delivery` release lane in
/// `.github/workflows/ci.yml` pins that skip by name
/// (`FRPS_RELEASE_WARN_DELIVERY_IGNORED`).
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug_assertions-only FRPS_CFGDIR_TEST_PANIC hook (frps/src/main.rs:777)"
)]
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
///
/// The barrier is a `debug_assertions`-only hook, so the release profile
/// compiles it out and there is nothing left for this test to observe: it is
/// `#[ignore]`d there rather than run against a barrier that is not there. The
/// `warn_delivery` release lane in `.github/workflows/ci.yml` pins that skip by
/// name (`FRPS_RELEASE_WARN_DELIVERY_IGNORED`).
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug_assertions-only FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS hook (frps/src/main.rs:656)"
)]
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
    let mut spawned = Spawned::run(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        capture_floor_config_dir(true),
    );

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
    let mut spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, true),
    );
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
        boot_records_with_dashboard() + want_web_server_port_records(),
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
        // The reload is a second load, so it owes a second reader-gated port
        // record in a build without `dashboard` (zero in the dashboard lane).
        boot_records_with_dashboard() + RELOAD_EXTRA_RECORDS + want_web_server_port_records() * 2,
    );
    assert_clause_matches_this_build("frps reload", &spawned);
}

/// The oracle's observation window is [`Spawned::run`]'s convergence freeze: a
/// record emitted **after** it is not in the capture, and the count rows cannot
/// see it. This pins that boundary — and the length of the window — by watching
/// the **live** buffer for [`LATE_WINDOW`] (long enough to cover the
/// adversarial's `warn!` at `+3 s`) and requiring the record count to stay put.
///
/// That is the honest answer to the M13b finding rather than a wider window on
/// every row: the emitted record is invisible *by construction* once the freeze
/// has happened, and extending the window to catch it on all 17 rows would cost
/// seconds per row to observe a record the oracle deliberately does not read.
/// Anything a mutant emits **before** the freeze is inside the window and does
/// red (see the emit-site mutants in the batch's evidence).
#[test]
fn records_emitted_after_the_snapshot_never_reach_the_capture() {
    let dir = TempDir::new("late");
    let cfg = frps_config(free_port(), free_port(), Section::Nested);
    let path = dir.write("frps.toml", &cfg);
    // `web = true`: this is a `[web_server]` shape with a non-zero port, so its
    // complete capture is the dashboard records (when compiled) plus the
    // `tls_enable` record plus the reader-gated port record (when it is owed).
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, true),
    );
    let frozen = records_carrying(&spawned.stdout(), KEY);
    assert_eq!(
        frozen,
        1,
        "the freeze the count rows read must see the warning\n--- stdout ---\n{}",
        spawned.stdout()
    );

    std::thread::sleep(LATE_WINDOW);
    let live = records_carrying(&spawned.peek_stdout(), KEY);
    assert_eq!(
        live, frozen,
        "a `{KEY}` record arrived inside {LATE_WINDOW:?} of the snapshot, yet the frozen capture \
         still reads {frozen} — the assertions read the snapshot, so anything after it is invisible"
    );
}

/// Negative control: without the key there is no record on either stream, so the
/// warning is presence-driven and not an unconditional startup line.
#[test]
fn no_warning_for_a_config_without_the_key() {
    let dir = TempDir::new("nokey");
    let cfg = frps_config(free_port(), free_port(), Section::None);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(false, false),
    );
    // This config writes `[web_server]`, so a dashboard build logs its three
    // records; the shape has no warning at all.
    assert_no_warning("frps -c (no key)", &spawned, boot_records_with_dashboard());
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
    // `web = true` for the same reason as the late-record row: `[web_server]`
    // with a non-zero port, so the dashboard records count toward the capture.
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, true),
    );
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
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, false),
    );
    assert_one_server_tls_enable_warning(
        "frps -c (tls_enable = true)",
        &spawned,
        boot_records_flat_tls_enable(),
    );
    assert_eq!(
        occurrences(&spawned.stdout(), KEY),
        0,
        "the dashboard key was not written, so its diagnostic must not fire\n--- stdout ---\n{}",
        spawned.stdout()
    );
    // The others here are the boot records this shape emits **plus** the flat
    // `tls_enable` warning it does emit: the web diagnostic is absent, but the
    // capture is not otherwise quiet.
    // This row's config writes no `[web_server]` section, but it does write
    // the flat `tls_enable`, so the capture is the plain boot plus that
    // warning — which is what [`boot_records_flat_tls_enable()`] does **not**
    // include (it is the baseline *beside* the flat warning, used by the rows
    // that count it).
    assert_web_server_tls_enable_records_are_exactly_the_message(
        "frps -c (dashboard key not written)",
        &spawned.stdout(),
        0,
        boot_records_flat_tls_enable() + 1,
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
    let spawned = Spawned::run(
        &dir,
        &["--config-dir", sub.to_str().unwrap()],
        capture_floor_config_dir(false),
    );
    assert_one_server_tls_enable_warning_from_config_dir(
        "frps --config-dir ([common] tls_enable)",
        &spawned,
    );

    let dir = TempDir::new("srv-dashc-common");
    let cfg = frps_config_server_tls(free_port(), ServerTls::CommonWritten);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, false),
    );
    assert_one_server_tls_enable_warning(
        "frps -c ([common] tls_enable)",
        &spawned,
        boot_records_flat_tls_enable(),
    );
}

/// `tls_enable = false` is just as inert as `true`, and just as likely to be
/// believed — a value gate would hide exactly this case.
#[test]
fn server_tls_enable_warning_reaches_a_dash_c_user_for_a_written_false() {
    let dir = TempDir::new("srv-false");
    let cfg = frps_config_server_tls(free_port(), ServerTls::WrittenFalse);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, false),
    );
    assert_one_server_tls_enable_warning(
        "frps -c (tls_enable = false)",
        &spawned,
        boot_records_flat_tls_enable(),
    );
}

/// Negative control: `[transport.tls] force = true` **synthesizes**
/// `tls_enable = true` inside the normalizer. The user never wrote the flat key,
/// so the warning must not fire — even though the field ends up `true`.
#[test]
fn no_server_tls_enable_warning_when_it_was_synthesized_from_transport_tls() {
    let dir = TempDir::new("srv-synth");
    let cfg = frps_config_server_tls(free_port(), ServerTls::SynthesizedForce);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(false, false),
    );
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
        boot_records_no_dashboard(),
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
    let mut spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor(true, false),
    );
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
        boot_records_no_dashboard(),
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
        boot_records_flat_tls_enable() + RELOAD_EXTRA_RECORDS,
    );
    assert_eq!(occurrences(&spawned.stderr(), SERVER_KEY), 0);
}

// ─── The reader-gated listener ports ─────────────────────────────────────────
//
// `web_server.port` is an **unconditional** `ServerConfig` field: every build's
// serde accepts the key. Only `frp-server`'s `dashboard` feature *reads* it, so
// a build without the feature binds nothing and the key is silently dropped —
// unless the caller turns the recorded presence into a record, which is what
// these rows pin. Unlike the `tls_enable` family the key is **live** in some
// builds, so the pin here has two directions: the no-dashboard lane must see
// exactly one record, and the `--features dashboard` lane must see **none**. A
// warning that fires when the feature is on is a bug, and only the second
// direction can see it — that is the positive control.

/// The one `web_server.port` record this build owes: absent reader ⇒ 1, present
/// reader ⇒ 0 (the port is honoured, so a record would be a false report).
fn want_web_server_port_records() -> usize {
    if cfg!(feature = "dashboard") {
        0
    } else {
        1
    }
}

/// The `Spawned::run` floor for a `[web_server] port = N` config: the shape has
/// the dashboard records when the feature is compiled, plus the one record this
/// build owes for the port.
fn capture_floor_web_server_port() -> usize {
    boot_records_with_dashboard() + want_web_server_port_records()
}

/// Byte-pin the `web_server.port` records: exactly `expected` of them carrying
/// the message, `others` beside them. In the dashboard lane `expected` is 0, so
/// this is also the assertion that the live build stayed silent.
fn assert_web_server_port_records_are_exactly_the_message(
    tag: &str,
    out: &str,
    expected: usize,
    others: usize,
) {
    assert_records_are_exactly_the_message(
        tag,
        out,
        frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING,
        expected,
        others,
    );
}

/// A config that names `web_server.port` and nothing else gated: no
/// `web_server.tls` table (so the `tls_enable` diagnostic is not a sibling) and
/// no `ssh_tunnel_gateway` section.
fn frps_config_web_server_port(bind_port: u16, dashboard_port: u16) -> String {
    frps_config(bind_port, dashboard_port, Section::None)
}

#[test]
fn web_server_port_warning_reaches_a_dash_c_user() {
    let dir = TempDir::new("port-dashc");
    let cfg = frps_config_web_server_port(free_port(), free_port());
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor_web_server_port(),
    );

    let want = want_web_server_port_records();
    assert_eq!(
        occurrences(
            &spawned.stdout(),
            frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING
        ),
        want,
        "this build owes {want} `web_server.port` record(s)\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert_web_server_port_records_are_exactly_the_message(
        "frps -c (web_server.port)",
        &spawned.stdout(),
        want,
        boot_records_with_dashboard(),
    );
    assert_eq!(
        occurrences(
            &spawned.stderr(),
            frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING
        ),
        0,
        "the diagnostic is a stdout record"
    );
}

/// The reload is a second in-process load through the **other** sink
/// (`frp-server/src/service.rs`), so the one-per-load rule is pinned on both
/// delivery sites. In the dashboard lane the same reload must stay silent.
#[cfg(unix)]
#[test]
fn a_sigusr1_reload_delivers_the_web_server_port_warning_again() {
    let dir = TempDir::new("port-reload");
    let cfg = frps_config_web_server_port(free_port(), free_port());
    let path = dir.write("frps.toml", &cfg);
    let mut spawned = Spawned::run(
        &dir,
        &["-c", path.to_str().unwrap()],
        capture_floor_web_server_port(),
    );
    let want = want_web_server_port_records();
    assert_eq!(
        occurrences(
            &spawned.stdout(),
            frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING
        ),
        want,
        "startup: one record per load\n--- stdout ---\n{}",
        spawned.stdout()
    );

    assert!(
        spawned.sigusr1_and_reload(),
        "the reload never logged {RELOAD_MARKER:?}\n--- stdout ---\n{}",
        spawned.stdout()
    );
    let out = spawned.stdout();
    assert_eq!(
        occurrences(&out, frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING),
        want * 2,
        "startup + reload = one per load\n--- stdout ---\n{out}"
    );
    assert_web_server_port_records_are_exactly_the_message(
        "startup + SIGUSR1 reload (web_server.port)",
        &out,
        want * 2,
        boot_records_with_dashboard() + RELOAD_EXTRA_RECORDS,
    );
}

/// `frps verify` cannot use `tracing` (the loader runs before any subscriber is
/// installed — see the `run_verify` doc), so the same record list is printed
/// directly. The pin is byte-exact on the **whole** stdout, because the Done-when
/// for this item is "reports the unhonoured key **without** disturbing the
/// byte-exact `syntax is ok` line": a record appended after the success line, or
/// one that reformats it, reds here even though the count would still be right.
///
/// This row lives in the `warn_delivery` file rather than `cli_exit_codes.rs`
/// on purpose: only this file has a `--features dashboard` lane, and the
/// zero-record direction ([`want_web_server_port_records`] `== 0`) is the
/// positive control that a `verify` printing unconditionally would red.
#[test]
fn verify_prints_the_gated_listener_port_record_before_the_go_success_line() {
    let dir = TempDir::new("port-verify");
    let cfg = frps_config_web_server_port(free_port(), free_port());
    let path = dir.write("frps.toml", &cfg);
    let out = Command::new(bin())
        .args(["verify", "-c", path.to_str().unwrap()])
        .current_dir(&dir.0)
        .output()
        .expect("spawn frps verify");
    assert!(
        out.status.success(),
        "`verify` on a valid config must exit 0: status={:?} stdout={:?} stderr={:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut expected = String::new();
    if want_web_server_port_records() == 1 {
        expected.push_str(frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING);
        expected.push('\n');
    }
    expected.push_str(&format!(
        "frps: the configuration file {} syntax is ok\n",
        path.display()
    ));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        expected,
        "the record (when this build owes one) goes before Go's byte-exact success line"
    );
    assert!(
        out.stderr.is_empty(),
        "verify keeps stderr empty on a valid config: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The **CLI** half of the same item: `frps --dashboard-port <N>` with **no**
/// `-c`/`--config-dir` reaches `web_server.port` through
/// `FrpsArgs::override_server_config`, which runs *after* the loader already
/// recorded (or declined to record) the config file's own request. Before this
/// item the overlay wrote the field without telling `ConfigPresence`, so a flag
/// user in a build with no dashboard got a port nothing bound and **no
/// diagnostic at all** — silently, while `[web_server] port = <N>` in a file
/// warned. The row pins the flag against the file's record set: the same
/// message, on stdout, once, in a build that owes it and never in a build that
/// binds the port.
///
/// The floor is the no-`[web_server]` boot baseline plus this build's `want`,
/// not [`capture_floor_web_server_port`]: a flag-only spawn writes no
/// `[web_server]` table, so in the dashboard lane it is the *lower* of the two
/// and still a true minimum (the running dashboard's own records sit above it).
/// The count assertions below are what pin the behaviour; the floor only lets
/// [`Spawned::run`] freeze a settled capture.
///
/// This is the spawn half. The per-shape half — which reader this build's
/// binary actually carries — is pinned by `frp-server/src/service.rs`'s
/// `dashboard_port_overlay_record_follows_this_builds_reader`, which runs in the
/// dashboard-off and dashboard-on `frp-server` suites alike, and the merge
/// itself by `frp-core`'s `cli` tests.
#[test]
fn web_server_port_warning_reaches_a_flag_user_without_a_config() {
    let dir = TempDir::new("port-flag");
    let port = free_port();
    let flag = port.to_string();
    // The file has to exist — `frps` resolves an absent `-c` to `./frps.toml`
    // and refuses to start when it cannot read it — but it must **not** request
    // the port, so the flag is the only source of `web_server.port` and the
    // loader's own presence record stays silent (proved by the floor below,
    // which is the no-`[web_server]` baseline, not the file's).
    dir.write(
        "frps.toml",
        &format!("bind_port = {}\ntoken = \"t\"\n", free_port()),
    );
    let spawned = Spawned::run(
        &dir,
        &["--dashboard-port", flag.as_str()],
        boot_records_no_dashboard() + want_web_server_port_records(),
    );

    let want = want_web_server_port_records();
    assert_eq!(
        occurrences(
            &spawned.stdout(),
            frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING
        ),
        want,
        "`--dashboard-port {port}` without `-c` owes the same {want} record(s) as \
         `[web_server] port = {port}` in a file\n--- stdout ---\n{}",
        spawned.stdout()
    );
    assert_eq!(
        occurrences(
            &spawned.stderr(),
            frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING
        ),
        0,
        "the diagnostic is a stdout record"
    );
}
