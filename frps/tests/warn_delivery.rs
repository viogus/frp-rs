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
const RELOAD_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the reload may take to log its summary after SIGUSR1.
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
/// The SIGUSR1 task's own progress witness: it is printed once the handler is
/// installed, so a signal sent after it cannot be lost to a startup race.
const SIGNAL_READY_MARKER: &str = "SIGUSR1 reload ready";
/// The server's reload summary line (`frps/src/main.rs`).
const RELOAD_MARKER: &str = "SIGUSR1:";
/// The key, as the message names it.
const KEY: &str = "web_server.tls.enable";
/// The marker unique to the **dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`): the only words a build with no
/// dashboard must never print.
const DASHBOARD_CLAUSE: &str = "plaintext HTTP";
/// The marker unique to the **no-dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`). The two clauses share
/// their whole first half, so `KEY` above is in both and cannot tell them apart.
const NO_DASHBOARD_CLAUSE: &str = "no dashboard support";
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

    /// Send `SIGUSR1`, wait (bounded) for the reload summary, settle, and
    /// re-snapshot. Returns `true` when the summary line was seen; the counts
    /// the caller reads afterwards are the post-reload ones.
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
    fn peek_streams(&self) -> String {
        format!("{}{}", self.peek_stdout(), self.peek_stderr())
    }

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
/// binary really did start, and the record carries the clause **this build**
/// answers with.
fn assert_one_warning_on_stdout(tag: &str, spawned: &Spawned) {
    assert_one_warning_on_stdout_for(tag, spawned, KEY);
    assert_clause_matches_this_build(tag, spawned);
}

/// The clause the emitted record must carry — decided by **this build**, not by
/// a literal argument.
///
/// The two variants share their whole first half (`web_server.tls.enable has no
/// effect: …`), so every count assertion in this file passes for either one: a
/// call site that hardcodes the other answer still compiles, still emits exactly
/// one `KEY` record, and still satisfies `frp-core`'s own dispatch test — that
/// one passes `has_dashboard` as an argument, so it never sees a real build's
/// answer. Only a `cfg!`-keyed assertion on the captured stdout can, and that is
/// what binds `frps/src/main.rs:219`/`:311` (and the reload site,
/// `frp-server/src/service.rs:2315`) to the build under test. The lane that runs
/// this file **without** `--features dashboard` is what makes the other
/// direction observable.
fn assert_clause_matches_this_build(tag: &str, spawned: &Spawned) {
    let out = spawned.stdout();
    let err = spawned.stderr();
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

/// The shared "no record at all" assertion, with the startup line still there so
/// the silence is a decision and not a failed run.
fn assert_no_warning(tag: &str, spawned: &Spawned) {
    assert_no_warning_for(tag, spawned, KEY);
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
/// with `unix_wait_status(158)` (`128+30`, shell message "User defined signal 1:
/// 30", measured by `/tmp/frps-cfgdir-probe/probe.sh`) and logged no summary.
///
/// The config is left **unchanged** across the signal, so the summary's wording
/// (`config reloaded: no changes detected`) is not what is asserted — only that
/// a summary arrived, i.e. that `Service::reload` ran on a process that is still
/// alive afterwards.
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

/// The reload is an in-process load with the sink already installed, so it gets
/// its **own** record — one per load, on top of the one the startup emitted. The
/// loader cannot supply it (it is silent on every path), so the reload site
/// emits it; without that, the base binary's record (measured +1 in the reload
/// window) is lost, and `enable` has no field for the reload summary to report.
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
    assert_one_warning_on_stdout_for("frps -c (tls_enable = true)", &spawned, SERVER_KEY);
    assert_eq!(
        occurrences(&spawned.stdout(), KEY),
        0,
        "the dashboard key was not written, so its diagnostic must not fire\n--- stdout ---\n{}",
        spawned.stdout()
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
    assert_one_warning_on_stdout_for(
        "frps --config-dir ([common] tls_enable)",
        &spawned,
        SERVER_KEY,
    );

    let dir = TempDir::new("srv-dashc-common");
    let cfg = frps_config_server_tls(free_port(), ServerTls::CommonWritten);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout_for("frps -c ([common] tls_enable)", &spawned, SERVER_KEY);
}

/// `tls_enable = false` is just as inert as `true`, and just as likely to be
/// believed — a value gate would hide exactly this case.
#[test]
fn server_tls_enable_warning_reaches_a_dash_c_user_for_a_written_false() {
    let dir = TempDir::new("srv-false");
    let cfg = frps_config_server_tls(free_port(), ServerTls::WrittenFalse);
    let path = dir.write("frps.toml", &cfg);
    let spawned = Spawned::run(&dir, &["-c", path.to_str().unwrap()]);
    assert_one_warning_on_stdout_for("frps -c (tls_enable = false)", &spawned, SERVER_KEY);
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
}

/// The reload is a second in-process load with the sink already installed, so it
/// adds its own record: startup 1, reload 2. One per load.
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
    assert_eq!(occurrences(&spawned.stderr(), SERVER_KEY), 0);
}
