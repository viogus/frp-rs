//! Bounded spawn tests for `frps`'s **log completion** — Go's
//! `LogConfig.Complete()` (`pkg/config/v1/common.go:119-123`), called from
//! `ServerConfig.Complete()` at `pkg/config/v1/server.go:105`.
//!
//! The defect these pin: `ServerConfig::complete` had no log fill, and the serde
//! defaults on `LogConfig` fire only when a key is **absent** — so an explicit
//! `--log-level ""` / `--log-file ""` / `--log-max-days 0` (or `level = ""` in
//! the file) survived completion and reached `init_logging`
//! (`frps/src/main.rs`). Measured on the pre-fix binary, own free port, stdout
//! and stderr counted **separately** before any signal:
//!
//! | shape | frp-rs before | Go v0.71.0 |
//! |---|---|---|
//! | `[log] level = ""` in the file | **0 B stdout / 0 B stderr**, listener up on `127.0.0.1:<port>` | 273 B on stdout, 3 `INFO` records |
//! | `[log] maxDays = 0` in the file | logs — 7 `INFO` records at startup (1482 B raw / 915 B stripped, implicit `./frps.toml` lane), 11 records / 2410–2412 B raw over the full run — but retention disabled | logs, retains 3 days |
//! | `--log-level ""` (CLI) | 0 B / 0 B, listener up | 282 B on stdout, 3 `INFO` records |
//! | `--log-file ""` (CLI) | 0 B / 0 B **and** a `frps.log.<date>` in the CWD | logs on stdout |
//! | `[log] to = ""` in the file | logs — same 7-record startup shape (1482 B raw / 915 B stripped), **no** `frps.log.*` file created | logs on stdout |
//!
//! The Go rows are the **flags-only** lane (`--bind-port <free>`, 282 B / 3
//! `INFO` records) or the **config-file** lane (273 B / 3 `INFO` records),
//! whichever matches the shape; the line count is `INFO` **records**, not
//! `grep -c .` on the raw stream, which over-counts by one on a trailing ANSI
//! reset (the item's "4 lines" was that artifact).
//!
//! `[log] to = ""` in the file is deliberately listed as **not** a pre-fix
//! defect: `resolve_log_file` already mapped an empty *config* value to
//! `console`, so that shape logged normally on the pre-fix binary and created no
//! file. Only the **flag** arm (`--log-file ""`) was broken, and only `level`
//! and `max_days` had a config-value defect. The pre-fix rows above are the
//! measured ones, with the false row removed.
//!
//! The two `logs` cells are re-measured on the HEAD binary, implicit `./frps.toml`
//! lane, own free port, stdout only and ANSI-stripped: 7 `INFO` records at startup
//! = 1482 B raw / 915 B stripped, 11 records over the full run = 2410–2412 B raw
//! / 1466–1473 B stripped (the `elapsed_secs=` width moves the total by a few
//! bytes; the pid digits move it by two each). No `frps.log.*` file is created in
//! either shape. The earlier `1498 B / 7 records` reproduced on neither binary nor
//! lane; for these two rows the record *shape* is the same on both sides of the
//! completion fix, which changed retention only (and not `to = ""` at all).
//!
//! **What this file models.** The end-to-end effect on the two streams and on the
//! CWD for the shipped `frps` binary, over two lanes: the config-file lane
//! (`-c`, which is where Go also completes a fresh struct,
//! `pkg/config/load.go:313-321`) and the CLI-override lane (no `-c`; frp-rs's
//! `cli_overrides_enabled` + `override_server_config`, which writes the flag
//! value into the struct **before** `cfg.complete()` runs).
//!
//! **What it panics on.** (1) The child exiting before its post-`init_logging`
//! startup line appears, (2) the startup line never appearing within
//! [`READY_TIMEOUT`], (3) nothing accepting a TCP connection on the child's bind
//! port within [`READY_TIMEOUT`], (4) a `frps.log.*` file appearing in the
//! child's CWD in the `console` shapes.
//!
//! **What it does NOT cover.** It does not read `tracing`'s internals, so it
//! cannot say *why* a stream was empty (the two pre-fix mechanisms here are
//! different: the empty level parses as `ERROR` — tracing-core 0.1.36 maps `""`
//! to `ERROR`, `metadata.rs:798` — so no `INFO` startup record is admitted,
//! while the empty file path is routed to `frps.log.<date>`). It does not
//! assert the **absolute** byte count or record count of a healthy run, for two
//! reasons: those are run-dependent, and this file's own liveness probe
//! (`assert_loopback_listens`, a bare `TcpStream::connect`) is itself a writer —
//! measured on `frps --bind-port <free>`: 1498 B / 7 records before the connect,
//! **1800 B / 8 records after it**, the extra record being
//! `WARN frp_server::service: Failed to detect connection type … early eof`
//! (302 B). The byte figures in the table above are therefore measured with
//! `lsof` as the liveness probe (see `/tmp/log-complete-report.md`), and this
//! file asserts *content* (the startup marker is present), never a byte count. It does not cover `--log-format`
//! (frp-rs-only; Go answers `unknown flag`), the `--config-dir` lane, or `frpc`.
//! It deliberately does **not** set `RUST_LOG`: that variable outranks the
//! configured level in `logging::filter_from_env`, so setting it would mask
//! exactly the defect under test (the sibling file
//! `frps/tests/cli_completion.rs` sets `RUST_LOG=info`, which is why these
//! shapes live here rather than there).
//!
//! Bounded: every wait has a deadline, every child is killed and reaped by
//! [`ChildGuard::drop`] even on panic, and each test picks its own port from the
//! ephemeral range (never 7000).

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_frps");
/// How long a shape may take from spawn to its listener being dialable.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a killed child may take to disappear before SIGKILL.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Settle time after the listener is dialable, so the startup records that
/// `init_logging` gates are all written before the streams are read. These
/// counts are taken BEFORE any signal (the harness's SIGTERM would append
/// graceful-shutdown lines).
const SETTLE: Duration = Duration::from_millis(500);
/// A substring of the first record `frps` emits **after** `init_logging`, so
/// seeing it proves the subscriber was built with a level that admits INFO.
/// (`frps (Rust) v{} starting...` in `frps/src/main.rs`.)
const STARTUP_MARKER: &str = "frps (Rust) v";

fn bin() -> String {
    std::env::var("FRPS_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as
/// `frps/tests/cli_completion.rs`: no `tempfile` dev-dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frps-log-completion-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.0.join(name), contents).expect("write config");
    }

    /// Write `name` (creating parent directories) and set its mtime to `when` —
    /// the aged-fixture shape `cleanup_expired_logs` acts on at startup.
    fn write_backdated(&self, name: &str, contents: &str, when: SystemTime) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create log dir");
        }
        std::fs::write(&path, contents).expect("write aged log");
        std::fs::File::open(&path)
            .expect("open aged log")
            .set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("set mtime");
        path
    }

    /// File names inside the subdirectory `sub` (empty when it does not exist).
    /// [`files`](TempDir::files) only reads the scratch root, and the file-lane
    /// shapes keep their rotation files under `logs/`.
    fn files_in(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = match std::fs::read_dir(self.0.join(sub)) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    /// Every file in the scratch dir, so a shape that is supposed to stay on
    /// the console can be checked for a log **file** having appeared.
    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free port from the ephemeral range, deduplicated inside this process.
/// Same documented residual race as `frps/tests/cli_completion.rs::free_port`:
/// a concurrent process can take the port between the probe's drop and the
/// child's bind; that fails loudly (the ready line never arrives, with the
/// child's own stderr in the panic message) rather than being papered over.
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

fn used_ports() -> &'static std::sync::Mutex<std::collections::HashSet<u16>> {
    static USED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    USED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// Kills and reaps the child on every exit path, including a panicking
/// assertion — a leaked `frps` holds a port and has produced false
/// measurements in this repository.
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
/// full pipe can never block the child), plus the scratch dir that outlives it.
struct Spawned {
    _guard: ChildGuard,
    dir: TempDir,
    stdout: std::sync::Arc<std::sync::Mutex<String>>,
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Spawned {
    /// Run `frps` with `argv` in a scratch dir holding `config` as
    /// `./frps.toml` (the path `frps` resolves when `-c` is absent, and the only
    /// shape in which the CLI overrides apply: `FrpsArgs::cli_overrides_enabled`).
    ///
    /// `RUST_LOG` is explicitly **removed** from the child's environment: it
    /// outranks `--log-level` and the config level in `filter_from_env`, so
    /// leaving it set (as the sibling `cli_completion.rs` does) would defeat the
    /// assertion this file exists to make.
    fn start(config: &str, argv: &[&str]) -> Self {
        let dir = TempDir::new("spawn");
        dir.write("frps.toml", config);
        Self::start_in(dir, argv)
    }

    /// [`Spawned::start`] with a caller-prepared scratch dir, so a test can drop
    /// a backdated log file into it first.
    fn start_in(dir: TempDir, argv: &[&str]) -> Self {
        let child = Command::new(bin())
            .args(argv)
            .current_dir(&dir.0)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn frps");
        Self::from_child(child, dir)
    }

    fn from_child(mut child: Child, dir: TempDir) -> Self {
        let out = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let err = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        drain(child.stdout.take().expect("child stdout"), out.clone());
        drain(child.stderr.take().expect("child stderr"), err.clone());
        Self {
            _guard: ChildGuard { child },
            dir,
            stdout: out,
            stderr: err,
        }
    }

    fn stdout(&self) -> String {
        self.stdout.lock().unwrap().clone()
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// `Some(status)` once the child has exited (non-blocking), so a shape that
    /// can never satisfy its readiness gate reports the child's own exit instead
    /// of burning [`READY_TIMEOUT`] on a process that is already gone.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        match self._guard.child.try_wait() {
            Ok(Some(status)) => Some(status),
            _ => None,
        }
    }
}

/// Read a child's pipe to EOF on its own thread, appending into `sink`.
fn drain<R: Read + Send + 'static>(mut pipe: R, sink: std::sync::Arc<std::sync::Mutex<String>>) {
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

/// An external liveness proof for the same shape the item measured: the
/// pre-fix binary **did** bind, so "it logged nothing" is the defect, not "it
/// died". A regression that makes the listener stop coming up must fail here.
fn assert_loopback_listens(port: u16) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "nothing accepted a TCP connection on 127.0.0.1:{port} within {READY_TIMEOUT:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The assertion every shape in this file makes: the child reached the line it
/// emits **after** `init_logging`, on **stdout** (the console destination), with
/// stderr available for the failure message. Counted/checked before any signal.
fn assert_logged_and_listening(tag: &str, spawned: &Spawned, port: u16) {
    assert_loopback_listens(port);
    // Let the remaining startup records land, then read the streams — the
    // counts below are pre-signal by construction (no SIGTERM has been sent).
    std::thread::sleep(SETTLE);
    let out = spawned.stdout();
    assert!(
        out.contains(STARTUP_MARKER),
        "{tag}: frps never logged {STARTUP_MARKER:?} on stdout, so an empty log \
         value reached init_logging\n--- stdout ({} B) ---\n{}\n--- stderr ({} B) ---\n{}",
        out.len(),
        out,
        spawned.stderr().len(),
        spawned.stderr(),
    );
    assert!(
        !out.is_empty(),
        "{tag}: stdout must carry the console log stream"
    );
}

/// The `console` shapes must not divert the log to a file: pre-fix, an empty
/// `--log-file ""` / `to = ""` made `tracing-appender` roll to
/// `frps.log.<date>` in the CWD while both streams stayed empty.
fn assert_no_log_file_created(tag: &str, spawned: &Spawned) {
    let leaked: Vec<String> = spawned
        .dir
        .files()
        .into_iter()
        .filter(|f| f.starts_with("frps.log"))
        .collect();
    assert!(
        leaked.is_empty(),
        "{tag}: console shapes must not create a log file, found {leaked:?}"
    );
}

fn config(port: u16, log_section: &str) -> String {
    format!(
        "bind_addr = \"127.0.0.1\"\nbind_port = {port}\n\n\
         [auth]\nmethod = \"token\"\ntoken = \"log-completion-test\"\n{log_section}"
    )
}

/// **Config-file lane, the `empty_all` shape.** `[log] to = ""`, `level = ""`,
/// `max_days = 0` — all three Go `util.EmptyOr` inputs present-but-zero, which
/// is what serde's `default` fns never fill. Pre-fix this was **0 B stdout /
/// 0 B stderr** with the listener up; Go v0.71.0 with the same config logs 4
/// `INFO` lines on stdout (measured).
#[test]
fn config_empty_log_values_still_log() {
    let port = free_port();
    let cfg = config(port, "\n[log]\nto = \"\"\nlevel = \"\"\nmax_days = 0\n");
    let spawned = Spawned::start(&cfg, &["-c", "frps.toml"]);
    assert_logged_and_listening("config empty_all", &spawned, port);
    assert_no_log_file_created("config empty_all", &spawned);
}

/// **Config-file lane, `level = ""` alone** — the shape whose mechanism is the
/// empty level parsing as `ERROR` rather than a file redirect.
#[test]
fn config_empty_log_level_still_logs() {
    let port = free_port();
    let cfg = config(port, "\n[log]\nlevel = \"\"\n");
    let spawned = Spawned::start(&cfg, &["-c", "frps.toml"]);
    assert_logged_and_listening("config empty level", &spawned, port);
}

/// **CLI-override lane**: `--log-level ""` reaches the struct through
/// `override_server_config` and must be filled before `init_logging`. The
/// `--bind-port` flag is passed for the same reason (it is the same lane), so
/// the shape does not depend on the ephemeral port the config holds.
#[test]
fn cli_empty_log_level_still_logs() {
    let port = free_port();
    let cfg = config(port, "");
    let spawned = Spawned::start(&cfg, &["--bind-port", &port.to_string(), "--log-level", ""]);
    assert_logged_and_listening("cli --log-level \"\"", &spawned, port);
}

/// **CLI-override lane, the file half**: `--log-file ""` must resolve to
/// `console` (stdout) and must not create `frps.log.<date>`. `--log-max-days 0`
/// rides along so the third Go field is exercised in the same spawn.
#[test]
fn cli_empty_log_file_keeps_logging_on_stdout() {
    let port = free_port();
    let cfg = config(port, "");
    let spawned = Spawned::start(
        &cfg,
        &[
            "--bind-port",
            &port.to_string(),
            "--log-file",
            "",
            "--log-max-days",
            "0",
        ],
    );
    assert_logged_and_listening("cli --log-file \"\"", &spawned, port);
    assert_no_log_file_created("cli --log-file \"\"", &spawned);
}

// ── `--log-max-days 0` / `[log] max_days = 0`: the retention observable ──────
//
// The item's third field has one **synchronous** observable, and it is not a
// byte count: `init_tracing` calls `cleanup_expired_logs` at startup
// (`frp-core/src/logging.rs`, `if max_days > 0`) before the process serves, so
// an expired rotation file either disappears during startup or does not. With
// `[log] to = "logs/frps.log"` and a backdated `logs/frps.log.2020-01-01`, that
// makes "was `--log-max-days 0` completed to 3?" a file-existence question.
//
// Pre-fix this shape is **red** in exactly one arm, and the other three arms are
// the falsification controls that keep it honest:
//
// | shape | pre-fix | at head |
// |---|---|---|
// | `--log-max-days 0` (CLI) | **SURVIVES** (cleanup disabled) | deleted |
// | no flag (defaults to 3) | deleted | deleted — the fixture is genuinely expired |
// | `--log-max-days -1` (CLI) | survives | survives — only the zero value is filtered |
// | `[log] max_days = 0` in the file | **SURVIVES** | deleted |
//
// The `[log] max_days = 0` arm was already fixed by `LogConfig::complete` in the
// previous commit; it is asserted here so the two halves of the same Go field
// are pinned in one place, and so a future change that drops the config-side
// fill fails loudly rather than silently.
//
// This test deliberately does **not** use `assert_logged_and_listening`: the
// config logs to a file, so stdout carries no startup record, and its
// `TcpStream::connect` liveness probe would inject a WARN record into the stream
// a byte-count assertion would be reading (the sibling shapes' 1498 B / 7-record
// convention is measured with no connect). Liveness here is the appender's own
// `STARTUP_MARKER` record in that file, not the file's existence — see `fresh_log_reached_appender`.

/// 2020-01-01T00:00:00Z — far outside any `max_days` this test uses.
const AGED: SystemTime = UNIX_EPOCH;

fn file_lane_config(port: u16, log_section: &str) -> String {
    format!(
        "bind_addr = \"127.0.0.1\"\nbind_port = {port}\n\n\
         [auth]\nmethod = \"token\"\ntoken = \"log-completion-test\"\n\n\
         [log]\nto = \"logs/frps.log\"\n{log_section}"
    )
}

/// The fresh rotation file the appender created under `logs/`, if it is on disk
/// yet: today's `frps.log.<date>`, never the backdated fixture.
fn fresh_rotation_file(dir: &TempDir) -> Option<PathBuf> {
    dir.files_in("logs")
        .into_iter()
        .find(|f| f.starts_with("frps.log.") && f != "frps.log.2020-01-01")
        .map(|f| dir.0.join("logs").join(f))
}

/// True when the fresh rotation file already carries the record `frps` writes
/// **after** `init_logging` returns ([`STARTUP_MARKER`], `frps/src/main.rs:317`).
///
/// Mere existence is not evidence that anything ran: `tracing_appender::rolling::daily`
/// creates `logs/frps.log.<date>` eagerly when it is constructed
/// (`frp-core/src/logging.rs:378`), *before* the subscriber is installed and
/// before `cleanup_expired_logs` runs (`frp-core/src/logging.rs:401-402`). A
/// probe that stops at the file's appearance can therefore read the aged file's
/// fate too early — measured on this host at load average ~40, 2 of 10 runs
/// failed a retention assertion although the cleanup deletes the file a moment
/// later. The marker is only reachable once `cleanup_expired_logs` has returned,
/// which is what makes the wait deterministic.
fn fresh_log_reached_appender(dir: &TempDir) -> bool {
    fresh_rotation_file(dir)
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|contents| contents.contains(STARTUP_MARKER))
}

/// Spawn in a scratch dir holding a backdated `logs/frps.log.2020-01-01`, then
/// report whether it survived startup. Bounded: every wait has a deadline, and
/// the child is reaped by [`ChildGuard`] on every path.
///
/// The wait is for the appender's own record ([`fresh_log_reached_appender`]),
/// not for the fresh file's existence and not for the aged file: the readiness
/// gate has to be strictly *after* the retention decision, or a surviving aged
/// file is reported as a retention outcome when it is only a timing artifact.
/// The child's own exit is checked on every poll, so a shape that can never
/// satisfy the gate reports *that* (with its streams) instead of a timeout.
fn aged_file_survives(tag: &str, config: &str, argv: &[&str]) -> bool {
    let dir = TempDir::new("aged");
    dir.write("frps.toml", config);
    let aged = dir.write_backdated("logs/frps.log.2020-01-01", "aged\n", AGED);
    let mut spawned = Spawned::start_in(dir, argv);

    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if fresh_log_reached_appender(&spawned.dir) {
            break;
        }
        if let Some(status) = spawned.exited() {
            panic!(
                "{tag}: frps exited ({status}) before the appender recorded {STARTUP_MARKER:?} in \
                 a fresh `logs/frps.log.<date>`, so the aged file's survival would not be evidence \
                 of a retention decision\n--- stdout ({}) ---\n{}\n--- stderr ({}) ---\n{}",
                spawned.stdout().len(),
                spawned.stdout(),
                spawned.stderr().len(),
                spawned.stderr(),
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "{tag}: no appender record reached a fresh `logs/frps.log.<date>` within \
                 {READY_TIMEOUT:?}, so the child never reached the appender — the aged file's \
                 survival would not be evidence of a retention decision\n--- stdout ({}) ---\n{}\n--- stderr ({}) ---\n{}",
                spawned.stdout().len(),
                spawned.stdout(),
                spawned.stderr().len(),
                spawned.stderr(),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    aged.exists()
}

#[test]
fn max_days_zero_is_completed_to_three_on_the_cli_and_in_the_file() {
    // Control: the fixture is genuinely expired, so the default deletes it.
    let port = free_port();
    assert!(
        !aged_file_survives(
            "control: no flag, default 3",
            &file_lane_config(port, ""),
            &["--bind-port", &port.to_string()],
        ),
        "a backdated frps.log.2020-01-01 must be deleted with the default max_days = 3"
    );

    // The defect: `--log-max-days 0` is Go's zero value, completed to 3, so
    // cleanup must still run. Pre-fix this arm alone leaves the file behind.
    let port = free_port();
    assert!(
        !aged_file_survives(
            "cli --log-max-days 0",
            &file_lane_config(port, ""),
            &["--bind-port", &port.to_string(), "--log-max-days", "0"],
        ),
        "`--log-max-days 0` must be completed to 3 (Go `util.EmptyOr(0, 3)`) and must not \
         disable startup cleanup"
    );

    // Falsification control: only the ZERO value is filtered. A negative CLI
    // value is explicit on Go too (`util.EmptyOr(-1, 3)` is `-1`) and must keep
    // cleanup disabled.
    let port = free_port();
    assert!(
        aged_file_survives(
            "cli --log-max-days -1",
            &file_lane_config(port, ""),
            &["--bind-port", &port.to_string(), "--log-max-days=-1"],
        ),
        "a negative --log-max-days is explicit and must disable cleanup (Go parity)"
    );

    // The config-file half of the same Go field.
    let port = free_port();
    assert!(
        !aged_file_survives(
            "config max_days = 0",
            &file_lane_config(port, "max_days = 0\n"),
            &["--bind-port", &port.to_string()],
        ),
        "`[log] max_days = 0` must be completed to 3 in the config"
    );
}

/// **Readiness-gate pin.** An existing but record-free rotation file must not
/// satisfy [`fresh_log_reached_appender`], and the aged fixture must never be
/// mistaken for the fresh one.
///
/// Mutations that must turn this test red (all three measured): (1) restore the
/// pre-fix predicate — `fresh_rotation_file(dir).is_some()` — as
/// [`fresh_log_reached_appender`]'s body: the first assertion then fails at
/// this test's `assert!` line, because `rolling::daily` has already created the
/// empty file (`frp-core/src/logging.rs:378`) while nothing has been written to
/// it; (2) drop the `frps.log.2020-01-01` exclusion from
/// [`fresh_rotation_file`]: the second assertion fails, since `files_in` sorts
/// and the aged fixture comes first; (3) delete the `spawned.exited()` arm in
/// [`aged_file_survives`]: the last arm below then receives the 15 s timeout
/// panic instead of the exit-status one, and fails on its wording.
#[test]
fn readiness_gate_needs_the_appenders_own_record() {
    let dir = TempDir::new("readiness");
    // The aged fixture is present and non-empty, and is never "fresh".
    dir.write_backdated("logs/frps.log.2020-01-01", "an aged record\n", AGED);
    // What `rolling::daily` leaves behind between constructing the appender and
    // the first record: a fresh rotation file with no content at all.
    let fresh = dir.0.join("logs").join("frps.log.2999-01-01");
    std::fs::write(&fresh, "").expect("write empty fresh rotation file");

    assert!(
        !fresh_log_reached_appender(&dir),
        "an empty rotation file must not satisfy the readiness gate — the file exists from \
         `frp-core/src/logging.rs:378`, before `cleanup_expired_logs` decides anything"
    );
    assert_eq!(
        fresh_rotation_file(&dir),
        Some(fresh.clone()),
        "the aged fixture must never be reported as the fresh rotation file"
    );

    // The gate keys on the **full** post-`init_logging` record, not on the
    // program name that every record in this file carries: a record holding the
    // name alone must still not satisfy it. Measured at head, the file holds
    // exactly one record before the gate opens — the marker line itself — so this
    // is the sharper form of the assertion above, and it is what makes a marker
    // weakened to a bare program name red.
    std::fs::write(&fresh, "INFO frps: starting\n").expect("write a name-only record");
    assert!(
        !fresh_log_reached_appender(&dir),
        "a name-only record must not satisfy the readiness gate — the marker is the appender's own \
         post-`init_logging` line, not the program name"
    );

    // The appender's own post-`init_logging` record is the evidence.
    std::fs::write(
        &fresh,
        format!("an earlier record\nINFO {STARTUP_MARKER}0.71.0 starting...\n"),
    )
    .expect("write the appender's own record");
    assert!(
        fresh_log_reached_appender(&dir),
        "the appender's own startup record must satisfy the readiness gate"
    );

    // Fail-fast arm: a child that can never satisfy the gate — here one whose
    // `--bind-port` is unparsable, so it is gone before `init_logging` — must be
    // reported by its own exit status and its streams, not by burning
    // [`READY_TIMEOUT`] on a process that is already gone. Measured at head:
    // this arm panics ~1.6 s in at [`aged_file_survives`]'s `spawned.exited()`
    // panic; without that arm the same input reaches the timeout panic ~15 s in.
    let port = free_port();
    let exited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        aged_file_survives(
            "fail-fast arm: unparsable --bind-port",
            &file_lane_config(port, ""),
            &["--bind-port", "not-a-port"],
        )
    }))
    .expect_err("a child that cannot start must panic, not return a retention verdict");
    let message = exited
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| exited.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default();
    assert!(
        message.contains("before the appender recorded"),
        "the readiness gate must report the child's own exit; got: {message}"
    );
}
