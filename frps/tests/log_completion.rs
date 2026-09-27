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
//! | `[log] level = ""` in the file | **0 B stdout / 0 B stderr**, listener up on `127.0.0.1:<port>` | 4 `INFO` lines on stdout (273 B in this run) |
//! (Go rows are the flags-only lane, `--bind-port <free>`: 3 `INFO` lines,
//! 282 B on stdout, 0 B stderr; the config-file lane is 4 lines / 273 B.)
//! | `[log] to = ""` in the file | 0 B / 0 B **and** a `frps.log.<date>` created in the CWD | logs on stdout |
//! | `[log] maxDays = 0` | logs, but retention disabled | logs |
//! | `--log-level ""` (CLI) | 0 B / 0 B, listener up | logs at `info` |
//! | `--log-file ""` (CLI) | 0 B / 0 B **and** a `frps.log.<date>` in the CWD | logs on stdout |
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
//! while the empty file path is routed to `frps.log.<date>`). It does not assert the **absolute** byte count
//! or line count of a healthy run — those are run-dependent and are reported in
//! `/tmp/log-complete-report.md` instead. It does not cover `--log-format`
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
use std::time::{Duration, Instant};

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
/// empty level parsing as `off` rather than a file redirect.
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
