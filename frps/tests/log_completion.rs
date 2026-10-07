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
//! | `[log] level = ""` in the file | **0 B stdout / 0 B stderr**, listener up on `127.0.0.1:<port>` | 273 B raw on stdout (`frps -c ./frps.toml`; `-c frps.toml` gives 271 B), 3 `INFO` records |
//! | `[log] maxDays = 0` in the file | logs — 7 `INFO` records at startup (1482 B raw / 915 B stripped, implicit `./frps.toml` lane), 11 records / 2410–2412 B raw over the full run — but retention disabled | logs, retains 3 days |
//! | `--log-level ""` (CLI) | 0 B / 0 B, listener up | 282 B on stdout, 3 `INFO` records |
//! | `--log-file ""` (CLI) | 0 B / 0 B **and** a `frps.log.<date>` in the CWD | logs on stdout |
//! | `[log] to = ""` in the file | logs — same 7-record startup shape (1482 B raw / 915 B stripped), **no** `frps.log.*` file created | logs on stdout |
//!
//! The Go rows are the **flags-only** lane (`--bind-port <free>`, 282 B / 3
//! `INFO` records) or the **config-file** lane, whichever matches the shape. The
//! config-file row is `frps -c ./frps.toml`: 273 B raw / 240 B stripped, 3 `INFO`
//! records, and its first record echoes the `-c` argument, so `-c frps.toml`
//! measures 271 / 238. The line count is `INFO` **records**, not
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
//! = 1482 B raw / 915 B stripped (1480 / 913 at the four-digit pids of a later
//! sample), 11 records over the full run = 2410–2412 B raw / 1471–1473 B stripped
//! (2407–2410 / 1468–1471 at four-digit pids; both ranges are for a five-digit
//! ephemeral port). Three terms move those totals: the `elapsed_secs=` value
//! width, the pid digit count, and the `bind_port` digit count — the config is
//! echoed eight times across the startup block's four `run{…}` records plus once
//! in each of the three shutdown records, so one port digit is 11 B (a forced
//! four-digit port measures 2401 B raw / 1462 B stripped). raw − stripped is a
//! constant 939 B in every sample. No `frps.log.*` file is created in either
//! shape. The earlier
//! `1498 B / 7 records` is the same lane and binary with this file's own template
//! `bind_addr = "127.0.0.1"` (`config()` below) instead of the binary default
//! `0.0.0.0`: the address is echoed eight times across the startup block's four
//! `run{…}` records, so its two extra characters add 16 B (1498 − 1482; 1496 B at
//! a four-digit pid). For these two rows the record *shape* is the same on both
//! sides of the completion fix, which changed retention only (and not `to = ""` at
//! all).
//!
//! A later fix sits one layer **above** completion and is pinned by the
//! `cli_empty_log_level_does_not_raise_the_files_warn`,
//! `cli_empty_log_file_keeps_the_files_destination` and
//! `cli_zero_log_max_days_keeps_the_files_retention` sections below:
//! `FrpsArgs::override_server_config` (`frp-core/src/cli.rs`) now treats every
//! zero value in the three Go `[log]` CLI fields as "flag not supplied" — an
//! empty `--log-level ""`, an empty `--log-file ""` and an explicit
//! `--log-max-days 0` leave the loaded file's `[log]` value in place, so
//! completion has nothing to fill and nothing outranks the file. The rows above
//! all use a config *without* `[log] level`/`file`/`max_days`, which is why they
//! are unchanged by it — there the completion fills the empty/zero value exactly
//! as Go's `EmptyOr` does. Go's `-c` lane arbitrates all three (the Go table is
//! in the level section below); only the `--log-max-days` retention *observable*
//! has no Go startup counterpart, which that section says explicitly.
//!
//! **What this file models.** The end-to-end effect on the two streams and on the
//! CWD for the shipped `frps` binary, over two lanes: the config-file lane
//! (`-c`, which is where Go also completes a fresh struct,
//! `pkg/config/load.go:313-321`) and the CLI-override lane (no `-c`; frp-rs's
//! `cli_overrides_enabled` + `override_server_config`, which writes a non-zero
//! flag value into the struct **before** `cfg.complete()` runs).
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
//! measured on `frps --bind-port <free>` with `bind_addr = "127.0.0.1"`: 1498 B
//! / 7 records before the connect (1496 B at a four-digit pid), **1800 B / 8
//! records after it**, the extra record being
//! `WARN frp_server::service: Failed to detect connection type … early eof`
//! (302 B). The byte figures in the table above are therefore measured with
//! `lsof` as the liveness probe (see `/tmp/log-complete-report.md`), and this
//! file asserts *content* (the startup marker is present), never a byte count. It does not cover `--log-format`
//! (frp-rs-only; Go answers `unknown flag`) or the `--config-dir` lane; the
//! `frpc` control lives in `frpc/tests/log_completion.rs`.
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

/// **CLI-override lane, the file half, with no `[log] file` in the config**:
/// `--log-file ""` is treated as *not supplied*, so the file's own value governs
/// — here that is serde's default `"console"`, so the shape logs on stdout and
/// must not create `frps.log.<date>`. `--log-max-days 0` rides along for the
/// same reason (it too is skipped, and the file's default `3` governs). The
/// discriminating file shape — a config that *names* a destination — is
/// `cli_empty_log_file_keeps_the_files_destination` below.
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

// ── the three `[log]` CLI zero values are "flag not supplied" ───────────────
//
// The lane matrix above ends at completion. This section pins the **overlay**
// one layer up: `FrpsArgs::override_server_config` (`frp-core/src/cli.rs`) writes
// CLI values into the struct before `cfg.complete()` runs, so an empty
// `--log-level ""` used to overwrite the file's `[log] level` with `""` and
// completion then filled it to `"info"` — *raising* the level. The same rewrite
// corrupted the two sibling fields: an empty `--log-file ""` became the concrete
// `"console"` and an explicit `--log-max-days 0` became `3`, each outranking the
// file it was supposed to leave alone.
//
// Go's `-c` lane discards every CLI flag outright (`cmd/frps/root.go:66-84` loads
// the file into a fresh struct and never merges the flag-bound `serverCfg`), so
// it arbitrates all three — measured on the real v0.71.0 binary, own free port,
// both streams captured, before any signal:
//
// | Go row | stdout | the file |
// |---|---|---|
// | `frps -c cfg(level=warn) --log_level ""` | 0 B | — (level stayed `warn`) |
// | `frps -c cfg(level=warn)` | 0 B | — |
// | `frps -c cfg(to=<dir>/frps-out.log) --log_file ""` | 0 B | 3 `INFO` written |
// | `frps -c cfg(to=<dir>/frps-out.log)` | 0 B | 3 `INFO` written (byte-identical) |
// | `frps -c cfg(to=…, maxDays=7) --log_max_days 0` + 5-day-old fixture | 0 B | fixture survives |
// | `frps -c cfg(to=…, maxDays=7)` + 5-day-old fixture | 0 B | fixture survives |
//
// The file-row byte total is **not** a constant and is deliberately not quoted:
// the first record echoes the `-c` path (`frps uses config file: <path>`,
// `cmd/frps/root.go:115`), so the same file measures 300 B with the absolute
// `-c` path of a scratch dir and 237 B with a relative one. What is constant —
// and what arbitrates the flag — is stdout 0 B, three `INFO` records, and the
// byte-for-byte identity of the two rows.
//
// The last two rows are the honest edge: Go's retention sweep is **midnight-only**
// (`golib@v0.8.2/log/output_rotatefile.go:103`), so no Go lane can *observe* a
// retention difference at startup. `--log-max-days 0` is Go-parity by
// construction there — the flag is discarded on the `-c` lane — and the arm
// below is stated as an observable pin of *our* rule, not as a Go measurement.
// `frpc` has no overlay at all, so its resolver's existing empty-CLI filter
// already keeps the file's value; that is pinned as a *control* in
// `frpc/tests/log_completion.rs`.
//
// The level's discriminating shape is `[log] level = "warn"` plus a written
// `[web_server.tls] enable = true`: the inert-key warning is a `WARN` record
// emitted on every build right after `init_logging`
// (`presence.warn_inert_web_server_tls_enable`, called at
// `frps/src/main.rs:1093`), while the startup marker is an `INFO` record
// (`frps/src/main.rs:1115`). So
// "`web_server.tls.enable has no effect` present **and** `frps (Rust) v` absent"
// pins the effective level at *exactly* `warn`: `info` would add the marker,
// `error` would drop the warning.
//
// Measured at head **with `--features dashboard`** (the CI feature shape — the
// inert-key clause is longer there than on the default build,
// `frp-core/src/config/loader.rs:524-541`), at the observation point the test
// itself uses: one loopback `TcpStream::connect` (`assert_loopback_listens`)
// followed by [`SETTLE`], both streams read **before** the child is signalled.
// (A run with *zero* connects gives 268 B / 235 B and **one** `WARN`; the
// post-`SIGTERM` shutdown records are excluded throughout.)
//
// Byte totals are the one machine-dependent column, and nothing asserts them:
// the timestamp is fixed-width but the pid and port digits are not, so the same
// shape drifts by a few bytes run to run (the header above records `1482 B /
// 915 B` becoming `1480 / 913` at a four-digit pid — worth ~2 B here — while one
// port digit is 8 B in this startup block and 11 B over the full run). Read them
// as "≈", the way `docs/config.md` does; every assertion below is on record
// composition instead — `WARN` present, marker and ` INFO` absent, stderr empty.
//
// | arm | stdout | records |
// |---|---|---|
// | `level = "warn"` + `--log-level ""` | 570 B / 472 B | 2 `WARN`, 0 `INFO`, marker absent |
// | `level = "warn"`, no flag | 570 B / 472 B | 2 `WARN`, 0 `INFO`, marker absent |
// | `level = "error"` + `--log-level ""` | 0 B | none |
// | `level = "warn"` + `--log-level info` (arm 3) | 2068 B / 1403 B | 7 `INFO` + 2 `WARN`, marker present |
//
// The `info` arm is the falsification control that proves the marker exists in
// this config shape, so its absence above is the file's `warn` rather than a
// missing record. Reverting the empty-value rule reds arm 1 on the marker
// assertion: the flag writes `""` into `[log] level`, completion fills it to
// `"info"`, and arm 1 becomes byte-for-byte the `info` arm (2068 B / 1403 B,
// 7 `INFO` + 2 `WARN`) instead of 0 `INFO`.
//
// Why this table quotes *pre-signal* counts: the same run read to EOF after
// `SIGTERM` measures 3004 B / 1967 B and **11** `INFO` records, because the
// graceful-shutdown sequence adds four more of them (`Received SIGTERM,
// initiating graceful shutdown...`, `Accept loop stopped...`, `Draining 0 active
// connections...`, `All connections drained in 0.0s`). Counting after the signal
// is what produced the older "11 `INFO`" figures.

/// The inert-key `WARN` that `[web_server.tls] enable = true` produces on every
/// build. Its text varies by build (`frps/tests/warn_delivery.rs` pins the three
/// clauses apart); the shared first half is stable and is all this file needs.
const INERT_TLS_WARN: &str = "web_server.tls.enable has no effect";

/// `[log] level = "{level}"` and the inert-key warning switched on, on its own
/// port so the two arms can run back to back without racing for the bind.
fn level_config(port: u16, level: &str) -> String {
    config(
        port,
        &format!("\n[log]\nlevel = \"{level}\"\n\n[web_server.tls]\nenable = true\n"),
    )
}

/// Assert, from the emitted records alone, that the effective level is exactly
/// the file's `warn`: a `WARN` record was admitted and no `INFO` record was.
fn assert_exactly_warn(tag: &str, spawned: &Spawned) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(INERT_TLS_WARN),
        "{tag}: no `{INERT_TLS_WARN}` WARN record reached stdout, so the \
         effective level is not the file's `warn` (or nothing logged)\n\
         --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{err}",
        out.len(),
        err.len(),
    );
    assert!(
        !out.contains(STARTUP_MARKER),
        "{tag}: the `{STARTUP_MARKER}` startup marker appeared, so the effective \
         level fell to `info` — the empty flag raised it above the file's `warn`\n\
         --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{err}",
        out.len(),
        err.len(),
    );
    assert!(
        !out.contains(" INFO"),
        "{tag}: an INFO record reached stdout, so the effective level is not \
         the file's `warn`\n--- stdout ({} B) ---\n{out}",
        out.len(),
    );
    assert!(
        err.is_empty(),
        "{tag}: stderr must stay empty, got {} B:\n{err}",
        err.len()
    );
}

/// **The pin:** an explicitly supplied but empty `--log-level ""` is not a
/// level — it leaves the file's `[log] level = "warn"` alone, so the two
/// binaries agree and the empty flag is observationally absent.
#[test]
fn cli_empty_log_level_does_not_raise_the_files_warn() {
    // Arm 1: the flag under test.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let spawned = Spawned::start(&cfg, &["--bind-port", &port.to_string(), "--log-level", ""]);
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        assert_exactly_warn("--log-level \"\"", &spawned);
    }

    // Arm 2: the same config with the flag omitted. The empty flag's *presence*
    // must make no difference, which is what "treated as not supplied" means.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let spawned = Spawned::start(&cfg, &["--bind-port", &port.to_string()]);
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        assert_exactly_warn("no flag (control)", &spawned);
    }

    // Arm 3: the marker's own control. A *non-empty* flag still wins, which
    // proves both that the marker is emitted at `info` in this config shape and
    // that the overlay was not disabled wholesale.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let spawned = Spawned::start(
            &cfg,
            &["--bind-port", &port.to_string(), "--log-level", "info"],
        );
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        let out = spawned.stdout();
        assert!(
            out.contains(STARTUP_MARKER),
            "--log-level info: a non-empty flag must still raise the level; no \
             `{STARTUP_MARKER}` record on stdout\n--- stdout ({} B) ---\n{out}",
            out.len(),
        );
        assert!(
            out.contains(INERT_TLS_WARN),
            "--log-level info: the WARN record must still be admitted"
        );
    }
}

// ── `-c <file>`: the file is authoritative for the whole `[log]` section ─────
//
// R1 (`TODO.md:11101`). On Go's `-c` lane the pflag-bound struct is discarded
// wholesale — `cmd/frps/root.go:67-83` takes the file branch, so `runServer` at
// `cmd/frps/root.go:112` inits the logger from the *file's* `cfg.Log` — and
// `frps -c frps.toml --log-level info` over a file with `[log] level = "warn"`
// therefore prints **0** records. Pre-fix, frp-rs gated only
// `override_server_config` on `cli_overrides_enabled` (`frps/src/main.rs:1068-1070`)
// while `init_logging` (`frps/src/main.rs:1080`) still read the raw CLI value:
// measured on that binary the same argv printed **11** `INFO` records (2434 B)
// and `--log-level debug` printed 11 `INFO` + 3 `DEBUG` (2860 B), while the
// no-flag control printed 231 B / 0 `INFO` / 1 `WARN` — `level_config` always
// adds the inert `[web_server.tls] enable` warning, which `assert_exactly_warn`
// requires. `init_logging` now masks the four CLI log flags whenever a `-c`
// config was loaded and no `--config-dir` is in play.
//
// Reverting the mask (an `init_logging` that always reads the CLI) reds arm 1
// below inside `assert_exactly_warn`'s startup-marker assertion with 11 `INFO`
// records on stdout; arms 2 and 3 stay green — measured on that reverted binary,
// `-c frps.toml` prints 231 B / 0 `INFO` / 1 `WARN` and the implicit lane prints
// 2434 B / 11 `INFO`. That pair is what distinguishes "the flag was ignored" from
// "the whole `[log]` section was ignored".

/// **The pin:** with `-c`, a non-empty `--log-level` is discarded like every
/// other CLI config flag — the file's `[log] level = "warn"` stands.
#[test]
fn cli_nonempty_log_level_flag_does_not_override_the_config_file() {
    // Arm 1: the flag under test, on the `-c` lane. `Spawned::start` runs the
    // child in a scratch dir holding `./frps.toml`, which is what the relative
    // `-c frps.toml` resolves against.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let spawned = Spawned::start(&cfg, &["-c", "frps.toml", "--log-level", "info"]);
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        assert_exactly_warn("-c frps.toml --log-level info", &spawned);
    }

    // Arm 2: the same config and lane with the flag omitted. The two arms must
    // look identical if and only if the flag is genuinely ignored here.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let spawned = Spawned::start(&cfg, &["-c", "frps.toml"]);
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        assert_exactly_warn("-c frps.toml (control)", &spawned);
    }

    // Arm 3: the *implicit* lane's own control. The same flag without `-c` must
    // still raise the level — that is the override #427 kept and the contract at
    // `frp-core/src/cli.rs:5090-5097`, and it is what proves the mask is scoped
    // to the `-c` lane rather than disabling the CLI log flags wholesale.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let spawned = Spawned::start(
            &cfg,
            &["--bind-port", &port.to_string(), "--log-level", "info"],
        );
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        let out = spawned.stdout();
        assert!(
            out.contains(STARTUP_MARKER),
            "implicit lane: a non-empty flag must still raise the level; no \
             `{STARTUP_MARKER}` record on stdout\n--- stdout ({} B) ---\n{out}",
            out.len(),
        );
    }

    // Arm 4: `-c` and `--config-dir` **together**. The config-dir branch
    // (`frps/src/main.rs:525`) is the one that runs, and its
    // `init_logging(&cli, None)` (`frps/src/main.rs:526`) honours the CLI flags,
    // so `--log-level warn` must still be applied. Masking on
    // `cli.config.is_some()` alone made this arm print 11 `INFO` records
    // (2092 B on this scratch fixture), byte-identical to dropping the flag.
    let port = free_port();
    let cfg = level_config(port, "warn");
    {
        let dir = TempDir::new("spawn-cfgdir");
        dir.write("frps.toml", &cfg);
        std::fs::create_dir_all(dir.0.join("cfgdir")).expect("create cfgdir");
        dir.write("cfgdir/frps.toml", &cfg);
        let spawned = Spawned::start_in(
            dir,
            &[
                "-c",
                "frps.toml",
                "--config-dir",
                "cfgdir",
                "--log-level",
                "warn",
            ],
        );
        assert_loopback_listens(port);
        std::thread::sleep(SETTLE);
        assert_exactly_warn(
            "-c frps.toml --config-dir cfgdir --log-level warn",
            &spawned,
        );
    }
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
// The CLI-zero half of this field moved one layer up in the empty-value commit:
// an explicit `--log-max-days 0` is now skipped by the overlay, so the *file's*
// `max_days` governs. The discriminating shape therefore needs a file value that
// differs from Go's zero default, and it is pinned by
// `cli_zero_log_max_days_keeps_the_files_retention` below. This test keeps the
// arms that pin what **completion** still owns; all of them are unchanged at
// head, and the table records why:
//
// | shape here | pre-fix | at head |
// |---|---|---|
// | no flag, no `max_days` key (defaults to 3) | deleted | deleted — the fixture is genuinely expired |
// | `--log-max-days 0`, no `max_days` key | **SURVIVES** (zero completed to 3 on the old overlay) | deleted — the flag is skipped, and the file's default 3 governs |
// | `--log-max-days -1` (CLI) | survives | survives — only the zero value is filtered |
// | `[log] max_days = 0` in the file | **SURVIVES** | deleted — the file's own zero completes to 3 |
//
// The `[log] max_days = 0` arm was already fixed by `LogConfig::complete` in the
// previous commit; it is asserted here so the two halves of the same Go field
// are pinned in one place, and so a future change that drops the config-side
// fill fails loudly rather than silently. The second row's *observable* is
// unchanged by the overlay skip but its mechanism is not — which is exactly why
// the 7-vs-0 pin exists alongside it.
//
// This test deliberately does **not** use `assert_logged_and_listening`: the
// config logs to a file, so stdout carries no startup record, and its
// `TcpStream::connect` liveness probe would inject a WARN record into the stream
// a byte-count assertion would be reading (the sibling shapes' 1498 B / 7-record
// convention is measured with no connect). Liveness here is the appender's own
// `STARTUP_MARKER` record in that file, not the file's existence — see `fresh_log_reached_appender`.

/// The fixture's mtime for the shapes that must be *expired under any positive
/// window*: `UNIX_EPOCH`, far outside any `max_days` these tests use. Retention
/// compares the file's **mtime**, not the date in its name
/// (`frp-core/src/logging.rs` `cleanup_expired_logs` → `is_log_expired(modified,
/// now, max_days)`), which is why the fixture is named `…2020-01-01` while its
/// mtime is the epoch — the name is decoration.
const AGED: SystemTime = UNIX_EPOCH;

/// A fixture that is expired at `max_days = 3` but alive at `max_days = 7` — the
/// window the `--log-max-days 0` pin needs in order to tell "the flag was
/// skipped (file's 7 governs)" from "the flag's 0 was completed to 3 and the
/// default governed".
const OLDER_THAN_THE_DEFAULT: Duration = Duration::from_secs(5 * 24 * 60 * 60);

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
/// **after** `init_logging` returns ([`STARTUP_MARKER`], `frps/src/main.rs:1115`).
///
/// Mere existence is not evidence that anything ran: `tracing_appender::rolling::daily`
/// creates `logs/frps.log.<date>` eagerly when it is constructed
/// (`frp-core/src/logging.rs:443`), *before* the subscriber is installed and
/// before `cleanup_expired_logs` runs (`frp-core/src/logging.rs:467`). A
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

/// Block until the appender's own post-`init_logging` record has reached the
/// fresh rotation file, or fail with a diagnostic that says which of the two
/// ways it did not happen — a child that exited, or a gate that never opened.
///
/// The wait is for the appender's own record ([`fresh_log_reached_appender`]),
/// not for the fresh file's existence and not for any caller's fixture: the
/// readiness gate has to be strictly *after* the retention decision (and after
/// `init_logging` returns), or a surviving fixture is reported as a retention
/// outcome when it is only a timing artifact. The child's own exit is checked on
/// every poll, so a shape that can never satisfy the gate reports *that* (with
/// its streams) instead of burning [`READY_TIMEOUT`].
fn wait_for_the_appenders_own_record(tag: &str, spawned: &mut Spawned) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if fresh_log_reached_appender(&spawned.dir) {
            return;
        }
        if let Some(status) = spawned.exited() {
            panic!(
                "{tag}: frps exited ({status}) before the appender recorded {STARTUP_MARKER:?} in \
                 a fresh `logs/frps.log.<date>`, so nothing measured after that point would be \
                 evidence about the child's configuration\n--- stdout ({}) ---\n{}\n--- stderr \
                 ({}) ---\n{}",
                spawned.stdout().len(),
                spawned.stdout(),
                spawned.stderr().len(),
                spawned.stderr(),
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "{tag}: no appender record reached a fresh `logs/frps.log.<date>` within \
                 {READY_TIMEOUT:?}, so the child never reached the appender\n--- stdout ({}) \
                 ---\n{}\n--- stderr ({}) ---\n{}",
                spawned.stdout().len(),
                spawned.stdout(),
                spawned.stderr().len(),
                spawned.stderr(),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Spawn in a scratch dir holding a backdated `logs/frps.log.2020-01-01`, then
/// report whether it survived startup. Bounded: every wait has a deadline, and
/// the child is reaped by [`ChildGuard`] on every path.
fn aged_file_survives(tag: &str, config: &str, argv: &[&str]) -> bool {
    aged_file_survives_with(tag, config, argv, AGED)
}

/// [`aged_file_survives`] with the fixture's mtime set explicitly. The epoch
/// fixture is expired under every positive window, which cannot distinguish a
/// window of `3` from a window of `7`; passing `SystemTime::now() - age`
/// produces the fixture that can.
fn aged_file_survives_with(tag: &str, config: &str, argv: &[&str], when: SystemTime) -> bool {
    let dir = TempDir::new("aged");
    dir.write("frps.toml", config);
    let aged = dir.write_backdated("logs/frps.log.2020-01-01", "aged\n", when);
    let mut spawned = Spawned::start_in(dir, argv);
    wait_for_the_appenders_own_record(tag, &mut spawned);
    aged.exists()
}

/// **The `--log-file ""` pin:** an explicitly supplied empty value is treated as
/// *not supplied*, so a config that names a destination keeps it — the records
/// must land in `logs/frps.log.<date>` and **not** on stdout.
///
/// Measured at head (`--features dashboard`, the file lane's own observation
/// point — `wait_for_the_appenders_own_record`, so no loopback connect and no
/// signal): stdout 0 B, and `logs/frps.log.2026-10-01` written with the startup
/// marker in it — the same observable as the identical config with no flag at
/// all. Go's `-c` lane is the arbiter:
/// `frps -c cfg(to=<dir>/frps-out.log) --log_file ""` → stdout 0 B and the file
/// written (three `INFO` records, byte-identical to the no-flag row — the byte
/// total varies with the `-c` path form, `cmd/frps/root.go:115`); Go's
/// flags-only lane completes the empty value to `"console"` (282 B / 3 `INFO`),
/// which is the same outcome, because it has no file value to preserve.
/// Pre-fix this shape wrote **2735 B to stdout and never created `logs/`**,
/// because completion had already rewritten the empty flag to the concrete
/// `"console"` before the resolver's own empty filter could see it.
#[test]
fn cli_empty_log_file_keeps_the_files_destination() {
    let port = free_port();
    let dir = TempDir::new("cli-empty-file");
    dir.write("frps.toml", &file_lane_config(port, "level = \"info\"\n"));
    let mut spawned = Spawned::start_in(dir, &["--bind-port", &port.to_string(), "--log-file", ""]);
    wait_for_the_appenders_own_record("cli --log-file \"\"", &mut spawned);

    let out = spawned.stdout();
    assert!(
        !out.contains(STARTUP_MARKER),
        "cli --log-file \"\": the file's `to` must still govern, but the {STARTUP_MARKER:?} \
         startup marker reached stdout — the empty flag diverted the log to `console`\n\
         --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{}",
        out.len(),
        spawned.stderr().len(),
        spawned.stderr(),
    );
    assert!(
        spawned
            .dir
            .files_in("logs")
            .iter()
            .any(|f| f.starts_with("frps.log.")),
        "cli --log-file \"\": no `frps.log.<date>` under `logs/`, so the records went nowhere \
         (dir listing: {:?})",
        spawned.dir.files(),
    );
}

/// **The `--log-max-days 0` pin:** the zero is treated as *not supplied*, so a
/// file that sets `max_days = 7` keeps a five-day-old fixture alive.
///
/// The discriminating shape needs a file value that differs from Go's zero
/// default **and** a fixture that the two candidate windows disagree about: with
/// `[log] max_days = 7` and a `logs/frps.log.2020-01-01` whose **mtime** is five
/// days old (expired at `3`, alive at `7`), pre-fix the flag's zero was written
/// into the struct and then completed to `3`, so the fixture was **deleted**; at
/// head the flag is skipped and the file's `7` governs, so it **survives**.
/// Measured at head (the file lane's own observation point, no liveness connect):
/// survives with `--log-max-days 0` and with no flag; **deleted** with
/// `--log-max-days 3`, which is the control that a non-zero flag still wins.
/// Go cannot observe this at startup — its sweep is midnight-only
/// (`golib@v0.8.2/log/output_rotatefile.go:103`), so `frps -c cfg(maxDays=7)
/// --log_max_days 0` and the no-flag row are indistinguishable (both leave the
/// fixture) — but its `-c` lane discards the flag the same way, so "the file's
/// value governs" is the Go-parity direction, not a guess.
#[test]
fn cli_zero_log_max_days_keeps_the_files_retention() {
    // The pin: the flag's zero leaves the file's 7 in place.
    let port = free_port();
    assert!(
        aged_file_survives_with(
            "file max_days = 7 + --log-max-days 0",
            &file_lane_config(port, "max_days = 7\n"),
            &["--bind-port", &port.to_string(), "--log-max-days", "0"],
            SystemTime::now() - OLDER_THAN_THE_DEFAULT,
        ),
        "`--log-max-days 0` must be treated as `flag not given` and leave the file's \
         max_days = 7 in place; pre-fix the zero was completed to 3 and deleted this 5-day-old \
         fixture"
    );

    // Control 1: a non-zero flag still wins over the file.
    let port = free_port();
    assert!(
        !aged_file_survives_with(
            "file max_days = 7 + --log-max-days 3",
            &file_lane_config(port, "max_days = 7\n"),
            &["--bind-port", &port.to_string(), "--log-max-days", "3"],
            SystemTime::now() - OLDER_THAN_THE_DEFAULT,
        ),
        "a non-zero `--log-max-days 3` must still win over the file's 7 and delete the fixture"
    );

    // Control 2: with no flag at all the file's own 7 governs, so the fixture
    // survives — the same observable the pin asserts, from the other direction.
    let port = free_port();
    assert!(
        aged_file_survives_with(
            "file max_days = 7, no flag",
            &file_lane_config(port, "max_days = 7\n"),
            &["--bind-port", &port.to_string()],
            SystemTime::now() - OLDER_THAN_THE_DEFAULT,
        ),
        "control: the file's max_days = 7 alone must preserve a 5-day-old fixture"
    );
}

/// **An explicit `0` never disables cleanup.** Go completes it to the default `3`
/// (`util.EmptyOr(0, 3)`, `pkg/config/v1/common.go:122`) whether it arrives from
/// `--log-max-days 0` or from `[log] max_days = 0`, so both shapes delete a
/// backdated fixture.
///
/// The two halves of the title are carried by different shapes. The CLI half is
/// exact because the overlay skips the zero, so the value that governs this
/// shape is serde's own default `3`; the shape that isolates the CLI zero against
/// a file value is `[log] max_days = 7` + `--log-max-days 0`, pinned by
/// [`cli_zero_log_max_days_keeps_the_files_retention`] above. The file half is the
/// last arm here: its fixture is five days old
/// ([`OLDER_THAN_THE_DEFAULT`]), so it dies only if the file's `0` really filled
/// to **3** — an uncompleted `0` disables cleanup and keeps it, and a wrong fill
/// such as `7` keeps it too. One pair stays unseparable and is not claimed:
/// `max_days = 0` and an absent `max_days` key are observationally identical,
/// because serde's default for the field is Go's `3` as well.
#[test]
fn max_days_zero_does_not_disable_cleanup_on_the_cli_or_in_the_file() {
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

    // The completion defect: `--log-max-days 0` is Go's zero value, completed to
    // 3, so cleanup must still run. (The overlay also skips the zero now, so the
    // value governing this shape is the file's absent `max_days` → serde's 3;
    // the shape that isolates the overlay skip is the `max_days = 7` pin above.)
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

    // The config-file half of the same Go field, and the arm that makes the
    // "in the file" half of this test's title discriminating: the fixture is five
    // days old, so it is deleted only if the file's `0` really completed to the
    // default **3**. (An uncompleted `0` would disable cleanup and keep it; a
    // wrong fill such as `7` would also keep it. The epoch fixture above cannot
    // tell those apart — see this test's doc comment.)
    let port = free_port();
    assert!(
        !aged_file_survives_with(
            "config max_days = 0",
            &file_lane_config(port, "max_days = 0\n"),
            &["--bind-port", &port.to_string()],
            SystemTime::now() - OLDER_THAN_THE_DEFAULT,
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
/// empty file (`frp-core/src/logging.rs:443`) while nothing has been written to
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
         `frp-core/src/logging.rs:443`, before `cleanup_expired_logs` decides anything"
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

// ── the `-c` lane discards **all four** log flags, not just `--log-level` ───
//
// The mask at `frps/src/main.rs:439` withholds four CLI values at once
// (`log_level`, `log_file`, `log_max_days`, `log_format`), but
// `cli_nonempty_log_level_flag_does_not_override_the_config_file` above drives
// `--log-level` only — so a regression that masked just one of the other three
// passed every pin in this file. Each arm below drives one of them on a `-c`
// lane whose file names the opposite behaviour, so unmasking that one value
// turns its arm red. Go's `-c` lane is the arbiter for all three: it discards
// the whole pflag-bound struct (`/tmp/frp-go-src/cmd/frps/root.go:67-83`).
#[test]
fn cli_file_retention_and_format_flags_do_not_override_the_config_file() {
    // Arm 1 — `--log-file console`. The file names `logs/frps.log`, so the flag
    // must be discarded and the records must land there, never in a rotation
    // file named after the flag's own value. Measured on Go v0.71.0:
    // `-c cfg(to=filelogs/frps.log) --log_file console` wrote `filelogs/frps.log`
    // (the flag-bound struct is discarded); unmasking `log_file` alone writes
    // `console.<date>` in the child's CWD (that row and the masked row differ
    // only in destination — stdout stays empty in both).
    let port = free_port();
    let dir = TempDir::new("cli-c-file");
    dir.write("frps.toml", &file_lane_config(port, "level = \"info\"\n"));
    let mut spawned = Spawned::start_in(dir, &["-c", "frps.toml", "--log-file", "console"]);
    assert_loopback_listens(port);
    // `init_logging` opens the appender's file before the listener binds, so on
    // this lane the diversion (if any) is already on disk — the failing
    // direction needs no wait, and the successful direction still gets the
    // appender-record wait below.
    std::thread::sleep(SETTLE);
    let diverted: Vec<String> = spawned
        .dir
        .files()
        .into_iter()
        .filter(|f| f.starts_with("console"))
        .collect();
    assert!(
        diverted.is_empty(),
        "`-c` must discard `--log-file console`: the file's `to` governs, but the log was \
         diverted to {diverted:?} (dir listing: {:?})",
        spawned.dir.files(),
    );
    wait_for_the_appenders_own_record("cli -c --log-file console", &mut spawned);
    assert!(
        spawned
            .dir
            .files_in("logs")
            .iter()
            .any(|f| f.starts_with("frps.log.")),
        "`-c` must keep the file's `to`: no `frps.log.<date>` under `logs/` (dir listing: {:?})",
        spawned.dir.files(),
    );

    // Arm 2 — `--log-max-days 3`. The file sets `max_days = 7`; a five-day-old
    // fixture is expired at 3 and alive at 7, so unmasking `log_max_days` alone
    // deletes it.
    let port = free_port();
    assert!(
        aged_file_survives_with(
            "file max_days = 7 + -c + --log-max-days 3",
            &file_lane_config(port, "max_days = 7\n"),
            &["-c", "frps.toml", "--log-max-days", "3"],
            SystemTime::now() - OLDER_THAN_THE_DEFAULT,
        ),
        "`-c` must discard `--log-max-days 3`: the file's `max_days = 7` governs, so the \
         five-day-old fixture survives; unmasking `log_max_days` alone applies the flag's 3 and \
         deletes it"
    );

    // Arm 3 — `--log-format json`. The file says `format = "text"`, so the
    // records must stay text: unmasking `log_format` alone turns stdout into
    // `"level":"INFO"` JSON records (the startup marker text still appears inside
    // the JSON `message` field, which is why the assertion keys on the level
    // field and not on the marker).
    let port = free_port();
    let cfg = config(port, "\n[log]\nlevel = \"info\"\nformat = \"text\"\n");
    let spawned = Spawned::start(&cfg, &["-c", "frps.toml", "--log-format", "json"]);
    assert_logged_and_listening("cli -c --log-format json", &spawned, port);
    let out = spawned.stdout();
    assert!(
        !out.contains("\"level\":\"INFO\""),
        "`-c` must discard `--log-format json`: the file's `format = \"text\"` governs, but the \
         records arrived as JSON\n--- stdout ({} B) ---\n{out}",
        out.len(),
    );
}
