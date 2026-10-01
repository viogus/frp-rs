//! `frpc`'s half of the **empty `--log-level ""`** pin.
//!
//! The item: an explicitly supplied but empty `--log-level ""` means `"info"`
//! on `frps` and *the file's level* on `frpc`, so the two binaries disagree
//! whenever the config sets a non-default `level`. Only `frps` overlays its CLI
//! flags onto the loaded config (`FrpsArgs::override_server_config`,
//! `frp-core/src/cli.rs`), so the empty flag reached `[log] level` there and
//! `LogConfig::complete` filled it to `"info"`. The fix is on the `frps` side —
//! the overlay now skips an empty `--log-level` — and `frps`'s arms live in
//! `frps/tests/log_completion.rs::cli_empty_log_level_does_not_raise_the_files_warn`.
//!
//! **This file is the client's control.** `frpc` has no overlay at all: it
//! passes `cli.log_level` straight to `logging::resolve_log_level`
//! (`frpc/src/main.rs:367-371`), whose existing empty-CLI filter already falls
//! through to `cfg.log.level`. So the correct outcome here is the one that was
//! always observed, and the test exists to make it a *contract*: if a future
//! change "aligns" the binaries by giving `frpc` the same overlay — writing `""`
//! into `[log] level` and completing it to `"info"` — this test goes red.
//!
//! **The observable.** `[log] level = "warn"` with `loginFailExit = false`
//! against a closed port: the client retries and logs `Login failed (attempt 1)`
//! at `WARN` on the first try, so a `WARN` record is guaranteed inside
//! [`RECORD_TIMEOUT`] with no server to run. The startup marker
//! (`frpc (Rust) v`) is an `INFO` record (`frpc/src/main.rs:649` installs the
//! sink, the marker follows). So "one `WARN`, no `INFO`, marker absent, clean
//! stderr" pins the effective level at exactly the file's `warn` — `info` would
//! add the marker and the `run`-span `INFO` records, `error` would drop the
//! login warning. Measured at head, at a **fixed** window the two arms are
//! byte-identical — the byte total is a function of how many retries fit, not of
//! whether the flag was passed:
//!
//! | window | `--log-level ""` | the same config, no flag |
//! |---|---|---|
//! | 1.5 s | 312 B / 247 B stripped, 1 `WARN`, 0 `INFO` | 312 B / 247 B, 1 `WARN`, 0 `INFO` |
//! | 3.0 s | 624 B / 494 B stripped, 2 `WARN`, 0 `INFO` | 624 B / 494 B, 2 `WARN`, 0 `INFO` |
//!
//! (retry interval ≈2.1 s). No byte total is asserted, because the count depends
//! on the window: the test waits for the record with [`Spawned::wait_for`] and
//! then asserts *composition*. The `info` falsification control for the marker
//! assertion measures **1066 B / 2 `INFO` + 2 `WARN`** at a 3 s window
//! (pre-`SIGTERM`; the graceful-shutdown sequence adds three more `INFO`
//! records), and is kept below.
//!
//! Gated on `full` because the `frpc` bin carries `required-features = ["full"]`,
//! so without the gate this file would fail to compile in the no-default-features
//! lanes CI runs.
#![cfg(feature = "full")]

use std::collections::HashSet;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The binary under test: the one `cargo test -p frpc` built for this target.
/// `FRPC_BIN` overrides it, which is how the pre-change falsification runs.
const BIN: &str = env!("CARGO_BIN_EXE_frpc");
/// How long the record under test may take to become visible on stdout. The
/// first login attempt succeeds on the first poll in practice; this is the
/// load-independent ceiling, not the expected wait.
const RECORD_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a killed child may take to disappear before the guard gives up.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// A substring of the first record `frpc` emits **after** `init_logging`, so
/// seeing it proves the load succeeded and an `INFO`-admitting subscriber
/// exists.
const STARTUP_MARKER: &str = "frpc (Rust) v";
/// The `WARN` the closed-port shape guarantees: attempt 1 fires immediately.
const LOGIN_WARN: &str = "Login failed (attempt 1)";
/// The level token as the fmt layer prints it (ANSI-wrapped in the raw stream,
/// but `" INFO"` survives the escape codes on either side of the word).
const INFO_RECORD: &str = " INFO";

fn bin() -> String {
    std::env::var("FRPC_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as `warn_delivery.rs`:
/// no `tempfile` dev-dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frpc-log-level-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.0.join(name), contents).expect("write config");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free port from the ephemeral range, deduplicated inside this process.
/// Same documented residual race as `frps/tests/log_completion.rs::free_port`.
/// Nothing binds this port in the closed-port shape — the client only dials it.
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

fn used_ports() -> &'static Mutex<HashSet<u16>> {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    USED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Kills and reaps the child on every exit path, including a panicking
/// assertion — a leaked `frpc` keeps retrying its dead server.
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
/// full pipe can never block the child) and snapshotted by the assertions.
struct Spawned {
    /// Declared first so the child is killed before the scratch dir is removed.
    _guard: ChildGuard,
    /// The scratch dir the child ran in; owns its own removal.
    _dir: TempDir,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

impl Spawned {
    /// Write `config` as `./frpc.toml` in a fresh scratch dir, then run
    /// `frpc -c frpc.toml <argv_tail>` there with `RUST_LOG` removed: the env var
    /// outranks both `--log-level` and the config level in `filter_from_env`, so
    /// leaving it set would defeat the assertion this file exists to make.
    fn start(config: &str, argv_tail: &[&str]) -> Self {
        let dir = TempDir::new();
        dir.write("frpc.toml", config);
        let mut argv = vec!["-c", "frpc.toml"];
        argv.extend_from_slice(argv_tail);
        let child = Command::new(bin())
            .args(&argv)
            .current_dir(&dir.0)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn frpc");
        Self::from_child(child, dir)
    }

    fn from_child(mut child: Child, dir: TempDir) -> Self {
        let out = Arc::new(Mutex::new(String::new()));
        let err = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take().expect("child stdout"), out.clone());
        drain(child.stderr.take().expect("child stderr"), err.clone());
        Self {
            _guard: ChildGuard { child },
            _dir: dir,
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

    /// Wait (bounded) until `needle` is visible on stdout. Waiting on the
    /// **record** rather than a fixed settle is load-independent: the record
    /// either arrives or the wait fails loudly with both streams.
    fn wait_for(&self, needle: &str) {
        let deadline = Instant::now() + RECORD_TIMEOUT;
        loop {
            let out = self.stdout();
            if out.contains(needle) {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "no {needle:?} record on stdout within {RECORD_TIMEOUT:?}\n\
                     --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{}",
                    out.len(),
                    self.stderr().len(),
                    self.stderr(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
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

/// `[log] level = "{level}"` with the retry behaviour that keeps the client
/// alive against `dead_port` (nothing listens there).
fn config(dead_port: u16, level: &str) -> String {
    format!(
        "serverAddr = \"127.0.0.1\"\nserverPort = {dead_port}\nloginFailExit = false\n\n\
         [log]\nlevel = \"{level}\"\n"
    )
}

/// Assert, from the emitted records alone, that the effective level is exactly
/// the file's `warn`: a `WARN` record was admitted and no `INFO` record was.
fn assert_exactly_warn(tag: &str, spawned: &Spawned) {
    let out = spawned.stdout();
    let err = spawned.stderr();
    assert!(
        out.contains(LOGIN_WARN),
        "{tag}: no {LOGIN_WARN:?} WARN record on stdout, so the effective level \
         is not the file's `warn` (or nothing logged)\n\
         --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{err}",
        out.len(),
        err.len(),
    );
    assert!(
        !out.contains(STARTUP_MARKER),
        "{tag}: the {STARTUP_MARKER:?} startup marker appeared, so the effective \
         level fell to `info` — the empty flag raised it above the file's `warn`\n\
         --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{err}",
        out.len(),
        err.len(),
    );
    assert!(
        !out.contains(INFO_RECORD),
        "{tag}: an INFO record reached stdout, so the effective level is not the \
         file's `warn`\n--- stdout ({} B) ---\n{out}",
        out.len(),
    );
    assert!(
        err.is_empty(),
        "{tag}: stderr must stay empty, got {} B:\n{err}",
        err.len()
    );
}

/// **The pin:** `frpc`'s `--log-level ""` leaves the file's `[log] level` alone,
/// exactly as the fixed `frps` does — the two binaries agree.
#[test]
fn cli_empty_log_level_does_not_raise_the_files_warn() {
    let dead = free_port();

    // Arm 1: the flag under test.
    {
        let spawned = Spawned::start(&config(dead, "warn"), &["--log-level", ""]);
        spawned.wait_for(LOGIN_WARN);
        assert_exactly_warn("--log-level \"\"", &spawned);
    }

    // Arm 2: the same config with the flag omitted. The empty flag's *presence*
    // must make no difference, which is what "treated as not supplied" means.
    {
        let spawned = Spawned::start(&config(dead, "warn"), &[]);
        spawned.wait_for(LOGIN_WARN);
        assert_exactly_warn("no flag (control)", &spawned);
    }

    // Arm 3: the marker's own control. At `info` the startup marker **is**
    // emitted and the `run`-span `INFO` records appear, so their absence in
    // arms 1–2 is the file's `warn` rather than a missing record.
    {
        let spawned = Spawned::start(&config(dead, "info"), &["--log-level", ""]);
        spawned.wait_for(STARTUP_MARKER);
        assert!(
            spawned.stdout().contains(LOGIN_WARN),
            "level = \"info\": the WARN record must still be admitted"
        );
    }
}
