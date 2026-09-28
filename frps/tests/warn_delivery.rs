//! The `[web_server.tls] enable` diagnostic a **`frps` user** actually sees:
//! bounded spawn tests against the real binary, on both config paths, with
//! stdout and stderr captured separately.
//!
//! **The defect these pin.** `normalize_web_server_section` accepts the key
//! (a deliberate divergence — Go's `TLSConfig` has no `Enable` field, so
//! `frps verify` refuses it with `json: unknown field "enable"`, measured with
//! `/private/tmp/frp_0.71.0_darwin_arm64/frps`), removes it because nothing
//! reads it, and used to warn from *inside the loader*. On the `-c` path the
//! loader runs **before** `init_logging` (`frps/src/main.rs:263` vs `:290`, a
//! deliberate Go-parity ordering — Go installs its logger only after a successful
//! load, `cmd/frps/root.go:112`), so the record reached no subscriber:
//!
//! | shape | before | after |
//! |---|---|---|
//! | `frps -c <cfg>` with `[web_server.tls] enable = true` | **0** stdout / 0 stderr | **1** stdout / 0 stderr |
//! | `frps -c` with `RUST_LOG=debug` | **0** / 0 | **1** / 0 |
//! | `frps --config-dir <dir>` | 1 / 0 | 1 / 0 |
//! | `frps -c` with no `enable` key | 0 / 0 | 0 / 0 |
//!
//! (Counts are `grep -o web_server\.tls\.enable | wc -l` over separately
//! captured streams; the full before/after table, including `frpc`, is
//! `/tmp/enable-warn-probe/out/{before,after}.txt` and the probe script is
//! `/tmp/enable-warn-probe/run-probe.sh`. The Go-parity ordering itself was
//! **not** moved — only the emission.)
//!
//! **What this file is for.** The `frp-core` sibling
//! (`frp-core/tests/web_server_tls_enable_warning.rs`) pins the presence flag and
//! the message with an in-process capture; it cannot see whether a user gets the
//! record. That is what a spawn test is: real binary, real config file, captured
//! output. Falsification (measured): run this file with
//! `FRPS_BIN=/tmp/enable-warn-probe/before/frps` — the pre-change binary — and
//! the `-c` test fails (`stdout: 0`) while the `--config-dir` test still passes,
//! which is exactly the defect.
//!
//! **What it does not cover.** `frpc` (the sibling file
//! `frpc/tests/warn_delivery.rs`), the dashboard's actual HTTP/HTTPS behaviour
//! (`frp-server` end to end), other sinks, and the message text beyond the
//! substrings asserted here.
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
/// `FRPS_BIN` overrides it, which is how the pre-change falsification runs.
const BIN: &str = env!("CARGO_BIN_EXE_frps");
/// How long a shape may take from spawn to its startup line being visible.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a killed child may take to disappear before the guard gives up.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Settle time after the startup line, so every record `init_logging` gates has
/// been written before the streams are read. Counts are taken BEFORE any signal.
const SETTLE: Duration = Duration::from_millis(500);
/// A substring of the first record `frps` emits **after** `init_logging`, so
/// seeing it proves the load succeeded and a subscriber exists. Without it, an
/// empty warning count would be indistinguishable from "the binary never ran".
const STARTUP_MARKER: &str = "frps (Rust) v";
/// The key, as the message names it.
const KEY: &str = "web_server.tls.enable";

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
/// full pipe can never block the child) and snapshotted **before** any signal.
/// The child stays alive until this value is dropped, which kills and reaps it.
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
        spawned.wait_for_marker();
        std::thread::sleep(SETTLE);
        spawned.snapshot();
        spawned
    }

    /// Wait until either stream carries the post-`init_logging` startup line.
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
                    "frps exited ({status}) before its startup line\n--- stdout ({} B) ---\n{}\n\
                     --- stderr ({} B) ---\n{}",
                    self.peek_stdout().len(),
                    self.peek_stdout(),
                    self.peek_stderr().len(),
                    self.peek_stderr(),
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "frps never logged {STARTUP_MARKER:?} within {READY_TIMEOUT:?}\n\
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

    /// Freeze what the reader threads have collected so far. Called before any
    /// signal, so the counts cannot include shutdown records.
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

/// `bind_port` is the only field a `frps` config needs to start; the dashboard
/// section is there because it is what the warning is about.
fn frps_config(bind_port: u16, dashboard_port: u16, enable: Option<&str>) -> String {
    let mut cfg = format!(
        "bind_port = {bind_port}\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\n\
         port = {dashboard_port}\n"
    );
    if let Some(value) = enable {
        cfg.push_str(&format!("[web_server.tls]\nenable = {value}\n"));
    }
    cfg
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The shared assertion: one record on **stdout**, none on **stderr**, and the
/// binary really did start.
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
}

#[test]
fn web_server_tls_enable_warning_reaches_a_dash_c_user() {
    let dir = TempDir::new("dashc");
    let port = free_port();
    let cfg = frps_config(port, free_port(), Some("true"));
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
    let cfg = frps_config(free_port(), free_port(), Some("true"));
    let sub = dir.0.join("conf.d");
    std::fs::create_dir_all(&sub).expect("create config dir");
    std::fs::write(sub.join("frps.toml"), &cfg).expect("write config");
    let spawned = Spawned::run(&dir, &["--config-dir", sub.to_str().unwrap()]);
    assert_one_warning_on_stdout("frps --config-dir", &spawned);
}

/// Negative control: without the key there is no record on either stream, so the
/// warning is presence-driven and not an unconditional startup line.
#[test]
fn no_warning_for_a_config_without_the_key() {
    let dir = TempDir::new("nokey");
    let cfg = frps_config(free_port(), free_port(), None);
    let path = dir.write("frps.toml", &cfg);
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
