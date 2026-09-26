//! `frps` CLI exit codes on the config-failure surface, pinned against Go frp
//! v0.71.0.
//!
//! Go's CLI is two-valued: 0 on success, 1 on any failure. Measured on Go
//! v0.71.0 (darwin/arm64) with one unknown top-level key added to an otherwise
//! valid server config:
//!
//! ```text
//! frps -c badfrps.toml   → rc 1, stdout `json: unknown field "notAKnownFrpKey"`
//! frps -c missing.toml   → rc 1, stdout `open missing.toml: no such file or directory`
//! ```
//!
//! frp-rs exited **2** (`EXIT_CONFIG`) on this path until this pin. Go has no
//! `frps --config-dir` at all (`Error: unknown flag: --config-dir`, rc 1);
//! frp-rs's is an extension whose refusals stay on `EXIT_CONFIG`/2 by the same
//! deliberate divergence as the client's. See `docs/developing.md`
//! § CLI exit codes.
//!
//! Gated on `full`: the `frps` bin carries `required-features = ["full"]`, so
//! without the gate this file's `CARGO_BIN_EXE_frps` would fail to compile in
//! the no-default-features lanes CI runs.

#![cfg(feature = "full")]

use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_frps");
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const BAD_CONFIG: &str = "bindPort = 7500\nnotAKnownFrpKey = 1\n";
const UNKNOWN_FIELD: &str = "unknown field \"notAKnownFrpKey\"";

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself — same pattern (and same reason: no
/// `tempfile` dev-dependency) as `frpc/tests/admin_cli.rs`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frps-cli-exit-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write config");
        path.to_str().expect("utf-8 temp path").to_string()
    }

    fn path(&self, name: &str) -> String {
        self.0
            .join(name)
            .to_str()
            .expect("utf-8 temp path")
            .to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_frps(args: &[&str]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn frps");
    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        match child.try_wait().expect("try_wait frps") {
            Some(_) => return child.wait_with_output().expect("collect frps output"),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let out = child.wait_with_output().expect("collect frps output");
                panic!(
                    "frps {args:?} did not exit within {EXIT_TIMEOUT:?}; stdout={:?} stderr={:?}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr),
                );
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// Go: `frps -c <bad>` → bare parse error on **stdout**, exit 1
/// (`cmd/frps/root.go`). frp-rs writes the same error inside a `tracing` line
/// (output-shape divergence, out of scope here); the exit code is the pin.
#[test]
fn bad_config_exits_1_and_names_the_unknown_field() {
    let dir = TempDir::new();
    let cfg = dir.write("badfrps.toml", BAD_CONFIG);

    let out = run_frps(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frps -c <bad config> must exit 1 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains(UNKNOWN_FIELD),
        "the load error must name the unknown field, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        all.contains(&cfg),
        "the load error must name the config file, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// The sibling of the previous test: a missing file is the same failure class
/// and the same code (Go rc 1).
#[test]
fn missing_config_exits_1() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    let out = run_frps(&["-c", &missing]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frps -c <missing> must exit 1 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// Positive control: a valid config starts a real server (exit 0 on SIGTERM,
/// the graceful-shutdown path), so the tests above pin "bad config → 1" rather
/// than "frps always fails".
///
/// The port is taken from an ephemeral bind and released immediately:
/// `bindPort = 0` is *not* "any port" here — frp-rs normalizes 0 back to the
/// default 7000 (`frp-core/src/config/server.rs:394-395`), which on macOS is
/// held by Control Center. The released-port window is microseconds and this
/// test only needs the listener to come up.
#[test]
fn good_config_starts_and_exits_0_on_sigterm() {
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        probe.local_addr().expect("local_addr").port()
    };
    let dir = TempDir::new();
    let cfg = dir.write(
        "goodfrps.toml",
        &format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {port}\n[auth]\ntoken = \"cli-exit-test\"\n"
        ),
    );

    // Output goes to a file, not a pipe: a child whose piped stdout nobody reads
    // can block on a full pipe, and this test only needs the log for diagnosis.
    let log_path = dir.path("frps.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(BIN)
        .args(["-c", &cfg])
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn frps");

    // `expect`, not `unwrap_or_default`: this reader only ever runs inside a
    // panic message, and swallowing a read error there would replace a real
    // diagnosis with an empty string. A read failure means the child wrote
    // nothing or the path is wrong — both are findings.
    let read_log = || std::fs::read_to_string(&log_path).expect("read frps diagnostic log");

    // Wait until the bind port accepts a connection. It is not enough to sleep:
    // the SIGTERM handler is installed only after the service has bound its
    // listener, so signalling an already-started-but-not-yet-listening frps
    // kills it with the *default* disposition (measured: `unix_wait_status(15)`,
    // i.e. `code() == None`, no exit). A successful connect proves the listener
    // exists, which is the ordering this test needs.
    let ready_deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait().expect("try_wait frps") {
            panic!(
                "frps exited ({status:?}) instead of listening on 127.0.0.1:{port}; log={:?}",
                read_log(),
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "frps never listened on 127.0.0.1:{port} within {EXIT_TIMEOUT:?}; log={:?}",
                read_log(),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();

    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        match child.try_wait().expect("try_wait frps") {
            Some(status) => {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "frps must exit 0 on SIGTERM with a valid config (signal={:?}); log={:?}",
                    status,
                    read_log(),
                );
                return;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "frps did not exit within {EXIT_TIMEOUT:?} of SIGTERM; log={:?}",
                    read_log(),
                );
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Deliberate divergence, pinned so it cannot drift silently: Go frps v0.71.0
/// has no `--config-dir` flag (`Error: unknown flag: --config-dir`, rc 1);
/// frp-rs's is an extension and its refusals stay on `EXIT_CONFIG`/2 — the same
/// non-zero refusal the client keeps where Go's own directory mode exits 0 for
/// a directory it could not load a config from.
#[test]
fn config_dir_extension_refuses_nonexistent_dir_with_2() {
    let dir = TempDir::new();
    let missing_dir = dir.path("no-such-dir");

    let out = run_frps(&["--config-dir", &missing_dir]);

    assert_eq!(
        out.status.code(),
        Some(2),
        "--config-dir is an frp-rs extension flag; its refusal must stay non-zero; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// The frp-rs space-separated `--strict-config` extension is made **loud** on
/// `frps` too: exactly one stderr line, and silence for the Go-faithful shapes
/// (`--strict-config=false`, the bare switch, absent). `BAD_CONFIG` carries no
/// `auth.token`, so the lenient load proceeds into the documented empty-token
/// refusal and the child still exits inside `run_frps`'s bound — a strict load
/// would stop at the unknown field, which is what the assertion below rules out.
#[test]
fn space_form_strict_config_warns_on_stderr() {
    let dir = TempDir::new();
    let cfg = dir.write("badfrps.toml", BAD_CONFIG);
    let warning = frp_core::cli::STRICT_CONFIG_SPACE_FORM_WARNING;

    let out = run_frps(&["--strict-config", "false", "-c", &cfg]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(warning),
        "the extension must warn on stderr; stdout={:?} stderr={stderr:?}",
        stdout_of(&out),
    );
    // Exactly once — a second emission must fail (a bare `contains` cannot
    // see it).
    assert_eq!(
        stderr.matches(warning).count(),
        1,
        "the warning must be printed exactly once; stderr={stderr:?}"
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !all.contains(UNKNOWN_FIELD),
        "the space form consumes `false`, so the unknown key must be tolerated: {all:?}"
    );

    // The Go-faithful shapes stay silent.
    for args in [
        &["--strict-config=false", "-c", &cfg][..],
        &["--strict-config", "-c", &cfg][..],
        &["-c", &cfg][..],
    ] {
        let out = run_frps(args);
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} is Go-faithful and must stay silent; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }
}
