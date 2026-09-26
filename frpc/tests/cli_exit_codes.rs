//! `frpc` CLI exit codes on the config-failure surface, pinned against Go frp
//! v0.71.0.
//!
//! Go's CLI is two-valued: 0 on success, 1 on any failure. Measured on Go
//! v0.71.0 (darwin/arm64) with one unknown top-level key added to an otherwise
//! valid client config:
//!
//! ```text
//! frpc -c bad.toml          → rc 1, stdout `json: unknown field "notAKnownFrpKey"`
//! frpc verify -c bad.toml   → rc 1, stdout `json: unknown field "notAKnownFrpKey"`
//! frpc verify -c good.toml  → rc 0, stdout `frpc: the configuration file … syntax is ok`
//! ```
//!
//! frp-rs exited **2** (`EXIT_CONFIG`) on the first two until this pin; the
//! admin subcommands (`reload`/`status`/`stop`) already exited 1 for the same
//! load error, which is the internal disagreement this file closes. The last
//! test pins the one deliberate divergence: Go's `--config-dir` mode exits 0
//! even for a directory that does not exist, is empty, or holds a config that
//! fails to parse, and frp-rs keeps its non-zero refusal. See
//! `docs/developing.md` § CLI exit codes.
//!
//! Gated on `full`: the `frpc` bin carries `required-features = ["full"]`, so
//! without the gate this file's `CARGO_BIN_EXE_frpc` would fail to compile in
//! the no-default-features lanes CI runs.

#![cfg(feature = "full")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_frpc");
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const BASE_CONFIG: &str = "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n";
const BAD_CONFIG: &str = "serverAddr = \"127.0.0.1\"\nserverPort = 7000\nnotAKnownFrpKey = 1\n";
const UNKNOWN_FIELD: &str = "unknown field \"notAKnownFrpKey\"";

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself — same pattern (and same reason: no
/// `tempfile` dev-dependency) as `frpc/tests/admin_cli.rs`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frpc-cli-exit-{}-{n}", std::process::id()));
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

/// Run `frpc` with `args` and wait for it to exit, with a hard bound: none of
/// the cases here may start a working daemon, so a child that outlives the
/// bound is a finding, not a timeout to tolerate.
fn run_frpc(args: &[&str]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn frpc");
    let deadline = std::time::Instant::now() + EXIT_TIMEOUT;
    loop {
        match child.try_wait().expect("try_wait frpc") {
            Some(_) => return child.wait_with_output().expect("collect frpc output"),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let out = child.wait_with_output().expect("collect frpc output");
                panic!(
                    "frpc {args:?} did not exit within {EXIT_TIMEOUT:?}; stdout={:?} stderr={:?}",
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

/// Go: `frpc -c <bad>` → bare parse error on **stdout**, exit 1
/// (`cmd/frpc/sub/root.go`). frp-rs writes the same error inside a `tracing`
/// line (an output/stream divergence that is out of scope here — see
/// `docs/developing.md` § CLI exit codes); the exit code is what this pins.
#[test]
fn daemon_bad_config_exits_1_and_names_the_unknown_field() {
    let dir = TempDir::new();
    let cfg = dir.write("bad.toml", BAD_CONFIG);

    let out = run_frpc(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frpc -c <bad config> must exit 1 like Go; stdout={:?} stderr={:?}",
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

/// Go: `frpc verify -c <bad>` → rc 1, the parse error on stdout
/// (`cmd/frpc/sub/verify.go`). frp-rs prints its refusal on **stderr**; same
/// stream caveat as above.
#[test]
fn verify_bad_config_exits_1_and_names_the_unknown_field() {
    let dir = TempDir::new();
    let cfg = dir.write("bad.toml", BAD_CONFIG);

    let out = run_frpc(&["verify", "-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frpc verify -c <bad config> must exit 1 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains(UNKNOWN_FIELD),
        "the refusal must name the unknown field, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        all.contains(&cfg),
        "the refusal must name the config file, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// The sibling of the previous test: a missing file is the same failure class
/// and the same code (Go rc 1).
#[test]
fn verify_missing_config_exits_1() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    let out = run_frpc(&["verify", "-c", &missing]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frpc verify -c <missing> must exit 1 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// Positive control: a valid config still verifies with rc 0, so the tests
/// above pin "bad config → 1" rather than "verify always fails".
#[test]
fn verify_good_config_exits_0() {
    let dir = TempDir::new();
    let cfg = dir.write("good.toml", BASE_CONFIG);

    let out = run_frpc(&["verify", "-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "frpc verify -c <good config> must exit 0; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).contains("is valid"),
        "got stdout={:?}",
        stdout_of(&out)
    );
}

/// Deliberate divergence, pinned so it cannot drift silently: Go's
/// `frpc --config-dir` returns **0** for a directory that does not exist, is
/// empty, or holds a config that fails to parse (the bad case prints only
/// `frpc service error for config file [...]`). frp-rs refuses with
/// `EXIT_CONFIG`/2 on all three, because a config that was never loaded is not
/// a success. Go-faithful here would mean exiting 0 — that is the trade, and it
/// is recorded in `docs/developing.md` § CLI exit codes.
#[test]
fn config_dir_refusals_exit_2_where_go_exits_0() {
    let dir = TempDir::new();
    let missing_dir = dir.path("no-such-dir");
    let empty_dir = dir.path("empty");
    std::fs::create_dir_all(&empty_dir).expect("create empty dir");

    let bad_dir = dir.path("bad");
    std::fs::create_dir_all(&bad_dir).expect("create bad dir");
    std::fs::write(std::path::Path::new(&bad_dir).join("one.toml"), BAD_CONFIG)
        .expect("write bad dir config");

    for (label, target) in [
        ("nonexistent", &missing_dir),
        ("empty", &empty_dir),
        ("one invalid config", &bad_dir),
    ] {
        let out = run_frpc(&["--config-dir", target]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "--config-dir with a {label} directory must exit 2 (frp-rs refusal; Go exits 0); \
             stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }
}
