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
//! Two further tests pin the *extension* codes on the client:
//! `unresolvable_token_source_exits_3_like_frps` (`EXIT_AUTH`/3 — the same
//! input makes Go exit 1, see `docs/developing.md`) and
//! `malformed_store_file_exits_4_where_go_exits_1` (`EXIT_BIND`/4, which is the
//! fallback for any construction error whose text lacks `token`/`auth`).
//!
//! Gated on `full`: the `frpc` bin carries `required-features = ["full"]`, so
//! without the gate this file's `CARGO_BIN_EXE_frpc` would fail to compile in
//! the no-default-features lanes CI runs. The `tiny` gate at the end is the
//! same pin for the `frpc-tiny` variant, which the `full` gate cannot cover.

#![cfg(any(feature = "full", feature = "tiny"))]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[cfg(feature = "full")]
const BIN: &str = env!("CARGO_BIN_EXE_frpc");
#[cfg(all(feature = "tiny", not(feature = "full")))]
const BIN: &str = env!("CARGO_BIN_EXE_frpc-tiny");
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

// ── the extension codes: 3 (auth) and 4 (the construction fallback) ─────────

/// `EXIT_AUTH`/3, pinned on the one input where it is a *genuine* divergence
/// rather than a hardening refusal: a `auth.tokenSource` whose file does not
/// exist. Go frp v0.71.0 exits **1** here (`failed to resolve auth.tokenSource:
/// failed to read file …`), frp-rs exits **3**.
///
/// The tokenless-token case (`[auth] method = "token"` with an empty token) is
/// *not* a code divergence at all: Go frps starts and keeps running there while
/// frp-rs refuses at construction with 3 — see `docs/developing.md`.
#[test]
fn unresolvable_token_source_exits_3_where_go_exits_1() {
    let dir = TempDir::new();
    let missing = dir.path("no-such-token-file");
    let cfg = dir.write(
        "badsource.toml",
        &format!(
            "{BASE_CONFIG}[auth]\nmethod = \"token\"\n\
             tokenSource = {{ type = \"file\", file = {{ path = \"{missing}\" }} }}\n"
        ),
    );

    let out = run_frpc(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(3),
        "an unresolvable tokenSource is the frp-rs EXIT_AUTH/3 extension (Go exits 1); \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains("tokenSource"),
        "the refusal must name tokenSource, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// `EXIT_BIND`/4 is **not** specifically about bind errors: it is the daemons'
/// fallback for any service-*construction* error whose text lacks `token` or
/// `auth`. A `[store] path` pointing at a file that is not JSON reaches it
/// without any port or token being involved.
///
/// Go frp v0.71.0 exits **1** on the identical config (`failed to create store
/// source: failed to load existing data: failed to parse JSON: …`), so this is
/// an frp-rs extension like 3. The `name` of this test is the finding: 4 is the
/// construction fallback, and `docs/developing.md` now says so.
#[test]
fn malformed_store_file_exits_4_where_go_exits_1() {
    let dir = TempDir::new();
    let store = dir.write("badstore.json", "this is not json\n");
    let cfg = dir.write(
        "badstore.toml",
        &format!("{BASE_CONFIG}[store]\npath = \"{store}\"\n"),
    );

    let out = run_frpc(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(4),
        "a malformed [store] file is the frp-rs EXIT_BIND/4 fallback (Go exits 1); \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains("badstore.json"),
        "the refusal must name the store file, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// A Go pflag bool takes `--flag=<bool>` as well as the bare `--flag`, and the
/// *value* decides what happens. `-v, --version` is such a bool on Go's root
/// command, so measured on Go frp v0.71.0 (darwin/arm64, bounded runner)
/// against a *missing* config file:
///
/// ```text
/// frpc --version=true  -c missing.toml → rc 0, stdout `0.71.0`
/// frpc --version=false -c missing.toml → rc 1, `open missing.toml: no such file or directory`
/// frpc --version=foo   -c missing.toml → rc 1, `invalid argument "foo" for "-v, --version" flag: strconv.ParseBool: …`
/// frpc --nope=1 --version              → rc 1, `Error: unknown flag: --nope`
/// ```
///
/// Two separate pre-fix defects are pinned here, both fixed by routing the flag
/// through the shared bool-value parser (`frp-core/src/cli.rs`) **and** moving
/// the `--version` check out of `frpc_parser()`'s `.map()` into
/// `parse_frpc_args`:
///
/// * the `.switch()` took no value, so `--version=false` was an argv error
///   where Go starts the client;
/// * that `.map()` closure printed the version and called `process::exit(0)`
///   while bpaf was still exploring alternatives, so *any* argv containing
///   `--version` exited 0 — `frpc --version=foo` and even
///   `frpc --nope=1 --version` printed `frpc 0.71.0 (Rust)` and exited 0
///   (measured on the base commit's binary), where Go refuses both with rc 1.
///
/// `--version=false -c <missing>` is the row that separates all three
/// outcomes: rc 1 naming the missing file can only be a run that consumed the
/// value and reached the loader.
#[test]
fn version_flag_value_spelling_decides_what_happens() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    // `=true`: the version short-circuit, before any config read.
    let out = run_frpc(&["--version=true", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "--version=true must print the version and exit 0 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).contains(frp_core::VERSION),
        "stdout must carry the version; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );

    // `=false`: false is consumed as the value, so the run reaches the load.
    let out = run_frpc(&["--version=false", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--version=false must fall through to the config load like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains(&missing),
        "--version=false must reach the loader and name the missing file; the pre-fix binary \
         printed the version instead; output={all:?}"
    );
    assert!(
        !stdout_of(&out).contains(frp_core::VERSION),
        "--version=false must not print the version; output={all:?}"
    );

    // `=foo`: refused, exactly as Go's `strconv.ParseBool` refuses it (rc 1).
    let out = run_frpc(&["--version=foo", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--version=foo must exit 1 like Go's ParseBool refusal; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).contains("`foo` is not expected in this context"),
        "the refusal must name the value; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );

    // The speculative-`exit` row: an unrelated invalid flag must win over
    // `--version`, as it does on Go (`unknown flag: --nope`, rc 1). The pre-fix
    // binary exited 0 here after printing the version.
    let out = run_frpc(&["--nope=1", "--version"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an invalid flag alongside --version must exit 1 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        !stdout_of(&out).contains(frp_core::VERSION),
        "--version must not short-circuit a parse that fails elsewhere; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// The second bool on the client's run mode, and a different kind of row:
/// `--disable-log-color` exists in Go only on `frpc tcp` (`Error: unknown flag:
/// --disable-log-color` on Go's root, rc 1), so there is no Go root behaviour to
/// match — the *value spelling* is the shared parser's, and reading the value as
/// `false` must leave the run on the normal load path. Before this branch
/// `--disable-log-color=false -c <missing>` exited 1 with
/// `` `false` is not expected in this context ``; now it exits 1 naming the
/// missing file, which is the difference between "argv refused" and "value
/// consumed, config load attempted".
#[test]
fn disable_log_color_value_spelling_is_consumed() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    let out = run_frpc(&["--disable-log-color=false", "-c", &missing]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "the run must reach the loader; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains(&missing),
        "the missing config must be named; output={all:?}"
    );
    assert!(
        !all.contains("is not expected in this context"),
        "the `=false` spelling must not be an argv error; output={all:?}"
    );

    // A non-bool value is refused with rc 1, the same exit code Go's pflag
    // produces for its own bools.
    let out = run_frpc(&["--disable-log-color=foo", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a non-bool value must exit 1; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        !format!("{}{}", stdout_of(&out), stderr_of(&out)).contains(&missing),
        "a refused value must not reach the loader; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

// ── the same pin for the `tiny` tier ────────────────────────────────────────

/// `frpc-tiny` includes `frpc/src/main.rs` verbatim, so the exit-code fix has
/// to hold in the no-default-features build too — and the `full`-gated tests
/// above cannot see it (the `frpc` bin is `required-features = ["full"]`).
/// CI's tiny lane runs this file for that variant: the crate-level
/// `#![cfg(any(feature = "full", feature = "tiny"))]` is what makes the file
/// compile there at all.
#[cfg(all(feature = "tiny", not(feature = "full")))]
mod tiny {
    use super::*;

    #[test]
    fn tiny_bad_config_exits_1_like_go() {
        let dir = TempDir::new();
        let cfg = dir.write("bad.toml", BAD_CONFIG);

        let out = run_frpc(&["-c", &cfg]);

        assert_eq!(
            out.status.code(),
            Some(1),
            "frpc-tiny -c <bad config> must exit 1 like Go; stdout={:?} stderr={:?}",
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
    }

    #[test]
    fn tiny_verify_bad_config_exits_1_like_go() {
        let dir = TempDir::new();
        let cfg = dir.write("bad.toml", BAD_CONFIG);

        let out = run_frpc(&["verify", "-c", &cfg]);

        assert_eq!(
            out.status.code(),
            Some(1),
            "frpc-tiny verify -c <bad config> must exit 1 like Go; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }
}
