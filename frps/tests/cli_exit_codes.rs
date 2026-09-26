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
/// The child's own **progress witness**: the SIGUSR1 task logs this line after
/// its `tokio::signal::unix::signal` call returns (`frps/src/main.rs:207-215`),
/// which a `frps` that is still pre-init cannot have printed. It is *not* proof
/// that SIGTERM's handler is installed — tokio registers signals per kind and
/// lazily (`tokio-1.53.1/src/signal/unix.rs:283-300`), so the SIGTERM
/// registration is a separate call that this line does not witness. See
/// [`start_listening_then_sigterm`] for what the marker does buy.
const SIGNAL_READY_MARKER: &str = "SIGUSR1 reload ready";
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
/// Spawn `frps` with `args` against the listener `port`, wait until the port
/// **accepts a connection**, then SIGTERM it and require a clean exit 0.
/// Returns the child's combined output.
///
/// It is not enough to sleep: the SIGTERM handler is installed only after the
/// service has asked for its listener, so signalling an already-started-but-not-
/// yet-listening frps kills it with the *default* disposition (measured:
/// `unix_wait_status(15)`, i.e. `code() == None`, no exit). A successful connect
/// proves *a* listener exists, which is the ordering these tests need — and it is
/// also how "the argv was accepted and a server really started" is asserted
/// without inferring it from an exit code. **It does not prove the listener is
/// this child's** — see the foreign-listener arm below.
///
/// **The readiness barrier is the second half of the flake, measured.** Two
/// mechanisms, both real, and the second one is the one that produces the
/// failures:
///
/// 1. *The install race.* `Service::run` spawns the SIGTERM task from the same
///    async fn that later runs the accept loop
///    (`frp-server/src/service.rs:1579-1619`), so the listener can be accepting
///    before that task has been polled even once — and then SIGTERM takes the
///    default disposition.
/// 2. *The foreign-listener false witness.* `ephemeral_port()` binds a port and
///    releases it before the child binds it; tests run in parallel, so another
///    test's `frps` can take that port first. A connect then succeeds against
///    the **wrong process**, and if that one is still pre-init its SIGTERM does
///    not shut down the child we are watching.
///
/// Both were measured on the connect-only helper, with the helper as the *only*
/// difference and 40 iterations of the whole file per run: **7/40** on the
/// author's host and **5/40** on the adversarial reviewer's, against **0/40,
/// 0/40 and 1/40** across three marker-helper loops on the author's host and
/// **0/40** on the reviewer's. The one residual marker failure is the
/// non-zero window below, not the foreign-listener arm. Every failure had an **empty child log**
/// although a connect had succeeded — impossible for the child under test, which
/// logs before it binds, and therefore the foreign-listener arm — and one
/// reviewer failure ended in `Address already in use (os error 48)`. Respawning
/// a fresh child does **not** fix it (3/3 fresh spawns lost the same race in one
/// run).
///
/// So the barrier is a **child-specific progress witness**: the SIGUSR1 task
/// logs `SIGUSR1 reload ready` after its `tokio::signal::unix::signal` call
/// returns (`frps/src/main.rs:207-215`), i.e. only after that `frps` is past its
/// own startup logging. A foreign listener cannot fake it — only the child under
/// test writes to that log path. If the line never appears (a platform without
/// the handler), the helper panics with the log rather than silently weakening
/// the assertion.
///
/// **What it does not prove, stated rather than implied.** tokio registers
/// signals per kind and lazily (`tokio-1.53.1/src/signal/unix.rs:283-300`), so
/// registering SIGUSR1 does *not* install SIGTERM's handler: a window remains
/// between the marker and SIGTERM's registration. The reviewer measured it at
/// **~0.16 ms median / 1.10 ms max**, i.e. small but nonzero — and it does
/// occasionally open: see the `1/40` above, not reproduced in a follow-up 30-run
/// loop (~1/100). That is why this helper reports such a failure rather than
/// retrying it away, and why a future CI flake here should be diagnosed as this
/// window before anything else.
///
/// Output goes to a file, not a pipe: a child whose piped stdout nobody reads
/// can block on a full pipe.
fn start_listening_then_sigterm(args: &[&str], port: u16, dir: &TempDir) -> String {
    let log_path = dir.path("frps.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(BIN)
        .args(args)
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

    let ready_deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        // Two witnesses, both needed: a connect for "the argv produced a
        // listener" (the port may be a foreign one, hence the second) and the
        // child's own progress line for "this child is the one that got there".
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
            && read_log().contains(SIGNAL_READY_MARKER)
        {
            break;
        }
        if let Some(status) = child.try_wait().expect("try_wait frps") {
            panic!(
                "frps {args:?} exited ({status:?}) instead of listening on 127.0.0.1:{port}; \
                 log={:?}",
                read_log(),
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "frps {args:?} never listened on 127.0.0.1:{port} and logged \
                 {SIGNAL_READY_MARKER:?} within {EXIT_TIMEOUT:?}; log={:?}",
                read_log(),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let started = Instant::now();
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();

    let deadline = started + EXIT_TIMEOUT;
    loop {
        match child.try_wait().expect("try_wait frps") {
            Some(status) => {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "frps {args:?} must exit 0 on SIGTERM (signal={status:?}); log={:?}",
                    read_log(),
                );
                return read_log();
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "frps {args:?} did not exit within {EXIT_TIMEOUT:?} of SIGTERM (the child had \
                     logged {SIGNAL_READY_MARKER:?}, but tokio registers each signal kind \
                     separately, so SIGTERM's own registration may still have been pending); \
                     log={:?}",
                    read_log(),
                );
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// An ephemeral port, released immediately: `bindPort = 0` is *not* "any port"
/// here — frp-rs normalizes 0 back to the default 7000
/// (`frp-core/src/config/server.rs:394-395`), which on macOS is held by Control
/// Center. The released-port window is microseconds and these tests only need
/// the listener to come up.
fn ephemeral_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    probe.local_addr().expect("local_addr").port()
}

fn valid_config(dir: &TempDir, port: u16) -> String {
    dir.write(
        "goodfrps.toml",
        &format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {port}\n[auth]\ntoken = \"cli-exit-test\"\n"
        ),
    )
}

#[test]
fn good_config_starts_and_exits_0_on_sigterm() {
    let port = ephemeral_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);

    start_listening_then_sigterm(&["-c", &cfg], port, &dir);
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

/// A Go pflag bool takes `--flag=<bool>` as well as the bare `--flag`, and the
/// *value* decides what happens. `-v, --version  version of frps` is such a
/// bool on Go, so measured on Go frp v0.71.0 (darwin/arm64, bounded runner)
/// against a *missing* config file:
///
/// ```text
/// frps --version=true  -c missing.toml  → rc 0, stdout `0.71.0` (config never read)
/// frps --version=false -c missing.toml  → rc 1, `open missing.toml: no such file or directory`
/// frps --version=foo   -c missing.toml  → rc 1, `invalid argument "foo" for "-v, --version" flag: strconv.ParseBool: …`
/// ```
///
/// The base commit's frp-rs registered `--version` as a bpaf `.switch()`
/// (no value), so all three rows exited 1 with
/// `` `false` / `foo` is not expected in this context `` — the config load
/// never happened. The missing config is what makes each row distinguish
/// *which* thing happened rather than only the exit code: rc 0 with the version
/// on stdout can only be the version short-circuit, and rc 1 naming the missing
/// path can only be a run that got past the flag.
///
/// The item's headline is the `frps --tls-only=false -c <valid>` row, where Go
/// starts and listens (rc 124 under the bound); that one is asserted by
/// actually binding and connecting, below. `TODO.md:1745`.
#[test]
fn version_flag_value_spelling_decides_what_happens() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    // `=true`: the version short-circuit, before any config read.
    let out = run_frps(&["--version=true", "-c", &missing]);
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
    assert!(
        !format!("{}{}", stdout_of(&out), stderr_of(&out)).contains(&missing),
        "the version short-circuit must not have read the config at all; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );

    // `=false`: false is consumed as the value, so the run reaches the load.
    let out = run_frps(&["--version=false", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--version=false must fall through to the config load like Go (which starts the \
         server there); stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains(&missing),
        "--version=false must reach the loader and name the missing file; the pre-fix \
         binary refused the argv instead; output={all:?}"
    );
    assert!(
        !all.contains("is not expected in this context"),
        "--version=false must not be an argv error any more; output={all:?}"
    );

    // `=foo`: refused, exactly as Go's `strconv.ParseBool` refuses it (rc 1).
    let out = run_frps(&["--version=foo", "-c", &missing]);
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
}

/// The `-v` **shorthand** grammar, which is where `.adjacent()` first bit: pflag
/// sets a bool short and re-parses the rest of the token as more shorthands
/// (`-vtrue` is `-v` + `-t rue`), while `-v=<bool>` is a value, and `-vfoo` is
/// an unknown shorthand — Go's own text is `unknown shorthand flag: 'f' in
/// -foo`, rc 1. Measured 2026-09-26 on Go v0.71.0 / base head `2b1d51f` / this
/// head, all with a *missing* config, so rc 0 proves the version short-circuit
/// and rc 1 naming the missing file proves the run reached the loader:
///
/// ```text
/// frps -vtrue   -c missing → 0 (version) / 0 (version) / 0 (version)
/// frps -vh                 → 0 (help)    / 0 (help)    / 0 (help)
/// frps -vtok    -c missing → 0 (version) / 0 (version) / 0 (version)
/// frps -vp7000  -c missing → 0 (version) / 0 (version) / 0 (version)
/// frps -v=false -c missing → 1 (load)    / 1 (argv)    / 1 (load)
/// frps -vfoo    -c missing → 1           / 1           / 1
/// frps -v0      -c missing → 1           / 1           / 1
/// ```
///
/// The middle column is the regression an earlier revision of this branch
/// introduced: the value branch carried the short, so bpaf's
/// `this_or_that_picks_first` discarded the flag branch's successful cluster
/// parse (see `docs/developing.md` § `--flag=<bool>`). Hence these rows are
/// pinned rather than only documented — `-vh` printing **help** and `-vtrue`/
/// `-vtok`/`-vp7000` printing the **version** cannot both hold if the cluster
/// path breaks again, and `-v=false` naming the missing config cannot hold
/// unless the `-v=` alias expansion consumed the value.
#[test]
fn version_short_shorthand_clusters_and_equals_spelling_match_go() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    // Shorthand clusters: `-v` set, the rest re-parsed. The version
    // short-circuit must win over the (missing) config.
    for args in [
        &["-vtrue", "-c", &missing][..],
        &["-vtok", "-c", &missing][..],
        &["-vp7000", "-c", &missing][..],
    ] {
        let out = run_frps(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} is a pflag shorthand cluster that sets -v, so the version must print \
             and exit 0 like Go; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert!(
            stdout_of(&out).contains(frp_core::VERSION),
            "{args:?} must print the version; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }

    // The same cluster with `h` as the next shorthand prints help, not version.
    let out = run_frps(&["-vh"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "-vh must print help and exit 0 like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).contains("frps is the server"),
        "-vh must render the help text (a broken cluster path exits 1 here); stdout={:?} \
         stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );

    // `-v=<bool>` is the short spelling of `--version=<bool>`: false is consumed
    // as the value, so the run reaches the loader.
    let out = run_frps(&["-v=false", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "-v=false must fall through to the config load; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        format!("{}{}", stdout_of(&out), stderr_of(&out)).contains(&missing),
        "-v=false must reach the loader and name the missing file; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );

    // A short that is not registered stays an error, as on Go.
    for args in [&["-vfoo", "-c", &missing][..], &["-v0", "-c", &missing][..]] {
        let out = run_frps(args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?} must exit 1 like Go's `unknown shorthand flag`; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert!(
            !stdout_of(&out).contains(frp_core::VERSION),
            "{args:?} must not print the version; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }
}

/// The item's measured row, end to end: `frps --tls-only=false -c <valid>`
/// starts and listens on Go (rc 124 under the bounded runner), and exited 1
/// with `` `false` is not expected in this context `` before the bool flags
/// were routed through the shared value parser. Asserting the exit code alone
/// would not distinguish "started" from "refused and exited 1", so this waits
/// for the bind port to accept a connection.
///
/// **What this does not prove.** Only that the argv was *accepted* and a server
/// came up: with `-c` the config file is authoritative for the transport
/// section (`cli_overrides_enabled()` is false, `frp-core/src/cli.rs:1730`), so
/// the parsed `tls_only = false` never reaches the service — a mutant that
/// consumed `=false` but stored `true` would still pass this test. The value
/// actually being applied is pinned in
/// `disable_log_color_value_spelling_is_applied`, whose flag *is* read from the
/// CLI (`frps/src/main.rs:55-56`).
#[test]
fn tls_only_false_value_starts_and_listens() {
    let port = ephemeral_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);

    start_listening_then_sigterm(&["--tls-only=false", "-c", &cfg], port, &dir);
}

/// The `=value` spelling is not merely accepted — it is the value the flag
/// carries. `--disable-log-color` is the observable one: the frps log
/// initialiser reads it straight off the CLI
/// (`logging::resolve_ansi(!disable)` → `with_ansi(ansi)`,
/// `frps/src/main.rs:55-56`), so the child's own output shows which value won.
///
/// Measured at this head with a valid config and a bounded runner, on the
/// `ESC [` sequences in the child's combined output:
/// `--disable-log-color=false` → some (140 on the author's host, 260 on a
/// reviewer's — the count is host-dependent, so the assertion below is
/// "some vs none"), `=true` → none, bare → none. Asserting only the exit code
/// would pass for all three.
///
/// One caveat, stated rather than implied: this pins that `false` and `true` are
/// *distinguished and applied*; that a rejected value (`=foo`) never reaches the
/// log initialiser is pinned by `run_frps`'s rc-1 row in
/// `version_flag_value_spelling_decides_what_happens`.
#[test]
fn disable_log_color_value_spelling_is_applied() {
    const ANSI_ESCAPE: &[u8] = b"\x1b[";

    // `=false` → colour stays on.
    let port = ephemeral_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);
    let log = start_listening_then_sigterm(&["--disable-log-color=false", "-c", &cfg], port, &dir);
    assert!(
        log.as_bytes()
            .windows(ANSI_ESCAPE.len())
            .any(|w| w == ANSI_ESCAPE),
        "--disable-log-color=false must leave ANSI colour in the log; log={log:?}"
    );

    // `=true` → colour is stripped, same server, same config shape.
    let port = ephemeral_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);
    let log = start_listening_then_sigterm(&["--disable-log-color=true", "-c", &cfg], port, &dir);
    assert!(
        !log.as_bytes()
            .windows(ANSI_ESCAPE.len())
            .any(|w| w == ANSI_ESCAPE),
        "--disable-log-color=true must strip ANSI colour from the log; log={log:?}"
    );
}

// ── pflag's `-c <dash-value>` rule on `frps` (the `TODO.md` item of that
// name) ─────────────────────────────────────────────────────────────
//
// Go's pflag hands a value-taking flag the **next argv token** whatever it
// looks like (`parseSingleShortArg`'s `len(args) > 0` arm consumes `args[0]`
// with no leading-`-` test — `spf13/pflag@v1.0.5/flag.go`), and `frps` uses
// pflag, so `frps -c -x` is not a flag error on Go: it is an attempt to open a
// file named `-x`. Measured on Go frp v0.71.0 (darwin/arm64, bounded children),
// against the same argv here:
//
// ```text
// frps -c --strict-config=false  → Go rc 1 `open --strict-config=false: no such file or directory`
//                                  (was rc 1 ``-c` requires an argument `FILE``)
// frps -c -x                     → Go rc 1 `open -x: no such file or directory`
//                                  (was rc 1 ``-c` requires an argument `FILE`, got a flag `-x` …``)
// frps -c --                     → Go rc 1 `open --: no such file or directory`
//                                  (was rc 1 ``-c` requires an argument `FILE``)
// ```
//
// What the pins assert is *which* thing happened, not just the code: the child
// must have reached the config load and named the flag-shaped token as the file
// it could not read, rather than the parser refusing the token. The exit code
// alone is 1 in every row, before and after.
//
// Two shapes the rewrite deliberately does **not** change stay pinned here: a
// `-`-prefixed token in any position other than the one right after a
// config-selecting flag, and a `--` that is a real separator rather than `-c`'s
// value.

/// Both streams, ANSI stripped: the load error arrives on stdout inside a
/// `tracing` line on this path, and these assertions are about the *path named*,
/// not the stream (the output-shape divergence is tracked separately). The
/// stripping mirrors what `--disable-log-color` does to the same line and keeps
/// the assertion about the message text, not the colour.
fn combined(out: &Output) -> String {
    let mut clean = String::new();
    for bytes in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(bytes);
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            // An SGR sequence is `ESC [` … one ASCII letter; the `ESC` itself
            // must go too, or the text keeps a stray 0x1b.
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            clean.push(c);
        }
    }
    clean
}

/// `-c` followed by a token that is itself a flag's spelling: the token is the
/// value. Both a Go bool (`--strict-config=false`) and a value-taking frps flag
/// (`--bind-port`, whose own argument is therefore *not* consumed) are covered —
/// pflag does not look at the token at all.
///
/// **Discrimination, per iteration.** The assertion is the load path's own line
/// (`Failed to load config: <value>: failed to read config file`) plus the
/// absence of any parser refusal, because "the output contains the token" is
/// *not* discriminating on its own: the base head's refusal text already names
/// `--bind-port`, `-x` and `-c` (`` … got a flag `-x`, try `-c=-x` …``). Only
/// `--strict-config=false` is named solely by its own refusal
/// (`` `-c` requires an argument `FILE` ``), so all four iterations assert the
/// load line; the base tree then fails on `--strict-config=false` for the old
/// reason and on the other three because "Failed to load config" is absent
/// (they were refusals, not loads).
#[test]
fn dash_shaped_config_value_is_the_value_not_a_flag() {
    for value in ["--strict-config=false", "--bind-port", "-x", "-c"] {
        let out = run_frps(&["-c", value]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "frps -c {value} must reach the load and fail there like Go; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        let all = combined(&out);
        assert!(
            all.contains("Failed to load config") && all.contains(value),
            "frps -c {value} must name `{value}` as the path it could not read, not refuse the \
             token as a flag; output={all:?}"
        );
        assert!(
            !all.contains("requires an argument"),
            "the parser must not have refused the dash-shaped token; output={all:?}"
        );
    }

    // The long spelling, and a dash value followed by a real flag that must
    // still be parsed as one (the rewrite consumes only the one token).
    for args in [
        &["--config", "-x"][..],
        &["-c", "-x", "--bind-port", "7000"][..],
    ] {
        let out = run_frps(args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "frps {args:?} must reach the load; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert!(
            combined(&out).contains("-x"),
            "frps {args:?} must name `-x` as the config path; output={:?}",
            combined(&out)
        );
    }
}

/// `-c --` is the same rule: pflag consumes the separator token as the value
/// before `parseArgs` can reach it as a terminator (`parseArgs` treats `--` as
/// one only when it is the *current* token, and the value arm has already taken
/// it). Measured on Go v0.71.0: rc 1, `open --: no such file or directory`.
#[test]
fn dash_dash_as_config_value_is_consumed_not_a_separator() {
    let out = run_frps(&["-c", "--"]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frps -c -- must try to open a file named `--` like Go; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        all.contains("--"),
        "the child must name `--` as the config path it could not read; output={all:?}"
    );
    assert!(
        !all.contains("not expected"),
        "`--` must not survive as a separator token for the parser to refuse; output={all:?}"
    );
}

/// The scope control: a real `--` still terminates flags, and a dangling `-c`
/// is still a refusal. **Measured on Go v0.71.0, and the `--` half is a larger
/// divergence than the message shape**: `frps -p <free> -- junk` and
/// `frps -p <free> -- --strict-config=false` **start the server** (alive at 3-6 s,
/// `frps started successfully`) because cobra takes everything after `--` as
/// positional args and `frps`'s `RunE` ignores them; only a positional *without*
/// `--` is an error (`frps junk` → rc 1 `unknown command "junk" for "frps"`).
/// frp-rs refuses a leftover positional with or without `--` — the recorded
/// divergence — so this test pins the refusal on our side, not a match with Go.
/// A dangling `-c` *is* a match: `flag needs an argument: 'c' in -c` on Go.
///
/// Without the first assertion, a mutant that attached `=` to whatever follows
/// any `-c` would pass this file.
#[test]
fn real_separator_and_dangling_config_stay_refused() {
    // A real `--`: the token after it is positional, never `-c`'s value. Go
    // ignores that positional and serves; frp-rs refuses it (both with and
    // without a `--`), which is this suite's recorded positional divergence.
    let out = run_frps(&["-c", "probe.toml", "--", "--strict-config=false"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "frp-rs refuses the leftover positional (Go starts the server); \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        all.contains("--strict-config=false"),
        "the refused leftover must be named; output={all:?}"
    );
    assert!(
        !all.contains("Failed to load config"),
        "the token after a real `--` must not have been taken as `-c`'s value; output={all:?}"
    );

    // Dangling `-c`: still a refusal, with no value invented from anywhere.
    let out = run_frps(&["-c"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a dangling -c must stay a refusal; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        combined(&out).contains("`-c` requires an argument"),
        "the dangling `-c` refusal must keep naming the flag; output={:?}",
        combined(&out)
    );
}

/// The control row, re-measured after the rewrite: `--config-dir` is an frp-rs
/// **extension** (Go frps answers `unknown flag: --config-dir`, rc 1) and it is
/// one of the four flags the rewrite covers — so its dash-valued form now
/// reaches the directory read (`-x` is opened, not refused) and lands on the
/// extension's `EXIT_CONFIG`/2 instead of the parser's rc 1
/// ``--config-dir` requires an argument `DIR``. Recorded in `docs/developing.md`
/// § CLI exit codes with this measurement; Go's row is a different divergence (a
/// flag it does not have) and cannot be matched.
#[test]
fn config_dir_dash_value_now_reaches_the_directory_read() {
    let out = run_frps(&["--config-dir", "-x"]);

    assert_eq!(
        out.status.code(),
        Some(2),
        "--config-dir is an frp-rs extension and its refusal stays on 2; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        all.contains("config directory"),
        "the dash-shaped value must reach the directory read; output={all:?}"
    );
    assert!(
        !all.contains("requires an argument"),
        "the parser must no longer refuse the dash-shaped value; output={all:?}"
    );
}

/// The item's third row, pinned **because it is sequencing, not parity**: Go has
/// `frps verify`, frp-rs does not. Measured on Go v0.71.0:
/// `frps verify -c --strict-config=false` is rc 1 `open --strict-config=false: no
/// such file or directory`; here the rewrite lets `-c` consume its value, so the
/// missing subcommand is now the first error.
///
/// **This test is a tripwire and its cheapest future fix is deletion — do not
/// take it.** Implementing `frps verify` makes this test fail; that is the
/// intended signal, and the fix is to move the pin to whatever the row now
/// reports (and the matching row in `docs/developing.md` § CLI inputs), not to
/// delete the test. The reason lives here and in the `frps verify` item in
/// `TODO.md`, which carries the same warning.
#[test]
fn verify_subcommand_is_now_the_first_error_for_a_dash_config_value() {
    let out = run_frps(&["verify", "-c", "--strict-config=false"]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "frp-rs has no `frps verify`; the unknown subcommand is rc 1 \
         (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        all.contains("verify") && all.contains("not expected"),
        "the current first error must be the unknown `verify` subcommand, not a `-c` refusal; \
         output={all:?}"
    );
    assert!(
        !all.contains("-c` requires an argument"),
        "the `-c` value must have been consumed by the rewrite; output={all:?}"
    );
}

/// The other side of the same pflag rule, pinned so the help-precedence change
/// is recorded rather than discovered: `--help` is only special when pflag
/// *reaches* it as a flag. `frps -c --help` therefore takes `--help` as the
/// config path.
///
/// Measured on Go v0.71.0 (free port): rc 1, `open --help: no such file or
/// directory`. frp-rs before this branch: **rc 0, the help text** (bpaf resolved
/// `--help` before the value); frp-rs now: rc 1 naming `--help` — a match, and a
/// deliberate loss of the old frp-rs convenience.
///
/// The neighbouring shape `frps --help` (no `-c`) prints help on both trees —
/// not pinned here because it is not discriminating; the value-position rule is
/// what this test is about. `frps -c <word> --help` is likewise rc 0 + help on
/// both trees (the value is a plain word, so no attachment happens) and is
/// deliberately not covered.
#[test]
fn dash_help_after_config_is_a_value_not_a_help_request() {
    const HELP_MARKER: &str = "frps is the server of frp-rs";

    let out = run_frps(&["-c", "--help"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "`-c --help` must read `--help` as the config path, as Go does \
         (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        all.contains("--help"),
        "the load error must name `--help` as the path; output={all:?}"
    );
    assert!(
        !all.contains(HELP_MARKER),
        "help must not have been printed — `--help` was `-c`'s value; output={all:?}"
    );
    assert!(
        !all.contains("requires an argument"),
        "the parser must not have refused the value; output={all:?}"
    );
}

/// Repeated `-c`, measured on both sides because the rewrite changes **which**
/// refusal is reported and frp-rs has no last-wins at all on `frps`:
///
/// ```text
/// Go v0.71.0:  frps -c a.toml -c b.toml                   → rc 1 `open b.toml: …` (last-wins; starts with a valid b)
/// Go v0.71.0:  frps -c --strict-config=false -c good.toml → starts (the second -c overwrites the first)
/// frp-rs base: frps -c a.toml -c b.toml                   → rc 1 `argument `-c` cannot be used multiple times …`
/// frp-rs head: frps -c a.toml -c b.toml                   → rc 1, unchanged
/// frp-rs base: frps -c --strict-config=false -c …         → rc 1 `` -c` requires an argument `FILE` ``
/// frp-rs head: frps -c --strict-config=false -c …         → rc 1 `argument `-c` cannot be used multiple times …`
/// ```
///
/// So `frps -c a -c b` is a **pre-existing, unchanged** divergence (frp-rs
/// refuses repetition; Go is last-wins), and this branch only makes the refusal
/// message for the dash-value spelling consistent with it. The item's "same rule
/// on both binaries" covers the dash-value attachment, *not* last-wins: the frpc
/// `-c` last-wins work (`config_arg()`'s `.last()`) did not touch the frps
/// parser, and this branch does not either.
#[test]
fn repeated_config_flags_refuse_with_the_multiple_times_message() {
    let out = run_frps(&["-c", "a.toml", "-c", "b.toml"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "repetition is refused on frp-rs (Go is last-wins); stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        combined(&out).contains("cannot be used multiple times"),
        "the pre-existing repetition refusal must be named; output={:?}",
        combined(&out)
    );

    // The dash-value spelling now lands on that same refusal instead of the
    // "requires an argument" one — a message change, same rc.
    let out = run_frps(&["-c", "--strict-config=false", "-c", "p.toml"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the repeated dash-valued -c is still rc 1; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        all.contains("cannot be used multiple times"),
        "with the dash value consumed, the repetition is what bpaf reports first; output={all:?}"
    );
    assert!(
        !all.contains("-c` requires an argument"),
        "the first `-c` must have taken `--strict-config=false` as its value; output={all:?}"
    );
}
