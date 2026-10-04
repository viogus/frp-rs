//! `frps` CLI exit codes on the config-failure surface, pinned against Go frp
//! v0.71.0.
//!
//! Go's CLI is two-valued: 0 on success, 1 on any failure. Measured on Go
//! v0.71.0 (darwin/arm64) with one unknown top-level key added to an otherwise
//! valid server config, **stdout and stderr captured separately**:
//!
//! ```text
//! frps -c badfrps.toml   → rc 1, stdout `json: unknown field "notAKnownFrpKey"`, stderr 0 bytes
//! frps -c missing.toml   → rc 1, stdout `open missing.toml: no such file or directory`, stderr 0 bytes
//! ```
//!
//! frp-rs exited **2** (`EXIT_CONFIG`) on this path until the exit-code pin. Go
//! has no `frps --config-dir` at all (`Error: unknown flag: --config-dir`, rc 1);
//! frp-rs's is an extension whose refusals stay on `EXIT_CONFIG`/2 by the same
//! deliberate divergence as the client's. See `docs/developing.md`
//! § CLI exit codes.
//!
//! **Stream and shape are pinned too** (the `TODO.md` item "A CLI failure's
//! output shape is still not Go's"): the single-config load failure is now bare
//! line(s) on **stdout** with nothing on stderr, matching Go's
//! `fmt.Println(err)` / `os.Exit(1)` (`cmd/frps/root.go`) instead of an
//! ANSI-coloured `tracing` record. Two things are recorded, not matched, and the
//! fixtures below are single-key so neither is visible in them: the wording
//! (frp-rs names the config file; Go's decoder error has no path) and the line
//! count at N ≥ 2 (frp-rs prints one line per rejected key, Go stops at the
//! first — pinned at the collector by
//! `strict_check_reports_every_unknown_key_not_just_the_first` in
//! `frp-core/src/config/tests.rs`).
//!
//! Gated on `full`: the `frps` bin carries `required-features = ["full"]`, so
//! without the gate this file's `CARGO_BIN_EXE_frps` would fail to compile in
//! the no-default-features lanes CI runs.

#![cfg(feature = "full")]

use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_frps");

/// Overridable binary, the same hook `frps/tests/warn_delivery.rs` carries: a
/// falsification run points `FRPS_BIN` at a pre-fix build (`FRPS_BIN=<base>
/// cargo test -p frps --test cli_exit_codes <pin>`), and the default is
/// unchanged.
fn bin() -> String {
    std::env::var("FRPS_BIN").unwrap_or_else(|_| BIN.to_string())
}
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// The child's own **progress witness**: the SIGUSR1 task logs this line after
/// its `tokio::signal::unix::signal` call returns (`frps/src/main.rs:568`/`:921`
/// in the `--config-dir` lane, `:1135`/`:1137` on `-c`),
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

/// `Child::try_wait`, but the error path kills **and reaps** the child before
/// panicking, so that panic cannot orphan it. `try_wait` fails only on an OS
/// error — an already-reaped child is not an error, std caches its status — so
/// this is the "kill in the expect path" fix for the shape `TODO.md`'s
/// reload-guards item lists for this file (`:87`, `:258`, `:284` at the head the
/// item was written on; `:99`, `:422`, `:448` here). At the two later sites the
/// child is signalled and expected to exit on its own, and the already-exited
/// arm has reaped it; only the `try_wait` error path had a live child.
fn try_wait_or_kill(child: &mut Child, what: &str) -> Option<std::process::ExitStatus> {
    match child.try_wait() {
        Ok(status) => status,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("try_wait {what} failed: {e}");
        }
    }
}

fn run_frps(args: &[&str]) -> Output {
    run_frps_inner(args, &[])
}

/// [`run_frps`] with extra environment variables set on the child, for the
/// debug-build-only hooks in `frps/src/main.rs` that make a spawn-level failure
/// (a panicking service task) deterministic.
fn run_frps_with_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    run_frps_inner(args, envs)
}

fn run_frps_inner(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("spawn frps");
    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        match try_wait_or_kill(&mut child, "frps") {
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

/// Go: `frps -c <bad>` → one bare parse error on **stdout**, exit 1
/// (`cmd/frps/root.go`: `fmt.Println(err); os.Exit(1)`). Measured on Go v0.71.0
/// with the streams captured separately: stdout 38 bytes
/// (`json: unknown field "notAKnownFrpKey"`), stderr 0 bytes.
///
/// frp-rs now writes the same bare line to stdout with stderr empty; it is one
/// line per rejected key, and this fixture has one key, so this is the N=1 pin
/// (the N ≥ 2 count lives in `frp-core/src/config/tests.rs`). The
/// wording stays frp-rs's own (`in config file <path>`) and is recorded in
/// `docs/developing.md` § CLI exit codes. Asserting the exact bytes means a
/// regression to a `tracing` record (ANSI, timestamp, level, target, the
/// duplicated `error=` field) fails here rather than silently.
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
    assert_eq!(
        stdout_of(&out),
        format!("{UNKNOWN_FIELD} in config file {cfg}\n"),
        "frps -c <bad config> must print one bare line on stdout for this one-key \
         fixture (the N >= 2 case is N lines — see the module doc), like Go's \
         `fmt.Println(err)`; stderr={:?}",
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go prints nothing on stderr for this failure; stderr={:?}",
        stderr_of(&out),
    );
}

/// The sibling of the previous test: a missing file is the same failure class,
/// the same code (Go rc 1) and the same stream. Measured on Go v0.71.0:
/// stdout `open <path>: no such file or directory`, stderr 0 bytes.
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
    assert!(
        stdout_of(&out).starts_with(&format!("{missing}: failed to read config file:")),
        "the load error must be one **bare** line on stdout — it starts with the path, with no \
         log prefix (timestamp/level/target) and no ANSI escape — and must name the missing \
         config file; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go prints nothing on stderr for this failure; stderr={:?}",
        stderr_of(&out),
    );
}

// ── the extension codes on the server: 3 (auth) ─────────────────────────────

/// `EXIT_AUTH`/3 on the **server**, on the same input the client pins: an
/// `auth.tokenSource` whose file does not exist. Go frp v0.71.0 exits **1**
/// (`failed to resolve auth.tokenSource: failed to read file …`); frp-rs exits
/// **3**. Measured on both binaries with the streams captured separately and the
/// ports distinct per run — see `docs/developing.md` § CLI exit codes.
///
/// Before the typed classification this arm read
/// `logging::is_token_error(&e)`, and it is one of the three sites that made the
/// code depend on the message text. The kind now comes from the constructor
/// (`frp-core/src/init_error.rs`).
#[test]
fn unresolvable_token_source_exits_3_where_go_exits_1() {
    let dir = TempDir::new();
    let missing = dir.path("no-such-token-file");
    let cfg = dir.write(
        "badsource.toml",
        &format!(
            "bindPort = 7500\n[auth]\nmethod = \"token\"\n\
             tokenSource = {{ type = \"file\", file = {{ path = \"{missing}\" }} }}\n"
        ),
    );

    let out = run_frps(&["-c", &cfg]);

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

/// The post-load `--allow-unsafe` gate runs on **verify**, because it now runs
/// on the load path — so `verify` refuses the same
/// `auth.tokenSource = { type = "exec" }` the daemon refuses at construction.
///
/// Measured on Go frp v0.71.0 with the two streams captured separately (a fresh
/// config and a fresh free port per row, every child bounded and reaped):
///
/// | argv | Go | this file's base |
/// |---|---|---|
/// | `frps verify -c <exec cfg>` | rc 1, stdout `unsafe feature "TokenSourceExec" is not enabled. To enable it, ensure it is allowed in the configuration or command line flags`, stderr 0 B | rc 0, `syntax is ok` |
/// | `frps verify … --allow-unsafe TokenSourceExec` | rc 0, `frps: the configuration file <p> syntax is ok` | rc 0 (the gate was never run) |
/// | `frps verify … --allow-unsafe WrongFeature` | rc 1 (fail-closed) | rc 0 (fail-open) |
/// | `frps verify … --allow-unsafe WrongFeature --allow-unsafe TokenSourceExec` | rc 0 (pflag `strings` appends) | rc 1 — bpaf refused the second occurrence |
/// | `frps verify … --allow-unsafe TokenSourceExec --allow-unsafe WrongFeature` | rc 0 (a later unrelated value does not cancel an earlier enabling one) | rc 1 |
/// | `frps verify … --allow-unsafe Ignored,TokenSourceExec` | rc 0 (each occurrence is comma-split) | rc 0 |
/// | `frps verify … --allow-unsafe WrongFeature --allow-unsafe Ignored --allow-unsafe TokenSourceExec` | rc 0 (three occurrences append too — the enabling value need not be within the first two) | rc 1 — bpaf refused the second occurrence |
/// | `frps verify … --allow-unsafe A --allow-unsafe B --allow-unsafe Cc --allow-unsafe TokenSourceExec` | rc 0 (four occurrences append too; Go accepts five as well — pflag's `strings` has no cap) | rc 1 — bpaf refused the second occurrence |
/// | `frps -c <exec cfg>` (run) | rc 1, the same stdout line | rc 3, `EXIT_AUTH` |
///
/// frp-rs's wording stays its own predicate message; what is pinned is the
/// **lane**: the refusal is one bare line on stdout with stderr empty and rc 1,
/// the same lane the parse failures take, and the run row stays **3** because
/// the gate is not moved out of service construction (that would silently move
/// the documented `EXIT_AUTH`/3 extension onto Go's rc 1).
///
/// Teeth: deleting the `check_server_unsafe_features` call from
/// `load_server_config_checked` makes the first row exit 0 (`left: Some(0)`);
/// making the allow-list check always true makes the `WrongFeature` row exit 0.
#[test]
fn verify_runs_the_post_load_allow_unsafe_gate_like_go() {
    let dir = TempDir::new();
    // No real port is needed: every refusing row exits before anything binds,
    // and the one row that would bind (`--allow-unsafe` on the run path) is not
    // exercised here.
    let cfg = dir.write(
        "execsource.toml",
        "bindPort = 7500\n[auth]\nmethod = \"token\"\n\
         [auth.tokenSource]\ntype = \"exec\"\n\
         [auth.tokenSource.exec]\ncommand = \"/bin/sh\"\nargs = [\"-c\", \"printf tok\"]\n",
    );
    const GATE_MSG: &str = "auth.tokenSource exec blocked: TokenSourceExec not in UnsafeFeatures \
                            allowlist. Pass --allow-unsafe TokenSourceExec to enable.";

    let refuse = run_frps(&["verify", "-c", &cfg]);
    assert_eq!(
        refuse.status.code(),
        Some(1),
        "Go refuses an exec tokenSource on verify with rc 1; the load-path gate must \
         reproduce that lane; stdout={:?} stderr={:?}",
        stdout_of(&refuse),
        stderr_of(&refuse),
    );
    assert_eq!(
        stdout_of(&refuse),
        format!("{GATE_MSG}\n"),
        "the refusal must be one bare line on **stdout** (no log prefix, no ANSI), \
         like Go's `fmt.Println(err)`; stderr={:?}",
        stderr_of(&refuse),
    );
    assert!(
        stderr_of(&refuse).is_empty(),
        "Go prints nothing on stderr for a verify refusal; stderr={:?}",
        stderr_of(&refuse),
    );

    let accept = run_frps(&["verify", "-c", &cfg, "--allow-unsafe", "TokenSourceExec"]);
    assert_eq!(
        accept.status.code(),
        Some(0),
        "--allow-unsafe TokenSourceExec must satisfy the gate (measured rc 0 on Go); \
         stdout={:?} stderr={:?}",
        stdout_of(&accept),
        stderr_of(&accept),
    );
    assert_eq!(
        stdout_of(&accept),
        format!("frps: the configuration file {cfg} syntax is ok\n"),
        "the accept row keeps Go's success line and empty stderr; stderr={:?}",
        stderr_of(&accept),
    );
    assert!(
        stderr_of(&accept).is_empty(),
        "stderr={:?}",
        stderr_of(&accept)
    );

    let wrong = run_frps(&["verify", "-c", &cfg, "--allow-unsafe", "WrongFeature"]);
    assert_eq!(
        wrong.status.code(),
        Some(1),
        "the allow-list is fail-closed: an unrelated feature does not enable \
         TokenSourceExec (measured rc 1 on Go); stdout={:?} stderr={:?}",
        stdout_of(&wrong),
        stderr_of(&wrong),
    );

    // pflag's `strings` **appends** on repetition and comma-splits every
    // occurrence, so Go's verify honours all five spellings below (measured
    // rc 0 on v0.71.0 for each, in both value orders; Go also accepts four and
    // five occurrences, so there is no bound to pin — the rows are one step each).
    // The `TokenSourceExec`-first row separates appending from a last-wins
    // reading; the three-occurrence row kills a parser that caps at two
    // (`.many().map(|mut v: Vec<String>| { v.truncate(2); v })`) and the
    // four-occurrence row kills the same mutant one step out (`v.truncate(3)`).
    // The unbounded class is pinned in `frp-core`'s unit test, which builds 32
    // occurrences rather than a literal row.
    for extra in [
        vec![
            "--allow-unsafe",
            "WrongFeature",
            "--allow-unsafe",
            "TokenSourceExec",
        ],
        vec![
            "--allow-unsafe",
            "TokenSourceExec",
            "--allow-unsafe",
            "WrongFeature",
        ],
        vec!["--allow-unsafe", "Ignored,TokenSourceExec"],
        vec![
            "--allow-unsafe",
            "WrongFeature",
            "--allow-unsafe",
            "Ignored",
            "--allow-unsafe",
            "TokenSourceExec",
        ],
        vec![
            "--allow-unsafe",
            "A",
            "--allow-unsafe",
            "B",
            "--allow-unsafe",
            "Cc",
            "--allow-unsafe",
            "TokenSourceExec",
        ],
    ] {
        let mut argv = vec!["verify", "-c", cfg.as_str()];
        argv.extend(extra.iter().copied());
        let repeated = run_frps(&argv);
        assert_eq!(
            repeated.status.code(),
            Some(0),
            "Go accepts `--allow-unsafe {extra:?}` on verify (measured rc 0): a repeated \
             pflag `strings` appends and each occurrence is comma-split; stdout={:?} stderr={:?}",
            stdout_of(&repeated),
            stderr_of(&repeated),
        );
        assert_eq!(
            stdout_of(&repeated),
            format!("frps: the configuration file {cfg} syntax is ok\n"),
            "the accepted repeat keeps Go's success line and empty stderr; stderr={:?}",
            stderr_of(&repeated),
        );
    }

    // The run path is untouched: the same config is still refused by
    // construction with the typed EXIT_AUTH/3, not by the loader.
    let run = run_frps(&["-c", &cfg]);
    assert_eq!(
        run.status.code(),
        Some(3),
        "the run path must keep the EXIT_AUTH/3 construction refusal; the load-path \
         gate exists for verify only; stdout={:?} stderr={:?}",
        stdout_of(&run),
        stderr_of(&run),
    );
}

/// The hardening divergence `:3313` names: `[auth] method = "token"` with an
/// empty `token` is refused at construction with **3**, whereas Go frps has no
/// such check and **starts and keeps running** (`frps started successfully`,
/// alive after 8 s, killed by the probe). There is therefore no Go exit code to
/// compare against — this is not "Go exits 1 here", and the test must not be
/// written as if it were.
///
/// It is 3 rather than 4 because the *kind* is auth (`AuthConfig::check_startup`
/// rejects the token material), which is the whole point of classifying by kind:
/// the refusal's message happens to contain "[auth].token", but it would be
/// tagged `Auth` even if it did not.
#[test]
fn empty_token_refusal_is_a_hardening_divergence_go_does_not_have() {
    let dir = TempDir::new();
    // A real port is not needed: the refusal happens before `Service::run`
    // binds anything, and this test requires the process to *exit*.
    let cfg = dir.write(
        "emptytoken.toml",
        "bindPort = 7500\n[auth]\nmethod = \"token\"\ntoken = \"\"\n",
    );

    let out = run_frps(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(3),
        "frp-rs refuses an empty token at construction with EXIT_AUTH/3 — a hardening \
         divergence: Go has no check and does not exit at all, so there is no Go code to \
         match here; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains("server would accept ALL connections"),
        "the refusal must say why the server is refusing, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// `[auth] method = "oidc"` with no issuer: frp-rs refuses at construction with
/// **3**; Go frps **panics** (`panic: Get "/.well-known/openid-configuration":
/// unsupported protocol scheme ""`) and its runtime exits **2**. That panic is
/// also why no blanket "Go only returns 0 or 1" belongs in the docs.
///
/// The issuer is not needed to reach the refusal. Note what this arm does **not**
/// demonstrate: it is **not** an example of the pre-change text coupling, and
/// `frps` was never the daemon where that coupling was reachable. Every frps
/// construction failure already carried `auth` or `token` in its message — this
/// one passes through `check_startup`'s `[auth]` text, and an OIDC *dial* failure
/// through the `Cannot start frps with OIDC auth: …` wrapper
/// (`frp-server/src/service.rs`) — so at base `frps` exited **3 for every
/// reachable construction failure** and `EXIT_BIND`/4 was **unreachable** there.
/// Measured at `d0f9ec5` for `/authz`, `/zzz`, a missing `tokenSource`, an empty
/// token, a missing OIDC CA file, an empty issuer and an empty audience. The
/// pre-change 3-vs-4 flip is a **client** property, pinned by
/// `frpc/tests/cli_exit_codes.rs::oidc_construction_failure_exits_3_whatever_the_issuer_path`.
#[test]
fn oidc_without_an_issuer_is_refused_with_3_where_go_panics() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "noissuer.toml",
        "bindPort = 7500\n[auth]\nmethod = \"oidc\"\n[auth.oidc]\naudience = \"x\"\n",
    );

    let out = run_frps(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(3),
        "frp-rs refuses an OIDC method with no issuer with EXIT_AUTH/3; Go exits 2 by \
         panicking, so there is no rc to match — only a divergence to record; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains("oidc_issuer is empty"),
        "the refusal must name the empty issuer, got stdout={:?} stderr={:?}",
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
/// default 7000 (`frp-core/src/config/server.rs:502-504`), which on macOS is
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
///    (`frp-server/src/service.rs:929-961`), so the listener can be accepting
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
/// returns (`frps/src/main.rs:568` installs the handler, `frps/src/main.rs:921`
/// logs the marker; the `-c` lane's twin is `frps/src/main.rs:1135`/`:1137`),
/// i.e. only after that `frps` is past its
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
/// **That window is now closed for `--config-dir` — and only there**
/// (`TODO.md:9531`). main installs its own `SIGTERM`/`SIGINT` recorder
/// (`EarlyShutdown` in `frps/src/main.rs`) *before* the startup line, and each
/// per-file task hands its `AppState` to that recorder when it registers, so a
/// `SIGTERM` that lands in this window is recorded and the service's shutdown
/// token is cancelled instead of the process dying by signal. `-c` is
/// deliberately unchanged and still carries the window: its single service has
/// no registration hook a test could drive, so owning the handler *there*
/// without a pinned handoff could only turn the signal death into a lost
/// `SIGTERM`, which is worse. The window path for `--config-dir` has its own
/// deterministic pin (below rather than spread over this helper):
/// `config_dir_sigterm_inside_the_registration_window_exits_0_through_the_recorded_request`.
///
/// The marker stays the readiness barrier for the tests using this helper — for
/// `--config-dir` it is no longer the *only* thing standing between a connect
/// and a signal death.
///
/// Output goes to a file, not a pipe: a child whose piped stdout nobody reads
/// can block on a full pipe.
fn start_listening_then_sigterm(args: &[&str], port: u16, dir: &TempDir) -> String {
    let log_path = dir.path("frps.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(bin())
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
        if let Some(status) = try_wait_or_kill(&mut child, "frps") {
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
        match try_wait_or_kill(&mut child, "frps") {
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
/// (`frp-core/src/config/server.rs:502-504`), which on macOS is held by Control
/// Center. The released-port window is microseconds and these tests only need
/// the listener to come up.
fn ephemeral_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    probe.local_addr().expect("local_addr").port()
}

/// An ephemeral port **held** by the returned listener for as long as the
/// binding lives, with its number.
///
/// [`ephemeral_port`] releases its probe, which is fine for a test that only
/// needs a number. A test that must *hold* the port — to prove that a command
/// which should not bind, does not — cannot reuse it: between the probe's drop
/// and the re-bind, another test running in parallel in this same binary can
/// take the port. That is a measured harness fault here, not a hypothesis: the
/// first cut of `verify_valid_config_prints_go_line_and_exits_0` used
/// `ephemeral_port()` and then re-bound it, and a full-file run collided with
/// `verify_resolves_leading_root_flags_and_ignores_the_rest` doing the same
/// thing, failing on `AddrInUse` (os error 48) rather than on the assertion.
fn held_port() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("hold an ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    (listener, port)
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

/// `--config-dir` must not report success when **every** file in the directory
/// fails service construction (as opposed to failing to load). At `b8e1dd6d`
/// the lane pushed its `tokio::spawn` handle *before* the service was built, so
/// `handles` was non-empty even when every task returned early inside
/// `Service::with_unsafe_features`; the `handles.is_empty()` guard never fired,
/// the already-finished tasks were awaited, and the process exited **0** — for a
/// server that started no listener.
///
/// The fixture file carries no `[auth].token`, so construction is refused on the
/// auth lane: `-c <that file>` exits 3 (`EXIT_AUTH`), and the directory lane must
/// exit on the same typed code.
#[test]
fn config_dir_where_every_service_fails_init_exits_like_dash_c() {
    let port = ephemeral_port();
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let file = conf_d.join("frps.toml");
    std::fs::write(&file, format!("bindPort = {port}\n")).expect("write config");
    let file = file.to_str().expect("utf-8 temp path");

    let control = run_frps(&["-c", file]);
    assert_eq!(
        control.status.code(),
        Some(3),
        "control: an empty-token config on `-c` must exit 3 (EXIT_AUTH); \
         stdout={:?} stderr={:?}",
        stdout_of(&control),
        stderr_of(&control),
    );

    let out = run_frps(&["--config-dir", conf_d.to_str().expect("utf-8 temp path")]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "every file failing service init must exit on the same typed lane as \
         `-c` (3), not 0; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// The **run**-failure sibling of the pin above: a directory whose every file
/// loads and constructs but whose services cannot start must not report success
/// either. The fixture is [`valid_config`] — a token and a real port — with the
/// port **held** ([`held_port`]), so `Service::run` fails on
/// `Address already in use (os error 48)`; that is the shape the `-c` control
/// exits 1 on (`EXIT_RUNTIME`, the single-config lane's mapping for any `run()`
/// error).
///
/// At `9a0df13d` the lane counted only *construction* failures: a task whose
/// `run()` failed reported `Ok(())`, so the exit guard's failure list stayed
/// empty and `frps --config-dir` exited **0** with zero listeners.
///
/// The second half pins the **mixed** shape — one file that cannot be
/// constructed (no `[auth].token`) plus one whose port is held — which also
/// exited 0 with nothing listening. `collect_config_files` returns files in
/// sorted order, so `a.toml` (construction failure, `EXIT_AUTH`/3) is position
/// 0 and `b.toml` (run failure, `EXIT_RUNTIME`/1) is position 1; the all-failed
/// decision exits the **file-order first** failure's code, exactly the code
/// `-c a.toml` exits on, so the pair exits 3. (The assertion used to be only
/// "non-zero" because the guard exited on whichever task the runtime happened
/// to complete first, which made the code scheduling-dependent — the guard in
/// `frps/src/main.rs` now sorts by the file's position in `files`.)
#[test]
fn config_dir_where_every_service_fails_to_run_exits_like_dash_c() {
    let (holder, port) = held_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let file = conf_d.join("frps.toml");
    std::fs::copy(&cfg, &file).expect("copy the held-port config into conf.d");
    let file = file.to_str().expect("utf-8 temp path");

    let control = run_frps(&["-c", file]);
    assert_eq!(
        control.status.code(),
        Some(1),
        "control: a config whose bindPort is held on `-c` must exit 1 \
         (EXIT_RUNTIME); stdout={:?} stderr={:?}",
        stdout_of(&control),
        stderr_of(&control),
    );

    let out = run_frps(&["--config-dir", conf_d.to_str().expect("utf-8 temp path")]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "every file failing to run must exit on the same lane as `-c` (1), not 0; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        !stdout_of(&out).contains("listener started"),
        "no listener can start on a held port; stdout={:?}",
        stdout_of(&out),
    );
    drop(holder);

    // Mixed shape: one unconstructible file plus one whose port is held.
    let (holder, port) = held_port();
    let mixed = dir.0.join("mixed.d");
    std::fs::create_dir_all(&mixed).expect("create mixed.d");
    std::fs::write(mixed.join("a.toml"), format!("bindPort = {port}\n")).expect("write a.toml");
    std::fs::copy(valid_config(&dir, port), mixed.join("b.toml")).expect("copy b.toml");
    let mixed_out = run_frps(&["--config-dir", mixed.to_str().expect("utf-8 temp path")]);
    assert_eq!(
        mixed_out.status.code(),
        Some(3),
        "a directory where every service failed must exit the file-order first \
         failure's code — `a.toml`'s construction refusal (3), the same code \
         `-c a.toml` exits on; stdout={:?} stderr={:?}",
        stdout_of(&mixed_out),
        stderr_of(&mixed_out),
    );
    assert!(
        !stdout_of(&mixed_out).contains("listener started"),
        "no listener can start on a held port; stdout={:?}",
        stdout_of(&mixed_out),
    );
    drop(holder);
}

/// The **converse** of the two all-failed pins above, and the shape that makes
/// the all-failed comparison itself load-bearing: one file's service fails at
/// run time (its `bindPort` is held, so its task returns `Err(EXIT_RUNTIME)`),
/// the other binds and serves. `failures.len() == files.len()` is false there,
/// so the directory has a survivor and must return normally — the process stays
/// up, keeps accepting connections on the surviving port, and exits 0 on
/// SIGTERM. Replacing that comparison with `if true` exits the failure's code
/// for this directory too; both all-failed pins stay green under that mutant
/// (every file in their fixtures fails), which is why this pin exists.
#[test]
fn config_dir_where_one_service_fails_keeps_serving_and_exits_zero() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let port = ephemeral_port();
    let (holder, held) = held_port();
    std::fs::write(
        conf_d.join("a.toml"),
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {port}\n[auth]\ntoken = \"cli-exit-test\"\n"),
    )
    .expect("write a.toml");
    std::fs::write(
        conf_d.join("b.toml"),
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {held}\n[auth]\ntoken = \"cli-exit-test\"\n"),
    )
    .expect("write b.toml");

    // Waits for the surviving listener to accept *and* the SIGUSR1 ready
    // marker, then sends SIGTERM and asserts the exit code is 0.
    let log = start_listening_then_sigterm(
        &["--config-dir", conf_d.to_str().expect("utf-8 temp path")],
        port,
        &dir,
    );
    assert!(
        log.contains("frps service error for config file")
            && log.contains("Address already in use"),
        "b.toml's held-port service must really have failed at run time, or this pin \
         would pass with no failure for the directory to survive; log={log:?}",
    );
    drop(holder);
}

/// The same converse pin with the file order **swapped**: `a.toml` is the file
/// whose service fails at run time and `b.toml` is the survivor.
///
/// The pin above cannot see a "the *first* file failed" short-circuit — its
/// failing file is `b.toml`, at index 1 — so appending
/// `|| failures.iter().any(|(file_index, _)| *file_index == 0)` to the all-failed
/// comparison survived it (35 `cli_exit_codes` + 16 `warn_delivery` + 19 tiny +
/// 18 full all green). Under that mutant this directory exits `a.toml`'s
/// `EXIT_RUNTIME`/1 after SIGTERM instead of returning, so the surviving
/// `b.toml` listener plus the `Some(0)` exit code are the teeth.
#[test]
fn config_dir_where_the_first_service_fails_keeps_serving_and_exits_zero() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let port = ephemeral_port();
    let (holder, held) = held_port();
    std::fs::write(
        conf_d.join("a.toml"),
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {held}\n[auth]\ntoken = \"cli-exit-test\"\n"),
    )
    .expect("write a.toml");
    std::fs::write(
        conf_d.join("b.toml"),
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {port}\n[auth]\ntoken = \"cli-exit-test\"\n"),
    )
    .expect("write b.toml");

    // Waits for the surviving listener to accept *and* the SIGUSR1 ready
    // marker, then sends SIGTERM and asserts the exit code is 0.
    let log = start_listening_then_sigterm(
        &["--config-dir", conf_d.to_str().expect("utf-8 temp path")],
        port,
        &dir,
    );
    assert!(
        log.contains("frps service error for config file")
            && log.contains("a.toml")
            && log.contains("Address already in use"),
        "a.toml's held-port service must really have failed at run time, or this pin \
         would pass with no failure for the directory to survive; log={log:?}",
    );
    drop(holder);
}

/// The startup line main logs **after** installing its `SIGTERM`/`SIGINT`
/// recorder and **before** spawning any per-file task (`frps/src/main.rs`), so it
/// is a hard lower bound for "the main task owns the signal" — the opposite
/// bound from [`SIGNAL_READY_MARKER`], which needs a *registered* service.
const STARTUP_LINE_FRAGMENT: &str = "starting 1 services from config directory";

/// Spawn `frps --config-dir` with the debug-only registration hold
/// (`FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS`) set far longer than this helper's
/// own timeout, wait only for the **startup line**, then SIGTERM and return the
/// exit status with the log.
///
/// [`start_listening_then_sigterm`] cannot drive this pin: it waits for
/// [`SIGNAL_READY_MARKER`], which the SIGUSR1 task logs only *after* the
/// registration barrier opens — i.e. after the very window this pin needs to
/// signal in. With the hold set, that marker arrives only once the hold is
/// released, so waiting for it would defeat the pin.
///
/// The hold is deliberately longer than `EXIT_TIMEOUT`: if the recorder's early
/// wake regresses, the child must fail this pin (by not exiting in time) instead
/// of quietly sleeping out the hold, registering afterwards, and shutting down
/// gracefully for the wrong reason.
#[cfg(unix)]
fn sigterm_inside_the_registration_window(
    args: &[&str],
    dir: &TempDir,
    hold_ms: u64,
) -> (ExitStatus, String) {
    let log_path = dir.path("frps-window.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(bin())
        .args(args)
        .env(
            "FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS",
            hold_ms.to_string(),
        )
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn frps");
    let read_log = || std::fs::read_to_string(&log_path).expect("read frps diagnostic log");

    let ready_deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if read_log().contains(STARTUP_LINE_FRAGMENT) {
            break;
        }
        if let Some(status) = try_wait_or_kill(&mut child, "frps") {
            panic!(
                "frps {args:?} exited ({status:?}) before logging its startup line; log={:?}",
                read_log()
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "frps {args:?} never logged its startup line within {EXIT_TIMEOUT:?}; log={:?}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();

    let started = Instant::now();
    let deadline = started + EXIT_TIMEOUT;
    loop {
        match try_wait_or_kill(&mut child, "frps") {
            Some(status) => return (status, read_log()),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "frps {args:?} did not exit within {EXIT_TIMEOUT:?} of a SIGTERM sent inside \
                     the pre-registration window (the hold is longer than this timeout, so it \
                     should have been ended by the recorded signal); log={:?}",
                    read_log()
                );
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// `TODO.md:9531`, the window driven **deterministically** instead of raced: the
/// debug-only `FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS` parks the per-file task
/// *before* it registers — therefore before `Service::run` installs its own
/// `SIGTERM` handler — and the hold is far longer than this pin's timeout, so
/// only the main task's recorder can end it.
///
/// Both assertions are causal:
///
/// 1. the child exits **0**. Before this fix, tokio's per-kind registration left
///    `SIGTERM` on the kernel's default disposition in this window and the child
///    died by signal (`code() == None`, shell rc 143); a lost signal would take
///    the same shape.
/// 2. the log carries `shutdown signal was recorded before this service installed
///    its own handler`, which the handoff can only print when it finds the signal
///    *already recorded* — so the exit came from the recorded request, not from a
///    race that happened to be won in the other order.
///
/// Assertion 1 alone would pass on any path that happened to drain gracefully;
/// assertion 2 is what proves *which* path did it. Falsification: remove the
/// recorder (no `EarlyShutdown::install()`, or no `early_shutdown.watch(...)`
/// handoff) and the child dies by signal inside the hold, failing both.
#[cfg(unix)]
// The `FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS` pin this drives is
// `#[cfg(debug_assertions)]` (`frps/src/main.rs:699`), so a release binary
// ignores it and the child outlives the SIGTERM hold the test needs. `ignore`
// (not `#[cfg]`) keeps the test compiled and *counted* in release: the
// `release-tests` lane in `.github/workflows/ci.yml` asserts the exact
// `41 passed; 0 failed; 3 ignored` summary and the exact three ignored names,
// so the release lane cannot widen its skip set unnoticed. It does *not* catch
// an unconditional `#[ignore]` (identical release output); that is the
// tests-unit lane's `FRPS_CLI_TESTS` count.
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug_assertions-only FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS hook (frps/src/main.rs:699)"
)]
#[test]
fn config_dir_sigterm_inside_the_registration_window_exits_0_through_the_recorded_request() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let port = ephemeral_port();
    std::fs::write(
        conf_d.join("a.toml"),
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {port}\n[auth]\ntoken = \"cli-exit-test\"\n"),
    )
    .expect("write a.toml");

    // 30 s: longer than `EXIT_TIMEOUT`, so the hold cannot end on its own.
    let (status, log) = sigterm_inside_the_registration_window(
        &["--config-dir", conf_d.to_str().expect("utf-8 temp path")],
        &dir,
        30_000,
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a SIGTERM recorded before the service registered must still drain to a clean 0 \
         (without the main-task recorder the child dies by signal here, so code() would be \
         None); status={status:?} log={log:?}",
    );
    assert!(
        log.contains("shutdown signal was recorded before this service installed its own handler"),
        "the exit must come from the **recorded** signal path: this line is emitted only when \
         the service's registration handoff finds the signal already recorded; log={log:?}",
    );
    assert!(
        log.contains("Accept loop stopped for graceful shutdown"),
        "the recorded signal must reach the service through the same graceful arm a \
         post-registration SIGTERM uses; log={log:?}",
    );
}

/// `TODO.md:9531`, the **fan-out** half of the recorder (review round 2, F7):
/// `record()` must cancel the tokens of services that registered *before* the
/// signal, not only let a later one observe it through the `watch()` handoff.
///
/// The interval where that matters is narrow. From the moment
/// `early_shutdown.watch(...)` puts a service into the fan-out list until
/// `Service::run` installs the service's own `SIGTERM` handler
/// (`frp-server/src/service.rs:1218-1245`), only the recorder can cancel that
/// token. The debug-only post-registration hold
/// (`FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS=30_000` with
/// `..._DELAY_FILES=a.toml`) parks `a.toml`'s task inside exactly that interval
/// and logs `test hold: registered for the shutdown fan-out` once it is in the
/// list. The second file is held by the *pre*-registration hook
/// (`FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS=30_000` with
/// `..._DELAY_FILES=c.toml`), so it registers after the signal and takes the
/// `watch()` handoff.
///
/// Both holds are longer than `EXIT_TIMEOUT` on purpose: their early wake comes
/// from `EarlyShutdown.recorded()`, so a regression that stops waking them shows
/// up as this pin timing out instead of as a hold that simply sleeps out.
///
/// After the hold line appears the pin sends one `SIGTERM` and requires:
///
/// 1. exit **0**. The held `a.toml` service's own `SIGTERM` handler does not
///    exist when the signal is delivered and the pin sends no second signal, so
///    only the recorder's fan-out can cancel its token; deleting that loop
///    leaves the service running on a live token with the main task awaiting it,
///    and this pin times out.
/// 2. the log carries the recorded-signal line, which the pre-registration-held
///    `c.toml` service can only print by registering after the signal and going
///    through `watch()` — so one run exercises both halves of the handoff.
/// 3. two graceful accept-loop stops: the fan-out service (woken by the recorded
///    request, running with a cancelled token) and the `watch()` one both
///    drained, which is what makes the exit code attributable to the recorder
///    rather than to one service happening to finish.
#[cfg(unix)]
// Same release skip as the sibling above: this pin additionally drives
// `FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS`
// (`#[cfg(all(unix, debug_assertions))]`, `frps/src/main.rs:776`), so in a
// release binary the fan-out service never reaches its hold and the run has
// nothing to observe. The `release-tests` lane's expected ignored-name set is
// what keeps this skip from spreading to tests that *can* run in release.
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug_assertions-only FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS / FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS hooks (frps/src/main.rs:699,:776)"
)]
#[test]
fn config_dir_recorded_signal_fans_out_to_an_already_registered_service() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let first_port = ephemeral_port();
    let second_port = ephemeral_port();
    std::fs::write(
        conf_d.join("a.toml"),
        format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {first_port}\n[auth]\ntoken = \"cli-exit-test\"\n"
        ),
    )
    .expect("write a.toml");
    std::fs::write(
        conf_d.join("c.toml"),
        format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {second_port}\n[auth]\ntoken = \"cli-exit-test\"\n"
        ),
    )
    .expect("write c.toml");

    let args = ["--config-dir", conf_d.to_str().expect("utf-8 temp path")];
    let log_path = dir.path("frps-fanout.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child: Child = Command::new(bin())
        .args(args)
        .env("FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS", "30000")
        .env("FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_FILES", "a.toml")
        .env("FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS", "30000")
        .env("FRPS_CFGDIR_TEST_REGISTRATION_DELAY_FILES", "c.toml")
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn frps");
    let read_log = || std::fs::read_to_string(&log_path).expect("read frps diagnostic log");

    // The hold line is the witness that `a.toml` is in the recorder's fan-out
    // list, which is the state this pin has to deliver the signal in.
    let ready_deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if read_log().contains("test hold: registered for the shutdown fan-out") {
            break;
        }
        if let Some(status) = try_wait_or_kill(&mut child, "frps") {
            panic!(
                "frps {args:?} exited ({status:?}) before the fan-out service registered; \
                 log={:?}",
                read_log()
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the fan-out service never registered within {EXIT_TIMEOUT:?}; log={:?}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();

    let deadline = Instant::now() + EXIT_TIMEOUT;
    let status = loop {
        match try_wait_or_kill(&mut child, "frps") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "frps {args:?} did not exit within {EXIT_TIMEOUT:?} of a SIGTERM sent after the \
                     fan-out service registered: the recorder must cancel the tokens of services \
                     that registered **before** the signal (without the fan-out that service runs \
                     on with a token nobody cancels and the main task awaits it forever); log={:?}",
                    read_log()
                );
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let log = read_log();
    assert_eq!(
        status.code(),
        Some(0),
        "both services must drain to a clean 0 through the recorded request; \
         status={status:?} log={log:?}",
    );
    assert!(
        log.contains("shutdown signal was recorded before this service installed its own handler"),
        "the service held across the signal must register through the `watch()` handoff; \
         log={log:?}",
    );
    assert_eq!(
        log.matches("Accept loop stopped for graceful shutdown")
            .count(),
        2,
        "the already-registered service (fan-out) and the held one (`watch()`) must both drain \
         through the graceful accept-loop arm; log={log:?}",
    );
}

/// `TODO.md:9531`, **recorded** rather than fixed: the collector admits a
/// directory entry by lowercased extension with no regular-file check
/// (`frp-core/src/config/file.rs:958`/`:976`; the `directory` guards live only in
/// the include-path `glob_in_dir` at `:873`/`:893`), and the loader then does a
/// blocking `std::fs::read_to_string` (`:435`). A FIFO named `*.toml` therefore
/// wedges the lane instead of being refused: the startup line is logged and the
/// per-file loop never gets past the read, so no service is ever constructed.
///
/// Go frp v0.71.0 is bounded the same way, measured on the real binaries
/// (`/private/tmp/frp_0.71.0_darwin_arm64/`): `frpc --config-dir` on a FIFO-only
/// directory was still running after 15 s with 0 bytes of log, and on FIFO +
/// valid file likewise; Go's `frps` has no `--config-dir` at all
/// (`Error: unknown flag: --config-dir`, rc 1, measured). The admission rule
/// itself is pinned in `frp-core`
/// (`test_collect_config_files_admits_a_non_regular_entry_by_extension`, where
/// an `if !path.is_file() { continue; }` guard reds it); this pin records the
/// process-level consequence and the one way out.
///
/// Measured before/after the main task owns the recorder (`EarlyShutdown`), on a
/// FIFO-only directory (nothing ever registers):
///
/// | `frps --config-dir` on a FIFO-only directory | 1st SIGTERM | 2nd SIGTERM |
/// | --- | --- | --- |
/// | base binary (`ea991757`, no main-task recorder) | died, rc 143 | — |
/// | this tree | alive (recorded, no service to stop) | exit 143 |
///
/// Both halves are load-bearing **for this fixture**. Without the recorder the
/// first signal kills the child (so "still alive after the first SIGTERM" reds),
/// and without the repeat-request escalation the second one is swallowed too (so
/// the pin times out).
///
/// **What this does not cover.** The escalation only fires while *no* service has
/// ever registered (`EarlyShutdown.states` is append-only, so "empty" cannot mean
/// "none running"). With a valid `a.toml` loaded first and the FIFO at `b.toml`,
/// one service registers and the lane is deaf to `SIGTERM` on both the base
/// binary and this tree: measured, both log `starting 2 services`, both survive
/// four SIGTERMs, and only `SIGKILL` ends them (`wait rc 137`). That is
/// pre-existing behaviour, not a regression from the recorder, and making it
/// killable is a behaviour change rather than a comment fix.
#[cfg(unix)]
#[test]
fn config_dir_fifo_entry_wedges_the_lane_and_a_repeat_signal_ends_it() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let fifo = conf_d.join("a.toml");
    let mkfifo = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(mkfifo.success(), "mkfifo {fifo:?} failed: {mkfifo:?}");

    let log_path = dir.path("frps-fifo.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child = Command::new(bin())
        .args(["--config-dir", conf_d.to_str().expect("utf-8 temp path")])
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn frps");
    let read_log = || std::fs::read_to_string(&log_path).expect("read frps diagnostic log");

    // The startup line proves the directory was *collected* (so the FIFO was
    // admitted, not refused) and the loop then blocked on the read.
    let ready_deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if read_log().contains(STARTUP_LINE_FRAGMENT) {
            break;
        }
        if let Some(status) = try_wait_or_kill(&mut child, "frps") {
            panic!(
                "frps exited ({status:?}) instead of wedging on the FIFO; log={:?}",
                read_log()
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "frps never logged its startup line within {EXIT_TIMEOUT:?}; log={:?}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    std::thread::sleep(Duration::from_secs(1));
    match child.try_wait() {
        Ok(None) => {}
        other => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the read on the FIFO is unbounded, so the lane must still be running a second \
                 after its startup line (Go's `frpc` matches); try_wait={other:?} log={:?}",
                read_log()
            );
        }
    }

    // 1st SIGTERM: the main task records it, but no service exists to cancel —
    // and the fix must not turn "dies on SIGTERM" into "signal lost".
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    std::thread::sleep(Duration::from_millis(1500));
    match child.try_wait() {
        Ok(None) => {}
        other => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "one recorded SIGTERM with nothing registered to stop cannot end this lane \
                 (HEAD died 143 here, and Go's client dies of the signal); try_wait={other:?} \
                 log={:?}",
                read_log()
            );
        }
    }

    // 2nd SIGTERM: nothing to cancel, so the recorder forces the exit — the lane
    // stays reversible without SIGKILL.
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let deadline = Instant::now() + EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = try_wait_or_kill(&mut child, "frps") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "a repeat SIGTERM with no registered service must force an exit within \
                 {EXIT_TIMEOUT:?}, otherwise a FIFO wedges the lane unkillably; log={:?}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        status.code(),
        Some(143),
        "the forced exit must report SIGTERM's 128 + 15 (not a graceful 0, which would claim a \
         service drained); status={status:?} log={:?}",
        read_log()
    );
    assert!(
        read_log().contains("requested again with no service registered to stop it"),
        "the forced exit must be diagnosed in the log; log={:?}",
        read_log()
    );
}

/// A file that fails to **load** never becomes a task, so it could not reach
/// the all-failed decision: at `d9f8e63c` a directory where every file failed
/// to load exited `EXIT_CONFIG`/2 purely because `handles` came out empty,
/// while `-c` on the same file exits 1 (`EXIT_RUNTIME`, the single-config
/// lane's mapping for every load error). The lane now records the load failure
/// in file order and exits that same code, so the two lanes agree.
#[test]
fn config_dir_where_every_file_fails_to_load_exits_like_dash_c() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let file = conf_d.join("frps.toml");
    // Not valid TOML: rejected in the loader, before any service is constructed.
    std::fs::write(&file, "this is not valid toml\n").expect("write config");
    let file = file.to_str().expect("utf-8 temp path");

    let control = run_frps(&["-c", file]);
    assert_eq!(
        control.status.code(),
        Some(1),
        "control: `-c` on an unparseable config must exit 1 (EXIT_RUNTIME); \
         stdout={:?} stderr={:?}",
        stdout_of(&control),
        stderr_of(&control),
    );

    let out = run_frps(&["--config-dir", conf_d.to_str().expect("utf-8 temp path")]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "every file failing to load must exit the same code `-c` does (1), not \
         the old EXIT_CONFIG 2; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// The **file-order sort** in the all-failed decision is load-bearing for
/// exactly one mix: a *later* file failing to **load** — recorded in file order
/// by the construction loop — plus an *earlier* file whose task fails **after**
/// the loop, so the two entries are appended out of order. Every other
/// all-failed fixture here fails in a single phase (or in file order within a
/// phase), so deleting `failures.sort_by_key(|(file_index, _)| *file_index)` in
/// `frps/src/main.rs` left the whole lane green — the review's F1.
///
/// `a.toml` carries no `[auth].token`, so its **task** returns
/// `Err(EXIT_AUTH)`/3 after the loop, while `b.toml` is unparseable and pushes
/// its load failure (`EXIT_RUNTIME`/1) into `load_failures` first. Sorted by
/// index the file-order first failure is `a.toml`'s 3 — the code `-c a.toml`
/// exits on — while with the sort deleted the lane exits `b.toml`'s 1.
#[test]
fn config_dir_exits_the_first_files_code_when_a_later_file_fails_to_load() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let port = ephemeral_port();
    // No `[auth].token`: construction is refused with `EXIT_AUTH`/3 *inside the
    // task*, i.e. after the loop has already recorded `b.toml`'s load failure.
    std::fs::write(conf_d.join("a.toml"), format!("bindPort = {port}\n")).expect("write a.toml");
    // Not valid TOML: rejected in the loader, so this file never becomes a task.
    std::fs::write(conf_d.join("b.toml"), "this is not valid toml\n").expect("write b.toml");
    let a = conf_d.join("a.toml");
    let a = a.to_str().expect("utf-8 temp path");

    let control = run_frps(&["-c", a]);
    assert_eq!(
        control.status.code(),
        Some(3),
        "control: `-c a.toml` (no auth token) must exit 3 (EXIT_AUTH), the code \
         the sorted all-failed decision must reproduce; stdout={:?} stderr={:?}",
        stdout_of(&control),
        stderr_of(&control),
    );

    let out = run_frps(&["--config-dir", conf_d.to_str().expect("utf-8 temp path")]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "the all-failed decision must exit the **file-order first** failure's code \
         (a.toml's EXIT_AUTH/3), not the entry appended last (b.toml's load \
         failure, 1); stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// An **existing but empty** `--config-dir` must be refused with
/// `EXIT_CONFIG`/2 and the empty-directory diagnostic, not fall through to the
/// all-load-failed arm below. The client's twin is pinned in
/// `frpc/tests/cli_exit_codes.rs::config_dir_refusals_exit_2_where_go_exits_0`;
/// on the server only the **message** discriminates: with `files.is_empty()`
/// deleted the directory still exits 2, because the all-load-failed arm's
/// `unwrap_or(EXIT_CONFIG)` fires when there are no load failures, but it
/// reports "No services started — all config files failed to load" instead.
/// This pin asserts both the code and that diagnostic.
#[test]
fn config_dir_refuses_an_empty_directory_with_2() {
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");

    let out = run_frps(&["--config-dir", conf_d.to_str().expect("utf-8 temp path")]);

    assert_eq!(
        out.status.code(),
        Some(2),
        "an existing but empty --config-dir must exit 2 (EXIT_CONFIG); \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        combined(&out).contains("No config files found in directory"),
        "the empty-directory refusal must name the condition — the \
         all-load-failed arm's message means `files.is_empty()` was skipped; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

/// A **panicking** service task must count toward the all-failed decision, not
/// merely be logged. The guard pushed `Ok(Err(code))` only, so a `JoinError`
/// was logged at `frps/src/main.rs` and dropped: with a directory whose every
/// task panicked, `failures.len() == files.len()` could never hold, nothing
/// stayed up, and the process exited **0**.
///
/// The panic is driven by the debug-only `FRPS_CFGDIR_TEST_PANIC` hook — gated
/// on `debug_assertions`, so it does not exist in a release binary — which
/// panics the task named by the value **after** it registered, i.e. exactly the
/// task shape the guard must count. The fixture needs no free port beyond the
/// config itself: the task panics before `Service::run`, so no listener starts;
/// the point is that the lane cannot report success with nothing served.
// The `FRPS_CFGDIR_TEST_PANIC` pin this drives is `#[cfg(debug_assertions)]`
// (`frps/src/main.rs:820`), so in a release binary the task panics at the
// ordinary startup path (or not at all) and the exit code this test asserts is
// not the code under test. The `release-tests` lane asserts that exactly these
// three names are ignored in release; an unconditional `#[ignore]` produces the
// same release output and is caught by the tests-unit lane's count instead.
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug_assertions-only FRPS_CFGDIR_TEST_PANIC hook (frps/src/main.rs:820)"
)]
#[test]
fn config_dir_where_every_task_panics_exits_nonzero() {
    let port = ephemeral_port();
    let dir = TempDir::new();
    let conf_d = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_d).expect("create conf.d");
    let cfg = valid_config(&dir, port);
    let file = conf_d.join("frps.toml");
    std::fs::copy(&cfg, &file).expect("copy the valid config into conf.d");
    let file = file.to_str().expect("utf-8 temp path");

    let out = run_frps_with_env(
        &["--config-dir", conf_d.to_str().expect("utf-8 temp path")],
        &[("FRPS_CFGDIR_TEST_PANIC", file)],
    );

    assert_eq!(
        out.status.code(),
        Some(1),
        "a directory whose only task panicked served nothing and must not exit 0; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        combined(&out).contains("frps service task panicked"),
        "the panic must still be logged; stdout={:?} stderr={:?}",
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
/// actually binding and connecting, below. `TODO.md:3498`.
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
/// section (`cli_overrides_enabled()` is false, `frp-core/src/cli.rs:5095`), so
/// the parsed `tls_only = false` never reaches the service — a mutant that
/// consumed `=false` but stored `true` would still pass this test. The value
/// actually being applied is pinned in
/// `disable_log_color_value_spelling_is_applied`, whose flag *is* read from the
/// CLI (`frps/src/main.rs:474`).
#[test]
fn tls_only_false_value_starts_and_listens() {
    let port = ephemeral_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);

    start_listening_then_sigterm(&["--tls-only=false", "-c", &cfg], port, &dir);
}

/// Go v0.71.0 accepts `--vhost-http-timeout 30 -c <valid>` on the run path and
/// starts (bounded run: rc 124). Before the flag was registered, frp-rs answered
/// rc **1** with stderr `` `--vhost-http-timeout` is not expected in this
/// context `` — an argv Go's `frps` accepts, refused.
///
/// Go registers the name with underscores
/// (`cmd.PersistentFlags().Int64VarP(&c.VhostHTTPTimeout, "vhost_http_timeout",
/// "", 60, …)`, `pkg/config/flags.go:237`) and rewrites every `_` to `-`
/// (`WordSepNormalizeFunc`, `:26-32`), so both spellings are valid flags and
/// this row runs both through the same bounded helper.
///
/// As with `--tls-only=false` above, "started" is proved by the bind port
/// accepting a connection, not by an exit code. **What this does not prove:**
/// with `-c` the file is authoritative (`cli_overrides_enabled()` is false,
/// `frp-core/src/cli.rs`), so the parsed value never reaches the service here.
/// That the value is applied on the lane where it *is* read (no `-c`) is pinned
/// by `frp-core/src/cli.rs::vhost_http_timeout_flag_applied_to_server_config`.
#[test]
fn vhost_http_timeout_flag_starts_and_listens() {
    for spelling in ["--vhost-http-timeout", "--vhost_http_timeout"] {
        let port = ephemeral_port();
        let dir = TempDir::new();
        let cfg = valid_config(&dir, port);

        start_listening_then_sigterm(&[spelling, "30", "-c", &cfg], port, &dir);
    }
}

/// The `=value` spelling is not merely accepted — it is the value the flag
/// carries. `--disable-log-color` is the observable one: the frps log
/// initialiser reads it straight off the CLI
/// (`logging::resolve_ansi(!disable)` → `with_ansi(ansi)`,
/// `frps/src/main.rs:474`), so the child's own output shows which value won.
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

/// Both streams, ANSI stripped. Retained for the assertions that genuinely want
/// "anywhere in the child's output" — the parser refusals, which go to stderr.
/// The single-config **load** error is no longer wrapped in a `tracing` line
/// (it is bare line(s) on stdout, see
/// [`bad_config_exits_1_and_names_the_unknown_field`]), so load-path assertions
/// read `stdout_of` directly and thereby pin the stream as well. The stripping
/// mirrors what `--disable-log-color` does to a log line and keeps a text
/// assertion about the message, not the colour.
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
/// (`<value>: failed to read config file`) on **stdout** plus the absence of any
/// parser refusal, because "the output contains the token" is *not*
/// discriminating on its own: the parser's refusal text already names
/// `--bind-port`, `-x` and `-c` (`` … got a flag `-x`, try `-c=-x` …``). Only
/// `--strict-config=false` is named solely by its own refusal
/// (`` `-c` requires an argument `FILE` ``), so all four iterations assert the
/// load line **and its stream** — a refusal would leave stdout empty; the base
/// tree then fails on `--strict-config=false` for the old reason and on the
/// other three because the load line is absent (they were refusals, not loads).
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
        let stdout = stdout_of(&out);
        assert!(
            stdout.contains("failed to read config file") && stdout.contains(value),
            "frps -c {value} must name `{value}` as the path it could not read on stdout, not \
             refuse the token as a flag; stdout={stdout:?} stderr={:?}",
            stderr_of(&out),
        );
        let all = combined(&out);
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
        !stdout_of(&out).contains("failed to read config file"),
        "the token after a real `--` must not have been taken as `-c`'s value — that would put \
         the load line on stdout; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
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

/// The item's third row, **re-pointed** now that `frps verify` exists — this was
/// the tripwire the `frps verify` item (`TODO.md`, "Go has `frps verify`, frp-rs
/// has no `frps verify` at all") was told to expect, and it is re-pointed rather
/// than deleted.
///
/// What it pinned before: with the shared dash-value rewrite in place,
/// `frps verify -c --strict-config=false` reported `` `verify` is not expected in
/// this context `` — the missing subcommand was the *first* error, because the
/// rewrite attaches `--strict-config=false` to `-c` as its value. `verify` is a
/// real command now, so that first error is gone; the rewrite is still the
/// reason the value is attached, and the first error is now the config read.
///
/// Measured on Go v0.71.0 with the two streams captured separately and the exit
/// status read directly from the child: rc **1**, stdout exactly
/// `open --strict-config=false: no such file or directory`, stderr 0 bytes. This
/// test pins the same rc, the same stream, and the two facts that make it the
/// *same row*: the output **names `--strict-config=false` as the path** (so the
/// rewrite still put it in the value position) and it is **not** an
/// unexpected-token refusal (so `verify` was resolved and the loader ran).
#[test]
fn verify_subcommand_resolves_so_the_dash_config_value_is_the_first_error() {
    let out = run_frps(&["verify", "-c", "--strict-config=false"]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "the value-position path must reach the loader and fail there, as Go does \
         (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).starts_with("--strict-config=false: failed to read config file:"),
        "the first error must be the config read, on **stdout**, naming \
         `--strict-config=false` as the path — that is what shows the rewrite consumed it as \
         `-c`'s value and `verify` was resolved as the command; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "the refusal is a bare stdout line like Go's `fmt.Println(err)`; stderr={:?}",
        stderr_of(&out),
    );
    let all = combined(&out);
    assert!(
        !all.contains("not expected"),
        "the argv must no longer be refused for the bare word `verify` — the command exists; \
         output={all:?}"
    );
    assert!(
        !all.contains("-c` requires an argument"),
        "the `-c` value must have been consumed by the rewrite; output={all:?}"
    );
}

// ── `frps verify` (Go's verifyCmd) ──────────────────────────────────────────

/// Go v0.71.0, streams captured separately, exit status read directly from the
/// child: `frps verify -c <valid config>` is rc **0**, stdout exactly
/// `frps: the configuration file <path> syntax is ok\n`, stderr 0 bytes
/// (`cmd/frps/verify.go:56`). The base binary answered rc 1 `` `verify` is not
/// expected in this context `` on stderr for this argv — a *valid* config
/// reported as a failure by the one command whose job is to say whether it is
/// valid.
///
/// The config's `bindPort` is **held** by this test's own listener for the whole
/// run. `verify` reads and validates a config; it never binds
/// (`cmd/frps/verify.go` calls `LoadServerConfig` + `ValidateServerConfig` and
/// returns), so a version of `verify` that fell through to the run path would
/// fail right here instead of passing. Nothing is timed and nothing is
/// reaped — the listener is this test's own socket, dropped at the end.
#[test]
fn verify_valid_config_prints_go_line_and_exits_0() {
    let (_held, port) = held_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);

    let out = run_frps(&["verify", "-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "`frps verify -c <valid>` must exit 0 like Go (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert_eq!(
        stdout_of(&out),
        format!("frps: the configuration file {cfg} syntax is ok\n"),
        "the success line is Go's, byte for byte — one bare stdout line, no ANSI and no log \
         prefix; stderr={:?}",
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go writes nothing on stderr for this row; stderr={:?}",
        stderr_of(&out),
    );
}

/// The `verify` side of the same flag. Go's `verifyCmd` reads only `cfgFile` and
/// `strictConfigMode` and **ignores** this value, so the success bytes are the
/// ones the row above pins. Measured on Go v0.71.0, streams separated, rc read
/// from the child: `frps verify --vhost-http-timeout 30 -c <valid>` and
/// `frps verify --vhost_http_timeout 30 -c <valid>` are both rc **0** with
/// stdout exactly `frps: the configuration file <path> syntax is ok\n` and
/// stderr 0 bytes. Before the flag was registered, frp-rs refused both spellings
/// with rc **1** and the same bpaf `` is not expected in this context `` line.
///
/// The config's `bindPort` is held for the whole run, as in
/// `verify_valid_config_prints_go_line_and_exits_0`: `verify` never binds, so a
/// version that fell through to the run path fails here instead of passing.
#[test]
fn verify_accepts_vhost_http_timeout_both_spellings_and_prints_go_line() {
    let (_held, port) = held_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);

    for spelling in ["--vhost-http-timeout", "--vhost_http_timeout"] {
        let out = run_frps(&["verify", spelling, "30", "-c", &cfg]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "`frps verify {spelling} 30 -c <valid>` must exit 0 like Go \
             (stdout={:?} stderr={:?})",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert_eq!(
            stdout_of(&out),
            format!("frps: the configuration file {cfg} syntax is ok\n"),
            "Go ignores the value on `verify`, so the success line is unchanged — one bare \
             stdout line, no ANSI and no log prefix; stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "Go writes nothing on stderr for this row; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// Signed `int64` rows on the same `verify` surface, for **both** flag
/// spellings. Go's flag is `Int64VarP` (`pkg/config/flags.go:237`) and its config
/// field is `int64`, so a negative value is accepted (`verify` ignores it) and
/// only a value outside `int64` is refused. Go also normalizes `_` to `-` before
/// parsing (`cmd/frps/root.go:105`
/// `SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)`), so
/// `--vhost_http_timeout` takes the same range as the hyphen spelling. Measured
/// on Go v0.71.0 for every row below, streams separated, rc read from the child:
/// `0`, `-1`, `-9223372036854775808` and `9223372036854775807` are rc **0** under
/// both spellings with the same success line; `9223372036854775808` and
/// `9999999999999999999` are rc **1** under both spellings, with
/// `strconv.ParseInt: … value out of range` on stderr naming the flag in its
/// hyphen form and 0 bytes on stdout.
///
/// **Which parts of the refusal are contractual (R4, `TODO.md:9934`).** The
/// sentence is not: frp-rs prints 84 B
/// ``Error: couldn't parse `9999999999999999999`: number too large to fit in
/// target type`` — bpaf's wording — where Go prints 2214 B (`strconv.ParseInt`'s
/// `value out of range` plus cobra's `Usage:` block). That residual difference is
/// deliberate and accepted here. What the refusal loop below pins is the shape
/// the two share and a user depends on: rc **1**, **0 bytes on stdout**, and
/// stderr naming the offending value, so it is possible to tell *which* flag
/// value was rejected. The exact sentence is quoted, not equality-asserted, so a
/// bpaf reword is a diff in this comment rather than a red test.
///
/// **Bound on this pin.** Because the guarded property is only "stderr names the
/// offending value", a mutant that keeps a `<String>` parser and merely re-words
/// the error still passes (measured: `.map_err(|_| "value out of range")` → rc 1
/// with a 64 B stderr, green). The assertion freezes the property against a
/// future *non-bpaf* refusal path; it is not a mutant detector for any refusal
/// that still echoes the token.
///
/// This is a separate `#[test]` from
/// `verify_accepts_vhost_http_timeout_both_spellings_and_prints_go_line` so the
/// `FRPS_CLI_TESTS` count guard in `.github/workflows/ci.yml` covers these rows:
/// a count guard counts test functions, so rows folded into another function can
/// be deleted without moving the count. The config's `bindPort` is held for the
/// whole run, as in `verify_valid_config_prints_go_line_and_exits_0`.
#[test]
fn verify_handles_vhost_http_timeout_go_signed_int64_range() {
    let (_held, port) = held_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);

    for spelling in ["--vhost-http-timeout", "--vhost_http_timeout"] {
        for value in ["0", "-1", "-9223372036854775808", "9223372036854775807"] {
            let out = run_frps(&["verify", spelling, value, "-c", &cfg]);
            assert_eq!(
                out.status.code(),
                Some(0),
                "`frps verify {spelling} {value} -c <valid>` is inside Go's int64 \
                 and must exit 0 (stdout={:?} stderr={:?})",
                stdout_of(&out),
                stderr_of(&out),
            );
            assert_eq!(
                stdout_of(&out),
                format!("frps: the configuration file {cfg} syntax is ok\n"),
                "Go ignores the value on `verify`, so the success line is unchanged — one bare \
                 stdout line, no ANSI and no log prefix; stderr={:?}",
                stderr_of(&out),
            );
        }
        for value in ["9223372036854775808", "9999999999999999999"] {
            let out = run_frps(&["verify", spelling, value, "-c", &cfg]);
            assert_eq!(
                out.status.code(),
                Some(1),
                "`frps verify {spelling} {value} -c <valid>` is outside Go's int64 and \
                 must be refused like Go (stdout={:?} stderr={:?})",
                stdout_of(&out),
                stderr_of(&out),
            );
            assert!(
                !stdout_of(&out).contains("syntax is ok"),
                "a refused value must not print the success line; stdout={:?}",
                stdout_of(&out),
            );
            assert!(
                stdout_of(&out).is_empty(),
                "frp-rs reports the parse refusal on stderr like Go; stdout={:?}",
                stdout_of(&out),
            );
            // Contractual part of the diagnostic (R4): the refusal must name the
            // offending value, so a user can tell which flag value was rejected.
            // The surrounding wording is bpaf's and incidental — see this
            // test's doc comment.
            assert!(
                stderr_of(&out).contains(value),
                "the refusal must echo the offending value `{value}`; stderr={:?}",
                stderr_of(&out),
            );
            assert!(
                !stderr_of(&out).is_empty(),
                "a refusal with an empty stderr is indistinguishable from silence; \
                 stdout={:?}",
                stdout_of(&out),
            );
        }
    }
}

/// `-l` is **not** a shorthand on `frps` (R5, `TODO.md:9944`). Go registers
/// `log_level` with an empty shorthand (`pkg/config/flags.go:244`,
/// `cmd.PersistentFlags().StringVarP(&c.Log.Level, "log_level", "", …)`), so
/// `frps -c cfg -l ""` is rc **1** there too — but pflag's wording is
/// `unknown shorthand flag: 'l' in -l`. frp-rs registers no `-l` short at all:
/// `svr_log` has only the long spellings (`frp-core/src/cli.rs:930`), and
/// `VALUE_TAKING_SHORTS_FRPS_ROOT` (`frp-core/src/cli.rs:1223`) is not the reason
/// — it only governs a **two-character** `-xy` token. Measured over a *valid*
/// config and over a missing one alike: rc **1**, **0 B stdout**, 44 B stderr
/// ``Error: `-l` is not expected in this context``.
///
/// The wording is bpaf's and incidental — the same status R4's note gives its
/// own sentence. What is contractual, and what this test pins, is that `-l` is
/// neither silently accepted as `--log-level`'s shorthand nor allowed to look
/// like a config-load failure: the refusal names the flag on **stderr** with
/// stdout empty, while the long spelling and the `-t` shorthand both reach the
/// loader (whose error goes to stdout, like Go's).
#[test]
fn short_l_is_not_a_frps_shorthand_and_the_refusal_is_pinned() {
    let dir = TempDir::new();
    let missing = dir.path("nope.toml");
    let load_failure_prefix = format!("{missing}: failed to read config file:");

    // The flag under test: refused at parse time, so the path is never read and
    // no load error can appear on stdout.
    let out = run_frps(&["-c", &missing, "-l", ""]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "`frps -c <cfg> -l \"\"` must be rc 1 (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).is_empty(),
        "the refusal belongs on stderr, not stdout; stdout={:?}",
        stdout_of(&out),
    );
    assert!(
        stderr_of(&out).contains("`-l`"),
        "the refusal must name the flag it refused; stderr={:?}",
        stderr_of(&out),
    );
    assert!(
        !stdout_of(&out).contains(&load_failure_prefix),
        "`-l` must be refused before the config is read; stdout={:?}",
        stdout_of(&out),
    );

    // Control 1: the long spelling does parse, and the process gets all the way
    // to the loader — the witness is the load error naming the missing path, on
    // stdout, with stderr empty (Go's shape). Same argv, only the flag form
    // differs from the case above.
    let out = run_frps(&["-c", &missing, "--log-level", ""]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the long spelling must parse and then fail on the missing file \
         (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).starts_with(&load_failure_prefix),
        "`--log-level \"\"` must have reached the loader; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "a parse success writes nothing on stderr; stderr={:?}",
        stderr_of(&out),
    );

    // Control 2: `-t` **is** a value-taking shorthand on this root (the same
    // constant), so it also reaches the loader. Without this arm, control 1
    // would not distinguish "the shorthand table has no `l`" from "every short
    // flag is refused on this lane".
    let out = run_frps(&["-c", &missing, "-t", "x"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "`-t` is a value-taking shorthand and must parse (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).starts_with(&load_failure_prefix),
        "`-t x` must have reached the loader; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "a parse success writes nothing on stderr; stderr={:?}",
        stderr_of(&out),
    );
}

/// The failure half of the same surface, both shapes of "bad config": an unknown
/// key under the default (strict) mode and a value that does not fit its type.
/// Measured on Go v0.71.0, streams separated, rc read directly — both are rc
/// **1** with one bare line on **stdout** and 0 bytes on stderr
/// (`cmd/frps/verify.go:41-44`: `fmt.Println(err); os.Exit(1)`):
///
/// ```text
/// frps verify -c <unknown-key>   → stdout `json: unknown field "notAKnownFrpKey"`
/// frps verify -c <string bindPort> → stdout `field "bindPort": cannot unmarshal string into int`
/// ```
///
/// The frp-rs wording is frp-rs's own (it names the config path — see
/// `docs/developing.md` § CLI exit codes), so these assert rc + stream + the
/// identifying fragment rather than Go's exact bytes; the *line shape* is what
/// would regress if a `tracing` record came back, and the assertions below catch
/// that.
#[test]
fn verify_invalid_config_exits_1_with_the_load_error_on_stdout() {
    let dir = TempDir::new();
    let bad_key = dir.write("badfrps.toml", BAD_CONFIG);
    let bad_port = dir.write("badportfrps.toml", "bindPort = \"not-a-port\"\n");

    // (config, identifying fragment, whether the fragment leads the line). The
    // two failure shapes put the path in different places: the strict-key
    // collector's message ends with `in config file <path>`, while the loader
    // wraps the serde type error with the path as a **prefix**. Both are one
    // bare line, which is the claim that would regress if a `tracing` record
    // came back.
    let rows: [(&str, &str, bool); 2] = [
        (&bad_key, UNKNOWN_FIELD, true),
        (
            &bad_port,
            "config validation error: invalid type: string \"not-a-port\"",
            false,
        ),
    ];
    for (cfg, fragment, fragment_leads) in rows {
        let out = run_frps(&["verify", "-c", cfg]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "`frps verify -c {cfg}` must exit 1 like Go (stdout={:?} stderr={:?})",
            stdout_of(&out),
            stderr_of(&out),
        );
        let stdout = stdout_of(&out);
        assert!(
            stdout.contains(fragment) && stdout.contains(cfg),
            "the load error must name both the fault ({fragment:?}) and the config file; \
             stdout={stdout:?} stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stdout.ends_with('\n') && stdout.lines().count() == 1,
            "the load error must be exactly one bare line on stdout for this one-fault fixture \
             — no timestamp/level/target prefix and no ANSI escape; stdout={stdout:?} \
             stderr={:?}",
            stderr_of(&out),
        );
        if fragment_leads {
            assert!(
                stdout.starts_with(fragment),
                "this row's message leads with the fault; stdout={stdout:?}"
            );
        } else {
            assert!(
                stdout.starts_with(cfg),
                "the loader wraps this row's message with the path as a prefix; stdout={stdout:?}"
            );
        }
        assert!(
            stderr_of(&out).is_empty(),
            "Go writes this refusal to stdout only; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// The missing-file row on the new subcommand: same failure class, same code and
/// same stream as the run path. Measured on Go v0.71.0: rc 1, stdout
/// `open <path>: no such file or directory`, stderr 0 bytes.
///
/// The assertion is a **prefix** pin (frp-rs names the path, then its own
/// wording), matching `missing_config_exits_1` on the run path.
#[test]
fn verify_missing_config_exits_1_naming_the_path() {
    let dir = TempDir::new();
    let missing = dir.path("does-not-exist.toml");

    let out = run_frps(&["verify", "-c", &missing]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "`frps verify -c <missing>` must exit 1 like Go (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).starts_with(&format!("{missing}: failed to read config file:")),
        "the load error must be one bare stdout line naming the missing path, with no log \
         prefix and no ANSI escape; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go writes nothing on stderr for this failure; stderr={:?}",
        stderr_of(&out),
    );
}

/// `frps verify` with **no** `-c` is not an error in Go, and that is a property
/// of `frps`, not of `verify`: its `-c` default is the empty string
/// (`cmd/frps/root.go:44`), and `verifyCmd` answers an empty `cfgFile` with
/// `frps: the configuration file is not specified` + `return nil`
/// (`cmd/frps/verify.go:36-39`). Measured on Go v0.71.0: rc **0**, stdout exactly
/// that line, stderr 0 bytes.
///
/// `frpc` is the opposite (its `-c` defaults to `./frpc.ini`), so this row is
/// deliberately not shared with the client's verify tests.
#[test]
fn verify_without_a_config_file_is_not_an_error() {
    let out = run_frps(&["verify"]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "an absent `-c` is rc 0 on Go for `frps verify` (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert_eq!(
        stdout_of(&out),
        "frps: the configuration file is not specified\n",
        "Go's exact line for this branch (`cmd/frps/verify.go:37`); stderr={:?}",
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go writes nothing on stderr for this row; stderr={:?}",
        stderr_of(&out),
    );
}

/// `--strict-config=false` must reach the verify loader in **every** flag
/// position Go accepts, because Go's `verifyCmd` reads the same persistent
/// pflag: after `-c`, before the command, and after the command.
///
/// Measured on Go v0.71.0 against a config with an unknown top-level key (rc 0,
/// `frps: the configuration file <path> syntax is ok`, stderr 0):
///
/// ```text
/// frps verify -c bad.toml --strict-config=false   → rc 0
/// frps verify --strict-config=false -c bad.toml   → rc 0
/// frps --strict-config=false verify -c bad.toml   → rc 0
/// frps --strict_config=false verify -c bad.toml   → rc 0   (the `_` alias, same pflag)
/// ```
///
/// The third and fourth rows only work because the hoist resolves a command that
/// follows root flags: the base binary answered rc 1 `` `verify` is not expected
/// in this context `` for them. The `=false` value is the discriminating half —
/// with strict on, the same config is rc 1 (the next test) — so these rows pin
/// the *value* arriving, not merely the command being found.
#[test]
fn verify_strict_config_false_is_lenient_in_every_flag_order() {
    let dir = TempDir::new();
    let cfg = dir.write("badfrps.toml", BAD_CONFIG);
    let expected = format!("frps: the configuration file {cfg} syntax is ok\n");

    for args in [
        &["verify", "-c", &cfg, "--strict-config=false"][..],
        &["verify", "--strict-config=false", "-c", &cfg][..],
        &["--strict-config=false", "verify", "-c", &cfg][..],
        &["--strict_config=false", "verify", "-c", &cfg][..],
    ] {
        let out = run_frps(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} must verify leniently, as Go does (stdout={:?} stderr={:?})",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert_eq!(
            stdout_of(&out),
            expected,
            "{args:?} must print Go's success line for the same config; stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "{args:?} is the Go-faithful `=` spelling and must not warn; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// The other side of the same flag: strict is still the default and still
/// refuses the unknown key — in the bare, `=true` and space-separated spellings.
///
/// Measured on Go v0.71.0 against the unknown-key config: rc 1 with
/// `json: unknown field "notAKnownFrpKey"` on stdout for `--strict-config`,
/// `--strict-config=true` **and** the space form `--strict-config true` (pflag's
/// bool does not consume `true`; the token is a positional `verifyCmd` ignores,
/// so strict stays at its `true` default). The space form is the one row where
/// frp-rs deliberately reads the token as the value — the documented extension —
/// and it prints its warning on stderr; strict is `true` there too, so the
/// verdict and rc agree with Go and only the warning is extra.
#[test]
fn verify_strict_config_true_still_refuses_the_unknown_key() {
    let dir = TempDir::new();
    let cfg = dir.write("badfrps.toml", BAD_CONFIG);
    let warning = frp_core::cli::STRICT_CONFIG_SPACE_FORM_WARNING;

    // (argv, is the space-separated extension). The flag is spelled out per row
    // rather than sniffed from the argv.
    let rows: [(&[&str], bool); 3] = [
        (&["verify", "-c", &cfg, "--strict-config"], false),
        (&["verify", "--strict-config=true", "-c", &cfg], false),
        (&["verify", "--strict-config", "true", "-c", &cfg], true),
    ];
    for (args, is_space_form) in rows {
        let out = run_frps(args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?} must refuse the unknown key under strict mode, as Go does \
             (stdout={:?} stderr={:?})",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert!(
            stdout_of(&out).starts_with(UNKNOWN_FIELD),
            "{args:?} must report the unknown field on stdout; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        let warned = stderr_of(&out).contains(warning);
        assert_eq!(
            warned,
            is_space_form,
            "{args:?}: the space form is the frp-rs extension and warns exactly once, every \
             other spelling is Go-faithful and silent; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// The `frps` root flags around the command, from the hoist's two directions:
/// a leading **value-taking** flag must not swallow the command, and a leading
/// **bool** flag must not either — while both keep their own value.
///
/// Measured on Go v0.71.0, each with its own free port and config, streams
/// separated, rc read directly (all rc 0, `frps: the configuration file <path>
/// syntax is ok`, stderr 0):
///
/// ```text
/// frps -c good.toml verify                          → the command resolves after `-c`
/// frps -p <free> verify -c good.toml                → `-p` swallows its port, not `verify`
/// frps --tls-only verify -c good.toml               → `--tls-only` is a pflag bool, so `verify` survives
/// frps --enable-prometheus verify -c good.toml      → same
/// frps verify --bind-port <free> -c good.toml       → a root flag after the command is accepted
/// frps verify --allow-unsafe X --version -c good.toml → accepted and ignored: no version is printed
/// frps verify -c good.toml -c later.toml            → pflag last-wins on the persistent `-c`
/// ```
///
/// The counter-example that keeps this honest is `--dashboard-tls-mode`, which is
/// **not** a pflag bool on Go (`VarP(BoolFuncFlag{…})`, `pkg/config/flags.go:256`)
/// and therefore *does* swallow `verify`: Go then starts the server instead of
/// verifying. It is not asserted here — frp-rs models that flag as a bool and
/// refuses the leftover token instead (rc 1, a recorded divergence in
/// `docs/developing.md` § CLI inputs) — but it is the row that decides the
/// exemption list in `consumes_value`.
#[test]
fn verify_resolves_leading_root_flags_and_ignores_the_rest() {
    let dir = TempDir::new();
    let (_held, port) = held_port();
    let cfg = valid_config(&dir, port);
    let expected = format!("frps: the configuration file {cfg} syntax is ok\n");
    // The two flag *values* below are never bound (`verify` binds nothing), so
    // a fresh ephemeral port is only a way to avoid a literal that could be a
    // real service on the runner.
    let swallowed = ephemeral_port().to_string();
    let after_cmd = ephemeral_port().to_string();

    let rows: [Vec<&str>; 6] = [
        vec!["-c", &cfg, "verify"],
        vec!["-p", swallowed.as_str(), "verify", "-c", &cfg],
        vec!["--tls-only", "verify", "-c", &cfg],
        vec!["--enable-prometheus", "verify", "-c", &cfg],
        vec!["verify", "--bind-port", after_cmd.as_str(), "-c", &cfg],
        vec!["verify", "--allow-unsafe", "X", "--version", "-c", &cfg],
    ];
    for args in &rows {
        let out = run_frps(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} must verify, as Go does (stdout={:?} stderr={:?})",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert_eq!(
            stdout_of(&out),
            expected,
            "{args:?} must print the verify success line — and for `--version` that is the \
             discriminator: Go prints a version only from the root command's `RunE`, never from \
             `verifyCmd`; stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "{args:?} must not warn; stderr={:?}",
            stderr_of(&out),
        );
    }

    let later = dir.write(
        "laterfrps.toml",
        &format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {}\n[auth]\ntoken = \"cli-exit-test\"\n",
            ephemeral_port()
        ),
    );
    let out = run_frps(&["verify", "-c", &cfg, "-c", &later]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a repeated `-c` on `verify` is pflag last-wins, as on Go (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert_eq!(
        stdout_of(&out),
        format!("frps: the configuration file {later} syntax is ok\n"),
        "the **last** `-c` is the one loaded, as Go's StringVar makes it; stderr={:?}",
        stderr_of(&out),
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
    // The first line of the rendered root document (Go's description, which the
    // cobra-shaped renderer prints verbatim). Only a help request can produce it.
    const HELP_MARKER: &str = "frps is the server of frp (https://github.com/fatedier/frp)";

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

/// `frps verify` must refuse the two **frp-rs-only** `frps` root flags, because
/// Go's `frps` refuses them. Measured on Go v0.71.0 with the streams separated
/// and the exit status read directly: `frps verify --log-format json -c <valid>`
/// and `frps verify --config-dir <dir> -c <valid>` are each rc **1**, stdout
/// 0 B, stderr `Error: unknown flag: --log-format` / `--config-dir` plus the
/// usage block.
///
/// This is the pin for the round's one behavioural fix: before it,
/// `frps verify --log-format json -c <valid>` printed
/// `frps: the configuration file <valid> syntax is ok` and exited **0** — a
/// validation command reporting success for an argv Go rejects, which is the
/// exact reason `--config-dir` was already refused on this branch. The control
/// at the end keeps the fix from over-reaching: both flags are *documented
/// extensions on the run path*, and the run path still parses them there.
///
/// The two flags are the complete extension set (measured by diffing the two
/// binaries' rendered `--help` flag lists: frp-rs-only = {`config-dir`,
/// `log-format`}, Go-only = {`vhost-http-timeout`}).
#[test]
fn verify_refuses_the_two_frp_rs_only_root_flags_like_go() {
    let port = ephemeral_port();
    let dir = TempDir::new();
    let cfg = valid_config(&dir, port);
    let missing = dir.path("does-not-exist.toml");

    for (args, flag) in [
        (
            vec!["verify", "--log-format", "json", "-c", cfg.as_str()],
            "--log-format",
        ),
        (
            vec!["verify", "--log-format=json", "-c", cfg.as_str()],
            "--log-format",
        ),
        (
            vec!["verify", "--log_format", "json", "-c", cfg.as_str()],
            "--log_format",
        ),
        (
            vec!["verify", "--config-dir", "conf.d", "-c", cfg.as_str()],
            "--config-dir",
        ),
        (
            vec!["verify", "--config_dir", "conf.d", "-c", cfg.as_str()],
            "--config_dir",
        ),
    ] {
        let out = run_frps(&args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?} must be refused with rc 1, as Go refuses it \
             (stdout={:?} stderr={:?})",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert!(
            stdout_of(&out).is_empty(),
            "{args:?} must not reach the loader at all — no `syntax is ok`, and no load \
             error either, because the flag is refused first; stdout={:?}",
            stdout_of(&out),
        );
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(flag) && stderr.contains("not expected"),
            "{args:?} must name {flag} as the token it could not place; stderr={stderr:?}",
        );
    }

    // Control: the run path still accepts the same extension, so the refusal
    // above is about the *verify* surface and not about dropping the flag. The
    // witness is the load error naming the missing path — a parse refusal would
    // name the flag instead and print nothing.
    let out = run_frps(&["--log-format", "json", "-c", &missing]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the run path must still parse --log-format (stdout={:?} stderr={:?})",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).starts_with(&format!("{missing}: failed to read config file:")),
        "the run path must have accepted --log-format and reached the loader; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
}

// ── `auth.method`: the one policy, at the server's two sites ─────────────────

/// **Site 1 — `frps`'s method parse (`frp-server/src/service.rs`).** Go frp
/// v0.71.0 compares the method exactly against `SupportedAuthMethods`
/// (`pkg/config/v1/validation/server.go:31`) after `Auth.Complete()` filled an
/// empty one to `token` (`pkg/config/v1/server.go:136-139`), so a spelling that
/// is not exactly `token`/`oidc` is a **load error**.
///
/// Measured on Go v0.71.0 (darwin/arm64), own config and free port per case,
/// stdout/stderr redirected to separate files, `rc` from `wait` on the direct
/// child: `frps -c <method = "OIDC">` → **rc 1, 54 B stdout, 0 B stderr**, whole
/// stdout `invalid auth method, optional values are [token oidc]\n`. The same
/// shape holds for `"Oidc"`, `" oidc"`, `"oidc "`, `"tokenn"` and a Cyrillic-о
/// lookalike.
///
/// frp-rs used to `to_lowercase()` the method and treat every non-`oidc`
/// spelling as **token**, so `method = "OIDC"` selected OIDC (Go errors) while
/// `" oidc"`/`"tokenn"` selected token — an operator who asked for OIDC got a
/// token-auth server. This pins the exact bytes, the stream and the code.
#[test]
fn invalid_auth_method_exits_1_like_go_and_names_the_accepted_values() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "badmethod.toml",
        "bindAddr = \"127.0.0.1\"\nbindPort = 7500\n\n[auth]\ntoken = \"cli-exit-test\"\nmethod = \"OIDC\"\n",
    );

    let out = run_frps(&["-c", &cfg]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "an unrecognised auth.method is Go's load error (rc 1), not a started server; \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).ends_with(": invalid auth method, optional values are [token oidc]\n"),
        "the refusal must be Go's text, on stdout, with frp-rs's `<path>: ` prefix from the \
         loader and nothing else — no ANSI, no timestamp, no level; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go prints nothing on stderr for this failure; stderr={:?}",
        stderr_of(&out),
    );
}

/// **Site 1, the other half.** An absent/empty `auth.method` is Go's
/// `util.EmptyOr(c.Method, "token")` (`pkg/config/v1/server.go:136-139`), so
/// `method = ""` and a config with no `[auth] method` key must both complete to
/// **token** and the server must **run** — measured on Go v0.71.0: a server with
/// `method = ""` starts and listens (its stdout is its startup log, rc only
/// changes when the probe signals it).
///
/// The two spellings are checked at the load path *and* one of them is started
/// for real, because "the loader completed the value" and "the process can use
/// it" are different claims: the construction site
/// (`frp-server/src/service.rs`) re-parses the method, and a completion that
/// only reached the validator would leave this config unstartable.
///
/// The load-path half also pins the split the old code got wrong: `""` is
/// completed, while `" oidc"` (a value Go rejects, and which the old
/// `to_lowercase` match sent to **token**) is an error.
#[test]
fn empty_auth_method_completes_to_token_and_the_server_runs() {
    let dir = TempDir::new();
    let absent = dir.write(
        "noauthmethod.toml",
        "bindAddr = \"127.0.0.1\"\nbindPort = 7500\n\n[auth]\ntoken = \"cli-exit-test\"\n",
    );
    let empty = dir.write(
        "emptyauthmethod.toml",
        "bindAddr = \"127.0.0.1\"\nbindPort = 7500\n\n[auth]\ntoken = \"cli-exit-test\"\nmethod = \"\"\n",
    );

    // Load-path half: both shapes complete to "token", and " oidc" does not.
    for path in [&absent, &empty] {
        let cfg = frp_core::config::load_server_config(path, true)
            .unwrap_or_else(|e| panic!("{path} must load (empty method → token): {e}"));
        assert_eq!(
            cfg.auth.method, "token",
            "the loader must hand on the completed value for {path}"
        );
    }
    let spaced = dir.write(
        "spacedmethod.toml",
        "bindAddr = \"127.0.0.1\"\nbindPort = 7500\n\n[auth]\ntoken = \"cli-exit-test\"\nmethod = \" oidc\"\n",
    );
    let err = frp_core::config::load_server_config(&spaced, true)
        .expect_err("\" oidc\" must be a load error, not a token fallback")
        .to_string();
    assert!(
        err.ends_with("invalid auth method, optional values are [token oidc]"),
        "got {err:?}"
    );

    // Runtime half: `method = ""` starts and listens.
    let port = ephemeral_port();
    let cfg = dir.write(
        "empty-method.serve.toml",
        &format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {port}\n\n[auth]\ntoken = \"cli-exit-test\"\nmethod = \"\"\n"
        ),
    );
    start_listening_then_sigterm(&["-c", &cfg], port, &dir);
}
