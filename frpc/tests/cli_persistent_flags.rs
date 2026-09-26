//! `frpc`'s **persistent rootCmd flags** on the subcommands that do not read
//! them (`TODO.md:2173`).
//!
//! Go registers `-c/--config`, `--config-dir`, `--strict-config`,
//! `--allow-unsafe` and `-v/--version` on `rootCmd`
//! (`cmd/frpc/sub/root.go`, `func init()`), so pflag parses all five for
//! **every** subcommand — `frpc tcp --help` lists them under `Global Flags`.
//! The eight single-proxy commands never read any of them, and the four
//! admin commands do not read `--config-dir`/`--allow-unsafe`/`--version`:
//! frp-rs's bpaf parsers did not define them, so argv Go runs exited 1 with
//! ``Error: `-c` is not expected in this context`` and the proxy never started.
//!
//! Every claim below was measured against Go frp **v0.71.0** darwin/arm64 and
//! the frp-rs `frpc` built from this branch, with fixtures in
//! `/private/tmp/frpc-pflags-probe/`:
//!
//! * **The five flags are accepted and ignored on all eight single-proxy
//!   commands.** With a fixed proxy name and a probe listener on
//!   `--server-port`, Go reaches `try to connect to server...` and connects
//!   for `-c <file>`, `--config <file>`, `--config-dir <dir>`, a repeated
//!   `-c a -c b`, a `-`-prefixed value after `-c`, `-c <missing file>`,
//!   `--strict-config[=false]`, `--allow-unsafe TokenSourceExec` and
//!   `--version` — every one byte-identical in observable to the same argv
//!   with the flag removed. The file is never opened on either side.
//! * **A `-`-prefixed token after `-c` is the flag's value in Go.** Measured:
//!   `frpc status -c --strict-config=false` is
//!   `open --strict-config=false: no such file or directory`, and the
//!   three-token form `frpc status -c --strict-config=false -c p7498.toml`
//!   dials `p7498.toml`'s port because the later `-c` overwrites it. bpaf
//!   refuses a `--long` token as an argument value (`State::take_arg` accepts
//!   only a plain word), so `parse_frpc_args` rewrites exactly those
//!   config-flag occurrences into the attached `-c=VALUE` spelling first.
//! * **Two shapes stay divergent and are pinned here as recorded
//!   divergences, not parity.** (1) Positional arguments: Go ignores them on
//!   every subcommand — `frpc status -c p7498.toml -- -c p7499.toml` dials
//!   7498, `frpc status extra` loads `./frpc.ini`, `frpc tcp … extra` starts
//!   the proxy — while frp-rs refuses a leftover token, with or without `--`.
//!   That is a positional-args rule, not a persistent-flag one, so this item
//!   fixes the flags and records the positionals (docs/developing.md § CLI
//!   inputs). (2) A *value* error on an ignored flag: Go's message is pflag's
//!   (`invalid argument "foo" for "--strict-config" flag: strconv.ParseBool:
//!   …`), frp-rs's is bpaf's leftover-token message; both exit 1.
//!
//! Gated on `full` because the `frpc` bin carries
//! `required-features = ["full"]`, so without the gate this file would fail to
//! compile in the no-default-features lanes CI runs.
#![cfg(feature = "full")]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_frpc");
/// A child that legitimately connects exits well within this once it has tried
/// (login-fail-exit is on by default).
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a "must stay silent" canary keeps accepting after the child exited.
/// Any connection the child made is already in the accept queue by then.
const ORACLE_WINDOW: Duration = Duration::from_millis(300);

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same convention as the sibling CLI
/// tests: one unique directory per test, named from pid + counter).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frpc-pflags-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn file(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write file");
        path.to_str().expect("utf-8 temp path").to_string()
    }

    fn subdir(&self, name: &str) -> String {
        let path = self.0.join(name);
        std::fs::create_dir_all(&path).expect("create subdir");
        path.to_str().expect("utf-8 temp path").to_string()
    }

    /// Write a file inside a subdirectory (used to fill the ignored
    /// `--config-dir`: a config-dir-reading implementation would find it there).
    fn file_in(&self, sub: &str, name: &str, contents: &str) -> String {
        let dir = self.0.join(sub);
        std::fs::create_dir_all(&dir).expect("create subdir");
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write file");
        path.to_str().expect("utf-8 temp path").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A loopback listener that records every connection that reaches it. Each
/// connection is closed immediately, so a client sees EOF / a closed socket —
/// enough to prove *which port* it dialled, which is the only thing these tests
/// read from it.
struct Canary {
    port: u16,
    rx: mpsc::Receiver<()>,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

fn canary() -> Canary {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind canary");
    let port = listener.local_addr().expect("canary addr").port();
    listener.set_nonblocking(true).expect("canary non-blocking");
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = tx.send(());
                    drop(stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });
    Canary {
        port,
        rx,
        stop,
        handle,
    }
}

impl Canary {
    /// Collect `expected` connection reports, then stop the listener.
    fn collect(self, expected: usize, context: &str) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut hits = 0;
        while hits < expected {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.rx.recv_timeout(left).is_err() {
                break;
            }
            hits += 1;
        }
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("canary thread");
        assert_eq!(
            hits, expected,
            "{context}: expected {expected} connection(s) on canary port {}, saw {hits}",
            self.port
        );
        hits
    }

    /// The child reached this listener exactly `expected` times.
    fn assert_hits(self, expected: usize, context: &str) {
        self.collect(expected, context);
    }

    /// The child did **not** reach this listener.
    fn assert_silent(self) {
        let hit = self.rx.recv_timeout(ORACLE_WINDOW).is_ok();
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("canary thread");
        assert!(
            !hit,
            "unexpected connection reached canary port {}",
            self.port
        );
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return Some(status),
            None if Instant::now() >= deadline => return None,
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn run_frpc(args: &[&str]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frpc");
    if wait_with_timeout(&mut child, EXIT_TIMEOUT).is_none() {
        let _ = child.kill();
        let out = child.wait_with_output().expect("collect timed-out child");
        panic!(
            "frpc {args:?} did not exit within {EXIT_TIMEOUT:?}; stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    child.wait_with_output().expect("collect frpc output")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn exit_code(out: &Output) -> i32 {
    out.status.code().expect("child exited normally")
}

/// A client config pointing the admin API at `port` (the shape `status` needs).
fn config_with_web_server(port: u16) -> String {
    format!("serverAddr = \"127.0.0.1\"\nserverPort = 7500\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n")
}

/// The eight single-proxy commands with their own required flags, and nothing
/// else. `--server-port` is appended per test because it names the canary.
const SINGLE_PROXY_BASE: [(&str, &[&str]); 8] = [
    (
        "tcp",
        &[
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--proxy-name",
            "x",
        ],
    ),
    (
        "udp",
        &[
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--proxy-name",
            "x",
        ],
    ),
    (
        "http",
        &[
            "--local-port",
            "5",
            "--custom-domains",
            "example.com",
            "--proxy-name",
            "x",
        ],
    ),
    (
        "https",
        &[
            "--local-port",
            "5",
            "--custom-domains",
            "example.com",
            "--proxy-name",
            "x",
        ],
    ),
    ("stcp", &["--local-port", "5", "--sk", "s"]),
    ("xtcp", &["--local-port", "5", "--sk", "s"]),
    (
        "sudp",
        &[
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--proxy-name",
            "x",
        ],
    ),
    (
        "tcpmux",
        &["--local-port", "5", "--mux-port", "7", "--proxy-name", "x"],
    ),
];

fn argv_for(cmd: &str, base: &[&str], extra: &[&str]) -> Vec<String> {
    let mut argv = vec![cmd.to_string()];
    argv.extend(base.iter().map(|s| s.to_string()));
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv
}

fn as_refs(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

// ── the five persistent root flags are accepted and ignored ────────────────

/// Go v0.71.0, all eight commands: appending all five root flags (with a
/// missing config file and a missing config dir, so any read would be
/// observable) still starts the single proxy and dials `--server-port`. frp-rs
/// exited 1 with `` `-c` is not expected in this context`` before this change.
#[test]
fn every_single_proxy_command_ignores_all_five_persistent_root_flags() {
    for (cmd, base) in SINGLE_PROXY_BASE {
        let canary = canary();
        let port = canary.port.to_string();
        let extra = [
            "--server-port",
            port.as_str(),
            "-c",
            "missing.toml",
            "--config-dir",
            "no-such-dir",
            "--strict-config=false",
            "--allow-unsafe",
            "TokenSourceExec",
            "--version",
        ];
        let argv = argv_for(cmd, base, &extra);
        let out = run_frpc(&as_refs(&argv));
        let stderr = stderr_of(&out);
        assert!(
            !stderr.contains("not expected"),
            "{cmd} refused a persistent root flag: {stderr}"
        );
        assert_eq!(exit_code(&out), 1, "{cmd}: stdout={:?}", stdout_of(&out));
        canary.assert_hits(1, cmd);
    }
}

/// A repeated pflag flag is last-wins (scalars) or appending (`--allow-unsafe`)
/// and never an error — Go v0.71.0 starts the proxy with every pair below.
#[test]
fn repeated_persistent_root_flags_are_not_an_error() {
    let canary = canary();
    let port = canary.port.to_string();
    let extra = [
        "--server-port",
        port.as_str(),
        "-c",
        "a.toml",
        "-c",
        "b.toml",
        "--config-dir",
        "a",
        "--config-dir",
        "b",
        "--strict-config",
        "--strict-config=false",
        "--version",
        "--version",
        "--allow-unsafe",
        "a",
        "--allow-unsafe",
        "b",
    ];
    let argv = argv_for("tcp", SINGLE_PROXY_BASE[0].1, &extra);
    let out = run_frpc(&as_refs(&argv));
    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert!(
        !stderr_of(&out).contains("not expected"),
        "{}",
        stderr_of(&out)
    );
    canary.assert_hits(1, "repeated flags");
}

/// pflag consumes the token after `-c` as its value even when it looks like a
/// flag; bpaf cannot, so `parse_frpc_args` rewrites those occurrences into the
/// attached `-c=VALUE` spelling. Measured on Go v0.71.0:
/// `frpc status -c --strict-config=false -c <p7498>` dials p7498's port
/// (the later `-c` overwrites the dash-shaped value). Before this change
/// frp-rs exited 1 with ``-c` requires an argument `FILE``.
#[test]
fn a_dash_prefixed_value_after_c_is_the_config_value() {
    let dir = TempDir::new();
    let dialled = canary();
    let cfg = dir.file("p7498.toml", &config_with_web_server(dialled.port));
    let out = run_frpc(&["status", "-c", "--strict-config=false", "-c", &cfg]);
    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    assert!(
        !stderr_of(&out).contains("requires an argument"),
        "{}",
        stderr_of(&out)
    );
    dialled.assert_hits(1, "dash-prefixed -c value");

    // Alone, the dash-shaped value is a *path*: Go prints
    // `open --strict-config=false: no such file or directory`. frp-rs's message
    // shape differs (a recorded divergence) but it must be a read failure, not
    // a parse refusal, and nothing may be dialled.
    let silent = canary();
    let out = run_frpc(&["status", "-c", "--strict-config=false"]);
    assert_eq!(exit_code(&out), 1);
    let combined = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        combined.contains("--strict-config=false"),
        "the token is not treated as the config value: {combined}"
    );
    assert!(
        !combined.contains("not expected") && !combined.contains("requires an argument"),
        "still a parse refusal: {combined}"
    );
    silent.assert_silent();
}

// ── the admin subcommands accept the flags they did not declare ────────────

/// `status -c <cfg> --config-dir <dir>` must dial the `-c` config and never the
/// directory: Go v0.71.0 dials the `-c` port (measured: `Get
/// "http://127.0.0.1:17498/api/status"` with a second canary on the directory's
/// port left silent). Before this change frp-rs exited 1 with
/// `` `--config-dir` is not expected in this context``.
#[test]
fn config_dir_is_ignored_by_the_admin_subcommands() {
    let dir = TempDir::new();
    let dialled = canary();
    let not_dialled = canary();
    let cfg = dir.file("chosen.toml", &config_with_web_server(dialled.port));
    let config_dir = dir.subdir("cDir");
    dir.file_in(
        "cDir",
        "unused.toml",
        &config_with_web_server(not_dialled.port),
    );

    for cmd in ["status", "reload", "stop"] {
        let out = run_frpc(&[cmd, "-c", &cfg, "--config-dir", &config_dir]);
        assert_eq!(exit_code(&out), 1, "{cmd}: stdout={:?}", stdout_of(&out));
        assert!(
            !stderr_of(&out).contains("not expected"),
            "{cmd} refused --config-dir: {}",
            stderr_of(&out)
        );
    }
    // One connection per command, all to the `-c` config's port.
    dialled.assert_hits(3, "status/reload/stop with --config-dir");
    not_dialled.assert_silent();
}

/// `verify` reads the config, but `--config-dir`/`--allow-unsafe`/`--version`
/// are still accepted and ignored. Go v0.71.0: `frpc verify -c p7498.toml
/// --config-dir cDir` is rc 0 `syntax is ok`.
#[test]
fn verify_accepts_the_root_flags_it_ignores() {
    let dir = TempDir::new();
    let cfg = dir.file("good.toml", &config_with_web_server(17498));
    let out = run_frpc(&[
        "verify",
        "-c",
        &cfg,
        "--config-dir",
        "cDir",
        "--allow-unsafe",
        "TokenSourceExec",
        "--version",
    ]);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
}

// ── guard rails ────────────────────────────────────────────────────────────

/// The acceptance must not swallow the errors Go also raises: a dangling `-c`
/// is `flag needs an argument: 'c' in -c` there, and a non-bool
/// `--strict-config` value is pflag's `invalid argument` — in both cases the
/// proxy must not start.
#[test]
fn dangling_config_flag_and_bad_bool_value_still_fail() {
    let canary = canary();
    let port = canary.port.to_string();
    let base: Vec<&str> = {
        let mut v = vec!["tcp"];
        v.extend(SINGLE_PROXY_BASE[0].1.iter().copied());
        v.push("--server-port");
        v.push(&port);
        v
    };
    let mut dangling = base.clone();
    dangling.push("-c");
    let out = run_frpc(&dangling);
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr_of(&out).contains("`-c` requires an argument"),
        "stderr={:?}",
        stderr_of(&out)
    );

    let mut bad_bool = base.clone();
    bad_bool.push("--strict-config=foo");
    let out = run_frpc(&bad_bool);
    assert_eq!(exit_code(&out), 1);
    canary.assert_silent();
}

// ── recorded divergences ───────────────────────────────────────────────────

/// Positional arguments are **not** fixed by this item and stay divergent.
///
/// Measured on Go v0.71.0: `frpc status -c p7498.toml -- -c p7499.toml` dials
/// 7498 (everything after `--` is positional and ignored), `frpc status extra`
/// loads `./frpc.ini`, and `frpc tcp … extra` starts the proxy. frp-rs refuses
/// a leftover token with or without `--`. The rule Go follows here is "ignore
/// positional args", which is a different rule from "parse the persistent root
/// flags"; it is recorded in `docs/developing.md` § CLI inputs rather than
/// half-fixed, because accepting bare words would also swallow unknown flags
/// (`frpc tcp -c -- -foo` is `unknown shorthand flag: 'f' in -foo`, rc 1 on
/// Go).
#[test]
fn positional_arguments_are_still_refused() {
    let dir = TempDir::new();
    let dialled = canary();
    let cfg = dir.file("chosen.toml", &config_with_web_server(dialled.port));
    let out = run_frpc(&["status", "-c", &cfg, "--", "-c", "p7499.toml"]);
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr_of(&out).contains("is not expected in this context"),
        "stderr={:?}",
        stderr_of(&out)
    );

    let canary2 = canary();
    let port = canary2.port.to_string();
    let mut argv = argv_for("tcp", SINGLE_PROXY_BASE[0].1, &["--server-port", &port]);
    argv.push("extra".to_string());
    let out = run_frpc(&as_refs(&argv));
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr_of(&out).contains("is not expected in this context"),
        "stderr={:?}",
        stderr_of(&out)
    );
    canary2.assert_silent();
    dialled.assert_silent();
}
