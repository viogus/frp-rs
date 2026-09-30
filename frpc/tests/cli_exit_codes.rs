//! `frpc` CLI exit codes on the config-failure surface, pinned against Go frp
//! v0.71.0.
//!
//! Go's CLI is two-valued: 0 on success, 1 on any failure. Measured on Go
//! v0.71.0 (darwin/arm64) with one unknown top-level key added to an otherwise
//! valid client config, **stdout and stderr captured separately**:
//!
//! ```text
//! frpc -c bad.toml          → rc 1, stdout `json: unknown field "notAKnownFrpKey"`, stderr 0 bytes
//! frpc verify -c bad.toml   → rc 1, stdout `json: unknown field "notAKnownFrpKey"`, stderr 0 bytes
//! frpc verify -c good.toml  → rc 0, stdout `frpc: the configuration file … syntax is ok`
//! ```
//!
//! frp-rs exited **2** (`EXIT_CONFIG`) on the first two until the exit-code pin;
//! the admin subcommands (`reload`/`status`/`stop`) already exited 1 for the
//! same load error, which was the internal disagreement that closed. The last
//! test pins the one deliberate divergence: Go's `--config-dir` mode exits 0
//! even for a directory that does not exist, is empty, or holds a config that
//! fails to parse, and frp-rs keeps its non-zero refusal. See
//! `docs/developing.md` § CLI exit codes.
//!
//! **Stream and shape are pinned too** (the `TODO.md` item "A CLI failure's
//! output shape is still not Go's"). Both load-failure paths now write bare
//! line(s) to **stdout** and nothing to stderr, matching Go's
//! `fmt.Println(err)` / `os.Exit(1)` (`cmd/frpc/sub/root.go`,
//! `cmd/frpc/sub/verify.go`); before, the daemon start path wrapped the error in
//! an ANSI-coloured `tracing` record on stdout and `verify` wrote its message to
//! stderr. Two things are recorded, not matched, and this file's fixtures are
//! single-key so neither is visible here: the *text* (frp-rs appends
//! `in config file <path>` — and sometimes a `did you mean …?` suggestion —
//! where Go prints the codec's `json: unknown field "…"` with no path), and the
//! *line count* at N ≥ 2 (frp-rs prints one line per rejected key, Go stops at
//! the first; pinned at the collector by
//! `strict_check_reports_every_unknown_key_not_just_the_first` in
//! `frp-core/src/config/tests.rs`). The exact single-line frp-rs bytes are
//! asserted here so the shape cannot drift back silently.
//!
//! Two further tests pin the *extension* codes on the client:
//! `unresolvable_token_source_exits_3_where_go_exits_1` (`EXIT_AUTH`/3 — the same
//! input makes Go exit 1, see `docs/developing.md`) and
//! `malformed_store_file_exits_4_regardless_of_the_file_name` (`EXIT_BIND`/4,
//! the tag for any construction failure that is not an auth one). The second is
//! also the **flip control**: it runs one failure class under an `auth`-bearing
//! and an auth-free file name and requires the same code from both, so a
//! reversion to a text-based classifier fails it (see the test's own docs).
//!
//! Gated on `full`: the `frpc` bin carries `required-features = ["full"]`, so
//! without the gate this file's `CARGO_BIN_EXE_frpc` would fail to compile in
//! the no-default-features lanes CI runs. The `tiny` gate at the end is the
//! same pin for the `frpc-tiny` variant, which the `full` gate cannot cover.

#![cfg(any(feature = "full", feature = "tiny"))]

use std::path::PathBuf;
use std::process::{Child, Command, Output};
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
/// `Child::try_wait`, but the error path kills **and reaps** the child before
/// panicking, so that panic cannot orphan it. `try_wait` fails only on an OS
/// error — an already-reaped child is not an error, std caches its status — so
/// this is the "kill in the expect path" fix for the shape `TODO.md`'s
/// reload-guards item lists (`frpc/tests/cli_exit_codes.rs:96`). The timeout arm
/// below already kills before it panics.
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

fn run_frpc(args: &[&str]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn frpc");
    let deadline = std::time::Instant::now() + EXIT_TIMEOUT;
    loop {
        match try_wait_or_kill(&mut child, "frpc") {
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

/// Go: `frpc -c <bad>` → one bare parse error on **stdout**, exit 1
/// (`cmd/frpc/sub/root.go`: `fmt.Println(err); os.Exit(1)`). Measured on Go
/// v0.71.0 with the streams captured separately: stdout 38 bytes
/// (`json: unknown field "notAKnownFrpKey"`), stderr 0 bytes.
///
/// frp-rs now writes the same bare line to stdout, with stderr empty. It is
/// **one line per rejected key**, so this single-key fixture is the N=1 case;
/// the N ≥ 2 count is pinned at the collector
/// (`frp-core/src/config/tests.rs`), not here.
/// The line's **text** is frp-rs's own and stays divergent, deliberately: it
/// names the config file (`in config file <path>`) where Go's decoder error
/// carries no path, and it can add a `did you mean …?` suggestion. That split —
/// stream and shape matched, wording kept — is recorded in
/// `docs/developing.md` § CLI exit codes. Asserting the exact bytes means a
/// regression to a `tracing` record (ANSI, timestamp, level, target, the
/// duplicated `error=` field) fails here rather than silently.
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
    assert_eq!(
        stdout_of(&out),
        format!("{UNKNOWN_FIELD} in config file {cfg}\n"),
        "frpc -c <bad config> must print one bare line on stdout for this one-key \
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

/// Go: `frpc verify -c <bad>` → rc 1, the parse error on **stdout**
/// (`cmd/frpc/sub/verify.go`: `fmt.Println(err); os.Exit(1)`). Measured on Go
/// v0.71.0 with the streams captured separately: stdout 38 bytes
/// (`json: unknown field "notAKnownFrpKey"`), stderr 0 bytes.
///
/// frp-rs now writes its refusal to stdout too, with stderr empty. Before, this
/// path was the one place a config failure went to stderr while the exit code
/// already matched. The wording (`Config file <path> is invalid: …`) stays
/// divergent and is recorded in `docs/developing.md` § CLI exit codes.
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
    assert_eq!(
        stdout_of(&out),
        format!("Config file {cfg} is invalid: {UNKNOWN_FIELD} in config file {cfg}\n"),
        "frpc verify -c <bad config> must put its refusal on stdout, where Go's \
         `fmt.Println(err)` puts it; stderr={:?}",
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
    assert!(
        stdout_of(&out).starts_with(&format!("Config file {missing} is invalid: {missing}:")),
        "the refusal must be on stdout and must name the missing config file; stdout={:?} \
         stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go prints nothing on stderr for this failure; stderr={:?}",
        stderr_of(&out),
    );
}

/// Positive control: a valid config still verifies with rc 0, so the tests
/// above pin "bad config → 1" rather than "verify always fails".
///
/// Exact bytes, because the success sentence is now Go's
/// (`frpc: the configuration file <path> syntax is ok`,
/// `cmd/frpc/sub/verify.go:52`); the three indented summary lines after it are
/// the frp-rs addition kept for `frpc/tests/legacy_ini_fixture.rs`.
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
    assert_eq!(
        stdout_of(&out),
        format!(
            "frpc: the configuration file {cfg} syntax is ok\n  Server: 127.0.0.1:7000\n  \
             Proxies: 0\n  Visitors: 0\n"
        ),
        "the success line must be Go's exact sentence; stderr={:?}",
        stderr_of(&out),
    );
}

/// The `.ini` half of the same positive control: a **typeless** legacy proxy
/// section is Go's `tcp` proxy, in both loader modes.
///
/// Measured on the real v0.71.0 binaries: `.ini` files whose only section is a
/// typeless `[myproxy]` (with `local_port`/`remote_port`) give `frpc verify` rc 0
/// under both `--strict-config` values, a real frps run logs `new proxy [myproxy]
/// type [tcp] success` and a real frpc run logs `[myproxy] start proxy success`.
/// frp-rs used to print `Proxies: 0` in lenient mode (the
/// silent drop) and refuse the file in strict mode with `unknown field
/// "myproxy" in config file …`.
#[test]
fn typeless_legacy_ini_proxy_verifies_in_both_modes() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "typeless.ini",
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [myproxy]\nlocal_port = 18080\nremote_port = 18081\n\
         [auth.foo]\nlocal_port = 18082\nremote_port = 18083\n",
    );

    for strict in ["--strict-config=false", "--strict-config"] {
        let out = run_frpc(&["verify", strict, "-c", &cfg]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "frpc verify {strict} -c <typeless ini> must exit 0; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert_eq!(
            stdout_of(&out),
            format!(
                "frpc: the configuration file {cfg} syntax is ok\n  Server: 127.0.0.1:7000\n  \
                 Proxies: 2\n  Visitors: 0\n"
            ),
            "both typeless sections must register as proxies ({strict}); stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "verify writes nothing to stderr on success; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// A port-carrying typeless `role = "visitor"` section is **not** defaulted to a
/// `tcp` proxy: the exclusion clause of the typeless-`.ini` rule covers it.
///
/// The port-key discriminator cannot separate this shape from a typeless proxy
/// (`local_port`/`remote_port` are the keys it tests for), so without the
/// `role != "visitor"` clause the section would be collected and routed into
/// `[visitors]` with a synthetic `type = "tcp"`. Measured on this head: lenient
/// rc 0 with `Proxies: 0`/`Visitors: 0`, strict rc 1 with `unknown field "v"`.
/// Go v0.71.0 refuses the same file in *both* modes (`failed to parse visitor v,
/// err: type shouldn't be empty`) — the lenient half is the pre-existing
/// divergence tracked as TODO residue, pinned here as-is so the exclusion clause
/// itself cannot be mutated away silently.
///
/// **Mutation teeth.** Replacing the clause with `true` makes the lenient run
/// exit 1 with `visitor 'v': server name is required`, so the exit-code
/// assertion below fails before the stdout one is reached.
#[test]
fn typeless_port_carrying_ini_visitor_is_not_a_proxy() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "typeless_visitor.ini",
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [v]\nrole = \"visitor\"\nlocal_port = 1\nremote_port = 2\n",
    );

    let out = run_frpc(&["verify", "--strict-config=false", "-c", &cfg]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the typeless visitor section is not collected at all; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert_eq!(
        stdout_of(&out),
        format!(
            "frpc: the configuration file {cfg} syntax is ok\n  Server: 127.0.0.1:7000\n  \
             Proxies: 0\n  Visitors: 0\n"
        ),
        "a typeless visitor must register as neither a proxy nor a visitor; stderr={:?}",
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "verify writes nothing to stderr on success; stderr={:?}",
        stderr_of(&out),
    );

    let out = run_frpc(&["verify", "--strict-config", "-c", &cfg]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "strict mode refuses the uncollected section; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).contains("unknown field \"v\""),
        "the refusal must name the uncollected section; stdout={:?}",
        stdout_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "the refusal goes to stdout, Go-style; stderr={:?}",
        stderr_of(&out),
    );
}

/// A typeless **camelCase** `[webServer]` in a client `.ini` is frpc's admin
/// block, not a legacy proxy: `verify` must report `Proxies: 0`.
///
/// Regression pin for the phantom-proxy bug in the known-section filter of
/// `collect_legacy_ini_proxy_sections` — see
/// `frp-core/src/config/tests.rs::typeless_camelcase_web_server_ini_is_not_a_phantom_proxy`.
/// Measured on the commit that added the typeless `.ini` proxy default: this
/// file gave `Proxies: 1` (with the admin section dropped), where base
/// `b8e1dd6d` gave `Proxies: 0`.
#[test]
fn typeless_camelcase_web_server_ini_is_not_a_proxy() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "web_admin.ini",
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [webServer]\nport = 7500\n",
    );

    for strict in ["--strict-config=false", "--strict-config"] {
        let out = run_frpc(&["verify", strict, "-c", &cfg]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "frpc verify {strict} -c <[webServer] ini> must exit 0; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert_eq!(
            stdout_of(&out),
            format!(
                "frpc: the configuration file {cfg} syntax is ok\n  Server: 127.0.0.1:7000\n  \
                 Proxies: 0\n  Visitors: 0\n"
            ),
            "[webServer] must stay the admin block, not a proxy ({strict}); stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "verify writes nothing to stderr on success; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// A **typed** `.ini` section named after a camelCase v1 root is still Go's
/// legacy proxy — the mirror image of the phantom fix above, and the row a
/// reviewer blocked on.
///
/// `collect_legacy_ini_proxy_sections` reserves only the snake_case spellings of
/// the v1 roots; the camelCase headers are the ones the INI reader expands, so
/// reserving them dropped `[webServer] type = tcp` (and `[httpPlugins]` /
/// `[sshTunnelGateway]`) whole: lenient `Proxies: 0`, strict rc 1 `unknown field
/// "web_server.type"`. Measured with the final rule, one `.ini` holding all
/// three: rc 0 with `Proxies: 3` under both `--strict-config` values, matching
/// base971 (`971e0fa0`) exactly.
#[test]
fn typed_camelcase_v1_root_ini_sections_verify_as_proxies() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "camel_typed.ini",
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [webServer]\ntype = tcp\nlocal_port = 8080\nremote_port = 9080\n\
         [httpPlugins]\ntype = tcp\nports = 7000,7001\n\
         [sshTunnelGateway]\ntype = tcp\nports = 7000,7001\n",
    );

    for strict in ["--strict-config=false", "--strict-config"] {
        let out = run_frpc(&["verify", strict, "-c", &cfg]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "frpc verify {strict} -c <typed camelCase ini> must exit 0; stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert_eq!(
            stdout_of(&out),
            format!(
                "frpc: the configuration file {cfg} syntax is ok\n  Server: 127.0.0.1:7000\n  \
                 Proxies: 3\n  Visitors: 0\n"
            ),
            "all three typed camelCase roots must register as proxies ({strict}); stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "verify writes nothing to stderr on success; stderr={:?}",
            stderr_of(&out),
        );
    }
}

/// A bogus `type` on one of those sections is refused by frp-rs's own
/// proxy-type check, in both loader modes — never the silent `Proxies: 0` the
/// dropped-section cut produced.
///
/// Measured: `[webServer] type = "bogus"` with ports gives rc 1 under both
/// `--strict-config` values with `proxy 'webServer': invalid proxy_type
/// 'bogus'`, identical to base971 (`971e0fa0`); Go v0.71.0 refuses it as
/// `failed to parse proxy webServer, err: invalid type [bogus]`.
#[test]
fn bogus_type_on_a_camelcase_legacy_proxy_is_refused() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "camel_bogus.ini",
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [webServer]\ntype = bogus\nlocal_port = 8080\nremote_port = 9080\n",
    );

    for strict in ["--strict-config=false", "--strict-config"] {
        let out = run_frpc(&["verify", strict, "-c", &cfg]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "a bogus proxy type must be refused ({strict}); stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        assert!(
            stdout_of(&out).contains("proxy 'webServer': invalid proxy_type 'bogus'"),
            "the refusal must name the proxy and the type ({strict}); stdout={:?}",
            stdout_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "the refusal goes to stdout, Go-style; stderr={:?}",
            stderr_of(&out),
        );
    }
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
/// tag for any service-*construction* failure that is not an auth one. A
/// `[store] path` pointing at a file that is not JSON reaches it without any
/// port or token being involved.
///
/// Go frp v0.71.0 exits **1** on the identical config (`failed to create store
/// source: failed to load existing data: failed to parse JSON: …`), so this is
/// an frp-rs extension like 3.
///
/// **This test is the flip control.** It runs the *same* failure class twice,
/// changing only the store file's *name*: `authstore.json` (the name supplies an
/// `auth` substring) and `plainstore.json` (it supplies none). Both must exit 4.
/// Before the typed classification, `is_token_error`'s
/// `msg.contains("token") || msg.contains("auth")` matched the first name and
/// not the second, so the one failure class exited 3 or 4 depending on the file
/// name — measured on the base commit, and against Go both names exit 1. A
/// revert to any text-based classifier fails here on the `authstore.json` arm,
/// which is the whole point of the loop; neither store path contains the
/// substring `token`, so the *only* thing that can move the `authstore.json` arm
/// to 3 is a text match on `auth`.
#[test]
fn malformed_store_file_exits_4_regardless_of_the_file_name() {
    for name in ["authstore.json", "plainstore.json"] {
        let dir = TempDir::new();
        let store = dir.write(name, "this is not json\n");
        let cfg = dir.write(
            "badstore.toml",
            &format!("{BASE_CONFIG}[store]\npath = \"{store}\"\n"),
        );

        let out = run_frpc(&["-c", &cfg]);

        assert_eq!(
            out.status.code(),
            Some(4),
            "a malformed [store] file is the frp-rs EXIT_BIND/4 fallback whatever it is \
             called (Go exits 1 on both names); name={name} stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains(name),
            "the refusal must name the store file, got stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }
}

/// The client-side OIDC construction failure, pinned on **both sides of the pair
/// the text classifier disagreed about**: an `auth`-bearing issuer path
/// (`…/authz`) and auth-free ones (`…/zzz`, `…/plain`). Before the typed
/// classification `…/authz` exited **3** while `…/zzz` and `…/plain` exited **4**
/// for the identical failure — measured on the base commit — and all of them must
/// now be 3.
///
/// The three paths are chosen for exactly that reason. The auth-free two contain
/// neither `auth` nor `token`, so a text classifier scores them 4; `/authz`
/// contains `auth`, so the same classifier scores it 3. Asserting **only** the
/// auth-free pair would still pass under a text classifier whose polarity was
/// inverted, so the array carries the auth-bearing path too and the assertion is
/// the same for all three. The config directory is `TempDir`'s and never reaches
/// an assertion. A mutant that reinstates `to_string().contains("auth")` fails
/// this test on the auth-free arms (measured: `left: Some(4)`, `right: Some(3)`).
///
/// An `[auth] method = "oidc"` config with `clientID`/`clientSecret` set and
/// **no** `oidc.tokenEndpointURL` makes `OidcClient::new` fetch
/// `<issuer>/.well-known/openid-configuration` (`frp-core/src/auth.rs`);
/// pointing the issuer at a **closed** port fails that fetch, and the error text
/// embeds the full discovery URL.
///
/// Go frp v0.71.0 has no like-for-like code here: it has no `auth.oidc.issuer`
/// key on the client at all (measured, `json: unknown field "issuer"`, rc 1) — not
/// because the client starts. This is an frp-rs extension like the
/// store/`tokenSource` arms, not a Go comparison.
///
/// Gated on `full`: the `oidc` feature is not in `tiny`, so `frpc-tiny` cannot
/// reach `OidcClient::new` at all and the test would be wrong (not merely
/// skipped) there.
#[cfg(feature = "full")]
#[test]
fn oidc_construction_failure_exits_3_whatever_the_issuer_path() {
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l.local_addr().expect("local_addr").port();
        drop(l);
        p
    }

    for path in ["authz", "zzz", "plain"] {
        let dir = TempDir::new();
        let issuer = format!("http://127.0.0.1:{}/{}", closed_port(), path);
        let cfg = dir.write(
            "oidcc.toml",
            &format!(
                "{BASE_CONFIG}[auth]\nmethod = \"oidc\"\n\
                 [auth.oidc]\nissuer = \"{issuer}\"\naudience = \"x\"\n\
                 clientID = \"cid\"\nclientSecret = \"csec\"\n"
            ),
        );

        let out = run_frpc(&["-c", &cfg]);

        assert_eq!(
            out.status.code(),
            Some(3),
            "a client OIDC construction failure is InitErrorKind::Auth (3) for every \
             issuer path — /authz and an auth-free path must not differ; path={path} \
             issuer={issuer} stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains("openid-configuration"),
            "the failure must be the discovery fetch (not a config-validation refusal \
             before it), got stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out),
        );
    }
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

/// `frpc-tiny` includes `frpc/src/main.rs` verbatim, so the exit-code **and
/// output-shape** fixes have to hold in the no-default-features build too — and
/// the `full`-gated tests above cannot see it (the `frpc` bin is
/// `required-features = ["full"]`). CI's tiny lane runs this file for that
/// variant: the crate-level `#![cfg(any(feature = "full", feature = "tiny"))]`
/// is what makes the file compile there at all.
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
        assert_eq!(
            stdout_of(&out),
            format!("{UNKNOWN_FIELD} in config file {cfg}\n"),
            "frpc-tiny -c <bad config> must print one bare line on stdout for this \
             one-key fixture like the full binary and like Go (N >= 2 is N lines); \
             stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "Go prints nothing on stderr for this failure; stderr={:?}",
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
        assert_eq!(
            stdout_of(&out),
            format!("Config file {cfg} is invalid: {UNKNOWN_FIELD} in config file {cfg}\n"),
            "frpc-tiny verify must put its refusal on stdout, where Go's `fmt.Println(err)` \
             puts it; stderr={:?}",
            stderr_of(&out),
        );
        assert!(
            stderr_of(&out).is_empty(),
            "Go prints nothing on stderr for this failure; stderr={:?}",
            stderr_of(&out),
        );
    }
}

// ── `auth.method`: the one policy, at the client's two sites ─────────────────

/// Go frp v0.71.0's method set is `{"token", "oidc"}` compared **exactly**
/// (`pkg/config/v1/validation/client.go:101` via `SupportedAuthMethods`,
/// `validation/validation.go:37-40`) after `AuthClientConfig.Complete()` filled
/// an empty method to `token` (`pkg/config/v1/client.go:206-209`). Measured on
/// the real `frpc` v0.71.0 (darwin/arm64), own config and free port:
/// `method = "OIDC"` → **rc 1, 54 B stdout, 0 B stderr**, whole stdout
/// `invalid auth method, optional values are [token oidc]\n`; `method = ""`
/// starts.
///
/// **Sites 2 and 3** of the client: `refuse_oidc_method_without_feature` (the
/// check `frpc verify` shares with `frpc run`) and the construction parse in
/// `Service::with_unsafe_features`. Both used to compare `== "oidc"`, so
/// `"OIDC"` built a **token** client — against a server that (at the pre-change
/// head) lowercased the same spelling into OIDC. `verify` reported the config
/// **valid** (rc 0).
#[test]
fn verify_and_run_refuse_a_non_exact_auth_method_like_go() {
    let dir = TempDir::new();
    // `oidcClientID` is deliberately absent: with the old `!= "oidc"` early
    // return the OIDC client-credentials check was skipped for this spelling,
    // and `frpc verify` said "valid". The text below is what must win instead.
    let cfg = dir.write(
        "badmethod.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n\n[auth]\nmethod = \"OIDC\"\ntoken = \"t\"\n",
    );

    // `verify` (site 2 — the shared helper).
    let out = run_frpc(&["verify", "-c", &cfg]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "frpc verify must refuse an unrecognised auth.method (Go exits 1); \
         stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert_eq!(
        stdout_of(&out),
        format!(
            "Config file {cfg} is invalid: {cfg}: invalid auth method, optional values are [token oidc]\n"
        ),
        "verify's refusal must carry Go's text and frp-rs's path prefix, on stdout; \
         stderr={:?}",
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go prints nothing on stderr here; stderr={:?}",
        stderr_of(&out),
    );

    // `run` (site 3 — the construction parse). The load path refuses this too,
    // so the load error is what a CLI run reaches; the construction parse is
    // pinned ungated by
    // `frp-client`'s `construction_refuses_a_non_exact_auth_method`, and for a
    // config that never went through the loader that is the only check.
    let out = run_frpc(&["-c", &cfg]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "frpc run must not start on an unrecognised auth.method; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stdout_of(&out).ends_with("invalid auth method, optional values are [token oidc]\n"),
        "the run path's refusal must be Go's text; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        stderr_of(&out).is_empty(),
        "Go prints nothing on stderr here; stderr={:?}",
        stderr_of(&out),
    );
}

/// The other half of the client policy: an **empty** `auth.method` is Go's
/// `util.EmptyOr(c.Method, "token")` (`pkg/config/v1/client.go:206-209`), so it
/// must complete to `token` and must not be reported as an unrecognised method.
///
/// Measured on Go v0.71.0: `method = ""` starts (it then fails to reach a
/// listener, which is this fixture's state on both implementations), while
/// `"OIDC"`/`" oidc"`/`"tokenn"` never get that far. The assertions are
/// deliberately about *which* refusal appears, not about a started daemon: the
/// full binary's runtime exit code for a refused login is its own pinned
/// surface (`login_fail_exit`), and mixing it in would make this test pass for
/// the wrong reason.
#[test]
fn empty_auth_method_completes_to_token_on_both_client_paths() {
    let dir = TempDir::new();
    let cfg = dir.write(
        "emptymethod.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 1\nloginFailExit = false\n\n[auth]\nmethod = \"\"\ntoken = \"t\"\n",
    );

    // The loader completes the value it hands on.
    let loaded = frp_core::config::load_client_config(&cfg, true)
        .expect("an empty auth.method must load (empty → token)");
    assert_eq!(
        loaded.auth.as_ref().map(|a| a.method.as_str()),
        Some("token"),
        "the loader must hand on the completed value"
    );

    // And no path reports the method as unrecognised.
    // `verify` must accept it outright.
    let out = run_frpc(&["verify", "-c", &cfg]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "frpc verify must accept an empty method; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );

    // `run` must get PAST the method parse and reach the dial. It cannot be
    // driven to a clean exit — `loginFailExit = false` keeps retrying by
    // design — so the witness is its own progress line, read from a file while
    // the child is alive, and then the child is signalled and reaped.
    let log_path = dir.path("emptymethod.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child = Command::new(BIN)
        .args(["-c", &cfg])
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn frpc");
    let deadline = std::time::Instant::now() + EXIT_TIMEOUT;
    loop {
        let text = std::fs::read_to_string(&log_path).expect("read frpc log");
        if text.contains("connecting to") {
            break;
        }
        assert!(
            !text.contains("invalid auth method"),
            "a config whose method is empty must not be refused as an              unrecognised method; log={text:?}"
        );
        if let Some(status) = try_wait_or_kill(&mut child, "frpc") {
            panic!("frpc exited ({status:?}) on an empty auth.method; log={text:?}");
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("frpc never reached its dial on an empty auth.method; log={text:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
}
