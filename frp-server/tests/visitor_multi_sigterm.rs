//! Regression pin: `frpc` must shut down cleanly on `SIGTERM` — rc **0** and no
//! `panicked at` in its output — when N >= 2 `stcp` visitors share one
//! `bind_port`, in both the explicit multi-visitor spelling and the legacy
//! `[range:...]` template with `role = visitor`.
//!
//! Measured before the fix (Rust frps + frpc, free ports, children reaped):
//! explicit-3 **3/3** and range-3 **3/3** panicked with
//! `fatal: panicked at tokio-1.53.1/src/runtime/task/core.rs:427: JoinHandle
//! polled after completion` and exited **101** (a crash on shutdown under the
//! release profile's `panic = "abort"`). Go frp v0.71.0 logs
//! `start error: listen tcp 127.0.0.1:<port>: bind: address already in use`
//! (`client/visitor/visitor_manager.go:132`) for the two losers and never
//! panics, so "one binds, the rest fail" is the intended shape and is asserted
//! here: a test that only checked the exit code would pass vacuously if the
//! shape ever stopped producing losers.
//!
//! Why the shape reaches the defect: the losers' `TcpListener::bind` fails, so
//! their listener task returns at once while the winner stays parked in
//! `accept()` past the 500 ms visitor grace window. `shutdown_visitor_tasks`
//! (`frp-client/src/service.rs`) awaited every `JoinHandle` a second time after
//! `join_all` had already driven the finished ones to `Ready`; tokio panics on
//! that second poll. The in-process unit pin for the same mechanism is
//! `frp-client/src/service/tests.rs`'s
//! `shutdown_visitor_tasks_tolerates_a_completed_handle`.
//!
//! These cases spawn the real binaries because the defect is an exit code and a
//! panic line on the process's stderr, not an in-process return value. The file
//! lives in `frp-server/tests/` because that is the only lane that builds both
//! `frps` and `frpc` and exports `FRPS_BIN`/`FRPC_BIN` (the same reason
//! `frp-server/tests/reload_integration.rs`, the other signal-driven frpc test,
//! lives here); `frp-client`'s test targets are also executed by the unit lane,
//! which builds neither binary.

mod common;

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::allocate_port;

/// Three visitors, as measured in the reproducer that found this: two must lose
/// the bind race, one must win it.
const VISITOR_COUNT: usize = 3;
const TOKEN: &str = "multi-visitor-sigterm-token";
/// The loser's bind error, without the errno suffix (macOS `os error 48`,
/// Linux `os error 98`); the message body is the pin, not the number.
const ADDR_IN_USE: &str = "Address already in use";
const PANIC_MARKER: &str = "panicked at";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// SIGTERM path: control teardown + the 500 ms visitor grace + task joins.
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolve a workspace binary the way `reload_integration.rs` does: `<NAME>_BIN`
/// (the server-integration lane exports `FRPS_BIN`/`FRPC_BIN`), then
/// `CARGO_BIN_EXE_<name>`, then `../<name>` (a downloaded release), then
/// `../target/{profile}/<name>` (built from source).
fn workspace_bin(name: &str) -> PathBuf {
    let env_key = format!("{}_BIN", name.to_uppercase().replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        let p = PathBuf::from(&path);
        if p.exists() {
            return p;
        }
    }
    let cargo_env_key = format!("CARGO_BIN_EXE_{}", name.to_uppercase().replace('-', "_"));
    if let Ok(path) = std::env::var(&cargo_env_key) {
        let p = PathBuf::from(&path);
        if p.exists() {
            return p;
        }
    }
    let local = PathBuf::from(format!("../{}", name));
    if local.is_file() {
        return local;
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root.join("target").join(profile).join(name)
}

/// A spawned child whose stdout **and** stderr go to one log file, with a
/// bounded wait and a `Drop` that kills and reaps it — so a failing assertion
/// can never leak a child that holds a bind port (the failure mode that has
/// produced false measurements in this series).
struct BoundedChild {
    child: Child,
    log_path: PathBuf,
}

impl BoundedChild {
    fn spawn(bin: &Path, config: &Path, log_path: PathBuf) -> Self {
        let log = std::fs::File::create(&log_path).expect("create child log file");
        let child = Command::new(bin)
            .arg("-c")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("clone log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));
        Self { child, log_path }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Poll `try_wait` until the child exits or `timeout` elapses. `None` means
    /// it is still running; `Drop` then reaps it.
    fn wait_bounded(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait().expect("child try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => return None,
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn output(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_port(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn frps_config(server_port: u16) -> String {
    format!(
        "bindPort = {server_port}\nauth.token = \"{TOKEN}\"\n\
         log.to = \"console\"\nlog.level = \"warn\"\n"
    )
}

fn common_section(server_port: u16) -> String {
    format!(
        "[common]\nserver_addr = 127.0.0.1\nserver_port = {server_port}\n\
         log_file = console\nlog_level = info\ntoken = {TOKEN}\n"
    )
}

fn visitor_section(name: &str, bind_port: u16) -> String {
    format!(
        "[{name}]\ntype = stcp\nrole = visitor\nserver_name = nope\nsk = abc\n\
         bind_addr = 127.0.0.1\nbind_port = {bind_port}\n"
    )
}

/// Explicit spelling: `VISITOR_COUNT` `[vN]` sections carrying the same
/// `bind_port`.
fn explicit_client_config(server_port: u16, bind_port: u16) -> String {
    let mut cfg = common_section(server_port);
    for i in 0..VISITOR_COUNT {
        cfg.push_str(&visitor_section(&format!("v{i}"), bind_port));
    }
    cfg
}

/// Legacy template spelling: one `[range:rv]` section with a single `bind_port`,
/// so the expanded visitors (`rv_0`..`rv_2`) share it. `local_port`/
/// `remote_port` are the range sources only — neither is ever bound (the probe
/// log shows all three expanded visitors binding `bind_port` and two of them
/// failing there), so fixed values are safe.
fn range_client_config(server_port: u16, bind_port: u16) -> String {
    let mut cfg = common_section(server_port);
    cfg.push_str(&format!(
        "[range:rv]\ntype = stcp\nrole = visitor\nserver_name = nope\nsk = abc\n\
         bind_addr = 127.0.0.1\nbind_port = {bind_port}\n\
         local_port = 6010-6012\nremote_port = 7010-7012\n"
    ));
    cfg
}

/// Ports the harness allocated for one case. `extra` is handed to the third
/// case only (a second, distinct visitor `bind_port`).
struct Ports {
    server: u16,
    bind: u16,
    extra: u16,
}

/// Two visitors with *distinct* `bind_port`s, one of them held by an external
/// listener, so exactly one visitor task completes at startup while the other
/// stays parked. This is the general precondition of the defect: it needs no
/// shared port, only "one visitor task finished before the grace window closed
/// while another was still parked".
fn held_port_client_config(server_port: u16, first: u16, held: u16) -> String {
    let mut cfg = common_section(server_port);
    cfg.push_str(&visitor_section("va", first));
    cfg.push_str(&visitor_section("vb", held));
    cfg
}

/// Start frps, start frpc with the config `make_client_config` builds from the
/// harness's own ports, wait until one visitor has bound `ports.bind`, send
/// SIGTERM, and assert a clean exit with `expect_losers` visitors having lost
/// the bind race. The ports are passed to the builder so the config can never
/// point somewhere other than the port frps actually bound (a bug that made an
/// earlier version of this test connect to a dead port). When `hold_extra` is
/// set, an external listener holds `ports.extra` for the duration.
fn assert_clean_sigterm(
    shape: &str,
    expect_losers: usize,
    hold_extra: bool,
    make_client_config: impl FnOnce(&Ports) -> String,
) {
    let ports = Ports {
        server: allocate_port(),
        bind: allocate_port(),
        extra: allocate_port(),
    };
    let dir = tempfile::TempDir::new().expect("scratch dir");

    let frps_cfg = dir.path().join("frps.toml");
    let frpc_cfg = dir.path().join(format!("frpc-{shape}.ini"));
    std::fs::write(&frps_cfg, frps_config(ports.server)).expect("write frps config");
    std::fs::write(&frpc_cfg, make_client_config(&ports)).expect("write frpc config");

    let frps = BoundedChild::spawn(
        &workspace_bin("frps"),
        &frps_cfg,
        dir.path().join("frps.log"),
    );
    let server_addr = SocketAddr::from(([127, 0, 0, 1], ports.server));
    assert!(
        wait_for_port(server_addr, STARTUP_TIMEOUT),
        "{shape}: frps never listened on {server_addr}; output:\n{}",
        frps.output()
    );

    // Held for the rest of the case, so the visitor that wants `ports.extra`
    // loses the bind race the way a second visitor on a shared port does.
    let _holder = hold_extra.then(|| {
        std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], ports.extra)))
            .unwrap_or_else(|e| panic!("{shape}: bind holder on {}: {e}", ports.extra))
    });

    let mut frpc = BoundedChild::spawn(
        &workspace_bin("frpc"),
        &frpc_cfg,
        dir.path().join("frpc.log"),
    );
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], ports.bind));
    assert!(
        wait_for_port(bind_addr, STARTUP_TIMEOUT),
        "{shape}: no visitor bound {bind_addr} within {STARTUP_TIMEOUT:?}\n\
         --- frpc log ---\n{}\n--- frps log ---\n{}",
        frpc.output(),
        frps.output()
    );

    let pid = frpc.pid();
    let kill = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("run kill -TERM");
    assert!(kill.success(), "{shape}: kill -TERM {pid} failed: {kill}");

    let status = frpc.wait_bounded(EXIT_TIMEOUT);
    let output = frpc.output();
    let status = status.unwrap_or_else(|| {
        panic!("{shape}: frpc did not exit within {EXIT_TIMEOUT:?} of SIGTERM; output:\n{output}")
    });

    assert!(
        !output.contains(PANIC_MARKER),
        "{shape}: frpc panicked on SIGTERM; output:\n{output}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "{shape}: frpc must exit 0 after SIGTERM, got {status:?}; output:\n{output}"
    );
    // One log line per losing visitor (the text also appears a second time in
    // each line's structured `error` field, so count lines, not substrings).
    let losers = output
        .lines()
        .filter(|line| line.contains(ADDR_IN_USE))
        .count();
    assert_eq!(
        losers, expect_losers,
        "{shape}: expected exactly {expect_losers} visitor(s) to lose the bind \
         race (the Go frp shape this regression needs); output:\n{output}"
    );
}

/// Explicit three-visitor spelling, one shared `bind_port`: measured 3/3 panics
/// (rc 101) before the fix.
#[test]
fn explicit_visitors_sharing_a_bind_port_exit_zero_on_sigterm() {
    assert_clean_sigterm("explicit", VISITOR_COUNT - 1, false, |p| {
        explicit_client_config(p.server, p.bind)
    });
}

/// Legacy `[range:...]` + `role = visitor` spelling, one shared `bind_port`:
/// measured 3/3 panics (rc 101) before the fix.
#[test]
fn range_template_visitors_sharing_a_bind_port_exit_zero_on_sigterm() {
    assert_clean_sigterm("range", VISITOR_COUNT - 1, false, |p| {
        range_client_config(p.server, p.bind)
    });
}

/// The general precondition, without a shared port: two visitors on distinct
/// `bind_port`s where one port is already held, so exactly one visitor task
/// finishes at startup. Measured 3/3 panics (rc 101) before the fix.
#[test]
fn distinct_bind_ports_with_one_held_exit_zero_on_sigterm() {
    assert_clean_sigterm("held-port", 1, true, |p| {
        held_port_client_config(p.server, p.bind, p.extra)
    });
}
