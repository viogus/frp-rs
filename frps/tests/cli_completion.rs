//! Bounded spawn tests for the **CLI-override completion order** of `frps`
//! (TODO.md "The rest of the server-side completion is not Go's").
//!
//! Two shapes, both measured against Go frp v0.71.0 as well as frp-rs:
//!
//! | argv / config | Go v0.71.0 | frp-rs before this file |
//! |---|---|---|
//! | `--dashboard-addr ""` (credentials set, `./frps.toml` with `[webServer] port`) | `dashboard listen on 127.0.0.1:<port>`, `TCP 127.0.0.1:<port> (LISTEN)` | `Dashboard web UI starting on :<port>` + `failed to lookup address information`; **nothing** listening |
//! | `--bind-addr ""` (`./frps.toml` with `bindPort`) | `frps tcp listen on 0.0.0.0:<port>`, `TCP *:<port> (LISTEN)` | `frps starting on :<port>` + `failed to lookup address information`, exits 1, binds nothing |
//!
//! The child's **own** bound-address report is the assertion, and the socket is
//! additionally proved live from outside with a real `TcpStream::connect` to
//! `127.0.0.1:<port>` (which is impossible while the child has exited — the
//! pre-fix shape of both rows). `lsof` was used for the measurements above; a
//! test asserting a third-party tool's output would be a probe of `lsof`, not
//! of `frps`, so the in-tree assertion stays on the address the server reports
//! at the point where it binds and on the socket being dialable.
//!
//! **Known limitation, stated rather than papered over.** The connect leg proves
//! liveness, not the address: on this platform both `0.0.0.0:<port>` and
//! `127.0.0.1:<port>` answer on loopback, so the wildcard-vs-loopback
//! distinction rests on the address string the listener logs **after** a
//! successful bind (`frp-server/src/service.rs` and `dashboard.rs` log it with
//! the value they bound). A socket-level discriminator does exist in this repo
//! for the sibling item — `frp-server/tests/dashboard_integration.rs`'s
//! `tcp_connect_ok` + `local_non_loopback_ipv4`, which dial the host's
//! non-loopback address and fail when the listener is loopback-only — and it was
//! deliberately **not** adopted here: it needs a non-loopback IPv4 on the host
//! (absent on some runners), it dials outside the loopback interface, and it
//! would make this file depend on the `frp-server` test module for a check whose
//! regression is "the string handed to `bind`". If that discrimination is ever
//! needed at socket level, that helper is the place to take it from.
//!
//! Bounded: every wait has a deadline, every child is killed and reaped by
//! [`ChildGuard::drop`] even on panic, and each test picks its own free ports.
//! Credentials are set in every dashboard shape: without them frp-rs's
//! no-auth force-bind rewrites any non-loopback dashboard address to
//! `127.0.0.1` (`frp-server/src/dashboard.rs`), which masks the bug — the
//! dashboard then looks Go-correct for the wrong reason.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_frps");
/// How long a shape may take from spawn to its listener line.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a killed child may take to disappear before SIGKILL.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);

/// The binary under test. `FRPS_BIN` (the same override
/// `frp-server/tests/common::frps_binary` resolves) lets the red evidence be
/// produced by pointing the file at a pre-fix build without rebuilding; it
/// defaults to this test's own `frps`.
fn bin() -> String {
    std::env::var("FRPS_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as
/// `frps/tests/cli_exit_codes.rs`: no `tempfile` dev-dependency here).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("frps-cli-completion-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    /// Write `./frps.toml` in the scratch dir — the path `frps` resolves when
    /// `-c` is absent (and the only shape in which CLI overrides apply:
    /// `FrpsArgs::cli_overrides_enabled`).
    fn write_default_config(&self, contents: &str) -> PathBuf {
        let path = self.0.join("frps.toml");
        std::fs::write(&path, contents).expect("write frps.toml");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free port, probed by binding and immediately releasing it. Same residual
/// race as `frps/tests/cli_exit_codes.rs::ephemeral_port` and
/// `frp-server/tests/common::allocate_port` (documented in TODO.md's
/// `allocate_port` addendum): the port came from the ephemeral range, so a
/// concurrent process can take it between the drop and the child's bind. Both
/// tests fail loudly in that case (the child exits and the ready line never
/// arrives, with the child's own stderr in the panic message) rather than
/// waiting out a longer timeout.
fn free_port() -> u16 {
    loop {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);
        // Guard against handing the same port to two tests in this process.
        if used_ports().lock().unwrap().insert(port) {
            return port;
        }
    }
}

fn used_ports() -> &'static std::sync::Mutex<std::collections::HashSet<u16>> {
    static USED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    USED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// Whether the resolved binary actually carries the dashboard.
///
/// `frps`'s `dashboard` feature is opt-in (`frps/Cargo.toml`), while this test
/// file is compiled by every `cargo test -p frps` invocation — including the
/// no-dashboard one. Rather than skip the dashboard shapes there, the test reads
/// one dashboard-only format string out of the binary and picks the shape's
/// no-dashboard equivalent, so the file is green in both configurations and its
/// assertions stay meaningful:
///
/// * dashboard present → the dashboard must bind the completed `127.0.0.1`;
/// * dashboard absent → `--dashboard-addr ""` must be inert (the dashboard is
///   not started at all) and, crucially, must **not** break the control
///   listener.
///
/// **What the no-dashboard arm does and does not prove.** It is a weaker check
/// than the dashboard arm: measured against a **true** pre-fix no-dashboard
/// binary, this file is **3 passed / 3 failed**:
///
/// ```text
/// # build it either way — plain default features, or tiny+full explicitly:
/// cargo build -p frps                       # no dashboard; no flag needed
/// cargo build -p frps --no-default-features --features full   # same dep graph
/// # NOT `cargo build -p frps --no-default-features` — that exits 0 but emits
/// # no target/debug/frps, because the bin is `required-features = ["full"]`.
/// FRPS_BIN=<that frps> cargo test -p frps --test cli_completion
/// ```
///
/// (Also note what that measurement is *not*: a dashboard binary run under a
/// no-dashboard *cargo* invocation still carries the dashboard listener, so it is
/// not a no-dashboard probe — a first draft of this note made exactly that
/// mistake and got 2 passed / 4 failed.)
///
/// The arm degenerates as follows: `cli_empty_dashboard_addr_binds_loopback`
/// **passes** pre-fix there, because with the dashboard compiled out there is no
/// empty address handed to a listener, so the arm reduces to "the control
/// listener still works". The dashboard regression itself is red only under
/// `--features dashboard` — against a
/// pre-fix dashboard binary the same six tests are **2 passed / 4 failed**, the
/// dashboard shape among the failures — which is why the CI step that runs this
/// file passes `--features dashboard`. The arm is kept rather than skipped
/// because "the flag is inert without the feature" is itself a behaviour worth
/// pinning, and because a silent skip would hide the file.
///
/// This is the same "does the binary carry the marker" check CI uses for the
/// artifact swap (`grep -ac "Dashboard listening on" target/debug/frps`, see
/// TODO.md's feature-swap item); it is a property of the file, not of the
/// process, so it costs one read per test.
fn dashboard_is_built_in() -> bool {
    /// A dashboard-only `tracing` format string (`frp-server/src/dashboard.rs`).
    const MARKER: &[u8] = b"Dashboard listening on";
    let path = bin();
    let Ok(bytes) = std::fs::read(&path) else {
        // Unreadable binary: let the spawn fail loudly rather than guess.
        return true;
    };
    bytes.windows(MARKER.len()).any(|window| window == MARKER)
}

/// Kills and reaps the child on every exit path, including a panicking
/// assertion — a leaked `frps` holds a port and has produced false
/// measurements in this repository.
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

/// A spawned `frps` whose stdout and stderr are drained by reader threads (so a
/// full pipe can never block the child), plus the scratch config dir that must
/// outlive it.
struct Spawned {
    _guard: ChildGuard,
    _dir: TempDir,
    stdout: std::sync::Arc<std::sync::Mutex<String>>,
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Spawned {
    /// Run `frps` with `argv` in a scratch dir holding `config` as
    /// `./frps.toml`.
    fn start(config: &str, argv: &[&str]) -> Self {
        let dir = TempDir::new();
        dir.write_default_config(config);

        let mut child = Command::new(bin())
            .args(argv)
            .current_dir(&dir.0)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn frps");

        let out = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let err = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
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

    /// Wait (bounded) for a line of the child's stdout, or panic with both
    /// streams so the failure names the child's own reason.
    fn wait_for_line(&self, needle: &str) -> String {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            {
                let log = self.stdout();
                if let Some(line) = log.lines().find(|l| l.contains(needle)) {
                    return line.to_string();
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "frps never logged a line containing {needle:?} within {READY_TIMEOUT:?}\n\
                     --- stdout ---\n{}\n--- stderr ---\n{}",
                    self.stdout(),
                    self.stderr(),
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Read a child's pipe to EOF on its own thread, appending into `sink`. Keeps a
/// full pipe from ever blocking the child, and lets a failing assertion print
/// whatever the child managed to say.
fn drain<R: Read + Send + 'static>(mut pipe: R, sink: std::sync::Arc<std::sync::Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    sink.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        }
    });
}

/// A loopback listener at `port` accepts a connection — an external proof that
/// the process is alive and bound there (the pre-fix shapes had no listener at
/// all, so this is the red/green witness, not a decoration).
fn assert_loopback_listens(port: u16) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "nothing accepted a TCP connection on 127.0.0.1:{port} within {READY_TIMEOUT:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn assert_streams_clean_of(tag: &str, spawned: &Spawned, needle: &str) {
    let combined = format!("{}{}", spawned.stdout(), spawned.stderr());
    assert!(
        !combined.contains(needle),
        "{tag}: output must not contain {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        spawned.stdout(),
        spawned.stderr(),
    );
}

/// `--dashboard-addr ""` must reach the dashboard as `127.0.0.1` (Go's
/// `WebServer.Complete()` fill), not as `:<port>`: the flag is applied before
/// `ServerConfig::complete`, exactly as Go applies its flags before
/// `ServerConfig.Complete()`.
#[test]
fn cli_empty_dashboard_addr_binds_loopback() {
    let bind_port = free_port();
    let dashboard_port = free_port();
    // Credentials are load-bearing: without them the no-auth force-bind
    // rewrites the dashboard to 127.0.0.1 anyway and masks the bug.
    let config = format!(
        "bind_addr = \"127.0.0.1\"\nbind_port = {bind_port}\n\n\
         [auth]\nmethod = \"token\"\ntoken = \"cli-completion-test\"\n\n\
         [web_server]\nport = {dashboard_port}\nuser = \"admin\"\npassword = \"adminpass\"\n"
    );

    let spawned = Spawned::start(
        &config,
        &[
            "--dashboard-addr",
            "",
            "--bind-port",
            &bind_port.to_string(),
        ],
    );

    if !dashboard_is_built_in() {
        // No-dashboard build: the flag must be inert and must not disturb the
        // control listener (the pre-fix defect left the process with no usable
        // listener at all). Readiness is the control listener's own line.
        let line = spawned.wait_for_line("frps listener started on");
        assert!(
            line.contains(&format!("127.0.0.1:{bind_port}")),
            "without the dashboard feature the configured bind_addr must still bind, got: {line}"
        );
        assert_streams_clean_of(
            "cli_empty_dashboard_addr_binds_loopback (no-dashboard build)",
            &spawned,
            "failed to lookup address information",
        );
        assert_loopback_listens(bind_port);
        return;
    }

    let line = spawned.wait_for_line("Dashboard listening on");
    assert!(
        line.contains(&format!("127.0.0.1:{dashboard_port}")),
        "dashboard must report the completed loopback address, got: {line}"
    );
    assert!(
        !line.contains(&format!(" :{dashboard_port}")),
        "the un-completed `:<port>` address must never reach the listener, got: {line}"
    );
    assert_streams_clean_of(
        "cli_empty_dashboard_addr_binds_loopback",
        &spawned,
        "failed to lookup address information",
    );
    // The socket is real: the control listener and the dashboard both accept.
    assert_loopback_listens(bind_port);
    assert_loopback_listens(dashboard_port);
}

/// The **absent-flag control**: with no `--dashboard-addr` at all, the value the
/// config file carries is what gets bound — a future change must not start
/// rewriting configured addresses.
#[test]
fn absent_dashboard_addr_flag_keeps_configured_value() {
    let bind_port = free_port();
    let dashboard_port = free_port();
    let config = format!(
        "bind_addr = \"127.0.0.1\"\nbind_port = {bind_port}\n\n\
         [auth]\nmethod = \"token\"\ntoken = \"cli-completion-test\"\n\n\
         [web_server]\naddr = \"127.0.0.1\"\nport = {dashboard_port}\n\
         user = \"admin\"\npassword = \"adminpass\"\n"
    );

    let spawned = Spawned::start(&config, &["--bind-port", &bind_port.to_string()]);

    if !dashboard_is_built_in() {
        // No-dashboard build: nothing to bind on the dashboard port; the
        // control listener is the observable, and it must keep the configured
        // address.
        let line = spawned.wait_for_line("frps listener started on");
        assert!(
            line.contains(&format!("127.0.0.1:{bind_port}")),
            "the configured bind_addr must survive an absent flag, got: {line}"
        );
        assert_loopback_listens(bind_port);
        return;
    }

    let line = spawned.wait_for_line("Dashboard listening on");
    assert!(
        line.contains(&format!("127.0.0.1:{dashboard_port}")),
        "the configured [web_server].addr must survive, got: {line}"
    );
    assert_loopback_listens(dashboard_port);
}

/// `--bind-addr ""` must be completed to `0.0.0.0` (Go `server.go:110`) and the
/// control listener must actually come up; before the fix the empty string
/// reached `TcpListener::bind` and the process exited 1 with nothing bound.
#[test]
fn cli_empty_bind_addr_binds_wildcard() {
    let bind_port = free_port();
    let config = format!(
        "bind_addr = \"127.0.0.1\"\nbind_port = {bind_port}\n\n\
         [auth]\nmethod = \"token\"\ntoken = \"cli-completion-test\"\n"
    );

    let spawned = Spawned::start(
        &config,
        &["--bind-addr", "", "--bind-port", &bind_port.to_string()],
    );

    let line = spawned.wait_for_line("frps listener started on");
    assert!(
        line.contains(&format!("0.0.0.0:{bind_port}")),
        "an empty --bind-addr must be completed to the wildcard, got: {line}"
    );
    assert_streams_clean_of(
        "cli_empty_bind_addr_binds_wildcard",
        &spawned,
        "failed to lookup address information",
    );
    assert_loopback_listens(bind_port);
}

/// `--bind-port 0` reaches the completion as 0 and must become the default
/// 7000, exactly like `bindPort = 0` in a file (`util.EmptyOr(BindPort, 7000)`,
/// Go `pkg/config/v1/server.go:111`). Before this change the CLI value was
/// written after `complete()`, so frp-rs bound an OS-chosen ephemeral port
/// where Go binds 7000.
///
/// Measured: Go v0.71.0 `--bind-port 0` (flags only) →
/// `create server listener error, listen tcp 0.0.0.0:7000: bind: address
/// already in use` (this host's Control Center holds 7000), i.e. Go tried
/// 7000; frp-rs (base `80199f4`, `./frps.toml` + `--bind-port 0`) logged
/// `frps starting on 127.0.0.1:0` and bound an ephemeral port.
///
/// This host's port 7000 is frequently occupied, so the assertion is on the
/// completed address in the listener line (emitted before the bind attempt) and
/// **not** on 7000 being dialable: either outcome — listening, or exiting with
/// `address already in use` — is only reachable after the port was completed.
/// The bind-port-zero completion itself is pinned by
/// `frp-core/src/config/tests.rs::test_server_bind_port_zero_maps_to_default_in_complete`.
#[test]
fn cli_bind_port_zero_is_completed_to_default() {
    let config = "bind_addr = \"127.0.0.1\"\nbind_port = 19845\n\n\
                  [auth]\nmethod = \"token\"\ntoken = \"cli-completion-test\"\n";

    let spawned = Spawned::start(config, &["--bind-port", "0"]);

    let line = spawned.wait_for_line("frps starting on");
    assert!(
        line.contains(":7000"),
        "an explicit --bind-port 0 must be completed to the default 7000, got: {line}"
    );
    assert!(
        !line.contains(":0 "),
        "the un-completed ephemeral port must never reach the listener, got: {line}"
    );
}

/// The **absent-flag control** for `bind_addr`: no `--bind-addr` means the
/// config's own value is what binds (here `127.0.0.1`, so the wildcard
/// completion must not fire).
#[test]
fn absent_bind_addr_flag_keeps_configured_value() {
    let bind_port = free_port();
    let config = format!(
        "bind_addr = \"127.0.0.1\"\nbind_port = {bind_port}\n\n\
         [auth]\nmethod = \"token\"\ntoken = \"cli-completion-test\"\n"
    );

    let spawned = Spawned::start(&config, &["--bind-port", &bind_port.to_string()]);

    let line = spawned.wait_for_line("frps listener started on");
    assert!(
        line.contains(&format!("127.0.0.1:{bind_port}")),
        "the configured bind_addr must survive an absent flag, got: {line}"
    );
    assert!(
        !line.contains(&format!("0.0.0.0:{bind_port}")),
        "an absent flag must not be completed to the wildcard, got: {line}"
    );
    assert_loopback_listens(bind_port);
}

/// The **`--config-dir` lane**: it never overlays CLI flags (Go parity — the
/// file is authoritative), so it still resolves through the completing
/// `load_server_config`, but the new `bind_addr` fill is observable in it.
/// Measured: with `bindAddr = ""` in the file, the pre-fix binary exits **0
/// with nothing bound** while logging the *same* `ERROR … failed to lookup
/// address information` shape the `-c` lane produces — the defect is the exit
/// code, not silence, and it is not "louder" on either lane. The fixed binary
/// binds `0.0.0.0:<port>`, which is what Go binds for the same file through its
/// `-c` lane (`frps` has no `--config-dir`: Go exits 1 with
/// `unknown flag: --config-dir`).
///
/// `--config-dir` collects every config file in a directory, so this test owns
/// a one-file directory and its own free port.
#[test]
fn config_dir_empty_bind_addr_binds_wildcard() {
    let bind_port = free_port();
    let dir = TempDir::new();
    let conf_dir = dir.0.join("conf.d");
    std::fs::create_dir_all(&conf_dir).expect("create config dir");
    std::fs::write(
        conf_dir.join("c1.toml"),
        format!(
            "bind_addr = \"\"\nbind_port = {bind_port}\n\n\
             [auth]\nmethod = \"token\"\ntoken = \"cli-completion-test\"\n"
        ),
    )
    .expect("write config");

    // Spawn by hand: `Spawned::start` writes `./frps.toml`, while this lane
    // takes its config from `--config-dir` and needs no cwd config at all.
    let mut child = Command::new(bin())
        .arg("--config-dir")
        .arg(&conf_dir)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frps");
    let out = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let err = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    drain(child.stdout.take().expect("child stdout"), out.clone());
    drain(child.stderr.take().expect("child stderr"), err.clone());
    let spawned = Spawned {
        _guard: ChildGuard { child },
        _dir: dir,
        stdout: out,
        stderr: err,
    };

    let line = spawned.wait_for_line("frps listener started on");
    assert!(
        line.contains(&format!("0.0.0.0:{bind_port}")),
        "an empty bind_addr from --config-dir must be completed to the wildcard, got: {line}"
    );
    assert_streams_clean_of(
        "config_dir_empty_bind_addr_binds_wildcard",
        &spawned,
        "failed to lookup address information",
    );
    assert_loopback_listens(bind_port);
}
