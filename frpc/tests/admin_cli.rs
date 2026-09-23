//! `frpc reload` / `frpc status` / `frpc stop` admin-address resolution, pinned
//! against Go frp v0.71.0.
//!
//! Go's `NewAdminCommand` (`cmd/frpc/sub/admin.go:56-71`, tag `v0.71.0`):
//!
//! ```text
//! cfg, _, _, _, err := config.LoadClientConfig(cfgFile, strictConfigMode)
//! if err != nil { fmt.Println(err); os.Exit(1) }
//! if cfg.WebServer.Port <= 0 {
//!     fmt.Println("web server port should be set if you want to use this feature")
//!     os.Exit(1)
//! }
//! if err := handler(cfg); err != nil { fmt.Println(err); os.Exit(1) }
//! ```
//!
//! So Go always loads the config, refuses on a load error without contacting
//! anything, and refuses a port-less `[webServer]` with a fixed message — there
//! is no `127.0.0.1:7400` fallback in this path. These tests pin those two
//! refusals (message on **stdout**, exit 1) plus the frp-rs-only `--admin-*`
//! address override, which now applies only *after* a successful load.
//!
//! The refusal tests use a `TcpListener` oracle. Where a test writes the
//! listener's port into the bad config's `webServer.port`, it asserts the
//! connections that arrived after the child exited: **zero** for the two
//! load-error tests, the `--admin-port 0` override test and
//! `reload_bad_config_with_admin_flags_*`, and **one** for the two
//! `--strict-config=false` tolerance tests and the positive control
//! `reload_valid_config_port_is_used`. Three further tests bind a listener as a
//! canary but never write its port into any config — the two port-zero tests
//! and `reload_missing_config_file_*` (there is no config to write it into) —
//! so what pins those is the exact stdout (Go's port message, or the open
//! error) plus exit 1. The remaining four
//! (`reload_valid_config_connection_error_*`, `reload_admin_flags_override_*`
//! and `reload_lone_admin_{addr,port}_*`) use the fixed, never-listened ports
//! 1 and 2 and assert the connection error names the expected port.
//!
//! Gated on `full`: the `frpc` bin carries `required-features = ["full"]`, so
//! without the gate this file's `CARGO_BIN_EXE_frpc` would fail to compile in
//! the no-default-features lanes CI runs.
//!
//! The `stop` tests reuse those refusals — Go registers `stop` through the same
//! `NewAdminCommand` refusal body (`cmd/frpc/sub/admin.go:42`, `:56-71`) — and
//! add a one-shot mock admin server that answers a captured request, so they can
//! pin `POST /api/stop` with `Content-Length: 0` and no bytes after the request
//! head, `stop success` on stdout and exit 0 (Go's `StopHandler` sends no body
//! and prints its own `stop success`). A black-hole variant accepts a connection
//! and never responds, pinning `--api-timeout`: without the deadline the client
//! blocks in `read_to_end` forever (measured pre-fix against `frpc status`, no
//! exit in 8 s), so the test hangs into `run_frpc`'s failure rather than passing.
#![cfg(feature = "full")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_frpc");
/// Go's exact refusal for a `webServer.port` that is not > 0
/// (`cmd/frpc/sub/admin.go:63-66`).
const GO_NO_PORT_MSG: &str = "web server port should be set if you want to use this feature";
/// A valid client config with the given `[webServer]` block appended.
const BASE_CONFIG: &str = "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n";
/// Ports 1 and 2 are privileged and never handed out as ephemeral ports, so a
/// loopback connect to them is refused by the kernel with nothing listening.
/// Using them (instead of a bind-then-drop ephemeral port) keeps the
/// "connection error names this port" assertions free of port-reuse races
/// between parallel tests.
const REFUSED_PORT_A: u16 = 1;
const REFUSED_PORT_B: u16 = 2;
/// How long the post-exit oracle keeps accepting. The child has already exited,
/// so any connection it made is already in the accept queue; this only allows
/// for the handshake to complete.
const ORACLE_WINDOW: Duration = Duration::from_millis(300);
/// A child that refuses must exit well within this; if it does not, it is
/// sitting on a connection it should never have made.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself. No `tempfile` dev-dependency: one
/// unique directory per test, named from the process id and a counter.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frpc-admin-cli-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    /// Write a config file and return its path as a string for `-c`.
    fn config(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write config");
        path.to_str().expect("utf-8 temp path").to_string()
    }

    fn missing_path(&self, name: &str) -> String {
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

/// Bind an oracle listener on an ephemeral loopback port.
fn oracle_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind oracle listener");
    let port = listener.local_addr().expect("oracle addr").port();
    (listener, port)
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

/// Run the child to completion, collecting both streams. Panics if it does not
/// exit within `EXIT_TIMEOUT` — for a refusal case that means it opened a
/// connection and is waiting on a response, which is itself the failure.
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
            "frpc {args:?} did not exit within {EXIT_TIMEOUT:?} (a refusal must not connect); \
             stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    child.wait_with_output().expect("collect frpc output")
}

/// Count every connection that arrived at the oracle by the time the window
/// closes. Called after the child exited, so a connection it opened is already
/// queued by the kernel.
fn connections_after_exit(listener: &TcpListener) -> usize {
    listener.set_nonblocking(true).expect("oracle non-blocking");
    let deadline = Instant::now() + ORACLE_WINDOW;
    let mut count = 0;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => count += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("oracle accept failed: {e}"),
        }
    }
    count
}

/// Spawn the child and wait for it to connect to `listener`. Used for the cases
/// where connecting *is* the expected behaviour.
fn expect_one_connection(args: &[&str], listener: &TcpListener) -> Child {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frpc");
    listener.set_nonblocking(true).expect("oracle non-blocking");
    let deadline = Instant::now() + EXIT_TIMEOUT;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => return child,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("oracle accept failed: {e}"),
        }
    }
    let _ = child.kill();
    let out = child.wait_with_output().expect("collect child");
    panic!(
        "frpc {args:?} never connected to the expected port; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
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

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

// ── load error: propagated, on stdout, exit 1, nothing contacted ────────────

#[test]
fn reload_load_error_is_printed_on_stdout_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "bad.toml",
        &format!(
            "{BASE_CONFIG}notAKnownFrpKey = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    );

    let out = run_frpc(&["reload", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("unknown field \"notAKnownFrpKey\""),
        "load error must be printed on stdout, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        !stderr_of(&out).contains("connect"),
        "no connection may be attempted: stderr={:?}",
        stderr_of(&out),
    );
    assert_eq!(
        connections_after_exit(&listener),
        0,
        "load error must not connect to the config's webServer.port"
    );
}

#[test]
fn status_load_error_is_printed_on_stdout_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "bad.toml",
        &format!(
            "{BASE_CONFIG}notAKnownFrpKey = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    );

    let out = run_frpc(&["status", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("unknown field \"notAKnownFrpKey\""),
        "load error must be printed on stdout, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        !stderr_of(&out).contains("connect"),
        "no connection may be attempted: stderr={:?}",
        stderr_of(&out),
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

#[test]
fn reload_missing_config_file_is_printed_on_stdout_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, _port) = oracle_listener();
    let missing = dir.missing_path("nope.toml");

    let out = run_frpc(&["reload", "-c", &missing]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("nope.toml"),
        "the open error must name the file, got stdout={stdout:?}"
    );
    assert!(
        !stderr_of(&out).contains("connect"),
        "no connection may be attempted: stderr={:?}",
        stderr_of(&out),
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

// ── web_server.port == 0: Go's message, stdout, exit 1, nothing contacted ───

#[test]
fn reload_port_zero_prints_go_message_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, _port) = oracle_listener();
    // No [webServer] section at all: WebServerConfig::port defaults to 0.
    let cfg = dir.config("noweb.toml", BASE_CONFIG);

    let out = run_frpc(&["reload", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out).trim_end(),
        GO_NO_PORT_MSG,
        "Go prints this exact string on stdout (cmd/frpc/sub/admin.go:63-66)"
    );
    assert!(
        !stderr_of(&out).contains("connect"),
        "no connection may be attempted (pre-fix this was `connect 127.0.0.1:0`): stderr={:?}",
        stderr_of(&out),
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

#[test]
fn status_port_zero_prints_go_message_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, _port) = oracle_listener();
    let cfg = dir.config("noweb.toml", BASE_CONFIG);

    let out = run_frpc(&["status", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert_eq!(stdout_of(&out).trim_end(), GO_NO_PORT_MSG);
    assert!(
        !stderr_of(&out).contains("connect"),
        "stderr={:?}",
        stderr_of(&out)
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

/// The frp-rs `--admin-port 0` extension is refused with Go's message rather
/// than treated as "not supplied". The oracle is real here: the config names a
/// port we are listening on, so falling back to it would connect to us.
#[test]
fn reload_admin_port_zero_override_does_not_fall_back_to_the_config_port() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"),
    );

    let out = run_frpc(&[
        "reload",
        "--admin-addr",
        "127.0.0.1",
        "--admin-port",
        "0",
        "-c",
        &cfg,
    ]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out).trim_end(),
        GO_NO_PORT_MSG,
        "an explicit --admin-port 0 is a port-0 configuration and uses Go's message"
    );
    assert!(
        !stderr_of(&out).contains("connect"),
        "no connection may be attempted: stderr={:?}",
        stderr_of(&out),
    );
    assert_eq!(
        connections_after_exit(&listener),
        0,
        "--admin-port 0 must not silently fall back to webServer.port"
    );
}

// ── a valid config's port is used, and its connection error names it ────────

#[test]
fn reload_valid_config_port_is_used() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"),
    );

    let mut child = expect_one_connection(&["reload", "-c", &cfg], &listener);
    kill(&mut child);
}

#[test]
fn reload_valid_config_connection_error_names_the_config_port() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {REFUSED_PORT_A}\n"),
    );

    let out = run_frpc(&["reload", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1);
    // Pre-existing frp-rs message/stream for connection failures (stderr);
    // Go's equivalent is a `Get "http://…"` error on stdout. Unchanged here.
    assert!(
        stderr_of(&out).contains(&format!("connect 127.0.0.1:{REFUSED_PORT_A}")),
        "the config's port must be the one dialed, got stderr={:?}",
        stderr_of(&out),
    );
    assert!(stdout_of(&out).is_empty(), "stdout={:?}", stdout_of(&out));
}

// ── the --admin-* extension: address override after a successful load ───────

#[test]
fn reload_admin_flags_override_the_config_address_after_a_successful_load() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {REFUSED_PORT_A}\n"),
    );

    let out = run_frpc(&[
        "reload",
        "--admin-addr",
        "127.0.0.1",
        "--admin-port",
        &REFUSED_PORT_B.to_string(),
        "-c",
        &cfg,
    ]);

    assert_eq!(exit_code(&out), 1);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!("connect 127.0.0.1:{REFUSED_PORT_B}")),
        "the flag port must win, got stderr={stderr:?}"
    );
    assert!(
        !stderr.contains(&format!("127.0.0.1:{REFUSED_PORT_A}")),
        "the config port must not be dialed when both flags are given, got stderr={stderr:?}"
    );
}

/// The behaviour change this item makes: the flags can no longer paper over a
/// config that fails to load.
#[test]
fn reload_bad_config_with_admin_flags_still_reports_the_config_error() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "bad.toml",
        &format!(
            "{BASE_CONFIG}notAKnownFrpKey = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    );

    let out = run_frpc(&[
        "reload",
        "--admin-addr",
        "127.0.0.1",
        "--admin-port",
        &port.to_string(),
        "-c",
        &cfg,
    ]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("unknown field \"notAKnownFrpKey\""),
        "the config error must win over the flags, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

/// Priority 1 needs BOTH flags (pre-existing rule, unchanged): a lone
/// `--admin-addr` falls through to the config's address.
#[test]
fn reload_lone_admin_addr_falls_through_to_the_config() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {REFUSED_PORT_A}\n"),
    );

    let out = run_frpc(&["reload", "--admin-addr", "10.0.0.1", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr_of(&out).contains(&format!("connect 127.0.0.1:{REFUSED_PORT_A}")),
        "a lone --admin-addr must not override, got stderr={:?}",
        stderr_of(&out),
    );
}

/// …and a lone `--admin-port` likewise.
#[test]
fn reload_lone_admin_port_falls_through_to_the_config() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {REFUSED_PORT_A}\n"),
    );

    let out = run_frpc(&[
        "reload",
        "--admin-port",
        &REFUSED_PORT_B.to_string(),
        "-c",
        &cfg,
    ]);

    assert_eq!(exit_code(&out), 1);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!("connect 127.0.0.1:{REFUSED_PORT_A}")),
        "a lone --admin-port must not override, got stderr={stderr:?}"
    );
    assert!(
        !stderr.contains(&format!("127.0.0.1:{REFUSED_PORT_B}")),
        "got stderr={stderr:?}"
    );
}

// ── --strict-config is accepted by status too, and is passed to the load ────

#[test]
fn reload_strict_config_false_tolerates_an_unknown_key() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "badwithport.toml",
        &format!(
            "{BASE_CONFIG}notAKnownFrpKey = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    );

    let mut child =
        expect_one_connection(&["reload", "--strict-config=false", "-c", &cfg], &listener);
    kill(&mut child);
}

#[test]
fn status_strict_config_false_tolerates_an_unknown_key() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "badwithport.toml",
        &format!(
            "{BASE_CONFIG}notAKnownFrpKey = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    );

    // `status` lacked the flag entirely before this change (`Error:
    // `--strict-config` is not expected in this context`); Go accepts it as a
    // persistent rootCmd flag. The underscore spelling is accepted too.
    let mut child =
        expect_one_connection(&["status", "--strict_config=false", "-c", &cfg], &listener);
    kill(&mut child);
}

// ── frpc stop: POST /api/stop, empty body, `stop success` on 200 ────────────

/// Start a one-shot mock admin server: accept exactly one connection, record
/// every request byte up to the blank line that ends the head **and any bytes
/// that follow it**, then answer `status` + `body`. The receiver yields the
/// captured bytes.
///
/// The post-head read is what gives the "no body" assertion power. frpc writes
/// the whole request in one `write_all`, so any body bytes are already in the
/// socket buffer when the terminator is seen; a short read therefore returns
/// them immediately, while a client that sends no body only makes this read
/// wait out its 200 ms timeout.
fn mock_admin(
    status: &'static str,
    body: &'static str,
) -> (u16, mpsc::Receiver<Vec<u8>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock admin");
    let port = listener.local_addr().expect("mock admin addr").port();
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("mock admin accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("mock admin read timeout");
        let mut captured = Vec::new();
        let mut byte = [0u8; 1];
        while !captured.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => captured.push(byte[0]),
            }
        }
        // Anything after the terminator is a request body; a client that sends
        // none makes this read time out.
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("mock admin body read timeout");
        let mut rest = [0u8; 1024];
        if let Ok(n) = stream.read(&mut rest) {
            captured.extend_from_slice(&rest[..n]);
        }
        let _ = tx.send(captured);
        let response = format!(
            "{status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });
    (port, rx, handle)
}

/// Start a black-hole admin server: accept exactly one connection, drain
/// whatever the client sends, and then keep the socket open without ever
/// writing a byte. The final read blocks until the client closes, so a client
/// without its own deadline waits forever and this thread ends only when that
/// client gives up.
fn black_hole_admin() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind black hole");
    let port = listener.local_addr().expect("black-hole addr").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("black-hole accept");
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    (port, handle)
}

fn config_for_port(dir: &TempDir, port: u16) -> String {
    dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"),
    )
}

#[test]
fn stop_posts_api_stop_without_a_body_and_prints_stop_success() {
    let dir = TempDir::new();
    // The response body is deliberately *not* `stop success`: the CLI must
    // print its own fixed string, as Go's StopHandler does, so a regression
    // that echoes the daemon's body must fail here. The real Go daemon returns
    // an empty body anyway (measured: `Content-Length: 0`).
    let (port, request_rx, handle) = mock_admin("HTTP/1.1 200 OK", "IGNORED");
    let cfg = config_for_port(&dir, port);

    let out = run_frpc(&["stop", "-c", &cfg]);

    assert_eq!(
        exit_code(&out),
        0,
        "stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    // Untrimmed: `println!` writes exactly this, newline included.
    assert_eq!(stdout_of(&out), "stop success\n");
    assert!(stderr_of(&out).is_empty(), "stderr={:?}", stderr_of(&out));
    let captured = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock admin received a request");
    handle.join().expect("mock admin thread");
    // Measured on Go v0.71.0: `POST /api/stop HTTP/1.1`, `Content-Length: 0`,
    // and no bytes after the blank line that ends the head.
    let head = String::from_utf8_lossy(&captured).to_string();
    assert!(
        head.starts_with("POST /api/stop HTTP/1.1\r\n"),
        "head={head:?}"
    );
    assert!(head.contains("Content-Length: 0\r\n"), "head={head:?}");
    assert!(
        captured.ends_with(b"\r\n\r\n"),
        "no body may follow the head: {captured:?}"
    );
}

#[test]
fn stop_non_200_reports_the_status_and_exits_1() {
    // Go v0.71.0 measured against a 500 response: stdout `api status code
    // [500]`, exit 1, no `stop success`. frp-rs keeps its pre-existing
    // message/stream shape (`stop failed: …` on stderr, like reload/status);
    // the exit code and the absence of `stop success` are what must match.
    let dir = TempDir::new();
    let (port, _rx, _handle) = mock_admin("HTTP/1.1 500 Internal Server Error", "bad");
    let cfg = config_for_port(&dir, port);

    let out = run_frpc(&["stop", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1);
    assert!(stdout_of(&out).is_empty(), "stdout={:?}", stdout_of(&out));
    assert!(
        stderr_of(&out).contains("stop failed:"),
        "stderr={:?}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("500"),
        "stderr={:?}",
        stderr_of(&out)
    );
}

#[test]
fn stop_load_error_is_printed_on_stdout_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = dir.config(
        "bad.toml",
        &format!(
            "{BASE_CONFIG}notAKnownFrpKey = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    );

    let out = run_frpc(&["stop", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("unknown field \"notAKnownFrpKey\""),
        "load error must be printed on stdout, got stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out),
    );
    assert!(
        !stderr_of(&out).contains("connect"),
        "no connection may be attempted: stderr={:?}",
        stderr_of(&out),
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

#[test]
fn stop_port_zero_prints_go_message_and_no_connection_is_made() {
    let dir = TempDir::new();
    let (listener, _port) = oracle_listener();
    let cfg = dir.config("noweb.toml", BASE_CONFIG);

    let out = run_frpc(&["stop", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert_eq!(stdout_of(&out).trim_end(), GO_NO_PORT_MSG);
    assert!(
        !stderr_of(&out).contains("connect"),
        "stderr={:?}",
        stderr_of(&out)
    );
    assert_eq!(connections_after_exit(&listener), 0);
}

// ── --api-timeout: grammar rejection, deadline, positive control ────────────

#[test]
fn stop_bad_api_timeout_is_rejected_before_any_connection() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = config_for_port(&dir, port);

    let out = run_frpc(&["stop", "--api-timeout=1", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("missing unit in duration"),
        "stderr={:?}",
        stderr_of(&out)
    );
    assert!(stdout_of(&out).is_empty(), "stdout={:?}", stdout_of(&out));
    assert_eq!(
        connections_after_exit(&listener),
        0,
        "a rejected flag must not connect"
    );
}

/// frp-rs's placement rule (subcommand word first, unchanged by this work):
/// Go's cobra also accepts a root-level `frpc --api-timeout 1s stop …`
/// (measured on v0.71.0), which frp-rs refuses — a pre-existing divergence,
/// pinned here so it cannot silently change.
#[test]
fn api_timeout_before_the_subcommand_is_refused_and_does_not_connect() {
    let dir = TempDir::new();
    let (listener, port) = oracle_listener();
    let cfg = config_for_port(&dir, port);

    let out = run_frpc(&["--api-timeout=1s", "stop", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stderr={:?}", stderr_of(&out));
    assert_eq!(connections_after_exit(&listener), 0);
}

#[test]
fn api_timeout_zero_or_negative_is_a_timeout_not_a_connection_error() {
    // Go treats 0, 0s and -1s as an already-expired context — measured:
    // `context deadline exceeded` even with the admin port refused. The
    // deadline must therefore be checked before dialing, or the refused port
    // would win the race with `connect 127.0.0.1:1: Connection refused`.
    let dir = TempDir::new();
    let cfg = dir.config(
        "good.toml",
        &format!("{BASE_CONFIG}[webServer]\naddr = \"127.0.0.1\"\nport = {REFUSED_PORT_A}\n"),
    );

    for value in ["0", "0s", "-1s"] {
        let flag = format!("--api-timeout={value}");
        let out = run_frpc(&["stop", &flag, "-c", &cfg]);
        assert_eq!(exit_code(&out), 1, "{flag}");
        assert!(
            stderr_of(&out).contains("admin request timed out"),
            "{flag}: stderr={:?}",
            stderr_of(&out)
        );
        assert!(
            !stderr_of(&out).contains("connect"),
            "{flag}: a refused port must not win the race, stderr={:?}",
            stderr_of(&out)
        );
    }
}

#[test]
fn api_timeout_one_second_still_succeeds_against_a_responding_server() {
    // Positive control: the deadline must not break the happy path. The body
    // is again not `stop success`, so this also fails if the CLI echoes it.
    let dir = TempDir::new();
    let (port, _rx, _handle) = mock_admin("HTTP/1.1 200 OK", "IGNORED");
    let cfg = config_for_port(&dir, port);

    let out = run_frpc(&["stop", "--api-timeout=1s", "-c", &cfg]);

    assert_eq!(
        exit_code(&out),
        0,
        "stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert_eq!(stdout_of(&out), "stop success\n");
}

/// The discriminating timeout test: the listener accepts and holds the socket
/// open without ever responding, so the child can only exit by enforcing its
/// own deadline. Pre-fix (`with_admin_timeout` reduced to a bare call) this
/// hangs and `run_frpc` panics after `EXIT_TIMEOUT`.
#[test]
fn api_timeout_bounds_a_black_hole_admin_listener_for_each_subcommand() {
    for command in ["reload", "status", "stop"] {
        let dir = TempDir::new();
        let (port, _handle) = black_hole_admin();
        let cfg = config_for_port(&dir, port);

        let started = Instant::now();
        let out = run_frpc(&[command, "--api-timeout", "1s", "-c", &cfg]);
        let elapsed = started.elapsed();

        assert_eq!(exit_code(&out), 1, "{command}");
        assert!(
            stdout_of(&out).is_empty(),
            "{command}: stdout={:?}",
            stdout_of(&out)
        );
        assert!(
            stderr_of(&out).contains("admin request timed out after 1s"),
            "{command}: stderr={:?}",
            stderr_of(&out)
        );
        assert!(
            elapsed < EXIT_TIMEOUT,
            "{command}: took {elapsed:?}, the deadline must fire well inside {EXIT_TIMEOUT:?}"
        );
    }
}
