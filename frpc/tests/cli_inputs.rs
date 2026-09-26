//! The three `frpc` CLI/config inputs Go frp v0.71.0 accepts and frp-rs used to
//! reject (`TODO.md:1632`).
//!
//! Each test here runs the real `CARGO_BIN_EXE_frpc` against a one-shot
//! loopback mock admin server and asserts on the request the mock received —
//! which proves a connection reached that listener and carries the request line
//! and `Host:` header the command sent. The address *dialled* is pinned by the
//! combination of (a) a listener bound on `127.0.0.1` at an ephemeral port that
//! only the config under test names and (b) that `Host:` header; the mock's
//! `local_addr` is, strictly, its own address on the accepted socket (equal to
//! the listening port by construction), and the `peer.ip().is_loopback()`
//! assertions are tautological once a connection has arrived. The load-bearing
//! assertions are the wrong-listener-must-stay-silent ones and the reversed-order
//! negative control.
//!
//! The Go measurements these tests encode were reproduced against the official
//! `frp_0.71.0_darwin_arm64` binary with configs in `/private/tmp/goprobe/`:
//!
//! * **Repeated `-c` is last-wins.** Go registers `-c` with pflag `StringVarP`
//!   inside `func init()` (`cmd/frpc/sub/root.go`), so every occurrence
//!   overwrites the previous one.
//!   `frpc status -c noweb.toml -c p7499.toml` dials `127.0.0.1:7499`; the
//!   reverse order prints `web server port should be set if you want to use
//!   this feature` because the last config has no `[webServer]`. frp-rs's bpaf
//!   used to exit before loading with
//!   ``Error: argument `-c` cannot be used multiple times in this context``.
//! * **An empty `webServer.addr` is completed to `127.0.0.1`.** Go's
//!   `WebServerConfig.Complete()` is `c.Addr = util.EmptyOr(c.Addr, "127.0.0.1")`
//!   (`pkg/config/v1/common.go:71-72`), reached from
//!   `ClientCommonConfig.Complete()` (`pkg/config/v1/client.go:96`). frp-rs's
//!   serde default only fired when the key was absent, so an explicit `addr = ""`
//!   produced `connect :7499: failed to lookup address information …`.
//!
//! The third measured input — case-insensitive config keys — is still a
//! divergence, but its array-element arm is now **refused** rather than
//! silently dropped: `check_strict` recurses into the proxy/visitor/plugin
//! arrays with exact-match key sets. It is recorded in
//! `docs/developing.md` § CLI inputs with its measurement and scope. The
//! case-shaped tests in this file pin what a CLI can see (`rc`, `is valid`,
//! the `unknown field` lines); the **values** are asserted at the config layer,
//! because a future serde alias would keep a CLI-level test green while
//! honouring the key. Citation pairs (each verified against
//! the test that actually contains the assertion):
//!
//! * walked-section refusal — `test_strict_rejects_nested_unknown_keys`
//!   (`log.levell`, `auth.tokenz`) and, for the admin section,
//!   `strict_mode_rejects_unknown_proxy_and_visitor_array_elements`
//!   (`web_server.addrr`) and `test_strict_rejects_unknown_web_server_key`
//!   (`web_server.unknown_web_server_key`) in `frp-core/src/config/tests.rs`;
//! * array-element refusal, value included —
//!   `case_insensitive_proxy_array_key_is_refused_in_strict_mode`
//!   (strict `Err` naming `proxies[0].RemotePort`; non-strict still
//!   `remote_port == 0`) there;
//! * table-alias drop — `case_insensitive_key_in_a_table_alias_is_dropped_in_strict_mode`
//!   (`virtual_net.address == ""`) there.
//!
//! Gated on `full` for the same reason as `admin_cli.rs`: the `frpc` bin carries
//! `required-features = ["full"]`, so without the gate this file would fail to
//! compile in the no-default-features lanes CI runs.
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
/// Go's refusal for a `webServer.port` that is not > 0
/// (`cmd/frpc/sub/admin.go:63-66`).
const GO_NO_PORT_MSG: &str = "web server port should be set if you want to use this feature";
/// Ports 1 and 2 are privileged and never handed out as ephemeral ports, so a
/// loopback connect to them is refused by the kernel with nothing listening.
const REFUSED_PORT: u16 = 1;
/// A child that legitimately connects exits well within this once its mock
/// answers; a child that hangs is a failure, not a slow success.
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the "nothing arrived on the *first* config's port" oracle keeps
/// accepting after the child exited. Any connection the child made is already in
/// the accept queue by then; this only allows the handshake to complete.
const ORACLE_WINDOW: Duration = Duration::from_millis(300);

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same convention as `admin_cli.rs`:
/// one unique directory per test, named from pid + counter — no `tempfile`).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frpc-cli-inputs-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn config(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write config");
        path.to_str().expect("utf-8 temp path").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One captured admin request: the bytes the daemon would have seen.
struct Captured {
    /// The mock socket's **own** address for the accepted connection — i.e. the
    /// listening socket's address, which by construction is
    /// `127.0.0.1:<listening port>`. It is *not* the address frpc dialled in the
    /// sense of a separate observation: the evidence that frpc dialled this
    /// listener is that the connection arrived at all, plus the request's
    /// `Host:` header. Captured instead of `peer_addr()` because the peer's port
    /// is frpc's ephemeral **source** port, and the first version of this
    /// harness compared that against the listening port and failed by a few
    /// counts.
    local_addr: std::net::SocketAddr,
    /// The client's address as the kernel recorded it (frpc's ephemeral source
    /// port). Used only for `is_loopback()`, which is tautological once a
    /// connection has arrived.
    peer: std::net::SocketAddr,
    /// Everything up to and including the blank line that ends the head.
    head: String,
}

/// A one-shot mock admin server: bind on an ephemeral loopback port, answer the
/// first request with `status` and a `{}` body, and report the captured request.
fn mock_admin(status: &'static str) -> (u16, mpsc::Receiver<Captured>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock admin");
    let port = listener.local_addr().expect("mock admin addr").port();
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, peer) = listener.accept().expect("mock admin accept");
        let local_addr = stream.local_addr().expect("accepted socket local addr");
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
        let head = String::from_utf8_lossy(&captured).to_string();
        // Drain the request body the head announces. `reload` posts
        // `{"strictConfig":true}`; closing the socket with those bytes still in
        // flight reset the connection and frpc reported `read: Connection reset
        // by peer` (measured: `reload` failed where `status` passed, purely
        // because `status` has no body). A body read that times out is fine —
        // that is the `stop`/`status` no-body case, which the 200 ms timeout
        // covers.
        if let Some(len) = content_length(&captured) {
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .expect("mock admin body read timeout");
            let mut remaining = len;
            let mut buf = [0u8; 512];
            while remaining > 0 {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => remaining = remaining.saturating_sub(n),
                }
            }
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        // Write the response BEFORE handing the captured request to the test:
        // the test's next act is `child.wait_with_output()`, and the child is
        // blocked in `read_to_end`. Reporting first would let the child finish
        // and close while the mock was still writing.
        let body = "{}";
        let response = format!(
            "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        // Half-close so the client's `read_to_end` sees EOF immediately; the
        // full `Drop` happens after the send below.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = tx.send(Captured {
            local_addr,
            peer,
            head,
        });
    });
    (port, rx, handle)
}

/// `Content-Length` of the captured request head, if the header is present.
fn content_length(head: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(head);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse::<usize>().ok();
            }
        }
    }
    None
}

/// Collect the first request `mock_admin` captured, joining its thread.
fn captured_request(rx: mpsc::Receiver<Captured>, handle: JoinHandle<()>) -> Captured {
    let captured = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock admin received a request");
    handle.join().expect("mock admin thread");
    captured
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

/// Run the child to completion under `EXIT_TIMEOUT`, collecting both streams.
/// Panics if it does not exit — for these cases that means it is parked on a
/// connection it should not have open.
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

/// Count every connection that reached a canary listener by the time the window
/// closes. Called after the child exited, so any connection it opened is already
/// queued by the kernel.
fn connections_after_exit(listener: &TcpListener) -> usize {
    listener.set_nonblocking(true).expect("canary non-blocking");
    let deadline = Instant::now() + ORACLE_WINDOW;
    let mut count = 0;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => count += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("canary accept failed: {e}"),
        }
    }
    count
}

/// A canary listener that accepts and immediately closes: enough to prove
/// *which port* a single-proxy child dialled, since a closed socket makes the
/// child exit at once instead of waiting out its login retry. Same shape as the
/// helper in `cli_persistent_flags.rs`.
struct Canary {
    port: u16,
    rx: mpsc::Receiver<()>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: JoinHandle<()>,
}

fn canary() -> Canary {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
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
    /// The child reached this listener exactly `expected` times — no more, no
    /// fewer. The extra window matters: stopping the read at `expected` would
    /// let a child that dialled twice (or a second child) pass, so after the
    /// expected reports arrive the listener keeps accepting for
    /// [`ORACLE_WINDOW`] and any report in that window fails the assertion.
    fn assert_hits(self, expected: usize, context: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut hits = 0;
        while hits < expected {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.rx.recv_timeout(left).is_err() {
                break;
            }
            hits += 1;
        }
        let mut extras = 0;
        while self.rx.recv_timeout(ORACLE_WINDOW).is_ok() {
            extras += 1;
        }
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle.join().expect("canary thread");
        assert_eq!(
            hits, expected,
            "{context}: expected {expected} connection(s) on canary port {}, saw {hits}",
            self.port
        );
        assert_eq!(
            extras, 0,
            "{context}: {extras} unexpected extra connection(s) on canary port {}",
            self.port
        );
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// The child never reached this listener.
    fn assert_silent(self, context: &str) {
        let hit = self.rx.recv_timeout(ORACLE_WINDOW).is_ok();
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle.join().expect("canary thread");
        assert!(
            !hit,
            "{context}: unexpected connection reached canary port {}",
            self.port
        );
    }
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

/// Config with the given `[webServer]` body, client server target unused by the
/// admin commands.
fn config_with_web_server(port: u16, addr_line: &str) -> String {
    format!(
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n[webServer]\n{addr_line}port = {port}\n"
    )
}

// ── case 1: repeated `-c` is last-wins ──────────────────────────────────────

/// The two configs used by every repeated-`-c` test: the first has no
/// `[webServer]` at all (so using it can only produce Go's port refusal), the
/// second points the admin API at `mock_port`.
fn two_configs(dir: &TempDir, mock_port: u16) -> (String, String) {
    let first = dir.config(
        "first.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n",
    );
    let second = dir.config(
        "second.toml",
        &config_with_web_server(mock_port, "addr = \"127.0.0.1\"\n"),
    );
    (first, second)
}

#[test]
fn status_repeated_config_flag_is_last_wins() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, second) = two_configs(&dir, port);

    let out = run_frpc(&["status", "-c", &first, "-c", &second]);

    let captured = captured_request(rx, handle);
    assert_eq!(
        exit_code(&out),
        0,
        "stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert!(
        captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
        "the LAST -c config must be loaded and queried; head={:?}",
        captured.head
    );
    assert!(
        captured
            .head
            .contains(&format!("Host: 127.0.0.1:{port}\r\n")),
        "head={:?}",
        captured.head
    );
    assert_eq!(
        captured.local_addr.port(),
        port,
        "the dial must go to the second config's webServer.port"
    );
}

#[test]
fn reload_repeated_config_flag_is_last_wins() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, second) = two_configs(&dir, port);

    let out = run_frpc(&["reload", "-c", &first, "-c", &second]);

    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(
        captured.head.starts_with("POST /api/reload HTTP/1.1\r\n"),
        "head={:?}",
        captured.head
    );
    assert_eq!(captured.local_addr.port(), port);
}

#[test]
fn stop_repeated_config_flag_is_last_wins() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, second) = two_configs(&dir, port);

    let out = run_frpc(&["stop", "-c", &first, "-c", &second]);

    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(
        captured.head.starts_with("POST /api/stop HTTP/1.1\r\n"),
        "head={:?}",
        captured.head
    );
    assert_eq!(captured.local_addr.port(), port);
}

/// The `--config` long spelling is the same pflag variable as `-c`, so mixing
/// the forms is last-wins across both.
#[test]
fn status_mixed_short_and_long_config_flags_are_last_wins() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, second) = two_configs(&dir, port);

    let out = run_frpc(&["status", "--config", &first, "-c", &second]);

    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(
        captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
        "head={:?}",
        captured.head
    );
    assert_eq!(captured.local_addr.port(), port);
}

/// The negative control for the whole repeated-`-c` case: reversing the order
/// must load the *first* config, whose lack of `[webServer]` is Go's port
/// refusal — nothing is dialled and the mock never answers.
#[test]
fn status_repeated_config_flag_reversed_order_uses_the_last_one_too() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, second) = two_configs(&dir, port);

    let out = run_frpc(&["status", "-c", &second, "-c", &first]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    assert_eq!(
        stdout_of(&out).trim_end(),
        GO_NO_PORT_MSG,
        "the last config has no [webServer], so Go's refusal is what must print"
    );
    // The mock must never have been contacted, so nothing may have been sent.
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "the second-config mock must not be contacted when it is listed first"
    );
    // Deliberately no `handle.join()`: the mock thread is parked in `accept()`,
    // which returns only when a connection arrives — and the point of this test
    // is that none does. Joining would hang the test forever (it did: an earlier
    // revision of this harness hung here for 25 minutes). The thread ends with
    // the test binary, and its listener is dropped with it.
    drop(handle);
}

/// `frpc -c a -c b` (run mode) parses the last config and dials its
/// `serverAddr:serverPort`; the first config names a refused port instead. Go's
/// `-c` is a single pflag variable here too, so this is the same last-wins rule.
#[test]
fn run_mode_repeated_config_flag_is_last_wins() {
    let dir = TempDir::new();
    // First config points at a privileged, never-listened port; if run mode
    // loaded it, the login attempt would target port 1 and the stderr line
    // would name it.
    let first = dir.config(
        "first.toml",
        &format!("serverAddr = \"127.0.0.1\"\nserverPort = {REFUSED_PORT}\n"),
    );
    // Second config points at a refused port too (run mode cannot be allowed to
    // hang reconnecting), but names a distinctive one.
    let second = dir.config(
        "second.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 65001\n",
    );

    let out = run_frpc(&["-c", &first, "-c", &second]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains("127.0.0.1:65001"),
        "run mode must dial the LAST -c config's serverPort; output={all:?}"
    );
    assert!(
        !all.contains(&format!("127.0.0.1:{REFUSED_PORT}:")),
        "the first config's serverPort must not be dialled; output={all:?}"
    );
}

/// `verify` takes a required `-c`; a repeated one is last-wins there too, and
/// the printed filename proves which file was loaded.
#[test]
fn verify_repeated_config_flag_is_last_wins() {
    let dir = TempDir::new();
    let first = dir.config(
        "first.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n",
    );
    let second = dir.config(
        "second.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7501\n",
    );

    let out = run_frpc(&["verify", "-c", &first, "-c", &second]);

    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("Config file") && stdout.contains("second.toml is valid"),
        "the last -c must be the file verified; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("first.toml"),
        "the first -c must not be verified; stdout={stdout:?}"
    );
}

/// An absent `-c` must keep its old meaning: the admin subcommands still run
/// against the frp-rs default `127.0.0.1:7400`, which nothing listens on.
#[test]
fn status_without_config_flag_still_uses_the_7400_default() {
    let out = run_frpc(&["status"]);

    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr_of(&out).contains("127.0.0.1:7400"),
        "stderr={:?}",
        stderr_of(&out)
    );
}

/// Both pflag attached spellings of the short flag (`-cp7499.toml`,
/// `-c=p7499.toml`) name the same variable as the separated form and are
/// last-wins with it. Measured on Go v0.71.0: `frpc status -cp7498.toml` and
/// `frpc status -c=p7498.toml` both dial `127.0.0.1:7498`; bpaf accepts both
/// spellings too (same measurement on the frp-rs binary), so nothing had to be
/// changed for them — this test keeps it that way.
#[test]
fn status_attached_short_config_spellings_are_last_wins() {
    for spelling in ["-c", "-c="] {
        let dir = TempDir::new();
        let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
        let (first, second) = two_configs(&dir, port);
        // `-c<path>` / `-c=<path>` attached, with the mock-pointing config last.
        let attached = format!("{spelling}{second}");

        let out = run_frpc(&["status", "-c", &first, &attached]);

        let captured = captured_request(rx, handle);
        assert_eq!(
            exit_code(&out),
            0,
            "{spelling:?}: stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out)
        );
        assert!(
            captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
            "{spelling:?}: head={:?}",
            captured.head
        );
        assert_eq!(captured.local_addr.port(), port, "{spelling:?}");
    }
}

/// An empty `-c` value is a value, not a fallback: Go treats `-c ""` as "open
/// the file named `\"\"`" and fails at load (`open : no such file or
/// directory`, exit 1, nothing contacted). The last-wins parser must therefore
/// keep `Some("")` rather than treating a blank occurrence as absent and
/// dropping back to the `frp-rs` `127.0.0.1:7400` default.
///
/// The exact wording differs (`: failed to read config file: No such file or
/// directory` vs Go's `open : no such file or directory`) — a pre-existing
/// message/stream divergence recorded with the other CLI output-shape items in
/// `TODO.md`, not part of this item. What is pinned here is the *choice*: exit
/// 1 from a load failure, and no connection to the 7400 default.
#[test]
fn status_empty_config_value_is_read_as_a_path_not_a_fallback() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, _second) = two_configs(&dir, port);

    let out = run_frpc(&["status", "-c", &first, "-c", ""]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !all.contains("7400"),
        "an empty -c must not fall back to the default address; output={all:?}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the first config's mock must not be contacted"
    );
    drop(handle); // parked in `accept()`; see the reversed-order test.
}

/// A `-c` with no value is still a parse error (`.last()` must not turn the
/// argument into a switch).
#[test]
fn config_flag_without_a_value_is_still_an_error() {
    let out = run_frpc(&["status", "-c"]);

    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr_of(&out).contains("requires an argument"),
        "stderr={:?}",
        stderr_of(&out)
    );
}

/// A *dangling* last occurrence (`-c good.toml -c`) is an error, not an
/// instruction to reuse the previous value. Measured on Go v0.71.0:
/// `frpc status -c p7498.toml -c` →
/// `Error: flag needs an argument: 'c' in -c`, exit 1, nothing dialled.
#[test]
fn dangling_last_config_flag_is_an_error_not_a_reuse() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let (first, _second) = two_configs(&dir, port);

    let out = run_frpc(&["status", "-c", &first, "-c"]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    assert!(
        stderr_of(&out).contains("requires an argument"),
        "stderr={:?}",
        stderr_of(&out)
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "nothing may be dialled for a dangling flag"
    );
    drop(handle); // parked in `accept()`; see the reversed-order test.
}

// ── case 3: an empty `webServer.addr` is completed to 127.0.0.1 ─────────────

/// Go fills an empty `[webServer] addr` with `127.0.0.1`
/// (`WebServerConfig.Complete()`, `pkg/config/v1/common.go:71-72`, reached from
/// `pkg/config/v1/client.go:96`). The proof is the dial: a listener bound on
/// `127.0.0.1` sees the request, and the peer/`Host` name loopback.
#[test]
fn status_with_empty_web_server_addr_dials_loopback() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = dir.config(
        "emptyaddr.toml",
        &config_with_web_server(port, "addr = \"\"\n"),
    );

    let out = run_frpc(&["status", "-c", &cfg]);

    let captured = captured_request(rx, handle);
    assert_eq!(
        exit_code(&out),
        0,
        "stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert!(
        captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
        "head={:?}",
        captured.head
    );
    assert_eq!(
        captured.local_addr.ip().to_string(),
        "127.0.0.1",
        "an empty addr must complete to loopback, not to the empty host"
    );
    assert!(
        captured.peer.ip().is_loopback(),
        "destination frpc dialled must be loopback: {:?}",
        captured.peer
    );
    assert_eq!(captured.local_addr.port(), port);
    assert!(
        captured
            .head
            .contains(&format!("Host: 127.0.0.1:{port}\r\n")),
        "head={:?}",
        captured.head
    );
}

/// `reload` and `stop` resolve the same address from the same config, so an
/// empty `addr` must complete there too. One test per command keeps the failure
/// message pointing at the command that broke.
#[test]
fn reload_with_empty_web_server_addr_dials_loopback() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = dir.config(
        "emptyaddr.toml",
        &config_with_web_server(port, "addr = \"\"\n"),
    );

    let out = run_frpc(&["reload", "-c", &cfg]);

    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert_eq!(captured.local_addr.ip().to_string(), "127.0.0.1");
    assert_eq!(captured.local_addr.port(), port);
    assert!(captured.peer.ip().is_loopback());
}

#[test]
fn stop_with_empty_web_server_addr_dials_loopback() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = dir.config(
        "emptyaddr.toml",
        &config_with_web_server(port, "addr = \"\"\n"),
    );

    let out = run_frpc(&["stop", "-c", &cfg]);

    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert_eq!(captured.local_addr.ip().to_string(), "127.0.0.1");
    assert_eq!(captured.local_addr.port(), port);
    assert!(captured.peer.ip().is_loopback());
}

/// The completion of case 3 fills **only** the empty string. Go measured on
/// v0.71.0: `addr = " "` is passed through verbatim and fails in the dialer
/// (`parse "http:// :7499/api/status": invalid character " " in host name`),
/// `"0.0.0.0"` is used literally, `"::1"` is bracketed to `[::1]:7499`, and
/// `"localhost"` resolves to `[::1]:7499` through the dialer. None of those may
/// be trimmed or rewritten by the completion.
///
/// The whitespace shape is the guard against an over-eager implementation: a
/// `trim()` (or a `trim().is_empty()`) would silently turn `" "` into
/// `127.0.0.1` and dial the mock, which this test would catch as `exit 0` plus
/// an arrived connection.
#[test]
fn status_with_whitespace_web_server_addr_is_not_completed_or_trimmed() {
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = dir.config(
        "spaceaddr.toml",
        &config_with_web_server(port, "addr = \" \"\n"),
    );

    let out = run_frpc(&["status", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    assert!(
        stderr_of(&out).contains(&format!(":{port}")),
        "the failure must be about the whitespace host, not a request: stderr={:?}",
        stderr_of(&out)
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a whitespace addr must not be completed to loopback and dialled"
    );
    drop(handle); // parked in `accept()`; see the reversed-order test.
}

/// The no-`[webServer]` config is the case that is **already** aligned: Go
/// refuses with its fixed sentence and contacts nothing. Pinned here so the
/// `addr` completion above cannot silently start treating "no section" as
/// "empty addr" and dialing loopback.
#[test]
fn status_without_web_server_section_still_refuses() {
    let dir = TempDir::new();
    let (listener, _port) = {
        let l = TcpListener::bind("127.0.0.1:0").expect("canary");
        let p = l.local_addr().expect("canary addr").port();
        (l, p)
    };
    let cfg = dir.config(
        "noweb.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n",
    );

    let out = run_frpc(&["status", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    assert_eq!(stdout_of(&out).trim_end(), GO_NO_PORT_MSG);
    assert_eq!(connections_after_exit(&listener), 0);
}

// ── case 2: case-insensitive keys — the shipped behaviour, pinned ───────────

/// A mis-cased key **inside `[[proxies]]`** is now refused in strict mode:
/// `check_strict` recurses into the array with its exact-match key set
/// (`PROXY_KNOWN_KEYS` in `frp-core/src/config/strict.rs`), so
/// `LocalPort`/`RemotePort` each produce an `unknown field "proxies[0].…"` line
/// and `frpc verify` exits **1**. Go accepts the same file (`frpc verify -c`
/// exits 0, measured) because its `encoding/json` decoder matches object keys
/// case-insensitively, so this is stricter than Go — but it replaces a silent
/// config loss, and the exact
/// same refusal already applied to a mis-cased key in a walked section or at
/// the top level. The **values** are asserted at the config layer by
/// `case_insensitive_proxy_array_key_is_refused_in_strict_mode` in
/// `frp-core/src/config/tests.rs`, which also pins that *non*-strict mode still
/// drops the key (`remote_port == 0`).
#[test]
fn case_insensitive_proxy_array_keys_are_refused_in_strict_mode() {
    let dir = TempDir::new();
    // The capital `L`/`R` on `LocalPort`/`RemotePort` are the Go-accepted
    // spellings; `name`/`type` are lowercase so the element still parses.
    let cfg = dir.config(
        "cap-proxy.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n\
         [[proxies]]\nname = \"t\"\ntype = \"tcp\"\nLocalPort = 7198\nRemotePort = 7198\n",
    );

    // Strict is the default (and Go's); no `--strict-config=false` here.
    let out = run_frpc(&["verify", "-c", &cfg]);

    assert_eq!(
        exit_code(&out),
        1,
        "strict mode must refuse the mis-cased element keys; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    // Both keys are reported, with the element index in the path and a
    // suggestion (each is one edit away from the alias serde does know).
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    for expected in [
        "unknown field \"proxies[0].LocalPort\"",
        "unknown field \"proxies[0].RemotePort\"",
    ] {
        assert!(all.contains(expected), "expected {expected:?} in: {all:?}");
    }

    // Non-strict mode keeps the lenient contract: rc 0, the keys dropped, no
    // diagnostic. That is what the earlier version of this test pinned.
    let out = run_frpc(&["verify", "--strict-config=false", "-c", &cfg]);
    assert_eq!(
        exit_code(&out),
        0,
        "non-strict mode must still load the file; stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert!(
        stdout_of(&out).contains("is valid"),
        "stdout={:?}",
        stdout_of(&out)
    );
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !all.contains("unknown field"),
        "non-strict mode drops the keys silently: {all:?}"
    );
}

/// The walked sections refuse in strict mode with the same sentence shape as
/// the array test above — the array recursion did not create a new class of
/// refusal. `webServer.Port` rather than the camel-case alias `port` is the
/// Go-accepted spelling.
#[test]
fn case_insensitive_key_in_a_walked_section_is_refused_in_strict_mode() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "cap-web.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n[webServer]\nPort = 7499\n",
    );

    let out = run_frpc(&["verify", "-c", &cfg]);

    assert_eq!(exit_code(&out), 1, "stdout={:?}", stdout_of(&out));
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        all.contains("unknown field \"web_server.Port\""),
        "the walked section must still refuse the mis-cased key: {all:?}"
    );
    // Non-strict drops the key instead and the refusal changes shape: the load
    // succeeds and the next error is about the missing port, not the bad key.
    let out = run_frpc(&["verify", "--strict-config=false", "-c", &cfg]);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("is valid"),
        "stdout={:?}",
        stdout_of(&out)
    );
}

// ── `--strict-config`: every spelling, pinned at the rc level ───────────────
//
// `verify` carries the whole matrix without a listener: a strict load of an
// unknown top-level key exits 1 with the unknown-field line, a lenient one
// exits 0 with `is valid`. That is what makes the two forms distinguishable
// here — the difference is *which config load happened*, not only an exit code.
//
// Every row also pins the **warning** (`frp_core::cli::STRICT_CONFIG_SPACE_FORM_WARNING`,
// whose exact text is pinned by a unit test in `frp-core/src/cli.rs`): the
// frp-rs space-separated extension prints exactly one stderr line and nothing
// else does, so the divergence cannot bite silently.
//
// The Go v0.71.0 rows this encodes (measured on the official darwin/arm64
// binary) and where frp-rs diverges:
//
// | argv | Go v0.71.0 | frp-rs |
// |---|---|---|
// | absent / bare / `=true` | strict, rc 1 (`json: unknown field …`) | strict, rc 1, silent |
// | `--strict-config=false` | lenient, rc 0 (`syntax is ok`) | lenient, rc 0, silent |
// | `--strict-config false` | strict, rc 1 (token is a positional) | lenient, rc 0 — **extension**, warns |
// | `--strict-config=foo` | rc 1, pflag `invalid argument … strconv.ParseBool` | rc 1, `` `foo` is not expected ``, silent |
// | `--strict-config foo` | rc 1 unknown field (token ignored, config still loaded) | rc 1, `` `foo` is not expected ``, silent |
// | `--strict-config=` | rc 1 `invalid argument "" … ParseBool` | rc 1, `` `` is not expected ``, silent |
// | `--strict-config ""` | rc 1 unknown field here (rc **0** with a valid config: the empty token is a positional) | rc 1, `` `` is not expected ``, silent |
// | `=true =false` (repeated) | rc 0 — pflag is last-wins, so lenient | rc 1 `cannot be used multiple times`, silent |
// | `=false =true` (repeated) | rc 1 unknown field (last-wins → strict) | rc 1, same refusal, silent |
// | `-c bad --strict-config false` | rc 1 unknown field (position does not matter) | rc 0 `is valid` — **extension**, warns |
//
// The full table (including `run`/`reload`/`status`/`stop`/`frps`), the measured
// drop branch and the reason the space form is kept are in
// `docs/developing.md` § "`--strict-config`: the space-separated value form".
#[test]
fn verify_strict_config_spellings_match_their_measured_rows() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "bad.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\nnotAKnownFrpKey = 1\n",
    );
    let warning = frp_core::cli::STRICT_CONFIG_SPACE_FORM_WARNING;

    // Go-faithful rows: absent, bare (both spellings) and `=true` are strict and
    // must not warn.
    for args in [
        &["verify", "-c", &cfg][..],
        &["verify", "--strict-config", "-c", &cfg][..],
        &["verify", "--strict_config", "-c", &cfg][..],
        &["verify", "--strict-config=true", "-c", &cfg][..],
        &["verify", "--strict_config=true", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 1, "{args:?} stderr={:?}", stderr_of(&out));
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains("unknown field \"notAKnownFrpKey\""),
            "{args:?}: {all:?}"
        );
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} is Go-faithful and must stay silent: stderr={:?}",
            stderr_of(&out)
        );
    }

    // Go-faithful row: the adjacent `=false` spelling is lenient on both.
    for args in [
        &["verify", "--strict-config=false", "-c", &cfg][..],
        &["verify", "--strict_config=false", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 0, "{args:?} stderr={:?}", stderr_of(&out));
        assert!(stdout_of(&out).contains("is valid"), "{args:?}");
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} is Go-faithful and must stay silent: stderr={:?}",
            stderr_of(&out)
        );
    }

    // The frp-rs extension, and the measured divergence: the space-separated
    // token **is** consumed as the value, so the load is lenient and the
    // warning fires. Go keeps strict on for the same argv and exits 1 without
    // ever reaching `verify`'s success path.
    for args in [
        &["verify", "--strict-config", "false", "-c", &cfg][..],
        &["verify", "--strict_config", "false", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 0, "{args:?} stderr={:?}", stderr_of(&out));
        assert!(stdout_of(&out).contains("is valid"), "{args:?}");
        assert!(
            stderr_of(&out).contains(warning),
            "{args:?} must warn on stderr: stderr={:?}",
            stderr_of(&out)
        );
    }

    // Position does not change the extension (measured: `-c` first is the same
    // divergence on Go and frp-rs), and the warning follows the flag, not the
    // position.
    let out = run_frpc(&["verify", "-c", &cfg, "--strict-config", "false"]);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(stdout_of(&out).contains("is valid"));
    assert!(
        stderr_of(&out).contains(warning),
        "stderr={:?}",
        stderr_of(&out)
    );

    // Non-bool values: exit 1 on both binaries and both spellings; only the
    // message differs (Go: pflag's `strconv.ParseBool` text for the adjacent
    // form, the stray token ignored for the space form). No value is consumed,
    // so there is nothing to warn about.
    for args in [
        &["verify", "--strict-config=foo", "-c", &cfg][..],
        &["verify", "--strict_config=foo", "-c", &cfg][..],
        &["verify", "--strict-config", "foo", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 1, "{args:?}");
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains("`foo` is not expected in this context"),
            "{args:?}: {all:?}"
        );
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} consumes no value, so it must not warn: stderr={:?}",
            stderr_of(&out)
        );
    }

    // The empty value: `=` is pflag's ParseBool failure on Go, and the
    // space-separated empty token is a *positional* on Go (rc 0 with a valid
    // config, measured) while bpaf does not consume it either — both refuse on
    // frp-rs, with a message difference and no warning.
    for args in [
        &["verify", "--strict-config=", "-c", &cfg][..],
        &["verify", "--strict-config", "", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 1, "{args:?}");
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains("`` is not expected in this context"),
            "{args:?}: {all:?}"
        );
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} consumes no value, so it must not warn: stderr={:?}",
            stderr_of(&out)
        );
    }

    // A repeated flag: Go's pflag is last-wins (`=true =false` → rc 0 lenient;
    // the reverse → rc 1 strict), frp-rs refuses the repetition outright. Same
    // code as the strict Go row, different reason, and no warning either way.
    for args in [
        &[
            "verify",
            "--strict-config=true",
            "--strict-config=false",
            "-c",
            &cfg,
        ][..],
        &[
            "verify",
            "--strict-config=false",
            "--strict-config=true",
            "-c",
            &cfg,
        ][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 1, "{args:?}");
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains("cannot be used multiple times in this context"),
            "{args:?}: {all:?}"
        );
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} parses no value, so it must not warn: stderr={:?}",
            stderr_of(&out)
        );
    }
}

/// The warning fires on **each** `frpc` parser, not only `verify`: one row per
/// parser family (`run`, `verify`, `reload`, `status`, `stop`), each with a
/// config that makes the command exit immediately (port 1 is privileged and
/// never listening) so no child outlives `run_frpc`'s bound — and the same rows
/// with the Go-faithful `=` spelling stay silent.
#[test]
fn space_form_warning_fires_on_each_frpc_parser() {
    let dir = TempDir::new();
    let bad = dir.config(
        "bad.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\nnotAKnownFrpKey = 1\n",
    );
    // The admin commands need a `webServer.port` to dial; port 1 is refused at
    // once by the kernel.
    let dial = dir.config(
        "dial.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 1\nnotAKnownFrpKey = 1\n\
         [webServer]\naddr = \"127.0.0.1\"\nport = 1\n",
    );
    // Run mode: the refused server port ends the login attempt immediately
    // (`login_fail_exit`), and with no `[webServer]` no admin listener is bound.
    let run = dir.config(
        "run.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 1\nnotAKnownFrpKey = 1\n",
    );

    let space_rows: [&[&str]; 5] = [
        &["verify", "--strict-config", "false", "-c", &bad],
        &["reload", "--strict-config", "false", "-c", &dial],
        &["status", "--strict-config", "false", "-c", &dial],
        &["stop", "--strict-config", "false", "-c", &dial],
        &["--strict-config", "false", "-c", &run],
    ];
    let equals_rows: [&[&str]; 5] = [
        &["verify", "--strict-config=false", "-c", &bad],
        &["reload", "--strict-config=false", "-c", &dial],
        &["status", "--strict-config=false", "-c", &dial],
        &["stop", "--strict-config=false", "-c", &dial],
        &["--strict-config=false", "-c", &run],
    ];
    let warning = frp_core::cli::STRICT_CONFIG_SPACE_FORM_WARNING;

    for args in space_rows {
        let out = run_frpc(args);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(warning),
            "{args:?} is the extension and must warn: stderr={stderr:?}"
        );
        // Exactly once: a warning printed per parser stage, or by both the
        // detection and a parser, must fail here (a bare `contains` cannot see
        // a second emission).
        assert_eq!(
            stderr.matches(warning).count(),
            1,
            "{args:?} must print the warning exactly once: stderr={stderr:?}"
        );
    }
    for args in equals_rows {
        let out = run_frpc(args);
        assert!(
            !stderr_of(&out).contains(warning),
            "{args:?} is Go-faithful and must stay silent: stderr={:?}",
            stderr_of(&out)
        );
    }
}

// ── a subcommand after leading root flags (`TODO.md:2566`) ──────────────────
//
// Go's cobra resolves a command that follows leading root flags: `Find`
// (`cobra-1.8.0/command.go`) strips flags from argv and looks at the first
// surviving bare word, so `frpc -c pA.toml status` runs the `status` command
// with `pA.toml` as its config and dials the `[webServer] port` in it. bpaf
// picks the run-mode branch before dispatch, so that argv used to fall through
// to run mode and answer ``Error: no such command or positional: `status`,
// did you mean `https`?`` (rc 1). `hoist_leading_subcommand` in
// `frp-core/src/cli.rs` now moves that token in front of bpaf.
//
// Every Go cell below was measured on the official `frp_0.71.0_darwin_arm64`
// binary and the frp-rs `frpc` at this branch's base (`5b9a084`, the "before"
// column) and head, with the mock's port written into the config the argv
// names. The measuring harness and the full 45-row table are recorded in
// `docs/developing.md` § CLI inputs.

/// Config whose `[webServer] port` is `port`; the client server target is
/// unused by the admin commands and refused at once by the kernel.
fn admin_config(dir: &TempDir, name: &str, port: u16) -> String {
    dir.config(
        name,
        &format!(
            "serverAddr = \"127.0.0.1\"\nserverPort = 1\n[webServer]\naddr = \"127.0.0.1\"\nport = {port}\n"
        ),
    )
}

#[test]
fn subcommand_after_leading_root_flags_reaches_that_command() {
    // The item's flag orders, each in its own test so no test has to share a
    // one-shot listener: the subcommand token follows one, two and three
    // leading root flags, and a `-c <cfg>` sits between the flag and the token
    // in one row and before it in another. Go resolves all three to `status`
    // (measured); each must dial this config's admin port.
    let orders: [&[&str]; 4] = [
        &["-c", "CFG", "status"],
        &["--strict-config=false", "status", "-c", "CFG"],
        &["-c", "CFG", "--strict-config=false", "status"],
        &[
            "--strict-config=false",
            "--allow-unsafe",
            "TokenSourceExec",
            "-c",
            "CFG",
            "status",
        ],
    ];
    for order in orders {
        let dir = TempDir::new();
        let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
        let cfg = admin_config(&dir, "led.toml", port);
        let argv: Vec<String> = order
            .iter()
            .map(|a| {
                if *a == "CFG" {
                    cfg.clone()
                } else {
                    (*a).to_string()
                }
            })
            .collect();
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();

        let out = run_frpc(&refs);

        // `captured_request` panics if no request arrived, which is the failure
        // a run-mode fallback produces (it never dials `[webServer].port`).
        let captured = captured_request(rx, handle);
        assert_eq!(
            exit_code(&out),
            0,
            "{refs:?} must dial the config's admin port: stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out)
        );
        assert!(
            captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
            "{refs:?} must run the status command: head={:?}",
            captured.head
        );
    }
}

/// Like [`run_frpc`], but for a child expected to *fail a parse*: the same
/// bounded-then-killed collection, with a timeout short enough that a dropped
/// subcommand (whose fallback would wait on the network instead of exiting)
/// fails the test rather than the suite's wall clock.
fn run_frpc_brief(args: &[&str]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frpc");
    if wait_with_timeout(&mut child, Duration::from_secs(5)).is_none() {
        let _ = child.kill();
        let out = child.wait_with_output().expect("collect timed-out child");
        panic!(
            "frpc {args:?} did not exit within 5s (a dropped subcommand would fall through to run mode); stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    child.wait_with_output().expect("collect frpc output")
}

#[test]
fn subcommand_after_leading_root_flags_dials_the_named_config() {
    // The item's first row, in the shape the report tables it: `status` follows
    // `-c <cfg>`. Pinned on the request the mock received, which is what proves
    // the `status` branch ran with the config's port rather than run mode.
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "pA.toml", port);

    let out = run_frpc(&["-c", &cfg, "status"]);

    let captured = captured_request(rx, handle);
    assert_eq!(
        exit_code(&out),
        0,
        "stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert!(
        captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
        "head={:?}",
        captured.head
    );
    assert!(
        captured.head.contains(&format!("Host: 127.0.0.1:{port}")),
        "the config's port must be the one dialled; head={:?}",
        captured.head
    );
}

#[test]
fn subcommand_after_leading_root_flags_runs_a_single_proxy() {
    // The item's third row: `-c <missing>.toml tcp …` starts the tcp proxy on
    // Go even though the config does not exist (the single-proxy branch never
    // reads it). The canary accepts and closes, so the child exits at once; its
    // hit is the evidence the branch ran.
    let dir = TempDir::new();
    let missing = dir.config("missing.toml", "not even TOML\n");
    std::fs::remove_file(&missing).expect("remove the config so it is genuinely missing");
    let canary = canary();
    let port = canary.port().to_string();

    let out = run_frpc(&[
        "-c",
        &missing,
        "tcp",
        "--local-port",
        "5",
        "--remote-port",
        "6",
        "--proxy-name",
        "x",
        "--server-port",
        &port,
    ]);

    canary.assert_hits(1, "the hoisted tcp branch must dial --server-port");
    let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !text.contains("no such command or positional"),
        "the tcp token must be resolved, not refused: {text:?}"
    );
    assert!(
        text.contains("starting single proxy"),
        "the single-proxy path must run: {text:?}"
    );
}

#[test]
fn attached_and_repeated_config_spellings_still_resolve_the_hoisted_subcommand() {
    // The same rule has to survive pflag's `=`/attached spellings and a
    // repeated flag, all measured on Go: each dials the mock. Every row gets
    // its own one-shot listener and asserts the **positive** outcome (rc 0 plus
    // the request the mock received), because a negative-only assertion
    // (`!contains("no such command or positional")`) would also pass on a third,
    // different error message.
    let dir = TempDir::new();
    for (i, spelling) in ["-c=", "-c", "--config="].iter().enumerate() {
        let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
        let cfg = admin_config(&dir, &format!("att{i}.toml"), port);
        let attached = format!("{spelling}{cfg}");
        let argv: Vec<&str> = vec![&attached, "status"];

        let out = run_frpc(&argv);

        let captured = captured_request(rx, handle);
        assert_eq!(
            exit_code(&out),
            0,
            "{argv:?} must dial the config's admin port: stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out)
        );
        assert!(
            captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
            "{argv:?} must run the status command: head={:?}",
            captured.head
        );
        assert!(
            captured.head.contains(&format!("Host: 127.0.0.1:{port}")),
            "{argv:?} must dial the config's port: head={:?}",
            captured.head
        );
    }

    // A repeated `-c`: the last one wins and the command still resolves.
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "att-rep.toml", port);
    let other = admin_config(&dir, "att-dead.toml", 1);
    let out = run_frpc(&["-c", &other, "-c", &cfg, "status"]);
    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(captured.head.starts_with("GET /api/status HTTP/1.1\r\n"));
    assert!(
        captured.head.contains(&format!("Host: 127.0.0.1:{port}")),
        "the last -c must win: head={:?}",
        captured.head
    );
}

#[test]
fn a_config_file_named_after_a_subcommand_stays_a_config_file() {
    // The value-position trap: `-c status` is a config file literally named
    // `status`, not the `status` command. Go loads it in run mode (measured:
    // `start frpc service for config file […/status]`), never the admin command;
    // frp-rs must do the same, so no mock admin can be reached.
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "status", port);

    for argv in [
        vec!["-c", cfg.as_str()],
        vec!["--config", cfg.as_str()],
        vec![&format!("--config={cfg}")],
        vec![&format!("-c={cfg}")],
        vec![&format!("-c{cfg}")],
    ] {
        let out = run_frpc_brief(&argv);
        assert_ne!(
            exit_code(&out),
            0,
            "{argv:?} is run mode against a config whose server port refuses"
        );
        let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
        // The config the argv names is what run mode loaded: its server target
        // (`serverPort = 1`, refused at once) is the only port the child
        // dials, and the status command would have dialled the mock's instead.
        // The log fields are ANSI-wrapped at every token boundary, so the
        // assertion is on the refused *server* port the config names, which no
        // admin command would ever dial (the admin path would show the mock's
        // port and the status output instead).
        assert!(
            text.contains("dial to 127.0.0.1:1") || text.contains("connect to 127.0.0.1:1"),
            "{argv:?} must load the config named `status` and dial its server port in run mode: {text:?}"
        );
        assert!(
            !text.contains(&port.to_string()),
            "{argv:?} must not reach the config's admin port: {text:?}"
        );
        assert!(
            !text.contains("Proxy Status") && !text.contains("NAME  TYPE"),
            "{argv:?} must not run the status command: {text:?}"
        );
    }
    // Nothing reached the admin mock: the port belonged to run mode's
    // `[webServer]`, which frp-rs never dialled (it binds it, and this run
    // ended on the refused server port first).
    assert!(
        rx.try_recv().is_err(),
        "the admin listener must stay silent for a config file named `status`"
    );
    // The mock thread is parked in `accept` and nothing will ever connect, so
    // its handle is dropped rather than joined (a `join` here would block the
    // harness forever). Dropping the handle detaches it; the thread exits when
    // the test's listener is dropped at the end of the function.
    drop(handle);
}

#[test]
fn a_flag_value_named_after_a_subcommand_is_still_a_value() {
    // `--proxy-name status` is a value; only the leading word can be a command.
    // Measured on Go: `tcp --proxy-name status …` starts the tcp proxy.
    let canary = canary();
    let port = canary.port().to_string();

    let out = run_frpc(&[
        "tcp",
        "--proxy-name",
        "status",
        "--local-port",
        "5",
        "--remote-port",
        "6",
        "--server-port",
        &port,
    ]);

    canary.assert_hits(1, "the proxy named `status` must still start");
    let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        text.contains("starting single proxy"),
        "the tcp branch must run: {text:?}"
    );
}

#[test]
fn a_word_that_is_not_a_command_is_refused_even_when_a_command_follows() {
    // Go refuses the *first* bare word (`unknown command "notacommand" for
    // "frpc"`, measured) even when a real command name follows it, so the hoist
    // must stay out of this argv entirely.
    let dir = TempDir::new();
    let cfg = dir.config("plain.toml", "serverAddr = \"127.0.0.1\"\nserverPort = 1\n");
    let out = run_frpc_brief(&["-c", &cfg, "notacommand", "status"]);
    let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        text.contains("notacommand"),
        "the first bare word must be the one refused: {text:?}"
    );
    assert!(
        !text.contains("Proxy Status"),
        "the later `status` word must not be hoisted: {text:?}"
    );
    assert_ne!(exit_code(&out), 0);
}

#[test]
fn a_real_double_dash_still_stops_the_hoist() {
    // Go treats everything after a real `--` as a positional: measured,
    // `frpc -c <cfg> -- status` starts the client in run mode and never dials
    // `[webServer].port`. frp-rs refuses the leftover positional (the recorded
    // positional divergence), but it must not turn it into the status command.
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "dd.toml", port);

    let out = run_frpc_brief(&["-c", &cfg, "--", "status"]);

    assert_ne!(exit_code(&out), 0, "the positional must be refused");
    let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        text.contains("status"),
        "the refused token must be named: {text:?}"
    );
    assert!(
        rx.try_recv().is_err(),
        "`-- status` must not reach the admin port"
    );
    // Parked in `accept` with nothing coming: drop rather than join (see
    // `a_config_file_named_after_a_subcommand_stays_a_config_file`).
    drop(handle);
}

#[test]
fn a_dash_prefixed_config_value_stays_the_config_value() {
    // `-c -status`: pflag gives `-c` the value `-status` (Go: `open -status: no
    // such file or directory`), so the token is a value and not a command. The
    // shared dash-value rewrite may attach it (`-c=-status`) — either way the
    // load error must name `-status`.
    let dir = TempDir::new();
    for argv in [vec!["-c", "-status"], vec!["--config", "--status"]] {
        let out = run_frpc_brief(&argv);
        assert_eq!(exit_code(&out), 1, "{argv:?} must fail on the load");
        let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
        let token = if argv[0] == "-c" {
            "-status"
        } else {
            "--status"
        };
        assert!(
            text.contains(token),
            "{argv:?} must try to read {token}: {text:?}"
        );
        assert!(
            !text.contains("no such command or positional"),
            "{argv:?} must not be a leftover-token refusal: {text:?}"
        );
    }
    let _ = dir;
}

#[test]
fn the_existing_frpc_order_is_unchanged() {
    // frp-rs's own `frpc <subcommand> [flags]` order keeps working, hoisted or
    // not: the same argv with the subcommand already leading must dial the same
    // mock port.
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "order.toml", port);

    let out = run_frpc(&["status", "-c", &cfg]);

    let captured = captured_request(rx, handle);
    assert_eq!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    assert!(captured.head.starts_with("GET /api/status HTTP/1.1\r\n"));
    assert!(captured.head.contains(&format!("Host: 127.0.0.1:{port}")));
}

#[test]
fn the_hoisted_subcommand_dials_the_same_port_as_the_unhoisted_order() {
    // The strongest equivalence available without a second mock in flight: the
    // hoisted `-c <cfg> status` and the already-leading `status -c <cfg>` argv
    // must produce the identical request head against the same config. Two
    // one-shot mocks, one per order, same config file.
    let dir = TempDir::new();
    let (port_a, rx_a, handle_a) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "same.toml", port_a);
    let first = run_frpc(&["-c", &cfg, "status"]);
    let captured_a = captured_request(rx_a, handle_a);
    assert_eq!(exit_code(&first), 0, "stderr={:?}", stderr_of(&first));

    let (port_b, rx_b, handle_b) = mock_admin("HTTP/1.1 200 OK");
    let cfg_b = admin_config(&dir, "same-b.toml", port_b);
    let second = run_frpc(&["status", "-c", &cfg_b]);
    let captured_b = captured_request(rx_b, handle_b);
    assert_eq!(exit_code(&second), 0, "stderr={:?}", stderr_of(&second));

    let norm = |head: &str, port: u16| head.replace(&port.to_string(), "<port>");
    assert_eq!(
        norm(&captured_a.head, port_a),
        norm(&captured_b.head, port_b),
        "the hoisted and unhoisted orders must send the same request"
    );
}

// ── `--strict-config`/`--strict_config` before the subcommand, both ways ────
//
// Go registers the flag with pflag `BoolVarP` (`cmd/frpc/sub/root.go:53`), and
// a pflag bool sets `NoOptDefVal = "true"` (`pflag-1.0.5/bool.go:56`), so
// cobra's `stripFlags` does **not** let it swallow the next argv token. Both
// signs of getting that wrong were measured on Go v0.71.0:
//
// * bare flag before the command word — `frpc --strict-config status -c cfg` is
//   rc 0 and dials the config's admin port (the command **is** resolved), so a
//   classifier that consumes the token misses it;
// * a word after the bare flag — `frpc --strict-config true status -c cfg` is
//   rc 1 `unknown command "true" for "frpc"` and never dials (`true` is the
//   first bare word, and `status` is not resolved), so a classifier that
//   consumes the token resolves a command Go refuses.
//
// These two tests pin one direction each, end to end.

#[test]
fn bare_strict_config_before_the_subcommand_still_resolves_it() {
    // Direction B: the flag does not consume `status`, so the status command
    // runs and dials. Each spelling gets its own one-shot mock.
    let dir = TempDir::new();
    // The command word must be the token immediately after the bare flag: that
    // is the shape where a consuming classifier loses it. (`--strict-config
    // CFG status` is a different, also-Go-refused shape — the config path is
    // the first bare word — and is covered by the direction-A test below.)
    let orders: [&[&str]; 4] = [
        &["--strict-config", "status", "-c", "CFG"],
        &["--strict_config", "status", "-c", "CFG"],
        &["-c", "CFG", "--strict-config", "status"],
        &["-c", "CFG", "--strict_config", "status"],
    ];
    for order in orders {
        let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
        let cfg = admin_config(&dir, "sc-led.toml", port);
        let argv: Vec<String> = order
            .iter()
            .map(|a| {
                if *a == "CFG" {
                    cfg.clone()
                } else {
                    (*a).to_string()
                }
            })
            .collect();
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();

        let out = run_frpc(&refs);

        let captured = captured_request(rx, handle);
        assert_eq!(
            exit_code(&out),
            0,
            "{refs:?} must resolve the status command: stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out)
        );
        assert!(
            captured.head.starts_with("GET /api/status HTTP/1.1\r\n"),
            "{refs:?} must run the status command: head={:?}",
            captured.head
        );
    }
}

#[test]
fn a_word_after_bare_strict_config_is_not_resolved_as_a_subcommand() {
    // Direction A (the regression the over-consuming classifier introduced):
    // `true`/`false` is the first bare word, so Go refuses that word and never
    // resolves the real command name that follows it. The listener must stay
    // silent and the exit code must be non-zero.
    let dir = TempDir::new();
    let (port, rx, handle) = mock_admin("HTTP/1.1 200 OK");
    let cfg = admin_config(&dir, "sc-true.toml", port);

    for argv in [
        vec!["--strict-config", "true", "status", "-c", cfg.as_str()],
        vec!["--strict-config", "false", "status", "-c", cfg.as_str()],
        vec!["--strict_config", "true", "stop", "-c", cfg.as_str()],
        vec!["--strict-config", "true", "reload", "-c", cfg.as_str()],
    ] {
        let out = run_frpc_brief(&argv);
        assert_ne!(
            exit_code(&out),
            0,
            "{argv:?} must be refused like Go's `unknown command \"true\"`: stdout={:?} stderr={:?}",
            stdout_of(&out),
            stderr_of(&out)
        );
        let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            !text.contains("Proxy Status")
                && !text.contains("stop success")
                && !text.contains("reload success"),
            "{argv:?} must not run the later command: {text:?}"
        );
    }

    // Nothing reached the admin mock: the config's `[webServer]` port was never
    // dialled (the status/stop/reload commands would have dialled it).
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "no admin request may arrive for a word-after-flag argv"
    );
    drop(handle); // parked in `accept()`; see the reversed-order test.

    // The same shape on a single-proxy command: Go refuses `true` and the tcp
    // proxy must not start, so the canary stays silent.
    let canary = canary();
    let out = run_frpc_brief(&[
        "--strict-config",
        "true",
        "tcp",
        "--local-port",
        "5",
        "--remote-port",
        "6",
        "--proxy-name",
        "x",
        "--server-port",
        &canary.port().to_string(),
    ]);
    assert_ne!(exit_code(&out), 0, "stderr={:?}", stderr_of(&out));
    let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !text.contains("starting single proxy"),
        "the tcp proxy must not start: {text:?}"
    );
    canary.assert_silent("a refused `--strict-config true tcp …` must not dial");
}
