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
//!   (`pkg/config/v1/common.go:71-73`), reached from
//!   `ClientCommonConfig.Complete()` (`pkg/config/v1/client.go:96`). frp-rs's
//!   serde default only fired when the key was absent, so an explicit `addr = ""`
//!   produced `connect :7499: failed to lookup address information …`.
//!
//! The third measured input — case-insensitive config keys — is deliberately
//! **not** fixed here; it is recorded as a divergence in
//! `docs/developing.md` § CLI inputs with its measurement and scope. The
//! case-shaped tests in this file pin only what a CLI can see (`rc 0`,
//! `is valid`, the absence of an `unknown field` line); the **values** are
//! asserted at the config layer, because a future serde alias would keep these
//! tests green while honouring the key. Citation pairs (each verified against
//! the test that actually contains the assertion):
//!
//! * walked-section refusal — `test_strict_rejects_nested_unknown_keys`
//!   (`log.levell`, `auth.tokenz`) and, for the admin section,
//!   `strict_mode_exempts_proxy_and_visitor_array_elements`
//!   (`web_server.addrr`) and `test_strict_rejects_unknown_web_server_key`
//!   (`web_server.unknown_web_server_key`) in `frp-core/src/config/tests.rs`;
//! * array-element drop, value included —
//!   `case_insensitive_proxy_array_key_is_dropped_in_strict_mode`
//!   (`remote_port == 0`) there, alongside the pre-existing
//!   `strict_mode_exempts_proxy_and_visitor_array_elements`;
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
/// (`WebServerConfig.Complete()`, `pkg/config/v1/common.go:71-73`, reached from
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

/// A mis-cased key **inside `[[proxies]]`** is silently dropped even in strict
/// mode: `LocalPort`/`RemotePort` are neither matched nor reported, and `frpc
/// verify` exits **0**. Go accepts the same file and *uses* the keys, so this
/// pins the current divergence rather than matching Go.
///
/// This is the strict-mode array exemption, not something this branch
/// introduced: `check_strict` recurses only into sections it has a key list for
/// and deliberately does not descend into `[[proxies]]`/`[[visitors]]`/
/// `[[httpPlugins]]` (`frp-core/src/config/strict.rs:277-285`), and
/// `ProxyConfig` carries no `deny_unknown_fields`. It is recorded in
/// `docs/deployment.md:710-747` with the end-to-end consequence (the same config
/// makes Go frpc bind the configured port while frp-rs registers
/// `remote_port: 0` and the server auto-allocates one).
///
/// **What this test does and does not pin.** It pins the CLI-visible outcome
/// only: `rc 0`, `is valid`, no `unknown field` line. It does NOT pin that the
/// keys were dropped — a `#[serde(alias = "RemotePort")]` would keep it green
/// while honouring the key. That is asserted by
/// `case_insensitive_proxy_array_key_is_dropped_in_strict_mode` in
/// `frp-core/src/config/tests.rs` (`remote_port == 0`), which is where the
/// value-level claim lives.
#[test]
fn case_insensitive_proxy_array_keys_are_dropped_in_strict_mode() {
    let dir = TempDir::new();
    // The capital `R` on `RemotePort` is the Go-accepted spelling; `name`/`type`
    // are lowercase so the element still parses.
    let cfg = dir.config(
        "cap-proxy.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n\
         [[proxies]]\nname = \"t\"\ntype = \"tcp\"\nLocalPort = 7198\nRemotePort = 7198\n",
    );

    // Strict is the default (and Go's); no `--strict-config=false` here.
    let out = run_frpc(&["verify", "-c", &cfg]);

    assert_eq!(
        exit_code(&out),
        0,
        "the array exemption must keep this loading (Go refuses it); stdout={:?} stderr={:?}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert!(
        stdout_of(&out).contains("is valid"),
        "stdout={:?}",
        stdout_of(&out)
    );
    // No unknown-field diagnostic for the array element — that is the point.
    let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !all.contains("unknown field"),
        "the array-element key must be dropped silently, not reported: {all:?}"
    );
}

/// The contrast for the test above: the walked sections still refuse in strict
/// mode, so the exemption is specifically the array element. `webServer.Port`
/// rather than the camel-case alias `port` is the Go-accepted spelling.
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
// The Go v0.71.0 rows this encodes (measured on the official darwin/arm64
// binary with `badwithport.toml`) and the one row where frp-rs diverges:
//
// | argv | Go v0.71.0 | frp-rs |
// |---|---|---|
// | absent / bare / `=true` | strict, rc 1 (`json: unknown field …`) | strict, rc 1 |
// | `--strict-config=false` | lenient, rc 0 (`syntax is ok`) | lenient, rc 0 |
// | `--strict-config false` | strict, rc 1 (token is a positional) | lenient, rc 0 — **extension** |
// | `--strict-config=foo` | rc 1, pflag `invalid argument … strconv.ParseBool` | rc 1, `` `foo` is not expected in this context `` |
//
// The full table (including `run`/`reload`/`status`/`stop`/`frps`) and the
// reason the space form is kept are in `docs/developing.md`
// § "`--strict-config`: the space-separated value form".
#[test]
fn verify_strict_config_spellings_match_their_measured_rows() {
    let dir = TempDir::new();
    let cfg = dir.config(
        "bad.toml",
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\nnotAKnownFrpKey = 1\n",
    );

    // Go-faithful rows: absent, bare (both spellings) and `=true` are strict.
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
    }

    // Go-faithful row: the adjacent `=false` spelling is lenient on both.
    for args in [
        &["verify", "--strict-config=false", "-c", &cfg][..],
        &["verify", "--strict_config=false", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 0, "{args:?} stderr={:?}", stderr_of(&out));
        assert!(stdout_of(&out).contains("is valid"), "{args:?}");
    }

    // The frp-rs extension, and the measured divergence: the space-separated
    // token **is** consumed as the value, so the load is lenient. Go keeps
    // strict on for the same argv and exits 1 without ever reaching `verify`'s
    // success path.
    for args in [
        &["verify", "--strict-config", "false", "-c", &cfg][..],
        &["verify", "--strict_config", "false", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 0, "{args:?} stderr={:?}", stderr_of(&out));
        assert!(stdout_of(&out).contains("is valid"), "{args:?}");
    }

    // Non-bool values: exit 1 on both binaries and both spellings; only the
    // message differs (Go: pflag's `strconv.ParseBool` text for the adjacent
    // form, the stray token ignored for the space form).
    for args in [
        &["verify", "--strict-config=foo", "-c", &cfg][..],
        &["verify", "--strict-config", "foo", "-c", &cfg][..],
    ] {
        let out = run_frpc(args);
        assert_eq!(exit_code(&out), 1, "{args:?}");
        let all = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            all.contains("`foo` is not expected in this context"),
            "{args:?}: {all:?}"
        );
    }
}
