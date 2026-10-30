//! The real `frps` daemon's OTLP exit flush, end to end: SIGTERM on the
//! single-config lane must still deliver the `run` span to the collector.
//!
//! The unit tests in `frp-core/src/logging.rs` pin `shutdown_otel()`'s state
//! transitions and `frp-core/tests/otel_export_shutdown.rs` pins its wire
//! behaviour, but only this test pins the *call site*: `frps/src/main.rs`'s
//! graceful tail. Deleting that one call keeps every unit/integration test in
//! `frp-core` green — the span is still queued when the process exits — and the
//! failure is invisible in production because the exporter logs nothing. That
//! is the defect this file exists for; the mutation is recorded in the PR.
//!
//! What it proves, in order:
//!
//! * the daemon builds its provider from `OTEL_EXPORTER_OTLP_ENDPOINT` and
//!   treats the value as a base URL (`/v1/traces` is appended by
//!   `normalize_otlp_endpoint`, not by this test);
//! * SIGTERM reaches the graceful tail (exit status 0, not a signal death);
//! * the exit path exported exactly one OTLP/HTTP request, with a non-empty
//!   body — the `run` span closed at shutdown — rather than waiting for the
//!   batch processor's first periodic export (measured at 10.006 s on the SDK
//!   defaults, longer than this test's whole timeout).
//!
//! Hermetic: its own temporary config, a free `bindPort`, an ephemeral sink
//! port, and a child process killed on every failure path.
//!
//! Gated on `full` for the same reason as the other `frps/tests/*.rs` files
//! (`CARGO_BIN_EXE_frps` needs the bin's `required-features`) and on `unix`
//! because `SIGTERM` is the trigger.

#![cfg(all(unix, feature = "full", feature = "otel"))]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_frps");

/// Overridable binary, the same hook `frps/tests/cli_exit_codes.rs` carries.
fn bin() -> String {
    std::env::var("FRPS_BIN").unwrap_or_else(|_| BIN.to_string())
}

/// The last `info!` before the accept loop; emitted by `Service::run` once the
/// listener is bound (`frp-server/src/service.rs`). It is *not* proof that
/// SIGTERM's handler is installed — tokio registers signals per kind, and
/// `spawn_signal_listener_task` runs a few statements later — so the test
/// leaves a short settle window before signalling. A signal that lands in that
/// window kills the child by default disposition, which fails the exit-status
/// assertion below rather than being silently tolerated.
const STARTUP_LINE: &str = "frps listener started on";
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const SINK_TIMEOUT: Duration = Duration::from_secs(10);

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself — same pattern (and same reason: no
/// `tempfile` dev-dependency) as `frps/tests/cli_exit_codes.rs`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frps-otel-flush-{}-{n}", std::process::id()));
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

/// An ephemeral port, released immediately: `bindPort = 0` is not "any port"
/// here (frp-rs normalises 0 to the default 7000, which macOS's Control Center
/// holds), so the daemon needs a concrete free port.
fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
    probe.local_addr().expect("probe local_addr").port()
}

fn try_wait(child: &mut Child) -> Option<ExitStatus> {
    child.try_wait().expect("try_wait")
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// One OTLP/HTTP request as the sink saw it.
struct Request {
    head: String,
    body: Vec<u8>,
}

/// A throwaway OTLP/HTTP sink on an ephemeral port.
///
/// Accepts one connection, reads HTTP requests off it (answering each with
/// `200`), and sends back everything it parsed once the connection closes. A
/// connection that never arrives or a request that stalls reports an empty list
/// after [`SINK_TIMEOUT`], so a missing flush fails the assertion below instead
/// of hanging the suite.
fn otlp_sink() -> (SocketAddr, mpsc::Receiver<Vec<Request>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the fake OTLP server");
    let addr = listener.local_addr().expect("sink local_addr");
    listener
        .set_nonblocking(true)
        .expect("non-blocking accept on the sink");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let accept_deadline = Instant::now() + SINK_TIMEOUT;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("fake OTLP server failed to accept: {e}"),
            }
        };
        // The listener is non-blocking only so the accept loop can time out;
        // the accepted socket must be blocking again or `read` would return
        // `WouldBlock` before the exporter's request lands.
        stream
            .set_nonblocking(false)
            .expect("blocking reads on the accepted sink connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("sink read timeout");
        let requests = read_requests(&mut stream);
        // `ok()`: the receiver is gone only if the test already panicked.
        tx.send(requests).ok();
    });
    (addr, rx)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().expect("content-length"))
    })
}

/// Read requests until the peer closes (the daemon has exited) or a read times
/// out, answering each with an empty `200` so the exporter's call resolves.
fn read_requests(stream: &mut TcpStream) -> Vec<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut requests = Vec::new();
    loop {
        if let Some(head_end) = find(&buf, b"\r\n\r\n").map(|i| i + 4) {
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            match content_length(&head) {
                Some(len) if buf.len() >= head_end + len => {
                    let body = buf[head_end..head_end + len].to_vec();
                    requests.push(Request { head, body });
                    buf.drain(..head_end + len);
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .expect("answer the OTLP export");
                    continue;
                }
                Some(_) => {}
                None => {
                    // Not an OTLP/HTTP request this parser understands; keep it
                    // so the assertion's failure message shows the head.
                    requests.push(Request {
                        head,
                        body: Vec::new(),
                    });
                    return requests;
                }
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => return requests,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return requests,
        }
    }
}

#[test]
fn sigterm_flushes_the_run_span_to_the_otlp_endpoint() {
    let dir = TempDir::new();
    let port = free_port();
    let config = dir.write(
        "frps.toml",
        &format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {port}\n[auth]\ntoken = \"otel-flush-test\"\n"
        ),
    );
    let log_path = dir.path("frps.log");
    let (sink_addr, requests_rx) = otlp_sink();
    let endpoint = format!("http://{sink_addr}");

    let log = std::fs::File::create(&log_path).expect("create diagnostic log");
    let mut child = Command::new(bin())
        .args(["-c", &config])
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", &endpoint)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn frps");
    // `expect`, not `unwrap_or_default`: this reader only runs in a panic
    // message, and swallowing a read error there would replace the diagnosis.
    let read_log = || std::fs::read_to_string(&log_path).expect("read frps diagnostic log");

    let ready_deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if read_log().contains(STARTUP_LINE) {
            break;
        }
        if let Some(status) = try_wait(&mut child) {
            panic!(
                "frps exited ({status:?}) before logging {STARTUP_LINE:?}; log={:?}",
                read_log()
            );
        }
        if Instant::now() >= ready_deadline {
            kill_and_reap(&mut child);
            panic!(
                "frps never logged {STARTUP_LINE:?} within {EXIT_TIMEOUT:?}; log={:?}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // Settle window for tokio's lazy, per-kind SIGTERM registration (see
    // `STARTUP_LINE`). Short enough not to matter for speed, long enough that
    // the few statements between the listener line and
    // `spawn_signal_listener_task` have completed.
    std::thread::sleep(Duration::from_millis(100));

    let kill_status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    assert!(
        kill_status.is_ok_and(|status| status.success()),
        "could not deliver SIGTERM to frps (pid {})",
        child.id()
    );

    let exit_deadline = Instant::now() + EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = try_wait(&mut child) {
            break status;
        }
        if Instant::now() >= exit_deadline {
            kill_and_reap(&mut child);
            panic!(
                "frps did not exit within {EXIT_TIMEOUT:?} of SIGTERM; log={:?}",
                read_log()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let log_text = read_log();
    assert_eq!(
        status.code(),
        Some(0),
        "frps must exit 0 on SIGTERM (signal={status:?}); log={log_text:?}"
    );

    let requests = requests_rx.recv_timeout(SINK_TIMEOUT).unwrap_or_else(|e| {
        panic!(
            "the exit path exported no OTLP request ({e}): the `run` span was still queued at \
             shutdown. `frps/src/main.rs`'s graceful tail must call `logging::shutdown_otel()`; \
             log={log_text:?}"
        )
    });
    assert_eq!(
        requests.len(),
        1,
        "expected exactly one OTLP export request from the shutdown flush, got {}: {:?}; \
         log={log_text:?}",
        requests.len(),
        requests.iter().map(|r| &r.head).collect::<Vec<_>>()
    );
    let request = &requests[0];
    assert!(
        request.head.starts_with("POST /v1/traces "),
        "the base endpoint must be normalised to /v1/traces; head={:?}",
        request.head
    );
    assert!(
        !request.body.is_empty(),
        "the export request carried no spans: the `run` span closed when `Service::run` \
         returned, so the flush has nothing to prove; head={:?}",
        request.head
    );
}
