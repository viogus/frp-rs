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
//! * the exit path exported exactly one OTLP/HTTP request whose body carries the
//!   span name `run` framed as protobuf field 5 (`Span.name`) — the span that
//!   closed at shutdown — rather than waiting for the batch processor's first
//!   periodic export (measured at 10.006 s on the SDK defaults, longer than
//!   this test's whole timeout).
//!
//! Hermetic: its own temporary config, a free `bindPort`, an ephemeral sink
//! port, and a child process killed on every failure path.
//!
//! Gated on `full` because `CARGO_BIN_EXE_frps` is only provided when the
//! package's `[[bin]] frps` — which declares `required-features = ["full"]` —
//! is built; without `full` this test has no binary to spawn. Gated on `unix`
//! because `SIGTERM` is the trigger.

#![cfg(all(unix, feature = "full", feature = "otel"))]

use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[path = "../../frp-core/tests/support/otel_sink_std.rs"]
mod otel_sink;

use otel_sink::{find, free_port, length_delimited_field, otlp_sink};

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

fn try_wait(child: &mut Child) -> Option<ExitStatus> {
    child.try_wait().expect("try_wait")
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Drop the ambient tracing configuration before spawning the daemon.
///
/// The `OTEL_*` names are read by the SDK itself, so a developer's exported
/// `OTEL_SDK_DISABLED=true`, `OTEL_TRACES_EXPORTER=none`, or a per-signal
/// endpoint override would silently change the run this test exists to observe
/// (and could turn a real regression into a pass). `RUST_LOG` is here for the
/// same reason from the other side: the daemon only prints `STARTUP_LINE` at
/// `info`, and the `run` span is only recorded under a filter that admits it,
/// so `RUST_LOG=error` or `RUST_LOG=off` in a developer's shell used to turn
/// this pin red with no product change. `env_clear()` is deliberately not used:
/// the daemon legitimately needs `HOME`, `PATH` and the temp-dir variables.
fn scrub_inherited_env(cmd: &mut Command) {
    for var in [
        "OTEL_SDK_DISABLED",
        "OTEL_TRACES_EXPORTER",
        "OTEL_METRICS_EXPORTER",
        "OTEL_LOGS_EXPORTER",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        "OTEL_EXPORTER_OTLP_TIMEOUT",
        "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
        "OTEL_EXPORTER_OTLP_COMPRESSION",
        "OTEL_EXPORTER_OTLP_TRACES_COMPRESSION",
        "OTEL_SERVICE_NAME",
        "OTEL_RESOURCE_ATTRIBUTES",
        "OTEL_TRACES_SAMPLER",
        // The daemon's own log filter (see the doc above).
        "RUST_LOG",
    ] {
        cmd.env_remove(var);
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
    let mut cmd = Command::new(bin());
    scrub_inherited_env(&mut cmd);
    let mut child = cmd
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
    // The body is protobuf, so a bare `find(body, b"run")` could match an
    // attribute value; the field-5 framing (`Span.name`, tag 0x2a) is what
    // makes this the span name rather than a coincidence.
    assert!(
        find(&request.body, &length_delimited_field(0x2a, b"run")).is_some(),
        "the exported body does not carry `run` as protobuf field 5 (`Span.name`): the \
         flush exported something, but not the span `Service::run` closed; body_len={}",
        request.body.len()
    );
    // Completion marker for the CI step (`--nocapture`). It proves the body
    // reached this line: an early return, a panic before the assertions or a
    // cfg'd-out test leaves no marker. It cannot prove the assertions above are
    // still there - deleting one while keeping this line would still pass.
    println!("otel-flush-pin: run span exported");
}
