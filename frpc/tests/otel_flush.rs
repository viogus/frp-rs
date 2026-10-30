//! `frpc`'s OTLP exit flush, end to end: a lane that exits non-zero after a
//! service ran must still deliver the `run` span to the collector.
//!
//! Two lanes reach a non-zero exit after `Service::run` was entered, and both
//! used to lose the queued span:
//!
//! * single config — the error branch in `run_normal` flushes, so this test is
//!   the control that keeps that call honest;
//! * `--config-dir` where **every** file's `run()` failed — that lane exits
//!   through `process::exit` after the join loop and skipped every flush
//!   (measured: exit 1, zero requests at the sink, while the same config via
//!   `-c` exported one 1090-byte request). The flush added before that exit is
//!   what the second test pins; deleting it makes the test fail, and the
//!   mutation is recorded in the PR.
//!
//! Both tests are hermetic: a dead server port (nothing listens, so the login
//! fails immediately), a temporary config, an ephemeral sink port, and a child
//! that has already exited when the assertions run. They need `full` for the
//! same reason `frps/tests/otel_flush.rs` does: `CARGO_BIN_EXE_frpc` only
//! exists when the package's `[[bin]] frpc` (`required-features = ["full"]`) is
//! built.

#![cfg(all(feature = "full", feature = "otel"))]

use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[path = "../../frp-core/tests/support/otel_sink_std.rs"]
mod otel_sink;

use otel_sink::{find, free_port, length_delimited_field, otlp_sink};

const BIN: &str = env!("CARGO_BIN_EXE_frpc");
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const SINK_TIMEOUT: Duration = Duration::from_secs(10);

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself — same pattern (and same reason: no
/// `tempfile` dev-dependency) as `frps/tests/cli_exit_codes.rs`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("frpc-otel-flush-{}-{n}", std::process::id()));
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

    fn as_str(&self) -> String {
        self.0.to_str().expect("utf-8 temp path").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Overridable binary, the same hook the other `frpc/tests/*.rs` files carry.
fn bin() -> String {
    std::env::var("FRPC_BIN").unwrap_or_else(|_| BIN.to_string())
}

/// A client config whose server is a port nothing listens on, so the first
/// login is refused and `login_fail_exit` (default `true`) ends the run.
fn client_config(dead_port: u16) -> String {
    format!(
        "serverAddr = \"127.0.0.1\"\nserverPort = {dead_port}\n[auth]\ntoken = \"otel-flush-test\"\n"
    )
}

/// Drop the ambient tracing configuration before spawning the daemon.
///
/// The `OTEL_*` names are read by the SDK itself, so a developer's exported
/// `OTEL_SDK_DISABLED=true`, `OTEL_TRACES_EXPORTER=none`, or a per-signal
/// endpoint override would silently change the run this test exists to observe
/// (and could turn a real regression into a pass). `RUST_LOG` is here for the
/// same reason from the other side: the `run` span is only recorded under a
/// filter that admits it, so `RUST_LOG=off` in a developer's shell used to turn
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

fn spawn_frpc(dir: &TempDir, args: &[&str], endpoint: &str) -> (Child, String) {
    let log_path = dir.path("frpc.log");
    let log = std::fs::File::create(&log_path).expect("create diagnostic log");
    let stderr = log.try_clone().expect("clone the log handle");
    let mut cmd = Command::new(bin());
    scrub_inherited_env(&mut cmd);
    let child = cmd
        .args(args)
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin()));
    (child, log_path)
}

fn wait_for_exit(child: &mut Child, log_path: &str) -> (ExitStatus, String) {
    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            return (status, log);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            panic!("frpc did not exit within {EXIT_TIMEOUT:?}; log={log:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The assertions every lane shares: one request, the signal path, a body that
/// carries a span named `run` framed as protobuf field 5 (`Span.name`).
fn assert_run_span_flushed(
    requests_rx: &std::sync::mpsc::Receiver<Vec<otel_sink::Request>>,
    log: &str,
) {
    let requests = requests_rx.recv_timeout(SINK_TIMEOUT).unwrap_or_else(|e| {
        panic!(
            "frpc exited without exporting an OTLP request ({e}): the `run` span was \
             still queued at shutdown, so this exit path is missing a \
             `logging::shutdown_otel()`; log={log:?}"
        )
    });
    assert_eq!(
        requests.len(),
        1,
        "expected exactly one OTLP export request from the shutdown flush, got {}: {:?}; \
         log={log:?}",
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
    assert!(
        find(&request.body, &length_delimited_field(0x2a, b"run")).is_some(),
        "the exported body does not carry `run` as protobuf field 5 (`Span.name`): the \
         flush exported something, but not the span `Service::run` closed; body_len={}",
        request.body.len()
    );
}

#[test]
fn single_config_run_failure_flushes_the_run_span() {
    let dir = TempDir::new();
    let config = dir.write("frpc.toml", &client_config(free_port()));
    let (sink_addr, requests_rx) = otlp_sink();
    let endpoint = format!("http://{sink_addr}");

    let (mut child, log_path) = spawn_frpc(&dir, &["-c", &config], &endpoint);
    let (status, log) = wait_for_exit(&mut child, &log_path);
    assert_eq!(
        status.code(),
        Some(1),
        "a refused login must exit 1 (EXIT_RUNTIME), got {status:?}; log={log:?}"
    );
    assert_run_span_flushed(&requests_rx, &log);
    // Completion marker for the CI step (`--nocapture`): a test body that
    // returns early or loses its assertions must not look green.
    println!("otel-flush-pin: run span exported");
}

#[test]
fn config_dir_all_failed_flushes_the_run_spans() {
    let dir = TempDir::new();
    // Two independent dead ports so neither file can succeed by accident.
    dir.write("a.toml", &client_config(free_port()));
    dir.write("b.toml", &client_config(free_port()));
    let dir_arg = dir.as_str();
    let (sink_addr, requests_rx) = otlp_sink();
    let endpoint = format!("http://{sink_addr}");

    let (mut child, log_path) = spawn_frpc(&dir, &["--config-dir", &dir_arg], &endpoint);
    let (status, log) = wait_for_exit(&mut child, &log_path);
    assert_eq!(
        status.code(),
        Some(1),
        "every service failed to run, so the directory must exit 1 (EXIT_RUNTIME) \
         rather than report success; log={log:?}"
    );
    assert_run_span_flushed(&requests_rx, &log);
    // Completion marker for the CI step (`--nocapture`): a test body that
    // returns early or loses its assertions must not look green.
    println!("otel-flush-pin: all-failed exit exported");
}
