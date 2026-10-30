//! Integration test: the **documented base-URL form** of `otlp_endpoint` must
//! reach the wire as an OTLP/HTTP request to `/v1/traces`.
//!
//! Defect this pins: `build_otel_provider` passed the configured string
//! straight to `with_endpoint`, and opentelemetry-otlp 0.33 appends the
//! `/v1/traces` signal path only to the endpoints it resolves itself (the
//! `OTEL_EXPORTER_OTLP_*` variables and its defaults). A user who set the base
//! URL from the docs/systemd unit — `http://collector:4318`, no path — got
//! `POST /`, the collector answered 404, and because the SDK's `internal-logs`
//! feature is off nothing was logged: every span vanished silently. The
//! measured evidence in the PR #552 delta review was exactly `POST / HTTP/1.1`
//! with zero spans and no error.
//!
//! One init case per test binary: the global subscriber and the process-wide
//! provider are once-per-process, so a second case here would either be ignored
//! or fight the first. The shapes that need no wire (`/`, `/custom`, a query
//! string, an unparseable value) are unit-tested next to the normalisation in
//! `frp-core/src/logging.rs`; this file proves the bare-endpoint case end to
//! end, including that the span body arrives.
#![cfg(feature = "otel")]

#[path = "support/otel_sink.rs"]
mod otel_sink;

use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use tokio::net::TcpListener;
use tracing_subscriber::layer::SubscriberExt as _;

use otel_sink::{find, length_delimited_field};

/// The `tracing` span name; it must survive into the exported OTLP `Span.name`
/// bytes.
const SPAN_NAME: &str = "otel_export_path_span";

/// Bound on `force_flush` + `shutdown`; both block the calling thread.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_endpoint_exports_to_the_v1_traces_signal_path() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the fake OTLP server");
    // The documented form: scheme + authority, no path at all.
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("fake server local_addr")
    );

    let server = tokio::spawn(async move { otel_sink::accept_and_serve(listener).await });

    // Production wiring — the same helper `init_tracing_otel` uses.
    let provider = frp_core::logging::build_otel_provider(&endpoint, "frp-rs-otel-path-test")
        .expect("build the OTLP tracer provider");
    let tracer = provider.tracer("frp-rs-otel-path-test");
    let subscriber =
        tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));

    tracing::subscriber::with_default(subscriber, || {
        // Must stay identical to `SPAN_NAME`: the macro needs a literal.
        let span = tracing::info_span!("otel_export_path_span");
        let _entered = span.enter();
    });

    // The batch processor waits on the tokio runtime, so drain it from the
    // blocking pool (see `otel_export.rs`).
    let flusher_provider = provider.clone();
    let flusher = tokio::task::spawn_blocking(move || {
        let flush = flusher_provider.force_flush();
        let shutdown = flusher_provider.shutdown();
        (flush, shutdown)
    });

    let request = server
        .await
        .expect("fake OTLP server task panicked: the span never reached the endpoint");

    // The assertion this test exists for. On the unfixed wiring the request
    // line is `POST / HTTP/1.1` (signalled by a 404 from a real collector; this
    // sink answers everything with 200, which is why the *path* is asserted
    // rather than a status code).
    assert!(
        request.head.starts_with("POST /v1/traces "),
        "a bare `otlp_endpoint` of {endpoint:?} must be exported to the OTLP/HTTP signal path \
         `/v1/traces`, but the exporter POSTed to:\n{}\n\
         (otlp 0.33 appends the signal path only to its own env/default endpoints, so the base \
         URL reaches `with_endpoint` verbatim unless frp-rs normalises it)",
        request.head
    );

    // The path is only half of it: the body must carry the span, framed as
    // OTLP `Span.name` (protobuf field 5, tag 0x2a, length-delimited).
    let framed_name = length_delimited_field(0x2a, SPAN_NAME.as_bytes());
    assert!(
        find(&request.body, &framed_name).is_some(),
        "the exported OTLP protobuf body ({} byte(s)) does not encode {SPAN_NAME:?} as protobuf \
         field 5 (`Span.name`); body:\n{:?}",
        request.body.len(),
        String::from_utf8_lossy(&request.body)
    );

    let (flush, shutdown) = match tokio::time::timeout(FLUSH_TIMEOUT, flusher).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => panic!("flush/shutdown task failed: {e}"),
        Err(_) => panic!("force_flush/shutdown did not finish within {FLUSH_TIMEOUT:?}"),
    };
    assert!(flush.is_ok(), "force_flush() failed: {flush:?}");
    assert!(shutdown.is_ok(), "shutdown() failed: {shutdown:?}");
}
