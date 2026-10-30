//! Integration test: spans recorded shortly before the daemon exits must still
//! reach the OTLP endpoint, with **no explicit flush** by the caller.
//!
//! Defect this pins: `init_tracing_otel` `Box::leak`ed the `SdkTracerProvider`
//! on both wiring branches, so nothing owned it, nothing called
//! `force_flush`/`shutdown`, and the process died with the last batch still
//! queued in the batch processor (its first periodic export is measured at
//! 10.006 s on the SDK defaults).
//! `frp-core/tests/otel_export.rs` never noticed because it flushes by hand.
//!
//! This test drives the *production* entry point — `init_tracing_otel`, with
//! the endpoint the daemons pass — then records and closes a span, calls
//! `frp_core::logging::shutdown_otel()` (what both daemons now call on their
//! exit path), and only then asserts the sink saw the span. It runs inside a
//! multi-thread tokio runtime, like production, which is what proves the
//! shutdown cannot deadlock against the batch task it is waiting for.
//!
//! "Eventually arrived" is not the claim. Because this test process keeps
//! running after the call, a leaked provider would still get the span out on
//! the batch processor's next periodic export tick — so the assertion is on
//! *how long* it took: a flush reaches the endpoint in milliseconds, the first
//! periodic export only after its measured 10.006 s (SDK defaults), which is
//! longer than a real daemon lives after `Service::run` returns. See
//! `FLAKE_ENVELOPE` for the one way this bound can be fooled.
//!
//! One init case per test binary: the global subscriber is once-per-process.
//! The second `shutdown_otel()` at the end pins idempotence (a second call must
//! be a no-op, not a second `shutdown()` on an already-shut-down provider).
#![cfg(feature = "otel")]

#[path = "support/otel_sink.rs"]
mod otel_sink;

use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use otel_sink::{find, length_delimited_field};

/// The `tracing` span name; it must survive into the exported OTLP `Span.name`
/// bytes.
const SPAN_NAME: &str = "otel_export_shutdown_span";

/// Upper bound on "record → span on the wire".
///
/// The batch processor's first periodic export is measured at 10.006 s on the
/// SDK defaults (it is not the scheduled 5 s delay: the stream skips a tick),
/// so a flush and a tick are three orders of magnitude apart. `FLAKE_ENVELOPE`:
/// this bound is only fooled if more than ~8 s elapse between provider
/// construction (which starts the timer) and the span being recorded, which
/// would let a tick land inside the window; nothing between the two does more
/// than allocate.
const FLAKE_ENVELOPE: Duration = Duration::from_secs(2);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_otel_flushes_spans_recorded_just_before_exit() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the fake OTLP server");
    // The endpoint carries the signal path explicitly: the base-URL form is
    // pinned by `tests/otel_export_path.rs`, and mixing the two defects here
    // would make a failure ambiguous.
    let endpoint = format!(
        "http://{}/v1/traces",
        listener.local_addr().expect("fake server local_addr")
    );

    // Stamped before the provider exists, so the measurement below covers
    // provider construction, span recording and shutdown — i.e. everything that
    // stands between "a span exists" and "the endpoint has it".
    let clock = Instant::now();
    let server = tokio::spawn(async move {
        let request = otel_sink::accept_and_serve(listener).await;
        (request, clock.elapsed())
    });

    // The daemons' wiring, exactly: `file: None` keeps this to the fmt layer on
    // stdout (the else branch of `init_tracing_otel`, which is one of the two
    // sites that used to leak the provider).
    frp_core::logging::init_tracing_otel(
        "info",
        None,
        0,
        "text",
        false,
        "frp-rs-otel-shutdown-test",
        Some(endpoint),
        "frpc.log",
    );

    // One span, created and closed. No `force_flush`, no `shutdown` on a local
    // provider: `shutdown_otel()` is the only thing that can get it out.
    // Must stay identical to `SPAN_NAME`: the macro needs a literal.
    {
        let span = tracing::info_span!("otel_export_shutdown_span");
        let _entered = span.enter();
    }

    // Call it from inside the runtime, like `frps`/`frpc`'s `#[tokio::main]`
    // exit path does. A blocking wait that starves the batch task would hang
    // here; `block_in_place` is what keeps the task polled.
    frp_core::logging::shutdown_otel();

    let (request, exported_at) = server.await.expect(
        "fake OTLP server task panicked: the span recorded before the exit path never reached \
         the endpoint",
    );

    // The requirement, stated as the daemon experiences it: had this been a real
    // `frps`/`frpc`, the process would be gone in milliseconds. A span that
    // arrives later than `FLAKE_ENVELOPE` was still queued when a real process
    // would have exited, which is exactly the defect (`Box::leak` → no flush on
    // exit).
    assert!(
        exported_at < FLAKE_ENVELOPE,
        "the span took {exported_at:?} to reach the endpoint after `shutdown_otel()` was called, \
         but a flush delivers in milliseconds and the batch processor's first periodic export — \
         the only thing that could have exported it instead — is measured at 10.006 s on the SDK \
         defaults. A real daemon is long gone by then, so this span would have been lost: the \
         provider must be owned by the process (not `Box::leak`ed) and flushed on the exit path"
    );

    assert!(
        request.head.starts_with("POST /v1/traces "),
        "expected the shutdown flush to POST to /v1/traces, got:\n{}",
        request.head
    );
    let framed_name = length_delimited_field(0x2a, SPAN_NAME.as_bytes());
    assert!(
        find(&request.body, &framed_name).is_some(),
        "the shutdown flush exported a body ({} byte(s)) that does not encode {SPAN_NAME:?} as \
         protobuf field 5 (`Span.name`); body:\n{:?}",
        request.body.len(),
        String::from_utf8_lossy(&request.body)
    );

    // Idempotence: the provider was moved out of the process-wide holder, so
    // the second call is a no-op rather than `AlreadyShutdown` or a panic — and
    // it must return promptly.
    let started = Instant::now();
    frp_core::logging::shutdown_otel();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a second shutdown_otel() must be a no-op, but it took {:?}",
        started.elapsed()
    );
}
