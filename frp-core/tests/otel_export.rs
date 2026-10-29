//! Integration test: a span recorded through frp-rs's production `otel` wiring
//! must actually be **exported over HTTP** to the configured OTLP endpoint.
//!
//! This is a regression test for the 0.33 migration, which replaced
//! `with_batch_exporter(exporter, runtime::Tokio)` with
//! `with_batch_exporter(exporter)`. The latter selects the *thread*-based
//! `BatchSpanProcessor`, whose worker drives the exporter with
//! `futures_executor::block_on` on a plain OS thread. The `hyper-client` OTLP
//! exporter then panics on that thread —
//!
//! ```text
//! panicked at opentelemetry-http-0.33.1/src/lib.rs:330:13:
//! there is no reactor running, must be called from the context of a Tokio 1.x runtime
//! ```
//!
//! — the processor thread dies, and every span is silently dropped. Nothing in
//! the old test suite noticed: the wiring compiled, `build_otel_layer` returned
//! `Ok`, and no test ever looked at the wire.
//!
//! So this test stands up a fake OTLP/HTTP server, builds the provider with the
//! production helper (`frp_core::logging::build_otel_provider`, the same code
//! `init_tracing_otel` uses), records and closes one span, flushes, and asserts
//! that the server received an HTTP `POST /v1/traces`. On the broken wiring the
//! connection never arrives; on the fix (an async-runtime `BatchSpanProcessor`
//! spawned on the ambient tokio runtime) it does.
//!
//! The assertion is deliberately about the *request*, not the exporter's
//! verdict: the fake server answers with an empty protobuf body, and an export
//! error after the request has been sent is not what this test is pinning.
#![cfg(feature = "otel")]

use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing_subscriber::layer::SubscriberExt as _;

/// How long to wait for the exporter to connect. Short on purpose: a broken
/// wiring must fail the suite quickly rather than hang it.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-read timeout while the fake server parses the request.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on `force_flush` + `shutdown`; both block the calling thread.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// `content-length` of an HTTP/1.x request head, case-insensitively.
fn content_length(head: &str) -> Option<usize> {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then_some(value)
        })
        .and_then(|v| v.trim().parse().ok())
}

/// Read exactly one HTTP request off `sock`, answer it, and return the request
/// head (request line + headers) as text.
async fn serve_one_request(mut sock: tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;

    // Headers.
    let body_start = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        match tokio::time::timeout_at(deadline, sock.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                panic!("OTLP exporter closed the connection before sending request headers")
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => panic!("fake OTLP server: reading the request failed: {e}"),
            Err(_) => panic!("fake OTLP server: timed out reading the request headers"),
        }
    };
    let head = String::from_utf8_lossy(&buf[..body_start]).into_owned();

    // Body, so the exporter is not left writing into a closed socket while we
    // answer. Absent `content-length` (chunked) we just answer after the head.
    if let Some(len) = content_length(&head) {
        while buf.len() < body_start + len {
            match tokio::time::timeout_at(deadline, sock.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) | Err(_) => break,
            }
        }
    }

    // Minimal 200 with an empty (valid) protobuf `ExportTraceServiceResponse`.
    let _ = sock
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              content-type: application/x-protobuf\r\n\
              content-length: 0\r\n\
              \r\n",
        )
        .await;
    let _ = sock.flush().await;
    head
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn span_is_exported_over_http_to_the_otlp_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the fake OTLP server");
    let endpoint = format!(
        // `with_endpoint` is used verbatim as the HTTP request URI (otlp 0.33
        // only appends the signal path for the env-var/default endpoints), so
        // the signal path is part of the endpoint here — exactly as frp's
        // `observability.otlp_endpoint` / `OTEL_EXPORTER_OTLP_ENDPOINT` value is
        // consumed.
        "http://{}/v1/traces",
        listener.local_addr().expect("fake server local_addr")
    );

    let server = tokio::spawn(async move {
        let accepted = tokio::time::timeout(ACCEPT_TIMEOUT, listener.accept()).await;
        let sock = match accepted {
            Ok(Ok((sock, _peer))) => sock,
            Ok(Err(e)) => panic!("fake OTLP server: accept failed: {e}"),
            Err(_) => panic!(
                "no connection reached the OTLP endpoint within {ACCEPT_TIMEOUT:?}: the batch span \
                 processor never exported the span (this is the 0.33 thread-based-processor bug — \
                 its worker panics with \"there is no reactor running\")"
            ),
        };
        serve_one_request(sock).await
    });

    // Production wiring: the same helper `init_tracing_otel` builds the
    // provider with when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
    let provider = frp_core::logging::build_otel_provider(&endpoint, "frp-rs-otel-export-test")
        .expect("build the OTLP tracer provider");
    let tracer = provider.tracer("frp-rs-otel-export-test");
    let subscriber =
        tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));

    // One span, created and closed on this thread. `with_default` keeps the
    // subscriber thread-local, so nothing leaks into other tests.
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("otel_export_regression_span");
        let _entered = span.enter();
    });

    // `force_flush`/`shutdown` block the calling thread until the batch task
    // answers, so run them on the blocking pool and keep the runtime free to
    // poll the processor task.
    let flusher_provider = provider.clone();
    let flusher = tokio::task::spawn_blocking(move || {
        let flush = flusher_provider.force_flush();
        let shutdown = flusher_provider.shutdown();
        (flush, shutdown)
    });

    let head = server.await.expect("fake OTLP server task panicked");
    assert!(
        head.starts_with("POST /v1/traces "),
        "expected the OTLP exporter to POST to /v1/traces, got:\n{head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/x-protobuf"),
        "expected a protobuf OTLP payload, got:\n{head}"
    );

    match tokio::time::timeout(FLUSH_TIMEOUT, flusher).await {
        Ok(Ok((flush, shutdown))) => {
            assert!(
                shutdown.is_ok(),
                "provider shutdown reported an error: {shutdown:?}"
            );
            // The export itself may still report an error (the fake server's
            // answer is minimal); the request above is what this test pins.
            let _ = flush;
        }
        Ok(Err(e)) => panic!("flush/shutdown task failed: {e}"),
        Err(_) => panic!("force_flush/shutdown did not finish within {FLUSH_TIMEOUT:?}"),
    }
}
