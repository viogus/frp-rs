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
//! (a) that the server received an HTTP `POST /v1/traces` with a protobuf
//! content type, (b) that the *body* the server read — exactly `content-length`
//! bytes — contains the span name as the raw bytes of OTLP `Span.name`
//! (protobuf field 5, length-delimited), and (c) that `force_flush()` returned
//! `Ok(())`, i.e. the batch processor answered with the exporter's verdict
//! rather than merely "a connection arrived". On the broken wiring the
//! connection never arrives at all; on the fix (an async-runtime
//! `BatchSpanProcessor` spawned on the ambient tokio runtime) the body carries
//! the span.
//!
//! The body is checked as bytes on purpose: a decode helper (or the proto
//! crate) would have to be trusted to prove that what went over the wire is
//! what was recorded, and an empty or truncated export would be the very bug
//! this test exists to catch.
#![cfg(feature = "otel")]

use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing_subscriber::layer::SubscriberExt as _;

/// The `tracing` span name; it must survive into the exported OTLP `Span.name`
/// bytes (see the module docs).
const SPAN_NAME: &str = "otel_export_regression_span";

/// How long to wait for the exporter to connect. Short on purpose: a broken
/// wiring must fail the suite quickly rather than hang it.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-read timeout while the fake server parses the request.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on `force_flush` + `shutdown`; both block the calling thread.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// One HTTP request as the fake OTLP server saw it on the wire.
struct CapturedRequest {
    /// Request line + headers.
    head: String,
    /// Exactly `content-length` body bytes.
    body: Vec<u8>,
}

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

/// Encode a protobuf length-delimited field. `tag` is the already-composed
/// field-number/wire-type byte; only one-byte lengths are needed here (the
/// span name is 27 bytes), which keeps the helper allocation-free and obvious.
fn length_delimited_field(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(
        value.len() < 0x80,
        "test helper only handles one-byte field lengths, got {}",
        value.len()
    );
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}

/// Read exactly one HTTP request off `sock`, answer it, and return what was
/// seen. The body is read to `content-length` (the exporter sends a fixed-size
/// protobuf payload, so there is no chunked encoding to handle); a missing
/// length, a truncated body or a read error is a test failure, not something
/// the assertions downstream should have to guess at.
async fn serve_one_request(mut sock: tokio::net::TcpStream) -> CapturedRequest {
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

    // Body: read exactly what `content-length` promised so the span-name
    // assertion cannot pass on a partial payload.
    let len = content_length(&head).unwrap_or_else(|| {
        panic!(
            "the OTLP export request carries no content-length, so its body cannot be \
             delimited (chunked encoding is not expected from this exporter); request was:\n{head}"
        )
    });
    let body_end = body_start + len;
    while buf.len() < body_end {
        match tokio::time::timeout_at(deadline, sock.read(&mut chunk)).await {
            Ok(Ok(0)) => panic!(
                "the OTLP export request body is truncated: content-length says {len} byte(s), \
                 but the connection closed after {} byte(s): {:?}",
                buf.len() - body_start,
                String::from_utf8_lossy(&buf[body_start..])
            ),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => panic!("fake OTLP server: reading the export body failed: {e}"),
            Err(_) => panic!(
                "timed out reading the OTLP export body: content-length says {len} byte(s), \
                 but only {} byte(s) arrived",
                buf.len() - body_start
            ),
        }
    }
    let body = buf[body_start..body_end].to_vec();

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
    CapturedRequest { head, body }
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
        // Must stay identical to `SPAN_NAME`: the macro needs a literal, and
        // the assertions below hold the exported bytes to that constant.
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

    let request = server.await.expect("fake OTLP server task panicked");
    assert!(
        request.head.starts_with("POST /v1/traces "),
        "expected the OTLP exporter to POST to /v1/traces, got:\n{}",
        request.head
    );
    assert!(
        request
            .head
            .to_ascii_lowercase()
            .contains("content-type: application/x-protobuf"),
        "expected a protobuf OTLP payload, got:\n{}",
        request.head
    );

    // The wire body, not a decode of it: OTLP encodes `Span.name` as a
    // length-delimited protobuf string, so the name appears verbatim.
    let name_bytes = SPAN_NAME.as_bytes();
    assert!(
        !request.body.is_empty(),
        "the OTLP export request carried an empty body (content-length resolved to 0), so no \
         span was exported; request was:\n{}",
        request.head
    );
    assert!(
        find(&request.body, name_bytes).is_some(),
        "the exported OTLP protobuf body ({} byte(s)) does not contain the span name {SPAN_NAME:?} \
         as raw bytes; body:\n{:?}",
        request.body.len(),
        String::from_utf8_lossy(&request.body)
    );
    // Stronger than "the literal appears somewhere": the occurrences must be
    // framed as protobuf field 5 (`Span.name`) wire type 2, i.e. tag byte
    // (5 << 3) | 2 = 0x2a followed by the name's length. This rejects an
    // incidental copy of the name (attribute value, scope name) standing in
    // for the span itself.
    let framed_name = length_delimited_field(0x2a, name_bytes);
    assert!(
        find(&request.body, &framed_name).is_some(),
        "the exported OTLP protobuf body ({} byte(s)) does not encode {SPAN_NAME:?} as protobuf \
         field 5 (`Span.name`, tag 0x2a, length-delimited); body:\n{:?}",
        request.body.len(),
        String::from_utf8_lossy(&request.body)
    );

    let (flush, shutdown) = match tokio::time::timeout(FLUSH_TIMEOUT, flusher).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => panic!("flush/shutdown task failed: {e}"),
        Err(_) => panic!("force_flush/shutdown did not finish within {FLUSH_TIMEOUT:?}"),
    };
    // `Ok(())` means the batch processor answered *and* the exporter's verdict
    // was success — the request above arrived and the server's response was
    // accepted. A request that arrived while the export failed is not the fix
    // this test pins.
    assert!(
        flush.is_ok(),
        "provider.force_flush() must return Ok(()) once the batch processor has drained and the \
         exporter has accepted the server's response, got: {flush:?}"
    );
    assert!(
        shutdown.is_ok(),
        "provider.shutdown() reported an error: {shutdown:?}"
    );
}
