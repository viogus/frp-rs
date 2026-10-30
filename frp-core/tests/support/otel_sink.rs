//! Fake OTLP/HTTP sink shared by the `otel_export*` integration tests.
//!
//! It reads **exactly one** HTTP request off the wire and hands it back
//! unparsed — head and body as the exporter sent them. The body is checked as
//! bytes on purpose: a decode helper (or the proto crate) would have to be
//! trusted to prove that what went over the wire is what was recorded, and an
//! empty or truncated export is the very bug these tests exist to catch.
//!
//! Each test binary `mod`s this file with
//! `#[path = "support/otel_sink.rs"] mod otel_sink;`; the tests that do not use
//! every helper are not errors here.
#![allow(dead_code)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long to wait for the exporter to connect. Short on purpose: a broken
/// wiring must fail the suite quickly rather than hang it.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-read timeout while the fake server parses the request.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// One HTTP request as the fake OTLP server saw it on the wire.
pub struct CapturedRequest {
    /// Request line + headers.
    pub head: String,
    /// Exactly `content-length` body bytes.
    pub body: Vec<u8>,
}

#[path = "otel_wire.rs"]
mod wire;

// Re-exported so the tests that `#[path]`-include this module keep a
// single import site for the decoder.
pub use wire::{content_length, find, length_delimited_field};

/// Read exactly one HTTP request off `sock`, answer it, and return what was
/// seen. The body is read to `content-length` (the exporter sends a fixed-size
/// protobuf payload, so there is no chunked encoding to handle); a missing
/// length, a truncated body or a read error is a test failure, not something
/// the assertions downstream should have to guess at.
pub async fn serve_one_request(mut sock: tokio::net::TcpStream) -> CapturedRequest {
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

/// Accept the exporter's connection (within [`ACCEPT_TIMEOUT`]) and serve it.
///
/// Panics with the diagnostic the tests depend on when no connection arrives:
/// that is the observable shape of "the span was never exported".
pub async fn accept_and_serve(listener: TcpListener) -> CapturedRequest {
    let accepted = tokio::time::timeout(ACCEPT_TIMEOUT, listener.accept()).await;
    let sock = match accepted {
        Ok(Ok((sock, _peer))) => sock,
        Ok(Err(e)) => panic!("fake OTLP server: accept failed: {e}"),
        Err(_) => panic!(
            "no connection reached the OTLP endpoint within {ACCEPT_TIMEOUT:?}: the batch span \
             processor never exported the span"
        ),
    };
    serve_one_request(sock).await
}
