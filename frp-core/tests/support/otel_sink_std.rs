//! A blocking OTLP/HTTP sink for tests that spawn a real frp binary.
//!
//! The async sink in `otel_sink.rs` needs a tokio test runtime; the daemon
//! tests drive a child process from a plain `#[test]` and only join a channel
//! afterwards, so they use this one. It accepts one connection, answers every
//! request on it with an empty `200` (the exporter keeps the connection alive
//! between exports), and sends back what it parsed once the peer closes or a
//! read times out.
//!
//! Each test binary includes this file with
//! `#[path = "../../frp-core/tests/support/otel_sink_std.rs"] mod otel_sink;`
//! (adjust the prefix for the crate it lives in); helpers this test does not
//! use are not errors here.

#![allow(dead_code)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[path = "otel_wire.rs"]
mod wire;

pub use wire::{content_length, find, length_delimited_field};

/// How long the sink waits for the exporter to connect before giving up and
/// reporting an empty list, so a missing flush fails the test instead of
/// hanging the suite.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// One OTLP/HTTP request as the sink saw it.
pub struct Request {
    pub head: String,
    pub body: Vec<u8>,
}

/// An ephemeral port, released immediately: `bindPort = 0` is not "any port"
/// in frp-rs (it normalises to the default 7000), so a daemon test needs a
/// concrete free port.
pub fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
    probe.local_addr().expect("probe local_addr").port()
}

/// A throwaway OTLP/HTTP sink on an ephemeral port.
pub fn otlp_sink() -> (SocketAddr, mpsc::Receiver<Vec<Request>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the fake OTLP server");
    let addr = listener.local_addr().expect("sink local_addr");
    listener
        .set_nonblocking(true)
        .expect("non-blocking accept on the sink");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let accept_deadline = Instant::now() + ACCEPT_TIMEOUT;
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
