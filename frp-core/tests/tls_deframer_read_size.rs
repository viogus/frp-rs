//! Regression test for the second vendored rustls patch
//! (frp-rs `[patch.crates-io]` → `vendor/rustls`).
//!
//! Upstream rustls 0.23 reads from the transport in 4 KiB steps
//! (`DeframerVecBuffer::prepare_read`, `const READ_SIZE: usize = 4096`) and
//! shrinks the buffer back to that size whenever it empties, so a 16 KiB
//! application record costs four reads and its pages are re-faulted for every
//! record. The vendored patch sets `READ_SIZE` to `MAX_WIRE_SIZE` (18 437 B),
//! i.e. one read per record. Profiling put `Vec::<u8>::resize` from this crate
//! at 16.9% of frpc's samples before the patch (see
//! `docs/archive/notes/2026-11-11-tls-record-read-size.md`).
//!
//! The observable difference is how many bytes the deframer asks the transport
//! for, so this test drives a real `ClientConnection` and records the length of
//! the first read request. No handshake or certificate is needed: the deframer
//! prepares its buffer before any record is parsed.
//!
//! If a future rustls sizes the read from the record it is waiting for, this
//! test will fail on a *legitimate* change — that is the signal to drop the
//! patch (it is the documented exit condition), not to loosen the assertion.

#![cfg(feature = "tls")]

use std::io::{self, Read};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::RootCertStore;

/// Records the largest buffer the TLS stack asked for, then reports EOF.
struct ReadProbe {
    largest_request: usize,
}

impl Read for ReadProbe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.largest_request = self.largest_request.max(buf.len());
        Ok(0)
    }
}

fn client_connection() -> ClientConnection {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    ClientConnection::new(
        Arc::new(config),
        "frp.test".try_into().expect("valid DNS name"),
    )
    .expect("client connection")
}

#[test]
fn deframer_asks_for_a_whole_record_per_read() {
    let mut conn = client_connection();
    let mut probe = ReadProbe { largest_request: 0 };

    // EOF is an error, and irrelevant: the request size is what is under test.
    let _ = conn.read_tls(&mut probe);

    // Upstream asks for 4096. The patched tree asks for MAX_WIRE_SIZE (18437),
    // which is what makes a 16 KiB record one read instead of four.
    assert!(
        probe.largest_request > 4096,
        "the vendored rustls `READ_SIZE` patch is missing: the deframer asked \
         for {} bytes, which is the upstream 4 KiB window. Re-apply the patch \
         in vendor/rustls/src/msgs/deframer/buffers.rs (see \
         vendor/rustls/README-FRP-RS.md), or, if upstream now sizes the read \
         from the pending record, drop the patch and delete this test.",
        probe.largest_request
    );
    assert!(
        probe.largest_request <= 64 * 1024,
        "the deframer asked for {} bytes, more than a handshake record; the \
         vendored `READ_SIZE` patch looks wrong",
        probe.largest_request
    );
}
