//! Regression test: WS-over-TLS data-plane stall (lost wakeup).
//!
//! Real-world signature: frpc `transport_protocol = "websocket"` (or "wss")
//! with TLS enabled, work conn bridges zero bytes; the client parks with
//! data sitting in its kernel Recv-Q and the server blocks on the TLS write
//! window. Plain WS (no TLS) sustains ~11 MB/s; plain TCP+TLS sustains
//! 40-150 MB/s. Only WsByteStream-over-TLS stalled.
//!
//! Root cause: WsByteStream's frame reader returned `Poll::Pending` after an
//! inner `Ready(partial)` read without registering any waker. Over plain TCP
//! the socket's readiness re-arming masks this; over TLS the inner
//! (tokio-rustls) serves reads from buffered plaintext and returns Ready
//! without touching the socket, so the caller parks with nothing registered
//! and nothing will ever wake it. Fix: `wake_by_ref()` before returning
//! Pending when the inner made progress.
//!
//! This test isolates the shared stack: a TLS socketpair, WsByteStream on
//! both ends, a server-side write burst (small head frame + continuous
//! 32 KiB frames, like the frps bridge writing StartWorkConn then data),
//! and a concurrent client reader. Without the fix the reader times out at
//! exactly the head frame's byte count; with it, everything arrives and the
//! clean shutdown (TLS close_notify) reads as EOF.

#![cfg(all(feature = "tls", feature = "websocket"))]

use std::net::TcpStream as StdTcpStream;
use std::sync::Arc;
use std::time::Duration;

use frp_core::transport::WsByteStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const HEAD_LEN: usize = 91; // StartWorkConn-sized head frame
const FRAME_LEN: usize = 32768; // bridge copy chunk
const TOTAL_FRAMES: usize = 320; // ~10 MB total

#[tokio::test(flavor = "multi_thread")]
async fn ws_over_tls_burst_does_not_stall() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client_std = StdTcpStream::connect(addr).expect("connect");
    let (server_std, _) = listener.accept().expect("accept");
    server_std.set_nonblocking(true).expect("nonblocking");
    client_std.set_nonblocking(true).expect("nonblocking");
    let server_tcp = tokio::net::TcpStream::from_std(server_std).expect("from_std");
    let client_tcp = tokio::net::TcpStream::from_std(client_std).expect("from_std");

    let server_cfg = frp_core::transport::generate_self_signed_tls_config().expect("server cfg");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let connector = frp_core::transport::build_tls_connector_skip_verify(None, None, None, true)
        .expect("connector");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("sni");

    let server_handle = tokio::spawn(async move {
        let tls = acceptor.accept(server_tcp).await.expect("tls accept");
        let mut ws = WsByteStream::from_raw(Box::new(tls), false); // server mode
        let head = vec![0x11u8; HEAD_LEN];
        ws.write_all(&head).await.expect("write head");
        let data = vec![0xABu8; FRAME_LEN];
        for i in 0..TOTAL_FRAMES {
            ws.write_all(&data).await.expect("write frame");
            // Pace every 16 frames (~512 KiB) so the client's kernel never
            // fills: this test targets the READ-side stall, and continuous
            // backpressure would trip the separate server-side
            // partial-write duplicate-frame bug (fixed on another branch).
            if i % 16 == 15 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        ws.flush().await.expect("flush");
        // Close the write half so the client sees a clean EOF after the last
        // frame (TLS close_notify → Ok(0) on the client read).
        ws.shutdown().await.expect("shutdown");
    });

    let client_handle = tokio::spawn(async move {
        let tls = connector
            .connect(server_name, client_tcp)
            .await
            .expect("tls connect");
        let mut ws = WsByteStream::from_raw(Box::new(tls), true); // client mode
        let mut total = 0usize;
        let mut buf = vec![0u8; FRAME_LEN];
        loop {
            match timeout(Duration::from_secs(5), ws.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => total += n,
                Ok(Err(e)) => panic!("read error: {e}"),
                Err(_) => panic!("STALLED: read timeout, total={total} bytes"),
            }
        }
        assert_eq!(total, HEAD_LEN + FRAME_LEN * TOTAL_FRAMES);
    });

    let (s, c) = tokio::join!(server_handle, client_handle);
    s.expect("server task");
    c.expect("client task");
}
