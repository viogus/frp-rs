use super::*;

#[test]
fn ws_frame_cap_covers_v2_aead_overhead() {
    // The transport frame cap must accept a full-size V2 frame plus the
    // AEAD overhead (tag + nonce), not just the plaintext cap.
    assert!(MAX_WS_FRAME_PAYLOAD >= crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128);
}

/// Real TCP socket pair (bind 127.0.0.1:0, connect, accept) — the
/// server-mode zero-copy fast path requires a raw TcpStream as the
/// innermost transport, so duplex streams won't exercise it.
async fn tcp_socket_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

/// All three server-mode header encodings (2/4/10 bytes) must be
/// byte-exact RFC 6455 unmasked frames.
#[test]
fn ws_server_frame_header_encoding() {
    let mut hdr = [0u8; 10];
    assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 0), 2);
    assert_eq!(&hdr[..2], &[0x82, 0]);
    assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 125), 2);
    assert_eq!(&hdr[..2], &[0x82, 125]);
    assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 126), 4);
    assert_eq!(&hdr[..4], &[0x82, 126, 0x00, 126]);
    assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 65535), 4);
    assert_eq!(&hdr[..4], &[0x82, 126, 0xff, 0xff]);
    assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 65536), 10);
    assert_eq!(&hdr[..10], &[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
}

/// MANDATORY frame-correctness check for the server-mode zero-copy
/// poll_write_vectored fast path: a WsByteStream over a real TcpStream
/// pair must emit the exact RFC 6455 unmasked server frame and report the
/// payload length as written. Covers the 2-byte header path (payload
/// < 126) and the 4-byte header path (126 <= payload <= 65535). The peer
/// reads concurrently so the frame reaches it even if the write splits.
#[tokio::test]
async fn ws_server_mode_fast_path_emits_exact_frames() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 2-byte header path: payload < 126.
    let (mut client, server) = tcp_socket_pair().await;
    let mut ws = WsByteStream::from_raw(Box::new(IoStream::Tcp(server)), false);
    let small = vec![0x11u8; 100];
    let mut expected = vec![0x82, small.len() as u8];
    expected.extend_from_slice(&small);
    let expect_len = expected.len();
    let reader = tokio::spawn(async move {
        let mut got = vec![0u8; expect_len];
        client.read_exact(&mut got).await.unwrap();
        got
    });
    let n = ws.write(&small).await.unwrap();
    assert_eq!(
        n,
        small.len(),
        "write must report the payload bytes, not the frame bytes"
    );
    let got = reader.await.unwrap();
    assert_eq!(&got, &expected, "peer must see the unmasked server frame");

    // 4-byte header path: 126 <= payload <= 65535.
    let (mut client, server) = tcp_socket_pair().await;
    let mut ws = WsByteStream::from_raw(Box::new(IoStream::Tcp(server)), false);
    let big = vec![0x22u8; 1000];
    let mut expected = vec![0x82, 126];
    expected.extend_from_slice(&(big.len() as u16).to_be_bytes());
    expected.extend_from_slice(&big);
    let expect_len = expected.len();
    let reader = tokio::spawn(async move {
        let mut got = vec![0u8; expect_len];
        client.read_exact(&mut got).await.unwrap();
        got
    });
    let n = ws.write(&big).await.unwrap();
    assert_eq!(n, big.len());
    let got = reader.await.unwrap();
    assert_eq!(&got, &expected, "peer must see the unmasked server frame");
}

/// Go frps may send the first WS frame in the same TCP segment as the
/// HTTP 101 response. The client must parse the frame instead of
/// exposing frame bytes as application bytes.
#[tokio::test]
async fn ws_client_parses_pipelined_frame_after_upgrade() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut server) = tokio::io::duplex(8192);
    let payload: &[u8] = b"hello-from-go-frps";
    let mut frame = vec![0x82u8, payload.len() as u8]; // FIN + BINARY
    frame.extend_from_slice(payload);

    let server_task = tokio::spawn(async move {
        // Consume the upgrade request up to the blank line.
        let mut req = vec![0u8; 4096];
        let mut total = 0usize;
        let mut client_key: Option<String> = None;
        loop {
            let n = server.read(&mut req[total..]).await.expect("read request");
            assert!(n > 0, "client closed before request completed");
            total += n;
            if req[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        // Extract the client's Sec-WebSocket-Key so the Accept header
        // can be computed (connect_ws_raw verifies it).
        let req_text = String::from_utf8_lossy(&req[..total]);
        for line in req_text.lines() {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("sec-websocket-key") {
                    client_key = Some(value.trim().to_string());
                }
            }
        }
        let client_key = client_key.expect("client Sec-WebSocket-Key header");
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(client_key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = super::super::base64_encode(&hasher.finalize());
        // 101 response + first WS frame in a single segment.
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             \r\n"
        );
        server.write_all(resp.as_bytes()).await.expect("write 101");
        server
            .write_all(&frame)
            .await
            .expect("write pipelined frame");
    });

    let mut io = super::super::connect_ws_raw(
        client,
        "example.com",
        7000,
        super::super::FRP_WEBSOCKET_PATH,
        "http",
    )
    .await
    .expect("ws upgrade");

    let mut buf = [0u8; 64];
    let n = io.read(&mut buf).await.expect("read ws payload");
    assert_eq!(
        &buf[..n],
        payload,
        "read must return the frame payload only, got: {:?}",
        &buf[..n]
    );
    server_task.await.expect("server task");
}

fn ws_binary_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x82];
    if payload.len() <= 125 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// Like [`ws_binary_frame`] but masked — what a compliant client sends
/// to the server (RFC 6455 §5.3). Server-mode `WsByteStream`s enforce
/// the mask direction, so tests feeding frames INTO a server-mode
/// stream must mask them.
fn ws_masked_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x82];
    let mask: [u8; 4] = rand::random();
    if payload.len() <= 125 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    frame
}

/// Zero-length BINARY frame with the mask bit set (client-mode wire
/// shape), for server-mode streams.
fn ws_masked_zero_frame() -> Vec<u8> {
    let mask: [u8; 4] = rand::random();
    let mut frame = vec![0x82, 0x80];
    frame.extend_from_slice(&mask);
    frame
}

/// Zero-length data frames must be consumed without surfacing a 0-byte
/// read (which tokio treats as EOF and would tear the tunnel down).
/// A zero-length frame followed by a real frame must deliver the real
/// frame's payload.
#[tokio::test]
async fn ws_zero_length_frame_is_swallowed_not_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut server_io, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

    // Zero-length BINARY frame, then a real frame. Masked: the stream
    // is server-mode and enforces RFC 6455 mask direction (L16).
    server_io.write_all(&ws_masked_zero_frame()).await.unwrap();
    let payload = b"after-zero-frame";
    server_io
        .write_all(&ws_masked_frame(payload))
        .await
        .unwrap();

    let mut out = vec![0u8; payload.len() + 1];
    let n = ws.read(&mut out).await.unwrap();
    assert_eq!(
        n,
        payload.len(),
        "zero-length frame must not surface as EOF; got {n} bytes"
    );
    assert_eq!(&out[..n], payload);

    // A second zero-length frame (through the extended-length path too:
    // masked 0x82 with extended length 0) must behave the same. Wire
    // order for a masked frame is header, extended length, THEN mask key
    // (RFC 6455 §5.2): [0x82, 0xFE, 0x00, 0x00, mask..4].
    let mut ext_zero = vec![0x82, 0x80 | 126, 0, 0];
    ext_zero.extend_from_slice(&ws_masked_zero_frame()[2..6]);
    server_io.write_all(&ext_zero).await.unwrap();
    let payload2 = b"second-payload";
    server_io
        .write_all(&ws_masked_frame(payload2))
        .await
        .unwrap();
    let n2 = ws.read(&mut out).await.unwrap();
    assert_eq!(n2, payload2.len());
    assert_eq!(&out[..n2], payload2);
}

/// Masked frame with an arbitrary (possibly reserved) opcode — the wire
/// shape a broken peer sends to a server-mode stream (mask bit set per
/// RFC 6455 §5.3, payload ≤ 125).
fn ws_masked_opcode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask: [u8; 4] = rand::random();
    let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    frame
}

/// GAP9: reserved opcodes must fail closed as a protocol error — never
/// swallowed, forwarded, or left hanging (RFC 6455 §5.5: "All other
/// opcodes [...] are reserved for future use and MUST NOT be used [...]
/// treated as a protocol error"). One reserved non-control (0x3) and one
/// reserved control (0xb) shape.
#[tokio::test]
async fn ws_reserved_opcode_is_protocol_error() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    for opcode in [0x03u8, 0x0b] {
        let (mut server_io, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
        server_io
            .write_all(&ws_masked_opcode_frame(opcode, &[0x61]))
            .await
            .unwrap();
        let err = timeout(Duration::from_secs(5), ws.read(&mut [0u8; 8]))
            .await
            .expect("reserved opcode must error, not hang")
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        let needle = format!("unexpected WS opcode: {opcode:#x}");
        assert!(
            msg.contains(&needle),
            "expected {needle:?} inside io error {msg:?}"
        );
    }
}

/// Round-15 finding: the `n == 0` stash arm of dispatch_raw_frame (caller
/// ReadBuf exactly full) had no coverage — a regression there (lost wake,
/// dropped stash) would silently stall the tunnel: poll_read returns
/// Pending after stashing the payload, and the next poll must deliver it
/// from read_buf. Drive poll_read directly with a zero-capacity ReadBuf
/// to hit the arm, then drain a ≥16 KiB payload through 32-byte buffers,
/// bounded by a timeout so a hang fails the test instead of parking it.
#[tokio::test]
async fn ws_readbuf_full_stash_delivers_payload_across_polls() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    let (mut server_io, client_io) = tokio::io::duplex(64 * 1024);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

    // Byte-distinct ≥16 KiB payload so truncation/duplication is caught.
    let payload: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
    server_io
        .write_all(&ws_masked_frame(&payload))
        .await
        .unwrap();

    // Poll 1 with a zero-capacity ReadBuf: the frame parses fully and
    // dispatch_raw_frame hits n == 0 → payload stashed, task woken,
    // Pending returned. Poll 2 (self-wake): stash present → Ready.
    // A lost wake parks this poll_fn forever — caught by the timeout.
    let mut empty = [0u8; 0];
    let mut zero_buf = ReadBuf::new(&mut empty);
    timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| Pin::new(&mut ws).poll_read(cx, &mut zero_buf)),
    )
    .await
    .expect("stash poll hung: wake lost in n == 0 arm")
    .expect("stash poll errored");
    assert_eq!(
        zero_buf.filled().len(),
        0,
        "zero-capacity ReadBuf must not be filled"
    );

    // Drain the stashed payload through 32-byte reads; all bytes must
    // arrive, nothing may hang or be dropped.
    let mut out = vec![0u8; payload.len()];
    let mut got = 0usize;
    while got < payload.len() {
        let mut chunk = [0u8; 32];
        let n = timeout(Duration::from_secs(5), ws.read(&mut chunk))
            .await
            .expect("read hung: stashed payload never delivered")
            .expect("read errored");
        assert!(n > 0, "stalled mid-payload after {got} bytes");
        out[got..got + n].copy_from_slice(&chunk[..n]);
        got += n;
    }
    assert_eq!(&out, &payload, "stashed payload must be byte-exact");
}

#[tokio::test]
async fn ws_raw_accepts_v2_sized_frames_and_rejects_oversized() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut server_io, client_io) = tokio::io::duplex(1024 * 1024);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

    // Between the old 14 KiB clamp and the V2 64 KiB cap: the WS
    // transport must accept it; V1 enforcement happens in protocol.rs.
    // Masked: the stream is server-mode and enforces RFC 6455 mask
    // direction (L16).
    let payload = vec![0x5a; 20 * 1024];
    server_io
        .write_all(&ws_masked_frame(&payload))
        .await
        .unwrap();
    let mut out = vec![0u8; payload.len()];
    let n = ws.read(&mut out).await.unwrap();
    assert_eq!(n, payload.len());
    assert_eq!(&out[..n], &payload[..]);

    // Exactly 64 KiB is the V2 limit and must pass the WS decoder.
    let big = vec![0x6b; 64 * 1024];
    server_io.write_all(&ws_masked_frame(&big)).await.unwrap();
    let mut big_out = vec![0u8; big.len()];
    let n2 = ws.read(&mut big_out).await.unwrap();
    assert_eq!(n2, big.len());
    assert_eq!(&big_out[..n2], &big[..]);

    // A V2 frame at the cap plus AEAD overhead (128 bytes) is accepted —
    // the transport must not clamp encrypted V2 frames below the cap.
    let aead_padded = vec![0x6c; 64 * 1024 + 128];
    server_io
        .write_all(&ws_masked_frame(&aead_padded))
        .await
        .unwrap();
    let mut padded_out = vec![0u8; aead_padded.len()];
    let n3 = ws.read(&mut padded_out).await.unwrap();
    assert_eq!(n3, aead_padded.len());
    assert_eq!(&padded_out[..n3], &aead_padded[..]);

    // One byte over the cap + AEAD overhead is rejected at the transport.
    let huge = vec![0x6c; 64 * 1024 + 129];
    server_io.write_all(&ws_masked_frame(&huge)).await.unwrap();
    let err = ws.read(&mut big_out).await.unwrap_err();
    assert!(
        err.to_string().contains("WS frame too large"),
        "unexpected error: {err}"
    );
}

/// AsyncRead+AsyncWrite stub returning `Ok(0)` for the first `zeros`
/// poll_write calls, then accepting everything — pins WriteZero handling
/// for a pathological inner transport.
struct ZeroThenSink {
    zeros: usize,
}

impl AsyncRead for ZeroThenSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ZeroThenSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.zeros > 0 {
            self.zeros -= 1;
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A partially-flushed frame whose inner writer returns `Ok(0)` must
/// surface as `WriteZero` on the continuation poll instead of self-waking
/// into an immediate-repoll 100% CPU spin.
#[test]
fn partial_frame_flush_ok_zero_is_write_zero() {
    let mut ws = WsByteStream::from_raw(Box::new(ZeroThenSink { zeros: 2 }), false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let buf = vec![0x5Au8; 32];

    // Poll 1: the fresh frame write hits Ok(0) → needs_flush, Pending.
    assert!(matches!(
        Pin::new(&mut ws).poll_write(&mut cx, &buf),
        Poll::Pending
    ));

    // Poll 2: the continuation flush hits Ok(0) on a non-empty remainder →
    // WriteZero error, not a self-wake → Pending spin.
    match Pin::new(&mut ws).poll_write(&mut cx, &buf) {
        Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
        other => panic!("expected WriteZero error, got {other:?}"),
    }
}

/// Same pathological-inner guard on the `poll_flush` continuation path.
#[test]
fn partial_frame_flush_ok_zero_in_poll_flush_is_write_zero() {
    let mut ws = WsByteStream::from_raw(Box::new(ZeroThenSink { zeros: 2 }), false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let buf = vec![0x5Au8; 32];

    // Prime a partial flush: fresh frame write hits Ok(0) → needs_flush.
    assert!(matches!(
        Pin::new(&mut ws).poll_write(&mut cx, &buf),
        Poll::Pending
    ));

    // The poll_flush continuation hits Ok(0) → WriteZero error.
    match Pin::new(&mut ws).poll_flush(&mut cx) {
        Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
        other => panic!("expected WriteZero error, got {other:?}"),
    }
}

/// AsyncWrite stub that accepts a fixed fraction of each write and counts
/// how often its flush is called, so a wrapper that swallows the flush is
/// detectable.
struct FlushCountingSink {
    flushes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    half: bool,
}

impl AsyncRead for FlushCountingSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FlushCountingSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = if self.half {
            (buf.len() / 2).max(1)
        } else {
            buf.len()
        };
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A TLS inner stream holds plaintext it has accepted but not yet written
/// until its own flush runs, so `WsByteStream::poll_flush` must always
/// reach the inner stream — even with no frame bytes left here. Returning
/// `Ready(Ok(()))` without it was the websocket + TLS stall: the last
/// record sat in the rustls buffer while both ends waited for data.
#[test]
fn flush_reaches_the_inner_stream_with_nothing_pending() {
    let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = FlushCountingSink {
        flushes: flushes.clone(),
        half: false,
    };
    let mut ws = WsByteStream::from_raw(Box::new(sink), false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(
        Pin::new(&mut ws).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(
        flushes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "poll_flush returned without flushing the inner stream"
    );
}

/// The same contract on the drain path: a partially written frame is
/// finished by `poll_flush`, and after the last byte the inner stream is
/// still flushed (a TLS inner needs that to push the record).
#[test]
fn flush_reaches_the_inner_stream_after_draining_a_partial_frame() {
    let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = FlushCountingSink {
        flushes: flushes.clone(),
        half: true,
    };
    let mut ws = WsByteStream::from_raw(Box::new(sink), false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let buf = vec![0x5Au8; 64];

    // The inner accepts only half of the frame, so the write parks with a
    // pending drain.
    assert!(matches!(
        Pin::new(&mut ws).poll_write(&mut cx, &buf),
        Poll::Pending
    ));

    // Drain to completion; the completing call must still flush the inner.
    let mut polls = 0;
    loop {
        match Pin::new(&mut ws).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => break,
            Poll::Pending => {
                polls += 1;
                assert!(polls < 32, "flush never completed");
            }
            Poll::Ready(Err(e)) => panic!("unexpected flush error: {e}"),
        }
    }
    assert_eq!(
        flushes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the drain path completed without exactly one flush of the inner stream"
    );
}

/// Regression test for the duplicate-frame bug: after a partial write,
/// the retained frame tail is drained to completion, and the caller's
/// re-polled buf (the SAME payload bytes) must be consumed — reported as
/// written — never re-sent as a fresh frame. The old code re-built a
/// frame from the re-polled buf after the drain completed, so the peer
/// received the payload twice (and for a buf larger than the socket
/// buffer, poll_write never returned Ok at all — the payload was re-sent
/// in an infinite duplicate loop).
///
/// Real TCP pair with a small SO_SNDBUF on the writer side: the first
/// writev of a multi-MiB frame can only accept a few KiB, so the partial
/// write → retention → drain → completion → re-poll sequence is hit
/// deterministically. The peer must receive EXACTLY ONE unmasked server
/// frame.
#[tokio::test]
async fn ws_partial_write_drain_does_not_duplicate_payload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    // Server side (the writer) gets a 2 KiB SO_SNDBUF — set on the
    // listening socket, which accepted sockets inherit on Linux; the
    // kernel doubles it to ~4-8 KiB effective, far below the 4 MiB
    // payload, so the first writev is always partial regardless of peer
    // read timing.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    sock.set_send_buffer_size(2048).unwrap();
    let listener = sock.listen(1).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mut ws = WsByteStream::from_raw(Box::new(IoStream::Tcp(server)), false);

    let payload = vec![0x5au8; 4 * 1024 * 1024];
    // 4 MiB > 65535 → 10-byte extended-length header (0x82, 127, u64 len).
    let expect_total = 10 + payload.len();
    let wire_payload = payload.clone();

    let writer = tokio::spawn(async move {
        // Note: with the pre-fix code this future NEVER completes — the
        // frame never fits the socket buffer, so poll_write keeps
        // re-sending the payload as fresh frames and never returns Ok.
        // The test does not await it: the reader's duplicate-evidence
        // cap already has the answer, and runtime shutdown aborts it.
        ws.write_all(&wire_payload).await.expect("ws write_all");
        // ws drops here → FIN to the reader.
    });

    let received = timeout(Duration::from_secs(30), async {
        let mut received = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => break, // EOF: writer finished and closed
                Ok(n) => {
                    received.extend_from_slice(&chunk[..n]);
                    if received.len() >= 2 * expect_total {
                        // Duplicate data arriving (pre-fix behavior) — no
                        // need to read the infinite stream any further.
                        break;
                    }
                }
            }
        }
        received
    })
    .await
    .expect("reader must terminate");

    // The writer must not be awaited: with the pre-fix code it hangs.
    drop(writer);

    assert_eq!(
        received.len(),
        expect_total,
        "peer received {} bytes; expected exactly one frame ({} bytes) — \
         the payload was sent more than once",
        received.len(),
        expect_total
    );
    // The single frame must parse as the exact unmasked server frame.
    assert_eq!(received[..2], [0x82, 127], "FIN+BINARY, extended length");
    assert_eq!(
        u64::from_be_bytes(received[2..10].try_into().unwrap()),
        payload.len() as u64
    );
    assert_eq!(&received[10..], &payload[..]);
}

/// The poll_flush drain-completion arm must set `drain_completed` so the
/// next poll_write consumes the caller's re-polled buf instead of
/// re-sending it. Deterministic unit version of the duplicate-frame
/// regression: a sink that accepts at most 7 bytes per poll forces the
/// partial write and a multi-poll drain; the re-polled buf must be
/// reported as written (Ok(32)) with exactly one frame on the wire.
#[test]
fn ws_poll_flush_drain_completion_consumes_repolled_buf() {
    struct LimitedSink {
        limit: usize,
        sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AsyncRead for LimitedSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for LimitedSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.limit);
            self.sent.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut ws = WsByteStream::from_raw(
        Box::new(LimitedSink {
            limit: 7,
            sent: sent.clone(),
        }),
        false,
    );
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let buf = vec![0x5au8; 32];

    // Fresh frame write: 2-byte header + 32 payload = 34 frame bytes,
    // but the sink accepts only 7 per poll → partial, needs_flush.
    assert!(matches!(
        Pin::new(&mut ws).poll_write(&mut cx, &buf),
        Poll::Pending
    ));

    // Drain the retained frame to completion via poll_flush (re-polling
    // after each Pending, as an executor would after the self-wake).
    loop {
        match Pin::new(&mut ws).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(e)) => panic!("flush failed: {e}"),
            Poll::Pending => {}
        }
    }

    // The caller re-polls with the SAME buf: it must be consumed as the
    // just-drained frame's payload — Ok(32) — not re-sent as a new frame.
    match Pin::new(&mut ws).poll_write(&mut cx, &buf) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 32, "re-polled buf must be consumed"),
        other => panic!("expected Ok(32) consuming the re-polled buf, got {other:?}"),
    }

    // Exactly one frame reached the wire: 2 header + 32 payload bytes.
    assert_eq!(
        sent.load(std::sync::atomic::Ordering::Relaxed),
        34,
        "exactly one frame must be sent; the re-polled buf must not be re-sent"
    );
}

/// L16: RSV1-3 bits must be zero (no extensions negotiated) and the
/// mask direction must match the role — server-mode streams reject
/// unmasked frames (a client MUST mask, §5.3), client-mode streams
/// reject masked frames (a server MUST NOT mask, §5.1).
#[tokio::test]
async fn ws_frame_rsv_and_mask_direction_enforced() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Server mode: an unmasked frame from a client is a protocol error.
    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
    raw.write_all(&[0x82, 0x02, b'a', b'b']).await.unwrap();
    let mut out = [0u8; 4];
    let err = ws.read(&mut out).await.unwrap_err();
    assert!(
        err.to_string().contains("must be masked"),
        "unexpected error: {err}"
    );

    // Server mode: RSV bits set → rejected regardless of masking.
    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
    // Masked frame with RSV1 (0x40) + RSV2 (0x20) set.
    let mut frame = ws_masked_zero_frame();
    frame[0] = 0x82 | 0x40 | 0x20;
    raw.write_all(&frame).await.unwrap();
    let err = ws.read(&mut out).await.unwrap_err();
    assert!(err.to_string().contains("RSV"), "unexpected error: {err}");

    // Client mode: a masked frame from a server is a protocol error.
    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
    raw.write_all(&[0x82, 0x80 | 0x02, 0, 0, 0, 0, b'a', b'b'])
        .await
        .unwrap();
    let err = ws.read(&mut out).await.unwrap_err();
    assert!(
        err.to_string().contains("must not be masked"),
        "unexpected error: {err}"
    );

    // And the legitimate shapes still decode: masked frame into a
    // server-mode stream, unmasked frame into a client-mode stream.
    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
    raw.write_all(&ws_masked_frame(b"ok-server")).await.unwrap();
    let mut out = [0u8; 16];
    let n = ws.read(&mut out).await.unwrap();
    assert_eq!(&out[..n], b"ok-server");

    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
    raw.write_all(&ws_binary_frame(b"ok-client")).await.unwrap();
    let n = ws.read(&mut out).await.unwrap();
    assert_eq!(&out[..n], b"ok-client");
}

/// M3: client-mode control frames (pong reply, shutdown close) are
/// masked per RFC 6455 §5.3 — a strict server peer must be able to
/// unmask them. The pong is a reply to an inbound (unmasked) ping; the
/// close frame must carry the masked 1000 code.
#[tokio::test]
async fn ws_client_mode_control_frames_are_masked() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    // Pong reply to an inbound ping must be a masked pong on the wire.
    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
    raw.write_all(&[0x89, 0x00]).await.unwrap(); // unmasked ping (server → client)
                                                 // Drive the read path so the ping is dispatched and the pong sent.
    let read_task = tokio::spawn(async move {
        let mut out = [0u8; 4];
        let _ = timeout(Duration::from_millis(200), ws.read(&mut out)).await;
    });
    let mut pong = [0u8; 6];
    let n = timeout(Duration::from_secs(5), raw.read(&mut pong))
        .await
        .expect("pong must arrive")
        .expect("read pong");
    read_task.await.expect("read task");
    assert_eq!(n, 6, "masked pong: 2 header + 4 mask bytes");
    assert_eq!(pong[0], 0x8a, "FIN + PONG opcode");
    assert_eq!(pong[1], 0x80, "MASK bit must be set on client-mode pong");
    // pong[2..6] is the 4-byte mask key: RFC 6455 §5.3 requires a fresh
    // random key per frame, so its value is asserted only where payload
    // exists to unmask (the close frame below). Empty payload → nothing
    // masked; the key bytes are arbitrary.

    // Shutdown close frame must be masked, with the 1000 code XORed
    // against the 4-byte mask key.
    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
    ws.shutdown().await.expect("shutdown");
    let mut close = [0u8; 8];
    let n = timeout(Duration::from_secs(5), raw.read(&mut close))
        .await
        .expect("close frame must arrive")
        .expect("read close");
    assert_eq!(n, 8, "masked close: 2 header + 4 mask + 2 payload");
    assert_eq!(close[0], 0x88, "FIN + CLOSE opcode");
    assert_eq!(close[1], 0x80 | 0x02, "MASK bit + 2-byte payload");
    assert_eq!(
        close[6] ^ close[2],
        0x03,
        "close code 1000 masked (high byte)"
    );
    assert_eq!(
        close[7] ^ close[3],
        0xe8,
        "close code 1000 masked (low byte)"
    );
}

/// L18: poll_shutdown must not drop a partially-flushed frame — it
/// drains write_buf (and the close frame) to completion before
/// delegating to the inner shutdown.
#[test]
fn ws_shutdown_drains_partially_flushed_frame() {
    struct ShutdownTrackingSink {
        limit: usize,
        sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        shutdown_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl AsyncRead for ShutdownTrackingSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ShutdownTrackingSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.limit);
            self.sent.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_called
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let shutdown_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut ws = WsByteStream::from_raw(
        Box::new(ShutdownTrackingSink {
            limit: 7,
            sent: sent.clone(),
            shutdown_called: shutdown_called.clone(),
        }),
        false,
    );
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let buf = vec![0x5au8; 32];

    // Fresh frame write: 34 frame bytes, but the sink accepts only 7 per
    // poll → partial, needs_flush (the frame is NOT fully on the wire).
    assert!(matches!(
        Pin::new(&mut ws).poll_write(&mut cx, &buf),
        Poll::Pending
    ));

    // Shutdown must drain the retained frame (34 bytes) AND the close
    // frame (4 bytes unmasked server-mode) before calling inner
    // shutdown — 38 bytes total on the wire.
    loop {
        match Pin::new(&mut ws).poll_shutdown(&mut cx) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(e)) => panic!("shutdown failed: {e}"),
            Poll::Pending => {}
        }
    }
    assert_eq!(
        sent.load(std::sync::atomic::Ordering::Relaxed),
        38,
        "shutdown must drain the partially-flushed frame (34) plus the close frame (4)"
    );
    assert!(
        shutdown_called.load(std::sync::atomic::Ordering::Relaxed),
        "inner shutdown must be delegated after the drain"
    );
}

/// Masked frame with an arbitrary opcode and an EXPLICIT raw length
/// field (126/127 allowed even for payloads that would not need the
/// extended encoding) — lets a test pin the raw-length-field and FIN
/// checks on control frames independently of the payload-size-driven
/// encoding of [`ws_masked_frame`]. Server-mode streams enforce
/// RFC 6455 mask direction, so protocol-violation frames fed into them
/// are masked.
fn ws_masked_frame_raw(opcode: u8, raw_len: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![opcode | if fin { 0x80 } else { 0 }];
    frame.push(0x80 | raw_len);
    match raw_len {
        126 => frame.extend_from_slice(&(payload.len() as u16).to_be_bytes()),
        127 => frame.extend_from_slice(&(payload.len() as u64).to_be_bytes()),
        _ => {}
    }
    let mask: [u8; 4] = rand::random();
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    frame
}

/// RFC 6455 §5.5 control-frame validation: a control frame whose raw
/// 7-bit length field is 126/127 (extended-length encoding), whose
/// decoded payload exceeds 125 bytes, or whose FIN bit is clear is a
/// protocol error that closes the connection — a >125-byte ping is NOT
/// truncatable to a pong. The raw-field rejection matches gorilla:
/// advanceFrame checks the raw length field against 125 for control
/// frames (conn.go:841) before decoding any extended length. A
/// continuation frame (opcode 0x00) with no fragmented message in
/// progress is likewise a protocol error (gorilla: "continuation after
/// FIN"), not a data frame.
#[tokio::test]
async fn ws_control_frame_and_continuation_validation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn expect_protocol_error(frame: Vec<u8>, needle: &str) {
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
        raw.write_all(&frame).await.unwrap();
        let mut out = [0u8; 8];
        let err = ws.read(&mut out).await.unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "expected error containing {needle:?}, got: {err}"
        );
    }

    // Oversized ping: a 126-byte payload requires the 16-bit extended
    // length encoding, which control frames must not use (previously
    // truncated to a 125-byte pong with a warning).
    expect_protocol_error(
        ws_masked_frame_raw(0x09, 126, true, &[0x55; 126]),
        "control",
    )
    .await;

    // Extended-length ping: the RAW length field is 127 (64-bit
    // encoding) even though the decoded payload is only 2 bytes — a
    // protocol error here although gorilla's decoded-length check
    // (2 ≤ 125) would admit it: frp-rs is stricter on the encoding.
    expect_protocol_error(ws_masked_frame_raw(0x09, 127, true, b"hi"), "control").await;

    // FIN=0 ping: control frames must have FIN set (RFC 6455 §5.5).
    expect_protocol_error(ws_masked_frame_raw(0x09, 1, false, b"x"), "FIN not set").await;

    // Stray continuation: opcode 0x00 with no fragmented message in
    // progress (the reader never starts one — every data frame is
    // treated as complete) is a protocol error, not a data frame.
    expect_protocol_error(ws_masked_frame_raw(0x00, 3, true, b"abc"), "continuation").await;
}

/// Masked control frame builder (client-mode wire shape: MASK bit + a
/// fresh random key). Payload must be ≤ 125 bytes (control-frame rule).
fn ws_masked_control_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 125, "control frame payload cap");
    let mask: [u8; 4] = rand::random();
    let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    frame
}

/// Unmask a masked server→client (client-mode outbound) frame payload:
/// returns (header_len, payload). Header is 2 + 4 mask bytes for
/// payloads ≤ 125.
fn ws_unmask_payload(frame: &[u8]) -> (usize, Vec<u8>) {
    assert!(frame.len() >= 6, "masked frame too short");
    assert_eq!(frame[1] & 0x80, 0x80, "expected MASK bit set");
    let mask = &frame[2..6];
    let payload = frame[6..]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i & 3])
        .collect::<Vec<u8>>();
    (6, payload)
}

/// Server mode, inbound MASKED ping with a payload (the client-mode wire
/// shape): the pong must echo the payload unmasked (server-mode replies
/// are never masked — RFC 6455 §5.3), and the ping must NOT surface as
/// data — the read stays parked. Control-frame pin (T11).
#[tokio::test]
async fn ws_server_mode_echoes_masked_ping_payload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false); // server mode

    let ping_payload = b"ping-with-payload";
    raw.write_all(&ws_masked_control_frame(0x09, ping_payload))
        .await
        .unwrap();

    let read_task = tokio::spawn(async move {
        let mut out = [0u8; 4];
        let _ = timeout(Duration::from_millis(200), ws.read(&mut out)).await;
    });

    // Server-mode pong: unmasked (no MASK bit), payload echoed verbatim.
    let mut pong = vec![0u8; 2 + ping_payload.len()];
    let n = timeout(Duration::from_secs(5), raw.read(&mut pong))
        .await
        .expect("pong must arrive")
        .expect("read pong");
    assert_eq!(n, pong.len(), "2 header + echoed payload");
    assert_eq!(pong[0], 0x8a, "FIN + PONG opcode");
    assert_eq!(pong[1] & 0x80, 0x00, "server-mode pong must be unmasked");
    assert_eq!(&pong[2..], ping_payload, "pong echoes the ping payload");

    // The ping is a control frame: it must not surface as read data —
    // the read task stays parked until its timeout fires.
    read_task.await.expect("read task");
}

/// Client mode, inbound UNMASKED ping with a payload (the server-mode
/// wire shape): the pong must be masked with a fresh key and carry the
/// SAME payload — unmask it to verify byte-exact echo. Control-frame
/// pin (T11).
#[tokio::test]
async fn ws_client_mode_masks_pong_and_echoes_payload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), true); // client mode

    let ping_payload = b"client-mode-ping";
    let mut ping = vec![0x89, ping_payload.len() as u8]; // unmasked ping
    ping.extend_from_slice(ping_payload);
    raw.write_all(&ping).await.unwrap();

    let read_task = tokio::spawn(async move {
        let mut out = [0u8; 4];
        let _ = timeout(Duration::from_millis(200), ws.read(&mut out)).await;
    });

    let mut pong = vec![0u8; 2 + 4 + ping_payload.len()];
    let n = timeout(Duration::from_secs(5), raw.read(&mut pong))
        .await
        .expect("pong must arrive")
        .expect("read pong");
    read_task.await.expect("read task");
    assert_eq!(n, pong.len(), "2 header + 4 mask + echoed payload");
    assert_eq!(pong[0], 0x8a, "FIN + PONG opcode");
    assert_eq!(pong[1] & 0x80, 0x80, "client-mode pong must be masked");
    let (_, echoed) = ws_unmask_payload(&pong);
    assert_eq!(echoed, ping_payload, "masked pong echoes the ping payload");
}

/// Inbound CLOSE (masked, server mode): the stream must reply with an
/// unmasked close frame carrying code 1000, and the read must surface
/// EOF (0 bytes) — never the close payload as data. Control-frame pin
/// (T11).
#[tokio::test]
async fn ws_server_mode_close_reply_then_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false); // server mode

    // Masked close with code 1000 (0x03e8), as a compliant client sends.
    raw.write_all(&ws_masked_control_frame(0x08, &[0x03, 0xe8]))
        .await
        .unwrap();

    // Drive the read: the close reply is written, then the read returns
    // EOF.
    let mut out = [0u8; 8];
    let n = timeout(Duration::from_secs(5), ws.read(&mut out))
        .await
        .expect("read must return after inbound close")
        .expect("read ok");
    assert_eq!(n, 0, "inbound close surfaces as EOF, got {n} bytes of data");

    // Reply close frame: unmasked, code 1000.
    let mut reply = [0u8; 4];
    let rn = timeout(Duration::from_secs(5), raw.read(&mut reply))
        .await
        .expect("close reply must arrive")
        .expect("read reply");
    assert_eq!(rn, 4, "server-mode close reply: 2 header + 2 code bytes");
    assert_eq!(reply[0], 0x88, "FIN + CLOSE opcode");
    assert_eq!(
        reply[1], 0x02,
        "server-mode reply is unmasked, 2-byte payload"
    );
    assert_eq!(&reply[2..], &[0x03, 0xe8], "close code 1000");
}

/// Inbound PONG must be swallowed (never surfaced as data), and frames
/// after it must still be delivered. Control-frame pin (T11).
#[tokio::test]
async fn ws_server_mode_swallows_pong_and_reads_next_frame() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut raw, client_io) = tokio::io::duplex(8192);
    let mut ws = WsByteStream::from_raw(Box::new(client_io), false); // server mode

    // Masked pong with a payload, then a masked binary data frame.
    raw.write_all(&ws_masked_control_frame(0x0a, b"pong-payload"))
        .await
        .unwrap();
    let data = b"data-after-pong";
    raw.write_all(&ws_masked_frame(data)).await.unwrap();

    let mut out = vec![0u8; data.len()];
    let n = ws.read(&mut out).await.expect("read data frame");
    assert_eq!(
        n,
        data.len(),
        "pong must be swallowed, data frame delivered"
    );
    assert_eq!(&out[..n], data);
}
