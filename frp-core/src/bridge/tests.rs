use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Plain bridge: basic bidirectional data flow.
#[tokio::test]
async fn test_bridge_plain_bidirectional() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (mut w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_plain(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            false,
            vec![],
            None,
        )
        .await;
    });

    // User → Work
    u_w_test.write_all(b"user->work").await.unwrap();
    u_w_test.flush().await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"user->work");

    // Work → User
    w_w_test.write_all(b"work->user").await.unwrap();
    w_w_test.flush().await.unwrap();
    let n2 = u_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"work->user");
}

/// Plain bridge with pre_read: bytes forwarded before main loop.
#[tokio::test]
async fn test_bridge_plain_pre_read() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (_w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    let pre_read = b"pre-read body".to_vec();

    tokio::spawn(async move {
        bridge_plain(
            u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge, false, pre_read, None,
        )
        .await;
    });

    let mut buf = vec![0u8; 1024];
    let n = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pre-read body");

    u_w_test.write_all(b"after").await.unwrap();
    u_w_test.flush().await.unwrap();
    let n2 = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"after");
}

/// Compressed plain bridge with pre_read: the pre-read bytes MUST be part
/// of the same Snappy stream as the main-loop body. The work side
/// (bridge_work_to_user's `make_decompressor`) decompresses the stream
/// from byte 0, so a RAW pre-read prefix is read as a garbage Snappy
/// header and the whole proxy direction dies. Regression pin for the
/// compressed-vhost pre_read bypass (H1).
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_plain_compressed_pre_read_stream_integrity() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(256 * 1024);
    let (mut w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(256 * 1024);

    let pre_read = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let body = b"body bytes following the vhost pre-read head".to_vec();

    let handle = tokio::spawn(async move {
        bridge_plain(
            u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge, true, pre_read, None,
        )
        .await;
    });

    // User → Work: write the body, then half-close the user write side
    // so bridge_user_to_work drains and ends.
    u_w_test.write_all(&body).await.unwrap();
    drop(u_w_test);

    // Work side: the ENTIRE stream (pre_read + body) must decompress from
    // byte 0, exactly as the production work→user decompressor reads it.
    let mut dec = crate::encryption::SnappyDecompressor::new();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    expected.extend_from_slice(&body);
    let mut received = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = w_r_test.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        let out = dec
            .feed(&buf[..n])
            .unwrap_or_else(|e| panic!("work side decompress from byte 0 failed: {e}"));
        received.extend_from_slice(&out);
    }
    // `feed` emits at most one complete frame per call — drain any
    // complete frames buffered when the last read ended mid-stream.
    loop {
        let out = dec
            .feed(&[])
            .unwrap_or_else(|e| panic!("work side decompress drain failed: {e}"));
        if out.is_empty() {
            break;
        }
        received.extend_from_slice(&out);
    }
    assert_eq!(received, expected);

    // Work → User: the test side must send a COMPRESSED response (the
    // bridge decompresses), which must arrive plaintext at the user side.
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    let mut comp = crate::encryption::SnappyCompressor::new();
    let mut comp_resp = Vec::new();
    comp.compress(&resp, &mut comp_resp).unwrap();
    w_w_test.write_all(&comp_resp).await.unwrap();
    // Close the work→user direction; the bridge's work_to_user half then
    // sees EOF and the join! completes.
    drop(w_w_test);

    let mut resp_buf = vec![0u8; 1024];
    let n = u_r_test.read(&mut resp_buf).await.unwrap();
    assert_eq!(&resp_buf[..n], &resp[..]);

    handle.await.unwrap();
}

/// Audit round-14 A1: `bridge_plain_decompressed_read` decouples the two
/// directions' compression. The work→user side is fed ALREADY-DECOMPRESSED
/// bytes (frp-server's injector path) and must forward them verbatim,
/// while the user→work side still compresses into a Snappy stream.
/// (Regression shape: a single `use_compression` bool would either
/// double-decode the read side or stop compressing the write side.)
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_plain_decompressed_read_direction_split() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(256 * 1024);
    let (mut w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(256 * 1024);

    let handle = tokio::spawn(async move {
        bridge_plain_decompressed_read(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            true,
            Vec::new(),
            None,
        )
        .await;
    });

    // Work → User: the test sends PLAINTEXT (no snappy) on the work side
    // — the read half of a `_decompressed_read` bridge is a plaintext
    // pipe. It must arrive at the user side byte-exact.
    let resp = b"HTTP/1.1 200 OK\r\nX-Injected: yes\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    w_w_test.write_all(&resp).await.unwrap();
    drop(w_w_test);

    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = u_r_test.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, resp, "work→user plaintext must pass through verbatim");

    // User → Work: writes on the user side must STILL be compressed into
    // a Snappy stream on the work side (write direction untouched).
    u_w_test.write_all(b"request body").await.unwrap();
    drop(u_w_test);

    let mut dec = crate::encryption::SnappyDecompressor::new();
    let mut received = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = w_r_test.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        let out = dec
            .feed(&buf[..n])
            .unwrap_or_else(|e| panic!("work side decompress failed: {e}"));
        received.extend_from_slice(&out);
    }
    loop {
        let out = dec
            .feed(&[])
            .unwrap_or_else(|e| panic!("work side decompress drain failed: {e}"));
        if out.is_empty() {
            break;
        }
        received.extend_from_slice(&out);
    }
    assert_eq!(received, b"request body");

    handle.await.unwrap();
}

/// Audit round-14 A1 encrypted analog: `SnappyStreamReader` under the
/// injector — the full pre-decompressed read stack. The wire carries
/// AES-128-CFB(snappy(plaintext)); the frp-server arm unwraps both layers
/// OUTSIDE the bridge (CipherReader → SnappyStreamReader), so the bridge
/// receives an already-decompressed plaintext stream and must not
/// decrypt/decompress it again, while its user→work write direction
/// still compresses AND encrypts.
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_encrypted_decompressed_read_direction_split() {
    let key = crate::encryption::derive_key("enc_decomp_read_key_a1");

    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
    let (w_w_bridge, w_r_test) = tokio::io::duplex(256 * 1024);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(256 * 1024);

    // Same stack the frp-server encrypted injector arm builds
    // (frp-server/src/control/bridge.rs): decompression now happens
    // BELOW the bridge's read position.
    let decrypted = crate::cipher_stream::CipherReader::new(w_r_bridge, key);
    let pre_decompressed = crate::snappy_stream::SnappyStreamReader::new(decrypted);

    let handle = tokio::spawn(async move {
        bridge_encrypted_decompressed_read(
            u_r_bridge,
            u_w_bridge,
            pre_decompressed,
            w_w_bridge,
            &key,
            true,
            Vec::new(),
            None,
            None,
        )
        .await;
    });

    // Work → User: emit the wire form of a compressed+encrypted proxy
    // response — AES-128-CFB(snappy(plaintext)) via CipherWriter.
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    let mut comp = crate::encryption::SnappyCompressor::new();
    let mut comp_resp = Vec::new();
    comp.compress(&resp, &mut comp_resp).unwrap();
    let mut enc_w = crate::cipher_stream::CipherWriter::new(w_w_test, key).expect("rng");
    enc_w.write_all(&comp_resp).await.unwrap();
    enc_w.flush().await.unwrap();
    drop(enc_w); // EOF on the chain above

    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = u_r_test.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(
        got, resp,
        "encrypted+compressed work→user must arrive plaintext"
    );

    // User → Work: must still be compressed AND encrypted on the wire.
    u_w_test.write_all(b"ping payload").await.unwrap();
    drop(u_w_test);

    let mut dec_r = crate::cipher_stream::CipherReader::new(w_r_test, key);
    let mut dec = crate::encryption::SnappyDecompressor::new();
    let mut received = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = dec_r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        let out = dec
            .feed(&buf[..n])
            .unwrap_or_else(|e| panic!("decrypted stream decompress failed: {e}"));
        received.extend_from_slice(&out);
    }
    loop {
        let out = dec
            .feed(&[])
            .unwrap_or_else(|e| panic!("decrypted stream decompress drain failed: {e}"));
        if out.is_empty() {
            break;
        }
        received.extend_from_slice(&out);
    }
    assert_eq!(received, b"ping payload");

    handle.await.unwrap();
}

/// Encrypted + compressed bridge with pre_read: byte-exact stream
/// integrity through the full server-side stack (compress → encrypt).
/// Same H1 pin as the plain variant, through bridge_encrypted.
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_encrypted_compressed_pre_read_stream_integrity() {
    let key = crate::encryption::derive_key("enc_comp_pre_read_key_1");

    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
    let (w_w_bridge, w_r_test) = tokio::io::duplex(256 * 1024);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(256 * 1024);

    let pre_read = b"GET /sec HTTP/1.1\r\nHost: secure.example.com\r\n\r\n".to_vec();
    let body = b"encrypted body after pre-read".to_vec();

    let handle = tokio::spawn(async move {
        bridge_encrypted(
            u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge, &key, true, pre_read, None, None, false,
        )
        .await;
    });

    u_w_test.write_all(&body).await.unwrap();
    drop(u_w_test);

    // Work side: CipherReader decrypts, then the Snappy stream must
    // decompress from byte 0 — same order as the production
    // bridge_work_to_user (CipherReader → make_decompressor).
    let mut dec_reader = CipherReader::new(w_r_test, key);
    let mut dec = crate::encryption::SnappyDecompressor::new();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"GET /sec HTTP/1.1\r\nHost: secure.example.com\r\n\r\n");
    expected.extend_from_slice(&body);
    let mut received = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = dec_reader.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        let out = dec
            .feed(&buf[..n])
            .unwrap_or_else(|e| panic!("decrypted stream decompress from byte 0 failed: {e}"));
        received.extend_from_slice(&out);
    }
    // `feed` emits at most one complete frame per call — drain any
    // complete frames buffered when the last read ended mid-stream.
    loop {
        let out = dec
            .feed(&[])
            .unwrap_or_else(|e| panic!("decrypted stream decompress drain failed: {e}"));
        if out.is_empty() {
            break;
        }
        received.extend_from_slice(&out);
    }
    assert_eq!(received, expected);

    // Work → User: test side sends compress-then-encrypt; the bridge must
    // deliver plaintext to the user side.
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let mut comp = crate::encryption::SnappyCompressor::new();
    let mut comp_resp = Vec::new();
    comp.compress(&resp, &mut comp_resp).unwrap();
    let mut enc_w = CipherWriter::new(w_w_test, key).expect("rng");
    enc_w.write_all(&comp_resp).await.unwrap();
    enc_w.flush().await.unwrap();
    drop(enc_w);

    let mut resp_buf = vec![0u8; 1024];
    let n = u_r_test.read(&mut resp_buf).await.unwrap();
    assert_eq!(&resp_buf[..n], &resp[..]);

    handle.await.unwrap();
}

/// Encrypted bridge: smoke test — starts, processes data, completes without panic.
/// Content verification is done in cipher_stream tests.
/// Note: bridge uses tokio::join! — both directions must complete. We drop
/// both write sides to signal EOF on both read sides.
#[tokio::test]
async fn test_encrypted_bridge_smoke() {
    let key = crate::encryption::derive_key("smoke_test_key_42");

    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, _w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    let handle = tokio::spawn(async move {
        bridge_encrypted(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            &key,
            false,
            vec![],
            None,
            None,
            false,
        )
        .await;
    });

    u_w_test.write_all(b"hello encrypted world").await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test); // EOF on user_r
    drop(w_w_test); // EOF on work_r (so enc_work_r.read() returns 0)

    handle.await.unwrap();
}

/// Encrypted bridge with compression: smoke test.
#[tokio::test]
async fn test_encrypted_bridge_compression_smoke() {
    let key = crate::encryption::derive_key("comp_smoke_key_99");

    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, _w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    let handle = tokio::spawn(async move {
        bridge_encrypted(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            &key,
            true,
            vec![],
            None,
            None,
            false,
        )
        .await;
    });

    let msg = b"AAAA".repeat(256);
    u_w_test.write_all(&msg).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);
    drop(w_w_test);

    handle.await.unwrap();
}

/// Encrypted bridge: large data smoke test.
#[tokio::test]
async fn test_encrypted_bridge_large_smoke() {
    let key = crate::encryption::derive_key("large_smoke_12345");

    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
    let (w_w_bridge, _w_r_test) = tokio::io::duplex(256 * 1024);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(256 * 1024);

    let handle = tokio::spawn(async move {
        bridge_encrypted(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            &key,
            false,
            vec![],
            None,
            None,
            false,
        )
        .await;
    });

    let large_msg = vec![0x42u8; 100_000];
    u_w_test.write_all(&large_msg).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);
    drop(w_w_test);

    handle.await.unwrap();
}

/// Half-close through the plain bridge (the classic frp data-loss bug
/// shape): the user shuts down its write half — NOT a drop — so the
/// work side must first drain the payload, then observe EOF; and the
/// work→user direction must keep delivering afterwards.
#[tokio::test]
async fn test_bridge_plain_half_close() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (mut w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    let handle = tokio::spawn(async move {
        bridge_plain(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            false,
            vec![],
            None,
        )
        .await;
    });

    // User → Work: write the payload, then half-close the write side.
    u_w_test.write_all(b"user->work half-close").await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);

    // Work side must see the payload ...
    let mut buf = vec![0u8; 1024];
    let n = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"user->work half-close");
    // ... and then EOF: the bridge must propagate the half-close.
    let n2 = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(
        n2, 0,
        "user→work EOF must propagate through the plain bridge"
    );

    // Work → User must still deliver after the user half-closed.
    w_w_test
        .write_all(b"work->user after half-close")
        .await
        .unwrap();
    w_w_test.flush().await.unwrap();
    let n3 = u_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n3], b"work->user after half-close");

    // Close the work→user direction too so the spawned bridge task
    // (join! of both halves) can exit.
    drop(w_w_test);
    handle.await.unwrap();
}

/// Half-close through the encrypted bridge with byte-exact verification.
///
/// Asymmetry note: on the encrypted bridge the user→work direction
/// arrives at the work side as ciphertext (the bridge wraps its writer
/// in a `CipherWriter`), so the work side must decrypt with a
/// `CipherReader` before asserting; conversely the work→user direction
/// is decrypted by the bridge's internal `CipherReader`, so the test
/// side must write CIPHERTEXT (through a `CipherWriter`), not
/// plaintext.
#[tokio::test]
async fn test_encrypted_bridge_half_close() {
    let key = crate::encryption::derive_key("half_close_enc_key_7");

    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    let handle = tokio::spawn(async move {
        bridge_encrypted(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            &key,
            false,
            vec![],
            None,
            None,
            false,
        )
        .await;
    });

    // User → Work: plaintext in, half-close the write side (NOT a drop).
    u_w_test.write_all(b"encrypted user->work").await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);

    // Work side: decrypt the ciphertext (CipherReader consumes the IV
    // written by the bridge's CipherWriter) and verify byte-exactness.
    let mut dec = CipherReader::new(w_r_test, key);
    let mut buf = vec![0u8; 1024];
    let n = dec.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"encrypted user->work");
    // The half-close must propagate as EOF through the encrypted
    // user→work direction.
    let n2 = dec.read(&mut buf).await.unwrap();
    assert_eq!(
        n2, 0,
        "user→work EOF must propagate through the encrypted bridge"
    );

    // Work → User: encrypt on the test side; the bridge decrypts and
    // delivers plaintext to the user side.
    let mut enc_w_w_test = CipherWriter::new(w_w_test, key).expect("rng");
    enc_w_w_test
        .write_all(b"encrypted work->user")
        .await
        .unwrap();
    enc_w_w_test.flush().await.unwrap();
    let n3 = u_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n3], b"encrypted work->user");

    // Drop the CipherWriter to close the work→user direction, letting
    // the bridge's work_to_user half see EOF and the task exit.
    drop(enc_w_w_test);
    handle.await.unwrap();
}

#[tokio::test]
async fn bridge_plain_flushes_per_read_full_or_short() {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    // Writer that counts flush() calls and discards data.
    struct CountingWriter(Arc<AtomicUsize>);
    impl AsyncWrite for CountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    // Reader that yields two full-capacity chunks then EOF.
    struct TwoFullChunks(usize);
    impl AsyncRead for TwoFullChunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.0 == 0 {
                return Poll::Ready(Ok(()));
            } // EOF
            self.0 -= 1;
            let n = buf.remaining();
            buf.initialize_unfilled_to(n);
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    let flushes = Arc::new(AtomicUsize::new(0));
    let user_r = TwoFullChunks(2);
    let work_w = CountingWriter(flushes.clone());
    // work_r EOFs immediately; user_w sinks.
    let work_r = TwoFullChunks(0);
    let user_w = CountingWriter(Arc::new(AtomicUsize::new(0)));

    bridge_plain(user_r, user_w, work_r, work_w, false, Vec::new(), None).await;

    // Two full-capacity reads => one flush per read plus the final
    // shutdown flush (Plain's shutdown_bridge flushes): 3 total. A flush
    // gated on `n < cap` would strand an exact-size burst in a buffered
    // transport (TLS/WS/yamux) — the unconditional flush is what pushes
    // each read's bytes out.
    assert_eq!(
        flushes.load(Ordering::SeqCst),
        3,
        "expected per-read flush plus final flush, got batched"
    );
}

#[tokio::test]
#[cfg(feature = "compression")]
async fn bridge_user_to_work_compressed_flushes_on_full_reads() {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct CountingWriter(Arc<AtomicUsize>);
    impl AsyncWrite for CountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // Reader that yields N full-capacity chunks (each = BUFFER_SIZE) then EOF.
    struct NFulllChunks(usize);
    impl AsyncRead for NFulllChunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.0 == 0 {
                return Poll::Ready(Ok(()));
            } // EOF
            self.0 -= 1;
            let n = buf.remaining();
            // Repeated bytes — snappy-compressible, so the compressed
            // output per chunk is tiny. Flush is unconditional per read
            // (see the loop note), so full reads must flush too.
            buf.put_slice(&vec![0x41u8; n]);
            Poll::Ready(Ok(()))
        }
    }

    let reads = 32usize;
    let flushes = Arc::new(AtomicUsize::new(0));
    let user_r = NFulllChunks(reads);
    let work_w = CountingWriter(flushes.clone());

    bridge_user_to_work(
        user_r,
        WorkWriter::Plain(work_w),
        true, // compression on — the batched path
        Vec::new(),
        None,
        None,
    )
    .await;

    // All reads are full capacity; the compressed path must still flush
    // per chunk — an exact-size burst (n == cap) in a buffered transport
    // would otherwise sit unflushed until more data or EOF. Expect one
    // flush per read (plus the final shutdown flush from Plain's
    // shutdown_bridge): at least `reads` total.
    let f = flushes.load(Ordering::SeqCst);
    assert!(
        f >= reads,
        "expected per-read flush on compressed full reads, got {f} flushes for {reads} reads"
    );
    assert!(f >= 1, "expected at least the final flush, got {f}");
}

#[tokio::test]
#[cfg(feature = "compression")]
async fn bridge_user_to_work_compressed_flushes_on_short_reads() {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct CountingWriter(Arc<AtomicUsize>);
    impl AsyncWrite for CountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // Reader that yields N short chunks (each < BUFFER_SIZE) then EOF.
    struct NShortChunks(usize);
    impl AsyncRead for NShortChunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.0 == 0 {
                return Poll::Ready(Ok(()));
            }
            self.0 -= 1;
            let n = buf.remaining().min(16);
            buf.put_slice(&vec![0x42u8; n]);
            Poll::Ready(Ok(()))
        }
    }

    let reads = 64usize;
    let flushes = Arc::new(AtomicUsize::new(0));
    let user_r = NShortChunks(reads);
    let work_w = CountingWriter(flushes.clone());

    bridge_user_to_work(
        user_r,
        WorkWriter::Plain(work_w),
        true,
        Vec::new(),
        None,
        None,
    )
    .await;

    // Flush is unconditional in bridge_user_to_work, so every read —
    // short or full — gets exactly one flush. This test pins the
    // interactive (short-read) case end to end.
    let f = flushes.load(Ordering::SeqCst);
    assert!(
        f >= reads,
        "expected per-read flush on short reads (interactive), got {f} for {reads} reads"
    );
}

#[tokio::test]
#[cfg(feature = "compression")]
async fn bridge_work_to_user_batches_compressed_frames() {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct CountingWriter {
        writes: Arc<AtomicUsize>,
        flushes: Arc<AtomicUsize>,
    }
    impl AsyncWrite for CountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // Reader that yields one transport chunk containing three snappy
    // frames (each decompresses to 64 KiB), then EOF.
    struct OneShot(Option<Vec<u8>>);
    impl AsyncRead for OneShot {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(data) = self.0.take() else {
                return Poll::Ready(Ok(()));
            };
            let n = data.len().min(buf.remaining());
            buf.put_slice(&data[..n]);
            if n < data.len() {
                self.0 = Some(data[n..].to_vec());
            }
            Poll::Ready(Ok(()))
        }
    }

    let mut frames = Vec::new();
    let payload = vec![0x42u8; 64 * 1024];
    for _ in 0..3 {
        frames.extend_from_slice(&crate::encryption::compress(&payload).unwrap());
    }

    let writes = Arc::new(AtomicUsize::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    bridge_work_to_user(
        OneShot(Some(frames)),
        CountingWriter {
            writes: writes.clone(),
            flushes: flushes.clone(),
        },
        true,
        None,
        None,
    )
    .await;

    // Three 64 KiB frames in one read => one batched write, plus the
    // final EOF flush. The old path wrote and flushed once per frame.
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(flushes.load(Ordering::SeqCst), 2);
}

// ── Extracted helper unit tests (bridge_user_to_work, bridge_work_to_user) ──

/// bridge_user_to_work: plain basic forwarding.
#[tokio::test]
async fn test_bridge_user_to_work_plain_basic() {
    let (mut u_w_test, u_r) = tokio::io::duplex(65536);
    let (w_w, mut w_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_user_to_work(u_r, WorkWriter::Plain(w_w), false, vec![], None, None).await;
    });

    u_w_test.write_all(b"hello").await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test); // EOF

    let mut buf = vec![0u8; 1024];
    let n = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}

/// bridge_user_to_work: pre_read bytes arrive before main loop data.
#[tokio::test]
async fn test_bridge_user_to_work_pre_read() {
    let (mut u_w_test, u_r) = tokio::io::duplex(65536);
    let (w_w, mut w_r_test) = tokio::io::duplex(65536);

    let pre_read = b"pre-read body".to_vec();

    tokio::spawn(async move {
        bridge_user_to_work(u_r, WorkWriter::Plain(w_w), false, pre_read, None, None).await;
    });

    // pre_read should arrive first
    let mut buf = vec![0u8; 1024];
    let n = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pre-read body");

    u_w_test.write_all(b"after").await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);

    let n2 = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"after");
}

/// bridge_work_to_user: basic forwarding.
#[tokio::test]
async fn test_bridge_work_to_user_basic() {
    let (mut w_w_test, w_r) = tokio::io::duplex(65536);
    let (u_w, mut u_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_work_to_user(w_r, u_w, false, None, None).await;
    });

    w_w_test.write_all(b"work->user").await.unwrap();
    w_w_test.flush().await.unwrap();
    drop(w_w_test); // EOF

    let mut buf = vec![0u8; 1024];
    let n = u_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"work->user");
}

/// bridge_work_to_user: decompressor flush residual data.
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_work_to_user_decompressor_flush() {
    use crate::encryption;

    let (mut w_w_test, w_r) = tokio::io::duplex(65536);
    let (u_w, mut u_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_work_to_user(w_r, u_w, true, None, None).await;
    });

    // Write compressed data that needs flush to produce final bytes
    let original = b"AAAA".repeat(64);
    let mut comp_buf = Vec::new();
    encryption::compress_into(&original, &mut comp_buf).unwrap();
    w_w_test.write_all(&comp_buf).await.unwrap();
    w_w_test.flush().await.unwrap();
    drop(w_w_test); // EOF triggers flush in bridge_work_to_user

    let mut out = Vec::new();
    let mut buf = vec![0u8; 1024];
    loop {
        match u_r_test.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    assert_eq!(out, original);
}

/// Encrypted round-trip: user_to_work (Encrypted) + work_to_user (CipherReader)
/// verifies byte-identical data after encrypt/decrypt cycle.
#[tokio::test]
async fn test_bridge_helpers_encrypted_roundtrip() {
    let key = crate::encryption::derive_key("roundtrip_key_42");

    // Create two duplex pairs:
    //   user_duplex: connects user_r (read by u2w) to test writer
    //   work_duplex: connects work_w (written by u2w, Encrypted) to work_r (read by w2u, CipherReader)
    let (mut u_w_test, u_r) = tokio::io::duplex(65536);
    let (work_duplex_w, work_duplex_r) = tokio::io::duplex(65536);
    let (u_w_sink, mut u_r_test) = tokio::io::duplex(65536);

    let enc_writer = CipherWriter::new(work_duplex_w, key).expect("rng");
    let enc_reader = CipherReader::new(work_duplex_r, key);

    let u2w = tokio::spawn(async move {
        bridge_user_to_work(
            u_r,
            WorkWriter::Encrypted(enc_writer),
            false,
            vec![],
            None,
            None,
        )
        .await;
    });

    let w2u = tokio::spawn(async move {
        bridge_work_to_user(enc_reader, u_w_sink, false, None, None).await;
    });

    // Write plaintext, read decrypted output
    let msg = b"hello encrypted roundtrip";
    u_w_test.write_all(msg).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test); // EOF on user_r → u2w sends data then exits

    // w2u reads from work_duplex_r (same duplex pair as work_duplex_w)
    // u2w encrypts and writes to work_duplex_w → w2u reads and decrypts

    let mut out = vec![0u8; 1024];
    let out_n = u_r_test.read(&mut out).await.unwrap();
    assert_eq!(&out[..out_n], msg);

    let (a, b) = tokio::join!(u2w, w2u);
    if let Err(e) = a {
        tracing::debug!(error = %e, "user->work relay error");
    }
    if let Err(e) = b {
        tracing::debug!(error = %e, "work->user relay error");
    }
}

#[test]
fn test_compress_chunk_identity_when_disabled() {
    let mut buf = Vec::new();
    let mut compressor = make_compressor(false);
    let compressed = compress_chunk_into(&mut compressor, b"hello", false, &mut buf).unwrap();
    assert!(!compressed); // false = passthrough (no compression)
}

#[test]
#[cfg(feature = "compression")]
fn test_compress_decompress_roundtrip() {
    let original = b"AAAA".repeat(64);
    let mut comp_buf = Vec::new();
    let mut compressor = make_compressor(true);
    compress_chunk_into(&mut compressor, &original, true, &mut comp_buf).expect("compress ok");
    let mut dec = make_decompressor(true);
    let mut decomp_buf = Vec::new();
    let added =
        decompress_chunk_append_into(&mut dec, &comp_buf, &mut decomp_buf).expect("decompress ok");
    assert_eq!(&decomp_buf[..added], original);
}

#[test]
#[cfg(feature = "compression")]
fn decompress_chunk_accepts_legal_one_megabyte_multi_chunk_read() {
    let original = vec![0x42; 1024 * 1024];
    let mut comp_buf = Vec::new();
    let mut compressor = make_compressor(true);
    compress_chunk_into(&mut compressor, &original, true, &mut comp_buf).expect("compress ok");
    let mut dec = make_decompressor(true);
    let mut decomp_buf = Vec::new();

    let mut output = Vec::new();
    let mut input = comp_buf.as_slice();
    loop {
        let before = decomp_buf.len();
        let added = decompress_chunk_append_into(&mut dec, input, &mut decomp_buf)
            .expect("legal multi-chunk read must decompress");
        input = &[];
        if added == 0 {
            break;
        }
        assert!(added <= 128 * 1024);
        output.extend_from_slice(&decomp_buf[before..before + added]);
    }
    assert_eq!(output, original);
}

#[tokio::test]
#[cfg(feature = "compression")]
async fn work_to_user_drains_all_compressed_chunks_after_peer_eof() {
    let original = vec![0x42; 3 * 1024 * 1024];
    let compressed = encryption::compress(&original).unwrap();
    let (mut work_tx, work_rx) = tokio::io::duplex(64 * 1024);
    let (user_tx, mut user_rx) = tokio::io::duplex(64 * 1024);

    let bridge = tokio::spawn(async move {
        bridge_work_to_user(work_rx, user_tx, true, None, None).await;
    });
    let writer = tokio::spawn(async move {
        work_tx.write_all(&compressed).await.unwrap();
        work_tx.shutdown().await.unwrap();
    });

    let mut received = Vec::new();
    user_rx.read_to_end(&mut received).await.unwrap();
    writer.await.unwrap();
    bridge.await.unwrap();
    assert_eq!(received, original);
}

#[tokio::test]
#[cfg(feature = "compression")]
async fn metadata_storm_drain_yields_to_runtime_timers() {
    let storm = [0xfe, 0, 0, 0].repeat(300_000);
    let (mut work_tx, work_rx) = tokio::io::duplex(64 * 1024);
    let (user_tx, mut user_rx) = tokio::io::duplex(64 * 1024);
    let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let timer_ticks = ticks.clone();

    let bridge = tokio::spawn(async move {
        bridge_work_to_user(work_rx, user_tx, true, None, None).await;
    });
    let timer = tokio::spawn(async move {
        for _ in 0..5 {
            tokio::task::yield_now().await;
            timer_ticks.fetch_add(1, Ordering::Relaxed);
        }
    });
    work_tx.write_all(&storm).await.unwrap();
    work_tx.shutdown().await.unwrap();
    let mut received = Vec::new();
    user_rx.read_to_end(&mut received).await.unwrap();
    timer.await.unwrap();
    bridge.await.unwrap();

    assert!(received.is_empty());
    assert_eq!(ticks.load(Ordering::Relaxed), 5);
}

#[test]
fn test_decompress_chunk_identity_when_none() {
    let mut dec: Option<encryption::SnappyDecompressor> = None;
    let mut buf = Vec::new();
    let added = decompress_chunk_append_into(&mut dec, b"raw", &mut buf).unwrap();
    assert_eq!(&buf[..added], b"raw");
}

/// Rate-limited plain bridge: bidirectional data flow with high limit.
#[tokio::test]
async fn test_bridge_plain_rate_limited_smoke() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (mut w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    // 1 GB/s — effectively unlimited for small data. One shared bucket
    // for both directions (Go single-limiter model).
    let lim = BandwidthLimiter::shared(1_000_000_000).unwrap();

    tokio::spawn(async move {
        bridge_plain_rate_limited(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            false,
            vec![],
            Some(&lim),
            None,
        )
        .await;
    });

    // User → Work
    u_w_test.write_all(b"user->work").await.unwrap();
    u_w_test.flush().await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = w_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"user->work");

    // Work → User
    w_w_test.write_all(b"work->user").await.unwrap();
    w_w_test.flush().await.unwrap();
    let n2 = u_r_test.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"work->user");
}

/// Rate-limited plain bridge: low bandwidth caps transfer speed.
#[tokio::test]
async fn test_bridge_plain_rate_limited_bandwidth() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    // 1 KB/s — very slow. Burst = 1 KB so first KB instant, rest throttled.
    let lim = BandwidthLimiter::shared(1024).unwrap();

    let start = std::time::Instant::now();

    let handle = tokio::spawn(async move {
        bridge_plain_rate_limited(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            false,
            vec![],
            Some(&lim),
            None,
        )
        .await;
    });

    // Send 2 KB. 1 KB burst + 1 KB deficit → ~1 s wait.
    let data = vec![0x41u8; 2 * 1024];
    u_w_test.write_all(&data).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test); // EOF on user_r
    drop(w_w_test); // EOF on work_r

    // Drain work side
    let mut buf = vec![0u8; 4 * 1024];
    let mut total = 0;
    loop {
        match w_r_test.read(&mut buf[total..]).await {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }

    handle.await.unwrap();
    let elapsed = start.elapsed().as_millis();

    assert_eq!(total, 2 * 1024, "all 2 KB should be transferred");
    assert!(
        elapsed >= 500,
        "expected >= 500 ms with 1 KB/s limit, got {elapsed} ms"
    );
    assert!(elapsed <= 3000, "expected <= 3000 ms, got {elapsed} ms");
}

/// Deterministic incompressible payload (xorshift32; not crypto, just
/// stable across runs so the Snappy output size is predictable).
fn pseudo_random_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xff) as u8
        })
        .collect()
}

/// Pre-read bytes (the VHost HTTP head) must be charged to the shared
/// limiter: with a 1 KB/s bucket (1 KB burst), a 2 KB pre_read forces
/// ~0.95 s of debt before the FIRST byte reaches the work side.
/// Uncharged (the pre-fix behavior), the head would arrive instantly.
/// Limiter-accounting pin (T5): the pre_read charge site.
#[tokio::test]
async fn test_bridge_plain_rate_limited_pre_read_charged() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    let lim = BandwidthLimiter::shared(1024).unwrap();
    let pre_read = vec![0x5au8; 2000]; // 2 KB pre-read head
    let body = b"after pre-read".to_vec();

    let start = std::time::Instant::now();
    let handle = tokio::spawn(async move {
        bridge_plain_rate_limited(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            false,
            pre_read,
            Some(&lim),
            None,
        )
        .await;
    });

    // Payload is available immediately; the work side only sees bytes
    // after the pre_read debt is paid (the bridge charges before the
    // first write).
    u_w_test.write_all(&body).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test); // EOF on user_r
    drop(w_w_test); // EOF on work_r

    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    loop {
        match w_r_test.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    handle.await.unwrap();
    let elapsed = start.elapsed().as_millis();

    let mut expected = vec![0x5au8; 2000];
    expected.extend_from_slice(&body);
    assert_eq!(received, expected, "byte-exact transfer with pre_read");
    assert!(
        elapsed >= 400,
        "pre_read must be charged: 2 KB against a 1 KB burst needs ~0.95 s, got {elapsed} ms"
    );
    assert!(elapsed <= 4000, "expected <= 4000 ms, got {elapsed} ms");
}

/// The compressed path must charge comp_buf.len() (the COMPRESSED bytes),
/// not the raw input: 8 KB of 'A' under a 1 KB/s limiter arrives almost
/// instantly (Snappy squeezes the run to tens of bytes — inside the 1 KB
/// burst), but raw-size charging would stall ~7 s. Limiter-accounting
/// pin (T5): the compressed-chunk charge site.
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_compressed_charges_compressed_size_not_raw() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    let lim = BandwidthLimiter::shared(1024).unwrap();

    let start = std::time::Instant::now();
    let handle = tokio::spawn(async move {
        bridge_plain_rate_limited(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            true,
            vec![],
            Some(&lim),
            None,
        )
        .await;
    });

    let data = vec![0x41u8; 8 * 1024]; // 'A' * 8 KiB — Snappy-compressible
    u_w_test.write_all(&data).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);
    drop(w_w_test);

    // Work side decompresses from byte 0 (production shape).
    let mut dec = crate::encryption::SnappyDecompressor::new();
    let mut received = Vec::new();
    let mut first_byte_ms: Option<u128> = None;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = w_r_test.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        let out = dec
            .feed(&buf[..n])
            .unwrap_or_else(|e| panic!("decompress from byte 0 failed: {e}"));
        if !out.is_empty() && first_byte_ms.is_none() {
            first_byte_ms = Some(start.elapsed().as_millis());
        }
        received.extend_from_slice(&out);
    }
    // `feed` emits at most one complete frame per call — drain buffered
    // frames when the last read ended mid-stream.
    loop {
        let out = dec
            .feed(&[])
            .unwrap_or_else(|e| panic!("decompress drain failed: {e}"));
        if out.is_empty() {
            break;
        }
        if first_byte_ms.is_none() {
            first_byte_ms = Some(start.elapsed().as_millis());
        }
        received.extend_from_slice(&out);
    }
    handle.await.unwrap();
    let elapsed = start.elapsed().as_millis();

    assert_eq!(received, data, "decompressed payload byte-exact");
    let ms = first_byte_ms.expect("payload must arrive at the work side");
    assert!(
        ms < 1000,
        "must charge compressed size: 8 KiB of 'A' compresses to ~hundreds of bytes (inside the 1 KB burst), first byte at {ms} ms — raw-size charging would stall ~7 s"
    );
    assert!(elapsed <= 2500, "expected <= 2500 ms, got {elapsed} ms");
}

/// The compressed bridge path enforces the limiter on incompressible
/// data: ~6 KB of random payload against a 2 KB/s bucket (2 KB burst)
/// must stall ~2 s before the work side sees the stream (the compressed
/// chunk is charged at its compressed length, which for random data is
/// ~the raw length). Limiter-accounting pin (T5): compressed path is
/// rate-limited at all.
#[tokio::test]
#[cfg(feature = "compression")]
async fn test_bridge_compressed_rate_limited_throttles_incompressible() {
    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
    let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
    let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
    let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

    let lim = BandwidthLimiter::shared(2048).unwrap();

    let start = std::time::Instant::now();
    let handle = tokio::spawn(async move {
        bridge_plain_rate_limited(
            u_r_bridge,
            u_w_bridge,
            w_r_bridge,
            w_w_bridge,
            true,
            vec![],
            Some(&lim),
            None,
        )
        .await;
    });

    let data = pseudo_random_bytes(6 * 1024, 0xfeed_beef);
    u_w_test.write_all(&data).await.unwrap();
    u_w_test.flush().await.unwrap();
    drop(u_w_test);
    drop(w_w_test);

    let mut dec = crate::encryption::SnappyDecompressor::new();
    let mut received = Vec::new();
    let mut first_byte_ms: Option<u128> = None;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = w_r_test.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        let out = dec
            .feed(&buf[..n])
            .unwrap_or_else(|e| panic!("decompress from byte 0 failed: {e}"));
        if !out.is_empty() && first_byte_ms.is_none() {
            first_byte_ms = Some(start.elapsed().as_millis());
        }
        received.extend_from_slice(&out);
    }
    loop {
        let out = dec
            .feed(&[])
            .unwrap_or_else(|e| panic!("decompress drain failed: {e}"));
        if out.is_empty() {
            break;
        }
        if first_byte_ms.is_none() {
            first_byte_ms = Some(start.elapsed().as_millis());
        }
        received.extend_from_slice(&out);
    }
    handle.await.unwrap();
    let elapsed = start.elapsed().as_millis();

    assert_eq!(received, data, "decompressed payload byte-exact");
    let ms = first_byte_ms.expect("payload must arrive at the work side");
    assert!(
        ms >= 900,
        "compressed path must throttle: ~6 KB of incompressible data against a 2 KB burst needs ~2 s, first byte at {ms} ms"
    );
    assert!(ms <= 8000, "expected <= 8000 ms, got {ms} ms");
    assert!(elapsed <= 9000, "expected <= 9000 ms, got {elapsed} ms");
}

/// AsyncRead wrapper that passes `remaining` bytes through, then fails
/// every subsequent read. Used to prove `relay_plain_pooled` propagates a
/// direction error instead of parking on the peer's open read half.
struct FailAfterRead<R> {
    inner: R,
    remaining: usize,
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for FailAfterRead<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = &mut *self;
        if me.remaining == 0 {
            return std::task::Poll::Ready(Err(io::Error::other("injected relay read failure")));
        }
        let take = buf.remaining().min(me.remaining);
        let filled = {
            let init = buf.initialize_unfilled_to(take);
            let mut sub = tokio::io::ReadBuf::new(init);
            std::task::ready!(std::pin::Pin::new(&mut me.inner).poll_read(cx, &mut sub))?;
            sub.filled().len()
        };
        me.remaining -= filled;
        buf.advance(filled);
        std::task::Poll::Ready(Ok(()))
    }
}

impl<R: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FailAfterRead<R> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `relay_plain_pooled` direct pin: byte-exact copies in BOTH directions
/// over real loopback TCP, and half-close FIN propagation — a write-half
/// shutdown at one end must surface as read-EOF at the other (Go
/// libio.Join / tokio copy_bidirectional semantics), letting both
/// directions end.
#[tokio::test]
async fn relay_plain_pooled_byte_exact_and_half_close_fin_propagation() {
    let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = la.local_addr().unwrap();
    let addr_b = lb.local_addr().unwrap();

    // Test handles (outside) + relay ends (inside).
    let (conn_a, srv_a) = {
        let conn_a = tokio::net::TcpStream::connect(addr_a).await.unwrap();
        let srv_a = la.accept().await.unwrap().0;
        (conn_a, srv_a)
    };
    let (conn_b, srv_b) = {
        let conn_b = tokio::net::TcpStream::connect(addr_b).await.unwrap();
        let srv_b = lb.accept().await.unwrap().0;
        (conn_b, srv_b)
    };
    let (mut conn_a, mut conn_b) = (conn_a, conn_b);

    let relay = tokio::spawn(async move { relay_plain_pooled(srv_a, srv_b).await });

    // Direction A -> B.
    let payload_a2b = pseudo_random_bytes(8192, 0xa2b2_a2b2);
    conn_a.write_all(&payload_a2b).await.unwrap();
    // Half-close A's write half: must surface as EOF at B after the data.
    // tokio's TcpStream::shutdown() closes the write half (sends FIN).
    conn_a.shutdown().await.unwrap();

    let mut got_a2b = vec![0u8; 8192];
    conn_b.read_exact(&mut got_a2b).await.unwrap();
    assert_eq!(got_a2b, payload_a2b, "A -> B byte-exact");
    let mut eof = [0u8; 1];
    let n = conn_b.read(&mut eof).await.unwrap();
    assert_eq!(
        n, 0,
        "A's write-half shutdown must propagate as FIN/EOF to B"
    );

    // Direction B -> A (independent half).
    let payload_b2a = pseudo_random_bytes(8192, 0xb2a2_b2a2);
    conn_b.write_all(&payload_b2a).await.unwrap();
    conn_b.shutdown().await.unwrap();

    let mut got_b2a = vec![0u8; 8192];
    conn_a.read_exact(&mut got_b2a).await.unwrap();
    assert_eq!(got_b2a, payload_b2a, "B -> A byte-exact");
    let n = conn_a.read(&mut eof).await.unwrap();
    assert_eq!(
        n, 0,
        "B's write-half shutdown must propagate as FIN/EOF to A"
    );

    // Both directions complete -> the relay returns the byte counts.
    let counts = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay must not hang after both halves close")
        .unwrap()
        .expect("relay must succeed");
    assert_eq!(counts, (8192, 8192), "(A->B, B->A) byte counts");
}

/// `relay_plain_pooled` cancel-on-error pin: when one direction's read
/// fails mid-stream (error-injecting wrapper), the sibling direction is
/// cancelled and the error propagates — no hang on the peer's still-open
/// read half.
#[tokio::test]
async fn relay_plain_pooled_cancels_sibling_direction_on_error() {
    let (mut test_a_w, a_r_bridge) = tokio::io::duplex(65536);
    // Side A fails after 4096 bytes; side B never writes (its read half
    // stays open forever — a hang pre-fix would park here).
    let (b_w_bridge, _b_r_bridge) = tokio::io::duplex(65536);

    let failing_a = FailAfterRead {
        inner: a_r_bridge,
        remaining: 4096,
    };

    let start = std::time::Instant::now();
    let relay = tokio::spawn(async move { relay_plain_pooled(failing_a, b_w_bridge).await });

    // Feed 8 KB: 4096 passes through, then the injected failure fires.
    let data = pseudo_random_bytes(8192, 0x0f41_aa11);
    test_a_w.write_all(&data).await.unwrap();
    test_a_w.flush().await.unwrap();

    let err = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay must return (not hang) when a direction errors")
        .unwrap()
        .expect_err("injected read failure must propagate");
    let elapsed = start.elapsed().as_millis();
    assert!(
        err.to_string().contains("injected relay read failure"),
        "unexpected error: {err}"
    );
    assert!(
        elapsed < 4000,
        "error must surface promptly (no sibling-direction hang), took {elapsed} ms"
    );
    // Keep test_a_w alive until the error check is done; the failed
    // direction owns the a_w half via BiLock split.
    drop(test_a_w);
}

/// `relay_plain_pooled` half-close LINGER pin: a peer that half-closes
/// while its counterpart never sends its own FIN must not park the relay
/// forever. Without the linger this leaked two sockets and two pooled
/// 32 KiB buffers per connection (1490 FIN_WAIT2 + 647 CLOSE_WAIT and
/// ~224 MB RSS+swap observed on a live frpc).
#[tokio::test]
async fn relay_plain_pooled_abandons_idle_half_closed_peer() {
    let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = la.local_addr().unwrap();
    let addr_b = lb.local_addr().unwrap();
    let (mut conn_a, srv_a) = {
        let conn_a = tokio::net::TcpStream::connect(addr_a).await.unwrap();
        let srv_a = la.accept().await.unwrap().0;
        (conn_a, srv_a)
    };
    // B's peer stays open for the whole test: it never writes and never
    // closes — the shape that leaked in production.
    let (mut conn_b, srv_b) = {
        let conn_b = tokio::net::TcpStream::connect(addr_b).await.unwrap();
        let srv_b = lb.accept().await.unwrap().0;
        (conn_b, srv_b)
    };

    let linger = Duration::from_millis(300);
    let start = std::time::Instant::now();
    let relay =
        tokio::spawn(async move { relay_plain_pooled_with_linger(srv_a, srv_b, linger).await });

    // Direction A -> B completes normally: 4 KiB then A's FIN.
    let payload = pseudo_random_bytes(4096, 0xa1a1_0001);
    conn_a.write_all(&payload).await.unwrap();
    conn_a.shutdown().await.unwrap();

    // The FIN must still propagate to B: half-close is preserved.
    let mut got = vec![0u8; 4096];
    conn_b.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload, "A -> B stays byte-exact under the linger");

    // B -> A never makes progress. The relay must give up one linger
    // window after A's EOF rather than parking for the process lifetime.
    let counts = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay must not park forever on a peer that never FINs")
        .unwrap()
        .expect("abandoning a stalled direction is a clean end, not an error");
    assert_eq!(counts, (4096, 0), "(A->B, B->A) byte counts");
    assert!(
        start.elapsed() >= linger,
        "must actually hold the half-close window open, gave up after {:?}",
        start.elapsed()
    );
}

/// `relay_plain_pooled` linger is an IDLE bound, not a deadline measured
/// from the moment of half-close: a peer that keeps sending — slowly —
/// across a total window longer than the linger must be copied to
/// completion (a long response to a half-closed request is the normal
/// HTTP/1.0-ish case this protects).
#[tokio::test]
async fn relay_plain_pooled_linger_does_not_truncate_progressing_peer() {
    let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = la.local_addr().unwrap();
    let addr_b = lb.local_addr().unwrap();
    let (mut conn_a, srv_a) = {
        let conn_a = tokio::net::TcpStream::connect(addr_a).await.unwrap();
        let srv_a = la.accept().await.unwrap().0;
        (conn_a, srv_a)
    };
    let (mut conn_b, srv_b) = {
        let conn_b = tokio::net::TcpStream::connect(addr_b).await.unwrap();
        let srv_b = lb.accept().await.unwrap().0;
        (conn_b, srv_b)
    };

    let linger = Duration::from_secs(1);
    let chunk_size = 2048usize;
    // 5 chunks spaced linger/4 apart: each gap leaves a 4x timing margin
    // (a loaded CI runner must stall for >750 ms to flake it), while the
    // 1.25 s of gaps adds up to more than one full window, so the test
    // still proves the window re-arms per read rather than being a single
    // deadline measured from the half-close.
    let chunks = 5u32;
    let gap = linger / 4;
    let start = std::time::Instant::now();
    let relay =
        tokio::spawn(async move { relay_plain_pooled_with_linger(srv_a, srv_b, linger).await });

    // A sends its request and half-closes: everything after this is on the
    // B -> A direction, which now runs under the linger.
    conn_a.write_all(b"req").await.unwrap();
    conn_a.shutdown().await.unwrap();

    let mut expected = Vec::new();
    for i in 0..chunks {
        let chunk = pseudo_random_bytes(chunk_size, 0x5eed_0000 + i);
        conn_b.write_all(&chunk).await.unwrap();
        let mut got = vec![0u8; chunk_size];
        conn_a.read_exact(&mut got).await.unwrap();
        assert_eq!(got, chunk, "chunk {i} must be forwarded intact");
        expected.extend_from_slice(&chunk);
        // Gap well inside the linger: progress, not a stall.
        tokio::time::sleep(gap).await;
    }
    conn_b.shutdown().await.unwrap();

    let counts = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay must finish once the slow peer finally FINs")
        .unwrap()
        .expect("relay must succeed");
    assert_eq!(
        counts,
        (3, (chunk_size * chunks as usize) as u64),
        "(A->B, B->A) byte counts"
    );
    assert!(
        start.elapsed() > linger,
        "the transfer must outlast a single linger window, took {:?}",
        start.elapsed()
    );
}

/// Work reader whose first read fails with InvalidData — the error
/// shape frp-server's ResponseHeaderInjector produces when it rejects
/// the backend response head (no status line, or the head exceeds the
/// 64 KiB cap).
struct InvalidDataWorkReader;

impl tokio::io::AsyncRead for InvalidDataWorkReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "backend response head has no status line",
        )))
    }
}

/// Work→user bridge: a rejected backend response head (InvalidData) must
/// answer the Go-shaped 404 NotFoundResponse on the user side — the
/// fixed head (Content-Length of the body, Content-Type: text/html,
/// Server: frp/version) plus the 489-byte builtin page — then end the
/// direction. Mirrors Go frp v0.71.0's vhost ErrorHandler
/// (pkg/util/vhost/http.go:128-138): every non-timeout reverse-proxy
/// failure writes the NotFound 404 page (undecodable and oversize
/// backend heads land here; Go's head cap is the 10 MiB
/// maxHeaderResponseSize default, transport.go:2106-2112).
#[tokio::test]
async fn test_bridge_work_to_user_invalid_data_writes_go_404() {
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_work_to_user(
            InvalidDataWorkReader,
            u_w_bridge,
            false, // plaintext passthrough — the error surfaces before any decode
            None,
            None,
        )
        .await;
    });

    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    // Bounded collection: a regression that never writes the 404 (or
    // never ends the direction) must fail this test, not hang the suite.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = u_r_test.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("bridge must write the 404 and end the direction within 5s");
    let expected_head = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nContent-Type: text/html\r\nServer: frp/{}\r\n\r\n",
        GO_404_NOT_FOUND_BODY.len(),
        crate::VERSION
    );
    let mut expected = expected_head.into_bytes();
    expected.extend_from_slice(GO_404_NOT_FOUND_BODY.as_bytes());
    assert_eq!(received, expected);
}

/// Work reader whose first read fails with UnexpectedEof — the error
/// shape frp-server's ResponseHeaderInjector produces when the backend
/// closes before completing a response head (a pre-head EOF is
/// converted to this kind by the injector; the partial unterminated
/// head is dropped, never relayed).
struct UnexpectedEofWorkReader;

impl tokio::io::AsyncRead for UnexpectedEofWorkReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "backend closed before completing a response head",
        )))
    }
}

/// Work→user bridge: a pre-head UnexpectedEof (backend closed without
/// a usable response head) must answer the same Go-shaped 404
/// NotFoundResponse as the InvalidData arm — Go frp v0.71.0's vhost
/// ErrorHandler answers the NotFound 404 page for every non-timeout
/// reverse-proxy failure, and the injector emits both kinds only from
/// its head-gather phase (pkg/util/vhost/http.go:128-138).
#[tokio::test]
async fn test_bridge_work_to_user_unexpected_eof_writes_go_404() {
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_work_to_user(
            UnexpectedEofWorkReader,
            u_w_bridge,
            false, // plaintext passthrough — the error surfaces before any decode
            None,
            None,
        )
        .await;
    });

    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    // Bounded collection: a regression that never writes the 404 (or
    // never ends the direction) must fail this test, not hang the suite.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = u_r_test.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("bridge must write the 404 and end the direction within 5s");
    let expected_head = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nContent-Type: text/html\r\nServer: frp/{}\r\n\r\n",
        GO_404_NOT_FOUND_BODY.len(),
        crate::VERSION
    );
    let mut expected = expected_head.into_bytes();
    expected.extend_from_slice(GO_404_NOT_FOUND_BODY.as_bytes());
    assert_eq!(received, expected);
}

/// Work reader whose first read fails with TimedOut — the error shape
/// frp-server's ResponseHeaderInjector surfaces when its absolute
/// response-head deadline fires (after interim 1xx bytes may already
/// have been served).
struct TimedOutWorkReader;

impl tokio::io::AsyncRead for TimedOutWorkReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "response-head deadline fired",
        )))
    }
}

/// Work→user bridge: a TimedOut read error (the upstream absolute
/// response-head deadline fired — Go's transport errors the whole
/// response and the vhost ErrorHandler answers 504, vhost http.go:128)
/// must write the bare Go-shaped 504 head
/// (`HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n`) and
/// end the direction.
#[tokio::test]
async fn test_bridge_work_to_user_timed_out_writes_go_504() {
    let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

    tokio::spawn(async move {
        bridge_work_to_user(
            TimedOutWorkReader,
            u_w_bridge,
            false, // plaintext passthrough — the error surfaces before any decode
            None,
            None,
        )
        .await;
    });

    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    // Bounded collection: a regression that never writes the 504 (or
    // never ends the direction) must fail this test, not hang the suite.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = u_r_test.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("bridge must write the 504 and end the direction within 5s");
    assert_eq!(
        received,
        GATEWAY_TIMEOUT_504,
        "response-head deadline must render Go's bare 504, got: {:?}",
        String::from_utf8_lossy(&received)
    );
}

/// The eight public entry points are combinations of three independent
/// booleans. Pin the derivation so a future edit cannot silently flip one
/// entry point's meaning — the first version of this plan collapsed
/// "read side already decrypted" and "read side needs decompressing" into one
/// axis, which stopped decompressing `bridge_encrypted(read_is_decrypted =
/// true, compression on)`.
#[test]
///
/// It pins the derivation only: deleting a `.limiter(limiter)` or a
/// `.read_is_plaintext(read_is_decrypted)` from an entry point's builder
/// chain would still pass, because the table never sees a plan built by a
/// wrapper. The pipe tests cover the limiter paths
/// (`test_bridge_plain_rate_limited_bandwidth` and friends); nothing covers
/// a wrapper that forgets to pass it.
fn bridge_plan_keeps_the_entry_point_semantics() {
    let key = [0u8; 16];
    let cases: Vec<(&str, BridgePlan<'_>, (bool, bool, bool))> = vec![
        (
            "bridge_plain(compress)",
            BridgePlan::plain(true),
            (true, true, false),
        ),
        (
            "bridge_plain(no compress)",
            BridgePlan::plain(false),
            (false, false, false),
        ),
        (
            "bridge_plain_decompressed_read",
            BridgePlan::plain(true).without_read_decompression(),
            (true, false, false),
        ),
        (
            "bridge_plain_rate_limited",
            BridgePlan::plain(true),
            (true, true, false),
        ),
        (
            "bridge_plain_rate_limited_decompressed_read",
            BridgePlan::plain(true).without_read_decompression(),
            (true, false, false),
        ),
        (
            "bridge_encrypted(read_is_decrypted = false)",
            BridgePlan::encrypted(&key, true),
            (true, true, false),
        ),
        (
            "bridge_encrypted(read_is_decrypted = true, compress)",
            BridgePlan::encrypted(&key, true).read_is_plaintext(true),
            (true, true, true),
        ),
        (
            "bridge_encrypted(read_is_decrypted = true, no compress)",
            BridgePlan::encrypted(&key, false).read_is_plaintext(true),
            (false, false, true),
        ),
        (
            "bridge_encrypted_decompressed_read",
            BridgePlan::encrypted(&key, true)
                .read_is_plaintext(true)
                .without_read_decompression(),
            (true, false, true),
        ),
        (
            "bridge_encrypted_io",
            BridgePlan::encrypted(&key, true),
            (true, true, false),
        ),
    ];
    for (name, plan, expected) in cases {
        assert_eq!(plan.core_flags(), expected, "{name}");
    }
}

/// The opt-in pieces default to off, so a plan built with `plain(true)` is
/// exactly the old `bridge_plain` call.
#[test]
fn bridge_plan_defaults_leave_the_optional_axes_off() {
    let plan = BridgePlan::plain(false);
    assert!(plan.pre_read.is_empty());
    assert!(plan.limiter.is_none());
    assert!(plan.metrics.is_none());
    assert!(!plan.read_is_plaintext);
    assert!(!plan.decompress_read);
    assert!(matches!(plan.crypto, Crypto::Plain));
}

/// The dispatcher's three answers, pinned so a dispatcher cannot drift from
/// `core_flags`: every encrypted plan runs whole, a plain plan with
/// compression or a limiter splits, and only a bare plain plan takes the
/// fast relay. A plain plan that carries pre-read bytes also splits, because
/// the fast relay has no way to inject them.
#[test]
fn bridge_plan_choice_matches_the_core_it_selects() {
    let key = [7u8; 16];
    let limiter = crate::bandwidth::BandwidthLimiter::shared(1024 * 1024).expect("rate > 0");
    let cases: Vec<(&str, BridgePlan<'_>, BridgeChoice)> = vec![
        (
            "plain, no limit",
            BridgePlan::plain(false),
            BridgeChoice::PlainFastRelay,
        ),
        (
            "plain, compressed",
            BridgePlan::plain(true),
            BridgeChoice::PlainSplit,
        ),
        (
            "plain, limited",
            BridgePlan::plain(false).limiter(Some(&limiter)),
            BridgeChoice::PlainSplit,
        ),
        (
            "plain, both",
            BridgePlan::plain(true).limiter(Some(&limiter)),
            BridgeChoice::PlainSplit,
        ),
        (
            "plain, pre-read only",
            BridgePlan::plain(false).pre_read(vec![1, 2, 3]),
            BridgeChoice::PlainSplit,
        ),
        (
            "encrypted, no limit",
            BridgePlan::encrypted(&key, false),
            BridgeChoice::EncryptedWhole,
        ),
        (
            "encrypted, limited",
            BridgePlan::encrypted(&key, true).limiter(Some(&limiter)),
            BridgeChoice::EncryptedWhole,
        ),
    ];
    for (name, plan, expected) in cases {
        assert_eq!(plan.choice(), expected, "{name}");
    }
}

/// `without_read_decompression` must not touch the write direction: the
/// decompressed-read entry points still compress user→work.
#[test]
fn without_read_decompression_keeps_the_write_side_compressing() {
    let plan = BridgePlan::plain(true).without_read_decompression();
    let (compress, decompress_read, _) = plan.core_flags();
    assert!(compress);
    assert!(!decompress_read);
}

/// Pins the non-Linux lock-free `TcpStream::into_split()` relay path on all
/// platforms (including Linux CI) for byte-exact bidirectional copy, FIN
/// propagation, and idle half-close linger abandonment.
#[tokio::test]
async fn relay_tcp_pooled_byte_exact_and_abandons_idle_half_closed_peer() {
    let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = la.local_addr().unwrap();
    let addr_b = lb.local_addr().unwrap();
    let (mut conn_a, srv_a) = {
        let conn_a = tokio::net::TcpStream::connect(addr_a).await.unwrap();
        let srv_a = la.accept().await.unwrap().0;
        (conn_a, srv_a)
    };
    let (mut conn_b, srv_b) = {
        let conn_b = tokio::net::TcpStream::connect(addr_b).await.unwrap();
        let srv_b = lb.accept().await.unwrap().0;
        (conn_b, srv_b)
    };

    let linger = Duration::from_millis(250);
    let relay =
        tokio::spawn(async move { relay_tcp_pooled_with_linger(srv_a, srv_b, linger).await });

    let a_to_b = pseudo_random_bytes(8192, 0xbeef_0001);
    let b_to_a = pseudo_random_bytes(4096, 0xbeef_0002);
    conn_a.write_all(&a_to_b).await.unwrap();
    conn_b.write_all(&b_to_a).await.unwrap();

    let mut got_b = vec![0u8; a_to_b.len()];
    conn_b.read_exact(&mut got_b).await.unwrap();
    assert_eq!(got_b, a_to_b);

    let mut got_a = vec![0u8; b_to_a.len()];
    conn_a.read_exact(&mut got_a).await.unwrap();
    assert_eq!(got_a, b_to_a);

    // A half-closes while B stays open and silent: linger must release the relay.
    conn_a.shutdown().await.unwrap();
    let mut eof = [0u8; 1];
    assert_eq!(conn_b.read(&mut eof).await.unwrap(), 0);

    let counts = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay_tcp_pooled_with_linger must not hang on silent half-closed peer")
        .unwrap()
        .expect("clean linger end");
    assert_eq!(counts, (a_to_b.len() as u64, b_to_a.len() as u64));
}

/// Regression pin for lock-free `TcpReadHalf` / `TcpWriteHalf` in
/// `transport::tcp`: dropping `TcpWriteHalf` must NOT implicitly call
/// `shutdown(SHUT_WR)` (preserving `tokio::io::WriteHalf` semantics). When
/// `had_pre_read` is true (VHost HTTP request forwarded via `pre_read`),
/// `bridge_user_to_work` skips explicit shutdown and drops `writer` once the
/// user side hits EOF; a client that half-closes right after sending its
/// request must still receive the backend's response without the backend
/// observing a premature TCP FIN on its read side.
#[tokio::test]
async fn tcp_into_split_pre_read_does_not_send_premature_fin() {
    let lu = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut user_client, user_srv) = {
        let c = tokio::net::TcpStream::connect(lu.local_addr().unwrap())
            .await
            .unwrap();
        let s = lu.accept().await.unwrap().0;
        (c, s)
    };
    let (mut backend, work_srv) = {
        let c = tokio::net::TcpStream::connect(lw.local_addr().unwrap())
            .await
            .unwrap();
        let s = lw.accept().await.unwrap().0;
        (c, s)
    };

    let (u_r, u_w) = crate::transport::IoStream::Tcp(user_srv)
        .into_split()
        .unwrap();
    let (w_r, w_w) = crate::transport::IoStream::Tcp(work_srv)
        .into_split()
        .unwrap();

    let pre_read = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let expected_req = pre_read.clone();
    let bridge = tokio::spawn(async move {
        bridge_plain(u_r, u_w, w_r, w_w, false, pre_read, None).await;
    });

    // User half-closes its write half immediately (no further request bytes).
    user_client.shutdown().await.unwrap();

    // Backend receives the pre_read request.
    let mut got_req = vec![0u8; expected_req.len()];
    backend.read_exact(&mut got_req).await.unwrap();
    assert_eq!(got_req, expected_req);

    // Backend must NOT observe premature EOF while preparing its response.
    let mut probe = [0u8; 1];
    let premature =
        tokio::time::timeout(Duration::from_millis(120), backend.read(&mut probe)).await;
    assert!(
        premature.is_err(),
        "backend must not see premature FIN while had_pre_read bridge awaits response: {premature:?}"
    );

    // Backend writes its response and closes; user receives full response.
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    backend.write_all(resp).await.unwrap();
    backend.shutdown().await.unwrap();

    let mut got_resp = Vec::new();
    user_client.read_to_end(&mut got_resp).await.unwrap();
    assert_eq!(got_resp, resp);

    tokio::time::timeout(Duration::from_secs(2), bridge)
        .await
        .expect("bridge must terminate cleanly")
        .unwrap();
}
