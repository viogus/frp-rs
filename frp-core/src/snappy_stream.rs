//! Streaming Snappy (de)compression as `AsyncRead`/`AsyncWrite` wrappers.
//!
//! # Why this module exists
//!
//! The provider-segment bridge (`frp_core::bridge`) compresses per-chunk with
//! a connection-lifetime [`encryption::SnappyCompressor`], which works because
//! the bridge owns both ends of the loop. The **visitor segment** of
//! STCP/XTCP/SUDP instead hands `AsyncRead`/`AsyncWrite` halves to
//! `copy_bidirectional`, `bridge_encrypted`, or the V1 frame protocol, so its
//! Snappy layer must be a transparent stream wrapper. Those wrappers live
//! here.
//!
//! # Wire order (Go frp parity)
//!
//! Go frp wraps the visitor conn as `WithCompression(WithEncryption(rwc, sk))`
//! — snappy **inside**, CFB **outside**:
//!
//! ```text
//! write: plaintext → Snappy frame stream → AES-128-CFB (IV + ciphertext) → socket
//! read:  socket → AES-128-CFB decrypt → Snappy frame stream decode → plaintext
//! ```
//!
//! So the combined wrapper for a visitor segment with both encryption and
//! compression is:
//!
//! ```text
//! SnappyStreamWriter::new(CipherWriter::new(w, sk))   // write half
//! SnappyStreamReader::new(CipherReader::new(r, sk))   // read half
//! ```
//!
//! Snappy framing is the `snap` framed stream (stream identifier + data
//! frames), byte-compatible with Go's `github.com/golang/snappy` writer used
//! by `WithCompression`.
//!
//! # Feature gate
//!
//! With the `compression` feature, the wrappers actually compress/decompress.
//! Without it they degrade to transparent passthrough (identical behavior to
//! the provider-segment bridge, which treats `use_compression` as off when
//! the feature is absent) so call sites need no `#[cfg]` plumbing.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "compression")]
use crate::encryption::{SnappyCompressor, SnappyDecompressor};

/// Read granularity for the decompressor's inner read. Matches the bridge's
/// `BUFFER_SIZE` (32 KiB default) so the two data planes share one working
/// size.
#[cfg(feature = "compression")]
const READ_CHUNK_SIZE: usize = 32 * 1024;

#[cfg(feature = "compression")]
fn io_err(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

// ===========================================================================
// SnappyStreamReader
// ===========================================================================

/// `AsyncRead` that decompresses a Snappy framed stream on the fly.
///
/// Buffers the decompressor's decoded output internally and serves it in
/// whatever-sized reads the caller requests. Handles arbitrary TCP chunk
/// boundaries: partial snappy frames are held by [`SnappyDecompressor`] until
/// a complete frame arrives.
///
/// Wrap *outside* a [`crate::cipher_stream::CipherReader`] for the
/// encrypted+compressed visitor segment (snappy inner, CFB outer — see the
/// module docs).
#[cfg(feature = "compression")]
pub struct SnappyStreamReader<R: AsyncRead + Unpin> {
    inner: R,
    decompressor: SnappyDecompressor,
    /// Decoded output ready to be consumed (produced by the last feed).
    out_buf: Vec<u8>,
    out_pos: usize,
    /// True while the decompressor still has complete frames buffered that
    /// can be drained without reading more input (e.g. a metadata-only
    /// batch from the last feed).
    has_more_complete: bool,
    /// Set once the inner reader returned EOF; no further inner reads.
    eof: bool,
    /// Reusable 32 KiB input scratch for the inner read.
    read_buf: [u8; READ_CHUNK_SIZE],
}

#[cfg(feature = "compression")]
impl<R: AsyncRead + Unpin> SnappyStreamReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            decompressor: SnappyDecompressor::new(),
            out_buf: Vec::new(),
            out_pos: 0,
            has_more_complete: false,
            eof: false,
            read_buf: [0u8; READ_CHUNK_SIZE],
        }
    }
}

#[cfg(feature = "compression")]
impl<R: AsyncRead + Unpin> AsyncRead for SnappyStreamReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = &mut *self;
        loop {
            // 1. Serve buffered decoded output first — one poll may satisfy
            //    the caller from a previously decoded batch without touching
            //    the inner stream again.
            if this.out_pos < this.out_buf.len() {
                let n = std::cmp::min(buf.remaining(), this.out_buf.len() - this.out_pos);
                buf.put_slice(&this.out_buf[this.out_pos..this.out_pos + n]);
                this.out_pos += n;
                return Poll::Ready(Ok(()));
            }

            // 2. Drain complete frames the decompressor already buffered from
            //    the previous feed (extra data frames, or a metadata-only
            //    batch whose output landed after step 1). `feed_into_*` is
            //    budgeted (≤1024 metadata frames per call) so this loop makes
            //    bounded forward progress without reading more input.
            if this.has_more_complete {
                this.out_buf.clear();
                this.out_pos = 0;
                let status = this
                    .decompressor
                    .feed_into_append_progress(&[], &mut this.out_buf)
                    .map_err(io_err)?;
                this.has_more_complete = status.has_more_complete;
                if !this.out_buf.is_empty() {
                    continue;
                }
            }

            // 3. Read a fresh chunk from the inner stream and feed it.
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let filled;
            {
                let mut tmp_buf = ReadBuf::new(&mut this.read_buf);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => filled = tmp_buf.filled().len(),
                    other => return other,
                }
            }
            if filled == 0 {
                this.eof = true;
                // A truncated stream (partial frame buffered at EOF) must
                // surface as an error, matching Go's snappy.Reader
                // (ErrUnexpectedEOF), instead of silently dropping the tail
                // bytes. Normal teardown is unaffected: the writer flushes
                // complete frames before shutdown, so validate_partial_eof()
                // is a no-op on a well-formed stream.
                if let Err(e) = this.decompressor.validate_partial_eof() {
                    return Poll::Ready(Err(io_err(e)));
                }
                return Poll::Ready(Ok(()));
            }
            this.out_buf.clear();
            this.out_pos = 0;
            let status = this
                .decompressor
                .feed_into_append_progress(&this.read_buf[..filled], &mut this.out_buf)
                .map_err(io_err)?;
            this.has_more_complete = status.has_more_complete;
            // Loop back: if a frame decoded, step 1 serves it; if the chunk
            // was a partial frame, step 3 reads more input.
        }
    }
}

/// Transparent passthrough reader (no `compression` feature).
#[cfg(not(feature = "compression"))]
pub struct SnappyStreamReader<R>(R);

#[cfg(not(feature = "compression"))]
impl<R: AsyncRead + Unpin> SnappyStreamReader<R> {
    pub fn new(inner: R) -> Self {
        Self(inner)
    }
}

#[cfg(not(feature = "compression"))]
impl<R: AsyncRead + Unpin> AsyncRead for SnappyStreamReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

// ===========================================================================
// SnappyStreamWriter
// ===========================================================================

/// `AsyncWrite` that compresses writes into a Snappy framed stream.
///
/// A connection-lifetime [`encryption::SnappyCompressor`] keeps the ~128 KiB
/// `FrameEncoder` allocation stable and emits the `sNaPpY` stream identifier
/// exactly once (first compressed chunk), matching Go's `snappy.Writer`.
///
/// **Partial-write safety**: `poll_write` returns the *original uncompressed*
/// length once the compressed form is fully flushed, and compresses at most
/// once per caller write. If the inner stream cannot accept all compressed
/// bytes at once, the remainder is buffered in `pending` and retried on
/// subsequent `poll_write`/`poll_flush` calls without re-compressing (re-
/// compressing would emit a duplicate stream identifier / duplicate frames
/// and corrupt the stream). Same pattern as
/// [`crate::cipher_stream::CipherWriter`].
#[cfg(feature = "compression")]
pub struct SnappyStreamWriter<W: AsyncWrite + Unpin> {
    inner: W,
    compressor: SnappyCompressor,
    /// Compressed-output scratch (allocation reused across writes).
    comp_buf: Vec<u8>,
    /// Compressed bytes left over from a partial write, pending retry.
    pending: Option<Vec<u8>>,
    pending_pos: usize,
    /// Uncompressed length of the pending write — the value `poll_write`
    /// reports once the compressed form is fully flushed.
    pending_orig_len: usize,
}

#[cfg(feature = "compression")]
impl<W: AsyncWrite + Unpin> SnappyStreamWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            compressor: SnappyCompressor::new(),
            comp_buf: Vec::new(),
            pending: None,
            pending_pos: 0,
            pending_orig_len: 0,
        }
    }

    /// Drain a partially-written compressed buffer. Returns `true` when all
    /// pending bytes have been flushed.
    fn drain_pending(this: &mut Self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        if let Some(ref pending) = this.pending {
            let remaining = &pending[this.pending_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    // `remaining` is non-empty here (pending is only held while
                    // bytes remain), so zero progress must surface as a fatal
                    // write-zero — self-waking and re-polling would spin at
                    // 100% CPU until the inner writer makes progress. Mirrors
                    // CipherWriter's WriteZero handling.
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Poll::Ready(Ok(n)) => {
                    this.pending_pos += n;
                    if this.pending_pos >= pending.len() {
                        let orig_len = this.pending_orig_len;
                        this.pending = None;
                        this.pending_pos = 0;
                        this.pending_orig_len = 0;
                        Poll::Ready(Ok(Some(orig_len)))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(None))
        }
    }
}

#[cfg(feature = "compression")]
impl<W: AsyncWrite + Unpin> AsyncWrite for SnappyStreamWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Retry any partially-written compressed bytes first.
        match Self::drain_pending(this, cx) {
            Poll::Ready(Ok(Some(orig_len))) => return Poll::Ready(Ok(orig_len)),
            Poll::Ready(Ok(None)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        this.compressor
            .compress(buf, &mut this.comp_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        match Pin::new(&mut this.inner).poll_write(cx, &this.comp_buf) {
            Poll::Ready(Ok(n)) if n >= this.comp_buf.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(n)) => {
                // Partial write: hand the un-written remainder to the pending
                // buffer (rare backpressure path — one alloc via take).
                this.pending = Some(std::mem::take(&mut this.comp_buf));
                this.pending_pos = n;
                this.pending_orig_len = buf.len();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.pending = Some(std::mem::take(&mut this.comp_buf));
                this.pending_pos = 0;
                this.pending_orig_len = buf.len();
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Drain a pending partial write before flushing, so a flush during
        // backpressure cannot lose compressed bytes.
        match Self::drain_pending(this, cx) {
            Poll::Ready(Ok(Some(_))) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(None)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Best-effort drain of a pending partial write before shutdown.
        match Self::drain_pending(this, cx) {
            Poll::Ready(Ok(Some(_))) => {
                // Still draining; retry once more on the next poll.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Ok(None)) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Transparent passthrough writer (no `compression` feature).
#[cfg(not(feature = "compression"))]
pub struct SnappyStreamWriter<W>(W);

#[cfg(not(feature = "compression"))]
impl<W: AsyncWrite + Unpin> SnappyStreamWriter<W> {
    pub fn new(inner: W) -> Self {
        Self(inner)
    }
}

#[cfg(not(feature = "compression"))]
impl<W: AsyncWrite + Unpin> AsyncWrite for SnappyStreamWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_KEY: [u8; 16] = *b"0123456789abcdef";

    /// Roundtrip a large compressible payload through
    /// `SnappyStreamWriter`→duplex→`SnappyStreamReader`, reading back in tiny
    /// chunks to exercise cross-chunk framing and partial-frame handling.
    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn roundtrip_large_payload_streamed_small_reads() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let write_handle = tokio::spawn(async move {
            let mut w = SnappyStreamWriter::new(client);
            w.write_all(&payload).await.unwrap();
            w.flush().await.unwrap();
            w.shutdown().await.unwrap();
        });

        let mut r = SnappyStreamReader::new(server);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 7]; // tiny reads force many feed boundaries
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        write_handle.await.unwrap();
        assert_eq!(out, expected, "streamed roundtrip must be byte-identical");
    }

    /// Roundtrip with encryption+compression: `SnappyStreamWriter` wrapping a
    /// `CipherWriter` (write side) and `SnappyStreamReader` wrapping a
    /// `CipherReader` (read side) — the exact visitor-segment wire order
    /// (snappy inner, CFB outer).
    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn roundtrip_encrypted_compressed_wire_order() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 97) as u8).collect();
        let expected = payload.clone();

        let write_handle = tokio::spawn(async move {
            let cipher_w = crate::cipher_stream::CipherWriter::new(client, TEST_KEY);
            let mut w = SnappyStreamWriter::new(cipher_w);
            w.write_all(&payload).await.unwrap();
            w.flush().await.unwrap();
            w.shutdown().await.unwrap();
        });

        let cipher_r = crate::cipher_stream::CipherReader::new(server, TEST_KEY);
        let mut r = SnappyStreamReader::new(cipher_r);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        write_handle.await.unwrap();
        assert_eq!(out, expected, "encrypted+compressed roundtrip must match");
    }

    /// Force partial writes with a tiny duplex buffer (64 bytes) — the Snappy
    /// frame stream expands the first write past the buffer capacity, so the
    /// writer must split it across polls without re-compressing (no duplicate
    /// stream identifier / frames). Assert the stream stays byte-identical.
    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn partial_write_no_corruption() {
        let (client, server) = tokio::io::duplex(64);
        let first: Vec<u8> = vec![0xA1u8; 40_000];
        let second: Vec<u8> = vec![0xB2u8; 40_000];
        let first_expected = first.clone();
        let second_expected = second.clone();

        let write_handle = tokio::spawn(async move {
            let mut w = SnappyStreamWriter::new(client);
            w.write_all(&first).await.unwrap();
            w.write_all(&second).await.unwrap();
            w.flush().await.unwrap();
            w.shutdown().await.unwrap();
        });

        let mut r = SnappyStreamReader::new(server);
        let total = first_expected.len() + second_expected.len();
        let mut buf = vec![0u8; total];
        r.read_exact(&mut buf).await.unwrap();

        assert_eq!(
            &buf[..first_expected.len()],
            &first_expected[..],
            "first write corrupted"
        );
        assert_eq!(
            &buf[first_expected.len()..],
            &second_expected[..],
            "second write corrupted"
        );
        write_handle.await.unwrap();
    }

    /// Incompressible data must still roundtrip (snappy falls back to raw
    /// blocks) and must survive interleaved small writes.
    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn roundtrip_incompressible_small_writes() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let payload: Vec<u8> = (0..50_000u32)
            .map(|i| (i.wrapping_mul(131) >> 7) as u8)
            .collect();
        let expected = payload.clone();

        let write_handle = tokio::spawn(async move {
            let mut w = SnappyStreamWriter::new(client);
            for chunk in payload.chunks(313) {
                w.write_all(chunk).await.unwrap();
            }
            w.flush().await.unwrap();
            w.shutdown().await.unwrap();
        });

        let mut r = SnappyStreamReader::new(server);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        write_handle.await.unwrap();
        assert_eq!(out, expected, "incompressible data must roundtrip");
    }

    /// Empty write must not deadlock the reader (EOF on an empty stream).
    #[tokio::test]
    #[cfg(feature = "compression")]
    async fn empty_stream_reports_eof() {
        let (client, server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let mut w = SnappyStreamWriter::new(client);
            let _ = w.shutdown().await;
        });
        let mut r = SnappyStreamReader::new(server);
        let mut buf = [0u8; 16];
        let n = r.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "empty compressed stream must read EOF");
    }

    /// AsyncWrite stub that returns `Ok(0)` for the first `zeros` calls, then
    /// accepts everything — pins how a pathological inner writer surfaces.
    #[cfg(feature = "compression")]
    struct ZeroThenSink {
        zeros: usize,
    }

    #[cfg(feature = "compression")]
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

    /// An inner writer returning `Ok(0)` while a partial write is pending must
    /// surface as `WriteZero` instead of self-waking into an immediate-repoll
    /// 100% CPU spin (the `drain_pending` retry loop).
    #[test]
    #[cfg(feature = "compression")]
    fn drain_pending_ok_zero_surfaces_as_write_zero() {
        let mut w = SnappyStreamWriter::new(ZeroThenSink { zeros: 2 });
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let buf = vec![0x42u8; 100];

        // Poll 1: the fresh write hits Ok(0) → buffered as pending, Pending.
        assert!(matches!(
            Pin::new(&mut w).poll_write(&mut cx, &buf),
            Poll::Pending
        ));

        // Poll 2: the drain retry hits Ok(0) again on a non-empty remainder →
        // WriteZero error, not a self-wake → Pending spin.
        match Pin::new(&mut w).poll_write(&mut cx, &buf) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
            other => panic!("expected WriteZero error, got {other:?}"),
        }
    }

    /// A single transient `Ok(0)` followed by real progress must still flush
    /// the pending write on the next poll — the WriteZero guard must not break
    /// the legitimate partial-write retry path.
    #[test]
    #[cfg(feature = "compression")]
    fn drain_pending_ok_zero_then_progress_flushes() {
        let mut w = SnappyStreamWriter::new(ZeroThenSink { zeros: 1 });
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let buf = vec![0x42u8; 100];

        // Poll 1: fresh write hits Ok(0) → buffered as pending, Pending.
        assert!(matches!(
            Pin::new(&mut w).poll_write(&mut cx, &buf),
            Poll::Pending
        ));

        // Poll 2: the drain retry succeeds → the original write is reported.
        match Pin::new(&mut w).poll_write(&mut cx, &buf) {
            Poll::Ready(Ok(n)) => assert_eq!(n, buf.len()),
            other => panic!("expected Ok({}), got {other:?}", buf.len()),
        }
    }

    /// passthrough stub (no `compression` feature) must behave as plain copy.
    #[tokio::test]
    #[cfg(not(feature = "compression"))]
    async fn passthrough_roundtrip() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let payload = vec![0x5Au8; 10_000];
        let expected = payload.clone();
        let write_handle = tokio::spawn(async move {
            let mut w = SnappyStreamWriter::new(client);
            w.write_all(&payload).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let mut r = SnappyStreamReader::new(server);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        write_handle.await.unwrap();
        assert_eq!(out, expected);
    }
}
