//! Buffered byte-replay transport: serves `buf[pos..]` first, then delegates
//! to the inner transport. Used when V2 magic is detected on a yamux stream:
//! if the bytes are NOT V2 magic, they're buffered and replayed for V1
//! processing.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{BoxedReadHalf, BoxedWriteHalf, Transport};

pub struct BufferedReadTransport {
    pub(super) buf: Vec<u8>,
    pub(super) pos: usize,
    pub(super) inner: Box<dyn Transport>,
}

impl BufferedReadTransport {
    pub fn new(buf: Vec<u8>, pos: usize, inner: Box<dyn Transport>) -> Self {
        Self { buf, pos, inner }
    }
}

impl AsyncRead for BufferedReadTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let remaining = &self.buf[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for BufferedReadTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Transport for BufferedReadTransport {
    fn debug_name(&self) -> &'static str {
        "IoStream::BufferedRead"
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }
    fn into_encrypted(self: Box<Self>, key: [u8; 16]) -> io::Result<Box<dyn Transport>> {
        // Buffered bytes are preserved inside the returned Cipher wrapper;
        // they will be replayed before encrypted reads begin.
        let BufferedReadTransport { buf, pos, inner } = *self;
        if pos < buf.len() {
            // Unconsumed plaintext below the cipher layer would be replayed
            // ABOVE it once the control stream is encrypted — a desync. This
            // is remote-triggerable (junk bytes after a proxy CONNECT
            // response land in the wrapper), so it must be a recoverable
            // error, never an assert panic (release builds are panic=abort).
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "into_encrypted called before buffered bytes consumed",
            ));
        }
        Ok(Box::new(BufferedReadTransport {
            buf,
            pos,
            inner: inner.into_encrypted(key)?,
        }))
    }
    fn into_split(self: Box<Self>) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let BufferedReadTransport { buf, pos, inner } = *self;
        if pos < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "into_split called with buffered bytes",
            ));
        }
        inner.into_split()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_stream::CipherStream;

    /// Build a `BufferedReadTransport` over an in-memory duplex wrapped in a
    /// `CipherStream` (itself a `Transport`), with `pos` bytes of the buffer
    /// consumed.
    fn buffered_read_with(buf: Vec<u8>, pos: usize) -> Box<BufferedReadTransport> {
        let (duplex, _peer) = tokio::io::duplex(1024);
        let inner: Box<dyn Transport> =
            Box::new(CipherStream::new(duplex, [0u8; 16]).expect("rng"));
        Box::new(BufferedReadTransport::new(buf, pos, inner))
    }

    #[test]
    fn into_encrypted_rejects_unconsumed_buffered_bytes() {
        // Regression test for a remote-triggerable panic: a proxy (or MITM)
        // sending junk bytes after the HTTP CONNECT response leaves
        // `pos < buf.len()`, and `into_encrypted` must return Err — never
        // assert-panic (release binaries build with panic=abort).
        let wrapped = buffered_read_with(vec![1, 2, 3], 0);
        // Match manually: `expect_err` requires `Debug` on the Ok type, and
        // `Box<dyn Transport>` does not implement it.
        let err = match wrapped.into_encrypted([0u8; 16]) {
            Ok(_) => panic!("unconsumed buffered bytes must be refused"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "expected InvalidData, got: {err}"
        );
    }

    #[test]
    fn into_encrypted_ok_when_buffered_bytes_consumed() {
        // Fully consumed buffer: the wrapper is preserved (buffered bytes
        // replay before ciphertext reads) and the inner stream is encrypted.
        let wrapped = buffered_read_with(vec![1, 2, 3], 3);
        let encrypted = wrapped
            .into_encrypted([0u8; 16])
            .expect("fully consumed buffer is encryptable");
        assert_eq!(
            encrypted.debug_name(),
            "IoStream::BufferedRead",
            "wrapper must survive into_encrypted"
        );
    }
}
