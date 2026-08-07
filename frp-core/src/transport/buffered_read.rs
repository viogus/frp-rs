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
    fn into_encrypted(self: Box<Self>, key: [u8; 16]) -> Box<dyn Transport> {
        // Buffered bytes are preserved inside the returned Cipher wrapper;
        // they will be replayed before encrypted reads begin.
        let BufferedReadTransport { buf, pos, inner } = *self;
        assert!(
            pos >= buf.len(),
            "into_encrypted called before buffered bytes consumed"
        );
        Box::new(BufferedReadTransport {
            buf,
            pos,
            inner: inner.into_encrypted(key),
        })
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
