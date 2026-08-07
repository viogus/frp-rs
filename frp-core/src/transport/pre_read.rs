//! Byte-replay transport: serves `pre_read` bytes first, then delegates to
//! the inner transport. Created by [`super::detect_and_strip_magic`] when the
//! consumed magic bytes are not V2 magic, and by the TLS accept path to
//! replay the consumed ClientHello prefix.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{BoxedReadHalf, BoxedWriteHalf, Transport};

pub struct PreReadTransport {
    pre_read: Vec<u8>,
    pos: usize,
    inner: Box<dyn Transport>,
}

impl PreReadTransport {
    pub fn new(pre_read: Vec<u8>, inner: Box<dyn Transport>) -> Self {
        Self {
            pre_read,
            pos: 0,
            inner,
        }
    }

    /// Consume: return the remaining buffered bytes and the inner transport.
    pub fn into_inner(self) -> (Vec<u8>, Box<dyn Transport>) {
        (self.pre_read[self.pos..].to_vec(), self.inner)
    }
}

impl AsyncRead for PreReadTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.pre_read.len() {
            let remaining = &self.pre_read[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PreReadTransport {
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

impl Transport for PreReadTransport {
    fn debug_name(&self) -> &'static str {
        "IoStream::PreRead"
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }
    fn into_parts(self: Box<Self>) -> Option<(Vec<u8>, Box<dyn Transport>)> {
        Some(self.into_inner())
    }
    fn into_split(self: Box<Self>) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let (pre_read, inner) = self.into_inner();
        if !pre_read.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "into_split called with buffered bytes",
            ));
        }
        inner.into_split()
    }
}
