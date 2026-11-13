//! Byte-replay transport: serves `pre_read` bytes first, then delegates to
//! the inner transport. Created by [`super::detect_and_strip_magic`] when the
//! consumed magic bytes are not V2 magic, and by the TLS accept path to
//! replay the consumed ClientHello prefix.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{poll_pre_read, BoxedReadHalf, BoxedWriteHalf, Transport};

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

    /// Whether every pre-read byte has already been replayed, i.e. the
    /// wrapper is now a pure pass-through and the inner transport can be
    /// handed out without losing data.
    fn fully_drained(&self) -> bool {
        self.pos >= self.pre_read.len()
    }
}

impl AsyncRead for PreReadTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if poll_pre_read(&this.pre_read, &mut this.pos, buf) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
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

    /// Delegate the raw-TCP fast path once the replayed prefix is spent.
    ///
    /// The server's work connection is wrapped in a `PreRead` after the
    /// connection-type sniff, so before this the zero-copy `splice(2)` bridge
    /// could never engage on the server's side of a plain TCP proxy: every
    /// byte was copied twice in userspace. A `PreRead` with nothing left to
    /// replay carries no state the inner transport cannot supply, so the
    /// wrapper is transparent for the purposes of the fast path (the same
    /// rule `into_split` already applies when it refuses buffered bytes).
    fn try_tcp(&self) -> Option<&tokio::net::TcpStream> {
        if self.fully_drained() {
            self.inner.try_tcp()
        } else {
            None
        }
    }

    fn try_tcp_mut(&mut self) -> Option<&mut tokio::net::TcpStream> {
        if self.fully_drained() {
            self.inner.try_tcp_mut()
        } else {
            None
        }
    }

    fn into_tcp(self: Box<Self>) -> Option<tokio::net::TcpStream> {
        if self.fully_drained() {
            self.inner.into_tcp()
        } else {
            None
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected loopback TCP pair — the only transport whose raw-TCP fast
    /// path (`splice(2)`) is worth probing here.
    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    #[tokio::test]
    async fn drained_prefix_forwards_the_raw_tcp_fast_path() {
        // The server's plain TCP work connection arrives here after the
        // connection-type sniff; before this delegation the splice fast path
        // could never engage on the server side of a plain TCP proxy.
        let (client, peer) = tcp_pair().await;
        let mut drained = Box::new(PreReadTransport::new(
            Vec::new(),
            Box::new(client) as Box<dyn Transport>,
        ));
        assert!(
            drained.try_tcp().is_some(),
            "an empty pre-read prefix must expose the raw TCP stream"
        );
        assert!(drained.try_tcp_mut().is_some());
        assert!(drained.into_tcp().is_some());
        drop(peer);
    }

    #[tokio::test]
    async fn unread_prefix_hides_the_raw_tcp_fast_path() {
        let (client, peer) = tcp_pair().await;
        let pending = Box::new(PreReadTransport::new(
            b"V2".to_vec(),
            Box::new(client) as Box<dyn Transport>,
        ));
        assert!(
            pending.try_tcp().is_none(),
            "bytes still waiting to be replayed cannot be spliced past"
        );
        assert!(pending.into_tcp().is_none());
        drop(peer);
    }
}
