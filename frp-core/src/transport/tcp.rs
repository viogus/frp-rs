//! TCP transport: the raw [`tokio::net::TcpStream`] implements [`Transport`].

use std::io;
use std::net::{Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{BoxedReadHalf, BoxedWriteHalf, Transport};

/// Lock-free read half of a split [`TcpStream`].
///
/// Shares the underlying `Arc<TcpStream>` with [`TcpWriteHalf`] without
/// `tokio::io::split`'s `BiLock` mutex. Unlike `tokio::net::tcp::OwnedWriteHalf`,
/// dropping [`TcpWriteHalf`] does NOT implicitly call `shutdown(Shutdown::Write)`,
/// preserving the exact drop semantics of `tokio::io::WriteHalf<TcpStream>`
/// (required by `bridge_user_to_work` when `had_pre_read` is true).
struct TcpReadHalf(Arc<TcpStream>);

/// Lock-free write half of a split [`TcpStream`] (see [`TcpReadHalf`]).
struct TcpWriteHalf(Arc<TcpStream>);

impl AsyncRead for TcpReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.0.poll_read_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            match self.0.try_read_buf(buf) {
                Ok(_) => return Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for TcpWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.0.poll_write_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            match self.0.try_write(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.0.poll_write_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            match self.0.try_write_vectored(bufs) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Match `tokio::net::TcpStream::poll_shutdown` (tokio-rs/tokio#4665):
        // macOS/BSD — and Linux under simultaneous close / RST — return
        // `ENOTCONN` when the peer has already disconnected.
        match socket2::SockRef::from(&*self.0).shutdown(Shutdown::Write) {
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            res => Poll::Ready(res),
        }
    }
}

impl Transport for TcpStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::Tcp"
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
    fn try_tcp(&self) -> Option<&TcpStream> {
        Some(self)
    }
    fn try_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        Some(self)
    }
    fn into_tcp(self: Box<Self>) -> Option<TcpStream> {
        Some(*self)
    }
    fn into_split(self: Box<Self>) -> std::io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let shared = Arc::new(*self);
        Ok((
            Box::new(TcpReadHalf(Arc::clone(&shared))),
            Box::new(TcpWriteHalf(shared)),
        ))
    }
}
