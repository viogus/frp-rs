//! TCP transport: the raw [`tokio::net::TcpStream`] implements [`Transport`].

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;

use super::{BoxedReadHalf, BoxedWriteHalf, Transport};

/// Lock-free write half of a split [`TcpStream`] wrapping [`OwnedWriteHalf`].
///
/// Delegates `poll_write`, `poll_write_vectored`, `poll_flush`, and
/// `poll_shutdown` directly to Tokio's lock-free [`OwnedWriteHalf`] (preserving
/// Tokio's short-read/short-write readiness clearing optimization,
/// tokio-rs/tokio#5866), while overriding [`Drop`] to call
/// [`OwnedWriteHalf::forget`] instead of implicitly sending `SHUT_WR`. This
/// preserves the exact drop semantics of `tokio::io::WriteHalf<TcpStream>`
/// (required by `bridge_user_to_work` when `had_pre_read` is true).
struct TcpWriteHalf(Option<OwnedWriteHalf>);

impl Drop for TcpWriteHalf {
    fn drop(&mut self) {
        if let Some(w) = self.0.take() {
            w.forget();
        }
    }
}

impl AsyncWrite for TcpWriteHalf {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.0.as_mut().expect("TcpWriteHalf alive")).poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.0.as_mut().expect("TcpWriteHalf alive")).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(OwnedWriteHalf::is_write_vectored)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.0.as_mut().expect("TcpWriteHalf alive")).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Match `tokio::net::TcpStream::poll_shutdown` (tokio-rs/tokio#4665)
        // plus Linux simultaneous-close / peer-RST `ENOTCONN`.
        match Pin::new(self.0.as_mut().expect("TcpWriteHalf alive")).poll_shutdown(cx) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            other => other,
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
        let (read_half, write_half) = (*self).into_split();
        Ok((
            Box::new(read_half),
            Box::new(TcpWriteHalf(Some(write_half))),
        ))
    }
}
