//! Closeable SSH stream wrappers and session teardown.
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-imports
//! `CloseableSshStream`/`terminate_ssh_session` for its listener loop, and the
//! sibling `tests` module also exercises them.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct CloseableSshStream {
    stream: tokio::net::TcpStream,
    read_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    write_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    flush_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    shutdown_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    close_state: Arc<CloseState>,
}

pub(super) struct CloseState {
    token: tokio_util::sync::CancellationToken,
    pub(super) dropped: tokio_util::sync::CancellationToken,
}

#[derive(Clone)]
pub(super) struct SshStreamCloser(pub(super) Arc<CloseState>);

impl CloseableSshStream {
    pub(super) fn new(stream: tokio::net::TcpStream) -> (Self, SshStreamCloser) {
        let token = tokio_util::sync::CancellationToken::new();
        let state = Arc::new(CloseState {
            token: token.clone(),
            dropped: tokio_util::sync::CancellationToken::new(),
        });
        (
            Self {
                stream,
                read_cancelled: Box::pin(token.clone().cancelled_owned()),
                write_cancelled: Box::pin(token.clone().cancelled_owned()),
                flush_cancelled: Box::pin(token.clone().cancelled_owned()),
                shutdown_cancelled: Box::pin(token.cancelled_owned()),
                close_state: state.clone(),
            },
            SshStreamCloser(state),
        )
    }
}

impl Drop for CloseableSshStream {
    fn drop(&mut self) {
        self.close_state.dropped.cancel();
    }
}

impl AsyncRead for CloseableSshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.close_state.token.is_cancelled() || self.read_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CloseableSshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.close_state.token.is_cancelled()
            || self.write_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.close_state.token.is_cancelled()
            || self.flush_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.close_state.token.is_cancelled()
            || self.shutdown_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl SshStreamCloser {
    pub(super) fn close(&self) {
        self.0.token.cancel();
    }

    pub(super) async fn wait_dropped(&self) {
        self.0.dropped.cancelled().await;
    }
}

pub(super) async fn terminate_ssh_session<D>(
    disconnect: D,
    session_task: &mut tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    stream_closer: &SshStreamCloser,
    stage_timeout: std::time::Duration,
) where
    D: Future<Output = ()>,
{
    let _ = tokio::time::timeout(stage_timeout, disconnect).await;
    stream_closer.close();

    if tokio::time::timeout(stage_timeout, &mut *session_task)
        .await
        .is_err()
    {
        session_task.abort();
        let _ = tokio::time::timeout(stage_timeout, &mut *session_task).await;
    }

    let _ = tokio::time::timeout(stage_timeout, stream_closer.wait_dropped()).await;
}
