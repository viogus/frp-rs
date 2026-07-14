//! Internal in-memory listener — channel-based listener for pipe connections.
//!
//! Port of Go frp v0.69.1 `pkg/util/net/listener.go`.
//! Used by the virtual client to accept in-process pipe connections.
//!
//! `Accept()` blocks until a connection is placed via `put_conn()`, which can
//! be called from any task (the sender is cloneable via `handle()`).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Internal in-memory listener that accepts connections sent via `put_conn`.
///
/// Capacity is 128 connections by default (matching Go frp).
pub struct InternalListener {
    /// Sender side — cloneable, stored so `put_conn()` works on any reference.
    tx: mpsc::Sender<DuplexPair>,
    /// Receiver side — unique, consumed by `accept()`.
    rx: mpsc::Receiver<DuplexPair>,
}

/// One half of an in-memory duplex connection (the end consumed by Accept).
#[derive(Debug)]
pub struct DuplexPair(pub(crate) tokio::io::DuplexStream);

impl InternalListener {
    /// Create a new internal listener with the default capacity (128).
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(128);
        Self { tx, rx }
    }

    /// Accept a connection. Blocks until `put_conn` sends one.
    pub async fn accept(&mut self) -> Option<DuplexPair> {
        self.rx.recv().await
    }

    /// Put a connection into the listener for `accept` to retrieve.
    ///
    /// Returns an error if the listener channel is full (128 pending connections).
    pub fn put_conn(&self, conn: DuplexPair) -> Result<(), DuplexPair> {
        self.tx.try_send(conn).map_err(|e| match e {
            mpsc::error::TrySendError::Full(c) => c,
            mpsc::error::TrySendError::Closed(c) => c,
        })
    }

    /// Return a cloneable handle that can be used to put connections.
    /// Useful when the listener is shared across tasks.
    pub fn handle(&self) -> InternalListenerHandle {
        InternalListenerHandle {
            tx: self.tx.clone(),
        }
    }
}

impl Default for InternalListener {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable handle for putting connections into an [`InternalListener`].
///
/// Multiple handles can put connections concurrently into the same listener.
#[derive(Debug, Clone)]
pub struct InternalListenerHandle {
    tx: mpsc::Sender<DuplexPair>,
}

impl InternalListenerHandle {
    /// Put a connection into the associated listener.
    pub fn put_conn(&self, conn: DuplexPair) -> Result<(), DuplexPair> {
        self.tx.try_send(conn).map_err(|e| match e {
            mpsc::error::TrySendError::Full(c) => c,
            mpsc::error::TrySendError::Closed(c) => c,
        })
    }
}

/// Create a paired duplex connection.
///
/// Returns `(A, B)` where data written to A is read from B and vice versa.
/// One end goes into the `InternalListener` (for VNet), the other is used by
/// the frpc service as its "connection" to the frps.
pub fn pipe() -> (DuplexPair, DuplexPair) {
    let (a, b) = tokio::io::duplex(65536);
    (DuplexPair(a), DuplexPair(b))
}

// ── AsyncRead / AsyncWrite for DuplexPair ────────────────────────────────────

impl AsyncRead for DuplexPair {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexPair {
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

    #[tokio::test]
    async fn test_pipe_basic() {
        let (mut a, mut b) = pipe();
        a.write_all(b"hello").await.unwrap();
        drop(a); // Close write end so read_to_end sees EOF

        let mut buf = Vec::new();
        b.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");
    }

    #[tokio::test]
    async fn test_internal_listener_accept() {
        let listener = InternalListener::new();

        // Put a connection, accept it.
        let (a, _b) = pipe();
        listener.put_conn(a).unwrap();

        let mut listener = listener; // make mutable
        let accepted = listener.accept().await;
        assert!(accepted.is_some());
    }

    #[tokio::test]
    async fn test_internal_listener_handle() {
        let listener = InternalListener::new();
        let handle = listener.handle();

        // Put via handle from another "task" context.
        let (a, _b) = pipe();
        handle.put_conn(a).unwrap();

        let mut listener = listener;
        let accepted = listener.accept().await;
        assert!(accepted.is_some());
    }

    #[tokio::test]
    async fn test_pipe_bidirectional() {
        let (mut a, mut b) = pipe();

        // A writes to B
        a.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // B writes to A
        b.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }
}
