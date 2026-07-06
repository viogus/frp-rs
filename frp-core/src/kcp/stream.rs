//! KCP stream — AsyncRead + AsyncWrite over a KCP session.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::socket::WriteRequest;

static KCP_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static KCP_READ_CALLS: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_CALLS: AtomicU64 = AtomicU64::new(0);

pub struct KcpStream {
    conv: u32,
    pub peer_addr: SocketAddr,
    write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    read_count: u64,
    write_count: u64,
    shutdown: bool,
}

impl KcpStream {
    pub(crate) fn new(
        conv: u32,
        peer_addr: SocketAddr,
        write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
        read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        Self {
            conv,
            peer_addr,
            write_tx,
            read_rx,
            read_buffer: Vec::new(),
            read_pos: 0,
            read_count: 0,
            write_count: 0,
            shutdown: false,
        }
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }
    pub fn global_read_bytes() -> u64 {
        KCP_READ_BYTES.load(Ordering::Relaxed)
    }
    pub fn global_write_bytes() -> u64 {
        KCP_WRITE_BYTES.load(Ordering::Relaxed)
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain buffered data first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            self.read_count += n as u64;
            KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                conv = self.conv,
                n = n,
                total = self.read_count,
                "KCP read: {} bytes (total={})",
                n,
                self.read_count,
            );
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_pos = n;
                }
                self.read_count += n as u64;
                KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    conv = self.conv,
                    n = n,
                    total = self.read_count,
                    first_hex = if n > 0 {
                        hex::encode(&data[..n.min(16)])
                    } else {
                        String::new()
                    },
                    "KCP read: {} bytes (total={})",
                    n,
                    self.read_count,
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "KCP stream shut down",
            )));
        }

        tracing::trace!(
            "KCP WRITE: {} bytes first_hex={}",
            buf.len(),
            hex::encode(&buf[..buf.len().min(32)])
        );

        let (confirm_tx, confirm_rx) = oneshot::channel();
        let req = WriteRequest {
            data: buf.to_vec(),
            confirm: confirm_tx,
        };

        if self.write_tx.send((self.conv, req)).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "KCP driver closed",
            )));
        }

        // Fire-and-forget: don't block on confirm — KCP's flow control via send window
        // handles backpressure. The oneshot confirm is for error reporting only.
        // Drop the receiver — we don't wait.
        drop(confirm_rx);

        let n = buf.len();
        self.write_count += n as u64;
        KCP_WRITE_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        KCP_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        if self.write_count <= 80 || self.write_count % 1024 == 0 {
            tracing::debug!(
                conv = self.conv,
                n = n,
                total = self.write_count,
                global_total = KCP_WRITE_BYTES.load(Ordering::Relaxed),
                first_hex = %hex::encode(&buf[..n.min(32)]),
                "KCP write: {} bytes (stream total={}, global total={})",
                n,
                self.write_count,
                KCP_WRITE_BYTES.load(Ordering::Relaxed),
            );
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}
