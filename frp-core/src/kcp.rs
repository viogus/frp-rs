//! KCP transport — reliable stream over UDP.
//!
//! Thin wrapper around `rust_tokio_kcp`, which claims full kcp-go v5 compatibility
//! (FEC Reed-Solomon encoding/decoding, matching xtaci/kcp-go wire format).
//!
//! KCP parameters (matching Go frp v0.69.1):
//!   - nodelay: true, interval: 20ms, resend: 2, nc: true
//!   - wndsize: (1024, 1024), mtu: 1350
//!   - FEC: dataShards=10, parityShards=3

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use rust_tokio_kcp::{KcpConfig, KcpNoDelayConfig};

/// Global counters for KCP diagnostics.
static KCP_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static KCP_READ_CALLS: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_CALLS: AtomicU64 = AtomicU64::new(0);

/// KCP stream — wraps `rust_tokio_kcp::KcpStream` with stored peer address
/// and conversation ID.
pub struct KcpStream {
    inner: rust_tokio_kcp::KcpStream,
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// KCP conversation ID.
    conv: u32,
    /// Per-stream read count for diagnostics.
    read_count: u64,
    /// Per-stream write count for diagnostics.
    write_count: u64,
}

impl KcpStream {
    /// Return the KCP conversation ID for this stream.
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Global read byte counter (all KCP streams).
    pub fn global_read_bytes() -> u64 {
        KCP_READ_BYTES.load(Ordering::Relaxed)
    }

    /// Global write byte counter (all KCP streams).
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
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        let n = after - before;
        if n > 0 {
            self.read_count += n as u64;
            KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        // Log all reads (including 0-byte and Pending) for diagnostics
        tracing::debug!(
            conv = self.conv,
            n = n,
            total = self.read_count,
            is_pending = matches!(&result, Poll::Pending),
            first_hex = if n > 0 { hex::encode(&buf.filled()[before..(after.min(before + 16))]) } else { String::new() },
            "KCP read: {} bytes (total={}, pending={})",
            n, self.read_count, matches!(&result, Poll::Pending),
        );
        result
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tracing::trace!("KCP WRITE: {} bytes first_hex={}", buf.len(), hex::encode(&buf[..buf.len().min(32)]));
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.write_count += *n as u64;
            KCP_WRITE_BYTES.fetch_add(*n as u64, Ordering::Relaxed);
            KCP_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
            if self.write_count <= 80 || self.write_count % 1024 == 0 {
                let preview_len = (*n).min(32);
                tracing::debug!(
                    conv = self.conv,
                    n = n,
                    total = self.write_count,
                    global_total = KCP_WRITE_BYTES.load(Ordering::Relaxed),
                    first_hex = %hex::encode(&buf[..preview_len]),
                    "KCP write: {} bytes (stream total={}, global total={})",
                    n, self.write_count, KCP_WRITE_BYTES.load(Ordering::Relaxed),
                );
            }
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// KCP listener — wraps `rust_tokio_kcp::KcpListener`.
pub struct KcpListener {
    inner: rust_tokio_kcp::KcpListener,
}

impl KcpListener {
    /// Bind a KCP listener on the given address.
    pub async fn bind(addr: &str, config: KcpConfig) -> io::Result<Self> {
        let inner = rust_tokio_kcp::KcpListener::bind(config, addr)
            .await
            .map_err(io::Error::other)?;
        Ok(Self { inner })
    }

    /// Accept the next incoming KCP connection.
    pub async fn accept(&mut self) -> io::Result<KcpStream> {
        let (inner, peer_addr) = self.inner.accept().await.map_err(io::Error::other)?;
        // conv not exposed by rust_tokio_kcp — use 0 as placeholder.
        // The server only uses conv for logging.
        Ok(KcpStream { inner, peer_addr, conv: 0, read_count: 0, write_count: 0 })
    }

    /// Local address of the underlying UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr().map_err(io::Error::other)
    }
}

/// Dial a KCP connection to a remote peer.
pub async fn dial_kcp(addr: &str, config: KcpConfig) -> io::Result<KcpStream> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;
    let conv: u32 = rand::random();
    let inner = rust_tokio_kcp::KcpStream::connect_with_conv(&config, conv, remote)
        .await
        .map_err(io::Error::other)?;
    Ok(KcpStream { inner, peer_addr: remote, conv, read_count: 0, write_count: 0 })
}

/// Build a KcpConfig matching Go frp v0.69.1 defaults.
pub fn default_kcp_config() -> KcpConfig {
    KcpConfig {
        nodelay: KcpNoDelayConfig {
            nodelay: true,
            interval: 20,
            resend: 2,
            nc: true,
        },
        wnd_size: (1024, 1024),
        mtu: 1350,
        fec_data_shards: 10,
        fec_parity_shards: 3,
        crypt: None, // No KCP-layer encryption — we use TLS on top
        stream: true,
        // Go frp v0.69.1: SetWriteDelay(true) = delay writes to combine small pkts
        //                 SetACKNoDelay(false) = delay ACKs
        // flush_write=true: each write flushes immediately (original behavior)
        flush_write: true,
        flush_acks_input: true,
        ..Default::default()
    }
}
