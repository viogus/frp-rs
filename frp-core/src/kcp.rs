//! KCP transport — reliable stream over UDP.
//!
//! Wraps the `kcp` protocol crate in an async Tokio adapter.
//! Each `KcpStream` spawns a background task that drives the KCP
//! state machine (calling `update()` at regular intervals) and
//! forwards data between the UDP socket and the stream read/write
//! channels.
//!
//! KCP parameters (matching xtaci/kcp-go in Go frp v0.69.1):
//!   - nodelay: false (disabled) | true (enabled)
//!   - interval: internal update interval in ms (default 100)
//!   - resend: fast retransmit threshold (default 2)
//!   - nc: no congestion control (default true)

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// KCP configuration parameters (matching Go frp v0.69.1).
#[derive(Debug, Clone)]
pub struct KcpConfig {
    pub nodelay: bool,
    pub interval: i32,
    pub resend: i32,
    pub nc: bool,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self { nodelay: false, interval: 100, resend: 2, nc: true }
    }
}

/// A writer that sends data to a UDP socket via `try_send_to`.
/// Implements `std::io::Write` so it can be used as the `Kcp` output.
///
/// IMPORTANT: the kcp crate's internal `Kcp::flush()` calls `output.write_all()`
/// but NOT `output.flush()`. Therefore `write()` must send immediately — the
/// `flush()` method is only called by the user-facing `Write::flush()` on `Kcp`.
struct UdpOutput {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

impl Write for UdpOutput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Send immediately — kcp crate never calls flush() on the output
        match self.socket.try_send_to(data, self.peer) {
            Ok(_) => Ok(data.len()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // UDP send buffer full — return Ok to avoid breaking KCP,
                // the packet will be retransmitted by KCP later.
                tracing::warn!("KCP UDP send would block ({} bytes)", data.len());
                Ok(data.len())
            }
            Err(e) => {
                tracing::warn!("KCP UDP send error: {}", e);
                Ok(data.len()) // KCP handles loss; don't break the state machine
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Data is already sent in write(); nothing to flush.
        Ok(())
    }
}

/// Async bidirectional KCP stream.
///
/// Created by:
/// - `KcpListener::accept()` — server-side accepted session
/// - `dial_kcp()` — client-side outgoing connection
pub struct KcpStream {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Channel for the accept() loop or client reader to feed raw UDP packets
    /// into the driver's KCP input. Public so KcpListener can store it.
    pub(crate) udp_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Remote peer address
    pub peer_addr: SocketAddr,
    _driver: tokio::task::JoinHandle<()>,
}

impl KcpStream {
    fn new(
        conv: u32,
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        config: KcpConfig,
        initial_data: Option<Vec<u8>>,
    ) -> Self {
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (read_tx, read_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (udp_tx, udp_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let sock = socket.clone();
        let driver = tokio::spawn(async move {
            run_kcp_driver(conv, sock, peer_addr, config, read_tx, write_rx, udp_rx, initial_data).await;
        });

        Self {
            read_rx,
            write_tx,
            udp_tx,
            read_buf: Vec::new(),
            read_pos: 0,
            peer_addr,
            _driver: driver,
        }
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        self._driver.abort();
    }
}

/// Background task that drives the KCP state machine.
///
/// Reads from UDP → feeds into KCP → emits to `read_tx`.
/// Reads from `write_rx` → feeds into KCP → KCP output flushes to UDP.
/// Calls `kcp.update()` periodically (every `interval` ms).
async fn run_kcp_driver(
    conv: u32,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    config: KcpConfig,
    read_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut udp_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    initial_data: Option<Vec<u8>>,
) {
    let output = UdpOutput { socket: socket.clone(), peer: peer_addr };
    let mut kcp = kcp::Kcp::new(conv, output);

    kcp.set_nodelay(config.nodelay, config.interval, config.resend, config.nc);
    kcp.set_wndsize(1024, 1024);
    let _ = kcp.set_mtu(1350);

    let mut recv_buf = vec![0u8; 65536];
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(config.interval as u64));

    // Feed initial data into KCP (first packet received by accept() before
    // the driver was spawned — otherwise it would be lost).
    if let Some(data) = initial_data {
        if kcp.input(&data).is_err() {
            return;
        }
        loop {
            match kcp.recv(&mut recv_buf) {
                Ok(n) if n > 0 => { let _ = read_tx.send(recv_buf[..n].to_vec()); }
                _ => break,
            }
        }
        let now = kcp_now_ms();
        let _ = kcp.update(now);
    }

    loop {
        tokio::select! {
            // Periodic KCP update (retransmissions, window probes, etc.)
            // update() internally calls output.write() + output.flush() for pending data.
            _ = tick.tick() => {
                let now = kcp_now_ms();
                let _ = kcp.update(now);
            }

            // Outgoing data: application writes → KCP send → KCP updates + flushes
            maybe_data = write_rx.recv() => {
                match maybe_data {
                    Some(data) => {
                        if kcp.send(&data).is_err() {
                            break;
                        }
                        let now = kcp_now_ms();
                        let _ = kcp.update(now);
                    }
                    None => break,
                }
            }

            // Incoming UDP data — forwarded from accept() loop (server) or
            // from the client-side UDP reader task.
            maybe_udp = udp_rx.recv() => {
                match maybe_udp {
                    Some(data) => {
                        if kcp.input(&data).is_err() {
                            break;
                        }
                        // Drain reassembled data
                        loop {
                            match kcp.recv(&mut recv_buf) {
                                Ok(n) if n > 0 => {
                                    let _ = read_tx.send(recv_buf[..n].to_vec());
                                }
                                _ => break,
                            }
                        }
                        let now = kcp_now_ms();
                        let _ = kcp.update(now);
                    }
                    None => break,
                }
            }
        }
    }
}

/// Monotonic millisecond clock for KCP timers.
fn kcp_now_ms() -> u32 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(0)
}

/// KCP listener — binds a UDP socket and accepts KCP sessions.
///
/// Incoming packets with a new conversation ID (conv) spawn a new KCP session.
/// This is a best-effort listener: the Go frp protocol uses the control connection
/// to exchange the KCP conversation ID, but our implementation auto-accepts
/// any new conv ID from a new peer address.
pub struct KcpListener {
    socket: Arc<UdpSocket>,
    #[allow(clippy::type_complexity)]
    active: Mutex<HashMap<(SocketAddr, u32), mpsc::UnboundedSender<Vec<u8>>>>,
    config: KcpConfig,
}

impl KcpListener {
    /// Bind a KCP listener on the given address.
    pub async fn bind(addr: &str, config: KcpConfig) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Ok(Self { socket, active: Mutex::new(HashMap::new()), config })
    }

    /// Accept the next incoming KCP connection.
    /// Blocks until a new KCP session is established (first data packet received).
    pub async fn accept(&mut self) -> io::Result<KcpStream> {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            // KCP header: first 4 bytes = conversation ID (little-endian)
            if n < 4 {
                continue;
            }
            let conv = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let key = (src, conv);

            {
                let active = self.active.lock().unwrap();
                if let Some(tx) = active.get(&key) {
                    let _ = tx.send(buf[..n].to_vec());
                    continue;
                }
            }

            // New session: create KCP stream, register for future packets.
            // Pass the initial packet so the driver can feed it into KCP input.
            let initial = buf[..n].to_vec();
            let stream = KcpStream::new(conv, self.socket.clone(), src, self.config.clone(), Some(initial));
            // Store udp_tx so subsequent packets for this session are routed to the driver.
            self.active.lock().unwrap().insert(key, stream.udp_tx.clone());
            return Ok(stream);
        }
    }

    /// Local address of the underlying UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// Dial a KCP connection to a remote peer.
/// Opens a UDP socket, sends the initial KCP packet to establish the session.
pub async fn dial_kcp(addr: &str, config: KcpConfig) -> io::Result<KcpStream> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // Generate a random conversation ID for this session
    let conv: u32 = rand::random();

    // Create the stream — it spawns the driver task.
    // No initial_data; the client driver reads UDP via the reader task below.
    let stream = KcpStream::new(conv, socket.clone(), remote, config, None);

    // Spawn a background task that reads UDP packets from the socket
    // and forwards them to the driver via udp_tx.
    let udp_tx = stream.udp_tx.clone();
    let sock = socket.clone();
    let peer = remote;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, src)) if src == peer => {
                    let _ = udp_tx.send(buf[..n].to_vec());
                }
                Ok(_) => continue, // wrong peer
                Err(_) => break,
            }
        }
    });

    // Don't send a separate initial empty packet — the driver handles
    // all KCP output. The first write to the stream (Login message)
    // produces the first KCP packet, which the server's accept() uses
    // to establish the session.

    Ok(stream)
}

// ---- AsyncRead / AsyncWrite ----

impl tokio::io::AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve buffered data first
        if self.read_pos < self.read_buf.len() {
            let rem = self.read_buf.len() - self.read_pos;
            let n = rem.min(buf.remaining());
            buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Poll the channel for new data from the driver task
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Unbounded channel — always ready
        match self.write_tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::other("kcp write channel closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // KCP sends are asynchronous — no buffering at this layer
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
