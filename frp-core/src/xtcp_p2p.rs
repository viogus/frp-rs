//! XTCP P2P data plane: UDP hole punching + KCP-over-UDP stream.
//!
//! Go frp v0.70 uses UDP for XTCP NAT hole punching, then runs KCP
//! (with yamux on top) or QUIC as the data-plane transport. The Rust
//! frp prior to v0.7.0 used TCP simultaneous-open, which is incompatible.
//!
//! This module implements the Go v0.70-compatible path:
//! 1. Reuse the STUN UDP socket for hole punching
//! 2. Exchange UDP punch packets with the peer's candidate addresses
//! 3. Create a KCP session over the established UDP path
//! 4. Expose an AsyncRead + AsyncWrite stream for bridging

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use crate::kcp::{KcpConfig, KcpSession};

/// Hole-punch magic bytes — must match Go frp v0.70 `var holePunchPacket = []byte("frp")`.
const HOLE_PUNCH_MAGIC: &[u8] = b"frp";

/// Default KCP tick interval (ms). 10 ms matches Go frp kcp-go default.
const KCP_TICK_MS: u32 = 10;

/// Default timeout for hole-punch response.
pub const DEFAULT_HOLE_PUNCH_TIMEOUT_MS: u64 = 5000;

/// Derive a KCP conversation ID from a shared session identifier.
///
/// Both sides of an XTCP P2P connection must use the same `conv` for KCP
/// packets to be accepted by the peer's session (the `kcp` crate drops
/// packets with mismatched `conv` when `input_conv` is `false`).
///
/// The NAT hole-punch session ID (`sid`) is known to both visitor (via
/// `NatHoleResp.sid`) and provider (via `XtcpNotification` / `NatHoleResp`).
pub fn conv_from_sid(sid: &str) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    sid.hash(&mut h);
    (h.finish() as u32).max(1)
}

// ---------------------------------------------------------------------------
// Hole punching
// ---------------------------------------------------------------------------

/// Punch a UDP hole to the peer by sending magic packets to each candidate
/// address and waiting for a response. Returns the confirmed peer address.
///
/// `socket` should be the same UDP socket used for STUN (already bound).
/// `candidates` are the peer's candidate addresses from the server's
/// NatHoleResp.
pub async fn punch_udp_hole(
    socket: &UdpSocket,
    candidates: &[String],
    timeout_ms: u64,
) -> Result<SocketAddr, String> {
    if candidates.is_empty() {
        return Err("no candidate addresses".into());
    }

    // Send hole-punch packets to all candidates.
    for addr_str in candidates {
        let peer: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("invalid candidate '{}': {}", addr_str, e))?;
        // Fire-and-forget — some packets may be dropped by NAT.
        let _ = socket.send_to(HOLE_PUNCH_MAGIC, peer).await;
    }

    // Wait for a hole-punch response from the peer.
    let mut buf = [0u8; 16];
    let deadline = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| format!("hole punch timeout after {}ms", timeout_ms))?;

    match deadline {
        Ok((n, peer)) => {
            if &buf[..n] != HOLE_PUNCH_MAGIC {
                // Not our magic — keep waiting (one more try).
                tracing::debug!(peer = %peer, n, "XTCP P2P: unexpected hole-punch data from {}", peer);
                let deadline2 = tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    socket.recv_from(&mut buf),
                )
                .await
                .map_err(|_| "hole punch timeout (2nd attempt)".to_string())?;
                match deadline2 {
                    Ok((n2, peer2)) => {
                        if &buf[..n2] != HOLE_PUNCH_MAGIC {
                            return Err(format!(
                                "unexpected hole-punch data from {}",
                                peer2
                            ));
                        }
                        Ok(peer2)
                    }
                    Err(e) => Err(format!("recv error: {}", e)),
                }
            } else {
                Ok(peer)
            }
        }
        Err(e) => Err(format!("recv error: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// XtcpP2pStream — AsyncRead + AsyncWrite over KCP-in-UDP
// ---------------------------------------------------------------------------

/// A bidirectional KCP stream over a single UDP socket to a specific peer.
///
/// This is a self-contained KCP session — no separate driver task or
/// multi-session KcpSocket. The KCP state machine is driven inline from
/// poll_read / poll_write / poll_flush.
pub struct XtcpP2pStream {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    session: KcpSession,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    /// Monotonic clock: Instant when the stream was created.
    created: Instant,
    /// Last time we ran kcp.update().
    last_update: Instant,
    shutdown: bool,
    /// Data written via poll_write, waiting to be flushed to KCP.
    pending_send: Vec<u8>,
    /// Waker to signal when pending_send is drained (write backpressure).
    write_notify: Arc<Notify>,
}

/// High-water mark for pending_send in bytes. When pending_send exceeds
/// this, poll_write returns Pending to signal backpressure to the caller.
/// KCP drains pending_send on each tick (every 10ms), so this only gates
/// burst writes that outpace the UDP send rate.
const PENDING_SEND_HIGH_WATER: usize = 256 * 1024; // 256 KiB

impl XtcpP2pStream {
    /// Create a new P2P stream from a hole-punched UDP socket.
    ///
    /// `socket` must already have had `punch_udp_hole()` called on it.
    /// `peer_addr` is the peer's confirmed address from the hole punch.
    /// `conv` is the KCP conversation ID (should be random, non-zero).
    /// `kcp_config` configures the KCP session (nodelay, window, MTU).
    pub fn new(
        socket: UdpSocket,
        peer_addr: SocketAddr,
        conv: u32,
        kcp_config: KcpConfig,
    ) -> io::Result<Self> {
        debug_assert!(conv != 0, "KCP conv must be non-zero");

        let (read_tx, read_rx) = mpsc::channel(256);
        let session = KcpSession::new(conv, peer_addr, kcp_config, read_tx);

        let now = Instant::now();
        Ok(Self {
            socket,
            peer_addr,
            session,
            read_rx,
            read_buffer: Vec::new(),
            read_pos: 0,
            created: now,
            last_update: now,
            shutdown: false,
            pending_send: Vec::new(),
            write_notify: Arc::new(Notify::new()),
        })
    }

    /// Return the peer's socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Drive one KCP tick: update clock, send output, recv input.
    fn drive_kcp(&mut self, now_ms: u32) -> io::Result<()> {
        // 1. Flush pending send data to KCP.
        let was_full = self.pending_send.len() >= PENDING_SEND_HIGH_WATER;
        if !self.pending_send.is_empty() {
            let data = std::mem::take(&mut self.pending_send);
            self.session.send(&data)?;
            // Wake write pollers that were blocked on the high-water mark.
            if was_full {
                self.write_notify.notify_waiters();
            }
        }

        // 2. Update KCP state machine → produce output packets.
        let out_packets = self.session.update(now_ms)?;

        // 3. Send output packets (KCP data + ACKs) to peer via UDP.
        for pkt in &out_packets {
            // Non-blocking send: UDP send buffer is typically large enough.
            // If it's full, we drop the packet (KCP retransmits).
            match self.socket.try_send_to(pkt, self.peer_addr) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tracing::debug!(
                        peer = %self.peer_addr,
                        len = pkt.len(),
                        "XTCP P2P: UDP send would block, dropping KCP packet"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        // 4. Drain incoming UDP data and feed to KCP.
        let mut buf = [0u8; 2048];
        loop {
            match self.socket.try_recv_from(&mut buf) {
                Ok((n, src)) => {
                    if src == self.peer_addr {
                        self.session.input(&buf[..n])?;
                    } else {
                        // Drop packets from unexpected sources after
                        // hole punch is established.
                        tracing::trace!(
                            peer = %self.peer_addr,
                            src = %src,
                            "XTCP P2P: ignoring packet from non-peer"
                        );
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        // 5. Push received KCP app data to the read channel.
        self.session.recv_and_push()?;

        self.last_update = Instant::now();
        Ok(())
    }

    /// Run a KCP tick if enough time has passed.
    fn maybe_tick(&mut self) -> io::Result<()> {
        let elapsed_ms = self.last_update.elapsed().as_millis() as u32;
        if elapsed_ms >= KCP_TICK_MS {
            // Monotonic millisecond clock: elapsed since stream creation.
            let now_ms = self.created.elapsed().as_millis() as u32;
            self.drive_kcp(now_ms)?;
            // Check for dead link after driving KCP so the background yamux
            // task (and raw KCP users) can detect dead peers and exit.
            if self.session.is_dead_link() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "KCP dead link (too many retransmissions)",
                ));
            }
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl AsyncRead for XtcpP2pStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }

        // Drain buffered data first.
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            return Poll::Ready(Ok(()));
        }

        // Drive KCP to get new data.
        self.maybe_tick()?;

        // Poll the read channel for app data from KCP.
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — EOF.
                self.shutdown = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for XtcpP2pStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "XTCP P2P stream shut down",
            )));
        }

        // Backpressure: if the pending send buffer exceeds the high-water
        // mark, return Pending and register the waker. The waker is woken
        // in drive_kcp after pending_send is flushed to KCP. Without this,
        // a write-heavy one-directional stream could grow pending_send
        // without bound if UDP sends are slower than data arrival.
        if self.pending_send.len() >= PENDING_SEND_HIGH_WATER {
            let notified = self.write_notify.clone().notified_owned();
            let mut pinned = Box::pin(notified);
            match pinned.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    // pending_send was drained between check and here.
                    // Fall through to append data.
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Accumulate send data — flush happens in drive_kcp.
        self.pending_send.extend_from_slice(buf);

        // Drive KCP to flush.
        self.maybe_tick()?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "XTCP P2P stream shut down",
            )));
        }

        // Force-flush: update KCP and send all output immediately.
        let now_ms = self.created.elapsed().as_millis() as u32;
        let out_packets = match self.session.force_flush(now_ms) {
            Ok(pkts) => pkts,
            Err(e) => return Poll::Ready(Err(e)),
        };

        for pkt in &out_packets {
            match self.socket.try_send_to(pkt, self.peer_addr) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Try blocking send for critical flush
                    tracing::debug!(
                        peer = %self.peer_addr,
                        "XTCP P2P: UDP send would block on flush"
                    );
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Also drain any incoming data.
        let mut buf = [0u8; 2048];
        loop {
            match self.socket.try_recv_from(&mut buf) {
                Ok((n, src)) if src == self.peer_addr => {
                    if let Err(e) = self.session.input(&buf[..n]) {
                        tracing::debug!(error = %e, "XTCP P2P: input error on flush");
                    }
                }
                Ok(_) => {} // Non-peer packet, ignore
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        self.last_update = Instant::now();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}

// Drop: UDP socket is closed when XtcpP2pStream is dropped.
// KCP session cleanup is automatic (drop).

// ---------------------------------------------------------------------------
// XTCP P2P io::stream helper: punch hole + create KCP stream in one step
// ---------------------------------------------------------------------------

/// Punch a UDP NAT hole to the peer and create a KCP-over-UDP stream.
///
/// This is the main entry point for XTCP P2P connections. It:
/// 1. Binds a UDP socket (or reuses an existing one)
/// 2. Sends hole-punch packets to candidates
/// 3. Waits for peer's hole-punch response
/// 4. Creates a KCP session over the established UDP path
/// 5. Returns an AsyncRead + AsyncWrite stream
pub async fn xtcp_p2p_connect(
    socket: UdpSocket,
    candidates: &[String],
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
) -> Result<XtcpP2pStream, String> {
    // 1. Punch hole.
    let peer_addr = punch_udp_hole(&socket, candidates, hole_punch_timeout_ms).await?;

    tracing::info!(
        peer = %peer_addr,
        conv,
        candidates = candidates.len(),
        "XTCP P2P: hole punched to {}, conv={}",
        peer_addr,
        conv,
    );

    // 2. Create KCP stream.
    XtcpP2pStream::new(socket, peer_addr, conv, kcp_config)
        .map_err(|e| format!("create P2P stream: {}", e))
}

// ---------------------------------------------------------------------------
// XTCP P2P connect with yamux multiplexing (Go v0.70 compat)
// ---------------------------------------------------------------------------
//
// Go frp v0.70 wraps KCP with yamux before sending application data:
//   UDP socket → KCP → yamux → user stream
//
// When the `tcp-mux` feature is enabled (default), yamux multiplexing is
// used for Go v0.70 wire compatibility. When disabled, falls back to raw
// KCP (Rust↔Rust only).

/// Create a KCP-over-UDP P2P stream with yamux multiplexing (Go v0.70 compat).
///
/// `yamux_client` selects the yamux role:
/// - `true` = visitor (opens yamux stream, Mode::Client)
/// - `false` = provider (accepts yamux stream, Mode::Server)
///
/// When `tcp-mux` feature is enabled, returns a yamux `Stream` (compat'd to
/// tokio traits). When disabled, returns the raw KCP stream.
///
/// A background task is spawned to drive the yamux Connection, which also
/// keeps KCP ticking (poll_read/poll_write trigger `maybe_tick` every 10ms).
/// Dead link detection in `maybe_tick` ensures the background task exits
/// when the peer stops responding.
// --- yamux-enabled path (default) ---
#[cfg(feature = "tcp-mux")]
pub async fn xtcp_p2p_connect_yamux(
    socket: UdpSocket,
    candidates: &[String],
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    yamux_client: bool,
) -> Result<crate::mux::YamuxStream, String> {
    use std::sync::Mutex;
    use std::time::Duration;
    use futures_util::future::poll_fn;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    use yamux::{Config, Connection, Mode};

    // 1. Punch hole + create KCP stream.
    let kcp_stream = xtcp_p2p_connect(
        socket,
        candidates,
        conv,
        kcp_config,
        hole_punch_timeout_ms,
    )
    .await?;

    // 2. Compat KCP stream to futures traits for yamux.
    let compat_stream = kcp_stream.compat();

    // 3. Create yamux Connection.
    let mut yamux_cfg = Config::default();
    yamux_cfg.set_max_connection_receive_window(Some(128 * 1024 * 1024));
    yamux_cfg.set_max_num_streams(256);

    let mode = if yamux_client {
        Mode::Client
    } else {
        Mode::Server
    };
    let conn = Connection::new(compat_stream, yamux_cfg, mode);
    let conn = Arc::new(Mutex::new(conn));

    // 4. Background task MUST start before the initial stream accept/open.
    //    Yamux I/O drives KCP ticks (poll_read/poll_write → maybe_tick).
    //    Without the background task, KCP stalls and the initial handshake
    //    times out because nobody reads UDP data while waiting.
    let tick_ms = KCP_TICK_MS as u64;
    let bg_conn = conn.clone();
    let (stream_tx, stream_rx) =
        tokio::sync::oneshot::channel::<Result<yamux::Stream, String>>();

    tokio::spawn(async move {
        let keepalive = Duration::from_millis(tick_ms);
        let mut stream_tx = Some(stream_tx);
        loop {
            let result = tokio::time::timeout(
                keepalive,
                poll_fn(|cx| {
                    let mut c = bg_conn.lock().unwrap();
                    // Double-poll: first poll processes stream commands
                    // into pending_frames; second poll sends them on wire.
                    match c.poll_next_inbound(cx) {
                        Poll::Ready(r) => Poll::Ready(r),
                        Poll::Pending => c.poll_next_inbound(cx),
                    }
                }),
            )
            .await;

            match result {
                Ok(Some(Ok(stream))) => {
                    if let Some(tx) = stream_tx.take() {
                        // Send first accepted stream back to connect function.
                        // If receiver is gone, connection closed — exit.
                        if tx.send(Ok(stream)).is_err() {
                            tracing::debug!("yamux P2P: caller dropped, exiting");
                            break;
                        }
                    } else {
                        tracing::debug!("yamux P2P: unexpected inbound stream, ignoring");
                    }
                }
                Ok(Some(Err(e))) => {
                    // If the caller hasn't received a stream yet, send the
                    // error so it doesn't wait for the full timeout.
                    if let Some(tx) = stream_tx.take() {
                        let _ = tx.send(Err(format!("yamux: {e}")));
                    }
                    tracing::debug!("yamux P2P: connection error, exiting");
                    break;
                }
                Ok(None) => {
                    if let Some(tx) = stream_tx.take() {
                        let _ = tx
                            .send(Err("yamux: connection closed before stream".into()));
                    }
                    tracing::debug!("yamux P2P: connection closed, exiting");
                    break;
                }
                Err(_elapsed) => {
                    // Normal timeout — poll_next_inbound was called and
                    // KCP was ticked. Continue the loop.
                }
            }
        }
        tracing::debug!("yamux P2P: background driver exiting");
    });

    // 5. Open or accept the first yamux stream.
    let stream = if yamux_client {
        // Visitor: open a new outbound stream on the shared connection.
        // The background task continuously drives poll_next_inbound,
        // which flushes yamux frames (including the SYN for this stream)
        // to the KCP socket.
        tokio::time::timeout(
            Duration::from_secs(10),
            poll_fn(|cx| conn.lock().unwrap().poll_new_outbound(cx)),
        )
        .await
        .map_err(|_| "yamux: timeout opening stream (10s)".to_string())?
        .map_err(|e| format!("yamux open stream: {e}"))?
    } else {
        // Provider: wait for the background task to accept the first stream.
        tokio::time::timeout(Duration::from_secs(10), stream_rx)
            .await
            .map_err(|_| "yamux: timeout waiting for stream (10s)".to_string())?
            .map_err(|e| format!("yamux accept: recv error: {e}"))?
            .map_err(|e| format!("yamux accept: {e}"))?
    };

    let tokio_stream = stream.compat();

    tracing::info!(
        conv,
        role = if yamux_client { "client" } else { "server" },
        "XTCP P2P yamux: stream established, conv={}",
        conv,
    );

    Ok(tokio_stream)
}

// --- Fallback when tcp-mux is disabled ---

#[cfg(not(feature = "tcp-mux"))]
pub async fn xtcp_p2p_connect_yamux(
    socket: UdpSocket,
    candidates: &[String],
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    _yamux_client: bool,
) -> Result<XtcpP2pStream, String> {
    tracing::info!(
        conv,
        "XTCP P2P: yamux disabled (tcp-mux feature off), using raw KCP stream, conv={}",
        conv,
    );
    xtcp_p2p_connect(socket, candidates, conv, kcp_config, hole_punch_timeout_ms).await
}
