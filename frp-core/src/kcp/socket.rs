//! KCP socket driver — UDP event loop shared across all sessions.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::time::{interval, Duration};

use super::config::KcpConfig;
use super::session::KcpSession;
use super::stream::KcpStream;

/// Max unprocessed write requests before KcpStream::poll_write applies
/// backpressure (returns Poll::Pending). Prevents unbounded memory growth
/// in the write_rx mpsc channel under high packet loss.
/// Threshold must be strictly less than the write channel capacity (256)
/// so the backlog gate triggers BEFORE the channel is full. This prevents
/// the try_send-Full lost-wake race in poll_write and poll_flush.
pub(crate) const KCP_WRITE_BACKLOG_THRESHOLD: usize = 200;

/// Hard limit on total KCP sessions. Prevents an attacker from exhausting
/// server memory by sending UDP packets with random conv values.
const MAX_SESSIONS: usize = 1024;

/// Per-IP session limit. Prevents a single host from monopolizing the
/// session table.
const MAX_SESSIONS_PER_IP: usize = 64;

/// Maximum time a KCP session can exist without being accepted by the
/// listener. Sessions that haven't been picked up within this window
/// are cleaned up by the tick loop.
const UNACCEPTED_SESSION_TIMEOUT_MS: u32 = 30_000; // 30 seconds

pub(crate) enum WriteRequest {
    Data(Vec<u8>),
    Flush(tokio::sync::oneshot::Sender<()>),
}

pub(crate) struct KcpSocketHandle {
    pub write_tx: mpsc::Sender<(u32, WriteRequest)>,
    pub register_tx: mpsc::Sender<(u32, SocketAddr, KcpSession)>,
    /// Channel to send newly accepted streams back to KcpListener::accept().
    /// Held here to keep the sender alive; streams are sent internally by KcpSocket.
    #[allow(dead_code)]
    pub accept_tx: mpsc::Sender<KcpStream>,
    /// Notify the socket driver that a session has been accepted by the
    /// listener, so it should no longer be subject to the unaccepted-
    /// session timeout. Carries (conv, peer_addr) to identify the session.
    pub accept_notify_tx: mpsc::Sender<(u32, SocketAddr)>,
    /// Shared write backlog counter: incremented by KcpSocket on recv from
    /// write_rx, decremented after processing. KcpStream reads this to gate
    /// poll_write before sending.
    pub write_backlog: Arc<AtomicUsize>,
    /// Wakes KcpStream poll_write tasks blocked on write backpressure.
    pub write_notify: Arc<Notify>,
}

pub(crate) struct KcpSocket {
    socket: Arc<UdpSocket>,
    config: KcpConfig,
    sessions: HashMap<(u32, SocketAddr), KcpSession>,
    /// conv → peer addr index for O(1) write-path lookups.
    /// Avoids O(n) `iter().find()` on `sessions` in Data/Flush handlers.
    conv_index: HashMap<u32, SocketAddr>,
    /// Per-IP session count for admission control (keyed by IpAddr, not
    /// SocketAddr, so varying source port cannot bypass the per-IP limit).
    peer_session_counts: HashMap<IpAddr, usize>,
    /// Session creation timestamps for sessions not yet accepted by the
    /// listener. Removed on accept (via accept_notify_rx) or on session
    /// removal (dead/error).
    session_created_at: HashMap<(u32, SocketAddr), u32>,
    write_tx: mpsc::Sender<(u32, WriteRequest)>,
    write_rx: mpsc::Receiver<(u32, WriteRequest)>,
    register_rx: mpsc::Receiver<(u32, SocketAddr, KcpSession)>,
    accept_tx: mpsc::Sender<KcpStream>,
    /// Back-channel: listener sends (conv, addr) when it accepts a stream,
    /// so the driver can remove it from the unaccepted timeout set.
    accept_notify_rx: mpsc::Receiver<(u32, SocketAddr)>,
    write_backlog: Arc<AtomicUsize>,
    write_notify: Arc<Notify>,
    start: Instant,
}

impl KcpSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        config: KcpConfig,
    ) -> (Self, KcpSocketHandle, mpsc::Receiver<KcpStream>) {
        const CAP_WRITE: usize = 256;
        const CAP_REGISTER: usize = 64;
        const CAP_ACCEPT: usize = 256;
        const CAP_ACCEPT_NOTIFY: usize = 256;
        let (write_tx, write_rx) = mpsc::channel(CAP_WRITE);
        let (register_tx, register_rx) = mpsc::channel(CAP_REGISTER);
        let (accept_tx, accept_rx) = mpsc::channel(CAP_ACCEPT);
        let (accept_notify_tx, accept_notify_rx) = mpsc::channel(CAP_ACCEPT_NOTIFY);
        let write_backlog = Arc::new(AtomicUsize::new(0));
        let write_notify = Arc::new(Notify::new());
        let this = Self {
            socket,
            config,
            sessions: HashMap::new(),
            conv_index: HashMap::new(),
            peer_session_counts: HashMap::new(),
            session_created_at: HashMap::new(),
            write_tx: write_tx.clone(),
            write_rx,
            register_rx,
            accept_tx: accept_tx.clone(),
            accept_notify_rx,
            write_backlog: write_backlog.clone(),
            write_notify: write_notify.clone(),
            start: Instant::now(),
        };
        let handle = KcpSocketHandle {
            write_tx,
            register_tx,
            accept_tx,
            accept_notify_tx,
            write_backlog,
            write_notify,
        };
        (this, handle, accept_rx)
    }

    pub async fn run(mut self) {
        // Drain any pending registrations sent before the driver was spawned.
        // This prevents a race where recv_from fires before register_tx is processed,
        // causing FEC fallback to create a duplicate session with wrong conv.
        while let Ok((conv, addr, session)) = self.register_rx.try_recv() {
            self.conv_index.insert(conv, addr);
            self.sessions.insert((conv, addr), session);
        }

        let mut tick = interval(Duration::from_millis(10));
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now_ms = self.start.elapsed().as_millis() as u32;
                    let mut to_remove = Vec::new();
                    for (key, session) in &mut self.sessions {
                        match session.update(now_ms) {
                            Ok(packets) => {
                                for pkt in packets {
                                    if let Err(e) = self.socket.send_to(&pkt, key.1).await {
                                        tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP UDP send error");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP session error");
                                to_remove.push(*key);
                                continue;
                            }
                        }
                        if let Err(e) = session.recv_and_push() {
                            tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP recv error");
                            to_remove.push(*key);
                            continue;
                        }
                        // Remove dead sessions (retransmission exhaustion).
                        // is_dead_link() was previously defined but never called.
                        if session.is_dead_link() {
                            tracing::warn!(conv = key.0, peer = %key.1, "KCP session dead link (retransmission limit)");
                            to_remove.push(*key);
                        }
                    }
                    // Mark dead before removal so KcpStream::poll_write fails fast.
                    for key in &to_remove {
                        if let Some(session) = self.sessions.get(key) {
                            session.mark_dead();
                        }
                    }
                    for key in to_remove {
                        self.sessions.remove(&key);
                        self.conv_index.remove(&key.0);
                        self.session_created_at.remove(&key);
                        let ip = key.1.ip();
                        if let Some(count) = self.peer_session_counts.get_mut(&ip) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                self.peer_session_counts.remove(&ip);
                            }
                        }
                    }
                    // Clean up sessions that were never accepted by the listener.
                    // These are created from garbage packets that happen to pass
                    // the first input() check but are never picked up.
                    let mut expired = Vec::new();
                    for (key, created_at) in &self.session_created_at {
                        if now_ms.wrapping_sub(*created_at) > UNACCEPTED_SESSION_TIMEOUT_MS {
                            expired.push(*key);
                        }
                    }
                    // Mark dead before removal.
                    for key in &expired {
                        if let Some(session) = self.sessions.get(key) {
                            session.mark_dead();
                        }
                    }
                    for key in expired {
                        tracing::debug!(conv = key.0, peer = %key.1, "KCP: removing unaccepted session");
                        self.sessions.remove(&key);
                        self.conv_index.remove(&key.0);
                        self.session_created_at.remove(&key);
                        let ip = key.1.ip();
                        if let Some(count) = self.peer_session_counts.get_mut(&ip) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                self.peer_session_counts.remove(&ip);
                            }
                        }
                    }
                }

                Some((conv, req)) = self.write_rx.recv() => {
                    // Backlog was incremented by KcpStream before try_send
                    // for Data requests only (not Flush). Decrement inside
                    // each arm.
                    match req {
                        WriteRequest::Data(data) => {
                            let len = data.len();
                            // O(1) lookup via conv_index instead of O(n) iter().find().
                            let _result = self.conv_index.get(&conv)
                                .and_then(|addr| self.sessions.get_mut(&(conv, *addr)))
                                .map(|s| s.send(&data))
                                .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotConnected, "session not found")));
                            if let Err(ref e) = _result {
                                tracing::error!(conv, len, error = %e, "KCP SOCKET: write failed — session not found");
                            } else {
                                tracing::trace!(conv, len, "KCP SOCKET: write queued {} bytes", len);
                            }
                            // Decrement backlog and wake ONE blocked writer.
                            // notify_one() stores a permit if no waiters exist,
                            // preventing the lost-wake race between poll_write's
                            // notified_owned() and our decrement. (If we used
                            // notify_waiters() and no waiter is registered yet,
                            // the notification is lost, permanently blocking the
                            // writer.)
                            let _prev = self.write_backlog.fetch_sub(1, Ordering::Release);
                            self.write_notify.notify_one();
                        }
                        WriteRequest::Flush(tx) => {
                            // Force immediate KCP flush: update → drain output →
                            // FEC encode → send UDP now. Critical for protocol
                            // correctness: caller needs StartWorkConn on wire
                            // before bridge data so Go frpc can process them as
                            // separate messages.
                            // No backlog decrement — poll_flush does not
                            // increment the backlog (it uses a oneshot for
                            // wakeup, not the backlog gate).
                            tracing::trace!(conv, "KCP SOCKET: flush");
                            let addr = self.conv_index.get(&conv).copied();
                            let packets = if let Some(session) = addr
                                .and_then(|a| self.sessions.get_mut(&(conv, a)))
                            {
                                let now_ms = self.start.elapsed().as_millis() as u32;
                                match session.force_flush(now_ms) {
                                    Ok(pkts) => pkts,
                                    Err(e) => {
                                        tracing::debug!(conv, error = %e, "KCP SOCKET: force_flush error");
                                        Vec::new()
                                    }
                                }
                            } else {
                                Vec::new()
                            };
                            // Send all output packets immediately.
                            if let Some(peer_addr) = addr {
                                for pkt in &packets {
                                    if let Err(e) = self.socket.send_to(pkt, peer_addr).await {
                                        tracing::debug!(conv, peer = %peer_addr, error = %e, "KCP SOCKET: flush send error");
                                    }
                                }
                            }
                            tracing::trace!(conv, npkts = packets.len(), "KCP SOCKET: flush sent {} packets", packets.len());
                            let _ = tx.send(());
                        }
                    }
                }

                recv_result = self.socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((n, src)) => {
                            let data = buf[..n].to_vec();
                            let key = Self::resolve_key(&data, src);
                            let is_fec = data.len() >= 6
                                && (u16::from_le_bytes([data[4], data[5]]) == 0xf1
                                    || u16::from_le_bytes([data[4], data[5]]) == 0xf2);
                            tracing::trace!(conv = key.0, peer = %src, n, is_fec, "KCP SOCKET: recv {} bytes conv={} fec={}", n, key.0, is_fec);
                            if let Some(session) = self.sessions.get_mut(&key) {
                                if let Err(e) = session.input(&data) {
                                    tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP input error");
                                }
                            } else {
                                // FEC fallback: parity shards and data shards whose conv
                                // wasn't found in sessions are routed by peer_addr.
                                // With 6-byte FEC header (Go kcp-go format), conv is only
                                // available in data shards at offset 8.
                                let is_fec = data.len() >= 6
                                    && (u16::from_le_bytes([data[4], data[5]]) == 0xf1
                                        || u16::from_le_bytes([data[4], data[5]]) == 0xf2);
                                let fec_key = if is_fec {
                                    // Find the session matching this peer addr.
                                    // .copied() converts Option<&(u32, SocketAddr)>
                                    // to Option<(u32, SocketAddr)>.
                                    self.sessions.keys()
                                        .find(|(_, a)| *a == src)
                                        .copied()
                                } else {
                                    None
                                };
                                if let Some(fk) = fec_key {
                                    if let Some(session) = self.sessions.get_mut(&fk) {
                                        if let Err(e) = session.input(&data) {
                                            tracing::debug!(conv = fk.0, peer = %src, error = %e, "KCP FEC fallback input error");
                                        }
                                    }
                                } else if key.0 != 0 {
                                    // New peer — validate packet before admission.
                                    // FEC-enabled sessions accept <6 byte packets as
                                    // Ok(()) (too short for header → no-op), which
                                    // would create a permanent session from garbage.
                                    // Require at minimum a valid KCP header (24 bytes
                                    // per kcp crate IKCP_OVERHEAD).
                                    const MIN_KCP_PACKET: usize = 24;
                                    if data.len() < MIN_KCP_PACKET {
                                        tracing::debug!(conv = key.0, peer = %src, len = data.len(), "KCP new peer: packet too short ({}, min {})", data.len(), MIN_KCP_PACKET);
                                        continue;
                                    }

                                    // Admission control — reject if global or per-IP
                                    // limit is reached. Key by IpAddr (not SocketAddr)
                                    // so varying source port cannot bypass per-IP cap.
                                    let ip = src.ip();
                                    let ip_count = self.peer_session_counts.get(&ip).copied().unwrap_or(0);
                                    if self.sessions.len() >= MAX_SESSIONS {
                                        tracing::warn!(conv = key.0, peer = %src, total = self.sessions.len(), "KCP: session limit reached ({MAX_SESSIONS}), dropping new conv={}", key.0);
                                        continue;
                                    }
                                    if ip_count >= MAX_SESSIONS_PER_IP {
                                        tracing::warn!(conv = key.0, peer = %src, ip_sessions = ip_count, "KCP: per-IP session limit reached ({MAX_SESSIONS_PER_IP}), dropping new conv={}", key.0);
                                        continue;
                                    }

                                    // Create session and validate the first packet.
                                    // If input() fails on the very first packet, the
                                    // data is garbage — don't create a permanent session.
                                    let (read_tx, read_rx) = mpsc::channel(256);
                                    let mut session = KcpSession::new(
                                        key.0, src, self.config.clone(), read_tx,
                                    );
                                    if let Err(e) = session.input(&data) {
                                        tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP new peer: first input failed, dropping");
                                        continue;
                                    }
                                    let stream = KcpStream::new(
                                        key.0, src,
                                        self.write_tx.clone(),
                                        read_rx,
                                        self.write_backlog.clone(),
                                        self.write_notify.clone(),
                                        session.alive_handle(),
                                    );
                                    if let Err(mpsc::error::TrySendError::Full(_)) =
                                        self.accept_tx.try_send(stream)
                                    {
                                        tracing::warn!(
                                            conv = key.0,
                                            peer = %key.1,
                                            "KCP: accept channel full, dropping new session"
                                        );
                                        // Clean up the partially-created session.
                                        self.sessions.remove(&key);
                                        self.conv_index.remove(&key.0);
                                        let ip = key.1.ip();
                                        if let Some(count) = self.peer_session_counts.get_mut(&ip) {
                                            *count = count.saturating_sub(1);
                                            if *count == 0 {
                                                self.peer_session_counts.remove(&ip);
                                            }
                                        }
                                        continue;
                                    }
                                    self.conv_index.insert(key.0, key.1);
                                    self.sessions.insert(key, session);
                                    *self.peer_session_counts.entry(src.ip()).or_default() += 1;
                                    let now_ms = self.start.elapsed().as_millis() as u32;
                                    self.session_created_at.insert(key, now_ms);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "KCP UDP recv error");
                        }
                    }
                }

                Some((conv, addr)) = self.accept_notify_rx.recv() => {
                    // KcpListener accepted this session — it is no longer
                    // subject to the unaccepted-session timeout.
                    let key = (conv, addr);
                    if self.session_created_at.remove(&key).is_some() {
                        tracing::debug!(conv, peer = %addr, "KCP: session accepted by listener, removed from expiry set");
                    }
                }

                Some((conv, addr, session)) = self.register_rx.recv() => {
                    let key = (conv, addr);
                    self.conv_index.insert(conv, addr);
                    self.sessions.insert(key, session);
                }
            }
        }
    }

    /// Extract (conv, peer_addr) key from a raw UDP packet.
    /// Plain KCP: conv is first 4 bytes (little-endian u32).
    /// FEC data shard: 6-byte header [seqid: u32 LE][flag: u16 LE], then
    ///   SIZE(2B) + raw KCP data; conv at offset 8 (skip 6B header + 2B SIZE).
    /// FEC parity shard: 6-byte header, no conv available → return (0, src);
    ///   routing handled by FEC fallback below.
    fn resolve_key(data: &[u8], src: SocketAddr) -> (u32, SocketAddr) {
        if data.len() >= 6 {
            let flag = u16::from_le_bytes([data[4], data[5]]);
            if flag == 0xf1 || flag == 0xf2 {
                // FEC packet: 6-byte header, no conv field.
                if flag == 0xf1 && data.len() >= 12 {
                    // Data shard: KCP conv at offset 8 (6B header + 2B SIZE).
                    let conv = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                    if conv != 0 {
                        return (conv, src);
                    }
                }
                // Parity shard or short data shard: can't extract conv.
                return (0, src);
            }
        }
        if data.len() >= 4 {
            let conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            return (conv, src);
        }
        (0, src)
    }
}
