//! KCP socket driver — UDP event loop shared across all sessions.

use std::collections::{HashMap, VecDeque};
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

/// Max KCP segments pending send (`snd_buf + snd_queue`, via `wait_snd()`) before
/// KcpStream::poll_write applies backpressure (returns Poll::Pending). Bounds
/// memory when a stalled peer (remote window 0, never ACKing) would otherwise
/// let the KCP send queue grow without limit.
/// Roughly 2x the default 1024-segment send window: with the default MSS of
/// ~1350 bytes this caps un-acked + queued data at ~2.7 MiB per session, far
/// above the healthy steady-state occupancy (snd_buf drains to the window,
/// snd_queue drains every flush), so normal full-window throughput is untouched.
/// Keep it below a single `Kcp`'s practical ceiling; it is a memory bound, not
/// a flow-control signal (KCP's own window remains the flow-control authority).
pub(crate) const KCP_SND_BACKLOG_THRESHOLD: usize = 2048;

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

/// Session-creation rate window (ms). Bursts of brand-new sessions are
/// limited per window so a UDP packet flood cannot fill the 256-entry
/// accept queue (or the session table) faster than legitimate handshakes.
/// Timestamps are `elapsed().as_millis() as u32`; age checks use
/// `wrapping_sub` so the counter's 2^32-ms (~49.7-day) wrap is handled
/// the same way as the `session_created_at` cleanup (window << wrap
/// period, so wrapping subtraction yields the correct elapsed time).
const SESSION_CREATE_WINDOW_MS: u32 = 10_000;

/// Max new sessions the driver accepts per window across all peers.
/// 256 (== accept queue depth) over 10 s — filling the queue now takes a
/// sustained 10 s flood instead of one 256-packet burst.
const MAX_SESSION_CREATES_PER_WINDOW: usize = 256;

/// Max new sessions per IP per window. A single host cannot churn the
/// session table / accept queue with new convs faster than this.
const MAX_SESSION_CREATES_PER_IP_PER_WINDOW: usize = 32;

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
    /// Rolling log of session-creation timestamps (ms) for global rate
    /// limiting. Trimmed on every admission check; bounded by
    /// MAX_SESSION_CREATES_PER_WINDOW.
    session_create_log: VecDeque<u32>,
    /// Per-IP rolling creation logs (ms) for per-source rate limiting.
    /// Entries whose window expires are trimmed; empty logs remove the key
    /// so a flood from many IPs does not accumulate map entries.
    ip_session_create_log: HashMap<IpAddr, VecDeque<u32>>,
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
    /// UDP packets that could not be sent immediately because the socket
    /// send buffer was full (try_send_to). Drained on the next tick — keeps
    /// the driver from blocking on `send_to().await` (head-of-line stall
    /// for every other session on this socket).
    pending_udp: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Pre-allocated Vec for session removal during tick (avoids per-tick allocation).
    to_remove: Vec<(u32, SocketAddr)>,
    /// Pre-allocated Vec for expired unaccepted sessions cleanup during tick.
    expired: Vec<(u32, SocketAddr)>,
    /// Reverse index from SocketAddr -> conv for O(1) FEC fallback lookup.
    /// Avoids O(n) iter().find(|(_, a)| *a == src) on every FEC non-matching packet.
    peer_addr_index: HashMap<SocketAddr, u32>,
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
            session_create_log: VecDeque::new(),
            ip_session_create_log: HashMap::new(),
            write_tx: write_tx.clone(),
            write_rx,
            register_rx,
            accept_tx: accept_tx.clone(),
            accept_notify_rx,
            write_backlog: write_backlog.clone(),
            write_notify: write_notify.clone(),
            start: Instant::now(),
            pending_udp: VecDeque::new(),
            to_remove: Vec::with_capacity(16),
            expired: Vec::with_capacity(16),
            peer_addr_index: HashMap::new(),
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
            self.peer_addr_index.insert(addr, conv);
            self.sessions.insert((conv, addr), session);
        }

        let mut tick = interval(Duration::from_millis(10));
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now_ms = self.start.elapsed().as_millis() as u32;
                    // Re-send packets queued by a full send buffer.
                    self.drain_pending_udp();
                    self.to_remove.clear();
                    for (key, session) in &mut self.sessions {
                        match session.update(now_ms) {
                            Ok(packets) => {
                                for pkt in packets {
                                    Self::send_udp_packet(
                                        &self.socket,
                                        &mut self.pending_udp,
                                        pkt,
                                        key.1,
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP session error");
                                self.to_remove.push(*key);
                                continue;
                            }
                        }
                        if let Err(e) = session.recv_and_push() {
                            tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP recv error");
                            self.to_remove.push(*key);
                            continue;
                        }
                        // Remove dead sessions (retransmission exhaustion).
                        // is_dead_link() was previously defined but never called.
                        if session.is_dead_link() {
                            tracing::warn!(conv = key.0, peer = %key.1, "KCP session dead link (retransmission limit)");
                            self.to_remove.push(*key);
                        }
                    }
                    self.drain_to_remove();
                    // Clean up sessions that were never accepted by the listener.
                    // These are created from garbage packets that happen to pass
                    // the first input() check but are never picked up.
                    self.expired.clear();
                    for (key, created_at) in &self.session_created_at {
                        if now_ms.wrapping_sub(*created_at) > UNACCEPTED_SESSION_TIMEOUT_MS {
                            self.expired.push(*key);
                        }
                    }
                    // Mark dead before removal.
                    for key in &self.expired {
                        if let Some(session) = self.sessions.get(key) {
                            session.mark_dead();
                        }
                    }
                    for key in self.expired.drain(..) {
                        tracing::debug!(conv = key.0, peer = %key.1, "KCP: removing unaccepted session");
                        self.sessions.remove(&key);
                        self.conv_index.remove(&key.0);
                        // Remove from reverse addr index only if this was the last session for this addr.
                        if let Some(&conv) = self.peer_addr_index.get(&key.1) {
                            if conv == key.0 {
                                let has_other = self.sessions.iter().any(|((_, a), _)| *a == key.1);
                                if !has_other {
                                    self.peer_addr_index.remove(&key.1);
                                }
                            }
                        }
                        self.session_created_at.remove(&key);
                        let ip = key.1.ip();
                        if let Some(count) = self.peer_session_counts.get_mut(&ip) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                self.peer_session_counts.remove(&ip);
                            }
                        }
                    }
                    // Trim per-IP session-creation logs and drop empty keys so
                    // a many-IP flood cannot accumulate map entries after their
                    // rate window expires.
                    self.ip_session_create_log.retain(|_, log| {
                        while let Some(&t) = log.front() {
                            if now_ms.wrapping_sub(t) > SESSION_CREATE_WINDOW_MS {
                                log.pop_front();
                            } else {
                                break;
                            }
                        }
                        !log.is_empty()
                    });
                }

                Some((conv, req)) = self.write_rx.recv() => {
                    // Backlog was incremented by KcpStream before try_send
                    // for Data requests only (not Flush). Decrement inside
                    // each arm.
                    match req {
                        WriteRequest::Data(data) => {
                            let len = data.len();
                            // O(1) lookup via conv_index instead of O(n) iter().find().
                            let addr = self.conv_index.get(&conv).copied();
                            let _result = addr
                                .and_then(|a| self.sessions.get_mut(&(conv, a)))
                                .map(|s| s.send(data))
                                .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotConnected, "session not found")));
                            if let Err(ref e) = _result {
                                tracing::error!(conv, len, error = %e, "KCP SOCKET: write failed — session not found");
                            } else {
                                tracing::trace!(conv, len, "KCP SOCKET: write queued {} bytes", len);
                                // Flush-on-write: Go kcp-go flushes on every
                                // Write, but the driver otherwise only drains
                                // output on the 10ms tick / explicit Flush —
                                // V1 control messages (Login/NewProxy/
                                // StartWorkConn) would sit in the send queue
                                // up to ~10-30ms per control round trip.
                                if let Some(peer_addr) = addr {
                                    self.flush_session_output(conv, peer_addr).await;
                                }
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
                            let npkts = if let Some(peer_addr) = addr {
                                self.flush_session_output(conv, peer_addr).await
                            } else {
                                0
                            };
                            tracing::trace!(conv, npkts, "KCP SOCKET: flush sent {} packets", npkts);
                            let _ = tx.send(());
                        }
                    }
                }

                recv_result = self.socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((n, src)) => {
                            // Borrow the receive buffer directly instead of
                            // copying with to_vec(): every use below (resolve_key,
                            // is_fec check, session.input) takes `data` by
                            // reference, and this arm contains no `.await`, so
                            // the borrow is dropped before `buf` is reused.
                            let data: &[u8] = &buf[..n];
                            let key = Self::resolve_key(data, src);
                            let is_fec = data.len() >= 6
                                && (u16::from_le_bytes([data[4], data[5]]) == 0xf1
                                    || u16::from_le_bytes([data[4], data[5]]) == 0xf2);
                            tracing::trace!(conv = key.0, peer = %src, n, is_fec, "KCP SOCKET: recv {} bytes conv={} fec={}", n, key.0, is_fec);
                            if let Some(session) = self.sessions.get_mut(&key) {
                                if let Err(e) = session.input(data) {
                                    tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP input error");
                                } else {
                                    // Deliver received data to the stream
                                    // immediately instead of waiting for the
                                    // next 10ms tick (Go kcp-go reads on
                                    // arrival).
                                    if let Err(e) = session.recv_and_push() {
                                        tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP recv push error");
                                        self.to_remove.push(key);
                                    }
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
                                    // O(1) reverse index lookup instead of O(n) sessions scan.
                                    self.peer_addr_index.get(&src).map(|conv| (*conv, src))
                                } else {
                                    None
                                };
                                if let Some(fk) = fec_key {
                                    if let Some(session) = self.sessions.get_mut(&fk) {
                                        if let Err(e) = session.input(data) {
                                            tracing::debug!(conv = fk.0, peer = %src, error = %e, "KCP FEC fallback input error");
                                        } else if let Err(e) = session.recv_and_push() {
                                            // Same immediate-delivery path as
                                            // the direct-session lookup above.
                                            tracing::debug!(conv = fk.0, peer = %src, error = %e, "KCP FEC fallback recv push error");
                                            self.to_remove.push(fk);
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
                                    // Session-creation RATE limiting (defense
                                    // vs the steady-state caps above): a UDP
                                    // flood of 24-byte packets with random
                                    // convs must not fill the 256-entry accept
                                    // queue (or churn the session table) in
                                    // one burst. Limits: 256 new sessions per
                                    // 10 s globally, 32 per IP per 10 s.
                                    let now_ms = self.start.elapsed().as_millis() as u32;
                                    // Trim global log outside the window.
                                    while let Some(&t) = self.session_create_log.front() {
                                        if now_ms.wrapping_sub(t) > SESSION_CREATE_WINDOW_MS {
                                            self.session_create_log.pop_front();
                                        } else {
                                            break;
                                        }
                                    }
                                    if self.session_create_log.len() >= MAX_SESSION_CREATES_PER_WINDOW
                                    {
                                        tracing::warn!(conv = key.0, peer = %src, "KCP: session-creation rate limit reached ({MAX_SESSION_CREATES_PER_WINDOW}/{SESSION_CREATE_WINDOW_MS}ms), dropping new conv={}", key.0);
                                        continue;
                                    }
                                    // Trim per-IP log (empty keys are dropped
                                    // by the tick cleanup).
                                    {
                                        let log = self.ip_session_create_log.entry(ip).or_default();
                                        while let Some(&t) = log.front() {
                                            if now_ms.wrapping_sub(t) > SESSION_CREATE_WINDOW_MS {
                                                log.pop_front();
                                            } else {
                                                break;
                                            }
                                        }
                                        if log.len() >= MAX_SESSION_CREATES_PER_IP_PER_WINDOW {
                                            tracing::warn!(conv = key.0, peer = %src, "KCP: per-IP session-creation rate limit reached ({MAX_SESSION_CREATES_PER_IP_PER_WINDOW}/{SESSION_CREATE_WINDOW_MS}ms), dropping new conv={}", key.0);
                                            continue;
                                        }
                                        // NOTE: the rate counters are NOT incremented
                                        // here — they are charged only after the
                                        // session is actually created and queued
                                        // (below), so garbage packets that fail
                                        // input() or a saturated accept queue cannot
                                        // consume quota and starve legitimate peers.
                                    }
                                    // Create session and validate the first packet.
                                    // If input() fails on the very first packet, the
                                    // data is garbage — don't create a permanent session.
                                    let (read_tx, read_rx) = mpsc::channel(256);
                                    let mut session = KcpSession::new(
                                        key.0, src, self.config.clone(), read_tx,
                                    );
                                    if let Err(e) = session.input(data) {
                                        tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP new peer: first input failed, dropping");
                                        continue;
                                    }
                                    // Share the session's send-queue backlog counter with the
                                    // stream so poll_write can gate on a stalled peer (window 0)
                                    // instead of letting snd_queue grow without bound.
                                    let (snd_backlog, snd_notify) = session.snd_backlog_handle();
                                    let stream = KcpStream::new(
                                        key.0, src,
                                        self.write_tx.clone(),
                                        read_rx,
                                        self.write_backlog.clone(),
                                        self.write_notify.clone(),
                                        snd_backlog,
                                        snd_notify,
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
                                        // peer_addr_index is NOT removed here: the
                                        // session was never inserted (insertion happens
                                        // only after successful try_send below). Removing
                                        // it would clobber the reverse-index entry of a
                                        // sibling session sharing the same SocketAddr,
                                        // silently dropping their FEC parity shards.
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
                                    self.peer_addr_index.insert(key.1, key.0);
                                    self.sessions.insert(key, session);
                                    *self.peer_session_counts.entry(src.ip()).or_default() += 1;
                                    let now_ms = self.start.elapsed().as_millis() as u32;
                                    self.session_created_at.insert(key, now_ms);
                                    // Charge the rate counters only now that the
                                    // session is actually created and queued — the
                                    // early-return paths above (input() failure,
                                    // accept queue full) must not consume quota.
                                    self.session_create_log.push_back(now_ms);
                                    self.ip_session_create_log
                                        .entry(ip)
                                        .or_default()
                                        .push_back(now_ms);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "KCP UDP recv error");
                        }
                    }
                    // Drain sessions whose read channel closed during this
                    // recv. The tick arm clears `to_remove` before its own
                    // scan, so entries pushed here would otherwise never be
                    // removed — session objects, index entries, and per-IP
                    // counts would leak.
                    self.drain_to_remove();
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
                    self.peer_addr_index.insert(addr, conv);
                    self.sessions.insert(key, session);
                }
            }
        }
    }

    /// Remove the sessions queued on `to_remove` (marking them dead first
    /// so KcpStream::poll_write fails fast) and drop their index entries.
    /// Called from the tick arm after its scan and from the recv arm after
    /// each receive — the tick arm clears `to_remove` before scanning, so
    /// sessions pushed by the recv arm (read channel closed mid-recv) would
    /// otherwise be wiped without ever being removed.
    fn drain_to_remove(&mut self) {
        // Mark dead before removal so KcpStream::poll_write fails fast.
        for key in &self.to_remove {
            if let Some(session) = self.sessions.get(key) {
                session.mark_dead();
            }
        }
        for key in self.to_remove.drain(..) {
            self.sessions.remove(&key);
            self.conv_index.remove(&key.0);
            // Remove from reverse addr index only if this was the last session for this addr.
            if let Some(&conv) = self.peer_addr_index.get(&key.1) {
                if conv == key.0 {
                    let has_other = self.sessions.iter().any(|((_, a), _)| *a == key.1);
                    if !has_other {
                        self.peer_addr_index.remove(&key.1);
                    }
                }
            }
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

    /// Send a UDP packet best-effort: `try_send_to` never blocks the driver.
    /// On a full kernel send buffer the packet is queued for the next tick;
    /// when the queue is full the packet is dropped (KCP retransmission will
    /// resend it, so dropping is safe). Prevents a slow receiver from
    /// stalling UDP receives and every other session on this socket.
    ///
    /// An associated function taking fields explicitly so it can be called
    /// while `self.sessions` is mutably borrowed (field-level borrows).
    fn send_udp_packet(
        socket: &UdpSocket,
        pending_udp: &mut VecDeque<(SocketAddr, Vec<u8>)>,
        pkt: Vec<u8>,
        peer: SocketAddr,
    ) {
        match socket.try_send_to(&pkt, peer) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if pending_udp.len() < 2048 {
                    pending_udp.push_back((peer, pkt));
                }
            }
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "KCP UDP send error");
            }
        }
    }

    /// Re-send packets queued by a previous full send buffer (FIFO).
    fn drain_pending_udp(&mut self) {
        let mut still_pending = VecDeque::new();
        while let Some((pa, pkt)) = self.pending_udp.pop_front() {
            match self.socket.try_send_to(&pkt, pa) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    still_pending.push_back((pa, pkt));
                }
                Err(e) => {
                    tracing::debug!(peer = %pa, error = %e, "KCP UDP pending send error");
                }
            }
        }
        self.pending_udp = still_pending;
    }

    /// Flush a session's pending KCP output to the wire immediately.
    /// Shared by the Data handler (flush-on-write, matching kcp-go's
    /// flush-on-every-Write behavior) and the Flush handler (StartWorkConn
    /// ordering guarantee). No-op when the session is gone. Returns the
    /// number of output packets force_flush produced.
    async fn flush_session_output(&mut self, conv: u32, peer_addr: SocketAddr) -> usize {
        // Drain the pending queue first so delayed packets keep ordering
        // relative to newly flushed ones.
        self.drain_pending_udp();
        let packets = if let Some(session) = self.sessions.get_mut(&(conv, peer_addr)) {
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
        let n = packets.len();
        for pkt in packets {
            Self::send_udp_packet(&self.socket, &mut self.pending_udp, pkt, peer_addr);
        }
        n
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

#[cfg(test)]
mod tests {
    use super::SESSION_CREATE_WINDOW_MS;

    /// The rate-limit trim uses `now.wrapping_sub(ts) > WINDOW` (same
    /// convention as `session_created_at` cleanup) so the u32-ms clock's
    /// 2^32-ms (~49.7-day) wrap cannot wedge the creation logs full and
    /// permanently reject new sessions. Verify the arithmetic both before
    /// and after the wrap.
    #[test]
    fn rate_window_age_handles_u32_wrap() {
        let window = SESSION_CREATE_WINDOW_MS;
        // Before wrap: 5 s before wrap, timestamps recorded 3 s / 60 s earlier.
        let now = u32::MAX - 5_000;
        let fresh = now - 3_000; // 3 s old → inside window
        assert!(now.wrapping_sub(fresh) <= window);
        let old = now - 60_000; // 60 s old → outside window
        assert!(now.wrapping_sub(old) > window);

        // After wrap: clock wrapped to 5 s; ts recorded 1 s before the wrap
        // (~6 s elapsed) and 60 s before the wrap (~65 s elapsed).
        let now_wrapped = 5_000u32;
        let just_before_wrap = u32::MAX - 1_000;
        assert!(now_wrapped.wrapping_sub(just_before_wrap) <= window);
        let long_ago = u32::MAX - 60_000;
        assert!(now_wrapped.wrapping_sub(long_ago) > window);
    }
}
