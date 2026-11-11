//! KCP socket driver — UDP event loop shared across all sessions.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crossbeam_queue::ArrayQueue;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::time::{interval, Duration};

use super::config::{KcpConfig, KCP_WIRE_OVERHEAD, MAX_KCP_MTU};
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

/// Max recycled write chunks kept in the per-socket chunk pool. Each chunk
/// is a reused bridge-write buffer (one `BUFFER_SIZE`, 64 KiB by default), so
/// the pool caps recycled memory at 8 × that per socket (512 KiB by default).
/// Chunks beyond the cap are
/// simply dropped on return.
pub(crate) const CHUNK_POOL_CAP: usize = 8;

/// Pop a reusable write chunk from the pool, or allocate one with
/// `min_capacity` when the pool is empty (first write, or the pool drained
/// by a burst of in-flight writes). The pool is bounded by CHUNK_POOL_CAP.
/// Lock-free (`crossbeam` `ArrayQueue` — the same queue type the bridge
/// buffer pool uses), so the pop/push on the driver hot path never
/// contends on a mutex.
pub(crate) fn chunk_pool_pop(pool: &ArrayQueue<Vec<u8>>, min_capacity: usize) -> Vec<u8> {
    pool.pop()
        .unwrap_or_else(|| Vec::with_capacity(min_capacity))
}

/// Return a consumed write chunk to the pool. Clears the payload (keeping
/// the allocation so the next writer reuses it) and drops the chunk when
/// the pool is at its cap (`push` returns it as `Err`).
pub(crate) fn chunk_pool_push(pool: &ArrayQueue<Vec<u8>>, mut chunk: Vec<u8>) {
    chunk.clear();
    let _ = pool.push(chunk);
}

/// Hard limit on total KCP sessions. Prevents an attacker from exhausting
/// server memory by sending UDP packets with random conv values.
const MAX_SESSIONS: usize = 1024;

// NOTE: a per-IP steady-state session cap was deliberately NOT kept
// (formerly MAX_SESSIONS_PER_IP = 64). Two reasons:
//   1. Same-NAT collateral DoS: UDP source IPs are shared by NAT, and one
//      frpc legitimately holds multiple sessions (a control conn plus one
//      KCP session per work conn). 64 sessions — a few loaded frpc behind
//      one NAT — blocked ALL new sessions from that NAT, including control
//      reconnects: a real availability regression vs Go (kcp-go has no
//      per-IP limit).
//   2. The cap defended nothing: UDP source IPs are spoofable, so per-IP
//      accounting is trivially bypassed by attackers. The actual flood
//      defenses are the global MAX_SESSIONS cap, the global + per-IP
//      session-creation RATE limits (32/IP/10 s), the 24-byte minimum
//      packet check, first-packet input() validation, and the 30 s
//      unaccepted-session reaper — all retained.

/// Maximum time a KCP session can exist without being accepted by the
/// listener. Sessions that haven't been picked up within this window
/// are cleaned up by the tick loop.
const UNACCEPTED_SESSION_TIMEOUT_MS: u32 = 30_000; // 30 seconds

/// Idle grace for the accepted-session reaper (M11): a session whose read
/// channel has closed (its KcpStream was dropped — the frp conn it served
/// ended or its handler's bounded read deadline fired) AND which has seen no
/// inbound packet for this window AND has nothing left to send is removed by
/// the tick arm. Live sessions are untouched — a KcpStream holds the read
/// channel open for the connection's whole lifetime, so the frp layer's own
/// liveness machinery (heartbeats, yamux keepalive) decides when a conn is
/// dead, not this transport timer (a client with a long heartbeat interval
/// keeps its stream open indefinitely — never reaped). The grace exceeds the
/// KCP retransmission ceiling (RTO max 2s), so a peer that is still alive and
/// merely retransmitting re-stamps the session and survives. Together with
/// the ~30s bounded reads of the accept-side handlers this keeps a crafted-
/// session flood's steady-state footprint well under MAX_SESSIONS, so the
/// KCP listener recovers after the flood ends instead of wedging forever.
const ACCEPTED_SESSION_REAP_GRACE_MS: u32 = 5_000; // 5 seconds

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

/// Driver receive buffer size. The recv buffer must absorb ANY wire packet
/// from a peer whose mtu is at most `MAX_KCP_MTU` (1492 + 8 FEC overhead =
/// 1500 wire bytes); the local session's mtu only bounds what we send.
/// Peers are clamped to `MAX_KCP_MTU` (see `KcpSocket::new` and
/// `KcpConfig::clamped`), so 1500 bytes covers every legitimately-sized packet.
pub(crate) const DRIVER_RECV_BUF_SIZE: usize = 1500;

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
    /// Count of live KcpStreams bound to this socket — incremented on
    /// stream creation, decremented on stream drop. The dial driver
    /// self-exits when this reaches zero AND the register channel is
    /// closed (no listener to keep it alive); the listen path keeps
    /// register_tx open, so the driver never exits there.
    pub alive_streams: Arc<AtomicUsize>,
    /// Recycled write-chunk pool shared with the streams of this socket.
    /// poll_write pops a chunk (avoiding a fresh 32 KiB Vec + memcpy per
    /// bridge write); the driver returns chunks after the session's
    /// segmentation has copied the payload out. Bounded by CHUNK_POOL_CAP;
    /// lock-free (`ArrayQueue`), so a chunk is never in two hands.
    pub chunk_pool: Arc<ArrayQueue<Vec<u8>>>,
}

pub(crate) struct KcpSocket {
    socket: Arc<UdpSocket>,
    config: KcpConfig,
    sessions: HashMap<(u32, SocketAddr), KcpSession>,
    /// conv → peer addr index for O(1) write-path lookups.
    /// Avoids O(n) `iter().find()` on `sessions` in Data/Flush handlers.
    conv_index: HashMap<u32, SocketAddr>,
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
    /// Live KcpStream count — shared with KcpSocketHandle, drives the
    /// dial-path driver self-exit check in run().
    alive_streams: Arc<AtomicUsize>,
    /// Recycled write-chunk pool (see KcpSocketHandle::chunk_pool). The
    /// driver returns consumed chunks here after segmenting them into the
    /// session's send queue.
    chunk_pool: Arc<ArrayQueue<Vec<u8>>>,
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
        mut config: KcpConfig,
    ) -> (Self, KcpSocketHandle, mpsc::Receiver<KcpStream>) {
        // Clamp a configured MTU that would overflow the driver's fixed recv
        // buffer: `mtu + KCP_WIRE_OVERHEAD` (max wire packet with FEC) must
        // fit in DRIVER_RECV_BUF_SIZE. The default MTU 1350 is far below the
        // cap; only an explicitly oversized config hits this. This is the
        // listen-path clamp; the dial path clamps earlier via
        // `KcpConfig::clamped` (before both KcpSocket::new and KcpSession::new)
        // so socket and session agree. Sessions created from this socket
        // inherit the clamped value.
        if config.mtu > MAX_KCP_MTU {
            tracing::warn!(
                configured_mtu = config.mtu,
                max_mtu = MAX_KCP_MTU,
                "KCP MTU clamped to {MAX_KCP_MTU} (mtu + FEC overhead {}B must fit the {}B driver recv buffer)",
                KCP_WIRE_OVERHEAD,
                DRIVER_RECV_BUF_SIZE
            );
            config.mtu = MAX_KCP_MTU;
        }
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
        let alive_streams = Arc::new(AtomicUsize::new(0));
        let chunk_pool = Arc::new(ArrayQueue::new(CHUNK_POOL_CAP));
        let this = Self {
            socket,
            config,
            sessions: HashMap::new(),
            conv_index: HashMap::new(),
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
            alive_streams: alive_streams.clone(),
            chunk_pool: chunk_pool.clone(),
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
            alive_streams,
            chunk_pool,
        };
        (this, handle, accept_rx)
    }

    /// Batch receive on Linux: one `recvmmsg` per burst, falling back to a
    /// single `recv_from` elsewhere. Returns `(slot, len, src)` per datagram,
    /// empty when the socket has nothing left.
    async fn drain_recv(&mut self, slots: &mut [Vec<u8>]) {
        // `try_io` clears tokio's readiness when a batch comes back empty; a
        // raw `recvmmsg` would leave the socket marked readable and starve
        // every other arm of the driver's `select!`.
        //
        // The datagrams of a batch are handed over before the next syscall:
        // subsequent rounds reuse the same slots.
        let count = slots.len().min(RECV_BATCH);
        let mut rounds = 0;
        loop {
            let batch = {
                let socket = &self.socket;
                match socket.try_io(Interest::READABLE, || recv_datagrams(socket, slots)) {
                    Ok(b) => b,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "KCP UDP recv error");
                        return;
                    }
                }
            };
            let got = batch.len();
            for (slot, len, src) in batch {
                self.handle_datagram(&slots[slot][..len], src).await;
            }
            rounds += 1;
            if !another_drain_round(got, count, rounds) {
                return;
            }
        }
    }

    async fn handle_datagram(&mut self, data: &[u8], src: SocketAddr) {
        if data.is_empty() {
            return;
        }
        // `data` is the received datagram, borrowed from the driver's receive
        // slot for this call only; nothing below holds it across an await.
        let key = Self::resolve_key(data, src);
        let is_fec = data.len() >= 6
            && (u16::from_le_bytes([data[4], data[5]]) == 0xf1
                || u16::from_le_bytes([data[4], data[5]]) == 0xf2);
        tracing::trace!(conv = key.0, peer = %src, len = data.len(), is_fec, "KCP SOCKET: recv {} bytes conv={} fec={}", data.len(), key.0, is_fec);
        if let Some(session) = self.sessions.get_mut(&key) {
            if let Err(e) = session.input(data) {
                tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP input error");
            } else {
                // Any inbound activity disproves idleness:
                // stamp for the accepted-session reaper
                // (M11) before delivering the data.
                let now_ms = self.start.elapsed().as_millis() as u32;
                session.note_inbound(now_ms);
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
                    // No reaper stamp here (M11): the
                    // fallback sees parity shards whose
                    // conv is not in the packet, and a
                    // parity-only flood from a reused
                    // peer addr must not keep a dead
                    // session alive. Real data frames
                    // always resolve via the direct
                    // lookup above, which stamps.
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
                    return;
                }

                // Admission control — reject if the global
                // session limit is reached (see the note
                // above the constants: the per-IP
                // steady-state cap was removed — same-NAT
                // collateral DoS, and spoofable source IPs
                // make per-IP accounting useless against
                // attackers; rate limits below are the
                // flood defense).
                let ip = src.ip();
                if self.sessions.len() >= MAX_SESSIONS {
                    tracing::warn!(conv = key.0, peer = %src, total = self.sessions.len(), "KCP: session limit reached ({MAX_SESSIONS}), dropping new conv={}", key.0);
                    return;
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
                if self.session_create_log.len() >= MAX_SESSION_CREATES_PER_WINDOW {
                    tracing::warn!(conv = key.0, peer = %src, "KCP: session-creation rate limit reached ({MAX_SESSION_CREATES_PER_WINDOW}/{SESSION_CREATE_WINDOW_MS}ms), dropping new conv={}", key.0);
                    return;
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
                        return;
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
                let mut session = KcpSession::with_chunk_pool(
                    key.0,
                    src,
                    self.config.clone(),
                    read_tx,
                    self.chunk_pool.clone(),
                );
                if let Err(e) = session.input(data) {
                    tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP new peer: first input failed, dropping");
                    return;
                }
                // Baseline the reaper clock (M11) at the
                // admission packet — an accepted session
                // that never receives more data is idle
                // from its creation instant.
                session.note_inbound(now_ms);
                // Share the session's send-queue backlog counter with the
                // stream so poll_write can gate on a stalled peer (window 0)
                // instead of letting snd_queue grow without bound.
                let (snd_backlog, snd_notify) = session.snd_backlog_handle();
                let stream = KcpStream::new(
                    key.0,
                    src,
                    self.write_tx.clone(),
                    read_rx,
                    self.write_backlog.clone(),
                    self.write_notify.clone(),
                    self.chunk_pool.clone(),
                    snd_backlog,
                    snd_notify,
                    session.alive_handle(),
                    self.alive_streams.clone(),
                );
                if let Err(mpsc::error::TrySendError::Full(_)) = self.accept_tx.try_send(stream) {
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
                    return;
                }
                self.conv_index.insert(key.0, key.1);
                self.peer_addr_index.insert(key.1, key.0);
                self.sessions.insert(key, session);
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
        // Fixed-size recv buffer: must hold any wire packet from a peer with
        // mtu <= MAX_KCP_MTU (1492 + 8 overhead = 1500 bytes). The local
        // session's mtu only bounds what WE send — sizing the buffer from it
        // would truncate legit mixed-mtu peers' packets, causing
        // InvalidSegmentDataSize → retransmit loop → dead link.
        // Batch receive buffers: one `recvmmsg` fills as many as are queued,
        // so the driver pays one syscall for a burst of datagrams instead of
        // one per packet (the recv counterpart of `send_udp_batch`).
        let mut recv_slots: Vec<Vec<u8>> = (0..RECV_BATCH)
            .map(|_| vec![0u8; DRIVER_RECV_BUF_SIZE])
            .collect();

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now_ms = self.start.elapsed().as_millis() as u32;
                    // Re-send packets queued by a full send buffer.
                    self.drain_pending_udp();
                    self.to_remove.clear();
                    for (key, session) in &mut self.sessions {
                        // A paused stream must not strand its last bytes: any
                        // held-back tail goes out on the tick.
                        if let Err(e) = session.flush_carry() {
                            tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP carry flush error");
                            self.to_remove.push(*key);
                            continue;
                        }
                        match session.update(now_ms) {
                            Ok(packets) => {
                                Self::send_packets(
                                    &self.socket,
                                    &mut self.pending_udp,
                                    packets,
                                    key.1,
                                    &self.chunk_pool,
                                );
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
                    }
                    // Accepted-session idle reaper (M11) — see
                    // `reap_accepted_idle_sessions`; extracted into its own
                    // method so the three guards are unit-testable.
                    self.reap_accepted_idle_sessions(now_ms);
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
                    // Dial-path self-exit (HIGH leak fix): once the last
                    // stream is dropped and no more registrations can
                    // arrive, the driver has no work left — looping on
                    // tick/recv with an empty session table would hold the
                    // UDP socket + task for the process lifetime (every KCP
                    // dial leaked one; reconnect churn grew unbounded).
                    // `register_rx.is_closed()` separates the dial path
                    // (register_tx is dropped when dial_kcp returns) from
                    // the listen path (KcpListener keeps the handle, and
                    // must keep accepting new wire sessions forever). The
                    // stream counter is the authoritative liveness signal:
                    // the sessions map can lag a dropped stream (the
                    // accepted-session reaper above reclaims idle
                    // closed-channel sessions within the 5s grace, and the
                    // dial path registers no accepted sessions at all) and
                    // must not gate exit. No grace period
                    // is needed — register_tx cannot close before the dial
                    // stream exists (KcpStream::new increments before
                    // dial_kcp returns), so this condition is never
                    // observed while a stream is alive.
                    // Check closed FIRST (round 6, LOW C2): observing the
                    // channel close happens-after every register send, and
                    // every send happens-after its stream's increment, so
                    // the subsequent Acquire read of alive_streams is
                    // guaranteed to see the final count. Reading the counter
                    // first could observe a stale 0 while a concurrent
                    // KcpStream::new is mid-increment.
                    //
                    // Pending-work gates: the driver must not exit while
                    // sessions still hold unsent/unacked segments, or while
                    // WriteRequests handed off by a dropped stream sit
                    // unprocessed in the write channel. `write_all` +
                    // `shutdown` + stream drop completes in milliseconds —
                    // long before the peer ACKs a full window — so
                    // `alive_streams == 0` alone (the round-7 leak fix)
                    // silently discarded trailing data: the session keeps
                    // its 268 queued segments forever, the peer's ACKs are
                    // never read, and the connection wedges. Once the stream
                    // is gone no new writes can arrive (write_tx dropped
                    // with it), so the write channel drains monotonically
                    // and `is_empty()` is race-free here.
                    if self.register_rx.is_closed()
                        && self.alive_streams.load(Ordering::Acquire) == 0
                        && self.write_rx.is_empty()
                        && !self.sessions.values().any(|s| s.wait_snd() > 0)
                    {
                        tracing::debug!(
                            "KCP SOCKET: dial driver exiting (no live streams, register channel closed)"
                        );
                        break;
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
                            let addr = self.conv_index.get(&conv).copied();
                            // Borrow the payload into the session: the KCP
                            // segmentation copies it into segments, so the
                            // chunk survives and is recycled into the pool
                            // below (M1: no fresh Vec alloc per bridge write).
                            //
                            // `send_chunked` splits by the window bound:
                            // `send` rejects one buffer larger than the send
                            // window (~176 KiB) with UserBufTooBig, which
                            // would silently drop the payload after
                            // poll_write already claimed it (write chunk >
                            // one KCP window = data loss).
                            let _result = match addr.and_then(|a| self.sessions.get_mut(&(conv, a))) {
                                Some(session) => session.send_carry(&data),
                                None => Err(io::Error::new(
                                    io::ErrorKind::NotConnected,
                                    "session not found",
                                )),
                            };
                            if let Err(ref e) = _result {
                                tracing::error!(conv, len, error = %e, "KCP SOCKET: write failed");
                            } else {
                                tracing::trace!(conv, len, "KCP SOCKET: write queued {} bytes", len);
                                // Flush-on-write: Go kcp-go flushes on every
                                // Write, but the driver otherwise only drains
                                // output on the 10ms tick / explicit Flush —
                                // V1 control messages (Login/NewProxy/
                                // StartWorkConn) would sit in the send queue
                                // up to ~10-30ms per control round trip.
                                //
                                // `send_carry` holds back a partial trailing
                                // segment, so a write that produced no whole
                                // segment has nothing to flush: the bytes wait
                                // in the carry for the next write or the tick.
                                let queued_full_segment = matches!(_result, Ok(true));
                                if queued_full_segment {
                                    if let Some(peer_addr) = addr {
                                        self.flush_session_output(conv, peer_addr).await;
                                    }
                                }
                            }
                            // Burst-end flush. `send_carry` holds a partial
                            // trailing segment back so the NEXT write can fill
                            // it, which is a win only while writes keep coming.
                            // When the writer has nothing else queued (a
                            // request/response shape rather than a bulk
                            // stream), that tail would otherwise wait for the
                            // 10 ms tick — and a reply that ends mid-segment
                            // then costs a full tick of latency, which measured
                            // as a 10x ping-pong regression (65 -> 6 MiB/s on
                            // the protocol matrix). Release it now.
                            if let Some(peer_addr) = addr {
                                if self.write_rx.is_empty() {
                                    if let Some(session) = self.sessions.get_mut(&(conv, peer_addr)) {
                                        if let Err(e) = session.flush_carry() {
                                            tracing::debug!(conv, error = %e, "KCP SOCKET: carry flush error");
                                        }
                                    }
                                    self.flush_session_output(conv, peer_addr).await;
                                }
                            }
                            // The session's segmentation copied the payload
                            // out; clear the chunk and return it to the pool
                            // (dropped if the pool is at its cap).
                            chunk_pool_push(&self.chunk_pool, data);
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
                                // Control messages must not wait for a full
                                // segment: release any held-back tail first.
                                if let Some(session) = self.sessions.get_mut(&(conv, peer_addr)) {
                                    if let Err(e) = session.flush_carry() {
                                        tracing::debug!(conv, error = %e, "KCP SOCKET: flush carry error");
                                    }
                                }
                                self.flush_session_output(conv, peer_addr).await
                            } else {
                                0
                            };
                            tracing::trace!(conv, npkts, "KCP SOCKET: flush sent {} packets", npkts);
                            let _ = tx.send(());
                        }
                    }
                }

                _ = self.socket.readable() => {
                    self.drain_recv(&mut recv_slots).await;
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

    /// Accepted-session idle reaper (M11): reclaim sessions whose stream was
    /// dropped (read channel closed) and that saw no inbound for the grace
    /// period with nothing left to send. Before this reaper, an accepted
    /// session whose stream dropped could only be reclaimed by inbound
    /// traffic or dead-link retransmission exhaustion — a silent peer left
    /// it pinned forever, and the 30-60s accept-handler deadlines made
    /// attacker-created sessions recyclable only at the 1024-session cap.
    /// Live streams are never reaped (channel open): the frp heartbeat
    /// layer — including configs that never heartbeat — owns that
    /// connection's lifetime, the transport does not override it. The grace
    /// exceeds KCP_RTO_MAX (2s) so a session mid-retransmission is never
    /// cut.
    ///
    /// Called from the tick arm with the driver clock. Extracted (round R6)
    /// so the guards are unit-testable; the call site is byte-identical to
    /// the original inline block.
    fn reap_accepted_idle_sessions(&mut self, now_ms: u32) {
        for (key, session) in &mut self.sessions {
            if self.session_created_at.contains_key(key) {
                continue; // unaccepted — the 30s expiry above owns it
            }
            if !session.read_channel_closed() {
                continue; // live stream — frp-layer liveness owns the conn
            }
            if session.wait_snd() > 0 {
                continue; // undelivered data — mirror the dial self-exit gate
            }
            let idle_ms = now_ms.wrapping_sub(session.last_inbound_ms());
            if idle_ms > ACCEPTED_SESSION_REAP_GRACE_MS {
                tracing::debug!(conv = key.0, peer = %key.1, idle_ms, "KCP: reaping accepted idle session (stream dropped, no inbound)");
                self.to_remove.push(*key);
            }
        }
        self.drain_to_remove();
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
        pool: &ArrayQueue<Vec<u8>>,
    ) {
        match socket.try_send_to(&pkt, peer) {
            Ok(_) => {
                // Sent — recycle the datagram buffer (F3). Only terminal
                // states return to the pool: a WouldBlock-queued packet keeps
                // its buffer until `drain_pending_udp` actually sends it.
                chunk_pool_push(pool, pkt);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if pending_udp.len() < 2048 {
                    pending_udp.push_back((peer, pkt));
                } else {
                    // Queue full — KCP retransmission resends the packet, so
                    // dropping is safe; recycle its buffer.
                    chunk_pool_push(pool, pkt);
                }
            }
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "KCP UDP send error");
                // Terminal failure — the datagram is not going anywhere
                // (retransmission re-encodes it); recycle its buffer.
                chunk_pool_push(pool, pkt);
            }
        }
    }

    /// Send a run of datagrams aimed at one peer, batching where the platform
    /// allows it and queueing whatever the kernel did not take.
    ///
    /// Both the flush path and the tick path (ACKs, retransmits) produce runs
    /// for a single peer, so they share this.
    fn send_packets(
        socket: &UdpSocket,
        pending_udp: &mut VecDeque<(SocketAddr, Vec<u8>)>,
        packets: Vec<Vec<u8>>,
        peer: SocketAddr,
        pool: &ArrayQueue<Vec<u8>>,
    ) {
        #[cfg(target_os = "linux")]
        let sent = Self::send_udp_batch(socket, &packets, peer);
        #[cfg(not(target_os = "linux"))]
        let sent = 0usize;

        for (i, pkt) in packets.into_iter().enumerate() {
            if i < sent {
                chunk_pool_push(pool, pkt);
            } else {
                Self::send_udp_packet(socket, pending_udp, pkt, peer, pool);
            }
        }
    }

    /// Send a run of datagrams that all target the same peer.
    ///
    /// On Linux this is one `sendmmsg(2)` — a KCP flush produces several
    /// segments at once (a 1326-byte MSS with 10+3 FEC means ~13 datagrams per
    /// 16 KiB input burst), and one syscall per segment is measurable at
    /// stream rates. Everything else keeps the one-syscall-per-packet loop.
    ///
    /// Returns how many were sent; the caller recycles those buffers into the
    /// chunk pool and queues the rest.
    #[cfg(target_os = "linux")]
    fn send_udp_batch(socket: &UdpSocket, packets: &[Vec<u8>], peer: SocketAddr) -> usize {
        use std::os::fd::AsRawFd;

        if packets.len() < 2 {
            return 0;
        }
        let (addr, addr_len) = Self::sockaddr_of(&peer);
        let mut iovs: Vec<libc::iovec> = packets
            .iter()
            .map(|p| libc::iovec {
                iov_base: p.as_ptr() as *mut libc::c_void,
                iov_len: p.len(),
            })
            .collect();
        // SAFETY: `mmsghdr` is a C POD and an all-zeroed one is a valid empty
        // header (null name/iov/control, zero lengths) that the loop below
        // fills in before the array is handed to the kernel.
        let zeroed: libc::mmsghdr = unsafe { std::mem::zeroed() };
        let mut msgs: Vec<libc::mmsghdr> = vec![zeroed; iovs.len()];
        // SAFETY: every pointer handed to the kernel points into a live
        // `iovs`/`addr` inside this function, and `msgs` is exactly as long as
        // `iovs`; the lengths come from the slices themselves.
        unsafe {
            for (i, msg) in msgs.iter_mut().enumerate() {
                msg.msg_hdr.msg_name = (&addr as *const libc::sockaddr_storage).cast_mut().cast();
                msg.msg_hdr.msg_namelen = addr_len;
                msg.msg_hdr.msg_iov = &mut iovs[i];
                msg.msg_hdr.msg_iovlen = 1;
            }
            let sent = libc::sendmmsg(
                socket.as_raw_fd(),
                msgs.as_mut_ptr(),
                msgs.len() as libc::c_uint,
                0,
            );
            if sent <= 0 {
                return 0;
            }
            sent as usize
        }
    }

    /// Build a `sockaddr` for `sendmmsg`.
    ///
    /// Returns the storage plus the length to pass in `msg_namelen`. The
    /// storage is `sockaddr_storage` rather than a byte array so that the
    /// `sockaddr_in`/`sockaddr_in6` writes below are aligned for their types
    /// (a `[u8; 128]` is only byte-aligned, and writing through a misaligned
    /// pointer is undefined even when the runtime address happens to be fine).
    #[cfg(target_os = "linux")]
    fn sockaddr_of(peer: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        // SAFETY: `sockaddr_storage` is a C POD; an all-zero value is a valid
        // empty storage for any address family, and both arms overwrite the
        // header they use before the value is handed to the kernel.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        match peer {
            SocketAddr::V4(v4) => {
                // SAFETY: `storage` is aligned for `sockaddr_in` (the family it
                // is being filled for) and large enough to hold it.
                unsafe {
                    let sa = std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in>();
                    (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sa).sin_port = v4.port().to_be();
                    (*sa).sin_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()),
                    };
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(v6) => {
                // SAFETY: as above, for `sockaddr_in6`.
                unsafe {
                    let sa = std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in6>();
                    (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sa).sin6_port = v6.port().to_be();
                    (*sa).sin6_addr = libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    };
                    (*sa).sin6_scope_id = v6.scope_id();
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    }

    /// Re-send packets queued by a previous full send buffer (FIFO).
    fn drain_pending_udp(&mut self) {
        let mut still_pending = VecDeque::new();
        while let Some((pa, pkt)) = self.pending_udp.pop_front() {
            match self.socket.try_send_to(&pkt, pa) {
                Ok(_) => chunk_pool_push(&self.chunk_pool, pkt),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    still_pending.push_back((pa, pkt));
                }
                Err(e) => {
                    tracing::debug!(peer = %pa, error = %e, "KCP UDP pending send error");
                    chunk_pool_push(&self.chunk_pool, pkt);
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
        Self::send_packets(
            &self.socket,
            &mut self.pending_udp,
            packets,
            peer_addr,
            &self.chunk_pool,
        );
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

/// Datagrams per `recvmmsg` call.
const RECV_BATCH: usize = 32;

/// Receive every datagram the socket has queued, up to `slots.len()`.
///
/// Linux uses one `recvmmsg`; other platforms take a single `recv_from` into
/// `slots[0]`, which keeps the behaviour identical at one packet per wakeup.
#[cfg(target_os = "linux")]
fn recv_datagrams(
    socket: &UdpSocket,
    slots: &mut [Vec<u8>],
) -> io::Result<Vec<(usize, usize, SocketAddr)>> {
    use std::os::fd::AsRawFd;

    let count = slots.len().min(RECV_BATCH);
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(count);
    for slot in slots.iter_mut().take(count) {
        iovecs.push(libc::iovec {
            iov_base: slot.as_mut_ptr().cast(),
            iov_len: slot.len(),
        });
    }
    // SAFETY: `sockaddr_storage` is plain old data, so an all-zero value is a
    // valid (family-0) instance; the kernel fills it in.
    let mut names: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; count];
    // SAFETY: `mmsghdr` is a C POD and an all-zeroed one is a valid empty
    // message header; field literals are not usable because musl's
    // `msghdr` carries private padding fields.
    let zeroed: libc::mmsghdr = unsafe { std::mem::zeroed() };
    let mut msgs: Vec<libc::mmsghdr> = vec![zeroed; count];
    for idx in 0..count {
        msgs[idx].msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovecs[idx]);
        msgs[idx].msg_hdr.msg_iovlen = 1;
        msgs[idx].msg_hdr.msg_name = std::ptr::addr_of_mut!(names[idx]).cast();
        msgs[idx].msg_hdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    }
    // SAFETY: `msgs`, `iovecs` and `names` outlive the call and each
    // `msg_hdr` points at its own entry; the kernel writes at most one
    // datagram per message, bounded by the slot's length.
    let rc = unsafe {
        libc::recvmmsg(
            socket.as_raw_fd(),
            msgs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::with_capacity(rc as usize);
    for (idx, msg) in msgs.iter().enumerate().take(rc as usize) {
        // The kernel reports the copied length because `MSG_TRUNC` is not
        // requested; clamp anyway so a surprising value cannot slice past the
        // slot and panic the driver task.
        let len = (msg.msg_len as usize).min(slots[idx].len());
        let src = match socket_addr_from_storage(&names[idx]) {
            Some(addr) => addr,
            None => continue,
        };
        out.push((idx, len, src));
    }
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
fn recv_datagrams(
    socket: &UdpSocket,
    slots: &mut [Vec<u8>],
) -> io::Result<Vec<(usize, usize, SocketAddr)>> {
    let slot = match slots.first_mut() {
        Some(slot) => slot,
        None => return Ok(Vec::new()),
    };
    // `recv_from` on a non-blocking socket reports WouldBlock exactly like
    // `recvmmsg` does, so the caller's drain loop is unchanged.
    match socket.try_recv_from(slot) {
        Ok((len, src)) => Ok(vec![(0, len, src)]),
        Err(e) => Err(e),
    }
}

/// Rounds (syscalls) one wakeup may drain before the driver returns to its
/// `select!`.
///
/// Without a bound, a peer that keeps the receive queue full would keep this
/// task inside the receive arm and starve the tick (KCP `update`, ACKs,
/// retransmits) and the write arms — the same starvation the readiness bug in
/// `drain_recv` caused, by another route. Four rounds still amortise the
/// syscall over up to `4 * RECV_BATCH` datagrams.
const MAX_DRAIN_ROUNDS: usize = 4;

/// Whether the driver should issue another receive syscall in this wakeup.
///
/// A short batch means the socket is drained; the round bound keeps a
/// persistently full queue from starving the other arms of the `select!`.
fn another_drain_round(got: usize, count: usize, rounds_done: usize) -> bool {
    got >= count && rounds_done < MAX_DRAIN_ROUNDS
}

/// Decode a `sockaddr_storage` filled by the kernel into a `SocketAddr`.
#[cfg(target_os = "linux")]
fn socket_addr_from_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr = {
                // SAFETY: `ss_family` says the storage holds a `sockaddr_in`;
                // the read is bounded by the storage's own size and only
                // scalar fields (address, port) are touched.
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() }
            };
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(addr.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: `ss_family` says the storage holds a `sockaddr_in6`; the
            // read is bounded by the storage's own size and only scalar fields
            // (address, port) are touched.
            let addr = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            // Keep the scope id: a link-local peer is only addressable (and
            // only matches its registered session) with it.
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(addr.sin6_port),
                0,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod batch_tests {
    use super::*;

    /// One `sendmmsg` must deliver every datagram, in order, to the peer the
    /// caller named — the batch path is only correct if it is indistinguishable
    /// from the one-syscall-per-packet loop.
    #[test]
    fn send_udp_batch_delivers_all_packets_in_order() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = receiver.local_addr().unwrap();
            let packets: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 16 + i as usize]).collect();

            let sent = KcpSocket::send_udp_batch(&sender, &packets, peer);
            assert_eq!(sent, packets.len(), "sendmmsg reported a short send");

            let mut buf = [0u8; 64];
            for (i, pkt) in packets.iter().enumerate() {
                let (n, from) =
                    tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
                        .await
                        .expect("datagram did not arrive")
                        .unwrap();
                assert_eq!(from, sender.local_addr().unwrap());
                assert_eq!(&buf[..n], &pkt[..], "datagram {i} came back changed");
            }
        });
    }

    /// A single packet takes the ordinary path (`sendmmsg` needs at least two),
    /// so the batch helper must decline rather than assume.
    #[test]
    fn send_udp_batch_declines_a_single_packet() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = receiver.local_addr().unwrap();
            let packets = vec![b"one".to_vec()];
            assert_eq!(KcpSocket::send_udp_batch(&sender, &packets, peer), 0);
        });
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    /// A full batch means more may be waiting, until the round bound.
    #[test]
    fn another_round_while_batches_stay_full() {
        assert!(another_drain_round(RECV_BATCH, RECV_BATCH, 1));
        assert!(another_drain_round(
            RECV_BATCH,
            RECV_BATCH,
            MAX_DRAIN_ROUNDS - 1
        ));
    }

    /// The bound is what keeps the driver's tick and write arms alive.
    #[test]
    fn no_round_past_the_bound() {
        assert!(!another_drain_round(
            RECV_BATCH,
            RECV_BATCH,
            MAX_DRAIN_ROUNDS
        ));
    }

    /// A short batch means the socket is drained; `WorthBlock` was handled by
    /// the caller and an empty batch must not spin.
    #[test]
    fn no_round_after_a_short_or_empty_batch() {
        assert!(!another_drain_round(0, RECV_BATCH, 1));
        assert!(!another_drain_round(RECV_BATCH - 1, RECV_BATCH, 1));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod recv_batch_tests {
    use super::*;

    /// One `recvmmsg` must hand back every datagram that is queued, with the
    /// sender address and length intact, and report `WouldBlock` when empty.
    #[tokio::test]
    async fn recv_datagrams_returns_queued_packets_in_order() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        for i in 0..3u8 {
            sender.send_to(&[i; 32], peer).await.unwrap();
        }

        let mut slots: Vec<Vec<u8>> = (0..RECV_BATCH)
            .map(|_| vec![0u8; DRIVER_RECV_BUF_SIZE])
            .collect();
        receiver.readable().await.unwrap();
        let batch = recv_datagrams(&receiver, &mut slots).unwrap();
        assert_eq!(batch.len(), 3, "one call must drain all three datagrams");
        for (idx, (slot, len, src)) in batch.iter().enumerate() {
            assert_eq!(*len, 32);
            assert_eq!(*src, sender.local_addr().unwrap());
            assert_eq!(
                slots[*slot][0], idx as u8,
                "datagrams must keep their order"
            );
        }

        // An empty socket reports the same `WouldBlock` the drain loop exits on.
        let err = recv_datagrams(&receiver, &mut slots).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Regression for the driver recv-buffer clamp defect: the recv buffer
    /// must absorb ANY wire packet a peer can legitimately send. A peer's
    /// mtu is clamped to MAX_KCP_MTU, so the largest wire packet is
    /// `MAX_KCP_MTU + KCP_WIRE_OVERHEAD` = 1500 bytes. The buffer used to be
    /// sized `mtu + KCP_WIRE_OVERHEAD` from the LOCAL config (1358 bytes for
    /// the default mtu 1350), truncating legit mixed-mtu peers' packets →
    /// InvalidSegmentDataSize → retransmit loop → dead link.
    #[test]
    fn driver_recv_buf_holds_max_peer_wire_packet() {
        // A peer at the clamp cap (mtu MAX_KCP_MTU) sends wire packets of at
        // most `mtu + KCP_WIRE_OVERHEAD` = 1500 bytes.
        let max_peer = KcpConfig {
            mtu: MAX_KCP_MTU,
            ..KcpConfig::default()
        };
        assert!(
            DRIVER_RECV_BUF_SIZE >= max_peer.mtu + KCP_WIRE_OVERHEAD,
            "driver recv buffer {}B < max peer wire packet {}B",
            DRIVER_RECV_BUF_SIZE,
            max_peer.mtu + KCP_WIRE_OVERHEAD
        );
        // The default config (mtu 1350) must also land >= 1500 — this is
        // the exact case that regressed (1358B).
        let default = KcpConfig::default();
        assert!(
            DRIVER_RECV_BUF_SIZE >= default.mtu + KCP_WIRE_OVERHEAD,
            "driver recv buffer {}B < default-config wire packet {}B",
            DRIVER_RECV_BUF_SIZE,
            default.mtu + KCP_WIRE_OVERHEAD
        );
    }

    /// `KcpConfig::clamped` must match `KcpSocket::new`'s clamp so the dial
    /// path's session (which reads config.mtu directly via kcp.set_mtu) and
    /// socket agree on the wire mtu — the dial-clamp defect regression.
    #[test]
    fn clamped_caps_mtu_to_max() {
        let oversized = KcpConfig {
            mtu: 2000,
            ..KcpConfig::default()
        };
        assert_eq!(oversized.clamped().mtu, MAX_KCP_MTU);
        // An in-range mtu is untouched.
        let default = KcpConfig::default();
        assert_eq!(default.clone().clamped().mtu, default.mtu);
    }

    /// Round-13: pin the chunk-pool contract — pooled reuse without
    /// reallocation, the CHUNK_POOL_CAP bound on recycled chunks, and
    /// min_capacity allocation when the pool is empty.
    #[test]
    fn chunk_pool_reuse_and_bounds() {
        let pool = ArrayQueue::new(CHUNK_POOL_CAP);
        // Empty pool: allocate with min_capacity.
        let c = chunk_pool_pop(&pool, 4096);
        assert!(c.capacity() >= 4096);
        // Return then re-pop: same allocation reused, length cleared.
        let cap = c.capacity();
        chunk_pool_push(&pool, c);
        let c2 = chunk_pool_pop(&pool, 4096);
        assert_eq!(
            c2.capacity(),
            cap,
            "pooled chunk must be reused without realloc"
        );
        assert!(c2.is_empty());
        // Cap: returns beyond CHUNK_POOL_CAP are dropped.
        chunk_pool_push(&pool, c2);
        for _ in 0..CHUNK_POOL_CAP + 4 {
            chunk_pool_push(&pool, vec![0u8; 1024]);
        }
        assert!(pool.len() <= CHUNK_POOL_CAP);
        // Empty pool (drained): min_capacity takes effect.
        while pool.pop().is_some() {}
        let c3 = chunk_pool_pop(&pool, 8192);
        assert!(c3.capacity() >= 8192);
    }

    /// Round R6: the accepted-session idle reaper (`reap_accepted_idle_sessions`,
    /// extracted from the tick arm) had zero test coverage. Pin its three
    /// guards on a wire-shaped accepted session (registered in the driver's
    /// maps, NOT in `session_created_at`, backed by a real KcpStream):
    /// 1. a live stream is never reaped no matter how idle (channel open),
    /// 2. a closed-channel session survives inside the grace window,
    /// 3. past the grace (idle > ACCEPTED_SESSION_REAP_GRACE_MS) it is
    ///    removed from every index and marked dead (streams observe
    ///    NotConnected instead of silently buffering).
    #[tokio::test]
    async fn accepted_session_reaper_guards_idle_and_live() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (mut driver, _handle, _accept_rx) = KcpSocket::new(udp, KcpConfig::default());

        let conv = 7u32;
        let peer: SocketAddr = "203.0.113.9:4711".parse().unwrap();
        let key = (conv, peer);

        // Wire-shaped accepted session: the driver's wire path builds the
        // session, shares the socket's chunk pool, and hands the read
        // channel to a KcpStream; acceptance removes it from
        // `session_created_at` (here: never inserted — the reaper treats
        // that as accepted).
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(256);
        let mut session = KcpSession::with_chunk_pool(
            conv,
            peer,
            KcpConfig::default(),
            read_tx,
            driver.chunk_pool.clone(),
        );
        session.note_inbound(1000); // driver stamped the first inbound packet
        let alive = session.alive_handle();
        let (snd_backlog, snd_notify) = session.snd_backlog_handle();
        let stream = KcpStream::new(
            conv,
            peer,
            driver.write_tx.clone(),
            read_rx,
            driver.write_backlog.clone(),
            driver.write_notify.clone(),
            driver.chunk_pool.clone(),
            snd_backlog,
            snd_notify,
            alive.clone(),
            driver.alive_streams.clone(),
        );
        driver.sessions.insert(key, session);
        driver.conv_index.insert(conv, peer);
        driver.peer_addr_index.insert(peer, conv);

        // Guard 1: live stream — idle far past the grace, channel open.
        driver.reap_accepted_idle_sessions(1000 + ACCEPTED_SESSION_REAP_GRACE_MS + 60_000);
        assert!(
            driver.sessions.contains_key(&key),
            "live stream must never be reaped, however idle"
        );
        assert!(alive.load(Ordering::Relaxed));

        // Closing the read channel is what makes the session reapable:
        // the single stream owned the channel's rx end for the connection
        // lifetime, so a closed channel means the frp connection is gone.
        drop(stream);
        assert!(
            driver.sessions.get(&key).unwrap().read_channel_closed(),
            "dropping the stream must close the session's read channel"
        );

        // Guard 2: inside the grace window the closed session survives.
        driver.reap_accepted_idle_sessions(1000 + ACCEPTED_SESSION_REAP_GRACE_MS - 1);
        assert!(
            driver.sessions.contains_key(&key),
            "closed session must survive inside the grace window"
        );

        // Guard 3: past the grace it is reaped from every index and marked
        // dead, so a KcpStream that somehow still holds a reference observes
        // NotConnected instead of buffering forever.
        driver.reap_accepted_idle_sessions(1000 + ACCEPTED_SESSION_REAP_GRACE_MS + 1);
        assert!(
            !driver.sessions.contains_key(&key),
            "closed idle session must be reaped past the grace"
        );
        assert!(
            !driver.conv_index.contains_key(&conv),
            "reaped session must drop its conv index entry"
        );
        assert!(
            !driver.peer_addr_index.contains_key(&peer),
            "reaped session must drop its peer-addr index entry (no other session on that addr)"
        );
        assert!(
            !alive.load(Ordering::Relaxed),
            "reaped session must be marked dead so streams fail fast"
        );

        // The reap must not disturb the to_remove queue the recv arm may
        // have filled (drain_to_remove contract).
        assert!(driver.to_remove.is_empty());
    }

    /// Round M4: the receive side must recycle delivered-message buffers
    /// through the shared chunk pool exactly like the send side —
    /// `KcpSession::recv_and_push` pops a pooled buffer per delivered KCP
    /// message and `KcpStream::poll_read` returns it once fully consumed.
    /// Before the read-side pool landed, every delivered message allocated a
    /// fresh Vec (dropped after the stream consumed it), so the shared pool
    /// stayed empty regardless of traffic volume. Red on the pre-fix code:
    /// the pool-length assertion below fails on the first message.
    #[tokio::test(start_paused = true)]
    async fn read_side_recycles_channel_buffers_through_chunk_pool() {
        use tokio::io::AsyncReadExt;
        use tokio::time::{timeout, Duration};

        use super::super::config::KcpNoDelayConfig;

        // Message-boundary mode: each send() is one KCP message = one
        // channel item, so per-message byte-exactness is assertable.
        let cfg = KcpConfig {
            mtu: 1400,
            wnd_size: (128, 128),
            stream: false,
            data_shards: 0,
            parity_shards: 0,
            nodelay: KcpNoDelayConfig {
                nodelay: true,
                interval: 10,
                resend: 2,
                nc: true,
            },
        };
        let (tx1, _rx1) = mpsc::channel::<Vec<u8>>(16);
        let mut sender = KcpSession::new(1, "127.0.0.1:9001".parse().unwrap(), cfg.clone(), tx1);

        // Receiver shares an externally observable pool — the same shape as
        // the driver path (session + stream share the socket's chunk_pool).
        let pool = Arc::new(ArrayQueue::new(CHUNK_POOL_CAP));
        let (tx2, rx2) = mpsc::channel::<Vec<u8>>(256);
        let mut receiver = KcpSession::with_chunk_pool(
            1,
            "127.0.0.1:9000".parse().unwrap(),
            cfg,
            tx2,
            pool.clone(),
        );

        // A real KcpStream over the receiver's read channel — the same
        // construction KcpSocket::run uses for wire sessions.
        let (snd_backlog, snd_notify) = receiver.snd_backlog_handle();
        let (write_tx, _write_rx) = mpsc::channel(16);
        let mut stream = KcpStream::new(
            1,
            "127.0.0.1:9000".parse().unwrap(),
            write_tx,
            rx2,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(Notify::new()),
            pool.clone(),
            snd_backlog,
            snd_notify,
            receiver.alive_handle(),
            Arc::new(AtomicUsize::new(0)),
        );

        let msgs: [&[u8]; 3] = [b"alpha", b"bravo!", b"charlie-42"];
        for (i, msg) in msgs.iter().enumerate() {
            sender.send(msg).unwrap();

            let mut now_ms = 0u32;
            let mut got: Option<Vec<u8>> = None;
            for _ in 0..300 {
                now_ms += 10;
                let packets = sender.update(now_ms).unwrap();
                for pkt in &packets {
                    receiver.input(pkt).unwrap();
                }
                receiver.recv_and_push().unwrap();
                // ACK flush — output dropped (window is 128 wide; three tiny
                // messages never depend on ACKs, mirroring the session
                // roundtrip tests).
                receiver.update(now_ms).unwrap();

                let mut buf = [0u8; 128];
                match timeout(Duration::from_millis(1), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        got = Some(buf[..n].to_vec());
                        break;
                    }
                    Ok(Ok(_)) => panic!("read hit EOF while the read channel is open"),
                    Ok(Err(e)) => panic!("stream read error: {e}"),
                    Err(_) => {} // not delivered yet — drive more ticks
                }
            }
            let data = got
                .unwrap_or_else(|| panic!("message {i} was not delivered within the tick budget"));
            assert!(
                data.as_slice() == *msg,
                "message {i}: recycled-buffer payload mismatch (got {:?}, want {:?})",
                data,
                msg
            );

            // After full consumption the buffer must be back in the shared
            // pool. RED on the pre-fix code: recv_and_push allocated fresh
            // and poll_read dropped the Vec after consuming it, so the pool
            // stays empty no matter the traffic.
            assert!(
                !pool.is_empty(),
                "message {i}: fully-consumed channel buffer was not recycled to the chunk pool"
            );
        }
    }
}
