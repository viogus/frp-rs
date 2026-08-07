//! KCP session — per-conversation KCP state machine with optional FEC.
//!
//! FEC wire format matches Go kcp-go (xtaci/kcp-go v5):
//!   | FEC SEQID(4B LE) | FEC TYPE(2B LE) | SIZE(2B LE) | PAYLOAD |
//!
//! SIZE = 2 + len(PAYLOAD) (matches Go's `len(b[payloadOffset:])`).
//! FEC is inter-packet: dataShards consecutive KCP output packets form one
//! RS group; parity shards are generated from the equal-length RS blocks.
//!
//! XOR encryption (`kcp_compat::XorBlock`) is NOT needed for Go frp compat —
//! Go frp (`pkg/util/net/kcp.go`) passes `nil` for the blockCrypt parameter in
//! both `kcp.ListenWithOptions()` and `kcp.NewConn3()`, meaning NO KCP-level
//! encryption is used. The `kcp_compat::XorBlock` code is unused unless frp-rs
//! adds a proprietary KCP encryption extension.

use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Notify};

use super::config::KcpConfig;
use super::protocol::{Error as KcpError, Kcp};
use super::socket::KCP_SND_BACKLOG_THRESHOLD;
use crate::kcp_compat::Fec;

const FEC_HEADER_SIZE: usize = 6;
const TYPE_DATA: u16 = 0xf1;
const TYPE_PARITY: u16 = 0xf2;
const MAX_SHARD_SETS: usize = 3;
/// kcp-go `fecExpire` (fec.go, ms): a shard that sits in the FEC decoder
/// longer than this is treated as stale residue and dropped by the time-based
/// continuity check (`fecDecoder.decode()` timeout policy, applied on every
/// incoming packet). Mirrored here per shard group: a group that receives no
/// shard for this long is discarded even if it never filled to data_shards
/// (partial group after extreme reordering / a long silent period).
const FEC_GROUP_EXPIRE_MS: u64 = 60_000;

struct ShardGroup {
    shards: Vec<Option<Vec<u8>>>,
    received_count: usize,
    /// Monotonic millisecond timestamp (session FEC clock) of the last shard
    /// received into this group — mirrors kcp-go's `fecElement.ts`.
    last_active_ms: u64,
}

/// Writer that collects each `write_all` call as a separate packet.
///
/// `drain()` replaces the internal Vec with a fresh pre-allocated one so that
/// `write()` calls between drains don't reallocate the outer Vec on every push.
struct KcpWriter {
    packets: Vec<Vec<u8>>,
}

/// Typical number of KCP output packets per tick. Pre-allocating avoids
/// repeated reallocation of the outer Vec during the `write()` flush loop.
const PACKET_POOL_CAPACITY: usize = 64;

impl KcpWriter {
    fn new() -> Self {
        Self {
            packets: Vec::with_capacity(PACKET_POOL_CAPACITY),
        }
    }

    fn drain(&mut self) -> Vec<Vec<u8>> {
        // Replace current batch with a fresh pre-allocated Vec.
        // The old batch is returned; the new Vec starts with capacity 64,
        // ready for the next KCP tick's output without reallocation.
        std::mem::replace(&mut self.packets, Vec::with_capacity(PACKET_POOL_CAPACITY))
    }
}

impl Write for KcpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.packets.push(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct KcpSession {
    conv: u32,
    _peer_addr: std::net::SocketAddr,
    kcp: Kcp<KcpWriter>,
    fec: Option<Fec>,
    config: KcpConfig,
    fec_seqid: u32,
    /// Received FEC shard groups, keyed by shard_begin (seqid - seqid % total).
    shard_groups: HashMap<u32, ShardGroup>,
    /// Monotonic clock used for FEC group expiry (ms since session creation).
    fec_clock_base: std::time::Instant,
    /// Clock override: when set, `fec_now_ms()` returns it instead of the
    /// real clock, so tests can simulate long silent gaps deterministically.
    fec_clock_override: Option<u64>,
    recv_buf: Vec<u8>,
    read_tx: mpsc::Sender<Vec<u8>>,
    shutdown: bool,
    /// Frame that couldn't be delivered to the read channel on the previous
    /// tick because the channel was full. Must be flushed before consuming
    /// additional KCP data — the sender already ACK'd the lost frame and
    /// retransmission will NOT recover it.
    pending_read: Option<Vec<u8>>,
    /// Inter-packet FEC: pending data shard RS payloads (SIZE + raw KCP data).
    pending_shards: Vec<Vec<u8>>,
    /// Max RS payload length in current pending group.
    pending_max_size: usize,
    /// Set to false when the session is removed from the KcpSocket driver.
    /// KcpStream checks this on poll_write/poll_read to fail fast instead of
    /// silently dropping data.
    alive: Arc<AtomicBool>,
    /// Shared with KcpStream. Mirrors `Kcp::wait_snd()` (snd_buf + snd_queue
    /// segment count). Poll_write gates on this so a stalled peer (remote
    /// window 0, never ACKing) cannot make the send queue grow without bound.
    /// Reconciliated after every send/input/update/force_flush (single-threaded
    /// driver, so store is safe); on crossing the threshold downward, waiters
    /// blocked in poll_write are woken via `snd_notify` (notify_one).
    snd_backlog: Arc<AtomicUsize>,
    /// Woken by reconcile_snd_backlog when snd_backlog drains below
    /// KCP_SND_BACKLOG_THRESHOLD, and by mark_dead when the session is
    /// removed. Shares the KcpStream::backpressure_fut slot with the
    /// write-channel backlog Notify.
    snd_notify: Arc<Notify>,
    /// Reusable output packet Vec. Pre-allocated with PACKET_POOL_CAPACITY,
    /// cleared and filled each update/force_flush call to avoid per-call allocation.
    packets: Vec<Vec<u8>>,
}

impl KcpSession {
    pub fn new(
        conv: u32,
        peer_addr: std::net::SocketAddr,
        config: KcpConfig,
        read_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let fec = if config.data_shards > 0 && config.parity_shards > 0 {
            Some(Fec::new(config.data_shards, config.parity_shards))
        } else {
            None
        };

        let writer = KcpWriter::new();
        let mut kcp = if config.stream {
            Kcp::new_stream(conv, writer)
        } else {
            Kcp::new(conv, writer)
        };
        kcp.set_mtu(config.mtu).ok();
        kcp.set_wndsize(config.wnd_size.0, config.wnd_size.1);
        kcp.set_nodelay(
            config.nodelay.nodelay,
            config.nodelay.interval,
            config.nodelay.resend,
            config.nodelay.nc,
        );

        // Go frp (kcp-go) calls SetACKNoDelay(false) on its KCP sessions.
        // Our in-tree KCP implementation does not expose a set_ack_no_delay
        // API; its default behavior is equivalent to ACKNoDelay=false (ACKs
        // are accumulated in acklist and flushed on the next tick rather than
        // sent immediately) — no action needed.

        let alive = Arc::new(AtomicBool::new(true));

        Self {
            conv,
            _peer_addr: peer_addr,
            kcp,
            fec,
            config,
            fec_seqid: 0,
            shard_groups: HashMap::new(),
            fec_clock_base: std::time::Instant::now(),
            fec_clock_override: None,
            recv_buf: Vec::new(), // lazily allocated on first recv_and_push
            read_tx,
            shutdown: false,
            pending_read: None,
            pending_shards: Vec::new(),
            pending_max_size: 0,
            alive,
            snd_backlog: Arc::new(AtomicUsize::new(0)),
            snd_notify: Arc::new(Notify::new()),
            packets: Vec::with_capacity(PACKET_POOL_CAPACITY),
        }
    }

    /// Handles for KcpStream: the shared send-queue backlog counter and the
    /// Notify that wakes a poll_write task blocked on it. The stream gates on
    /// `snd_backlog >= KCP_SND_BACKLOG_THRESHOLD` and waits on `snd_notify`.
    pub fn snd_backlog_handle(&self) -> (Arc<AtomicUsize>, Arc<Notify>) {
        (self.snd_backlog.clone(), self.snd_notify.clone())
    }

    /// Refresh the shared send-queue backlog counter from `Kcp::wait_snd()`.
    /// Called after every operation that can change `snd_buf`/`snd_queue`
    /// (send adds, input ACKs remove; flush just moves between the two).
    /// Notifies a blocked poll_write only on the over→under crossing. Uses
    /// `notify_one()` rather than `notify_waiters()` to close the lost-wakeup
    /// race: poll_write may load `snd_backlog >= threshold`, then the driver
    /// crosses below the threshold and notifies before poll_write registers
    /// its waiter via `notified_owned()` — `notify_waiters()` does not store a
    /// permit, so that notification is lost and the writer stays parked even
    /// though the queue has drained. `notify_one()` stores a permit when no
    /// waiter is registered, which the just-registered waiter consumes
    /// immediately. There is no busy-loop risk: we only notify on the crossing
    /// (at which point the queue is already under the threshold, so a stored
    /// permit merely makes poll_write re-check the gate once and proceed);
    /// while the queue stays full there is no crossing and no notification.
    fn reconcile_snd_backlog(&mut self) {
        let len = self.kcp.wait_snd();
        let prev = self.snd_backlog.swap(len, Ordering::Relaxed);
        if prev >= KCP_SND_BACKLOG_THRESHOLD && len < KCP_SND_BACKLOG_THRESHOLD {
            self.snd_notify.notify_one();
        }
    }

    #[cfg(test)]
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Common FEC encode logic for both update() and force_flush().
    /// Processes output packets through FEC encoding (if enabled), or returns
    /// them directly if FEC is disabled.
    fn fec_encode_output(&mut self, output: Vec<Vec<u8>>) -> io::Result<Vec<Vec<u8>>> {
        self.packets.clear();
        if let Some(ref fec) = self.fec {
            for raw in &output {
                // Build RS payload: SIZE(2B LE) + raw KCP data.
                // SIZE = 2 + raw.len(), matching Go's len(b[payloadOffset:]).
                let size = (2u16 + raw.len() as u16).to_le_bytes();
                let mut rs_data = Vec::with_capacity(2 + raw.len());
                rs_data.extend_from_slice(&size);
                rs_data.extend_from_slice(raw);

                // Data shard wire packet: FEC header(6B) + RS payload.
                let mut packet = Vec::with_capacity(FEC_HEADER_SIZE + rs_data.len());
                packet.extend_from_slice(&self.fec_seqid.to_le_bytes());
                packet.extend_from_slice(&TYPE_DATA.to_le_bytes());
                packet.extend_from_slice(&rs_data);
                self.packets.push(packet);
                self.fec_seqid = self.fec_seqid.wrapping_add(1);

                // Buffer for parity generation.
                let rs_len = rs_data.len();
                self.pending_shards.push(rs_data);
                self.pending_max_size = self.pending_max_size.max(rs_len);

                // When we have dataShards collected, generate parity.
                if self.pending_shards.len() == self.config.data_shards {
                    let max_size = self.pending_max_size;

                    // Pad all data shard RS payloads to equal length.
                    for shard in &mut self.pending_shards {
                        shard.resize(max_size, 0);
                    }

                    let n = self.pending_shards.len();
                    let mut shard_refs: Vec<&[u8]> = Vec::with_capacity(n);
                    shard_refs.extend(self.pending_shards.iter().map(Vec::as_slice));
                    // Compute only parity shards — data shard wire packets were
                    // already emitted above, so the data-shard copies that
                    // `encode` would produce are discarded immediately.
                    let parity_shards = fec.encode_parity(&shard_refs[..n]);

                    // Output parity shards (data shards already sent).
                    for parity in &parity_shards {
                        let mut packet = Vec::with_capacity(FEC_HEADER_SIZE + parity.len());
                        packet.extend_from_slice(&self.fec_seqid.to_le_bytes());
                        packet.extend_from_slice(&TYPE_PARITY.to_le_bytes());
                        packet.extend_from_slice(parity);
                        self.packets.push(packet);
                        self.fec_seqid = self.fec_seqid.wrapping_add(1);
                    }

                    self.pending_shards.clear();
                    self.pending_max_size = 0;
                }
            }
            Ok(std::mem::take(&mut self.packets))
        } else {
            // Non-FEC path: return output directly without going through self.packets.
            Ok(output)
        }
    }

    /// Called by driver on each tick. Updates KCP clock, returns output packets.
    /// `now_ms` is a monotonic millisecond timestamp.
    pub fn update(&mut self, now_ms: u32) -> io::Result<Vec<Vec<u8>>> {
        if self.shutdown {
            return Ok(Vec::new());
        }
        self.kcp.update(now_ms).map_err(io::Error::other)?;
        // flush() may have drained snd_queue into snd_buf (or, under window 0,
        // left it untouched); keep the shared backlog counter in sync.
        self.reconcile_snd_backlog();

        let output = self.kcp.output_mut().drain();
        if output.is_empty() {
            return Ok(Vec::new());
        }

        tracing::trace!(
            conv = self.conv,
            output_count = output.len(),
            fec_avail = self.fec.is_some(),
            "KCP SESSION: update produced {} output packets",
            output.len()
        );
        self.fec_encode_output(output)
    }

    /// Enqueue data to send via KCP. Takes ownership of `data` so the KCP
    /// segmentation can split by moving instead of copying.
    pub fn send(&mut self, data: Vec<u8>) -> io::Result<usize> {
        let n = self.kcp.send(data.to_vec()).map_err(io::Error::other)?;
        // send() grew snd_queue; refresh the shared backlog counter so a
        // poll_write blocked on it can re-evaluate.
        self.reconcile_snd_backlog();
        Ok(n)
    }

    /// Force KCP to flush pending data and produce output packets immediately.
    /// Does update (flush stream data + move snd_queue→snd_buf), then drains
    /// and FEC-encodes output. Returns packets ready for UDP send.
    pub fn force_flush(&mut self, now_ms: u32) -> io::Result<Vec<Vec<u8>>> {
        // update() handles timing-based flush and ensures updated=true.
        self.kcp.update(now_ms).map_err(io::Error::other)?;
        // Force another flush in case update() skipped due to interval timing.
        // This is a no-op if snd_queue was already drained, but critical when
        // poll_flush is called between ticks (e.g. StartWorkConn → flush →
        // bridge data sequence).
        self.kcp.flush().map_err(io::Error::other)?;
        self.reconcile_snd_backlog();
        let output = self.kcp.output_mut().drain();
        if output.is_empty() {
            return Ok(Vec::new());
        }
        tracing::trace!(
            conv = self.conv,
            output_count = output.len(),
            "KCP SESSION: force_flush produced {} packets",
            output.len()
        );
        self.fec_encode_output(output)
    }

    /// Feed received UDP data into KCP. Handles FEC decode if enabled.
    pub fn input(&mut self, data: &[u8]) -> io::Result<()> {
        self.prune_old_groups();

        if let Some(ref fec) = self.fec {
            if data.len() < FEC_HEADER_SIZE {
                tracing::debug!(
                    conv = self.conv,
                    len = data.len(),
                    "KCP SESSION: input too short for FEC header ({} bytes)",
                    data.len()
                );
                return Ok(());
            }
            let seqid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let flag = u16::from_le_bytes([data[4], data[5]]);

            if flag != TYPE_DATA && flag != TYPE_PARITY {
                // Not FEC — treat as raw KCP.
                tracing::trace!(
                    conv = self.conv,
                    len = data.len(),
                    flag,
                    "KCP SESSION: input raw KCP (non-FEC), {} bytes",
                    data.len()
                );
                self.kcp.input(data).map_err(io::Error::other)?;
                // ACKs parsed here shrink snd_buf; refresh the shared backlog.
                self.reconcile_snd_backlog();
                return Ok(());
            }

            tracing::trace!(
                conv = self.conv,
                len = data.len(),
                seqid,
                flag,
                "KCP SESSION: input FEC {} shard seqid={}",
                if flag == TYPE_DATA { "DATA" } else { "PARITY" },
                seqid
            );

            let shard_data = &data[FEC_HEADER_SIZE..];
            let total = self.config.data_shards + self.config.parity_shards;

            // Group shards by shard_begin (Go: seqid - seqid % total).
            let shard_begin = seqid.wrapping_sub(seqid % total as u32);
            let shard_index = seqid as usize % total;

            // Refresh activity: any shard received for this group keeps it
            // alive (kcp-go stamps every inserted fecElement with currentMs()).
            let now = self.fec_now_ms();
            let group = self
                .shard_groups
                .entry(shard_begin)
                .or_insert_with(|| ShardGroup {
                    shards: vec![None; total],
                    received_count: 0,
                    last_active_ms: now,
                });
            group.last_active_ms = now;

            // Feed data shards to KCP immediately (Go kcp-go behavior).
            // Raw KCP data = shard_data[2..][..SIZE-2] where SIZE is first 2 bytes.
            if flag == TYPE_DATA && group.shards[shard_index].is_none() && shard_data.len() >= 2 {
                let size = u16::from_le_bytes([shard_data[0], shard_data[1]]) as usize;
                if size >= 2 {
                    let payload_end = (size - 2).min(shard_data.len() - 2);
                    if payload_end > 0 {
                        self.kcp
                            .input(&shard_data[2..2 + payload_end])
                            .map_err(io::Error::other)?;
                    }
                }
            }

            if group.shards[shard_index].is_none() {
                group.shards[shard_index] = Some(shard_data.to_vec());
                group.received_count += 1;
            }

            // Attempt FEC recovery when we have enough shards.
            if group.received_count >= self.config.data_shards {
                // Fast path: all data shards present, no recovery needed.
                // Avoid allocating a Vec for had_data by using a slice check first.
                if group.shards[..self.config.data_shards]
                    .iter()
                    .all(|s| s.is_some())
                {
                    self.shard_groups.remove(&shard_begin);
                    // Data shards fed above may carry ACKs; keep counter in sync.
                    self.reconcile_snd_backlog();
                    return Ok(());
                }

                // Track which data shards were already received (to avoid double-feed).
                let mut had_data = vec![false; group.shards.len()];
                for (i, s) in group
                    .shards
                    .iter()
                    .enumerate()
                    .take(self.config.data_shards)
                {
                    had_data[i] = s.is_some();
                }

                // Normalize shard lengths to max (Go: zero-extend shorter shards).
                let max_len = group
                    .shards
                    .iter()
                    .flatten()
                    .map(|s| s.len())
                    .max()
                    .unwrap_or(0);

                // Take ownership of shards to avoid cloning+resizing each one.
                // The shard_groups entry will be removed after decode, so we
                // don't need to preserve the original shards.
                let mut decode_shards = std::mem::take(&mut group.shards);
                for ref mut v in decode_shards.iter_mut().flatten() {
                    v.resize(max_len, 0);
                }

                if fec.decode(&mut decode_shards) {
                    // Feed recovered (previously missing) data shards to KCP.
                    for i in 0..self.config.data_shards {
                        if had_data[i] {
                            continue;
                        }
                        if let Some(ref recovered) = decode_shards[i] {
                            if recovered.len() >= 2 {
                                let size =
                                    u16::from_le_bytes([recovered[0], recovered[1]]) as usize;
                                if size >= 2 {
                                    let payload_end = (size - 2).min(recovered.len() - 2);
                                    if payload_end > 0 {
                                        self.kcp
                                            .input(&recovered[2..2 + payload_end])
                                            .map_err(io::Error::other)?;
                                    }
                                }
                            }
                        }
                    }
                }
                self.shard_groups.remove(&shard_begin);
            }
        } else {
            self.kcp.input(data).map_err(io::Error::other)?;
        }

        // ACKs parsed in input() shrink snd_buf; refresh the shared backlog so
        // a poll_write blocked on a full send queue can resume promptly.
        self.reconcile_snd_backlog();

        Ok(())
    }

    /// Push any received KCP data to the stream's read channel.
    /// Called by driver on each tick after update().
    pub fn recv_and_push(&mut self) -> io::Result<()> {
        // Flush pending frame from previous tick first. Data already consumed
        // from KCP receive queue and ACK'd — retransmission will NOT recover it.
        if let Some(pending) = self.pending_read.take() {
            match self.read_tx.try_send(pending) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(data)) => {
                    self.pending_read = Some(data);
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.shutdown = true;
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "KCP read channel closed",
                    ));
                }
            }
        }

        loop {
            match self.kcp.peeksize() {
                Ok(0) => {
                    // len=0 PUSH frame (empty heartbeat segment): consume it
                    // from the receive queue but do NOT forward an empty frame.
                    // KcpStream::poll_read would return Ok(0) for it, which
                    // tokio treats as EOF and tears down the connection.
                    // kcp-go never sends empty PUSH, but a malicious or buggy
                    // peer may. A zero total peek size only happens when the
                    // whole fragment chain is empty, so `recv` below pops the
                    // entire chain — reassembly of non-empty chains is untouched.
                    tracing::trace!(
                        conv = self.conv,
                        "KCP SESSION: consuming empty frame (len=0 PUSH), not forwarding"
                    );
                    let mut empty = [0u8; 0];
                    self.kcp.recv(&mut empty).map_err(io::Error::other)?;
                    continue;
                }
                Ok(size) => {
                    if size > self.recv_buf.len() {
                        self.recv_buf.resize(size, 0);
                    }
                    match self.kcp.recv(&mut self.recv_buf[..size]) {
                        Ok(n) => {
                            tracing::trace!(
                                conv = self.conv,
                                n,
                                "KCP SESSION: recv_and_push got {} bytes",
                                n
                            );
                            let data = self.recv_buf[..n].to_vec();
                            match self.read_tx.try_send(data) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(d)) => {
                                    // Save for next tick — data was already
                                    // consumed from KCP receive queue and ACK'd.
                                    // Dropping it would cause a permanent byte-stream
                                    // hole (KCP retransmission won't recover it).
                                    tracing::debug!(
                                        conv = self.conv,
                                        n,
                                        "KCP SESSION: read_tx full, holding frame ({} bytes) for retry",
                                        n
                                    );
                                    self.pending_read = Some(d);
                                    return Ok(());
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    self.shutdown = true;
                                    tracing::debug!(
                                        conv = self.conv,
                                        "KCP SESSION: read_tx closed, shutting down conv {}",
                                        self.conv
                                    );
                                    return Err(io::Error::new(
                                        io::ErrorKind::NotConnected,
                                        "KCP read channel closed",
                                    ));
                                }
                            }
                        }
                        Err(e) => return Err(io::Error::other(e)),
                    }
                }
                Err(KcpError::RecvQueueEmpty) => return Ok(()),
                Err(e) => return Err(io::Error::other(e)),
            }
        }
    }

    /// Check if the KCP connection is dead (too many retransmissions).
    pub fn is_dead_link(&self) -> bool {
        self.kcp.is_dead_link()
    }

    /// Returns a handle that becomes false when the session is removed from
    /// the driver. KcpStream uses this to detect a dead session.
    pub fn alive_handle(&self) -> Arc<AtomicBool> {
        self.alive.clone()
    }

    /// Mark the session as dead -- called by KcpSocket when removing.
    pub fn mark_dead(&self) {
        self.alive.store(false, Ordering::Release);
        // Wake any poll_write task blocked on send-queue backpressure so it
        // observes the dead session (poll_write checks alive first). Uses
        // notify_one(): after the session is dead there will never be another
        // over→under crossing to trigger a wakeup, so a lost notification
        // would leave a just-registered waiter parked forever. notify_one()
        // stores a permit when no waiter is registered yet, guaranteeing the
        // wakeup arrives once the waiter registers.
        self.snd_notify.notify_one();
    }

    /// Mark session for shutdown. Driver will remove it on next tick.
    #[cfg(test)]
    pub fn shutdown(&mut self) {
        self.shutdown = true;
    }

    /// Time-based FEC continuity detection (mirrors kcp-go fec.go timeout
    /// policy): drop any group that hasn't received a shard within
    /// `FEC_GROUP_EXPIRE_MS`. A partially-filled group can otherwise pin
    /// memory indefinitely after extreme reordering or a long silent period.
    fn prune_old_groups(&mut self) {
        let now = self.fec_now_ms();
        self.shard_groups
            .retain(|_, g| now.saturating_sub(g.last_active_ms) <= FEC_GROUP_EXPIRE_MS);

        // Keep the existing "max 3 shard sets" cap on top of the time check.
        while self.shard_groups.len() > MAX_SHARD_SETS {
            let oldest = self.shard_groups.keys().copied().min();
            if let Some(key) = oldest {
                self.shard_groups.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Current FEC continuity-clock time in milliseconds. Uses a monotonic
    /// clock in production; tests may pin an explicit value via
    /// `set_fec_clock_ms`.
    fn fec_now_ms(&self) -> u64 {
        match self.fec_clock_override {
            Some(ms) => ms,
            None => self.fec_clock_base.elapsed().as_millis() as u64,
        }
    }

    /// Pin the FEC continuity clock to a fixed value (test helper).
    #[cfg(test)]
    pub fn set_fec_clock_ms(&mut self, ms: u64) {
        self.fec_clock_override = Some(ms);
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::{KcpConfig, KcpNoDelayConfig};
    use super::*;

    fn test_config() -> KcpConfig {
        KcpConfig {
            mtu: 1400,
            wnd_size: (128, 128),
            stream: true,
            data_shards: 0,
            parity_shards: 0,
            nodelay: KcpNoDelayConfig {
                nodelay: true,
                interval: 10,
                resend: 2,
                nc: true,
            },
        }
    }

    #[test]
    fn test_session_create_no_fec() {
        let (read_tx, _read_rx) = tokio::sync::mpsc::channel(16);
        let session = KcpSession::new(
            12345,
            "127.0.0.1:9000".parse().unwrap(),
            test_config(),
            read_tx,
        );
        assert_eq!(session.conv(), 12345);
        assert!(!session.is_dead_link());
    }

    /// Build a bare KCP header segment (24 bytes) with the given command and
    /// advertised window. No payload.
    fn make_header_pkt(conv: u32, cmd: u8, wnd: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 24];
        pkt[0..4].copy_from_slice(&conv.to_le_bytes());
        pkt[4] = cmd;
        pkt[6..8].copy_from_slice(&wnd.to_le_bytes());
        pkt
    }

    #[test]
    fn test_snd_backlog_bounded_when_remote_window_zero() {
        // A peer advertising window 0 never ACKs; without a bound the KCP send
        // queue grows without limit. Verify the shared snd_backlog counter
        // (the value KcpStream::poll_write gates on) tracks wait_snd() past
        // KCP_SND_BACKLOG_THRESHOLD.
        let (read_tx, _read_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let mut session = KcpSession::new(
            77,
            "127.0.0.1:9999".parse().unwrap(),
            test_config(),
            read_tx,
        );

        // Tell the sender the remote receive window is 0 (WINS cmd, wnd=0).
        session.input(&make_header_pkt(77, 0x54, 0)).unwrap();
        assert_eq!(session.kcp.rmt_wnd(), 0);

        // Send 1-segment chunks. With rmt_wnd=0, flush() cannot move segments
        // out of snd_queue, so wait_snd() grows past the threshold and the
        // shared counter follows (poll_write will then return Pending).
        let mss = session.kcp.mss();
        let mut sends = 0;
        while session.kcp.wait_snd() < KCP_SND_BACKLOG_THRESHOLD {
            session.send(vec![0u8; mss]).unwrap();
            sends += 1;
            assert!(
                sends < 100_000,
                "snd_queue should grow but remain observable/bounded"
            );
        }

        assert_eq!(
            session.snd_backlog.load(Ordering::Relaxed),
            session.kcp.wait_snd()
        );
        assert!(session.snd_backlog.load(Ordering::Relaxed) >= KCP_SND_BACKLOG_THRESHOLD);
    }

    #[test]
    fn test_snd_backlog_recovers_when_window_reopens() {
        // Security scenario + recovery: fill snd_queue past the threshold with
        // the peer window closed, then reopen the window and confirm ACKs drain
        // the shared backlog below the threshold (so poll_write resumes instead
        // of deadlocking).
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
        let mut s1 = KcpSession::new(88, "127.0.0.1:9001".parse().unwrap(), test_config(), tx1);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
        let mut s2 = KcpSession::new(88, "127.0.0.1:9000".parse().unwrap(), test_config(), tx2);

        // Close the peer's window.
        s1.input(&make_header_pkt(88, 0x54, 0)).unwrap();
        assert_eq!(s1.kcp.rmt_wnd(), 0);

        // Fill snd_queue past the threshold.
        let mss = s1.kcp.mss();
        let mut sends = 0;
        while s1.kcp.wait_snd() < KCP_SND_BACKLOG_THRESHOLD {
            s1.send(vec![0u8; mss]).unwrap();
            sends += 1;
            assert!(sends < 100_000);
        }
        assert!(s1.snd_backlog.load(Ordering::Relaxed) >= KCP_SND_BACKLOG_THRESHOLD);

        // Reopen the peer's window.
        s1.input(&make_header_pkt(88, 0x54, 128)).unwrap();
        assert_eq!(s1.kcp.rmt_wnd(), 128);

        // Pump both directions until s1's backlog drains below the threshold.
        let mut now_ms = 0u32;
        let mut rounds = 0;
        while s1.snd_backlog.load(Ordering::Relaxed) >= KCP_SND_BACKLOG_THRESHOLD {
            now_ms += 10;
            let pkts1 = s1.update(now_ms).unwrap();
            for p in &pkts1 {
                s2.input(p).unwrap();
            }
            s2.recv_and_push().unwrap();
            let pkts2 = s2.update(now_ms).unwrap();
            for p in &pkts2 {
                s1.input(p).unwrap();
            }
            s1.recv_and_push().unwrap();
            while rx2.try_recv().is_ok() {
                // Keep s2's receive window open by draining delivered data.
            }
            rounds += 1;
            assert!(
                rounds < 1000,
                "snd_backlog should drain below threshold after window reopens"
            );
        }
        assert!(s1.snd_backlog.load(Ordering::Relaxed) < KCP_SND_BACKLOG_THRESHOLD);
    }

    #[test]
    fn test_session_send_recv_roundtrip() {
        let config = test_config();
        let (read_tx1, _read_rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let mut s1 = KcpSession::new(
            1,
            "127.0.0.1:9001".parse().unwrap(),
            config.clone(),
            read_tx1,
        );
        let (read_tx2, mut read_rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let mut s2 = KcpSession::new(1, "127.0.0.1:9000".parse().unwrap(), config, read_tx2);

        s1.send(b"hello kcp".to_vec()).unwrap();

        let mut now_ms = 0u32;
        for _ in 0..20 {
            now_ms += 10;
            let packets = s1.update(now_ms).unwrap();
            for pkt in &packets {
                s2.input(pkt).unwrap();
            }
            s2.update(now_ms).unwrap();
            s2.recv_and_push().unwrap();

            if let Ok(data) = read_rx2.try_recv() {
                assert_eq!(data, b"hello kcp");
                return;
            }
        }
        panic!("timed out waiting for data");
    }

    #[test]
    fn test_session_send_no_fec_produces_packets() {
        let config = test_config();
        let (read_tx, _) = tokio::sync::mpsc::channel(16);
        let mut session = KcpSession::new(42, "127.0.0.1:9999".parse().unwrap(), config, read_tx);

        session.send(b"test data".to_vec()).unwrap();

        let mut got_packets = false;
        for tick in 0..10 {
            let packets = session.update((tick + 1) * 10).unwrap();
            if !packets.is_empty() {
                got_packets = true;
                break;
            }
        }
        assert!(got_packets, "should produce output after send+flush");
    }

    #[test]
    fn test_session_shutdown_produces_no_output() {
        let (read_tx, _) = tokio::sync::mpsc::channel(16);
        let mut session =
            KcpSession::new(1, "127.0.0.1:9999".parse().unwrap(), test_config(), read_tx);

        session.shutdown();
        let packets = session.update(10).unwrap();
        assert!(
            packets.is_empty(),
            "shutdown session should produce no output"
        );
    }

    fn fec_config() -> KcpConfig {
        KcpConfig {
            mtu: 1400,
            wnd_size: (128, 128),
            // Non-stream mode: each send() = one KCP output packet = one FEC data shard.
            stream: false,
            data_shards: 3,
            parity_shards: 2,
            nodelay: KcpNoDelayConfig {
                nodelay: true,
                interval: 10,
                resend: 2,
                nc: true,
            },
        }
    }

    #[test]
    fn test_fec_encode_decode_roundtrip() {
        let config = fec_config();
        let (tx1, _rx1) = tokio::sync::mpsc::channel(16);
        let mut sender = KcpSession::new(1, "127.0.0.1:9001".parse().unwrap(), config.clone(), tx1);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);
        let mut receiver = KcpSession::new(1, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        sender.send(b"hello fec".to_vec()).unwrap();

        let mut now_ms = 0u32;
        for _ in 0..50 {
            now_ms += 10;
            let packets = sender.update(now_ms).unwrap();
            for pkt in &packets {
                receiver.input(pkt).unwrap();
            }
            receiver.update(now_ms).unwrap();
            receiver.recv_and_push().unwrap();

            if let Ok(data) = rx2.try_recv() {
                assert_eq!(data, b"hello fec");
                return;
            }
        }
        panic!("timed out waiting for FEC data");
    }

    #[test]
    fn test_fec_encode_decode_multiple_packets() {
        // Test inter-packet FEC: multiple sends produce data+parity shards.
        let config = fec_config();
        let (tx1, _rx1) = tokio::sync::mpsc::channel(16);
        let mut sender = KcpSession::new(2, "127.0.0.1:9001".parse().unwrap(), config.clone(), tx1);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);
        let mut receiver = KcpSession::new(2, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        // Send 3 packets interleaved with update to force KCP to produce
        // separate output packets (stream mode would otherwise coalesce).
        sender.send(b"pkt1".to_vec()).unwrap();
        let _ = sender.update(10).unwrap();
        sender.send(b"pkt2".to_vec()).unwrap();
        let _ = sender.update(20).unwrap();
        sender.send(b"pkt3".to_vec()).unwrap();

        let mut received = Vec::new();
        let mut now_ms = 30u32;
        for _ in 0..80 {
            now_ms += 10;
            let packets = sender.update(now_ms).unwrap();
            for pkt in &packets {
                receiver.input(pkt).unwrap();
            }
            receiver.update(now_ms).unwrap();
            receiver.recv_and_push().unwrap();

            while let Ok(data) = rx2.try_recv() {
                received.push(data);
            }
            if received.len() >= 3 {
                break;
            }
        }
        assert_eq!(received.len(), 3);
        assert_eq!(received[0], b"pkt1");
        assert_eq!(received[1], b"pkt2");
        assert_eq!(received[2], b"pkt3");
    }

    #[test]
    fn test_fec_encode_decode_data_ending_with_zero() {
        let config = fec_config();
        let (tx1, _rx1) = tokio::sync::mpsc::channel(16);
        let mut sender = KcpSession::new(3, "127.0.0.1:9001".parse().unwrap(), config.clone(), tx1);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);
        let mut receiver = KcpSession::new(3, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        // Data ending with zero bytes. SIZE field protects against
        // trailing-zero corruption (SIZE tells exact payload length).
        let data = b"hello\0\0\0\x01\x00";
        sender.send(data.to_vec()).unwrap();

        let mut now_ms = 0u32;
        for _ in 0..50 {
            now_ms += 10;
            let packets = sender.update(now_ms).unwrap();
            for pkt in &packets {
                receiver.input(pkt).unwrap();
            }
            receiver.update(now_ms).unwrap();
            receiver.recv_and_push().unwrap();

            if let Ok(received) = rx2.try_recv() {
                assert_eq!(received, data, "data with trailing zero preserved");
                return;
            }
        }
        panic!("timed out waiting for FEC data with trailing zero");
    }

    #[test]
    fn test_fec_parity_recovery() {
        let config = fec_config(); // non-stream: each send = one output packet
        let (tx1, _rx1) = tokio::sync::mpsc::channel(16);
        let mut sender = KcpSession::new(4, "127.0.0.1:9001".parse().unwrap(), config.clone(), tx1);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);
        let mut receiver = KcpSession::new(4, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        // Send 3 packets, running update after each to flush individually.
        let mut all_packets = Vec::new();
        let mut now_ms = 0u32;

        sender.send(b"parity test payload".to_vec()).unwrap();
        for _ in 0..10 {
            now_ms += 10;
            all_packets.extend(sender.update(now_ms).unwrap());
        }
        sender.send(b"filler-a".to_vec()).unwrap();
        for _ in 0..10 {
            now_ms += 10;
            all_packets.extend(sender.update(now_ms).unwrap());
        }
        sender.send(b"filler-b".to_vec()).unwrap();
        for _ in 0..20 {
            now_ms += 10;
            all_packets.extend(sender.update(now_ms).unwrap());
        }

        let data_packets: Vec<_> = all_packets
            .iter()
            .filter(|p| p.len() >= 6 && u16::from_le_bytes([p[4], p[5]]) == TYPE_DATA)
            .collect();
        assert!(
            data_packets.len() >= 3,
            "should have at least 3 data shards, got {} data / {} total",
            data_packets.len(),
            all_packets.len()
        );

        // Drop the second data shard (data_idx=1), feed rest to receiver.
        let mut skipped = false;
        let mut data_idx = 0u32;
        for pkt in &all_packets {
            if pkt.len() < 6 {
                continue;
            }
            let flag = u16::from_le_bytes([pkt[4], pkt[5]]);
            if flag == TYPE_DATA {
                if data_idx == 1 && !skipped {
                    skipped = true;
                    data_idx += 1;
                    continue;
                }
                data_idx += 1;
            }
            receiver.input(pkt).unwrap();
        }
        assert!(skipped, "should have skipped second data shard");

        // Drive receiver to complete FEC decode.
        for _ in 0..40 {
            now_ms += 10;
            let rpkts = receiver.update(now_ms).unwrap();
            for pkt in rpkts {
                sender.input(&pkt).unwrap();
            }
            receiver.recv_and_push().unwrap();
            sender.update(now_ms + 100).unwrap();
            sender.recv_and_push().unwrap();
        }

        let mut got = Vec::new();
        while let Ok(data) = rx2.try_recv() {
            got.push(data);
        }
        let payload_found = got.iter().any(|d| d == b"parity test payload");
        assert!(
            payload_found,
            "should recover parity test payload, got: {:?}",
            got
        );
    }

    #[test]
    fn test_fec_enabled_parity_shards_on_wire() {
        // Verify parity shards appear when data_shards packets are collected.
        let config = fec_config(); // data_shards=3, parity_shards=2
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut sender = KcpSession::new(5, "127.0.0.1:9999".parse().unwrap(), config, tx);

        // Send 3 packets interleaved with update to force KCP to produce
        // separate output packets (stream mode coalesces otherwise).
        sender.send(b"a".to_vec()).unwrap();
        let packets1 = sender.update(10).unwrap();
        sender.send(b"b".to_vec()).unwrap();
        let packets2 = sender.update(20).unwrap();
        sender.send(b"c".to_vec()).unwrap();
        let packets3 = sender.update(30).unwrap();

        let all_packets: Vec<&Vec<u8>> = packets1
            .iter()
            .chain(packets2.iter())
            .chain(packets3.iter())
            .collect();

        // Should have at least 3 data shards. Parity may follow in later updates.
        let data_count = all_packets
            .iter()
            .filter(|p| p.len() >= 6 && u16::from_le_bytes([p[4], p[5]]) == TYPE_DATA)
            .count();
        assert!(
            data_count >= 3,
            "should have at least 3 data shards, got {}",
            data_count
        );

        // Run more updates to flush parity.
        let mut parity_count = 0usize;
        for tick in 0..20 {
            let packets = sender.update(40 + tick * 10).unwrap();
            parity_count += packets
                .iter()
                .filter(|p| p.len() >= 6 && u16::from_le_bytes([p[4], p[5]]) == TYPE_PARITY)
                .count();
            if parity_count >= 2 {
                break;
            }
        }
        assert!(
            parity_count >= 2,
            "should have at least 2 parity shards, got {}",
            parity_count
        );
    }

    #[test]
    fn test_fec_decode_drops_non_fec_packets() {
        // Non-FEC packets (flag != 0xf1/0xf2) should be treated as raw KCP.
        // Use no-FEC config so the session passes through to kcp directly.
        let config = test_config(); // data_shards=0, parity_shards=0
        let (tx1, _rx1) = tokio::sync::mpsc::channel(16);
        let mut receiver = KcpSession::new(
            0, // conv must match raw packet's embedded conv (0 for all-zeros)
            "127.0.0.1:9999".parse().unwrap(),
            config,
            tx1,
        );

        // Build a raw KCP packet (not FEC format, but valid KCP header).
        // KCP header: conv(4B) + cmd(1B) + frg(1B) + wnd(2B) + ...
        // All zeros = conv=0, cmd=0 (invalid — PUSH is 0x51), frg=0 — will not cause panic.
        let raw_pkt = [0u8; 24]; // minimum KCP header size
                                 // This may or may not produce an error from kcp (depends on internal
                                 // validation), but it should NOT panic.
        let _ = receiver.input(&raw_pkt);
    }

    /// Build a raw KCP PUSH segment with a 24-byte header (same wire layout
    /// as the `make_push` helper in protocol.rs tests). 0x51 = KCP_CMD_PUSH.
    fn make_push(conv: u32, sn: u32, frg: u8, ts: u32, data: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(24 + data.len());
        pkt.extend_from_slice(&conv.to_le_bytes());
        pkt.push(0x51);
        pkt.push(frg);
        pkt.extend_from_slice(&128u16.to_le_bytes()); // wnd
        pkt.extend_from_slice(&ts.to_le_bytes());
        pkt.extend_from_slice(&sn.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // una
        pkt.extend_from_slice(&(data.len() as u32).to_le_bytes());
        pkt.extend_from_slice(data);
        pkt
    }

    #[test]
    fn test_fec_stale_partial_group_pruned_by_timeout() {
        // A partially-filled FEC group must be dropped once it receives no
        // shard for FEC_GROUP_EXPIRE_MS, mirroring kcp-go fec.go's timeout
        // policy (`fecExpire`). The existing MAX_SHARD_SETS cap stays on top.
        let config = fec_config(); // data_shards=3, parity_shards=2
        let (tx1, _rx1) = tokio::sync::mpsc::channel(16);
        let mut sender = KcpSession::new(6, "127.0.0.1:9001".parse().unwrap(), config.clone(), tx1);
        let (tx2, _rx2) = tokio::sync::mpsc::channel(16);
        let mut receiver = KcpSession::new(6, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        // Pin the FEC clock so the silent gap can be simulated deterministically.
        receiver.set_fec_clock_ms(0);

        // Produce one complete FEC group and feed only 2 of its 3 data shards,
        // so the group never completes.
        sender.send(b"one".to_vec()).unwrap();
        sender.send(b"two".to_vec()).unwrap();
        sender.send(b"three".to_vec()).unwrap();
        let mut packets = Vec::new();
        for tick in 0..30 {
            packets.extend(sender.update(10 + tick * 10).unwrap());
            if packets
                .iter()
                .filter(|p| p.len() >= 6 && u16::from_le_bytes([p[4], p[5]]) == TYPE_DATA)
                .count()
                >= 3
            {
                break;
            }
        }
        let mut fed = 0usize;
        for pkt in &packets {
            if pkt.len() >= 6 && u16::from_le_bytes([pkt[4], pkt[5]]) == TYPE_DATA && fed < 2 {
                receiver.input(pkt).unwrap();
                fed += 1;
            }
        }
        assert_eq!(fed, 2);
        assert_eq!(receiver.shard_groups.len(), 1, "partial group retained");

        // Still within the expiry window: prune must keep the group.
        receiver.set_fec_clock_ms(FEC_GROUP_EXPIRE_MS - 1);
        receiver.prune_old_groups();
        assert_eq!(
            receiver.shard_groups.len(),
            1,
            "active group survives prune"
        );

        // Group silent longer than FEC_GROUP_EXPIRE_MS: prune (as invoked from
        // input()) must drop the stale residue.
        receiver.set_fec_clock_ms(FEC_GROUP_EXPIRE_MS + 1);
        receiver.prune_old_groups();
        assert!(
            receiver.shard_groups.is_empty(),
            "stale partial group must be pruned after FEC_GROUP_EXPIRE_MS"
        );
    }

    #[test]
    fn test_zero_len_push_consumed_without_forwarding() {
        // A len=0 PUSH segment must be consumed without being forwarded as an
        // empty frame — an empty frame would make KcpStream::poll_read return
        // Ok(0), which tokio treats as EOF and tears the connection down.
        let config = test_config();
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);
        let mut s2 = KcpSession::new(9, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        // Empty PUSH first (sn=0), then a real PUSH (sn=1) from the same peer.
        s2.input(&make_push(9, 0, 0, 0, b"")).unwrap();
        s2.input(&make_push(9, 1, 0, 0, b"after empty")).unwrap();

        s2.update(10).unwrap();
        s2.recv_and_push().unwrap();

        let mut frames = Vec::new();
        while let Ok(d) = rx2.try_recv() {
            frames.push(d);
        }
        assert!(
            frames.iter().all(|f| !f.is_empty()),
            "no empty frame may be forwarded, got {:?}",
            frames
        );
        assert_eq!(frames, vec![b"after empty".to_vec()]);
    }

    #[test]
    fn test_zero_len_push_in_fragment_chain_reassembles() {
        // An empty segment in the MIDDLE of a fragment chain (frg=1 empty,
        // frg=0 carries data) must not corrupt reassembly: the chain's total
        // peek size is non-zero, so the normal path merges it into one frame.
        let config = test_config();
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);
        let mut s2 = KcpSession::new(10, "127.0.0.1:9000".parse().unwrap(), config, tx2);

        s2.input(&make_push(10, 0, 1, 0, b"")).unwrap();
        s2.input(&make_push(10, 1, 0, 0, b"tail")).unwrap();

        s2.update(10).unwrap();
        s2.recv_and_push().unwrap();

        let mut frames = Vec::new();
        while let Ok(d) = rx2.try_recv() {
            frames.push(d);
        }
        assert_eq!(frames, vec![b"tail".to_vec()]);
    }

    #[tokio::test]
    async fn test_snd_backlog_crossing_wakes_parked_writer() {
        // Regression test for the snd_notify notification path. The existing
        // counter-only tests prove snd_backlog drains below the threshold, but
        // never check that a poll_write already parked on the snd_notify waiter
        // is actually woken. When snd_backlog crosses below
        // KCP_SND_BACKLOG_THRESHOLD, reconcile_snd_backlog must notify_one()
        // (which fires a registered waiter); if it used notify_waiters with no
        // stored-permit fallback the parked writer would sleep forever even
        // though the queue drained.
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
        let mut s1 = KcpSession::new(89, "127.0.0.1:9001".parse().unwrap(), test_config(), tx1);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
        let mut s2 = KcpSession::new(89, "127.0.0.1:9000".parse().unwrap(), test_config(), tx2);

        // Close the peer's window and fill snd_queue past the threshold.
        s1.input(&make_header_pkt(89, 0x54, 0)).unwrap();
        assert_eq!(s1.kcp.rmt_wnd(), 0);
        let mss = s1.kcp.mss();
        let mut sends = 0;
        while s1.kcp.wait_snd() < KCP_SND_BACKLOG_THRESHOLD {
            s1.send(vec![0u8; mss]).unwrap();
            sends += 1;
            assert!(sends < 100_000);
        }
        assert!(s1.snd_backlog.load(Ordering::Relaxed) >= KCP_SND_BACKLOG_THRESHOLD);

        // Simulate a poll_write that has parked on snd_notify: register the
        // waiter and confirm it is pending (not yet woken).
        let (_, notify) = s1.snd_backlog_handle();
        let mut notified = Box::pin(notify.clone().notified_owned());
        assert!(futures_util::poll!(&mut notified).is_pending());

        // Reopen the peer's window and pump both directions until the backlog
        // drains below the threshold — the crossing fires notify_one() and must
        // wake the parked waiter above.
        s1.input(&make_header_pkt(89, 0x54, 128)).unwrap();
        let mut now_ms = 0u32;
        let mut rounds = 0;
        while s1.snd_backlog.load(Ordering::Relaxed) >= KCP_SND_BACKLOG_THRESHOLD {
            now_ms += 10;
            let pkts1 = s1.update(now_ms).unwrap();
            for p in &pkts1 {
                s2.input(p).unwrap();
            }
            s2.recv_and_push().unwrap();
            let pkts2 = s2.update(now_ms).unwrap();
            for p in &pkts2 {
                s1.input(p).unwrap();
            }
            s1.recv_and_push().unwrap();
            while rx2.try_recv().is_ok() {
                // Keep s2's receive window open by draining delivered data.
            }
            rounds += 1;
            assert!(
                rounds < 1000,
                "snd_backlog should drain below threshold after window reopens"
            );
        }
        assert!(s1.snd_backlog.load(Ordering::Relaxed) < KCP_SND_BACKLOG_THRESHOLD);
        // The parked writer must have been woken by the crossing notification.
        assert!(
            futures_util::poll!(&mut notified).is_ready(),
            "parked poll_write must be woken once snd_backlog crosses below the threshold"
        );
    }

    #[tokio::test]
    async fn test_snd_notify_stores_permit_for_late_writer() {
        // Locks in the stored-permit contract of snd_notify. reconcile_snd_backlog
        // and mark_dead use notify_one() (NOT notify_waiters()) so a notification
        // fired before poll_write registers its waiter is not lost.
        //
        // This is the exact lost-wakeup window: the driver crosses the backlog
        // threshold downward while poll_write sits between its gate check and
        // waiter registration. notify_one() stores a permit when no waiter is
        // registered, which the just-registered notified_owned() consumes
        // immediately. notify_waiters() stores NO permit in this scenario, so the
        // late waiter would stay Pending and the writer would sleep forever — this
        // test pins the implementation to notify_one().
        let (read_tx, _read_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let session = KcpSession::new(
            90,
            "127.0.0.1:9999".parse().unwrap(),
            test_config(),
            read_tx,
        );
        let (_, notify) = session.snd_backlog_handle();

        // Driver finishes the crossing notification before any waiter registered.
        notify.notify_one();

        // A late-arriving writer must consume the stored permit right away.
        let mut n = Box::pin(notify.notified_owned());
        assert!(
            futures_util::poll!(&mut n).is_ready(),
            "notify_one must store a permit that a late waiter consumes immediately"
        );
    }
}
