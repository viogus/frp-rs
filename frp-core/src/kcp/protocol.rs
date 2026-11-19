//! Self-implemented KCP protocol state machine.
//!
//! This is the frp-rs in-tree replacement for the vendored `kcp` 0.6.0 crate,
//! which was removed from the tree together with `rust_tokio_kcp` (see
//! `CHANGELOG.md`, "KCP self-implementation"). It implements the same wire
//! protocol and the same three kcp-go v5.6.13 compatibility patches that the
//! vendored crate carried:
//!
//! 1. RTO **linear** backoff (`rto += rx_rto / 2`) instead of the original
//!    exponential `rto += rto / 2` when `nodelay` is enabled.
//! 2. `flush()` retransmission order: initial → fast_retransmit →
//!    early_retransmit → RTO (the original C kcp checks RTO first).
//! 3. Early retransmit on `fastack > 0 && new_segs == 0`.
//!
//! Only the synchronous API used by [`super::session::KcpSession`] is kept;
//! async and unused helper methods from the vendored crate are omitted. The
//! `Output` generic is driven through `std::io::Write` — every `write_all`
//! call is collected by the session as one outgoing UDP datagram.
//!
//! The wire layout is unchanged: 24-byte little-endian header
//! `conv u32 | cmd u8 | frg u8 | wnd u16 | ts u32 | sn u32 | una u32 | len u32`
//! followed by the payload.

use std::cmp;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Cursor, Read, Write};

use thiserror::Error;

// ── protocol constants (must stay wire-compatible with kcp/kcp-go) ──────

/// No-delay minimum RTO (ms).
const KCP_RTO_NDL: u32 = 30;
/// Normal minimum RTO (ms).
const KCP_RTO_MIN: u32 = 100;
/// Default RTO (ms).
const KCP_RTO_DEF: u32 = 200;
/// Maximum RTO (ms).
const KCP_RTO_MAX: u32 = 60_000;

/// Cmd: push data.
const KCP_CMD_PUSH: u8 = 81;
/// Cmd: acknowledge.
const KCP_CMD_ACK: u8 = 82;
/// Cmd: window probe (ask).
pub(crate) const KCP_CMD_WASK: u8 = 83;
/// Cmd: window size (tell).
const KCP_CMD_WINS: u8 = 84;

/// Need to send `IKCP_CMD_WASK`.
const KCP_ASK_SEND: u32 = 1;
/// Need to send `IKCP_CMD_WINS`.
const KCP_ASK_TELL: u32 = 2;

/// Default send window.
const KCP_WND_SND: u16 = 32;
/// Default receive window; must be >= max fragment count.
pub(crate) const KCP_WND_RCV: u16 = 128;

/// Default MTU.
const KCP_MTU_DEF: usize = 1400;

/// Default flush interval (ms).
const KCP_INTERVAL: u32 = 100;

/// KCP header size (bytes).
pub const KCP_OVERHEAD: usize = 24;

/// Retransmission limit before the link is marked dead.
const KCP_DEADLINK: u32 = 20;

/// Initial congestion threshold.
const KCP_THRESH_INIT: u16 = 2;
/// Minimum congestion threshold.
const KCP_THRESH_MIN: u16 = 2;

/// First window probe delay (ms).
const KCP_PROBE_INIT: u32 = 7000;
/// Maximum window probe delay (ms).
const KCP_PROBE_LIMIT: u32 = 120_000;
#[inline]
fn bound(lower: u32, v: u32, upper: u32) -> u32 {
    cmp::min(cmp::max(lower, v), upper)
}

/// Signed time difference with u32 wraparound semantics (same as kcp-go).
#[inline]
fn timediff(later: u32, earlier: u32) -> i32 {
    later as i32 - earlier as i32
}

// ── error type ──────────────────────────────────────────────────────────

/// KCP protocol errors. Mirrors the vendored crate's `Error` variants so the
/// session's pattern matching (`Error::RecvQueueEmpty` etc.) keeps working.
#[derive(Debug, Error)]
pub enum Error {
    #[error("conv inconsistent, expected {0}, found {1}")]
    ConvInconsistent(u32, u32),
    #[error("invalid mtu {0}")]
    InvalidMtu(usize),
    #[error("invalid segment size {0}")]
    InvalidSegmentSize(usize),
    #[error("invalid segment data size, expected {0}, found {1}")]
    InvalidSegmentDataSize(usize, usize),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("need to call update() once")]
    NeedUpdate,
    #[error("recv queue is empty")]
    RecvQueueEmpty,
    #[error("expecting fragment")]
    ExpectingFragment,
    #[error("unexpected fragment {0} in stream mode")]
    UnexpectedFragment(u8),
    #[error("command {0} is not supported")]
    UnsupportedCmd(u8),
    #[error("user's send buffer is too big")]
    UserBufTooBig,
    #[error("user's recv buffer is too small")]
    UserBufTooSmall,
}

/// Result alias returned by the state machine.
pub type Result<T> = std::result::Result<T, Error>;

// ── segment ─────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct KcpSegment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    data: Vec<u8>,
}

impl KcpSegment {
    fn new_with_data(data: Vec<u8>) -> Self {
        KcpSegment {
            data,
            ..Default::default()
        }
    }

    /// Append this segment to `buf` in the 24-byte little-endian wire format.
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.conv.to_le_bytes());
        buf.push(self.cmd);
        buf.push(self.frg);
        buf.extend_from_slice(&self.wnd.to_le_bytes());
        buf.extend_from_slice(&self.ts.to_le_bytes());
        buf.extend_from_slice(&self.sn.to_le_bytes());
        buf.extend_from_slice(&self.una.to_le_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
    }
}

// ── state machine ───────────────────────────────────────────────────────

/// KCP control state machine.
///
/// `Output` is the packet sink; `Kcp` writes complete datagrams to it through
/// `std::io::Write` (each `write_all` call is one outgoing packet).
/// frp-rs patch: cap on recycled segment payload buffers (F3). 64 × ~1376 B
/// (MSS) ≈ 88 KiB worst case per KCP session — bounded, so the freelist is a
/// cache, not an unbounded sink.
const KCP_SEGMENT_POOL_CAP: usize = 64;

pub struct Kcp<Output> {
    /// Conversation ID.
    conv: u32,
    /// Maximum Transmission Unit.
    mtu: usize,
    /// Maximum Segment Size.
    mss: usize,
    /// Connection state: 0 = alive, -1 = dead link.
    state: i32,

    /// First unacknowledged packet.
    snd_una: u32,
    /// Next send sequence number.
    snd_nxt: u32,
    /// Next expected receive sequence number.
    rcv_nxt: u32,

    /// Slow-start congestion threshold.
    ssthresh: u16,

    /// ACK receive variance (RTT).
    rx_rttval: u32,
    /// ACK receive smoothed RTT.
    rx_srtt: u32,
    /// Resend timeout (derived from RTT).
    rx_rto: u32,
    /// Minimal resend timeout.
    rx_minrto: u32,

    /// Send window.
    snd_wnd: u16,
    /// Receive window.
    rcv_wnd: u16,
    /// Remote receive window.
    rmt_wnd: u16,
    /// Congestion window.
    cwnd: u16,
    /// Pending window probe flags (`KCP_ASK_SEND` / `KCP_ASK_TELL`).
    probe: u32,

    /// Last `update` time.
    current: u32,
    /// Flush interval (ms).
    interval: u32,
    /// Next scheduled flush time.
    ts_flush: u32,
    /// Total RTO retransmissions (dead-link counter).
    xmit: u32,

    /// `nodelay` mode: uses `KCP_RTO_NDL` min RTO and linear RTO backoff.
    nodelay: bool,
    /// `update` has been called at least once.
    updated: bool,

    /// Next window-probe timestamp.
    ts_probe: u32,
    /// Window-probe wait time.
    probe_wait: u32,

    /// Maximum resend count before `state = -1`.
    dead_link: u32,
    /// Congestion-control increment accumulator.
    incr: usize,

    snd_queue: VecDeque<KcpSegment>,
    rcv_queue: VecDeque<KcpSegment>,
    snd_buf: VecDeque<KcpSegment>,
    rcv_buf: VecDeque<KcpSegment>,
    /// frp-rs patch: freelist of retired segment payload buffers (F3).
    /// ACKed / `snd_una`-discarded segments return their `data` `Vec` here
    /// instead of freeing it; `send()` reuses a buffer instead of a fresh
    /// `to_vec()`. Bounded by `KCP_SEGMENT_POOL_CAP`, so a flood of
    /// out-of-order ACKs cannot grow it without bound. `Kcp` is owned by a
    /// single `KcpSession` (one driver task), so a plain `Vec` freelist is
    /// safe — no Arc, no lock.
    snd_data_pool: Vec<Vec<u8>>,
    /// frp-rs patch: receive-side counterpart of `snd_data_pool`. `recv()`
    /// returns consumed segment payloads here; `input()` reuses a buffer
    /// instead of a fresh `Vec::with_capacity` per PUSH segment (~24
    /// segments per 64 KiB bridge chunk). Same cap and single-owner rules
    /// as the send-side pool.
    rcv_data_pool: Vec<Vec<u8>>,

    /// Pending ACKs `(sn, ts)`.
    acklist: VecDeque<(u32, u32)>,
    /// Output accumulation buffer (filled with one or more segments).
    buf: Vec<u8>,

    /// Fast-resend threshold (0 = disabled).
    fastresend: u32,
    /// Disable congestion control.
    nocwnd: bool,
    /// Stream mode (no message boundaries).
    stream: bool,

    /// Adopt the conversation ID from the next `input` call.
    input_conv: bool,

    output: Output,
}

impl<Output> fmt::Debug for Kcp<Output> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kcp")
            .field("conv", &self.conv)
            .field("mtu", &self.mtu)
            .field("mss", &self.mss)
            .field("state", &self.state)
            .field("snd_una", &self.snd_una)
            .field("snd_nxt", &self.snd_nxt)
            .field("rcv_nxt", &self.rcv_nxt)
            .field("ssthresh", &self.ssthresh)
            .field("rx_rttval", &self.rx_rttval)
            .field("rx_srtt", &self.rx_srtt)
            .field("rx_rto", &self.rx_rto)
            .field("snd_wnd", &self.snd_wnd)
            .field("rcv_wnd", &self.rcv_wnd)
            .field("rmt_wnd", &self.rmt_wnd)
            .field("cwnd", &self.cwnd)
            .field("probe", &self.probe)
            .field("current", &self.current)
            .field("interval", &self.interval)
            .field("xmit", &self.xmit)
            .field("nodelay", &self.nodelay)
            .field("updated", &self.updated)
            .field("dead_link", &self.dead_link)
            .field("incr", &self.incr)
            .field("snd_buf.len", &self.snd_buf.len())
            .field("snd_queue.len", &self.snd_queue.len())
            .field("rcv_buf.len", &self.rcv_buf.len())
            .field("rcv_queue.len", &self.rcv_queue.len())
            .field("acklist.len", &self.acklist.len())
            .field("fastresend", &self.fastresend)
            .field("nocwnd", &self.nocwnd)
            .field("stream", &self.stream)
            .field("input_conv", &self.input_conv)
            .finish()
    }
}

impl<Output> Kcp<Output> {
    /// Creates a KCP control object. `conv` must be equal on both endpoints
    /// of one connection. `output` is the packet sink.
    pub fn new(conv: u32, output: Output) -> Self {
        Self::construct(conv, output, false)
    }

    /// Creates a KCP control object in stream mode (no message boundaries).
    pub fn new_stream(conv: u32, output: Output) -> Self {
        Self::construct(conv, output, true)
    }

    fn construct(conv: u32, output: Output, stream: bool) -> Self {
        Kcp {
            conv,
            mtu: KCP_MTU_DEF,
            mss: KCP_MTU_DEF - KCP_OVERHEAD,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: KCP_THRESH_INIT,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: KCP_RTO_DEF,
            rx_minrto: KCP_RTO_MIN,
            snd_wnd: KCP_WND_SND,
            rcv_wnd: KCP_WND_RCV,
            rmt_wnd: KCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            current: 0,
            interval: KCP_INTERVAL,
            ts_flush: KCP_INTERVAL,
            xmit: 0,
            nodelay: false,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: KCP_DEADLINK,
            incr: 0,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            snd_data_pool: Vec::new(),
            rcv_data_pool: Vec::new(),
            acklist: VecDeque::new(),
            buf: Vec::with_capacity((KCP_MTU_DEF + KCP_OVERHEAD) * 3),
            fastresend: 0,
            nocwnd: false,
            stream,
            input_conv: false,
            output,
        }
    }

    /// frp-rs patch: recycle a retired segment's payload buffer (F3). Called
    /// when an ACKed / `snd_una`-discarded segment leaves `snd_buf`; the
    /// `data` `Vec` is cached for the next `send()` instead of being freed.
    /// Empty payloads (ACK / probe segments) and a full freelist are dropped.
    #[inline]
    fn recycle_segment_data(&mut self, seg: KcpSegment) {
        if !seg.data.is_empty() && self.snd_data_pool.len() < KCP_SEGMENT_POOL_CAP {
            self.snd_data_pool.push(seg.data);
        }
    }

    /// frp-rs patch: receive-side counterpart of [`Self::recycle_segment_data`]
    /// — return a dropped segment's payload to `rcv_data_pool`. Covers every
    /// path where a PUSH segment leaves the state machine without being
    /// stored: `recv()` consumption, the in-window duplicate (repeat) arm and
    /// the out-of-window / stale early return in `parse_data`. Without these,
    /// a retransmit flood would drain every buffer `input()` popped from the
    /// pool (perf-only: `recv()` would refill it).
    #[inline]
    fn recycle_rcv_data(&mut self, seg: KcpSegment) {
        if !seg.data.is_empty() && self.rcv_data_pool.len() < KCP_SEGMENT_POOL_CAP {
            self.rcv_data_pool.push(seg.data);
        }
    }

    /// Move available data from `rcv_buf` into `rcv_queue` in order.
    fn move_buf(&mut self) {
        while !self.rcv_buf.is_empty() {
            let nrcv_que = self.rcv_queue.len();
            {
                let seg = self
                    .rcv_buf
                    .front()
                    .expect("rcv_buf non-empty — while !is_empty() loop guard");
                if seg.sn == self.rcv_nxt && nrcv_que < self.rcv_wnd as usize {
                    self.rcv_nxt += 1;
                } else {
                    break;
                }
            }
            let seg = self
                .rcv_buf
                .pop_front()
                .expect("rcv_buf non-empty — while !is_empty() loop guard");
            self.rcv_queue.push_back(seg);
        }
    }

    /// Receive data from the buffer.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.rcv_queue.is_empty() {
            return Err(Error::RecvQueueEmpty);
        }

        let peeksize = self.peeksize()?;

        if peeksize > buf.len() {
            return Err(Error::UserBufTooSmall);
        }

        let recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        // Merge fragment chain. frp-rs patch: consumed payloads are recycled
        // into `rcv_data_pool` (F3 mirror) instead of freed; the cap keeps
        // the cache bounded exactly like the send-side pool.
        let mut cur = Cursor::new(buf);
        while let Some(seg) = self.rcv_queue.pop_front() {
            let chain_end = seg.frg == 0;
            cur.write_all(&seg.data)?;
            self.recycle_rcv_data(seg);
            if chain_end {
                break;
            }
        }
        debug_assert_eq!(cur.position() as usize, peeksize);

        self.move_buf();

        // Fast recover: tell the remote our window size.
        if self.rcv_queue.len() < self.rcv_wnd as usize && recover {
            self.probe |= KCP_ASK_TELL;
        }

        Ok(cur.position() as usize)
    }

    /// Check the size of the next receivable message without consuming it.
    pub fn peeksize(&self) -> Result<usize> {
        match self.rcv_queue.front() {
            Some(segment) => {
                if segment.frg == 0 {
                    return Ok(segment.data.len());
                }

                if self.rcv_queue.len() < (segment.frg + 1) as usize {
                    return Err(Error::ExpectingFragment);
                }

                let mut len = 0;
                for segment in &self.rcv_queue {
                    len += segment.data.len();
                    if segment.frg == 0 {
                        break;
                    }
                }

                Ok(len)
            }
            None => Err(Error::RecvQueueEmpty),
        }
    }

    /// Send bytes into the buffer. In stream mode a trailing partial segment
    /// is extended when possible; in message mode the data is split into
    /// `MSS`-sized segments chained by the `frg` field.
    ///
    /// The buffer is consumed through a single advancing offset: every byte
    /// is copied exactly once, into the segment that owns it. No
    /// `Vec::split_off` tail moves, so the shrinking-remainder chain that
    /// would re-allocate and re-copy the unconsumed tail on every segment is
    /// avoided entirely.
    ///
    /// The payload is borrowed (`impl AsRef<[u8]>`, so both `Vec<u8>` and
    /// `&[u8]` callers work): the segmentation copies each byte into its
    /// segments, so the caller retains ownership of the buffer and can
    /// recycle it (KcpStream's pooled write chunks).
    pub fn send(&mut self, buf: impl AsRef<[u8]>) -> Result<usize> {
        let buf = buf.as_ref();
        let mut sent_size = 0;
        let mut offset = 0;

        assert!(self.mss > 0, "mss must be positive");

        // Append to the previous segment in streaming mode (if possible).
        if self.stream {
            if let Some(old) = self.snd_queue.back_mut() {
                let l = old.data.len();
                if l < self.mss {
                    let capacity = self.mss - l;
                    let extend = cmp::min(buf.len() - offset, capacity);
                    old.data.extend_from_slice(&buf[offset..offset + extend]);
                    offset += extend;

                    old.frg = 0;
                    sent_size += extend;
                }
            }

            if offset == buf.len() {
                return Ok(sent_size);
            }
        }

        let remaining = buf.len() - offset;
        let count = if remaining <= self.mss {
            1
        } else {
            remaining.div_ceil(self.mss)
        };

        if count >= KCP_WND_RCV as usize {
            return Err(Error::UserBufTooBig);
        }

        let count = cmp::max(1, count);

        for i in 0..count {
            let size = cmp::min(self.mss, buf.len() - offset);
            // One exact-size copy per segment, straight out of the original
            // buffer (no split_off tail moves): each byte is copied exactly
            // once, into the single segment that owns it. frp-rs patch (F3):
            // reuse a retired segment's payload buffer instead of a fresh
            // `to_vec()` per segment (~48 segments per 64 KiB bridge chunk).
            let data = match self.snd_data_pool.pop() {
                Some(mut v) => {
                    v.clear();
                    v.extend_from_slice(&buf[offset..offset + size]);
                    v
                }
                None => buf[offset..offset + size].to_vec(),
            };
            let mut new_segment = KcpSegment::new_with_data(data);
            offset += size;

            new_segment.frg = if self.stream {
                0
            } else {
                (count - i - 1) as u8
            };

            self.snd_queue.push_back(new_segment);
            sent_size += size;
        }

        Ok(sent_size)
    }

    /// RFC 6298-style RTT smoothing.
    fn update_ack(&mut self, rtt: u32) {
        // Clamp hostile RTTs to the largest RTO we ever emit (KCP_RTO_MAX).
        // The ACK `ts` field is attacker-controlled: ts=0 against a large
        // `current` clock yields rtt ~ 2^31 ms, and the pre-fix arithmetic
        // `(7 * rx_srtt + rtt) / 8` overflowed u32 — a debug-build panic
        // killed the whole driver task on the second ACK (one-packet
        // session kill). With the clamp, rx_srtt <= 60_000 and rx_rttval
        // <= 60_000 (the smoothing's fixed point at the clamp, reachable
        // with alternating extreme ACKs), so no intermediate
        // (`7 * rx_srtt + rtt` <= 480_000, `4 * rx_rttval` <= 240_000) can
        // overflow u32.
        let rtt = rtt.min(KCP_RTO_MAX);
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.rx_srtt);
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8;
            if self.rx_srtt < 1 {
                self.rx_srtt = 1;
            }
        }
        let rto = self.rx_srtt + cmp::max(self.interval, 4 * self.rx_rttval);
        self.rx_rto = bound(self.rx_minrto, rto, KCP_RTO_MAX);
    }

    #[inline]
    fn shrink_buf(&mut self) {
        self.snd_una = match self.snd_buf.front() {
            Some(seg) => seg.sn,
            None => self.snd_nxt,
        };
    }

    fn parse_ack(&mut self, sn: u32) {
        if timediff(sn, self.snd_una) < 0 || timediff(sn, self.snd_nxt) >= 0 {
            return;
        }

        // Fast path: ACKs normally target the oldest unacked segment
        // (snd_una). pop_front is O(1); the linear scan below is only for
        // out-of-order ACKs.
        // frp-rs patch: recycle the ACKed segment's payload (F3). The closure
        // only reads the peeked front (no `self` capture), so pop_front_if's
        // borrow is fine — the owned segment is recycled after it returns.
        if let Some(seg) = self.snd_buf.pop_front_if(|front| front.sn == sn) {
            self.recycle_segment_data(seg);
            return;
        }

        let mut i = 0usize;
        while i < self.snd_buf.len() {
            match sn.cmp(&self.snd_buf[i].sn) {
                cmp::Ordering::Equal => {
                    // frp-rs patch: recycle the ACKed segment's payload (F3).
                    // `i` was found by the loop, so `i < snd_buf.len()` is a
                    // loop invariant — the expect is unreachable (round-18
                    // review: index check → debug_assert; the cost of a
                    // wrong guess is a skipped recycle, not a crash).
                    // `VecDeque::remove` returns `None` only for an
                    // out-of-range index — the buffer is never sparse (no
                    // kcp-go-style nil slots) — so the unwrap is guarded by
                    // the loop bound above, not by slot occupancy.
                    debug_assert!(i < self.snd_buf.len());
                    let seg = self.snd_buf.remove(i);
                    self.recycle_segment_data(seg.expect("ACKed segment must be Some"));
                    break;
                }
                cmp::Ordering::Less => break,
                _ => i += 1,
            }
        }
    }

    fn parse_una(&mut self, una: u32) {
        // frp-rs patch: recycle the discarded segment's payload (F3) — pop
        // while the front is within the una window, same loop semantics.
        while let Some(seg) = self
            .snd_buf
            .pop_front_if(|front| timediff(una, front.sn) > 0)
        {
            self.recycle_segment_data(seg);
        }
    }

    fn parse_fastack(&mut self, sn: u32, ts: u32) {
        if timediff(sn, self.snd_una) < 0 || timediff(sn, self.snd_nxt) >= 0 {
            return;
        }

        for seg in &mut self.snd_buf {
            if timediff(sn, seg.sn) < 0 {
                break;
            } else if sn != seg.sn && timediff(ts, seg.ts) >= 0 {
                seg.fastack += 1;
            }
        }
    }

    #[inline]
    fn ack_push(&mut self, sn: u32, ts: u32) {
        self.acklist.push_back((sn, ts));
    }

    fn parse_data(&mut self, new_segment: KcpSegment) {
        let sn = new_segment.sn;

        if timediff(sn, self.rcv_nxt + self.rcv_wnd as u32) >= 0 || timediff(sn, self.rcv_nxt) < 0 {
            // Out-of-window / stale (behind rcv_nxt): the buffer `input()`
            // popped from `rcv_data_pool` returns there instead of being
            // freed, so a stale-segment flood cannot drain the pool.
            self.recycle_rcv_data(new_segment);
            return;
        }

        let mut repeat = false;
        let mut new_index = self.rcv_buf.len();

        for segment in self.rcv_buf.iter().rev() {
            if segment.sn == sn {
                repeat = true;
                break;
            }
            if timediff(sn, segment.sn) > 0 {
                break;
            }
            new_index -= 1;
        }

        if !repeat {
            self.rcv_buf.insert(new_index, new_segment);
        } else {
            // In-window duplicate (network retransmission): not stored, so
            // recycle its payload — without this a retransmit flood would
            // drain every buffer popped from the pool.
            self.recycle_rcv_data(new_segment);
        }

        // Move available data from rcv_buf into rcv_queue.
        self.move_buf();
    }

    /// Adopt the `conv` value from the next `input` call.
    #[inline]
    pub fn input_conv(&mut self) {
        self.input_conv = true;
    }

    /// Whether this KCP is waiting to adopt a conversation ID from the next
    /// `input` call.
    #[inline]
    pub fn waiting_conv(&self) -> bool {
        self.input_conv
    }

    /// Set the conversation ID.
    #[inline]
    pub fn set_conv(&mut self, conv: u32) {
        self.conv = conv;
    }

    /// Get the conversation ID.
    #[inline]
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Feed a received UDP datagram into the state machine. May contain
    /// multiple concatenated KCP segments; each is parsed in turn.
    pub fn input(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() < KCP_OVERHEAD {
            return Err(Error::InvalidSegmentSize(buf.len()));
        }

        let mut flag = false;
        let mut max_ack = 0u32;
        let old_una = self.snd_una;
        let mut latest_ts = 0u32;

        let mut buf = Cursor::new(buf);
        while buf.get_ref().len() - buf.position() as usize >= KCP_OVERHEAD {
            let conv = read_u32_le(&mut buf);
            if conv != self.conv {
                // This allows adopting a conv from this call (server-side
                // conversation allocation).
                if self.input_conv {
                    self.conv = conv;
                    self.input_conv = false;
                } else {
                    return Err(Error::ConvInconsistent(self.conv, conv));
                }
            }

            let cmd = read_u8(&mut buf);
            let frg = read_u8(&mut buf);
            let wnd = read_u16_le(&mut buf);
            let ts = read_u32_le(&mut buf);
            let sn = read_u32_le(&mut buf);
            let una = read_u32_le(&mut buf);
            let len = read_u32_le(&mut buf) as usize;

            let remaining = buf.get_ref().len() - buf.position() as usize;
            if remaining < len {
                return Err(Error::InvalidSegmentDataSize(len, remaining));
            }

            match cmd {
                KCP_CMD_PUSH | KCP_CMD_ACK | KCP_CMD_WASK | KCP_CMD_WINS => {}
                _ => {
                    return Err(Error::UnsupportedCmd(cmd));
                }
            }

            self.rmt_wnd = wnd;

            self.parse_una(una);
            self.shrink_buf();

            let mut has_read_data = false;

            match cmd {
                KCP_CMD_ACK => {
                    let rtt = timediff(self.current, ts);
                    if rtt >= 0 {
                        self.update_ack(rtt as u32);
                    }
                    self.parse_ack(sn);
                    self.shrink_buf();

                    if !flag {
                        flag = true;
                        max_ack = sn;
                        latest_ts = ts;
                    } else if timediff(sn, max_ack) > 0 && timediff(ts, latest_ts) > 0 {
                        max_ack = sn;
                        latest_ts = ts;
                    }
                }
                KCP_CMD_PUSH => {
                    if timediff(sn, self.rcv_nxt + self.rcv_wnd as u32) < 0 {
                        self.ack_push(sn, ts);
                        if timediff(sn, self.rcv_nxt) >= 0 {
                            // Stream-mode sessions (the only mode frp runs —
                            // Go frp `SetStreamMode(true)`, `KcpConfig.stream`
                            // defaults) never carry fragment chains: every
                            // segment has frg=0. A hostile in-window PUSH with
                            // frg>0 would sit at the front of rcv_queue with
                            // its chain never completing, turning every
                            // peeksize() into ExpectingFragment and killing
                            // the session via recv_and_push — a one-packet
                            // session kill. Reject the whole datagram instead:
                            // input() errors are non-fatal (the driver logs
                            // and drops), so the session survives.
                            if self.stream && frg != 0 {
                                return Err(Error::UnexpectedFragment(frg));
                            }
                            // Reject oversized segments (beyond MSS): a conforming
                            // peer always fragments at MSS. Guards the per-connection
                            // recv buffer against len up to 64 KiB × window.
                            if len > self.mss {
                                return Err(Error::InvalidSegmentDataSize(self.mss, len));
                            }
                            // frp-rs patch (F3 mirror): reuse a recycled
                            // payload buffer instead of a fresh allocation
                            // per received segment — the receive-side twin
                            // of the send path's snd_data_pool pop.
                            let mut sbuf = match self.rcv_data_pool.pop() {
                                Some(v) => v,
                                None => Vec::with_capacity(len),
                            };
                            // Reuse-safe: a fresh `with_capacity(len)` needs
                            // nothing; a recycled buffer may have shrunk
                            // below `len` (segments vary in size).
                            sbuf.reserve(len);
                            // SAFETY: read_exact below fills exactly `len`
                            // bytes before returning; on error the Vec is
                            // dropped and `u8` is always-initialized, so the
                            // unwritten tail is never observed. Saves the
                            // memset of `vec![0u8; len]` per received segment.
                            #[allow(clippy::uninit_vec)]
                            // sound: u8, filled before read or dropped
                            unsafe {
                                sbuf.set_len(len)
                            };
                            buf.read_exact(&mut sbuf)?;
                            has_read_data = true;

                            let mut segment = KcpSegment::new_with_data(sbuf);
                            segment.conv = conv;
                            segment.cmd = cmd;
                            segment.frg = frg;
                            segment.wnd = wnd;
                            segment.ts = ts;
                            segment.sn = sn;
                            segment.una = una;

                            self.parse_data(segment);
                        }
                    }
                }
                KCP_CMD_WASK => {
                    // Ready to tell the remote our window size.
                    self.probe |= KCP_ASK_TELL;
                }
                KCP_CMD_WINS => {
                    // No-op: remote already knows our window.
                }
                _ => unreachable!("cmd validated above"),
            }

            // Skip any unread payload bytes.
            if !has_read_data {
                let next_pos = buf.position() + len as u64;
                buf.set_position(next_pos);
            }
        }

        if flag {
            self.parse_fastack(max_ack, latest_ts);
        }

        // Congestion window growth (slow start / congestion avoidance).
        if timediff(self.snd_una, old_una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr += (mss * mss) / self.incr + (mss / 16);
                if (self.cwnd as usize + 1) * mss <= self.incr {
                    // kcp-go uses floor division here; div_ceil would over-inflate
                    // cwnd by up to one MSS per round in congestion avoidance.
                    self.cwnd = (self.incr / mss) as u16;
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd as usize * mss;
            }
        }

        Ok(buf.position() as usize)
    }

    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            self.rcv_wnd - self.rcv_queue.len() as u16
        } else {
            0
        }
    }

    /// Ask the peer for its window on the next `flush()`.
    ///
    /// The driver uses this as a liveness probe for a session that has
    /// nothing in flight: `IKCP_CMD_WASK` is answered with `IKCP_CMD_WINS`,
    /// so a quiet session produces a datagram each way without inventing
    /// application bytes. Both commands are part of the KCP wire format that
    /// kcp-go implements, so this adds no incompatibility.
    pub fn request_window_probe(&mut self) {
        self.probe |= KCP_ASK_SEND;
    }

    /// Exponential-backoff window probing while the remote window is zero.
    fn probe_wnd_size(&mut self) {
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = KCP_PROBE_INIT;
                self.ts_probe = self.current + self.probe_wait;
            } else if timediff(self.current, self.ts_probe) >= 0 {
                if self.probe_wait < KCP_PROBE_INIT {
                    self.probe_wait = KCP_PROBE_INIT;
                }

                self.probe_wait += self.probe_wait / 2;

                if self.probe_wait > KCP_PROBE_LIMIT {
                    self.probe_wait = KCP_PROBE_LIMIT;
                }

                self.ts_probe = self.current + self.probe_wait;
                self.probe |= KCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }
    }
}

impl<Output> Kcp<Output> {
    /// Change MTU size. Default is 1400.
    pub fn set_mtu(&mut self, mtu: usize) -> Result<()> {
        if mtu < 50 || mtu < KCP_OVERHEAD {
            return Err(Error::InvalidMtu(mtu));
        }

        self.mtu = mtu;
        self.mss = mtu - KCP_OVERHEAD;

        let target_size = (mtu + KCP_OVERHEAD) * 3;
        if target_size > self.buf.capacity() {
            self.buf.reserve(target_size - self.buf.capacity());
        }

        Ok(())
    }

    /// Get MTU.
    #[inline]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Set the flush interval (clamped to [10, 5000] ms).
    pub fn set_interval(&mut self, interval: u32) {
        self.interval = interval.clamp(10, 5000);
    }

    /// Set nodelay options.
    ///
    /// Fastest config: `nodelay(true, 20, 2, true)`.
    ///
    /// - `nodelay`: enable no-delay mode (min RTO = 30ms, linear RTO backoff).
    /// - `interval`: internal flush interval in ms (default 100ms).
    /// - `resend`: 0 = disable fast resend (default), otherwise threshold.
    /// - `nc`: disable congestion control.
    pub fn set_nodelay(&mut self, nodelay: bool, interval: i32, resend: i32, nc: bool) {
        if nodelay {
            self.nodelay = true;
            self.rx_minrto = KCP_RTO_NDL;
        } else {
            self.nodelay = false;
            self.rx_minrto = KCP_RTO_MIN;
        }

        self.interval = if interval < 10 {
            10
        } else if interval > 5000 {
            5000
        } else {
            interval as u32
        };

        if resend >= 0 {
            self.fastresend = resend as u32;
        }

        self.nocwnd = nc;
    }

    /// Set maximum window sizes: `sndwnd=32`, `rcvwnd=32` by default.
    pub fn set_wndsize(&mut self, sndwnd: u16, rcvwnd: u16) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd;
        }

        if rcvwnd > 0 {
            self.rcv_wnd = cmp::max(rcvwnd, KCP_WND_RCV);
        }
    }

    /// Get the send window.
    #[inline]
    pub fn snd_wnd(&self) -> u16 {
        self.snd_wnd
    }

    /// Get the receive window.
    #[inline]
    pub fn rcv_wnd(&self) -> u16 {
        self.rcv_wnd
    }

    /// How many packets are waiting to be sent (`snd_buf + snd_queue`).
    #[inline]
    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Segments already handed to the wire but not yet ACKed.
    ///
    /// Distinct from `wait_snd`: data can wait in `snd_queue` behind a zero
    /// peer window without ever reaching the wire, and only in-flight
    /// segments can reach the retransmission bound (see
    /// `KcpSession::should_probe`).
    pub fn in_flight(&self) -> usize {
        self.snd_buf.len()
    }

    /// Get the remote window size.
    #[inline]
    pub fn rmt_wnd(&self) -> u16 {
        self.rmt_wnd
    }

    /// Force the remote window, for tests that need a flow-controlled sender
    /// without a live peer. Only the probe tests use it: with `0` a send can
    /// only park in `snd_queue`, which is the state the retransmission bound
    /// cannot see (see `KcpSession::should_probe`).
    #[cfg(test)]
    pub(crate) fn set_remote_window(&mut self, wnd: u16) {
        self.rmt_wnd = wnd;
    }

    /// Set `rx_minrto`.
    #[inline]
    pub fn set_rx_minrto(&mut self, rto: u32) {
        self.rx_minrto = rto;
    }

    /// Set the fast-resend threshold.
    #[inline]
    pub fn set_fast_resend(&mut self, fr: u32) {
        self.fastresend = fr;
    }

    /// KCP header size.
    #[inline]
    pub fn header_len() -> usize {
        KCP_OVERHEAD
    }

    /// Whether stream mode is enabled.
    #[inline]
    pub fn is_stream(&self) -> bool {
        self.stream
    }

    /// Maximum segment size.
    #[inline]
    pub fn mss(&self) -> usize {
        self.mss
    }

    /// Set the maximum resend times before the link is considered dead.
    #[inline]
    pub fn set_maximum_resend_times(&mut self, dead_link: u32) {
        self.dead_link = dead_link;
    }

    /// The retransmission bound currently in force (`[transport.kcp]
    /// deadLink`, kcp-go's `dead_link`).
    #[inline]
    pub fn maximum_resend_times(&self) -> u32 {
        self.dead_link
    }

    /// Whether the connection is dead (retransmissions exceeded the limit).
    #[inline]
    pub fn is_dead_link(&self) -> bool {
        self.state != 0
    }

    /// Get a mutable reference to the output writer.
    #[inline]
    pub fn output_mut(&mut self) -> &mut Output {
        &mut self.output
    }
}

impl<Output: Write> Kcp<Output> {
    /// Flush the accumulated output buffer, if non-empty.
    fn flush_buf(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.output.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }

    /// Flush all pending ACKs into the output buffer.
    fn _flush_ack(&mut self, segment: &mut KcpSegment) -> Result<()> {
        for &(sn, ts) in &self.acklist {
            if self.buf.len() + KCP_OVERHEAD > self.mtu {
                self.output.write_all(&self.buf)?;
                self.buf.clear();
            }
            segment.sn = sn;
            segment.ts = ts;
            segment.encode(&mut self.buf);
        }
        self.acklist.clear();

        Ok(())
    }

    fn _flush_probe_commands(&mut self, cmd: u8, segment: &mut KcpSegment) -> Result<()> {
        segment.cmd = cmd;
        if self.buf.len() + KCP_OVERHEAD > self.mtu {
            self.output.write_all(&self.buf)?;
            self.buf.clear();
        }
        segment.encode(&mut self.buf);
        Ok(())
    }

    fn flush_probe_commands(&mut self, segment: &mut KcpSegment) -> Result<()> {
        // Flush window probing commands.
        if (self.probe & KCP_ASK_SEND) != 0 {
            self._flush_probe_commands(KCP_CMD_WASK, segment)?;
        }
        if (self.probe & KCP_ASK_TELL) != 0 {
            self._flush_probe_commands(KCP_CMD_WINS, segment)?;
        }
        self.probe = 0;
        Ok(())
    }

    /// Flush pending ACKs.
    pub fn flush_ack(&mut self) -> Result<()> {
        if !self.updated {
            return Err(Error::NeedUpdate);
        }

        let mut segment = KcpSegment {
            conv: self.conv,
            cmd: KCP_CMD_ACK,
            wnd: self.wnd_unused(),
            una: self.rcv_nxt,
            ..Default::default()
        };

        self._flush_ack(&mut segment)
    }

    /// Flush pending data in the buffer to the output.
    pub fn flush(&mut self) -> Result<()> {
        if !self.updated {
            return Err(Error::NeedUpdate);
        }

        let mut segment = KcpSegment {
            conv: self.conv,
            cmd: KCP_CMD_ACK,
            wnd: self.wnd_unused(),
            una: self.rcv_nxt,
            ..Default::default()
        };

        self._flush_ack(&mut segment)?;
        self.probe_wnd_size();
        self.flush_probe_commands(&mut segment)?;

        // Calculate the effective congestion window.
        let mut cwnd = cmp::min(self.snd_wnd, self.rmt_wnd);
        if !self.nocwnd {
            cwnd = cmp::min(self.cwnd, cwnd);
        }
        // Move data from snd_queue to snd_buf.
        let mut new_segs_count: u32 = 0;
        while timediff(self.snd_nxt, self.snd_una + cwnd as u32) < 0 {
            match self.snd_queue.pop_front() {
                Some(mut new_segment) => {
                    new_segment.conv = self.conv;
                    new_segment.cmd = KCP_CMD_PUSH;
                    new_segment.wnd = segment.wnd;
                    new_segment.ts = self.current;
                    new_segment.sn = self.snd_nxt;
                    self.snd_nxt += 1;
                    new_segment.una = self.rcv_nxt;
                    new_segment.resendts = self.current;
                    new_segment.rto = self.rx_rto;
                    new_segment.fastack = 0;
                    new_segment.xmit = 0;
                    self.snd_buf.push_back(new_segment);
                    new_segs_count += 1;
                }
                None => break,
            }
        }

        // Fast-resend threshold.
        let resent = if self.fastresend > 0 {
            self.fastresend
        } else {
            u32::MAX
        };

        let rtomin = if !self.nodelay { self.rx_rto >> 3 } else { 0 };

        let mut lost = false;
        let mut change = 0u32;

        // Retransmission logic — order matches kcp-go v5.6.13:
        //   initial → fast_retransmit → early_retransmit → RTO
        // (the original C kcp checks RTO before fast_retransmit; kcp-go
        // reordered it).
        for snd_segment in &mut self.snd_buf {
            let mut need_send = false;

            if snd_segment.xmit == 0 {
                // ── initial transmit ──
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.rto = self.rx_rto;
                snd_segment.resendts = self.current + snd_segment.rto + rtomin;
            } else if snd_segment.fastack >= resent {
                // ── fast retransmit (kcp-go: before RTO) ──
                // No xmit cap, matching kcp-go v5.6.13 (which has no fastlimit
                // concept). The old C-kcp fastlimit gate combined with kcp-go's
                // branch order could permanently wedge a segment: fastack >= resent
                // with xmit > fastlimit entered the branch but skipped the send,
                // and the else-if chain then never evaluated the RTO fallback —
                // the segment was never retransmitted and the connection froze
                // under sustained loss.
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.fastack = 0;
                // kcp-go: reset rto to rx_rto on fast retransmit.
                snd_segment.rto = self.rx_rto;
                snd_segment.resendts = self.current + snd_segment.rto;
                change += 1;
            } else if snd_segment.fastack > 0 && new_segs_count == 0 {
                // ── early retransmit (kcp-go only; not in the original C) ──
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.fastack = 0;
                snd_segment.rto = self.rx_rto;
                snd_segment.resendts = self.current + snd_segment.rto;
                change += 1;
            } else if timediff(self.current, snd_segment.resendts) >= 0 {
                // ── RTO timeout ──
                need_send = true;
                snd_segment.xmit += 1;
                self.xmit += 1;
                if !self.nodelay {
                    snd_segment.rto += cmp::max(snd_segment.rto, self.rx_rto);
                } else {
                    // kcp-go: LINEAR backoff rto += rx_rto/2
                    // (the original C kcp uses EXPONENTIAL: rto += rto/2).
                    snd_segment.rto += self.rx_rto / 2;
                }
                snd_segment.fastack = 0;
                snd_segment.resendts = self.current + snd_segment.rto;
                lost = true;
            }

            if need_send {
                snd_segment.ts = self.current;
                snd_segment.wnd = segment.wnd;
                snd_segment.una = self.rcv_nxt;

                let need = KCP_OVERHEAD + snd_segment.data.len();

                if self.buf.len() + need > self.mtu {
                    self.output.write_all(&self.buf)?;
                    self.buf.clear();
                }

                snd_segment.encode(&mut self.buf);

                if snd_segment.xmit >= self.dead_link {
                    self.state = -1; // dead link
                }
            }
        }

        // Flush all data left in the buffer.
        self.flush_buf()?;

        // Update ssthresh after a fast/early retransmit.
        if change > 0 {
            let inflight = self.snd_nxt - self.snd_una;
            self.ssthresh = inflight as u16 / 2;
            if self.ssthresh < KCP_THRESH_MIN {
                self.ssthresh = KCP_THRESH_MIN;
            }
            // kcp-go computes cwnd = ssthresh + resent with u32 wraparound;
            // when fastresend is 0, resent is u32::MAX so this wraps to 1.
            self.cwnd = self.ssthresh.wrapping_add(resent as u16);
            self.incr = self.cwnd as usize * self.mss;
        }

        if lost {
            self.ssthresh = cwnd / 2;
            if self.ssthresh < KCP_THRESH_MIN {
                self.ssthresh = KCP_THRESH_MIN;
            }
            self.cwnd = 1;
            self.incr = self.mss;
        }

        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss;
        }

        Ok(())
    }

    /// Update state every 10ms ~ 100ms (or ask `check` when to call again).
    pub fn update(&mut self, current: u32) -> Result<()> {
        self.current = current;

        if !self.updated {
            self.updated = true;
            self.ts_flush = self.current;
        }

        let mut slap = timediff(self.current, self.ts_flush);

        if !(-10_000..10_000).contains(&slap) {
            self.ts_flush = self.current;
            slap = 0;
        }

        if slap >= 0 {
            self.ts_flush += self.interval;
            if timediff(self.current, self.ts_flush) >= 0 {
                self.ts_flush = self.current + self.interval;
            }
            self.flush()?;
        }

        Ok(())
    }
}

// ── little-endian reader helpers ────────────────────────────────────────

#[inline]
fn read_u8(buf: &mut Cursor<&[u8]>) -> u8 {
    let mut b = [0u8; 1];
    buf.read_exact(&mut b)
        .expect("buffer bounds checked by caller");
    b[0]
}

#[inline]
fn read_u16_le(buf: &mut Cursor<&[u8]>) -> u16 {
    let mut b = [0u8; 2];
    buf.read_exact(&mut b)
        .expect("buffer bounds checked by caller");
    u16::from_le_bytes(b)
}

#[inline]
fn read_u32_le(buf: &mut Cursor<&[u8]>) -> u32 {
    let mut b = [0u8; 4];
    buf.read_exact(&mut b)
        .expect("buffer bounds checked by caller");
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod tests;
