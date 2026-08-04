//! Self-implemented KCP protocol state machine.
//!
//! This is the frp-rs in-tree replacement for the vendored `kcp` crate
//! (`frp-core/vendored/kcp-0.6.0`). It implements the same wire protocol and
//! the same three kcp-go v5.6.13 compatibility patches as the vendored crate:
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
const KCP_CMD_WASK: u8 = 83;
/// Cmd: window size (tell).
const KCP_CMD_WINS: u8 = 84;

/// Need to send `IKCP_CMD_WASK`.
const KCP_ASK_SEND: u32 = 1;
/// Need to send `IKCP_CMD_WINS`.
const KCP_ASK_TELL: u32 = 2;

/// Default send window.
const KCP_WND_SND: u16 = 32;
/// Default receive window; must be >= max fragment count.
const KCP_WND_RCV: u16 = 128;

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
/// Maximum fast-ack count before a segment is always retransmitted.
const KCP_FASTACK_LIMIT: u32 = 5;

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

    /// Pending ACKs `(sn, ts)`.
    acklist: VecDeque<(u32, u32)>,
    /// Output accumulation buffer (filled with one or more segments).
    buf: Vec<u8>,

    /// Fast-resend threshold (0 = disabled).
    fastresend: u32,
    /// Max fast retransmissions before RTO takes over.
    fastlimit: u32,
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
            .field("fastlimit", &self.fastlimit)
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
            acklist: VecDeque::new(),
            buf: Vec::with_capacity((KCP_MTU_DEF + KCP_OVERHEAD) * 3),
            fastresend: 0,
            fastlimit: KCP_FASTACK_LIMIT,
            nocwnd: false,
            stream,
            input_conv: false,
            output,
        }
    }

    /// Move available data from `rcv_buf` into `rcv_queue` in order.
    fn move_buf(&mut self) {
        while !self.rcv_buf.is_empty() {
            let nrcv_que = self.rcv_queue.len();
            {
                let seg = self.rcv_buf.front().unwrap();
                if seg.sn == self.rcv_nxt && nrcv_que < self.rcv_wnd as usize {
                    self.rcv_nxt += 1;
                } else {
                    break;
                }
            }
            let seg = self.rcv_buf.pop_front().unwrap();
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

        // Merge fragment chain.
        let mut cur = Cursor::new(buf);
        while let Some(seg) = self.rcv_queue.pop_front() {
            cur.write_all(&seg.data)?;

            if seg.frg == 0 {
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
    pub fn send(&mut self, mut buf: &[u8]) -> Result<usize> {
        let mut sent_size = 0;

        assert!(self.mss > 0, "mss must be positive");

        // Append to the previous segment in streaming mode (if possible).
        if self.stream {
            if let Some(old) = self.snd_queue.back_mut() {
                let l = old.data.len();
                if l < self.mss {
                    let capacity = self.mss - l;
                    let extend = cmp::min(buf.len(), capacity);

                    let (lf, rt) = buf.split_at(extend);
                    old.data.extend_from_slice(lf);
                    buf = rt;

                    old.frg = 0;
                    sent_size += extend;
                }
            }

            if buf.is_empty() {
                return Ok(sent_size);
            }
        }

        let count = if buf.len() <= self.mss {
            1
        } else {
            buf.len().div_ceil(self.mss)
        };

        if count >= KCP_WND_RCV as usize {
            return Err(Error::UserBufTooBig);
        }

        let count = cmp::max(1, count);

        for i in 0..count {
            let size = cmp::min(self.mss, buf.len());

            let (lf, rt) = buf.split_at(size);
            let mut new_segment = KcpSegment::new_with_data(lf.to_vec());
            buf = rt;

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

        let mut i = 0usize;
        while i < self.snd_buf.len() {
            match sn.cmp(&self.snd_buf[i].sn) {
                cmp::Ordering::Equal => {
                    self.snd_buf.remove(i);
                    break;
                }
                cmp::Ordering::Less => break,
                _ => i += 1,
            }
        }
    }

    fn parse_una(&mut self, una: u32) {
        while let Some(seg) = self.snd_buf.front() {
            if timediff(una, seg.sn) > 0 {
                self.snd_buf.pop_front();
            } else {
                break;
            }
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
                            // Reject oversized segments (beyond MSS): a conforming
                            // peer always fragments at MSS. Guards the per-connection
                            // recv buffer against len up to 64 KiB × window.
                            if len > self.mss {
                                return Err(Error::InvalidSegmentDataSize(self.mss, len));
                            }
                            let mut sbuf = vec![0u8; len];
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
                    self.cwnd = self.incr.div_ceil(mss) as u16;
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

    /// Get the remote window size.
    #[inline]
    pub fn rmt_wnd(&self) -> u16 {
        self.rmt_wnd
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
                if snd_segment.xmit <= self.fastlimit || self.fastlimit == 0 {
                    need_send = true;
                    snd_segment.xmit += 1;
                    snd_segment.fastack = 0;
                    // kcp-go: reset rto to rx_rto on fast retransmit.
                    snd_segment.rto = self.rx_rto;
                    snd_segment.resendts = self.current + snd_segment.rto;
                    change += 1;
                }
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
mod tests {
    use super::*;
    use rand::Rng;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    // ── test helpers ─────────────────────────────────────────────────────

    /// Collects each write_all call as one packet.
    #[derive(Default)]
    struct PacketWriter {
        packets: Vec<Vec<u8>>,
    }

    impl Write for PacketWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.packets.push(data.to_vec());
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PacketWriter {
        fn drain(&mut self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.packets)
        }
    }

    /// Parse the 24-byte header of one packet.
    #[allow(clippy::type_complexity)]
    fn parse_packet(pkt: &[u8]) -> (u32, u8, u8, u16, u32, u32, u32, Vec<u8>) {
        assert!(pkt.len() >= KCP_OVERHEAD, "packet too short");
        let conv = u32::from_le_bytes(pkt[0..4].try_into().unwrap());
        let cmd = pkt[4];
        let frg = pkt[5];
        let wnd = u16::from_le_bytes(pkt[6..8].try_into().unwrap());
        let ts = u32::from_le_bytes(pkt[8..12].try_into().unwrap());
        let sn = u32::from_le_bytes(pkt[12..16].try_into().unwrap());
        let una = u32::from_le_bytes(pkt[16..20].try_into().unwrap());
        let len = u32::from_le_bytes(pkt[20..24].try_into().unwrap()) as usize;
        assert_eq!(len, pkt.len() - KCP_OVERHEAD, "payload length mismatch");
        (
            conv,
            cmd,
            frg,
            wnd,
            ts,
            sn,
            una,
            pkt[KCP_OVERHEAD..].to_vec(),
        )
    }

    /// Build a PUSH segment with a 24-byte header.
    fn make_push(conv: u32, sn: u32, frg: u8, ts: u32, data: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(KCP_OVERHEAD + data.len());
        pkt.extend_from_slice(&conv.to_le_bytes());
        pkt.push(KCP_CMD_PUSH);
        pkt.push(frg);
        pkt.extend_from_slice(&128u16.to_le_bytes()); // wnd
        pkt.extend_from_slice(&ts.to_le_bytes());
        pkt.extend_from_slice(&sn.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // una
        pkt.extend_from_slice(&(data.len() as u32).to_le_bytes());
        pkt.extend_from_slice(data);
        pkt
    }

    /// Build an ACK segment with a 24-byte header.
    fn make_ack(conv: u32, sn: u32, wnd: u16, ts: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(KCP_OVERHEAD);
        pkt.extend_from_slice(&conv.to_le_bytes());
        pkt.push(KCP_CMD_ACK);
        pkt.push(0);
        pkt.extend_from_slice(&wnd.to_le_bytes());
        pkt.extend_from_slice(&ts.to_le_bytes());
        pkt.extend_from_slice(&sn.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // una
        pkt.extend_from_slice(&0u32.to_le_bytes()); // len
        pkt
    }

    /// Drive a fresh Kcp through two updates so queued data actually flushes
    /// (the congestion window starts at 0, so the first flush only arms it).
    fn send_and_flush(kcp: &mut Kcp<PacketWriter>, data: &[u8]) {
        kcp.send(data).unwrap();
        // Default interval is 100ms, so the flush at update(100) moves the
        // queued segment into snd_buf and writes it to the output.
        kcp.update(0).unwrap();
        kcp.update(200).unwrap();
    }

    // ── 1. 24-byte header encoding / decoding ────────────────────────────

    #[test]
    fn header_encode_little_endian() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true); // nocwnd: first flush sends data
        a.send(b"hello").unwrap();
        a.update(0).unwrap();

        let out = a.output_mut().drain();
        assert_eq!(out.len(), 1, "expected one packet");

        let (conv, cmd, frg, wnd, ts, sn, una, data) = parse_packet(&out[0]);
        assert_eq!(conv, 0x1122_3344);
        assert_eq!(cmd, KCP_CMD_PUSH);
        assert_eq!(frg, 0);
        assert_eq!(wnd, 128, "wnd = rcv_wnd(128) - empty queue");
        assert_eq!(ts, 0, "sent at current=0");
        assert_eq!(sn, 0);
        assert_eq!(una, 0);
        assert_eq!(data, b"hello");

        // Byte-exact little-endian layout.
        let expected: Vec<u8> = [
            0x44, 0x33, 0x22, 0x11, // conv LE
            0x51, // cmd = 81 (PUSH)
            0x00, // frg
            0x80, 0x00, // wnd = 128 LE
            0x00, 0x00, 0x00, 0x00, // ts
            0x00, 0x00, 0x00, 0x00, // sn
            0x00, 0x00, 0x00, 0x00, // una
            0x05, 0x00, 0x00, 0x00, // len = 5 LE
        ]
        .to_vec();
        let mut with_payload = expected.clone();
        with_payload.extend_from_slice(b"hello");
        assert_eq!(out[0], with_payload);
    }

    #[test]
    fn input_decodes_multiple_segments_in_one_datagram() {
        let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
        b.update(0).unwrap(); // arm updated

        // Two PUSH segments concatenated into a single datagram.
        let mut datagram = make_push(0x1122_3344, 0, 1, 5, b"aa");
        datagram.extend_from_slice(&make_push(0x1122_3344, 1, 0, 5, b"bb"));

        b.input(&datagram).unwrap();
        assert_eq!(b.peeksize().unwrap(), 4, "frg chain merged");
        let mut buf = [0u8; 16];
        assert_eq!(b.recv(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"aabb");
    }

    #[test]
    fn input_rejects_wrong_conv() {
        let mut b = Kcp::new(0x1111_1111, PacketWriter::default());
        let pkt = make_push(0x2222_2222, 0, 0, 0, b"x");
        match b.input(&pkt) {
            Err(Error::ConvInconsistent(0x1111_1111, 0x2222_2222)) => {}
            other => panic!("expected ConvInconsistent, got {:?}", other.map(|n| n)),
        }
    }

    // ── 2. basic roundtrip ───────────────────────────────────────────────

    #[test]
    fn roundtrip_no_loss() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        let mut b = Kcp::new(0x1122_3344, PacketWriter::default());

        send_and_flush(&mut a, b"hello");
        for pkt in a.output_mut().drain() {
            b.input(&pkt).unwrap();
        }
        assert_eq!(b.peeksize().unwrap(), 5);
        let mut buf = [0u8; 16];
        assert_eq!(b.recv(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");

        // Reverse direction.
        send_and_flush(&mut b, b"world");
        for pkt in b.output_mut().drain() {
            a.input(&pkt).unwrap();
        }
        assert_eq!(a.peeksize().unwrap(), 5);
        assert_eq!(a.recv(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"world");
    }

    #[test]
    fn recv_empty_returns_recv_queue_empty() {
        let mut a = Kcp::new(1, PacketWriter::default());
        let mut buf = [0u8; 16];
        assert!(matches!(a.recv(&mut buf), Err(Error::RecvQueueEmpty)));
        assert!(matches!(a.peeksize(), Err(Error::RecvQueueEmpty)));
    }

    // ── 3. fragmentation and reassembly ──────────────────────────────────

    #[test]
    fn fragmentation_message_mode() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true);

        // mss = 1400 - 24 = 1376, so 3000 bytes split into 3 fragments.
        let big = vec![0xabu8; 3000];
        a.send(&big).unwrap();
        a.update(0).unwrap();

        let out = a.output_mut().drain();
        assert_eq!(out.len(), 3, "3000 bytes over mss=1376 -> 3 packets");

        // frg counts down across the fragments: 2, 1, 0.
        let mut frgs = Vec::new();
        let mut total = 0usize;
        for pkt in &out {
            let (_, _, frg, _, _, _, _, data) = parse_packet(pkt);
            frgs.push(frg);
            total += data.len();
        }
        assert_eq!(frgs, vec![2, 1, 0]);
        assert_eq!(total, 3000);

        for pkt in &out {
            b.input(pkt).unwrap();
        }
        assert_eq!(b.peeksize().unwrap(), 3000, "fragment chain reassembled");
        let mut buf = vec![0u8; 3000];
        assert_eq!(b.recv(&mut buf).unwrap(), 3000);
        assert_eq!(buf, big);
    }

    #[test]
    fn stream_mode_merges_byte_stream() {
        let mut a = Kcp::new_stream(0x1122_3344, PacketWriter::default());
        let mut b = Kcp::new_stream(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true);

        // Two small sends merge into the trailing segment.
        a.send(b"ab").unwrap();
        a.send(b"cde").unwrap();
        a.update(0).unwrap();

        let out = a.output_mut().drain();
        assert_eq!(out.len(), 1, "merged into one packet");
        let (_, _, _, _, _, _, _, data) = parse_packet(&out[0]);
        assert_eq!(data, b"abcde");

        b.input(&out[0]).unwrap();
        assert_eq!(b.peeksize().unwrap(), 5);
        let mut buf = [0u8; 16];
        assert_eq!(b.recv(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"abcde");
    }

    #[test]
    fn stream_mode_large_send_splits_with_frg_zero() {
        let mut a = Kcp::new_stream(0x1122_3344, PacketWriter::default());
        let mut b = Kcp::new_stream(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true);

        // In stream mode every fragment carries frg=0; the receiver drains
        // them one recv at a time (byte-stream semantics).
        let big: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        a.send(&big).unwrap();
        a.update(0).unwrap();

        let out = a.output_mut().drain();
        let total: usize = out.iter().map(|p| parse_packet(p).7.len()).sum();
        assert_eq!(total, 3000);
        assert!(out.iter().all(|p| parse_packet(p).2 == 0), "stream frg=0");

        for pkt in &out {
            b.input(pkt).unwrap();
        }

        let mut received = Vec::new();
        let mut buf = vec![0u8; 2000];
        loop {
            match b.peeksize() {
                Err(Error::RecvQueueEmpty) => break,
                Ok(size) => {
                    assert!(size <= buf.len());
                    let n = b.recv(&mut buf[..size]).unwrap();
                    received.extend_from_slice(&buf[..n]);
                }
                Err(e) => panic!("peeksize error: {e:?}"),
            }
        }
        assert_eq!(received, big);
    }

    // ── 4. send window rejection ─────────────────────────────────────────

    #[test]
    fn send_rejects_message_larger_than_receive_window() {
        let mut a = Kcp::new(1, PacketWriter::default());
        // mss=1376; KCP_WND_RCV=128 => max message ~ 128 * 1376.
        let too_big = vec![0u8; 128 * 1376];
        assert!(matches!(a.send(&too_big), Err(Error::UserBufTooBig)));
    }

    // ── 5. kcp-go v5.6.13 compat patches ─────────────────────────────────

    /// Patch 1: with nodelay enabled, RTO backoff is LINEAR (rto += rx_rto/2),
    /// not the original exponential rto += rto/2. rx_rto stays 200 because no
    /// ACK ever arrives, so every retransmission adds exactly rx_rto/2 = 100.
    #[test]
    fn rto_linear_backoff_nodelay() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true); // nodelay + nc
        a.send(b"data").unwrap();

        // update(0) arms the window and flushes the segment (nocwnd).
        a.update(0).unwrap();
        assert_eq!(a.snd_buf.len(), 1);
        assert_eq!(a.snd_buf[0].xmit, 1);
        assert_eq!(a.snd_buf[0].rto, 200);
        assert_eq!(a.snd_buf[0].resendts, 200); // 0 + rto(200) + rtomin(0)

        // Drop the output packet (simulate loss), then hit the RTO deadline.
        let _dropped = a.output_mut().drain();
        a.update(200).unwrap(); // resendts reached -> RTO retransmit
        assert_eq!(a.snd_buf[0].xmit, 2);
        assert_eq!(a.snd_buf[0].rto, 300, "200 + rx_rto/2 = 300 (linear)");
        assert_eq!(a.snd_buf[0].resendts, 500); // 200 + 300

        let _dropped = a.output_mut().drain();
        a.update(500).unwrap(); // second RTO retransmit
        assert_eq!(a.snd_buf[0].xmit, 3);
        assert_eq!(a.snd_buf[0].rto, 400, "300 + rx_rto/2 = 400 (linear)");
        // Exponential backoff would have produced 200 -> 400 -> 800.
        assert!(a.snd_buf[0].rto < 800, "must not be exponential backoff");
    }

    /// Patch 3: early retransmit fires when fastack > 0 AND no new segments
    /// were moved from snd_queue in this flush (fastresend is 0, so the fast
    /// retransmit branch cannot claim the segment first).
    #[test]
    fn early_retransmit_trigger() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true); // fastresend=2, nc
        b.set_nodelay(true, 10, 2, true);

        // Two segments in flight; sn=1 is delivered, sn=0 is lost.
        a.send(&vec![0x11u8; 1000]).unwrap();
        a.send(&vec![0x22u8; 1000]).unwrap();
        a.update(0).unwrap(); // nocwnd -> both segments flushed now

        let out = a.output_mut().drain();
        assert_eq!(out.len(), 2);
        let sn0_pkt = parse_packet(&out[0]).5;
        let sn1_pkt = parse_packet(&out[1]).5;
        assert_eq!((sn0_pkt, sn1_pkt), (0, 1));

        // Receiver sees sn=1 only; ACKs it (sn=0 stays in snd_buf with
        // fastack incremented via parse_fastack).
        b.input(&out[1]).unwrap();
        b.update(0).unwrap();
        let ack_pkt = b.output_mut().drain();
        assert_eq!(ack_pkt.len(), 1);
        let (_, cmd, _, _, _, ack_sn, _, _) = parse_packet(&ack_pkt[0]);
        assert_eq!(cmd, KCP_CMD_ACK);
        assert_eq!(ack_sn, 1);

        a.input(&ack_pkt[0]).unwrap();
        assert_eq!(a.snd_buf[0].sn, 0);
        assert_eq!(
            a.snd_buf[0].fastack, 1,
            "out-of-order ACK counts as fastack"
        );
        assert_eq!(a.snd_buf.len(), 1, "sn=1 was acked and removed");

        // Next flush: queue is empty (new_segs_count == 0) so early
        // retransmit re-sends sn=0 immediately, well before its RTO.
        a.update(10).unwrap();
        let out = a.output_mut().drain();
        let pushed: Vec<(u8, u32)> = out
            .iter()
            .map(|p| {
                let (_, cmd, _, _, _, sn, _, _) = parse_packet(p);
                (cmd, sn)
            })
            .collect();
        assert!(
            pushed.contains(&(KCP_CMD_PUSH, 0)),
            "expected retransmitted PUSH sn=0, got {pushed:?}"
        );
    }

    /// Patch 2: fast retransmit fires before RTO. With fastresend=1 the
    /// segment is retransmitted on fastack>=1 even though its resend deadline
    /// is still far in the future.
    #[test]
    fn fast_retransmit_before_rto() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 1, true); // fastresend=1, nc
        b.set_nodelay(true, 10, 1, true);

        a.send(&vec![0x11u8; 1000]).unwrap();
        a.send(&vec![0x22u8; 1000]).unwrap();
        a.update(0).unwrap();

        let out = a.output_mut().drain();
        // Deliver sn=1 only.
        b.input(&out[1]).unwrap();
        b.update(0).unwrap();
        let ack_pkt = b.output_mut().drain();
        assert_eq!(ack_pkt.len(), 1);

        a.input(&ack_pkt[0]).unwrap();
        assert_eq!(a.snd_buf[0].fastack, 1);

        // resend deadline for sn=0 is 0 + 200 = 200; current is 10, so RTO
        // has NOT fired. The fastack>=1 branch retransmits it anyway.
        assert!(a.snd_buf[0].resendts > 10);
        a.update(10).unwrap();
        let out = a.output_mut().drain();
        let pushed: Vec<(u8, u32)> = out
            .iter()
            .map(|p| {
                let (_, cmd, _, _, _, sn, _, _) = parse_packet(p);
                (cmd, sn)
            })
            .collect();
        assert!(
            pushed.contains(&(KCP_CMD_PUSH, 0)),
            "expected fast retransmit of PUSH sn=0, got {pushed:?}"
        );
    }

    /// Window probing: when rmt_wnd reaches 0, WASK is sent with exponential
    /// backoff (7000ms -> +50% -> capped at 120s).
    #[test]
    fn window_probe_sends_wask() {
        let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
        a.set_nodelay(true, 10, 2, true);
        a.send(b"x").unwrap();
        a.update(0).unwrap(); // flush sn=0
        let _dropped = a.output_mut().drain();

        // Fake ACK with window 0: remote cannot receive more data.
        let ack = make_ack(0x1122_3344, 0, 0, 0);
        a.input(&ack).unwrap();
        assert_eq!(a.rmt_wnd(), 0);

        // First probe schedules ts_probe = current + 7000 but sends nothing.
        a.update(7000).unwrap();
        let out = a.output_mut().drain();
        assert!(
            !out.iter().any(|p| parse_packet(p).1 == KCP_CMD_WASK),
            "first probe must only arm the timer"
        );

        // Second probe (wait already 7000ms) emits WASK and backs off.
        a.update(14_000).unwrap();
        let out = a.output_mut().drain();
        assert!(
            out.iter().any(|p| parse_packet(p).1 == KCP_CMD_WASK),
            "expected a WASK packet after the probe deadline"
        );
        assert_eq!(a.probe_wait, 10_500, "probe_wait += probe_wait/2");
    }

    // ── 6. lossy link model (ported from upstream tests/kcp.rs) ───────────

    struct DelayPacket {
        buf: Vec<u8>,
        ts: u32,
    }

    /// Fisher-Yates pool of 0..size-1 used to decide packet drops.
    struct Random {
        seeds: Vec<u32>,
        size: usize,
    }

    impl Random {
        fn new(size: usize) -> Self {
            Random {
                seeds: vec![0u32; size],
                size: 0,
            }
        }

        fn random(&mut self) -> u32 {
            if self.seeds.is_empty() {
                return 0;
            }
            if self.size == 0 {
                for (i, e) in self.seeds.iter_mut().enumerate() {
                    *e = i as u32;
                }
                self.size = self.seeds.len();
            }
            let i = rand::thread_rng().gen_range(0..self.size);
            let x = self.seeds[i];
            self.size -= 1;
            self.seeds[i] = self.seeds[self.size];
            x
        }
    }

    /// Virtual network between two peers: per-direction loss, delay, and a
    /// bounded queue. Timestamps are simulated milliseconds (monotonic).
    struct LatencySimulator {
        lostrate: u32,
        rttmin: u32,
        rttmax: u32,
        nmax: usize,
        current: u32,
        p12: VecDeque<DelayPacket>,
        p21: VecDeque<DelayPacket>,
        r12: Random,
        r21: Random,
    }

    impl LatencySimulator {
        fn new(lostrate: u32, rttmin: u32, rttmax: u32, nmax: usize) -> Self {
            LatencySimulator {
                lostrate: lostrate / 2,
                rttmin: rttmin / 2,
                rttmax: rttmax / 2,
                nmax,
                current: 0,
                p12: VecDeque::new(),
                p21: VecDeque::new(),
                r12: Random::new(100),
                r21: Random::new(100),
            }
        }

        fn send(&mut self, peer: u32, data: &[u8]) -> usize {
            if peer == 0 {
                if self.r12.random() < self.lostrate {
                    return data.len();
                }
                if self.p12.len() >= self.nmax {
                    return data.len();
                }
            } else {
                if self.r21.random() < self.lostrate {
                    return data.len();
                }
                if self.p21.len() >= self.nmax {
                    return data.len();
                }
            }

            let mut delay = self.rttmin;
            if self.rttmax > self.rttmin {
                delay += rand::thread_rng().gen_range(0..(self.rttmax - self.rttmin));
            }

            let pkg = DelayPacket {
                buf: data.to_vec(),
                ts: self.current + delay,
            };

            if peer == 0 {
                self.p12.push_back(pkg);
            } else {
                self.p21.push_back(pkg);
            }
            data.len()
        }

        fn recv(&mut self, peer: u32, data: &mut [u8]) -> io::Result<usize> {
            let front = if peer == 0 {
                self.p12.front()
            } else {
                self.p21.front()
            };
            let pkg = match front {
                None => {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "No packet yet"));
                }
                Some(p) => p,
            };

            if self.current < pkg.ts {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "No packet yet"));
            }

            if data.len() < pkg.buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Buffer is too small",
                ));
            }

            let pkg = if peer == 0 {
                self.p12.pop_front().unwrap()
            } else {
                self.p21.pop_front().unwrap()
            };
            let n = pkg.buf.len();
            data[..n].copy_from_slice(&pkg.buf);
            Ok(n)
        }

        fn tick(&mut self, ms: u32) {
            self.current += ms;
        }
    }

    struct VnetOutput {
        sim: Rc<RefCell<LatencySimulator>>,
        peer: u32,
    }

    impl Write for VnetOutput {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            Ok(self.sim.borrow_mut().send(self.peer, data))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Default,
        Normal,
        Fast,
    }

    /// End-to-end reliability test over a lossy/delayed virtual network:
    /// kcp1 sends 8-byte messages every 20ms, kcp2 echoes them back, and
    /// kcp1 verifies it receives each sequence number exactly once in order.
    fn run_lossy(mode: Mode, msgcount: u32, lostrate: u32) {
        let sim = Rc::new(RefCell::new(LatencySimulator::new(lostrate, 60, 125, 1000)));

        let mut kcp1 = Kcp::new(
            0x1122_3344,
            VnetOutput {
                sim: sim.clone(),
                peer: 0,
            },
        );
        let mut kcp2 = Kcp::new(
            0x1122_3344,
            VnetOutput {
                sim: sim.clone(),
                peer: 1,
            },
        );

        kcp1.set_wndsize(128, 128);
        kcp2.set_wndsize(128, 128);

        match mode {
            Mode::Default => {
                kcp1.set_nodelay(false, 10, 0, false);
                kcp2.set_nodelay(false, 10, 0, false);
            }
            Mode::Normal => {
                kcp1.set_nodelay(false, 10, 0, true);
                kcp2.set_nodelay(false, 10, 0, true);
            }
            Mode::Fast => {
                kcp1.set_nodelay(true, 10, 2, true);
                kcp2.set_nodelay(true, 10, 2, true);
                kcp1.set_rx_minrto(10);
                kcp2.set_fast_resend(1);
            }
        }

        let interval = 10u32;
        let mut current = 0u32;
        let mut slap = current + 20;
        let mut index = 0u32;
        let mut next = 0u32;

        let mut buf = [0u8; 2000];
        let mut guard = 0u32;
        while next <= msgcount {
            guard += 1;
            assert!(guard < 2_000_000, "run_lossy did not converge");

            sim.borrow_mut().tick(interval);
            current += interval;
            kcp1.update(current).unwrap();
            kcp2.update(current).unwrap();

            // kcp1 sends one 8-byte message every 20ms.
            while current >= slap {
                let mut msg = Vec::with_capacity(8);
                msg.extend_from_slice(&index.to_le_bytes());
                msg.extend_from_slice(&current.to_le_bytes());
                kcp1.send(&msg).unwrap();
                index += 1;
                slap += 20;
            }

            // Deliver vnet p1 -> p2.
            loop {
                let n = match sim.borrow_mut().recv(1, &mut buf) {
                    Err(..) => break,
                    Ok(n) => n,
                };
                kcp2.input(&buf[..n]).unwrap();
            }

            // Deliver vnet p2 -> p1.
            loop {
                let n = match sim.borrow_mut().recv(0, &mut buf) {
                    Err(..) => break,
                    Ok(n) => n,
                };
                kcp1.input(&buf[..n]).unwrap();
            }

            // kcp2 echoes everything it received back to kcp1.
            loop {
                match kcp2.recv(&mut buf) {
                    Err(..) => break,
                    Ok(n) => {
                        kcp2.send(&buf[..n]).unwrap();
                    }
                }
            }

            // kcp1 verifies the echoed messages arrive exactly in order.
            loop {
                match kcp1.recv(&mut buf) {
                    Err(..) => break,
                    Ok(_) => {
                        let sn = u32::from_le_bytes(buf[..4].try_into().unwrap());
                        assert_eq!(sn, next, "received out-of-order or duplicated data");
                        next += 1;
                    }
                }
            }
        }
    }

    #[test]
    fn link_lossy_default() {
        run_lossy(Mode::Default, 1000, 10);
    }

    #[test]
    fn link_lossy_normal() {
        run_lossy(Mode::Normal, 1000, 10);
    }

    #[test]
    fn link_lossy_fast() {
        run_lossy(Mode::Fast, 1000, 10);
    }

    #[test]
    fn link_massive_loss_default() {
        run_lossy(Mode::Default, 500, 50);
    }

    #[test]
    fn link_massive_loss_normal() {
        run_lossy(Mode::Normal, 500, 50);
    }

    #[test]
    fn link_massive_loss_fast() {
        run_lossy(Mode::Fast, 500, 50);
    }
}
