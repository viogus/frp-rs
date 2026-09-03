//! WebSocket transport: the [`WsByteStream`] adapter converts between
//! WebSocket messages and a byte stream suitable for the V1/V2 protocol
//! functions, and implements [`Transport`].
//!
//! Single mode — manual RFC 6455 framing (client + server, binary frames;
//! the server tolerates text frames for backward compatibility with Go frp
//! < v0.70.1). The previous tungstenite-based variant was removed
//! 2026-08-09 (audit D1-1/D1-2/D1-3): it had no callers, and the manual
//! path reuses buffers across frames (no per-frame allocation).

use std::any::Any;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{AsyncReadWrite, IoStream, Transport};

/// Maximum WebSocket frame payload accepted by the raw decoder. The V2
/// framing layer permits 64 KiB messages, so the transport must not clamp
/// below that; the V1 10 KiB limit stays enforced by `protocol.rs`.
/// +128 bytes covers the V2 AEAD overhead (AES-256-GCM tag + nonce) so an
/// encrypted V2 frame at the payload cap is not rejected by the transport.
const MAX_WS_FRAME_PAYLOAD: u64 = crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128;

/// Cap on no-progress frames (zero-length data, ping, pong) drained within a
/// single `poll_read` call. Each such frame is consumed, woken, and re-polled
/// — a peer flooding empty frames at line rate would otherwise keep the poll
/// loop spinning through the buffered batch CPU-bound (each empty frame is
/// only 2-6 bytes on the wire, so a 64 KiB socket buffer holds tens of
/// thousands of them). Beyond the cap the loop returns `Poll::Pending`
/// (already woken by the frame dispatch), yielding to the executor; the next
/// poll continues draining. Bounded per-call work — a full buffer of empty
/// frames still drains, just across multiple polls instead of one.
const MAX_NO_PROGRESS_FRAMES_PER_POLL: u32 = 1024;

/// A WebSocket-to-byte-stream adapter that implements AsyncRead/AsyncWrite.
/// Converts between WebSocket messages and a byte stream suitable
/// for use with the V1 protocol functions.
pub struct WsByteStream {
    inner: Box<dyn AsyncReadWrite>,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Write buffer for the Raw variant (frame bytes not yet flushed).
    write_buf: Vec<u8>,
    write_pos: usize,
    needs_flush: bool,
    /// Payload length of the frame currently held in `write_buf` (i.e. the
    /// frame being drained after a partial write). A frame only enters
    /// `write_buf` via a partial write of the caller's current buf, and the
    /// AsyncWrite contract mandates that the caller re-polls with that same
    /// buf until `poll_write` returns `Ok` — so the caller's buf IS the
    /// payload of the frame being drained. The drain completion reports this
    /// length as the bytes consumed; the payload must never be re-sent as a
    /// fresh frame (that was the duplicate-frame bug).
    pending_frame_payload_len: usize,
    /// Set when a drain completes inside `poll_flush`, which cannot consume
    /// the caller's buf (it has no buf argument). The next `poll_write` sees
    /// this first and consumes the caller's re-polled buf by returning
    /// `pending_frame_payload_len` — completing the frame without re-sending
    /// its payload.
    drain_completed: bool,
    /// When true, outgoing frames are masked (RFC 6455 §5.3 — client requirement).
    client_mode: bool,
    /// State machine for incremental WebSocket frame reads (Raw variant).
    raw_read_state: RawReadState,
    /// Frame opcode from the last fully-read WS header.
    raw_frame_opcode: u8,
    /// Whether the last fully-read WS header had the MASK bit set.
    raw_frame_masked: bool,
    /// Masking key from the last fully-read WS header.
    raw_frame_mask_key: [u8; 4],
    /// Payload length from the last fully-read WS header (after extended length parsing).
    raw_frame_payload_len: u64,
    /// Reused payload buffer for the Raw read path (capacity kept across
    /// frames — avoids a fresh `vec![0u8; n]` allocation per frame).
    raw_payload_buf: Vec<u8>,
    /// Control frame bytes (close/pong reply, and the shutdown close frame)
    /// not yet fully written to the inner stream. A control frame is tiny
    /// (<= 10 bytes) but the inner may still return Pending mid-write; the
    /// tail is stashed here and drained before any further frame parse or
    /// the inner shutdown. Also carries the shutdown close frame across
    /// polls.
    pending_control_write: Vec<u8>,
    pending_control_pos: usize,
}

/// The post-upgrade stream. Manual WebSocket frame handling (RFC 6455),
/// type-erased to support both plain TCP and TLS-wrapped streams.
/// (The tungstenite-based variant was removed 2026-08-09: it had no callers —
/// every production path upgrades manually via `from_raw`.)
impl WsByteStream {
    /// Build a WebSocket data frame (FIN + BINARY opcode) for the Raw path,
    /// writing into `out`. The caller keeps `out` (e.g. `write_buf`) so its
    /// capacity is reused across bridge chunks — no per-chunk frame alloc.
    fn build_frame_into(out: &mut Vec<u8>, buf: &[u8], client_mode: bool) {
        let len = buf.len();
        out.clear();
        out.reserve(len + 14); // header + mask + payload
        let frame = out;
        frame.push(0x82); // FIN + BINARY opcode
        if client_mode {
            // Client MUST mask frames per RFC 6455 §5.3
            if len < 126 {
                frame.push(0x80 | len as u8);
            } else if len <= 65535 {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
            let mask: [u8; 4] = rand::random();
            frame.extend_from_slice(&mask);
            // Single-pass copy + XOR (RFC 6455 §5.3): each payload byte is
            // written exactly once, already masked — no separate
            // copy-then-XOR pass over the payload. Word-aligned like
            // `xor_mask` (same ~4x gain over a byte loop with a per-byte
            // modulo), but the payload never sits unmasked in the buffer.
            let mask_u32 = u32::from_ne_bytes(mask);
            let mut i = 0;
            while i + 4 <= len {
                let mut word = [0u8; 4];
                word.copy_from_slice(&buf[i..i + 4]);
                let word = u32::from_ne_bytes(word) ^ mask_u32;
                frame.extend_from_slice(&word.to_ne_bytes());
                i += 4;
            }
            while i < len {
                frame.push(buf[i] ^ mask[i & 3]);
                i += 1;
            }
        } else {
            // Server MUST NOT mask frames per RFC 6455 §5.1
            if len < 126 {
                frame.push(len as u8);
            } else if len <= 65535 {
                frame.push(126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                frame.push(127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
            frame.extend_from_slice(buf);
        }
    }

    /// Encode the server-mode (unmasked) frame header for a payload of `len`
    /// bytes into `hdr` (capacity ≥ 10) and return its length: 2 bytes for
    /// `len < 126`, 4 for `len <= 65535`, 10 otherwise (RFC 6455 §5.2).
    /// Mirrors the server branch of [`build_frame_into`] so the zero-copy
    /// fast path emits byte-identical frames without touching write_buf.
    fn build_server_frame_header(hdr: &mut [u8; 10], len: usize) -> usize {
        hdr[0] = 0x82; // FIN + BINARY opcode
        if len < 126 {
            hdr[1] = len as u8;
            2
        } else if len <= 65535 {
            hdr[1] = 126;
            hdr[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            4
        } else {
            hdr[1] = 127;
            hdr[2..10].copy_from_slice(&(len as u64).to_be_bytes());
            10
        }
    }
}

/// Downcast the erased inner stream to a raw `TcpStream`, if the innermost
/// transport is raw TCP — the same downcast the splice(2) fast path uses
/// (`IoStream::try_tcp_mut`, which returns `None` for TLS/QUIC/KCP-wrapped
/// streams and for the leftover-`BufferedRead` accept variant). Server
/// accept paths box an `IoStream`, so the erased `Box<dyn AsyncReadWrite>`
/// is peeled via `Any` first (the trait is `'static`); client-side
/// `PrependStream` boxes yield `None`, which is fine — the client path never
/// uses this.
fn inner_tcp_mut(inner: &mut Box<dyn AsyncReadWrite>) -> Option<&mut TcpStream> {
    // Trait upcast `dyn AsyncReadWrite` → `dyn Any` (supertrait; trait
    // upcasting is stable since Rust 1.86), then downcast to the concrete
    // `IoStream` the accept paths boxed.
    let any: &mut dyn Any = &mut **inner;
    any.downcast_mut::<IoStream>()
        .and_then(|io| io.try_tcp_mut())
}

/// XOR a payload with an RFC 6455 masking key.
///
/// The aligned prefix is processed as 32-bit words instead of a byte-by-byte
/// loop with a per-byte modulo, which is ~4x cheaper on the 32 KiB bridge
/// chunks used by the WebSocket transport.
#[inline]
fn xor_mask(payload: &mut [u8], mask: [u8; 4]) {
    let mask_u32 = u32::from_ne_bytes(mask);
    let mut i = 0;
    while i + 4 <= payload.len() {
        let mut word = [0u8; 4];
        word.copy_from_slice(&payload[i..i + 4]);
        let word = u32::from_ne_bytes(word) ^ mask_u32;
        payload[i..i + 4].copy_from_slice(&word.to_ne_bytes());
        i += 4;
    }
    while i < payload.len() {
        payload[i] ^= mask[i % 4];
        i += 1;
    }
}

/// Build an RFC 6455 control frame (FIN + control opcode, payload <= 125
/// bytes) into `out`. Masked when `client_mode` per RFC 6455 §5.3; a server
/// MUST NOT mask its frames.
fn build_control_frame(out: &mut Vec<u8>, opcode: u8, payload: &[u8], client_mode: bool) {
    out.clear();
    out.push(0x80 | opcode); // FIN + control opcode
    if client_mode {
        let mask: [u8; 4] = rand::random();
        out.push(0x80 | payload.len() as u8);
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask[i & 3]);
        }
    } else {
        out.push(payload.len() as u8);
        out.extend_from_slice(payload);
    }
}

/// Attempt to write a control frame (close/pong reply) to the raw inner.
/// Returns `Poll::Ready(Ok(true))` when the frame was fully written,
/// `Ready(Ok(false))` when the inner is busy — the unwritten tail is stashed
/// in `stash` (drained at the top of the next `poll_read`) and the caller's
/// waker is registered — and `Ready(Err)` on write failure. Never returns
/// `Poll::Pending` itself: control frames are tiny and stashing lets the
/// caller's loop continue without blocking the read path on a write.
fn poll_write_control(
    raw: &mut Box<dyn AsyncReadWrite>,
    cx: &mut Context<'_>,
    stash: &mut Vec<u8>,
    pos: &mut usize,
    frame: &[u8],
) -> Poll<io::Result<bool>> {
    match Pin::new(raw.as_mut()).poll_write(cx, frame) {
        Poll::Ready(Ok(n)) if n >= frame.len() => Poll::Ready(Ok(true)),
        Poll::Ready(Ok(0)) => {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
        }
        Poll::Ready(Ok(n)) => {
            stash.clear();
            stash.extend_from_slice(&frame[n..]);
            *pos = 0;
            cx.waker().wake_by_ref();
            Poll::Ready(Ok(false))
        }
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Pending => {
            stash.clear();
            stash.extend_from_slice(frame);
            *pos = 0;
            Poll::Ready(Ok(false))
        }
    }
}

/// State machine for incremental WebSocket frame reads on Raw streams.
/// Resumes partial reads across async yield points so frame header/mask/payload
/// parsing does not lose progress when the underlying stream returns Pending.
enum RawReadState {
    Idle,
    ReadingHeader { head: [u8; 2], filled: usize },
    ReadingExtendedLen2 { ext: [u8; 2], filled: usize },
    ReadingExtendedLen8 { ext: [u8; 8], filled: usize },
    ReadingMaskKey { mask_key: [u8; 4], filled: usize },
    ReadingPayload { payload: Vec<u8>, filled: usize },
}

/// Dispatch a fully-read WebSocket frame payload (Raw path).
/// Resets `raw_read_state` to Idle. Returns Poll::Pending for ping/pong
/// so the caller loops back to read the next frame.
#[allow(clippy::too_many_arguments)]
fn dispatch_raw_frame(
    read_buf: &mut Vec<u8>,
    read_pos: &mut usize,
    raw_read_state: &mut RawReadState,
    opcode: u8,
    raw: &mut Box<dyn AsyncReadWrite>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    payload: &[u8],
    client_mode: bool,
    pending_control_write: &mut Vec<u8>,
    pending_control_pos: &mut usize,
) -> Poll<io::Result<()>> {
    *raw_read_state = RawReadState::Idle;
    match opcode {
        0x00 => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WS continuation frame without a fragmented message",
        ))),
        0x01..=0x02 => {
            if payload.is_empty() {
                // Zero-length data frame: consume it without forwarding.
                // Returning `Ready(Ok(()))` with zero bytes filled reads as
                // EOF to tokio and tears the tunnel down — mirror the KCP
                // behavior (a zero-length read is swallowed and the next
                // frame is read instead). Wake + Pending so the caller
                // re-polls and the poll_read loop continues to the next
                // frame.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = payload.len().min(buf.remaining());
            if n == 0 {
                // The caller's ReadBuf has no remaining capacity: a
                // Ready(Ok(())) with zero bytes filled reads as EOF to
                // tokio (AsyncRead contract), tearing the tunnel down —
                // same hazard the zero-length-frame arm above guards.
                // Stash the whole payload for the next poll and return
                // wake + Pending so it is delivered then.
                *read_buf = payload.to_vec();
                *read_pos = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            buf.put_slice(&payload[..n]);
            if n < payload.len() {
                *read_buf = payload[n..].to_vec();
                *read_pos = 0;
            }
            Poll::Ready(Ok(()))
        }
        0x08 => {
            // RFC 6455 §5.5.1: reply with a close frame before surfacing
            // EOF. Masked in client mode (§5.3); if the inner is busy the
            // reply is stashed and the next poll finishes it — a single
            // ignored poll_write could drop the reply entirely.
            let mut frame = Vec::with_capacity(10);
            build_control_frame(&mut frame, 0x08, &[0x03, 0xe8], client_mode);
            match poll_write_control(raw, cx, pending_control_write, pending_control_pos, &frame) {
                Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
                Poll::Ready(Ok(false)) => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    unreachable!("poll_write_control never returns Pending")
                }
            }
        }
        0x09 => {
            // RFC 6455 §5.5: control frame payload MUST be ≤125 bytes. The
            // header arm already rejects raw length fields 126/127 before
            // the extended length is parsed, so this guard is unreachable
            // in practice — kept as defense in depth mirroring gorilla's
            // advanceFrame decoded-length rule: a peer ping payload >125
            // bytes is a protocol error that closes the connection, never
            // a truncatable pong.
            if payload.len() > 125 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WS control frame length > 125",
                )));
            }
            // Masked in client mode (§5.3); a busy inner stashes the reply
            // and the next poll drains it before reading further frames.
            let mut frame = Vec::with_capacity(2 + 4 + payload.len());
            build_control_frame(&mut frame, 0x0a, payload, client_mode);
            match poll_write_control(raw, cx, pending_control_write, pending_control_pos, &frame) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => {
                    tracing::debug!(error = %e, "WS pong write failed");
                }
                Poll::Pending => unreachable!("poll_write_control never returns Pending"),
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        0x0a => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        _ => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected WS opcode: {opcode:#x}"),
        ))),
    }
}

impl WsByteStream {
    /// Create from a raw stream after manual WebSocket upgrade.
    /// Used on the server accept path for Go frp compat.
    /// When `client_mode` is true, outgoing frames are masked per RFC 6455 §5.3.
    pub fn from_raw(stream: Box<dyn AsyncReadWrite>, client_mode: bool) -> Self {
        Self {
            inner: stream,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
            pending_frame_payload_len: 0,
            drain_completed: false,
            client_mode,
            raw_read_state: RawReadState::Idle,
            raw_frame_opcode: 0,
            raw_frame_masked: false,
            raw_frame_mask_key: [0u8; 4],
            raw_frame_payload_len: 0,
            raw_payload_buf: Vec::new(),
            pending_control_write: Vec::new(),
            pending_control_pos: 0,
        }
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, return it
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let len = available.len().min(buf.remaining());
            buf.put_slice(&available[..len]);
            self.read_pos += len;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Destructure to get independent field borrows, avoiding borrow conflicts
        // between inner (Raw) and the raw_read_state / raw_frame_* fields.
        // &mut *self is safe because WsByteStream is Unpin (all fields are Unpin),
        // so Pin<&mut Self> implements DerefMut.
        let this = &mut *self;
        let WsByteStream {
            inner,
            read_buf,
            read_pos,
            write_buf: _,
            write_pos: _,
            needs_flush: _,
            pending_frame_payload_len: _,
            drain_completed: _,
            client_mode,
            raw_read_state,
            raw_frame_opcode,
            raw_frame_masked,
            raw_frame_mask_key,
            raw_frame_payload_len,
            raw_payload_buf,
            pending_control_write,
            pending_control_pos,
        } = this;

        let raw = inner;

        // Flush any stashed control frame (close/pong reply, or the shutdown
        // close frame) before parsing the next frame — the write parks on
        // Pending with the waker registered, never silently dropped.
        if !pending_control_write.is_empty() {
            let remaining = &pending_control_write[*pending_control_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *pending_control_pos += n;
                    if *pending_control_pos >= pending_control_write.len() {
                        pending_control_write.clear();
                        *pending_control_pos = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // No-progress frames (zero-length data / ping / pong) consumed in
        // this poll call — capped so a peer flooding empty frames cannot pin
        // the poll loop CPU-bound within a single call (see the constant).
        // Every no-progress dispatch resets `raw_read_state` to Idle and the
        // caller `continue`s, so the Idle arm below is the single funnel
        // point for counting them (productive frames return Ready directly
        // and never pass through Idle again). The initial Idle entry before
        // the first frame counts one spurious frame — irrelevant at the
        // 1024 cap.
        let mut no_progress_frames = 0u32;
        loop {
            match raw_read_state {
                RawReadState::Idle => {
                    no_progress_frames += 1;
                    if no_progress_frames > MAX_NO_PROGRESS_FRAMES_PER_POLL {
                        // Yield: dispatch_raw_frame already registered the
                        // waker, so the executor re-polls us and the drain
                        // continues from the next buffered frame.
                        return Poll::Pending;
                    }
                    *raw_read_state = RawReadState::ReadingHeader {
                        head: [0u8; 2],
                        filled: 0,
                    };
                    continue;
                }
                RawReadState::ReadingHeader {
                    ref mut head,
                    ref mut filled,
                } => {
                    let mut frame_read_buf = ReadBuf::new(&mut head[*filled..]);
                    match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = frame_read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled < 2 {
                                // Inner made progress but the header is
                                // incomplete — same wake contract as the
                                // payload arm: returning Pending here with no
                                // registered waker parks the caller forever.
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            let opcode = head[0] & 0x0f;
                            let masked = (head[1] & 0x80) != 0;
                            let raw_len = (head[1] & 0x7f) as u64;
                            *raw_frame_opcode = opcode;
                            *raw_frame_masked = masked;
                            // RFC 6455 §5.2: RSV1-3 MUST be 0 unless an
                            // extension that defines them is negotiated —
                            // none is here, so any set bit is protocol
                            // corruption (or a masking bypass attempt).
                            if head[0] & 0x70 != 0 {
                                *raw_read_state = RawReadState::Idle;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "WS frame has RSV bits set",
                                )));
                            }
                            // RFC 6455 §5.1/§5.3 mask direction: client→server
                            // frames MUST be masked, server→client MUST NOT.
                            // We are the server when !client_mode, the client
                            // when client_mode.
                            if masked == *client_mode {
                                *raw_read_state = RawReadState::Idle;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    if *client_mode {
                                        "WS frame from server must not be masked"
                                    } else {
                                        "WS frame from client must be masked"
                                    },
                                )));
                            }
                            // RFC 6455 §5.5: control frames (close/ping/pong)
                            // MUST have FIN set and a payload of at most 125
                            // bytes, and MUST NOT use the extended length
                            // encodings. gorilla/websocket v1.5.x enforces
                            // this at the same point we do: advanceFrame
                            // compares the RAW 7-bit length field
                            // (readRemaining) against
                            // maxControlFramePayloadSize=125 for control
                            // frames (conn.go:841) BEFORE any extended
                            // length is decoded, so gorilla likewise rejects
                            // a 126/127-encoded control frame outright — not
                            // a truncatable pong — and "FIN not set on
                            // control" likewise closes the connection.
                            if matches!(opcode, 0x08..=0x0a) {
                                if head[0] & 0x80 == 0 {
                                    *raw_read_state = RawReadState::Idle;
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "WS control frame has FIN not set",
                                    )));
                                }
                                if raw_len > 125 {
                                    *raw_read_state = RawReadState::Idle;
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "WS control frame length > 125",
                                    )));
                                }
                            }
                            if raw_len == 126 {
                                *raw_read_state = RawReadState::ReadingExtendedLen2 {
                                    ext: [0u8; 2],
                                    filled: 0,
                                };
                            } else if raw_len == 127 {
                                *raw_read_state = RawReadState::ReadingExtendedLen8 {
                                    ext: [0u8; 8],
                                    filled: 0,
                                };
                            } else {
                                if raw_len > MAX_WS_FRAME_PAYLOAD {
                                    *raw_read_state = RawReadState::Idle;
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "WS frame too large",
                                    )));
                                }
                                *raw_frame_payload_len = raw_len;
                                if masked {
                                    *raw_read_state = RawReadState::ReadingMaskKey {
                                        mask_key: [0u8; 4],
                                        filled: 0,
                                    };
                                } else if raw_len > 0 {
                                    let mut payload = std::mem::take(&mut *raw_payload_buf);
                                    payload.resize(raw_len as usize, 0);
                                    *raw_read_state =
                                        RawReadState::ReadingPayload { payload, filled: 0 };
                                } else {
                                    let disp = dispatch_raw_frame(
                                        read_buf,
                                        read_pos,
                                        raw_read_state,
                                        *raw_frame_opcode,
                                        raw,
                                        cx,
                                        buf,
                                        &[],
                                        *client_mode,
                                        pending_control_write,
                                        pending_control_pos,
                                    );
                                    if disp.is_pending() {
                                        continue;
                                    } else {
                                        return disp;
                                    }
                                }
                            }
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RawReadState::ReadingExtendedLen2 {
                    ref mut ext,
                    ref mut filled,
                } => {
                    let mut frame_read_buf = ReadBuf::new(&mut ext[*filled..]);
                    match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = frame_read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled < 2 {
                                // See the header arm: wake after progress.
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            let payload_len = u16::from_be_bytes(*ext) as u64;
                            if payload_len > MAX_WS_FRAME_PAYLOAD {
                                *raw_read_state = RawReadState::Idle;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "WS frame too large",
                                )));
                            }
                            *raw_frame_payload_len = payload_len;
                            if *raw_frame_masked {
                                *raw_read_state = RawReadState::ReadingMaskKey {
                                    mask_key: [0u8; 4],
                                    filled: 0,
                                };
                            } else if payload_len > 0 {
                                let mut payload = std::mem::take(&mut *raw_payload_buf);
                                payload.resize(payload_len as usize, 0);
                                *raw_read_state =
                                    RawReadState::ReadingPayload { payload, filled: 0 };
                            } else {
                                let disp = dispatch_raw_frame(
                                    read_buf,
                                    read_pos,
                                    raw_read_state,
                                    *raw_frame_opcode,
                                    raw,
                                    cx,
                                    buf,
                                    &[],
                                    *client_mode,
                                    pending_control_write,
                                    pending_control_pos,
                                );
                                if disp.is_pending() {
                                    continue;
                                } else {
                                    return disp;
                                }
                            }
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RawReadState::ReadingExtendedLen8 {
                    ref mut ext,
                    ref mut filled,
                } => {
                    let mut frame_read_buf = ReadBuf::new(&mut ext[*filled..]);
                    match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = frame_read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled < 8 {
                                // See the header arm: wake after progress.
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            let payload_len = u64::from_be_bytes(*ext);
                            if payload_len > MAX_WS_FRAME_PAYLOAD {
                                *raw_read_state = RawReadState::Idle;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "WS frame too large",
                                )));
                            }
                            *raw_frame_payload_len = payload_len;
                            if *raw_frame_masked {
                                *raw_read_state = RawReadState::ReadingMaskKey {
                                    mask_key: [0u8; 4],
                                    filled: 0,
                                };
                            } else if payload_len > 0 {
                                let mut payload = std::mem::take(&mut *raw_payload_buf);
                                payload.resize(payload_len as usize, 0);
                                *raw_read_state =
                                    RawReadState::ReadingPayload { payload, filled: 0 };
                            } else {
                                let disp = dispatch_raw_frame(
                                    read_buf,
                                    read_pos,
                                    raw_read_state,
                                    *raw_frame_opcode,
                                    raw,
                                    cx,
                                    buf,
                                    &[],
                                    *client_mode,
                                    pending_control_write,
                                    pending_control_pos,
                                );
                                if disp.is_pending() {
                                    continue;
                                } else {
                                    return disp;
                                }
                            }
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RawReadState::ReadingMaskKey {
                    ref mut mask_key,
                    ref mut filled,
                } => {
                    let mut frame_read_buf = ReadBuf::new(&mut mask_key[*filled..]);
                    match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = frame_read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled < 4 {
                                // See the header arm: wake after progress.
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            *raw_frame_mask_key = *mask_key;
                            let pl = *raw_frame_payload_len;
                            if pl > 0 {
                                let mut payload = std::mem::take(&mut *raw_payload_buf);
                                payload.resize(pl as usize, 0);
                                *raw_read_state =
                                    RawReadState::ReadingPayload { payload, filled: 0 };
                            } else {
                                let disp = dispatch_raw_frame(
                                    read_buf,
                                    read_pos,
                                    raw_read_state,
                                    *raw_frame_opcode,
                                    raw,
                                    cx,
                                    buf,
                                    &[],
                                    *client_mode,
                                    pending_control_write,
                                    pending_control_pos,
                                );
                                if disp.is_pending() {
                                    continue;
                                } else {
                                    return disp;
                                }
                            }
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RawReadState::ReadingPayload {
                    ref mut payload,
                    ref mut filled,
                } => {
                    let mut frame_read_buf = ReadBuf::new(&mut payload[*filled..]);
                    match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = frame_read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled < payload.len() {
                                // Inner made progress (n > 0) but the frame
                                // is incomplete. The inner layer returned
                                // Ready without registering a waker (TLS may
                                // have served this from buffered plaintext),
                                // so returning Pending here would park the
                                // caller with nothing to wake it. Self-wake
                                // once: the re-poll consumes progress; if the
                                // inner is truly idle it returns Pending and
                                // registers its own waker. Bounded — one wake
                                // per progress, no spin.
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            if *raw_frame_masked {
                                xor_mask(payload, *raw_frame_mask_key);
                            }
                            // Take ownership of payload and reset state before
                            // dispatch to avoid double-borrow on raw_read_state.
                            let owned_payload = std::mem::take(payload);
                            *raw_read_state = RawReadState::Idle;
                            let disp = dispatch_raw_frame(
                                read_buf,
                                read_pos,
                                raw_read_state,
                                *raw_frame_opcode,
                                raw,
                                cx,
                                buf,
                                &owned_payload,
                                *client_mode,
                                pending_control_write,
                                pending_control_pos,
                            );
                            // Return the payload Vec (with its capacity) to
                            // raw_payload_buf for reuse by the next frame —
                            // dispatch_raw_frame is synchronous, so the
                            // borrow has ended.
                            *raw_payload_buf = owned_payload;
                            if disp.is_pending() {
                                continue;
                            } else {
                                return disp;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for WsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Destructure self to get separate borrows on each field.
        // This is safe because WsByteStream is Unpin.
        let this = &mut *self;
        let WsByteStream {
            inner,
            write_buf,
            write_pos,
            needs_flush,
            pending_frame_payload_len,
            drain_completed,
            client_mode,
            ..
        } = this;

        let raw = inner;
        {
            // A drain completed inside a previous poll_flush, which cannot
            // consume the caller's buf. The buf the caller re-polls with IS
            // the payload of the frame that just drained — consume it by
            // reporting the recorded payload length. Never re-send it as a
            // fresh frame: the peer already received that payload (re-sending
            // was the duplicate-frame bug).
            if *drain_completed {
                *drain_completed = false;
                // The re-polled buf is normally the drained frame's payload
                // (every in-tree caller honors the same-buf-until-Ok
                // AsyncWrite contract); clamp to the actual buf length so a
                // contract-violating caller can never be over-credited —
                // over-crediting would make it skip bytes never written.
                let claimed = (*pending_frame_payload_len).min(buf.len());
                return Poll::Ready(Ok(claimed));
            }
            if !*needs_flush && !buf.is_empty() {
                // Server-mode zero-copy fast path: no masking, so the payload
                // never needs in-place mutation — emit [frame header, payload]
                // as two iovecs straight to the raw TcpStream (real writev),
                // skipping the per-chunk memcpy of the payload into write_buf
                // (32 KiB per bridge chunk). The downcast is the same one the
                // splice(2) fast path uses; TLS/QUIC/KCP-wrapped WS (and the
                // leftover-BufferedRead accept variant) fall through to the
                // combined-buffer path below. The writev goes DIRECTLY on the
                // downcast TcpStream, never on the IoStream wrapper — its
                // default poll_write_vectored writes only the first non-empty
                // iovec.
                if !*client_mode {
                    if let Some(tcp) = inner_tcp_mut(raw) {
                        let mut hdr = [0u8; 10];
                        let hdr_len = WsByteStream::build_server_frame_header(&mut hdr, buf.len());
                        let iovecs = [IoSlice::new(&hdr[..hdr_len]), IoSlice::new(buf)];
                        return match Pin::new(tcp).poll_write_vectored(cx, &iovecs) {
                            Poll::Ready(Ok(n)) if n >= hdr_len + buf.len() => {
                                // Full frame accepted. Return the *input* bytes
                                // consumed (buf.len()), per the AsyncWrite
                                // contract — the WS frame overhead is not part
                                // of the stream.
                                Poll::Ready(Ok(buf.len()))
                            }
                            Poll::Ready(Ok(n)) => {
                                // Partial write (rare): the frame is split
                                // across the wire; retain the unwritten tail in
                                // write_buf and hand off to the existing
                                // needs_flush machinery — the next poll drains
                                // write_buf via the unchanged path below (one
                                // memcpy of the remainder only, not the whole
                                // chunk). Record the frame's payload length so
                                // the drain completion can consume the caller's
                                // re-polled buf (which IS this payload) instead
                                // of re-sending it as a new frame.
                                write_buf.clear();
                                if n < hdr_len {
                                    write_buf.extend_from_slice(&hdr[n..hdr_len]);
                                    write_buf.extend_from_slice(buf);
                                } else {
                                    write_buf.extend_from_slice(&buf[n - hdr_len..]);
                                }
                                *pending_frame_payload_len = buf.len();
                                *write_pos = 0;
                                *needs_flush = true;
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                            Poll::Pending => Poll::Pending,
                        };
                    }
                }
                // Build the frame directly into write_buf (capacity reused
                // across chunks — no per-chunk frame allocation), then try
                // to flush it immediately. Record the frame's payload length
                // (the caller's buf) so a partial write's drain completion
                // can consume the re-polled buf instead of re-sending it.
                WsByteStream::build_frame_into(write_buf, buf, *client_mode);
                *pending_frame_payload_len = buf.len();
                match Pin::new(raw.as_mut()).poll_write(cx, write_buf) {
                    Poll::Ready(Ok(n)) if n >= write_buf.len() => {
                        write_buf.clear(); // keep capacity for next chunk
                                           // Return the *input* bytes consumed (buf.len()), per
                                           // the AsyncWrite contract — the WS frame overhead
                                           // (2-14 header bytes) is not part of the stream.
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Ok(n)) => {
                        *write_pos = n;
                        *needs_flush = true;
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        *write_pos = 0;
                        *needs_flush = true;
                        Poll::Pending
                    }
                }
            } else if *needs_flush {
                // Continue writing a partially-flushed frame. A frame enters
                // write_buf only via a partial write of the caller's current
                // buf, and AsyncWrite mandates that the caller re-polls with
                // that same buf until poll_write returns Ok — so the buf IS
                // the payload of the frame being drained. When the drain
                // completes, report the recorded payload length as the bytes
                // consumed (this consumes the caller's buf). Re-building a
                // fresh frame from the same buf would deliver the payload to
                // the peer TWICE — the duplicate-frame bug this fix removes.
                let remaining = &write_buf[*write_pos..];
                match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                    Poll::Ready(Ok(0)) => {
                        // `remaining` is non-empty here (needs_flush is only
                        // set while frame bytes remain), so zero progress is a
                        // fatal write-zero — self-waking and re-polling would
                        // spin at 100% CPU until the inner makes progress.
                        // Mirrors CipherWriter's WriteZero handling.
                        *needs_flush = false;
                        *drain_completed = false;
                        Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                    }
                    Poll::Ready(Ok(n)) => {
                        *write_pos += n;
                        if *write_pos >= write_buf.len() {
                            // The frame is fully on the wire — consume the
                            // caller's re-polled buf directly (it is this
                            // frame's payload). Clamp the claim to the
                            // current buffer (the drain_completed arm at
                            // line ~925 does the same): a contract-violating
                            // or interleaved writer re-polling with a
                            // smaller buf must not be over-credited —
                            // slicing &buf[n..] past the end would panic
                            // under panic=abort.
                            *write_pos = 0;
                            *needs_flush = false;
                            Poll::Ready(Ok((*pending_frame_payload_len).min(buf.len())))
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        *needs_flush = false;
                        *drain_completed = false;
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => Poll::Pending,
                }
            } else {
                Poll::Ready(Ok(0))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Destructure to get separate borrows — same pattern as poll_write.
        let this = &mut *self;
        let WsByteStream {
            inner,
            write_buf,
            write_pos,
            needs_flush,
            drain_completed,
            ..
        } = this;
        let needs_flush_local = *needs_flush;
        let raw = inner;
        if needs_flush_local {
            let remaining = &write_buf[*write_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    // Same pathological-inner guard as poll_write: zero
                    // progress on a non-empty remainder is a write-zero error,
                    // not a self-wake spin.
                    *needs_flush = false;
                    *drain_completed = false;
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Poll::Ready(Ok(n)) => {
                    *write_pos += n;
                    if *write_pos >= write_buf.len() {
                        *write_pos = 0;
                        *needs_flush = false;
                        // poll_flush has no buf to consume, so record that
                        // the frame completed; the next poll_write consumes
                        // the caller's re-polled buf (returning the recorded
                        // payload length) instead of re-sending it.
                        *drain_completed = true;
                        Poll::Ready(Ok(()))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
                Poll::Ready(Err(e)) => {
                    *needs_flush = false;
                    *drain_completed = false;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let WsByteStream {
            inner,
            write_buf,
            write_pos,
            needs_flush,
            pending_control_write,
            pending_control_pos,
            client_mode,
            ..
        } = this;

        let raw = inner;

        // Shutdown must not drop a partially-flushed frame: drain write_buf
        // first (its payload was already accepted from the caller's buf).
        if *needs_flush {
            let remaining = &write_buf[*write_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *write_pos += n;
                    if *write_pos >= write_buf.len() {
                        *write_pos = 0;
                        *needs_flush = false;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Send the RFC 6455 close frame (masked in client mode, §5.3),
        // retrying on Pending instead of a single ignored poll_write. The
        // frame rides the same stash as the read-path close/pong replies.
        if pending_control_write.is_empty() {
            build_control_frame(pending_control_write, 0x08, &[0x03, 0xe8], *client_mode);
            *pending_control_pos = 0;
        }
        if !pending_control_write.is_empty() {
            let remaining = &pending_control_write[*pending_control_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *pending_control_pos += n;
                    if *pending_control_pos >= pending_control_write.len() {
                        pending_control_write.clear();
                        *pending_control_pos = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(raw.as_mut()).poll_shutdown(cx)
    }
}
impl Transport for WsByteStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::WebSocket"
    }
}

/// Stream wrapper that serves a byte prefix before delegating to the
/// underlying stream. Used by the WebSocket client upgrade path to feed
/// leftover bytes (a WS frame that arrived in the same TCP segment as the
/// HTTP 101 response) through the raw WS frame parser instead of exposing
/// them as application bytes.
pub(crate) struct PrependStream {
    pub(crate) prepend: Vec<u8>,
    pub(crate) pos: usize,
    pub(crate) inner: Box<dyn AsyncReadWrite>,
}

impl AsyncRead for PrependStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prepend.len() {
            let n = (self.prepend.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.prepend[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.prepend.len() {
                self.prepend.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrependStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_frame_cap_covers_v2_aead_overhead() {
        // The transport frame cap must accept a full-size V2 frame plus the
        // AEAD overhead (tag + nonce), not just the plaintext cap.
        assert!(MAX_WS_FRAME_PAYLOAD >= crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128);
    }

    /// Real TCP socket pair (bind 127.0.0.1:0, connect, accept) — the
    /// server-mode zero-copy fast path requires a raw TcpStream as the
    /// innermost transport, so duplex streams won't exercise it.
    async fn tcp_socket_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// All three server-mode header encodings (2/4/10 bytes) must be
    /// byte-exact RFC 6455 unmasked frames.
    #[test]
    fn ws_server_frame_header_encoding() {
        let mut hdr = [0u8; 10];
        assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 0), 2);
        assert_eq!(&hdr[..2], &[0x82, 0]);
        assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 125), 2);
        assert_eq!(&hdr[..2], &[0x82, 125]);
        assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 126), 4);
        assert_eq!(&hdr[..4], &[0x82, 126, 0x00, 126]);
        assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 65535), 4);
        assert_eq!(&hdr[..4], &[0x82, 126, 0xff, 0xff]);
        assert_eq!(WsByteStream::build_server_frame_header(&mut hdr, 65536), 10);
        assert_eq!(&hdr[..10], &[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
    }

    /// MANDATORY frame-correctness check for the server-mode zero-copy
    /// poll_write_vectored fast path: a WsByteStream over a real TcpStream
    /// pair must emit the exact RFC 6455 unmasked server frame and report the
    /// payload length as written. Covers the 2-byte header path (payload
    /// < 126) and the 4-byte header path (126 <= payload <= 65535). The peer
    /// reads concurrently so the frame reaches it even if the write splits.
    #[tokio::test]
    async fn ws_server_mode_fast_path_emits_exact_frames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 2-byte header path: payload < 126.
        let (mut client, server) = tcp_socket_pair().await;
        let mut ws = WsByteStream::from_raw(Box::new(IoStream::Tcp(server)), false);
        let small = vec![0x11u8; 100];
        let mut expected = vec![0x82, small.len() as u8];
        expected.extend_from_slice(&small);
        let expect_len = expected.len();
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; expect_len];
            client.read_exact(&mut got).await.unwrap();
            got
        });
        let n = ws.write(&small).await.unwrap();
        assert_eq!(
            n,
            small.len(),
            "write must report the payload bytes, not the frame bytes"
        );
        let got = reader.await.unwrap();
        assert_eq!(&got, &expected, "peer must see the unmasked server frame");

        // 4-byte header path: 126 <= payload <= 65535.
        let (mut client, server) = tcp_socket_pair().await;
        let mut ws = WsByteStream::from_raw(Box::new(IoStream::Tcp(server)), false);
        let big = vec![0x22u8; 1000];
        let mut expected = vec![0x82, 126];
        expected.extend_from_slice(&(big.len() as u16).to_be_bytes());
        expected.extend_from_slice(&big);
        let expect_len = expected.len();
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; expect_len];
            client.read_exact(&mut got).await.unwrap();
            got
        });
        let n = ws.write(&big).await.unwrap();
        assert_eq!(n, big.len());
        let got = reader.await.unwrap();
        assert_eq!(&got, &expected, "peer must see the unmasked server frame");
    }

    /// Go frps may send the first WS frame in the same TCP segment as the
    /// HTTP 101 response. The client must parse the frame instead of
    /// exposing frame bytes as application bytes.
    #[tokio::test]
    async fn ws_client_parses_pipelined_frame_after_upgrade() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(8192);
        let payload: &[u8] = b"hello-from-go-frps";
        let mut frame = vec![0x82u8, payload.len() as u8]; // FIN + BINARY
        frame.extend_from_slice(payload);

        let server_task = tokio::spawn(async move {
            // Consume the upgrade request up to the blank line.
            let mut req = vec![0u8; 4096];
            let mut total = 0usize;
            let mut client_key: Option<String> = None;
            loop {
                let n = server.read(&mut req[total..]).await.expect("read request");
                assert!(n > 0, "client closed before request completed");
                total += n;
                if req[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Extract the client's Sec-WebSocket-Key so the Accept header
            // can be computed (connect_ws_raw verifies it).
            let req_text = String::from_utf8_lossy(&req[..total]);
            for line in req_text.lines() {
                if let Some((name, value)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("sec-websocket-key") {
                        client_key = Some(value.trim().to_string());
                    }
                }
            }
            let client_key = client_key.expect("client Sec-WebSocket-Key header");
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(client_key.as_bytes());
            hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            let accept = super::super::base64_encode(&hasher.finalize());
            // 101 response + first WS frame in a single segment.
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 \r\n"
            );
            server.write_all(resp.as_bytes()).await.expect("write 101");
            server
                .write_all(&frame)
                .await
                .expect("write pipelined frame");
        });

        let mut io = super::super::connect_ws_raw(
            client,
            "example.com",
            7000,
            super::super::FRP_WEBSOCKET_PATH,
            "http",
        )
        .await
        .expect("ws upgrade");

        let mut buf = [0u8; 64];
        let n = io.read(&mut buf).await.expect("read ws payload");
        assert_eq!(
            &buf[..n],
            payload,
            "read must return the frame payload only, got: {:?}",
            &buf[..n]
        );
        server_task.await.expect("server task");
    }

    fn ws_binary_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x82];
        if payload.len() <= 125 {
            frame.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    /// Like [`ws_binary_frame`] but masked — what a compliant client sends
    /// to the server (RFC 6455 §5.3). Server-mode `WsByteStream`s enforce
    /// the mask direction, so tests feeding frames INTO a server-mode
    /// stream must mask them.
    fn ws_masked_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x82];
        let mask: [u8; 4] = rand::random();
        if payload.len() <= 125 {
            frame.push(0x80 | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
        frame
    }

    /// Zero-length BINARY frame with the mask bit set (client-mode wire
    /// shape), for server-mode streams.
    fn ws_masked_zero_frame() -> Vec<u8> {
        let mask: [u8; 4] = rand::random();
        let mut frame = vec![0x82, 0x80];
        frame.extend_from_slice(&mask);
        frame
    }

    /// Zero-length data frames must be consumed without surfacing a 0-byte
    /// read (which tokio treats as EOF and would tear the tunnel down).
    /// A zero-length frame followed by a real frame must deliver the real
    /// frame's payload.
    #[tokio::test]
    async fn ws_zero_length_frame_is_swallowed_not_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut server_io, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

        // Zero-length BINARY frame, then a real frame. Masked: the stream
        // is server-mode and enforces RFC 6455 mask direction (L16).
        server_io.write_all(&ws_masked_zero_frame()).await.unwrap();
        let payload = b"after-zero-frame";
        server_io
            .write_all(&ws_masked_frame(payload))
            .await
            .unwrap();

        let mut out = vec![0u8; payload.len() + 1];
        let n = ws.read(&mut out).await.unwrap();
        assert_eq!(
            n,
            payload.len(),
            "zero-length frame must not surface as EOF; got {n} bytes"
        );
        assert_eq!(&out[..n], payload);

        // A second zero-length frame (through the extended-length path too:
        // masked 0x82 with extended length 0) must behave the same. Wire
        // order for a masked frame is header, extended length, THEN mask key
        // (RFC 6455 §5.2): [0x82, 0xFE, 0x00, 0x00, mask..4].
        let mut ext_zero = vec![0x82, 0x80 | 126, 0, 0];
        ext_zero.extend_from_slice(&ws_masked_zero_frame()[2..6]);
        server_io.write_all(&ext_zero).await.unwrap();
        let payload2 = b"second-payload";
        server_io
            .write_all(&ws_masked_frame(payload2))
            .await
            .unwrap();
        let n2 = ws.read(&mut out).await.unwrap();
        assert_eq!(n2, payload2.len());
        assert_eq!(&out[..n2], payload2);
    }

    /// Round-15 finding: the `n == 0` stash arm of dispatch_raw_frame (caller
    /// ReadBuf exactly full) had no coverage — a regression there (lost wake,
    /// dropped stash) would silently stall the tunnel: poll_read returns
    /// Pending after stashing the payload, and the next poll must deliver it
    /// from read_buf. Drive poll_read directly with a zero-capacity ReadBuf
    /// to hit the arm, then drain a ≥16 KiB payload through 32-byte buffers,
    /// bounded by a timeout so a hang fails the test instead of parking it.
    #[tokio::test]
    async fn ws_readbuf_full_stash_delivers_payload_across_polls() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        let (mut server_io, client_io) = tokio::io::duplex(64 * 1024);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

        // Byte-distinct ≥16 KiB payload so truncation/duplication is caught.
        let payload: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
        server_io
            .write_all(&ws_masked_frame(&payload))
            .await
            .unwrap();

        // Poll 1 with a zero-capacity ReadBuf: the frame parses fully and
        // dispatch_raw_frame hits n == 0 → payload stashed, task woken,
        // Pending returned. Poll 2 (self-wake): stash present → Ready.
        // A lost wake parks this poll_fn forever — caught by the timeout.
        let mut empty = [0u8; 0];
        let mut zero_buf = ReadBuf::new(&mut empty);
        timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| Pin::new(&mut ws).poll_read(cx, &mut zero_buf)),
        )
        .await
        .expect("stash poll hung: wake lost in n == 0 arm")
        .expect("stash poll errored");
        assert_eq!(
            zero_buf.filled().len(),
            0,
            "zero-capacity ReadBuf must not be filled"
        );

        // Drain the stashed payload through 32-byte reads; all bytes must
        // arrive, nothing may hang or be dropped.
        let mut out = vec![0u8; payload.len()];
        let mut got = 0usize;
        while got < payload.len() {
            let mut chunk = [0u8; 32];
            let n = timeout(Duration::from_secs(5), ws.read(&mut chunk))
                .await
                .expect("read hung: stashed payload never delivered")
                .expect("read errored");
            assert!(n > 0, "stalled mid-payload after {got} bytes");
            out[got..got + n].copy_from_slice(&chunk[..n]);
            got += n;
        }
        assert_eq!(&out, &payload, "stashed payload must be byte-exact");
    }

    #[tokio::test]
    async fn ws_raw_accepts_v2_sized_frames_and_rejects_oversized() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

        // Between the old 14 KiB clamp and the V2 64 KiB cap: the WS
        // transport must accept it; V1 enforcement happens in protocol.rs.
        // Masked: the stream is server-mode and enforces RFC 6455 mask
        // direction (L16).
        let payload = vec![0x5a; 20 * 1024];
        server_io
            .write_all(&ws_masked_frame(&payload))
            .await
            .unwrap();
        let mut out = vec![0u8; payload.len()];
        let n = ws.read(&mut out).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&out[..n], &payload[..]);

        // Exactly 64 KiB is the V2 limit and must pass the WS decoder.
        let big = vec![0x6b; 64 * 1024];
        server_io.write_all(&ws_masked_frame(&big)).await.unwrap();
        let mut big_out = vec![0u8; big.len()];
        let n2 = ws.read(&mut big_out).await.unwrap();
        assert_eq!(n2, big.len());
        assert_eq!(&big_out[..n2], &big[..]);

        // A V2 frame at the cap plus AEAD overhead (128 bytes) is accepted —
        // the transport must not clamp encrypted V2 frames below the cap.
        let aead_padded = vec![0x6c; 64 * 1024 + 128];
        server_io
            .write_all(&ws_masked_frame(&aead_padded))
            .await
            .unwrap();
        let mut padded_out = vec![0u8; aead_padded.len()];
        let n3 = ws.read(&mut padded_out).await.unwrap();
        assert_eq!(n3, aead_padded.len());
        assert_eq!(&padded_out[..n3], &aead_padded[..]);

        // One byte over the cap + AEAD overhead is rejected at the transport.
        let huge = vec![0x6c; 64 * 1024 + 129];
        server_io.write_all(&ws_masked_frame(&huge)).await.unwrap();
        let err = ws.read(&mut big_out).await.unwrap_err();
        assert!(
            err.to_string().contains("WS frame too large"),
            "unexpected error: {err}"
        );
    }

    /// AsyncRead+AsyncWrite stub returning `Ok(0)` for the first `zeros`
    /// poll_write calls, then accepting everything — pins WriteZero handling
    /// for a pathological inner transport.
    struct ZeroThenSink {
        zeros: usize,
    }

    impl AsyncRead for ZeroThenSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ZeroThenSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.zeros > 0 {
                self.zeros -= 1;
                return Poll::Ready(Ok(0));
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A partially-flushed frame whose inner writer returns `Ok(0)` must
    /// surface as `WriteZero` on the continuation poll instead of self-waking
    /// into an immediate-repoll 100% CPU spin.
    #[test]
    fn partial_frame_flush_ok_zero_is_write_zero() {
        let mut ws = WsByteStream::from_raw(Box::new(ZeroThenSink { zeros: 2 }), false);
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let buf = vec![0x5Au8; 32];

        // Poll 1: the fresh frame write hits Ok(0) → needs_flush, Pending.
        assert!(matches!(
            Pin::new(&mut ws).poll_write(&mut cx, &buf),
            Poll::Pending
        ));

        // Poll 2: the continuation flush hits Ok(0) on a non-empty remainder →
        // WriteZero error, not a self-wake → Pending spin.
        match Pin::new(&mut ws).poll_write(&mut cx, &buf) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
            other => panic!("expected WriteZero error, got {other:?}"),
        }
    }

    /// Same pathological-inner guard on the `poll_flush` continuation path.
    #[test]
    fn partial_frame_flush_ok_zero_in_poll_flush_is_write_zero() {
        let mut ws = WsByteStream::from_raw(Box::new(ZeroThenSink { zeros: 2 }), false);
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let buf = vec![0x5Au8; 32];

        // Prime a partial flush: fresh frame write hits Ok(0) → needs_flush.
        assert!(matches!(
            Pin::new(&mut ws).poll_write(&mut cx, &buf),
            Poll::Pending
        ));

        // The poll_flush continuation hits Ok(0) → WriteZero error.
        match Pin::new(&mut ws).poll_flush(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
            other => panic!("expected WriteZero error, got {other:?}"),
        }
    }

    /// Regression test for the duplicate-frame bug: after a partial write,
    /// the retained frame tail is drained to completion, and the caller's
    /// re-polled buf (the SAME payload bytes) must be consumed — reported as
    /// written — never re-sent as a fresh frame. The old code re-built a
    /// frame from the re-polled buf after the drain completed, so the peer
    /// received the payload twice (and for a buf larger than the socket
    /// buffer, poll_write never returned Ok at all — the payload was re-sent
    /// in an infinite duplicate loop).
    ///
    /// Real TCP pair with a small SO_SNDBUF on the writer side: the first
    /// writev of a multi-MiB frame can only accept a few KiB, so the partial
    /// write → retention → drain → completion → re-poll sequence is hit
    /// deterministically. The peer must receive EXACTLY ONE unmasked server
    /// frame.
    #[tokio::test]
    async fn ws_partial_write_drain_does_not_duplicate_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        // Server side (the writer) gets a 2 KiB SO_SNDBUF — set on the
        // listening socket, which accepted sockets inherit on Linux; the
        // kernel doubles it to ~4-8 KiB effective, far below the 4 MiB
        // payload, so the first writev is always partial regardless of peer
        // read timing.
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        sock.set_send_buffer_size(2048).unwrap();
        let listener = sock.listen(1).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut ws = WsByteStream::from_raw(Box::new(IoStream::Tcp(server)), false);

        let payload = vec![0x5au8; 4 * 1024 * 1024];
        // 4 MiB > 65535 → 10-byte extended-length header (0x82, 127, u64 len).
        let expect_total = 10 + payload.len();
        let wire_payload = payload.clone();

        let writer = tokio::spawn(async move {
            // Note: with the pre-fix code this future NEVER completes — the
            // frame never fits the socket buffer, so poll_write keeps
            // re-sending the payload as fresh frames and never returns Ok.
            // The test does not await it: the reader's duplicate-evidence
            // cap already has the answer, and runtime shutdown aborts it.
            ws.write_all(&wire_payload).await.expect("ws write_all");
            // ws drops here → FIN to the reader.
        });

        let received = timeout(Duration::from_secs(30), async {
            let mut received = Vec::new();
            let mut chunk = [0u8; 16 * 1024];
            loop {
                match client.read(&mut chunk).await {
                    Ok(0) | Err(_) => break, // EOF: writer finished and closed
                    Ok(n) => {
                        received.extend_from_slice(&chunk[..n]);
                        if received.len() >= 2 * expect_total {
                            // Duplicate data arriving (pre-fix behavior) — no
                            // need to read the infinite stream any further.
                            break;
                        }
                    }
                }
            }
            received
        })
        .await
        .expect("reader must terminate");

        // The writer must not be awaited: with the pre-fix code it hangs.
        drop(writer);

        assert_eq!(
            received.len(),
            expect_total,
            "peer received {} bytes; expected exactly one frame ({} bytes) — \
             the payload was sent more than once",
            received.len(),
            expect_total
        );
        // The single frame must parse as the exact unmasked server frame.
        assert_eq!(received[..2], [0x82, 127], "FIN+BINARY, extended length");
        assert_eq!(
            u64::from_be_bytes(received[2..10].try_into().unwrap()),
            payload.len() as u64
        );
        assert_eq!(&received[10..], &payload[..]);
    }

    /// The poll_flush drain-completion arm must set `drain_completed` so the
    /// next poll_write consumes the caller's re-polled buf instead of
    /// re-sending it. Deterministic unit version of the duplicate-frame
    /// regression: a sink that accepts at most 7 bytes per poll forces the
    /// partial write and a multi-poll drain; the re-polled buf must be
    /// reported as written (Ok(32)) with exactly one frame on the wire.
    #[test]
    fn ws_poll_flush_drain_completion_consumes_repolled_buf() {
        struct LimitedSink {
            limit: usize,
            sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }

        impl AsyncRead for LimitedSink {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for LimitedSink {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let n = buf.len().min(self.limit);
                self.sent.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut ws = WsByteStream::from_raw(
            Box::new(LimitedSink {
                limit: 7,
                sent: sent.clone(),
            }),
            false,
        );
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let buf = vec![0x5au8; 32];

        // Fresh frame write: 2-byte header + 32 payload = 34 frame bytes,
        // but the sink accepts only 7 per poll → partial, needs_flush.
        assert!(matches!(
            Pin::new(&mut ws).poll_write(&mut cx, &buf),
            Poll::Pending
        ));

        // Drain the retained frame to completion via poll_flush (re-polling
        // after each Pending, as an executor would after the self-wake).
        loop {
            match Pin::new(&mut ws).poll_flush(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => panic!("flush failed: {e}"),
                Poll::Pending => {}
            }
        }

        // The caller re-polls with the SAME buf: it must be consumed as the
        // just-drained frame's payload — Ok(32) — not re-sent as a new frame.
        match Pin::new(&mut ws).poll_write(&mut cx, &buf) {
            Poll::Ready(Ok(n)) => assert_eq!(n, 32, "re-polled buf must be consumed"),
            other => panic!("expected Ok(32) consuming the re-polled buf, got {other:?}"),
        }

        // Exactly one frame reached the wire: 2 header + 32 payload bytes.
        assert_eq!(
            sent.load(std::sync::atomic::Ordering::Relaxed),
            34,
            "exactly one frame must be sent; the re-polled buf must not be re-sent"
        );
    }

    /// L16: RSV1-3 bits must be zero (no extensions negotiated) and the
    /// mask direction must match the role — server-mode streams reject
    /// unmasked frames (a client MUST mask, §5.3), client-mode streams
    /// reject masked frames (a server MUST NOT mask, §5.1).
    #[tokio::test]
    async fn ws_frame_rsv_and_mask_direction_enforced() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Server mode: an unmasked frame from a client is a protocol error.
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
        raw.write_all(&[0x82, 0x02, b'a', b'b']).await.unwrap();
        let mut out = [0u8; 4];
        let err = ws.read(&mut out).await.unwrap_err();
        assert!(
            err.to_string().contains("must be masked"),
            "unexpected error: {err}"
        );

        // Server mode: RSV bits set → rejected regardless of masking.
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
        // Masked frame with RSV1 (0x40) + RSV2 (0x20) set.
        let mut frame = ws_masked_zero_frame();
        frame[0] = 0x82 | 0x40 | 0x20;
        raw.write_all(&frame).await.unwrap();
        let err = ws.read(&mut out).await.unwrap_err();
        assert!(err.to_string().contains("RSV"), "unexpected error: {err}");

        // Client mode: a masked frame from a server is a protocol error.
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
        raw.write_all(&[0x82, 0x80 | 0x02, 0, 0, 0, 0, b'a', b'b'])
            .await
            .unwrap();
        let err = ws.read(&mut out).await.unwrap_err();
        assert!(
            err.to_string().contains("must not be masked"),
            "unexpected error: {err}"
        );

        // And the legitimate shapes still decode: masked frame into a
        // server-mode stream, unmasked frame into a client-mode stream.
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
        raw.write_all(&ws_masked_frame(b"ok-server")).await.unwrap();
        let mut out = [0u8; 16];
        let n = ws.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"ok-server");

        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
        raw.write_all(&ws_binary_frame(b"ok-client")).await.unwrap();
        let n = ws.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"ok-client");
    }

    /// M3: client-mode control frames (pong reply, shutdown close) are
    /// masked per RFC 6455 §5.3 — a strict server peer must be able to
    /// unmask them. The pong is a reply to an inbound (unmasked) ping; the
    /// close frame must carry the masked 1000 code.
    #[tokio::test]
    async fn ws_client_mode_control_frames_are_masked() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        // Pong reply to an inbound ping must be a masked pong on the wire.
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
        raw.write_all(&[0x89, 0x00]).await.unwrap(); // unmasked ping (server → client)
                                                     // Drive the read path so the ping is dispatched and the pong sent.
        let read_task = tokio::spawn(async move {
            let mut out = [0u8; 4];
            let _ = timeout(Duration::from_millis(200), ws.read(&mut out)).await;
        });
        let mut pong = [0u8; 6];
        let n = timeout(Duration::from_secs(5), raw.read(&mut pong))
            .await
            .expect("pong must arrive")
            .expect("read pong");
        read_task.await.expect("read task");
        assert_eq!(n, 6, "masked pong: 2 header + 4 mask bytes");
        assert_eq!(pong[0], 0x8a, "FIN + PONG opcode");
        assert_eq!(pong[1], 0x80, "MASK bit must be set on client-mode pong");
        // pong[2..6] is the 4-byte mask key: RFC 6455 §5.3 requires a fresh
        // random key per frame, so its value is asserted only where payload
        // exists to unmask (the close frame below). Empty payload → nothing
        // masked; the key bytes are arbitrary.

        // Shutdown close frame must be masked, with the 1000 code XORed
        // against the 4-byte mask key.
        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), true);
        ws.shutdown().await.expect("shutdown");
        let mut close = [0u8; 8];
        let n = timeout(Duration::from_secs(5), raw.read(&mut close))
            .await
            .expect("close frame must arrive")
            .expect("read close");
        assert_eq!(n, 8, "masked close: 2 header + 4 mask + 2 payload");
        assert_eq!(close[0], 0x88, "FIN + CLOSE opcode");
        assert_eq!(close[1], 0x80 | 0x02, "MASK bit + 2-byte payload");
        assert_eq!(
            close[6] ^ close[2],
            0x03,
            "close code 1000 masked (high byte)"
        );
        assert_eq!(
            close[7] ^ close[3],
            0xe8,
            "close code 1000 masked (low byte)"
        );
    }

    /// L18: poll_shutdown must not drop a partially-flushed frame — it
    /// drains write_buf (and the close frame) to completion before
    /// delegating to the inner shutdown.
    #[test]
    fn ws_shutdown_drains_partially_flushed_frame() {
        struct ShutdownTrackingSink {
            limit: usize,
            sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
            shutdown_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        impl AsyncRead for ShutdownTrackingSink {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for ShutdownTrackingSink {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let n = buf.len().min(self.limit);
                self.sent.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.shutdown_called
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
        }

        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let shutdown_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut ws = WsByteStream::from_raw(
            Box::new(ShutdownTrackingSink {
                limit: 7,
                sent: sent.clone(),
                shutdown_called: shutdown_called.clone(),
            }),
            false,
        );
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let buf = vec![0x5au8; 32];

        // Fresh frame write: 34 frame bytes, but the sink accepts only 7 per
        // poll → partial, needs_flush (the frame is NOT fully on the wire).
        assert!(matches!(
            Pin::new(&mut ws).poll_write(&mut cx, &buf),
            Poll::Pending
        ));

        // Shutdown must drain the retained frame (34 bytes) AND the close
        // frame (4 bytes unmasked server-mode) before calling inner
        // shutdown — 38 bytes total on the wire.
        loop {
            match Pin::new(&mut ws).poll_shutdown(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => panic!("shutdown failed: {e}"),
                Poll::Pending => {}
            }
        }
        assert_eq!(
            sent.load(std::sync::atomic::Ordering::Relaxed),
            38,
            "shutdown must drain the partially-flushed frame (34) plus the close frame (4)"
        );
        assert!(
            shutdown_called.load(std::sync::atomic::Ordering::Relaxed),
            "inner shutdown must be delegated after the drain"
        );
    }

    /// Masked frame with an arbitrary opcode and an EXPLICIT raw length
    /// field (126/127 allowed even for payloads that would not need the
    /// extended encoding) — lets a test pin the raw-length-field and FIN
    /// checks on control frames independently of the payload-size-driven
    /// encoding of [`ws_masked_frame`]. Server-mode streams enforce
    /// RFC 6455 mask direction, so protocol-violation frames fed into them
    /// are masked.
    fn ws_masked_frame_raw(opcode: u8, raw_len: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![opcode | if fin { 0x80 } else { 0 }];
        frame.push(0x80 | raw_len);
        match raw_len {
            126 => frame.extend_from_slice(&(payload.len() as u16).to_be_bytes()),
            127 => frame.extend_from_slice(&(payload.len() as u64).to_be_bytes()),
            _ => {}
        }
        let mask: [u8; 4] = rand::random();
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
        frame
    }

    /// RFC 6455 §5.5 control-frame validation: a control frame whose raw
    /// 7-bit length field is 126/127 (extended-length encoding), whose
    /// decoded payload exceeds 125 bytes, or whose FIN bit is clear is a
    /// protocol error that closes the connection — a >125-byte ping is NOT
    /// truncatable to a pong. The raw-field rejection matches gorilla:
    /// advanceFrame checks the raw length field against 125 for control
    /// frames (conn.go:841) before decoding any extended length. A
    /// continuation frame (opcode 0x00) with no fragmented message in
    /// progress is likewise a protocol error (gorilla: "continuation after
    /// FIN"), not a data frame.
    #[tokio::test]
    async fn ws_control_frame_and_continuation_validation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn expect_protocol_error(frame: Vec<u8>, needle: &str) {
            let (mut raw, client_io) = tokio::io::duplex(8192);
            let mut ws = WsByteStream::from_raw(Box::new(client_io), false);
            raw.write_all(&frame).await.unwrap();
            let mut out = [0u8; 8];
            let err = ws.read(&mut out).await.unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "expected error containing {needle:?}, got: {err}"
            );
        }

        // Oversized ping: a 126-byte payload requires the 16-bit extended
        // length encoding, which control frames must not use (previously
        // truncated to a 125-byte pong with a warning).
        expect_protocol_error(
            ws_masked_frame_raw(0x09, 126, true, &[0x55; 126]),
            "control",
        )
        .await;

        // Extended-length ping: the RAW length field is 127 (64-bit
        // encoding) even though the decoded payload is only 2 bytes — a
        // protocol error here although gorilla's decoded-length check
        // (2 ≤ 125) would admit it: frp-rs is stricter on the encoding.
        expect_protocol_error(ws_masked_frame_raw(0x09, 127, true, b"hi"), "control").await;

        // FIN=0 ping: control frames must have FIN set (RFC 6455 §5.5).
        expect_protocol_error(ws_masked_frame_raw(0x09, 1, false, b"x"), "FIN not set").await;

        // Stray continuation: opcode 0x00 with no fragmented message in
        // progress (the reader never starts one — every data frame is
        // treated as complete) is a protocol error, not a data frame.
        expect_protocol_error(ws_masked_frame_raw(0x00, 3, true, b"abc"), "continuation").await;
    }

    /// Masked control frame builder (client-mode wire shape: MASK bit + a
    /// fresh random key). Payload must be ≤ 125 bytes (control-frame rule).
    fn ws_masked_control_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= 125, "control frame payload cap");
        let mask: [u8; 4] = rand::random();
        let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
        frame
    }

    /// Unmask a masked server→client (client-mode outbound) frame payload:
    /// returns (header_len, payload). Header is 2 + 4 mask bytes for
    /// payloads ≤ 125.
    fn ws_unmask_payload(frame: &[u8]) -> (usize, Vec<u8>) {
        assert!(frame.len() >= 6, "masked frame too short");
        assert_eq!(frame[1] & 0x80, 0x80, "expected MASK bit set");
        let mask = &frame[2..6];
        let payload = frame[6..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i & 3])
            .collect::<Vec<u8>>();
        (6, payload)
    }

    /// Server mode, inbound MASKED ping with a payload (the client-mode wire
    /// shape): the pong must echo the payload unmasked (server-mode replies
    /// are never masked — RFC 6455 §5.3), and the ping must NOT surface as
    /// data — the read stays parked. Control-frame pin (T11).
    #[tokio::test]
    async fn ws_server_mode_echoes_masked_ping_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false); // server mode

        let ping_payload = b"ping-with-payload";
        raw.write_all(&ws_masked_control_frame(0x09, ping_payload))
            .await
            .unwrap();

        let read_task = tokio::spawn(async move {
            let mut out = [0u8; 4];
            let _ = timeout(Duration::from_millis(200), ws.read(&mut out)).await;
        });

        // Server-mode pong: unmasked (no MASK bit), payload echoed verbatim.
        let mut pong = vec![0u8; 2 + ping_payload.len()];
        let n = timeout(Duration::from_secs(5), raw.read(&mut pong))
            .await
            .expect("pong must arrive")
            .expect("read pong");
        assert_eq!(n, pong.len(), "2 header + echoed payload");
        assert_eq!(pong[0], 0x8a, "FIN + PONG opcode");
        assert_eq!(pong[1] & 0x80, 0x00, "server-mode pong must be unmasked");
        assert_eq!(&pong[2..], ping_payload, "pong echoes the ping payload");

        // The ping is a control frame: it must not surface as read data —
        // the read task stays parked until its timeout fires.
        read_task.await.expect("read task");
    }

    /// Client mode, inbound UNMASKED ping with a payload (the server-mode
    /// wire shape): the pong must be masked with a fresh key and carry the
    /// SAME payload — unmask it to verify byte-exact echo. Control-frame
    /// pin (T11).
    #[tokio::test]
    async fn ws_client_mode_masks_pong_and_echoes_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), true); // client mode

        let ping_payload = b"client-mode-ping";
        let mut ping = vec![0x89, ping_payload.len() as u8]; // unmasked ping
        ping.extend_from_slice(ping_payload);
        raw.write_all(&ping).await.unwrap();

        let read_task = tokio::spawn(async move {
            let mut out = [0u8; 4];
            let _ = timeout(Duration::from_millis(200), ws.read(&mut out)).await;
        });

        let mut pong = vec![0u8; 2 + 4 + ping_payload.len()];
        let n = timeout(Duration::from_secs(5), raw.read(&mut pong))
            .await
            .expect("pong must arrive")
            .expect("read pong");
        read_task.await.expect("read task");
        assert_eq!(n, pong.len(), "2 header + 4 mask + echoed payload");
        assert_eq!(pong[0], 0x8a, "FIN + PONG opcode");
        assert_eq!(pong[1] & 0x80, 0x80, "client-mode pong must be masked");
        let (_, echoed) = ws_unmask_payload(&pong);
        assert_eq!(echoed, ping_payload, "masked pong echoes the ping payload");
    }

    /// Inbound CLOSE (masked, server mode): the stream must reply with an
    /// unmasked close frame carrying code 1000, and the read must surface
    /// EOF (0 bytes) — never the close payload as data. Control-frame pin
    /// (T11).
    #[tokio::test]
    async fn ws_server_mode_close_reply_then_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false); // server mode

        // Masked close with code 1000 (0x03e8), as a compliant client sends.
        raw.write_all(&ws_masked_control_frame(0x08, &[0x03, 0xe8]))
            .await
            .unwrap();

        // Drive the read: the close reply is written, then the read returns
        // EOF.
        let mut out = [0u8; 8];
        let n = timeout(Duration::from_secs(5), ws.read(&mut out))
            .await
            .expect("read must return after inbound close")
            .expect("read ok");
        assert_eq!(n, 0, "inbound close surfaces as EOF, got {n} bytes of data");

        // Reply close frame: unmasked, code 1000.
        let mut reply = [0u8; 4];
        let rn = timeout(Duration::from_secs(5), raw.read(&mut reply))
            .await
            .expect("close reply must arrive")
            .expect("read reply");
        assert_eq!(rn, 4, "server-mode close reply: 2 header + 2 code bytes");
        assert_eq!(reply[0], 0x88, "FIN + CLOSE opcode");
        assert_eq!(
            reply[1], 0x02,
            "server-mode reply is unmasked, 2-byte payload"
        );
        assert_eq!(&reply[2..], &[0x03, 0xe8], "close code 1000");
    }

    /// Inbound PONG must be swallowed (never surfaced as data), and frames
    /// after it must still be delivered. Control-frame pin (T11).
    #[tokio::test]
    async fn ws_server_mode_swallows_pong_and_reads_next_frame() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut raw, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false); // server mode

        // Masked pong with a payload, then a masked binary data frame.
        raw.write_all(&ws_masked_control_frame(0x0a, b"pong-payload"))
            .await
            .unwrap();
        let data = b"data-after-pong";
        raw.write_all(&ws_masked_frame(data)).await.unwrap();

        let mut out = vec![0u8; data.len()];
        let n = ws.read(&mut out).await.expect("read data frame");
        assert_eq!(
            n,
            data.len(),
            "pong must be swallowed, data frame delivered"
        );
        assert_eq!(&out[..n], data);
    }
}
