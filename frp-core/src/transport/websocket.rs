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
pub(crate) const MAX_WS_FRAME_PAYLOAD: u64 = crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128;

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
/// streams and for a `PreRead`/`BufferedRead` accept variant that still holds
/// unread bytes). Server accept paths box an `IoStream`, so the erased
/// `Box<dyn AsyncReadWrite>` is peeled via `Any` first (the trait is
/// `'static`); client-side `PrependStream` boxes yield `None`, which is fine
/// — the client path never uses this.
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
/// loop with a per-byte modulo, which is ~4x cheaper on the bridge chunks the
/// WebSocket transport writes.
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
                // `clear` + `extend_from_slice` (not `= payload.to_vec()`):
                // the stash keeps `read_buf`'s allocation across stashes
                // instead of dropping it and allocating a fresh Vec every
                // time the caller's buffer is smaller than the frame. The
                // buffer is fully drained on entry to this path (the
                // cursor-served prefix at the top of `poll_read` clears it
                // once `read_pos` reaches the end), so `clear` never discards
                // undelivered bytes.
                read_buf.clear();
                read_buf.extend_from_slice(payload);
                *read_pos = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            buf.put_slice(&payload[..n]);
            if n < payload.len() {
                read_buf.clear();
                read_buf.extend_from_slice(&payload[n..]);
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
                // (one bridge chunk per frame). The downcast is the same one the
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
        let raw = inner;
        if *needs_flush {
            let remaining = &write_buf[*write_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    // Same pathological-inner guard as poll_write: zero
                    // progress on a non-empty remainder is a write-zero error,
                    // not a self-wake spin.
                    *needs_flush = false;
                    *drain_completed = false;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *write_pos += n;
                    if *write_pos < write_buf.len() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    *write_pos = 0;
                    *needs_flush = false;
                    // poll_flush has no buf to consume, so record that the
                    // frame completed; the next poll_write consumes the
                    // caller's re-polled buf (returning the recorded payload
                    // length) instead of re-sending it.
                    *drain_completed = true;
                }
                Poll::Ready(Err(e)) => {
                    *needs_flush = false;
                    *drain_completed = false;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        // Always flush the inner stream, even when no frame bytes remain here.
        // A TLS inner accepts plaintext into its own buffer and only its flush
        // pushes those records onto the socket; returning `Ready(Ok(()))` at
        // this point let the last record sit in userspace while both ends
        // waited for data — the intermittent stall the interleaved benchmark
        // hit on the websocket + TLS + tcpMux shape (both processes at zero
        // CPU with nothing in flight, repaired only by the next write).
        Pin::new(raw.as_mut()).poll_flush(cx)
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
mod tests;
