//! WebSocket transport: the [`WsByteStream`] adapter converts between
//! WebSocket messages and a byte stream suitable for the V1/V2 protocol
//! functions, and implements [`Transport`].
//!
//! Single mode — manual RFC 6455 framing (client + server, binary frames;
//! the server tolerates text frames for backward compatibility with Go frp
//! < v0.70.1). The previous tungstenite-based variant was removed
//! 2026-08-09 (audit D1-1/D1-2/D1-3): it had no callers, and the manual
//! path reuses buffers across frames (no per-frame allocation).

use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{AsyncReadWrite, Transport};

/// Maximum WebSocket frame payload accepted by the raw decoder. The V2
/// framing layer permits 64 KiB messages, so the transport must not clamp
/// below that; the V1 10 KiB limit stays enforced by `protocol.rs`.
/// +128 bytes covers the V2 AEAD overhead (AES-256-GCM tag + nonce) so an
/// encrypted V2 frame at the payload cap is not rejected by the transport.
pub(crate) const MAX_WS_FRAME_PAYLOAD: u64 = crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128;

/// Stack `IoSlice` budget for vectored outgoing frames: 1 header + up to 15
/// payload slices so multi-slice writes (such as yamux `[header, body]`) emit
/// a single WS frame without heap allocation on the vectored fast path.
const MAX_WS_VECT_SLICES: usize = 15;

/// Cap on no-progress frames (zero-length data, ping, pong) drained within a
/// single `poll_read` call. Each such frame is consumed without stalling the
/// poll loop on the happy path, and after the cap we wake and yield so a peer
/// flooding empty/control frames cannot starve other tasks.
const MAX_NO_PROGRESS_FRAMES_PER_POLL: u32 = 1024;

/// A WebSocket-to-byte-stream adapter that implements AsyncRead/AsyncWrite.
/// Converts between WebSocket messages and a byte stream suitable
/// for use with the V1 protocol functions.
pub struct WsByteStream {
    inner: Box<dyn AsyncReadWrite>,
    /// Write buffer for masked client frames and partial-write continuations.
    write_buf: Vec<u8>,
    write_pos: usize,
    needs_flush: bool,
    /// Payload length of the frame currently held in `write_buf` (i.e. the
    /// frame being drained after a partial write). The AsyncWrite contract
    /// mandates that the caller re-polls with that same data until `poll_write`
    /// returns `Ok`; returning this length consumes it without re-sending.
    pending_frame_payload_len: usize,
    /// Set when a drain completes inside `poll_flush`, which cannot consume
    /// the caller's buf (it has no buf argument). The next `poll_write` /
    /// `poll_write_vectored` sees this first and returns
    /// `pending_frame_payload_len`.
    drain_completed: bool,
    /// Set once the shutdown Close frame has been written in full so a resumed
    /// `poll_shutdown` after inner `Pending` does not emit a duplicate Close.
    close_sent: bool,
    /// Set once an inbound Close frame (`0x08`) has been received; ensures
    /// `poll_read` returns EOF once any stashed Close reply finishes draining.
    close_received: bool,
    /// When true, outgoing frames are masked (RFC 6455 §5.3 — client requirement).
    client_mode: bool,
    /// State machine for incremental zero-copy WebSocket frame reads.
    raw_read_state: RawReadState,
    /// Inline read-ahead buffer for frame headers (up to 14 bytes) and small
    /// pipelined frame boundaries (avoids per-frame small header syscalls and
    /// 64 KiB staging buffer allocations/zeroing).
    preroll: [u8; 64],
    preroll_pos: u8,
    preroll_len: u8,
    /// Inline buffer for RFC 6455 control frame payloads (always <= 125 bytes).
    ctrl_buf: [u8; 125],
    /// Control frame bytes (close/pong reply, and the shutdown close frame)
    /// not yet fully written to the inner stream.
    pending_control_write: Vec<u8>,
    pending_control_pos: usize,
    /// True iff `pending_control_write` holds a Close (`0x08`) frame tail
    /// rather than a Pong (`0x0a`) reply.
    pending_control_is_close: bool,
    /// Inner read error observed after payload bytes were already handed to
    /// the caller in the same poll; surfaced on the next `poll_read` so a
    /// mid-frame socket error is never downgraded to a clean EOF.
    read_error: Option<io::Error>,
}

impl WsByteStream {
    /// Encode an RFC 6455 BINARY data frame header into `out[..14]` and return
    /// the encoded byte length (`2`, `4`, or `10`, plus `4` if `mask.is_some()`).
    #[inline]
    fn encode_frame_header(out: &mut [u8], len: usize, mask: Option<[u8; 4]>) -> usize {
        out[0] = 0x82; // FIN + BINARY opcode
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let hdr_len = if len < 126 {
            out[1] = mask_bit | (len as u8);
            2
        } else if len <= 65535 {
            out[1] = mask_bit | 126;
            out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            4
        } else {
            out[1] = mask_bit | 127;
            out[2..10].copy_from_slice(&(len as u64).to_be_bytes());
            10
        };
        if let Some(m) = mask {
            out[hdr_len..hdr_len + 4].copy_from_slice(&m);
            hdr_len + 4
        } else {
            hdr_len
        }
    }

    /// Build a single WebSocket data frame (FIN + BINARY opcode) across one or
    /// more payload `slices` (totalling `total_len` bytes) into `out`.
    fn build_vectored_frame_into(
        out: &mut Vec<u8>,
        slices: &[&[u8]],
        total_len: usize,
        client_mode: bool,
    ) {
        out.clear();
        out.reserve(total_len + 14);
        let mut hdr = [0u8; 14];
        if client_mode {
            let mask: [u8; 4] = rand::random();
            let hdr_len = Self::encode_frame_header(&mut hdr, total_len, Some(mask));
            out.extend_from_slice(&hdr[..hdr_len]);
            let mut offset = 0usize;
            for slice in slices {
                copy_masked(out, slice, mask, offset);
                offset = (offset + slice.len()) & 3;
            }
        } else {
            let hdr_len = Self::encode_frame_header(&mut hdr, total_len, None);
            out.extend_from_slice(&hdr[..hdr_len]);
            for slice in slices {
                out.extend_from_slice(slice);
            }
        }
    }

    /// Build a WebSocket data frame (FIN + BINARY opcode) into `out`.
    #[cfg(test)]
    #[allow(dead_code)]
    fn build_frame_into(out: &mut Vec<u8>, buf: &[u8], client_mode: bool) {
        Self::build_vectored_frame_into(out, &[buf], buf.len(), client_mode);
    }

    /// Encode the server-mode (unmasked) frame header for a payload of `len`
    /// bytes into `hdr` (capacity ≥ 10) and return its length: 2 bytes for
    /// `len < 126`, 4 for `len <= 65535`, 10 otherwise (RFC 6455 §5.2).
    fn build_server_frame_header(hdr: &mut [u8; 10], len: usize) -> usize {
        Self::encode_frame_header(hdr, len, None)
    }
}

/// Expand a 4-byte RFC 6455 masking key rotated by `offset` into 32 bytes so
/// LLVM auto-vectorizes XOR loops to 256-bit AVX2 / 128-bit NEON ops in safe Rust.
#[inline]
fn expand_mask32(mask: [u8; 4], offset: usize) -> [u8; 32] {
    let rot = [
        mask[offset & 3],
        mask[(offset + 1) & 3],
        mask[(offset + 2) & 3],
        mask[(offset + 3) & 3],
    ];
    let mut out = [0u8; 32];
    for chunk in out.as_chunks_mut::<4>().0 {
        chunk.copy_from_slice(&rot);
    }
    out
}

/// XOR a payload with an RFC 6455 masking key starting at key rotation `offset`.
#[inline]
fn xor_mask_offset(payload: &mut [u8], mask: [u8; 4], offset: usize) {
    if payload.is_empty() {
        return;
    }
    let mask32 = expand_mask32(mask, offset);
    let (chunks, tail) = payload.as_chunks_mut::<32>();
    for chunk in chunks {
        for i in 0..32 {
            chunk[i] ^= mask32[i];
        }
    }
    for (i, b) in tail.iter_mut().enumerate() {
        *b ^= mask32[i];
    }
}

/// Copy and mask `src` into `dst` via a single contiguous extend + SIMD-friendly XOR pass.
#[inline]
fn copy_masked(dst: &mut Vec<u8>, src: &[u8], mask: [u8; 4], offset: usize) {
    let start = dst.len();
    dst.extend_from_slice(src);
    xor_mask_offset(&mut dst[start..], mask, offset);
}

/// XOR a payload with an RFC 6455 masking key from offset 0 (used in unit tests).
#[cfg(test)]
#[allow(dead_code)]
#[inline]
fn xor_mask(payload: &mut [u8], mask: [u8; 4]) {
    xor_mask_offset(payload, mask, 0);
}

/// Build an RFC 6455 control frame (FIN + control opcode, payload <= 125
/// bytes) into stack buffer `out[..131]`, returning the encoded byte length.
fn build_control_frame_stack(
    out: &mut [u8; 131],
    opcode: u8,
    payload: &[u8],
    client_mode: bool,
) -> usize {
    out[0] = 0x80 | opcode;
    let plen = payload.len();
    if client_mode {
        let mask: [u8; 4] = rand::random();
        out[1] = 0x80 | plen as u8;
        out[2..6].copy_from_slice(&mask);
        out[6..6 + plen].copy_from_slice(payload);
        xor_mask_offset(&mut out[6..6 + plen], mask, 0);
        6 + plen
    } else {
        out[1] = plen as u8;
        out[2..2 + plen].copy_from_slice(payload);
        2 + plen
    }
}

/// Attempt to write a control frame (close/pong reply) to the raw inner.
/// Returns `Poll::Ready(Ok(true))` when fully written, `Ready(Ok(false))` when
/// the unwritten tail was stashed in `stash` (drained at top of next `poll_read`),
/// and `Ready(Err)` on write failure.
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

/// State machine for incremental zero-copy WebSocket frame reads on Raw streams.
enum RawReadState {
    Idle,
    /// Streaming payload bytes of an active data frame (`0x01`/`0x02`) straight
    /// into the caller's `ReadBuf` with zero intermediate payload allocation.
    StreamingData {
        remaining: u64,
        masked: bool,
        mask_key: [u8; 4],
        mask_pos: usize,
    },
    /// Accumulating a small RFC 6455 control frame (`0x08..=0x0a`, <= 125 bytes)
    /// into `WsByteStream::ctrl_buf`.
    ReadingControl {
        opcode: u8,
        masked: bool,
        mask_key: [u8; 4],
        len: u8,
        filled: u8,
    },
}

/// Ensure at least `need` (`<= 14`) unread bytes are buffered in `preroll`.
/// Returns `Poll::Ready(Ok(true))` when satisfied, `Poll::Ready(Ok(false))` on
/// inner EOF, `Poll::Pending` when inner parks, and `Poll::Ready(Err)` on read error.
fn fill_preroll(
    raw: &mut Box<dyn AsyncReadWrite>,
    cx: &mut Context<'_>,
    preroll: &mut [u8; 64],
    preroll_pos: &mut u8,
    preroll_len: &mut u8,
    need: usize,
) -> Poll<io::Result<bool>> {
    while ((*preroll_len - *preroll_pos) as usize) < need {
        let avail = (*preroll_len - *preroll_pos) as usize;
        if *preroll_pos > 0 {
            if avail > 0 {
                preroll.copy_within(*preroll_pos as usize..*preroll_len as usize, 0);
            }
            *preroll_pos = 0;
            *preroll_len = avail as u8;
        }
        let mut rb = ReadBuf::new(&mut preroll[*preroll_len as usize..]);
        match Pin::new(raw.as_mut()).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(false));
                }
                *preroll_len += n as u8;
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(true))
}

/// Dispatch a completed control frame (`0x08` Close, `0x09` Ping, `0x0a` Pong).
/// Returns `Poll::Ready(Some(res))` if `poll_read` should return immediately
/// (`Close` EOF/Err), or `Poll::Ready(None)` if control handling finished or
/// stashed pending bytes (`Pending` yield handled via `pending_control_write`).
#[allow(clippy::too_many_arguments)]
fn dispatch_control_frame(
    opcode: u8,
    payload: &[u8],
    raw: &mut Box<dyn AsyncReadWrite>,
    cx: &mut Context<'_>,
    client_mode: bool,
    pending_control_write: &mut Vec<u8>,
    pending_control_pos: &mut usize,
    pending_control_is_close: &mut bool,
    close_sent: &mut bool,
) -> Poll<io::Result<()>> {
    match opcode {
        0x08 => {
            let mut stack_frame = [0u8; 131];
            let flen =
                build_control_frame_stack(&mut stack_frame, 0x08, &[0x03, 0xe8], client_mode);
            match poll_write_control(
                raw,
                cx,
                pending_control_write,
                pending_control_pos,
                &stack_frame[..flen],
            ) {
                Poll::Ready(Ok(true)) => {
                    *close_sent = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(false)) => {
                    *pending_control_is_close = true;
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => unreachable!("poll_write_control never returns Pending"),
            }
        }
        0x09 => {
            if payload.len() > 125 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WS control frame length > 125",
                )));
            }
            let mut stack_frame = [0u8; 131];
            let flen = build_control_frame_stack(&mut stack_frame, 0x0a, payload, client_mode);
            match poll_write_control(
                raw,
                cx,
                pending_control_write,
                pending_control_pos,
                &stack_frame[..flen],
            ) {
                Poll::Ready(Ok(done)) => {
                    if !done {
                        *pending_control_is_close = false;
                    }
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    tracing::debug!(error = %e, "WS pong write failed");
                    Poll::Pending
                }
                Poll::Pending => unreachable!("poll_write_control never returns Pending"),
            }
        }
        0x0a => Poll::Pending,
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
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
            pending_frame_payload_len: 0,
            drain_completed: false,
            close_sent: false,
            close_received: false,
            client_mode,
            raw_read_state: RawReadState::Idle,
            preroll: [0u8; 64],
            preroll_pos: 0,
            preroll_len: 0,
            ctrl_buf: [0u8; 125],
            pending_control_write: Vec::new(),
            pending_control_pos: 0,
            pending_control_is_close: false,
            read_error: None,
        }
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(e) = this.read_error.take() {
            return Poll::Ready(Err(e));
        }
        let WsByteStream {
            inner: raw,
            client_mode,
            raw_read_state,
            preroll,
            preroll_pos,
            preroll_len,
            ctrl_buf,
            pending_control_write,
            pending_control_pos,
            pending_control_is_close,
            close_sent,
            close_received,
            read_error,
            ..
        } = this;

        // Flush any stashed control frame (close/pong reply, or the shutdown
        // close frame) before parsing the next frame — never silently dropped.
        if !pending_control_write.is_empty() {
            let remaining = &pending_control_write[*pending_control_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    pending_control_write.clear();
                    *pending_control_pos = 0;
                    *pending_control_is_close = false;
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
                        if *pending_control_is_close {
                            *pending_control_is_close = false;
                            *close_sent = true;
                        }
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if *close_received {
            return Poll::Ready(Ok(()));
        }

        let mut no_progress_frames = 0u32;
        loop {
            match raw_read_state {
                RawReadState::Idle => {
                    no_progress_frames += 1;
                    if no_progress_frames > MAX_NO_PROGRESS_FRAMES_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    match fill_preroll(raw, cx, preroll, preroll_pos, preroll_len, 2) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let pos = *preroll_pos as usize;
                    let b0 = preroll[pos];
                    let b1 = preroll[pos + 1];
                    let opcode = b0 & 0x0f;
                    let fin = (b0 & 0x80) != 0;
                    let masked = (b1 & 0x80) != 0;
                    let raw_len = (b1 & 0x7f) as u64;

                    if b0 & 0x70 != 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "WS frame has RSV bits set",
                        )));
                    }
                    if masked == *client_mode {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            if *client_mode {
                                "WS frame from server must not be masked"
                            } else {
                                "WS frame from client must be masked"
                            },
                        )));
                    }
                    if matches!(opcode, 0x08..=0x0a) {
                        if !fin {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "WS control frame has FIN not set",
                            )));
                        }
                        if raw_len > 125 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "WS control frame length > 125",
                            )));
                        }
                    }

                    let ext_len = if raw_len == 126 {
                        2
                    } else if raw_len == 127 {
                        8
                    } else {
                        0
                    };
                    let mask_len = if masked { 4 } else { 0 };
                    let total_hdr = 2 + ext_len + mask_len;

                    match fill_preroll(raw, cx, preroll, preroll_pos, preroll_len, total_hdr) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }

                    let pos = *preroll_pos as usize;
                    let payload_len = match ext_len {
                        2 => u16::from_be_bytes([preroll[pos + 2], preroll[pos + 3]]) as u64,
                        8 => u64::from_be_bytes([
                            preroll[pos + 2],
                            preroll[pos + 3],
                            preroll[pos + 4],
                            preroll[pos + 5],
                            preroll[pos + 6],
                            preroll[pos + 7],
                            preroll[pos + 8],
                            preroll[pos + 9],
                        ]),
                        _ => raw_len,
                    };
                    let mask_key = if masked {
                        let mpos = pos + 2 + ext_len;
                        [
                            preroll[mpos],
                            preroll[mpos + 1],
                            preroll[mpos + 2],
                            preroll[mpos + 3],
                        ]
                    } else {
                        [0u8; 4]
                    };

                    *preroll_pos += total_hdr as u8;
                    if *preroll_pos == *preroll_len {
                        *preroll_pos = 0;
                        *preroll_len = 0;
                    }

                    if payload_len > MAX_WS_FRAME_PAYLOAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "WS frame too large",
                        )));
                    }

                    match opcode {
                        0x00 => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "WS continuation frame without a fragmented message",
                            )));
                        }
                        0x01 | 0x02 => {
                            if payload_len == 0 {
                                continue;
                            }
                            *raw_read_state = RawReadState::StreamingData {
                                remaining: payload_len,
                                masked,
                                mask_key,
                                mask_pos: 0,
                            };
                        }
                        0x08..=0x0a => {
                            if payload_len == 0 {
                                if opcode == 0x08 {
                                    *close_received = true;
                                }
                                let res = dispatch_control_frame(
                                    opcode,
                                    &[],
                                    raw,
                                    cx,
                                    *client_mode,
                                    pending_control_write,
                                    pending_control_pos,
                                    pending_control_is_close,
                                    close_sent,
                                );
                                if let Poll::Ready(r) = res {
                                    return Poll::Ready(r);
                                }
                                if !pending_control_write.is_empty() {
                                    return Poll::Pending;
                                }
                                continue;
                            }
                            *raw_read_state = RawReadState::ReadingControl {
                                opcode,
                                masked,
                                mask_key,
                                len: payload_len as u8,
                                filled: 0,
                            };
                        }
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unexpected WS opcode: {opcode:#x}"),
                            )));
                        }
                    }
                }
                RawReadState::ReadingControl {
                    opcode,
                    masked,
                    mask_key,
                    len,
                    filled,
                } => {
                    if *preroll_pos < *preroll_len && *filled < *len {
                        let avail = (*preroll_len - *preroll_pos) as usize;
                        let need = (*len - *filled) as usize;
                        let take = avail.min(need);
                        let ppos = *preroll_pos as usize;
                        let fpos = *filled as usize;
                        ctrl_buf[fpos..fpos + take].copy_from_slice(&preroll[ppos..ppos + take]);
                        *filled += take as u8;
                        *preroll_pos += take as u8;
                        if *preroll_pos == *preroll_len {
                            *preroll_pos = 0;
                            *preroll_len = 0;
                        }
                    }
                    while *filled < *len {
                        let mut rb = ReadBuf::new(&mut ctrl_buf[*filled as usize..*len as usize]);
                        match Pin::new(raw.as_mut()).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                *filled += n as u8;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let op = *opcode;
                    let is_masked = *masked;
                    let mk = *mask_key;
                    let clen = *len as usize;
                    *raw_read_state = RawReadState::Idle;
                    if is_masked {
                        xor_mask_offset(&mut ctrl_buf[..clen], mk, 0);
                    }
                    if op == 0x08 {
                        *close_received = true;
                    }
                    let res = dispatch_control_frame(
                        op,
                        &ctrl_buf[..clen],
                        raw,
                        cx,
                        *client_mode,
                        pending_control_write,
                        pending_control_pos,
                        pending_control_is_close,
                        close_sent,
                    );
                    if let Poll::Ready(r) = res {
                        return Poll::Ready(r);
                    }
                    if !pending_control_write.is_empty() {
                        return Poll::Pending;
                    }
                }
                RawReadState::StreamingData {
                    remaining,
                    masked,
                    mask_key,
                    mask_pos,
                } => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let mut wrote_from_preroll = false;
                    if *preroll_pos < *preroll_len {
                        let avail = (*preroll_len - *preroll_pos) as usize;
                        let take = (*remaining as usize).min(buf.remaining()).min(avail);
                        if take > 0 {
                            let start = buf.filled().len();
                            let ppos = *preroll_pos as usize;
                            buf.put_slice(&preroll[ppos..ppos + take]);
                            if *masked {
                                xor_mask_offset(
                                    &mut buf.filled_mut()[start..],
                                    *mask_key,
                                    *mask_pos,
                                );
                                *mask_pos = (*mask_pos + take) & 3;
                            }
                            *preroll_pos += take as u8;
                            if *preroll_pos == *preroll_len {
                                *preroll_pos = 0;
                                *preroll_len = 0;
                            }
                            *remaining -= take as u64;
                            wrote_from_preroll = true;
                            if *remaining == 0 {
                                *raw_read_state = RawReadState::Idle;
                                return Poll::Ready(Ok(()));
                            }
                            if buf.remaining() == 0 {
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                    let mut wrote_any = wrote_from_preroll;
                    let mut noop_cx = Context::from_waker(std::task::Waker::noop());
                    while *remaining > 0 && buf.remaining() > 0 {
                        let want = (*remaining as usize).min(buf.remaining());
                        let is_masked = *masked;
                        let mk = *mask_key;
                        let mpos = *mask_pos;
                        let poll_cx: &mut Context<'_> = if wrote_any { &mut noop_cx } else { cx };
                        let poll_res = {
                            let dst = buf.initialize_unfilled_to(want);
                            let mut sub = ReadBuf::new(dst);
                            let r = Pin::new(raw.as_mut()).poll_read(poll_cx, &mut sub);
                            if let Poll::Ready(Ok(())) = &r {
                                let n = sub.filled().len();
                                if n > 0 && is_masked {
                                    xor_mask_offset(&mut dst[..n], mk, mpos);
                                }
                                Ok(n)
                            } else {
                                Err(r)
                            }
                        };
                        match poll_res {
                            Ok(0) => return Poll::Ready(Ok(())),
                            Ok(n) => {
                                if is_masked {
                                    *mask_pos = (*mask_pos + n) & 3;
                                }
                                buf.advance(n);
                                *remaining -= n as u64;
                                wrote_any = true;
                                if *remaining == 0 {
                                    *raw_read_state = RawReadState::Idle;
                                    return Poll::Ready(Ok(()));
                                }
                            }
                            Err(Poll::Ready(Err(e))) => {
                                if wrote_any {
                                    *read_error = Some(e);
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(e));
                            }
                            Err(Poll::Pending) => {
                                if wrote_any {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Pending;
                            }
                            Err(Poll::Ready(Ok(()))) => unreachable!(),
                        }
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl WsByteStream {
    /// Shared write implementation for both `poll_write` and `poll_write_vectored`.
    fn poll_write_slices(
        &mut self,
        cx: &mut Context<'_>,
        slices: &[&[u8]],
        total_input: usize,
    ) -> Poll<io::Result<usize>> {
        let WsByteStream {
            inner: raw,
            write_buf,
            write_pos,
            needs_flush,
            pending_frame_payload_len,
            drain_completed,
            client_mode,
            ..
        } = self;

        if *drain_completed {
            *drain_completed = false;
            return Poll::Ready(Ok((*pending_frame_payload_len).min(total_input)));
        }

        if *needs_flush {
            let remaining = &write_buf[*write_pos..];
            return match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    *needs_flush = false;
                    *drain_completed = false;
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Poll::Ready(Ok(n)) => {
                    *write_pos += n;
                    if *write_pos >= write_buf.len() {
                        *write_pos = 0;
                        *needs_flush = false;
                        write_buf.clear();
                        Poll::Ready(Ok((*pending_frame_payload_len).min(total_input)))
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
            };
        }

        if total_input == 0 {
            return Poll::Ready(Ok(0));
        }

        let payload_len: usize = slices.iter().map(|s| s.len()).sum();
        if payload_len == 0 {
            return Poll::Ready(Ok(0));
        }

        if !*client_mode && raw.is_write_vectored() {
            let mut hdr = [0u8; 10];
            let hdr_len = Self::build_server_frame_header(&mut hdr, payload_len);
            let total_len = hdr_len + payload_len;
            let mut written = 0usize;

            let stash_tail = |write_buf: &mut Vec<u8>, skip_bytes: usize| {
                write_buf.clear();
                write_buf.reserve(total_len.saturating_sub(skip_bytes));
                let mut skip = skip_bytes;
                if skip < hdr_len {
                    write_buf.extend_from_slice(&hdr[skip..hdr_len]);
                    skip = 0;
                } else {
                    skip -= hdr_len;
                }
                for s in slices {
                    if skip >= s.len() {
                        skip -= s.len();
                    } else {
                        write_buf.extend_from_slice(&s[skip..]);
                        skip = 0;
                    }
                }
            };

            loop {
                let mut rem_iovecs: [IoSlice<'_>; MAX_WS_VECT_SLICES + 1] =
                    [IoSlice::new(&[]); MAX_WS_VECT_SLICES + 1];
                let mut rem_count = 0usize;
                let mut skip = written;
                if skip < hdr_len {
                    rem_iovecs[rem_count] = IoSlice::new(&hdr[skip..hdr_len]);
                    rem_count += 1;
                    skip = 0;
                } else {
                    skip -= hdr_len;
                }
                for s in slices {
                    if skip >= s.len() {
                        skip -= s.len();
                    } else {
                        rem_iovecs[rem_count] = IoSlice::new(&s[skip..]);
                        rem_count += 1;
                        skip = 0;
                    }
                }

                match Pin::new(raw.as_mut()).poll_write_vectored(cx, &rem_iovecs[..rem_count]) {
                    Poll::Ready(Ok(0)) => {
                        if written == 0 {
                            stash_tail(write_buf, 0);
                            *pending_frame_payload_len = payload_len;
                            *write_pos = 0;
                            *needs_flush = true;
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        written += n;
                        if written >= total_len {
                            return Poll::Ready(Ok(payload_len));
                        }
                    }
                    Poll::Pending => {
                        if written == 0 {
                            return Poll::Pending;
                        }
                        stash_tail(write_buf, written);
                        *pending_frame_payload_len = payload_len;
                        *write_pos = 0;
                        *needs_flush = true;
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
        }

        Self::build_vectored_frame_into(write_buf, slices, payload_len, *client_mode);
        *pending_frame_payload_len = payload_len;
        match Pin::new(raw.as_mut()).poll_write(cx, write_buf) {
            Poll::Ready(Ok(n)) if n >= write_buf.len() => {
                write_buf.clear();
                Poll::Ready(Ok(payload_len))
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
    }
}

impl AsyncWrite for WsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, &[buf], buf.len())
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let max_payload = MAX_WS_FRAME_PAYLOAD as usize;
        let mut chosen: [&[u8]; MAX_WS_VECT_SLICES] = [&[]; MAX_WS_VECT_SLICES];
        let mut count = 0usize;
        let mut payload_len = 0usize;
        let mut total_input = 0usize;
        for slice in bufs {
            let s: &[u8] = slice;
            total_input += s.len();
            if s.is_empty() || count >= MAX_WS_VECT_SLICES {
                continue;
            }
            if count == 0 {
                chosen[0] = s;
                count = 1;
                payload_len = s.len();
            } else if payload_len < max_payload {
                let take = s.len().min(max_payload - payload_len);
                chosen[count] = &s[..take];
                count += 1;
                payload_len += take;
            }
        }
        self.poll_write_slices(cx, &chosen[..count], total_input)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let WsByteStream {
            inner: raw,
            write_buf,
            write_pos,
            needs_flush,
            drain_completed,
            ..
        } = &mut *self;
        if *needs_flush {
            let remaining = &write_buf[*write_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
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
                    write_buf.clear();
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
        Pin::new(raw.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let WsByteStream {
            inner: raw,
            write_buf,
            write_pos,
            needs_flush,
            close_sent,
            pending_control_write,
            pending_control_pos,
            pending_control_is_close,
            client_mode,
            ..
        } = &mut *self;

        if *needs_flush {
            let remaining = &write_buf[*write_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    *write_pos = 0;
                    *needs_flush = false;
                    write_buf.clear();
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
                        write_buf.clear();
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Drain a stashed control frame first. It may be a Pong/Close reply
        // stashed by `poll_read` or a partial shutdown Close; `pending_control_is_close`
        // tracks whether it is a Close frame even when only a tail slice was stashed.
        if !pending_control_write.is_empty() {
            let remaining = &pending_control_write[*pending_control_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    pending_control_write.clear();
                    *pending_control_pos = 0;
                    *pending_control_is_close = false;
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
                        if *pending_control_is_close {
                            *pending_control_is_close = false;
                            *close_sent = true;
                        }
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !*close_sent {
            let mut stack_frame = [0u8; 131];
            let flen =
                build_control_frame_stack(&mut stack_frame, 0x08, &[0x03, 0xe8], *client_mode);
            match poll_write_control(
                raw,
                cx,
                pending_control_write,
                pending_control_pos,
                &stack_frame[..flen],
            ) {
                Poll::Ready(Ok(true)) => {
                    *close_sent = true;
                }
                Poll::Ready(Ok(false)) => {
                    *pending_control_is_close = true;
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => unreachable!("poll_write_control never returns Pending"),
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
                self.prepend = Vec::new();
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
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
