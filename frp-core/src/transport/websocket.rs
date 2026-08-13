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
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{AsyncReadWrite, Transport};

/// Maximum WebSocket frame payload accepted by the raw decoder. The V2
/// framing layer permits 64 KiB messages, so the transport must not clamp
/// below that; the V1 10 KiB limit stays enforced by `protocol.rs`.
/// +128 bytes covers the V2 AEAD overhead (AES-256-GCM tag + nonce) so an
/// encrypted V2 frame at the payload cap is not rejected by the transport.
const MAX_WS_FRAME_PAYLOAD: u64 = crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128;

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
            // XOR the payload with the mask key (RFC 6455 §5.3).
            let start = frame.len();
            frame.extend_from_slice(buf);
            xor_mask(&mut frame[start..], mask);
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
) -> Poll<io::Result<()>> {
    *raw_read_state = RawReadState::Idle;
    match opcode {
        0x00..=0x02 => {
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
            buf.put_slice(&payload[..n]);
            if n < payload.len() {
                *read_buf = payload[n..].to_vec();
                *read_pos = 0;
            }
            Poll::Ready(Ok(()))
        }
        0x08 => {
            let _ = Pin::new(raw.as_mut()).poll_write(cx, &[0x88, 0x02, 0x03, 0xe8]);
            Poll::Ready(Ok(()))
        }
        0x09 => {
            // RFC 6455 §5.5: control frame payload MUST be ≤125 bytes.
            // Extended length encoding is disallowed for control frames.
            let pong_payload = if payload.len() > 125 {
                tracing::warn!(
                    "WS pong payload {} bytes exceeds 125-byte limit, truncating",
                    payload.len()
                );
                &payload[..125]
            } else {
                payload
            };
            let mut pong = [0u8; 128];
            // RFC 6455 caps control-frame payloads at 125 bytes, so the
            // stack buffer always fits: 2-byte header + payload.
            pong[0] = 0x8a;
            pong[1] = pong_payload.len() as u8;
            pong[2..2 + pong_payload.len()].copy_from_slice(pong_payload);
            let pong_len = 2 + pong_payload.len();
            if let Poll::Ready(Err(e)) = Pin::new(raw.as_mut()).poll_write(cx, &pong[..pong_len]) {
                tracing::debug!(error = %e, "WS pong write failed");
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
            client_mode,
            raw_read_state: RawReadState::Idle,
            raw_frame_opcode: 0,
            raw_frame_masked: false,
            raw_frame_mask_key: [0u8; 4],
            raw_frame_payload_len: 0,
            raw_payload_buf: Vec::new(),
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
            client_mode: _,
            raw_read_state,
            raw_frame_opcode,
            raw_frame_masked,
            raw_frame_mask_key,
            raw_frame_payload_len,
            raw_payload_buf,
        } = this;

        let raw = inner;
        loop {
            match raw_read_state {
                RawReadState::Idle => {
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
                                return Poll::Pending;
                            }
                            let opcode = head[0] & 0x0f;
                            let masked = (head[1] & 0x80) != 0;
                            let raw_len = (head[1] & 0x7f) as u64;
                            *raw_frame_opcode = opcode;
                            *raw_frame_masked = masked;
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
            client_mode,
            ..
        } = this;

        let raw = inner;
        {
            if !*needs_flush && !buf.is_empty() {
                // Build the frame directly into write_buf (capacity reused
                // across chunks — no per-chunk frame allocation), then try
                // to flush it immediately.
                WsByteStream::build_frame_into(write_buf, buf, *client_mode);
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
                // Continue writing a partially-flushed frame. When the old
                // frame finishes, the CURRENT buf has NOT been written — it
                // must not be reported as written (returning Ok(buf.len())
                // here would make write_all drop it → data loss). Return
                // Pending; the caller re-polls with the same buf, which then
                // builds and writes a fresh frame.
                let remaining = &write_buf[*write_pos..];
                match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                    Poll::Ready(Ok(0)) => {
                        // `remaining` is non-empty here (needs_flush is only
                        // set while frame bytes remain), so zero progress is a
                        // fatal write-zero — self-waking and re-polling would
                        // spin at 100% CPU until the inner makes progress.
                        // Mirrors CipherWriter's WriteZero handling.
                        *needs_flush = false;
                        Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                    }
                    Poll::Ready(Ok(n)) => {
                        *write_pos += n;
                        if *write_pos >= write_buf.len() {
                            *write_pos = 0;
                            *needs_flush = false;
                            cx.waker().wake_by_ref();
                        } else {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                    Poll::Ready(Err(e)) => {
                        *needs_flush = false;
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
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Poll::Ready(Ok(n)) => {
                    *write_pos += n;
                    if *write_pos >= write_buf.len() {
                        *write_pos = 0;
                        *needs_flush = false;
                        Poll::Ready(Ok(()))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
                Poll::Ready(Err(e)) => {
                    *needs_flush = false;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let raw = &mut *self.inner;
        let _ = Pin::new(&mut *raw).poll_write(cx, &[0x88, 0x02, 0x03, 0xe8]);
        Pin::new(&mut *raw).poll_shutdown(cx)
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

    /// Zero-length data frames must be consumed without surfacing a 0-byte
    /// read (which tokio treats as EOF and would tear the tunnel down).
    /// A zero-length frame followed by a real frame must deliver the real
    /// frame's payload.
    #[tokio::test]
    async fn ws_zero_length_frame_is_swallowed_not_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut server_io, client_io) = tokio::io::duplex(8192);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

        // Zero-length BINARY frame, then a real frame.
        server_io.write_all(&[0x82, 0x00]).await.unwrap();
        let payload = b"after-zero-frame";
        server_io
            .write_all(&ws_binary_frame(payload))
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
        // 0x82 with extended length 0) must behave the same.
        server_io.write_all(&[0x82, 126, 0, 0]).await.unwrap();
        let payload2 = b"second-payload";
        server_io
            .write_all(&ws_binary_frame(payload2))
            .await
            .unwrap();
        let n2 = ws.read(&mut out).await.unwrap();
        assert_eq!(n2, payload2.len());
        assert_eq!(&out[..n2], payload2);
    }

    #[tokio::test]
    async fn ws_raw_accepts_v2_sized_frames_and_rejects_oversized() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

        // Between the old 14 KiB clamp and the V2 64 KiB cap: the WS
        // transport must accept it; V1 enforcement happens in protocol.rs.
        let payload = vec![0x5a; 20 * 1024];
        server_io
            .write_all(&ws_binary_frame(&payload))
            .await
            .unwrap();
        let mut out = vec![0u8; payload.len()];
        let n = ws.read(&mut out).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&out[..n], &payload[..]);

        // Exactly 64 KiB is the V2 limit and must pass the WS decoder.
        let big = vec![0x6b; 64 * 1024];
        server_io.write_all(&ws_binary_frame(&big)).await.unwrap();
        let mut big_out = vec![0u8; big.len()];
        let n2 = ws.read(&mut big_out).await.unwrap();
        assert_eq!(n2, big.len());
        assert_eq!(&big_out[..n2], &big[..]);

        // A V2 frame at the cap plus AEAD overhead (128 bytes) is accepted —
        // the transport must not clamp encrypted V2 frames below the cap.
        let aead_padded = vec![0x6c; 64 * 1024 + 128];
        server_io
            .write_all(&ws_binary_frame(&aead_padded))
            .await
            .unwrap();
        let mut padded_out = vec![0u8; aead_padded.len()];
        let n3 = ws.read(&mut padded_out).await.unwrap();
        assert_eq!(n3, aead_padded.len());
        assert_eq!(&padded_out[..n3], &aead_padded[..]);

        // One byte over the cap + AEAD overhead is rejected at the transport.
        let huge = vec![0x6c; 64 * 1024 + 129];
        server_io.write_all(&ws_binary_frame(&huge)).await.unwrap();
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
}
