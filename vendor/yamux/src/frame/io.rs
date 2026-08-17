// Copyright (c) 2019 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

use super::{
    header::{self, HeaderDecodeError},
    Frame,
};
use crate::connection::Id;
use futures::{prelude::*, ready};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

/// Maximum Yamux frame body length
///
/// Limits the amount of bytes a remote can cause the local node to allocate at once when reading.
///
/// Chosen based on intuition in past iterations.
const MAX_FRAME_BODY_LEN: usize = crate::MIB;

/// Hard cap on the number of frames buffered in the write queue.
///
/// `start_send` rejects frames beyond this cap, so the queue cannot grow
/// without bound even if a caller skips the drain-loop guard. `Connection`'s
/// receiver drain loop gates itself on `write_queue_len() <
/// MAX_WRITE_QUEUE_FRAMES`, so in practice the cap is never hit.
///
/// Worst-case buffered write data: `write_queue` holds up to 256 frames
/// (<= 32 KiB each, ~8 MiB) while `flush_buf` can simultaneously hold one
/// fully-encoded batch of up to 256 frames (~8 MiB) stuck behind an
/// unreadable socket — so ~16 MiB per connection, not ~8 MiB.
pub(crate) const MAX_WRITE_QUEUE_FRAMES: usize = 256;

/// A [`Stream`] and writer of [`Frame`] values.
#[derive(Debug)]
pub(crate) struct Io<T> {
    id: Id,
    io: T,
    /// Frames handed to the sink but not yet written to `io`.
    ///
    /// Batching: `poll_ready` drains this queue into a single contiguous
    /// `flush_buf` and writes it with as few `poll_write` calls as possible.
    /// Queue order == `start_send` order == frame order on the wire.
    write_queue: VecDeque<Frame<()>>,
    /// Contiguous batch of encoded frames (each frame's 12-byte header
    /// immediately followed by its body) currently being written to `io`.
    flush_buf: Vec<u8>,
    /// Number of bytes of `flush_buf` already handed to `io`.
    flush_offset: usize,
    /// Reusable read buffer. Allocated once, grown to a 64 KiB steady state,
    /// reused for the lifetime of the connection.
    read_buf: Vec<u8>,
    /// Index of the first unprocessed byte in `read_buf`.
    read_start: usize,
    /// Index one past the last byte read from `io` into `read_buf`.
    read_end: usize,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Io<T> {
    pub(crate) fn new(id: Id, io: T) -> Self {
        Io {
            id,
            io,
            write_queue: VecDeque::new(),
            flush_buf: Vec::new(),
            flush_offset: 0,
            read_buf: Vec::new(),
            read_start: 0,
            read_end: 0,
        }
    }

    /// Number of frames currently buffered in the write queue.
    pub(crate) fn write_queue_len(&self) -> usize {
        self.write_queue.len()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Sink<Frame<()>> for Io<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = Pin::into_inner(self);
        loop {
            // A queued frame is written as one contiguous `flush_buf`, so a
            // single `poll_write` call carries many frames. Header and body of
            // each frame stay adjacent and frames stay in queue order, so the
            // byte stream on the wire is identical to stock yamux's one-frame
            // header-then-body writes.
            if this.flush_offset == this.flush_buf.len() && !this.write_queue.is_empty() {
                this.flush_buf.clear();
                let n_frames = this.write_queue.len();
                while let Some(f) = this.write_queue.pop_front() {
                    this.flush_buf
                        .extend_from_slice(&header::encode(f.header()));
                    // Only `Data` frames carry a body; all other tags encode
                    // their payload in the 12-byte header itself.
                    if f.header().tag() == header::Tag::Data {
                        this.flush_buf.extend_from_slice(&f.body);
                    }
                }
                log::trace!(
                    "{}: writing {} frames ({} bytes) as one batch",
                    this.id,
                    n_frames,
                    this.flush_buf.len()
                );
                this.flush_offset = 0;
            }

            if this.flush_offset < this.flush_buf.len() {
                match Pin::new(&mut this.io).poll_write(cx, &this.flush_buf[this.flush_offset..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        if n > this.flush_buf.len() - this.flush_offset {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "Writer returned invalid write count n={n}: {} > {}",
                                this.flush_offset + n,
                                this.flush_buf.len(),
                            ))));
                        }
                        this.flush_offset += n;
                    }
                }
            } else {
                // Flush buffer drained and nothing queued. The batch-build
                // branch above always drains a non-empty queue before this
                // point, so a non-empty queue can never be observed here; the
                // queue cap is enforced in `start_send` instead.
                return Poll::Ready(Ok(()));
            }
        }
    }

    fn start_send(self: Pin<&mut Self>, f: Frame<()>) -> Result<(), Self::Error> {
        // Enforce the queue cap here: the drain loop's
        // `write_queue_len() < MAX_WRITE_QUEUE_FRAMES` guard and Closing's
        // poll_ready-then-start_send pattern never hit this, but a future
        // caller that skips them gets a hard error instead of unbounded
        // queue growth.
        let this = self.get_mut();
        if this.write_queue.len() >= MAX_WRITE_QUEUE_FRAMES {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "yamux write queue full",
            ));
        }
        this.write_queue.push_back(f);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = Pin::into_inner(self);
        ready!(this.poll_ready_unpin(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = Pin::into_inner(self);
        ready!(this.poll_ready_unpin(cx))?;
        Pin::new(&mut this.io).poll_close(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Stream for Io<T> {
    type Item = Result<Frame<()>, FrameDecodeError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        loop {
            // Compact the buffer once the consumed prefix grows past 32 KiB
            // (or whenever fewer than a full header's worth of unprocessed
            // bytes remain): everything still needed moves to the front, so
            // `read_buf` is reused for the connection lifetime.
            if this.read_start == this.read_end {
                this.read_start = 0;
                this.read_end = 0;
            } else if this.read_start > 0
                && (this.read_start >= 32 * 1024
                    || this.read_end - this.read_start < header::HEADER_SIZE)
            {
                this.read_buf.copy_within(this.read_start..this.read_end, 0);
                this.read_end -= this.read_start;
                this.read_start = 0;
            }

            // Make sure a full header is buffered.
            if this.read_end - this.read_start < header::HEADER_SIZE {
                if this.read_buf.len() < this.read_start + header::HEADER_SIZE {
                    this.read_buf
                        .resize(this.read_start + header::HEADER_SIZE, 0);
                }
                let n = match ready!(
                    Pin::new(&mut this.io).poll_read(cx, &mut this.read_buf[this.read_end..])
                )? {
                    0 => {
                        if this.read_end - this.read_start == 0 {
                            return Poll::Ready(None);
                        }
                        let e = FrameDecodeError::Io(io::ErrorKind::UnexpectedEof.into());
                        return Poll::Ready(Some(Err(e)));
                    }
                    n => n,
                };
                this.read_end += n;
                continue;
            }

            let mut header_buf = [0; header::HEADER_SIZE];
            header_buf.copy_from_slice(
                &this.read_buf[this.read_start..this.read_start + header::HEADER_SIZE],
            );
            let header = match header::decode(&header_buf) {
                Ok(hd) => hd,
                Err(e) => return Poll::Ready(Some(Err(e.into()))),
            };

            log::trace!("{}: read: {}", this.id, header);

            if header.tag() != header::Tag::Data {
                this.read_start += header::HEADER_SIZE;
                return Poll::Ready(Some(Ok(Frame::new(header))));
            }

            let body_len = header.len().val() as usize;

            if body_len > MAX_FRAME_BODY_LEN {
                return Poll::Ready(Some(Err(FrameDecodeError::FrameTooLarge(body_len))));
            }

            // Make sure the full frame body is buffered.
            if this.read_end - this.read_start < header::HEADER_SIZE + body_len {
                let target = this.read_start + header::HEADER_SIZE + body_len;
                if this.read_buf.len() < target {
                    let grow = target.max(64 * 1024);
                    this.read_buf.resize(grow, 0);
                }
                let n = match ready!(
                    Pin::new(&mut this.io).poll_read(cx, &mut this.read_buf[this.read_end..])
                )? {
                    0 => {
                        let e = FrameDecodeError::Io(io::ErrorKind::UnexpectedEof.into());
                        return Poll::Ready(Some(Err(e)));
                    }
                    n => n,
                };
                this.read_end += n;
                continue;
            }

            // The `to_vec()` is ONE deliberate memcpy per frame — up to 32 KiB
            // with the split_send_size used by frp-core, the largest body this
            // crate normally handles — the price of reusing one buffer. It
            // buys back >= 2 syscalls + 1 waker round trip per frame, which
            // dominates loopback ping-pong latency. Stock yamux avoided the
            // copy but paid per-frame allocations and tiny 12-byte header
            // reads.
            let body = this.read_buf[this.read_start + header::HEADER_SIZE
                ..this.read_start + header::HEADER_SIZE + body_len]
                .to_vec();
            this.read_start += header::HEADER_SIZE + body_len;
            return Poll::Ready(Some(Ok(Frame { header, body })));
        }
    }
}

/// Possible errors while decoding a message frame.
#[non_exhaustive]
#[derive(Debug)]
pub enum FrameDecodeError {
    /// An I/O error.
    Io(io::Error),
    /// Decoding the frame header failed.
    Header(HeaderDecodeError),
    /// A data frame body length is larger than the configured maximum.
    FrameTooLarge(usize),
}

impl std::fmt::Display for FrameDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FrameDecodeError::Io(e) => write!(f, "i/o error: {e}"),
            FrameDecodeError::Header(e) => write!(f, "decode error: {e}"),
            FrameDecodeError::FrameTooLarge(n) => write!(f, "frame body is too large ({n})"),
        }
    }
}

impl std::error::Error for FrameDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameDecodeError::Io(e) => Some(e),
            FrameDecodeError::Header(e) => Some(e),
            FrameDecodeError::FrameTooLarge(_) => None,
        }
    }
}

impl From<std::io::Error> for FrameDecodeError {
    fn from(e: std::io::Error) -> Self {
        FrameDecodeError::Io(e)
    }
}

impl From<HeaderDecodeError> for FrameDecodeError {
    fn from(e: HeaderDecodeError) -> Self {
        FrameDecodeError::Header(e)
    }
}
