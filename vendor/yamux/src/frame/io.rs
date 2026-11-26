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
use crossbeam_queue::ArrayQueue;
use futures::{prelude::*, ready, Sink};
use std::{
    collections::VecDeque,
    fmt,
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// Maximum Yamux frame body length
///
/// Limits the amount of bytes a remote can cause the local node to allocate at once when reading.
///
/// Chosen based on intuition in past iterations.
const MAX_FRAME_BODY_LEN: usize = crate::MIB;

/// The read half of a connection's I/O: frame decoding plus the read-side
/// body-pool bookkeeping.
///
/// frp-rs patch: the read and write halves are separate types so the I/O
/// halves can come from a `tokio::io::split`. Reads stay with the connection
/// driver (see `frame::Writer` for the write side).
#[derive(Debug)]
pub(crate) struct Reader<R> {
    id: Id,
    io: R,
    read_state: ReadState,
    /// frp-rs patch: connection-scoped body-buffer pool (send + read side).
    /// A fully written data-frame body is returned here (WriteState::Body
    /// completion) and `Stream::poll_write` draws from it on the send path;
    /// read bodies are drawn at ReadState::Body init and returned once the
    /// chunk is fully consumed in `Stream::poll_read`, removing the
    /// per-chunk `Vec` allocation + zero-fill in both directions.
    body_pool: Arc<ArrayQueue<Vec<u8>>>,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub(crate) fn new(id: Id, io: R, body_pool: Arc<ArrayQueue<Vec<u8>>>) -> Self {
        Reader {
            id,
            io,
            read_state: ReadState::Init,
            body_pool,
        }
    }
}

/// The write half of a connection's I/O: frame encoding, the body-pool
/// return path, and the outbound frame queues.
///
/// frp-rs patch: the connection driver owns the `Writer` and writes frames
/// directly. Only one frame is ever in flight (`WriteState`): a frame's header
/// and body must reach the socket contiguously, so a new frame is only started
/// once the previous one is fully written. Header and body are written as one
/// vectored write (`writev`) — one syscall per frame. `queue` is used only by
/// `Closing` to drain remaining frames in FIFO order.
#[derive(Debug)]
pub(crate) struct Writer<W> {
    id: Id,
    io: W,
    write_state: WriteState,
    /// Pending frames queued during graceful close ([`Closing`]).
    queue: VecDeque<Frame<()>>,
    /// frp-rs patch: connection-scoped body-buffer pool (send + read side).
    /// A fully written data-frame body is returned here (WriteState::Body
    /// completion) and `Stream::poll_write` draws from it on the send path.
    body_pool: Arc<ArrayQueue<Vec<u8>>>,
    /// frp-rs patch: the configured send-split size. A fully-written body at
    /// or below this size is returned to `body_pool`; larger buffers are
    /// dropped (best-effort pool — a pool must not grow its stored buffers
    /// arbitrarily large, or reuse would pin oversized allocations). Using
    /// the CONFIG value (not `DEFAULT_SPLIT_SEND_SIZE`) matters: frp-rs sets
    /// `split_send_size` to its bridge buffer (64KiB default, 64KiB cap), so
    /// bodies of that size must qualify for reuse — the DEFAULT (16KiB) gate
    /// silently disabled the send pool, leaving one fresh `Vec` per chunk.
    split_send_size: usize,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub(crate) fn new(
        id: Id,
        io: W,
        body_pool: Arc<ArrayQueue<Vec<u8>>>,
        split_send_size: usize,
    ) -> Self {
        Writer {
            id,
            io,
            write_state: WriteState::Init,
            queue: VecDeque::new(),
            body_pool,
            split_send_size,
        }
    }

    /// Queue a frame for draining by [`Closing`].
    pub(crate) fn push_data(&mut self, frame: Frame<()>) {
        self.queue.push_back(frame);
    }

    /// Whether a new frame can be started right away: nothing is in flight
    /// and nothing is queued.
    pub(crate) fn is_idle(&self) -> bool {
        matches!(self.write_state, WriteState::Init) && self.queue.is_empty()
    }

    /// Drive any in-flight frame to completion without flushing `io`.
    pub(crate) fn poll_finish_current(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self).poll_ready(cx)
    }

    /// Start sending `frame` (caller must ensure `is_idle()`) and immediately
    /// drive its vectored write without calling `io.poll_flush`.
    pub(crate) fn poll_send_frame(
        &mut self,
        cx: &mut Context<'_>,
        frame: Frame<()>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self).start_send(frame)?;
        Pin::new(self).poll_ready(cx)
    }

    /// Flush the underlying writer once a burst finishes.
    pub(crate) fn poll_flush_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self).poll_flush(cx)
    }

    /// Write every queued frame, control queue first, then flush.
    ///
    /// Returns `Pending` only when the socket is backpressured; the caller's
    /// waker is then registered with the socket and the unwritten frames stay
    /// queued (at most one of them is in flight), so the next holder of the
    /// writer finishes the job. `Ready` therefore means both queues are empty
    /// and the socket has been flushed.
    pub(crate) fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            // `start_send` requires `poll_ready` to have returned `Ready`;
            // starting a frame while another one is in flight would splice
            // the two frames' bytes together on the wire.
            if matches!(self.write_state, WriteState::Init) {
                match self.queue.pop_front() {
                    Some(frame) => Pin::new(&mut *self).start_send(frame)?,
                    // Nothing queued: write whatever is in flight and flush.
                    None => {
                        ready!(Pin::new(&mut *self).poll_flush(cx))?;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            ready!(Pin::new(&mut *self).poll_ready(cx))?;
        }
    }
}

/// The stages of writing a new `Frame`.
///
/// frp-rs patch: a frame's header and body are handed to the socket as ONE
/// vectored write, so a 64 KiB data frame costs one `sendmsg` instead of a
/// header `write` plus a body `write`. The two offsets record how much of
/// each slice the socket has accepted: a vectored write may stop anywhere,
/// including part-way through the 12-byte header.
enum WriteState {
    Init,
    Frame {
        header: [u8; header::HEADER_SIZE],
        header_offset: usize,
        body: Vec<u8>,
        body_offset: usize,
    },
    Poisoned,
}

impl fmt::Debug for WriteState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WriteState::Init => f.write_str("(WriteState::Init)"),
            WriteState::Frame {
                header_offset,
                body,
                body_offset,
                ..
            } => {
                write!(
                    f,
                    "(WriteState::Frame (header-offset {}) (body-offset {} of {}))",
                    header_offset,
                    body_offset,
                    body.len()
                )
            }
            WriteState::Poisoned => f.write_str("(WriteState::Poisoned)"),
        }
    }
}

impl<W: AsyncWrite + Unpin> Sink<Frame<()>> for Writer<W> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = Pin::into_inner(self);
        loop {
            log::trace!("{}: write: {:?}", this.id, this.write_state);
            match &mut this.write_state {
                WriteState::Init => return Poll::Ready(Ok(())),
                WriteState::Frame {
                    header,
                    ref mut header_offset,
                    body,
                    ref mut body_offset,
                } => {
                    // Only non-empty slices are offered to the socket: an
                    // empty leading slice would let a vectored write report
                    // progress it did not make.
                    let head = &header[*header_offset..];
                    let tail = &body[*body_offset..];
                    let slices = [IoSlice::new(head), IoSlice::new(tail)];
                    let bufs: &[IoSlice<'_>] = match (head.is_empty(), tail.is_empty()) {
                        (false, false) => &slices[..],
                        (false, true) => &slices[..1],
                        (true, false) => &slices[1..],
                        // Both slices are fully written; the frame completed
                        // on the write that emptied them.
                        (true, true) => {
                            this.write_state = WriteState::Init;
                            continue;
                        }
                    };
                    match Pin::new(&mut this.io).poll_write_vectored(cx, bufs) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(n)) => {
                            if n == 0 {
                                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                            }
                            if n > head.len() + tail.len() {
                                let err = io::Error::other(format!(
                                    "Writer returned invalid write count n={n}: {} > {}",
                                    n,
                                    head.len() + tail.len(),
                                ));

                                this.write_state = WriteState::Poisoned;

                                return Poll::Ready(Err(err));
                            }
                            if n < head.len() {
                                // Header not yet complete: keep the frame in
                                // flight and let the caller poll again.
                                *header_offset += n;
                                continue;
                            }
                            let body_n = n - head.len();
                            *header_offset = header.len();
                            *body_offset += body_n;
                            debug_assert!(*body_offset <= body.len());
                            if *body_offset == body.len() {
                                let buffer = std::mem::take(body);
                                this.write_state = WriteState::Init;
                                // frp-rs patch: the body is fully on the wire
                                // and exclusively owned here — return it to
                                // the connection-scoped pool for reuse by the
                                // next `Stream::poll_write`. Best-effort: a
                                // full pool or a buffer above the configured
                                // split size is simply dropped. Buffers lost
                                // to WriteZero / Poisoned / teardown are fine
                                // — the pool dies with the connection.
                                if !buffer.is_empty()
                                    && buffer.capacity() <= this.split_send_size
                                {
                                    let _ = this.body_pool.push(buffer);
                                }
                            }
                        }
                    }
                }
                WriteState::Poisoned => {
                    return Poll::Ready(Err(io::Error::other(
                        "Sink is in poisoned state due to previous write error",
                    )))
                }
            }
        }
    }

    fn start_send(self: Pin<&mut Self>, f: Frame<()>) -> Result<(), Self::Error> {
        let header = header::encode(&f.header);
        let buffer = f.body;
        self.get_mut().write_state = WriteState::Frame {
            header,
            header_offset: 0,
            body: buffer,
            body_offset: 0,
        };
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

/// The stages of reading a new `Frame`.
enum ReadState {
    /// Initial reading state.
    Init,
    /// Reading the frame header.
    Header {
        offset: usize,
        buffer: [u8; header::HEADER_SIZE],
    },
    /// Reading the frame body.
    Body {
        header: header::Header<()>,
        offset: usize,
        buffer: Vec<u8>,
    },
}

impl<R: AsyncRead + Unpin> Stream for Reader<R> {
    type Item = Result<Frame<()>, FrameDecodeError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        loop {
            log::trace!("{}: read: {:?}", this.id, this.read_state);
            match this.read_state {
                ReadState::Init => {
                    this.read_state = ReadState::Header {
                        offset: 0,
                        buffer: [0; header::HEADER_SIZE],
                    };
                }
                ReadState::Header {
                    ref mut offset,
                    ref mut buffer,
                } => {
                    if *offset == header::HEADER_SIZE {
                        let header = match header::decode(buffer) {
                            Ok(hd) => hd,
                            Err(e) => return Poll::Ready(Some(Err(e.into()))),
                        };

                        log::trace!("{}: read: {}", this.id, header);

                        if header.tag() != header::Tag::Data {
                            this.read_state = ReadState::Init;
                            return Poll::Ready(Some(Ok(Frame::new(header))));
                        }

                        let body_len = header.len().val() as usize;

                        if body_len > MAX_FRAME_BODY_LEN {
                            return Poll::Ready(Some(Err(FrameDecodeError::FrameTooLarge(
                                body_len,
                            ))));
                        }

                        // frp-rs patch: draw the read body from the
                        // connection-scoped pool instead of `vec![0; len]`
                        // (which also zero-fills every byte `poll_read` then
                        // overwrites). `resize` reuses a pooled allocation
                        // when it is large enough; a bigger body (peer used a
                        // larger split size) just allocates fresh. The buffer
                        // is returned to the pool in `Stream::poll_read` once
                        // the chunk is fully consumed. Empty bodies stay out
                        // of the pool (they are dropped by `Chunks::push`
                        // anyway).
                        let buffer = if body_len == 0 {
                            Vec::new()
                        } else {
                            // Under `opt-level = "z"`, `Vec::resize(n, 0)`
                            // compiles `Vec::extend_with` as a byte-by-byte
                            // loop (~20-30% of frpc CPU on tcp-mux). Use
                            // `vec![0u8; body_len]` (`alloc_zeroed`/`calloc`)
                            // on pool miss and copy from a static zero slab
                            // (`memcpy`) when growing a shorter pooled buffer.
                            static ZERO_CHUNK: [u8; 4096] = [0u8; 4096];
                            match this.body_pool.pop() {
                                Some(mut buf) if buf.capacity() >= body_len => {
                                    if buf.len() >= body_len {
                                        buf.truncate(body_len);
                                    } else {
                                        let mut need = body_len - buf.len();
                                        while need > 0 {
                                            let step = need.min(ZERO_CHUNK.len());
                                            buf.extend_from_slice(&ZERO_CHUNK[..step]);
                                            need -= step;
                                        }
                                    }
                                    buf
                                }
                                _ => vec![0u8; body_len],
                            }
                        };
                        this.read_state = ReadState::Body {
                            header,
                            offset: 0,
                            buffer,
                        };

                        continue;
                    }

                    let buf = &mut buffer[*offset..header::HEADER_SIZE];
                    match ready!(Pin::new(&mut this.io).poll_read(cx, buf))? {
                        0 => {
                            if *offset == 0 {
                                return Poll::Ready(None);
                            }
                            let e = FrameDecodeError::Io(io::ErrorKind::UnexpectedEof.into());
                            return Poll::Ready(Some(Err(e)));
                        }
                        n => *offset += n,
                    }
                }
                ReadState::Body {
                    ref header,
                    ref mut offset,
                    ref mut buffer,
                } => {
                    let body_len = header.len().val() as usize;

                    if *offset == body_len {
                        let h = header.clone();
                        let v = std::mem::take(buffer);
                        this.read_state = ReadState::Init;
                        return Poll::Ready(Some(Ok(Frame { header: h, body: v })));
                    }

                    let buf = &mut buffer[*offset..body_len];
                    match ready!(Pin::new(&mut this.io).poll_read(cx, buf))? {
                        0 => {
                            let e = FrameDecodeError::Io(io::ErrorKind::UnexpectedEof.into());
                            return Poll::Ready(Some(Err(e)));
                        }
                        n => *offset += n,
                    }
                }
            }
        }
    }
}

impl fmt::Debug for ReadState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReadState::Init => f.write_str("(ReadState::Init)"),
            ReadState::Header { offset, .. } => {
                write!(f, "(ReadState::Header (offset {offset}))")
            }
            ReadState::Body {
                header,
                offset,
                buffer,
            } => {
                write!(
                    f,
                    "(ReadState::Body (header {}) (offset {}) (buffer-len {}))",
                    header,
                    offset,
                    buffer.len()
                )
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen, QuickCheck};
    use rand::Rng;

    impl Arbitrary for Frame<()> {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut header: header::Header<()> = Arbitrary::arbitrary(g);
            let body = if header.tag() == header::Tag::Data {
                header.set_len(header.len().val() % 4096);
                let mut b = vec![0; header.len().val() as usize];
                rand::rng().fill_bytes(&mut b);
                b
            } else {
                Vec::new()
            };
            Frame { header, body }
        }
    }

    #[test]
    fn encode_decode_identity() {
        fn property(f: Frame<()>) -> bool {
            futures::executor::block_on(async move {
                let id = crate::connection::Id::next();
                let pool = Arc::new(ArrayQueue::new(1));
                let mut writer = Writer::new(
                    id,
                    Vec::new(),
                    pool.clone(),
                    crate::DEFAULT_SPLIT_SEND_SIZE,
                );
                if writer.send(f.clone()).await.is_err() {
                    return false;
                }
                if writer.flush().await.is_err() {
                    return false;
                }
                let written = writer.io;
                let mut reader =
                    Reader::new(id, futures::io::Cursor::new(written), pool);
                if let Ok(Some(x)) = reader.try_next().await {
                    x == f
                } else {
                    false
                }
            })
        }

        QuickCheck::new()
            .tests(10_000)
            .quickcheck(property as fn(Frame<()>) -> bool)
    }
}
