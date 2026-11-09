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
use futures::{
    io::{ReadHalf, WriteHalf},
    prelude::*,
    ready, Sink,
};
use std::{
    fmt, io,
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
/// frp-rs patch: the read and write halves are separate types so the write
/// half can be moved behind a lock and driven by whoever owns a stream (see
/// `frame::Writer`). Reads stay with the connection driver.
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

/// The write half of a connection's I/O: frame encoding and the body-pool
/// return path.
#[derive(Debug)]
pub(crate) struct Writer<W> {
    id: Id,
    io: W,
    write_state: WriteState,
    /// frp-rs patch: connection-scoped body-buffer pool (send + read side).
    /// A fully written data-frame body is returned here (WriteState::Body
    /// completion) and `Stream::poll_write` draws from it on the send path.
    body_pool: Arc<ArrayQueue<Vec<u8>>>,
    /// frp-rs patch: the configured send-split size. A fully-written body at
    /// or below this size is returned to `body_pool`; larger buffers are
    /// dropped (best-effort pool — a pool must not grow its stored buffers
    /// arbitrarily large, or reuse would pin oversized allocations). Using
    /// the CONFIG value (not `DEFAULT_SPLIT_SEND_SIZE`) matters: frp-rs sets
    /// `split_send_size` to its bridge buffer (32KiB default, 64KiB cap), so
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
            body_pool,
            split_send_size,
        }
    }
}

/// A [`Stream`] and writer of [`Frame`] values over a single I/O object.
///
/// Thin façade over [`Reader`] and [`Writer`] for the `Connection::new` path;
/// the socket is split with [`AsyncReadExt::split`]. The split halves are only
/// ever polled from the same task here, so the split's internal lock is never
/// contended.
pub(crate) struct Io<T> {
    reader: Reader<ReadHalf<T>>,
    writer: Writer<WriteHalf<T>>,
}

impl<T> fmt::Debug for Io<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // The split halves only render their socket when `T: Debug`; the
        // connection id is the useful part.
        write!(f, "Io({})", self.reader.id)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Io<T> {
    pub(crate) fn new(
        id: Id,
        io: T,
        body_pool: Arc<ArrayQueue<Vec<u8>>>,
        split_send_size: usize,
    ) -> Self {
        let (read, write) = io.split();
        Io {
            reader: Reader::new(id, read, body_pool.clone()),
            writer: Writer::new(id, write, body_pool, split_send_size),
        }
    }
}

impl<T: AsyncRead + Unpin> Stream for Io<T> {
    type Item = Result<Frame<()>, FrameDecodeError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().reader).poll_next(cx)
    }
}

impl<T: AsyncWrite + Unpin> Sink<Frame<()>> for Io<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, f: Frame<()>) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().writer).start_send(f)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_close(cx)
    }
}

/// The stages of writing a new `Frame`.
enum WriteState {
    Init,
    Header {
        header: [u8; header::HEADER_SIZE],
        buffer: Vec<u8>,
        offset: usize,
    },
    Body {
        buffer: Vec<u8>,
        offset: usize,
    },
    Poisoned,
}

impl fmt::Debug for WriteState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WriteState::Init => f.write_str("(WriteState::Init)"),
            WriteState::Header { offset, .. } => {
                write!(f, "(WriteState::Header (offset {offset}))")
            }
            WriteState::Body { offset, buffer } => {
                write!(
                    f,
                    "(WriteState::Body (offset {}) (buffer-len {}))",
                    offset,
                    buffer.len()
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
                WriteState::Header {
                    header,
                    buffer,
                    ref mut offset,
                } => match Pin::new(&mut this.io).poll_write(cx, &header[*offset..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        *offset += n;

                        if *offset > header.len() {
                            let err = io::Error::other(format!(
                                "Writer header returned invalid write count n={n}: {offset} > {} ",
                                header.len(),
                            ));

                            this.write_state = WriteState::Poisoned;

                            return Poll::Ready(Err(err));
                        }

                        if *offset == header.len() {
                            if !buffer.is_empty() {
                                let buffer = std::mem::take(buffer);
                                this.write_state = WriteState::Body { buffer, offset: 0 };
                            } else {
                                this.write_state = WriteState::Init;
                            }
                        }
                    }
                },
                WriteState::Body {
                    buffer,
                    ref mut offset,
                } => match Pin::new(&mut this.io).poll_write(cx, &buffer[*offset..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        *offset += n;

                        if *offset > buffer.len() {
                            let err = io::Error::other(format!(
                                "Writer body returned invalid write count n={n}: {offset} > {} ",
                                buffer.len(),
                            ));

                            this.write_state = WriteState::Poisoned;

                            return Poll::Ready(Err(err));
                        }

                        if *offset == buffer.len() {
                            let buffer = std::mem::take(buffer);
                            this.write_state = WriteState::Init;
                            // frp-rs patch: the body is fully on the wire and
                            // exclusively owned here — return it to the
                            // connection-scoped pool for reuse by the next
                            // `Stream::poll_write`. Best-effort: a full pool
                            // or a buffer above the default split-send size
                            // (custom `split_send_size`) is simply dropped.
                            // Buffers lost to WriteZero / Poisoned / teardown
                            // are fine — the pool dies with the connection.
                            if !buffer.is_empty()
                                && buffer.capacity() <= this.split_send_size
                            {
                                let _ = this.body_pool.push(buffer);
                            }
                        }
                    }
                },
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
        self.get_mut().write_state = WriteState::Header {
            header,
            buffer,
            offset: 0,
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
                            let mut buf = this.body_pool.pop().unwrap_or_default();
                            buf.resize(body_len, 0);
                            buf
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
