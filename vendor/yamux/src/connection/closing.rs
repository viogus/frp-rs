use crate::connection::{ConnWriter, StreamCommand};
use crate::frame::Frame;
use crate::tagged_stream::TaggedStream;
use crate::Result;
use crate::StreamId;
use futures::channel::mpsc;
use futures::stream::SelectAll;
use futures::{ready, Sink, StreamExt};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A [`Future`] that gracefully closes the yamux connection.
///
/// frp-rs patch: it writes through the connection's shared write lock (the
/// same one streams use for inline writes) instead of owning the socket, and
/// no longer holds the read half — it never reads.
#[must_use]
pub struct Closing {
    state: State,
    stream_receivers: SelectAll<TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>>,
    pending_frames: VecDeque<Frame<()>>,
    writer: Arc<ConnWriter>,
}

impl Closing {
    pub(crate) fn new(
        stream_receivers: SelectAll<TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>>,
        pending_frames: VecDeque<Frame<()>>,
        writer: Arc<ConnWriter>,
    ) -> Self {
        Self {
            state: State::ClosingStreamReceiver,
            stream_receivers,
            pending_frames,
            writer,
        }
    }
}

impl Future for Closing {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match this.state {
                State::ClosingStreamReceiver => {
                    for stream in this.stream_receivers.iter_mut() {
                        stream.inner_mut().close();
                    }
                    this.state = State::DrainingStreamReceiver;
                }

                State::DrainingStreamReceiver => {
                    match this.stream_receivers.poll_next_unpin(cx) {
                        Poll::Ready(Some((_, Some(StreamCommand::SendFrame(frame))))) => {
                            this.pending_frames.push_back(frame.into());
                        }
                        Poll::Ready(Some((id, Some(StreamCommand::CloseStream { ack })))) => {
                            this.pending_frames
                                .push_back(Frame::close_stream(id, ack).into());
                        }
                        Poll::Ready(Some((_, None))) => {}
                        Poll::Pending | Poll::Ready(None) => {
                            // No more frames from streams, append `Term` frame and flush them all.
                            this.pending_frames.push_back(Frame::term().into());
                            this.state = State::FlushingPendingFrames;
                            continue;
                        }
                    }
                }
                State::FlushingPendingFrames => {
                    let writer = this.writer.clone();
                    // Contended: a stream is writing inline. It closes its
                    // own sender first (above), so this is a short-lived
                    // race, and `lock_owner` registers us to be woken.
                    let Some(mut w) = writer.lock_owner(cx) else {
                        return Poll::Pending;
                    };
                    for frame in this.pending_frames.drain(..) {
                        w.push_data(frame);
                    }
                    match w.poll_drain(cx) {
                        Poll::Ready(Ok(())) => this.state = State::ClosingSocket,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                State::ClosingSocket => {
                    let writer = this.writer.clone();
                    let Some(mut w) = writer.lock_owner(cx) else {
                        return Poll::Pending;
                    };
                    ready!(Pin::new(&mut *w).poll_close(cx))?;

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

enum State {
    ClosingStreamReceiver,
    DrainingStreamReceiver,
    FlushingPendingFrames,
    ClosingSocket,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;
    use futures::FutureExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// Records writes into shared state: the write half is boxed (`'static`),
    /// so the test cannot look at a socket it handed over.
    struct Socket {
        written: Arc<Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }
    impl futures::AsyncWrite for Socket {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            assert!(!self.closed.load(Ordering::SeqCst));
            self.written
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            assert!(!self.closed.swap(true, Ordering::SeqCst));
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn pending_frames() {
        let frame_pending = Frame::data(StreamId::new(1), vec![2]).unwrap().into();
        let frame_data = Frame::data(StreamId::new(3), vec![4]).unwrap().into();
        let frame_close = Frame::close_stream(StreamId::new(5), false).into();
        let frame_close_ack = Frame::close_stream(StreamId::new(6), true).into();
        let frame_term = Frame::term().into();
        fn encode(buf: &mut Vec<u8>, frame: &Frame<()>) {
            buf.extend_from_slice(&crate::frame::header::encode(frame.header()));
            if frame.header().tag() == crate::frame::header::Tag::Data {
                buf.extend_from_slice(frame.clone().into_data().body());
            }
        }
        let mut expected_written = vec![];
        encode(&mut expected_written, &frame_pending);
        encode(&mut expected_written, &frame_data);
        encode(&mut expected_written, &frame_close);
        encode(&mut expected_written, &frame_close_ack);
        encode(&mut expected_written, &frame_term);

        let receiver = |frame: &Frame<_>, command: StreamCommand| {
            TaggedStream::new(frame.header().stream_id(), {
                let (mut tx, rx) = mpsc::channel(1);
                tx.try_send(command).unwrap();
                rx
            })
        };

        let mut stream_receivers: SelectAll<_> = Default::default();
        stream_receivers.push(receiver(
            &frame_data,
            StreamCommand::SendFrame(frame_data.clone().into_data().left()),
        ));
        stream_receivers.push(receiver(
            &frame_close,
            StreamCommand::CloseStream { ack: false },
        ));
        stream_receivers.push(receiver(
            &frame_close_ack,
            StreamCommand::CloseStream { ack: true },
        ));
        let pending_frames = vec![frame_pending];
        let written = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let socket = Socket {
            written: written.clone(),
            closed: closed.clone(),
        };
        let writer = Arc::new(ConnWriter::new(
            crate::connection::Id(0),
            Box::new(socket),
            Arc::new(crossbeam_queue::ArrayQueue::new(1)),
            crate::DEFAULT_SPLIT_SEND_SIZE,
        ));
        let mut closing = Closing::new(stream_receivers, pending_frames.into(), writer);
        futures::executor::block_on(async { poll_fn(|cx| closing.poll_unpin(cx)).await.unwrap() });
        assert!(closing.pending_frames.is_empty());
        assert!(closed.load(Ordering::SeqCst));
        assert_eq!(
            *written.lock().unwrap_or_else(|e| e.into_inner()),
            expected_written
        );
    }
}
