//! KCP stream — AsyncRead + AsyncWrite over a KCP session.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use crossbeam_queue::ArrayQueue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

use super::socket::{
    chunk_pool_pop, chunk_pool_push, WriteRequest, KCP_SND_BACKLOG_THRESHOLD,
    KCP_WRITE_BACKLOG_THRESHOLD,
};

static KCP_READ_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(debug_assertions)]
static KCP_READ_CALLS: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(debug_assertions)]
static KCP_WRITE_CALLS: AtomicU64 = AtomicU64::new(0);

pub struct KcpStream {
    conv: u32,
    pub peer_addr: SocketAddr,
    write_tx: mpsc::Sender<(u32, WriteRequest)>,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    read_count: u64,
    write_count: u64,
    shutdown: bool,
    /// Pending flush confirmation — set by poll_flush, cleared on receipt.
    flush_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    /// Shared write backlog counter with KcpSocket. poll_write gates on this
    /// to prevent unbounded write_rx channel growth under high packet loss.
    write_backlog: Arc<AtomicUsize>,
    /// Woken by KcpSocket when backlog drains below threshold (via notify_one).
    write_notify: Arc<Notify>,
    /// Pending backpressure wait future. Created when the write-channel backlog
    /// or the KCP send-queue backlog is full; resolved when KcpSocket drains
    /// enough backlog and notifies (via write_notify or snd_notify).
    /// Uses OwnedNotified (not Notified<'_>) so the future holds its own
    /// Arc<Notify> reference — no transmute, no field ordering dependency.
    backpressure_fut: Option<Pin<Box<tokio::sync::futures::OwnedNotified>>>,
    /// Shared send-queue backlog counter with KcpSession. Mirrors
    /// `Kcp::wait_snd()` (snd_buf + snd_queue segment count). poll_write gates
    /// on this so a stalled peer (remote window 0) cannot make the KCP send
    /// queue grow without bound.
    snd_backlog: Arc<AtomicUsize>,
    /// Woken by KcpSession::reconcile_snd_backlog when snd_backlog drains below
    /// KCP_SND_BACKLOG_THRESHOLD (or by mark_dead when the session is removed).
    snd_notify: Arc<Notify>,
    /// Shared with KcpSession. Set to false when the session is removed from
    /// the driver, so poll_write/poll_read can fail fast.
    session_alive: Arc<AtomicBool>,
    /// Live-stream counter shared with the KcpSocket driver. Incremented at
    /// construction, decremented on drop: the dial driver self-exits once
    /// the last stream is gone and no registrations can arrive.
    alive_streams: Arc<AtomicUsize>,
    /// Recycled write-chunk pool shared with the KcpSocket driver (see
    /// KcpSocketHandle::chunk_pool). poll_write pops a chunk here instead
    /// of allocating a fresh Vec per bridge write; the driver returns
    /// chunks once the session has segmented them. Bounded by CHUNK_POOL_CAP.
    chunk_pool: Arc<ArrayQueue<Vec<u8>>>,
}

impl KcpStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        conv: u32,
        peer_addr: SocketAddr,
        write_tx: mpsc::Sender<(u32, WriteRequest)>,
        read_rx: mpsc::Receiver<Vec<u8>>,
        write_backlog: Arc<AtomicUsize>,
        write_notify: Arc<Notify>,
        chunk_pool: Arc<ArrayQueue<Vec<u8>>>,
        snd_backlog: Arc<AtomicUsize>,
        snd_notify: Arc<Notify>,
        session_alive: Arc<AtomicBool>,
        alive_streams: Arc<AtomicUsize>,
    ) -> Self {
        // Register this stream with the socket driver's liveness counter.
        // The dial driver self-exits when the counter reaches zero (see
        // KcpSocket::run); the increment must happen-before the stream is
        // handed to the caller, and the counter decrements in Drop below.
        alive_streams.fetch_add(1, Ordering::AcqRel);
        Self {
            conv,
            peer_addr,
            write_tx,
            read_rx,
            read_buffer: Vec::new(),
            read_pos: 0,
            read_count: 0,
            write_count: 0,
            shutdown: false,
            flush_rx: None,
            write_backlog,
            write_notify,
            backpressure_fut: None,
            chunk_pool,
            snd_backlog,
            snd_notify,
            session_alive,
            alive_streams,
        }
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }
    pub fn global_read_bytes() -> u64 {
        KCP_READ_BYTES.load(Ordering::Relaxed)
    }
    pub fn global_write_bytes() -> u64 {
        KCP_WRITE_BYTES.load(Ordering::Relaxed)
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        // Best-effort (M4): return an undrained read_buffer allocation to
        // the shared pool. Channel messages still queued in read_rx are
        // dropped with the channel — draining up to 256 items in Drop is
        // not worth it, so only the one buffer the stream owns outright is
        // returned. The allocation is wasted either way once the connection
        // is gone; this just lets the pool reuse it.
        if !self.read_buffer.is_empty() {
            chunk_pool_push(&self.chunk_pool, std::mem::take(&mut self.read_buffer));
        }
        // Release the socket driver's liveness signal: the dial driver
        // self-exits once the last stream is dropped and no registrations
        // remain (see KcpSocket::run). AcqRel pairs with the driver's
        // Acquire load so an observed zero implies this stream is gone.
        self.alive_streams.fetch_sub(1, Ordering::AcqRel);
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Bytes handed to the caller by this call. Kept local so a
        // coalescing pass reports one total instead of one per segment.
        let mut filled = 0usize;

        // Drain the buffered remainder of a message the previous call could
        // not fit, before asking the session for more.
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.read_pos += take;
            filled += take;
            if self.read_pos == self.read_buffer.len() {
                // Fully drained (M4): this buffer was the oversized tail of
                // a channel message stashed by the partial-consume arm —
                // recycle its allocation instead of holding it until drop.
                // `chunk_pool_push` clears the payload, so no stale bytes
                // can leak into a later message.
                let drained = std::mem::take(&mut self.read_buffer);
                chunk_pool_push(&self.chunk_pool, drained);
            }
        }

        // Coalesce: the session delivers one KCP segment per channel message
        // (~1376 bytes at the production MTU of 1400), while the callers that
        // matter hand us a much larger buffer — the bridge hands out 64 KiB.
        // Returning after the first segment made every bridge read a
        // one-segment copy, and the far side then paid a second pass over the
        // same bytes. Keep pulling while the caller has room and the channel
        // still holds segments.
        //
        // Returning `Ready` after a `Pending` poll is allowed and the waker
        // stays registered, so a caller that gets data still gets woken for
        // the next segment.
        while buf.remaining() > 0 {
            match self.read_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    let take = data.len().min(buf.remaining());
                    buf.put_slice(&data[..take]);
                    filled += take;
                    if take < data.len() {
                        // Oversized message: stash the tail for the next call.
                        self.read_buffer = data;
                        self.read_pos = take;
                        break;
                    }
                    // Fully consumed (M4): recycle the channel buffer into
                    // the shared chunk pool instead of dropping it —
                    // `KcpSession::recv_and_push` pops pooled buffers, so
                    // the per-message allocation cycles instead of
                    // allocating on every delivered message. The pool
                    // clears on return, so no stale bytes can leak into a
                    // later message.
                    chunk_pool_push(&self.chunk_pool, data);
                }
                Poll::Ready(None) => {
                    if filled > 0 {
                        break;
                    }
                    // If session is dead, return an error instead of EOF so
                    // the bridge fails fast rather than hanging.
                    return Poll::Ready(if !self.session_alive.load(Ordering::Acquire) {
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "KCP session removed",
                        ))
                    } else {
                        Ok(()) // EOF
                    });
                }
                Poll::Pending => {
                    if filled > 0 {
                        break;
                    }
                    return if !self.session_alive.load(Ordering::Acquire) {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "KCP session removed",
                        )))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }

        self.read_count += filled as u64;
        KCP_READ_BYTES.fetch_add(filled as u64, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        if tracing::level_enabled!(tracing::Level::DEBUG) {
            tracing::debug!(
                conv = self.conv,
                n = filled,
                total = self.read_count,
                "KCP read: {} bytes (total={})",
                filled,
                self.read_count,
            );
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Check if the underlying KCP session is still alive.
        // Sessions removed by the driver (dead link, error, timeout) can no
        // longer deliver data, and writes would be silently discarded.
        if !self.session_alive.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "KCP session removed",
            )));
        }

        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "KCP stream shut down",
            )));
        }

        // If we were blocked on write backpressure, poll the Notified future
        // to see if KcpSocket has drained enough backlog.
        if let Some(ref mut fut) = self.backpressure_fut {
            match fut.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.backpressure_fut = None;
                    // Fall through to re-check backlog and try send.
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Gate: if write_rx channel backlog is too high, apply backpressure.
        // This prevents unbounded memory growth in the mpsc channel when
        // KCP send window is full (high packet loss / slow peer).
        let backlog = self.write_backlog.load(Ordering::Relaxed);
        if backlog >= KCP_WRITE_BACKLOG_THRESHOLD {
            // Create a Notified future to wait for KcpSocket to drain backlog.
            // notified_owned() takes an Arc<Notify> and returns an OwnedNotified
            // that holds its own reference — no unsafe transmute, no lifetime issue.
            let notified = self.write_notify.clone().notified_owned();
            self.backpressure_fut = Some(Box::pin(notified));
            // Re-poll the newly created future with the current waker.
            if let Some(ref mut fut) = self.backpressure_fut {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        self.backpressure_fut = None;
                        // Backlog drained between check and notify registration.
                        // Fall through to send.
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        // Gate: if the KCP session's send queue (snd_buf + snd_queue, via
        // wait_snd()) is too deep, apply backpressure. This bounds memory when
        // the remote window is 0 — the peer stops ACKing, flush() cannot move
        // segments out of snd_queue, and without this gate snd_queue would grow
        // without limit. KcpSession reconciles the counter and notifies via
        // snd_notify once ACKs (or session teardown) drain it below the
        // threshold. Same OwnedNotified pattern as the write-backlog gate.
        let snd_backlog = self.snd_backlog.load(Ordering::Relaxed);
        if snd_backlog >= KCP_SND_BACKLOG_THRESHOLD {
            let notified = self.snd_notify.clone().notified_owned();
            self.backpressure_fut = Some(Box::pin(notified));
            if let Some(ref mut fut) = self.backpressure_fut {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        self.backpressure_fut = None;
                        // Queue drained between check and notify registration.
                        // Fall through to send.
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        tracing::trace!(
            "KCP WRITE: {} bytes first_hex={}",
            buf.len(),
            crate::hex_encode(&buf[..buf.len().min(32)])
        );

        // M1 perf: pop a recycled chunk from the pool (or allocate with
        // with_capacity when the pool is empty) instead of buf.to_vec()'s
        // fresh chunk-sized alloc + memcpy on every bridge write. The driver
        // returns the chunk to the pool once the session's segmentation has
        // copied the payload out.
        let mut chunk = chunk_pool_pop(&self.chunk_pool, buf.len());
        chunk.extend_from_slice(buf);
        let req = WriteRequest::Data(chunk);

        // Increment backlog BEFORE try_send so it reflects queued messages,
        // not just those being processed. Decrement on Full to avoid
        // permanently consuming capacity.
        self.write_backlog.fetch_add(1, Ordering::Relaxed);
        match self.write_tx.try_send((self.conv, req)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                self.write_backlog.fetch_sub(1, Ordering::Relaxed);
                // The message was not queued — return the chunk to the pool
                // (poll_write only ever sends Data payloads). Same
                // backpressure as before.
                if let WriteRequest::Data(chunk) = msg.1 {
                    chunk_pool_push(&self.chunk_pool, chunk);
                }
                // Apply backpressure — wait for socket to drain.
                let notified = self.write_notify.clone().notified_owned();
                self.backpressure_fut = Some(Box::pin(notified));
                if let Some(ref mut fut) = self.backpressure_fut {
                    let _ = fut.as_mut().poll(cx);
                }
                return Poll::Pending;
            }
            Err(mpsc::error::TrySendError::Closed(msg)) => {
                self.write_backlog.fetch_sub(1, Ordering::Relaxed);
                // Channel closed — return the chunk to the pool as well.
                if let WriteRequest::Data(chunk) = msg.1 {
                    chunk_pool_push(&self.chunk_pool, chunk);
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "KCP driver closed",
                )));
            }
        }

        // Fire-and-forget: KCP's send window handles backpressure.
        // Channel backpressure is handled by the backlog gate above.
        // Write errors surface via the driver's debug log.

        let n = buf.len();
        self.write_count += n as u64;
        KCP_WRITE_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        KCP_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        if (self.write_count <= 80 || self.write_count.is_multiple_of(1024))
            && tracing::level_enabled!(tracing::Level::DEBUG)
        {
            tracing::debug!(
                conv = self.conv,
                n = n,
                total = self.write_count,
                global_total = KCP_WRITE_BYTES.load(Ordering::Relaxed),
                first_hex = %crate::hex_encode(&buf[..n.min(32)]),
                "KCP write: {} bytes (stream total={}, global total={})",
                n,
                self.write_count,
                KCP_WRITE_BYTES.load(Ordering::Relaxed),
            );
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First: poll any pending backpressure future from poll_write.
        if let Some(ref mut fut) = self.backpressure_fut {
            match fut.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.backpressure_fut = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Send a flush request if we don't have one pending.
        if self.flush_rx.is_none() {
            // Backlog gate: same as poll_write, prevents lost wake by ensuring
            // capacity exists before try_send.
            let backlog = self.write_backlog.load(Ordering::Relaxed);
            if backlog >= KCP_WRITE_BACKLOG_THRESHOLD {
                let notified = self.write_notify.clone().notified_owned();
                self.backpressure_fut = Some(Box::pin(notified));
                if let Some(ref mut fut) = self.backpressure_fut {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.backpressure_fut = None;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            match self.write_tx.try_send((self.conv, WriteRequest::Flush(tx))) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Backlog gate should prevent this; defensive fallback.
                    let notified = self.write_notify.clone().notified_owned();
                    self.backpressure_fut = Some(Box::pin(notified));
                    if let Some(ref mut fut) = self.backpressure_fut {
                        let _ = fut.as_mut().poll(cx);
                    }
                    return Poll::Pending;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "KCP driver closed",
                    )));
                }
            }
            self.flush_rx = Some(rx);
        }

        // Poll the oneshot — properly registers the waker (no busy-spin).
        let mut rx = self
            .flush_rx
            .take()
            .expect("flush_rx set to Some just above");
        match Pin::new(&mut rx).poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => {
                // Driver dropped the sender — treat as flushed.
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                self.flush_rx = Some(rx);
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream wired to a caller-controlled read channel. Everything the
    /// read path touches is inert here: no writer task, no session.
    fn stream_reading_from(read_rx: mpsc::Receiver<Vec<u8>>) -> KcpStream {
        let (write_tx, _write_rx) = mpsc::channel(8);
        KcpStream::new(
            7,
            "127.0.0.1:1".parse().unwrap(),
            write_tx,
            read_rx,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(Notify::new()),
            Arc::new(ArrayQueue::new(8)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(Notify::new()),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicUsize::new(0)),
        )
    }

    fn poll_once(stream: &mut KcpStream, buf: &mut [u8]) -> (Poll<io::Result<()>>, usize) {
        let mut read_buf = ReadBuf::new(buf);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let poll = Pin::new(stream).poll_read(&mut cx, &mut read_buf);
        (poll, read_buf.filled().len())
    }

    #[tokio::test]
    async fn poll_read_coalesces_every_queued_segment() {
        let (tx, rx) = mpsc::channel(8);
        let mut stream = stream_reading_from(rx);
        for _ in 0..3 {
            tx.send(vec![7u8; 100]).await.unwrap();
        }
        let mut buf = [0u8; 1024];
        let (poll, filled) = poll_once(&mut stream, &mut buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(
            filled, 300,
            "one poll must hand over every segment the session already queued, \
             not just the first: the bridge asks for 64 KiB and a segment is ~1.4 KiB"
        );
    }

    #[tokio::test]
    async fn poll_read_stops_at_the_buffer_edge_and_keeps_the_tail() {
        let (tx, rx) = mpsc::channel(8);
        let mut stream = stream_reading_from(rx);
        tx.send(vec![1u8; 10]).await.unwrap();
        tx.send(vec![2u8; 100]).await.unwrap();

        let mut buf = [0u8; 50];
        let (poll, filled) = poll_once(&mut stream, &mut buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(filled, 50, "the caller's buffer is the only limit");
        assert_eq!(&buf[..10], &[1u8; 10], "first segment must come first");

        let mut buf = [0u8; 100];
        let (poll, filled) = poll_once(&mut stream, &mut buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(filled, 60, "the stashed tail must survive to the next poll");
        assert_eq!(&buf[..60], &[2u8; 60]);
    }
}
