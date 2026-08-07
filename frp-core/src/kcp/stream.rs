//! KCP stream — AsyncRead + AsyncWrite over a KCP session.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

use super::socket::{WriteRequest, KCP_SND_BACKLOG_THRESHOLD, KCP_WRITE_BACKLOG_THRESHOLD};

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
        snd_backlog: Arc<AtomicUsize>,
        snd_notify: Arc<Notify>,
        session_alive: Arc<AtomicBool>,
    ) -> Self {
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
            snd_backlog,
            snd_notify,
            session_alive,
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

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain buffered data first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            self.read_count += n as u64;
            KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            #[cfg(debug_assertions)]
            KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                conv = self.conv,
                n = n,
                total = self.read_count,
                "KCP read: {} bytes (total={})",
                n,
                self.read_count,
            );
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                // Capture hex preview before data may be moved into read_buffer.
                #[cfg(debug_assertions)]
                let hex_preview = if n > 0 {
                    Some(crate::hex_encode(&data[..n.min(16)]))
                } else {
                    None
                };
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_pos = n;
                }
                self.read_count += n as u64;
                KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                #[cfg(debug_assertions)]
                KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
                #[cfg(debug_assertions)]
                if tracing::level_enabled!(tracing::Level::DEBUG) {
                    tracing::debug!(
                        conv = self.conv,
                        n = n,
                        total = self.read_count,
                        first_hex = hex_preview.unwrap_or_default(),
                        "KCP read: {} bytes (total={})",
                        n,
                        self.read_count,
                    );
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // If session is dead, return an error instead of EOF so the
                // bridge fails fast rather than hanging.
                if !self.session_alive.load(Ordering::Acquire) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "KCP session removed",
                    )))
                } else {
                    Poll::Ready(Ok(())) // EOF
                }
            }
            Poll::Pending => {
                if !self.session_alive.load(Ordering::Acquire) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "KCP session removed",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
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

        let req = WriteRequest::Data(buf.to_vec());

        // Increment backlog BEFORE try_send so it reflects queued messages,
        // not just those being processed. Decrement on Full to avoid
        // permanently consuming capacity.
        self.write_backlog.fetch_add(1, Ordering::Relaxed);
        match self.write_tx.try_send((self.conv, req)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.write_backlog.fetch_sub(1, Ordering::Relaxed);
                // Apply backpressure — wait for socket to drain.
                let notified = self.write_notify.clone().notified_owned();
                self.backpressure_fut = Some(Box::pin(notified));
                if let Some(ref mut fut) = self.backpressure_fut {
                    let _ = fut.as_mut().poll(cx);
                }
                return Poll::Pending;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.write_backlog.fetch_sub(1, Ordering::Relaxed);
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
