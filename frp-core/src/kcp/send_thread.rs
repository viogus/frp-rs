//! Dedicated UDP sender thread for a KCP socket.
//!
//! The driver thread ([`super::driver_thread`]) is a single-threaded runtime and
//! must stay that way (`DriverThread::drop` joins it), but profiling a bulk KCP
//! stream shows ~70% of its cycles inside `sendmmsg` — the kernel-side send path
//! plus, on loopback, the peer's receive processing that runs in the sender's
//! syscall. That work does not need the driver's state: by the time
//! `force_flush` returns, the flush's datagrams are an owned `Vec<Vec<u8>>`.
//!
//! So the driver hands a run of datagrams to this thread and moves on to the
//! next write batch while the kernel drains the socket. Ordering is preserved:
//! one FIFO consumer, and every send (flush path and tick path) goes through the
//! same channel.
//!
//! Unike the driver, this thread may block. When the kernel send buffer is full
//! it waits for writability instead of dropping the rest of the run on the floor
//! or spinning on `try_send_to`: a flush is a run of segments that must reach
//! the wire, and the wait is exactly the backpressure the bounded queue needs —
//! it stalls the sender, not the driver's receive loop.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use tokio::net::UdpSocket;

use super::socket::chunk_pool_push;
#[cfg(target_os = "linux")]
use super::socket::KcpSocket;

/// Pending runs of datagrams before the driver falls back to sending inline.
///
/// A run is one flush or one tick's retransmissions; on a bulk stream that is
/// ~50-60 datagrams of ~1.4 KB, so the depth bounds buffered datagrams at
/// roughly 5 MiB per socket.
const SEND_QUEUE_DEPTH: usize = 64;

/// How long one writability wait may last before the thread re-checks its
/// shutdown flag. Not a send deadline: a blocked run keeps waiting.
const WAIT_SLICE: Duration = Duration::from_millis(5);

/// One run of datagrams addressed to a single peer.
pub(crate) struct SendJob {
    pub(crate) peer: SocketAddr,
    pub(crate) packets: Vec<Vec<u8>>,
}

/// Handle to the sender thread: `dispatch` is the driver's queue push, and
/// dropping the handle shuts the thread down.
pub(crate) struct SendThread {
    tx: Option<SyncSender<SendJob>>,
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl SendThread {
    /// Spawn the sender thread for `socket`.
    ///
    /// The thread owns nothing but a clone of the `Arc`s: the socket (sends are
    /// `try_send_to` on the fd, which needs no reactor) and the chunk pool
    /// (datagram buffers are recycled there exactly as the driver did).
    pub(crate) fn spawn(socket: Arc<UdpSocket>, pool: Arc<ArrayQueue<Vec<u8>>>) -> Self {
        let (tx, rx) = sync_channel::<SendJob>(SEND_QUEUE_DEPTH);
        let shutdown = Arc::new(AtomicBool::new(false));
        let should_stop = Arc::clone(&shutdown);
        let handle = std::thread::Builder::new()
            .name("frp-kcp-send".into())
            .spawn(move || run(&socket, &pool, &rx, &should_stop));
        match handle {
            Ok(handle) => Self {
                tx: Some(tx),
                handle: Some(handle),
                shutdown,
            },
            Err(e) => {
                // No sender thread: `dispatch` reports failure and the driver
                // keeps its own inline path. Degraded, not broken.
                tracing::warn!(error = %e, "KCP SEND: cannot spawn sender thread, sending inline");
                Self {
                    tx: None,
                    handle: None,
                    shutdown,
                }
            }
        }
    }

    /// Whether the sender thread is alive (false only when spawn failed).
    pub(crate) fn has_thread(&self) -> bool {
        self.tx.is_some()
    }

    /// Queue a run for the sender thread.
    ///
    /// Returns the job back when there is no thread or the queue is full, so the
    /// caller can send it inline.
    pub(crate) fn try_dispatch(&self, job: SendJob) -> Result<(), SendJob> {
        match self.tx.as_ref() {
            None => Err(job),
            Some(tx) => match tx.try_send(job) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(job)) | Err(TrySendError::Disconnected(job)) => Err(job),
            },
        }
    }
}

impl Drop for SendThread {
    fn drop(&mut self) {
        // Closing the channel ends the loop; a run that is blocked on a full
        // send buffer notices the flag within one WAIT_SLICE and yields.
        self.shutdown.store(true, Ordering::Release);
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run(
    socket: &UdpSocket,
    pool: &ArrayQueue<Vec<u8>>,
    rx: &Receiver<SendJob>,
    should_stop: &AtomicBool,
) {
    while let Ok(job) = rx.recv() {
        send_run_blocking(socket, pool, job.peer, job.packets, should_stop);
    }
}

/// Send a whole run, waiting out a full kernel buffer instead of dropping the
/// tail. Batching is retried for whatever is left, so a run that fits in the
/// buffer still costs one syscall.
fn send_run_blocking(
    socket: &UdpSocket,
    pool: &ArrayQueue<Vec<u8>>,
    peer: SocketAddr,
    packets: Vec<Vec<u8>>,
    should_stop: &AtomicBool,
) {
    let mut remaining = packets;
    while !remaining.is_empty() {
        if should_stop.load(Ordering::Acquire) {
            // Shutting down: KCP re-sends whatever is left anyway.
            for pkt in remaining.drain(..) {
                chunk_pool_push(pool, pkt);
            }
            return;
        }
        #[cfg(target_os = "linux")]
        let sent = KcpSocket::send_udp_batch(socket, &remaining, peer);
        #[cfg(not(target_os = "linux"))]
        let sent = 0usize;
        if sent > 0 {
            for pkt in remaining.drain(..sent) {
                chunk_pool_push(pool, pkt);
            }
            continue;
        }
        // Nothing went out: either the buffer is full (wait for room) or this
        // packet cannot be sent at all (drop it, or a poisoned address would
        // spin here forever).
        match socket.try_send_to(&remaining[0], peer) {
            Ok(_) => {
                let pkt = remaining.remove(0);
                chunk_pool_push(pool, pkt);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait_writable(socket),
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "KCP SEND: dropping datagram");
                let pkt = remaining.remove(0);
                chunk_pool_push(pool, pkt);
            }
        }
    }
}

/// Block until the socket reports room, or one [`WAIT_SLICE`] passes (the
/// caller re-checks shutdown then).
#[cfg(target_os = "linux")]
fn wait_writable(socket: &UdpSocket) {
    use std::os::fd::AsRawFd;

    let mut pfd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: `pfd` is one initialised `pollfd` and the count matches.
    unsafe {
        libc::poll(&mut pfd, 1, WAIT_SLICE.as_millis() as libc::c_int);
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_writable(_socket: &UdpSocket) {
    std::thread::sleep(WAIT_SLICE);
}
