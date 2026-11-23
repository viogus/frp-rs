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
//! Unlike the driver, this thread may block. When the kernel send buffer is full
//! it waits for writability instead of dropping the rest of the run on the floor
//! or spinning on `try_send_to`: a flush is a run of segments that must reach
//! the wire, and the wait is exactly the backpressure the bounded queue needs —
//! it stalls the sender, not the driver's receive loop. The wait is bounded
//! (`MAX_STALLS`), so a socket that never drains hands the run back to KCP's
//! retransmission instead of wedging every session on this socket.

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

/// Pending runs of datagrams before the driver drops the run.
///
/// A run is one flush or one tick's retransmissions; on a bulk stream that is
/// ~50-60 datagrams of ~1.4 KB, so the depth bounds buffered datagrams at
/// roughly 5 MiB per socket.
const SEND_QUEUE_DEPTH: usize = 64;

/// How long one writability wait may last before the thread re-checks its
/// shutdown flag. Not a send deadline: a blocked run keeps waiting.
const WAIT_SLICE: Duration = Duration::from_millis(5);

/// Writability waits one run may spend before it is handed back to KCP.
///
/// Without a bound a socket whose peer stopped reading would pin this thread
/// (and every session sharing the socket) for as long as the peer is gone; KCP
/// retransmits a dropped run anyway, so giving up is the cheaper failure. The
/// count also bounds a pathological `poll` that reports writability while
/// `try_send_to` still answers `WouldBlock`.
const MAX_STALLS: u32 = 200;

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

/// What happened to a dispatched run. See [`SendThread::try_dispatch`].
pub(crate) enum Dispatch {
    /// The run is on the queue; the sender thread will write it.
    Queued,
    /// The queue is full: the sender is a whole queue behind and this run is
    /// dropped rather than written from the driver (two producers on one socket
    /// reorder segments against the queued runs).
    QueueFull(SendJob),
    /// No sender thread, or it is gone: the caller must send the run itself.
    NoThread(SendJob),
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

    /// A handle over a channel with no worker, so tests can drive the queue
    /// policy (full / disconnected) without racing a live thread.
    #[cfg(test)]
    pub(crate) fn test_handle(capacity: usize) -> (Self, Receiver<SendJob>) {
        let (tx, rx) = sync_channel(capacity);
        (
            Self {
                tx: Some(tx),
                handle: None,
                shutdown: Arc::new(AtomicBool::new(false)),
            },
            rx,
        )
    }

    /// Queue a run for the sender thread.
    ///
    /// The three outcomes are distinguished because they mean opposite things to
    /// the caller: a full queue is backpressure (drop the run — the peer is not
    /// draining), while a missing or dead thread means nobody else will ever
    /// write this socket (send it inline).
    pub(crate) fn try_dispatch(&self, job: SendJob) -> Dispatch {
        match self.tx.as_ref() {
            None => Dispatch::NoThread(job),
            Some(tx) => match tx.try_send(job) {
                Ok(()) => Dispatch::Queued,
                Err(TrySendError::Full(job)) => Dispatch::QueueFull(job),
                Err(TrySendError::Disconnected(job)) => Dispatch::NoThread(job),
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
    let mut stalls: u32 = 0;
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
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                stalls += 1;
                if stalls > MAX_STALLS {
                    // The socket has not drained for MAX_STALLS waits: hand the
                    // rest back to KCP (it re-sends unacked segments) instead of
                    // holding every session on this socket hostage.
                    tracing::debug!(
                        peer = %peer,
                        packets = remaining.len(),
                        "KCP SEND: giving up on a stalled run"
                    );
                    for pkt in remaining.drain(..) {
                        chunk_pool_push(pool, pkt);
                    }
                    return;
                }
                wait_writable(socket);
            }
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
    // SAFETY: `pfd` is one initialised `pollfd`, `nfds` matches the single
    // entry, and `fd` comes from a `UdpSocket` borrowed for the whole call, so
    // the descriptor cannot be closed underneath `poll`. `poll` only reports
    // readiness — it does not consume bytes, so tokio's read registration on the
    // same descriptor is untouched.
    unsafe {
        libc::poll(&mut pfd, 1, WAIT_SLICE.as_millis() as libc::c_int);
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_writable(_socket: &UdpSocket) {
    std::thread::sleep(WAIT_SLICE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn pool(capacity: usize) -> Arc<ArrayQueue<Vec<u8>>> {
        Arc::new(ArrayQueue::new(capacity))
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
    }

    /// Three runs of four datagrams must reach the peer in dispatch order: the
    /// sender is the socket's only writer, so a reordering here is a protocol
    /// bug (KCP answers it with retransmissions, not with correctness).
    #[test]
    fn runs_reach_the_peer_in_dispatch_order() {
        runtime().block_on(async {
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let peer = receiver.local_addr().unwrap();
            let thread = SendThread::spawn(Arc::clone(&socket), pool(32));

            let mut expected: Vec<Vec<u8>> = Vec::new();
            for run in 0..3u8 {
                let packets: Vec<Vec<u8>> = (0..4u8)
                    .map(|i| {
                        let pkt = vec![run * 10 + i; 8];
                        expected.push(pkt.clone());
                        pkt
                    })
                    .collect();
                assert!(
                    matches!(
                        thread.try_dispatch(SendJob { peer, packets }),
                        Dispatch::Queued
                    ),
                    "run {run} was not queued"
                );
            }
            // Read while the thread is alive: `Drop` stops the worker, and a
            // run still queued at shutdown is deliberately discarded (the
            // socket is going away and KCP re-sends what it never acked).
            let mut buf = [0u8; 64];
            for (i, want) in expected.iter().enumerate() {
                let (n, _) =
                    tokio::time::timeout(StdDuration::from_secs(2), receiver.recv_from(&mut buf))
                        .await
                        .expect("datagram did not arrive")
                        .unwrap();
                assert_eq!(&buf[..n], &want[..], "datagram {i} changed or reordered");
            }
            drop(thread);
        });
    }

    /// A full queue is reported as such, and the run comes back whole so the
    /// caller can recycle its buffers (this is the path that drops datagrams).
    #[test]
    fn a_full_queue_returns_the_whole_run() {
        let (thread, _rx) = SendThread::test_handle(2);
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        for _ in 0..2 {
            assert!(matches!(
                thread.try_dispatch(SendJob {
                    peer,
                    packets: vec![vec![0u8; 8]],
                }),
                Dispatch::Queued
            ));
        }
        match thread.try_dispatch(SendJob {
            peer,
            packets: vec![vec![7u8; 8], vec![8u8; 8]],
        }) {
            Dispatch::QueueFull(job) => {
                assert_eq!(job.peer, peer);
                assert_eq!(job.packets.len(), 2, "a dropped run must come back whole");
                assert_eq!(job.packets[1], vec![8u8; 8]);
            }
            _ => panic!("a full queue must report QueueFull"),
        }
    }

    /// A disconnected channel is not backpressure: the caller has to send the
    /// run itself, or every datagram on the socket is lost without a trace.
    #[test]
    fn a_dead_receiver_is_reported_as_no_thread() {
        let (thread, rx) = SendThread::test_handle(2);
        drop(rx);
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        match thread.try_dispatch(SendJob {
            peer,
            packets: vec![vec![1u8; 8]],
        }) {
            Dispatch::NoThread(job) => assert_eq!(job.packets.len(), 1),
            _ => panic!("a disconnected receiver must not look like a full queue"),
        }
    }

    /// Shutdown must recycle the buffers it refuses to send, or every close
    /// leaks the run the socket was holding.
    #[test]
    fn a_shutdown_run_returns_its_buffers_to_the_pool() {
        runtime().block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = socket.local_addr().unwrap();
            let pool = pool(8);
            let stop = AtomicBool::new(true);
            send_run_blocking(
                &socket,
                &pool,
                peer,
                vec![vec![1u8; 4], vec![2u8; 4]],
                &stop,
            );
            assert_eq!(pool.len(), 2, "a shutdown run must return its buffers");
        });
    }
}
