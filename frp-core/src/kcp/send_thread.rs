//! Shared UDP sender pool for KCP sockets.
//!
//! The driver thread ([`super::driver_thread`]) is a single-threaded runtime and
//! must stay that way (`DriverThread::drop` joins it), but profiling a bulk KCP
//! stream shows ~70% of its cycles inside `sendmmsg` — the kernel-side send path
//! plus, on loopback, the peer's receive processing that runs in the sender's
//! syscall. That work does not need the driver's state: by the time
//! `force_flush` returns, the flush's datagrams are an owned `Vec<Vec<u8>>`.
//!
//! So the driver hands a run of datagrams to a pool worker and moves on to the
//! next write batch while the kernel drains the socket. Ordering is preserved
//! because a socket is bound to exactly one worker at construction and never
//! migrates: every send on that socket (flush path and tick path) enters the
//! same FIFO, so a peer cannot see run *n+1* before run *n*.
//!
//! The pool exists because one thread per socket is expensive to own: with
//! `tcpMux = false` every work connection dials its own `KcpSocket`, so a busy
//! client would carry one sender thread per connection on top of one driver
//! thread per connection. Instead a fixed number of workers (one per core, at
//! most [`MAX_WORKERS`]) is started lazily and shared by all sockets; sockets
//! are handed out round-robin.
//!
//! Unlike the driver, a worker may block. When the kernel send buffer is full
//! it waits for writability instead of dropping the rest of the run on the floor
//! or spinning on `try_send_to`: a flush is a run of segments that must reach
//! the wire, and the wait is exactly the backpressure the bounded queue needs —
//! it stalls one worker, not the driver's receive loop. The wait is bounded
//! ([`MAX_STALLS`]), so a socket that never drains hands the run back to KCP's
//! retransmission instead of wedging every session sharing that worker.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
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
/// ~50-60 datagrams of ~1.4 KB. The depth is per worker, shared by the sockets
/// bound to it, so it bounds buffered datagrams at roughly 10 MiB per worker.
const SEND_QUEUE_DEPTH: usize = 128;

/// Workers in the pool: one per core, capped so a large machine does not end up
/// with more send threads than it can keep busy.
const MAX_WORKERS: usize = 4;

/// How long one writability wait may last before the thread re-checks its
/// shutdown flag. Not a send deadline: a blocked run keeps waiting.
const WAIT_SLICE: Duration = Duration::from_millis(5);

/// Writability waits one run may spend before it is handed back to KCP.
///
/// Without a bound a socket whose peer stopped reading would pin its worker
/// (and every socket sharing it) for as long as the peer is gone; KCP
/// retransmits a dropped run anyway, so giving up is the cheaper failure. The
/// count also bounds a pathological `poll` that reports writability while
/// `try_send_to` still answers `WouldBlock`.
const MAX_STALLS: u32 = 200;

/// One run of datagrams addressed to a single peer, plus what the worker needs
/// to write it. The socket and the chunk pool travel with the job because a
/// worker serves many sockets.
pub(crate) struct SendJob {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) pool: Arc<ArrayQueue<Vec<u8>>>,
    pub(crate) peer: SocketAddr,
    pub(crate) packets: Vec<Vec<u8>>,
}

/// What happened to a dispatched run. See [`Worker::try_dispatch`].
pub(crate) enum Dispatch {
    /// The run is on the queue; a worker will write it.
    Queued,
    /// The queue is full: the worker is a whole queue behind and this run is
    /// dropped rather than written from the driver (two producers on one socket
    /// reorder segments against the queued runs).
    QueueFull(SendJob),
    /// No worker, or the worker died: the caller must send the run itself.
    NoThread(SendJob),
}

/// A started worker: its queue and the thread draining it.
struct Running {
    tx: SyncSender<SendJob>,
    /// Kept so the thread handle is not dropped on the floor; never joined —
    /// workers live for the process.
    _thread: Option<JoinHandle<()>>,
}

/// One pool worker. The thread starts on the first dispatch that reaches it, so
/// a process with one KCP socket starts one send thread, not one per core.
pub(crate) struct Worker {
    running: OnceLock<Option<Running>>,
}

impl Worker {
    fn new() -> Self {
        Self {
            running: OnceLock::new(),
        }
    }

    fn sender(&self) -> Option<&SyncSender<SendJob>> {
        self.running
            .get_or_init(|| {
                let (tx, rx) = sync_channel::<SendJob>(SEND_QUEUE_DEPTH);
                match std::thread::Builder::new()
                    .name("frp-kcp-send".into())
                    .spawn(move || run(&rx))
                {
                    Ok(thread) => Some(Running {
                        tx,
                        _thread: Some(thread),
                    }),
                    Err(e) => {
                        // No worker: `try_dispatch` reports `NoThread` and the
                        // driver keeps its own inline path. Degraded, not broken.
                        tracing::warn!(
                            error = %e,
                            "KCP SEND: cannot spawn sender thread, sending inline"
                        );
                        None
                    }
                }
            })
            .as_ref()
            .map(|running| &running.tx)
    }

    /// A worker over a queue with no thread, so tests can drive the queue policy
    /// (full / disconnected) without racing a live worker.
    #[cfg(test)]
    pub(crate) fn test_handle(capacity: usize) -> (Self, Receiver<SendJob>) {
        let (tx, rx) = sync_channel(capacity);
        let worker = Self {
            running: OnceLock::new(),
        };
        let _ = worker.running.set(Some(Running { tx, _thread: None }));
        (worker, rx)
    }

    /// Queue a run for the worker that owns this socket.
    ///
    /// The three outcomes are distinguished because they mean opposite things to
    /// the caller: a full queue is backpressure (drop the run — the peer is not
    /// draining), while a missing worker means nobody else will ever write this
    /// socket (send it inline).
    pub(crate) fn try_dispatch(&self, job: SendJob) -> Dispatch {
        match self.sender() {
            None => Dispatch::NoThread(job),
            Some(tx) => match tx.try_send(job) {
                Ok(()) => Dispatch::Queued,
                Err(TrySendError::Full(job)) => Dispatch::QueueFull(job),
                Err(TrySendError::Disconnected(job)) => Dispatch::NoThread(job),
            },
        }
    }
}

/// The process-wide pool. Sockets pick a worker once, at construction, and keep
/// it for their lifetime — that binding is what makes per-socket ordering hold
/// while several sockets share one thread.
pub(crate) struct SenderPool {
    workers: Vec<Worker>,
    next: AtomicUsize,
}

static POOL: OnceLock<SenderPool> = OnceLock::new();

impl SenderPool {
    fn get() -> &'static SenderPool {
        POOL.get_or_init(|| {
            let count = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .clamp(1, MAX_WORKERS);
            SenderPool {
                workers: (0..count).map(|_| Worker::new()).collect(),
                next: AtomicUsize::new(0),
            }
        })
    }

    /// The worker a newly created socket should send through.
    pub(crate) fn pick() -> &'static Worker {
        let pool = Self::get();
        let index = pool.next.fetch_add(1, Ordering::Relaxed) % pool.workers.len();
        &pool.workers[index]
    }

    /// Pool width. Test-only: production code never needs to know it.
    #[cfg(test)]
    pub(crate) fn width() -> usize {
        Self::get().workers.len()
    }
}

fn run(rx: &Receiver<SendJob>) {
    while let Ok(job) = rx.recv() {
        send_run_blocking(&job.socket, &job.pool, job.peer, job.packets);
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
) {
    let mut remaining = packets;
    let mut stalls: u32 = 0;
    while !remaining.is_empty() {
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

/// Block until the socket reports room, or one [`WAIT_SLICE`] passes.
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

    fn job(socket: &Arc<UdpSocket>, peer: SocketAddr, packets: Vec<Vec<u8>>) -> SendJob {
        SendJob {
            socket: Arc::clone(socket),
            pool: pool(16),
            peer,
            packets,
        }
    }

    /// Three runs of four datagrams must reach the peer in dispatch order: a
    /// socket's runs all enter one FIFO, so a reordering here is a protocol bug
    /// (KCP answers it with retransmissions, not with correctness).
    #[test]
    fn runs_reach_the_peer_in_dispatch_order() {
        runtime().block_on(async {
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let peer = receiver.local_addr().unwrap();
            let worker = Worker::new();

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
                        worker.try_dispatch(job(&socket, peer, packets)),
                        Dispatch::Queued
                    ),
                    "run {run} was not queued"
                );
            }

            let mut buf = [0u8; 64];
            for (i, want) in expected.iter().enumerate() {
                let (n, _) =
                    tokio::time::timeout(StdDuration::from_secs(2), receiver.recv_from(&mut buf))
                        .await
                        .expect("datagram did not arrive")
                        .unwrap();
                assert_eq!(&buf[..n], &want[..], "datagram {i} changed or reordered");
            }
        });
    }

    /// A full queue is reported as such, and the run comes back whole so the
    /// caller can recycle its buffers (this is the path that drops datagrams).
    #[test]
    fn a_full_queue_returns_the_whole_run() {
        runtime().block_on(async {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let (worker, _rx) = Worker::test_handle(2);
            for _ in 0..2 {
                assert!(matches!(
                    worker.try_dispatch(job(&socket, peer, vec![vec![0u8; 8]])),
                    Dispatch::Queued
                ));
            }
            match worker.try_dispatch(job(&socket, peer, vec![vec![7u8; 8], vec![8u8; 8]])) {
                Dispatch::QueueFull(job) => {
                    assert_eq!(job.peer, peer);
                    assert_eq!(job.packets.len(), 2, "a dropped run must come back whole");
                    assert_eq!(job.packets[1], vec![8u8; 8]);
                }
                _ => panic!("a full queue must report QueueFull"),
            }
        });
    }

    /// A disconnected queue is not backpressure: the caller has to send the run
    /// itself, or every datagram on the socket is lost without a trace.
    #[test]
    fn a_dead_receiver_is_reported_as_no_thread() {
        runtime().block_on(async {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let (worker, rx) = Worker::test_handle(2);
            drop(rx);
            match worker.try_dispatch(job(&socket, peer, vec![vec![1u8; 8]])) {
                Dispatch::NoThread(job) => assert_eq!(job.packets.len(), 1),
                _ => panic!("a disconnected queue must not look like a full one"),
            }
        });
    }

    /// A run that cannot be written must still return every buffer, or every
    /// stalled or poisoned send leaks its chunks.
    #[test]
    fn an_undeliverable_run_returns_its_buffers_to_the_pool() {
        runtime().block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            // Unroutable: the send fails and the datagram is dropped, not parked.
            let peer: SocketAddr = "0.0.0.0:9".parse().unwrap();
            let pool = pool(8);
            send_run_blocking(&socket, &pool, peer, vec![vec![1u8; 4], vec![2u8; 4]]);
            assert_eq!(pool.len(), 2, "a failed run must return its buffers");
        });
    }

    /// Every socket must get a worker, and the pool must not grow past its cap.
    #[test]
    fn sockets_share_a_bounded_pool() {
        let first = SenderPool::pick() as *const Worker;
        let second = SenderPool::pick() as *const Worker;
        assert_eq!(SenderPool::width().min(1), 1, "the pool is never empty");
        assert!(SenderPool::width() <= MAX_WORKERS, "the cap must hold");
        if SenderPool::width() > 1 {
            assert_ne!(first, second, "round-robin must hand out distinct workers");
        }
    }
}
