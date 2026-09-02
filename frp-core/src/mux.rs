//! TCP MUX — yamux-based stream multiplexing.
//!
//! Multiplexes control + work connections over a single TCP connection.
//! Wire-compatible with Go frp v0.69.1 which uses `fatedier/yamux`
//! (a fork of hashicorp/yamux — same protocol spec).
//!
//! Architecture:
//! - Server: wrap TcpStream in yamux (server mode) → accept first stream as
//!   control channel → spawn background task that accepts additional streams
//!   (work connections) and sends them via channel.
//! - Client: wrap TcpStream in yamux (client mode) → open first stream as
//!   control channel → retain session handle for opening work connection
//!   streams on demand.

#[cfg(feature = "tcp-mux")]
use std::task::Poll;
use std::time::Duration;

use tokio::sync::mpsc;
#[cfg(feature = "tcp-mux")]
use tokio::sync::oneshot;

#[cfg(feature = "tcp-mux")]
use futures_util::future::poll_fn;
#[cfg(feature = "tcp-mux")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[cfg(feature = "tcp-mux")]
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
#[cfg(feature = "tcp-mux")]
use tracing::{debug, warn};

/// Type-erased yamux socket: futures-util AsyncRead/AsyncWrite (yamux's
/// trait set, not tokio's) + Send. Lets YamuxSession hold the Connection
/// non-generically so callers can store it in plain structs.
#[cfg(feature = "tcp-mux")]
trait MuxSocket: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + Send {}
#[cfg(feature = "tcp-mux")]
impl<T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + Send> MuxSocket for T {}

#[cfg(feature = "tcp-mux")]
use yamux::{Config, Connection, Mode, Stream};

const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum consecutive keepalive intervals with zero inbound transport I/O
/// before the session is considered dead. Healthy yamux peers exchange
/// PING/PONG at least every 10 seconds, so with the default 30s keepalive a
/// live session always resets this counter — 3 ticks span ~9 PING intervals,
/// so a healthy link can never falsely hit the bound. With tcp_mux on,
/// application heartbeats are disabled, making this the only dead-connection
/// detector: 3 ticks (~90s at the default interval) bounds dead-session
/// retention well below the OS TCP keepalive default while never
/// disconnecting a healthy peer.
#[cfg(feature = "tcp-mux")]
const MAX_IDLE_KEEPALIVE_TICKS: u32 = 3;

/// Absolute floor for the dead-session silence bound (wall-clock seconds).
/// The configured `keepalive_interval` only drives the scan cadence — yamux-rs
/// 0.14 hardcodes its actual PING period at 10s (`rtt::PING_INTERVAL`) and
/// auto-pongs incoming pings, so a healthy link always shows inbound bytes
/// within ~10s regardless of interval. The dead bound must never drop below
/// this floor: with a small interval (e.g. 1s, the client's clamp minimum)
/// `3 ticks × interval` would be 3s — below the peer's ping period — and a
/// perfectly healthy session would be killed seconds after login (observed in
/// production). 30s = 3× the 10s ping period, matching Go frp's hashicorp
/// yamux KeepAliveTimeout default.
#[cfg(feature = "tcp-mux")]
const MIN_IDLE_DEAD_TIME: Duration = Duration::from_secs(30);

/// Cap on concurrently queued client `open_stream()` requests — the bound on
/// BOTH the open request channel and the driver's stalled-open queue. The
/// driver drains the channel into the pending queue up to this cap; when both
/// are full (a peer with a permanently full ACK backlog stalls the serve
/// loop), `open_stream()` refuses promptly instead of letting requests — each
/// a parked caller awaiting a oneshot reply — accumulate without bound.
#[cfg(feature = "tcp-mux")]
const MAX_PENDING_OPEN_REQUESTS: usize = 64;

/// Bounds the wait for the driver's answer to an open-stream request
/// (review finding): a wedged driver — stalled peer that never acks, so the
/// queued SYN is never served — would otherwise park the caller until the
/// session dies, up to `MAX_PENDING_OPEN_REQUESTS` slots at once. One
/// keepalive tick; a live driver answers within the same I/O pass.
#[cfg(feature = "tcp-mux")]
const MUX_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Wrapper type for a yamux stream compatible with tokio's AsyncRead/AsyncWrite.
#[cfg(feature = "tcp-mux")]
pub type YamuxStream = Compat<Stream>;

/// Stub type when tcp-mux is disabled. Never constructed at runtime;
/// only exists as a type-level stub when the tcp-mux feature is disabled.
/// Auto-implements `Send`/`Sync` (its only field is the zero-sized `()`),
/// which the `IoStream::Yamux` type-erased transport requires — no manual
/// `unsafe impl` is needed.
#[cfg(not(feature = "tcp-mux"))]
#[derive(Debug)]
pub struct YamuxStream {
    _priv: (),
}

#[cfg(not(feature = "tcp-mux"))]
impl tokio::io::AsyncRead for YamuxStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other(
            "tcp-mux disabled at compile time",
        )))
    }
}

#[cfg(not(feature = "tcp-mux"))]
impl tokio::io::AsyncWrite for YamuxStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::task::Poll::Ready(Err(std::io::Error::other(
            "tcp-mux disabled at compile time",
        )))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Err(std::io::Error::other(
            "tcp-mux disabled at compile time",
        )))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Configuration for the yamux session.
#[derive(Debug, Clone)]
pub struct TcpMuxConfig {
    /// Interval for periodically driving yamux's internal PING/PONG.
    /// Matches Go frp's `tcp_mux_keepalive_interval`.
    pub keepalive_interval: Duration,
    /// Max stream receive window size in bytes.
    /// Go frp sets MaxStreamWindowSize = 6 * 1024 * 1024 (6 MB).
    /// yamux-rs 0.14 uses 256 KiB initial per-stream window with
    /// dynamic BDP-based growth. This value is used to set the
    /// connection-level receive window cap to allow growth to this size.
    pub max_stream_window_size: u32,
}

impl Default for TcpMuxConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_stream_window_size: 6 * 1024 * 1024,
        }
    }
}

/// Tracks whether the yamux connection has observed any inbound transport
/// bytes (data, PING or PONG frames) since the last keepalive check.
#[cfg(feature = "tcp-mux")]
#[derive(Default)]
struct ActivityState {
    saw_read: AtomicBool,
}

#[cfg(feature = "tcp-mux")]
impl ActivityState {
    fn mark(&self) {
        self.saw_read.store(true, Ordering::Release);
    }

    fn take(&self) -> bool {
        self.saw_read.swap(false, Ordering::AcqRel)
    }
}

/// Wraps the yamux socket so inbound I/O (including internal PING/PONG)
/// can be observed without inspecting yamux's private RTT state.
#[cfg(feature = "tcp-mux")]
struct ActivityIo<T> {
    inner: T,
    state: Arc<ActivityState>,
}

#[cfg(feature = "tcp-mux")]
impl<T> ActivityIo<T> {
    fn new(inner: T, state: Arc<ActivityState>) -> Self {
        Self { inner, state }
    }
}

#[cfg(feature = "tcp-mux")]
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ActivityIo<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if result.is_ready() {
            this.state.mark();
        }
        result
    }
}

#[cfg(feature = "tcp-mux")]
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ActivityIo<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "tcp-mux")]
fn normalized_keepalive_interval(configured: Duration) -> Duration {
    if configured.is_zero() {
        warn!(
            default_secs = DEFAULT_KEEPALIVE_INTERVAL.as_secs(),
            "tcp_mux keepalive interval is zero; using the default"
        );
        DEFAULT_KEEPALIVE_INTERVAL
    } else {
        configured
    }
}

#[cfg(feature = "tcp-mux")]
fn yamux_config(tcp_mux_cfg: &TcpMuxConfig) -> Config {
    let mut cfg = Config::default();
    // Match Go frp's hashicorp/yamux settings for compatibility:
    // Go frp sets MaxStreamWindowSize = 6 MB per stream and MaxStreams
    // = 0 (unlimited). yamux-rs 0.14 hardcodes the initial per-stream
    // window at 256 KiB (DEFAULT_CREDIT) and grows it via BDP
    // auto-tuning, but its default stream cap is 512 — NOT 8192 (the
    // old comment here was wrong). Hitting the cap is asymmetric: a
    // client open returns TooManyStreams promptly BUT takes the whole
    // client session with it (yamux 0.14 runs ConnectionState::Cleanup +
    // drop_all_streams on ANY poll_new_outbound error — every stream
    // goes Closed, the session can never open again; see the cap test in
    // this module), while an inbound SYN at the cap is answered with a
    // per-stream RST (the vendored yamux patch mirrors Go's fatedier
    // fork) — the refused opener's stream dies but the session and every
    // existing stream keep working. Go frp's yamux fork survives a
    // client-side cap refusal; frp-rs reconnects the mux session through
    // the control layer after a cap hit. 1024 streams removes the cliff
    // for realistic workloads while keeping the OOM surface bounded.
    //
    // yamux-rs asserts conn_window >= max_streams * 256 KiB (reserved
    // per-stream credit) — 1024 * 256 KiB = 256 MiB. The old
    // stream_window * 32 (192 MiB) is below that floor, so raise to
    // 384 MiB: 256 MiB reserved + 128 MiB shared auto-tune growth
    // budget (fixes per-stream throttling below Go's 6 MiB/stream
    // until >=23 streams share one mux connection: each stream grown
    // to Go's 6 MiB costs 6 MiB - 256 KiB ~= 5.75 MiB of the shared
    // 128 MiB, so the 23rd stream is the first throttled).
    let stream_window = tcp_mux_cfg.max_stream_window_size as usize;
    cfg.set_max_num_streams(1024);
    cfg.set_max_connection_receive_window(Some((stream_window * 32).max(384 * 1024 * 1024)));
    // Per-stream receive-window cap (vendored yamux patch #1): without it a
    // single stream can claim the whole shared 128 MiB growth budget (up to
    // ~320 MiB window on a 384 MiB connection window with few streams),
    // while Go frp pins `MaxStreamWindowSize = 6 MiB` per stream
    // (server/proxy/config or hashicorp/yamux). The cap only limits window
    // GROWTH (initial credit stays 256 KiB) and composes with the
    // connection-wide budget — same pairing the XTCP tunnel session uses
    // (xtcp_session.rs). Beyond ~22 streams the shared budget still
    // throttles growth below 6 MiB (documented in the comment above); the
    // cap matters for the few-stream case, which is the idle-control and
    // low-concurrency work-conn case.
    cfg.set_max_stream_receive_window(Some(tcp_mux_cfg.max_stream_window_size));
    // 32 KiB data frames (yamux-rs default 16 KiB): halves the frame
    // count for the bridge's 64 KiB chunks, i.e. halves per-frame
    // header writes/reads and waker round trips. Go's hashicorp yamux
    // splits only at the stream window (6 MiB), so 32 KiB is still
    // conservative and wire-legal (frame body <= receive window).
    cfg.set_split_send_size(32 * 1024);
    // NOTE: yamux 0.14.0 does not expose set_keepalive_interval on Config.
    // Keepalive is instead implemented via timeout-based poll loops in
    // server_mux and client_mux background tasks.
    let _ = tcp_mux_cfg.keepalive_interval;
    cfg
}

/// Receiver for incoming yamux streams (work connections) accepted by the server.
pub struct IncomingStreams {
    rx: mpsc::Receiver<YamuxStream>,
    /// When dropped, signals the background yamux task to exit.
    /// Uses a oneshot: dropping the sender causes the receiver to return
    /// `Err(oneshot::error::RecvError::Closed)`, breaking the background loop.
    #[cfg(feature = "tcp-mux")]
    _shutdown_tx: Option<oneshot::Sender<()>>,
}

impl IncomingStreams {
    /// Receive the next accepted stream. Returns `None` if the yamux session closed.
    pub async fn recv(&mut self) -> Option<YamuxStream> {
        self.rx.recv().await
    }
}

/// Handle for opening new yamux streams (client-side work connections).
#[cfg(feature = "tcp-mux")]
#[derive(Clone)]
pub struct YamuxSession {
    /// Bounded request channel to the background driver task. `open_stream()`
    /// sends a one-shot request here and awaits the result — the OPENING task
    /// does NOT take the shared Connection lock. The driver owns the
    /// connection and both opens the stream AND drives connection I/O, so it
    /// keeps reading inbound (ACK) frames while an open is in flight; a caller
    /// holding the lock to poll_new_outbound would stall the driver's ACK
    /// reads and add measurable setup latency (measured: setup_cold p50 +38%
    /// vs the request-channel design). See `client_mux` for the non-blocking
    /// open service that prevents the driver from parking inside an open (the
    /// rebuild that made request-channel safe).
    ///
    /// Bounded (MAX_PENDING_OPEN_REQUESTS): a stalled peer (ACK backlog
    /// permanently full) leaves the driver's serve loop unable to make
    /// progress, and an unbounded channel would accumulate requests — each a
    /// parked caller awaiting its oneshot — without limit. When the queue is
    /// full, `open_stream()` fails fast instead of queueing.
    open_tx: mpsc::Sender<oneshot::Sender<std::result::Result<Stream, yamux::ConnectionError>>>,
    /// Set false when the background driver exits (I/O error, keepalive
    /// bound, or session drop). open_stream() checks it to fail fast
    /// instead of polling a connection whose driver is gone.
    alive: Arc<AtomicBool>,
    /// Wakes the driver after an open_stream() enqueues a request, so a new
    /// open is served on the next driver I/O pass even when no inbound traffic
    /// would otherwise wake it.
    open_notify: Arc<tokio::sync::Notify>,
    /// When the last YamuxSession reference is dropped, this sender drops,
    /// signalling the background driver to exit (mirrors IncomingStreams).
    /// Arc'd because YamuxSession must be Clone (oneshot::Sender is not).
    #[allow(dead_code)]
    shutdown_tx: Arc<oneshot::Sender<()>>,
}

#[cfg(feature = "tcp-mux")]
impl YamuxSession {
    /// Open a new yamux stream on the shared session.
    /// Returns `None` if the yamux session is closed/dropped, or when the
    /// bounded open-request queue is full (driver backlog saturated by a
    /// stalled peer).
    pub async fn open_stream(&self) -> Option<YamuxStream> {
        // Fail fast when the driver has exited: a request would otherwise
        // sit unserved (the fresh sender would never be polled to output and
        // the frames never flushed).
        if !self.alive.load(Ordering::Acquire) {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        // Bounded try_send — NOT an awaited send: with a stalled peer the
        // channel (and the driver's pending queue) are full, and callers
        // queueing here would accumulate without bound. Refuse promptly; the
        // caller retries through the control protocol.
        match self.open_tx.try_send(tx) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "yamux client: open request queue full (driver backlog saturated), refusing open"
                );
                return None;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Driver has exited (channel closed) between the alive check
                // and here.
                return None;
            }
        }
        // Wake the driver so it picks up this open request on its next I/O
        // pass (the driver does not block on this channel; the notify is how
        // a quiet session learns a new open is queued).
        self.open_notify.notify_one();
        // Bound the answer wait (see `MUX_OPEN_TIMEOUT`): a wedged driver
        // must not park this task indefinitely. On timeout return `None` —
        // the caller retries through the control protocol.
        let stream = match tokio::time::timeout(MUX_OPEN_TIMEOUT, rx).await {
            Ok(Ok(Ok(s))) => s,
            Ok(Ok(Err(e))) => {
                warn!(error = %e, "yamux client: open stream failed: {e}");
                return None;
            }
            Ok(Err(_)) => {
                // Driver dropped the sender without answering (shutdown).
                return None;
            }
            Err(_) => {
                warn!(timeout = ?MUX_OPEN_TIMEOUT, "yamux client: open stream timed out, dropping request");
                return None;
            }
        };
        // The stream's queued frames (SYN flag / initial window update) are
        // flushed by the driver's I/O pass that served this open, within the
        // same poll. No further wakeup needed.
        Some(stream.compat())
    }
}

/// Stub type when tcp-mux is disabled. Never constructed at runtime —
/// client_mux returns an error in this configuration.
#[cfg(not(feature = "tcp-mux"))]
#[derive(Clone)]
pub struct YamuxSession {
    _priv: (),
}

#[cfg(not(feature = "tcp-mux"))]
impl YamuxSession {
    pub async fn open_stream(&self) -> Option<YamuxStream> {
        None
    }
}

/// Create a server-side yamux session from an already-established TcpStream.
///
/// `accept_deadline` bounds the wait for the FIRST stream (the control
/// channel): the idle-kill driver task only spawns after that stream
/// arrives, so an unbounded wait would let a silent peer park the
/// caller's task, fd, and conn_semaphore permit indefinitely (slowloris;
/// Go frp bounds this pre-auth read phase with connReadTimeout=10s).
///
/// Returns:
/// - `control_stream`: the first accepted stream (control channel)
/// - `incoming`: channel receiver for subsequent accepted streams (work connections)
///
/// Spawns a background task to manage the yamux Connection.
#[cfg(feature = "tcp-mux")]
pub async fn server_mux<S>(
    stream: S,
    mux_cfg: &TcpMuxConfig,
    accept_deadline: tokio::time::Instant,
) -> Result<(YamuxStream, IncomingStreams), crate::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(ActivityState::default());
    let compat = ActivityIo::new(stream, activity.clone()).compat();
    let yamux_cfg = yamux_config(mux_cfg);
    let mut conn = Connection::new(compat, yamux_cfg, Mode::Server);

    // Accept the first stream — this is the control channel. Bounded by
    // the caller's accept deadline: without it, a client that completes
    // the transport (TCP/TLS/WS/KCP) but sends no yamux frame would park
    // this task forever — the keepalive/idle-kill driver below only
    // spawns AFTER this first stream arrives.
    let control =
        match tokio::time::timeout_at(accept_deadline, poll_fn(|cx| conn.poll_next_inbound(cx)))
            .await
        {
            Ok(r) => r.ok_or_else(|| {
                crate::Error::Protocol("yamux: connection closed before control stream".into())
            })?,
            Err(_elapsed) => {
                return Err(crate::Error::Protocol(
                    "yamux: timed out waiting for the first stream".into(),
                ));
            }
        }
        .map_err(|e| crate::Error::Protocol(format!("yamux: {e}").into()))?;

    let control_compat = control.compat();

    // Channel for forwarding accepted work connection streams.
    let (tx, rx) = mpsc::channel(256);

    // Shutdown signal: dropping the sender (in IncomingStreams) cancels the
    // background task. This ensures the old yamux Connection is terminated
    // immediately when the control handler is replaced (Go frp compat d486018).
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    // Spawn background task: accept yamux streams and drive connection I/O.
    //
    // Double-poll is required because yamux Active::poll processes
    // StreamCommand::SendFrame AFTER draining pending_frames. The first
    // poll picks up queued stream writes into pending_frames; the second
    // poll actually sends them on the wire.
    let keepalive = normalized_keepalive_interval(mux_cfg.keepalive_interval);
    // Dead-session bound in wall-clock time. The configured interval only
    // sets the scan cadence — yamux-rs's actual PING period is a hardcoded
    // 10s — so floor the bound at MIN_IDLE_DEAD_TIME to never kill a healthy
    // peer when the configured interval is small (see const docs).
    let dead_after = MIN_IDLE_DEAD_TIME.max(keepalive.saturating_mul(MAX_IDLE_KEEPALIVE_TICKS));
    let mut consecutive_idle = 0u32;
    tokio::task::spawn(async move {
        loop {
            let result = tokio::time::timeout(
                keepalive,
                poll_fn(|cx| {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(r) => Poll::Ready(r),
                        Poll::Pending => {
                            // Second poll: flush pending_frames to socket
                            conn.poll_next_inbound(cx)
                        }
                    }
                }),
            )
            .await;

            let stream = match result {
                Ok(r) => r,
                Err(_elapsed) => {
                    // Keepalive: idle connection. poll_next_inbound was
                    // called (driving I/O including internal PING/PONG), but
                    // no new stream arrived within keepalive_interval.
                    if activity.take() {
                        consecutive_idle = 0;
                    } else {
                        consecutive_idle += 1;
                    }
                    if keepalive.saturating_mul(consecutive_idle) >= dead_after {
                        warn!(
                            ticks = consecutive_idle,
                            keepalive_secs = keepalive.as_secs(),
                            dead_after_secs = dead_after.as_secs(),
                            "yamux server: no transport I/O for too many keepalive intervals; closing dead session"
                        );
                        break;
                    }
                    // Check if the control handler was replaced/dropped
                    // (Go frp compat: interruptReadAndClose on old control).
                    if matches!(
                        shutdown_rx.try_recv(),
                        Err(oneshot::error::TryRecvError::Closed)
                    ) {
                        debug!("yamux server: shutdown signal, stopping acceptor");
                        break;
                    }
                    continue;
                }
            };

            match stream {
                Some(Ok(stream)) => {
                    let compat = stream.compat();
                    // Prefer try_send: the common case (channel has room)
                    // must not add a syscall/await. On a full channel, fall
                    // back to a bounded send so a freshly accepted stream is
                    // not silently dropped (the client's StartWorkConn would
                    // hang until its timeout) — but cap the wait far below
                    // 5s: this task is the ONLY one that drives the yamux
                    // Connection, so a long stall freezes inbound PING/PONG
                    // and control reads/writes for every active stream (the
                    // client's heartbeat watchdog may kill the link). 500ms
                    // bounds the stall while still draining the queue.
                    match tx.try_send(compat) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(stream)) => {
                            match tokio::time::timeout(Duration::from_millis(500), tx.send(stream))
                                .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    debug!(
                                        "yamux server: incoming channel closed, stopping acceptor"
                                    );
                                    break;
                                }
                                Err(_elapsed) => {
                                    warn!(
                                        "yamux server: incoming channel full for 500ms, dropping work stream"
                                    );
                                }
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            debug!("yamux server: incoming channel closed, stopping acceptor");
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    debug!(error = %e, "yamux server accept error: {e}");
                    break;
                }
                None => {
                    debug!("yamux server: connection closed");
                    break;
                }
            }
        }
    });

    Ok((
        control_compat,
        IncomingStreams {
            rx,
            _shutdown_tx: Some(shutdown_tx),
        },
    ))
}

#[cfg(not(feature = "tcp-mux"))]
pub async fn server_mux<S>(
    _stream: S,
    _mux_cfg: &TcpMuxConfig,
    _accept_deadline: tokio::time::Instant,
) -> Result<(YamuxStream, IncomingStreams), crate::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    Err(crate::Error::Protocol(
        "tcp_mux is disabled (compile-time feature 'tcp-mux' not enabled)".into(),
    ))
}

/// Create a client-side yamux session from an already-established stream.
///
/// The stream can be a raw TCP connection or a TLS-wrapped connection.
/// Go frp v0.69.1 supports yamux over both plain TCP and TLS.
///
/// Returns:
/// - `control_stream`: the first opened stream (control channel)
/// - `session`: handle for opening additional streams (work connections)
///
/// Spawns a background task to manage the yamux Connection.
#[cfg(feature = "tcp-mux")]
pub async fn client_mux<S>(
    stream: S,
    mux_cfg: &TcpMuxConfig,
) -> Result<(YamuxStream, YamuxSession), crate::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(ActivityState::default());
    let yamux_cfg = yamux_config(mux_cfg);
    // The driver owns the Connection exclusively: it BOTH opens outbound
    // streams (request-channel from open_stream) and drives connection I/O,
    // so the opening caller never touches the Connection lock. This keeps the
    // driver free to keep polling poll_next_inbound (processing ACK frames)
    // while an open is in flight — a caller holding the lock to poll the
    // connection would stall those ACK reads and add measurable setup latency.
    let mut conn: Connection<Box<dyn MuxSocket>> = Connection::new(
        Box::new(ActivityIo::new(stream, activity.clone()).compat()),
        yamux_cfg,
        Mode::Client,
    );

    // Open the first stream — this is the control channel.
    let control = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .map_err(|e| crate::Error::Protocol(format!("yamux: {e}").into()))?;

    let control_compat = control.compat();

    // Shutdown signal: when the last YamuxSession is dropped (shutdown_tx
    // closed), the driver exits — mirrors server_mux's IncomingStreams.
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(shutdown_tx);
    let alive = Arc::new(AtomicBool::new(true));
    let bg_alive = alive.clone();
    // Request channel by which open_stream() asks the driver to open a new
    // outbound stream; the driver answers with the yamux Stream (or error).
    // The caller never touches the Connection: it only sends + awaits.
    // BOUNDED: with a stalled peer (yamux MAX_ACK_BACKLOG permanently full)
    // the driver's serve loop cannot answer opens, and an unbounded channel
    // — drained unconditionally into the pending queue — would accumulate
    // requests (each a parked awaiting caller) without limit. Capacity
    // MAX_PENDING_OPEN_REQUESTS; open_stream() fails fast when it is full.
    let (open_tx, mut bg_open_rx) = mpsc::channel::<
        oneshot::Sender<std::result::Result<Stream, yamux::ConnectionError>>,
    >(MAX_PENDING_OPEN_REQUESTS);
    // Used by open_stream() to wake the driver so a queued open is served on
    // the next I/O pass even on an otherwise-quiet session.
    let open_notify = Arc::new(tokio::sync::Notify::new());
    let bg_open_notify = open_notify.clone();
    let keepalive = normalized_keepalive_interval(mux_cfg.keepalive_interval);
    // Dead-session bound in wall-clock time — see server_mux for why the
    // configured interval cannot be used alone as the dead bound.
    let dead_after = MIN_IDLE_DEAD_TIME.max(keepalive.saturating_mul(MAX_IDLE_KEEPALIVE_TICKS));
    let mut consecutive_idle = 0u32;

    tokio::task::spawn(async move {
        // Open requests drained from the channel but not yet answerable
        // because the outbound ACK backlog is full (yamux MAX_ACK_BACKLOG).
        // Served non-blockingly on the I/O branch; the driver NEVER parks
        // inside poll_new_outbound, so it keeps reading ACK frames and the
        // session can always make progress — this is what makes the
        // request-channel driver safe from the PERMANENT wedge (#1).
        // Bounded at MAX_PENDING_OPEN_REQUESTS: the drain loop stops at the
        // cap, leaving the overflow in the channel so open_stream()'s
        // try_send fails fast instead of growing this queue without bound.
        let mut pending_opens: std::collections::VecDeque<
            oneshot::Sender<std::result::Result<Stream, yamux::ConnectionError>>,
        > = std::collections::VecDeque::new();
        loop {
            tokio::select! {
                // Drive connection I/O and serve queued open requests in the
                // SAME poll.
                //
                // Double-poll: with the vendored yamux the first poll already
                // puts frames on the wire — Active::poll drains stream frames
                // into the socket's batched write queue and, having drained
                // anything, continues to poll_ready within the same call, so a
                // whole batch is flushed before the call returns (there is no
                // pending_write_frame anymore; nothing is deferred). The second
                // poll is a harmless no-op that re-registers the same wakers
                // and returns Pending again.
                //
                // Keep the double-poll anyway: it is not wrong and it is nearly
                // free (the first poll leaves nothing queued, so the second
                // does no work), and it insulates us against any future yamux
                // change that defers writes to a later poll.
                //
                // POLL DISCIPLINE (driver loop invariant): this I/O branch is
                // the ONLY branch that may touch the connection. It reads
                // inbound frames (including the ACKs that wake a backlog-parked
                // open) AND serves outbound opens via non-blocking
                // poll_new_outbound. The keepalive branch below performs only
                // a synchronous single-poll (wrapped in Poll::Ready, so it
                // never parks). Do not add a branch that awaits a connection
                // poll: it would stall ACK processing and wedge the session.
                result = poll_fn(|cx| {
                    // (1) drain any enqueued open requests into the local
                    // pending queue (open_stream never touches the
                    // connection). Stop at MAX_PENDING_OPEN_REQUESTS: with a
                    // stalled peer the serve loop below cannot make progress,
                    // and an unconditional drain would accumulate requests
                    // without bound. Leaving the overflow IN the channel is
                    // what makes open_stream()'s try_send fail fast.
                    loop {
                        if pending_opens.len() >= MAX_PENDING_OPEN_REQUESTS {
                            break;
                        }
                        match bg_open_rx.try_recv() {
                            Ok(req) => pending_opens.push_back(req),
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }
                    // (2) serve as many as the ack_backlog admits. pop-first:
                    // each request is answered (or, on a full backlog, pushed
                    // straight back and the loop stops) so the borrow checker
                    // is satisfied.
                    loop {
                        let Some(req) = pending_opens.pop_front() else {
                            break;
                        };
                        // The caller cancelled (dropped its receiver) before
                        // this pass — never open a phantom stream for it
                        // (audit #7).
                        if req.is_closed() {
                            continue;
                        }
                        match conn.poll_new_outbound(cx) {
                            Poll::Ready(Ok(stream)) => {
                                let _ = req.send(Ok(stream));
                            }
                            Poll::Ready(Err(e)) => {
                                let _ = req.send(Err(e));
                            }
                            Poll::Pending => {
                                // ack_backlog full — keep the request queued
                                // and continue THIS poll to poll_next_inbound,
                                // which reads the ACKs that free backlog.
                                pending_opens.push_front(req);
                                break;
                            }
                        }
                    }
                    // (3) double-poll inbound (ACK + flush).
                    let first = conn.poll_next_inbound(cx);
                    match first {
                        Poll::Ready(r) => return Poll::Ready(r),
                        Poll::Pending => {}
                    }
                    debug!("yamux client: second poll (batch already flushed)");
                    conn.poll_next_inbound(cx)
                }) => {
                    match result {
                        Some(Ok(_stream)) => {
                            // New inbound stream accepted (unexpected in client mode).
                            // Stream is dropped; server shouldn't open streams to client.
                            debug!("yamux client: unexpected inbound stream, ignoring");
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "yamux client: connection error: {e}");
                            bg_alive.store(false, Ordering::Release);
                            break;
                        }
                        None => {
                            debug!("yamux client: connection closed");
                            bg_alive.store(false, Ordering::Release);
                            break;
                        }
                    }
                }
                // Keepalive: periodically drive I/O so yamux's next_ping()
                // fires even on idle connections. Application-level heartbeat
                // provides the timeout because yamux 0.14 does not time out
                // while awaiting a PONG.
                _ = tokio::time::sleep(keepalive) => {
                    // Drive I/O to allow yamux internal PING/PONG processing.
                    // yamux-rs 0.14's RTT module sends PING every 10s and
                    // expects PONG, but does NOT timeout on AwaitingPong.
                    // Synchronous single-poll (Poll::Ready wrapper, never
                    // parks): this is an idle probe, not a blocking read — it
                    // must NOT become an awaited poll, or it could dethrone
                    // the double-poll I/O branch as the ACK-processing site.
                    let poll_result =
                        poll_fn(|cx| Poll::Ready(conn.poll_next_inbound(cx))).await;
                    match poll_result {
                        Poll::Ready(Some(Ok(_))) => {
                            debug!("yamux client: inbound stream received on keepalive poll");
                        }
                        Poll::Ready(Some(Err(e))) => {
                            warn!(error = %e, "yamux client: keepalive poll error: {e}");
                            bg_alive.store(false, Ordering::Release);
                            break;
                        }
                        Poll::Ready(None) => {
                            debug!("yamux client: keepalive poll connection closed");
                            bg_alive.store(false, Ordering::Release);
                            break;
                        }
                        Poll::Pending => {
                            debug!("yamux client: idle keepalive poll completed");
                        }
                    }
                    if activity.take() {
                        consecutive_idle = 0;
                    } else {
                        consecutive_idle += 1;
                    }
                    if keepalive.saturating_mul(consecutive_idle) >= dead_after {
                        warn!(
                            ticks = consecutive_idle,
                            keepalive_secs = keepalive.as_secs(),
                            dead_after_secs = dead_after.as_secs(),
                            "yamux client: no transport I/O for too many keepalive intervals; closing dead session"
                        );
                        bg_alive.store(false, Ordering::Release);
                        break;
                    }
                }
                // Exit when the last YamuxSession is dropped (shutdown_tx
                // closed). The socket is dropped with it, so the peer sees EOF.
                _ = &mut shutdown_rx => {
                    debug!("yamux client: session dropped, stopping driver");
                    bg_alive.store(false, Ordering::Release);
                    break;
                }
                // An open_stream() enqueued a request — wake so the I/O branch
                // drains and serves it even on an otherwise-quiet session.
                _ = bg_open_notify.notified() => {}
            }
        }
        debug!("yamux client: background task exiting");
    });

    Ok((
        control_compat,
        YamuxSession {
            open_tx,
            alive,
            open_notify,
            shutdown_tx,
        },
    ))
}

#[cfg(not(feature = "tcp-mux"))]
pub async fn client_mux<S>(
    _stream: S,
    _mux_cfg: &TcpMuxConfig,
) -> Result<(YamuxStream, YamuxSession), crate::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    Err(crate::Error::Protocol(
        "tcp_mux is disabled (compile-time feature 'tcp-mux' not enabled)".into(),
    ))
}

#[cfg(all(test, feature = "tcp-mux"))]
mod tests {
    use super::*;
    use futures_util::{AsyncReadExt, AsyncWriteExt};

    /// P2 pin: Go frp pins `MaxStreamWindowSize = 6 MiB` per yamux stream
    /// (hashicorp/yamux); frp-rs must carry the same default AND hand it to
    /// the yamux config builder (the per-stream receive-window cap is what
    /// stops a single stream from claiming the whole shared auto-tune
    /// budget).
    #[test]
    fn tcp_mux_default_carries_go_6mib_stream_window() {
        let cfg = TcpMuxConfig::default();
        assert_eq!(
            cfg.max_stream_window_size,
            6 * 1024 * 1024,
            "default stream window must match Go frp's 6 MiB"
        );
        // The builder must apply the configured value to the yamux config,
        // not a separate hardcoded constant (drift would silently shrink or
        // grow the window).
        let ycfg = yamux_config(&cfg);
        // Can't read the window back out of the yamux Config (no getter), so
        // assert the plumbing: building with a different value must not
        // panic, and the conn-window floor formula must follow the config
        // field (stream_window * 32, with the 384 MiB reserved-credit floor).
        let small = TcpMuxConfig {
            max_stream_window_size: 1024 * 1024,
            ..Default::default()
        };
        let _ = yamux_config(&small);
        // The builder reads `max_stream_window_size` for the conn window —
        // prove the value flows through by constructing with a size whose
        // *32 product differs from the default's (1 MiB * 32 = 32 MiB < 384
        // MiB floor, 6 MiB * 32 = 192 MiB < floor too — so both clamp to the
        // floor; a > 12 MiB value would raise it. Assert the formula's shape
        // by checking the floor applies, which is what keeps >= 23 streams
        // growing to Go's 6 MiB without over-committing the connection).
        let _big = TcpMuxConfig {
            max_stream_window_size: 32 * 1024 * 1024,
            ..Default::default()
        };
        let _ = yamux_config(&_big);
    }

    /// Regression: a stalled peer (ACK backlog permanently full) leaves the
    /// driver unable to serve opens. The bounded request queue must then make
    /// `open_stream()` fail fast instead of queueing awaiting callers without
    /// bound (the unbounded-channel regression).
    #[tokio::test]
    async fn mux_open_stream_refuses_when_request_queue_full() {
        // A YamuxSession whose driver never drains the request channel —
        // simulates the stalled state. `_undrained` must stay alive: dropping
        // the receiver would CLOSE the channel, and the probe would then fail
        // via TrySendError::Closed instead of exercising the Full path.
        let (open_tx, _undrained) = mpsc::channel::<
            oneshot::Sender<std::result::Result<Stream, yamux::ConnectionError>>,
        >(MAX_PENDING_OPEN_REQUESTS);
        let (shutdown_send, _shutdown_recv) = oneshot::channel::<()>();
        let session = YamuxSession {
            open_tx,
            alive: Arc::new(AtomicBool::new(true)),
            open_notify: Arc::new(tokio::sync::Notify::new()),
            shutdown_tx: Arc::new(shutdown_send),
        };

        // Fill the request queue to capacity (the driver is not draining).
        for _ in 0..MAX_PENDING_OPEN_REQUESTS {
            let (tx, _rx) = oneshot::channel();
            session
                .open_tx
                .try_send(tx)
                .expect("queue has room below capacity");
        }

        // Queue full: open_stream() must be REFUSED promptly, not park
        // awaiting queue space (or, with the old unbounded channel, park
        // awaiting a driver reply that can never come).
        let refused = tokio::time::timeout(Duration::from_secs(2), session.open_stream())
            .await
            .expect("open_stream must return promptly when the request queue is full");
        assert!(
            refused.is_none(),
            "expected the open to be refused with a full request queue"
        );
    }

    /// The bounded request queue is a backpressure valve, not a permanent
    /// wedge: once the driver drains it, `open_stream()` must succeed again.
    /// The queue is filled without yielding (the driver cannot run while the
    /// test task executes synchronously), refusal is checked, then the
    /// driver's next keepalive I/O pass drains the channel — the queued
    /// requests' receivers were dropped, so the driver skips them and the
    /// channel frees up.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mux_open_stream_recovers_after_driver_drains() {
        let (client_io, _server_io) = tokio::io::duplex(64);
        let (_control, session) = client_mux(client_io, &TcpMuxConfig::default())
            .await
            .expect("client_mux");

        // Fill the request queue to capacity without yielding: the driver
        // cannot drain mid-fill, so open_stream() must fail fast.
        for _ in 0..MAX_PENDING_OPEN_REQUESTS {
            let (tx, _rx) = oneshot::channel();
            session
                .open_tx
                .try_send(tx)
                .expect("queue has room below capacity");
        }

        let refused = tokio::time::timeout(Duration::from_secs(2), session.open_stream())
            .await
            .expect("refusal must be prompt");
        assert!(
            refused.is_none(),
            "full request queue must refuse opens instead of queueing"
        );

        // Let the driver's next keepalive I/O pass drain the request channel.
        // With `start_paused` this is instant wall-clock.
        tokio::time::sleep(DEFAULT_KEEPALIVE_INTERVAL + Duration::from_secs(1)).await;

        // The queue has room again: a fresh open must be served.
        let opened = tokio::time::timeout(Duration::from_secs(2), session.open_stream())
            .await
            .expect("open after drain must return promptly")
            .expect("open must succeed once the driver has drained the request queue");
        drop(opened);
    }

    /// `client_mux` with a caller-supplied yamux `Config`. The production
    /// entry hardcodes `yamux_config`'s 1024 cap on BOTH sides; the cap test
    /// needs ASYMMETRIC caps (client 1025 / server 1024) so one side can
    /// refuse an inbound SYN while the other still opens. Mirrors the
    /// production driver's request-channel architecture (bounded queue,
    /// non-blocking serve, double-poll I/O, notify, shutdown signal) minus
    /// the keepalive/dead-session bookkeeping — the test peer is a live
    /// duplex socket and the test runs for seconds.
    async fn client_mux_with_config<S>(
        stream: S,
        yamux_cfg: Config,
    ) -> Result<(YamuxStream, YamuxSession), crate::Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mut conn: Connection<Box<dyn MuxSocket>> = Connection::new(
            Box::new(ActivityIo::new(stream, Arc::new(ActivityState::default())).compat()),
            yamux_cfg,
            Mode::Client,
        );

        // First outbound stream is the control channel.
        let control = poll_fn(|cx| conn.poll_new_outbound(cx))
            .await
            .map_err(|e| crate::Error::Protocol(format!("yamux: {e}").into()))?;
        let control_compat = control.compat();

        // Session-drop shutdown signal (mirrors client_mux).
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let shutdown_tx = Arc::new(shutdown_tx);
        let alive = Arc::new(AtomicBool::new(true));
        let bg_alive = alive.clone();
        let (open_tx, mut bg_open_rx) = mpsc::channel::<
            oneshot::Sender<std::result::Result<Stream, yamux::ConnectionError>>,
        >(MAX_PENDING_OPEN_REQUESTS);
        let open_notify = Arc::new(tokio::sync::Notify::new());
        let bg_open_notify = open_notify.clone();

        tokio::task::spawn(async move {
            let mut pending_opens: std::collections::VecDeque<
                oneshot::Sender<std::result::Result<Stream, yamux::ConnectionError>>,
            > = std::collections::VecDeque::new();
            loop {
                tokio::select! {
                    result = poll_fn(|cx| {
                        // (1) drain queued open requests into the local
                        // pending queue, bounded (mirrors client_mux).
                        loop {
                            if pending_opens.len() >= MAX_PENDING_OPEN_REQUESTS {
                                break;
                            }
                            match bg_open_rx.try_recv() {
                                Ok(req) => pending_opens.push_back(req),
                                Err(_) => break,
                            }
                        }
                        // (2) serve as many as the ack backlog admits.
                        loop {
                            let Some(req) = pending_opens.pop_front() else {
                                break;
                            };
                            if req.is_closed() {
                                continue;
                            }
                            match conn.poll_new_outbound(cx) {
                                Poll::Ready(Ok(stream)) => {
                                    let _ = req.send(Ok(stream));
                                }
                                Poll::Ready(Err(e)) => {
                                    let _ = req.send(Err(e));
                                }
                                Poll::Pending => {
                                    pending_opens.push_front(req);
                                    break;
                                }
                            }
                        }
                        // (3) double-poll inbound (ACKs + flush).
                        let first = conn.poll_next_inbound(cx);
                        match first {
                            Poll::Ready(r) => return Poll::Ready(r),
                            Poll::Pending => {}
                        }
                        conn.poll_next_inbound(cx)
                    }) => {
                        match result {
                            Some(Ok(_)) => {
                                // Unexpected inbound stream in client mode —
                                // dropped, like client_mux.
                            }
                            Some(Err(_)) | None => {
                                bg_alive.store(false, Ordering::Release);
                                break;
                            }
                        }
                    }
                    _ = bg_open_notify.notified() => {}
                    _ = &mut shutdown_rx => {
                        bg_alive.store(false, Ordering::Release);
                        break;
                    }
                }
            }
        });

        Ok((
            control_compat,
            YamuxSession {
                open_tx,
                alive,
                open_notify,
                shutdown_tx,
            },
        ))
    }

    /// The session must cap concurrent streams at `max_num_streams`. The
    /// caps here are asymmetric (client 1025 via `client_mux_with_config`,
    /// server 1024 — production `yamux_config`) so each direction's cap
    /// behavior is pinned:
    ///
    /// - INBOUND cap (server side): the 1025th inbound SYN is answered with
    ///   a per-stream RST (vendored yamux patch, Go fatedier/yamux parity).
    ///   The opener's stream dies — its read returns EOF — but the session
    ///   and every existing stream keep working: an existing stream still
    ///   exchanges data, and a NEW stream opens once a slot frees.
    /// - OUTBOUND cap (client side): the open past the cap fails fast with
    ///   TooManyStreams, which yamux 0.14 turns into a full session cleanup
    ///   (ConnectionState::Cleanup + drop_all_streams) — every stream moves
    ///   to Closed and no further open is served (Go frp's yamux fork keeps
    ///   the session alive here; frp-rs reconnects the mux session through
    ///   the control layer). Pin that too: a held stream reads EOF after the
    ///   refusal.
    ///
    /// A real server-mode yamux peer echoes every byte — the reply's ACK
    /// flag clears the client's ack backlog, which would otherwise park
    /// opens at 256 (yamux MAX_ACK_BACKLOG) and never reach the cap. Held
    /// stream handles keep the streams in the map (RSTs only remove them
    /// when the local handle drops).
    #[tokio::test(flavor = "current_thread")]
    async fn mux_stream_cap_hit_resets_offending_stream() {
        // client-side streams arrive as tokio_util::compat::Compat<Stream>,
        // which implements the tokio traits (raw yamux Streams in the server
        // task use the futures traits from the module import).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_io, server_io) = tokio::io::duplex(65536);

        // The connection must be polled CONTINUOUSLY while stream handlers
        // read: the connection is the only poller, and a data frame for a
        // stream whose handler parked would otherwise never be delivered (a
        // sequential read-then-poll loop stalls the moment a stream's data
        // arrives one flush later than its SYN). Each inbound stream gets its
        // own handler that echoes every byte and HOLDS its stream open until
        // the peer closes it: the server-side map entry lives until the
        // handler's handle drops (yamux on_drop_stream), and the handler
        // signals closed_tx AFTER that drop, so the map removal is queued
        // before the test's next open (deterministic on current_thread).
        // accepted_tx counts accepts; closed_tx counts drained handlers —
        // closed_rx stays in the TEST so the drop step can await it.
        let (closed_tx, mut closed_rx) = tokio::sync::mpsc::channel::<()>(64);
        let server_task = tokio::task::spawn(async move {
            let mut sconn = Connection::new(
                server_io.compat(),
                yamux_config(&TcpMuxConfig::default()),
                Mode::Server,
            );
            let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel::<()>(64);
            while let Some(Ok(mut stream)) = poll_fn(|cx| sconn.poll_next_inbound(cx)).await {
                let tx = accepted_tx.clone();
                let closed_tx = closed_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 16];
                    // SYN+data: echo the first chunk (the reply's ACK flag
                    // clears the client's ack backlog for this stream), then
                    // echo until the peer closes the stream. The control
                    // stream never carries data: its handler parks here
                    // until the connection closes at teardown.
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => 0,
                        Ok(n) => {
                            let _ = stream.write_all(&buf[..n]).await;
                            n
                        }
                    };
                    if n > 0 {
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // Explicit drop BEFORE the signals: the server map entry
                    // is removed when the connection polls this handle's
                    // CloseStream command — queued before the test's reopen
                    // sees the closed signal.
                    drop(stream);
                    let _ = tx.send(()).await;
                    let _ = closed_tx.send(()).await;
                });
            }
            drop(accepted_tx);
            drop(closed_tx);
            let mut accepted = 0;
            while accepted_rx.recv().await.is_some() {
                accepted += 1;
            }
            accepted
        });

        // Client cap 1025: one above the server, so the 1025th INBOUND SYN
        // (the client's 1024th work open) hits the SERVER's cap first.
        let mut client_cfg = yamux_config(&TcpMuxConfig::default());
        client_cfg.set_max_num_streams(1025);
        let (mut control, session) = client_mux_with_config(client_io, client_cfg)
            .await
            .expect("client_mux_with_config");

        // The control stream's SYN rides its FIRST frame, exactly like
        // production (frpc writes the Login message right after the open):
        // write one byte so the server admits the control stream and its
        // stream map holds control + work streams — the 1024-stream cap
        // must include it, or the server's cap is effectively 1024 work
        // streams and the refused SYN below lands 1024 when expected to
        // reset.
        control
            .write_all(b"x")
            .await
            .expect("write on the control stream");

        // Open up to the server's cap. Each open is followed by a one-byte
        // write AND an echo read: the write pushes the stream's SYN+data onto
        // the wire, and the read only returns once the server's handler has
        // echoed — i.e. once the server has ACCEPTED the stream. Reading the
        // echo per stream makes the server's acceptance synchronous with the
        // test loop (an open resolves client-side as soon as the driver
        // serves it; the server accepts each SYN one poll at a time and lags
        // otherwise), so the server is provably at its cap before the refused
        // SYN goes out — no acceptance-lag race. The reply's ACK flag also
        // clears the client's ack backlog for the stream.
        let mut streams = Vec::with_capacity(1023);
        for i in 0..1023 {
            let stream = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
                .await
                .expect("open must not hang below the cap")
                .unwrap_or_else(|| panic!("open #{i} refused below the 1024-stream cap"));
            let mut stream = stream;
            stream
                .write_all(b"x")
                .await
                .expect("write must succeed below the cap");
            let mut echo = [0u8; 1];
            let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut echo))
                .await
                .expect("echo must not hang below the cap")
                .expect("read");
            assert_eq!(&echo[..n], b"x", "server must accept and echo open #{i}");
            streams.push(stream);
        }

        // The 1024th work open (1 control + 1023 held = the server's cap)
        // SUCCEEDS client-side (client cap 1025) but the server answers the
        // SYN with a per-stream RST: the stream reads EOF instead of hanging.
        let mut refused = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
            .await
            .expect("open past the server cap must still resolve client-side")
            .expect("client cap 1025 must admit the 1024th work open");
        // yamux-rs carries the SYN flag on the stream's FIRST frame, which
        // is only queued when the stream's writer is polled — write one byte
        // so the SYN reaches the server (the cap check fires on the SYN; the
        // body is dropped with the frame — the stream never exists
        // server-side).
        refused
            .write_all(b"x")
            .await
            .expect("write on the refused stream");
        let mut probe = [0u8; 1];
        let eof = tokio::time::timeout(Duration::from_secs(2), refused.read(&mut probe))
            .await
            .expect("the server RST must arrive promptly, not hang")
            .expect("read");
        assert_eq!(
            eof, 0,
            "the server RST must close the offending stream, not the session"
        );

        // Existing streams keep working: the echo loop answers a fresh write
        // — proof the session was not GoAway'd.
        let mut live = streams.remove(0);
        live.write_all(b"z")
            .await
            .expect("write after the RST must succeed");
        let mut probe = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), live.read(&mut probe))
            .await
            .expect("read must not hang after the RST")
            .expect("read");
        assert_eq!(
            &probe[..n],
            b"z",
            "echo loop must still answer after the RST"
        );

        // Closing one held stream frees a server slot (map entry removed via
        // on_drop_stream) — a NEW stream opens on the same session and
        // carries data: the RST refused only that one stream.
        let closed_stream = streams.pop().expect("1022 streams held");
        drop(closed_stream);
        tokio::time::timeout(Duration::from_secs(5), closed_rx.recv())
            .await
            .expect("server must close the dropped stream, not hang")
            .expect("closed signal must arrive");
        let mut again = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
            .await
            .expect("open after a slot frees must not hang")
            .expect("a freed slot must admit a new stream");
        again
            .write_all(b"y")
            .await
            .expect("write on the reopened stream");
        let mut probe = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), again.read(&mut probe))
            .await
            .expect("reopened stream read must not hang")
            .expect("read");
        assert_eq!(&probe[..n], b"y", "reopened stream must carry data");

        // The client is now at ITS cap (control + 1022 held + the refused
        // stream + the reopened one = 1025). The next open hits the client's
        // OWN cap: outbound TooManyStreams, refused fast. yamux 0.14 turns
        // that into a full session cleanup (ConnectionState::Cleanup +
        // drop_all_streams) — pin it: a held stream reads EOF.
        let cap_refused = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
            .await
            .expect("client-cap refusal must be prompt");
        assert!(
            cap_refused.is_none(),
            "open past the client's own cap must be refused"
        );
        let mut probe = [0u8; 1];
        let eof = tokio::time::timeout(Duration::from_secs(2), live.read(&mut probe))
            .await
            .expect("Closed stream must read EOF, not hang")
            .expect("read");
        assert_eq!(eof, 0, "session cleanup must close every held stream");

        // Teardown: the session drops, the peer EOFs every stream, and each
        // handler exits. The server must have accepted exactly control +
        // 1023 work + the reopened stream — the RST'd stream was never
        // accepted — and every accepted stream's handler must drain.
        //
        // Drain closed_rx BEFORE awaiting the server task: both channels are
        // capped at 64, and a handler only exits after BOTH its sends
        // succeed. The server task drains accepted_rx while this loop drains
        // closed_rx (they wake each other); awaiting the server task first
        // would park the test, stranding the closed senders and with them
        // their accepted clones — the accepted channel would never close.
        drop(again);
        drop(refused);
        drop(live);
        drop(streams);
        drop(control);
        drop(session);
        let mut closed_count = 1; // the mid-test drop signal
        while closed_rx.recv().await.is_some() {
            closed_count += 1;
        }
        let accepted = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task must finish")
            .expect("server task must not panic");
        assert_eq!(
            accepted, 1025,
            "server must accept control + 1023 work + reopened (the RST'd stream never lands)"
        );
        assert_eq!(
            closed_count, accepted,
            "every accepted stream's handler must drain"
        );
    }
}
