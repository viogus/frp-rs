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
use tokio::sync::{oneshot, watch};

#[cfg(feature = "tcp-mux")]
use futures_util::future::poll_fn;
#[cfg(feature = "tcp-mux")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
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

/// Wrapper type for a yamux stream compatible with tokio's AsyncRead/AsyncWrite.
#[cfg(feature = "tcp-mux")]
pub type YamuxStream = Compat<Stream>;

/// Stub type when tcp-mux is disabled. Never constructed at runtime;
/// only exists so IoStream::Yamux variant compiles.
#[cfg(not(feature = "tcp-mux"))]
#[derive(Debug)]
pub struct YamuxStream {
    _priv: (),
}

// SAFETY: When tcp-mux is disabled, YamuxStream is never constructed at
// runtime — it exists only as a type-level stub so IoStream::Yamux variant
// compiles. All trait impls return errors. Marking Send is sound because
// no instance of this type can exist.
#[cfg(not(feature = "tcp-mux"))]
unsafe impl Send for YamuxStream {}

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
    // Match Go frp's hashicorp/yamux settings for compatibility.
    // Go frp sets MaxStreamWindowSize = 6 MB which controls per-stream
    // receive window. yamux-rs 0.14 hardcodes the initial per-stream
    // window at 256 KiB (DEFAULT_CREDIT) but grows it dynamically via
    // BDP-based auto-tuning. To allow each stream to grow to the
    // configured max_stream_window_size without allowing all 256
    // streams to simultaneously consume their full window (which
    // would risk OOM at 1.5 GiB), set the connection receive window
    // to max_stream_window_size * 32 = 192 MiB — moderate increase
    // from old 128 MiB, still accommodates the larger per-stream
    // window without memory exhaustion risk.
    let stream_window = tcp_mux_cfg.max_stream_window_size as usize;
    cfg.set_max_connection_receive_window(Some(stream_window * 32));
    // NOTE: yamux 0.14.0 does not expose set_keepalive_interval on Config.
    // max_num_streams not set — uses yamux-rs default (8192) vs Go's unlimited.
    // 8192 accommodates high concurrent workloads (HTTP proxy, long-lived streams)
    // without capping at 256 which would reject streams under load.
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
    /// Shared yamux connection. open_stream() polls poll_new_outbound
    /// directly on it — no background-task round trip through a request
    /// channel. The background driver task holds the same Arc.
    conn: Arc<Mutex<Connection<Box<dyn MuxSocket>>>>,
    /// Set false when the background driver exits (I/O error, keepalive
    /// bound, or session drop). open_stream() checks it to fail fast
    /// instead of polling a connection whose driver is gone.
    alive: Arc<AtomicBool>,
    /// Stateful wakeup for the driver after open_stream(): a `watch` send
    /// is never lost — if the driver is mid-iteration (processing inbound
    /// I/O) when the send happens, its next `changed()` resolves
    /// immediately. A plain `Notify` would drop a wakeup fired while no
    /// waiter was registered, leaving the new stream's queued frames
    /// (SYN flag / initial window update) unflushed until the next
    /// keepalive tick (30s default) or inbound traffic.
    opened: Arc<watch::Sender<()>>,
    /// When the last YamuxSession reference is dropped, this sender drops,
    /// signalling the background driver to exit (mirrors IncomingStreams).
    /// Arc'd because YamuxSession must be Clone (oneshot::Sender is not).
    #[allow(dead_code)]
    shutdown_tx: Arc<oneshot::Sender<()>>,
}

#[cfg(feature = "tcp-mux")]
impl YamuxSession {
    /// Open a new yamux stream on the shared session.
    /// Returns `None` if the yamux session is closed/dropped.
    pub async fn open_stream(&self) -> Option<YamuxStream> {
        // Fail fast when the driver has exited: poll_new_outbound on a
        // driver-less connection would succeed, but the new stream's frames
        // could never be flushed to the wire.
        if !self.alive.load(Ordering::Acquire) {
            return None;
        }
        let c = self.conn.clone();
        let result = poll_fn(move |cx| {
            c.lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_new_outbound(cx)
        })
        .await;
        let stream = match result {
            Ok(s) => Some(s.compat()),
            Err(e) => {
                warn!(error = %e, "yamux client: open stream failed: {e}");
                None
            }
        };
        // Wake the driver so it re-polls and flushes the new stream's queued
        // frames: the stream's command channel was just registered with the
        // connection and no waker has observed it yet, so a write on the
        // stream would otherwise sit until the next keepalive tick. The
        // watch send is stateful: it also wakes the driver if the send lands
        // while the driver is mid-select-iteration (a Notify would lose it).
        let _ = self.opened.send(());
        stream
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
/// Returns:
/// - `control_stream`: the first accepted stream (control channel)
/// - `incoming`: channel receiver for subsequent accepted streams (work connections)
///
/// Spawns a background task to manage the yamux Connection.
#[cfg(feature = "tcp-mux")]
pub async fn server_mux<S>(
    stream: S,
    mux_cfg: &TcpMuxConfig,
) -> Result<(YamuxStream, IncomingStreams), crate::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(ActivityState::default());
    let compat = ActivityIo::new(stream, activity.clone()).compat();
    let yamux_cfg = yamux_config(mux_cfg);
    let mut conn = Connection::new(compat, yamux_cfg, Mode::Server);

    // Accept the first stream — this is the control channel.
    let control = poll_fn(|cx| conn.poll_next_inbound(cx))
        .await
        .ok_or_else(|| {
            crate::Error::Protocol("yamux: connection closed before control stream".into())
        })?
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
                    // send() with backpressure instead of try_send: on a full
                    // channel a freshly accepted stream must NOT be silently
                    // dropped — the client's StartWorkConn would hang until
                    // its timeout. The bounded (256) channel makes the
                    // acceptor wait briefly for room instead. The wait is
                    // itself bounded: this task is the ONLY one that drives
                    // the yamux Connection, so a persistently full channel
                    // must not stall inbound PING/PONG processing and
                    // control reads/writes for the whole session (the
                    // client's heartbeat watchdog may kill the link). On
                    // timeout the stream is dropped, but the channel may
                    // drain later — keep accepting.
                    match tokio::time::timeout(Duration::from_secs(5), tx.send(compat)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {
                            debug!("yamux server: incoming channel closed, stopping acceptor");
                            break;
                        }
                        Err(_elapsed) => {
                            warn!(
                                "yamux server: incoming channel full for 5s, dropping work stream"
                            );
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
    // Type-erased connection: YamuxSession holds an Arc<Mutex<Connection>> so
    // open_stream() can poll poll_new_outbound directly (no request-channel
    // round trip), while the driver task below drives connection I/O.
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

    let conn = Arc::new(Mutex::new(conn));
    let bg_conn = conn.clone();
    // Shutdown signal: when the last YamuxSession is dropped (shutdown_tx
    // closed), the driver exits — mirrors server_mux's IncomingStreams.
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(shutdown_tx);
    let alive = Arc::new(AtomicBool::new(true));
    let bg_alive = alive.clone();
    let (opened_tx, mut bg_opened) = watch::channel(());
    let opened = Arc::new(opened_tx);
    let keepalive = normalized_keepalive_interval(mux_cfg.keepalive_interval);
    // Dead-session bound in wall-clock time — see server_mux for why the
    // configured interval cannot be used alone as the dead bound.
    let dead_after = MIN_IDLE_DEAD_TIME.max(keepalive.saturating_mul(MAX_IDLE_KEEPALIVE_TICKS));
    let mut consecutive_idle = 0u32;

    tokio::task::spawn(async move {
        loop {
            tokio::select! {
                // Drive connection I/O.
                //
                // Double-poll is required because yamux Active::poll processes
                // StreamCommand::SendFrame (step 3) AFTER flushing pending_write_frame
                // (step 1). The first poll picks up queued stream writes into
                // pending_write_frame; the second poll actually sends them on the wire.
                // Without the second poll, frames sit in pending_write_frame until
                // the next wake-up — which may never arrive.
                //
                // Guard: only double-poll when there might be pending frames.
                // Without this guard, two successive Pending results on the same cx
                // can cause a tight re-poll loop (the second poll re-registers the
                // same waker, and the runtime may re-wake immediately).
                //
                // Streams opened from open_stream() are flushed by the `opened`
                // wakeup branch below, which wakes this poll so the double-poll
                // picks up the new stream's queued frames.
                result = poll_fn(|cx| {
                    let mut conn = bg_conn.lock().unwrap_or_else(|e| e.into_inner());
                    // First poll: process stream commands → collect SendFrame
                    // into pending_write_frame, read incoming data → route to streams.
                    let first = conn.poll_next_inbound(cx);
                    match first {
                        Poll::Ready(r) => return Poll::Ready(r),
                        Poll::Pending => {}
                    }
                    // Second poll: send pending_write_frame to socket, read again.
                    debug!("yamux client: flushing pending frames");
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
                    let poll_result = poll_fn(|cx| {
                        Poll::Ready(
                            bg_conn
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .poll_next_inbound(cx),
                        )
                    }).await;
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
                // A stream was opened from open_stream() — wake so the I/O
                // branch re-polls and flushes the new stream's queued frames
                // (SYN flag / initial window update) to the wire. watch's
                // changed() resolves immediately if the send happened while
                // this driver was busy elsewhere in the select, so the
                // wakeup is never lost (a Notify would drop those).
                _ = bg_opened.changed() => {}
            }
        }
        debug!("yamux client: background task exiting");
    });

    Ok((
        control_compat,
        YamuxSession {
            conn,
            alive,
            opened,
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
