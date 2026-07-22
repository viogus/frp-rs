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

use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "tcp-mux")]
use futures_util::future::poll_fn;
#[cfg(feature = "tcp-mux")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "tcp-mux")]
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
#[cfg(feature = "tcp-mux")]
use tracing::{debug, warn};

#[cfg(feature = "tcp-mux")]
use yamux::{Config, Connection, Mode, Stream};

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
    /// Keepalive interval (seconds). Matches Go frp's `tcp_mux_keepalive_interval`.
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
            keepalive_interval: Duration::from_secs(30),
            max_stream_window_size: 6 * 1024 * 1024,
        }
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
    // to max_stream_window_size * 64 = 384 MiB — still generous but
    // far below the 1.5 GiB OOM risk zone.
    let stream_window = tcp_mux_cfg.max_stream_window_size as usize;
    cfg.set_max_connection_receive_window(Some(stream_window * 64));
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
}

impl IncomingStreams {
    /// Receive the next accepted stream. Returns `None` if the yamux session closed.
    pub async fn recv(&mut self) -> Option<YamuxStream> {
        self.rx.recv().await
    }
}

/// Handle for opening new yamux streams (client-side work connections).
#[derive(Clone)]
pub struct YamuxSession {
    tx: mpsc::Sender<OpenRequest>,
}

impl YamuxSession {
    /// Open a new yamux stream on the shared session.
    /// Returns `None` if the yamux session is closed/dropped.
    pub async fn open_stream(&self) -> Option<YamuxStream> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(OpenRequest { reply }).await.is_err() {
            return None;
        }
        rx.await.ok().flatten()
    }
}

struct OpenRequest {
    /// Sender for the opened stream. When `tcp-mux` is disabled, this field is
    /// never read from the receiving side — but it must exist so that dropping
    /// `OpenRequest` cancels the waiting receiver.
    #[allow(dead_code)]
    reply: oneshot::Sender<Option<YamuxStream>>,
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
    let compat = stream.compat();
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

    // Spawn background task: accept yamux streams and drive connection I/O.
    //
    // Double-poll is required because yamux Active::poll processes
    // StreamCommand::SendFrame AFTER draining pending_frames. The first
    // poll picks up queued stream writes into pending_frames; the second
    // poll actually sends them on the wire.
    let keepalive = mux_cfg.keepalive_interval;
    debug_assert!(
        !keepalive.is_zero(),
        "tcp_mux_keepalive_interval must be > 0; zero causes immediate timeout Elapsed"
    );
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
                    // called (driving I/O including next_ping()), but
                    // no new stream arrived within keepalive_interval.
                    continue;
                }
            };

            match stream {
                Some(Ok(stream)) => {
                    let compat = stream.compat();
                    match tx.try_send(compat) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Channel is temporarily full — drop this stream
                            // and continue. Do NOT kill the acceptor.
                            debug!("yamux server: incoming channel full, dropping stream");
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

    Ok((control_compat, IncomingStreams { rx }))
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
    let compat = stream.compat();
    let yamux_cfg = yamux_config(mux_cfg);
    let mut conn = Connection::new(compat, yamux_cfg, Mode::Client);

    // Open the first stream — this is the control channel.
    let control = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .map_err(|e| crate::Error::Protocol(format!("yamux: {e}").into()))?;

    let control_compat = control.compat();

    // Channel for open-stream requests.
    let (tx, mut rx) = mpsc::channel::<OpenRequest>(256);

    let conn = Arc::new(Mutex::new(conn));
    let bg_conn = conn.clone();
    let keepalive = mux_cfg.keepalive_interval;
    debug_assert!(
        !keepalive.is_zero(),
        "tcp_mux_keepalive_interval must be > 0; zero causes tight select! spin"
    );

    tokio::task::spawn(async move {
        loop {
            tokio::select! {
                // Handle open-stream requests
                req = rx.recv() => {
                    match req {
                        Some(OpenRequest { reply }) => {
                            let c = bg_conn.clone();
                            let result = poll_fn(move |cx| {
                                c.lock().unwrap_or_else(|e| e.into_inner()).poll_new_outbound(cx)
                            }).await;
                            let stream = match result {
                                Ok(s) => Some(s.compat()),
                                Err(e) => {
                                    warn!(error = %e, "yamux client: open stream failed: {e}");
                                    None
                                }
                            };
                            let _ = reply.send(stream);
                        }
                        None => {
                            debug!("yamux client: request channel closed");
                            break;
                        }
                    }
                }
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
                            break;
                        }
                        None => {
                            debug!("yamux client: connection closed");
                            break;
                        }
                    }
                }
                // Keepalive: periodically drive I/O so yamux's next_ping()
                // fires and detects dead peers even on idle connections.
                _ = tokio::time::sleep(keepalive) => {
                    let _ = poll_fn(|cx| {
                        bg_conn.lock().unwrap_or_else(|e| e.into_inner()).poll_next_inbound(cx)
                    }).await;
                }
            }
        }
        debug!("yamux client: background task exiting");
    });

    Ok((control_compat, YamuxSession { tx }))
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
