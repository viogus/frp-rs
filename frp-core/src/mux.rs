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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::poll_fn;
use tokio::sync::{mpsc, oneshot};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, warn};

use yamux::{Config, Connection, Mode, Stream};

/// Configuration for the yamux session.
#[derive(Debug, Clone)]
pub struct TcpMuxConfig {
    /// Keepalive interval (seconds). Matches Go frp's `tcp_mux_keepalive_interval`.
    pub keepalive_interval: Duration,
}

impl Default for TcpMuxConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
        }
    }
}

fn yamux_config(_cfg: &TcpMuxConfig) -> Config {
    Config::default()
    // Go frp uses 6 MB max stream window size.
    // yamux 0.14 default: 1 GiB connection receive window, 16 KiB split send size.
    // These defaults are fine for frp workloads.
}

/// Wrapper type for a yamux stream compatible with tokio's AsyncRead/AsyncWrite.
/// yamux::Stream impls futures-io traits; Compat wraps them into tokio traits.
pub type YamuxStream = Compat<Stream>;

/// Receiver for incoming yamux streams (work connections) accepted by the server.
pub struct IncomingStreams {
    rx: mpsc::UnboundedReceiver<YamuxStream>,
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
    tx: mpsc::UnboundedSender<OpenRequest>,
}

impl YamuxSession {
    /// Open a new yamux stream on the shared session.
    /// Returns `None` if the yamux session is closed/dropped.
    pub async fn open_stream(&self) -> Option<YamuxStream> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(OpenRequest { reply }).is_err() {
            return None;
        }
        rx.await.ok().flatten()
    }
}

struct OpenRequest {
    reply: oneshot::Sender<Option<YamuxStream>>,
}

/// Create a server-side yamux session from an already-established TcpStream.
///
/// Returns:
/// - `control_stream`: the first accepted stream (control channel)
/// - `incoming`: channel receiver for subsequent accepted streams (work connections)
///
/// Spawns a background task to manage the yamux Connection.
pub async fn server_mux(
    stream: TcpStream,
    mux_cfg: &TcpMuxConfig,
) -> Result<(YamuxStream, IncomingStreams), crate::Error> {
    let compat = stream.compat();
    let yamux_cfg = yamux_config(mux_cfg);
    let mut conn = Connection::new(compat, yamux_cfg, Mode::Server);

    // Accept the first stream — this is the control channel.
    let control = poll_fn(|cx| conn.poll_next_inbound(cx))
        .await
        .ok_or_else(|| crate::Error::Protocol("yamux: connection closed before control stream".into()))?
        .map_err(|e| crate::Error::Protocol(format!("yamux: {e}")))?;

    let control_compat = control.compat();

    // Channel for forwarding accepted work connection streams.
    let (tx, rx) = mpsc::unbounded_channel();

    // Spawn background task: continuously accept yamux streams.
    tokio::task::spawn(async move {
        loop {
            match poll_fn(|cx| conn.poll_next_inbound(cx)).await {
                Some(Ok(stream)) => {
                    let compat = stream.compat();
                    if tx.send(compat).is_err() {
                        debug!("yamux server: incoming channel closed, stopping acceptor");
                        break;
                    }
                }
                Some(Err(e)) => {
                    debug!("yamux server accept error: {e}");
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

/// Create a client-side yamux session from an already-established TcpStream.
///
/// Returns:
/// - `control_stream`: the first opened stream (control channel)
/// - `session`: handle for opening additional streams (work connections)
///
/// Spawns a background task to manage the yamux Connection.
pub async fn client_mux(
    stream: TcpStream,
    mux_cfg: &TcpMuxConfig,
) -> Result<(YamuxStream, YamuxSession), crate::Error> {
    let compat = stream.compat();
    let yamux_cfg = yamux_config(mux_cfg);
    let mut conn = Connection::new(compat, yamux_cfg, Mode::Client);

    // Open the first stream — this is the control channel.
    let control = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .map_err(|e| crate::Error::Protocol(format!("yamux: {e}")))?;

    let control_compat = control.compat();

    // Channel for open-stream requests.
    let (tx, mut rx) = mpsc::unbounded_channel::<OpenRequest>();

    let conn = Arc::new(Mutex::new(conn));
    let bg_conn = conn.clone();

    tokio::task::spawn(async move {
        loop {
            tokio::select! {
                // Handle open-stream requests
                req = rx.recv() => {
                    match req {
                        Some(OpenRequest { reply }) => {
                            let c = bg_conn.clone();
                            let result = poll_fn(move |cx| {
                                c.lock().unwrap().poll_new_outbound(cx)
                            }).await;
                            let stream = match result {
                                Ok(s) => Some(s.compat()),
                                Err(e) => {
                                    warn!("yamux client: open stream failed: {e}");
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
                // Drive connection I/O — poll_next_inbound processes inbound data
                // frames (ACKs, window updates, received data) and routes them to
                // stream buffers, waking stream readers. Without this, streams can
                // never receive data.
                _ = poll_fn(|cx| {
                    bg_conn.lock().unwrap().poll_next_inbound(cx)
                }) => {}
            }
        }
    });

    Ok((control_compat, YamuxSession { tx }))
}
