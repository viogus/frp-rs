//! Persistent XTCP tunnel session — Go frp v0.71.0 tunnel-session semantics.
//!
//! Go frp v0.71 keeps ONE hole-punched data-plane session per XTCP proxy and
//! reuses it across user connections (`KCPTunnelSession` / `QUICTunnelSession`
//! in client/visitor/xtcp.go; `listenByKCP` / `listenByQUIC` in
//! client/proxy/xtcp.go). A dead session is closed and re-punched by the
//! visitor's `processTunnelStartEvents` / `keepTunnelOpenWorker`, and the
//! provider accepts streams from the persistent session until it dies.
//!
//! This module provides the session abstraction:
//!
//! - [`XtcpTunnelSession`] — yamux-over-KCP when the `tcp-mux` feature is on
//!   (Go parity: `fmux.Client`/`fmux.Server` with `KeepAliveInterval=10s` —
//!   Go sends real keepalive pings; yamux-rs has no keepalive machinery, so
//!   the tunnel sends none. Idle half-open tunnels are reclaimed by a
//!   driver-side idle watchdog instead: the transport is wrapped in
//!   [`ReadActivity`], which stamps a timestamp on every inbound read, and
//!   the driver closes the session after [`TUNNEL_IDLE_CLOSE_MS`] (90s) of
//!   total inbound silence — an alive idle peer still delivers yamux
//!   ping/pong frames every ~10s. Outbound-only traffic with a dead peer
//!   still dies via KCP send-side dead-link detection — and
//!   `MaxStreamWindowSize=6MB`); without `tcp-mux`, a one-shot raw KCP
//!   stream (the pre-existing Rust↔Rust fallback capability — one
//!   connection per punch, no multiplexing).
//! - [`QuicTunnelSession`] — QUIC over the punched UDP socket (NO yamux;
//!   QUIC multiplexes streams itself, matching Go's `quic.Dial`/`quic.Listen`
//!   on `result.lConn`).
//!
//! The yamux session owns a background driver task that keeps the KCP state
//! machine ticking (10 ms, same as the per-stream driver) and serves open /
//! accept requests through bounded channels — modeled on the request-channel
//! driver in `crate::mux::client_mux` (no caller ever touches the
//! `yamux::Connection` directly). The driver lives for the lifetime of the
//! SESSION (last `Arc` dropped / `close()`), NOT of a single stream; the
//! legacy per-stream wrapper `xtcp_p2p_connect_yamux` is unchanged.
//!
//! Wire-visible behavior is identical to the per-stream path: KCP over the
//! winning hole-punch socket, yamux framing, `conv` from the session id.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
#[cfg(feature = "tcp-mux")]
use tokio::sync::{mpsc, oneshot, watch, Notify};

use crate::kcp::KcpConfig;
use crate::msg::NatHoleDetectBehavior;
use crate::xtcp_p2p::P2pStream;
#[cfg(feature = "tcp-mux")]
use crate::xtcp_p2p::KCP_TICK_MS;

/// Cap on queued open-stream requests (visitor side) before the driver can
/// serve them — mirrors `mux.rs` `MAX_PENDING_OPEN_REQUESTS`. A stalled peer
/// (yamux ACK backlog full) makes the driver unable to answer opens; the
/// bounded channel makes `open_stream` fail fast instead of accumulating
/// parked callers.
#[cfg(feature = "tcp-mux")]
const MAX_PENDING_OPEN_REQUESTS: usize = 64;

/// Cap on queued inbound streams (provider side) before the driver stops
/// delivering — mirrors `mux.rs` `server_mux`'s inbound channel cap.
#[cfg(feature = "tcp-mux")]
const MAX_INBOUND_QUEUE: usize = 256;

/// Cap on concurrent streams on the tunnel session — the yamux
/// `max_num_streams` config value, mirrored into the driver's open pre-check
/// so an outbound cap hit fails the INDIVIDUAL open instead of yamux 0.14
/// converting `Err(TooManyStreams)` into a session-wide cleanup (see
/// [`spawn_tunnel_driver`]). Go's fatedier yamux fork has no stream cap.
#[cfg(feature = "tcp-mux")]
const MAX_TUNNEL_STREAMS: usize = 256;

/// M10 idle-watchdog window (ms): the driver closes the tunnel session after
/// this long with no inbound KCP input, reclaiming an idle half-open tunnel
/// (peer vanished without RST — UDP — and nothing to send, so KCP dead-link
/// detection never trips).
///
/// Implementation choice (documented per the round-13 plan): a DRIVER-SIDE
/// IDLE WATCHDOG over a yamux keepalive ping. The vendored yamux 0.14
/// exposes no ping/keepalive API (its RTT pings are internal and never
/// time out), so a Go-style "3 missed 10s keepalives → close" countdown is
/// not reachable from the driver. Instead the driver observes inbound KCP
/// input directly: an ALIVE idle tunnel carries a yamux ping (or pong)
/// roughly every 5-10s — both sides' connections send a ping every 10s and
/// answer the peer's — so 90s of total silence proves the peer is gone.
/// (Go's fmux keepalive interval is 10s; 90s is 9x that, a conservative
/// bound.) Outbound-only traffic with a dead peer still dies via KCP
/// send-side dead-link, so the watchdog only fires in the true idle case.
#[cfg(feature = "tcp-mux")]
const TUNNEL_IDLE_CLOSE_MS: u64 = 90_000;

/// Round-13 adaptive idle tick (ms): when a driver pass produces no activity
/// (no open served, no request drained, no inbound stream), the driver's next
/// wake stretches from `KCP_TICK_MS` (10ms — 100 wakes/s of UDP try_recv
/// syscalls on an idle tunnel) to this value. Any activity snaps back to the
/// fast tick. The idle tick does not delay dead-link detection past the 90s
/// idle watchdog, and inbound data/ACKs still wake the driver immediately via
/// the poll wakers; the idle tick only paces the nothing-at-all case.
#[cfg(feature = "tcp-mux")]
const TUNNEL_IDLE_TICK_MS: u64 = 1000;

/// Wall-clock millis (same clock for writer and reader; a clock jump would
/// have to exceed [`TUNNEL_IDLE_CLOSE_MS`] to matter).
#[cfg(feature = "tcp-mux")]
fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// L24: flips the driver's `bg_alive` flag when dropped, so ANY task exit —
/// the normal loop break AND a panic-unwind in the loop body — marks the
/// session dead instead of leaving `is_alive()` stuck true on a task that no
/// longer runs (which would strand callers waiting on a driver that is gone).
#[cfg(feature = "tcp-mux")]
struct BgAliveGuard(Arc<AtomicBool>);

#[cfg(feature = "tcp-mux")]
impl Drop for BgAliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Yamux-over-KCP session (tcp-mux feature on)
// ---------------------------------------------------------------------------

/// A persistent XTCP data-plane session: one yamux connection over one
/// hole-punched KCP-over-UDP socket, multiplexing many streams.
///
/// The background driver owns the `yamux::Connection` exclusively; callers
/// open (visitor / yamux client) or accept (provider / yamux server) streams
/// through bounded request channels. The driver — and with it the UDP socket
/// and KCP session — lives until `close()` or the last handle is dropped.
#[cfg(feature = "tcp-mux")]
pub struct XtcpTunnelSession {
    /// Open requests for the driver (visitor role). Bounded; full queue means
    /// a stalled peer.
    open_tx: mpsc::Sender<oneshot::Sender<Result<Box<dyn P2pStream>, String>>>,
    /// Inbound streams delivered by the driver (provider role). Closed when
    /// the driver exits, so `accept_stream` fails instead of parking. The
    /// inner tokio Mutex lets `accept_stream` take `&self` while `recv`
    /// needs `&mut` (the session is shared via `Arc`; only the provider
    /// accept loop ever calls it). The driver's `try_send` path never
    /// touches this Mutex, so no contention on the data path.
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Box<dyn P2pStream>>>,
    /// False once the driver exits (close, connection error, dead link).
    alive: Arc<AtomicBool>,
    /// Driver exit signal: `close()` sends; dropping the last handle closes
    /// the channel, which also wakes the driver.
    driver_drop_tx: watch::Sender<()>,
    /// Wake channel for queued open requests (round-13 fix): the driver's
    /// open-serving drain only runs when the driver is polled, and the idle
    /// tick can be as long as 1s (adaptive idle loop) — without this wake an
    /// open would wait up to 1s to be served. `open_stream` notify_one()s
    /// after a successful try_send; the stored permit makes the wake
    /// loss-proof (a notify arriving while the driver is inside its select
    /// completes the next `notified()` immediately).
    open_wake: Arc<Notify>,
}

#[cfg(feature = "tcp-mux")]
impl XtcpTunnelSession {
    /// Open a new stream on the session (visitor / yamux client role).
    ///
    /// Bounded by `timeout`: a healthy session answers in milliseconds; a
    /// dead-but-undetected session (peer vanished without RST — UDP) is
    /// closed by the driver's idle watchdog after ~90s of no inbound KCP
    /// input (see [`TUNNEL_IDLE_CLOSE_MS`]), or times out here once
    /// `timeout` expires. The caller (`getTunnelConn` semantics) then closes
    /// the session and triggers a re-punch.
    pub async fn open_stream(&self, timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        if !self.is_alive() {
            return Err("no tunnel session".into());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        match self.open_tx.try_send(reply_tx) {
            Ok(()) => {
                // Wake the driver to serve the request promptly: with the
                // adaptive idle tick the driver may be parked on a 1s
                // timeout, and the notify (stored permit — loss-proof)
                // completes the select's `open_wake.notified()` arm so the
                // request is drained immediately.
                self.open_wake.notify_one();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err("tunnel session open queue full (peer stalled?)".to_string());
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Driver exited (close, connection error, idle watchdog):
                // the session is DEAD, not busy — classify the channel
                // Disconnected as dead so the caller re-punches instead of
                // misreading it as congestion.
                return Err("tunnel session closed".to_string());
            }
        }
        // The driver's open-serving drain runs within one tick (fast KCP
        // tick with activity; up to ~1s on the idle path) — the notify above
        // shortens that to the next driver poll.
        tokio::time::timeout(timeout, reply_rx)
            .await
            .map_err(|_| format!("timeout opening tunnel stream ({timeout:?})"))?
            .map_err(|_| "tunnel session closed while opening stream".to_string())?
    }

    /// Accept the next inbound stream (provider / yamux server role).
    ///
    /// Returns `Err` when the session is closed/dropped (channel closed) or
    /// on `timeout` (no stream within the window — the caller re-checks
    /// `is_alive()` to decide whether to keep waiting).
    pub async fn accept_stream(&self, timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        let mut rx = self.inbound_rx.lock().await;
        tokio::time::timeout(timeout, rx.recv())
            .await
            .map_err(|_| format!("timeout waiting for inbound stream ({timeout:?})"))?
            .ok_or_else(|| "tunnel session closed".to_string())
    }

    /// Whether the session driver is still running.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Close the session: flips `is_alive()` false immediately (synchronous,
    /// so a caller racing `close()` cannot open a stream on a closing
    /// session) and wakes the driver, which drops the yamux connection, KCP
    /// session and UDP socket (async — resources free shortly after).
    pub async fn close(&self) {
        self.alive.store(false, Ordering::Release);
        let _ = self.driver_drop_tx.send(());
    }
}

// ---------------------------------------------------------------------------
// Raw-KCP one-shot session (tcp-mux feature off)
// ---------------------------------------------------------------------------

/// A one-shot raw KCP stream as a session — the pre-existing no-tcp-mux
/// capability (single connection per punch, no multiplexing). `open_stream`
/// and `accept_stream` each hand out the stream once; the first caller wins,
/// later calls fail with "no tunnel session". `close()` drops the stream.
#[cfg(not(feature = "tcp-mux"))]
pub struct XtcpTunnelSession {
    inner: tokio::sync::Mutex<Option<crate::xtcp_p2p::XtcpP2pStream>>,
    alive: Arc<AtomicBool>,
}

#[cfg(not(feature = "tcp-mux"))]
impl XtcpTunnelSession {
    pub async fn open_stream(&self, _timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        // Single-connection raw KCP: the stream exists from the moment the
        // session is created, so a timeout bound is meaningless here. Taking
        // it spends the session — alive flips false so the provider accept
        // loop (which re-checks is_alive after a failed accept) sees a spent
        // session and exits instead of spinning.
        let taken = self.inner.lock().await.take();
        if taken.is_some() {
            self.alive.store(false, Ordering::Release);
        }
        match taken {
            Some(s) => Ok(Box::new(s)),
            None => Err("no tunnel session".into()),
        }
    }

    pub async fn accept_stream(&self, _timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        let taken = self.inner.lock().await.take();
        if taken.is_some() {
            self.alive.store(false, Ordering::Release);
        }
        match taken {
            Some(s) => Ok(Box::new(s)),
            None => Err("no tunnel session".into()),
        }
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub async fn close(&self) {
        self.alive.store(false, Ordering::Release);
        let _ = self.inner.lock().await.take();
    }
}

// ---------------------------------------------------------------------------
// QUIC session (quic feature on)
// ---------------------------------------------------------------------------

/// A persistent QUIC XTCP data-plane session: one quinn connection over one
/// hole-punched UDP socket. No yamux — QUIC multiplexes streams itself (Go
/// `QUICTunnelSession`). The quinn connection owns the endpoint and the UDP
/// socket; dropping the session closes both.
#[cfg(feature = "quic")]
pub struct QuicTunnelSession {
    conn: crate::quic::QuicConnection,
    alive: Arc<AtomicBool>,
}

#[cfg(feature = "quic")]
impl QuicTunnelSession {
    /// Open a new bidirectional stream (visitor / QUIC client role).
    pub async fn open_stream(&self, timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        if !self.is_alive() {
            return Err("no tunnel session".into());
        }
        match tokio::time::timeout(timeout, self.conn.open_bi()).await {
            Ok(Ok(stream)) => Ok(Box::new(stream)),
            Ok(Err(e)) => {
                // Connection-level error: the QUIC connection is dead
                // (remote close / reset / idle timeout) — mark the session
                // dead so callers (getTunnelConn / provider accept loop)
                // re-punch instead of spinning on a dead session.
                self.alive.store(false, Ordering::Release);
                Err(format!("quic open stream: {e}"))
            }
            Err(_elapsed) => Err(format!("timeout opening tunnel stream ({timeout:?})")),
        }
    }

    /// Accept the next bidirectional stream (provider / QUIC server role).
    pub async fn accept_stream(&self, timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        match tokio::time::timeout(timeout, self.conn.accept_bi()).await {
            Ok(Ok(stream)) => Ok(Box::new(stream)),
            Ok(Err(e)) => {
                // Connection-level error: the QUIC connection is dead —
                // mark the session dead (see open_stream).
                self.alive.store(false, Ordering::Release);
                Err(format!("quic accept stream: {e}"))
            }
            Err(_elapsed) => Err(format!("timeout waiting for inbound stream ({timeout:?})")),
        }
    }

    /// Whether the session has been closed locally.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Close the QUIC connection (Go `CloseWithError(0, "")`).
    pub async fn close(&self) {
        self.alive.store(false, Ordering::Release);
        self.conn.close(b"");
    }
}

// ---------------------------------------------------------------------------
// Session connect functions (punch + session setup)
// ---------------------------------------------------------------------------

/// Punch a UDP NAT hole and create a persistent yamux-over-KCP tunnel session
/// (Go frp v0.71 `KCPTunnelSession.Init` + provider `listenByKCP`).
///
/// `yamux_client` selects the yamux role: `true` = visitor (opens streams,
/// `Mode::Client`), `false` = provider (accepts streams, `Mode::Server`).
/// `sid`/`key` enable Go-compat NatHoleSid detection; when both are `None`
/// the simple "frp" magic is used (Rust↔Rust).
///
/// Unlike the per-stream [`crate::xtcp_p2p::xtcp_p2p_connect_yamux`], NO
/// stream is opened/accepted here — the session is created and returned,
/// and streams are opened per user connection via
/// [`XtcpTunnelSession::open_stream`] / [`XtcpTunnelSession::accept_stream`].
#[cfg(feature = "tcp-mux")]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_yamux_session(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&NatHoleDetectBehavior>,
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    yamux_client: bool,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<XtcpTunnelSession, String> {
    use tokio_util::compat::TokioAsyncReadCompatExt;
    use yamux::{Config, Connection, Mode};

    // 1. Punch hole + create KCP stream.
    let kcp_stream = crate::xtcp_p2p::xtcp_p2p_connect(
        socket,
        candidates,
        assisted,
        behavior,
        conv,
        kcp_config,
        hole_punch_timeout_ms,
        sid,
        key,
    )
    .await?;

    // 2. Wrap the KCP stream in ReadActivity so the driver's idle watchdog
    //    (TUNNEL_IDLE_CLOSE_MS) can observe inbound KCP input: yamux-rs
    //    exposes no activity signal, so the timestamp is stamped here on
    //    every read the connection makes. (Tokio side — futures-util has no
    //    `io` feature in this crate — then compat'd to futures traits below.)
    let last_read_ms = Arc::new(AtomicU64::new(now_epoch_ms()));
    let kcp_stream = ReadActivity {
        inner: kcp_stream,
        last_read_ms: last_read_ms.clone(),
    };
    let compat_stream = kcp_stream.compat();

    // 3. Create the yamux Connection. Go frp v0.71 sets
    //    KeepAliveInterval=10s and MaxStreamWindowSize=6MB in the XTCP path
    //    (fmux.Config; the fatedier fork sends real ping frames). yamux-rs
    //    0.14 has NO keepalive field — its Config has no ping machinery — so
    //    the tunnel data plane sends no keepalive pings at all. Idle
    //    half-open tunnels are reclaimed by the driver-side idle watchdog
    //    instead (ReadActivity timestamp vs TUNNEL_IDLE_CLOSE_MS — an alive
    //    idle peer still delivers yamux ping/pong frames every ~10s, so 90s
    //    of silence proves the peer is gone); outbound-only traffic with a
    //    dead peer still dies via KCP send-side dead-link. Only the receive
    //    window needs setting (same values as the per-stream path).
    let mut yamux_cfg = Config::default();
    yamux_cfg.set_max_connection_receive_window(Some(6 * 1024 * 1024 * 64));
    // Round-13 per-stream window cap: Go frp pins MaxStreamWindowSize=6MiB
    // on the XTCP data plane (client/connector.go `MaxStreamWindowSize`,
    // client/visitor/xtcp.go + server/service.go — 6<<20). yamux-rs
    // auto-tunes a single stream's receive window up to the connection
    // limit (~320MiB at this 384MiB connection window, see
    // `ConnectionWindowUpdate`), so one stream could claim the entire
    // window — the vendored `max_stream_receive_window` cap (vendor
    // fork, default None = crates.io behavior) restores Go's per-stream
    // bound; the connection window keeps bounding the sum.
    yamux_cfg.set_max_stream_receive_window(Some(6 * 1024 * 1024));
    yamux_cfg.set_max_num_streams(MAX_TUNNEL_STREAMS);
    let mode = if yamux_client {
        Mode::Client
    } else {
        Mode::Server
    };
    let conn = Connection::new(compat_stream, yamux_cfg, mode);
    tracing::info!(
        conv,
        role = if yamux_client { "client" } else { "server" },
        "XTCP P2P: tunnel session created"
    );

    // 4. Background driver: owns the Connection exclusively; drives KCP
    //    ticks (10ms timeout poll → poll_read → maybe_tick) and serves
    //    open/accept requests through bounded channels. Modeled on the
    //    request-channel driver in mux.rs client_mux — the driver NEVER parks
    //    inside a poll, so a full ACK backlog cannot wedge the session.
    //
    //    The driver's lifetime is bound to the SESSION: the `driver_drop_rx`
    //    resolves when `close()` sends or the last session handle drops its
    //    sender. The legacy per-stream wrapper keeps its own (per-stream)
    //    driver; this is the persistent-session model.
    let tick_ms = KCP_TICK_MS as u64;
    Ok(spawn_tunnel_driver(
        conn,
        !yamux_client,
        MAX_TUNNEL_STREAMS,
        tick_ms,
        last_read_ms,
    ))
}

/// A tunnel stream handed out by the driver, tracking it in the driver's
/// live-stream mirror until the caller drops it.
///
/// yamux 0.14 exposes no stream-count API, so the driver mirrors its own
/// accounting with a counter: incremented when an outbound open is handed
/// out OR an inbound stream is admitted, decremented here when the caller
/// (or the driver, client-mode) drops the stream (yamux removes the stream
/// from its own map on the next driver poll — the driver polls inbound
/// before serving opens, so the mirror is consistent with yamux's
/// `streams.len()`).
#[cfg(feature = "tcp-mux")]
struct LiveP2pStream {
    inner: Box<dyn P2pStream>,
    live: Arc<AtomicUsize>,
}

#[cfg(feature = "tcp-mux")]
impl Drop for LiveP2pStream {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(feature = "tcp-mux")]
impl tokio::io::AsyncRead for LiveP2pStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "tcp-mux")]
impl tokio::io::AsyncWrite for LiveP2pStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wraps the tunnel transport to record the wall-clock time of the last
/// successful read into a shared [`AtomicU64`], for the driver's idle
/// watchdog ([`TUNNEL_IDLE_CLOSE_MS`]). yamux exposes no inbound-activity
/// signal, so the driver observes KCP input at the transport level: when a
/// datagram arrives, the KcpStream read returns data and the timestamp
/// updates; an idle-but-alive peer still delivers yamux ping/pong frames
/// every ~10s, so a 90s gap in reads means the peer is gone.
#[cfg(feature = "tcp-mux")]
struct ReadActivity<S> {
    inner: S,
    last_read_ms: Arc<AtomicU64>,
}

// NOTE: implemented on the TOKIO side (before `.compat()` into futures
// traits for yamux) because frp-core's futures-util has no `io` feature —
// `futures_util::io::ReadBuf` is unavailable there. The wrapper is applied
// to the raw `KcpStream` in `xtcp_p2p_connect_yamux_session`, then
// `TokioAsyncReadCompatExt` converts the whole thing for the yamux
// connection.
#[cfg(feature = "tcp-mux")]
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ReadActivity<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if r.is_ready() {
            self.last_read_ms.store(now_epoch_ms(), Ordering::Release);
        }
        r
    }
}

#[cfg(feature = "tcp-mux")]
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ReadActivity<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Spawn the background driver for a yamux tunnel connection and return the
/// session handle.
///
/// The driver owns the `yamux::Connection` exclusively and serves open /
/// accept requests through bounded channels until `close()` or the last
/// session handle drop.
///
/// `max_streams` MUST match the `Config::max_num_streams` the connection was
/// built with: the driver mirrors yamux's own cap accounting (`poll_new_outbound`
/// / `poll_next_inbound` refuse once `streams.len() >= max_num_streams`) with
/// a caller-side counter that counts BOTH outbound opens and admitted inbound
/// streams (round-13 fix: an outbound-only mirror passes while the inbound
/// poll already filled the map — the cap check would then miss the window and
/// `poll_new_outbound`'s `Err(TooManyStreams)` would convert into a
/// session-wide `ConnectionState::Cleanup` (`drop_all_streams` — every live
/// stream dies and the tunnel must be re-punched)). A cap hit fails the
/// INDIVIDUAL open request instead. Go's fatedier fork has no stream cap and
/// fails per-open; the vendored inbound path already RSTs per-stream at the
/// cap, and this mirror gives the outbound direction the same survival.
#[cfg(feature = "tcp-mux")]
fn spawn_tunnel_driver<T>(
    mut conn: yamux::Connection<T>,
    server_mode: bool,
    max_streams: usize,
    tick_ms: u64,
    idle_watch: Arc<AtomicU64>,
) -> XtcpTunnelSession
where
    T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + Send + 'static,
{
    use futures_util::future::poll_fn;
    use std::task::Poll;
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let (open_tx, mut bg_open_rx) = mpsc::channel::<
        oneshot::Sender<Result<Box<dyn P2pStream>, String>>,
    >(MAX_PENDING_OPEN_REQUESTS);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Box<dyn P2pStream>>(MAX_INBOUND_QUEUE);
    let (driver_drop_tx, mut driver_drop_rx) = watch::channel(());
    let alive = Arc::new(AtomicBool::new(true));
    let bg_alive = alive.clone();
    // Mirror of the connection's live stream-map count (see `max_streams`
    // above): outbound opens AND admitted inbound streams (round-13 fix —
    // the inbound poll below runs BEFORE the open-serving loop, so an
    // inbound stream admitted this pass occupies a map slot the mirror must
    // already reflect when the loop checks the cap). Incremented when an
    // open is handed to its caller or an inbound stream is admitted;
    // decremented by the per-stream drop guard when the stream is dropped.
    let live_streams = Arc::new(AtomicUsize::new(0));
    // Round-13 wake channel for queued open requests (see the struct field
    // `open_wake`): the driver parks on `open_wake.notified()` in its select,
    // so an open queued between polls is served at the next driver wake, not
    // at the next (possibly 1s-idle) tick. A notify during the select stores
    // a permit — the next `notified()` completes immediately.
    let open_wake = Arc::new(Notify::new());
    let driver_open_wake = open_wake.clone();
    // Teardown-signal clone for the nested select inside the inbound-delivery
    // path (the outer loop's receiver cannot be borrowed twice). Both
    // receivers observe sends after their creation, so `close()` /
    // last-handle drop always resolves one of them promptly.
    let mut driver_drop_rx_inner = driver_drop_rx.clone();

    tokio::spawn(async move {
        let mut pending_opens: std::collections::VecDeque<
            oneshot::Sender<Result<Box<dyn P2pStream>, String>>,
        > = std::collections::VecDeque::new();
        // L24: the guard flips `bg_alive` false on ANY task exit, including
        // a panic in the loop body — the explicit store below covers the
        // normal break paths, the guard covers the rest (with panic=abort
        // the process dies anyway; under unwind the task must not leave a
        // stale "alive" behind for callers to wait on).
        let _alive_guard = BgAliveGuard(bg_alive.clone());
        // M8 cap-mirror retry guard: set when an open request is requeued
        // after a TooManyStreams from poll_new_outbound (the mirror said
        // "room" but yamux's stream map was still at the cap — the caller's
        // drop decrements the mirror immediately, yamux frees the slot on
        // the driver's next inbound poll). The requeue + break lets that
        // inbound poll run before the retry; the flag keeps the retry to ONE
        // per request — a second TooManyStreams for the same request means
        // the cap is genuinely reached and must fail the open rather than
        // requeue forever. Reset when the retried request resolves.
        let mut too_many_retried = false;
        // Round-13 adaptive idle tick: with steady traffic the driver wakes
        // every KCP_TICK_MS (fast tick — drives KCP, serves opens). When a
        // pass produced NO activity (no open served, no request drained, no
        // inbound stream), the next timeout stretches to TUNNEL_IDLE_TICK_MS
        // — a completely idle session must not wake 100 times per second
        // (each wake is a UDP try_recv syscall through poll_read). Any
        // activity snaps the tick back to the fast value. The idle tick does
        // not delay KCP dead-link detection past the 90s idle watchdog
        // (TUNNEL_IDLE_CLOSE_MS), and inbound data/ACKs still wake the
        // driver immediately via the poll wakers — the idle tick only paces
        // the nothing-at-all case.
        let mut tick_ms = tick_ms;
        loop {
            // M10 idle watchdog: close the session after ~90s of no inbound
            // KCP input (see TUNNEL_IDLE_CLOSE_MS). Checked per iteration —
            // each pass is ≤ one tick (+ bounded delivery waits), so the
            // granularity is ~90s ± 0.5s. The timestamp is written by the
            // ReadActivity wrapper around the transport on every successful
            // read (any inbound datagram carrying a yamux frame — including
            // the ~10s ping/pong keepalive traffic of an alive idle peer).
            if now_epoch_ms().saturating_sub(idle_watch.load(Ordering::Acquire))
                > TUNNEL_IDLE_CLOSE_MS
            {
                tracing::warn!(
                    idle_ms = TUNNEL_IDLE_CLOSE_MS,
                    "XTCP P2P: tunnel session idle (no inbound KCP input for {}s), closing",
                    TUNNEL_IDLE_CLOSE_MS / 1000,
                );
                break;
            }
            // Timeout-driven I/O poll: the timeout both keeps KCP ticking
            // (via poll_read → maybe_tick → drive_kcp inside
            // poll_next_inbound) and bounds every iteration, so open
            // requests queued outside the poll are served within one tick
            // (or immediately — the `open_wake` arm below).
            let mut had_activity = false;
            let result = tokio::select! {
                _ = driver_drop_rx.changed() => break,
                // Open-request wake (round-13): an open_stream queued between
                // polls must be served now, not at the next (possibly 1s)
                // idle tick. The stored permit makes the wake loss-proof; the
                // drain happens on the next loop pass (this arm breaks out of
                // the select, the loop body then re-enters with a fast tick).
                _ = driver_open_wake.notified() => None,
                r = tokio::time::timeout(Duration::from_millis(tick_ms), poll_fn(|cx| {
                    // (1) Drain enqueued open requests (visitor role). Stop at
                    // the cap: a stalled peer must make open_stream fail fast
                    // instead of growing this queue without bound.
                    loop {
                        if pending_opens.len() >= MAX_PENDING_OPEN_REQUESTS {
                            break;
                        }
                        match bg_open_rx.try_recv() {
                            Ok(req) => {
                                had_activity = true;
                                pending_opens.push_back(req);
                            }
                            Err(mpsc::error::TryRecvError::Empty)
                            | Err(mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }
                    // (2) Poll inbound BEFORE serving opens: per-stream drops
                    // are only removed from yamux's stream map here, so
                    // draining first keeps the cap mirror below consistent
                    // with yamux's own accounting (a stream dropped by its
                    // caller still occupies a map slot until this poll).
                    let first = conn.poll_next_inbound(cx);
                    // Round-13 cap-mirror fix: an inbound stream admitted by
                    // the poll above now occupies a stream-map slot — count
                    // it BEFORE the open-serving loop so the mirror reflects
                    // the map when the loop checks the cap. (Without this,
                    // the mirror passes while the map is full, poll_new_outbound
                    // returns TooManyStreams, and yamux 0.14 converts that into
                    // a session-wide cleanup — drop_all_streams kills every
                    // live bridge.) The double-poll below counts its own
                    // admission for the NEXT iteration.
                    if matches!(&first, Poll::Ready(Some(Ok(_)))) {
                        live_streams.fetch_add(1, Ordering::Release);
                        had_activity = true;
                    }
                    // (3) Serve as many opens as the ACK backlog admits.
                    // pop-first so a full backlog stops the loop; the request
                    // stays queued and is served on a later pass after the
                    // inbound poll below reads the ACKs that free backlog.
                    // `too_many_retried` (declared at task scope, above the
                    // driver loop) guards the M8 cap-mirror retry — see the
                    // Err(TooManyStreams) arm below — to one extra pass per
                    // request.
                    loop {
                        let Some(req) = pending_opens.pop_front() else {
                            break;
                        };
                        // Caller cancelled (dropped its receiver) — never
                        // open a phantom stream for it. Also settles any
                        // in-flight M8 retry: its request is gone, so the
                        // next TooManyStreams gets a fresh retry.
                        if req.is_closed() {
                            too_many_retried = false;
                            continue;
                        }
                        // Mirror yamux's own stream-cap check
                        // (vendor/yamux `Active::poll_new_outbound`:
                        // `streams.len() >= max_num_streams`): refuse the
                        // INDIVIDUAL open here. Calling poll_new_outbound at
                        // the cap would make it return Err(TooManyStreams),
                        // which yamux 0.14 turns into a session-wide cleanup
                        // (drop_all_streams — all live streams die, tunnel
                        // re-punch). The mirror counts live outbound AND
                        // admitted inbound streams (round-13 fix — the
                        // inbound poll in (2) admitted a stream into the map
                        // that the mirror must already reflect; with an
                        // outbound-only mirror the cap check misses that
                        // window and the TooManyStreams cleanup kills the
                        // tunnel). Go's fatedier fork has no cap and fails
                        // per-open; this gives the outbound direction the
                        // same survival as the vendored inbound per-stream
                        // RST.
                        if live_streams.load(Ordering::Acquire) >= max_streams {
                            // Mirror refusal settles any in-flight M8 retry
                            // (the request resolves here, failing properly).
                            too_many_retried = false;
                            let _ = req.send(Err(format!(
                                "yamux tunnel stream cap reached ({max_streams})"
                            )));
                            continue;
                        }
                        match conn.poll_new_outbound(cx) {
                            Poll::Ready(Ok(stream)) => {
                                // yamux-rs 0.14 attaches the SYN flag lazily
                                // to the stream's first emitted frame (write
                                // or window-update); a fresh stream emits
                                // neither, so an open with no immediate write
                                // never reaches the provider. Go yamux sends
                                // SYN eagerly on Open — flush an empty
                                // DATA+SYN frame here so the provider's
                                // accept fires as soon as the visitor opens.
                                // (On a Pending write — stream command
                                // channel full, unreachable for a fresh
                                // stream — the caller's first write still
                                // carries the SYN.)
                                let mut stream = stream;
                                match futures_util::AsyncWrite::poll_write(
                                    std::pin::Pin::new(&mut stream),
                                    cx,
                                    &[],
                                ) {
                                    Poll::Ready(Ok(_)) | Poll::Pending => {
                                        // Count BEFORE handing out: the guard
                                        // below decrements when the caller
                                        // drops the stream. The open resolved,
                                        // settling any in-flight M8 retry.
                                        too_many_retried = false;
                                        live_streams.fetch_add(1, Ordering::Release);
                                        had_activity = true;
                                        let _ = req.send(Ok(Box::new(LiveP2pStream {
                                            inner: Box::new(stream.compat())
                                                as Box<dyn P2pStream>,
                                            live: live_streams.clone(),
                                        }) as Box<dyn P2pStream>));
                                    }
                                    Poll::Ready(Err(e)) => {
                                        too_many_retried = false;
                                        let _ = req.send(Err(format!(
                                            "yamux open stream: {e}"
                                        )));
                                    }
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                if !too_many_retried
                                    && matches!(
                                        e,
                                        yamux::ConnectionError::TooManyStreams
                                    )
                                {
                                    // M8 cap-mirror TOCTOU: the caller's drop
                                    // guard decrements `live_streams`
                                    // immediately, but yamux frees the
                                    // stream-map slot only when the driver
                                    // polls inbound. If a caller dropped a
                                    // stream between the mirror check above
                                    // and this poll, the mirror says "room"
                                    // while yamux's map is still at the cap —
                                    // poll_new_outbound returns
                                    // TooManyStreams, and propagating it
                                    // would make yamux 0.14 clean up the
                                    // WHOLE session (drop_all_streams — all
                                    // live streams die, tunnel re-punch).
                                    // Requeue the request and let the NEXT
                                    // iteration's inbound poll (2) process
                                    // the drop; the re-check then either
                                    // opens or refuses via the mirror. One
                                    // retry per request (guarded by
                                    // `too_many_retried`, reset when the
                                    // request resolves in any of the arms
                                    // above) — a second TooManyStreams for
                                    // the same request means the cap is
                                    // genuinely reached.
                                    too_many_retried = true;
                                    pending_opens.push_front(req);
                                    break;
                                }
                                too_many_retried = false;
                                let _ = req.send(Err(format!("yamux open stream: {e}")));
                            }
                            Poll::Pending => {
                                pending_opens.push_front(req);
                                break;
                            }
                        }
                    }
                    // (4) Double-poll inbound (ACK + flush; drives the KCP
                    // tick on the read path; the flush pushes the SYN frames
                    // written by (3) onto the wire this tick). A stream
                    // admitted here is counted for the NEXT iteration's cap
                    // check (the serve loop already ran — its mirror check
                    // cannot collide with this admission).
                    let inbound = match first {
                        Poll::Ready(r) => Poll::Ready(r),
                        Poll::Pending => conn.poll_next_inbound(cx),
                    };
                    if matches!(&inbound, Poll::Ready(Some(Ok(_)))) {
                        live_streams.fetch_add(1, Ordering::Release);
                        had_activity = true;
                    }
                    inbound
                })) => Some(r),
            };
            // Open-request wake: the queued request is served next pass —
            // snap back to the fast tick so a burst of opens is not paced by
            // the idle tick, then loop (the drain runs in the next select).
            let Some(result) = result else {
                tick_ms = KCP_TICK_MS as u64;
                continue;
            };
            match result {
                Ok(Some(Ok(stream))) => {
                    // Activity (inbound stream admitted): keep the fast tick.
                    tick_ms = KCP_TICK_MS as u64;
                    if server_mode {
                        // Provider: deliver to the accept queue. On a full
                        // queue, a bounded wait for a permit gives the accept
                        // loop time to drain before the stream is dropped
                        // (server_mux pattern). Wrapped in the drop-guard
                        // (round-13): the stream was counted in the mirror at
                        // admission, and the guard decrements when the accept
                        // loop drops it.
                        let stream = Box::new(LiveP2pStream {
                            inner: Box::new(stream.compat()) as Box<dyn P2pStream>,
                            live: live_streams.clone(),
                        }) as Box<dyn P2pStream>;
                        if let Err(e) = inbound_tx.try_send(stream) {
                            match e {
                                mpsc::error::TrySendError::Full(s) => {
                                    // Bounded wait for a permit, then deliver
                                    // or drop the stream (full after 500ms or
                                    // receiver gone). Raced against the
                                    // teardown signal so close() cancels the
                                    // wait immediately instead of stalling
                                    // the driver tick for the full 500ms.
                                    tokio::select! {
                                        _ = driver_drop_rx_inner.changed() => {
                                            // Teardown: drop the stream; the
                                            // loop's exit check above breaks
                                            // on the next iteration.
                                        }
                                        res = tokio::time::timeout(
                                            Duration::from_millis(500),
                                            inbound_tx.reserve(),
                                        ) => {
                                            if let Ok(Ok(permit)) = res {
                                                permit.send(s);
                                            }
                                        }
                                    }
                                }
                                mpsc::error::TrySendError::Closed(_) => {}
                            }
                        }
                    } else {
                        // Client mode: the provider never opens streams to
                        // the visitor — drop unexpected inbound. Wrapped in
                        // the drop-guard (round-13) so the mirror decrements
                        // with the drop (the map slot frees on the driver's
                        // next inbound poll) — an unwrapped drop would leak
                        // the admission count and permanently shrink the
                        // mirror's headroom.
                        tracing::debug!(
                            stream_id = stream.id().val(),
                            "XTCP P2P: unexpected inbound stream on client session, dropping"
                        );
                        drop(Box::new(LiveP2pStream {
                            inner: Box::new(stream.compat()) as Box<dyn P2pStream>,
                            live: live_streams.clone(),
                        }) as Box<dyn P2pStream>);
                    }
                }
                Ok(Some(Err(e))) => {
                    tracing::warn!(error = %e, "XTCP P2P: tunnel session connection error, exiting");
                    break;
                }
                Ok(None) => {
                    tracing::debug!("XTCP P2P: tunnel session connection closed, exiting");
                    break;
                }
                Err(_elapsed) => {
                    // KCP tick — no I/O event this pass. Adaptive idle tick
                    // (round-13): any activity (open served, request drained,
                    // inbound stream) keeps the fast KCP tick; a completely
                    // quiet pass stretches the next wake to
                    // TUNNEL_IDLE_TICK_MS so an idle session stops waking
                    // 100×/s.
                    if had_activity {
                        tick_ms = KCP_TICK_MS as u64;
                    } else {
                        tick_ms = TUNNEL_IDLE_TICK_MS;
                    }
                }
            }
        }
        bg_alive.store(false, Ordering::Release);
        tracing::debug!("XTCP P2P: tunnel session driver exiting");
    });

    XtcpTunnelSession {
        open_tx,
        inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        alive,
        driver_drop_tx,
        open_wake,
    }
}

/// Punch a UDP NAT hole and create a raw-KCP one-shot session (no tcp-mux).
/// The punch stream IS the session: single connection per punch.
#[cfg(not(feature = "tcp-mux"))]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_yamux_session(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&NatHoleDetectBehavior>,
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    _yamux_client: bool,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<XtcpTunnelSession, String> {
    let stream = crate::xtcp_p2p::xtcp_p2p_connect(
        socket,
        candidates,
        assisted,
        behavior,
        conv,
        kcp_config,
        hole_punch_timeout_ms,
        sid,
        key,
    )
    .await?;
    Ok(XtcpTunnelSession {
        inner: tokio::sync::Mutex::new(Some(stream)),
        alive: Arc::new(AtomicBool::new(true)),
    })
}

/// Punch a UDP NAT hole and create a persistent QUIC tunnel session (Go frp
/// v0.71 `QUICTunnelSession.Init` + provider `listenByQUIC`), using the
/// given [`crate::quic::QuicTransportParams`] for the quinn transport config.
///
/// Go builds the tunnel from the client's `transport.QUIC` config
/// (`MaxIdleTimeout` / `MaxIncomingStreams` / `KeepAlivePeriod` — see
/// client/visitor/xtcp.go `QUICTunnelSession.Init` and client/proxy/xtcp.go
/// `listenByQUIC`); this variant lets the caller do the same instead of
/// accepting the crate defaults.
///
/// `is_server` selects the QUIC role: `true` = provider (QUIC server, accepts
/// the connection), `false` = visitor (QUIC client, dials). NO stream is
/// opened here — streams are opened per user connection via
/// [`QuicTunnelSession::open_stream`] / [`QuicTunnelSession::accept_stream`].
/// The winning hole-punch socket is handed to quinn directly so the NAT
/// mapping is preserved (Go `quic.Dial`/`quic.Listen` on `result.lConn`).
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_quic_session_with_params(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&NatHoleDetectBehavior>,
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
    is_server: bool,
    params: crate::quic::QuicTransportParams,
) -> Result<QuicTunnelSession, String> {
    // 1. Punch hole. With a server-provided DetectBehavior use the full Go
    //    MakeHole state machine, otherwise the simplified punch.
    let (win_socket, peer_addr) = match behavior {
        Some(b) => {
            crate::xtcp_p2p::punch_udp_hole_makehole_owned(
                socket, candidates, assisted, b, timeout_ms, sid, key,
            )
            .await?
        }
        None => {
            let peer_addr =
                crate::xtcp_p2p::punch_udp_hole(&socket, candidates, timeout_ms, sid, key).await?;
            (socket, peer_addr)
        }
    };

    tracing::info!(
        peer = %peer_addr,
        role = if is_server { "server" } else { "client" },
        "XTCP P2P QUIC: hole punched to {}",
        peer_addr,
    );

    // 2. Hand the winning tokio socket to quinn as a std socket.
    let std_socket = win_socket
        .into_std()
        .map_err(|e| format!("convert UDP socket to std: {e}"))?;

    // 3. QUIC data plane over the punched socket. The connection itself owns
    //    the quinn endpoint (and with it the UDP socket); the returned
    //    handle is cloned per stream.
    let conn = if is_server {
        // Provider = QUIC server: self-signed TLS, accept one connection.
        let tls_config = crate::transport::generate_self_signed_tls_config()
            .map_err(|e| format!("generate self-signed TLS config: {e}"))?;
        crate::quic::quic_accept_on_socket(std_socket, tls_config, params)
            .await
            .map_err(|e| format!("QUIC accept: {e}"))?
    } else {
        // Visitor = QUIC client: dial (InsecureSkipVerify) without opening a
        // phantom stream (Go `QUICTunnelSession.Init` dials only).
        crate::quic::quic_dial_conn_on_socket(
            std_socket,
            peer_addr,
            &peer_addr.ip().to_string(),
            params,
        )
        .await
        .map_err(|e| format!("QUIC dial: {e}"))?
    };

    Ok(QuicTunnelSession {
        conn,
        alive: Arc::new(AtomicBool::new(true)),
    })
}

/// Thin wrapper over [`xtcp_p2p_connect_quic_session_with_params`] using the
/// crate's default [`crate::quic::QuicTransportParams`] — kept for callers
/// that do not thread the client QUIC config through (Go parity requires the
/// params variant).
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_quic_session(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&NatHoleDetectBehavior>,
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
    is_server: bool,
) -> Result<QuicTunnelSession, String> {
    xtcp_p2p_connect_quic_session_with_params(
        socket,
        candidates,
        assisted,
        behavior,
        timeout_ms,
        sid,
        key,
        is_server,
        crate::quic::QuicTransportParams::default(),
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "tcp-mux"))]
mod tests {
    use super::*;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    /// Returns the error from a failing open (the Ok side is a non-Debug
    /// trait object, so `expect_err` is unavailable).
    async fn expect_open_error(session: &XtcpTunnelSession, what: &str) -> String {
        match session.open_stream(Duration::from_secs(2)).await {
            Err(e) => e,
            Ok(_) => panic!("{what}"),
        }
    }

    /// The outbound stream cap must fail the INDIVIDUAL open request and
    /// leave the session alive — Go fatedier/yamux-fork parity, where a
    /// stream-cap hit is a per-open error instead of yamux 0.14's
    /// session-wide `TooManyStreams` cleanup (all live streams die, tunnel
    /// re-punch). Once a slot frees, the session must open again.
    ///
    /// The peer half of the duplex is held but never read: no ACKs arrive,
    /// but that is fine — opens succeed locally (yamux's ACK backlog is 256,
    /// well above this test's cap) and the cap pre-check is what is under
    /// test. The driver polls inbound before serving opens, so the dropped
    /// stream's map removal is deterministic before the re-open.
    #[tokio::test(flavor = "current_thread")]
    async fn tunnel_driver_cap_fails_individual_open_session_survives() {
        const CAP: usize = 4;
        let (driver_io, _peer_io) = tokio::io::duplex(65536);
        let mut cfg = yamux::Config::default();
        cfg.set_max_num_streams(CAP);
        let conn = yamux::Connection::new(driver_io.compat(), cfg, yamux::Mode::Client);
        let session = spawn_tunnel_driver(
            conn,
            false,
            CAP,
            10,
            Arc::new(AtomicU64::new(now_epoch_ms())),
        );

        let mut streams: Vec<Box<dyn P2pStream>> = Vec::new();
        for _ in 0..CAP {
            let s = session
                .open_stream(Duration::from_secs(2))
                .await
                .expect("open within the cap");
            streams.push(s);
        }

        // The open past the cap fails individually...
        let err = expect_open_error(&session, "open past the cap must fail").await;
        assert!(err.contains("cap"), "unexpected error: {err}");

        // ... and the SESSION survives (no yamux TooManyStreams cleanup).
        assert!(session.is_alive(), "session must survive the cap hit");

        // Freeing a slot lets the session open again...
        drop(streams.pop().expect("held stream"));
        let s = session
            .open_stream(Duration::from_secs(2))
            .await
            .expect("open after a slot frees");
        streams.push(s);
        assert!(session.is_alive(), "session must survive reopen");

        // ... and the cap re-engages at the new full count.
        let err = expect_open_error(&session, "open past the cap must fail again").await;
        assert!(err.contains("cap"), "unexpected error: {err}");
        assert!(session.is_alive(), "session must survive repeated cap hits");

        session.close().await;
        assert!(!session.is_alive(), "close must mark the session dead");
    }
}
