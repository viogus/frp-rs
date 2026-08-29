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
//!   (Go parity: `fmux.Client`/`fmux.Server` with `KeepAliveInterval=10s`,
//!   `MaxStreamWindowSize=6MB`); without `tcp-mux`, a one-shot raw KCP stream
//!   (the pre-existing Rust↔Rust fallback capability — one connection per
//!   punch, no multiplexing).
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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
#[cfg(feature = "tcp-mux")]
use tokio::sync::{mpsc, oneshot, watch};

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
}

#[cfg(feature = "tcp-mux")]
impl XtcpTunnelSession {
    /// Open a new stream on the session (visitor / yamux client role).
    ///
    /// Bounded by `timeout`: a healthy session answers in milliseconds; a
    /// dead-but-undetected session (peer vanished without RST — UDP) times
    /// out once KCP dead-link detection trips or `timeout` expires. The
    /// caller (`getTunnelConn` semantics) then closes the session and
    /// triggers a re-punch.
    pub async fn open_stream(&self, timeout: Duration) -> Result<Box<dyn P2pStream>, String> {
        if !self.is_alive() {
            return Err("no tunnel session".into());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx
            .try_send(reply_tx)
            .map_err(|_| "tunnel session open queue full (peer stalled?)".to_string())?;
        // The driver's I/O branch re-arms every KCP_TICK_MS, so the request
        // is served within one tick without an extra wake-up channel.
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
    use futures_util::future::poll_fn;
    use std::task::Poll;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
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

    // 2. Compat KCP stream to futures traits for yamux.
    let compat_stream = kcp_stream.compat();

    // 3. Create the yamux Connection. Go frp v0.71 sets
    //    KeepAliveInterval=10s and MaxStreamWindowSize=6MB in the XTCP path;
    //    yamux-rs's default keepalive is 10s, so only the receive window
    //    needs setting (same values as the per-stream path).
    let mut yamux_cfg = Config::default();
    yamux_cfg.set_max_connection_receive_window(Some(6 * 1024 * 1024 * 64));
    yamux_cfg.set_max_num_streams(256);
    let mode = if yamux_client {
        Mode::Client
    } else {
        Mode::Server
    };
    let mut conn = Connection::new(compat_stream, yamux_cfg, mode);
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
    //    The driver's lifetime is bound to the SESSION: `driver_drop_rx`
    //    resolves when `close()` sends or the last session handle drops its
    //    sender. The legacy per-stream wrapper keeps its own (per-stream)
    //    driver; this is the persistent-session model.
    let tick_ms = KCP_TICK_MS as u64;
    let (open_tx, mut bg_open_rx) = mpsc::channel::<
        oneshot::Sender<Result<Box<dyn P2pStream>, String>>,
    >(MAX_PENDING_OPEN_REQUESTS);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Box<dyn P2pStream>>(MAX_INBOUND_QUEUE);
    let (driver_drop_tx, mut driver_drop_rx) = watch::channel(());
    let alive = Arc::new(AtomicBool::new(true));
    let bg_alive = alive.clone();
    let server_mode = !yamux_client;

    tokio::spawn(async move {
        let mut pending_opens: std::collections::VecDeque<
            oneshot::Sender<Result<Box<dyn P2pStream>, String>>,
        > = std::collections::VecDeque::new();
        loop {
            // Timeout-driven I/O poll: the timeout both keeps KCP ticking
            // (via poll_read → maybe_tick → drive_kcp inside
            // poll_next_inbound) and bounds every iteration, so open
            // requests queued outside the poll are served within one tick.
            let result = tokio::select! {
                _ = driver_drop_rx.changed() => break,
                r = tokio::time::timeout(Duration::from_millis(tick_ms), poll_fn(|cx| {
                    // (1) Drain enqueued open requests (visitor role). Stop at
                    // the cap: a stalled peer must make open_stream fail fast
                    // instead of growing this queue without bound.
                    loop {
                        if pending_opens.len() >= MAX_PENDING_OPEN_REQUESTS {
                            break;
                        }
                        match bg_open_rx.try_recv() {
                            Ok(req) => pending_opens.push_back(req),
                            Err(mpsc::error::TryRecvError::Empty)
                            | Err(mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }
                    // (2) Serve as many opens as the ACK backlog admits.
                    // pop-first so a full backlog stops the loop; the request
                    // stays queued and is served on a later pass after the
                    // inbound poll below reads the ACKs that free backlog.
                    loop {
                        let Some(req) = pending_opens.pop_front() else {
                            break;
                        };
                        // Caller cancelled (dropped its receiver) — never
                        // open a phantom stream for it.
                        if req.is_closed() {
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
                                        let _ = req.send(Ok(Box::new(stream.compat())
                                            as Box<dyn P2pStream>));
                                    }
                                    Poll::Ready(Err(e)) => {
                                        let _ = req.send(Err(format!(
                                            "yamux open stream: {e}"
                                        )));
                                    }
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                let _ = req.send(Err(format!("yamux open stream: {e}")));
                            }
                            Poll::Pending => {
                                pending_opens.push_front(req);
                                break;
                            }
                        }
                    }
                    // (3) Double-poll inbound (ACK + flush; drives the KCP
                    // tick on the read path).
                    let first = conn.poll_next_inbound(cx);
                    match first {
                        Poll::Ready(r) => Poll::Ready(r),
                        Poll::Pending => conn.poll_next_inbound(cx),
                    }
                })) => r,
            };
            match result {
                Ok(Some(Ok(stream))) => {
                    if server_mode {
                        // Provider: deliver to the accept queue. On a full
                        // queue, a bounded wait for a permit gives the accept
                        // loop time to drain before the stream is dropped
                        // (server_mux pattern).
                        let stream = Box::new(stream.compat()) as Box<dyn P2pStream>;
                        if let Err(e) = inbound_tx.try_send(stream) {
                            match e {
                                mpsc::error::TrySendError::Full(s) => {
                                    // Bounded wait for a permit, then deliver
                                    // or drop the stream (full after 500ms or
                                    // receiver gone).
                                    if let Ok(Ok(permit)) = tokio::time::timeout(
                                        Duration::from_millis(500),
                                        inbound_tx.reserve(),
                                    )
                                    .await
                                    {
                                        permit.send(s);
                                    }
                                }
                                mpsc::error::TrySendError::Closed(_) => {}
                            }
                        }
                    } else {
                        // Client mode: the provider never opens streams to
                        // the visitor — drop unexpected inbound.
                        tracing::debug!(
                            stream_id = stream.id().val(),
                            "XTCP P2P: unexpected inbound stream on client session, dropping"
                        );
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
                    // KCP tick — no I/O event this pass; loop and re-poll.
                }
            }
        }
        bg_alive.store(false, Ordering::Release);
        tracing::debug!("XTCP P2P: tunnel session driver exiting");
    });

    Ok(XtcpTunnelSession {
        open_tx,
        inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        alive,
        driver_drop_tx,
    })
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
/// v0.71 `QUICTunnelSession.Init` + provider `listenByQUIC`).
///
/// `is_server` selects the QUIC role: `true` = provider (QUIC server, accepts
/// the connection), `false` = visitor (QUIC client, dials). NO stream is
/// opened here — streams are opened per user connection via
/// [`QuicTunnelSession::open_stream`] / [`QuicTunnelSession::accept_stream`].
/// The winning hole-punch socket is handed to quinn directly so the NAT
/// mapping is preserved (Go `quic.Dial`/`quic.Listen` on `result.lConn`).
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
    let params = crate::quic::QuicTransportParams::default();

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
