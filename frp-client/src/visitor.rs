use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::mux::YamuxSession;
use frp_core::protocol::{
    read_msg_v1, read_msg_v2_with_udp_codec, write_msg_v2_with_udp_codec, write_v1_frame_scratch,
};
use frp_core::transport::{
    dial_server, split_work_conn_halves, BoxedReadHalf, BoxedWriteHalf, DialOptions, IoStream,
    TransportProtocol,
};

/// Configuration for an STCP/XTCP visitor listener.
pub(crate) struct VisitorListenerConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: TransportProtocol,
    pub server_name: String,
    pub server_user: String,
    pub secret_key: String,
    pub bind_addr: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub name: String,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub visitor_type: String,
    pub fallback_timeout_ms: u64,
    pub keep_tunnel_open: bool,
    pub max_retries_an_hour: i32,
    pub min_retry_interval: i64,
    pub stun_server: String,
    /// XTCP P2P data plane protocol: "quic" (default, Go parity) or "kcp".
    /// Both data planes are implemented; "quic" requires BOTH the `quic` and
    /// `kcp` features (the QUIC data plane reuses the KCP hole-punch
    /// machinery).
    pub p2p_protocol: String,
    pub visitor_tx: mpsc::Sender<crate::service::VisitorRequest>,
    pub fallback_to: String,
    pub disable_assisted_addrs: bool,
    /// Graceful shutdown signal. When true, the listener stops accepting
    /// new connections and exits. Checked between accept iterations.
    pub shutdown: Arc<AtomicBool>,
    /// Client's user name for proxy_name prefix (Go frp BuildTargetServerProxyName compat).
    pub user: String,
    /// Current session run_id for NewVisitorConn (Go frp compat).
    pub run_id: String,
    // --- Transport options matching DialOptions / Go frp connector ---
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub tcp_mux_keepalive_timeout: i64,
    pub proxy_url: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub connect_bind_addr: Option<String>,
    pub disable_custom_tls_first_byte: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub v2: bool,
    /// Negotiated UDPPacket codec (`"binary-v1"` or empty) of this frpc's
    /// control session (Go frp v0.71.0). The SUDP visitor data plane uses it
    /// so the visitor segment matches the provider segment's packet codec
    /// when wire protocol v2 is negotiated; empty means JSON framing.
    pub udp_packet_codec: String,
    /// Client-configured QUIC transport params for the XTCP tunnel session
    /// (Go `clientCfg.Transport.QUIC` — both the visitor's
    /// `NewQUICTunnelSession(sv.clientCfg)` and the provider's
    /// `listenByQUIC` read `clientCfg.Transport.QUIC`).
    ///
    /// Gated on `kcp` as well as `quic`: the only consumer is the QUIC
    /// tunnel session, and `frp_core::xtcp_p2p::QuicTunnelSession` (with its
    /// `xtcp_p2p_connect_quic_session*` constructors) is re-exported by
    /// frp-core only under `#[cfg(all(feature = "kcp", feature = "quic"))]`
    /// (`frp-core/src/xtcp_p2p.rs`). Under `quic` without `kcp` nothing on
    /// this chain — config field, punch config, session call — exists, so the
    /// field must not either, or it reads as dead under `-D warnings`.
    #[cfg(all(feature = "quic", feature = "kcp"))]
    pub quic_params: frp_core::quic::QuicTransportParams,
}

// The STCP/XTCP visitor accept loop lives in a child module
// (`visitor/stcp.rs`), together with the loop-invariant `VisitorConnCtx` it
// shares with each accepted connection's task. It is a *child* of `visitor`
// so it keeps reaching this module's private dial-planning, tunnel-session and
// bridge helpers with **no** visibility change on any of them; `stcp` itself
// is private. `run_visitor_listener` is re-exported because
// `crate::visitor::run_visitor_listener` is the spelled path at its only
// caller (`service/session.rs:1030`) and a path previously reachable from
// outside this module must stay reachable. Its `pub(crate)` is the function's
// original token — the re-export preserves it, it does not widen it.
mod stcp;
pub(crate) use stcp::run_visitor_listener;
mod xtcp;
use xtcp::{do_hole_punch, XtcpPunchConfig};

// The SUDP visitor cluster lives in a child module (`visitor/sudp.rs`): the
// lazy UDP listener, its shutdown/datagram helpers and the tunnel dial/worker
// it spawns. It is a *child* of `visitor`, so through `use super::*;` it keeps
// reaching this module's private `VisitorListenerConfig`,
// `VisitorTransportConfig` and `plan_visitor_dial` with no visibility change
// on any of them; `sudp` itself is private. `run_sudp_visitor_listener` is
// re-exported because it is `pub(crate)` at base and its only caller
// (`visitor/stcp.rs`) reaches it through that file's `use super::*;` — the
// re-export preserves the original token, it does not widen it.
mod sudp;
pub(crate) use sudp::run_sudp_visitor_listener;

// The `virtual_net` visitor cluster lives in a child module
// (`visitor/vnet.rs`): the no-bind visitor tunnel, its tunnel packet loop,
// the TUN-ingress fan-out, the two shutdown waiters and the TUN map aliases
// they share. It is a *child* of `visitor`, so through `use super::*;` it
// keeps reaching this module's private `VisitorTransportConfig` and
// `plan_visitor_dial`, plus this module's imports, with no visibility change
// on any of them; `vnet` itself is private and, because `vnet` is not a
// default feature, the declaration is feature-gated so the file stays out of
// non-vnet builds. `run_virtual_net_visitor` and `VirtualNetVisitorConfig` are
// re-exported because `crate::visitor::run_virtual_net_visitor` and
// `crate::visitor::VirtualNetVisitorConfig` are the spelled paths at their only
// external caller, the `virtual_net` visitor spawn in
// `frp-client/src/service/session.rs`; their `pub(crate)` tokens are the
// originals — the re-export preserves them, it does not widen them.
#[cfg(feature = "vnet")]
mod vnet;
#[cfg(feature = "vnet")]
pub(crate) use vnet::{run_virtual_net_visitor, VirtualNetVisitorConfig};

// ── Visitor dial planning (pure, testable) ────────────────────────────

/// Subset of visitor config fields that influence the dial and yamux
/// decision. Kept as a standalone struct so the dial-planning logic
/// can be exercised in unit tests without a running server.
#[derive(Debug, Clone, PartialEq)]
struct VisitorTransportConfig {
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub tcp_mux_keepalive_timeout: i64,
    pub proxy_url: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub connect_bind_addr: Option<String>,
    pub disable_custom_tls_first_byte: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub v2: bool,
}

impl VisitorTransportConfig {}

/// Result of visitor dial planning: the DialOptions to pass to
/// dial_server, together with an optional yamux keepalive interval
/// and idle-dead-timeout. When `yamux_keepalive_secs` is `Some(n)`
/// (paired with `yamux_idle_dead_timeout_secs: Some(t)`), the caller
/// must wrap the raw stream in yamux via `wrap_client_mux(raw, n, t)`.
#[derive(Debug)]
struct VisitorDialPlan {
    opts: DialOptions,
    yamux_keepalive_secs: Option<i64>,
    yamux_idle_dead_timeout_secs: Option<i64>,
}

/// Build the DialOptions and yamux decision for a visitor→server
/// connection.  Pure — no I/O, no spawn, no network.  The caller
/// is responsible for calling `dial_server(&plan.opts)` and, when
/// `plan.yamux_keepalive_secs` is `Some(n)` (paired with
/// `plan.yamux_idle_dead_timeout_secs: Some(t)`), wrapping the
/// result with `crate::control::wrap_client_mux(raw_stream, n, t)`.
fn plan_visitor_dial(
    server_addr: &str,
    server_port: u16,
    protocol: &TransportProtocol,
    tls_enable: bool,
    tls_server_name: &str,
    tls_ca_file: &Option<String>,
    transport: &VisitorTransportConfig,
) -> VisitorDialPlan {
    let opts = DialOptions {
        server_addr: server_addr.to_string(),
        server_port,
        protocol: protocol.clone(),
        tls_enable,
        tls_server_name: tls_server_name.to_string(),
        tls_ca_file: tls_ca_file.clone(),
        tls_skip_verify: false,
        tls_cert_file: transport.tls_cert_file.clone(),
        tls_key_file: transport.tls_key_file.clone(),
        dns_server: transport.dns_server.clone(),
        disable_custom_tls_first_byte: transport.disable_custom_tls_first_byte,
        keepalive_secs: transport.keepalive_secs,
        bind_addr: transport.connect_bind_addr.clone(),
        tcp_send_buffer_size: 0,
        tcp_recv_buffer_size: 0,
        proxy_url: transport.proxy_url.clone(),
        dial_timeout_secs: transport.dial_timeout_secs,
        v2: transport.v2,
    };
    let yamux_keepalive_secs = if transport.tcp_mux {
        Some(transport.tcp_mux_keepalive_interval)
    } else {
        None
    };
    let yamux_idle_dead_timeout_secs = if transport.tcp_mux {
        Some(transport.tcp_mux_keepalive_timeout)
    } else {
        None
    };
    VisitorDialPlan {
        opts,
        yamux_keepalive_secs,
        yamux_idle_dead_timeout_secs,
    }
}

// ── Persistent XTCP tunnel session (Go frp v0.71 keepTunnelOpenWorker) ──
//
// Go frp v0.71 keeps ONE hole-punched data-plane session per XTCP visitor
// (`KCPTunnelSession` / `QUICTunnelSession` in client/visitor/xtcp.go) and
// reuses it across user connections. A dead session is closed and re-punched
// in the background (`processTunnelStartEvents`), optionally kept alive by
// `keepTunnelOpenWorker`. User connections wait up to a budget for the
// session to yield a stream (`openTunnel` / `getTunnelConn`); there is NO
// per-connection punch+retry loop anymore.

/// Minimum gap between hole punches (Go `processTunnelStartEvents` sleeps
/// the remainder of 10s after each makeNatHole).
const MIN_PUNCH_INTERVAL: Duration = Duration::from_secs(10);

/// A persistent XTCP data-plane session, one per visitor listener.
///
/// `Kcp` is the yamux-over-KCP session (raw KCP when `tcp-mux` is off; an
/// erroring stub when `kcp` is off — tiny/micro builds fall back to STCP).
/// `Quic` is the QUIC session (no yamux), requiring both `quic` and `kcp`
/// features (the QUIC data plane reuses the KCP hole-punch machinery).
pub(crate) enum TunnelSession {
    Kcp(frp_core::xtcp_p2p::XtcpTunnelSession),
    #[cfg(all(feature = "quic", feature = "kcp"))]
    Quic(frp_core::xtcp_p2p::QuicTunnelSession),
}

impl TunnelSession {
    /// Open a new stream (visitor / client role).
    pub(crate) async fn open_stream(
        &self,
        timeout: Duration,
    ) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
        match self {
            TunnelSession::Kcp(s) => s.open_stream(timeout).await,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.open_stream(timeout).await,
        }
    }

    /// Accept the next inbound stream (provider / server role).
    pub(crate) async fn accept_stream(
        &self,
        timeout: Duration,
    ) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
        match self {
            TunnelSession::Kcp(s) => s.accept_stream(timeout).await,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.accept_stream(timeout).await,
        }
    }

    /// Whether the session is alive.
    pub(crate) fn is_alive(&self) -> bool {
        match self {
            TunnelSession::Kcp(s) => s.is_alive(),
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.is_alive(),
        }
    }

    /// Whether opening a throwaway probe stream is safe for this session.
    ///
    /// The no-tcp-mux raw-KCP session is ONE-SHOT: `open_stream` hands out
    /// the session's only stream and flips `alive=false` — a keepalive probe
    /// would SPEND a freshly punched session and force a re-punch churn on
    /// the next user connection. Go has no such mode (its KCP tunnel is
    /// always yamux-wrapped), so there is no parity constraint; user
    /// connections re-punch on demand. QUIC and yamux sessions multiplex
    /// streams, so probing them is harmless.
    pub(crate) fn probe_safe(&self) -> bool {
        match self {
            #[cfg(not(feature = "tcp-mux"))]
            TunnelSession::Kcp(_) => false,
            #[cfg(feature = "tcp-mux")]
            TunnelSession::Kcp(_) => true,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(_) => true,
        }
    }

    /// Close the session (releases the UDP socket / KCP / yamux / QUIC).
    pub(crate) async fn close(&self) {
        match self {
            TunnelSession::Kcp(s) => s.close().await,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.close().await,
        }
    }
}

/// Server-supplied `read_timeout_ms` → punch timeout (ms). Go MakeHole
/// floors the guard at 5s (`timeout := 5*time.Second; if
/// m.DetectBehavior.ReadTimeoutMs > 0`, nathole.go:248-250) — a
/// hostile/misbehaving server sending 0 or negative must not make the punch
/// fail instantly. Capped at
/// [`frp_core::xtcp_p2p::MAX_HOLE_PUNCH_TIMEOUT_MS`] (60s): Go's analyzer
/// emits ReadTimeoutMs ≤ ~45s, so anything above is a hostile server
/// stretching the punch (`read_timeout_ms` is i32 — uncapped it would wait
/// ~24.8 days before the visitor could re-punch).
fn clamp_hp_timeout(read_timeout_ms: i32) -> u64 {
    // DEFAULT_HOLE_PUNCH_TIMEOUT_MS <= MAX_HOLE_PUNCH_TIMEOUT_MS (constant
    // invariant), so `clamp` cannot panic.
    (read_timeout_ms.max(0) as u64).clamp(
        frp_core::xtcp_p2p::DEFAULT_HOLE_PUNCH_TIMEOUT_MS,
        frp_core::xtcp_p2p::MAX_HOLE_PUNCH_TIMEOUT_MS,
    )
}

/// Go frp v0.71 `processTunnelStartEvents`: on each start signal, punch a
/// new hole and swap the fresh session into the slot (closing the old one
/// first). At least `MIN_PUNCH_INTERVAL` between punches.
async fn process_tunnel_start_events(
    cfg: XtcpPunchConfig,
    slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    mut start_rx: mpsc::Receiver<()>,
    armed: &AtomicBool,
    cancel: CancellationToken,
) {
    loop {
        // Parked-gate (Go unbuffered startTunnelCh): while this receiver is
        // parked in recv, non-blocking senders may deliver a signal; once a
        // signal arrives the gate drops — the receiver is busy punching and
        // sleeping, and further signals are dropped, exactly like a send to
        // Go's unbuffered channel while the receiver is not in select.
        // Release/Acquire (not Relaxed): the store must be visible to a
        // sender's load BEFORE the sender's channel send, and the load on
        // the send side must not observe a stale "not parked" — a lost
        // signal on weak-memory CPUs would strand the session until the
        // next user connection. Zero cost on x86.
        //
        // L22: the sender's check-then-send is not atomic — a sender can
        // load `armed==true` just before our dequeue flips it false and
        // deliver a signal the busy receiver never asked for. That stale
        // signal would be consumed immediately on re-parking, triggering a
        // redundant punch (during which genuine signals are dropped — Go's
        // unbuffered channel drops them too, but only because the receiver
        // is NOT in select). Draining before re-parking removes stale
        // signals, restoring Go's drop-while-busy semantics exactly.
        while start_rx.try_recv().is_ok() {}
        armed.store(true, Ordering::Release);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = start_rx.recv() => {
                armed.store(false, Ordering::Release);
                let start = std::time::Instant::now();
                match do_hole_punch(&cfg).await {
                    Ok(new_session) => {
                        let old = {
                            let mut guard = slot.lock().await;
                            guard.replace(Arc::new(new_session))
                        };
                        if let Some(old) = old {
                            old.close().await;
                        }
                        info!(visitor_name = %cfg.visitor_name, "Visitor '{}': XTCP tunnel session (re)established", cfg.visitor_name);
                    }
                    Err(e) => {
                        warn!(visitor_name = %cfg.visitor_name, error = %e, "Visitor '{}': XTCP hole punch failed: {}", cfg.visitor_name, e);
                    }
                }
                // avoid too frequently (Go: sleep remainder of 10s)
                let elapsed = start.elapsed();
                if elapsed < MIN_PUNCH_INTERVAL {
                    tokio::select! {
                        _ = tokio::time::sleep(MIN_PUNCH_INTERVAL - elapsed) => {}
                        _ = cancel.cancelled() => return,
                    }
                }
            }
        }
    }
}

/// Go frp v0.71 `getTunnelConn`: open a stream on the persistent session.
///
/// Error taxonomy (the session's own `open_stream` wording, see
/// frp-core/src/xtcp_session.rs):
/// - "timeout opening tunnel stream (...)" — the session's driver is STILL
///   ALIVE but could not serve the open within `timeout` (peer ACK backlog /
///   stream-cap congestion). This is BUSY, not dead: closing the session
///   would kill every in-flight bridge. Go never hits this — its KCP
///   `session.Open()` blocks until a stream opens (fatedier yamux fork has
///   no cap) and QUIC `OpenStreamSync(ctx)` waits on the caller's deadline —
///   so a slow open is never treated as a dead session there. The 500ms
///   user-connection probe can time out on a healthy session under a
///   >64-open burst (the driver's 64-request queue cap) — see `open_tunnel`.
/// - "tunnel session open queue full (peer stalled?)" — same family: the
///   driver is alive but its 64-slot request queue is congested.
/// - every other error (is_alive false, driver exited, connection error) is
///   a DEAD session.
///
/// On a dead session: close it, clear the slot (only if it still holds THIS
/// session — a re-punch may have swapped in a fresh one while we were
/// failing) and signal `startTunnelCh` (non-blocking) so the re-punch task
/// runs. The signal fires on EVERY error path — empty slot included (Go:
/// getTunnelConn sends the non-blocking startTunnelCh after any OpenConn
/// failure) — gated on the receiver being parked (`armed`): Go's unbuffered
/// channel drops the signal when the receiver is busy punching/sleeping, so
/// the gate keeps the cap-1 channel empty and drops those signals too.
///
/// `close_on_timeout`: the caller's verdict on the BUSY case. `open_tunnel`
/// (500ms user probes) passes false — the session is healthy, just busy,
/// and the probe is retried. `keep_tunnel_open_worker` (30s liveness probe)
/// passes true — 30s without service means the session is effectively dead
/// and must be re-punched (Go's worker closes + re-punches on any probe
/// failure too).
async fn get_tunnel_conn(
    slot: &Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: &mpsc::Sender<()>,
    armed: &AtomicBool,
    timeout: Duration,
    close_on_timeout: bool,
) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
    let session = {
        let guard = slot.lock().await;
        match guard.as_ref() {
            Some(s) => s.clone(),
            None => {
                // Go parity: getTunnelConn signals startTunnelCh (non-blocking)
                // on every error path — with keep_tunnel_open=false the first
                // user connection's failure is what triggers the initial punch.
                if armed.load(Ordering::Acquire) {
                    let _ = start_tx.try_send(());
                }
                return Err("no tunnel session".into());
            }
        }
    };
    match session.open_stream(timeout).await {
        Ok(stream) => Ok(stream),
        // Capacity errors PROVE the session is alive (its driver served the
        // refusal) — never close for these, even when the caller
        // (keepalive probe) treats probe timeouts as death: closing would
        // kill every in-flight bridge on a healthy session.
        Err(e) if is_session_capacity_error(&e) => Err(format!("tunnel session busy: {e}")),
        Err(e) if is_busy_open_error(&e) => {
            if close_on_timeout {
                // The caller (keepalive probe) judged this a dead session.
                close_and_signal(session, slot, start_tx, armed, &e).await
            } else {
                // Session alive but busy: do NOT close it (that would kill
                // every in-flight bridge and force a 10s+ re-punch cascade);
                // let the caller retry the probe.
                Err(format!("tunnel session busy: {e}"))
            }
        }
        Err(e) => close_and_signal(session, slot, start_tx, armed, &e).await,
    }
}

/// Whether an `open_stream` error means "session alive but busy" rather
/// than "session dead". See the taxonomy comment on `get_tunnel_conn`.
fn is_busy_open_error(e: &str) -> bool {
    is_session_capacity_error(e)
        // Both session variants (yamux-over-KCP and QUIC) format open
        // timeouts identically in frp-core/src/xtcp_session.rs. The timeout
        // class is AMBIGUOUS (alive-but-stalled vs dead-but-undetected —
        // KCP dead-link detection lags); the caller's `close_on_timeout`
        // flag decides whether a probe timeout means death.
        || e.starts_with("timeout opening tunnel stream")
}

/// Errors that prove the session driver is alive and serving requests — the
/// open failed on CAPACITY, not health:
/// - `yamux tunnel stream cap reached (256)`: the driver's own outbound-cap
///   mirror refused the open (frp-core/src/xtcp_session.rs — per-open
///   refusal so the session survives; Go's fatedier fork has no cap at all).
/// - `tunnel session open queue full (peer stalled?)`: the driver's bounded
///   64-slot request queue (open_stream fails fast instead of accumulating).
///
/// A 500ms probe hitting either on a busy-but-healthy session must NOT close
/// the session (that was the round-10 HIGH: probe killed every in-flight
/// bridge + forced a 10s+ re-punch cascade).
fn is_session_capacity_error(e: &str) -> bool {
    e.starts_with("yamux tunnel stream cap reached") || e.contains("tunnel session open queue full")
}

/// Close + clear the session and signal a re-punch (Go getTunnelConn error
/// path). The slot is cleared only if it still holds THIS session, so a
/// fresh session swapped in by a re-punch is not churned by a stale failure;
/// the signal is gated on the receiver being parked (`armed`).
async fn close_and_signal(
    session: Arc<TunnelSession>,
    slot: &Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: &mpsc::Sender<()>,
    armed: &AtomicBool,
    e: &str,
) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
    session.close().await;
    let mut guard = slot.lock().await;
    let cleared = guard
        .as_ref()
        .map(|cur| Arc::ptr_eq(cur, &session))
        .unwrap_or(false);
    if cleared {
        guard.take();
    }
    drop(guard);
    if cleared && armed.load(Ordering::Acquire) {
        let _ = start_tx.try_send(());
    }
    Err(e.to_string())
}

/// Go frp v0.71 `openTunnel`: poll `get_tunnel_conn` until a tunnel stream is
/// available or `budget` expires. The effective budget is capped at 20s — Go
/// ALWAYS wraps the caller's ctx in `context.WithTimeout(ctx, 20s)`
/// (xtcp.go:202-206), so when `fallback_to` is set the budget is
/// min(20s, fallback_timeout_ms), never the raw fallback timeout. Each probe
/// is bounded by 500ms so a dead session cannot eat the whole budget on one
/// attempt (Go: OpenConn carries the full deadline, timer.Reset(500ms) paces
/// retries).
///
/// `get_tunnel_conn` is called with close_on_timeout=false: a probe TIMEOUT
/// means the session is alive but busy (peer ACK backlog / request-queue
/// congestion — e.g. a >64-concurrent-open burst), NOT dead — closing it
/// would kill every in-flight bridge on that session. The busy error is
/// retried like any other; the session stays in the slot. (Capacity errors
/// — stream-cap reached / request queue full — never close the session
/// regardless of the flag: they prove the driver is alive.)
async fn open_tunnel(
    visitor_name: &str,
    slot: &Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: &mpsc::Sender<()>,
    armed: &AtomicBool,
    conn_cancel: &CancellationToken,
    budget: Duration,
) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if conn_cancel.is_cancelled() {
            return Err("visitor shutting down".into());
        }
        match get_tunnel_conn(
            slot,
            start_tx,
            armed,
            Duration::from_millis(500),
            false, // probe timeout = busy session, not dead
        )
        .await
        {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': open tunnel attempt failed: {}", visitor_name, e);
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!("open tunnel timeout after {budget:?}"));
                }
            }
        }
        // Pace attempts (Go: timer.Reset(500ms)); a healthy session answers
        // in milliseconds so this only paces failures. Cancellation-aware: a
        // bare sleep would park up to 500ms past shutdown.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = conn_cancel.cancelled() => return Err("visitor shutting down".into()),
        }
    }
}

/// Go frp v0.71 `keepTunnelOpenWorker`: keep a live session punched in the
/// background. FIRST action is a BLOCKING startTunnelCh send (initial
/// punch); then every `min_retry_interval` seconds probe the session via
/// `get_tunnel_conn` — a healthy session yields a probe stream that is
/// closed immediately; a failure waits on the retry limiter (token bucket:
/// `max_retries_an_hour` per hour) before the next tick.
async fn keep_tunnel_open_worker(
    cfg: XtcpPunchConfig,
    slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: mpsc::Sender<()>,
    armed: &AtomicBool,
    cancel: CancellationToken,
    min_retry_interval: i64,
    max_retries_an_hour: i32,
) {
    // FIRST action: blocking send (Go: `sv.startTunnelCh <- struct{}{}`).
    // UNGATED on purpose: Go's initial send blocks until received; the
    // cap-1 buffer absorbs it if the receiver has not parked yet (the gate
    // covers only non-blocking sends — same net effect).
    tokio::select! {
        _ = start_tx.send(()) => {}
        _ = cancel.cancelled() => return,
    }
    // Token bucket: burst = max_retries_an_hour, one token per
    // (3600 / max_retries_an_hour) seconds (Go
    // rate.NewLimiter(rate.Every(Hour/MaxRetriesAnHour), MaxRetriesAnHour)).
    // The limiter starts full (Go rate.NewLimiter initial burst).
    let burst = max_retries_an_hour.max(1) as usize;
    let refill_secs = (3600.0 / max_retries_an_hour.max(1) as f64).max(1.0);
    let mut tokens = burst;
    let mut ticker = tokio::time::interval(Duration::from_secs(min_retry_interval.max(1) as u64));
    // Consume the immediate first tick: the initial punch above already
    // covers the first check (Go's ticker also fires after one interval).
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {
                // No-tcp-mux raw-KCP sessions are ONE-SHOT: `open_stream`
                // spends the session's only stream, so every probe would
                // force a re-punch churn on the next user connection. Go
                // has no such mode (KCP tunnel is always yamux-wrapped);
                // skip the probe — user connections re-punch on demand.
                let probe_skipped = {
                    let guard = slot.lock().await;
                    guard
                        .as_ref()
                        .map(|s| !s.probe_safe())
                        .unwrap_or(false)
                };
                if probe_skipped {
                    continue;
                }
                // Probe the session: open a stream (bounded — a healthy
                // session answers in milliseconds; 30s covers a
                // dead-but-undetected peer until KCP dead-link trips).
                // On success close the probe stream; on failure rate-limit
                // and continue (Go: retryLimiter.Wait + continue).
                // close_on_timeout=true: this is a liveness check, not a
                // user open — 30s without service is a dead session, and
                // Go's worker closes + re-punches on any probe failure.
                // (Capacity errors — stream cap / request queue — still
                // never close the session: the driver provably lives.)
                match get_tunnel_conn(&slot, &start_tx, armed, Duration::from_secs(30), true)
                    .await
                {
                    Ok(stream) => drop(stream),
                    Err(e) => {
                        warn!(visitor_name = %cfg.visitor_name, error = %e, "Visitor '{}': keepTunnelOpenWorker probe failed, rate-limiting retries", cfg.visitor_name);
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = wait_for_retry_token(&mut tokens, refill_secs) => {}
                        }
                    }
                }
            }
        }
    }
}

/// Wait for the next retry token (token bucket, single consumer — the
/// `keepTunnelOpenWorker`). Consumes one token when the burst is available;
/// otherwise sleeps one refill interval (Go `rate.Limiter.Wait`).
async fn wait_for_retry_token(tokens: &mut usize, refill_secs: f64) {
    if *tokens > 0 {
        *tokens -= 1;
        return;
    }
    tokio::time::sleep(Duration::from_secs_f64(refill_secs)).await;
    // Tokens stay at 0: the sleep IS the refill for this single consumer.
}

/// Runs a bridge future to completion, aborting early when the
/// per-connection cancellation token is cancelled (listener teardown /
/// proxy removal). Without the select, the bridge task holds the UDP fd +
/// KCP session + yamux and a 10ms driver task forever while the peer is
/// alive. Returns true when the bridge completed normally; false when the
/// token was cancelled (callers return and drop the bridge halves).
async fn bridge_until_cancelled(
    visitor_name: &str,
    closed_debug: &str,
    abort_info: &str,
    conn_cancel: &CancellationToken,
    bridge_fut: impl Future,
) -> bool {
    tokio::select! {
        _ = bridge_fut => {
            debug!(visitor_name = %visitor_name, "Visitor '{}' {} closed", visitor_name, closed_debug);
            true
        }
        _ = conn_cancel.cancelled() => {
            info!(visitor_name = %visitor_name, "Visitor '{}': {}", visitor_name, abort_info);
            false
        }
    }
}

/// Discover local non-loopback IPv4 addresses for assisted NAT hole punching.
/// Go frp equivalent: ListLocalIPsForNatHole(10) in pkg/nathole/utils.go:65-93.
/// Filters out IPv6, loopback, link-local unicast, and link-local multicast addresses.
///
/// On Linux, reads /proc/net/fib_trie to enumerate local IPs without requiring
/// external crate dependencies. Falls back to a simpler method if unavailable.
fn list_local_ips() -> Vec<String> {
    // Cache result with 30-second TTL to avoid per-connection
    // filesystem reads (/proc/net/fib_trie) and UDP socket creation.
    static CACHE: std::sync::Mutex<Option<(Vec<String>, Instant)>> = std::sync::Mutex::new(None);
    {
        if let Ok(cache) = CACHE.lock() {
            if let Some((ref ips, ref time)) = *cache {
                if time.elapsed() < std::time::Duration::from_secs(30) {
                    return ips.clone();
                }
            }
        }
    }

    let mut ips = Vec::new();

    // Linux-specific: parse /proc/net/fib_trie for local IPv4 addresses.
    // On non-Linux platforms (macOS, Windows), this path is skipped and we
    // fall through to the UDP connect fallback below, which only discovers
    // the default-route IP. For full multi-homed NAT hole punching on macOS,
    // a getifaddrs-based approach would be needed.
    //
    // Lines like "|-- 192.168.1.100" followed by "/32 host LOCAL" indicate
    // local interface IPs assigned to this machine.
    if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
        let lines: Vec<&str> = content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            // Look for a line containing a dotted IPv4 address
            if trimmed.starts_with("|--") || trimmed.starts_with("+--") {
                if let Some(ip_str) = trimmed
                    .split_whitespace()
                    .find(|s| s.contains('.') && s.parse::<std::net::Ipv4Addr>().is_ok())
                {
                    // Check next non-empty line for /32 host LOCAL marker
                    let is_local = lines
                        .get(i + 1)
                        .or(lines.get(i.wrapping_add(2)))
                        .map(|n| {
                            let n = n.trim();
                            n.contains("/32 host LOCAL") || n.contains("LOCAL")
                        })
                        .unwrap_or(false);
                    if is_local {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            if !ip.is_loopback() && !ip.is_link_local() && !ip.is_multicast() {
                                ips.push(ip.to_string());
                                if ips.len() >= 10 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: try to get the default route interface IP.
    if ips.is_empty() {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            // Connect to 8.8.8.8:53 — no data sent, just triggers the kernel
            // to select the default route interface for us.
            if socket.connect("8.8.8.8:53").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    let ip = local_addr.ip();
                    if ip.is_ipv4() {
                        let ipv4 = match ip {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => unreachable!(),
                        };
                        if !ipv4.is_loopback() && !ipv4.is_link_local() && !ipv4.is_multicast() {
                            ips.push(ipv4.to_string());
                        }
                    }
                }
            }
        }
    }

    // Update cache
    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some((ips.clone(), Instant::now()));
    }

    ips
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    fn make_transport() -> VisitorTransportConfig {
        VisitorTransportConfig {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 30,
            tcp_mux_keepalive_timeout: 0,
            proxy_url: Some("socks5://proxy:1080".into()),
            dns_server: Some("8.8.8.8".into()),
            dial_timeout_secs: 15,
            keepalive_secs: 60,
            connect_bind_addr: Some("10.0.0.1".into()),
            disable_custom_tls_first_byte: true,
            tls_cert_file: Some("/path/cert.pem".into()),
            tls_key_file: Some("/path/key.pem".into()),
            v2: true,
        }
    }

    /// When tcp_mux=true, plan_visitor_dial sets yamux_keepalive_secs
    /// to the configured keepalive interval and populates proxy_url
    /// into the DialOptions.
    #[test]
    fn plan_with_tcp_mux_yields_yamux_and_proxy() {
        let transport = make_transport();
        let plan = plan_visitor_dial(
            "frps.example.com",
            7443,
            &TransportProtocol::Tcp,
            true,
            "frps.example.com",
            &Some("/etc/ca.pem".into()),
            &transport,
        );

        // Yamux decision
        assert_eq!(
            plan.yamux_keepalive_secs,
            Some(30),
            "tcp_mux=true must request yamux wrapping with keepalive 30"
        );

        // Key transport fields in DialOptions
        assert_eq!(plan.opts.server_addr, "frps.example.com");
        assert_eq!(plan.opts.server_port, 7443);
        assert_eq!(plan.opts.proxy_url.as_deref(), Some("socks5://proxy:1080"));
        assert_eq!(plan.opts.dns_server.as_deref(), Some("8.8.8.8"));
        assert_eq!(plan.opts.dial_timeout_secs, 15);
        assert_eq!(plan.opts.keepalive_secs, 60);
        assert_eq!(plan.opts.bind_addr.as_deref(), Some("10.0.0.1"));
        assert!(plan.opts.disable_custom_tls_first_byte);
        assert_eq!(plan.opts.tls_cert_file.as_deref(), Some("/path/cert.pem"));
        assert_eq!(plan.opts.tls_key_file.as_deref(), Some("/path/key.pem"));
        assert!(plan.opts.v2);
        assert!(plan.opts.tls_enable);
        assert_eq!(plan.opts.tls_ca_file.as_deref(), Some("/etc/ca.pem"));
    }

    /// When tcp_mux=false, plan_visitor_dial returns no yamux keepalive
    /// and still propagates all other transport fields.
    #[test]
    fn plan_without_tcp_mux_omits_yamux() {
        let mut transport = make_transport();
        transport.tcp_mux = false;
        let plan = plan_visitor_dial(
            "frps.example.com",
            7000,
            &TransportProtocol::Tcp,
            false,
            "",
            &None,
            &transport,
        );

        assert_eq!(plan.yamux_keepalive_secs, None);
        // Proxy and other fields still flow through even without yamux
        assert_eq!(plan.opts.proxy_url.as_deref(), Some("socks5://proxy:1080"));
        assert_eq!(plan.opts.dial_timeout_secs, 15);
        assert!(plan.opts.v2);
    }

    /// Building a VisitorTransportConfig inline (the pattern used by
    /// run_visitor_listener) and passing it to plan_visitor_dial preserves
    /// all fields through to the DialOptions.
    #[test]
    fn inline_transport_to_dial_options_round_trip() {
        let transport = VisitorTransportConfig {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 45,
            tcp_mux_keepalive_timeout: 0,
            proxy_url: Some("http://p:8080".into()),
            dns_server: Some("1.1.1.1".into()),
            dial_timeout_secs: 25,
            keepalive_secs: 90,
            connect_bind_addr: Some("192.168.0.1".into()),
            disable_custom_tls_first_byte: false,
            tls_cert_file: Some("/c.pem".into()),
            tls_key_file: Some("/k.pem".into()),
            v2: false,
        };
        let plan = plan_visitor_dial(
            "frps.example.com",
            7443,
            &TransportProtocol::Tcp,
            false,
            "",
            &None,
            &transport,
        );

        assert_eq!(plan.yamux_keepalive_secs, Some(45));
        assert_eq!(plan.opts.proxy_url.as_deref(), Some("http://p:8080"));
        assert_eq!(plan.opts.dns_server.as_deref(), Some("1.1.1.1"));
        assert_eq!(plan.opts.dial_timeout_secs, 25);
        assert_eq!(plan.opts.keepalive_secs, 90);
        assert_eq!(plan.opts.bind_addr.as_deref(), Some("192.168.0.1"));
        assert!(!plan.opts.disable_custom_tls_first_byte);
        assert_eq!(plan.opts.tls_cert_file.as_deref(), Some("/c.pem"));
        assert_eq!(plan.opts.tls_key_file.as_deref(), Some("/k.pem"));
        assert!(!plan.opts.v2);
    }
}

#[cfg(all(test, feature = "kcp"))]
mod tunnel_session_tests {
    use super::*;

    /// Hole-punch two loopback UDP sockets into a yamux session pair
    /// (Rust↔Rust "frp" magic, no sid/key — same pattern as
    /// frp-core/tests/xtcp_p2p.rs). Returns (server/provider, client/visitor)
    /// sessions; both drivers run in the background.
    async fn loopback_session_pair() -> (Arc<TunnelSession>, Arc<TunnelSession>) {
        let sock_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let cand_b = vec![addr_b.to_string()];
        let cand_a = vec![addr_a.to_string()];
        let kcp_cfg = frp_core::kcp::default_kcp_config();
        let conv = 42u32;
        let (server, client) = tokio::join!(
            frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
                sock_a,
                &cand_b,
                &[],
                None,
                conv,
                kcp_cfg.clone(),
                3000,
                false, // yamux_client = false (provider)
                None,
                None,
            ),
            frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
                sock_b,
                &cand_a,
                &[],
                None,
                conv,
                kcp_cfg,
                3000,
                true, // yamux_client = visitor
                None,
                None,
            ),
        );
        let server = server.expect("server-side session");
        let client = client.expect("client-side session");
        (
            Arc::new(TunnelSession::Kcp(server)),
            Arc::new(TunnelSession::Kcp(client)),
        )
    }

    /// get_tunnel_conn on an empty slot fails immediately AND signals a
    /// re-punch (Go getTunnelConn sends the non-blocking startTunnelCh signal
    /// on every error path, empty slot included — with keep_tunnel_open=false
    /// the first user connection's failure is what triggers the initial
    /// punch). armed=true + cap-1 channel: try_send always succeeds,
    /// making the "signal is sent" assertion deterministic.
    #[tokio::test]
    async fn get_tunnel_conn_empty_slot_signals_repunch() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let err =
            get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100), false).await;
        match err {
            Err(e) => assert!(
                e.contains("no tunnel session"),
                "error must mention no tunnel session, got: {e}"
            ),
            Ok(_) => panic!("empty slot must error"),
        }
        assert!(
            start_rx.try_recv().is_ok(),
            "empty slot must signal a re-punch"
        );
    }

    /// get_tunnel_conn on an empty slot with the parked-gate DOWN (receiver
    /// busy punching) drops the signal — Go unbuffered startTunnelCh: a send
    /// only succeeds while the receiver is parked in select.
    #[tokio::test]
    async fn get_tunnel_conn_empty_slot_armed_false_drops_signal() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(false);
        let err =
            get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100), false).await;
        match err {
            Err(e) => assert!(
                e.contains("no tunnel session"),
                "error must mention no tunnel session, got: {e}"
            ),
            Ok(_) => panic!("empty slot must error"),
        }
        // Parked recv: nothing may arrive (armed=false dropped the signal).
        let recv_task = tokio::spawn(async move { start_rx.recv().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), recv_task)
                .await
                .is_err(),
            "armed=false must drop the re-punch signal"
        );
    }

    /// get_tunnel_conn on a dead session: errors, clears the slot, and
    /// signals startTunnelCh (triggering a re-punch). Every error path
    /// signals — a second call on the cleared slot errors AND re-signals
    /// (Go: getTunnelConn sends the non-blocking startTunnelCh on any error;
    /// in production the armed gate drops it unless the receiver is parked,
    /// so there is no pile-up).
    #[tokio::test]
    async fn get_tunnel_conn_dead_session_clears_slot_and_signals_repunch() {
        let (_server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);

        // Close the session → open_stream fails (alive=false).
        client.close().await;
        let err =
            get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100), false).await;
        assert!(err.is_err(), "closed session must fail open_stream");
        assert!(slot.lock().await.is_none(), "dead session must be cleared");
        assert!(
            start_rx.try_recv().is_ok(),
            "clearing the slot must signal a re-punch"
        );
        // Second call: slot is empty → error, but STILL signals (Go: every
        // error path sends the non-blocking signal; the armed gate only drops
        // it when the receiver is not parked).
        let err =
            get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100), false).await;
        assert!(err.is_err());
        assert!(
            start_rx.try_recv().is_ok(),
            "empty slot must still signal a re-punch"
        );
    }

    /// get_tunnel_conn on a live session opens a stream without touching the
    /// slot or signalling a re-punch.
    #[tokio::test]
    async fn get_tunnel_conn_live_session_opens_stream() {
        let (server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);

        // Provider side accepts (the driver pushes the stream into the
        // inbound queue; accept completes the yamux open).
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                server
                    .accept_stream(Duration::from_secs(3))
                    .await
                    .expect("provider accept_stream")
            }
        });
        let stream = get_tunnel_conn(
            &slot,
            &start_tx,
            &armed,
            Duration::from_secs(3),
            false, // probe timeout = busy session, not dead
        )
        .await
        .expect("live session must open a stream");
        let _accepted = accept_task.await.expect("accept task");

        assert!(
            slot.lock().await.is_some(),
            "live session stays in the slot"
        );
        assert!(
            start_rx.try_recv().is_err(),
            "successful open must not signal a re-punch"
        );
        drop(stream); // closes the probe stream
        assert!(client.is_alive(), "session survives a stream close");
    }

    /// The driver refuses an open at the 256-stream cap with a PER-OPEN
    /// error while the session stays healthy — `get_tunnel_conn` must treat
    /// that as "session busy", never "session dead": with
    /// close_on_timeout=true (keepalive probe) the round-10 HIGH behavior
    /// would close the session and kill every in-flight bridge on a healthy
    /// session. The same session must serve the next open once capacity
    /// frees.
    #[tokio::test]
    async fn get_tunnel_conn_cap_reached_is_busy_not_dead() {
        let (_server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let _ = start_rx.try_recv(); // drain any initial signal

        // Fill the session to the driver's outbound cap (MAX_TUNNEL_STREAMS
        // = 256). Opens complete client-side (the driver emits the SYN
        // eagerly), so no accept loop is needed.
        let mut held: Vec<Box<dyn frp_core::xtcp_p2p::P2pStream>> = Vec::new();
        for i in 0..256 {
            match client.open_stream(Duration::from_secs(2)).await {
                Ok(s) => held.push(s),
                Err(e) => panic!("open {i} within the cap must succeed, got: {e}"),
            }
        }
        let cap_err = match client.open_stream(Duration::from_secs(2)).await {
            Ok(_) => panic!("open beyond the cap must be refused"),
            Err(e) => e,
        };
        assert!(
            cap_err.contains("yamux tunnel stream cap reached"),
            "got: {cap_err}"
        );

        // close_on_timeout=true (keepalive-probe semantics): a capacity
        // error is busy, NOT dead — the session survives and nothing is
        // signalled.
        let err = match get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(200), true)
            .await
        {
            Ok(_) => panic!("cap-reached probe must be busy"),
            Err(e) => e,
        };
        assert!(err.contains("tunnel session busy"), "got: {err}");
        assert!(
            slot.lock()
                .await
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &client)),
            "session must survive a cap-reached probe"
        );
        assert!(
            start_rx.try_recv().is_err(),
            "no re-punch signal for a live session"
        );
        assert!(client.is_alive(), "session alive");

        // close_on_timeout=false (open_tunnel semantics): same.
        let err = match get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(200), false)
            .await
        {
            Ok(_) => panic!("cap-reached probe must be busy"),
            Err(e) => e,
        };
        assert!(err.contains("tunnel session busy"), "got: {err}");
        assert!(
            slot.lock()
                .await
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &client)),
            "session must survive a cap-reached probe"
        );
        assert!(start_rx.try_recv().is_err());

        // Capacity frees (handles dropped) → the SAME session serves the
        // next open: it was never dead.
        drop(held);
        let stream = client
            .open_stream(Duration::from_secs(2))
            .await
            .expect("session recovers once capacity frees");
        drop(stream);
        assert!(client.is_alive(), "session alive after recovery");
    }

    /// Error-string taxonomy: what counts as "session alive but busy" vs
    /// "session dead", and the provably-alive capacity subclass that never
    /// closes a session regardless of the caller's flag.
    #[test]
    fn busy_error_classification() {
        // Capacity errors: the driver served the refusal — session alive.
        assert!(is_busy_open_error("yamux tunnel stream cap reached (256)"));
        assert!(is_busy_open_error(
            "tunnel session open queue full (peer stalled?)"
        ));
        assert!(is_session_capacity_error(
            "yamux tunnel stream cap reached (256)"
        ));
        assert!(is_session_capacity_error(
            "tunnel session open queue full (peer stalled?)"
        ));
        // Open timeout: ambiguous (alive-but-stalled vs dead-but-undetected).
        assert!(is_busy_open_error("timeout opening tunnel stream (500ms)"));
        assert!(!is_session_capacity_error(
            "timeout opening tunnel stream (500ms)"
        ));
        // Genuine errors: the session is dead — close + re-punch.
        assert!(!is_busy_open_error("no tunnel session"));
        assert!(!is_busy_open_error(
            "tunnel session closed while opening stream"
        ));
        assert!(!is_busy_open_error("quic open stream: connection closed"));
        assert!(!is_busy_open_error("yamux open stream: connection reset"));
        assert!(!is_busy_open_error(""));
    }

    /// open_tunnel polls (every 500ms) until a session appears in the slot;
    /// the budget bounds the wait.
    #[tokio::test]
    async fn open_tunnel_polls_until_session_appears() {
        let (server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, _start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let conn_cancel = CancellationToken::new();

        // Populate the slot + start accepting after 300ms — the first probe
        // fails, later ones succeed.
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                server
                    .accept_stream(Duration::from_secs(3))
                    .await
                    .expect("provider accept_stream")
            }
        });
        tokio::spawn({
            let slot = slot.clone();
            let client = client.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                *slot.lock().await = Some(client);
            }
        });
        let stream = open_tunnel(
            "t",
            &slot,
            &start_tx,
            &armed,
            &conn_cancel,
            Duration::from_secs(5),
        )
        .await
        .expect("open_tunnel must poll until the session appears");
        let _accepted = accept_task.await.expect("accept task");
        drop(stream);
    }

    /// open_tunnel gives up once the budget is exhausted.
    #[tokio::test]
    async fn open_tunnel_times_out_without_session() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, _start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let conn_cancel = CancellationToken::new();
        let start = std::time::Instant::now();
        let result = open_tunnel(
            "t",
            &slot,
            &start_tx,
            &armed,
            &conn_cancel,
            Duration::from_millis(150),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("empty slot with a tiny budget must time out"),
        };
        assert!(
            err.contains("timeout"),
            "error must mention the timeout, got: {err}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timeout must respect the budget (elapsed {:?})",
            start.elapsed()
        );
    }

    /// open_tunnel aborts on cancellation even with a budget left.
    #[tokio::test]
    async fn open_tunnel_aborts_on_cancellation() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, _start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let conn_cancel = CancellationToken::new();
        let task = tokio::spawn({
            let slot = slot.clone();
            let start_tx = start_tx.clone();
            let conn_cancel = conn_cancel.clone();
            async move {
                open_tunnel(
                    "t",
                    &slot,
                    &start_tx,
                    &armed,
                    &conn_cancel,
                    Duration::from_secs(30),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn_cancel.cancel();
        let result = task.await.expect("open_tunnel task");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("cancelled wait must error"),
        };
        assert!(err.contains("shutting down"), "got: {err}");
    }

    /// keepTunnelOpenWorker's FIRST action is a blocking startTunnelCh send
    /// (the initial punch signal), even with an empty slot.
    #[tokio::test]
    async fn keep_tunnel_open_worker_sends_initial_punch_signal() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let (vtx, _vtx_rx) = mpsc::channel::<crate::service::VisitorRequest>(1);
        let cfg = XtcpPunchConfig {
            visitor_name: "t".into(),
            sn: "tunnel".into(),
            sk: String::new(),
            stun_server: String::new(),
            pp: "kcp".into(),
            daa: true,
            vtx,
            cancel: CancellationToken::new(),
            #[cfg(all(feature = "quic", feature = "kcp"))]
            quic_params: frp_core::quic::QuicTransportParams::default(),
        };
        let cancel = CancellationToken::new();
        let armed = AtomicBool::new(true);
        let worker = tokio::spawn({
            let cfg = cfg.clone();
            let slot = slot.clone();
            let start_tx = start_tx.clone();
            let cancel = cancel.clone();
            async move {
                keep_tunnel_open_worker(cfg, slot, start_tx, &armed, cancel, 1, 8).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(3), start_rx.recv())
            .await
            .expect("initial punch signal must be sent")
            .expect("channel open");
        cancel.cancel();
        let _ = worker.await;
    }

    /// keepTunnelOpenWorker probes the session every min_retry_interval; a
    /// dead session fails the probe, gets cleared, and re-signals
    /// startTunnelCh.
    #[tokio::test]
    async fn keep_tunnel_open_worker_probes_and_resignals_on_dead_session() {
        let (_server, client) = loopback_session_pair().await;
        client.close().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let (vtx, _vtx_rx) = mpsc::channel::<crate::service::VisitorRequest>(1);
        let cfg = XtcpPunchConfig {
            visitor_name: "t".into(),
            sn: "tunnel".into(),
            sk: String::new(),
            stun_server: String::new(),
            pp: "kcp".into(),
            daa: true,
            vtx,
            cancel: CancellationToken::new(),
            #[cfg(all(feature = "quic", feature = "kcp"))]
            quic_params: frp_core::quic::QuicTransportParams::default(),
        };
        let cancel = CancellationToken::new();
        let armed = AtomicBool::new(true);
        let worker = tokio::spawn({
            let slot = slot.clone();
            let start_tx = start_tx.clone();
            let cancel = cancel.clone();
            async move {
                keep_tunnel_open_worker(cfg, slot, start_tx, &armed, cancel, 1, 8).await;
            }
        });
        // Initial punch signal (first action).
        tokio::time::timeout(Duration::from_secs(3), start_rx.recv())
            .await
            .expect("initial punch signal")
            .expect("channel open");
        // The first tick (1s) probes the dead session → cleared + re-signal.
        tokio::time::timeout(Duration::from_secs(5), start_rx.recv())
            .await
            .expect("re-punch signal after dead probe")
            .expect("channel open");
        assert!(slot.lock().await.is_none(), "dead session must be cleared");
        cancel.cancel();
        let _ = worker.await;
    }

    /// The retry token bucket: burst tokens are consumed without waiting; an
    /// exhausted bucket sleeps one refill interval.
    #[tokio::test]
    async fn retry_token_bucket_limits_consecutive_failures() {
        let mut tokens = 2usize;
        let start = tokio::time::Instant::now();
        wait_for_retry_token(&mut tokens, 10.0).await;
        wait_for_retry_token(&mut tokens, 10.0).await;
        assert_eq!(tokens, 0);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "burst tokens must not sleep (elapsed {:?})",
            start.elapsed()
        );
        // Exhausted bucket sleeps one refill interval.
        let start = tokio::time::Instant::now();
        wait_for_retry_token(&mut tokens, 0.05).await;
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "exhausted bucket must sleep the refill interval (elapsed {:?})",
            start.elapsed()
        );
    }

    /// `do_hole_punch`'s pre_check stage distinguishes a *closed* control-loop
    /// channel from a *backlogged* one, and aborts on listener teardown instead
    /// of riding out the 5s pre_check timeout. Every e2e lane drives a live,
    /// draining control loop, so none of these three arms has another lane.
    /// Nothing here touches the network: all three return before STUN.
    #[tokio::test]
    async fn do_hole_punch_precheck_channel_and_cancel_arms() {
        async fn punch_err(cfg: &XtcpPunchConfig) -> String {
            match do_hole_punch(cfg).await {
                Ok(_) => panic!("expected do_hole_punch to fail"),
                Err(e) => e,
            }
        }

        fn punch_cfg(
            vtx: mpsc::Sender<crate::service::VisitorRequest>,
            cancel: CancellationToken,
        ) -> XtcpPunchConfig {
            XtcpPunchConfig {
                visitor_name: "t".into(),
                sn: "tunnel".into(),
                sk: String::new(),
                stun_server: String::new(),
                pp: "kcp".into(),
                daa: true,
                vtx,
                cancel,
                #[cfg(all(feature = "quic", feature = "kcp"))]
                quic_params: frp_core::quic::QuicTransportParams::default(),
            }
        }

        fn filler() -> crate::service::VisitorRequest {
            let (reply, _reply_rx) = oneshot::channel();
            crate::service::VisitorRequest {
                nhv: msg::NatHoleVisitor {
                    transaction_id: "x".into(),
                    proxy_name: "x".into(),
                    pre_check: true,
                    protocol: None,
                    sign_key: None,
                    timestamp: None,
                    mapped_addrs: None,
                    assisted_addrs: None,
                },
                reply,
            }
        }

        // (a) control loop gone: the channel is closed.
        let (vtx, rx) = mpsc::channel::<crate::service::VisitorRequest>(1);
        drop(rx);
        let err = punch_err(&punch_cfg(vtx, CancellationToken::new())).await;
        assert!(err.contains("channel closed"), "got: {err}");

        // (b) control loop alive but not draining: the capacity-1 channel is
        //     already full, so try_send errors while is_closed() stays false.
        let (vtx, _held) = mpsc::channel::<crate::service::VisitorRequest>(1);
        vtx.clone()
            .try_send(filler())
            .expect("capacity-1 channel accepts the first request");
        let err = punch_err(&punch_cfg(vtx, CancellationToken::new())).await;
        assert!(err.contains("backlogged"), "got: {err}");

        // (c) listener teardown while pre_check is in flight: the cancel arm
        //     wins over the 5s timeout, so this returns promptly.
        let (vtx, _held) = mpsc::channel::<crate::service::VisitorRequest>(1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let start = std::time::Instant::now();
        let err = punch_err(&punch_cfg(vtx, cancel)).await;
        assert!(err.contains("pre_check cancelled"), "got: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "cancel must short-circuit the 5s pre_check timeout (elapsed {:?})",
            start.elapsed()
        );
    }
}

#[cfg(test)]
mod bridge_cancel_tests {
    use super::*;

    /// The shared bridge-until-cancelled helper (used by the XTCP P2P and
    /// STCP relay sites) must abort when the per-connection cancellation
    /// token is cancelled (listener teardown / proxy removal). Without the
    /// select, the bridge task holds the UDP fd + KCP session + yamux and a
    /// 10ms driver task forever while the peer is alive. Two duplex pairs
    /// stand in for the user connection and the peer stream; bridge_plain
    /// would block on reads indefinitely, so only the cancellation arm can
    /// resolve the select.
    #[tokio::test]
    async fn p2p_bridge_cancels_on_token_cancel() {
        let (user_a, _user_b) = tokio::io::duplex(8192);
        let (p2p_a, _p2p_b) = tokio::io::duplex(8192);
        let (user_r, user_w) = tokio::io::split(user_a);
        let (p2p_r, p2p_w) = tokio::io::split(p2p_a);
        let conn_cancel = CancellationToken::new();
        let bridge_cancel = conn_cancel.clone();

        let bridge_task = tokio::spawn(async move {
            // Production bridge site: exercises the same select path the
            // XTCP P2P / STCP relay sites use.
            bridge_until_cancelled(
                "test",
                "XTCP",
                "shutting down, aborting XTCP P2P bridge",
                &bridge_cancel,
                frp_core::bridge::bridge_plain(user_r, user_w, p2p_r, p2p_w, false, vec![], None),
            )
            .await;
        });

        conn_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), bridge_task)
            .await
            .expect("bridge must abort when the connection token is cancelled")
            .expect("bridge task must not panic");
    }
}
