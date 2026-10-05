use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio_util::sync::CancellationToken;

/// Internal request from a visitor task to the control loop.
/// Visitor sends NatHoleVisitor on the control connection (Go frps compat:
/// fresh TCP connections with NatHoleVisitor are not handled by Go frps v0.69.1).
/// The oneshot delivers the server's NatHoleResp back to the waiting visitor.
pub(crate) struct VisitorRequest {
    pub nhv: msg::NatHoleVisitor,
    pub reply: oneshot::Sender<Result<msg::NatHoleResp, String>>,
}

/// Event from a health check task to the control loop.
/// Close: the proxy exceeded max failures and should be closed on the server.
/// Recover: the proxy recovered and should be re-registered.
#[derive(Debug, Clone)]
pub(crate) enum HealthEvent {
    Close(String),   // proxy_name
    Recover(String), // proxy_name
}
use rand::RngExt;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{debug, info, instrument, warn};

use frp_core::auth::{AuthConfig, AuthMethod, OidcClient};
use frp_core::config::ClientConfig;
use frp_core::init_error::ConstructError;
use frp_core::unsafe_features::UnsafeFeatures;

use frp_core::encryption;
use frp_core::msg::{self, ClientSpec, FrpMessage};
use frp_core::protocol::{read_msg, write_msg};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{IoStream, TransportProtocol};

use frp_core::metrics::ProxyMetricsRegistry;

#[cfg(feature = "admin")]
use crate::admin::AdminState;
use crate::control::ControlConnection;
use crate::plugin::{self, PluginContext, PluginHandle};
use crate::proxy::wire_proxy_name;
use crate::proxy_runtime::{ProxyPhase, ProxyRuntimeInfo, ReloadRequest};
use crate::store::{merge_client_config, StoreSource};
use crate::util::opt_if_empty;

/// Serializes control-message writes onto a single dedicated writer task.
///
/// Producers call [`ControlWriter::send`] — a `try_send` on a bounded
/// channel that never blocks, so a slow peer (TCP backpressure) cannot
/// stall the control loop or any sub-task behind a `Mutex<BoxedWriteHalf>`
/// (audit v0.70.1 P1-A1). The writer task owns the raw write half
/// exclusively and writes FIFO; on a write error it marks the writer failed
/// and wakes the control loop, which tears the connection down and
/// reconnects. A full channel drops the message (bounded, Go frp parity:
/// "when full, drop").
#[derive(Clone)]
pub(crate) struct ControlWriter {
    tx: tokio::sync::mpsc::Sender<(FrpMessage, bool)>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    notify: std::sync::Arc<tokio::sync::Notify>,
}

impl ControlWriter {
    /// Try to enqueue `msg` for the writer task. Never blocks. Returns an
    /// error when the writer has failed, the channel is full (peer slow) or
    /// the connection is being torn down.
    pub(crate) fn send(&self, msg: FrpMessage, v2: bool) -> Result<(), String> {
        if self.failed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("control writer failed".to_string());
        }
        self.tx.try_send((msg, v2)).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                "control channel full (peer slow)".to_string()
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                "control channel closed".to_string()
            }
        })
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.failed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until the writer task reports a failure. Re-checks the flag
    /// after every wake so a notification cannot be lost.
    pub(crate) async fn wait_failed(&self) {
        loop {
            if self.is_failed() {
                return;
            }
            self.notify.notified().await;
        }
    }
}

impl frp_core::ControlSink for ControlWriter {
    fn send_msg(&self, msg: FrpMessage, v2: bool) -> Result<(), String> {
        self.send(msg, v2)
    }

    fn is_failed(&self) -> bool {
        ControlWriter::is_failed(self)
    }
}
#[cfg(feature = "vnet")]
use crate::vnet::{
    add_os_route, advertise_vnet_visitor_route, local_vnet_set, remove_os_route, remove_vnet_tun,
    send_vnet_route_advertise, spawn_vnet_tun_controller, virtual_net_visitor_route_adv,
    vnet_proxy_snapshot, vnet_tun_params, VnetPeerRoute, VnetTunCancelMap, VnetTunMap,
    VnetTunSubnetMap, VnetTunTxMap,
};
use crate::work_conn::XtcpNotification;

/// Go frp v0.70.1 visitor plugin type for virtual-net host routes.
pub(crate) const VISITOR_PLUGIN_VIRTUAL_NET: &str = "virtual_net";

// Read an env-overridable millisecond duration knob (used by the
// integration tests to shrink the 30s wall-clock cadence) and clamp it to
// >= 1ms. A 0ms override must degrade rather than panic — tokio::time::interval
// panics on a zero period, and a zero timeout makes every registration
// response time out instantly, turning frpc into a 1k msg/s NewProxy flood
// against its server (the LOW finding that prompted this helper).
fn env_duration_ms(var: &str, default: Duration) -> Duration {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .map(|d| d.max(Duration::from_millis(1)))
        .unwrap_or(default)
}

/// Go frp v0.71.0 parity gate for health monitoring.
///
/// Go `client/proxy/proxy_wrapper.go` NewWrapper arms the health monitor —
/// and sets `health = 1` so registration waits for the first healthy probe —
/// only when `HealthCheck.Type != "" && LocalPort > 0`. Plugin proxies carry
/// `local_port == 0` (their real listener is the plugin socket on
/// 127.0.0.1), so a health config on them is inert: the proxy is never
/// monitored, registers immediately like a non-health proxy, and no probe
/// is ever aimed at a plugin listener that does not speak the probe
/// protocol (a plain-HTTP GET against a socks5 listener, for instance,
/// could never succeed — wedging the proxy unregistered forever).
fn health_check_monitored(p: &frp_core::config::ProxyConfig) -> bool {
    !p.health_check_type.is_empty() && p.local_port > 0
}

/// Bounds each registration-response read in the registration phase.
///
/// A server that accepts Login but never answers NewProxy (stays connected,
/// stays silent) must not block the client forever. Go frp bounds each
/// proxy's response wait with `startErrTimeout` (10s) in its own goroutine
/// and tolerates slow registration — this is the frp-rs equivalent with
/// headroom for N pipelined requests and the `remote_addr` round-trip. On
/// timeout the pending proxies are marked StartErr and the message loop's
/// retry re-registers them; the session itself is NOT torn down.
pub(crate) static REGISTRATION_RESPONSE_TIMEOUT: LazyLock<Duration> = LazyLock::new(|| {
    env_duration_ms(
        "FRP_REGISTRATION_RESPONSE_TIMEOUT_MS",
        Duration::from_secs(30),
    )
});

/// StartErr retry cadence for the message-loop retry arm: re-register
/// proxies stuck in StartErr (anchored on the last StartErr time — Go frp's
/// `lastStartErr.Add(startErrTimeout)`, so a proxy that errors right after a
/// tick is not re-sent until a full interval has elapsed since ITS error).
/// Matches Go frp's proxy_wrapper.checkWorker (default startErrTimeout 30s).
/// The WaitStart-stuck re-send uses its own cadence,
/// [`WAIT_START_RETRY_TIMEOUT`] (Go's waitResponseTimeout, 20s) — see the
/// retry arm.
pub(crate) static PROXY_RETRY_INTERVAL: LazyLock<Duration> =
    LazyLock::new(|| env_duration_ms("FRP_PROXY_RETRY_INTERVAL_MS", Duration::from_secs(30)));

/// WaitStart-stuck re-send timeout for the message-loop retry arm: how long
/// a proxy may sit in WaitStart (a NewProxy that is never answered — a
/// silent server that still Pongs) before its NewProxy is re-sent. Go frp
/// parity: client/proxy/proxy_wrapper.go `waitResponseTimeout` (20s) —
/// distinct from `startErrTimeout` (30s, [`PROXY_RETRY_INTERVAL`]) used for
/// StartErr retries.
pub(crate) static WAIT_START_RETRY_TIMEOUT: LazyLock<Duration> =
    LazyLock::new(|| env_duration_ms("FRP_WAIT_START_RETRY_TIMEOUT_MS", Duration::from_secs(20)));

/// Tolerance for the WaitStart-stuck check in the retry arm. The stuck
/// elapsed time compares two wall-clock `Instant`s (first-seen vs tick), so
/// it can measure a hair under one full interval and a retry would slip to
/// the next tick. The grace only ever advances a retry by at most one tick.
const PROXY_RETRY_GRACE: Duration = Duration::from_millis(100);

/// Finished STUN discovery result, handed from the off-loop STUN task back
/// to the control loop so the NatHoleClient write + pending_xtcp bookkeeping
/// stay on the loop (preserving the write-before-NatHoleResp ordering).
struct StunResult {
    sid: String,
    proxy_name: String,
    msg: FrpMessage,
}

/// How the message loop exited. `Shutdown` when a stop was requested (admin
/// API or signal — the session must not reconnect); `Reconnect` when the
/// session died and run() should tear down and reconnect.
enum LoopExit {
    Shutdown,
    Reconnect,
}

/// The session-agnostic inputs to the message loop, created once in run()
/// and outliving sessions. Held by `&mut` borrow (not owned) because run()
/// needs `stop_rx` and `health_cancels` again after the loop returns — the
/// reconnect-backoff race and teardown both use them.
struct SessionChannels<'a> {
    /// Health-check results from the spawned health check tasks.
    health_rx: &'a mut mpsc::Receiver<HealthEvent>,
    /// Reload requests from the admin API (config hot-reload).
    reload_rx: &'a mut mpsc::Receiver<ReloadRequest>,
    /// XTCP STUN results from the off-loop STUN discovery tasks.
    xtcp_rx: &'a mut mpsc::Receiver<XtcpNotification>,
    /// New-visitor requests from spawned visitor listeners (STCP/XTCP).
    visitor_rx: &'a mut mpsc::Receiver<VisitorRequest>,
    /// Stop request from the admin API / signal handler.
    stop_rx: &'a mut mpsc::Receiver<()>,
    /// Cancellation flags for health check tasks, shared with teardown.
    health_cancels: &'a Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    /// STUN server address used for XTCP hole punching.
    nat_hole_stun_server: &'a str,
}

/// Per-session state shared across the login → registration → message-loop
/// phases of one connection attempt. Created on successful login, dropped on
/// teardown. Holds exactly the locals that used to live inline in run().
///
/// `control_stream` is `Option` because phase 5 splits it (`into_split`)
/// into the writer task's halves; every use before that point unwraps it.
struct SessionCtx {
    /// Control connection stream, AES-128-CFB-wrapped, yamux-unwrapped.
    /// `None` after phase 5 splits it into reader/writer halves.
    control_stream: Option<IoStream>,
    /// Server-assigned run_id for this session (Go frp compat: previousRunID
    /// carries over to the next attempt via run()).
    run_id: String,
    /// Yamux session handle. Held so the previous session's handle can be
    /// dropped before creating a new connection (Go frp compat: svr.ctl.Close()).
    yamux: Option<std::sync::Arc<frp_core::mux::YamuxSession>>,
    /// Protocol version negotiated for this session (V1 vs V2).
    v2: bool,
    /// QUIC connection handle, forwarded to work-conn configs.
    #[cfg(feature = "quic")]
    quic_conn: Option<std::sync::Arc<QuicConnection>>,
    /// Heartbeat ping interval, armed at login. None disables heartbeats.
    ping_interval: Option<tokio::time::Interval>,
    /// Delay for the next heartbeat attempt after a ping whose auth setup
    /// failed (OIDC token fetch / token source). None = no consecutive
    /// failure in flight and the ping runs on the normal interval cadence.
    /// When set, the ping arm re-arms `ping_interval` via
    /// `Interval::reset_after(delay)` so the retry fires on Go frp's
    /// exponential backoff schedule instead of the next interval tick
    /// (client/control.go heartbeatWorker → wait.BackoffUntil). Cleared by
    /// the next non-skipped ping attempt.
    ping_retry_backoff: Option<Duration>,
    /// Last Pong receive time; the watchdog fires if no Pong arrives within
    /// heartbeat_timeout (also bounds the registration phase).
    last_pong: Instant,
    /// Configured heartbeat timeout in seconds (raw config value).
    hb_timeout: i64,
    /// heartbeat_timeout as a Duration (clamped at 0).
    hb_timeout_dur: Duration,
    /// Whether the heartbeat watchdog is armed (interval > 0 && timeout > 0).
    hb_watchdog_active: bool,
    /// Shared session-alive flag for spawned work-conn tasks.
    session_alive: Arc<AtomicBool>,
    // --- Work-conn config snapshot fields ---
    wc_server_addr: String,
    wc_server_port: u16,
    wc_tls_enable: bool,
    wc_tls_server_name: String,
    wc_tls_ca_file: Option<String>,
    wc_tls_cert_file: Option<String>,
    wc_tls_key_file: Option<String>,
    wc_dns_server: Option<String>,
    wc_udp_packet_size: usize,
    /// Negotiated UDPPacket codec (`"binary-v1"` or empty; Go frp v0.71.0).
    /// Snapshot from the V2 ServerHello handshake, forwarded to UDP/SUDP
    /// work-conn bridges.
    wc_udp_packet_codec: String,
    wc_disable_custom_tls_first_byte: bool,
    wc_keepalive_secs: u64,
    wc_bind_addr: Option<String>,
    wc_proxy_url: String,
    wc_dial_timeout_secs: u64,
    /// Transport protocol for work connections (snapshot of cfg_local.protocol).
    protocol: TransportProtocol,
    /// Client-declared additional auth scopes, for heartbeat auth decisions.
    client_scopes: Vec<String>,
    /// Server-advertised auth scopes, for heartbeat auth decisions.
    server_scopes: Vec<String>,
    /// Per-session shutdown flag; set only when a stop was requested (the
    /// stop_rx arm in the message loop, or the reconnect backoff race), read
    /// at teardown. Never set on error/reconnect exits.
    shutdown_flag: Arc<AtomicBool>,
    /// Session start time, used to reset the backoff counter when a session
    /// runs healthily for a long time (Go frp's FastBackoffManager only
    /// counts consecutive failures).
    session_started_at: Instant,
    // --- Registration bookkeeping (phase 4) ---
    /// Wire proxy names of proxies whose NewProxy was written but whose
    /// NewProxyResp has not arrived yet, paired with their index in the
    /// active-proxies snapshot.
    pending_proxies: Vec<(String, usize)>,
    /// Same for visitors whose NewVisitorConn has not been acked yet.
    pending_visitors: Vec<(String, usize)>,
    /// Set when a NewProxy/NewVisitorConn write failed — the stream state
    /// is undefined, so the registration response phase is skipped entirely.
    write_failed: bool,
    /// False until the first NewProxyResp / NewVisitorConnResp / visitor-ack
    /// ReqWorkConn has been handled. The server's pool pre-warm
    /// ReqWorkConns always precede every registration response on the wire,
    /// so anonymous ReqWorkConns received before this point can never be
    /// visitor acks.
    seen_registration_response: bool,
    /// Anonymous ReqWorkConns consumed so far — bounds the pool pre-warm
    /// when no proxy registration exists to mark its end.
    req_work_conns_seen: usize,
    // --- Control writer (phase 5) ---
    /// Control writer handle (bounded channel + dedicated writer task),
    /// used by the message loop and teardown. `None` only before phase 5
    /// creates it.
    writer: Option<Arc<ControlWriter>>,
    /// Receiver half of the control channel — moved into the writer task
    /// when it is spawned.
    control_rx: Option<tokio::sync::mpsc::Receiver<(FrpMessage, bool)>>,
    /// Writer-failure flag shared with `ControlWriter`.
    control_failed: Option<Arc<AtomicBool>>,
    /// Wakeup used by the writer task to notify the control loop of a
    /// write failure.
    control_notify: Option<Arc<tokio::sync::Notify>>,
    /// Read half of the split control stream, owned by the message loop.
    /// `None` before phase 5 splits it; the message loop takes it out.
    reader: Option<frp_core::transport::BoxedReadHalf>,
    /// Shared graceful shutdown signal for all visitor listener tasks.
    /// Set to true at session end so tasks exit cleanly.
    visitor_shutdown: Option<Arc<AtomicBool>>,
    /// Join handles of the current session's visitor listener tasks,
    /// cancelled at teardown.
    visitor_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Join handles of the current session's work-conn tasks, aborted at
    /// teardown. Standalone work conns (tcp/ws/kcp/quic-direct dial) own
    /// their own connection to the server and would otherwise keep bridging
    /// until a socket error, outliving the session (HIGH leak on reconnect
    /// churn). Mux-bound tasks would die with the yamux session, but
    /// aborting them is an ordinary stream close and releases their session
    /// Arc clones — one mechanism for both.
    work_conn_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Join handle of the dedicated control writer task (phase 5). Aborted
    /// at teardown AFTER the vnet route-removal sends (which ride the writer
    /// channel) and the yamux/socket drop. On tcp_mux=false the raw write
    /// half lives only inside this task: against a wedged-but-alive peer
    /// (zero-window TCP that ACKs keepalive/window probes, or no-mux KCP
    /// with no dead-conn detection) `write_msg` blocks forever, and without
    /// the abort teardown cannot close the socket — one task+fd leaked per
    /// reconnect cycle.
    control_writer_handle: Option<tokio::task::JoinHandle<()>>,
    // --- Message loop (phase 6) ---
    /// Map sid -> proxy_name for XTCP NatHoleResp routing (provider side).
    pending_xtcp: std::collections::HashMap<String, String>,
    /// Map sid -> STUN UDP socket for XTCP P2P hole punching.
    xtcp_sockets: std::sync::Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
        >,
    >,
    /// Map sid -> oneshot sender for visitor NatHoleResp routing (Go frps compat).
    visitor_pending:
        std::collections::HashMap<String, oneshot::Sender<Result<msg::NatHoleResp, String>>>,
    /// Finished STUN results handed back to the control loop (off-loop STUN
    /// discovery), created in the message loop.
    stun_result_tx: Option<mpsc::Sender<StunResult>>,
    stun_result_rx: Option<mpsc::Receiver<StunResult>>,
    /// Stale XTCP entry reclaim channel (created in the message loop).
    xtcp_cleanup_rx: Option<mpsc::Receiver<String>>,
    /// 30s proxy retry interval; armed in the message loop (first tick
    /// skipped so the first retry happens a full interval after login).
    proxy_retry_interval: Option<tokio::time::Interval>,
    /// When each proxy last entered WaitStart (initial registration or a
    /// retry send). A proxy whose NewProxy is never answered (a silent
    /// server that still Pongs) stays in WaitStart forever — the StartErr
    /// transition happens only on a NewProxyResp error — so the retry arm
    /// tracks this to re-send after one full interval (Go frp parity:
    /// proxy_wrapper re-arms startErrTimeout while in waitStart and
    /// retries indefinitely). Pruned when the proxy leaves WaitStart.
    waitstart_seen: HashMap<String, Instant>,
    /// Copy of the client user name for the retry arm — the cfg snapshot
    /// read guard is dropped before the message loop starts.
    cfg_user: String,
}

/// The main frpc service.
pub struct Service {
    pub(crate) cfg: Arc<RwLock<ClientConfig>>,
    proxies: Arc<RwLock<Arc<Vec<frp_core::config::ProxyConfig>>>>,
    /// Optional file-backed store shared with the admin API.
    store_source: Option<Arc<StoreSource>>,
    pub(crate) auth_cfg: Arc<AuthConfig>,
    encryption_key: [u8; 16],
    /// Map proxy_name -> runtime info for looking up where to connect
    pub(crate) proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    /// Plugin handles keyed by proxy name. Drop removes the plugin task.
    plugin_handles: Arc<std::sync::Mutex<HashMap<String, PluginHandle>>>,
    /// OIDC client for fetching access tokens (None when auth method is Token).
    pub(crate) oidc_client: Option<Arc<OidcClient>>,
    /// Server-side auth scopes from LoginResp, used for Ping/NewWorkConn gating.
    server_auth_scopes: tokio::sync::RwLock<Vec<String>>,
    /// Per-proxy traffic metrics for admin API.
    proxy_metrics: Arc<ProxyMetricsRegistry>,
    /// Path to config file for admin reload/config endpoints.
    config_file: Option<String>,
    /// Channel to trigger config reload from external signal (SIGUSR1).
    reload_tx: mpsc::Sender<ReloadRequest>,
    /// Receiver side of reload channel — consumed by run().
    reload_rx: std::sync::Mutex<Option<mpsc::Receiver<ReloadRequest>>>,
    /// Channel to trigger graceful shutdown from external signal (SIGTERM)
    /// or the admin API. The receiver is consumed by run().
    stop_tx: mpsc::Sender<()>,
    /// Receiver side of stop channel — consumed by run().
    stop_rx: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
    /// STUN server address for XTCP NAT traversal.
    nat_hole_stun_server: String,
    /// Channel from work connection tasks to the control loop for XTCP (provider side).
    xtcp_tx: mpsc::Sender<XtcpNotification>,
    /// Receiver side of XTCP channel — consumed by run().
    xtcp_rx: std::sync::Mutex<Option<mpsc::Receiver<XtcpNotification>>>,
    /// Channel from visitor tasks to the control loop (Go frps compat:
    /// NatHoleVisitor is sent on the control connection, not fresh TCP).
    visitor_tx: mpsc::Sender<VisitorRequest>,
    /// Receiver side of visitor channel — consumed by run().
    visitor_rx: std::sync::Mutex<Option<mpsc::Receiver<VisitorRequest>>>,
    /// Set when a reload changed visitors; the session loop restarts so the
    /// new visitor set is fully rebuilt (visitors are session-scoped).
    visitor_reload_needed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Per-proxy health check cancel flags. Keyed by the WIRE proxy name
    /// ({user}.{name}) — the same key spawn_health_checks inserts with and
    /// the CloseProxy handler looks up. Set to true on CloseProxy/CloseProxyResp;
    /// entry removed in try_reload.
    health_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    /// Monotonic control-session generation for health monitors (H2): bumped
    /// once per successful login; monitors re-arm to the pristine
    /// "unregistered" state on change so a healthy proxy re-registers on the
    /// new session's first probe (Go parity: fresh Monitor per control.Run()).
    health_session_gen: Arc<AtomicU64>,
    /// Per-proxy cancellation tokens for provider-side XTCP P2P bridge tasks.
    /// Keyed by the WIRE proxy name ({user}.{name}) like health_cancels.
    /// Lazily created at the nat_hole call sites; cancelled on CloseProxy and
    /// reload removal so a deleted proxy aborts in-flight hole punches and
    /// closes active P2P bridges (else the bridge task + UDP fd + KCP + yamux
    /// leak until the peer closes).
    p2p_bridge_tokens: Arc<Mutex<HashMap<String, CancellationToken>>>,
    /// Proxy configs for health-checked proxies, used to re-register on health
    /// recovery. Keyed by the WIRE proxy name ({user}.{name}) — the same key
    /// Service::new populates with and the Recover handler looks up.
    health_proxy_configs: Arc<Mutex<HashMap<String, frp_core::config::ProxyConfig>>>,
    /// Channel sender for health check events (Close/Recover). Cloned by try_reload()
    /// to spawn health checks for new/changed proxies after reload.
    health_tx: mpsc::Sender<HealthEvent>,
    /// Receiver side of health channel — consumed by run().
    health_rx: std::sync::Mutex<Option<mpsc::Receiver<HealthEvent>>>,
    /// Shared TUN devices for vnet proxies, keyed by proxy name.
    /// Work connection tasks take ownership of the TUN device via Option::take().
    #[cfg(feature = "vnet")]
    pub(crate) vnet_tuns: VnetTunMap,
    /// Shared client-side vnet controller: routing table used by TUN-backed
    /// VnetControllers (TX direction) plus virtual_net visitor tunnel
    /// delivery channels (RX direction).
    #[cfg(feature = "vnet")]
    vnet_controller: Arc<frp_vnet::controller::ClientVnetController>,
    /// Per-proxy TX channels for forwarding received VnetPackets to TUN devices.
    /// Keyed by proxy name. Elements are `Arc<[u8]>` so a fan-out shares one
    /// packet buffer by refcount instead of copying per peer.
    #[cfg(feature = "vnet")]
    vnet_tun_tx: VnetTunTxMap,
    /// Per-proxy cancellation senders for running vnet controllers.
    #[cfg(feature = "vnet")]
    vnet_tun_cancels: VnetTunCancelMap,
    /// Per-proxy TUN device names for OS route injection.
    #[cfg(feature = "vnet")]
    pub(crate) vnet_tun_names: Arc<Mutex<HashMap<String, String>>>,
    /// Per-proxy subnet for directing virtual_net visitor return traffic.
    /// Registered precompiled (see `vnet_tun_subnets` insert at
    /// `open_vnet_tun_for_proxy`) so the per-packet fan-out never parses a CIDR.
    #[cfg(feature = "vnet")]
    pub(crate) vnet_tun_subnets: VnetTunSubnetMap,
    /// Peer proxy name → (advertised subnet, TUN interface, virtual net) for
    /// OS routes injected from VnetRouteAdvertise. The vnet is stored so route
    /// table entries can be removed in the right partition on VnetRouteRemove
    /// and on control disconnect.
    #[cfg(feature = "vnet")]
    vnet_peer_routes: Arc<Mutex<HashMap<String, VnetPeerRoute>>>,
}

/// The delay the heartbeat loop re-arms to after the **first** consecutive
/// auth-skipped ping: Go frp v0.71.0 doubles `InitDurationIfFail` even on the
/// first consecutive error (`wait.FastBackoffOptions{InitDurationIfFail: 1s,
/// Factor: 2}`, so 1s × 2), which is the delay [`next_ping_backoff`] returns
/// for `prev == None`.
///
/// This constant is the **single source of truth** for that value, and the
/// re-arm oracle asserts the observed wall-clock gap against *it* rather than
/// against a hand-written window: `heartbeat_ping_backoff_progression` in this
/// file compares [`next_ping_backoff`] to it, and the end-to-end test
/// `skipped_ping_rearms_interval_on_two_second_backoff` in
/// `frp-client/tests/heartbeat_wire_order.rs` derives its tolerance from it, so
/// a wrong-but-in-range backoff hard-coded at the `interval.reset_after(delay)`
/// call site (5s satisfied the old `[1.0s, 6.0s]` window) now reds the e2e test
/// (TODO.md:9475). A duplicated literal in either place is what this constant
/// exists to prevent.
pub const PING_FIRST_BACKOFF: Duration = Duration::from_secs(2);

/// Delay before the next heartbeat attempt after a consecutive
/// auth-skipped ping, mirroring the Go frp v0.71.0 client heartbeat
/// backoff exactly (client/control.go heartbeatWorker runs sendHeartBeat
/// through wait.BackoffUntil with wait.FastBackoffOptions{
/// InitDurationIfFail: 1s, Factor: 2, MaxDuration: heartbeat interval,
/// Jitter: 0.1} — pkg/util/wait/backoff.go). Go's manager doubles
/// InitDurationIfFail too (fastBackoffImpl: on the FIRST consecutive
/// error, duration = InitDurationIfFail, then `duration * Factor`), so
/// the retry sequence is [`PING_FIRST_BACKOFF`], 4s, 8s, … capped at the
/// heartbeat interval — a long outage still probes at most every interval
/// after reaching the cap. The 0.1 jitter is skipped (wire-invisible, and
/// it exists only to desynchronize independent Go processes).
///
/// `prev` is the previous consecutive failure's delay; None means the
/// last attempt succeeded (or no failure has happened yet) and this is
/// the first failure of a streak.
fn next_ping_backoff(prev: Option<Duration>, interval: Duration) -> Duration {
    let next = match prev {
        // First failure: InitDurationIfFail(1s) × Factor(2).
        None => PING_FIRST_BACKOFF,
        Some(prev) => prev.saturating_mul(2),
    };
    next.min(interval)
}

/// Refuse an `auth.method = "oidc"` client configuration when this crate was
/// compiled without the `oidc` feature. Always defined, so a caller does not
/// need its own `#[cfg]`. In an oidc build it is **not** fully a no-op: it still
/// applies the shared exact-method parse (so `"OIDC"` is refused here too) and
/// only the `"oidc"` arm is compiled away.
///
/// Shared by [`Service::with_unsafe_features`] (so `frpc run` refuses) and by
/// `frpc verify`, which only *loads* the config — without this, `verify` would
/// print `frpc: the configuration file … syntax is ok` and exit 0 for a config
/// that `run` exits 3 on.
///
/// The method match is `frp_core::auth`'s exact policy, not a local
/// `== "oidc"`: the string comparison this replaced accepted every non-exact
/// spelling as if it were token auth, which in an oidc-less build meant
/// `method = "OIDC"` started a **token** client against a server that (at the
/// pre-change head) lowercased the same spelling into OIDC. It now returns the
/// shared parse error for any unrecognised spelling, and the feature error for
/// exactly `"oidc"`. In an oidc build the construction parse below in
/// [`Service::with_unsafe_features`] raises both errors too, so this helper's
/// own answer is not the only gate there — but the two must not disagree, which
/// is why both call the same function rather than each spelling their own match.
pub fn refuse_oidc_method_without_feature(
    auth: Option<&frp_core::config::AuthClientConfig>,
) -> Result<(), String> {
    let Some(ac) = auth else {
        return Ok(());
    };
    let method = frp_core::auth::parse_auth_method(&ac.method)?;
    if method == AuthMethod::Oidc {
        #[cfg(not(feature = "oidc"))]
        {
            return Err(frp_core::auth::OIDC_FEATURE_REQUIRED.to_string());
        }
    }
    Ok(())
}

impl Service {
    /// Wait briefly for visitor listener tasks to exit gracefully, then
    /// force-abort any still blocked in `accept()` so their listeners drop
    /// and the bind ports are released immediately. Without the abort, an
    /// idle visitor listener (no inbound traffic) never wakes from `accept()`,
    /// the dropped `JoinHandle` does NOT cancel the task, and the next
    /// session's `bind()` fails with AddrInUse — permanently killing the
    /// visitor (STCP/XTCP) until frpc restarts.
    async fn shutdown_visitor_tasks(&self, mut handles: Vec<tokio::task::JoinHandle<()>>) {
        // &mut JoinHandle implements Future (tokio); &JoinHandle does not.
        let graceful = tokio::time::timeout(
            Duration::from_millis(500),
            futures_util::future::join_all(handles.iter_mut()),
        )
        .await;
        if graceful.is_err() {
            tracing::warn!(
                count = handles.len(),
                "Visitor shutdown timed out after 500ms; aborting stuck listener task(s) to release bind ports"
            );
            // Snapshot completion BEFORE the aborts and skip the handles that
            // are already finished. The invariant this preserves: **each handle
            // is awaited at most once, and `is_finished()` is true exactly for
            // the handles whose output `join_all` already took.** Two measured
            // facts make it the fix:
            //
            // 1. A `JoinHandle` may be polled to `Ready` only once, and
            //    `join_all` above polls every handle. The handles whose task
            //    already finished have had their output taken and now sit at
            //    `Stage::Consumed` (`store_output` puts `Stage::Finished` there,
            //    `take_output` replaces it with `Stage::Consumed`), so awaiting
            //    them again hits `take_output`'s
            //    `_ => panic!("JoinHandle polled after completion")`
            //    (tokio-1.53.1/src/runtime/task/core.rs:427). That is the
            //    SIGTERM crash: with N >= 2 visitors sharing one `bind_port`
            //    the losers' `TcpListener::bind` fails and their task returns
            //    at once, so `join_all` completes their handles while the
            //    winner stays parked in `accept()` past the 500ms grace.
            // 2. A finished task has already dropped its future, so skipping it
            //    releases nothing that this abort path exists to release. The
            //    future is dropped by `store_output` on normal completion
            //    (harness.rs:549 -> core.rs:434, where `set_stage`'s assignment
            //    drops the replaced `Stage::Running(future)`) or by
            //    `drop_future_or_output` on cancellation (harness.rs:503 ->
            //    core.rs:399), and the COMPLETE bit `is_finished` reads
            //    (join.rs:258 -> state.rs:599) is set afterwards by
            //    `transition_to_complete` (harness.rs:334). The listener socket
            //    is therefore already closed when `is_finished()` turns true.
            //    `service::tests::shutdown_visitor_tasks_releases_listeners`
            //    measures both halves of that: a finished task's port is
            //    bindable again while its handle is still un-awaited, and a
            //    parked listener's port is released by the abort+await below.
            //
            // Snapshotting before `abort()` keeps the skip set to handles that
            // were already complete when the grace window expired, so every
            // handle this branch aborts is still awaited exactly once. The
            // 500ms grace is unchanged — skipping a finished handle can only
            // make shutdown return no later than before. Observability is
            // unchanged too: this branch already discarded join results
            // (`let _ = h.await`), and a task's panic is reported by the panic
            // hook when it happens, so a panicking finished visitor is no more
            // hidden by the skip than by the await it replaces.
            let already_finished: Vec<bool> = handles.iter().map(|h| h.is_finished()).collect();
            for h in &handles {
                h.abort();
            }
            for (h, was_finished) in handles.into_iter().zip(already_finished) {
                if was_finished {
                    continue;
                }
                let _ = h.await;
            }
        }
    }

    /// Create a new client Service with default unsafe features (all blocked).
    pub async fn new(
        cfg: ClientConfig,
        config_file: Option<String>,
    ) -> Result<Self, ConstructError> {
        Self::with_unsafe_features(cfg, config_file, UnsafeFeatures::default()).await
    }

    /// Create a new client Service with a custom unsafe features allowlist.
    ///
    /// The error is a [`ConstructError`], whose [`ConstructError::kind`] is the
    /// *only* thing the daemons turn into a process exit code (they never look
    /// at the message). See `frp-core/src/init_error.rs` for why.
    pub async fn with_unsafe_features(
        mut cfg: ClientConfig,
        config_file: Option<String>,
        unsafe_features: UnsafeFeatures,
    ) -> Result<Self, ConstructError> {
        // Load the file-backed store when [store] path is set and overlay its
        // proxies/visitors on the config file entries (Go frp v0.70.1 store
        // source semantics).
        //
        // The only non-auth construction failure reachable here, so it takes
        // the `From<String>` default (`InitErrorKind::Other`); it must not be
        // tagged `Auth` — the failure class is "the store file cannot be read
        // or parsed", whatever the path happens to be spelled.
        let store_source = if let Some(ref store_cfg) = cfg.store {
            if store_cfg.path.is_empty() {
                None
            } else {
                Some(Arc::new(StoreSource::new(&store_cfg.path).map_err(
                    |e| format!("failed to load store from {}: {e}", store_cfg.path),
                )?))
            }
        } else {
            None
        };
        if let Some(ref store) = store_source {
            let merged = merge_client_config(&cfg, Some(store));
            cfg.proxies = merged.proxies;
            cfg.visitors = merged.visitors;
            info!(
                path = %store.path().display(),
                proxies = %cfg.proxies.len(),
                visitors = %cfg.visitors.len(),
                "store enabled: {} proxies, {} visitors after merge",
                cfg.proxies.len(),
                cfg.visitors.len()
            );
        }
        // Filter out disabled entries from the config source before running.
        // Go frp source.Load() treats enabled=false as source-local filtering.
        cfg.proxies.retain(|p| p.enabled);
        cfg.visitors.retain(|v| v.enabled);
        // Go frp FilterClientConfigurers applies `start` to visitors too, so
        // visitors outside the allowlist must not register or start.
        cfg.visitors = filter_active_visitors(&cfg, &cfg.visitors);

        // Refuse an `auth.method = "oidc"` config when this crate was built
        // without the `oidc` feature — otherwise it would silently fall through to
        // token auth below. `frpc verify` calls the same helper, so it cannot
        // report valid a config `frpc run` refuses. No-op in an oidc build.
        refuse_oidc_method_without_feature(cfg.auth.as_ref()).map_err(ConstructError::auth)?;

        // Determine auth method from [auth] section if present, otherwise token.
        // The parse is the one `frp_core::auth` policy, called unconditionally
        // (not only under `#[cfg(feature = "oidc")]`): `refuse_oidc_method_without_feature`
        // above runs the same function, so an unrecognised spelling is already
        // refused there and this call is the construction-time backstop for a
        // `ClientConfig` built without going through the loader. The old code
        // read `ac.method == "oidc"` inside the oidc-on arm and a bare
        // `AuthMethod::Token` in the oidc-off arm, so `method = "OIDC"` selected
        // **token** on both sides — against a server that (at the pre-change
        // head) lowercased it into OIDC.
        let auth_method = match &cfg.auth {
            Some(ac) => {
                frp_core::auth::parse_auth_method(&ac.method).map_err(ConstructError::auth)?
            }
            None => AuthMethod::Token,
        };

        let auth_token_source = cfg.auth.as_ref().and_then(|a| a.token_source.clone());
        // Every failure below is an *auth* construction failure and is tagged as
        // one here, at the raise site — the messages happen to contain "auth"
        // today, but the tag does not depend on that.
        let token = if let Some(ref source) = auth_token_source {
            source
                .validate()
                .map_err(|e| ConstructError::auth(format!("invalid auth.tokenSource: {e}")))?;
            frp_core::auth::validate_token_source_unsafe(source, &unsafe_features)
                .map_err(ConstructError::auth)?;
            source.resolve().map_err(|e| {
                ConstructError::auth(format!("failed to resolve auth.tokenSource: {e}"))
            })?
        } else {
            // Go frp v0.70.1: a token-source resolution failure is a startup
            // error — no silent empty-token fallback (an empty token on both
            // sides would silently degrade auth to no-auth).
            frp_core::auth::resolve_dynamic_token_checked(&cfg.token, &unsafe_features)
                .map_err(|e| ConstructError::auth(format!("failed to resolve auth token: {e}")))?
        };
        let auth_cfg = AuthConfig {
            method: auth_method.clone(),
            token,
            // Deliberately NOT the source again: `token` above is this
            // service's resolved snapshot, and Go frp resolves a
            // `tokenSource` exactly once, at client-service construction
            // (`client/service.go:168 auth.BuildClientAuth`), then hands the
            // same cached auth runtime to every login/reconnect
            // (`client/service.go:316`; `pkg/auth/token.go` SetLogin/SetPing/
            // SetNewWorkConn only call `util.GetAuthKey(auth.token, ts)`).
            // Carrying the source here made `AuthConfig::resolve_token()`
            // re-execute it a second time on the first login (and on every
            // later Ping/NewWorkConn), which is the divergence this
            // construction-time snapshot closes. The server keeps its live
            // source (frp-server/src/service.rs build_auth_config) so a
            // server-side refresh still re-reads per verification.
            token_source: None,
            oidc_issuer: cfg
                .auth
                .as_ref()
                .map(|a| a.oidc_issuer.clone())
                .unwrap_or_default(),
            oidc_audience: cfg
                .auth
                .as_ref()
                .map(|a| a.oidc_audience.clone())
                .unwrap_or_default(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_skip_nbf: false,
            oidc_skip_audience: false,
            oidc_additional_audience: Vec::new(),
            oidc_tls_trusted_ca_file: String::new(),
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0, // client side doesn't validate timestamps
            token_auth_timeout: true,
            use_encryption: false,
        };

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);

        // Create OIDC client if auth method is OIDC
        #[cfg(feature = "oidc")]
        let oidc_client = if auth_method == AuthMethod::Oidc {
            let ac = cfg.auth.as_ref().ok_or_else(|| {
                ConstructError::auth("OIDC auth requires [auth] section in config")
            })?;
            // Go frp v0.70.1 compat: auth.oidc.tokenSource (dynamic token
            // source, mutually exclusive with the client-credentials flow).
            // The config validator enforces mutual exclusivity; exec sources
            // additionally require the unsafe-features gate like auth.tokenSource.
            let token_source = ac.oidc_token_source.clone();
            if let Some(ref source) = token_source {
                frp_core::auth::validate_token_source_unsafe(source, &unsafe_features)
                    .map_err(ConstructError::auth)?;
            }
            let client = OidcClient::new(
                ac.oidc_client_id.clone(),
                ac.oidc_client_secret.clone(),
                ac.oidc_audience.clone(),
                Some(ac.oidc_token_endpoint.clone()).filter(|s| !s.is_empty()),
                ac.oidc_scope.clone(),
                Some(ac.oidc_issuer.clone()).filter(|s| !s.is_empty()),
                &ac.additional_endpoint_params,
                Some(ac.oidc_tls_trusted_ca_file.clone()).filter(|s| !s.is_empty()),
                ac.oidc_tls_insecure_skip_verify,
                Some(ac.oidc_proxy_url.clone()).filter(|s| !s.is_empty()),
                token_source,
            )
            .await
            .map_err(|e| ConstructError::auth(format!("OIDC client init failed: {e}")))?;
            info!(endpoint = %client.token_endpoint(), "OIDC client initialized, token endpoint: {}", client.token_endpoint());
            Some(Arc::new(client))
        } else {
            None
        };
        #[cfg(not(feature = "oidc"))]
        let oidc_client: Option<Arc<OidcClient>> = None;

        // Start plugins for proxies that have them configured.
        let mut plugin_handles_map: HashMap<String, PluginHandle> = HashMap::new();
        let mut plugin_addrs: HashMap<String, String> = HashMap::new();

        // Register a successfully started plugin.
        fn record_plugin(
            plugin_type: &str,
            proxy_name: &str,
            result: Result<PluginHandle, frp_core::Error>,
            addrs: &mut HashMap<String, String>,
            handles: &mut HashMap<String, PluginHandle>,
        ) {
            match result {
                Ok(handle) => {
                    let addr = handle.local_addr.to_string();
                    info!(plugin_type = %plugin_type, proxy_name = %proxy_name, addr = %addr, "{plugin_type} plugin for '{proxy_name}' started on {addr}");
                    addrs.insert(proxy_name.to_string(), addr);
                    handles.insert(proxy_name.to_string(), handle);
                }
                Err(e) => {
                    warn!(plugin_type = %plugin_type, proxy_name = %proxy_name, error = %e, "Failed to start {plugin_type} plugin for '{proxy_name}': {e}");
                }
            }
        }

        for p in &cfg.proxies {
            if let Some(ref plugin_cfg) = p.plugin {
                // virtual_net is not a local-listener plugin; work connections
                // are handed to the shared vnet controller in work_conn.rs.
                if plugin_cfg.plugin_type == "virtual_net" {
                    continue;
                }
                let result = if plugin_cfg.plugin_type == "tls2raw" {
                    // Propagate proxy-level proxyProtocolVersion into the
                    // plugin config so the tls2raw handler can read+strip
                    // the proxy protocol header from the tunnel stream
                    // and write it to the local raw TCP before TLS.
                    let mut effective = plugin_cfg.clone();
                    if effective.proxy_protocol_version.is_empty()
                        && !p.proxy_protocol_version.is_empty()
                    {
                        effective.proxy_protocol_version = p.proxy_protocol_version.clone();
                    }
                    plugin::start_tls2raw_plugin(&effective).await
                } else if plugin_cfg.plugin_type == "visitor_plugin" {
                    let plugin_ctx = PluginContext {
                        server_addr: cfg.server_addr.clone(),
                        server_port: cfg.server_port,
                        transport_protocol: cfg.transport_protocol.clone(),
                        tls_enable: cfg.tls_enable,
                        tls_server_name: cfg.tls_server_name.clone(),
                        tls_ca_file: opt_if_empty!(cfg.tls_ca_file),
                        use_encryption: p.use_encryption,
                        use_compression: p.use_compression,
                        token: auth_cfg.token.clone(),
                        oidc_client: oidc_client.clone(),
                        tcp_mux: cfg.tcp_mux,
                        tcp_mux_keepalive_interval: cfg.tcp_mux_keepalive_interval,
                        tcp_mux_keepalive_timeout: cfg.tcp_mux_keepalive_timeout,
                        proxy_url: opt_if_empty!(cfg.proxy_url.clone()),
                        dns_server: opt_if_empty!(cfg.dns_server.clone()),
                        dial_timeout_secs: cfg.dial_server_timeout.max(1) as u64,
                        keepalive_secs: cfg.dial_server_keepalive.max(0) as u64,
                        connect_bind_addr: opt_if_empty!(cfg.connect_server_local_ip.clone()),
                        disable_custom_tls_first_byte: cfg.disable_custom_tls_first_byte,
                        tls_cert_file: opt_if_empty!(cfg.tls_cert_file.clone()),
                        tls_key_file: opt_if_empty!(cfg.tls_key_file.clone()),
                        v2: cfg.v2,
                    };
                    plugin::dispatch_plugin_start(plugin_cfg, Some(plugin_ctx)).await
                } else {
                    plugin::dispatch_plugin_start(plugin_cfg, None).await
                };
                record_plugin(
                    &plugin_cfg.plugin_type,
                    &p.name,
                    result,
                    &mut plugin_addrs,
                    &mut plugin_handles_map,
                );
            }
        }

        // NOTE: Duplicate proxy/visitor names are caught at config parse time
        // by validate_no_duplicate_names(). No runtime dedup needed.
        let mut map: HashMap<String, ProxyRuntimeInfo> = HashMap::new();
        for p in &cfg.proxies {
            let bw_limit = frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
            // Use plugin address if available, otherwise use configured local_ip:local_port
            let local_addr = plugin_addrs
                .get(&p.name)
                .cloned()
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let plugin_type = p
                .plugin
                .as_ref()
                .map(|pl| pl.plugin_type.clone())
                .unwrap_or_default();
            let snapshot = crate::reload::config_snapshot(p);
            let wn = wire_proxy_name(&cfg.user, &p.name);
            map.insert(
                wn.clone(),
                ProxyRuntimeInfo {
                    local_addr,
                    proxy_type: p.proxy_type.clone(),
                    use_encryption: p.use_encryption,
                    use_compression: p.use_compression,
                    sk: p.sk.clone(),
                    bandwidth_limit: bw_limit,
                    bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
                    // Per-proxy SHARED limiter (F1/F2): created once at
                    // registration when the client side owns the limiting
                    // (mode ""/client/both — Go EmptyOr default + client
                    // NewProxy gate). One bucket for both directions and all
                    // concurrent connections; bridges clone this Arc.
                    bandwidth_limiter: frp_core::bandwidth::client_side_limiter(
                        bw_limit,
                        &p.bandwidth_limit_mode,
                    ),
                    proxy_protocol_version: p.proxy_protocol_version.clone(),
                    plugin: plugin_type,
                    remote_addr: String::new(),
                    err: String::new(),
                    config_snapshot: snapshot,
                    phase: ProxyPhase::New,
                },
            );
        }
        let proxy_info_map = Arc::new(RwLock::new(map));

        let (reload_tx, reload_rx) = mpsc::channel::<ReloadRequest>(64);
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);
        let (xtcp_tx, xtcp_rx) = mpsc::channel::<XtcpNotification>(64);
        let (visitor_tx, visitor_rx) = mpsc::channel::<VisitorRequest>(64);
        let (health_tx, health_rx) = mpsc::channel::<HealthEvent>(16);

        let nat_hole_stun_server = if cfg.nat_hole_stun_server.is_empty() {
            // Go frp v0.70.1 default STUN server (no "stun:" URI prefix needed).
            "stun.easyvoip.com:3478".to_string()
        } else {
            cfg.nat_hole_stun_server.clone()
        };

        #[cfg(feature = "vnet")]
        let vnet_tuns = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(feature = "vnet")]
        let vnet_controller = Arc::new(frp_vnet::controller::ClientVnetController::new());
        #[cfg(feature = "vnet")]
        let vnet_tun_tx = Arc::new(std::sync::Mutex::new(HashMap::new()));
        #[cfg(feature = "vnet")]
        let vnet_tun_cancels = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(feature = "vnet")]
        let vnet_tun_names = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(feature = "vnet")]
        let vnet_tun_subnets = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(feature = "vnet")]
        let vnet_peer_routes = Arc::new(Mutex::new(HashMap::new()));

        let health_proxy_configs = Arc::new(Mutex::new(
            cfg.proxies
                .iter()
                .filter(|p| health_check_monitored(p))
                .map(|p| (wire_proxy_name(&cfg.user, &p.name), p.clone()))
                .collect(),
        ));

        let proxies = Arc::new(RwLock::new(Arc::new(cfg.proxies.clone())));

        Ok(Self {
            cfg: Arc::new(RwLock::new(cfg)),
            proxies,
            store_source,
            auth_cfg: Arc::new(auth_cfg),
            encryption_key: enc_key,
            proxy_info_map,
            plugin_handles: Arc::new(std::sync::Mutex::new(plugin_handles_map)),
            oidc_client,
            server_auth_scopes: tokio::sync::RwLock::new(Vec::new()),
            proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
            config_file,
            reload_tx,
            reload_rx: std::sync::Mutex::new(Some(reload_rx)),
            stop_tx,
            stop_rx: std::sync::Mutex::new(Some(stop_rx)),
            nat_hole_stun_server,
            xtcp_tx,
            xtcp_rx: std::sync::Mutex::new(Some(xtcp_rx)),
            visitor_tx,
            visitor_rx: std::sync::Mutex::new(Some(visitor_rx)),
            visitor_reload_needed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            health_cancels: Arc::new(Mutex::new(HashMap::new())),
            health_session_gen: Arc::new(AtomicU64::new(0)),
            p2p_bridge_tokens: Arc::new(Mutex::new(HashMap::new())),
            health_proxy_configs,
            health_tx,
            health_rx: std::sync::Mutex::new(Some(health_rx)),
            #[cfg(feature = "vnet")]
            vnet_tuns,
            #[cfg(feature = "vnet")]
            vnet_controller,
            #[cfg(feature = "vnet")]
            vnet_tun_tx,
            #[cfg(feature = "vnet")]
            vnet_tun_cancels,
            #[cfg(feature = "vnet")]
            vnet_tun_names,
            #[cfg(feature = "vnet")]
            vnet_tun_subnets,
            #[cfg(feature = "vnet")]
            vnet_peer_routes,
        })
    }

    /// Request a graceful shutdown. Safe to call from signal handler.
    /// Returns immediately; the actual shutdown happens asynchronously in run().
    pub fn request_stop(&self) {
        match self.stop_tx.try_send(()) {
            Ok(()) => tracing::info!("Stop requested, initiating graceful shutdown"),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("Stop channel full — a stop request is already queued");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("Stop channel closed — service already shutting down");
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cfg_snapshot = self.cfg.read().await.clone();
        info!(
            version = %frp_core::VERSION, server_addr = %cfg_snapshot.server_addr, server_port = %cfg_snapshot.server_port,
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, cfg_snapshot.server_addr, cfg_snapshot.server_port
        );

        let protocol: TransportProtocol = match cfg_snapshot.transport_protocol.parse() {
            Ok(p) => p,
            Err(_) => {
                return Err(format!(
                    "unknown transport protocol '{}'. Valid transports: tcp, kcp, quic, websocket, wss",
                    cfg_snapshot.transport_protocol
                )
                .into());
            }
        };
        let pool_count = cfg_snapshot.pool_count.max(0);

        // Take the receiver from self (created in constructor, consumed once).
        let mut health_rx = self
            .health_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("health_rx already taken — run() called twice?");

        // Cancellation flags for health check tasks — set to true when a proxy
        // is closed (via CloseProxy from server, admin, or health check failure).
        // Stored on self so try_reload() can cancel health checks for removed proxies.
        let health_cancels = self.health_cancels.clone();

        let all_startup_proxies = Arc::clone(&*self.proxies.read().await);
        let startup_proxies = filter_active_proxies(&cfg_snapshot, &all_startup_proxies);
        self.spawn_health_checks(
            &cfg_snapshot.user,
            &startup_proxies,
            &self.health_tx,
            &health_cancels,
            &self.health_session_gen,
        )
        .await;

        // Start admin HTTP server if configured
        let _reload_tx = self.reload_tx.clone();
        let mut reload_rx = self
            .reload_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("reload_rx already taken — run() called twice?");
        let mut xtcp_rx = self
            .xtcp_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("xtcp_rx already taken — run() called twice?");
        let mut visitor_rx = self
            .visitor_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("visitor_rx already taken — run() called twice?");
        let nat_hole_stun_server = self.nat_hole_stun_server.clone();
        let mut stop_rx = self
            .stop_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("stop_rx already taken — run() called twice?");

        // Handle of the spawned admin HTTP server task; aborted on shutdown
        // (cancel_detached_tasks). Only spawned with the `admin` feature.
        #[cfg(feature = "admin")]
        let mut admin_handle: Option<tokio::task::JoinHandle<()>> =
            self.spawn_admin_server(&_reload_tx, &self.stop_tx).await;
        #[cfg(not(feature = "admin"))]
        let mut admin_handle: Option<tokio::task::JoinHandle<()>> = None;

        // Main session loop with reconnection.
        // Go frp dev two-phase fast-backoff:
        //   Phase 1 (first 3 retries within 60s window): 200ms × full jitter (0.5-1.5)
        //   Phase 2 (after that): 1s × 2ⁿ × full jitter (0.5-1.5), cap 20s
        // Matches Go frp dev wait.FastBackoffManager (full multiplicative
        // jitter replaces the additive jitter so clients restarting together
        // de-synchronize instead of re-clustering in a narrow band).
        let mut did_login_once = false;
        let mut consecutive_err_count: u32 = 0;
        // Last computed reconnect delay — the Go fast-backoff anchors Phase 2
        // to this value (previousDuration) instead of recomputing 1s·2^n.
        let mut previous_delay: std::time::Duration = std::time::Duration::ZERO;
        let mut fast_retry_timestamps: Vec<Instant> = Vec::new();
        // When a session runs healthily for a long time, the consecutive
        // error count is reset so an occasional blip doesn't reconnect with
        // the backoff cap already reached (Go frp's FastBackoffManager only
        // counts consecutive failures).
        // Carry over run_id across reconnections (Go frp compat: previousRunID).
        let mut previous_run_id = String::new();
        // Explicitly hold the previous session's yamux handle so we can drop it
        // before creating a new connection (Go frp compat: svr.ctl.Close()).
        // Dropping the Arc causes the background yamux task to notice the
        // closed sender channel and exit, closing the TCP socket.
        #[cfg(feature = "tcp-mux")]
        let mut prev_yamux: Option<std::sync::Arc<frp_core::mux::YamuxSession>> = None;
        loop {
            // Read guard over the config instead of cloning the whole
            // ClientConfig (all proxies/visitors/strings) per connection
            // attempt. Field reads go through the guard's Deref; the guard
            // The guard is held through ctl.login().await and (on failure)
            // the backoff sleep — 800+ lines and several await points below.
            // This is safe because every cfg writer (try_reload / do_reload)
            // runs in the same task and the message loop's reload arm polls
            // internal_rx, not a blocking lock. An early drop before the
            // backoff sleep would be cleaner but is not reachable without
            // cloning: the guard is needed again below (v2, client_scopes,
            // transport locals, ping interval, heartbeat timeout, cfg_user)
            // after a successful login. The trade-off is accepted.
            let cfg_local = self.cfg.read().await;
            let all_proxies = Arc::clone(&*self.proxies.read().await);
            let proxies = filter_active_proxies(&cfg_local, &all_proxies);

            // Go frp compat (d486018): drop previous yamux session before
            // creating a new control connection. This drops the sender channel,
            // causing the background yamux task to exit and close the TCP socket.
            #[cfg(feature = "tcp-mux")]
            drop(prev_yamux.take());

            // Phases 1-3 (config snapshot, dial + login, encryption wrap,
            // yamux, heartbeat init) live in connect_and_login; it returns
            // the per-session state or the error. Backoff counters stay here.
            let mut ctx = match self
                .connect_and_login(
                    &cfg_local,
                    &protocol,
                    pool_count,
                    previous_run_id.clone(),
                    &mut did_login_once,
                )
                .await
            {
                Ok(ctx) => ctx,
                Err(e) => {
                    consecutive_err_count += 1;
                    warn!(attempt = %consecutive_err_count, error = %e, "Login failed (attempt {}): {}", consecutive_err_count, e);
                    if cfg_local.login_fail_exit && !did_login_once {
                        // Cancel detached health/admin tasks so a caller that
                        // handles the error (e.g. tests) does not keep them
                        // running after run() returns.
                        self.cancel_detached_tasks(&health_cancels, admin_handle)
                            .await;
                        return Err(e.into());
                    }
                    let delay = if did_login_once {
                        // Session reconnect: full fast-backoff with Phase 1 (200ms) + Phase 2 (exponential).
                        fast_retry_timestamps.push(Instant::now());
                        let window_count =
                            crate::backoff::prune_fast_retry_count(&mut fast_retry_timestamps);
                        let d = crate::backoff::fast_backoff_delay(
                            consecutive_err_count,
                            window_count,
                            previous_delay,
                        );
                        previous_delay = d;
                        d
                    } else {
                        // Initial login: pure exponential, no fast retry phase.
                        // Matches Go frp's loopLoginUntilSuccess (FastBackoffOptions
                        // without FastRetryCount, MaxDuration=10s).
                        // Go frp v0.70.1: initial login cap is 10s, reconnection cap is 20s.
                        // See /tmp/frp-source/client/service.go:261,286.
                        let mut delay_ms = 1000u64;
                        for _ in 0..consecutive_err_count {
                            delay_ms = delay_ms.saturating_mul(2).min(10_000);
                        }
                        let jitter_ms =
                            (rand::rng().random::<f64>() * 0.1 * delay_ms as f64) as u64;
                        Duration::from_millis(delay_ms.saturating_add(jitter_ms).min(10_000))
                    };
                    // Race the backoff against a stop request: with
                    // login_fail_exit = false and an unreachable server, the
                    // plain sleep below would hold a buffered admin/signal
                    // stop (cap-1 stop_tx) until a login eventually succeeds —
                    // shutdown would hang indefinitely (Go client/service.go
                    // loopLoginUntilSuccess has no stop path either; this is
                    // client-side robustness beyond parity, same shape as the
                    // reconnect-sleep select below). There is no ctx on the
                    // login-failure path (it is bound only in the Ok arm
                    // above), so this branch only cancels the detached
                    // health/admin tasks and returns.
                    tokio::select! {
                        Some(()) = stop_rx.recv() => {
                            info!("Stop requested while waiting to retry login, shutting down");
                            self.cancel_detached_tasks(&health_cancels, admin_handle).await;
                            return Ok(());
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    continue;
                }
            };

            // Store for explicit cleanup before next reconnect (Go frp compat d486018).
            #[cfg(feature = "tcp-mux")]
            {
                prev_yamux = ctx.yamux.clone();
            }
            previous_run_id = ctx.run_id.clone();

            // Session boundary for the long-lived health monitors (H2): this
            // login started a NEW control session whose server holds no proxy
            // registrations yet. Bump the generation so monitors re-arm and
            // re-register their proxies on the first healthy probe of this
            // session (Go parity: a fresh control.Run() builds a fresh
            // Monitor with statusOK=false). Monitors observe the change on
            // their next tick, so the bump must precede the registration
            // phase — a Recover sent before this point would ride the dead
            // previous session's writer.
            self.health_session_gen.fetch_add(1, Ordering::Relaxed);

            // Phase 4: pipelined NewProxy/NewVisitorConn registration + the
            // registration response read loop (2s visitor grace +
            // REGISTRATION_RESPONSE_TIMEOUT + heartbeat watchdog races), vnet
            // TUN opens, and the StartErr drain — extracted into
            // register_proxies. Returns false when the registration phase
            // aborted (a read error or the heartbeat watchdog fired); the
            // session continuation below is then skipped and the session
            // goes straight to teardown + reconnect.
            let aborted = !self
                .register_proxies(&mut ctx, &cfg_local, &proxies, pool_count)
                .await;

            // Control writes are funneled through a bounded channel to a
            // single dedicated writer task (audit v0.70.1 P1-A1): producers
            // never block on a slow peer, the raw write half is owned by
            // exactly one task, and a write failure wakes the control loop
            // to tear down and reconnect. Created before the guarded session
            // continuation so the teardown below can use `writer` even when
            // the continuation was skipped (registration heartbeat watchdog).
            let (control_tx, control_rx) = tokio::sync::mpsc::channel::<(FrpMessage, bool)>(1024);
            let control_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let control_notify = Arc::new(tokio::sync::Notify::new());
            ctx.writer = Some(Arc::new(ControlWriter {
                tx: control_tx,
                failed: control_failed.clone(),
                notify: control_notify.clone(),
            }));
            ctx.control_rx = Some(control_rx);
            ctx.control_failed = Some(control_failed);
            ctx.control_notify = Some(control_notify);

            // Shared graceful shutdown signal for all visitor listener tasks.
            // Set to true at session end so tasks exit cleanly (Fix 8).
            // Declared here (outside the continuation guard) because the
            // teardown below uses it even when the continuation was skipped.
            ctx.visitor_shutdown = Some(Arc::new(AtomicBool::new(false)));

            // Session continuation: split the stream, spawn the writer task
            // and vnet controllers, spawn visitor listeners, then run the
            // message loop. Skipped when the registration phase aborted (a
            // read error or the heartbeat watchdog fired): the connection is
            // unresponsive, so the session goes straight to teardown +
            // reconnect below — the same path a message-loop heartbeat
            // timeout takes. An aborted session has no spawned visitors or
            // writer task to clean up; the shared teardown below handles
            // both. The loop exit is captured as `Option` so the aborted
            // path (no loop ran) feeds into the same teardown + decision
            // tail as a `LoopExit::Reconnect` exit.
            let exit = if !aborted {
                // Phase 5: split the stream, spawn the writer task and vnet
                // controllers, cancel the previous session's visitor
                // listeners, and spawn the current session's visitors.
                self.spawn_session_tasks(
                    &mut ctx,
                    &cfg_local,
                    &proxies,
                    &protocol,
                    &nat_hole_stun_server,
                )
                .await?;

                // The message loop handles config reloads (try_reload), which
                // take the config write lock — the snapshot read guard must be
                // dropped first. `user` is the only snapshot field the loop
                // still needs; copy it here.
                ctx.cfg_user = cfg_local.user.clone();
                drop(cfg_local);

                // Phase 6: the message loop, until the session ends.
                Some(
                    self.run_message_loop(
                        &mut ctx,
                        &mut SessionChannels {
                            health_rx: &mut health_rx,
                            reload_rx: &mut reload_rx,
                            xtcp_rx: &mut xtcp_rx,
                            visitor_rx: &mut visitor_rx,
                            stop_rx: &mut stop_rx,
                            health_cancels: &health_cancels,
                            nat_hole_stun_server: &nat_hole_stun_server,
                        },
                    )
                    .await,
                )
            } else {
                // Registration aborted (read error or heartbeat watchdog):
                // no writer task or visitors were spawned; `None` means there
                // is no message-loop exit, and the session reconnects exactly
                // as a `Reconnect` exit does.
                None
            };

            // Phase 7: tear down the session exactly once, whether the
            // message loop exited or registration aborted. Returns true only
            // when a stop was requested during the session (shutdown_flag
            // set).
            let stop_requested = self
                .teardown_session(
                    &mut ctx,
                    #[cfg(feature = "tcp-mux")]
                    &mut prev_yamux,
                    &health_cancels,
                    &mut admin_handle,
                )
                .await;

            // Single exit-vs-reconnect decision point. A stop (admin API /
            // signal) always exits — the session must not reconnect. A dead
            // session or aborted registration reconnects with backoff unless
            // the teardown itself found a stop request.
            match exit {
                Some(LoopExit::Shutdown) => return Ok(()),
                Some(LoopExit::Reconnect) | None => {
                    if stop_requested {
                        return Ok(());
                    }
                }
            }

            // Session dropped — reconnect with Go frp dev two-phase fast-backoff.
            // login_fail_exit only applies to initial login, not session drops.
            // Reset the consecutive-error count when the previous session was
            // healthy for ≥5 minutes, so a stable connection followed by an
            // occasional blip reconnects from Phase 1 instead of the 20s cap.
            if healthy_resets_error_count(
                consecutive_err_count,
                Some(ctx.session_started_at),
                Instant::now(),
                Duration::from_secs(300),
            ) {
                consecutive_err_count = 0;
            }
            let delay = crate::backoff::reconnect_delay_after_session(
                &mut consecutive_err_count,
                &mut fast_retry_timestamps,
                previous_delay,
            );
            previous_delay = delay;
            warn!(delay_ms = %delay.as_millis(), attempt = %consecutive_err_count, "Session ended, reconnecting in {}ms (attempt {})...",
                delay.as_millis(), consecutive_err_count);
            // Race the backoff against a stop request: an admin/signal stop
            // must not be held up by up to 20s of reconnect sleep.
            tokio::select! {
                Some(()) = stop_rx.recv() => {
                    info!("Stop requested while waiting to reconnect, shutting down");
                    ctx.shutdown_flag.store(true, Ordering::SeqCst);
                    self.cancel_detached_tasks(&health_cancels, admin_handle).await;
                    return Ok(());
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Phases 1-3 of one connection attempt: snapshot the work-conn config
    /// fields from the current client config, dial + login a new control
    /// connection, wrap the stream in AES-128-CFB, and initialize the
    /// per-session state (yamux handle, heartbeat watchdog, auth scopes,
    /// shutdown flag) that registration and the message loop build on.
    ///
    /// Returns the per-session state on success; on failure returns the
    /// error so run() can apply backoff + reconnect exactly as before.
    /// Backoff counters (consecutive_err_count, fast_retry_timestamps,
    /// previous_run_id) stay in run() scope — `did_login_once` is passed in
    /// so it is set at login success (before the encryption wrap), matching
    /// the previous ordering where a wrap failure still saw did_login_once
    /// already true.
    async fn connect_and_login(
        &self,
        cfg_local: &ClientConfig,
        protocol: &TransportProtocol,
        pool_count: i32,
        previous_run_id: String,
        did_login_once: &mut bool,
    ) -> Result<SessionCtx, frp_core::Error> {
        // Owned copies of the snapshot fields the work-conn config needs.
        // `handle_req_work_conn` (which builds the same config) also runs from
        // the message loop, where the snapshot guard is no longer held, so the
        // fields are stored on SessionCtx instead of read from the guard.
        // Keeps the snapshot semantics (fields fixed at connection start)
        // without cloning the whole ClientConfig.
        let wc_server_addr = cfg_local.server_addr.clone();
        let wc_server_port = cfg_local.server_port;
        let wc_tls_enable = cfg_local.tls_enable;
        let wc_tls_server_name = cfg_local.tls_server_name.clone();
        let wc_tls_ca_file = opt_if_empty!(cfg_local.tls_ca_file);
        let wc_tls_cert_file = opt_if_empty!(cfg_local.tls_cert_file);
        let wc_tls_key_file = opt_if_empty!(cfg_local.tls_key_file);
        let wc_dns_server = opt_if_empty!(cfg_local.dns_server);
        // Upper bound (65507, max UDP payload) is enforced at config load
        // (frp-core config/client.rs — every load path, reload included);
        // `.max(0)` guards programmatically-built configs with a negative
        // value so the buffer size stays sane.
        let wc_udp_packet_size = cfg_local.udp_packet_size.max(0) as usize;
        let wc_disable_custom_tls_first_byte = cfg_local.disable_custom_tls_first_byte;
        let wc_keepalive_secs = cfg_local.dial_server_keepalive.max(0) as u64;
        let wc_bind_addr = opt_if_empty!(cfg_local.connect_server_local_ip);
        let wc_proxy_url = cfg_local.proxy_url.clone();
        let wc_dial_timeout_secs = cfg_local.dial_server_timeout.max(1) as u64;

        let mut ctl = ControlConnection::new(
            cfg_local.server_addr.clone(),
            cfg_local.server_port,
            self.auth_cfg.clone(),
            protocol.clone(),
            pool_count,
            cfg_local.user.clone(),
            cfg_local.client_id.clone(),
            cfg_local.tls_enable,
            cfg_local.tls_server_name.clone(),
            opt_if_empty!(cfg_local.tls_ca_file),
            cfg_local.tls_skip_verify,
            opt_if_empty!(cfg_local.tls_cert_file),
            opt_if_empty!(cfg_local.tls_key_file),
            opt_if_empty!(cfg_local.dns_server),
            cfg_local.tcp_mux,
            cfg_local.disable_custom_tls_first_byte,
            cfg_local.dial_server_keepalive.max(0) as u64,
            cfg_local.tcp_mux_keepalive_interval,
            cfg_local.tcp_mux_keepalive_timeout,
            opt_if_empty!(cfg_local.connect_server_local_ip),
            cfg_local.v2,
            cfg_local.tcp_send_buffer_size,
            cfg_local.tcp_recv_buffer_size,
            self.oidc_client.clone(),
            cfg_local.metas.clone(),
            cfg_local.proxy_url.clone(),
            previous_run_id.clone(),
            Some(ClientSpec {
                client_type: Some("frpc".into()),
                always_auth_pass: None,
            }),
            cfg_local.dial_server_timeout,
            #[cfg(feature = "quic")]
            frp_core::quic::quic_params_from_option_values(
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.keepalive_period)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_idle_timeout)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_incoming_streams)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.stream_receive_window)
                    .unwrap_or(0),
            ),
        );

        // Initialized to None: the post-login Ok arm overwrites it, and
        // the error path (below) diverges before it can be read.
        #[cfg(feature = "quic")]
        let mut quic_conn: Option<QuicConnection> = None;

        // Login and the post-login encryption wrap funnel into one Result:
        // `into_encrypted` can fail when the transport carries unconsumed
        // read-ahead bytes (remote-triggerable: a proxy injecting junk
        // after its CONNECT response), and that failure must take the
        // same retry/exit path as a login error — never panic (release
        // binaries build with panic=abort).
        let enc_result = match ctl.login().await {
            Ok(r) => {
                *did_login_once = true;
                *self.server_auth_scopes.write().await = ctl.server_auth_scopes.clone();
                // After login, wrap control stream in AES-128-CFB encryption.
                // Go frps v0.69.1 always encrypts the control connection for V1.
                #[cfg(feature = "quic")]
                let (stream, run_id, yamux, quic, udp_codec) = r;
                #[cfg(not(feature = "quic"))]
                let (stream, run_id, yamux, udp_codec) = r;
                let enc_key = encryption::derive_key(&self.auth_cfg.token);
                #[cfg(feature = "quic")]
                {
                    quic_conn = quic;
                }
                stream
                    .into_encrypted(enc_key)
                    .map(|stream| (stream, run_id, yamux, udp_codec))
                    .map_err(frp_core::Error::from)
            }
            Err(e) => Err(e),
        };
        let (control_stream, run_id, yamux_session, udp_codec) = match enc_result {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        let yamux = yamux_session.map(std::sync::Arc::new);
        #[cfg(feature = "quic")]
        let quic_conn = quic_conn.map(std::sync::Arc::new);
        let v2 = cfg_local.v2;
        info!(run_id = %run_id, "Logged in. run_id: {}", run_id);

        // --- Heartbeat state: single arm point ---
        // `last_pong` is initialized at login success so the heartbeat
        // watchdog bounds the REGISTRATION phase too: no Ping is sent
        // until the message loop starts, so a server that stays
        // connected but never answers NewProxy is detected within
        // heartbeat_timeout instead of hanging the client in
        // registration forever (Go frp's heartbeat timer also runs
        // continuously while proxies register in their own goroutines).
        // The message loop below reuses these same variables — this is
        // the only initialization point (the watchdog must not be
        // double-armed with a fresh timer after registration).
        let ping_interval = if cfg_local.heartbeat_interval > 0 {
            let secs = cfg_local.heartbeat_interval as u64;
            info!(interval = %secs, "Heartbeat interval: {}s", secs);
            Some(tokio::time::interval(Duration::from_secs(secs)))
        } else {
            info!("Heartbeat: explicitly disabled (heartbeat_interval <= 0)");
            None
        };
        let last_pong = Instant::now();
        let hb_timeout = cfg_local.heartbeat_timeout;
        let hb_timeout_dur = Duration::from_secs(hb_timeout.max(0) as u64);
        // The watchdog only makes sense while the ping loop is active:
        // with heartbeat_interval <= 0 the client never sends Pings, so
        // no Pong can ever arrive and an active watchdog would fire right
        // after login and reconnect forever (Go frp gates its heartbeat
        // on the interval too).
        let hb_watchdog_active = hb_timeout > 0 && ping_interval.is_some();

        let session_alive = Arc::new(AtomicBool::new(true));

        let client_scopes: Vec<String> = cfg_local
            .auth
            .as_ref()
            .map(|a| a.additional_auth_scopes.clone())
            .unwrap_or_default();
        let server_scopes = self.server_auth_scopes.read().await.clone();

        Ok(SessionCtx {
            control_stream: Some(control_stream),
            run_id,
            yamux,
            v2,
            #[cfg(feature = "quic")]
            quic_conn,
            ping_interval,
            ping_retry_backoff: None,
            last_pong,
            hb_timeout,
            hb_timeout_dur,
            hb_watchdog_active,
            session_alive,
            wc_server_addr,
            wc_server_port,
            wc_tls_enable,
            wc_tls_server_name,
            wc_tls_ca_file,
            wc_tls_cert_file,
            wc_tls_key_file,
            wc_dns_server,
            wc_udp_packet_size,
            wc_udp_packet_codec: udp_codec,
            wc_disable_custom_tls_first_byte,
            wc_keepalive_secs,
            wc_bind_addr,
            wc_proxy_url,
            wc_dial_timeout_secs,
            protocol: protocol.clone(),
            client_scopes,
            server_scopes,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            session_started_at: Instant::now(),
            pending_proxies: Vec::new(),
            pending_visitors: Vec::new(),
            write_failed: false,
            seen_registration_response: false,
            req_work_conns_seen: 0,
            writer: None,
            control_rx: None,
            control_failed: None,
            control_notify: None,
            reader: None,
            visitor_shutdown: None,
            visitor_handles: Vec::new(),
            work_conn_handles: Vec::new(),
            control_writer_handle: None,
            pending_xtcp: std::collections::HashMap::new(),
            xtcp_sockets: Default::default(),
            visitor_pending: std::collections::HashMap::new(),
            stun_result_tx: None,
            stun_result_rx: None,
            xtcp_cleanup_rx: None,
            proxy_retry_interval: None,
            waitstart_seen: HashMap::new(),
            cfg_user: String::new(),
        })
    }

    /// Phase 5 of one connection attempt: split the control stream into
    /// reader/writer halves, spawn the dedicated writer task (bounded
    /// channel — producers never block on a slow peer, the raw write half is
    /// owned by exactly one task, and a write failure wakes the control loop
    /// to tear down and reconnect), spawn VnetControllers for vnet proxies,
    /// cancel the previous session's visitor listener tasks, and spawn the
    /// current session's virtual_net / STCP / XTCP visitor listeners. Only
    /// called when the registration phase did not abort (the session
    /// continuation guard in run()).
    ///
    /// A split failure propagates to run() as a session error (matching the
    /// original `into_split()?` in run(), which returned from run() itself).
    async fn spawn_session_tasks(
        &self,
        ctx: &mut SessionCtx,
        cfg_local: &ClientConfig,
        #[cfg_attr(not(feature = "vnet"), allow(unused_variables))]
        proxies: &[frp_core::config::ProxyConfig],
        protocol: &TransportProtocol,
        nat_hole_stun_server: &str,
    ) -> std::io::Result<()> {
        // Split control stream for reading and writing.
        let (reader, raw_writer) = ctx
            .control_stream
            .take()
            .expect("control_stream available before split")
            .into_split()?;
        ctx.reader = Some(reader);

        {
            let failed = ctx
                .control_failed
                .as_ref()
                .expect("control_failed available before split")
                .clone();
            let notify = ctx
                .control_notify
                .as_ref()
                .expect("control_notify available before split")
                .clone();
            let control_rx = ctx
                .control_rx
                .take()
                .expect("control_rx available before split");
            // Keep the JoinHandle on SessionCtx so teardown can abort the
            // writer (F7): the raw write half lives only inside this task,
            // and against a wedged-but-alive peer a blocked write_msg would
            // otherwise keep the task + socket fd alive past session end.
            let writer_handle = tokio::spawn(async move {
                let mut rx = control_rx;
                let mut w = raw_writer;
                while let Some((msg, v2)) = rx.recv().await {
                    if let Err(e) = write_msg(&mut w, &msg, v2).await {
                        tracing::error!(error = %e, "Control writer failed: {}", e);
                        failed.store(true, std::sync::atomic::Ordering::SeqCst);
                        notify.notify_waiters();
                        break;
                    }
                }
            });
            ctx.control_writer_handle = Some(writer_handle);
        }

        // Spawn VnetControllers for all vnet proxies now that the
        // control connection writer is available.
        #[cfg(feature = "vnet")]
        for p in proxies {
            if vnet_tun_params(p, &cfg_local.virtual_net.address).is_none() {
                continue;
            }
            let writer = ctx
                .writer
                .as_ref()
                .expect("writer available before vnet controller spawn");
            if spawn_vnet_tun_controller(
                &self.vnet_tuns,
                &self.vnet_tun_tx,
                &self.vnet_tun_cancels,
                &self.vnet_controller,
                &p.name,
                &p.virtual_net,
                writer,
                ctx.v2,
            )
            .await
            .is_some()
            {
                send_vnet_route_advertise(writer, ctx.v2, p).await;
            }
        }

        // Cancel old visitor listener tasks from a previous session.
        // Signal gracefully and wait briefly for the previous session's
        // visitors to exit, instead of aborting them (Go frp compat:
        // visitor_manager.Close() closes each visitor cleanly). The
        // previous session's visitor_shutdown was already set when the
        // session ended; tasks should exit on their own. Any listener
        // still stuck in accept() after the grace period is force-aborted
        // so the bind port is released for the new session.
        self.shutdown_visitor_tasks(std::mem::take(&mut ctx.visitor_handles))
            .await;

        // Spawn STCP/XTCP visitor listeners
        let session_visitors = self.cfg.read().await.visitors.clone();
        for v in &session_visitors {
            if !v.enabled {
                continue;
            }
            if v.bind_port == 0 {
                continue;
            }
            // Virtual_net visitors do not bind a local listener; they
            // establish a persistent STCP/XTCP tunnel and register their
            // destinationIP host route with the client vnet controller.
            if v.plugin
                .as_ref()
                .is_some_and(|p| p.plugin_type == VISITOR_PLUGIN_VIRTUAL_NET)
            {
                #[cfg(feature = "vnet")]
                {
                    if let Some(adv) = virtual_net_visitor_route_adv(v) {
                        let sa = cfg_local.server_addr.clone();
                        let sp = cfg_local.server_port;
                        let pt = protocol.clone();
                        let server_name = v.server_name.clone();
                        let server_user = v.server_user.clone();
                        let secret_key = v.secret_key.clone();
                        let use_enc = v.use_encryption;
                        let use_comp = v.use_compression;
                        let name = v.name.clone();
                        let tls_enable = cfg_local.tls_enable;
                        let tls_server_name = cfg_local.tls_server_name.clone();
                        let tls_ca_file = opt_if_empty!(cfg_local.tls_ca_file);
                        let transport_proxy_url = opt_if_empty!(cfg_local.proxy_url.clone());
                        let transport_dns = opt_if_empty!(cfg_local.dns_server.clone());
                        let transport_bind =
                            opt_if_empty!(cfg_local.connect_server_local_ip.clone());
                        let transport_tls_cert = opt_if_empty!(cfg_local.tls_cert_file.clone());
                        let transport_tls_key = opt_if_empty!(cfg_local.tls_key_file.clone());
                        let transport_tcp_mux = cfg_local.tcp_mux;
                        let transport_tcp_mux_keepalive = cfg_local.tcp_mux_keepalive_interval;
                        let transport_tcp_mux_keepalive_timeout =
                            cfg_local.tcp_mux_keepalive_timeout;
                        let transport_dial_timeout = cfg_local.dial_server_timeout.max(1) as u64;
                        let transport_keepalive = cfg_local.dial_server_keepalive.max(0) as u64;
                        let transport_nocustomtls = cfg_local.disable_custom_tls_first_byte;
                        let user = cfg_local.user.clone();
                        let rid = ctx.run_id.clone();
                        let v2 = ctx.v2;
                        let controller = self.vnet_controller.clone();
                        let vnet_tun_tx = self.vnet_tun_tx.clone();
                        let tun_subnets = self.vnet_tun_subnets.clone();
                        let shutdown = ctx
                            .visitor_shutdown
                            .as_ref()
                            .expect("visitor_shutdown available before visitor spawn")
                            .clone();
                        let handle = tokio::spawn(async move {
                            crate::visitor::run_virtual_net_visitor(
                                crate::visitor::VirtualNetVisitorConfig {
                                    server_addr: sa,
                                    server_port: sp,
                                    protocol: pt,
                                    server_name,
                                    server_user,
                                    secret_key,
                                    use_encryption: use_enc,
                                    use_compression: use_comp,
                                    name,
                                    tls_enable,
                                    tls_server_name,
                                    tls_ca_file,
                                    user,
                                    run_id: rid,
                                    tcp_mux: transport_tcp_mux,
                                    tcp_mux_keepalive_interval: transport_tcp_mux_keepalive,
                                    tcp_mux_keepalive_timeout: transport_tcp_mux_keepalive_timeout,
                                    proxy_url: transport_proxy_url.clone(),
                                    dns_server: transport_dns.clone(),
                                    dial_timeout_secs: transport_dial_timeout,
                                    keepalive_secs: transport_keepalive,
                                    connect_bind_addr: transport_bind.clone(),
                                    disable_custom_tls_first_byte: transport_nocustomtls,
                                    tls_cert_file: transport_tls_cert.clone(),
                                    tls_key_file: transport_tls_key.clone(),
                                    v2,
                                    destination_cidr: adv.subnet,
                                    controller,
                                    vnet_tun_tx,
                                    tun_subnets,
                                    shutdown,
                                },
                            )
                            .await;
                        });
                        ctx.visitor_handles.push(handle);
                    }
                }
                continue;
            }
            let sa = cfg_local.server_addr.clone();
            let sp = cfg_local.server_port;
            let pt = protocol.clone();
            let server_name = v.server_name.clone();
            let server_user = v.server_user.clone();
            let secret_key = v.secret_key.clone();
            let bind_addr = format!("{}:{}", v.bind_addr, v.bind_port);
            let use_enc = v.use_encryption;
            let use_comp = v.use_compression;
            let name = v.name.clone();
            let tls_enable = cfg_local.tls_enable;
            let tls_server_name = cfg_local.tls_server_name.clone();
            let tls_ca_file = opt_if_empty!(cfg_local.tls_ca_file);
            let transport_proxy_url = opt_if_empty!(cfg_local.proxy_url.clone());
            let transport_dns = opt_if_empty!(cfg_local.dns_server.clone());
            let transport_bind = opt_if_empty!(cfg_local.connect_server_local_ip.clone());
            let transport_tls_cert = opt_if_empty!(cfg_local.tls_cert_file.clone());
            let transport_tls_key = opt_if_empty!(cfg_local.tls_key_file.clone());
            let transport_tcp_mux = cfg_local.tcp_mux;
            let transport_tcp_mux_keepalive = cfg_local.tcp_mux_keepalive_interval;
            let transport_tcp_mux_keepalive_timeout = cfg_local.tcp_mux_keepalive_timeout;
            let transport_dial_timeout = cfg_local.dial_server_timeout.max(1) as u64;
            let transport_keepalive = cfg_local.dial_server_keepalive.max(0) as u64;
            let transport_nocustomtls = cfg_local.disable_custom_tls_first_byte;
            let visitor_type = v.visitor_type.clone();
            let fallback_timeout_ms = v.fallback_timeout_ms;
            let keep_tunnel_open = v.keep_tunnel_open;
            let max_retries_an_hour = v.max_retries_an_hour;
            let min_retry_interval = v.min_retry_interval;
            // nat_hole_stun_server is a &str param here (was a String local in
            // run()); to_string() keeps the String-typed visitor field unchanged.
            let stun_server = nat_hole_stun_server.to_string();
            let fallback_to = v.fallback_to.clone();
            let disable_assisted_addrs = v.disable_assisted_addrs;
            let p2p_protocol = v.protocol.clone();
            let user = cfg_local.user.clone();
            let rid = ctx.run_id.clone();
            let v2 = ctx.v2;
            let vtx = self.visitor_tx.clone();
            let shutdown = ctx
                .visitor_shutdown
                .as_ref()
                .expect("visitor_shutdown available before visitor spawn")
                .clone();
            // Clone the negotiated UDPPacket codec before `ctx` moves into
            // the spawn (Go frp v0.71.0 sessionCtx.UDPPacketCodec).
            let ctx_udp_packet_codec = ctx.wc_udp_packet_codec.clone();
            // Client QUIC transport params for the XTCP tunnel session (Go
            // `clientCfg.Transport.QUIC`).
            //
            // `kcp` as well as `quic`: this value flows into
            // `VisitorListenerConfig::quic_params` → `XtcpPunchConfig` →
            // `do_hole_punch`'s QUIC session call, and frp-core re-exports
            // `QuicTunnelSession` only under `all(feature = "kcp", feature =
            // "quic")`. See the field gate in `frp-client/src/visitor.rs`.
            #[cfg(all(feature = "quic", feature = "kcp"))]
            let visitor_quic_params = frp_core::quic::quic_params_from_option_values(
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.keepalive_period)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_idle_timeout)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.max_incoming_streams)
                    .unwrap_or(0),
                cfg_local
                    .quic_options
                    .as_ref()
                    .map(|q| q.stream_receive_window)
                    .unwrap_or(0),
            );
            let handle = tokio::spawn(async move {
                crate::visitor::run_visitor_listener(crate::visitor::VisitorListenerConfig {
                    server_addr: sa,
                    server_port: sp,
                    protocol: pt,
                    server_name,
                    server_user,
                    secret_key,
                    bind_addr,
                    use_encryption: use_enc,
                    use_compression: use_comp,
                    name,
                    tls_enable,
                    tls_server_name,
                    tls_ca_file,
                    visitor_type,
                    fallback_timeout_ms,
                    keep_tunnel_open,
                    max_retries_an_hour,
                    min_retry_interval,
                    stun_server,
                    p2p_protocol,
                    visitor_tx: vtx,
                    fallback_to,
                    disable_assisted_addrs,
                    shutdown,
                    user,
                    run_id: rid,
                    tcp_mux: transport_tcp_mux,
                    tcp_mux_keepalive_interval: transport_tcp_mux_keepalive,
                    tcp_mux_keepalive_timeout: transport_tcp_mux_keepalive_timeout,
                    proxy_url: transport_proxy_url.clone(),
                    dns_server: transport_dns.clone(),
                    dial_timeout_secs: transport_dial_timeout,
                    keepalive_secs: transport_keepalive,
                    connect_bind_addr: transport_bind.clone(),
                    disable_custom_tls_first_byte: transport_nocustomtls,
                    tls_cert_file: transport_tls_cert.clone(),
                    tls_key_file: transport_tls_key.clone(),
                    v2,
                    // Negotiated UDPPacket codec (Go frp v0.71.0): the SUDP
                    // visitor data plane must match the provider segment's
                    // packet codec so the server keeps the zero-copy
                    // byte-stream bridge; mismatches fall back to the
                    // message-level transcoding bridge.
                    udp_packet_codec: ctx_udp_packet_codec.clone(),
                    #[cfg(all(feature = "quic", feature = "kcp"))]
                    quic_params: visitor_quic_params,
                })
                .await;
            });
            ctx.visitor_handles.push(handle);
        }

        Ok(())
    }

    /// F2 liveness guard for the XTCP punch paths. Reload removal and the
    /// health Close event cancel the per-proxy P2P bridge token (and remove
    /// the proxy from `proxy_info_map` / mark it CheckFailed) at one loop
    /// iteration, but the server's nathole session outlives proxy
    /// unregistration (NAT_HOLE_TIMEOUT = 10s): a NatHoleClient/NatHoleResp
    /// the server already put on the wire arrives at a LATER iteration and
    /// would re-insert a FRESH uncancelled token via
    /// `entry(name).or_insert_with(CancellationToken::new)` — the
    /// cancel-before-reinsert race. The punch/bridge it spawns would then
    /// never observe the earlier cancellation (the removed proxy gets no
    /// further CloseProxy/HealthEvent to cancel it) and would run until the
    /// peer closes. A proxy is dead for punching when it is absent from
    /// `proxy_info_map` (reload removal) or in CheckFailed (health Close).
    pub(crate) async fn punch_proxy_still_live(&self, proxy_name: &str) -> bool {
        let map = self.proxy_info_map.read().await;
        match map.get(proxy_name) {
            None => false,
            Some(info) => !matches!(info.phase, ProxyPhase::CheckFailed | ProxyPhase::Closed),
        }
    }

    /// Phase 6 of one connection attempt: the message loop. Reads control
    /// frames, ticks the heartbeat ping, retries StartErr proxies every 30s,
    /// and handles health / reload / XTCP / visitor / stop events until the
    /// session ends. Returns how it ended: `Shutdown` when a stop was
    /// requested (run() must not reconnect), `Reconnect` when the session
    /// died (run() tears down and reconnects).
    ///
    /// The session-agnostic receivers and handles are bundled in `channels`:
    /// they are created once in run() and outlive sessions.
    async fn run_message_loop(
        &self,
        ctx: &mut SessionCtx,
        channels: &mut SessionChannels<'_>,
    ) -> LoopExit {
        // The message loop owns the split reader half. It is shared with
        // the persisted read future below via an async Mutex: the future
        // holds the guard only while a frame is being read (control-plane
        // rate), and no other loop arm touches `reader`.
        let reader = Arc::new(Mutex::new(
            ctx.reader
                .take()
                .expect("reader available before message loop"),
        ));

        // Control writes are funneled through the writer handle
        // (always set by phase 5 before the loop starts).
        let writer = ctx
            .writer
            .as_ref()
            .expect("writer available before message loop")
            .clone();

        // --- Message loop ---
        // Map sid -> proxy_name for XTCP NatHoleResp routing (provider side).
        // Map sid -> STUN UDP socket for XTCP P2P hole punching.
        // Map sid -> oneshot sender for visitor NatHoleResp routing (Go frps compat).
        // (All three maps live on SessionCtx, as do waitstart_seen and
        // cfg_user — see the field docs.)
        // STUN discovery runs off the control loop (two STUN round-trips can
        // stall up to ~10s). The finished NatHoleClient is sent back here so
        // the write + pending_xtcp bookkeeping stay on the loop, preserving
        // the write-before-NatHoleResp ordering. A separate cleanup channel
        // lets a timeout task reclaim stale xtcp_sockets/pending_xtcp entries
        // when the server never sends NatHoleResp.
        let (stun_result_tx, stun_result_rx) = mpsc::channel::<StunResult>(64);
        ctx.stun_result_tx = Some(stun_result_tx);
        ctx.stun_result_rx = Some(stun_result_rx);
        let (xtcp_cleanup_tx, xtcp_cleanup_rx) = mpsc::channel::<String>(64);
        ctx.xtcp_cleanup_rx = Some(xtcp_cleanup_rx);

        // Proxy retry cadence: Go's proxy_wrapper.checkWorker ticks every
        // statusCheckInterval (3s) and gates each condition on its own
        // timeout (startErrTimeout 30s / waitResponseTimeout 20s). frp-rs
        // folds both into one tick — the smaller of the two timeouts — and
        // gates each retry class on its own anchor below (last_start_err /
        // waitstart_seen). At defaults a StartErr retry fires 30–40s after
        // its last error and a WaitStart re-send 20–40s after it was
        // observed (anchor set at the first tick where the proxy is seen in
        // WaitStart, so up to one tick late vs Go's 3s-tick 20–23s), staying
        // consistent under env overrides.
        let mut proxy_retry_interval =
            tokio::time::interval(PROXY_RETRY_INTERVAL.min(*WAIT_START_RETRY_TIMEOUT));
        proxy_retry_interval.tick().await; // Skip first immediate tick
        ctx.proxy_retry_interval = Some(proxy_retry_interval);

        // When each proxy last entered StartErr (message-loop
        // NewProxyResp error). Go frp's proxy_wrapper anchors the
        // StartErr retry on the error time (`lastStartErr.Add(
        // startErrTimeout)`), so a proxy that errors right before a
        // tick must NOT be re-sent at the tick — that would re-arm
        // the error immediately and, for a permanently-rejected
        // proxy (e.g. remote_port in use), hammer the server with a
        // NewProxy every tick while staying in StartErr. The retry
        // arm gates StartErr proxies on
        // `now - last_start_err >= PROXY_RETRY_INTERVAL`, mirroring
        // Go's `startErrTimeout` anchored on the error. Proxies that
        // entered StartErr during the REGISTRATION phase (before the
        // message loop) have no entry here — treated as eligible at
        // the first tick, preserving the pre-loop behavior. Pruned
        // when the proxy leaves StartErr.
        let mut last_start_err: HashMap<String, Instant> = HashMap::new();

        // Persist a partial control-frame read across select iterations
        // (audit finding S3 — HIGH; exact mirror of the server round-14 fix
        // in frp-server/src/control/mod.rs, whose fairness regression test
        // this comment chain mirrors too): the select drops every branch
        // future when another arm wins, and `read_msg`'s two-phase framing
        // (read_exact header, then read_exact payload) keeps its partial
        // state only in the branch future's locals. A peer that splits a
        // frame across two writes while a competing arm wins mid-frame
        // (heartbeat ping tick, proxy-retry tick, health/reload/xtcp/
        // visitor/stop event, heartbeat watchdog, writer failure) would
        // lose the consumed bytes; the next iteration would parse the frame
        // tail as a fresh header — a garbage type/length → protocol error →
        // LoopExit::Reconnect → infinite reconnect churn under a
        // slow-dribbling peer. The boxed future survives the select, so
        // consumed bytes are retained until the frame completes. The loop
        // shape stays fair (no biased branch ordering — tokio::select!
        // without `biased;` randomizes Ready-branch order each round): the
        // read still progresses only at loop top, exactly like a fresh
        // future would, and a mid-frame read is NOT polled again until the
        // select round that follows the competing arm's body. Correctness
        // never relies on the read winning — the future lives in the
        // loop-outer Option, so a lost round drops the branch's reference,
        // not the future: a completed read stays Ready and wins the first
        // round in which no earlier arm is also Ready (a Ready future needs
        // no waker to make progress), and a partial read keeps its consumed
        // bytes until completion. The arm body's reset below therefore can
        // never strand a completed future.
        //
        // The future owns an Arc<Mutex<BoxedReadHalf>> clone and locks
        // inside its own poll, so it borrows nothing from the loop — a
        // loop-local borrow could not be stored across select iterations
        // (the Option's type region would keep the borrow alive for the
        // whole loop, conflicting with the loop-top recreation below).
        type PendingRead =
            Pin<Box<dyn Future<Output = Result<FrpMessage, frp_core::Error>> + Send>>;
        let mut pending_read: Option<PendingRead> = None;

        // Persistent heartbeat-watchdog timer (perf audit LOW): one `Sleep`
        // lives for the whole message loop instead of a fresh
        // `sleep(hb_timeout_dur - last_pong.elapsed())` built on every select
        // iteration — the per-iteration form paid an `Instant::now()` plus a
        // timer construction on every control frame, while the deadline is
        // fully determined by `last_pong` + `hb_timeout_dur`. The deadline is
        // absolute, so the timer is re-armed at the loop top only when a Pong
        // moved `last_pong` or after it has fired (an elapsed `Sleep` polls
        // Ready immediately — the same guard shape as the Wave-1
        // xtcp_session ticker). Cadence is unchanged: the first fire is one
        // full `hb_timeout` after login, and no tick is ever replayed or
        // coalesced, because the reset target is the absolute deadline
        // `last_pong + hb_timeout_dur`, never `now + interval`.
        let mut hb_armed_pong = ctx.last_pong;
        // A hostile heartbeat_timeout (the config preserves i64::MAX raw)
        // makes `last_pong + hb_timeout_dur` overflow `Instant` — a panic
        // that aborts the process under panic=abort. Degrade to never-fire:
        // an absurd interval means "no watchdog", and the deadline is
        // unreachable (round-13 dropped the 3600s clamp on both sides).
        let mut hb_deadline: Option<std::time::Instant> =
            ctx.last_pong.checked_add(ctx.hb_timeout_dur);
        // The timer holds a placeholder deadline while `hb_deadline` is None
        // (overflow); the select arm below is gated off in that state, so
        // the placeholder is never polled and never fires.
        let mut hb_sleep = Box::pin(tokio::time::sleep_until(
            hb_deadline
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(tokio::time::Instant::now),
        ));

        loop {
            // Re-arm the watchdog only when its deadline moved or the timer
            // already fired. A disabled watchdog (heartbeat interval <= 0,
            // hb_watchdog_active false) is never armed at all — its select
            // arm below is gated off, so the timer would never be polled.
            if ctx.hb_watchdog_active && (ctx.last_pong != hb_armed_pong || hb_sleep.is_elapsed()) {
                hb_armed_pong = ctx.last_pong;
                hb_deadline = ctx.last_pong.checked_add(ctx.hb_timeout_dur);
                // Overflow degrades to never-fire (see the initial arm); the
                // placeholder timer is left alone — the gated select arm
                // never polls it.
                if let Some(deadline) = hb_deadline {
                    hb_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::from_std(deadline));
                }
            }
            // Recreate the control-read future when the previous frame
            // completed (the arm body detached it). Starts a fresh read at
            // the next frame boundary. The async block owns an Arc clone
            // and takes the lock only while the frame is in flight.
            if pending_read.is_none() {
                let reader = reader.clone();
                let v2 = ctx.v2;
                pending_read = Some(Box::pin(async move {
                    let mut guard = reader.lock().await;
                    read_msg(&mut *guard, v2).await
                }));
            }
            tokio::select! {
                msg = pending_read.as_mut().expect("pending read armed at loop top") => {
                    // Detach the completed future before handling the
                    // message: the select has dropped the branch future,
                    // and the loop-top `if pending_read.is_none()` above
                    // recreates a fresh one for the next frame. A
                    // `continue` inside the message match below therefore
                    // also restarts the read at the next frame boundary.
                    pending_read = None;
                    match msg {
                        Ok(FrpMessage::ReqWorkConn(_)) => {
                            // Shared with the registration read loop above.
                            self.handle_req_work_conn(ctx);
                        }
                        Ok(FrpMessage::Pong(pong)) => {
                            if let Some(ref err) = pong.error {
                                if !err.is_empty() {
                                    warn!(error = %err, "Pong contains error: {}", err);
                                    return LoopExit::Reconnect;
                                }
                            }
                            debug!("Pong received");
                            ctx.last_pong = Instant::now();
                        }
                        Ok(FrpMessage::Ping(_)) => {
                            // Answer an unsolicited server Ping with Pong
                            // (Go frp client parity). Previously inbound
                            // Ping fell into the ignored-messages bucket, so
                            // a server that probes liveness with Ping would
                            // have its watchdog kill a healthy connection.
                            let pong = FrpMessage::Pong(msg::Pong { error: None });
                            if let Err(e) = writer.send(pong, ctx.v2) {
                                debug!(error = %e, "Pong reply to server Ping failed: {}", e);
                            }
                        }
                        Ok(FrpMessage::CloseProxy(cp)) => {
                            info!(proxy_name = %cp.proxy_name, "Server closed proxy: {}", cp.proxy_name);
                            // Registration race: a server CloseProxy for an
                            // OLD registration can land while a same-name
                            // reload re-registration (phase New/WaitStart) is
                            // in flight. Marking it Closed would kill the NEW
                            // proxy — Closed is excluded from the retry loop
                            // and the health-monitor kill below is not re-armed
                            // — so skip the teardown when a registration is
                            // pending; the authoritative phase comes from its
                            // NewProxyResp. (Go deletes the entry by name —
                            // same-keyed semantics — so this is client-side
                            // robustness beyond parity.)
                            let kill = {
                                let mut map = self.proxy_info_map.write().await;
                                match map.get_mut(&cp.proxy_name) {
                                    Some(info)
                                        if matches!(
                                            info.phase,
                                            ProxyPhase::New | ProxyPhase::WaitStart
                                        ) =>
                                    {
                                        false
                                    }
                                    Some(info) => {
                                        info.phase = ProxyPhase::Closed;
                                        true
                                    }
                                    None => true, // absent: still reap stale handles
                                }
                            };
                            if !kill {
                                continue;
                            }
                            // Cancel health check task and remove map entry.
                            let mut cancels = channels.health_cancels.lock().await;
                            if let Some(cancel) = cancels.get(&cp.proxy_name) {
                                cancel.store(true, Ordering::Relaxed);
                            }
                            cancels.remove(&cp.proxy_name);
                            // Cancel any XTCP P2P bridge tasks for this proxy
                            // and drop the token (a re-registered proxy gets a
                            // fresh token via lazy get_or_insert_with).
                            let mut tokens = self.p2p_bridge_tokens.lock().await;
                            if let Some(token) = tokens.remove(&cp.proxy_name) {
                                token.cancel();
                            }
                            // Mirror the reload-removal path (try_reload
                            // commit phase): drop the local plugin listener
                            // handle — PluginHandle::Drop fires the shutdown
                            // oneshot, so the plugin task exits and its bind
                            // port is released — and tear down the vnet TUN
                            // controller. Without this, a server-initiated
                            // CloseProxy (dashboard delete) leaves the plugin
                            // listener and TUN running even though the proxy
                            // is gone (finding 2).
                            //
                            // plugin_handles and the vnet maps are keyed by
                            // the BARE proxy name (start_plugin /
                            // register_vnet_tun), while the wire CloseProxy
                            // name carries the {user.} prefix — strip it.
                            let bare_name = if ctx.cfg_user.is_empty() {
                                cp.proxy_name.clone()
                            } else {
                                let prefix = format!("{}.", ctx.cfg_user);
                                cp.proxy_name
                                    .strip_prefix(&prefix)
                                    .unwrap_or(&cp.proxy_name)
                                    .to_string()
                            };
                            // Teardown order mirrors try_reload: vnet TUN
                            // removal first, then the plugin handle drop.
                            #[cfg(feature = "vnet")]
                            {
                                let vnet = self
                                    .cfg
                                    .read()
                                    .await
                                    .proxies
                                    .iter()
                                    .find(|p| p.name == bare_name)
                                    .map(|p| p.virtual_net.clone())
                                    .unwrap_or_default();
                                remove_vnet_tun(
                                    &self.vnet_tuns,
                                    &self.vnet_tun_tx,
                                    &self.vnet_tun_cancels,
                                    &self.vnet_tun_names,
                                    &self.vnet_tun_subnets,
                                    &self.vnet_controller.route_table(),
                                    &self.vnet_peer_routes,
                                    &writer,
                                    ctx.v2,
                                    &bare_name,
                                    &vnet,
                                )
                                .await;
                            }
                            {
                                let mut handles = self
                                    .plugin_handles
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                if handles.remove(&bare_name).is_some() {
                                    debug!(proxy_name = %bare_name, "CloseProxy: dropped plugin handle for '{}'", bare_name);
                                }
                            }
                            // The Closed phase (set above, outside the lock
                            // order used by HealthEvent): the server's nathole
                            // session outlives the close (NAT_HOLE_TIMEOUT =
                            // 10s), so a late NatHoleClient/NatHoleResp would
                            // otherwise punch/bridge for a proxy the server
                            // just deleted — punch_proxy_still_live must reject
                            // it (matches the health-Close CheckFailed marking
                            // in HealthEvent).
                        }
                        Ok(FrpMessage::CloseProxyResp(cpr)) => {
                            info!(proxy_name = %cpr.proxy_name, "Server confirmed proxy close: {}", cpr.proxy_name);
                            // Do NOT cancel/remove health check here. This response comes from
                            // our CloseProxy (health check failure → CloseProxy → server → CloseProxyResp).
                            // The health check monitor keeps running for recovery detection (Go frp compat).
                        }
                        Ok(FrpMessage::Error(err)) => {
                            warn!(error = %err.error, "Server error: {}", err.error);
                        }
                        Ok(FrpMessage::NatHoleClient(nhc)) => {
                            // F2 cancel-before-reinsert guard: a reload removal
                            // or health Close at an earlier iteration cancelled
                            // this proxy's P2P token; a NatHoleClient the server
                            // already queued must not re-arm a fresh uncancelled
                            // token here (the punch/bridge would then run until
                            // the peer closes). Bail before the insert — the same
                            // guard therefore covers the spawn in
                            // handle_nat_hole_client (no token, no punch).
                            if !self.punch_proxy_still_live(&nhc.proxy_name).await {
                                debug!(proxy_name = %nhc.proxy_name, "Ignoring NatHoleClient for dead proxy '{}'", nhc.proxy_name);
                                continue;
                            }
                            let proxy_token = self
                                .p2p_bridge_tokens
                                .lock()
                                .await
                                .entry(nhc.proxy_name.clone())
                                .or_insert_with(CancellationToken::new)
                                .clone();
                            self.handle_nat_hole_client(*nhc, &writer, ctx.v2, ctx.session_alive.clone(), proxy_token).await;
                        }
                        Ok(FrpMessage::NatHoleResp(resp)) => {
                            // Lazily resolve the provider's cancel token from the
                            // sid → proxy_name map. A visitor-routed resp (or an
                            // unknown sid) has no pending provider proxy; the
                            // fresh inert token it gets is never inserted into
                            // the map and simply stays uncancelled.
                            let sid = resp.sid.clone().unwrap_or_default();
                            let proxy_name = if sid.is_empty() {
                                None
                            } else {
                                ctx.pending_xtcp.get(&sid).cloned()
                            };
                            // F2 cancel-before-reinsert guard, same race as the
                            // NatHoleClient arm: a reload removal or health Close
                            // cancelled this proxy's P2P token at an earlier
                            // iteration; a NatHoleResp the server already queued
                            // must not re-arm a fresh uncancelled token. Reclaim
                            // the sid's socket + pending_xtcp entries so the
                            // bailed resp cannot leak the STUN UDP socket.
                            let proxy_token = match proxy_name {
                                Some(name) if !name.is_empty() => {
                                    if !self.punch_proxy_still_live(&name).await {
                                        debug!(proxy_name = %name, "Ignoring NatHoleResp for dead proxy '{}'", name);
                                        ctx.pending_xtcp.remove(&sid);
                                        ctx.xtcp_sockets.lock().await.remove(&sid);
                                        continue;
                                    }
                                    self
                                        .p2p_bridge_tokens
                                        .lock()
                                        .await
                                        .entry(name)
                                        .or_insert_with(CancellationToken::new)
                                        .clone()
                                }
                                _ => CancellationToken::new(),
                            };
                            self.handle_nat_hole_resp(*resp, &mut ctx.pending_xtcp, &mut ctx.visitor_pending, &ctx.xtcp_sockets, &writer, ctx.session_alive.clone(), proxy_token).await;
                        }
                        Ok(FrpMessage::NewProxyResp(resp)) => {
                            if let Some(err) = resp.error.as_ref().filter(|e| !e.is_empty()) {
                                warn!(proxy_name = %resp.proxy_name, error = %err, "Proxy '{}' registration error: {}", resp.proxy_name, err);
                                // Update phase if proxy was being retried (WaitStart -> StartErr).
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&resp.proxy_name) {
                                    if info.phase == ProxyPhase::WaitStart {
                                        info.err = err.clone();
                                        info.phase = ProxyPhase::StartErr(err.clone());
                                        // Anchor the StartErr retry on the error
                                        // time (Go frp: lastStartErr.Add(
                                        // startErrTimeout)) so the next tick
                                        // does not immediately re-send.
                                        last_start_err.insert(
                                            resp.proxy_name.clone(),
                                            Instant::now(),
                                        );
                                    }
                                }
                            } else {
                                // Successful registration from retry path.
                                // Accept it from WaitStart (normal) or
                                // StartErr (a healthy response that just
                                // missed the 30s retry deadline must not
                                // be thrown away — Go frp keeps
                                // re-registering until the response
                                // lands).
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&resp.proxy_name) {
                                    if info.phase == ProxyPhase::WaitStart
                                        || matches!(info.phase, ProxyPhase::StartErr(_))
                                    {
                                        if let Some(ref remote) = resp.remote_addr {
                                            info.remote_addr.clone_from(remote);
                                        }
                                        info.err.clear();
                                        info.phase = ProxyPhase::Running;
                                        info!(proxy_name = %resp.proxy_name, "Proxy '{}' re-registered", resp.proxy_name);
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetRouteAdvertise(adv)) => {
                            // Isolation: only accept routes for virtual nets
                            // this client participates in. Advertisements for
                            // other vnets are ignored (design spec: different
                            // virtual nets have isolated routing tables).
                            let vnet = adv.virtual_net.clone().unwrap_or_default();
                            if !local_vnet_set(&*self.cfg.read().await).contains(&vnet) {
                                debug!(
                                    vnet,
                                    proxy_name = %adv.proxy_name,
                                    "ignoring vnet route advertisement for unknown virtual net"
                                );
                            } else {
                                info!(vnet, subnet = %adv.subnet, proxy_name = %adv.proxy_name, "peer vnet route advertisement received");
                                // Update the shared route table (TX direction lookup).
                                {
                                    let route_table = self.vnet_controller.route_table();
                                    let mut routes = route_table.write().await;
                                    if let Err(e) =
                                        routes.insert(&vnet, &adv.proxy_name, &adv.subnet)
                                    {
                                        warn!(%e, "failed to add vnet route");
                                    }
                                }
                                // Inject OS route so the kernel sends matching packets
                                // through the TUN device instead of the default gateway.
                                // vnet_tun_names is keyed by *local* proxy name, while
                                // adv.proxy_name is the *remote* peer's name — so match
                                // by virtual_net (the route's isolation domain, already
                                // validated above) instead of by name. The local vnet
                                // proxy owning that virtual net is the one whose TUN must
                                // carry this route; with no local TUN for the net (e.g.
                                // this client is only a visitor) there is nothing to
                                // inject, which is correct — the old code grabbed an
                                // arbitrary TUN and silently misrouted.
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                {
                                    let local_tun_proxy: Option<String> = {
                                        let cfg = self.cfg.read().await;
                                        cfg.proxies
                                            .iter()
                                            .find(|p| {
                                                p.proxy_type == "vnet" && p.virtual_net == vnet
                                            })
                                            .map(|p| p.name.clone())
                                    };
                                    let names = self.vnet_tun_names.lock().await;
                                    if let Some(tun_name) =
                                        local_tun_proxy.as_deref().and_then(|n| names.get(n))
                                    {
                                        add_os_route(&adv.subnet, tun_name);
                                        self.vnet_peer_routes.lock().await.insert(
                                            adv.proxy_name.clone(),
                                            (
                                                adv.subnet.clone(),
                                                tun_name.clone(),
                                                vnet.clone(),
                                            ),
                                        );
                                    } else {
                                        debug!(
                                            vnet,
                                            proxy_name = %adv.proxy_name,
                                            "vnet route advertise: no local TUN for virtual net '{}' — skipping OS route",
                                            vnet
                                        );
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetPacket(vpkt)) => {
                            match frp_core::base64::decode(&vpkt.data) {
                                Ok(packet) => {
                                    // Virtual_net visitors first: deliver into
                                    // the visitor's STCP/XTCP tunnel. TUN-backed
                                    // vnet proxies fall back to their TUN channel
                                    // only when no visitor consumed the packet
                                    // (Err returns the packet untouched).
                                    match self
                                        .vnet_controller
                                        .deliver_visitor_packet(&vpkt.proxy_name, packet)
                                    {
                                        Ok(()) => {}
                                        Err(packet) => {
                                            let txs = self
                                                .vnet_tun_tx
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            if let Some(tx) = txs.get(&vpkt.proxy_name) {
                                                // Single destination: the Vec
                                                // moves into the Arc (no copy).
                                                if tx.try_send(Arc::from(packet)).is_err() {
                                                    warn!(proxy_name = %vpkt.proxy_name, "vnet TUN channel closed");
                                                }
                                            } else {
                                                debug!(proxy_name = %vpkt.proxy_name, "vnet packet dropped: no visitor or TUN target");
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(%e, "VnetPacket base64 decode error");
                                }
                            }
                        }
                        #[cfg(feature = "vnet")]
                        Ok(FrpMessage::VnetRouteRemove(adv)) => {
                            // Isolation: mirror the advertise handler — only
                            // accept removals for virtual nets this client
                            // participates in. Removals for other vnets are
                            // ignored (defensive symmetry; in practice there
                            // is no matching route to clean up anyway).
                            let vnet = adv.virtual_net.clone().unwrap_or_default();
                            if !local_vnet_set(&*self.cfg.read().await).contains(&vnet) {
                                debug!(
                                    vnet,
                                    proxy_name = %adv.proxy_name,
                                    "ignoring vnet route removal for unknown virtual net"
                                );
                            } else {
                                info!(vnet, proxy_name = %adv.proxy_name, "peer vnet route removed");
                                if let Some((subnet, tun_name, _)) = self
                                    .vnet_peer_routes
                                    .lock()
                                    .await
                                    .remove(&adv.proxy_name)
                                {
                                    remove_os_route(&subnet, &tun_name);
                                }
                                self.vnet_controller
                                    .route_table()
                                    .write()
                                    .await
                                    .remove(&vnet, &adv.proxy_name);
                                self.vnet_controller
                                    .unregister_visitor_route(&adv.proxy_name)
                                    .await;
                            }
                        }
                        Ok(_) => {
                            // Other messages are ignored
                        }
                        Err(e) => {
                            warn!(error = %e, "Control read error: {}. Reconnecting...", e);
                            return LoopExit::Reconnect;
                        }
                    }
                }

                _ = async {
                    if let Some(ref mut interval) = ctx.ping_interval {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    let mut ping_msg = msg::Ping {
                        privilege_key: None,
                        timestamp: None,
                    };
                    // Go frp v0.71.0: ping auth failures skip this heartbeat
                    // instead of tearing the session down.
                    let mut skip_ping = false;
                    // Auth scopes: unioning the client's own scopes with the
                    // server-advertised scopes is a Rust-to-Rust extension.
                    // Go v0.70.1's TokenAuthSetterVerifier.SetPing checks only
                    // the client's own additionalAuthScopes
                    // (pkg/auth/token.go:44-51); Go has no
                    // serverAdditionalAuthScopes field in LoginResp, so the
                    // server side of this union is ignored by Go peers.
                    let send_auth = crate::backoff::heartbeat_requires_auth(
                        &ctx.client_scopes,
                        &ctx.server_scopes,
                    );
                    if send_auth {
                        if let Some(ref oidc) = self.oidc_client {
                            if let Err(e) = oidc.set_ping(&mut ping_msg).await {
                                // Go frp v0.71.0: ping auth failure only
                                // SKIPS this heartbeat — the session stays
                                // up and the next heartbeat retries
                                // (client/control.go "skip sending ping
                                // message"). A full reconnect is wasted when
                                // the control link is healthy.
                                warn!(error = %e, "OIDC ping token failed, skipping this ping");
                                skip_ping = true;
                            }
                        } else {
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;
                            match self.auth_cfg.try_generate_login_key(ts) {
                                Ok(key) => {
                                    ping_msg.privilege_key = Some(key);
                                    ping_msg.timestamp = Some(ts);
                                }
                                Err(e) => {
                                    warn!(error = %e, "Ping token source failed, skipping this ping");
                                    skip_ping = true;
                                }
                            }
                        }
                    }
                    if skip_ping {
                        // Go parity (client/control.go:253-265): a ping whose
                        // auth setup failed is retried on a fast exponential
                        // backoff instead of at the next interval tick — a
                        // token outage is probed within ~2s, not after a full
                        // heartbeat_interval (+watchdog). Go's
                        // wait.BackoffUntil re-arms the ticker itself, so the
                        // retry REPLACES the next interval tick: reset_after
                        // points the existing interval at now + backoff. The
                        // session stays up (skip, not teardown — a reconnect
                        // is wasted when the control link is healthy).
                        if let Some(interval) = ctx.ping_interval.as_mut() {
                            let delay = next_ping_backoff(ctx.ping_retry_backoff, interval.period());
                            ctx.ping_retry_backoff = Some(delay);
                            interval.reset_after(delay);
                        }
                        continue;
                    }
                    let ping = FrpMessage::Ping(ping_msg);
                    if let Err(e) = writer.send(ping, ctx.v2) {
                        warn!(error = %e, "Ping write failed: {}", e);
                        // Non-fatal: heartbeat timeout will detect actual dead connection.
                    } else {
                        debug!("Ping sent");
                    }
                    // A non-skipped attempt ends the failure streak (Go's
                    // sendHeartBeat returns no error here — even a failed
                    // Send is swallowed with `_ =`, so only auth failures
                    // engage the backoff). The next attempt runs on the
                    // interval cadence again.
                    ctx.ping_retry_backoff = None;
                }

                _ = ctx
                    .proxy_retry_interval
                    .as_mut()
                    .expect("proxy retry interval available")
                    .tick() => {
                    let now = Instant::now();
                    let mut to_retry: Vec<(String, String)> = {
                        let map = self.proxy_info_map.read().await;
                        map.iter()
                            .filter(|(_, info)| matches!(info.phase, ProxyPhase::StartErr(_)))
                            // Go frp parity: a StartErr proxy is retried only
                            // once a full interval has elapsed since ITS last
                            // error (lastStartErr.Add(startErrTimeout)) — not
                            // on the tick boundary. A permanently-rejected
                            // proxy therefore gets at most one NewProxy per
                            // interval instead of one per tick (which, when
                            // an error lands just before a tick, re-arms the
                            // error and re-sends immediately — hammering the
                            // server). Proxies that entered StartErr during
                            // registration have no entry here; they are
                            // eligible at the first tick (pre-loop behavior).
                            .filter(|(name, _)| {
                                last_start_err
                                    .get(*name)
                                    .is_none_or(|t| now.duration_since(*t) >= *PROXY_RETRY_INTERVAL)
                            })
                            .map(|(name, info)| (name.clone(), info.local_addr.clone()))
                            .collect()
                    };
                    // Fold proxies stuck in WaitStart past the
                    // WaitStart response timeout into the retry set. A NewProxy that is never
                    // answered (a silent server that still Pongs) keeps the
                    // proxy in WaitStart — the StartErr transition happens
                    // only on a NewProxyResp error, so without this check a
                    // single unanswered retry would stop the retries
                    // forever. Go frp parity: proxy_wrapper re-arms
                    // waitResponseTimeout while in waitStart and retries
                    // indefinitely. `waitstart_seen` records when each
                    // proxy last entered WaitStart (initial registration or
                    // a retry send) and is pruned once it leaves WaitStart
                    // (registered, errored, or closed).
                    {
                        let map = self.proxy_info_map.read().await;
                        ctx.waitstart_seen.retain(|name, _| {
                            map.get(name).is_some_and(|info| {
                                info.phase == ProxyPhase::WaitStart
                            })
                        });
                        // Prune StartErr anchors for proxies that left
                        // StartErr (registered, closed, or re-entered
                        // WaitStart via a retry send below).
                        last_start_err.retain(|name, _| {
                            map.get(name).is_some_and(|info| {
                                matches!(info.phase, ProxyPhase::StartErr(_))
                            })
                        });
                        for (name, info) in map.iter() {
                            if info.phase == ProxyPhase::WaitStart
                                && !ctx.waitstart_seen.contains_key(name)
                            {
                                // First observed in WaitStart at this tick
                                // (e.g. the initial registration left it
                                // pending past retry setup): start its
                                // clock now.
                                ctx.waitstart_seen.insert(name.clone(), now);
                            }
                        }
                        to_retry.extend(map.iter().filter_map(|(name, info)| {
                            if info.phase == ProxyPhase::WaitStart
                                && ctx.waitstart_seen.get(name).is_some_and(|first_seen| {
                                    // saturating_sub: an env-shrunk
                                    // interval below the 100ms grace must
                                    // not underflow (panic).
                                    now.duration_since(*first_seen)
                                        >= (*WAIT_START_RETRY_TIMEOUT)
                                            .saturating_sub(PROXY_RETRY_GRACE)
                                })
                            {
                                Some((name.clone(), info.local_addr.clone()))
                            } else {
                                None
                            }
                        }));
                    }
                    if !to_retry.is_empty() {
                        // Retry candidates come from the LIVE proxy set:
                        // try_reload refreshes self.proxies, so a proxy
                        // ADDED by a reload that failed to register
                        // (StartErr) is retried too — the session-start
                        // `proxies` snapshot (still used by the
                        // registration loop above) would miss it.
                        // Lock order: proxies read then cfg read (the
                        // session loop takes them in the opposite order).
                        // Not a deadlock: both locks' writers (try_reload)
                        // run only in this message-loop task, so these read
                        // guards never contend with a writer across tasks.
                        let all_proxies = Arc::clone(&*self.proxies.read().await);
                        let retry_candidates =
                            filter_active_proxies(&*self.cfg.read().await, &all_proxies);
                        // Hoist the wire-name prefix (format! allocates); it is
                        // loop-invariant within this tick.
                        let cfg_user_prefix = if ctx.cfg_user.is_empty() {
                            None
                        } else {
                            Some(format!("{}.", ctx.cfg_user))
                        };
                        for (name, local_addr) in to_retry {
                            let bare_name = match &cfg_user_prefix {
                                Some(prefix) => name.strip_prefix(prefix).unwrap_or(&name),
                                None => name.as_str(),
                            };
                            if let Some(p) = retry_candidates.iter().find(|p| p.name == bare_name) {
                                let new_proxy = crate::proxy::create_new_proxy_msg(p, &local_addr, &ctx.cfg_user);
                                if let Err(e) = writer.send(new_proxy, ctx.v2) {
                                    warn!(proxy_name = %name, error = %e, "Proxy '{}' retry: write NewProxy failed: {}", name, e);
                                } else {
                                    info!(proxy_name = %name, "Proxy '{}' retry: sent NewProxy", name);
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&name) {
                                        info.phase = ProxyPhase::WaitStart;
                                    }
                                    // Re-arm the WaitStart clock at the send
                                    // (Go frp's proxy_wrapper re-arms
                                    // startErrTimeout per NewProxy send).
                                    ctx.waitstart_seen.insert(name.clone(), Instant::now());
                                }
                            }
                        }
                    }
                }

                Some(event) = channels.health_rx.recv() => {
                    match event {
                        HealthEvent::Close(proxy_name) => {
                            info!(proxy_name = %proxy_name, "Health check sending CloseProxy for unhealthy proxy: {}", proxy_name);
                            // Cancel + drop the XTCP P2P bridge token for this
                            // proxy, mirroring the CloseProxy handler: a
                            // health-closed XTCP provider must not leave its
                            // in-flight P2P bridge + UDP socket running.
                            let mut tokens = self.p2p_bridge_tokens.lock().await;
                            if let Some(token) = tokens.remove(&proxy_name) {
                                token.cancel();
                            }
                            // Set phase to CheckFailed before sending CloseProxy
                            // (Go frp compat: PhaseCheckFailed is an explicit state in proxy lifecycle).
                            {
                                let mut map = self.proxy_info_map.write().await;
                                if let Some(info) = map.get_mut(&proxy_name) {
                                    info.phase = ProxyPhase::CheckFailed;
                                }
                            }
                            let close = FrpMessage::CloseProxy(msg::CloseProxy {
                                proxy_name: proxy_name.clone(),
                            });
                            if let Err(e) = writer.send(close, ctx.v2) {
                                warn!(proxy_name = %proxy_name, error = %e, "Failed to send CloseProxy for {}: {}", proxy_name, e);
                            }
                            // Keep health check running -- monitor for recovery (Go frp compat).
                        }
                        HealthEvent::Recover(proxy_name) => {
                            info!(proxy_name = %proxy_name, "Health check recovered for '{}', re-registering", proxy_name);
                            // Look up proxy config and send NewProxy to re-register.
                            let need_send = {
                                let configs = self.health_proxy_configs.lock().await;
                                configs.get(&proxy_name).cloned()
                            };
                            if let Some(cfg) = need_send {
                                let local_addr = self.proxy_info_map.read().await
                                    .get(&proxy_name)
                                    .map(|info| info.local_addr.clone())
                                    .unwrap_or_else(|| format!("{}:{}", cfg.local_ip, cfg.local_port));
                                // Set phase to WaitStart so NewProxyResp handler
                                // transitions it to Running on success (Go frp compat:
                                // CheckFailed -> re-register -> Running).
                                {
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&proxy_name) {
                                        info.phase = ProxyPhase::WaitStart;
                                    }
                                }
                                let new_proxy = crate::proxy::create_new_proxy_msg(&cfg, &local_addr, &ctx.cfg_user);
                                if let Err(e) = writer.send(new_proxy, ctx.v2) {
                                    warn!(proxy_name = %proxy_name, error = %e, "Failed to re-register proxy on health recovery: {}", e);
                                } else {
                                    info!(proxy_name = %proxy_name, "Health recovery: re-registered proxy '{}'", proxy_name);
                                }
                            } else {
                                warn!(proxy_name = %proxy_name, "Health check recovered but no config found for '{}'", proxy_name);
                            }
                        }
                    }
                }

                Some(req) = channels.reload_rx.recv() => {
                    let result = match &self.config_file {
                        Some(path) => self.try_reload(path, req.strict, &writer).await,
                        None => Err("no config file path stored".into()),
                    };
                    if result.is_ok()
                        && self.visitor_reload_needed.swap(false, Ordering::AcqRel)
                    {
                        // Visitor changes require a clean session restart.
                        tracing::info!("Visitor config changed — restarting session");
                        let _ = req.reply.send(Ok("reload success: visitor changes applied on session restart".into()));
                        return LoopExit::Reconnect;
                    }
                    let _ = req.reply.send(result);
                }

                Some(xtcp_notif) = channels.xtcp_rx.recv() => {
                    let XtcpNotification { sid, proxy_name } = xtcp_notif;
                    info!(proxy_name = %proxy_name, "XTCP provider: received NatHoleSid for '{}'", proxy_name);
                    // STUN discovery runs off the control loop: two STUN
                    // round-trips can stall up to ~10s and would block the
                    // message loop (heartbeats, work conns, reloads). The
                    // spawned task does the STUN, persists the socket, and
                    // hands the finished NatHoleClient back for the loop to
                    // write + bookkeep, preserving the write-before-NatHoleResp
                    // ordering.
                    let stun_server = channels.nat_hole_stun_server.to_string();
                    let stun_sockets = Arc::clone(&ctx.xtcp_sockets);
                    let stun_tx = ctx
                        .stun_result_tx
                        .as_ref()
                        .expect("stun_result_tx available before STUN spawn")
                        .clone();
                    tokio::spawn(async move {
                        // 1. Do STUN discovery on a persistent UDP socket.
                        //    Go frps needs ≥2 mapped addresses for NAT classification.
                        let mut mapped_addrs = Vec::new();
                        let stun_socket = match frp_core::stun::stun_binding_with_details(&stun_server).await {
                            Ok((sock, result1)) => {
                                let addr1 = result1.mapped_addr;
                                debug!(addr = %addr1, "XTCP STUN #1: {}", addr1);
                                mapped_addrs.push(addr1);
                                // Use OTHER-ADDRESS as second STUN target if available
                                // (Go frp v0.70 discovery.go:137 dual-server probing).
                                // This gives the server a second mapped address for NAT
                                // classification (RFC 5780, detects endpoint-independent
                                // vs address-dependent mapping).
                                let second_target =
                                    result1.other_addr.as_deref().unwrap_or(&stun_server);
                                match frp_core::stun::stun_binding_on_socket(&sock, second_target).await {
                                    Ok(addr2) => {
                                        debug!(addr = %addr2, "XTCP STUN #2 from '{}': {}", second_target, addr2);
                                        // Go frps NAT classifier needs ≥2 addresses.
                                        // Always push — Go frp doesn't dedup.
                                        mapped_addrs.push(addr2);
                                    }
                                    Err(e) => warn!(error = %e, "XTCP STUN #2 failed: {}", e),
                                }
                                Some(sock)
                            }
                            Err(e) => {
                                warn!(error = %e, "XTCP STUN failed: {}", e);
                                None
                            }
                        };
                        // Get the local port from the STUN socket for assisted_addrs.
                        // Go frp compat: assisted_addrs = local IPs + STUN port, NOT STUN
                        // mapped addresses. The server uses assisted_addrs as localIPs
                        // parameter to ClassifyNATFeature — STUN addresses would never
                        // match local interfaces, causing misclassification.
                        let local_port = stun_socket
                            .as_ref()
                            .and_then(|sock| sock.local_addr().ok())
                            .map(|addr| addr.port());
                        // Save socket for later UDP+KCP hole punch.
                        if let Some(sock) = stun_socket {
                            stun_sockets
                                .lock()
                                .await
                                .insert(sid.clone(), std::sync::Arc::new(sock));
                        }
                        // Build assisted_addrs from local IPs + STUN port.
                        // Go frp v0.69.1: ListLocalIPsForNatHole returns non-loopback
                        // IPv4 addresses filtered from all network interfaces.
                        let assisted_addrs: Option<Vec<String>> = local_port.and_then(|port| {
                            let local_ips = crate::nat_hole::list_local_ips_for_nat_hole(10);
                            if local_ips.is_empty() {
                                None
                            } else {
                                Some(
                                    local_ips
                                        .iter()
                                        .map(|ip| format!("{}:{}", ip, port))
                                        .collect(),
                                )
                            }
                        });
                        // 2. Send NatHoleClient on control (Go v0.70 compat: protocol "kcp").
                        // Use a unique transaction_id per request (Go frp compat: UUID).
                        let txn_id = uuid::Uuid::new_v4().to_string();
                        let client_msg = FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
                            transaction_id: txn_id.clone(),
                            proxy_name: proxy_name.clone(),
                            sid: Some(sid.clone()),
                            protocol: Some("kcp".to_string()),
                            mapped_addrs: if mapped_addrs.is_empty() { None } else { Some(mapped_addrs) },
                            assisted_addrs,
                            visitor_addr: None,
                        }));
                        // Hand the finished message back to the control loop.
                        if stun_tx
                            .send(StunResult { sid, proxy_name, msg: client_msg })
                            .await
                            .is_err()
                        {
                            warn!("XTCP: control loop dropped STUN result channel");
                        }
                    });
                }

                // STUN finished off-loop: write NatHoleClient on the control
                // connection and track sid→proxy_name for NatHoleResp routing.
                Some(stun_result) = ctx
                    .stun_result_rx
                    .as_mut()
                    .expect("stun_result_rx available before STUN result recv")
                    .recv() => {
                    let StunResult { sid, proxy_name, msg } = stun_result;
                    if let Err(e) = writer.send(msg, ctx.v2) {
                        warn!(error = %e, "XTCP: failed to send NatHoleClient: {}", e);
                        // The STUN socket was stored in xtcp_sockets but no
                        // pending_xtcp entry was created; reclaim it now so it
                        // does not sit until control-loop teardown.
                        ctx.xtcp_sockets.lock().await.remove(&sid);
                    } else {
                        ctx.pending_xtcp.insert(sid.clone(), proxy_name);
                        // Defensive cleanup: if the server never sends
                        // NatHoleResp for this sid, the socket + pending_xtcp
                        // entry would leak until the control loop tears down.
                        // Reclaim them after the server's NAT session window
                        // (NAT_HOLE_TIMEOUT = 10s) plus margin. If NatHoleResp
                        // arrives in time, handle_nat_hole_resp already removed
                        // both entries and these removes are no-ops.
                        let cleanup_sockets = Arc::clone(&ctx.xtcp_sockets);
                        let cleanup_tx = xtcp_cleanup_tx.clone();
                        let cleanup_sid = sid.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(15)).await;
                            cleanup_sockets.lock().await.remove(&cleanup_sid);
                            let _ = cleanup_tx.send(cleanup_sid).await;
                        });
                    }
                }

                // A NatHoleResp never arrived within the timeout window:
                // reclaim the pending provider-side entry (socket already
                // removed) and any residual visitor-side sender. `cleanup_sid`
                // carries either a provider sid or a visitor txn_id; the two
                // namespaces are independent, so reclaiming from both is
                // always safe (see reclaim_stale_xtcp_entry).
                Some(cleanup_sid) = ctx
                    .xtcp_cleanup_rx
                    .as_mut()
                    .expect("xtcp_cleanup_rx available before cleanup recv")
                    .recv() => {
                    if reclaim_stale_xtcp_entry(
                        &mut ctx.pending_xtcp,
                        &mut ctx.visitor_pending,
                        &cleanup_sid,
                    ) {
                        debug!(sid = %cleanup_sid, "XTCP: reclaimed stale entry for '{}'", cleanup_sid);
                    }
                }

                // Visitor requests: send NatHoleVisitor on control connection.
                // Go frps v0.69.1 only handles NatHoleVisitor on the control
                // connection path, not on fresh TCP connections.
                Some(vreq) = channels.visitor_rx.recv() => {
                    let txn_id = vreq.nhv.transaction_id.clone();
                    let nhv = FrpMessage::NatHoleVisitor(vreq.nhv);
                    match writer.send(nhv, ctx.v2) {
                        Ok(()) => {
                            debug!(sid = %txn_id, "Visitor: sent NatHoleVisitor on control, sid={}", txn_id);
                            ctx.visitor_pending.insert(txn_id.clone(), vreq.reply);
                            // Defensive cleanup: if the server never sends a
                            // NatHoleResp for this txn, the visitor_pending
                            // entry would otherwise sit until control-loop
                            // teardown. Reclaim it after 20s. Why 20s: the
                            // visitor side gives up after its own 15s timeout
                            // (visitor.rs), so by the time we run the
                            // receiver is already dropped and the entry is
                            // only reclaimed after the visitor stopped
                            // waiting — we never preempt a slow-but-valid
                            // response. The server's NAT session window is
                            // 10s plus network latency, well under 20s. If
                            // NatHoleResp arrives in time,
                            // handle_nat_hole_resp already removed the entry
                            // and this is a no-op.
                            let cleanup_tx = xtcp_cleanup_tx.clone();
                            let cleanup_key = txn_id.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(20)).await;
                                // Channel closed (control loop exited) — ignore.
                                let _ = cleanup_tx.send(cleanup_key).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Visitor: failed to send NatHoleVisitor on control: {}", e);
                            let _ = vreq.reply.send(Err(format!("send failed: {e}")));
                        }
                    }
                }

                Some(()) = channels.stop_rx.recv() => {
                    info!("Stop requested, shutting down");
                    ctx.shutdown_flag.store(true, Ordering::SeqCst);
                    return LoopExit::Shutdown;
                }

                // Heartbeat timeout watchdog: triggers reconnect if no Pong
                // received within heartbeat_timeout seconds (Go frp compat).
                // Event-driven: the persistent timer armed at the loop top
                // (hb_sleep) waits until the absolute deadline (last_pong +
                // hb_timeout_dur), so each Pong arrival re-arms it there
                // instead of rebuilding a `Sleep` per iteration. Uses sleep
                // so the timer is only active when hb_timeout > 0. Explicit
                // negative values disable it independently of tcp_mux.
                // Gated on the ping loop being active (hb_watchdog_active):
                // with heartbeat_interval <= 0 no Pong can ever arrive. Also
                // gated on hb_deadline (Some): an overflowing timeout
                // degrades the watchdog to never-fire, so its placeholder
                // timer must never be polled here.
                _ = &mut hb_sleep, if ctx.hb_watchdog_active && hb_deadline.is_some() => {
                    warn!("Heartbeat timeout ({}s), reconnecting...", ctx.hb_timeout);
                    return LoopExit::Reconnect;
                }
                // The dedicated writer task hit a write failure (peer
                // dead / connection reset on the control path). Tear down
                // and reconnect, mirroring the read-error branch.
                _ = writer.wait_failed() => {
                    warn!("Control writer failed, reconnecting...");
                    return LoopExit::Reconnect;
                }
            }
        }
    }

    /// Phase 7 of one connection attempt: tear down the session — remove
    /// vnet routes advertised by virtual_net visitors, signal the work-conn
    /// pool and visitor listeners to stop, drop the yamux handle, and wait
    /// briefly for visitor tasks to exit. Returns true when a stop was
    /// requested during the session (shutdown_flag set); run() then exits
    /// instead of reconnecting.
    async fn teardown_session(
        &self,
        ctx: &mut SessionCtx,
        #[cfg(feature = "tcp-mux")] prev_yamux: &mut Option<
            std::sync::Arc<frp_core::mux::YamuxSession>,
        >,
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
        admin_handle: &mut Option<tokio::task::JoinHandle<()>>,
    ) -> bool {
        // Clean up vnet routes advertised by virtual_net visitors before
        // dropping the control connection. The server also removes routes
        // during control teardown; this mirrors Go frp's explicit
        // VnetRouteRemove from the visitor plugin Close().
        #[cfg(feature = "vnet")]
        {
            let writer = ctx
                .writer
                .as_ref()
                .expect("writer available before teardown")
                .clone();
            // Remove OS routes learned from peers and clear their route
            // table entries so a reconnect starts from a clean slate.
            {
                let peer_routes = self.vnet_peer_routes.lock().await;
                for (proxy_name, (subnet, tun_name, vnet)) in peer_routes.iter() {
                    remove_os_route(subnet, tun_name);
                    self.vnet_controller
                        .route_table()
                        .write()
                        .await
                        .remove(vnet, proxy_name);
                }
            }
            self.vnet_peer_routes.lock().await.clear();

            let session_visitors = self.cfg.read().await.visitors.clone();
            // The VnetRouteRemove below rides the control writer channel.
            // That channel is only consumed by the dedicated writer task,
            // which is spawned with the message loop (`control_rx.take()`).
            // On the registration-abort teardown path no writer task exists,
            // so a send would enqueue into a never-consumed channel and the
            // `info!` success log would be misleading — skip it (the local
            // route removal above already ran, and the server also removes
            // routes during control teardown).
            let writer_task_active = ctx.control_rx.is_none();
            for v in &session_visitors {
                if v.plugin.as_ref().is_none() || !v.enabled {
                    continue;
                }
                if let Some(adv) = virtual_net_visitor_route_adv(v) {
                    self.vnet_controller.unregister_visitor_route(&v.name).await;
                    if !writer_task_active {
                        debug!(visitor_name = %v.name, "vnet route removal skipped (no control writer task on registration-abort teardown)");
                        continue;
                    }
                    let rem = msg::VnetRouteRemove {
                        proxy_name: adv.proxy_name,
                        virtual_net: adv.virtual_net,
                    };
                    let msg = FrpMessage::VnetRouteRemove(rem);
                    if let Err(e) = writer.send(msg, ctx.v2) {
                        warn!(visitor_name = %v.name, error = %e, "failed to remove vnet route for visitor '{}'", v.name);
                    } else {
                        info!(visitor_name = %v.name, "vnet route removed for visitor '{}'", v.name);
                    }
                }
            }
        }

        // Go frp GracefulClose ordering: close proxies first, then visitors,
        // then the control connection. See /tmp/frp-source/client/control.go:203-210.
        // Step 1: Signal work connection pool to stop replenishment cascade.
        ctx.session_alive.store(false, Ordering::Release);

        // Step 2: Abort this session's work-conn tasks. Standalone work
        // conns (tcp/ws/kcp/quic-direct dial, tcp_mux off) own their own
        // connection to the server and would otherwise keep bridging until
        // a socket error — the orphaned-connection leak Go frp avoids by
        // closing work conns on control close (workConnManager.Close); on
        // reconnect each one lived until the peer timed it out. Under
        // tcp-mux the tasks are yamux streams on the session dropped in
        // step 4, but aborting them is also correct: it is an ordinary
        // stream close, and it releases the YamuxSession Arc clones that
        // would otherwise keep the yamux driver alive past teardown. Abort
        // is immediate; await so the sockets are closed before the next
        // session's dials.
        let mut work_conn_handles = std::mem::take(&mut ctx.work_conn_handles);
        if !work_conn_handles.is_empty() {
            debug!(
                count = work_conn_handles.len(),
                "Aborting work-conn tasks at session teardown"
            );
            for h in &work_conn_handles {
                h.abort();
            }
            // Abort only lands at the task's next await point; bound the
            // join so teardown can never hang on a stuck task (same
            // pattern as shutdown_visitor_tasks). On timeout, report the
            // stragglers and continue — the aborted tasks finish on their
            // own.
            let joined = tokio::time::timeout(
                Duration::from_secs(5),
                futures_util::future::join_all(work_conn_handles.iter_mut()),
            )
            .await;
            if joined.is_err() {
                let unfinished = work_conn_handles
                    .iter()
                    .filter(|h| !h.is_finished())
                    .count();
                warn!(
                    count = unfinished,
                    "Work-conn teardown timed out after 5s; continuing without waiting for unfinished task(s)"
                );
            }
        }

        // Step 3: Signal visitor listeners to stop accepting new connections
        // (Go frp compat: vm.Close() closes all visitors before session is torn down).
        ctx.visitor_shutdown
            .as_ref()
            .expect("visitor_shutdown available before teardown")
            .store(true, Ordering::Release);

        // Step 4: Drop the control connection (Go frp compat: closeSession()).
        // Dropping prev_yamux closes the underlying TCP socket so the background
        // yamux task exits before we attempt to reconnect. This prevents
        // dual-yamux-session leaks through a half-open TCP mux connection.
        #[cfg(feature = "tcp-mux")]
        drop(prev_yamux.take());

        // Step 5: Abort the control writer task. This must come after the
        // vnet route-removal sends above (they ride the writer channel, so
        // the writer must still be alive to drain them) and after dropping
        // the yamux session. On the tcp-mux path dropping prev_yamux already
        // closed the socket, so the writer exits on its own and this abort is
        // a no-op or immediate. On tcp_mux=false the raw write half lives
        // only inside the writer task: against a wedged-but-alive peer
        // (zero-window TCP that ACKs keepalive/window probes, or no-mux KCP
        // with no dead-conn detection) write_msg would block forever and
        // nothing else can close the socket — aborting the task drops the
        // write half (and the fd) instead of leaking one task+fd per
        // reconnect cycle.
        let control_writer_handle = std::mem::take(&mut ctx.control_writer_handle);
        if let Some(handle) = control_writer_handle {
            handle.abort();
            // Abort only lands at the task's next await point; bound the
            // join so teardown can never hang on a stuck writer (same
            // pattern as the work-conn abort above). On timeout the aborted
            // task finishes on its own — the write half it owns is dropped
            // the moment the abort takes effect.
            let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
            if joined.is_err() {
                warn!("Control writer teardown timed out after 5s; continuing without waiting for the writer task");
            }
        }

        // Wait briefly for visitor tasks to notice the shutdown signal and
        // exit gracefully (timeout so we never block reconnection).
        // Any listener still blocked in accept() after the grace period is
        // force-aborted so the bind port is released for the next session.
        self.shutdown_visitor_tasks(std::mem::take(&mut ctx.visitor_handles))
            .await;

        // Check if admin stop was requested
        if ctx.shutdown_flag.load(Ordering::SeqCst) {
            info!("frpc shutting down");
            // Cancel health check tasks and abort the admin HTTP server
            // before returning. Both are detached tokio tasks; without
            // this they keep running after run() exits (holding bind
            // ports and channels until process exit).
            self.cancel_detached_tasks(health_cancels, admin_handle.take())
                .await;
            return true;
        }
        false
    }

    /// Spawn a work connection in response to a ReqWorkConn message from the
    /// server (pool pre-warm sent right after LoginResp, NewVisitorConn acks,
    /// and on-demand requests — handled in the registration read loop and the
    /// message loop). Go frp compat: work connections are created ONLY in
    /// response to ReqWorkConn messages; pool_count is sent to the server via
    /// Login so it knows how many ReqWorkConn messages to issue, and the
    /// client never eagerly spawns pool connections.
    fn handle_req_work_conn(&self, ctx: &mut SessionCtx) {
        // Go frp v0.70.1 spawns each ReqWorkConn handler asynchronously
        // with no client-side in-flight cap (client/control.go:
        // handleReqWorkConn). Spawn directly so a burst of requests
        // cannot overflow a queue or tear down the control session;
        // each work conn's dial/StartWorkConn read is still bounded by
        // its own timeout in work_conn.rs.
        debug!("Received ReqWorkConn, spawning work connection");
        #[cfg(feature = "quic")]
        let quic_arg = ctx.quic_conn.clone();
        #[cfg(not(feature = "quic"))]
        let quic_arg = ();
        let handle = crate::work_conn::spawn_work_conn(crate::work_conn::WorkConnConfig {
            server_addr: ctx.wc_server_addr.clone(),
            server_port: ctx.wc_server_port,
            protocol: ctx.protocol.clone(),
            run_id: ctx.run_id.clone(),
            proxy_info_map: self.proxy_info_map.clone(),
            enc_key: self.encryption_key,
            pool_id: -1,
            auth_cfg: self.auth_cfg.clone(),
            tls_enable: ctx.wc_tls_enable,
            tls_server_name: ctx.wc_tls_server_name.clone(),
            tls_ca_file: ctx.wc_tls_ca_file.clone(),
            tls_cert_file: ctx.wc_tls_cert_file.clone(),
            tls_key_file: ctx.wc_tls_key_file.clone(),
            dns_server: ctx.wc_dns_server.clone(),
            yamux: ctx.yamux.clone(),
            quic_conn: quic_arg,
            v2: ctx.v2,
            oidc_client: self.oidc_client.clone(),
            udp_packet_size: ctx.wc_udp_packet_size,
            proxy_metrics: self.proxy_metrics.clone(),
            client_auth_scopes: ctx.client_scopes.clone(),
            server_auth_scopes: ctx.server_scopes.clone(),
            disable_custom_tls_first_byte: ctx.wc_disable_custom_tls_first_byte,
            keepalive_secs: ctx.wc_keepalive_secs,
            bind_addr: ctx.wc_bind_addr.clone(),
            proxy_url: ctx.wc_proxy_url.clone(),
            dial_timeout_secs: ctx.wc_dial_timeout_secs,
            xtcp_tx: self.xtcp_tx.clone(),
            session_alive: ctx.session_alive.clone(),
            udp_packet_codec: ctx.wc_udp_packet_codec.clone(),
            spawned_counter: None,
            #[cfg(feature = "vnet")]
            vnet_tuns: self.vnet_tuns.clone(),
            #[cfg(feature = "vnet")]
            vnet_controller: self.vnet_controller.clone(),
            #[cfg(feature = "vnet")]
            vnet_tun_tx: self.vnet_tun_tx.clone(),
        });
        // Track the task so teardown can abort it: a standalone work conn
        // owns its own connection to the server and must not outlive the
        // session (Go frp closes work conns on control close via
        // workConnManager).
        //
        // Reap finished handles here too, or a long-lived session
        // accumulates one entry per ReqWorkConn (idle pool churn: ~1
        // handle per pool slot per 10s; they would otherwise only free at
        // teardown). The sweep runs before the push, so the just-spawned
        // handle is never removed.
        ctx.work_conn_handles.retain(|h| !h.is_finished());
        ctx.work_conn_handles.push(handle);
    }

    /// Spawn per-proxy health check tasks (once, outside reconnect loop).
    /// Reads local address from proxy_info_map to determine what to check.
    /// `user` is explicit: during a reload the caller passes the NEW user
    /// (self.cfg is only refreshed at the end of try_reload), so the tasks
    /// and their health_cancels/health_proxy_configs keys match the wire
    /// names the reload registers.
    async fn spawn_health_checks(
        &self,
        user: &str,
        proxies: &[frp_core::config::ProxyConfig],
        health_tx: &mpsc::Sender<HealthEvent>,
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
        session_gen: &Arc<AtomicU64>,
    ) {
        for p in proxies {
            let wn = wire_proxy_name(user, &p.name);
            // Go parity gate (health_check_monitored): monitor only when a
            // health type is configured AND local_port > 0. A plugin proxy
            // (local_port == 0) with a health config is never monitored —
            // its "listener" is the plugin socket, which never answers the
            // probe protocol.
            if !health_check_monitored(p) {
                continue;
            }
            let hc_type = p.health_check_type.clone();
            if hc_type != "tcp" && hc_type != "http" {
                warn!(health_check_type = %hc_type, proxy_name = %p.name, "Health check type '{}' not yet supported for '{}'", hc_type, p.name);
                continue;
            }
            let la = self
                .proxy_info_map
                .read()
                .await
                .get(&wn)
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let pn = wn.clone();
            // Round 10 (MEDIUM, Go parity): Go only substitutes defaults when
            // the configured value is <= 0 (health.go:57-64; the fields are
            // u64 here, so a negative config fails deserialization up front).
            // `.max(N)` silently rewrote an explicit 1-9s value, so an
            // operator asking for fast 2s checks got 10s instead.
            let interval =
                std::time::Duration::from_secs(if p.health_check_interval_seconds == 0 {
                    10
                } else {
                    p.health_check_interval_seconds
                });
            let timeout = std::time::Duration::from_secs(if p.health_check_timeout_seconds == 0 {
                3
            } else {
                p.health_check_timeout_seconds
            });
            let max_failed = if p.health_check_max_failed == 0 {
                1
            } else {
                p.health_check_max_failed
            };
            let tx = health_tx.clone();
            let hc_url = if hc_type == "http" {
                let url = p.health_check_url.clone();
                if !url.contains("://") {
                    // Go frp compat: auto-construct URL as
                    // "http://{local_ip}:{local_port}/{path}" (Go
                    // proxy_wrapper.go:125 JoinHostPort + health.go:68-76).
                    // An empty path config means "/" (Go health.go:68-76
                    // checks the bare address) — and build_health_check_url
                    // brackets literal IPv6, where the old split(':') here
                    // mangled unbracketed "::1:8080" into "http://:/path".
                    crate::health::build_health_check_url(&la, &url)
                } else {
                    url
                }
            } else {
                String::new()
            };
            let hc_headers = p.health_check_http_headers.clone();
            let cancel = Arc::new(AtomicBool::new(false));
            {
                let mut cancels = health_cancels.lock().await;
                cancels.insert(pn.clone(), cancel.clone());
            }
            let session_gen = session_gen.clone();
            tokio::spawn(async move {
                crate::health::run_health_check(crate::health::HealthCheckConfig {
                    proxy_name: pn,
                    local_addr: la,
                    check_type: hc_type,
                    check_url: hc_url,
                    hc_headers,
                    interval,
                    timeout,
                    max_failed,
                    health_tx: tx,
                    cancel,
                    session_gen,
                })
                .await;
            });
        }
    }

    /// Cancel health check tasks and abort the admin HTTP server before
    /// run() returns. Both are detached tokio tasks; without this they keep
    /// running after run() exits (holding bind ports and channels until
    /// process exit).
    async fn cancel_detached_tasks(
        &self,
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
        admin_handle: Option<tokio::task::JoinHandle<()>>,
    ) {
        {
            let mut cancels = health_cancels.lock().await;
            for cancel in cancels.values() {
                cancel.store(true, Ordering::Relaxed);
            }
            cancels.clear();
        }
        #[cfg(feature = "admin")]
        if let Some(admin) = admin_handle {
            admin.abort();
        }
        // Non-admin builds never read the handle; keep the parameter used so
        // the no-admin compile stays warning-free.
        #[cfg(not(feature = "admin"))]
        let _ = admin_handle;
    }

    /// Start the admin HTTP server if configured.
    /// Spawns as a background task; returns its JoinHandle (None when the
    /// admin server is not configured).
    #[cfg(feature = "admin")]
    async fn spawn_admin_server(
        &self,
        reload_tx: &mpsc::Sender<ReloadRequest>,
        stop_tx: &mpsc::Sender<()>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let cfg_snapshot = self.cfg.read().await.clone();
        if cfg_snapshot.web_server.port > 0 {
            let admin_addr = frp_core::format_socket_addr(
                &cfg_snapshot.web_server.addr,
                cfg_snapshot.web_server.port,
            );
            // Seed the admin config GET's dedup cell with the answer the startup
            // load just reported, so a GET does not repeat that record — and, the
            // reason it is seeded rather than left at `NO_BASELINE`, so a
            // hand-edit that *adds* `[web_server.tls] enable` **after the admin
            // server has started** is still reported (the seed recorded
            // "absent"). An edit landing between the startup load and this spawn
            // is baselined instead, because the seed reads the file only here.
            // Best-effort: an unreadable file leaves `NO_BASELINE`, and the first
            // GET then baselines silently. See
            // `crate::admin::seed_web_server_tls_enable_seen`.
            let seeded = crate::admin::seed_web_server_tls_enable_seen(self.config_file.as_deref());
            let admin_state = AdminState {
                proxy_metrics: self.proxy_metrics.clone(),
                proxies: self.proxy_info_map.clone(),
                reload_tx: reload_tx.clone(),
                stop_tx: stop_tx.clone(),
                config_path: self.config_file.clone(),
                store: self.store_source.clone(),
                web_server_tls_enable_seen: Arc::new(std::sync::atomic::AtomicU8::new(seeded)),
            };
            let admin_auth_user = cfg_snapshot.web_server.user.clone();
            let admin_auth_pwd = cfg_snapshot.web_server.password.clone();
            let admin_tls_cert = if cfg_snapshot.web_server.tls_cert().is_empty() {
                None
            } else {
                Some(cfg_snapshot.web_server.tls_cert().to_string())
            };
            let admin_tls_key = if cfg_snapshot.web_server.tls_key().is_empty() {
                None
            } else {
                Some(cfg_snapshot.web_server.tls_key().to_string())
            };
            let handle = tokio::spawn(async move {
                if let Err(e) = crate::admin::run_admin_server(
                    admin_addr,
                    admin_state,
                    admin_auth_user,
                    admin_auth_pwd,
                    admin_tls_cert,
                    admin_tls_key,
                )
                .await
                {
                    tracing::error!(error = %e, "frpc admin server failed: {}", e);
                }
            });
            info!(addr = %cfg_snapshot.web_server.addr, port = %cfg_snapshot.web_server.port, "frpc admin server starting on {}:{}", cfg_snapshot.web_server.addr, cfg_snapshot.web_server.port);
            Some(handle)
        } else {
            None
        }
    }
}
/// Whether a session that stayed up for at least `healthy_duration` warrants
/// resetting the consecutive-error count before the next reconnect backoff.
///
/// A long-healthy session followed by an occasional blip must reconnect from
/// Phase 1 (fast retry) instead of the 20s exponential cap — Go frp's
/// FastBackoffManager only counts consecutive failures. Sessions shorter than
/// the healthy duration keep their error count so the backoff cap is
/// preserved across rapid reconnects.
///
/// Pure decision (no clock reads) so the 5-minute production window can be
/// unit-tested without wall-clock sleeps; the call site supplies `now` and
/// the production healthy duration.
fn healthy_resets_error_count(
    consecutive_err_count: u32,
    last_session_start: Option<Instant>,
    now: Instant,
    healthy_duration: Duration,
) -> bool {
    consecutive_err_count > 0
        && last_session_start.is_some_and(|start| now.duration_since(start) > healthy_duration)
}

/// Reclaim a stale XTCP entry whose NatHoleResp never arrived in time.
///
/// `key` carries two independent namespaces: it is a provider-side NAT session
/// id (`sid`) in `pending_xtcp`, and a visitor transaction id (`txn_id`) in
/// `visitor_pending`. Because the two maps are independent, attempting to
/// remove the key from both is always safe — whichever map actually held the
/// entry is cleaned, the other remove is a no-op. If a residual visitor sender
/// is found, it is notified with a timeout error; this is usually a no-op too,
/// since the visitor already timed out at 15s and dropped its receiver, but it
/// covers the window where the visitor has not timed out yet.
///
/// Returns true if any entry was removed from either map.
pub(crate) fn reclaim_stale_xtcp_entry(
    pending_xtcp: &mut HashMap<String, String>,
    visitor_pending: &mut HashMap<String, oneshot::Sender<Result<msg::NatHoleResp, String>>>,
    key: &str,
) -> bool {
    let mut removed = pending_xtcp.remove(key).is_some();
    if let Some(tx) = visitor_pending.remove(key) {
        let _ = tx.send(Err("NatHoleResp timeout: server did not respond".into()));
        removed = true;
    }
    removed
}

// The registration-frame plumbing and `register_proxies` live in a child
// module (`service/registration.rs`). Nothing here or elsewhere in the crate
// names those items by path, so no re-export is needed; `register_proxies`
// carries `pub(super)` because a private method declared in a child module is
// not visible to this module (E0624) and `service/tests.rs` calls it too.
mod registration;
mod reload_apply;
#[cfg(test)]
mod tests;

// The reload entry points live in a child module. `filter_active_proxies`/
// `filter_active_visitors` are re-exported because `crate::service::filter_active_
// {proxies,visitors}` is the spelled path at `store.rs:592` and at this file's own
// startup/message-loop call sites; `reload_apply` is private, so without the
// re-export those two names would be unreachable from here. `pub(crate)` matches
// the functions' original visibility — it does not widen it. Nothing outside
// `service.rs` names the other four moved items.
pub(crate) use reload_apply::{filter_active_proxies, filter_active_visitors};
