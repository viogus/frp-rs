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
/// (TODO.md:9850). A duplicated literal in either place is what this constant
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

// The control-channel message loop lives in a child module
// (`service/message_loop.rs`). `run_message_loop` carries `pub(super)`
// because a private method declared in a child module is not visible to this
// module (E0624) and `run()` calls it here; `LoopExit`, `SessionChannels` and
// `StunResult` carry `pub(super)` for the same reason — this module names the
// return type it matches on, the `SessionChannels` literal at the call site,
// and `SessionCtx`'s STUN sender/receiver field types. `SessionChannels`' seven
// fields are `pub(super)` because that literal is built by field name here, and
// a struct visible to a module does not expose its private fields (E0451).
// None needs a re-export: nothing outside `service` names them. The retry
// statics stay inside `message_loop.rs`, which holds all of their references.
mod message_loop;
use message_loop::{LoopExit, SessionChannels, StunResult};

// The session lifecycle (P2 S4) lives in a child module (`service/session.rs`).
// `shutdown_visitor_tasks` and `teardown_session` carry `pub(super)` because a
// private method declared in a child module is not visible to this module
// (E0624) and `service/tests.rs` drives both; `run` and `request_stop` keep
// their original `pub` token and nothing else needed a visibility change. No
// re-export: no file outside `service` names any of the eight moved items.
mod session;

// The health-check plumbing (P2 S5) lives in a child module
// (`service/health.rs`). All three items carry `pub(super)` — `service` itself
// calls `health_check_monitored`, `registration.rs`/`reload_apply.rs` call it
// through their existing `use super::*;`, `reload_apply.rs` calls
// `spawn_health_checks` by method-call syntax, and `tests.rs` calls
// `healthy_resets_error_count`. The parent imports the two free functions
// with a private `use` because the sibling modules and `tests.rs` still spell
// them unqualified; a private `use` in this module is visible to `service` and
// its descendants, which is exactly their original reach.
mod health;
use health::{health_check_monitored, healthy_resets_error_count};
