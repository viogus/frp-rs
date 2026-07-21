use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(feature = "dashboard")]
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use frp_core::auth::{AuthConfig, OidcVerifier};
use frp_core::metrics::ProxyMetricsRegistry;
use frp_core::transport::IoStream;

use crate::nathole::controller::Controller;
use crate::proxy::ProxyManager;
use crate::registry::ClientRegistry;
use crate::tcpmux::TcpMuxManager;
use crate::vhost::VhostManager;

#[cfg(feature = "vnet")]
type VnetRouteMap = Arc<RwLock<HashMap<(String, String), (String, String)>>>;

// ---------------------------------------------------------------
// Shared state for cross-task communication
// ---------------------------------------------------------------

#[derive(Debug)]
pub enum InternalMsg {
    NewWorkConn(IoStream),
    VisitorConn {
        proxy_name: String,
        visitor_conn: IoStream,
    },
    ProxyUserConn {
        proxy_name: String,
        user_conn: IoStream,
        pre_read: Vec<u8>,
    },
    /// UDP proxy needs a work connection for data forwarding
    /// (Go frp v0.69.1 uses work connections, not control connection).
    UdpNeedsWorkConn {
        proxy_name: String,
    },
    /// Sent when a new control connection claims the same run_id.
    /// The old handler should stop listening and clean up.
    /// The `done` oneshot is signaled after cleanup completes,
    /// allowing the new handler to wait for handoff.
    Shutdown {
        done: tokio::sync::oneshot::Sender<()>,
    },
    // NatHoleClient variant removed — dead code. Go frp compat uses
    // NatHoleSidOnWorkConn path (server is pure relay, provider does STUN).
    /// Send NatHoleSid to provider on a work connection (Go frp v0.69.1 XTCP compat).
    /// The server writes NatHoleSid on a pooled work connection to notify
    /// the provider that a new XTCP visitor has arrived. The provider then
    /// does its own STUN discovery and sends NatHoleClient back on the
    /// control connection with its mapped addresses.
    NatHoleSidOnWorkConn {
        sid: String,
        proxy_name: String,
    },
    /// Forward NatHoleSid to visitor via control channel (Go frp compat).
    WriteNatHoleSid {
        sid: String,
    },
    /// Forward NatHoleReport to visitor via control channel (Go frp compat).
    WriteNatHoleReport {
        sid: String,
    },
    /// Forward NatHoleResp to visitor via control channel (Go frp XTCP compat).
    /// Carries provider's candidate/assisted addresses for NAT traversal.
    WriteNatHoleResp {
        transaction_id: String,
        error: Option<String>,
        sid: Option<String>,
        protocol: Option<String>,
        candidate_addrs: Option<Vec<String>>,
        assisted_addrs: Option<Vec<String>>,
    },
    /// Send a CloseProxy message to the client via its control channel.
    /// Used by the dashboard delete API to notify the client to shut
    /// down its proxy listener.
    WriteCloseProxy {
        proxy_name: String,
    },
    /// Forward a vnet IP packet to a target client's control handler.
    #[cfg(feature = "vnet")]
    VnetPacketForward {
        proxy_name: String,
        data: String, // base64-encoded IP packet
    },
}

/// Per-client pool statistics, shared between the control handler
/// and Prometheus scrape / admin API threads.
#[derive(Debug, Default)]
pub struct PoolStats {
    pub pool_size: AtomicI64,
    pub pending_requests: AtomicI64,
}

#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::Sender<InternalMsg>,
    pub client_addr: Option<SocketAddr>,
    pub login_time: Instant,
    /// Absolute Unix epoch timestamp of login, for dashboard v2 API.
    pub login_time_unix: i64,
    pub pool_stats: Arc<PoolStats>,
    pub user: String,
    /// Monotonically increasing control generation ID.
    /// Distinguished old vs new control connections with the same run_id.
    pub control_id: u64,
}

/// Hot-reloadable server configuration subset, updated atomically on SIGUSR1.
#[derive(Debug, Clone)]
pub struct ReloadableState {
    pub auth_cfg: Arc<AuthConfig>,
    pub encryption_key: [u8; 16],
    pub allow_ports: Vec<(u16, u16)>,
    pub additional_auth_scopes: Vec<String>,
}

/// Aggregate work-conn pool metrics, read by Prometheus / admin API.
#[derive(Debug, Default)]
pub struct PoolMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub drops: AtomicU64,
    /// Idle timeout for pooled work conns. `Duration::ZERO` = disabled.
    pub idle_timeout: Duration,
}

/// OIDC verification state.
pub struct OidcState {
    pub verifier: Option<Arc<OidcVerifier>>,
    pub subjects: Arc<RwLock<HashMap<String, String>>>,
}

/// XTCP NAT-hole-punch coordination state.
pub struct XtcpState {
    pub nat_hole: Arc<Controller>,
    /// Key: `proxy_name` (unique per ProxyManager — no collision when
    /// multiple STCP/XTCP proxies share the same secret key).
    /// Value: `raw_sk` — used for fallback auth during the
    /// NewVisitorConn-before-registration race window.
    pub sk_index: Arc<RwLock<HashMap<String, String>>>,
}

/// Token bucket rate limiter for connection accept loops.
/// Uses f64 token accounting — zero allocation per check.
pub struct RateLimiter {
    rate: f64,   // tokens per second; 0.0 = unlimited
    tokens: f64, // current token balance (max: burst)
    burst: f64,  // max tokens that can accumulate
    last_refill: Instant,
}

impl RateLimiter {
    /// `max_per_sec`: 0 = unlimited. Burst = min(max_per_sec, 1024).
    pub fn new(max_per_sec: u32) -> Self {
        let rate = max_per_sec as f64;
        Self {
            rate,
            tokens: if rate > 0.0 { rate.min(1024.0) } else { 0.0 },
            burst: rate.min(1024.0),
            last_refill: Instant::now(),
        }
    }

    /// Configured rate in tokens per second (0 = unlimited).
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Try to consume one token. Returns `Ok(())` if allowed, or the
    /// duration to wait before a token becomes available.
    pub fn try_acquire(&mut self) -> Result<(), Duration> {
        if self.rate == 0.0 {
            return Ok(());
        }
        let now = Instant::now();
        let elapsed = (now - self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Time until one token refills
            let wait = Duration::from_secs_f64((1.0 - self.tokens) / self.rate);
            Err(wait)
        }
    }
}

pub struct AppState {
    pub proxy_manager: Arc<ProxyManager>,
    /// Hot-reloadable config (auth, encryption, allow_ports).
    /// Uses std::sync::RwLock — blocking read has no async overhead.
    /// Writes only happen on SIGUSR1 reload (vanishingly rare).
    pub reloadable: Arc<std::sync::RwLock<ReloadableState>>,
    pub used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    pub run_id_to_ctl_tx: Arc<RwLock<HashMap<String, ControlTx>>>,
    /// Client registry tracking connected frpc instances with metadata.
    pub client_registry: Arc<ClientRegistry>,
    /// Monotonically increasing counter for control generation IDs.
    pub control_id_counter: AtomicU64,
    /// Per-runID mutex for serializing control lifecycle transitions
    /// (Add/Activate/completeLogin/Remove). Inherited from old to new control
    /// to prevent concurrent lifecycle operations for the same run_id.
    pub run_mu_map: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    pub proxy_bind_addr: String,
    pub vhost_manager: Arc<VhostManager>,
    pub vhost_http_port: u16,
    pub xtcp: XtcpState,
    pub oidc: OidcState,
    pub dashboard_start: std::time::Instant,
    pub sub_domain_host: String,
    pub tcp_mux: bool,
    pub tcp_mux_keepalive: i64,
    pub heartbeat_timeout: i64,
    pub udp_packet_size: usize,
    pub tls_only: bool,
    /// Shared UDP port for SUDP proxies. When > 0, all SUDP proxies
    /// use this port instead of their individual remote_port.
    pub sudp_port: u16,
    pub vhost_http_timeout: u64,
    pub user_conn_timeout: u64,
    pub tcp_mux_passthrough: bool,
    /// Custom 404 page body (HTML) from WebServerConfig.
    pub custom_404_page: String,
    /// Server-side HTTP plugin manager for lifecycle hooks.
    pub plugin_manager: Arc<crate::plugin::HttpPluginManager>,
    /// In-memory store for proxy configs submitted via dashboard Store API.
    pub proxy_config_store: Arc<RwLock<HashMap<String, frp_core::config::ProxyConfig>>>,
    /// Path to the JSON store file for proxy_config_store persistence.
    pub store_path: Option<std::path::PathBuf>,
    /// TCPMux HTTP CONNECT route table (domain → proxy mapping).
    pub tcpmux_manager: Arc<TcpMuxManager>,
    /// Per-proxy traffic metrics for dashboard API.
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
    /// Per-client proxy count limit. 0 = unlimited.
    pub max_ports_per_client: u64,
    /// When false (default), internal error details are not sent to clients.
    pub detailed_errors_to_client: bool,
    /// Shared TLS acceptor for hot-reload. Cert renewal tools (certbot, cert-manager)
    /// replace cert files in-place — periodic poll detects mtime changes and swaps
    /// this acceptor atomically. SIGUSR1 reload also swaps when cert paths change.
    #[cfg(feature = "tls")]
    pub tls_acceptor: Arc<std::sync::RwLock<Option<tokio_rustls::TlsAcceptor>>>,
    /// Semaphore to limit concurrent connections. None = unlimited.
    pub conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Token bucket rate limiter for the accept loop.
    /// Limits connections-per-second across all listeners.
    pub accept_rate_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    /// Per-IP failed login attempt counter: IP -> (count, window_start).
    /// Window resets after 60 seconds. Max 5 failed attempts per window.
    pub login_throttle: Arc<
        tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
    >,
    /// Timestamp-indexed run_id set for replay attack detection.
    ///
    /// Key: Unix timestamp (seconds). Value: set of run_ids that logged in
    /// at that timestamp. Duplicate (run_id, ts) pairs within the freshness
    /// window are rejected as replay attacks.
    ///
    /// Cleanup uses `BTreeMap::split_off` (O(log n)) instead of a full
    /// `HashSet::retain` scan (O(n)), avoiding lock-hold latency under
    /// heavy reconnect churn.
    ///
    /// Memory bound: at `R` logins/sec and default 15s timeout, ~15·R entries,
    /// or ~1,500 entries (~60 KB) at 100 QPS.
    /// Protected by a tokio::sync::Mutex (async-safe).
    pub used_timestamps: tokio::sync::Mutex<std::collections::BTreeMap<i64, HashSet<String>>>,
    /// CancellationToken for graceful shutdown. Cancelled on SIGTERM/SIGINT.
    /// Main accept loop and control handlers watch this to stop accepting new
    /// connections while letting existing bridge tasks drain.
    pub shutdown_token: CancellationToken,
    /// Active bridge connection counter. Incremented when a bridge task starts,
    /// decremented when it completes. The drain phase polls this counter.
    pub active_connections: AtomicU64,
    /// Aggregate work-conn pool metrics (hits/misses/drops/idle_timeout).
    /// Updated atomically from control handlers, read by Prometheus /admin API.
    pub pool: PoolMetrics,
    /// Immutable snapshot of server config fields exposed via dashboard v2 API.
    /// Captured at startup; not affected by reload. Go frp v0.70.0 compat.
    pub server_config_snapshot: frp_core::config::ServerConfigSnapshot,
    /// Virtual network routing table: (virtual_net, subnet) → (run_id, proxy_name).
    /// Populated by VnetRouteAdvertise messages, used to forward VnetPacket.
    #[cfg(feature = "vnet")]
    pub vnet_routes: VnetRouteMap,
    /// Broadcast channel for admin WebSocket event stream.
    /// Capacity 1024 — each event is ~200 bytes JSON (max ~200 KiB).
    /// Slow clients get `Lagged` and receive a synthetic Error event
    /// telling them to re-sync via the REST API.
    #[cfg(feature = "dashboard")]
    pub event_tx: broadcast::Sender<crate::event::ServerEvent>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_cfg: AuthConfig,
        proxy_bind_addr: String,
        encryption_key: [u8; 16],
        allow_ports: Vec<(u16, u16)>,
        sub_domain_host: String,
        tcp_mux: bool,
        tcp_mux_keepalive: i64,
        heartbeat_timeout: i64,
        udp_packet_size: usize,
        tls_only: bool,
        oidc_verifier: Option<Arc<OidcVerifier>>,
        sudp_port: u16,
        vhost_http_timeout: u64,
        user_conn_timeout: u64,
        tcp_mux_passthrough: bool,
        custom_404_page: String,
        plugin_manager: Arc<crate::plugin::HttpPluginManager>,
        max_ports_per_client: u64,
        nat_hole_analysis_data_reserve_hours: u64,
        detailed_errors_to_client: bool,
        max_connections: usize,
        max_accept_rate: u32,
        server_config_snapshot: frp_core::config::ServerConfigSnapshot,
    ) -> Self {
        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            reloadable: Arc::new(std::sync::RwLock::new(ReloadableState {
                auth_cfg: Arc::new(auth_cfg.clone()),
                encryption_key,
                allow_ports,
                additional_auth_scopes: auth_cfg.additional_auth_scopes.clone(),
            })),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            run_id_to_ctl_tx: Arc::new(RwLock::new(HashMap::new())),
            client_registry: Arc::new(ClientRegistry::new()),
            control_id_counter: AtomicU64::new(1),
            run_mu_map: Arc::new(std::sync::Mutex::new(HashMap::new())),
            proxy_bind_addr,
            vhost_manager: Arc::new(VhostManager::new()),
            vhost_http_port: 0, // set by Service::run() before starting listeners
            dashboard_start: std::time::Instant::now(),
            xtcp: XtcpState {
                nat_hole: Arc::new(Controller::new(Duration::from_secs(
                    nat_hole_analysis_data_reserve_hours.saturating_mul(3600),
                ))),
                sk_index: Arc::new(RwLock::new(HashMap::new())),
            },
            sub_domain_host,
            tcp_mux,
            tcp_mux_keepalive,
            heartbeat_timeout,
            udp_packet_size,
            tls_only,
            oidc: OidcState {
                verifier: oidc_verifier,
                subjects: Arc::new(RwLock::new(HashMap::new())),
            },
            tcpmux_manager: Arc::new(TcpMuxManager::new()),
            proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
            max_ports_per_client,
            sudp_port,
            vhost_http_timeout,
            user_conn_timeout,
            tcp_mux_passthrough,
            custom_404_page,
            plugin_manager,
            proxy_config_store: Arc::new(RwLock::new(HashMap::new())),
            store_path: None,
            detailed_errors_to_client,
            conn_semaphore: if max_connections > 0 {
                Some(Arc::new(tokio::sync::Semaphore::new(max_connections)))
            } else {
                None
            },
            accept_rate_limiter: Arc::new(std::sync::Mutex::new(RateLimiter::new(max_accept_rate))),
            login_throttle: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            used_timestamps: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(feature = "tls")]
            tls_acceptor: Arc::new(std::sync::RwLock::new(None)),
            shutdown_token: CancellationToken::new(),
            active_connections: AtomicU64::new(0),
            pool: PoolMetrics::default(),
            #[cfg(feature = "vnet")]
            vnet_routes: Arc::new(RwLock::new(HashMap::new())),
            server_config_snapshot,
            #[cfg(feature = "dashboard")]
            event_tx: broadcast::channel(1024).0,
        }
    }

    /// Check if an IP has exceeded the login attempt throttle.
    /// Returns true if the login should be allowed, false if throttled.
    ///
    /// This method atomically checks AND reserves an attempt slot within
    /// a single lock hold. Unlike the old two-phase design, this counts ALL
    /// login attempts (both successes and failures) against the window.
    /// This is acceptable because:
    /// - A successful login means the attacker knew the token — they don't
    ///   need to brute-force.
    /// - The 60s window means even a legitimate frpc restart-loop (6+
    ///   reconnects/minute) self-throttles briefly then recovers.
    /// - Counting failures-only (old design) had a TOCTOU race: concurrent
    ///   attackers all passed the check before any reached the increment.
    ///
    /// Max 5 attempts per 60-second window per IP.
    ///
    /// Also performs inline cleanup of expired entries to prevent unbounded
    /// memory growth from DDoS attacks with randomized source IPs.
    pub async fn check_login_throttle(&self, addr: std::net::SocketAddr) -> bool {
        const MAX_THROTTLE_ENTRIES: usize = 512;

        let ip = addr.ip();
        let now = std::time::Instant::now();
        let mut throttle = self.login_throttle.lock().await;

        // Cleanup: remove entries older than 90s (60s window + 30s grace).
        const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
        throttle.retain(|_, (_, window_start)| now.duration_since(*window_start) < CLEANUP_TIMEOUT);

        // Cap: refuse new entries when the map is full. Check BEFORE
        // calling entry() to avoid a borrow conflict with the mutable ref.
        if !throttle.contains_key(&ip) && throttle.len() >= MAX_THROTTLE_ENTRIES {
            return true; // Silently allow — existing entries stay throttled.
        }

        let (count, window_start) = throttle.entry(ip).or_insert((0, now));
        if now.duration_since(*window_start) > std::time::Duration::from_secs(60) {
            // Window expired — reset and allow this attempt.
            *count = 1;
            *window_start = now;
            return true;
        }
        if *count >= 5 {
            return false; // Throttled
        }
        *count += 1; // Reserve this attempt atomically
        true
    }

    /// Get or create the per-run_id serialization mutex.
    ///
    /// This mutex ensures that only one lifecycle transition (admit/activate/
    /// completeLogin/remove) happens at a time for a given run_id. It is
    /// inherited by new control connections when they supersede old ones.
    pub fn get_run_mu(&self, run_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.run_mu_map.lock().unwrap();
        map.entry(run_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}
