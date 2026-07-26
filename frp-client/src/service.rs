use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

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
use rand::Rng;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{debug, info, instrument, warn};

use frp_core::auth::{AuthConfig, AuthMethod, OidcClient};
use frp_core::config::ClientConfig;
use frp_core::unsafe_features::UnsafeFeatures;

#[cfg(feature = "vnet")]
type VnetTunMap = Arc<Mutex<HashMap<String, Option<Box<dyn frp_vnet::tun::TunDevice>>>>>;
use frp_core::encryption;
use frp_core::msg::{self, ClientSpec, FrpMessage};
use frp_core::protocol::{read_msg, write_msg};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{TransportProtocol, WriteHalf};

use frp_core::metrics::ProxyMetricsRegistry;

#[cfg(feature = "admin")]
use crate::admin::AdminState;
use crate::control::ControlConnection;
use crate::plugin::{self, PluginContext, PluginHandle};
use crate::proxy_runtime::{ProxyPhase, ProxyRuntimeInfo, ReloadRequest};
use crate::util::opt_if_empty;
use crate::work_conn::XtcpNotification;

/// Dispatch to the correct plugin start function based on plugin_type.
/// For `visitor_plugin`, `plugin_ctx` must be `Some`; for all other types,
/// `plugin_ctx` is ignored.
async fn dispatch_plugin_start(
    plugin_cfg: &frp_core::config::PluginConfig,
    plugin_ctx: Option<PluginContext>,
) -> Result<PluginHandle, frp_core::Error> {
    match plugin_cfg.plugin_type.as_str() {
        "http_proxy" => plugin::start_http_proxy(plugin_cfg).await,
        "socks5" => plugin::start_socks5_proxy(plugin_cfg).await,
        "static_file" => plugin::start_static_file_proxy(plugin_cfg).await,
        "unix_domain_socket" => plugin::start_unix_socket_plugin(plugin_cfg).await,
        "tls2raw" => plugin::start_tls2raw_plugin(plugin_cfg).await,
        "http2http" => plugin::start_http2http_plugin(plugin_cfg).await,
        "http2https" => plugin::start_http2https_plugin(plugin_cfg).await,
        "https2http" => plugin::start_https2http_plugin(plugin_cfg).await,
        "https2https" => plugin::start_https2https_plugin(plugin_cfg).await,
        "visitor_plugin" => {
            let ctx = plugin_ctx.ok_or_else(|| {
                frp_core::Error::Config("visitor_plugin requires PluginContext".into())
            })?;
            plugin::start_visitor_plugin(plugin_cfg, ctx).await
        }
        other => Err(frp_core::Error::Config(
            format!("unknown plugin type: {other}").into(),
        )),
    }
}

/// The main frpc service.
pub struct Service {
    cfg: ClientConfig,
    auth_cfg: Arc<AuthConfig>,
    encryption_key: [u8; 16],
    /// Map proxy_name -> runtime info for looking up where to connect
    proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    /// Plugin handles keyed by proxy name. Drop removes the plugin task.
    plugin_handles: Arc<std::sync::Mutex<HashMap<String, PluginHandle>>>,
    /// OIDC client for fetching access tokens (None when auth method is Token).
    oidc_client: Option<Arc<OidcClient>>,
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
    /// Per-proxy health check cancel flags. Keyed by proxy name.
    /// Set to true on CloseProxy/CloseProxyResp; entry removed in try_reload.
    health_cancels: Arc<std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>>,
    /// Proxy configs for health-checked proxies, used to re-register on health recovery.
    health_proxy_configs: Arc<std::sync::Mutex<HashMap<String, frp_core::config::ProxyConfig>>>,
    /// Channel sender for health check events (Close/Recover). Cloned by try_reload()
    /// to spawn health checks for new/changed proxies after reload.
    health_tx: mpsc::Sender<HealthEvent>,
    /// Receiver side of health channel — consumed by run().
    health_rx: std::sync::Mutex<Option<mpsc::Receiver<HealthEvent>>>,
    /// Shared TUN devices for vnet proxies, keyed by proxy name.
    /// Work connection tasks take ownership of the TUN device via Option::take().
    #[cfg(feature = "vnet")]
    vnet_tuns: VnetTunMap,
    /// Shared routing table for vnet packet forwarding (TX direction).
    /// Updated by the service when peer route advertisements arrive,
    /// read by VnetController during packet forwarding.
    #[cfg(feature = "vnet")]
    vnet_routes: Arc<tokio::sync::RwLock<frp_vnet::router::RouteTable>>,
    /// Per-proxy TX channels for forwarding received VnetPackets to TUN devices.
    /// Keyed by proxy name.
    #[cfg(feature = "vnet")]
    vnet_tun_tx: Arc<Mutex<HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Per-proxy TUN device names for OS route injection.
    #[cfg(feature = "vnet")]
    vnet_tun_names: Arc<Mutex<HashMap<String, String>>>,
}

impl Service {
    /// Create a new client Service with default unsafe features (all blocked).
    pub async fn new(
        cfg: ClientConfig,
        config_file: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_unsafe_features(cfg, config_file, UnsafeFeatures::default()).await
    }

    /// Create a new client Service with a custom unsafe features allowlist.
    pub async fn with_unsafe_features(
        cfg: ClientConfig,
        config_file: Option<String>,
        unsafe_features: UnsafeFeatures,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Determine auth method from [auth] section if present, otherwise token
        #[cfg(feature = "oidc")]
        let auth_method = if let Some(ref ac) = cfg.auth {
            if ac.method == "oidc" {
                AuthMethod::Oidc
            } else {
                AuthMethod::Token
            }
        } else {
            AuthMethod::Token
        };
        #[cfg(not(feature = "oidc"))]
        let auth_method = AuthMethod::Token;

        let auth_cfg = AuthConfig {
            method: auth_method.clone(),
            token: frp_core::auth::resolve_dynamic_token_checked(&cfg.token, &unsafe_features)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "resolve_dynamic_token error: {e}");
                    String::new()
                }),
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
            let ac = cfg
                .auth
                .as_ref()
                .ok_or("OIDC auth requires [auth] section in config")?;
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
            )
            .await
            .map_err(|e| format!("OIDC client init failed: {e}"))?;
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
                    };
                    dispatch_plugin_start(plugin_cfg, Some(plugin_ctx)).await
                } else {
                    dispatch_plugin_start(plugin_cfg, None).await
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
            map.insert(
                p.name.clone(),
                ProxyRuntimeInfo {
                    local_addr,
                    proxy_type: p.proxy_type.clone(),
                    use_encryption: p.use_encryption,
                    use_compression: p.use_compression,
                    sk: p.sk.clone(),
                    bandwidth_limit: bw_limit,
                    bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
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
        let vnet_routes = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
        #[cfg(feature = "vnet")]
        let vnet_tun_tx = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(feature = "vnet")]
        let vnet_tun_names = Arc::new(Mutex::new(HashMap::new()));

        let health_proxy_configs = Arc::new(std::sync::Mutex::new(
            cfg.proxies
                .iter()
                .filter(|p| !p.health_check_type.is_empty())
                .map(|p| (p.name.clone(), p.clone()))
                .collect(),
        ));

        Ok(Self {
            cfg,
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
            nat_hole_stun_server,
            xtcp_tx,
            xtcp_rx: std::sync::Mutex::new(Some(xtcp_rx)),
            visitor_tx,
            visitor_rx: std::sync::Mutex::new(Some(visitor_rx)),
            health_cancels: Arc::new(std::sync::Mutex::new(HashMap::new())),
            health_proxy_configs,
            health_tx,
            health_rx: std::sync::Mutex::new(Some(health_rx)),
            #[cfg(feature = "vnet")]
            vnet_tuns,
            #[cfg(feature = "vnet")]
            vnet_routes,
            #[cfg(feature = "vnet")]
            vnet_tun_tx,
            #[cfg(feature = "vnet")]
            vnet_tun_names,
        })
    }

    /// Count errors in the 60s fast-retry sliding window, pruning expired timestamps.
    /// Matches Go frp dev FastBackoffManager.FastRetryWindow = time.Minute.
    fn prune_fast_retry_count(timestamps: &mut Vec<Instant>) -> u32 {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(60);
        timestamps.retain(|ts| *ts >= cutoff);
        timestamps.len() as u32
    }

    /// Compute reconnect delay with the Go frp dev two-phase fast-backoff.
    /// Phase 1 (first 3 retries within 60s window): 200ms base, 0.5 jitter, no cap.
    /// Phase 2 (after that): 1s base, 2x factor, 0.1 jitter, cap 20s.
    ///
    /// Matches Go frp dev wait.FastBackoffManager:
    ///   FastBackoffOptions{
    ///       Duration:        time.Second,
    ///       Factor:          2,
    ///       Jitter:          0.1,
    ///       MaxDuration:     20 * time.Second,
    ///       FastRetryCount:  3,
    ///       FastRetryDelay:  200 * time.Millisecond,
    ///       FastRetryJitter: 0.5,
    ///       FastRetryWindow: time.Minute,
    ///   }
    ///
    /// # Architectural Note (Fix 10)
    /// Go frp uses a **nested** backoff architecture: `loopLoginUntilSuccess` contains
    /// its own `BackoffUntil` with a basic exponential (Duration=1s, Factor=2, MaxDuration=10s/20s),
    /// while `keepControllerWorking` wraps it in an outer `BackoffUntil` with the full
    /// two-phase FastBackoffManager. This means:
    ///   - Initial login: inner loop retries forever with 10s cap.
    ///   - Reconnection: outer loop adds fast-retry (200ms) and exponential (20s cap) BETWEEN
    ///     inner-loop invocations, while each inner-loop invocation itself has exponential backoff.
    ///
    /// Rust's implementation uses a **combined** approach: a single reconnection loop with
    /// the full two-phase backoff applied to each reconnect attempt. This is functionally
    /// equivalent because Go's inner loop (loopLoginUntilSuccess) guarantees it returns
    /// only on success, and the outer loop provides the error-aware backoff between retries.
    fn fast_backoff_delay(
        consecutive_err_count: u32,
        counts_in_fast_retry_window: u32,
    ) -> Duration {
        let mut rng = rand::thread_rng();

        // Phase 1: fast retries
        if counts_in_fast_retry_window <= 3 {
            // Jitter is additive: 200ms + random(0, 0.5 * 200ms)
            let base_ms = 200;
            let jitter_ms = rng.gen_range(0..=100);
            return Duration::from_millis((base_ms + jitter_ms) as u64);
        }

        // Phase 2: exponential backoff
        // Go frp: InitDurationIfFail(1s) * Factor(2) → 2s on first error, then compounds.
        // Matches Go frp dev wait.FastBackoffImpl.Backoff():
        //   consecutiveErrCount=1 → InitDurationIfFail(1s) * Factor(2) = 2s + jitter
        //   consecutiveErrCount=2 → previousDuration(2s) * Factor(2) = 4s + jitter
        //   etc.
        let mut duration_ms = 1000u64; // InitDurationIfFail = 1 second base
        for _ in 0..consecutive_err_count {
            duration_ms = duration_ms.saturating_mul(2);
            if duration_ms >= 20_000 {
                duration_ms = 20_000;
                break;
            }
        }
        // Additive jitter: duration_ms + random(0, 0.1 * duration_ms)
        let jitter_ms = (rng.gen::<f64>() * 0.1 * duration_ms as f64) as u64;
        duration_ms = duration_ms.saturating_add(jitter_ms);
        let duration_ms = duration_ms.min(20_000);

        Duration::from_millis(duration_ms)
    }

    /// Request a config reload. Safe to call from signal handler.
    /// Returns immediately; actual reload happens asynchronously in run().
    /// Logs a warning if the reload channel is full or closed — the reload
    /// will be retried on the next try_send (periodic or on next event).
    pub fn request_reload(&self) {
        match self.reload_tx.try_send(ReloadRequest {
            strict: false,
            reply: {
                let (tx, _) = tokio::sync::oneshot::channel();
                tx
            },
        }) {
            Ok(()) => tracing::info!("Config reload requested (SIGUSR1)"),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("Config reload channel full (capacity 64) — reload queued; will be processed when prior reload completes");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("Config reload channel closed — reload not possible (service may be shutting down)");
            }
        }
    }

    #[instrument(skip(self), fields(server_addr = %self.cfg.server_addr, server_port = %self.cfg.server_port))]
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            version = %frp_core::VERSION, server_addr = %self.cfg.server_addr, server_port = %self.cfg.server_port,
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, self.cfg.server_addr, self.cfg.server_port
        );

        let protocol: TransportProtocol = match self.cfg.transport_protocol.parse() {
            Ok(p) => p,
            Err(_) => {
                return Err(format!(
                    "unknown transport protocol '{}'. Valid transports: tcp, kcp, quic, websocket, wss",
                    self.cfg.transport_protocol
                )
                .into());
            }
        };
        let pool_count = self.cfg.pool_count.max(0);
        let proxies = self.cfg.proxies.clone();

        // Selective proxy start: if `start` is non-empty, only start proxies
        // whose names are in the start list. Go frp compat.
        let proxies: Vec<frp_core::config::ProxyConfig> = if self.cfg.start.is_empty() {
            proxies
        } else {
            let start_set: std::collections::HashSet<&str> =
                self.cfg.start.iter().map(|s| s.as_str()).collect();
            let filtered: Vec<_> = proxies
                .into_iter()
                .filter(|p| start_set.contains(p.name.as_str()))
                .collect();
            info!(
                active = %filtered.len(), total = %self.cfg.proxies.len(), start = ?self.cfg.start,
                "Selective proxy start: {} of {} proxies active (start={:?})",
                filtered.len(),
                self.cfg.proxies.len(),
                self.cfg.start,
            );
            filtered
        };

        // Filter out disabled proxies. Go frp compat: proxy.enabled.
        let proxies: Vec<frp_core::config::ProxyConfig> =
            proxies.into_iter().filter(|p| p.enabled).collect();
        if proxies.len() < self.cfg.proxies.len() {
            let disabled: Vec<&str> = self
                .cfg
                .proxies
                .iter()
                .filter(|p| !p.enabled)
                .map(|p| p.name.as_str())
                .collect();
            info!(disabled = ?disabled, "Disabled proxies (skipped): {:?}", disabled);
        }

        if proxies.is_empty() {
            warn!("No proxies configured");
        }

        // Take the receiver from self (created in constructor, consumed once).
        let mut health_rx = self
            .health_rx
            .lock()
            .unwrap()
            .take()
            .expect("health_rx already taken — run() called twice?");

        // Cancellation flags for health check tasks — set to true when a proxy
        // is closed (via CloseProxy from server, admin, or health check failure).
        // Stored on self so try_reload() can cancel health checks for removed proxies.
        let health_cancels = self.health_cancels.clone();

        self.spawn_health_checks(&proxies, &self.health_tx, &health_cancels)
            .await;

        // Start admin HTTP server if configured
        let _reload_tx = self.reload_tx.clone();
        let mut reload_rx = self
            .reload_rx
            .lock()
            .unwrap()
            .take()
            .expect("reload_rx already taken — run() called twice?");
        let mut xtcp_rx = self
            .xtcp_rx
            .lock()
            .unwrap()
            .take()
            .expect("xtcp_rx already taken — run() called twice?");
        let mut visitor_rx = self
            .visitor_rx
            .lock()
            .unwrap()
            .take()
            .expect("visitor_rx already taken — run() called twice?");
        let xtcp_tx = self.xtcp_tx.clone();
        let nat_hole_stun_server = self.nat_hole_stun_server.clone();
        let (_stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        #[cfg(feature = "admin")]
        self.spawn_admin_server(&_reload_tx, &_stop_tx);

        // Main session loop with reconnection.
        // Go frp dev two-phase fast-backoff:
        //   Phase 1 (first 3 retries within 60s window): 200ms + 0.5 jitter
        //   Phase 2 (after that): 1s × 2ⁿ + 0.1 jitter, cap 20s
        // Matches Go frp dev wait.FastBackoffManager.
        let mut did_login_once = false;
        let mut consecutive_err_count: u32 = 0;
        let mut fast_retry_timestamps: Vec<Instant> = Vec::new();
        // Track visitor listener tasks so they can be cancelled on reconnect.
        let mut visitor_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        // Carry over run_id across reconnections (Go frp compat: previousRunID).
        let mut previous_run_id = String::new();
        // Explicitly hold the previous session's yamux handle so we can drop it
        // before creating a new connection (Go frp compat: svr.ctl.Close()).
        // Dropping the Arc causes the background yamux task to notice the
        // closed sender channel and exit, closing the TCP socket.
        #[cfg(feature = "tcp-mux")]
        let mut prev_yamux: Option<std::sync::Arc<frp_core::mux::YamuxSession>> = None;
        loop {
            // Go frp compat (d486018): drop previous yamux session before
            // creating a new control connection. This drops the sender channel,
            // causing the background yamux task to exit and close the TCP socket.
            #[cfg(feature = "tcp-mux")]
            drop(prev_yamux.take());
            let mut ctl = ControlConnection::new(
                self.cfg.server_addr.clone(),
                self.cfg.server_port,
                self.auth_cfg.clone(),
                protocol.clone(),
                pool_count,
                self.cfg.user.clone(),
                self.cfg.client_id.clone(),
                self.cfg.tls_enable,
                self.cfg.tls_server_name.clone(),
                opt_if_empty!(self.cfg.tls_ca_file),
                opt_if_empty!(self.cfg.tls_cert_file),
                opt_if_empty!(self.cfg.tls_key_file),
                opt_if_empty!(self.cfg.dns_server),
                self.cfg.tcp_mux,
                self.cfg.disable_custom_tls_first_byte,
                self.cfg.dial_server_keepalive.max(0) as u64,
                self.cfg.tcp_mux_keepalive_interval,
                opt_if_empty!(self.cfg.connect_server_local_ip),
                self.cfg.v2,
                self.oidc_client.clone(),
                self.cfg.metas.clone(),
                self.cfg.proxy_url.clone(),
                previous_run_id.clone(),
                Some(ClientSpec {
                    client_type: Some("frpc".into()),
                    always_auth_pass: None,
                }),
                self.cfg.dial_server_timeout,
            );

            #[cfg(feature = "quic")]
            let quic_conn: Option<QuicConnection>;

            let (mut control_stream, run_id, yamux_session) = match ctl.login().await {
                Ok(r) => {
                    did_login_once = true;
                    consecutive_err_count = 0;
                    fast_retry_timestamps.clear();
                    *self.server_auth_scopes.write().await = ctl.server_auth_scopes.clone();
                    // After login, wrap control stream in AES-128-CFB encryption.
                    // Go frps v0.69.1 always encrypts the control connection for V1.
                    #[cfg(feature = "quic")]
                    let (stream, run_id, yamux, quic) = r;
                    #[cfg(not(feature = "quic"))]
                    let (stream, run_id, yamux) = r;
                    let enc_key = encryption::derive_key(&self.auth_cfg.token);
                    #[cfg(feature = "quic")]
                    {
                        quic_conn = quic;
                    }
                    (stream.into_encrypted(enc_key), run_id, yamux)
                }
                Err(e) => {
                    consecutive_err_count += 1;
                    warn!(attempt = %consecutive_err_count, error = %e, "Login failed (attempt {}): {}", consecutive_err_count, e);
                    if self.cfg.login_fail_exit && !did_login_once {
                        return Err(e.into());
                    }
                    let delay = if did_login_once {
                        // Session reconnect: full fast-backoff with Phase 1 (200ms) + Phase 2 (exponential).
                        fast_retry_timestamps.push(Instant::now());
                        let window_count = Self::prune_fast_retry_count(&mut fast_retry_timestamps);
                        Self::fast_backoff_delay(consecutive_err_count, window_count)
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
                            (rand::thread_rng().gen::<f64>() * 0.1 * delay_ms as f64) as u64;
                        Duration::from_millis(delay_ms.saturating_add(jitter_ms).min(10_000))
                    };
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
            let yamux = yamux_session.map(std::sync::Arc::new);
            // Store for explicit cleanup before next reconnect (Go frp compat d486018).
            #[cfg(feature = "tcp-mux")]
            {
                prev_yamux = yamux.clone();
            }
            #[cfg(feature = "quic")]
            let quic_conn = quic_conn.map(std::sync::Arc::new);
            previous_run_id = run_id.clone();
            let v2 = self.cfg.v2;
            info!(run_id = %run_id, "Logged in. run_id: {}", run_id);

            let session_alive = Arc::new(AtomicBool::new(true));

            // Register proxies using IoStream directly (supports TCP and TLS).
            // NOTE: each proxy is registered sequentially via a NewProxy
            // request/response round-trip over the control channel. N proxies
            // cost N sequential network round-trips. Batching could speed up
            // registration for clients with many proxies, but would require
            // protocol changes beyond Go frp v0.70.0 wire compatibility.
            for p in &proxies {
                let local_addr = self
                    .proxy_info_map
                    .read()
                    .await
                    .get(&p.name)
                    .map(|info| info.local_addr.clone())
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                match ctl
                    .register_proxy(p, &local_addr, &mut control_stream)
                    .await
                {
                    Ok(resp) => {
                        let remote = resp
                            .remote_addr
                            .unwrap_or_else(|| format!("0.0.0.0:{}", p.remote_port));
                        info!(proxy_name = %p.name, remote = %remote, "Proxy '{}' registered on remote port {}", p.name, remote);
                        // Update runtime info for admin API
                        let mut map = self.proxy_info_map.write().await;
                        if let Some(info) = map.get_mut(&p.name) {
                            info.remote_addr = remote;
                            info.err.clear();
                            info.phase = ProxyPhase::Running;
                        }

                        #[cfg(feature = "vnet")]
                        if p.proxy_type == "vnet" && !p.vnet_ip.is_empty() {
                            use std::net::Ipv4Addr;
                            let ip: Ipv4Addr = match p.vnet_ip.parse() {
                                Ok(ip) => ip,
                                Err(e) => {
                                    warn!(proxy_name = %p.name, error = %e, "invalid vnet_ip '{}'", p.vnet_ip);
                                    continue;
                                }
                            };
                            let netmask: Ipv4Addr = match p.vnet_netmask.parse() {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!(proxy_name = %p.name, error = %e, "invalid vnet_netmask '{}'", p.vnet_netmask);
                                    continue;
                                }
                            };
                            let mtu = p.vnet_mtu;

                            match frp_vnet::tun::open_tun("").await {
                                Ok(tun) => {
                                    let tun_name = tun.name().to_string();
                                    if let Err(e) = tun.configure(ip, netmask, mtu) {
                                        warn!(proxy_name = %p.name, error = %e, "TUN configure failed");
                                    } else {
                                        info!(proxy_name = %p.name, name = %tun_name, "TUN device ready");
                                    }
                                    // Store TUN name for OS route injection
                                    {
                                        let mut names = self.vnet_tun_names.lock().await;
                                        names.insert(p.name.clone(), tun_name);
                                    }
                                    // Store TUN device for later controller spawning.
                                    // The controller is spawned after the control
                                    // connection writer is created.
                                    {
                                        let mut tuns = self.vnet_tuns.lock().await;
                                        tuns.insert(p.name.clone(), Some(tun));
                                    }
                                    // Send VnetRouteAdvertise if subnet is configured
                                    if !p.advertise_subnet.is_empty() {
                                        let adv = FrpMessage::VnetRouteAdvertise(
                                            msg::VnetRouteAdvertise {
                                                proxy_name: p.name.clone(),
                                                subnet: p.advertise_subnet.clone(),
                                                virtual_net: if p.virtual_net.is_empty() {
                                                    None
                                                } else {
                                                    Some(p.virtual_net.clone())
                                                },
                                            },
                                        );
                                        let send_result = if v2 {
                                            control_stream.write_v2_frame(&adv).await
                                        } else {
                                            control_stream.write_v1_frame(&adv).await
                                        };
                                        if let Err(e) = send_result {
                                            warn!(proxy_name = %p.name, error = %e, "failed to send VnetRouteAdvertise");
                                        } else {
                                            info!(proxy_name = %p.name, subnet = %p.advertise_subnet, "VnetRouteAdvertise sent");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(proxy_name = %p.name, error = %e, "TUN open failed (need root/CAP_NET_ADMIN?)");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(proxy_name = %p.name, error = %e, "Failed to register proxy '{}': {}", p.name, e);
                        let mut map = self.proxy_info_map.write().await;
                        if let Some(info) = map.get_mut(&p.name) {
                            info.err = e.to_string();
                            info.phase = ProxyPhase::StartErr(e.to_string());
                        }
                    }
                }
            }

            // Register STCP/XTCP visitors on the control connection.
            // Go frps v0.69.1 requires visitor registration before NatHoleVisitor
            // can be sent on the control connection (otherwise: "auth failed").
            for v in &self.cfg.visitors {
                if v.bind_port == 0 {
                    continue;
                }
                match ctl.register_visitor(v, &mut control_stream).await {
                    Ok(_) => {
                        info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}'", v.name, v.server_name);
                    }
                    Err(e) => {
                        warn!(visitor_name = %v.name, error = %e, "Failed to register visitor '{}': {}", v.name, e);
                    }
                }
            }

            // Split control stream for reading and writing
            let (mut reader, raw_writer) = control_stream.into_split()?;
            let writer = Arc::new(Mutex::new(raw_writer));

            // Spawn VnetControllers for all vnet proxies now that the
            // control connection writer is available.
            #[cfg(feature = "vnet")]
            {
                let mut tuns = self.vnet_tuns.lock().await;
                for (proxy_name, tun_opt) in tuns.iter_mut() {
                    if let Some(tun) = tun_opt.take() {
                        let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                        {
                            let mut txs = self.vnet_tun_tx.lock().await;
                            txs.insert(proxy_name.clone(), tun_tx);
                        }
                        let ctl_writer = writer.clone();
                        let routes = self.vnet_routes.clone();
                        let pn = proxy_name.clone();
                        tokio::spawn(async move {
                            let ctrl =
                                frp_vnet::controller::VnetController::new(pn.clone(), routes, v2);
                            if let Err(e) = ctrl.run(tun, ctl_writer, tun_rx).await {
                                tracing::error!(proxy_name = %pn, error = %e, "vnet controller exited with error");
                            }
                            tracing::info!(proxy_name = %pn, "vnet controller stopped");
                        });
                    }
                }
                tuns.clear();
            }

            // Bind local UDP sockets for UDP proxies.
            // UDP data flows over work connections (Go frp v0.69.1 compat).
            // Sockets are shared with work conn tasks via Arc.
            let udp_sockets: Arc<tokio::sync::Mutex<HashMap<String, Arc<UdpSocket>>>> =
                Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            let udp_enc_cfg: Arc<tokio::sync::Mutex<HashMap<String, (bool, bool)>>> =
                Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            for p in &proxies {
                if p.proxy_type == "udp" || p.proxy_type == "sudp" {
                    let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                    let bind_addr = format!("{}:0", p.local_ip);
                    let socket = match UdpSocket::bind(&bind_addr).await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            warn!(proxy_name = %p.name, error = %e, "UDP proxy '{}': bind failed: {}", p.name, e);
                            continue;
                        }
                    };
                    // Connect to local UDP service for send/recv
                    if let Err(e) = socket.connect(&local_addr).await {
                        warn!(proxy_name = %p.name, local_addr = %local_addr, error = %e, "UDP proxy '{}': connect to local {} failed: {}", p.name, local_addr, e);
                        continue;
                    }
                    {
                        let mut map = udp_sockets.lock().await;
                        map.insert(local_addr.clone(), socket.clone());
                        map.insert(p.name.clone(), socket);
                    }
                    {
                        let mut cfg = udp_enc_cfg.lock().await;
                        let enc = (p.use_encryption, p.use_compression);
                        cfg.insert(local_addr.clone(), enc);
                        cfg.insert(p.name.clone(), enc);
                    }
                    let enc_label = if p.use_encryption {
                        "encrypted"
                    } else {
                        "plain"
                    };
                    info!(proxy_name = %p.name, local_addr = %local_addr, enc_label = %enc_label, "UDP proxy '{}' ready, bridging to {} ({})", p.name, local_addr, enc_label);
                }
            }

            // Spawn initial pool work connections
            let auth_token = self.auth_cfg.token.clone();
            let client_scopes: Vec<String> = self
                .cfg
                .auth
                .as_ref()
                .map(|a| a.additional_auth_scopes.clone())
                .unwrap_or_default();
            let server_scopes = self.server_auth_scopes.read().await.clone();
            // Both the pool-spawn loop below and the on-demand ReqWorkConn
            // handler build a byte-identical WorkConnConfig differing only in
            // `pool_id`. Collapse into one macro (defined here so its free
            // identifier references resolve against the locals in scope).
            macro_rules! spawn_wc {
                ($pool_id:expr) => {{
                    #[cfg(feature = "quic")]
                    let quic_arg = quic_conn.clone();
                    #[cfg(not(feature = "quic"))]
                    let quic_arg = ();
                    crate::work_conn::spawn_work_conn(crate::work_conn::WorkConnConfig {
                        server_addr: self.cfg.server_addr.clone(),
                        server_port: self.cfg.server_port,
                        protocol: protocol.clone(),
                        run_id: run_id.clone(),
                        proxy_info_map: self.proxy_info_map.clone(),
                        enc_key: self.encryption_key,
                        pool_id: $pool_id,
                        auth_token: auth_token.clone(),
                        tls_enable: self.cfg.tls_enable,
                        tls_server_name: self.cfg.tls_server_name.clone(),
                        tls_ca_file: opt_if_empty!(self.cfg.tls_ca_file),
                        yamux: yamux.clone(),
                        quic_conn: quic_arg,
                        v2,
                        oidc_client: self.oidc_client.clone(),
                        udp_sockets: udp_sockets.clone(),
                        udp_enc_cfg: udp_enc_cfg.clone(),
                        proxy_metrics: self.proxy_metrics.clone(),
                        client_auth_scopes: client_scopes.clone(),
                        server_auth_scopes: server_scopes.clone(),
                        disable_custom_tls_first_byte: self.cfg.disable_custom_tls_first_byte,
                        keepalive_secs: self.cfg.dial_server_keepalive.max(0) as u64,
                        bind_addr: opt_if_empty!(self.cfg.connect_server_local_ip),
                        proxy_url: self.cfg.proxy_url.clone(),
                        user: self.cfg.user.clone(),
                        dial_timeout_secs: self.cfg.dial_server_timeout as u64,
                        xtcp_tx: xtcp_tx.clone(),
                        session_alive: session_alive.clone(),
                        #[cfg(feature = "vnet")]
                        vnet_tuns: self.vnet_tuns.clone(),
                        #[cfg(feature = "vnet")]
                        vnet_routes: self.vnet_routes.clone(),
                    });
                }};
            }

            // Go frp compat: work connections are created ONLY in response to
            // ReqWorkConn messages from the server (handled in the message loop
            // below, which calls spawn_wc!(-1)). Do NOT eagerly spawn pool_count
            // connections here; pool_count is sent to the server via Login so it
            // knows how many ReqWorkConn messages to issue.

            // Shared graceful shutdown signal for all visitor listener tasks.
            // Set to true at session end so tasks exit cleanly (Fix 8).
            let visitor_shutdown = Arc::new(AtomicBool::new(false));

            // Cancel old visitor listener tasks from a previous session.
            // Signal gracefully and wait briefly for the previous session's
            // visitors to exit, instead of aborting them (Go frp compat:
            // visitor_manager.Close() closes each visitor cleanly).
            for h in visitor_handles.drain(..) {
                // Previous session's visitor_shutdown was already set when
                // the session ended; tasks should exit on their own.
                // Give them a moment to notice and exit.
                let _ = tokio::time::timeout(Duration::from_millis(500), h).await;
            }

            // Spawn STCP/XTCP visitor listeners
            for v in &self.cfg.visitors {
                if v.bind_port == 0 {
                    continue;
                }
                let sa = self.cfg.server_addr.clone();
                let sp = self.cfg.server_port;
                let pt = protocol.clone();
                let server_name = v.server_name.clone();
                let server_user = v.server_user.clone();
                let secret_key = v.secret_key.clone();
                let bind_addr = format!("{}:{}", v.bind_addr, v.bind_port);
                let use_enc = v.use_encryption;
                let use_comp = v.use_compression;
                let name = v.name.clone();
                let tls_enable = self.cfg.tls_enable;
                let tls_server_name = self.cfg.tls_server_name.clone();
                let tls_ca_file = opt_if_empty!(self.cfg.tls_ca_file);
                let visitor_type = v.visitor_type.clone();
                let fallback_timeout_ms = v.fallback_timeout_ms;
                let keep_tunnel_open = v.keep_tunnel_open;
                let max_retries_an_hour = v.max_retries_an_hour;
                let min_retry_interval = v.min_retry_interval;
                let stun_server = nat_hole_stun_server.clone();
                let fallback_to = v.fallback_to.clone();
                let disable_assisted_addrs = v.disable_assisted_addrs;
                let p2p_protocol = v.protocol.clone();
                let user = self.cfg.user.clone();
                let rid = run_id.clone();
                let vtx = self.visitor_tx.clone();
                let shutdown = visitor_shutdown.clone();
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
                    })
                    .await;
                });
                visitor_handles.push(handle);
            }

            // --- Message loop ---
            // Map sid -> proxy_name for XTCP NatHoleResp routing (provider side).
            let mut pending_xtcp: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            // Map sid -> STUN UDP socket for XTCP P2P hole punching.
            let xtcp_sockets: std::sync::Arc<
                tokio::sync::Mutex<
                    std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
                >,
            > = Default::default();
            // Map sid -> oneshot sender for visitor NatHoleResp routing (Go frps compat).
            let mut visitor_pending: std::collections::HashMap<
                String,
                oneshot::Sender<Result<msg::NatHoleResp, String>>,
            > = std::collections::HashMap::new();
            let mut ping_interval = if self.cfg.heartbeat_interval > 0 {
                let secs = self.cfg.heartbeat_interval as u64;
                info!(interval = %secs, "Heartbeat interval: {}s", secs);
                Some(tokio::time::interval(Duration::from_secs(secs)))
            } else {
                info!("Heartbeat: disabled (heartbeat_interval <= 0, tcp_mux provides keepalive)");
                None
            };

            // Proxy retry interval: every 30s, re-register proxies stuck in StartErr.
            // Matches Go frp's proxy_wrapper.checkWorker (default startErrTimeout 30s).
            let mut proxy_retry_interval = tokio::time::interval(Duration::from_secs(30));
            proxy_retry_interval.tick().await; // Skip first immediate tick

            let mut last_pong = Instant::now();
            let hb_timeout = self.cfg.heartbeat_timeout;
            let hb_timeout_dur = Duration::from_secs(hb_timeout.max(0) as u64);

            loop {
                tokio::select! {
                    msg = read_msg(&mut reader, v2) => {
                        match msg {
                            Ok(FrpMessage::ReqWorkConn(_)) => {
                                debug!("Received ReqWorkConn, creating work connection");
                                spawn_wc!(-1); // on-demand, not pool
                            }
                            Ok(FrpMessage::Pong(pong)) => {
                                if let Some(ref err) = pong.error {
                                    if !err.is_empty() {
                                        warn!(error = %err, "Pong contains error: {}", err);
                                        break;
                                    }
                                }
                                debug!("Pong received");
                                last_pong = Instant::now();
                            }
                            Ok(FrpMessage::CloseProxy(cp)) => {
                                info!(proxy_name = %cp.proxy_name, "Server closed proxy: {}", cp.proxy_name);
                                // Cancel health check task and remove map entry.
                                let mut cancels = health_cancels.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(cancel) = cancels.get(&cp.proxy_name) {
                                    cancel.store(true, Ordering::Relaxed);
                                }
                                cancels.remove(&cp.proxy_name);
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
                                self.handle_nat_hole_client(*nhc, &writer, v2).await;
                            }
                            Ok(FrpMessage::NatHoleResp(resp)) => {
                                self.handle_nat_hole_resp(*resp, &mut pending_xtcp, &mut visitor_pending, &xtcp_sockets, &writer).await;
                            }
                            Ok(FrpMessage::NewProxyResp(resp)) => {
                                let is_error = resp.error.as_ref().is_some_and(|e| !e.is_empty());
                                if is_error {
                                    let err = resp.error.as_ref().unwrap();
                                    warn!(proxy_name = %resp.proxy_name, error = %err, "Proxy '{}' registration error: {}", resp.proxy_name, err);
                                    // Update phase if proxy was being retried (WaitStart -> StartErr).
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&resp.proxy_name) {
                                        if info.phase == ProxyPhase::WaitStart {
                                            info.err = err.clone();
                                            info.phase = ProxyPhase::StartErr(err.clone());
                                        }
                                    }
                                } else {
                                    // Successful registration from retry path.
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&resp.proxy_name) {
                                        if info.phase == ProxyPhase::WaitStart {
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
                                info!(subnet = %adv.subnet, proxy_name = %adv.proxy_name, "peer vnet route advertisement received");
                                // Update the shared route table (TX direction lookup).
                                {
                                    let mut routes = self.vnet_routes.write().await;
                                    if let Err(e) = routes.insert(&adv.proxy_name, &adv.subnet) {
                                        warn!(%e, "failed to add vnet route");
                                    }
                                }
                                // Inject OS route so the kernel sends matching packets
                                // through the TUN device instead of the default gateway.
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                {
                                    let names = self.vnet_tun_names.lock().await;
                                    if let Some(tun_name) = names.values().next() {
                                        add_os_route(&adv.subnet, tun_name);
                                    }
                                }
                            }
                            #[cfg(feature = "vnet")]
                            Ok(FrpMessage::VnetPacket(vpkt)) => {
                                match data_encoding::BASE64.decode(vpkt.data.as_bytes()) {
                                    Ok(packet) => {
                                        let txs = self.vnet_tun_tx.lock().await;
                                        if let Some(tx) = txs.get(&vpkt.proxy_name) {
                                            if tx.try_send(packet).is_err() {
                                                warn!(proxy_name = %vpkt.proxy_name, "vnet TUN channel closed");
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
                                info!(proxy_name = %adv.proxy_name, "peer vnet route removed");
                                let mut routes = self.vnet_routes.write().await;
                                routes.remove(&adv.proxy_name);
                            }
                            Ok(_) => {
                                // Other messages are ignored
                            }
                            Err(e) => {
                                warn!(error = %e, "Control read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }

                    _ = async {
                        if let Some(ref mut interval) = ping_interval {
                            interval.tick().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        let mut ping_msg = msg::Ping {
                            privilege_key: None,
                            timestamp: None,
                        };
                        // Go frp v0.70.1 compat: Ping sends auth ONLY when the
                        // server's additionalAuthScopes includes "HeartBeats".
                        // Go's heartbeatWorker checks
                        // ctl.GetController().GetAuthCfg().AdditionalAuthScopes
                        // for "HeartBeats". Default scope is empty, so Ping has
                        // no auth fields unless the scope was negotiated.
                        // See /tmp/frp-source/client/control.go:heartbeatWorker.
                        let send_auth = server_scopes.iter().any(|s| s == "HeartBeats");
                        if send_auth {
                            if let Some(ref oidc) = self.oidc_client {
                                if let Err(e) = oidc.set_ping(&mut ping_msg).await {
                                    warn!(error = %e, "OIDC ping token failed: {}. Reconnecting...", e);
                                    break;
                                }
                            } else {
                                let ts = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs() as i64;
                                let ping_auth = AuthConfig::with_token(self.auth_cfg.token.clone());
                                ping_msg.privilege_key = ping_auth.generate_login_key(ts);
                                ping_msg.timestamp = Some(ts);
                            }
                        }
                        let ping = FrpMessage::Ping(ping_msg);
                        if let Err(e) = write_msg(&mut *writer.lock().await, &ping, v2).await {
                            warn!(error = %e, "Ping write failed: {}", e);
                            // Non-fatal: heartbeat timeout will detect actual dead connection.
                        } else {
                            debug!("Ping sent");
                        }
                    }

                    _ = proxy_retry_interval.tick() => {
                        let to_retry: Vec<(String, String)> = {
                            let map = self.proxy_info_map.read().await;
                            map.iter()
                                .filter(|(_, info)| matches!(info.phase, ProxyPhase::StartErr(_)))
                                .map(|(name, info)| (name.clone(), info.local_addr.clone()))
                                .collect()
                        };
                        for (name, local_addr) in to_retry {
                            if let Some(p) = proxies.iter().find(|p| p.name == name) {
                                let new_proxy = crate::proxy::create_new_proxy_msg(p, &local_addr);
                                if let Err(e) = write_msg(&mut *writer.lock().await, &new_proxy, v2).await {
                                    warn!(proxy_name = %name, error = %e, "Proxy '{}' retry: write NewProxy failed: {}", name, e);
                                } else {
                                    info!(proxy_name = %name, "Proxy '{}' retry: sent NewProxy", name);
                                    let mut map = self.proxy_info_map.write().await;
                                    if let Some(info) = map.get_mut(&name) {
                                        info.phase = ProxyPhase::WaitStart;
                                    }
                                }
                            }
                        }
                    }

                    Some(event) = health_rx.recv() => {
                        match event {
                            HealthEvent::Close(proxy_name) => {
                                info!(proxy_name = %proxy_name, "Health check sending CloseProxy for unhealthy proxy: {}", proxy_name);
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
                                if let Err(e) = write_msg(&mut *writer.lock().await, &close, v2).await {
                                    warn!(proxy_name = %proxy_name, error = %e, "Failed to send CloseProxy for {}: {}", proxy_name, e);
                                }
                                // Keep health check running -- monitor for recovery (Go frp compat).
                            }
                            HealthEvent::Recover(proxy_name) => {
                                info!(proxy_name = %proxy_name, "Health check recovered for '{}', re-registering", proxy_name);
                                // Look up proxy config and send NewProxy to re-register.
                                let need_send = {
                                    let configs = self.health_proxy_configs.lock().unwrap_or_else(|e| e.into_inner());
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
                                    let new_proxy = crate::proxy::create_new_proxy_msg(&cfg, &local_addr);
                                    if let Err(e) = write_msg(&mut *writer.lock().await, &new_proxy, v2).await {
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

                    Some(req) = reload_rx.recv() => {
                        let result = match &self.config_file {
                            Some(path) => self.try_reload(path, req.strict, &writer).await,
                            None => Err("no config file path stored".into()),
                        };
                        let _ = req.reply.send(result);
                    }

                    Some(xtcp_notif) = xtcp_rx.recv() => {
                        let XtcpNotification { sid, proxy_name } = xtcp_notif;
                        info!(proxy_name = %proxy_name, "XTCP provider: received NatHoleSid for '{}'", proxy_name);
                        // 1. Do STUN discovery on a persistent UDP socket.
                        //    Go frps needs ≥2 mapped addresses for NAT classification.
                        let mut mapped_addrs = Vec::new();
                        let stun_socket = match frp_core::stun::stun_binding_with_details(&nat_hole_stun_server).await {
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
                                    result1.other_addr.as_deref().unwrap_or(&nat_hole_stun_server);
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
                            xtcp_sockets.lock().await.insert(sid.clone(), std::sync::Arc::new(sock));
                        }
                        // Build assisted_addrs from local IPs + STUN port.
                        // Go frp v0.69.1: ListLocalIPsForNatHole returns non-loopback
                        // IPv4 addresses filtered from all network interfaces.
                        let assisted_addrs: Option<Vec<String>> = local_port.and_then(|port| {
                            let local_ips = list_local_ips_for_nat_hole(10);
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
                        if let Err(e) = write_msg(&mut *writer.lock().await, &client_msg, v2).await {
                            warn!(error = %e, "XTCP: failed to send NatHoleClient: {}", e);
                        } else {
                            // Track sid→proxy_name for NatHoleResp routing
                            pending_xtcp.insert(sid, proxy_name);
                        }
                    }

                    // Visitor requests: send NatHoleVisitor on control connection.
                    // Go frps v0.69.1 only handles NatHoleVisitor on the control
                    // connection path, not on fresh TCP connections.
                    Some(vreq) = visitor_rx.recv() => {
                        let txn_id = vreq.nhv.transaction_id.clone();
                        let nhv = FrpMessage::NatHoleVisitor(vreq.nhv);
                        match write_msg(&mut *writer.lock().await, &nhv, v2).await {
                            Ok(()) => {
                                debug!(sid = %txn_id, "Visitor: sent NatHoleVisitor on control, sid={}", txn_id);
                                visitor_pending.insert(txn_id, vreq.reply);
                            }
                            Err(e) => {
                                warn!(error = %e, "Visitor: failed to send NatHoleVisitor on control: {}", e);
                                let _ = vreq.reply.send(Err(format!("send failed: {e}")));
                            }
                        }
                    }

                    Some(()) = stop_rx.recv() => {
                        info!("Admin stop requested, shutting down");
                        shutdown_flag.store(true, Ordering::SeqCst);
                        break;
                    }

                    // Heartbeat timeout watchdog: triggers reconnect if no Pong
                    // received within heartbeat_timeout seconds (Go frp compat).
                    // Uses sleep instead of interval so the timer is only
                    // active when hb_timeout > 0 (disabled when tcp_mux is on).
                    _ = tokio::time::sleep(Duration::from_secs(1)), if hb_timeout > 0 => {
                        if last_pong.elapsed() > hb_timeout_dur {
                            warn!("Heartbeat timeout ({}s), reconnecting...", hb_timeout);
                            break;
                        }
                    }
                }
            }

            // Go frp GracefulClose ordering: close proxies first, then visitors,
            // then the control connection. See /tmp/frp-source/client/control.go:203-210.
            // Step 1: Signal work connection pool to stop replenishment cascade.
            session_alive.store(false, Ordering::Release);

            // Step 2: Signal visitor listeners to stop accepting new connections
            // (Go frp compat: vm.Close() closes all visitors before session is torn down).
            visitor_shutdown.store(true, Ordering::Release);

            // Step 3: Drop the control connection (Go frp compat: closeSession()).
            // Dropping prev_yamux closes the underlying TCP socket so the background
            // yamux task exits before we attempt to reconnect. This prevents
            // dual-yamux-session leaks through a half-open TCP mux connection.
            #[cfg(feature = "tcp-mux")]
            drop(prev_yamux.take());

            // Wait briefly for visitor tasks to notice the shutdown signal and
            // exit gracefully (timeout so we never block reconnection).
            for h in visitor_handles.drain(..) {
                let _ = tokio::time::timeout(Duration::from_millis(500), h).await;
            }

            // Check if admin stop was requested
            if shutdown_flag.load(Ordering::SeqCst) {
                info!("frpc shutting down");
                return Ok(());
            }

            // Session dropped — reconnect with Go frp dev two-phase fast-backoff.
            // login_fail_exit only applies to initial login, not session drops.
            consecutive_err_count += 1;
            fast_retry_timestamps.push(Instant::now());
            let window_count = Self::prune_fast_retry_count(&mut fast_retry_timestamps);
            let delay = Self::fast_backoff_delay(consecutive_err_count, window_count);
            warn!(delay_ms = %delay.as_millis(), attempt = %consecutive_err_count, "Session ended, reconnecting in {}ms (attempt {})...",
                delay.as_millis(), consecutive_err_count);
            tokio::time::sleep(delay).await;
        }
    }

    /// Spawn per-proxy health check tasks (once, outside reconnect loop).
    /// Reads local address from proxy_info_map to determine what to check.
    async fn spawn_health_checks(
        &self,
        proxies: &[frp_core::config::ProxyConfig],
        health_tx: &mpsc::Sender<HealthEvent>,
        health_cancels: &Arc<std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>>,
    ) {
        for p in proxies {
            let hc_type = p.health_check_type.clone();
            if hc_type.is_empty() {
                continue;
            }
            if hc_type != "tcp" && hc_type != "http" {
                warn!(health_check_type = %hc_type, proxy_name = %p.name, "Health check type '{}' not yet supported for '{}'", hc_type, p.name);
                continue;
            }
            let la = self
                .proxy_info_map
                .read()
                .await
                .get(&p.name)
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let pn = p.name.clone();
            let interval = std::time::Duration::from_secs(p.health_check_interval_seconds.max(10));
            let timeout = std::time::Duration::from_secs(p.health_check_timeout_seconds.max(3));
            let max_failed = p.health_check_max_failed.max(1);
            let tx = health_tx.clone();
            let hc_url = if hc_type == "http" {
                let url = p.health_check_url.clone();
                if !url.is_empty() && !url.contains("://") {
                    // Go frp compat: auto-construct URL as "http://{local_ip}:{local_port}/{path}"
                    let host = la.split(':').next().unwrap_or("127.0.0.1");
                    let port = la.split(':').nth(1).unwrap_or("0");
                    let path = if url.starts_with('/') {
                        url.clone()
                    } else {
                        format!("/{}", url)
                    };
                    format!("http://{}:{}{}", host, port, path)
                } else {
                    url
                }
            } else {
                String::new()
            };
            let hc_headers = p.health_check_http_headers.clone();
            let cancel = Arc::new(AtomicBool::new(false));
            {
                let mut cancels = health_cancels.lock().unwrap_or_else(|e| e.into_inner());
                cancels.insert(pn.clone(), cancel.clone());
            }
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
                })
                .await;
            });
        }
    }

    /// Start the admin HTTP server if configured.
    /// Spawns as a background task; returns immediately.
    #[cfg(feature = "admin")]
    fn spawn_admin_server(
        &self,
        reload_tx: &mpsc::Sender<ReloadRequest>,
        stop_tx: &mpsc::Sender<()>,
    ) {
        if self.cfg.web_server.port > 0 {
            let admin_addr =
                frp_core::format_socket_addr(&self.cfg.web_server.addr, self.cfg.web_server.port);
            let admin_state = AdminState {
                proxy_metrics: self.proxy_metrics.clone(),
                proxies: self.proxy_info_map.clone(),
                reload_tx: reload_tx.clone(),
                stop_tx: stop_tx.clone(),
                config_path: self.config_file.clone(),
            };
            let admin_auth_user = self.cfg.web_server.user.clone();
            let admin_auth_pwd = self.cfg.web_server.password.clone();
            let admin_tls_cert = if self.cfg.web_server.tls_cert_file.is_empty() {
                None
            } else {
                Some(self.cfg.web_server.tls_cert_file.clone())
            };
            let admin_tls_key = if self.cfg.web_server.tls_key_file.is_empty() {
                None
            } else {
                Some(self.cfg.web_server.tls_key_file.clone())
            };
            tokio::spawn(async move {
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
            info!(addr = %self.cfg.web_server.addr, port = %self.cfg.web_server.port, "frpc admin server starting on {}:{}", self.cfg.web_server.addr, self.cfg.web_server.port);
        }
    }

    /// Handle a NatHoleClient message from the server (XTCP provider side).
    ///
    /// Sends NatHoleSid to synchronize with the visitor, performs TCP simultaneous
    /// open, connects to local service, and spawns a P2P bridge task.
    async fn handle_nat_hole_client(
        &self,
        nhc: msg::NatHoleClient,
        writer: &Arc<Mutex<WriteHalf>>,
        v2: bool,
    ) {
        debug!(proxy_name = %nhc.proxy_name, "Received NatHoleClient for proxy '{}'", nhc.proxy_name);
        let visitor_addr = nhc.visitor_addr.unwrap_or_default();
        let proxy_name = nhc.proxy_name.clone();
        let sid = nhc.transaction_id.clone();
        let proxy_info = self.proxy_info_map.read().await.get(&proxy_name).map(|p| {
            (
                p.local_addr.clone(),
                p.use_encryption,
                p.use_compression,
                p.sk.clone(),
            )
        });
        let local_addr = proxy_info.as_ref().map(|p| p.0.clone());
        let xtcp_use_enc = proxy_info.as_ref().map(|p| p.1).unwrap_or(false);
        let xtcp_use_comp = proxy_info.as_ref().map(|p| p.2).unwrap_or(false);
        let xtcp_sk = proxy_info.as_ref().map(|p| p.3.clone()).unwrap_or_default();

        if visitor_addr.is_empty() {
            warn!(proxy_name = %proxy_name, "NatHoleClient without visitor_addr for '{}'", proxy_name);
            Self::send_nat_hole_report(writer, v2, sid.clone(), false, "no visitor_addr").await;
            return;
        }

        // Go v0.70 compat: UDP hole punch + KCP data plane.
        // Bind socket FIRST (before sending NatHoleSid) so the UDP port
        // is ready when the visitor starts sending probe packets.
        // Go frp compat: bind UDP before sending NatHoleSid notification.
        let is_v4 = visitor_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.is_ipv4())
            .unwrap_or(false);
        let bind_addr = if is_v4 { "0.0.0.0:0" } else { "[::]:0" };
        let fallback = if is_v4 { "[::]:0" } else { "0.0.0.0:0" };
        let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => match tokio::net::UdpSocket::bind(fallback).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(proxy_name = %proxy_name, error = %e, "XTCP: failed to bind UDP socket: {}", e);
                    Self::send_nat_hole_report(writer, v2, sid, false, "bind failed").await;
                    return;
                }
            },
        };

        // Send NatHoleSid now that the UDP socket is bound and ready.
        let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
            sid: Some(sid.clone()),
            ..Default::default()
        });
        if let Err(e) = write_msg(&mut *writer.lock().await, &sid_msg, v2).await {
            warn!(error = %e, "Failed to send NatHoleSid: {}", e);
            return;
        }

        let candidates = vec![visitor_addr];
        let conv = frp_core::xtcp_p2p::conv_from_sid(&sid);
        #[allow(clippy::default_constructed_unit_structs)]
        let kcp_cfg = frp_core::kcp::default_kcp_config();
        let p2p_key = if !xtcp_sk.is_empty() {
            Some(frp_core::xtcp_p2p::derive_detect_key(&xtcp_sk))
        } else {
            None
        };
        let p2p_sid = if sid.is_empty() {
            None
        } else {
            Some(sid.as_str())
        };

        match frp_core::xtcp_p2p::xtcp_p2p_connect_yamux(
            socket,
            &candidates,
            conv,
            kcp_cfg,
            5000,
            false, // yamux_client = false (provider/server)
            p2p_sid,
            p2p_key.as_ref(),
        )
        .await
        {
            Ok(mut p2p_stream) => {
                // Send NatHoleReport with success=true after successful hole punch
                // (Go frp compat: provider reports hole punch result to server)
                Self::send_nat_hole_report(writer, v2, sid.clone(), true, "hole punch succeeded")
                    .await;
                if let Some(ref local) = local_addr {
                    match tokio::net::TcpStream::connect(local).await {
                        Ok(local_stream) => {
                            frp_core::transport::set_nodelay(&local_stream);
                            let use_enc = xtcp_use_enc && !xtcp_sk.is_empty();
                            let use_comp = xtcp_use_comp;
                            let sk = xtcp_sk.clone();
                            let pn = proxy_name.clone();
                            tokio::spawn(async move {
                                let (local_r, local_w) = local_stream.into_split();
                                let (p2p_r, p2p_w) = tokio::io::split(&mut p2p_stream);
                                if use_enc {
                                    let key = frp_core::encryption::derive_key(&sk);
                                    frp_core::bridge::bridge_encrypted(
                                        local_r,
                                        local_w,
                                        p2p_r,
                                        p2p_w,
                                        &key,
                                        use_comp,
                                        vec![],
                                        None,
                                        None,
                                        None,
                                    )
                                    .await;
                                } else {
                                    frp_core::bridge::bridge_plain(
                                        local_r,
                                        local_w,
                                        p2p_r,
                                        p2p_w,
                                        use_comp,
                                        vec![],
                                        None,
                                    )
                                    .await;
                                }
                                debug!(proxy_name = %pn, "XTCP provider '{}' encrypted P2P closed", pn);
                            });
                        }
                        Err(e) => {
                            warn!(proxy_name = %proxy_name, error = %e, "XTCP provider '{}': connect local failed: {}", proxy_name, e);
                            Self::send_nat_hole_report(
                                writer,
                                v2,
                                sid,
                                false,
                                "connect local failed",
                            )
                            .await;
                        }
                    }
                } else {
                    warn!(proxy_name = %proxy_name, "XTCP provider '{}': no local address", proxy_name);
                    Self::send_nat_hole_report(writer, v2, sid, false, "no local addr").await;
                }
            }
            Err(e) => {
                warn!(proxy_name = %proxy_name, error = %e, "XTCP hole punch for '{}' failed: {}", proxy_name, e);
                Self::send_nat_hole_report(writer, v2, sid, false, "hole punch failed").await;
            }
        }
    }

    /// Build and send a NatHoleReport for `sid`; log at debug on failure.
    /// `reason` labels the failure context in the log line.
    async fn send_nat_hole_report(
        writer: &Arc<Mutex<WriteHalf>>,
        v2: bool,
        sid: String,
        success: bool,
        reason: &str,
    ) {
        let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
            sid: Some(sid),
            success,
        });
        if let Err(e) = write_msg(&mut *writer.lock().await, &report, v2).await {
            debug!(error = %e, "Failed to send NatHoleReport ({reason})");
        }
    }

    /// Handle a NatHoleResp message from the server (XTCP response).
    ///
    /// Routes to waiting visitor (by transaction_id) or spawns provider hole
    /// punch task (by sid). Provider side iterates candidate addresses from
    /// the server's NAT analysis.
    async fn handle_nat_hole_resp(
        &self,
        resp: msg::NatHoleResp,
        pending_xtcp: &mut HashMap<String, String>,
        visitor_pending: &mut HashMap<String, oneshot::Sender<Result<msg::NatHoleResp, String>>>,
        xtcp_sockets: &std::sync::Arc<
            tokio::sync::Mutex<
                std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
            >,
        >,
        writer: &Arc<Mutex<WriteHalf>>,
    ) {
        // Route to waiting visitor first (Go frps compat path).
        let txn_id = resp.transaction_id.clone();
        if !txn_id.is_empty() {
            if let Some(tx) = visitor_pending.remove(&txn_id) {
                info!(transaction_id = %txn_id, "XTCP visitor: received NatHoleResp for txn '{}'", txn_id);
                let _ = tx.send(Ok(resp));
                return;
            }
        }
        // Fall through: route to provider by server sid
        let sid = resp.sid.clone().unwrap_or_default();
        if let Some(err) = resp.error {
            warn!(error = %err, "XTCP NatHoleResp error: {}", err);
            if let Some(ref sid) = resp.sid {
                pending_xtcp.remove(sid);
            }
            return;
        }
        let proxy_name = pending_xtcp.remove(&sid).unwrap_or_default();
        if proxy_name.is_empty() {
            warn!(sid = %sid, "XTCP NatHoleResp: unknown sid '{}'", sid);
            return;
        }
        let candidate_addrs = resp.candidate_addrs.unwrap_or_default();
        info!(proxy_name = %proxy_name, candidate_count = %candidate_addrs.len(), "XTCP provider '{}': received {} candidate addresses from server",
            proxy_name, candidate_addrs.len());

        // Go frp v0.69.1 compat: use ReadTimeoutMs from the server's
        // NatHoleResp.detect_behavior as the hole-punch timeout, not a
        // hardcoded 5000ms. The server computes this as max(SendDelayMs) + 5000
        // (+30000 if listen_random_ports) minus the side's own send_delay.
        // Default to 5000ms if detect_behavior is not available.
        let hole_punch_timeout = resp
            .detect_behavior
            .as_ref()
            .map(|db| db.read_timeout_ms.max(0) as u64)
            .unwrap_or(5000);

        // Spawn hole punch task (don't block control loop)
        let proxy_info = self.proxy_info_map.read().await.get(&proxy_name).map(|p| {
            (
                p.local_addr.clone(),
                p.use_encryption,
                p.use_compression,
                p.sk.clone(),
            )
        });
        let local_addr = proxy_info.as_ref().map(|p| p.0.clone());
        let xtcp_use_enc = proxy_info.as_ref().map(|p| p.1).unwrap_or(false);
        let xtcp_use_comp = proxy_info.as_ref().map(|p| p.2).unwrap_or(false);
        let xtcp_sk = proxy_info.as_ref().map(|p| p.3.clone()).unwrap_or_default();
        let proxy_name_clone = proxy_name.clone();
        let sid_clone = sid.clone();
        let xtcp_sockets_clone = xtcp_sockets.clone();
        let hp_timeout = hole_punch_timeout;
        let resp_writer = writer.clone();
        let resp_v2 = self.cfg.v2;
        tokio::spawn(async move {
            // Retrieve the STUN socket persisted by the control loop.
            let stun_socket = {
                let mut map = xtcp_sockets_clone.lock().await;
                map.remove(&sid_clone)
            };

            // Bind socket address family matching the first candidate to avoid
            // IPv4/IPv6 mismatch (EINVAL on macOS).
            let is_v4 = candidate_addrs
                .first()
                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                .map(|a| a.is_ipv4())
                .unwrap_or(false);
            let bind_addr = if is_v4 { "0.0.0.0:0" } else { "[::]:0" };
            let fallback_bind = if is_v4 { "[::]:0" } else { "0.0.0.0:0" };

            let socket = if let Some(arc_sock) = stun_socket {
                // Try to unwrap the Arc. If there are other references,
                // bind a fresh socket (unlikely — we removed from map).
                match std::sync::Arc::try_unwrap(arc_sock) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!(proxy_name = %proxy_name_clone, "XTCP provider '{}': STUN socket still shared, binding fresh", proxy_name_clone);
                        match tokio::net::UdpSocket::bind(bind_addr).await {
                            Ok(s) => s,
                            Err(_) => match tokio::net::UdpSocket::bind(fallback_bind).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': failed to bind UDP socket", proxy_name_clone);
                                    return;
                                }
                            },
                        }
                    }
                }
            } else {
                match tokio::net::UdpSocket::bind(bind_addr).await {
                    Ok(s) => s,
                    Err(_) => match tokio::net::UdpSocket::bind(fallback_bind).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': failed to bind UDP socket", proxy_name_clone);
                            return;
                        }
                    },
                }
            };

            // UDP hole punch + KCP data plane (Go v0.70 compat).
            let conv = frp_core::xtcp_p2p::conv_from_sid(&sid_clone);
            #[allow(clippy::default_constructed_unit_structs)]
            let kcp_cfg = frp_core::kcp::default_kcp_config();
            let p2p_key = if !xtcp_sk.is_empty() {
                Some(frp_core::xtcp_p2p::derive_detect_key(&xtcp_sk))
            } else {
                None
            };
            let p2p_sid = if sid_clone.is_empty() {
                None
            } else {
                Some(sid_clone.as_str())
            };
            // Provider acts as yamux server: accepts the visitor's stream.
            match frp_core::xtcp_p2p::xtcp_p2p_connect_yamux(
                socket,
                &candidate_addrs,
                conv,
                kcp_cfg,
                hp_timeout,
                false, // yamux_client = false (provider/server)
                p2p_sid,
                p2p_key.as_ref(),
            )
            .await
            {
                Ok(mut p2p_stream) => {
                    // Send NatHoleReport with success=true after successful hole punch
                    // (Go frp compat: provider reports hole punch result to server).
                    let ok_report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                        sid: Some(sid_clone.clone()),
                        success: true,
                    });
                    let mut w = resp_writer.lock().await;
                    let _ = frp_core::protocol::write_msg(&mut *w, &ok_report, resp_v2).await;
                    drop(w);
                    info!(proxy_name = %proxy_name_clone, "XTCP provider '{}': P2P connected via KCP+yamux", proxy_name_clone);
                    if let Some(ref local) = local_addr {
                        match tokio::net::TcpStream::connect(local).await {
                            Ok(local_conn) => {
                                frp_core::transport::set_nodelay(&local_conn);
                                let use_enc = xtcp_use_enc && !xtcp_sk.is_empty();
                                let (local_r, local_w) = local_conn.into_split();
                                let (p2p_r, p2p_w) = tokio::io::split(&mut p2p_stream);
                                if use_enc {
                                    let key = frp_core::encryption::derive_key(&xtcp_sk);
                                    frp_core::bridge::bridge_encrypted(
                                        local_r,
                                        local_w,
                                        p2p_r,
                                        p2p_w,
                                        &key,
                                        xtcp_use_comp,
                                        vec![],
                                        None,
                                        None,
                                        None,
                                    )
                                    .await;
                                } else {
                                    frp_core::bridge::bridge_plain(
                                        local_r,
                                        local_w,
                                        p2p_r,
                                        p2p_w,
                                        xtcp_use_comp,
                                        vec![],
                                        None,
                                    )
                                    .await;
                                }
                                debug!(proxy_name = %proxy_name_clone, "XTCP provider '{}' P2P closed", proxy_name_clone);
                            }
                            Err(e) => {
                                warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': connect local failed", proxy_name_clone);
                                let fail_report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                    sid: Some(sid_clone.clone()),
                                    success: false,
                                });
                                let mut w = resp_writer.lock().await;
                                let _ =
                                    frp_core::protocol::write_msg(&mut *w, &fail_report, resp_v2)
                                        .await;
                                drop(w);
                            }
                        }
                    } else {
                        warn!(proxy_name = %proxy_name_clone, "XTCP provider '{}': no local address", proxy_name_clone);
                        let fail_report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                            sid: Some(sid_clone.clone()),
                            success: false,
                        });
                        let mut w = resp_writer.lock().await;
                        let _ = frp_core::protocol::write_msg(&mut *w, &fail_report, resp_v2).await;
                        drop(w);
                    }
                }
                Err(e) => {
                    warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': UDP+KCP+yamux hole punch failed", proxy_name_clone);
                    let fail_report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                        sid: Some(sid_clone.clone()),
                        success: false,
                    });
                    let mut w = resp_writer.lock().await;
                    let _ = frp_core::protocol::write_msg(&mut *w, &fail_report, resp_v2).await;
                    drop(w);
                }
            }
        });
    }

    /// Start a single plugin and return its handle with resolved bound address.
    /// Used during reload to restart plugins with updated config.
    /// Returns None if plugin_type is unknown or start fails (logged internally).
    async fn start_plugin(
        &self,
        proxy_name: &str,
        plugin_cfg: &frp_core::config::PluginConfig,
    ) -> Option<PluginHandle> {
        let result = if plugin_cfg.plugin_type == "visitor_plugin" {
            let ctx = PluginContext {
                server_addr: self.cfg.server_addr.clone(),
                server_port: self.cfg.server_port,
                transport_protocol: self.cfg.transport_protocol.clone(),
                tls_enable: self.cfg.tls_enable,
                tls_server_name: self.cfg.tls_server_name.clone(),
                tls_ca_file: opt_if_empty!(self.cfg.tls_ca_file),
                use_encryption: true,
                use_compression: false,
                token: self.auth_cfg.token.clone(),
                oidc_client: self.oidc_client.clone(),
            };
            dispatch_plugin_start(plugin_cfg, Some(ctx)).await
        } else {
            dispatch_plugin_start(plugin_cfg, None).await
        };

        match result {
            Ok(handle) => {
                info!(
                    plugin_type = %plugin_cfg.plugin_type,
                    proxy_name = %proxy_name,
                    addr = %handle.local_addr,
                    "{} plugin for '{}' restarted on {}",
                    plugin_cfg.plugin_type, proxy_name, handle.local_addr
                );
                Some(handle)
            }
            Err(e) => {
                warn!(
                    plugin_type = %plugin_cfg.plugin_type,
                    proxy_name = %proxy_name,
                    error = %e,
                    "Failed to restart {} plugin for '{}': {}",
                    plugin_cfg.plugin_type, proxy_name, e
                );
                None
            }
        }
    }

    /// Reload configuration from file. Used by admin API and SIGUSR1.
    ///
    /// Diffs old vs new proxy configs, restarts affected plugins, sends
    /// CloseProxy/NewProxy messages with correct plugin bound addresses,
    /// and updates the shared proxy_info_map.
    pub async fn try_reload(
        &self,
        config_path: &str,
        strict: bool,
        writer: &Arc<Mutex<WriteHalf>>,
    ) -> Result<String, String> {
        let delta = crate::reload::do_reload(&self.proxy_info_map, config_path, strict).await?;

        if delta.removed.is_empty() && delta.added.is_empty() && delta.changed.is_empty() {
            return Ok(delta.summary);
        }

        let v2 = self.cfg.v2;

        // Step 1: Cancel health checks and drop old PluginHandles for removed
        // and changed proxies. Health check tasks hold Arc<AtomicBool> cancel
        // flags — setting them to true stops the health check loop. PluginHandle::Drop
        // sends a oneshot shutdown signal to the plugin task.
        {
            let mut cancels = self
                .health_cancels
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for name in delta.removed.iter().chain(delta.changed.iter()) {
                if let Some(cancel) = cancels.get(name) {
                    cancel.store(true, Ordering::Relaxed);
                }
                cancels.remove(name);
            }
        }
        {
            let mut handles = self
                .plugin_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for name in delta.removed.iter().chain(delta.changed.iter()) {
                if handles.remove(name).is_some() {
                    debug!(proxy_name = %name, "Dropped old plugin handle for '{}'", name);
                }
            }
        }

        // Step 2: Start new plugins for added and changed proxies that have plugin config.
        // Collect actual bound addresses for use in NewProxy messages and map updates.
        let mut plugin_addrs: HashMap<String, String> = HashMap::new();
        for name in delta.added.iter().chain(delta.changed.iter()) {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                if let Some(ref plugin_cfg) = p.plugin {
                    if let Some(handle) = self.start_plugin(name, plugin_cfg).await {
                        let addr = handle.local_addr.to_string();
                        plugin_addrs.insert(name.clone(), addr);
                        self.plugin_handles
                            .lock()
                            .unwrap()
                            .insert(name.clone(), handle);
                    }
                    // If plugin start fails, plugin_addrs won't have an entry;
                    // the proxy uses configured local_ip:local_port as fallback.
                }
            }
        }

        // Step 3: Collect all messages, then send them atomically while
        // holding the writer lock (no other .await work between writes).
        // NOTICE: Do NOT hold the writer lock across any non-write .await.
        let mut changes: Vec<String> = Vec::new();

        struct ReloadMsg {
            label: String,
            msg: FrpMessage,
        }
        let mut msgs: Vec<ReloadMsg> = Vec::new();

        // CloseProxy for removed proxies
        for name in &delta.removed {
            msgs.push(ReloadMsg {
                label: format!("send CloseProxy for '{name}'"),
                msg: FrpMessage::CloseProxy(msg::CloseProxy {
                    proxy_name: name.clone(),
                }),
            });
            changes.push(format!("proxy '{name}' removed"));
        }

        // CloseProxy + NewProxy for changed proxies
        for name in &delta.changed {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                let local_addr = plugin_addrs
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                msgs.push(ReloadMsg {
                    label: format!("send CloseProxy for changed '{name}'"),
                    msg: FrpMessage::CloseProxy(msg::CloseProxy {
                        proxy_name: name.clone(),
                    }),
                });
                msgs.push(ReloadMsg {
                    label: format!("send NewProxy for changed '{name}'"),
                    msg: crate::proxy::create_new_proxy_msg(p, &local_addr),
                });
                changes.push(format!("proxy '{name}' updated"));
            }
        }

        // NewProxy for added proxies
        for name in &delta.added {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                let local_addr = plugin_addrs
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                msgs.push(ReloadMsg {
                    label: format!("send NewProxy for added '{name}'"),
                    msg: crate::proxy::create_new_proxy_msg(p, &local_addr),
                });
                changes.push(format!("proxy '{name}' added"));
            }
        }

        // Acquire writer lock once and send all messages in a tight loop.
        // Lock is dropped after the last write — no other .await happens
        // between lock acquisition and drop.
        {
            let mut w = writer.lock().await;
            for rm in &msgs {
                write_msg(&mut *w, &rm.msg, v2)
                    .await
                    .map_err(|e| format!("{}: {e}", rm.label))?;
            }
        }

        // Log summary (no longer interleaved with sends, but functionally identical).
        for name in &delta.removed {
            tracing::info!(name = %name, "Reload: sent CloseProxy for removed '{}'", name);
        }
        for name in &delta.changed {
            tracing::info!(name = %name, "Reload: sent CloseProxy+NewProxy for changed '{}'", name);
        }
        for name in &delta.added {
            tracing::info!(name = %name, "Reload: sent NewProxy for added '{}'", name);
        }

        // Step 4: Update proxy_info_map so admin API and work conn lookups
        // reflect the new proxy set with correct plugin bound addresses.
        {
            let mut map = self.proxy_info_map.write().await;
            for name in &delta.removed {
                map.remove(name);
            }
            for name in delta.changed.iter().chain(delta.added.iter()) {
                if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                    let bw_limit =
                        frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
                    let local_addr = plugin_addrs
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                    let plugin_type = p
                        .plugin
                        .as_ref()
                        .map(|pl| pl.plugin_type.clone())
                        .unwrap_or_default();
                    let snapshot = crate::reload::config_snapshot(p);
                    let mut err = String::new();
                    // If this proxy has a plugin but plugin_addrs doesn't have it,
                    // the plugin failed to start — record the error
                    if p.plugin.is_some() && !plugin_addrs.contains_key(name) {
                        err = format!("plugin '{}' failed to start", plugin_type);
                    }
                    map.insert(
                        name.clone(),
                        ProxyRuntimeInfo {
                            local_addr,
                            proxy_type: p.proxy_type.clone(),
                            use_encryption: p.use_encryption,
                            use_compression: p.use_compression,
                            sk: p.sk.clone(),
                            bandwidth_limit: bw_limit,
                            bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
                            proxy_protocol_version: p.proxy_protocol_version.clone(),
                            plugin: plugin_type,
                            remote_addr: String::new(),
                            err,
                            config_snapshot: snapshot,
                            phase: ProxyPhase::New,
                        },
                    );
                }
            }
        }

        // Step 5: Spawn health checks for added and changed proxies that
        // have health_check configured. The health_cancels entries for
        // changed proxies were removed in step 1 — re-add them here.
        if !delta.added.is_empty() || !delta.changed.is_empty() {
            let hc_proxies: Vec<frp_core::config::ProxyConfig> = delta
                .new_config
                .proxies
                .iter()
                .filter(|p| delta.added.contains(&p.name) || delta.changed.contains(&p.name))
                .cloned()
                .collect();
            if !hc_proxies.is_empty() {
                self.spawn_health_checks(&hc_proxies, &self.health_tx, &self.health_cancels)
                    .await;
            }
        }

        // Step 6: Update health_proxy_configs to match the new proxy set.
        // This ensures that on HealthEvent::Recover, the correct config is
        // used to re-register the proxy after reload.
        {
            let mut configs = self
                .health_proxy_configs
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for name in &delta.removed {
                configs.remove(name);
            }
            for name in delta.changed.iter().chain(delta.added.iter()) {
                if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                    if p.health_check_type.is_empty() {
                        configs.remove(name);
                    } else {
                        configs.insert(name.clone(), p.clone());
                    }
                }
            }
        }

        let summary = changes.join("; ");
        tracing::info!(summary = %summary, "Config reload summary: {}", summary);
        Ok(format!("reload success: {summary}"))
    }
}

/// Inject an OS-level route directing traffic for `subnet` through the
/// given TUN interface. This makes the kernel send matching packets to
/// the TUN device instead of the physical NIC / default gateway.
#[cfg(feature = "vnet")]
fn add_os_route(subnet: &str, tun_name: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(["route", "add", subnet, "dev", tun_name])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let (net, _mask) = match subnet.split_once('/') {
            Some(s) => s,
            None => {
                tracing::warn!("invalid subnet format for OS route: {subnet}");
                return;
            }
        };
        let _ = std::process::Command::new("route")
            .args(["add", "-net", net, "-interface", tun_name])
            .output();
    }
}

/// List local non-loopback IPv4 addresses for NAT hole punching.
/// Go frp v0.69.1 compat: nathole.ListLocalIPsForNatHole.
///
/// Enumerates local network interfaces and returns up to `max_items`
/// non-loopback, non-link-local IPv4 addresses. On Linux, reads from
/// /proc/net/fib_trie, with a fallback to `ip -o -4 addr show`. On
/// macOS, uses `/sbin/ifconfig`. On other platforms (e.g. Windows),
/// returns an empty vec.
fn list_local_ips_for_nat_hole(max_items: usize) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();

    // Linux: parse /proc/net/fib_trie for local IPs
    #[cfg(target_os = "linux")]
    {
        if ips.len() < max_items {
            if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
                let mut in_local = false;
                for line in content.lines() {
                    if ips.len() >= max_items {
                        break;
                    }
                    let trimmed = line.trim();
                    if trimmed == "Local:" {
                        in_local = true;
                        continue;
                    }
                    if in_local && trimmed.is_empty() {
                        break;
                    }
                    if in_local {
                        // Lines with "|" under "Local:" section contain local IPs
                        if let Some(ip_part) = trimmed
                            .strip_prefix('|')
                            .or_else(|| trimmed.strip_prefix("+-"))
                        {
                            for word in ip_part.split_whitespace() {
                                if let Ok(ip) = word.parse::<std::net::Ipv4Addr>() {
                                    if !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_multicast()
                                    {
                                        ips.push(ip.to_string());
                                    }
                                    break; // first valid IP per line
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Linux fallback: `ip -o -4 addr show`
    #[cfg(target_os = "linux")]
    {
        if ips.is_empty() {
            if let Ok(output) = std::process::Command::new("ip")
                .args(["-o", "-4", "addr", "show"])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if ips.len() >= max_items {
                            break;
                        }
                        // Format: "1: lo    inet 127.0.0.1/8 scope host lo"
                        // We want the "inet" line with the IP address
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for part in &parts {
                            if let Some(ip_str) = part.split('/').next() {
                                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                    if !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_multicast()
                                    {
                                        ips.push(ip.to_string());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // macOS fallback: parse ifconfig output
    #[cfg(target_os = "macos")]
    {
        if ips.is_empty() {
            if let Ok(output) = std::process::Command::new("/sbin/ifconfig").output() {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if ips.len() >= max_items {
                            break;
                        }
                        let trimmed = line.trim();
                        if let Some(ip_str) = trimmed.strip_prefix("inet ") {
                            let fields: Vec<&str> = ip_str.split_whitespace().collect();
                            if let Some(addr) = fields.first() {
                                if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                                    if !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_multicast()
                                    {
                                        ips.push(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_backoff_delay_phase1_fast_retry() {
        // First 3 retries (counts_in_fast_retry_window <= 3) use 200ms + 0.5 jitter
        // Expected range: 200ms-300ms
        for i in 1..=3u32 {
            for _ in 0..100 {
                let delay = Service::fast_backoff_delay(i, i);
                let ms = delay.as_millis();
                assert!(ms >= 200, "delay {ms}ms too low for fast retry {i}");
                assert!(ms <= 300, "delay {ms}ms too high for fast retry {i}");
            }
        }
    }

    #[test]
    fn fast_backoff_delay_phase2_base_first() {
        // After fast retries (counts_in_fast_retry_window > 3), consecutive_err_count=1
        // Go frp: InitDurationIfFail(1s) * Factor(2) = 2s + 10% additive jitter -> 2000-2200ms
        for _ in 0..100 {
            let delay = Service::fast_backoff_delay(1, 4);
            let ms = delay.as_millis();
            assert!(ms >= 2000, "delay {ms}ms below 2s for phase2 first");
            assert!(ms <= 2200, "delay {ms}ms above 2.2s for phase2 first");
        }
    }

    #[test]
    fn fast_backoff_delay_phase2_exponential() {
        // consecutive_err_count=4, counts_in_fast_retry_window=5 -> 1s*2^4=16s + 10% jitter
        // Range: 16000-17600ms
        for _ in 0..100 {
            let delay = Service::fast_backoff_delay(4, 5);
            let ms = delay.as_millis();
            assert!(ms >= 16000, "delay {ms}ms below 16s for err=4");
            assert!(ms <= 17600, "delay {ms}ms above 17.6s for err=4");
        }
    }

    #[test]
    fn fast_backoff_delay_phase2_caps_at_20s() {
        // High consecutive_err_count should cap at 20s
        for _ in 0..100 {
            let delay = Service::fast_backoff_delay(20, 20);
            let ms = delay.as_millis();
            assert!(ms >= 20000, "delay {ms}ms below 20s cap");
            assert!(ms <= 21000, "delay {ms}ms above 21s cap (20s + 10% jitter)");
        }
    }

    #[test]
    fn fast_backoff_delay_monotonic_in_mean() {
        // Mean delay should increase with consecutive_err_count
        fn mean_delay(consecutive: u32, window: u32) -> f64 {
            (0..50)
                .map(|_| Service::fast_backoff_delay(consecutive, window).as_millis() as f64)
                .sum::<f64>()
                / 50.0
        }
        let m1 = mean_delay(1, 4); // phase2, 2s
        let m2 = mean_delay(2, 5); // phase2, 4s
        let m5 = mean_delay(5, 6); // phase2, 20s (capped)
        assert!(m2 > m1, "mean delay should grow: {m2} > {m1}");
        assert!(m5 > m2, "mean delay should grow: {m5} > {m2}");
    }
}
