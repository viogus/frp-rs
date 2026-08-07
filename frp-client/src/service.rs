use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
#[cfg(all(feature = "vnet", test))]
use tokio::sync::watch;
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

use frp_core::encryption;
use frp_core::msg::{self, ClientSpec, FrpMessage};
use frp_core::protocol::{read_msg, write_msg};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{BoxedWriteHalf, TransportProtocol};

use frp_core::metrics::ProxyMetricsRegistry;

#[cfg(feature = "admin")]
use crate::admin::AdminState;
use crate::control::ControlConnection;
use crate::plugin::{self, PluginContext, PluginHandle};
use crate::proxy::wire_proxy_name;
use crate::proxy_runtime::{ProxyPhase, ProxyRuntimeInfo, ReloadRequest};
use crate::store::{merge_client_config, StoreSource};
use crate::util::opt_if_empty;
#[cfg(feature = "vnet")]
use crate::vnet::*;
use crate::work_conn::XtcpNotification;

/// Go frp v0.70.1 visitor plugin type for virtual-net host routes.
pub(crate) const VISITOR_PLUGIN_VIRTUAL_NET: &str = "virtual_net";

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
    /// Per-proxy health check cancel flags. Keyed by proxy name.
    /// Set to true on CloseProxy/CloseProxyResp; entry removed in try_reload.
    health_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    /// Proxy configs for health-checked proxies, used to re-register on health recovery.
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
    /// Keyed by proxy name.
    #[cfg(feature = "vnet")]
    vnet_tun_tx: Arc<std::sync::Mutex<HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Per-proxy cancellation senders for running vnet controllers.
    #[cfg(feature = "vnet")]
    vnet_tun_cancels: VnetTunCancelMap,
    /// Per-proxy TUN device names for OS route injection.
    #[cfg(feature = "vnet")]
    pub(crate) vnet_tun_names: Arc<Mutex<HashMap<String, String>>>,
    /// Per-proxy subnet CIDR for directing virtual_net visitor return traffic.
    #[cfg(feature = "vnet")]
    pub(crate) vnet_tun_subnets: Arc<Mutex<HashMap<String, String>>>,
    /// Peer proxy name → (advertised subnet, TUN interface, virtual net) for
    /// OS routes injected from VnetRouteAdvertise. The vnet is stored so route
    /// table entries can be removed in the right partition on VnetRouteRemove
    /// and on control disconnect.
    #[cfg(feature = "vnet")]
    vnet_peer_routes: Arc<Mutex<HashMap<String, VnetPeerRoute>>>,
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
        mut cfg: ClientConfig,
        config_file: Option<String>,
        unsafe_features: UnsafeFeatures,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Load the file-backed store when [store] path is set and overlay its
        // proxies/visitors on the config file entries (Go frp v0.70.1 store
        // source semantics).
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

        let auth_token_source = cfg.auth.as_ref().and_then(|a| a.token_source.clone());
        let token = if let Some(ref source) = auth_token_source {
            source
                .validate()
                .map_err(|e| format!("invalid auth.tokenSource: {e}"))
                .map_err(std::io::Error::other)?;
            frp_core::auth::validate_token_source_unsafe(source, &unsafe_features)
                .map_err(std::io::Error::other)?;
            source
                .resolve()
                .map_err(|e| format!("failed to resolve auth.tokenSource: {e}"))
                .map_err(std::io::Error::other)?
        } else {
            frp_core::auth::resolve_dynamic_token_checked(&cfg.token, &unsafe_features)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "resolve_dynamic_token error: {e}");
                    String::new()
                })
        };
        let auth_cfg = AuthConfig {
            method: auth_method.clone(),
            token,
            token_source: auth_token_source,
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
            // Go frp v0.70.1 compat: auth.oidc.tokenSource (dynamic token
            // source, mutually exclusive with the client-credentials flow).
            // The config validator enforces mutual exclusivity; exec sources
            // additionally require the unsafe-features gate like auth.tokenSource.
            let token_source = ac.oidc_token_source.clone();
            if let Some(ref source) = token_source {
                frp_core::auth::validate_token_source_unsafe(source, &unsafe_features)
                    .map_err(std::io::Error::other)?;
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
                .filter(|p| !p.health_check_type.is_empty())
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
            nat_hole_stun_server,
            xtcp_tx,
            xtcp_rx: std::sync::Mutex::new(Some(xtcp_rx)),
            visitor_tx,
            visitor_rx: std::sync::Mutex::new(Some(visitor_rx)),
            visitor_reload_needed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            health_cancels: Arc::new(Mutex::new(HashMap::new())),
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
        self.spawn_health_checks(&startup_proxies, &self.health_tx, &health_cancels)
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
        let xtcp_tx = self.xtcp_tx.clone();
        let nat_hole_stun_server = self.nat_hole_stun_server.clone();
        let (_stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        #[cfg(feature = "admin")]
        self.spawn_admin_server(&_reload_tx, &_stop_tx).await;

        // Main session loop with reconnection.
        // Go frp dev two-phase fast-backoff:
        //   Phase 1 (first 3 retries within 60s window): 200ms × full jitter (0.5-1.5)
        //   Phase 2 (after that): 1s × 2ⁿ × full jitter (0.5-1.5), cap 20s
        // Matches Go frp dev wait.FastBackoffManager (full multiplicative
        // jitter replaces the additive jitter so clients restarting together
        // de-synchronize instead of re-clustering in a narrow band).
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
            let cfg_local = self.cfg.read().await.clone();
            let all_proxies = Arc::clone(&*self.proxies.read().await);
            let proxies = filter_active_proxies(&cfg_local, &all_proxies);

            // Go frp compat (d486018): drop previous yamux session before
            // creating a new control connection. This drops the sender channel,
            // causing the background yamux task to exit and close the TCP socket.
            #[cfg(feature = "tcp-mux")]
            drop(prev_yamux.take());
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
                opt_if_empty!(cfg_local.tls_cert_file),
                opt_if_empty!(cfg_local.tls_key_file),
                opt_if_empty!(cfg_local.dns_server),
                cfg_local.tcp_mux,
                cfg_local.disable_custom_tls_first_byte,
                cfg_local.dial_server_keepalive.max(0) as u64,
                cfg_local.tcp_mux_keepalive_interval,
                opt_if_empty!(cfg_local.connect_server_local_ip),
                cfg_local.v2,
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
                ),
            );

            #[cfg(feature = "quic")]
            let quic_conn: Option<QuicConnection>;

            let (mut control_stream, run_id, yamux_session) = match ctl.login().await {
                Ok(r) => {
                    did_login_once = true;
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
                    if cfg_local.login_fail_exit && !did_login_once {
                        return Err(e.into());
                    }
                    let delay = if did_login_once {
                        // Session reconnect: full fast-backoff with Phase 1 (200ms) + Phase 2 (exponential).
                        fast_retry_timestamps.push(Instant::now());
                        let window_count =
                            crate::backoff::prune_fast_retry_count(&mut fast_retry_timestamps);
                        crate::backoff::fast_backoff_delay(consecutive_err_count, window_count)
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
            let v2 = cfg_local.v2;
            info!(run_id = %run_id, "Logged in. run_id: {}", run_id);

            let session_alive = Arc::new(AtomicBool::new(true));

            // Shared pool/work-conn configuration. Both the registration read
            // loop (below) and the on-demand ReqWorkConn handler in the message
            // loop build a byte-identical WorkConnConfig differing only in
            // `pool_id`. Collapse into one macro (defined here so its free
            // identifier references resolve against the locals in scope).
            let client_scopes: Vec<String> = cfg_local
                .auth
                .as_ref()
                .map(|a| a.additional_auth_scopes.clone())
                .unwrap_or_default();
            let server_scopes = self.server_auth_scopes.read().await.clone();
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
            macro_rules! work_conn_config {
                ($pool_id:expr) => {{
                    #[cfg(feature = "quic")]
                    let quic_arg = quic_conn.clone();
                    #[cfg(not(feature = "quic"))]
                    let quic_arg = ();
                    crate::work_conn::WorkConnConfig {
                        server_addr: cfg_local.server_addr.clone(),
                        server_port: cfg_local.server_port,
                        protocol: protocol.clone(),
                        run_id: run_id.clone(),
                        proxy_info_map: self.proxy_info_map.clone(),
                        enc_key: self.encryption_key,
                        pool_id: $pool_id,
                        auth_cfg: self.auth_cfg.clone(),
                        tls_enable: cfg_local.tls_enable,
                        tls_server_name: cfg_local.tls_server_name.clone(),
                        tls_ca_file: opt_if_empty!(cfg_local.tls_ca_file),
                        tls_cert_file: opt_if_empty!(cfg_local.tls_cert_file),
                        tls_key_file: opt_if_empty!(cfg_local.tls_key_file),
                        dns_server: opt_if_empty!(cfg_local.dns_server),
                        yamux: yamux.clone(),
                        quic_conn: quic_arg,
                        v2,
                        oidc_client: self.oidc_client.clone(),
                        udp_sockets: udp_sockets.clone(),
                        udp_enc_cfg: udp_enc_cfg.clone(),
                        udp_packet_size: cfg_local.udp_packet_size.max(0) as usize,
                        proxy_metrics: self.proxy_metrics.clone(),
                        client_auth_scopes: client_scopes.clone(),
                        server_auth_scopes: server_scopes.clone(),
                        disable_custom_tls_first_byte: cfg_local.disable_custom_tls_first_byte,
                        keepalive_secs: cfg_local.dial_server_keepalive.max(0) as u64,
                        bind_addr: opt_if_empty!(cfg_local.connect_server_local_ip),
                        proxy_url: cfg_local.proxy_url.clone(),
                        dial_timeout_secs: cfg_local.dial_server_timeout.max(1) as u64,
                        xtcp_tx: xtcp_tx.clone(),
                        session_alive: session_alive.clone(),
                        spawned_counter: None,
                        #[cfg(feature = "vnet")]
                        vnet_tuns: self.vnet_tuns.clone(),
                        #[cfg(feature = "vnet")]
                        vnet_controller: self.vnet_controller.clone(),
                        #[cfg(feature = "vnet")]
                        vnet_tun_tx: self.vnet_tun_tx.clone(),
                    }
                }};
            }

            // Go frp compat: work connections are created ONLY in response to
            // ReqWorkConn messages from the server (pool pre-warm sent right
            // after LoginResp, NewVisitorConn acks, and on-demand requests —
            // handled in the registration read loop below and the message loop
            // further down). Do NOT eagerly spawn pool_count connections here;
            // pool_count is sent to the server via Login so it knows how many
            // ReqWorkConn messages to issue.
            let handle_req_work_conn = || {
                // Go frp v0.70.1 spawns each ReqWorkConn handler asynchronously
                // with no client-side in-flight cap (client/control.go:
                // handleReqWorkConn). Spawn directly so a burst of requests
                // cannot overflow a queue or tear down the control session;
                // each work conn's dial/StartWorkConn read is still bounded by
                // its own timeout in work_conn.rs.
                debug!("Received ReqWorkConn, spawning work connection");
                crate::work_conn::spawn_work_conn(work_conn_config!(-1));
            };

            // Register proxies using IoStream directly (supports TCP and TLS).
            // Pipelined: write ALL NewProxy frames first, then collect the
            // responses in a single read loop — N proxies no longer cost N
            // sequential network round-trips (Go frpc registers each proxy in
            // its own goroutine, so Go frps may answer out of order; each
            // response is matched to its proxy by wire proxy_name). ReqWorkConn
            // frames arriving in this window (pool pre-warm, or a user conn
            // hitting the server mid-registration) are handled here instead of
            // dropped: skipping them left the pool empty after login and let
            // the server's work-conn wait stall for up to 10s.
            let mut pending_proxies: Vec<(String, usize)> = Vec::new();
            let mut write_failed = false;
            for (idx, p) in proxies.iter().enumerate() {
                let local_addr = self
                    .proxy_info_map
                    .read()
                    .await
                    .get(&wire_proxy_name(&cfg_local.user, &p.name))
                    .map(|info| info.local_addr.clone())
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                let np = crate::proxy::create_new_proxy_msg(p, &local_addr, &cfg_local.user);
                debug!(
                    name = %p.name,
                    proxy_type = %p.proxy_type,
                    remote_port = p.remote_port,
                    encrypted = p.use_encryption,
                    compressed = p.use_compression,
                    "NewProxy message prepared"
                );
                info!(name = %p.name, proxy_type = %p.proxy_type, remote_port = %p.remote_port, local_addr = %local_addr,
                    "Registering proxy '{}' type={} remote_port={} local={}",
                    p.name, p.proxy_type, p.remote_port, local_addr);
                let wire_name = wire_proxy_name(&cfg_local.user, &p.name);
                let write_result = if v2 {
                    control_stream.write_v2_frame(&np).await
                } else {
                    control_stream.write_v1_frame(&np).await
                };
                if let Err(e) = write_result {
                    // A failed write leaves the stream state undefined; record
                    // the failure, mark the proxy failed, and skip the response
                    // phase entirely (responses for the unwritten requests may
                    // never arrive — see `write_failed`/`aborted` below).
                    write_failed = true;
                    warn!(proxy_name = %p.name, error = %e, "Failed to register proxy '{}': {}", p.name, e);
                    let mut map = self.proxy_info_map.write().await;
                    if let Some(info) = map.get_mut(&wire_name) {
                        info.err = e.to_string();
                        info.phase = ProxyPhase::StartErr(e.to_string());
                    }
                    continue;
                }
                pending_proxies.push((wire_name, idx));
            }

            // Register STCP/XTCP visitors on the control connection.
            // Go frps v0.69.1 requires visitor registration before NatHoleVisitor
            // can be sent on the control connection (otherwise: "auth failed").
            // Pipelined like the proxies: write all NewVisitorConn frames, then
            // resolve them in the shared read loop below.
            let session_visitors_cfg = self.cfg.read().await.visitors.clone();
            let session_visitors: Vec<&frp_core::config::VisitorConfig> = session_visitors_cfg
                .iter()
                .filter(|v| v.enabled && v.bind_port != 0)
                .collect();
            let mut pending_visitors: Vec<(String, usize)> = Vec::new();
            for (idx, v) in session_visitors.iter().enumerate() {
                let nvc = crate::proxy::create_visitor_conn_msg(
                    &v.server_name,
                    &v.secret_key,
                    v.use_encryption,
                    v.use_compression,
                    Some(v.server_user.as_str()).filter(|s| !s.is_empty()),
                    Some(cfg_local.user.as_str()).filter(|s| !s.is_empty()),
                    Some(run_id.as_str()).filter(|s| !s.is_empty()),
                );
                debug!(
                    server_name = %v.server_name,
                    encrypted = v.use_encryption,
                    compressed = v.use_compression,
                    "NewVisitorConn message prepared"
                );
                info!(visitor_name = %v.name, proxy_name = %v.server_name, "Registering visitor '{}' for proxy '{}'", v.name, v.server_name);
                let wire_name = crate::proxy::visitor_wire_name(
                    Some(v.server_user.as_str()).filter(|s| !s.is_empty()),
                    Some(cfg_local.user.as_str()).filter(|s| !s.is_empty()),
                    &v.server_name,
                );
                let write_result = if v2 {
                    control_stream.write_v2_frame(&nvc).await
                } else {
                    control_stream.write_v1_frame(&nvc).await
                };
                if let Err(e) = write_result {
                    write_failed = true;
                    warn!(visitor_name = %v.name, error = %e, "Failed to register visitor '{}': {}", v.name, e);
                    continue;
                }
                pending_visitors.push((wire_name, idx));
            }

            // Collect responses. NewProxyResp/NewVisitorConnResp are matched to
            // their request by wire proxy_name — the server answers
            // synchronously in request order, but matching by name keeps this
            // robust regardless of response order. ReqWorkConn spawns a work
            // connection (pool pre-warm — written by the server immediately
            // after LoginResp, BEFORE any registration response — a
            // NewVisitorConn success ack, or an on-demand user conn that
            // arrived while the client was still registering).
            let mut aborted = write_failed;
            let mut unexpected = 0u32;
            // False until the first NewProxyResp / NewVisitorConnResp /
            // visitor-ack ReqWorkConn has been handled. The server's pool
            // pre-warm ReqWorkConns always precede every registration
            // response on the wire (see I2), so anonymous ReqWorkConns
            // received before this point can never be visitor acks.
            let mut seen_registration_response = false;
            // Anonymous ReqWorkConns consumed so far — bounds the pool
            // pre-warm when no proxy registration exists to mark its end.
            let mut req_work_conns_seen = 0usize;
            while !aborted && (!pending_proxies.is_empty() || !pending_visitors.is_empty()) {
                // Go frp v0.70.1 never acks control-channel NewVisitorConn —
                // its stcp/xtcp visitors register per user connection when the
                // connection arrives, not at startup. A pure-visitor client
                // must therefore not wait forever for a visitor ack the server
                // will never send. Once every proxy response is in, give the
                // remaining visitor acks a 2s grace period — our server writes
                // its ack in the same control iteration as the pool conns (ms
                // under load, ~200x headroom) — then assume the un-acked
                // visitors registered (Go frps semantics) and stop reading.
                // Any frames the server still writes afterwards are handled by
                // the session's main read loop.
                let resp_msg = if pending_proxies.is_empty() && !pending_visitors.is_empty() {
                    let read = async {
                        if v2 {
                            control_stream.read_v2_frame().await
                        } else {
                            control_stream.read_v1_frame().await
                        }
                    };
                    match tokio::time::timeout(Duration::from_millis(2000), read).await {
                        Ok(Ok(m)) => m,
                        Ok(Err(e)) => {
                            warn!(error = %e, "Registration response read failed: {}", e);
                            aborted = true;
                            continue;
                        }
                        Err(_elapsed) => {
                            // The server will not ack the remaining visitors
                            // (Go frps semantics: NewVisitorConn succeeds
                            // silently; per-user connections register
                            // themselves when they arrive). FIFO-drain them
                            // as registered — same semantics as the
                            // ReqWorkConn attribution above, but with no
                            // server response at all.
                            while !pending_visitors.is_empty() {
                                let (_, idx) = pending_visitors.remove(0);
                                let v = session_visitors[idx];
                                info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}' (no registration response — assumed registered)", v.name, v.server_name);
                                #[cfg(feature = "vnet")]
                                advertise_vnet_visitor_route(&mut control_stream, v2, v).await;
                            }
                            break;
                        }
                    }
                } else {
                    if v2 {
                        match control_stream.read_v2_frame().await {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(error = %e, "Registration response read failed: {}", e);
                                aborted = true;
                                continue;
                            }
                        }
                    } else {
                        match control_stream.read_v1_frame().await {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(error = %e, "Registration response read failed: {}", e);
                                aborted = true;
                                continue;
                            }
                        }
                    }
                };
                match resp_msg {
                    FrpMessage::NewProxyResp(resp) => {
                        seen_registration_response = true;
                        // Match by wire proxy_name: responses may arrive in any
                        // order relative to the requests they answer.
                        let Some(pos) = pending_proxies
                            .iter()
                            .position(|(name, _)| *name == resp.proxy_name)
                        else {
                            unexpected += 1;
                            warn!(proxy_name = %resp.proxy_name, "NewProxyResp for proxy not in this registration batch");
                            continue;
                        };
                        let (_, idx) = pending_proxies.swap_remove(pos);
                        let p = &proxies[idx];
                        if let Some(err) = resp.error {
                            warn!(proxy_name = %p.name, error = %err, "Failed to register proxy '{}': {}", p.name, err);
                            let mut map = self.proxy_info_map.write().await;
                            if let Some(info) =
                                map.get_mut(&wire_proxy_name(&cfg_local.user, &p.name))
                            {
                                info.err = err.clone();
                                info.phase = ProxyPhase::StartErr(err);
                            }
                        } else {
                            let remote = resp
                                .remote_addr
                                .unwrap_or_else(|| format!("0.0.0.0:{}", p.remote_port));
                            info!(proxy_name = %p.name, remote = %remote, "Proxy '{}' registered on remote port {}", p.name, remote);
                            // Update runtime info for admin API
                            let mut map = self.proxy_info_map.write().await;
                            if let Some(info) =
                                map.get_mut(&wire_proxy_name(&cfg_local.user, &p.name))
                            {
                                info.remote_addr = remote;
                                info.err.clear();
                                info.phase = ProxyPhase::Running;
                            }

                            #[cfg(feature = "vnet")]
                            if vnet_tun_params(p, &cfg_local.virtual_net.address).is_some() {
                                if let Err(e) = self.open_vnet_tun_for_proxy(p, &cfg_local).await {
                                    warn!(proxy_name = %p.name, error = %e, "TUN open/register failed (need root/CAP_NET_ADMIN?)");
                                }
                            }
                        }
                    }
                    FrpMessage::NewVisitorConnResp(resp) => {
                        seen_registration_response = true;
                        let Some(pos) = pending_visitors
                            .iter()
                            .position(|(name, _)| *name == resp.proxy_name)
                        else {
                            unexpected += 1;
                            // Defensive: an out-of-batch response is almost
                            // always a REJECTED visitor whose earlier
                            // ReqWorkConn ack was misattributed (e.g. a pool
                            // pre-warm conn consumed as its success signal),
                            // leaving the failure unnamed and discarded here.
                            // Resolve the wire name against the configured
                            // visitor list and surface the error so a future
                            // ordering change cannot silently swallow an auth
                            // failure.
                            let configured = session_visitors.iter().find(|v| {
                                crate::proxy::visitor_wire_name(
                                    Some(v.server_user.as_str()).filter(|s| !s.is_empty()),
                                    Some(cfg_local.user.as_str()).filter(|s| !s.is_empty()),
                                    &v.server_name,
                                ) == resp.proxy_name
                            });
                            match configured {
                                Some(v) => {
                                    warn!(visitor_name = %v.name, proxy_name = %resp.proxy_name, error = ?resp.error, "NewVisitorConnResp for visitor '{}' (wire '{}') not in this registration batch: {:?}", v.name, resp.proxy_name, resp.error)
                                }
                                None => {
                                    warn!(proxy_name = %resp.proxy_name, "NewVisitorConnResp for visitor not in this registration batch")
                                }
                            }
                            continue;
                        };
                        let (_, idx) = pending_visitors.swap_remove(pos);
                        let v = session_visitors[idx];
                        if let Some(err) = resp.error {
                            warn!(visitor_name = %v.name, error = %err, "Failed to register visitor '{}': {}", v.name, err);
                        } else {
                            info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}'", v.name, v.server_name);
                            // Virtual-net visitors advertise their destination IP
                            // as a host route instead of binding a local listener.
                            #[cfg(feature = "vnet")]
                            advertise_vnet_visitor_route(&mut control_stream, v2, v).await;
                        }
                    }
                    FrpMessage::ReqWorkConn(_) => {
                        handle_req_work_conn();
                        // Go frps v0.69.1 acks a successful NewVisitorConn on
                        // the control channel with an anonymous ReqWorkConn
                        // (no proxy_name; failures get a named
                        // NewVisitorConnResp{error}). While visitors are
                        // still pending, attribute the ack to the oldest one
                        // (FIFO — the server answers registrations in request
                        // order, so acks arrive in visitor order).
                        //
                        // The server writes its pool pre-warm ReqWorkConns
                        // immediately after LoginResp, BEFORE it processes any
                        // registration frame, so they always precede every
                        // NewProxyResp/NewVisitorConnResp on the wire. An
                        // anonymous ReqWorkConn can therefore only be a
                        // visitor success ack once a registration response has
                        // been seen. (With no proxies there is no NewProxyResp
                        // to mark the pool's end; the client's own pool_count
                        // bounds it instead — the server never sends more pool
                        // conns than the client asked for.) Without this gate
                        // the pool conns were FIFO-attributed to the oldest
                        // pending visitors, marking them registered (and
                        // advertising vnet routes) before the server had even
                        // seen their NewVisitorConn — a rejected visitor's
                        // real response then hit the out-of-batch branch above
                        // and was silently discarded.
                        let pool_conns_done = seen_registration_response
                            || (pending_proxies.is_empty()
                                && req_work_conns_seen >= pool_count.max(1) as usize);
                        if pool_conns_done && !pending_visitors.is_empty() {
                            let (_, idx) = pending_visitors.remove(0);
                            let v = session_visitors[idx];
                            info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}' (Go frps compat: ReqWorkConn after NewVisitorConn)", v.name, v.server_name);
                            #[cfg(feature = "vnet")]
                            advertise_vnet_visitor_route(&mut control_stream, v2, v).await;
                        }
                        req_work_conns_seen += 1;
                    }
                    other => {
                        unexpected += 1;
                        warn!(
                            type_byte = other.v1_type_byte(),
                            "Unexpected message during registration"
                        );
                    }
                }
                if unexpected >= 100 {
                    warn!("Registration aborted: too many unexpected messages");
                    aborted = true;
                }
            }

            // Any request still pending here never got an answer (write
            // failure, read error, or too many unexpected frames). Mark the
            // proxies failed and log the unresolved visitors; the session
            // continues — registration errors do not abort the client
            // (login_fail_exit only governs the login phase).
            if !pending_proxies.is_empty() || !pending_visitors.is_empty() {
                warn!(proxies = %pending_proxies.len(), visitors = %pending_visitors.len(), "Registration aborted; marking still-pending proxies/visitors as failed");
                for (wire_name, _) in pending_proxies.drain(..) {
                    let mut map = self.proxy_info_map.write().await;
                    if let Some(info) = map.get_mut(&wire_name) {
                        info.err = "registration aborted (no response)".to_string();
                        info.phase =
                            ProxyPhase::StartErr("registration aborted (no response)".to_string());
                    }
                }
                for (_, idx) in pending_visitors.drain(..) {
                    let v = session_visitors[idx];
                    warn!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registration unresolved", v.name);
                }
            }

            // Split control stream for reading and writing
            let (mut reader, raw_writer) = control_stream.into_split()?;
            let writer = Arc::new(Mutex::new(raw_writer));

            // Spawn VnetControllers for all vnet proxies now that the
            // control connection writer is available.
            #[cfg(feature = "vnet")]
            for p in &proxies {
                if vnet_tun_params(p, &cfg_local.virtual_net.address).is_none() {
                    continue;
                }
                if spawn_vnet_tun_controller(
                    &self.vnet_tuns,
                    &self.vnet_tun_tx,
                    &self.vnet_tun_cancels,
                    &self.vnet_controller,
                    &p.name,
                    &p.virtual_net,
                    &writer,
                    v2,
                )
                .await
                .is_some()
                {
                    send_vnet_route_advertise(&writer, v2, p).await;
                }
            }

            // Shared graceful shutdown signal for all visitor listener tasks.
            // Set to true at session end so tasks exit cleanly (Fix 8).
            let visitor_shutdown = Arc::new(AtomicBool::new(false));

            // Cancel old visitor listener tasks from a previous session.
            // Signal gracefully and wait briefly for the previous session's
            // visitors to exit, instead of aborting them (Go frp compat:
            // visitor_manager.Close() closes each visitor cleanly). The
            // previous session's visitor_shutdown was already set when the
            // session ended; tasks should exit on their own. join_all waits on
            // all tasks in parallel — per-task sequential 500ms timeouts would
            // multiply the reconnect delay by the number of stuck visitors.
            // Dropped (still-running) tasks poll the shutdown flag and exit.
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                futures_util::future::join_all(visitor_handles.drain(..)),
            )
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
                            let transport_dial_timeout =
                                cfg_local.dial_server_timeout.max(1) as u64;
                            let transport_keepalive = cfg_local.dial_server_keepalive.max(0) as u64;
                            let transport_nocustomtls = cfg_local.disable_custom_tls_first_byte;
                            let user = cfg_local.user.clone();
                            let rid = run_id.clone();
                            let controller = self.vnet_controller.clone();
                            let vnet_tun_tx = self.vnet_tun_tx.clone();
                            let tun_subnets = self.vnet_tun_subnets.clone();
                            let shutdown = visitor_shutdown.clone();
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
                                        proxy_url: transport_proxy_url.clone(),
                                        dns_server: transport_dns.clone(),
                                        dial_timeout_secs: transport_dial_timeout,
                                        keepalive_secs: transport_keepalive,
                                        connect_bind_addr: transport_bind.clone(),
                                        disable_custom_tls_first_byte: transport_nocustomtls,
                                        tls_cert_file: transport_tls_cert.clone(),
                                        tls_key_file: transport_tls_key.clone(),
                                        v2: cfg_local.v2,
                                        destination_cidr: adv.subnet,
                                        controller,
                                        vnet_tun_tx,
                                        tun_subnets,
                                        shutdown,
                                    },
                                )
                                .await;
                            });
                            visitor_handles.push(handle);
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
                let transport_dial_timeout = cfg_local.dial_server_timeout.max(1) as u64;
                let transport_keepalive = cfg_local.dial_server_keepalive.max(0) as u64;
                let transport_nocustomtls = cfg_local.disable_custom_tls_first_byte;
                let visitor_type = v.visitor_type.clone();
                let fallback_timeout_ms = v.fallback_timeout_ms;
                let keep_tunnel_open = v.keep_tunnel_open;
                let max_retries_an_hour = v.max_retries_an_hour;
                let min_retry_interval = v.min_retry_interval;
                let stun_server = nat_hole_stun_server.clone();
                let fallback_to = v.fallback_to.clone();
                let disable_assisted_addrs = v.disable_assisted_addrs;
                let p2p_protocol = v.protocol.clone();
                let user = cfg_local.user.clone();
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
                        tcp_mux: transport_tcp_mux,
                        tcp_mux_keepalive_interval: transport_tcp_mux_keepalive,
                        proxy_url: transport_proxy_url.clone(),
                        dns_server: transport_dns.clone(),
                        dial_timeout_secs: transport_dial_timeout,
                        keepalive_secs: transport_keepalive,
                        connect_bind_addr: transport_bind.clone(),
                        disable_custom_tls_first_byte: transport_nocustomtls,
                        tls_cert_file: transport_tls_cert.clone(),
                        tls_key_file: transport_tls_key.clone(),
                        v2: cfg_local.v2,
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
            let mut ping_interval = if cfg_local.heartbeat_interval > 0 {
                let secs = cfg_local.heartbeat_interval as u64;
                info!(interval = %secs, "Heartbeat interval: {}s", secs);
                Some(tokio::time::interval(Duration::from_secs(secs)))
            } else {
                info!("Heartbeat: explicitly disabled (heartbeat_interval <= 0)");
                None
            };

            // Proxy retry interval: every 30s, re-register proxies stuck in StartErr.
            // Matches Go frp's proxy_wrapper.checkWorker (default startErrTimeout 30s).
            let mut proxy_retry_interval = tokio::time::interval(Duration::from_secs(30));
            proxy_retry_interval.tick().await; // Skip first immediate tick

            let mut last_pong = Instant::now();
            let hb_timeout = cfg_local.heartbeat_timeout;
            let hb_timeout_dur = Duration::from_secs(hb_timeout.max(0) as u64);

            loop {
                tokio::select! {
                    msg = read_msg(&mut reader, v2) => {
                        match msg {
                            Ok(FrpMessage::ReqWorkConn(_)) => {
                                // Shared with the registration read loop above.
                                handle_req_work_conn();
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
                                let mut cancels = health_cancels.lock().await;
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
                                    let err = resp
                                        .error
                                        .as_ref()
                                        .expect("is_some_and guard above guarantees Some");
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
                                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                                    {
                                        let names = self.vnet_tun_names.lock().await;
                                        if let Some(tun_name) = names.values().next() {
                                            add_os_route(&adv.subnet, tun_name);
                                            self.vnet_peer_routes.lock().await.insert(
                                                adv.proxy_name.clone(),
                                                (
                                                    adv.subnet.clone(),
                                                    tun_name.clone(),
                                                    vnet.clone(),
                                                ),
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
                                                    if tx.try_send(packet).is_err() {
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
                        // Auth scopes: unioning the client's own scopes with the
                        // server-advertised scopes is a Rust-to-Rust extension.
                        // Go v0.70.1's TokenAuthSetterVerifier.SetPing checks only
                        // the client's own additionalAuthScopes
                        // (pkg/auth/token.go:44-51); Go has no
                        // serverAdditionalAuthScopes field in LoginResp, so the
                        // server side of this union is ignored by Go peers.
                        let send_auth = crate::backoff::heartbeat_requires_auth(
                            &client_scopes,
                            &server_scopes,
                        );
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
                                match self.auth_cfg.try_generate_login_key(ts) {
                                    Ok(key) => {
                                        ping_msg.privilege_key = Some(key);
                                        ping_msg.timestamp = Some(ts);
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "Ping token source failed: {}. Reconnecting...", e);
                                        break;
                                    }
                                }
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
                            let bare_name = if cfg_local.user.is_empty() { name.as_str() } else {
                                name.strip_prefix(&format!("{}.", cfg_local.user)).unwrap_or(&name)
                            };
                            if let Some(p) = proxies.iter().find(|p| p.name == bare_name) {
                                let new_proxy = crate::proxy::create_new_proxy_msg(p, &local_addr, &cfg_local.user);
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
                                    let new_proxy = crate::proxy::create_new_proxy_msg(&cfg, &local_addr, &cfg_local.user);
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
                        if result.is_ok()
                            && self.visitor_reload_needed.swap(false, Ordering::AcqRel)
                        {
                            // Visitor changes require a clean session restart.
                            tracing::info!("Visitor config changed — restarting session");
                            let _ = req.reply.send(Ok("reload success: visitor changes applied on session restart".into()));
                            break;
                        }
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
                    // active when hb_timeout > 0. Explicit negative values
                    // disable it independently of tcp_mux.
                    _ = tokio::time::sleep(Duration::from_secs(1)), if hb_timeout > 0 => {
                        if last_pong.elapsed() > hb_timeout_dur {
                            warn!("Heartbeat timeout ({}s), reconnecting...", hb_timeout);
                            break;
                        }
                    }
                }
            }

            // Clean up vnet routes advertised by virtual_net visitors before
            // dropping the control connection. The server also removes routes
            // during control teardown; this mirrors Go frp's explicit
            // VnetRouteRemove from the visitor plugin Close().
            #[cfg(feature = "vnet")]
            {
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
                for v in &session_visitors {
                    if v.plugin.as_ref().is_none() || !v.enabled {
                        continue;
                    }
                    if let Some(adv) = virtual_net_visitor_route_adv(v) {
                        self.vnet_controller.unregister_visitor_route(&v.name).await;
                        let rem = msg::VnetRouteRemove {
                            proxy_name: adv.proxy_name,
                            virtual_net: adv.virtual_net,
                        };
                        let msg = FrpMessage::VnetRouteRemove(rem);
                        if let Err(e) = write_msg(&mut *writer.lock().await, &msg, v2).await {
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
            // join_all waits on all tasks in parallel — sequential per-task
            // 500ms timeouts would cost N×500ms for N stuck visitors, twice per
            // reconnect. Dropped (still-running) tasks poll the shutdown flag.
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                futures_util::future::join_all(visitor_handles.drain(..)),
            )
            .await;

            // Check if admin stop was requested
            if shutdown_flag.load(Ordering::SeqCst) {
                info!("frpc shutting down");
                return Ok(());
            }

            // Session dropped — reconnect with Go frp dev two-phase fast-backoff.
            // login_fail_exit only applies to initial login, not session drops.
            let delay = crate::backoff::reconnect_delay_after_session(
                &mut consecutive_err_count,
                &mut fast_retry_timestamps,
            );
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
        health_cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    ) {
        let user = self.cfg.read().await.user.clone();
        for p in proxies {
            let wn = wire_proxy_name(&user, &p.name);
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
                .get(&wn)
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let pn = wn.clone();
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
                let mut cancels = health_cancels.lock().await;
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
    async fn spawn_admin_server(
        &self,
        reload_tx: &mpsc::Sender<ReloadRequest>,
        stop_tx: &mpsc::Sender<()>,
    ) {
        let cfg_snapshot = self.cfg.read().await.clone();
        if cfg_snapshot.web_server.port > 0 {
            let admin_addr = frp_core::format_socket_addr(
                &cfg_snapshot.web_server.addr,
                cfg_snapshot.web_server.port,
            );
            let admin_state = AdminState {
                proxy_metrics: self.proxy_metrics.clone(),
                proxies: self.proxy_info_map.clone(),
                reload_tx: reload_tx.clone(),
                stop_tx: stop_tx.clone(),
                config_path: self.config_file.clone(),
                store: self.store_source.clone(),
            };
            let admin_auth_user = cfg_snapshot.web_server.user.clone();
            let admin_auth_pwd = cfg_snapshot.web_server.password.clone();
            let admin_tls_cert = if cfg_snapshot.web_server.tls_cert_file.is_empty() {
                None
            } else {
                Some(cfg_snapshot.web_server.tls_cert_file.clone())
            };
            let admin_tls_key = if cfg_snapshot.web_server.tls_key_file.is_empty() {
                None
            } else {
                Some(cfg_snapshot.web_server.tls_key_file.clone())
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
            info!(addr = %cfg_snapshot.web_server.addr, port = %cfg_snapshot.web_server.port, "frpc admin server starting on {}:{}", cfg_snapshot.web_server.addr, cfg_snapshot.web_server.port);
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
        writer: &Arc<Mutex<BoxedWriteHalf>>,
    ) -> Result<String, String> {
        self.reload_from_sources(config_path, strict, writer).await
    }

    /// Reload the config file, merge the optional store overlay, and apply the
    /// resulting proxy/visitor changes to the running service.
    ///
    /// Also refreshes the in-memory config/proxy snapshots so the next session
    /// and admin API see the merged result.
    pub async fn reload_from_sources(
        &self,
        config_path: &str,
        strict: bool,
        writer: &Arc<Mutex<BoxedWriteHalf>>,
    ) -> Result<String, String> {
        let mut new_cfg = frp_core::config::load_client_config(config_path, strict)
            .map_err(|e| format!("failed to load config: {e}"))?;
        if let Some(ref store) = self.store_source {
            if let Err(e) = store.reload() {
                tracing::warn!(error = %e, "store reload failed, using in-memory state");
            }
            new_cfg = merge_client_config(&new_cfg, Some(store));
        }
        // Source-local enabled filtering, then apply the start allowlist so the
        // reload diff never registers store/config proxies outside `start`.
        new_cfg.proxies.retain(|p| p.enabled);
        new_cfg.visitors.retain(|v| v.enabled);
        let active_proxies = filter_active_proxies(&new_cfg, &new_cfg.proxies);
        new_cfg.proxies = active_proxies;
        new_cfg.visitors = filter_active_visitors(&new_cfg, &new_cfg.visitors);

        let user = new_cfg.user.clone();
        let old_visitors = self.cfg.read().await.visitors.clone();
        #[cfg(feature = "vnet")]
        let mut delta =
            crate::reload::do_reload(&self.proxy_info_map, &old_visitors, new_cfg, &user).await?;
        #[cfg(not(feature = "vnet"))]
        let delta =
            crate::reload::do_reload(&self.proxy_info_map, &old_visitors, new_cfg, &user).await?;

        // reload::config_snapshot omits vnet-only fields; extend the delta so
        // a subnet/IP/mask change still rebuilds the TUN during reload.
        #[cfg(feature = "vnet")]
        {
            let old_cfg = self.cfg.read().await.clone();
            let old_proxies = Arc::clone(&*self.proxies.read().await);
            for p in &delta.new_config.proxies {
                let old = old_proxies.iter().find(|old| old.name == p.name);
                let vnet_field_changed =
                    old.is_some_and(|old| vnet_proxy_snapshot(old) != vnet_proxy_snapshot(p));
                let global_changed = old_cfg.virtual_net.address
                    != delta.new_config.virtual_net.address
                    && p.plugin
                        .as_ref()
                        .is_some_and(|pl| pl.plugin_type == "virtual_net");
                if (vnet_field_changed || global_changed) && !delta.changed.contains(&p.name) {
                    delta.changed.push(p.name.clone());
                }
            }
        }

        if delta.removed.is_empty()
            && delta.added.is_empty()
            && delta.changed.is_empty()
            && delta.visitor_removed.is_empty()
            && delta.visitor_added.is_empty()
            && delta.visitor_changed.is_empty()
        {
            let merged = delta.new_config;
            *self.cfg.write().await = merged;
            *self.proxies.write().await = Arc::new(self.cfg.read().await.proxies.clone());
            return Ok(delta.summary);
        }

        // Visitor listeners are session-scoped; a visitor change requires a
        // clean session restart so the new visitor set is fully rebuilt
        // (Go frp's visitor_manager stop/start equivalent).
        let visitor_changed = !delta.visitor_removed.is_empty()
            || !delta.visitor_added.is_empty()
            || !delta.visitor_changed.is_empty();

        let v2 = delta.new_config.v2;

        // Step 1: Cancel health checks and drop old PluginHandles for removed
        // and changed proxies. Health check tasks hold Arc<AtomicBool> cancel
        // flags — setting them to true stops the health check loop. PluginHandle::Drop
        // sends a oneshot shutdown signal to the plugin task.
        {
            let mut cancels = self.health_cancels.lock().await;
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

        // Drop TUN state for removed and changed proxies before recreating it.
        // Changed proxies must get a fresh TUN and a fresh delivery channel.
        // The vnet comes from the pre-reload config (removed proxies are still
        // present there; self.cfg is refreshed at the end of the reload).
        #[cfg(feature = "vnet")]
        for name in delta.removed.iter().chain(delta.changed.iter()) {
            let vnet = self
                .cfg
                .read()
                .await
                .proxies
                .iter()
                .find(|p| &p.name == name)
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
                writer,
                v2,
                name,
                &vnet,
            )
            .await;
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
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(name.clone(), handle);
                    }
                    // If plugin start fails, plugin_addrs won't have an entry;
                    // the proxy uses configured local_ip:local_port as fallback.
                }
            }
        }

        // Open/register TUN devices and spawn controllers for added and
        // changed vnet proxies before NewProxy is sent, so a work conn that
        // arrives immediately can find the fresh delivery channel.
        #[cfg(feature = "vnet")]
        for name in delta.added.iter().chain(delta.changed.iter()) {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                if vnet_tun_params(p, &delta.new_config.virtual_net.address).is_none() {
                    continue;
                }
                if let Err(e) = self.open_vnet_tun_for_proxy(p, &delta.new_config).await {
                    warn!(proxy_name = %name, error = %e, "reload TUN open/register failed");
                    continue;
                }
                spawn_vnet_tun_controller(
                    &self.vnet_tuns,
                    &self.vnet_tun_tx,
                    &self.vnet_tun_cancels,
                    &self.vnet_controller,
                    name,
                    &p.virtual_net,
                    writer,
                    v2,
                )
                .await;
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
        let user = delta.new_config.user.clone();
        for name in &delta.removed {
            let wn = wire_proxy_name(&user, name);
            msgs.push(ReloadMsg {
                label: format!("send CloseProxy for '{name}'"),
                msg: FrpMessage::CloseProxy(msg::CloseProxy { proxy_name: wn }),
            });
            changes.push(format!("proxy '{name}' removed"));
        }

        // CloseProxy + NewProxy for changed proxies
        for name in &delta.changed {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                let wn = wire_proxy_name(&user, name);
                let local_addr = plugin_addrs
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                msgs.push(ReloadMsg {
                    label: format!("send CloseProxy for changed '{name}'"),
                    msg: FrpMessage::CloseProxy(msg::CloseProxy { proxy_name: wn }),
                });
                msgs.push(ReloadMsg {
                    label: format!("send NewProxy for changed '{name}'"),
                    msg: crate::proxy::create_new_proxy_msg(p, &local_addr, &user),
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
                    msg: crate::proxy::create_new_proxy_msg(p, &local_addr, &user),
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

        // Advertise vnet subnets only after the corresponding NewProxy has
        // been sent, so the server has a proxy to associate the route with.
        #[cfg(feature = "vnet")]
        for name in delta.added.iter().chain(delta.changed.iter()) {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                send_vnet_route_advertise(writer, v2, p).await;
            }
        }

        // Step 4: Update proxy_info_map so admin API and work conn lookups
        // reflect the new proxy set with correct plugin bound addresses.
        {
            let mut map = self.proxy_info_map.write().await;
            for name in &delta.removed {
                map.remove(&wire_proxy_name(&user, name));
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
                        wire_proxy_name(&user, name),
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
            let mut configs = self.health_proxy_configs.lock().await;
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

        // Step 7: Refresh the in-memory config/proxy snapshots so the next
        // session, reconnect, and admin status endpoint use the merged config.
        *self.cfg.write().await = delta.new_config;
        *self.proxies.write().await = Arc::new(self.cfg.read().await.proxies.clone());

        if visitor_changed {
            // Signal the session loop to restart so visitors are rebuilt.
            self.visitor_reload_needed.store(true, Ordering::Release);
            tracing::info!("Reload changed visitors — requesting session restart");
        }

        let summary = changes.join("; ");
        tracing::info!(summary = %summary, "Config reload summary: {}", summary);
        Ok(format!("reload success: {summary}"))
    }
}
/// Apply the client `start` allowlist and `enabled` flag to a proxy list.
/// Store-backed proxies go through the same filter as config-file proxies.
pub(crate) fn filter_active_proxies(
    cfg: &frp_core::config::ClientConfig,
    proxies: &[frp_core::config::ProxyConfig],
) -> Vec<frp_core::config::ProxyConfig> {
    let mut active: Vec<frp_core::config::ProxyConfig> = if cfg.start.is_empty() {
        proxies.to_vec()
    } else {
        let start_set: std::collections::HashSet<&str> =
            cfg.start.iter().map(|s| s.as_str()).collect();
        let filtered: Vec<_> = proxies
            .iter()
            .filter(|p| start_set.contains(p.name.as_str()))
            .cloned()
            .collect();
        info!(
            active = %filtered.len(), total = %proxies.len(), start = ?cfg.start,
            "Selective proxy start: {} of {} proxies active (start={:?})",
            filtered.len(),
            proxies.len(),
            cfg.start,
        );
        filtered
    };
    active.retain(|p| p.enabled);
    active
}

/// Apply the client `start` allowlist and `enabled` flag to a visitor list.
/// Mirrors Go frp v0.70.1 `FilterClientConfigurers`, which filters visitors by
/// the same `start` set as proxies.
pub(crate) fn filter_active_visitors(
    cfg: &frp_core::config::ClientConfig,
    visitors: &[frp_core::config::VisitorConfig],
) -> Vec<frp_core::config::VisitorConfig> {
    let mut active: Vec<frp_core::config::VisitorConfig> = if cfg.start.is_empty() {
        visitors.to_vec()
    } else {
        let start_set: std::collections::HashSet<&str> =
            cfg.start.iter().map(|s| s.as_str()).collect();
        let filtered: Vec<_> = visitors
            .iter()
            .filter(|v| start_set.contains(v.name.as_str()))
            .cloned()
            .collect();
        info!(
            active = %filtered.len(), total = %visitors.len(), start = ?cfg.start,
            "Selective visitor start: {} of {} visitors active (start={:?})",
            filtered.len(),
            visitors.len(),
            cfg.start,
        );
        filtered
    };
    active.retain(|v| v.enabled);
    active
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_auth_scope_unions_client_and_server_requirements() {
        let heartbeat = vec!["HeartBeats".to_string()];
        let unrelated = vec!["NewWorkConns".to_string()];

        assert!(crate::backoff::heartbeat_requires_auth(&heartbeat, &[]));
        assert!(crate::backoff::heartbeat_requires_auth(&[], &heartbeat));
        assert!(!crate::backoff::heartbeat_requires_auth(&unrelated, &[]));
        assert!(!crate::backoff::heartbeat_requires_auth(&[], &unrelated));
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn virtual_net_visitor_route_advertisement() {
        use frp_core::config::VisitorPluginConfig;

        let visitor = frp_core::config::VisitorConfig {
            name: "vnet-visitor".into(),
            visitor_type: "stcp".into(),
            server_name: "vnet-server".into(),
            bind_port: -1,
            plugin: Some(VisitorPluginConfig {
                plugin_type: "virtual_net".into(),
                destination_ip: "100.86.0.1".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let adv = virtual_net_visitor_route_adv(&visitor).expect("route advertisement");
        assert_eq!(adv.proxy_name, "vnet-visitor");
        assert_eq!(adv.subnet, "100.86.0.1/32");
        assert_eq!(adv.virtual_net, None);

        // Non-virtual-net plugins and invalid IPs produce no advertisement.
        let plain = frp_core::config::VisitorConfig {
            name: "plain".into(),
            plugin: Some(VisitorPluginConfig {
                plugin_type: "other".into(),
                destination_ip: "100.86.0.1".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(virtual_net_visitor_route_adv(&plain).is_none());

        let bad_ip = frp_core::config::VisitorConfig {
            name: "bad".into(),
            plugin: Some(VisitorPluginConfig {
                plugin_type: "virtual_net".into(),
                destination_ip: "not-an-ip".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(virtual_net_visitor_route_adv(&bad_ip).is_none());

        // IPv6 destinations advertise a /128 host route.
        let v6 = frp_core::config::VisitorConfig {
            name: "v6".into(),
            plugin: Some(VisitorPluginConfig {
                plugin_type: "virtual_net".into(),
                destination_ip: "2001:db8::1".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let adv6 = virtual_net_visitor_route_adv(&v6).expect("IPv6 route advertisement");
        assert_eq!(adv6.proxy_name, "v6");
        assert_eq!(adv6.subnet, "2001:db8::1/128");
        // VnetRouteRemove is keyed only by proxy name, so the same advertisement
        // can be converted for both IPv4 and IPv6 destinations.
        let _remove = msg::VnetRouteRemove {
            proxy_name: adv6.proxy_name,
            virtual_net: adv6.virtual_net,
        };
    }

    #[test]
    fn stable_sessions_do_not_reset_backoff_escalation() {
        // Go frp v0.70.1's fastBackoffImpl resets only when the retry callback
        // reports success; keepControllerWorking always reports an error after a
        // session closes, so escalation continues regardless of session length.
        // With full multiplicative jitter a single sample can land below the
        // previous level, so escalation is asserted on the mean over samples.
        let mut errors = 0;
        let mut retries = Vec::new();
        let fast_delays = (0..3)
            .map(|_| crate::backoff::reconnect_delay_after_session(&mut errors, &mut retries))
            .collect::<Vec<_>>();
        // Phase 1 stays sub-second (100-300ms).
        assert!(fast_delays
            .iter()
            .all(|delay| *delay < Duration::from_secs(1)));
        fn mean_level(consecutive: u32, window: u32) -> f64 {
            (0..200)
                .map(|_| crate::backoff::fast_backoff_delay(consecutive, window).as_millis() as f64)
                .sum::<f64>()
                / 200.0
        }
        let m4 = mean_level(4, 4); // phase 2, 16s base (partially capped at 20s)
        let m5 = mean_level(5, 5); // phase 2, 20s capped base
        assert!(m5 > m4, "phase-2 mean should escalate: {m5} > {m4}");
        assert_eq!(errors, 3);
    }

    #[test]
    fn fast_backoff_delay_phase1_fast_retry() {
        // First 3 retries (counts_in_fast_retry_window <= 3) use
        // 200ms × full jitter (0.5-1.5) → 100ms-300ms.
        for i in 1..=3u32 {
            for _ in 0..100 {
                let delay = crate::backoff::fast_backoff_delay(i, i);
                let ms = delay.as_millis();
                assert!(ms >= 100, "delay {ms}ms too low for fast retry {i}");
                assert!(ms <= 300, "delay {ms}ms too high for fast retry {i}");
            }
        }
    }

    #[test]
    fn fast_backoff_delay_phase2_base_first() {
        // After fast retries (counts_in_fast_retry_window > 3), consecutive_err_count=1
        // Go frp: InitDurationIfFail(1s) * Factor(2) = 2s × full jitter (0.5-1.5)
        // -> 1000-3000ms
        for _ in 0..100 {
            let delay = crate::backoff::fast_backoff_delay(1, 4);
            let ms = delay.as_millis();
            assert!(ms >= 1000, "delay {ms}ms below 1s for phase2 first");
            assert!(ms <= 3000, "delay {ms}ms above 3s for phase2 first");
        }
    }

    #[test]
    fn fast_backoff_delay_phase2_exponential() {
        // consecutive_err_count=4, counts_in_fast_retry_window=5 -> 1s*2^4=16s
        // × full jitter (0.5-1.5) -> 8000-24000ms, capped at 20000ms
        for _ in 0..100 {
            let delay = crate::backoff::fast_backoff_delay(4, 5);
            let ms = delay.as_millis();
            assert!(ms >= 8000, "delay {ms}ms below 8s for err=4");
            assert!(ms <= 20000, "delay {ms}ms above 20s cap for err=4");
        }
    }

    #[test]
    fn fast_backoff_delay_phase2_caps_at_20s() {
        // High consecutive_err_count caps the base at 20s; full jitter then
        // spreads it to 10-20s (never above the cap).
        for _ in 0..100 {
            let delay = crate::backoff::fast_backoff_delay(20, 20);
            let ms = delay.as_millis();
            assert!(ms >= 10000, "delay {ms}ms below 10s at the 20s cap");
            assert!(ms <= 20000, "delay {ms}ms above 20s cap");
        }
    }

    #[test]
    fn fast_backoff_delay_monotonic_in_mean() {
        // Mean delay should increase with consecutive_err_count
        fn mean_delay(consecutive: u32, window: u32) -> f64 {
            (0..50)
                .map(|_| crate::backoff::fast_backoff_delay(consecutive, window).as_millis() as f64)
                .sum::<f64>()
                / 50.0
        }
        let m1 = mean_delay(1, 4); // phase2, 2s
        let m2 = mean_delay(2, 5); // phase2, 4s
        let m5 = mean_delay(5, 6); // phase2, 20s (capped)
        assert!(m2 > m1, "mean delay should grow: {m2} > {m1}");
        assert!(m5 > m2, "mean delay should grow: {m5} > {m2}");
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn vnet_tun_params_and_cidr_for_plugin_and_vnet_proxies() {
        let plugin = frp_core::config::ProxyConfig {
            name: "plugin".into(),
            proxy_type: "tcp".into(),
            plugin: Some(frp_core::config::PluginConfig {
                plugin_type: "virtual_net".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (ip, netmask, mtu) = vnet_tun_params(&plugin, "10.0.0.1").expect("plugin TUN params");
        assert_eq!(ip, "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(
            netmask,
            "255.255.255.0".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(mtu, 1420);
        assert_eq!(
            vnet_tun_cidr(&plugin, "10.0.0.1").as_deref(),
            Some("10.0.0.0/24")
        );

        let vnet = frp_core::config::ProxyConfig {
            name: "vnet".into(),
            proxy_type: "vnet".into(),
            vnet_ip: "10.1.2.3".into(),
            vnet_netmask: "255.255.0.0".into(),
            vnet_mtu: 1400,
            ..Default::default()
        };
        let (ip, netmask, mtu) = vnet_tun_params(&vnet, "").expect("vnet TUN params");
        assert_eq!(ip, "10.1.2.3".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(
            netmask,
            "255.255.0.0".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(mtu, 1400);
        assert_eq!(vnet_tun_cidr(&vnet, "").as_deref(), Some("10.1.0.0/16"));
        assert!(vnet_tun_params(&vnet, "").is_some());
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn vnet_proxy_snapshot_detects_tun_only_changes() {
        let base = frp_core::config::ProxyConfig {
            name: "vnet".into(),
            proxy_type: "vnet".into(),
            vnet_ip: "10.0.0.1".into(),
            vnet_netmask: "255.255.255.0".into(),
            ..Default::default()
        };
        let changed_ip = frp_core::config::ProxyConfig {
            vnet_ip: "10.0.0.2".into(),
            ..base.clone()
        };
        assert_ne!(vnet_proxy_snapshot(&base), vnet_proxy_snapshot(&changed_ip));
    }

    #[test]
    fn filter_active_visitors_honors_start_allowlist_and_enabled() {
        let cfg = frp_core::config::ClientConfig {
            start: vec!["v1".into()],
            ..Default::default()
        };
        let visitors = vec![
            frp_core::config::VisitorConfig {
                name: "v1".into(),
                visitor_type: "stcp".into(),
                ..Default::default()
            },
            frp_core::config::VisitorConfig {
                name: "v2".into(),
                visitor_type: "stcp".into(),
                ..Default::default()
            },
            frp_core::config::VisitorConfig {
                name: "v3".into(),
                visitor_type: "stcp".into(),
                enabled: false,
                ..Default::default()
            },
        ];

        let active = filter_active_visitors(&cfg, &visitors);
        let names: Vec<&str> = active.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["v1"], "start allowlist must filter visitors");

        let all = filter_active_visitors(&frp_core::config::ClientConfig::default(), &visitors);
        let names: Vec<&str> = all.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["v1", "v2"], "disabled visitors stay filtered");
    }

    #[cfg(feature = "vnet")]
    struct FakeTun {
        inner: tokio::io::DuplexStream,
        configured: Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(feature = "vnet")]
    impl tokio::io::AsyncRead for FakeTun {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[cfg(feature = "vnet")]
    impl tokio::io::AsyncWrite for FakeTun {
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

    #[cfg(feature = "vnet")]
    impl frp_vnet::tun::TunDevice for FakeTun {
        fn configure(
            &self,
            _addr: std::net::Ipv4Addr,
            _netmask: std::net::Ipv4Addr,
            _mtu: u16,
        ) -> anyhow::Result<()> {
            self.configured
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }

        fn name(&self) -> &str {
            "fake"
        }

        fn mtu(&self) -> u16 {
            1420
        }
    }

    #[cfg(feature = "vnet")]
    fn fake_tun() -> (Box<FakeTun>, Arc<std::sync::atomic::AtomicBool>) {
        let configured = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tun = Box::new(FakeTun {
            inner: tokio::io::duplex(4096).0,
            configured: configured.clone(),
        });
        (tun, configured)
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn register_and_remove_vnet_tun_updates_all_maps() {
        let tuns: VnetTunMap = Arc::new(Mutex::new(HashMap::new()));
        let tx: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let cancels: VnetTunCancelMap = Arc::new(Mutex::new(HashMap::new()));
        let names = Arc::new(Mutex::new(HashMap::new()));
        let subnets = Arc::new(Mutex::new(HashMap::new()));
        let peer_routes = Arc::new(Mutex::new(HashMap::new()));
        let route_table = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
        let (_peer, writer_raw) = tokio::io::duplex(4096);
        let writer_stream: Box<dyn frp_core::transport::AsyncReadWrite> = Box::new(writer_raw);
        let (_, writer_half) = tokio::io::split(writer_stream);
        let writer = Arc::new(Mutex::new(
            Box::new(writer_half) as frp_core::transport::BoxedWriteHalf
        ));
        let (tun, configured) = fake_tun();

        register_vnet_tun(
            &tuns,
            &names,
            "vnet-a",
            (
                "10.0.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                1420,
            ),
            tun,
        )
        .await
        .unwrap();
        assert!(configured.load(std::sync::atomic::Ordering::Relaxed));
        assert!(tuns.lock().await.contains_key("vnet-a"));
        assert_eq!(
            names.lock().await.get("vnet-a").map(String::as_str),
            Some("fake")
        );

        route_table
            .write()
            .await
            .insert("corp-net", "vnet-a", "10.0.0.0/24")
            .unwrap();
        remove_vnet_tun(
            &tuns,
            &tx,
            &cancels,
            &names,
            &subnets,
            &route_table,
            &peer_routes,
            &writer,
            false,
            "vnet-a",
            "corp-net",
        )
        .await;
        assert!(tuns.lock().await.is_empty());
        assert!(tx.lock().unwrap().is_empty());
        assert!(cancels.lock().await.is_empty());
        assert!(names.lock().await.is_empty());
        assert!(subnets.lock().await.is_empty());
        assert!(route_table.read().await.is_empty());
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn reload_tun_controller_rebuilds_delivery_channel() {
        let tuns: VnetTunMap = Arc::new(Mutex::new(HashMap::new()));
        let tx_map: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let cancels: VnetTunCancelMap = Arc::new(Mutex::new(HashMap::new()));
        let names = Arc::new(Mutex::new(HashMap::new()));
        let subnets = Arc::new(Mutex::new(HashMap::new()));
        let peer_routes = Arc::new(Mutex::new(HashMap::new()));
        let route_table = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
        let controller = Arc::new(frp_vnet::controller::ClientVnetController::new());
        let (_peer, writer_raw) = tokio::io::duplex(4096);
        let writer_stream: Box<dyn frp_core::transport::AsyncReadWrite> = Box::new(writer_raw);
        let (_, writer_half) = tokio::io::split(writer_stream);
        let writer = Arc::new(Mutex::new(
            Box::new(writer_half) as frp_core::transport::BoxedWriteHalf
        ));

        let (tun, _) = fake_tun();
        register_vnet_tun(
            &tuns,
            &names,
            "vnet-a",
            (
                "10.0.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                1420,
            ),
            tun,
        )
        .await
        .unwrap();
        spawn_vnet_tun_controller(
            &tuns,
            &tx_map,
            &cancels,
            &controller,
            "vnet-a",
            "corp-net",
            &writer,
            false,
        )
        .await
        .expect("first controller should spawn");
        let old_tx = tx_map
            .lock()
            .unwrap()
            .get("vnet-a")
            .cloned()
            .expect("first delivery channel");

        remove_vnet_tun(
            &tuns,
            &tx_map,
            &cancels,
            &names,
            &subnets,
            &route_table,
            &peer_routes,
            &writer,
            false,
            "vnet-a",
            "corp-net",
        )
        .await;
        assert!(tx_map.lock().unwrap().is_empty());

        let (tun, _) = fake_tun();
        register_vnet_tun(
            &tuns,
            &names,
            "vnet-a",
            (
                "10.0.0.2".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                1420,
            ),
            tun,
        )
        .await
        .unwrap();
        spawn_vnet_tun_controller(
            &tuns,
            &tx_map,
            &cancels,
            &controller,
            "vnet-a",
            "corp-net",
            &writer,
            false,
        )
        .await
        .expect("second controller should spawn");
        let new_tx = tx_map
            .lock()
            .unwrap()
            .get("vnet-a")
            .cloned()
            .expect("rebuilt delivery channel");
        assert!(
            !old_tx.same_channel(&new_tx),
            "reload must not reuse the old TUN delivery channel"
        );

        remove_vnet_tun(
            &tuns,
            &tx_map,
            &cancels,
            &names,
            &subnets,
            &route_table,
            &peer_routes,
            &writer,
            false,
            "vnet-a",
            "corp-net",
        )
        .await;
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn remove_vnet_tun_sends_vnet_route_remove_and_cleans_maps() {
        let tuns: VnetTunMap = Arc::new(Mutex::new(HashMap::new()));
        let tx: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let cancels: VnetTunCancelMap = Arc::new(Mutex::new(HashMap::new()));
        let names = Arc::new(Mutex::new(HashMap::new()));
        let subnets = Arc::new(Mutex::new(HashMap::new()));
        let peer_routes = Arc::new(Mutex::new(HashMap::new()));
        let route_table = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
        let (mut peer, writer_raw) = tokio::io::duplex(4096);
        let writer_stream: Box<dyn frp_core::transport::AsyncReadWrite> = Box::new(writer_raw);
        let (_, writer_half) = tokio::io::split(writer_stream);
        let writer = Arc::new(Mutex::new(
            Box::new(writer_half) as frp_core::transport::BoxedWriteHalf
        ));

        // Pre-populate every map the removal path must clean up.
        names.lock().await.insert("vnet-a".into(), "tun0".into());
        subnets
            .lock()
            .await
            .insert("vnet-a".into(), "10.0.0.0/24".into());
        route_table
            .write()
            .await
            .insert("corp-net", "vnet-a", "10.0.0.0/24")
            .unwrap();
        route_table
            .write()
            .await
            .insert("other-net", "other", "10.9.0.0/24")
            .unwrap();
        peer_routes.lock().await.insert(
            "vnet-a".into(),
            ("192.168.0.0/24".into(), "tun0".into(), "corp-net".into()),
        );
        tuns.lock().await.insert("vnet-a".into(), None);
        tx.lock()
            .unwrap()
            .insert("vnet-a".into(), mpsc::channel(4).0);
        cancels
            .lock()
            .await
            .insert("vnet-a".into(), watch::channel(false).0);

        remove_vnet_tun(
            &tuns,
            &tx,
            &cancels,
            &names,
            &subnets,
            &route_table,
            &peer_routes,
            &writer,
            false,
            "vnet-a",
            "corp-net",
        )
        .await;

        assert!(tuns.lock().await.is_empty());
        assert!(tx.lock().unwrap().is_empty());
        assert!(cancels.lock().await.is_empty());
        assert!(names.lock().await.is_empty());
        assert!(subnets.lock().await.is_empty());
        assert!(peer_routes.lock().await.is_empty());
        // The removed proxy's route is gone; unrelated vnets are untouched.
        assert_eq!(
            route_table
                .read()
                .await
                .lookup("corp-net", &"10.0.0.5".parse().unwrap()),
            None
        );
        assert_eq!(
            route_table
                .read()
                .await
                .lookup("other-net", &"10.9.0.5".parse().unwrap()),
            Some("other")
        );

        // A VnetRouteRemove for the proxy's virtual net is sent to the server.
        match frp_core::protocol::read_msg_v1(&mut peer).await.unwrap() {
            FrpMessage::VnetRouteRemove(rem) => {
                assert_eq!(rem.proxy_name, "vnet-a");
                assert_eq!(rem.virtual_net.as_deref(), Some("corp-net"));
            }
            other => panic!("expected VnetRouteRemove frame, got {:?}", other),
        }
    }

    #[cfg(feature = "vnet")]
    #[test]
    fn local_vnet_set_collects_participating_vnets() {
        let mut cfg = frp_core::config::ClientConfig::default();
        cfg.virtual_net.address = "10.0.0.1".into();
        cfg.proxies.push(frp_core::config::ProxyConfig {
            name: "vnet-a".into(),
            proxy_type: "vnet".into(),
            vnet_ip: "10.0.0.2".into(),
            vnet_netmask: "255.255.255.0".into(),
            virtual_net: "corp-net".into(),
            ..Default::default()
        });
        cfg.proxies.push(frp_core::config::ProxyConfig {
            name: "vnet-default".into(),
            proxy_type: "vnet".into(),
            vnet_ip: "10.1.0.2".into(),
            vnet_netmask: "255.255.255.0".into(),
            ..Default::default()
        });
        cfg.visitors.push(frp_core::config::VisitorConfig {
            name: "vnet-visitor".into(),
            visitor_type: "stcp".into(),
            plugin: Some(frp_core::config::VisitorPluginConfig {
                plugin_type: "virtual_net".into(),
                destination_ip: "100.86.0.1".into(),
                ..Default::default()
            }),
            ..Default::default()
        });

        let vnets = local_vnet_set(&cfg);
        assert!(vnets.contains("corp-net"));
        assert!(
            vnets.contains(""),
            "default-net proxies and virtual_net visitors join the default vnet"
        );
        assert!(!vnets.contains("other-net"));
    }
}
