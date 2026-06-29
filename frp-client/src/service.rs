use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock, oneshot};

/// Internal request from a visitor task to the control loop.
/// Visitor sends NatHoleVisitor on the control connection (Go frps compat:
/// fresh TCP connections with NatHoleVisitor are not handled by Go frps v0.69.1).
/// The oneshot delivers the server's NatHoleResp back to the waiting visitor.
pub(crate) struct VisitorRequest {
    pub nhv: msg::NatHoleVisitor,
    pub reply: oneshot::Sender<Result<msg::NatHoleResp, String>>,
}
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};
use rand::Rng;

use frp_core::auth::{AuthConfig, AuthMethod, OidcClient};
use frp_core::config::ClientConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg, write_msg};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::TransportProtocol;

use frp_core::metrics::ProxyMetricsRegistry;

use crate::plugin::{self, PluginHandle, PluginContext};
use crate::control::ControlConnection;
use crate::admin::{AdminState, ReloadRequest, ProxyRuntimeInfo};
use crate::work_conn::XtcpNotification;

/// The main frpc service.
pub struct Service {
    cfg: ClientConfig,
    auth_cfg: Arc<AuthConfig>,
    encryption_key: [u8; 16],
    /// Map proxy_name -> runtime info for looking up where to connect
    proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    /// Plugin handles kept alive for the lifetime of the service.
    _plugin_handles: Vec<PluginHandle>,
    /// OIDC client for fetching access tokens (None when auth method is Token).
    oidc_client: Option<Arc<OidcClient>>,
    /// Server-side auth scopes from LoginResp, used for Ping/NewWorkConn gating.
    server_auth_scopes: tokio::sync::RwLock<Vec<String>>,
    /// Per-proxy traffic metrics for admin API.
    proxy_metrics: Arc<ProxyMetricsRegistry>,
    /// Path to config file for admin reload/config endpoints.
    config_file: Option<String>,
    /// Channel to trigger config reload from external signal (SIGUSR1).
    reload_tx: mpsc::UnboundedSender<ReloadRequest>,
    /// Receiver side of reload channel — consumed by run().
    reload_rx: Mutex<Option<mpsc::UnboundedReceiver<ReloadRequest>>>,
    /// STUN server address for XTCP NAT traversal.
    nat_hole_stun_server: String,
    /// Channel from work connection tasks to the control loop for XTCP (provider side).
    xtcp_tx: mpsc::UnboundedSender<XtcpNotification>,
    /// Receiver side of XTCP channel — consumed by run().
    xtcp_rx: Mutex<Option<mpsc::UnboundedReceiver<XtcpNotification>>>,
    /// Channel from visitor tasks to the control loop (Go frps compat:
    /// NatHoleVisitor is sent on the control connection, not fresh TCP).
    visitor_tx: mpsc::UnboundedSender<VisitorRequest>,
    /// Receiver side of visitor channel — consumed by run().
    visitor_rx: Mutex<Option<mpsc::UnboundedReceiver<VisitorRequest>>>,
}

impl Service {
    pub async fn new(cfg: ClientConfig, config_file: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        // Determine auth method from [auth] section if present, otherwise token
        #[cfg(feature = "oidc")]
        let auth_method = if let Some(ref ac) = cfg.auth {
            if ac.method == "oidc" { AuthMethod::Oidc } else { AuthMethod::Token }
        } else {
            AuthMethod::Token
        };
        #[cfg(not(feature = "oidc"))]
        let auth_method = AuthMethod::Token;

        let auth_cfg = AuthConfig {
            method: auth_method.clone(),
            token: frp_core::auth::resolve_dynamic_token(&cfg.token),
            oidc_issuer: cfg.auth.as_ref().map(|a| a.oidc_issuer.clone()).unwrap_or_default(),
            oidc_audience: cfg.auth.as_ref().map(|a| a.oidc_audience.clone()).unwrap_or_default(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
        };

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);

        // Create OIDC client if auth method is OIDC
        #[cfg(feature = "oidc")]
        let oidc_client = if auth_method == AuthMethod::Oidc {
            let ac = cfg.auth.as_ref().ok_or("OIDC auth requires [auth] section in config")?;
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
            ).await.map_err(|e| format!("OIDC client init failed: {e}"))?;
            info!("OIDC client initialized, token endpoint: {}", client.token_endpoint());
            Some(Arc::new(client))
        } else {
            None
        };
        #[cfg(not(feature = "oidc"))]
        let oidc_client: Option<Arc<OidcClient>> = None;

        // Start plugins for proxies that have them configured.
        let mut plugin_handles = Vec::new();
        let mut plugin_addrs: HashMap<String, String> = HashMap::new();

        // Register a successfully started plugin.
        fn record_plugin(
            plugin_type: &str,
            proxy_name: &str,
            result: Result<PluginHandle, frp_core::Error>,
            addrs: &mut HashMap<String, String>,
            handles: &mut Vec<PluginHandle>,
        ) {
            match result {
                Ok(handle) => {
                    let addr = handle.local_addr.to_string();
                    info!("{plugin_type} plugin for '{proxy_name}' started on {addr}");
                    addrs.insert(proxy_name.to_string(), addr);
                    handles.push(handle);
                }
                Err(e) => {
                    warn!("Failed to start {plugin_type} plugin for '{proxy_name}': {e}");
                }
            }
        }

        for p in &cfg.proxies {
            if let Some(ref plugin_cfg) = p.plugin {
                match plugin_cfg.plugin_type.as_str() {
                    "http_proxy" => {
                        record_plugin("http_proxy", &p.name,
                            plugin::start_http_proxy(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "socks5" => {
                        record_plugin("socks5", &p.name,
                            plugin::start_socks5_proxy(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "static_file" => {
                        record_plugin("static_file", &p.name,
                            plugin::start_static_file_proxy(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "unix_domain_socket" => {
                        record_plugin("unix_domain_socket", &p.name,
                            plugin::start_unix_socket_plugin(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "tls2raw" => {
                        record_plugin("tls2raw", &p.name,
                            plugin::start_tls2raw_plugin(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "http2http" => {
                        record_plugin("http2http", &p.name,
                            plugin::start_http2http_plugin(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "http2https" => {
                        record_plugin("http2https", &p.name,
                            plugin::start_http2https_plugin(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "https2http" => {
                        record_plugin("https2http", &p.name,
                            plugin::start_https2http_plugin(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "https2https" => {
                        record_plugin("https2https", &p.name,
                            plugin::start_https2https_plugin(plugin_cfg).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    "visitor_plugin" => {
                        let plugin_ctx = PluginContext {
                            server_addr: cfg.server_addr.clone(),
                            server_port: cfg.server_port,
                            transport_protocol: cfg.transport_protocol.clone(),
                            tls_enable: cfg.tls_enable,
                            tls_server_name: cfg.tls_server_name.clone(),
                            tls_ca_file: if cfg.tls_ca_file.is_empty() { None } else { Some(cfg.tls_ca_file.clone()) },
                            use_encryption: p.use_encryption,
                            use_compression: p.use_compression,
                            token: auth_cfg.token.clone(),
                            oidc_client: oidc_client.clone(),
                        };
                        record_plugin("visitor", &p.name,
                            plugin::start_visitor_plugin(plugin_cfg, plugin_ctx).await,
                            &mut plugin_addrs, &mut plugin_handles);
                    }
                    other => {
                        warn!("Unknown plugin type '{other}' for proxy '{}'", p.name);
                    }
                }
            }
        }

        let mut map: HashMap<String, ProxyRuntimeInfo> = HashMap::new();
        for p in &cfg.proxies {
            if map.contains_key(&p.name) {
                warn!("Duplicate proxy name '{}' — only the first entry will be used", p.name);
                continue;
            }
            let bw_limit = frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
            // Use plugin address if available, otherwise use configured local_ip:local_port
            let local_addr = plugin_addrs
                .get(&p.name)
                .cloned()
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let plugin_type = p.plugin.as_ref()
                .map(|pl| pl.plugin_type.clone())
                .unwrap_or_default();
            let snapshot = crate::reload::config_snapshot(p);
            map.insert(p.name.clone(), ProxyRuntimeInfo {
                local_addr,
                proxy_type: p.proxy_type.clone(),
                use_encryption: p.use_encryption,
                use_compression: p.use_compression,
                bandwidth_limit: bw_limit,
                bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
                proxy_protocol_version: p.proxy_protocol_version.clone(),
                plugin: plugin_type,
                remote_addr: String::new(),
                err: String::new(),
                config_snapshot: snapshot,
            });
        }
        let proxy_info_map = Arc::new(RwLock::new(map));

        let (reload_tx, reload_rx) = mpsc::unbounded_channel::<ReloadRequest>();
        let (xtcp_tx, xtcp_rx) = mpsc::unbounded_channel::<XtcpNotification>();
        let (visitor_tx, visitor_rx) = mpsc::unbounded_channel::<VisitorRequest>();

        let nat_hole_stun_server = if cfg.nat_hole_stun_server.is_empty() {
            "stun:stun.l.google.com:19302".to_string()
        } else {
            cfg.nat_hole_stun_server.clone()
        };

        Ok(Self {
            cfg,
            auth_cfg: Arc::new(auth_cfg),
            encryption_key: enc_key,
            proxy_info_map,
            _plugin_handles: plugin_handles,
            oidc_client,
            server_auth_scopes: tokio::sync::RwLock::new(Vec::new()),
            proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
            config_file,
            reload_tx,
            reload_rx: Mutex::new(Some(reload_rx)),
            nat_hole_stun_server,
            xtcp_tx,
            xtcp_rx: Mutex::new(Some(xtcp_rx)),
            visitor_tx,
            visitor_rx: Mutex::new(Some(visitor_rx)),
        })
    }

    /// Compute reconnect delay with exponential backoff and jitter.
    /// Formula: min(24s × failed_count, 720s) × jitter[0.8, 1.2].
    /// Matches Go frp v0.69.1 reconnect behavior.
    fn reconnect_delay_secs(failed_count: u32) -> u64 {
        let base = (24 * failed_count as u64).min(720);
        let mut rng = rand::thread_rng();
        let jitter: f64 = rng.gen_range(0.8..1.2);
        ((base as f64) * jitter) as u64
    }

    async fn reconnect_delay(failed_count: u32) {
        let secs = Self::reconnect_delay_secs(failed_count);
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }

    /// Request a config reload. Safe to call from signal handler.
    /// Returns immediately; actual reload happens asynchronously in run().
    pub fn request_reload(&self) {
        let _ = self.reload_tx.send(ReloadRequest {
            strict: false,
            reply: {
                let (tx, _) = tokio::sync::oneshot::channel();
                tx
            },
        });
        tracing::info!("Config reload requested (SIGUSR1)");
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, self.cfg.server_addr, self.cfg.server_port
        );

        let protocol: TransportProtocol = match self.cfg.transport_protocol.parse() {
            Ok(p) => p,
            Err(_) => {
                warn!("Unknown transport protocol '{}', falling back to tcp", self.cfg.transport_protocol);
                TransportProtocol::Tcp
            }
        };
        let pool_count = self.cfg.pool_count.max(0);
        let proxies = self.cfg.proxies.clone();

        // Selective proxy start: if `start` is non-empty, only start proxies
        // whose names are in the start list. Go frp compat.
        let proxies: Vec<frp_core::config::ProxyConfig> = if self.cfg.start.is_empty() {
            proxies
        } else {
            let start_set: std::collections::HashSet<&str> = self.cfg.start.iter().map(|s| s.as_str()).collect();
            let filtered: Vec<_> = proxies.into_iter().filter(|p| start_set.contains(p.name.as_str())).collect();
            info!(
                "Selective proxy start: {} of {} proxies active (start={:?})",
                filtered.len(),
                self.cfg.proxies.len(),
                self.cfg.start,
            );
            filtered
        };

        // Filter out disabled proxies. Go frp compat: proxy.enabled.
        let proxies: Vec<frp_core::config::ProxyConfig> = proxies
            .into_iter()
            .filter(|p| p.enabled)
            .collect();
        if proxies.len() < self.cfg.proxies.len() {
            let disabled: Vec<&str> = self.cfg.proxies.iter()
                .filter(|p| !p.enabled)
                .map(|p| p.name.as_str())
                .collect();
            info!("Disabled proxies (skipped): {:?}", disabled);
        }

        if proxies.is_empty() {
            warn!("No proxies configured");
        }

        // Channel for health checks to signal unhealthy proxies.
        // Health checks send the proxy name; the control loop sends CloseProxy to the server.
        let (health_tx, mut health_rx) = mpsc::unbounded_channel::<String>();

        // Spawn health checks once, outside reconnect loop (they are per-proxy, not per-session)
        for p in &proxies {
            let hc_type = p.health_check_type.clone();
            if hc_type.is_empty() {
                continue;
            }
            if hc_type != "tcp" && hc_type != "http" {
                warn!("Health check type '{}' not yet supported for '{}'", hc_type, p.name);
                continue;
            }
            let la = self.proxy_info_map.read().await
                .get(&p.name)
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let pn = p.name.clone();
            let interval = std::time::Duration::from_secs(
                p.health_check_interval_seconds.max(10)
            );
            let timeout = std::time::Duration::from_secs(
                p.health_check_timeout_seconds.max(3)
            );
            let max_failed = p.health_check_max_failed.max(1);
            let tx = health_tx.clone();
            let hc_url = if hc_type == "http" { p.health_check_url.clone() } else { String::new() };
            let hc_headers = p.health_check_http_headers.clone();
            tokio::spawn(async move {
                crate::health::run_health_check(pn, la, hc_type, hc_url, hc_headers, interval, timeout, max_failed, tx).await;
            });
        }

        // Start admin HTTP server if configured
        let reload_tx = self.reload_tx.clone();
        let mut reload_rx = self.reload_rx.lock().await.take()
            .expect("reload_rx already taken — run() called twice?");
        let mut xtcp_rx = self.xtcp_rx.lock().await.take()
            .expect("xtcp_rx already taken — run() called twice?");
        let mut visitor_rx = self.visitor_rx.lock().await.take()
            .expect("visitor_rx already taken — run() called twice?");
        let xtcp_tx = self.xtcp_tx.clone();
        let nat_hole_stun_server = self.nat_hole_stun_server.clone();
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel::<()>();
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        if self.cfg.web_server.port > 0 {
            let admin_addr = frp_core::format_socket_addr(
                &self.cfg.web_server.addr,
                self.cfg.web_server.port,
            );
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
                    admin_addr, admin_state, admin_auth_user, admin_auth_pwd,
                    admin_tls_cert, admin_tls_key,
                ).await {
                    tracing::error!("frpc admin server failed: {}", e);
                }
            });
            info!("frpc admin server starting on {}:{}", self.cfg.web_server.addr, self.cfg.web_server.port);
        }

        // Main session loop with reconnection.
        // Exponential backoff: 24s × failedCount with jitter [0.8, 1.2], capped at 720s.
        // Matches Go frp v0.69.1 reconnect behavior.
        let mut did_login_once = false;
        let mut failed_count: u32 = 0;
        loop {
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
                if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
                if self.cfg.tls_cert_file.is_empty() { None } else { Some(self.cfg.tls_cert_file.clone()) },
                if self.cfg.tls_key_file.is_empty() { None } else { Some(self.cfg.tls_key_file.clone()) },
                if self.cfg.dns_server.is_empty() { None } else { Some(self.cfg.dns_server.clone()) },
                self.cfg.tcp_mux,
                self.cfg.disable_custom_tls_first_byte,
                self.cfg.dial_server_keepalive.max(0) as u64,
                if self.cfg.connect_server_local_ip.is_empty() { None } else { Some(self.cfg.connect_server_local_ip.clone()) },
                self.cfg.v2,
                self.oidc_client.clone(),
                self.cfg.metas.clone(),
                self.cfg.proxy_url.clone(),
            );

            #[cfg(feature = "quic")]
            let quic_conn: Option<QuicConnection>;

            let (mut control_stream, run_id, yamux_session) = match ctl.login().await {
                Ok(r) => {
                    did_login_once = true;
                    failed_count = 0;
                    *self.server_auth_scopes.write().await = ctl.server_auth_scopes.clone();
                    // After login, wrap control stream in AES-128-CFB encryption.
                    // Go frps v0.69.1 always encrypts the control connection for V1.
                    #[cfg(feature = "quic")]
                    let (stream, run_id, yamux, quic) = r;
                    #[cfg(not(feature = "quic"))]
                    let (stream, run_id, yamux) = r;
                    let enc_key = encryption::derive_key(&self.auth_cfg.token);
                    #[cfg(feature = "quic")]
                    { quic_conn = quic; }
                    (stream.into_encrypted(enc_key), run_id, yamux)
                }
                Err(e) => {
                    failed_count += 1;
                    warn!("Login failed (attempt {}): {}", failed_count, e);
                    if self.cfg.login_fail_exit && !did_login_once {
                        return Err(e.into());
                    }
                    Self::reconnect_delay(failed_count).await;
                    continue;
                }
            };
            let yamux = yamux_session.map(std::sync::Arc::new);
            #[cfg(feature = "quic")]
            let quic_conn = quic_conn.map(std::sync::Arc::new);
            let v2 = self.cfg.v2;
            info!("Logged in. run_id: {}", run_id);

            // Register proxies using IoStream directly (supports TCP and TLS)
            for p in &proxies {
                let local_addr = self.proxy_info_map.read().await
                    .get(&p.name)
                    .map(|info| info.local_addr.clone())
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                match ctl.register_proxy(p, &local_addr, &mut control_stream).await {
                    Ok(resp) => {
                        let remote = resp.remote_addr
                            .unwrap_or_else(|| format!("0.0.0.0:{}", p.remote_port));
                        info!("Proxy '{}' registered on remote port {}", p.name, remote);
                        // Update runtime info for admin API
                        let mut map = self.proxy_info_map.write().await;
                        if let Some(info) = map.get_mut(&p.name) {
                            info.remote_addr = remote;
                            info.err.clear();
                        }
                    }
                    Err(e) => {
                        warn!("Failed to register proxy '{}': {}", p.name, e);
                        let mut map = self.proxy_info_map.write().await;
                        if let Some(info) = map.get_mut(&p.name) {
                            info.err = e.to_string();
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
                        info!("Visitor '{}' registered for proxy '{}'", v.name, v.server_name);
                    }
                    Err(e) => {
                        warn!("Failed to register visitor '{}': {}", v.name, e);
                    }
                }
            }

            // Split control stream for reading and writing
            let (mut reader, raw_writer) = control_stream.into_split();
            let writer = Arc::new(Mutex::new(raw_writer));

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
                            warn!("UDP proxy '{}': bind failed: {}", p.name, e);
                            continue;
                        }
                    };
                    // Connect to local UDP service for send/recv
                    if let Err(e) = socket.connect(&local_addr).await {
                        warn!("UDP proxy '{}': connect to local {} failed: {}", p.name, local_addr, e);
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
                    let enc_label = if p.use_encryption { "encrypted" } else { "plain" };
                    info!("UDP proxy '{}' ready, bridging to {} ({})", p.name, local_addr, enc_label);
                }
            }

            // Spawn initial pool work connections
            let auth_token = self.auth_cfg.token.clone();
            let client_scopes: Vec<String> = self.cfg.auth.as_ref()
                .map(|a| a.additional_auth_scopes.clone())
                .unwrap_or_default();
            let server_scopes = self.server_auth_scopes.read().await.clone();
            for i in 0..pool_count {
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
                    pool_id: i,
                    auth_token: auth_token.clone(),
                    tls_enable: self.cfg.tls_enable,
                    tls_server_name: self.cfg.tls_server_name.clone(),
                    tls_ca_file: if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
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
                    bind_addr: if self.cfg.connect_server_local_ip.is_empty() { None } else { Some(self.cfg.connect_server_local_ip.clone()) },
                    proxy_url: self.cfg.proxy_url.clone(),
                    xtcp_tx: xtcp_tx.clone(),
                });
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
                let secret_key = v.secret_key.clone();
                let bind_addr = format!("{}:{}", v.bind_addr, v.bind_port);
                let use_enc = v.use_encryption;
                let use_comp = v.use_compression;
                let name = v.name.clone();
                let tls_enable = self.cfg.tls_enable;
                let tls_server_name = self.cfg.tls_server_name.clone();
                let tls_ca_file = if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) };
                let visitor_type = v.visitor_type.clone();
                let fallback_timeout_ms = v.fallback_timeout_ms;
                let keep_tunnel_open = v.keep_tunnel_open;
                let max_retries_an_hour = v.max_retries_an_hour;
                let min_retry_interval = v.min_retry_interval;
                let stun_server = nat_hole_stun_server.clone();
                let vtx = self.visitor_tx.clone();
                tokio::spawn(async move {
                    crate::visitor::run_visitor_listener(sa, sp, pt, server_name, secret_key, bind_addr, use_enc, use_comp, name,
                        tls_enable, tls_server_name, tls_ca_file, visitor_type, fallback_timeout_ms,
                        keep_tunnel_open, max_retries_an_hour, min_retry_interval, stun_server, vtx).await;
                });
            }

            // --- Message loop ---
            // Map sid -> proxy_name for XTCP NatHoleResp routing (provider side).
            let mut pending_xtcp: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            // Map sid -> oneshot sender for visitor NatHoleResp routing (Go frps compat).
            let mut visitor_pending: std::collections::HashMap<String, oneshot::Sender<Result<msg::NatHoleResp, String>>> = std::collections::HashMap::new();
            let ping_secs = self.cfg.heartbeat_interval.max(1) as u64;
        info!("Heartbeat interval: {}s", ping_secs);
        let mut ping_interval = interval(Duration::from_secs(ping_secs));

            loop {
                tokio::select! {
                    msg = read_msg(&mut reader, v2) => {
                        match msg {
                            Ok(FrpMessage::ReqWorkConn(_)) => {
                                debug!("Received ReqWorkConn, creating work connection");
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
                                    pool_id: -1, // on-demand, not pool
                                    auth_token: auth_token.clone(),
                                    tls_enable: self.cfg.tls_enable,
                                    tls_server_name: self.cfg.tls_server_name.clone(),
                                    tls_ca_file: if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
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
                                    bind_addr: if self.cfg.connect_server_local_ip.is_empty() { None } else { Some(self.cfg.connect_server_local_ip.clone()) },
                                    proxy_url: self.cfg.proxy_url.clone(),
                                    xtcp_tx: xtcp_tx.clone(),
                                });
                            }
                            Ok(FrpMessage::Pong(_)) => {
                                debug!("Pong received");
                            }
                            Ok(FrpMessage::CloseProxy(cp)) => {
                                info!("Server closed proxy: {}", cp.proxy_name);
                            }
                            Ok(FrpMessage::CloseProxyResp(cpr)) => {
                                info!("Server confirmed proxy close: {}", cpr.proxy_name);
                            }
                            Ok(FrpMessage::Error(err)) => {
                                warn!("Server error: {}", err.error);
                            }
                            Ok(FrpMessage::NatHoleClient(nhc)) => {
                                debug!("Received NatHoleClient for proxy '{}'", nhc.proxy_name);
                                let visitor_addr = nhc.visitor_addr.unwrap_or_default();
                                let proxy_name = nhc.proxy_name.clone();
                                let sid = nhc.transaction_id.clone();
                                let local_addr = self.proxy_info_map.read().await
                                    .get(&proxy_name)
                                    .map(|p| p.local_addr.clone());

                                if visitor_addr.is_empty() {
                                    warn!("NatHoleClient without visitor_addr for '{}'", proxy_name);
                                    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                        sid: Some(sid.clone()),
                                    });
                                    let _ = write_msg(&mut *writer.lock().await, &report, v2).await;
                                    continue;
                                }

                                // Send NatHoleSid FIRST — so visitor can start punching concurrently
                                let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                    sid: Some(sid.clone()),
                                    provider_addr: None, // server fills from control connection peer addr
                                });
                                if let Err(e) = write_msg(&mut *writer.lock().await, &sid_msg, v2).await {
                                    warn!("Failed to send NatHoleSid: {}", e);
                                    continue;
                                }

                                // TCP simultaneous open (visitor is punching at the same time)
                                match crate::visitor::tcp_simultaneous_open(&visitor_addr, 5000).await {
                                    Ok(p2p_stream) => {
                                        // Connect to local service and bridge
                                        if let Some(ref local) = local_addr {
                                            match tokio::net::TcpStream::connect(local).await {
                                                Ok(local_stream) => {
                                                    tokio::spawn(async move {
                                                        let mut p2p = p2p_stream;
                                                        let mut local = local_stream;
                                                        match tokio::io::copy_bidirectional(&mut p2p, &mut local).await {
                                                            Ok((to_local, to_p2p)) => {
                                                                debug!("XTCP provider '{}' closed: {}B to local, {}B to P2P",
                                                                    proxy_name, to_local, to_p2p);
                                                            }
                                                            Err(e) => {
                                                                debug!("XTCP provider '{}' bridge error: {}", proxy_name, e);
                                                            }
                                                        }
                                                    });
                                                    // Don't send NatHoleReport — Go frp uses implicit success.
                                                    // If bridge fails, the TCP close propagates naturally.
                                                }
                                                Err(e) => {
                                                    warn!("XTCP provider '{}': connect local failed: {}", proxy_name, e);
                                                    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                                        sid: Some(sid),
                                                    });
                                                    let _ = write_msg(&mut *writer.lock().await, &report, v2).await;
                                                }
                                            }
                                        } else {
                                            warn!("XTCP provider '{}': no local address", proxy_name);
                                            let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                                sid: Some(sid),
                                            });
                                            let _ = write_msg(&mut *writer.lock().await, &report, v2).await;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("XTCP hole punch for '{}' failed: {}", proxy_name, e);
                                        // Report failure — triggers STCP fallback on visitor side
                                        let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                            sid: Some(sid),
                                        });
                                        let _ = write_msg(&mut *writer.lock().await, &report, v2).await;
                                    }
                                }
                            }
                            Ok(FrpMessage::NatHoleResp(resp)) => {
                                // Route to waiting visitor first (Go frps compat path).
                                let sid = resp.sid.clone().unwrap_or_default();
                                if let Some(tx) = visitor_pending.remove(&sid) {
                                    info!("XTCP visitor: received NatHoleResp for sid '{}'", sid);
                                    let _ = tx.send(Ok(resp));
                                    continue;
                                }
                                // Provider receives server's analysis with visitor's candidate addresses.
                                if let Some(err) = resp.error {
                                    warn!("XTCP NatHoleResp error: {}", err);
                                    // Clean up pending tracking
                                    if let Some(ref sid) = resp.sid {
                                        pending_xtcp.remove(sid);
                                    }
                                    continue;
                                }
                                let proxy_name = pending_xtcp.remove(&sid).unwrap_or_default();
                                if proxy_name.is_empty() {
                                    warn!("XTCP NatHoleResp: unknown sid '{}'", sid);
                                    continue;
                                }
                                let candidate_addrs = resp.candidate_addrs.unwrap_or_default();
                                info!("XTCP provider '{}': received {} candidate addresses from server",
                                    proxy_name, candidate_addrs.len());

                                // Spawn hole punch task (don't block control loop)
                                let local_addr = self.proxy_info_map.read().await
                                    .get(&proxy_name)
                                    .map(|p| p.local_addr.clone());
                                let proxy_name_clone = proxy_name.clone();
                                tokio::spawn(async move {
                                    for addr in &candidate_addrs {
                                        debug!("XTCP provider '{}': trying simultaneous open to {}", proxy_name_clone, addr);
                                        match crate::visitor::tcp_simultaneous_open(addr, 5000).await {
                                            Ok(mut p2p) => {
                                                info!("XTCP provider '{}': P2P connected to {}", proxy_name_clone, addr);
                                                if let Some(ref local) = local_addr {
                                                    match tokio::net::TcpStream::connect(local).await {
                                                        Ok(mut local_conn) => {
                                                            match tokio::io::copy_bidirectional(&mut p2p, &mut local_conn).await {
                                                                Ok((to_local, to_p2p)) => {
                                                                    debug!("XTCP provider '{}' closed: {}B to local, {}B to P2P",
                                                                        proxy_name_clone, to_local, to_p2p);
                                                                }
                                                                Err(e) => {
                                                                    debug!("XTCP provider '{}' bridge error: {}", proxy_name_clone, e);
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("XTCP provider '{}': connect local failed: {}", proxy_name_clone, e);
                                                        }
                                                    }
                                                } else {
                                                    warn!("XTCP provider '{}': no local address", proxy_name_clone);
                                                }
                                                return;
                                            }
                                            Err(e) => {
                                                debug!("XTCP provider '{}': hole punch to {} failed: {}", proxy_name_clone, addr, e);
                                            }
                                        }
                                    }
                                    warn!("XTCP provider '{}': all hole punch attempts failed", proxy_name_clone);
                                });
                            }
                            Ok(FrpMessage::NewProxyResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Proxy registration error: {}", err);
                                }
                            }
                            Ok(_) => {
                                // Other messages are ignored
                            }
                            Err(e) => {
                                warn!("Control read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }

                    _ = ping_interval.tick() => {
                        let mut ping_msg = msg::Ping {
                            privilege_key: None,
                            timestamp: None,
                        };
                        let client_scopes: Vec<String> = self.cfg.auth.as_ref()
                            .map(|a| a.additional_auth_scopes.clone())
                            .unwrap_or_default();
                        let requires_auth = crate::work_conn::scope_requires_auth(
                            &client_scopes, &self.server_auth_scopes.read().await, "HeartBeats"
                        );
                        if requires_auth {
                            if let Some(ref oidc) = self.oidc_client {
                                if let Err(e) = oidc.set_ping(&mut ping_msg).await {
                                    warn!("OIDC ping token failed: {}. Reconnecting...", e);
                                    break;
                                }
                            } else {
                                let ts = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs() as i64;
                                let ping_auth = AuthConfig {
                                    method: AuthMethod::Token,
                                    token: self.auth_cfg.token.clone(),
                                    oidc_issuer: String::new(),
                                    oidc_audience: String::new(),
                                    oidc_skip_expiry: false,
                                    oidc_skip_issuer: false,
                                    additional_data: None,
            oidc_proxy_url: String::new(),
                                    additional_auth_scopes: Vec::new(),
                                };
                                ping_msg.privilege_key = ping_auth.generate_login_key(ts);
                                ping_msg.timestamp = Some(ts);
                            }
                        }
                        let ping = FrpMessage::Ping(ping_msg);
                        if let Err(e) = write_msg(&mut *writer.lock().await, &ping, v2).await {
                            warn!("Ping failed: {}. Reconnecting...", e);
                            break;
                        }
                        debug!("Ping sent");
                    }

                    Some(proxy_name) = health_rx.recv() => {
                        info!("Health check sending CloseProxy for unhealthy proxy: {}", proxy_name);
                        let close = FrpMessage::CloseProxy(msg::CloseProxy {
                            proxy_name: proxy_name.clone(),
                        });
                        if let Err(e) = write_msg(&mut *writer.lock().await, &close, v2).await {
                            warn!("Failed to send CloseProxy for {}: {}", proxy_name, e);
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
                        info!("XTCP provider: received NatHoleSid for '{}'", proxy_name);
                        // 1. Do STUN discovery
                        let mapped_addrs = match frp_core::stun::stun_binding(&nat_hole_stun_server).await {
                            Ok(addr) => {
                                debug!("XTCP STUN result: {}", addr);
                                vec![addr]
                            }
                            Err(e) => {
                                warn!("XTCP STUN failed: {}", e);
                                vec![]
                            }
                        };
                        // 2. Send NatHoleClient on control
                        let client_msg = FrpMessage::NatHoleClient(msg::NatHoleClient {
                            transaction_id: sid.clone(),
                            proxy_name: proxy_name.clone(),
                            sid: Some(sid.clone()),
                            protocol: Some("tcp".to_string()),
                            mapped_addrs: if mapped_addrs.is_empty() { None } else { Some(mapped_addrs) },
                            assisted_addrs: None,
                            visitor_addr: None,
                        });
                        if let Err(e) = write_msg(&mut *writer.lock().await, &client_msg, v2).await {
                            warn!("XTCP: failed to send NatHoleClient: {}", e);
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
                                debug!("Visitor: sent NatHoleVisitor on control, sid={}", txn_id);
                                visitor_pending.insert(txn_id, vreq.reply);
                            }
                            Err(e) => {
                                warn!("Visitor: failed to send NatHoleVisitor on control: {}", e);
                                let _ = vreq.reply.send(Err(format!("send failed: {e}")));
                            }
                        }
                    }

                    Some(()) = stop_rx.recv() => {
                        info!("Admin stop requested, shutting down");
                        shutdown_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }

            // Check if admin stop was requested
            if shutdown_flag.load(Ordering::SeqCst) {
                info!("frpc shutting down");
                return Ok(());
            }

            // Session dropped — reconnect with exponential backoff.
            // login_fail_exit only applies to initial login, not session drops.
            failed_count += 1;
            warn!("Session ended, reconnecting in {}s (attempt {})...",
                Self::reconnect_delay_secs(failed_count), failed_count);
            Self::reconnect_delay(failed_count).await;
        }
    }

    /// Reload configuration from file. Used by admin API.
    ///
    /// Sends NewProxy for added proxies and CloseProxy for removed proxies
    /// over the control connection. Responses are handled asynchronously by
    /// the message loop. Plugin-based proxies log a warning (plugin restart
    /// requires a full frpc restart).
    pub async fn try_reload(
        &self,
        config_path: &str,
        strict: bool,
        writer: &Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>,
    ) -> Result<String, String> {
        crate::reload::do_reload(
            &self.proxy_info_map,
            self.cfg.v2,
            config_path,
            strict,
            writer,
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_secs_failed_count_zero() {
        // failed_count=0 → base=0 → delay=0 regardless of jitter
        let delay = Service::reconnect_delay_secs(0);
        assert_eq!(delay, 0, "no failures → zero delay");
    }

    #[test]
    fn reconnect_delay_secs_failed_count_one() {
        // failed_count=1 → base=24s → jitter [0.8, 1.2] → [19, 28]
        for _ in 0..100 {
            let delay = Service::reconnect_delay_secs(1);
            assert!(delay >= 19, "delay {} too low for n=1", delay);
            assert!(delay <= 29, "delay {} too high for n=1", delay);
        }
    }

    #[test]
    fn reconnect_delay_secs_linear_growth() {
        // failed_count=2 → base=48s → [38, 57]
        for _ in 0..100 {
            let delay = Service::reconnect_delay_secs(2);
            assert!(delay >= 38, "delay {} too low for n=2", delay);
            assert!(delay <= 58, "delay {} too high for n=2", delay);
        }
    }

    #[test]
    fn reconnect_delay_secs_caps_at_720s() {
        // failed_count=100 → base=min(2400, 720)=720 → [576, 864]
        for _ in 0..100 {
            let delay = Service::reconnect_delay_secs(100);
            assert!(delay >= 576, "delay {} below 80% of cap", delay);
            assert!(delay <= 864, "delay {} above 120% of cap", delay);
        }
    }

    #[test]
    fn reconnect_delay_secs_cap_exact() {
        // failed_count=30 → base=min(720, 720)=720 → jitter [0.8, 1.2]
        for _ in 0..100 {
            let delay = Service::reconnect_delay_secs(30);
            assert!(delay >= 576, "delay {} below 80% of cap", delay);
            assert!(delay <= 864, "delay {} above 120% of cap", delay);
        }
    }

    #[test]
    fn reconnect_delay_secs_monotonic_in_mean() {
        // Mean delay should increase with failed_count
        fn mean_delay(n: u32) -> f64 {
            (0..50).map(|_| Service::reconnect_delay_secs(n) as f64).sum::<f64>() / 50.0
        }
        let m1 = mean_delay(1);
        let m2 = mean_delay(2);
        let m5 = mean_delay(5);
        assert!(m2 > m1, "mean delay should grow: {} > {}", m2, m1);
        assert!(m5 > m2, "mean delay should grow: {} > {}", m5, m2);
    }
}
