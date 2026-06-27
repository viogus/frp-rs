use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};
use rand::Rng;

use frp_core::auth::{AuthConfig, AuthMethod, OidcClient};
use frp_core::config::{ClientConfig, ProxyConfig};
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg, write_msg, read_msg_v1, write_msg_v1, read_msg_v2, write_msg_v2};
use frp_core::mux::YamuxSession;
use frp_core::transport::{TransportProtocol, DialOptions, dial_server, IoStream};

use frp_core::metrics::ProxyMetricsRegistry;

use crate::plugin::{self, PluginHandle, PluginContext};
use crate::proxy;
use crate::control::ControlConnection;
use crate::admin::{AdminState, ReloadRequest, ProxyRuntimeInfo};

/// Check if an auth scope is enabled, considering both client and server config.
fn scope_requires_auth(client_scopes: &[String], server_scopes: &[String], scope: &str) -> bool {
    client_scopes.iter().any(|s| s == scope) || server_scopes.iter().any(|s| s == scope)
}

/// Build a config snapshot string for reload change detection.
/// Includes all fields that matter for proxy registration.
fn config_snapshot(p: &ProxyConfig) -> String {
    // Sort and serialize key fields deterministically
    let mut fields: Vec<(&str, String)> = Vec::new();
    fields.push(("type", p.proxy_type.clone()));
    fields.push(("local_ip", p.local_ip.clone()));
    fields.push(("local_port", p.local_port.to_string()));
    fields.push(("remote_port", p.remote_port.to_string()));
    fields.push(("use_encryption", p.use_encryption.to_string()));
    fields.push(("use_compression", p.use_compression.to_string()));
    fields.push(("sk", p.sk.clone()));
    fields.push(("custom_domains", format!("{:?}", p.custom_domains)));
    fields.push(("subdomain", p.subdomain.clone()));
    fields.push(("http_user", p.http_user.clone()));
    fields.push(("http_pwd", p.http_pwd.clone()));
    fields.push(("host_header_rewrite", p.host_header_rewrite.clone()));
    fields.push(("locations", format!("{:?}", p.locations)));
    fields.push(("bandwidth_limit", p.bandwidth_limit.clone()));
    fields.push(("bandwidth_limit_mode", p.bandwidth_limit_mode.clone()));
    fields.push(("group", p.group.clone()));
    fields.push(("group_key", p.group_key.clone()));
    fields.push(("multiplexer", p.multiplexer.clone()));
    fields.push(("proxy_protocol_version", p.proxy_protocol_version.clone()));
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let parts: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.join("|")
}

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
}

impl Service {
    pub async fn new(cfg: ClientConfig, config_file: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        // Determine auth method from [auth] section if present, otherwise token
        let auth_method = if let Some(ref ac) = cfg.auth {
            if ac.method == "oidc" { AuthMethod::Oidc } else { AuthMethod::Token }
        } else {
            AuthMethod::Token
        };

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

        // Start plugins for proxies that have them configured.
        let mut plugin_handles = Vec::new();
        let mut plugin_addrs: HashMap<String, String> = HashMap::new();
        for p in &cfg.proxies {
            if let Some(ref plugin_cfg) = p.plugin {
                if plugin_cfg.plugin_type == "http_proxy" {
                    match plugin::start_http_proxy(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("http_proxy plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start http_proxy plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "socks5" {
                    match plugin::start_socks5_proxy(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("socks5 plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start socks5 plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "static_file" {
                    match plugin::start_static_file_proxy(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("static_file plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start static_file plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "unix_domain_socket" {
                    match plugin::start_unix_socket_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("unix_domain_socket plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start unix_domain_socket plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "tls2raw" {
                    match plugin::start_tls2raw_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("tls2raw plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start tls2raw plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "http2http" {
                    match plugin::start_http2http_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("http2http plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start http2http plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "http2https" {
                    match plugin::start_http2https_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("http2https plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start http2https plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "https2http" {
                    match plugin::start_https2http_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("https2http plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start https2http plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "https2https" {
                    match plugin::start_https2https_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("https2https plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start https2https plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "visitor_plugin" {
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
                    match plugin::start_visitor_plugin(plugin_cfg, plugin_ctx).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("visitor plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start visitor plugin for '{}': {}", p.name, e);
                        }
                    }
                } else {
                    warn!("Unknown plugin type '{}' for proxy '{}'", plugin_cfg.plugin_type, p.name);
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
            let snapshot = config_snapshot(p);
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
                run_health_check(pn, la, hc_type, hc_url, hc_headers, interval, timeout, max_failed, tx).await;
            });
        }

        // Start admin HTTP server if configured
        let reload_tx = self.reload_tx.clone();
        let mut reload_rx = self.reload_rx.lock().await.take()
            .expect("reload_rx already taken — run() called twice?");
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

            let (mut control_stream, run_id, yamux_session) = match ctl.login().await {
                Ok(r) => {
                    did_login_once = true;
                    failed_count = 0;
                    *self.server_auth_scopes.write().await = ctl.server_auth_scopes.clone();
                    // After login, wrap control stream in AES-128-CFB encryption.
                    // Go frps v0.69.1 always encrypts the control connection for V1.
                    let (stream, run_id, yamux) = r;
                    let enc_key = encryption::derive_key(&self.auth_cfg.token);
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
                spawn_work_conn(
                    &self.cfg.server_addr,
                    self.cfg.server_port,
                    &protocol,
                    &run_id,
                    self.proxy_info_map.clone(),
                    self.encryption_key,
                    i,
                    auth_token.clone(),
                    self.cfg.tls_enable,
                    self.cfg.tls_server_name.clone(),
                    if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
                    yamux.clone(),
                    v2,
                    self.oidc_client.clone(),
                    udp_sockets.clone(),
                    udp_enc_cfg.clone(),
                    self.proxy_metrics.clone(),
                    client_scopes.clone(),
                    server_scopes.clone(),
                    self.cfg.disable_custom_tls_first_byte,
                    self.cfg.dial_server_keepalive.max(0) as u64,
                    if self.cfg.connect_server_local_ip.is_empty() { None } else { Some(self.cfg.connect_server_local_ip.clone()) },
                    self.cfg.proxy_url.clone(),
                );
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
                tokio::spawn(async move {
                    run_visitor_listener(sa, sp, pt, server_name, secret_key, bind_addr, use_enc, use_comp, name,
                        tls_enable, tls_server_name, tls_ca_file, visitor_type, fallback_timeout_ms,
                        keep_tunnel_open, max_retries_an_hour, min_retry_interval).await;
                });
            }

            // --- Message loop ---
            let ping_secs = self.cfg.heartbeat_interval.max(1) as u64;
        info!("Heartbeat interval: {}s", ping_secs);
        let mut ping_interval = interval(Duration::from_secs(ping_secs));

            loop {
                tokio::select! {
                    msg = read_msg(&mut reader, v2) => {
                        match msg {
                            Ok(FrpMessage::ReqWorkConn(_)) => {
                                debug!("Received ReqWorkConn, creating work connection");
                                spawn_work_conn(
                                    &self.cfg.server_addr,
                                    self.cfg.server_port,
                                    &protocol,
                                    &run_id,
                                    self.proxy_info_map.clone(),
                                    self.encryption_key,
                                    -1, // on-demand, not pool
                                    auth_token.clone(),
                                    self.cfg.tls_enable,
                                    self.cfg.tls_server_name.clone(),
                                    if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
                                    yamux.clone(),
                                    v2,
                                    self.oidc_client.clone(),
                                    udp_sockets.clone(),
                                    udp_enc_cfg.clone(),
                                    self.proxy_metrics.clone(),
                                    client_scopes.clone(),
                                    server_scopes.clone(),
                                    self.cfg.disable_custom_tls_first_byte,
                    self.cfg.dial_server_keepalive.max(0) as u64,
                    if self.cfg.connect_server_local_ip.is_empty() { None } else { Some(self.cfg.connect_server_local_ip.clone()) },
                    self.cfg.proxy_url.clone(),
                                );
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
                                match tcp_simultaneous_open(&visitor_addr, 5000).await {
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
                        let requires_auth = scope_requires_auth(
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
        use std::collections::HashSet;

        let new_cfg: ClientConfig = frp_core::config::load_client_config(config_path)
            .map_err(|e| format!("failed to load config: {e}"))?;

        // Diff old vs new proxy names
        let old_names: HashSet<String> = {
            self.proxy_info_map.read().await.keys().cloned().collect()
        };
        let new_names: HashSet<String> = new_cfg.proxies.iter().map(|p| p.name.clone()).collect();

        let removed: Vec<String> = old_names.difference(&new_names).cloned().collect();
        let added: Vec<String> = new_names.difference(&old_names).cloned().collect();

        // Detect changed proxies: same name, different config
        let common: HashSet<&String> = old_names.intersection(&new_names).collect();
        let mut changed: Vec<String> = Vec::new();
        {
            let map = self.proxy_info_map.read().await;
            for name in &common {
                if let (Some(old_info), Some(new_p)) = (map.get(*name), new_cfg.proxies.iter().find(|p| &p.name == *name)) {
                    let new_snapshot = config_snapshot(new_p);
                    if old_info.config_snapshot != new_snapshot {
                        changed.push((*name).clone());
                    }
                }
            }
        }

        if strict && (!removed.is_empty() || !added.is_empty() || !changed.is_empty()) {
            let mut parts: Vec<String> = Vec::new();
            if !removed.is_empty() { parts.push(format!("removed: {:?}", removed)); }
            if !added.is_empty() { parts.push(format!("added: {:?}", added)); }
            if !changed.is_empty() { parts.push(format!("changed: {:?}", changed)); }
            return Err(format!("config changed — {}", parts.join("; ")));
        }

        if removed.is_empty() && added.is_empty() && changed.is_empty() {
            return Ok("reload success: no changes detected".into());
        }

        let mut changes: Vec<String> = Vec::new();
        let mut w = writer.lock().await;

        // Send CloseProxy for removed proxies (fire-and-forget; CloseProxyResp
        // is handled by the message loop)
        for name in &removed {
            let close = FrpMessage::CloseProxy(msg::CloseProxy {
                proxy_name: name.clone(),
            });
            write_msg(&mut *w, &close, self.cfg.v2).await
                .map_err(|e| format!("send CloseProxy for '{name}': {e}"))?;
            changes.push(format!("proxy '{name}' removed"));
            tracing::info!("Reload: sent CloseProxy for '{name}'");
        }

        // Send CloseProxy + NewProxy for changed proxies
        for name in &changed {
            if let Some(p) = new_cfg.proxies.iter().find(|p| &p.name == name) {
                if p.plugin.is_some() {
                    tracing::warn!(
                        "Reload: proxy '{name}' has a plugin — plugin restart requires full frpc restart"
                    );
                }
                let close = FrpMessage::CloseProxy(msg::CloseProxy {
                    proxy_name: name.clone(),
                });
                write_msg(&mut *w, &close, self.cfg.v2).await
                    .map_err(|e| format!("send CloseProxy for changed '{name}': {e}"))?;
                let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                let np = crate::proxy::create_new_proxy_msg(p, &local_addr);
                write_msg(&mut *w, &np, self.cfg.v2).await
                    .map_err(|e| format!("send NewProxy for changed '{name}': {e}"))?;
                changes.push(format!("proxy '{name}' updated"));
                tracing::info!("Reload: sent CloseProxy+NewProxy for changed '{name}'");
            }
        }

        // Send NewProxy for added proxies (fire-and-forget; NewProxyResp
        // is handled by the message loop)
        for name in &added {
            if let Some(p) = new_cfg.proxies.iter().find(|p| &p.name == name) {
                if p.plugin.is_some() {
                    tracing::warn!(
                        "Reload: proxy '{name}' has a plugin — plugin restart requires full frpc restart"
                    );
                }
                let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                let np = crate::proxy::create_new_proxy_msg(p, &local_addr);
                write_msg(&mut *w, &np, self.cfg.v2).await
                    .map_err(|e| format!("send NewProxy for '{name}': {e}"))?;
                changes.push(format!("proxy '{name}' added"));
                tracing::info!("Reload: sent NewProxy for '{name}'");
            }
        }
        drop(w);

        // Update the shared proxy_info_map so admin API and work conn lookups
        // reflect the new proxy set.
        {
            let mut map = self.proxy_info_map.write().await;
            for name in &removed {
                map.remove(name);
            }
            for name in changed.iter().chain(added.iter()) {
                if let Some(p) = new_cfg.proxies.iter().find(|p| &p.name == name) {
                    let bw_limit = frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
                    let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                    let plugin_type = p.plugin.as_ref()
                        .map(|pl| pl.plugin_type.clone())
                        .unwrap_or_default();
                    let snapshot = config_snapshot(p);
                    map.insert(name.clone(), ProxyRuntimeInfo {
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
            }
        }

        let summary = changes.join("; ");
        tracing::info!("Config reload summary: {}", summary);
        Ok(format!("reload success: {summary}"))
    }
}

// ---------------------------------------------------------------
// Work connection management
// ---------------------------------------------------------------

/// Spawn a single work connection task.
///
/// The task:
/// 1. Under TcpMux: opens a yamux stream on the shared session
///    Without TcpMux: dials the server via TCP/TLS/WS
/// 2. Without TcpMux: sends NewWorkConn (with run_id + auth)
/// 3. Reads StartWorkConn from the server
///
/// Write HAProxy PROXY protocol v2 binary header to the stream.
///
/// Format: 12-byte signature + 4-byte header + address block (binary).
async fn write_proxy_protocol_v2(
    stream: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<(), String> {
    // Parse source address
    let src_ip: std::net::IpAddr = src_addr.parse().map_err(|e| format!("v2 src_addr parse: {e}"))?;
    let dst_ip: std::net::IpAddr = dst_addr.parse().map_err(|e| format!("v2 dst_addr parse: {e}"))?;

    // Determine transport and address families
    let (transport_byte, addr_len) = match (&src_ip, &dst_ip) {
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => (0x11u8, 12u16),
        (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => (0x21u8, 36u16),
        _ => return Err("v2 PROXY: mismatched address families (IPv4/IPv6)".into()),
    };

    let mut buf = Vec::with_capacity(16 + addr_len as usize);

    // 12-byte v2 signature
    buf.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A");

    // 1 byte: version (0x20) | command (0x01 = PROXY for locally-terminated connections)
    buf.push(0x21);

    // 1 byte: transport protocol (0x11 = TCPv4, 0x21 = TCPv6)
    buf.push(transport_byte);

    // 2 bytes: address length (big-endian)
    buf.extend_from_slice(&addr_len.to_be_bytes());

    // Address block: src_addr + dst_addr + src_port + dst_port (all binary)
    match (&src_ip, &dst_ip) {
        (std::net::IpAddr::V4(s4), std::net::IpAddr::V4(d4)) => {
            buf.extend_from_slice(&s4.octets());
            buf.extend_from_slice(&d4.octets());
        }
        (std::net::IpAddr::V6(s6), std::net::IpAddr::V6(d6)) => {
            buf.extend_from_slice(&s6.octets());
            buf.extend_from_slice(&d6.octets());
        }
        _ => unreachable!(),
    }
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());

    stream.write_all(&buf).await.map_err(|e| format!("v2 PROXY write: {e}"))?;
    Ok(())
}

/// 4. Connects to the local service
/// 5. Bridges data bidirectionally
///
/// `pool_id` is for logging only (< 0 means on-demand).
#[allow(clippy::too_many_arguments)]
fn spawn_work_conn(
    server_addr: &str,
    server_port: u16,
    protocol: &TransportProtocol,
    run_id: &str,
    proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    enc_key: [u8; 16],
    pool_id: i32,
    auth_token: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    yamux: Option<std::sync::Arc<YamuxSession>>,
    v2: bool,
    oidc_client: Option<Arc<OidcClient>>,
    udp_sockets: Arc<tokio::sync::Mutex<HashMap<String, Arc<UdpSocket>>>>,
    udp_enc_cfg: Arc<tokio::sync::Mutex<HashMap<String, (bool, bool)>>>,
    proxy_metrics: Arc<ProxyMetricsRegistry>,
    client_auth_scopes: Vec<String>,
    server_auth_scopes: Vec<String>,
    disable_custom_tls_first_byte: bool,
    keepalive_secs: u64,
    bind_addr: Option<String>,
    proxy_url: String,
) {
    let server_addr = server_addr.to_string();
    let run_id = run_id.to_string();
    let protocol = protocol.clone();
    let proxy_info_map = proxy_info_map.clone();
    let tls_server_name = tls_server_name.clone();
    // Clone for replenishment call (used after async block consumes originals)
    let repl_udp_sockets = udp_sockets.clone();
    let repl_udp_enc_cfg = udp_enc_cfg.clone();
    let repl_proxy_metrics = proxy_metrics.clone();
    let repl_proxy_url = proxy_url.clone();

    tokio::spawn(async move {
        let label = if pool_id >= 0 {
            format!("pool-{}", pool_id)
        } else {
            "on-demand".to_string()
        };

        // Acquire the underlying transport stream.
        // Under TcpMux: open a yamux stream instead of dialing new TCP.
        let mut work = if let Some(ref yamux) = yamux {
            match yamux.open_stream().await {
                Some(stream) => {
                    debug!("Work conn {} opened yamux stream", label);
                    IoStream::Yamux(stream)
                }
                None => {
                    warn!("Work conn {}: yamux open stream failed, session closed?", label);
                    return;
                }
            }
        } else {
            debug!("Work conn {} dialing server", label);
            let opts = DialOptions {
                server_addr: server_addr.clone(),
                server_port,
                protocol: protocol.clone(),
                tls_enable,
                tls_server_name: tls_server_name.clone(),
                tls_ca_file: tls_ca_file.clone(),
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr: bind_addr.clone(),
                proxy_url: if proxy_url.is_empty() { None } else { Some(proxy_url.clone()) },
                ..Default::default()
            };
            match dial_server(&opts).await {
                Ok(io) => io,
                Err(e) => {
                    debug!("Work conn {} dial failed: {}", label, e);
                    return;
                }
            }
        };

        // Send NewWorkConn — required for both yamux and raw transports.
        // Go frps needs the run_id and auth to associate the stream.
        {
            let nwc_token = auth_token.clone();
            let mut nwc_msg = msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            };
            let requires_auth = scope_requires_auth(&client_auth_scopes, &server_auth_scopes, "NewWorkConns");
            if requires_auth {
                if let Some(ref oidc) = oidc_client {
                    if let Err(e) = oidc.set_new_work_conn(&mut nwc_msg).await {
                        warn!("Work conn {} OIDC NewWorkConn auth failed: {}", label, e);
                        return;
                    }
                } else {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let auth_cfg = frp_core::auth::AuthConfig {
                        method: frp_core::auth::AuthMethod::Token,
                        token: nwc_token,
                        oidc_issuer: String::new(),
                        oidc_audience: String::new(),
                        oidc_skip_expiry: false,
                        oidc_skip_issuer: false,
                        additional_data: None,
            oidc_proxy_url: String::new(),
                        additional_auth_scopes: Vec::new(),
                    };
                    nwc_msg.privilege_key = auth_cfg.generate_login_key(timestamp);
                    nwc_msg.timestamp = Some(timestamp);
                }
            }
            let nwc = FrpMessage::NewWorkConn(nwc_msg);
            let write_result = if v2 {
                work.write_v2_frame(&nwc).await
            } else {
                work.write_v1_frame(&nwc).await
            };
            if let Err(e) = write_result {
                warn!("Work conn {} failed to send NewWorkConn: {}", label, e);
                return;
            }
            debug!("Work conn {} sent NewWorkConn, waiting for StartWorkConn", label);
        }

        // Read StartWorkConn
        let swc_result = if v2 {
            work.read_v2_frame().await
        } else {
            work.read_v1_frame().await
        };
        match swc_result {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                let proxy_name = &swc.proxy_name;
                debug!("Work conn {} assigned to proxy '{}'", label, proxy_name);

                // Look up the proxy runtime info
                let info = {
                    let map = proxy_info_map.read().await;
                    map.get(proxy_name).cloned()
                };
                let info = match info {
                    Some(info) => info,
                    None => {
                        warn!("Work conn {}: unknown proxy '{}'", label, proxy_name);
                        return;
                    }
                };

                if info.proxy_type == "udp" {
                    // UDP proxy: bridge work conn ↔ local UDP socket
                    let sock = {
                        let map = udp_sockets.lock().await;
                        map.get(proxy_name).cloned()
                    };
                    let sock = match sock {
                        Some(s) => s,
                        None => {
                            warn!("Work conn {}: no UDP socket for proxy '{}'", label, proxy_name);
                            return;
                        }
                    };
                    let enc_cfg = {
                        let cfg = udp_enc_cfg.lock().await;
                        cfg.get(proxy_name).copied().unwrap_or((false, false))
                    };
                    let (use_enc, use_comp) = enc_cfg;

                    info!("Work conn {} bridging UDP for '{}' (enc={}, comp={})",
                        label, proxy_name, use_enc, use_comp);

                    let (mut w_r, mut w_w) = work.into_split();

                    // Shared last_remote_addr: the server tells us the remote user's address
                    // in each UDPPacket. We must echo it back so the server can route
                    // the response to the correct remote user (not the local echo service).
                    let last_remote: Arc<tokio::sync::Mutex<Option<msg::UdpAddr>>> =
                        Arc::new(tokio::sync::Mutex::new(None));

                    // Reader: work conn → local UDP socket
                    // Decrypt/decompress before forwarding to local service
                    let sock_r = sock.clone();
                    let pn_r = proxy_name.clone();
                    let enc_key_r = enc_key;
                    let last_remote_r = last_remote.clone();
                    tokio::spawn(async move {
                        debug!("UDP reader '{}' started", pn_r);
                        loop {
                            let result = if v2 {
                                read_msg_v2(&mut w_r).await
                            } else {
                                read_msg_v1(&mut w_r).await
                            };
                            match result {
                                Ok(FrpMessage::UDPPacket(up)) => {
                                    // Save the original remote address for the response
                                    if let Some(ref ra) = up.remote_addr {
                                        *last_remote_r.lock().await = Some(ra.clone());
                                    }
                                    let n = up.content.len();
                                    let mut payload = up.content;
                                    if use_enc {
                                        if let Ok(d) = encryption::decrypt(&payload, &enc_key_r) {
                                            payload = d;
                                        }
                                    }
                                    if use_comp {
                                        if let Ok(d) = encryption::decompress(&payload) {
                                            payload = d;
                                        }
                                    }
                                    debug!("UDP reader '{}': forwarding {} bytes to local", pn_r, n);
                                    if let Err(e) = sock_r.send(&payload).await {
                                        debug!("UDP '{}' send to local failed: {}", pn_r, e);
                                        break;
                                    }
                                }
                                Ok(FrpMessage::Ping(_)) | Ok(FrpMessage::Pong(_)) => continue,
                                Ok(other) => {
                                    debug!("UDP work conn '{}': unexpected msg 0x{:02x}", pn_r, other.v1_type_byte());
                                }
                                Err(e) => {
                                    debug!("UDP work conn '{}' read closed: {}", pn_r, e);
                                    break;
                                }
                            }
                        }
                    });

                    // Writer: local UDP socket → work conn
                    // Encrypt/compress before sending to server
                    let pn_w = proxy_name.clone();
                    let local_addr_str = info.local_addr.clone();
                    let last_remote_w = last_remote.clone();
                    tokio::spawn(async move {
                        debug!("UDP writer '{}' started", pn_w);
                        let mut buf = vec![0u8; 65535];
                        loop {
                            match sock.recv_from(&mut buf).await {
                                Ok((n, src)) => {
                                    debug!("UDP writer '{}': recv'd {} bytes from local {}", pn_w, n, src);
                                    let mut payload = buf[..n].to_vec();
                                    if use_comp {
                                        if let Ok(c) = encryption::compress(&payload) { payload = c; }
                                    }
                                    if use_enc {
                                        if let Ok(e) = encryption::encrypt(&payload, &enc_key) { payload = e; }
                                    }
                                    // Use saved remote_addr from server (the true remote user)
                                    let remote = last_remote_w.lock().await.clone();
                                    let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                                        content: payload,
                                        local_addr: msg::UdpAddr::from_string(&local_addr_str),
                                        remote_addr: remote,
                                    });
                                    let write_result = if v2 {
                                        write_msg_v2(&mut w_w, &pkt).await
                                    } else {
                                        write_msg_v1(&mut w_w, &pkt).await
                                    };
                                    if let Err(e) = write_result {
                                        debug!("UDP '{}' send to work conn failed: {}", pn_w, e);
                                        break;
                                    }
                                    debug!("UDP writer '{}': sent {} bytes to work conn", pn_w, n);
                                }
                                Err(e) => {
                                    debug!("UDP '{}' recv from local failed: {}", pn_w, e);
                                    break;
                                }
                            }
                        }
                    });
                } else {
                    // TCP/HTTP/STCP: connect to local TCP service and bridge
                    match proxy::connect_local(&info.local_addr).await {
                        Ok(mut local) => {
                            // Write PROXY protocol header if configured
                            if !info.proxy_protocol_version.is_empty() {
                                if let Some(ref src) = swc.src_addr {
                                    if info.proxy_protocol_version == "v1" {
                                        let header = format!(
                                            "PROXY TCP4 {} {} {} {}\r\n",
                                            src,
                                            swc.dst_addr.as_deref().unwrap_or("0.0.0.0"),
                                            swc.src_port.unwrap_or(0),
                                            swc.dst_port.unwrap_or(0),
                                        );
                                        if let Err(e) = local.write_all(header.as_bytes()).await {
                                            warn!("Failed to write PROXY v1 header: {}", e);
                                        }
                                    } else if info.proxy_protocol_version == "v2" {
                                        if let Err(e) = write_proxy_protocol_v2(
                                            &mut local, src,
                                            swc.dst_addr.as_deref().unwrap_or("0.0.0.0"),
                                            swc.src_port.unwrap_or(0) as u16,
                                            swc.dst_port.unwrap_or(0) as u16,
                                        ).await {
                                            warn!("Failed to write PROXY v2 header: {}", e);
                                        }
                                    }
                                }
                            }
                            let enc = if info.use_encryption { Some(&enc_key) } else { None };
                            proxy::bridge_streams(local, work, proxy_name, info.use_encryption, info.use_compression, enc, info.bandwidth_limit, &info.bandwidth_limit_mode, proxy_metrics).await;
                        }
                        Err(e) => {
                            warn!("Work conn {}: failed to connect to local {}: {}", label, info.local_addr, e);
                        }
                    }
                }
            }
            Ok(other) => {
                warn!("Work conn {}: unexpected message: {:?}", label, other.v1_type_byte());
            }
            Err(e) => {
                debug!("Work conn {}: read error: {}", label, e);
            }
        }

        debug!("Work conn {} completed", label);

        // Replenish pool: spawn replacement to maintain pool_count
        // (Go frp v0.69.1 compat — idle work conns refilled after use)
        if pool_id >= 0 {
            spawn_work_conn(
                &server_addr,
                server_port,
                &protocol,
                &run_id,
                proxy_info_map.clone(),
                enc_key,
                pool_id,
                auth_token,
                tls_enable,
                tls_server_name,
                tls_ca_file,
                yamux,
                v2,
                oidc_client,
                repl_udp_sockets,
                repl_udp_enc_cfg,
                repl_proxy_metrics,
                client_auth_scopes.clone(),
                server_auth_scopes.clone(),
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr.clone(),
                repl_proxy_url,
            );
        }
    });
}

/// Run a health check for a proxy.
/// Supports "tcp" (connect only) and "http" (GET + check 2xx status).
/// When the local service exceeds max_failed consecutive failures, sends
/// the proxy name on `health_tx` so the control loop can send CloseProxy
/// to the server.
#[allow(clippy::too_many_arguments)]
async fn run_health_check(
    proxy_name: String,
    local_addr: String,
    check_type: String,
    check_url: String,
    hc_headers: std::collections::HashMap<String, String>,
    interval: std::time::Duration,
    timeout: std::time::Duration,
    max_failed: u32,
    health_tx: mpsc::UnboundedSender<String>,
) {
    info!("Health check ({}) started for '{}' -> {} (interval: {:?}, timeout: {:?})",
        check_type, proxy_name, local_addr, interval, timeout);

    let mut failures: u32 = 0;

    loop {
        tokio::time::sleep(interval).await;

        let result = if check_type == "http" {
            run_http_check(&local_addr, &check_url, timeout, &hc_headers).await
        } else {
            run_tcp_check(&local_addr, timeout).await
        };

        match result {
            Ok(()) => {
                failures = 0;
                debug!("Health check OK for '{}'", proxy_name);
            }
            Err(e) => {
                failures += 1;
                warn!("Health check FAIL for '{}' ({}): {}", proxy_name, failures, e);
            }
        }

        if failures >= max_failed {
            warn!("Health check: proxy '{}' exceeded max failures ({}), sending CloseProxy",
                proxy_name, max_failed);
            let _ = health_tx.send(proxy_name.clone());
            failures = 0; // Reset to avoid repeated warnings
        }
    }
}

/// TCP health check: connect to addr, then close. Success = connection established.
async fn run_tcp_check(addr: &str, timeout: std::time::Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("TCP connect: {e}")),
        Err(_) => Err("timeout".into()),
    }
}

/// HTTP health check: connect, send GET, verify 2xx status code.
/// Uses raw TCP to avoid adding an HTTP client dependency.
async fn run_http_check(addr: &str, url: &str, timeout: std::time::Duration, headers: &std::collections::HashMap<String, String>) -> Result<(), String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("TCP connect: {e}"))?;

    // Extract host from addr (strip port for Host header)
    let host = addr.split(':').next().unwrap_or(addr);
    let mut req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close",
        url, host
    );
    for (key, value) in headers {
        req.push_str(&format!("\r\n{}: {}", key, value));
    }
    req.push_str("\r\n\r\n");

    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;

    if n == 0 {
        return Err("empty response".into());
    }

    // Parse status line: "HTTP/1.x NNN ..."
    let response = std::str::from_utf8(&buf[..n]).map_err(|e| format!("utf8: {e}"))?;
    let status_line = response.lines().next().ok_or("no status line")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad status line: {status_line}"));
    }
    let code: u16 = parts[1].parse().map_err(|_| format!("bad status code: {}", parts[1]))?;

    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(format!("HTTP {code}"))
    }
}

/// Run an STCP/XTCP visitor listener.
/// Binds a local port, accepts connections, and tunnels them
/// through the frps server to the remote STCP proxy.
/// Attempt TCP simultaneous open to `peer_addr`.
///
/// Binds a local port with SO_REUSEADDR (required for simultaneous open),
/// then dials the peer. When both sides do this at roughly the same time,
/// the kernel's TCP stack matches the SYN packets and establishes a P2P
/// connection through most NAT types.
///
/// Returns the connected TcpStream on success, or an error on timeout (5s)
/// or other failures.
async fn tcp_simultaneous_open(peer_addr: &str, timeout_ms: u64) -> Result<tokio::net::TcpStream, String> {
    use std::net::SocketAddr;
    use tokio::net::TcpSocket;

    let peer: SocketAddr = peer_addr
        .parse()
        .map_err(|e| format!("invalid peer address '{}': {}", peer_addr, e))?;

    // Use socket family matching peer address (IPv4 or IPv6)
    let local = if peer.is_ipv4() {
        TcpSocket::new_v4().map_err(|e| format!("TcpSocket::new_v4: {}", e))?
    } else {
        TcpSocket::new_v6().map_err(|e| format!("TcpSocket::new_v6: {}", e))?
    };

    // SO_REUSEADDR is required for TCP simultaneous open:
    // both sides bind to the same port they use to connect.
    local
        .set_reuseaddr(true)
        .map_err(|e| format!("set_reuseaddr: {}", e))?;
    #[cfg(unix)]
    local.set_reuseport(true).ok();

    // Bind to any available port
    let wildcard: &str = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    local
        .bind(wildcard.parse().unwrap())
        .map_err(|e| format!("bind: {}", e))?;

    debug!("TCP simultaneous open: bound to local, dialing {}", peer);

    // Dial with configured timeout
    match tokio::time::timeout(Duration::from_millis(timeout_ms), local.connect(peer)).await {
        Ok(Ok(stream)) => {
            debug!("TCP simultaneous open to {} succeeded", peer);
            Ok(stream)
        }
        Ok(Err(e)) => {
            debug!("TCP simultaneous open to {} failed: {}", peer, e);
            Err(format!("connect failed: {}", e))
        }
        Err(_) => {
            debug!("TCP simultaneous open to {} timed out after {}ms", peer, timeout_ms);
            Err("hole punch timeout".into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_visitor_listener(
    server_addr: String,
    server_port: u16,
    protocol: TransportProtocol,
    server_name: String,
    secret_key: String,
    bind_addr: String,
    use_encryption: bool,
    use_compression: bool,
    name: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    visitor_type: String,
    fallback_timeout_ms: u64,
    keep_tunnel_open: bool,
    max_retries_an_hour: i32,
    min_retry_interval: i64,
) {
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    info!("Visitor '{}' listening on {}", name, bind_addr);

    loop {
        match listener.accept().await {
            Ok((mut user_conn, peer)) => {
                debug!("Visitor '{}': user connection from {}", name, peer);

                let sa = server_addr.clone();
                let sp = server_port;
                let pt = protocol.clone();
                let sn = server_name.clone();
                let sk = secret_key.clone();
                let visitor_name = name.clone();
                let tls_sn = tls_server_name.clone();
                let tls_ca = tls_ca_file.clone();
                let vt = visitor_type.clone();

                tokio::spawn(async move {
                    // Connect to the server
                    let opts = DialOptions {
                        server_addr: sa.clone(),
                        server_port: sp,
                        protocol: pt.clone(),
                        tls_enable,
                        tls_server_name: tls_sn,
                        tls_ca_file: tls_ca,
                        ..Default::default()
                    };

                    if vt == "xtcp" {
                        // --- XTCP NAT hole punch path (with optional retry) ---
                        let max_retries = if keep_tunnel_open { max_retries_an_hour.max(0) as usize } else { 0 };
                        let retry_delay = Duration::from_secs(min_retry_interval.max(1) as u64);
                        let mut hole_punch_ok = false;

                        for attempt in 0..=max_retries {
                            if attempt > 0 {
                                debug!(
                                    "Visitor '{}': XTCP retry {}/{} after {:?}",
                                    visitor_name, attempt, max_retries, retry_delay
                                );
                                tokio::time::sleep(retry_delay).await;
                            }

                            let mut server_conn = match dial_server(&opts).await {
                                Ok(io) => io,
                                Err(e) => {
                                    warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            };

                            // Build NatHoleVisitor
                            let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
                                transaction_id: uuid::Uuid::new_v4().to_string(),
                                proxy_name: sn.clone(),
                                pre_check: true,
                                ..Default::default()
                            });
                            if let Err(e) = server_conn.write_v1_frame(&nhv).await {
                                warn!("Visitor '{}': send NatHoleVisitor failed: {}", visitor_name, e);
                                if keep_tunnel_open && attempt < max_retries { continue; }
                                return;
                            }
                            debug!("Visitor '{}': sent NatHoleVisitor for '{}'", visitor_name, sn);

                            // Read NatHoleSid (contains provider address)
                            match server_conn.read_v1_frame().await {
                                Ok(FrpMessage::NatHoleSid(sid_msg)) => {
                                    let provider_addr = sid_msg.provider_addr.unwrap_or_default();
                                    debug!("Visitor '{}': got provider addr '{}'", visitor_name, provider_addr);

                                    // Read NatHoleReport (provider is ready)
                                    match server_conn.read_v1_frame().await {
                                        Ok(FrpMessage::NatHoleReport(_)) => {
                                            debug!("Visitor '{}': provider ready, attempting P2P", visitor_name);

                                            if !provider_addr.is_empty() {
                                                match tcp_simultaneous_open(&provider_addr, fallback_timeout_ms).await {
                                                    Ok(p2p_stream) => {
                                                        info!("Visitor '{}': XTCP P2P connected to {}", visitor_name, provider_addr);
                                                        let mut p2p = p2p_stream;
                                                        match tokio::io::copy_bidirectional(&mut user_conn, &mut p2p).await {
                                                            Ok((to_p2p, to_user)) => {
                                                                debug!("Visitor '{}' XTCP closed: {}B to P2P, {}B to user",
                                                                    visitor_name, to_p2p, to_user);
                                                            }
                                                            Err(e) => {
                                                                debug!("Visitor '{}' XTCP bridge error: {}", visitor_name, e);
                                                            }
                                                        }
                                                        hole_punch_ok = true;
                                                        break; // P2P succeeded
                                                    }
                                                    Err(e) => {
                                                        warn!("Visitor '{}': XTCP hole punch failed: {}", visitor_name, e);
                                                        if keep_tunnel_open && attempt < max_retries { continue; }
                                                        // Fall through to STCP fallback
                                                    }
                                                }
                                            }
                                        }
                                        Ok(FrpMessage::NatHoleResp(resp)) => {
                                            if let Some(err) = resp.error {
                                                warn!("Visitor '{}': server error: {}", visitor_name, err);
                                            }
                                            if keep_tunnel_open && attempt < max_retries { continue; }
                                            return;
                                        }
                                        other => {
                                            warn!("Visitor '{}': unexpected NatHole response: {:?}", visitor_name,
                                                other.as_ref().map(|m| m.v1_type_byte()));
                                            if keep_tunnel_open && attempt < max_retries { continue; }
                                            return;
                                        }
                                    }
                                }
                                Ok(FrpMessage::NatHoleResp(resp)) => {
                                    if let Some(err) = resp.error {
                                        warn!("Visitor '{}': server error: {}", visitor_name, err);
                                    }
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                                other => {
                                    warn!("Visitor '{}': unexpected response to NatHoleVisitor: {:?}", visitor_name,
                                        other.as_ref().map(|m| m.v1_type_byte()));
                                    if keep_tunnel_open && attempt < max_retries { continue; }
                                    return;
                                }
                            }
                        }

                        if hole_punch_ok {
                            return; // XTCP P2P succeeded
                        }

                        // --- STCP fallback (hole punch failed) ---
                        // Open a NEW connection for STCP relay
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                debug!("Visitor '{}': STCP fallback dial failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!("Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!("Visitor '{}': STCP fallback send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        info!("Visitor '{}': fell back to STCP relay for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!("Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!("Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!("Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let mut user = user_conn;
                        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                            Ok((to_server, to_user)) => {
                                debug!("Visitor '{}' STCP relay closed: {}B to server, {}B to user",
                                    visitor_name, to_server, to_user);
                            }
                            Err(e) => {
                                debug!("Visitor '{}' STCP relay bridge error: {}", visitor_name, e);
                            }
                        }
                    } else {
                        // --- STCP relay path (existing) ---
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!("Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!("Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        debug!("Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!("Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!("Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!("Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let mut user = user_conn;
                        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                            Ok((to_server, to_user)) => {
                                debug!("Visitor '{}' closed: {}B to server, {}B to user", visitor_name, to_server, to_user);
                            }
                            Err(e) => {
                                debug!("Visitor '{}' bridge error: {}", visitor_name, e);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                warn!("Visitor '{}': accept error: {}", name, e);
                break;
            }
        }
    }
}
