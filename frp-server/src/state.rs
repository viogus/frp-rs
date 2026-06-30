use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use frp_core::auth::{AuthConfig, OidcVerifier};
use frp_core::transport::IoStream;
use frp_core::metrics::ProxyMetricsRegistry;

use crate::proxy::ProxyManager;
use crate::nathole::controller::Controller;
use crate::vhost::VhostManager;
use crate::tcpmux::TcpMuxManager;

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
    Shutdown,
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
        provider_addr: Option<String>,
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
    /// Forward a vnet IP packet to a target client's control handler.
    #[cfg(feature = "vnet")]
    VnetPacketForward {
        proxy_name: String,
        data: String, // base64-encoded IP packet
    },
}

#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::UnboundedSender<InternalMsg>,
    pub client_addr: Option<SocketAddr>,
    pub login_time: Instant,
}

/// Hot-reloadable server configuration subset, updated atomically on SIGUSR1.
#[derive(Debug, Clone)]
pub struct ReloadableState {
    pub auth_cfg: Arc<AuthConfig>,
    pub encryption_key: [u8; 16],
    pub allow_ports: Vec<(u16, u16)>,
    pub additional_auth_scopes: Vec<String>,
}

pub struct AppState {
    pub proxy_manager: Arc<ProxyManager>,
    /// Hot-reloadable config (auth, encryption, allow_ports).
    /// Uses std::sync::RwLock — blocking read has no async overhead.
    /// Writes only happen on SIGUSR1 reload (vanishingly rare).
    pub reloadable: Arc<std::sync::RwLock<ReloadableState>>,
    pub used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    pub run_id_to_ctl_tx: Arc<RwLock<HashMap<String, ControlTx>>>,
    pub proxy_bind_addr: String,
    pub vhost_manager: Arc<VhostManager>,
    pub vhost_http_port: u16,
    pub sk_index: Arc<RwLock<HashMap<String, String>>>,
    pub dashboard_start: std::time::Instant,
    pub sub_domain_host: String,
    pub tcp_mux: bool,
    pub tcp_mux_keepalive: i64,
    pub heartbeat_timeout: i64,
    pub udp_packet_size: usize,
    pub tls_only: bool,
    pub oidc_verifier: Option<Arc<OidcVerifier>>,
    pub oidc_subjects: Arc<RwLock<HashMap<String, String>>>,
    pub nat_hole: Arc<Controller>,
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
    /// CancellationToken for graceful shutdown. Cancelled on SIGTERM/SIGINT.
    /// Main accept loop and control handlers watch this to stop accepting new
    /// connections while letting existing bridge tasks drain.
    pub shutdown_token: CancellationToken,
    /// Active bridge connection counter. Incremented when a bridge task starts,
    /// decremented when it completes. The drain phase polls this counter.
    pub active_connections: AtomicU64,
    /// Virtual network routing table: (virtual_net, subnet) → (run_id, proxy_name).
    /// Populated by VnetRouteAdvertise messages, used to forward VnetPacket.
    #[cfg(feature = "vnet")]
    pub vnet_routes: Arc<RwLock<HashMap<(String, String), (String, String)>>>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(auth_cfg: AuthConfig, proxy_bind_addr: String, encryption_key: [u8; 16], allow_ports: Vec<(u16, u16)>, sub_domain_host: String, tcp_mux: bool, tcp_mux_keepalive: i64, heartbeat_timeout: i64, udp_packet_size: usize, tls_only: bool, oidc_verifier: Option<Arc<OidcVerifier>>, sudp_port: u16, vhost_http_timeout: u64, user_conn_timeout: u64, tcp_mux_passthrough: bool, custom_404_page: String, plugin_manager: Arc<crate::plugin::HttpPluginManager>, max_ports_per_client: u64, nat_hole_analysis_data_reserve_hours: u64, detailed_errors_to_client: bool) -> Self {
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
            proxy_bind_addr,
            vhost_manager: Arc::new(VhostManager::new()),
            vhost_http_port: 0, // set by Service::run() before starting listeners
            dashboard_start: std::time::Instant::now(),
            sk_index: Arc::new(RwLock::new(HashMap::new())),
            sub_domain_host,
            tcp_mux,
            tcp_mux_keepalive,
            heartbeat_timeout,
            udp_packet_size,
            tls_only,
            oidc_verifier,
            oidc_subjects: Arc::new(RwLock::new(HashMap::new())),
            nat_hole: Arc::new(Controller::new(Duration::from_secs(nat_hole_analysis_data_reserve_hours.saturating_mul(3600)))),
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
            #[cfg(feature = "tls")]
            tls_acceptor: Arc::new(std::sync::RwLock::new(None)),
            shutdown_token: CancellationToken::new(),
            active_connections: AtomicU64::new(0),
            #[cfg(feature = "vnet")]
            vnet_routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
