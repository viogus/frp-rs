use serde::{Deserialize, Serialize};

use super::server::{
    default_authentication_timeout, default_heartbeat_timeout, default_token_auth_timeout,
    default_true, FeatureConfig, LogConfig, ObservabilityConfig, PluginConfig, QuicOptions,
    StoreConfig, ValueSource, WebServerConfig, MAX_HEARTBEAT_TIMEOUT_SECS,
};

fn default_udp_packet_size_i64() -> i64 {
    1500
}

fn default_visitor_bind_addr() -> String {
    "127.0.0.1".into()
}
fn default_fallback_timeout_ms() -> u64 {
    1000
}

fn default_pool_count() -> i32 {
    1
}

fn default_health_check_url() -> String {
    "".into()
}

fn default_local_ip() -> String {
    "127.0.0.1".into()
}

fn default_bandwidth_limit_mode() -> String {
    "client".into()
}

fn default_health_check_timeout_seconds() -> u64 {
    3
}

fn default_health_check_max_failed() -> u32 {
    1
}

fn default_health_check_interval_seconds() -> u64 {
    10
}

/// Client-side authentication configuration ([auth] section in frpc.toml).
/// Mirrors Go frp v0.69.1 AuthClientConfig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClientConfig {
    #[serde(
        default,
        alias = "authentication_method",
        alias = "auth_method",
        alias = "authMethod"
    )]
    pub method: String,
    #[serde(default)]
    pub token: String,
    /// Dynamic source for the auth token. Mutually exclusive with `token`.
    /// Go frp v0.70.1 compat: auth.tokenSource.
    #[serde(default, alias = "tokenSource")]
    pub token_source: Option<ValueSource>,
    #[serde(default, alias = "oidcClientId")]
    pub oidc_client_id: String,
    #[serde(default, alias = "oidcClientSecret")]
    pub oidc_client_secret: String,
    #[serde(default, alias = "oidcAudience")]
    pub oidc_audience: String,
    #[serde(
        default,
        alias = "oidcTokenEndpoint",
        alias = "oidc_token_endpoint_url"
    )]
    pub oidc_token_endpoint: String,
    #[serde(default, alias = "oidcScope")]
    pub oidc_scope: String,
    #[serde(default, alias = "oidcIssuer")]
    pub oidc_issuer: String,
    /// Extra params for token endpoint. Go frp v0.70.1 compat:
    /// AuthOIDCClientConfig.AdditionalEndpointParams (map[string]string).
    #[serde(default, alias = "additionalEndpointParams")]
    pub additional_endpoint_params: std::collections::HashMap<String, String>,
    /// Dynamic source for the OIDC token. Mutually exclusive with every
    /// other field of `[auth.oidc]`. Go frp v0.70.1 compat: tokenSource
    /// (normalized from the `[auth.oidc]` sub-table).
    #[serde(default)]
    pub oidc_token_source: Option<ValueSource>,
    /// Path to a custom CA certificate PEM file for OIDC provider TLS.
    /// Go frp compat: tls_trusted_ca_file.
    #[serde(default, alias = "tls_trusted_ca_file")]
    pub oidc_tls_trusted_ca_file: String,
    /// Skip TLS certificate verification for OIDC (dev only).
    /// Go frp compat: insecure_skip_verify.
    #[serde(default)]
    pub oidc_tls_insecure_skip_verify: bool,
    /// HTTP/SOCKS5 proxy URL for OIDC HTTP client connections.
    /// Go frp compat: oidcProxyURL.
    #[serde(default, alias = "oidcProxyURL")]
    pub oidc_proxy_url: String,
    /// Additional auth scopes: "HeartBeats", "NewWorkConns".
    /// Client-side scopes, unioned with server's scopes.
    /// Go frp compat: additionalAuthScopes.
    #[serde(default, alias = "additionalAuthScopes", alias = "additionalScopes")]
    pub additional_auth_scopes: Vec<String>,
    /// Maximum allowed clock skew for timestamp-based replay protection
    /// (server-side only; client ignores this field). 0 disables the check.
    /// Go frp compat: authentication_timeout.
    #[serde(
        default = "default_authentication_timeout",
        alias = "authenticationTimeout"
    )]
    pub authentication_timeout: i64,
    /// When true (default), token auth validates timestamp freshness and
    /// rejects duplicate (run_id, timestamp) pairs to prevent replay attacks.
    /// This field is primarily configured on the server; the client includes
    /// it for config passthrough.
    /// Go frp compat: tokenAuthTimeout.
    #[serde(default = "default_token_auth_timeout", alias = "tokenAuthTimeout")]
    pub token_auth_timeout: bool,
}

impl Default for AuthClientConfig {
    fn default() -> Self {
        Self {
            method: "token".into(),
            token: String::new(),
            token_source: None,
            oidc_client_id: String::new(),
            oidc_client_secret: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
            oidc_scope: String::new(),
            oidc_issuer: String::new(),
            additional_endpoint_params: std::collections::HashMap::new(),
            oidc_token_source: None,
            oidc_tls_trusted_ca_file: String::new(),
            oidc_tls_insecure_skip_verify: false,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            token_auth_timeout: true,
        }
    }
}

/// Client virtual network controller configuration ([virtualNet] section in frpc.toml).
/// Go frp v0.70.1 compat: VirtualNetConfig.address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtualNetConfig {
    /// TUN device address configured on the client controller.
    #[serde(default, alias = "address")]
    pub address: String,
}

/// One HTTP header for a proxy health check (Go frp `HTTPHeader{name,value}`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct HealthCheckHttpHeader {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_server_addr")]
    pub server_addr: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub auth: Option<AuthClientConfig>,
    #[serde(default)]
    pub user: String,
    #[serde(default, alias = "clientID")]
    pub client_id: String,
    /// Client-level metadata sent in the Login message.
    /// Go frp compat: metadatas.
    #[serde(default, alias = "metadatas")]
    pub metas: std::collections::HashMap<String, String>,
    /// Upstream proxy URL for the client→server control connection.
    /// Supports http://, socks5:// schemes. Empty = direct connection.
    /// Go frp compat: transport.proxyURL.
    #[serde(default, alias = "proxyURL")]
    pub proxy_url: String,
    /// Custom STUN server address for NAT traversal.
    /// Format: "stun:host:port". Empty = use default.
    /// Go frp compat: natHoleStunServer. Default: "stun.easyvoip.com:3478".
    #[serde(default = "default_nat_hole_stun_server", alias = "natHoleStunServer")]
    pub nat_hole_stun_server: String,
    /// Selective proxy start: if non-empty, only proxies with names in this
    /// list are started. Empty = start all proxies.
    /// Go frp compat: start.
    #[serde(default)]
    pub start: Vec<String>,
    /// Config file include patterns. Each entry is a glob pattern for
    /// additional TOML/INI config files to merge. Relative to the main
    /// config file directory.
    /// Go frp compat: includes.
    #[serde(default)]
    pub includes: Vec<String>,
    /// File-backed runtime config store. When path is set, proxies and
    /// visitors managed through the store API are loaded from and persisted
    /// to the JSON file, overlaying config-file entries with the same name.
    /// Go frp v0.70.1 compat: [store] section.
    #[serde(default, alias = "store")]
    pub store: Option<StoreConfig>,
    #[serde(default = "default_true")]
    pub tls_enable: bool,
    #[serde(default)]
    pub tls_cert_file: String,
    #[serde(default)]
    pub tls_key_file: String,
    #[serde(default)]
    pub tls_ca_file: String,
    /// Explicitly skip TLS server-certificate verification (Go frp's
    /// InsecureSkipVerify=true). Default `false` preserves the Go-compatible
    /// behavior: with `tls_ca_file` set the server cert is verified against
    /// it; without it, verification is skipped (the frp-rs default for
    /// auto-generated self-signed certs, matching Go frp). Set `true` to
    /// force-skip verification even when `tls_ca_file` is configured — for
    /// operators who want the decision explicit. This is a security
    /// downgrade; prefer setting `tls_ca_file` to a trusted CA instead.
    /// Go frp compat: insecureSkipVerify (frp-rs ships the safer default).
    #[serde(default, alias = "tlsSkipVerify")]
    pub tls_skip_verify: bool,
    #[serde(default, alias = "tlsServerName")]
    pub tls_server_name: String,
    /// Disable the custom TLS head byte (0x17) written before the TLS handshake.
    /// When true, the client skips the Go frp protocol marker and starts TLS directly.
    /// Go frp compat: disableCustomTLSFirstByte. Default: true.
    #[serde(default = "default_true", alias = "disableCustomTLSFirstByte")]
    pub disable_custom_tls_first_byte: bool,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_true", alias = "loginFailExit")]
    pub login_fail_exit: bool,
    #[serde(default = "default_pool_count", alias = "poolCount")]
    pub pool_count: i32,
    /// Ping interval in seconds. Client sends a heartbeat Ping at this
    /// interval. Default: 30. Go frp compat: transport.heartbeatInterval.
    #[serde(default = "default_heartbeat_interval", alias = "heartbeatInterval")]
    pub heartbeat_interval: i64,
    /// Heartbeat timeout in seconds. Disconnect if no Pong received within
    /// this interval. Default: 90. Go frp compat: transport.heartbeatTimeout.
    #[serde(default = "default_heartbeat_timeout", alias = "heartbeatTimeout")]
    pub heartbeat_timeout: i64,
    #[serde(default, alias = "dnsServer")]
    pub dns_server: String,
    /// TCP keepalive interval in seconds for outbound connections to the
    /// frp server. An explicit 0 means "use the default" (Go
    /// util.EmptyOr): 7200s. Go frp compat: dialServerKeepalive.
    #[serde(
        default = "default_dial_server_keepalive",
        alias = "dialServerKeepalive"
    )]
    pub dial_server_keepalive: i64,
    /// Timeout in seconds for dialing the frp server.
    /// Go frp v0.70.1 compat: dialServerTimeout. Default: 10.
    #[serde(default = "default_dial_server_timeout", alias = "dialServerTimeout")]
    pub dial_server_timeout: i64,
    /// Local IP address to bind when dialing the frp server.
    /// Empty means use system default. Go frp compat: connectServerLocalIP.
    #[serde(default, alias = "connectServerLocalIP")]
    pub connect_server_local_ip: String,
    #[serde(default = "default_tcp_mux")]
    pub tcp_mux: bool,
    /// TCP mux keepalive interval in seconds. Controls how often yamux
    /// sends keepalive pings to detect dead peers. Default: 30.
    /// Go frp compat: transport.tcpMuxKeepaliveInterval.
    #[serde(default, alias = "tcpMuxKeepaliveInterval")]
    pub tcp_mux_keepalive_interval: i64,
    /// TCP send-buffer size in bytes on outbound connections (SO_SNDBUF).
    /// 0 = OS default. frp-rs extension for high-BDP links.
    #[serde(default, alias = "tcpSendBuffer")]
    pub tcp_send_buffer_size: u32,
    /// TCP receive-buffer size in bytes on outbound connections (SO_RCVBUF).
    /// 0 = OS default. frp-rs extension for high-BDP links.
    #[serde(default, alias = "tcpRecvBuffer")]
    pub tcp_recv_buffer_size: u32,
    #[serde(default)]
    pub v2: bool,
    /// QUIC protocol options.
    #[serde(default, rename = "quic")]
    pub quic_options: Option<QuicOptions>,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    #[serde(default)]
    pub visitors: Vec<VisitorConfig>,
    #[serde(default, alias = "webServer")]
    pub web_server: WebServerConfig,
    /// Client virtual network controller configuration.
    /// Go frp v0.70.1 compat: [virtualNet] section.
    #[serde(default, alias = "virtualNet")]
    pub virtual_net: VirtualNetConfig,
    /// Experimental feature gates. Go frp compat: [feature] section.
    #[serde(default, alias = "featureGates")]
    pub feature: FeatureConfig,
    /// UDP packet buffer size in bytes. Controls the receive buffer for UDP
    /// proxy datagrams. Default: 1500 (Go frp compat).
    /// Go frp compat: udpPacketSize / UDPPacketSize.
    #[serde(default = "default_udp_packet_size_i64", alias = "udpPacketSize")]
    pub udp_packet_size: i64,
    /// OpenTelemetry / observability settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0".into(),
            server_port: default_server_port(),
            transport_protocol: default_transport_protocol(),
            token: String::new(),
            auth: None,
            user: String::new(),
            client_id: String::new(),
            metas: std::collections::HashMap::new(),
            proxy_url: String::new(),
            nat_hole_stun_server: default_nat_hole_stun_server(),
            start: Vec::new(),
            includes: Vec::new(),
            store: None,
            tls_enable: true,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_skip_verify: false,
            tls_server_name: String::new(),
            disable_custom_tls_first_byte: true,
            log: LogConfig::default(),
            login_fail_exit: true,
            pool_count: 1,
            heartbeat_interval: default_heartbeat_interval(),
            heartbeat_timeout: default_heartbeat_timeout(),
            dns_server: String::new(),
            dial_server_keepalive: default_dial_server_keepalive(),
            dial_server_timeout: default_dial_server_timeout(),
            connect_server_local_ip: String::new(),
            tcp_mux: default_tcp_mux(),
            tcp_mux_keepalive_interval: 30,
            tcp_send_buffer_size: 0,
            tcp_recv_buffer_size: 0,
            v2: false,
            quic_options: None,
            proxies: vec![],
            visitors: vec![],
            web_server: WebServerConfig::default(),
            virtual_net: VirtualNetConfig::default(),
            feature: FeatureConfig::default(),
            udp_packet_size: default_udp_packet_size_i64(),
            observability: ObservabilityConfig::default(),
        }
    }
}

impl ClientConfig {
    /// Apply conditional defaults matching Go frp dev (fatedier/frp@d486018)
    /// `ClientCommonConfig.Complete()` + `ClientTransportConfig.Complete()`.
    /// Call after deserialization, before consuming the config.
    pub fn complete(&mut self) {
        self.complete_with_heartbeat_set(false, false);
    }

    pub(super) fn complete_with_heartbeat_set(
        &mut self,
        heartbeat_interval_set: bool,
        heartbeat_timeout_set: bool,
    ) {
        // MEDIUM-7: Fallback to http_proxy/HTTP_PROXY env var when proxy_url is empty
        if self.proxy_url.is_empty() {
            if let Ok(proxy) = std::env::var("http_proxy") {
                if !proxy.is_empty() {
                    self.proxy_url = proxy;
                }
            } else if let Ok(proxy) = std::env::var("HTTP_PROXY") {
                if !proxy.is_empty() {
                    self.proxy_url = proxy;
                }
            }
        }

        // Go v0.70.1: with tcpMux enabled, application-layer heartbeats are
        // disabled by default (-1) and yamux keepalive covers liveness. An
        // explicit value is preserved (Option-style set tracking). This
        // branch keeps its exact current behavior.
        if self.tcp_mux {
            if !heartbeat_interval_set {
                self.heartbeat_interval = -1;
            }
            if !heartbeat_timeout_set {
                self.heartbeat_timeout = -1;
            }
        } else {
            // Go v0.71.0: with tcpMux off, an explicit 0 is the Go zero
            // value (util.EmptyOr) → the default: 30 / 90.
            if self.heartbeat_interval == 0 {
                self.heartbeat_interval = default_heartbeat_interval();
            }
            if self.heartbeat_timeout == 0 {
                self.heartbeat_timeout = default_heartbeat_timeout();
            }
        }

        // Go v0.71.0: PoolCount = EmptyOr(0, 1) — an explicit 0 means
        // "use the default" (1), not "disabled".
        if self.pool_count == 0 {
            self.pool_count = default_pool_count();
        }

        // Go v0.71.0: DialServerKeepAlive = EmptyOr(0, 7200) — an explicit
        // 0 means "use the default" (7200), not "disabled".
        if self.dial_server_keepalive == 0 {
            self.dial_server_keepalive = default_dial_server_keepalive();
        }

        // Go v0.70.1: dialServerTimeout = 0 means "use the default" (10s).
        if self.dial_server_timeout == 0 {
            self.dial_server_timeout = default_dial_server_timeout();
        }

        // Clamp huge explicit heartbeat values — parity with the server-side
        // clamp in ServerTransportConfig::complete_with_heartbeat_timeout_set
        // (round-7 finding 5). The client control watchdog sleeps
        // `hb_timeout.saturating_sub(last_pong.elapsed())`
        // (frp-client/src/service.rs), and tokio's internal sleep-deadline
        // math (Instant + duration, i64-scale) overflows only at values far
        // beyond 3600s — but Go frp has no clamp at all and accepts e.g.
        // 7200, so this deliberately rewrites pathological values instead of
        // honoring them (documented divergence, not parity). 3600s is far
        // beyond any sane heartbeat interval. Values <= 0 (explicit disable)
        // keep their semantics.
        if self.heartbeat_interval > MAX_HEARTBEAT_TIMEOUT_SECS {
            self.heartbeat_interval = MAX_HEARTBEAT_TIMEOUT_SECS;
        }
        if self.heartbeat_timeout > MAX_HEARTBEAT_TIMEOUT_SECS {
            self.heartbeat_timeout = MAX_HEARTBEAT_TIMEOUT_SECS;
        }
    }

    /// Merge file-stored proxies/visitors over this config.
    ///
    /// Go frp v0.70.1 uses the store source as a higher-priority overlay:
    /// store entries with the same name replace config-file entries, and names
    /// present only in one source are carried through unchanged. Disabled
    /// entries are filtered by the caller before merging (Go frp source-local
    /// filtering), so they do not reach this function.
    pub fn merge_store_items(
        &self,
        store_proxies: impl IntoIterator<Item = ProxyConfig>,
        store_visitors: impl IntoIterator<Item = VisitorConfig>,
    ) -> Self {
        let mut merged = self.clone();
        let mut proxy_map: std::collections::HashMap<String, ProxyConfig> = merged
            .proxies
            .into_iter()
            .map(|p| (p.name.clone(), p))
            .collect();
        for p in store_proxies {
            proxy_map.insert(p.name.clone(), p);
        }
        merged.proxies = proxy_map.into_values().collect();
        merged.proxies.sort_by(|a, b| a.name.cmp(&b.name));

        let mut visitor_map: std::collections::HashMap<String, VisitorConfig> = merged
            .visitors
            .into_iter()
            .map(|v| (v.name.clone(), v))
            .collect();
        for v in store_visitors {
            visitor_map.insert(v.name.clone(), v);
        }
        merged.visitors = visitor_map.into_values().collect();
        merged.visitors.sort_by(|a, b| a.name.cmp(&b.name));
        merged
    }
}

fn default_server_port() -> u16 {
    7000
}
/// Go `ClientCommonConfig.Complete()` defaults `serverAddr` to "0.0.0.0"
/// (client.go:86) — `server_addr` is the only Go-defaulted field that had no
/// serde default, so a config omitting it failed at load (round 10 MEDIUM).
fn default_server_addr() -> String {
    "0.0.0.0".into()
}
fn default_transport_protocol() -> String {
    "tcp".into()
}
fn default_tcp_mux() -> bool {
    true
}
pub(super) fn default_heartbeat_interval() -> i64 {
    30
}
fn default_nat_hole_stun_server() -> String {
    "stun.easyvoip.com:3478".into()
}
pub(super) fn default_dial_server_timeout() -> i64 {
    10
}

/// Outbound TCP keepalive idle time (Go frp default: 7200s).
pub(super) fn default_dial_server_keepalive() -> i64 {
    7200
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    #[serde(default = "default_local_ip", alias = "localIp", alias = "localIP")]
    pub local_ip: String,
    #[serde(default, alias = "localPort")]
    pub local_port: u16,
    #[serde(default, alias = "remotePort")]
    pub remote_port: u16,
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,
    #[serde(default, alias = "secretKey")]
    pub sk: String,
    #[serde(default)]
    pub plugin: Option<PluginConfig>,
    #[serde(default, alias = "customDomains")]
    pub custom_domains: Vec<String>,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default, alias = "httpUser")]
    pub http_user: String,
    #[serde(default, alias = "httpPwd")]
    pub http_pwd: String,
    #[serde(default, alias = "httpPassword")]
    pub http_password: String,
    #[serde(default)]
    pub locations: Vec<String>,
    #[serde(default, alias = "hostHeaderRewrite")]
    pub host_header_rewrite: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default, alias = "responseHeaders")]
    pub response_headers: std::collections::HashMap<String, String>,
    #[serde(default, alias = "routeByHTTPUser")]
    pub route_by_http_user: String,
    #[serde(default, alias = "allowUsers")]
    pub allow_users: Vec<String>,
    #[serde(default, alias = "bandwidthLimit")]
    pub bandwidth_limit: String,
    #[serde(default = "default_bandwidth_limit_mode", alias = "bandwidthLimitMode")]
    pub bandwidth_limit_mode: String,
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
    #[serde(default, alias = "metadatas")]
    pub metas: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub multiplexer: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub group_key: String,
    #[serde(default)]
    pub health_check_type: String,
    #[serde(default = "default_health_check_url")]
    pub health_check_url: String,
    /// Custom HTTP headers for health check requests (Go frp compat: healthCheckHttpHeaders).
    #[serde(default, alias = "healthCheckHttpHeaders")]
    pub health_check_http_headers: Vec<HealthCheckHttpHeader>,
    #[serde(default = "default_health_check_interval_seconds")]
    pub health_check_interval_seconds: u64,
    #[serde(default = "default_health_check_timeout_seconds")]
    pub health_check_timeout_seconds: u64,
    #[serde(default = "default_health_check_max_failed")]
    pub health_check_max_failed: u32,
    /// Virtual network name for STCP/XTCP proxy isolation.
    /// Proxies in different virtual nets cannot reach each other.
    /// Empty string (default) means the default (global) network.
    #[serde(default)]
    pub virtual_net: String,
    /// CIDR subnet this vnet client advertises to peers (e.g. "10.0.0.0/24").
    /// Only used when type = "vnet". Go frp compat: advertiseSubnet.
    #[serde(default, alias = "advertiseSubnet")]
    pub advertise_subnet: String,
    /// IP address for the local TUN device. Go frp compat: vnetIp.
    #[serde(default, alias = "vnetIp")]
    pub vnet_ip: String,
    /// Netmask for the TUN device (default: 255.255.255.0). Go frp compat: vnetNetmask.
    #[serde(default = "default_vnet_netmask", alias = "vnetNetmask")]
    pub vnet_netmask: String,
    /// MTU for the TUN device (default: 1420). Go frp compat: vnetMtu.
    #[serde(default = "default_vnet_mtu", alias = "vnetMtu")]
    pub vnet_mtu: u16,
    /// PROXY protocol version: "v1", "v2", or "" (disabled).
    /// Go frp compat: proxyProtocolVersion.
    #[serde(default, alias = "proxyProtocolVersion")]
    pub proxy_protocol_version: String,
    /// Whether this proxy is enabled. Disabled proxies are not started.
    /// Go frp compat: enabled. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Disable NAT traversal assisted address reporting for XTCP.
    /// Go frp compat: natTraversal.disableAssistedAddrs.
    #[serde(default, alias = "disableAssistedAddrs")]
    pub disable_assisted_addrs: bool,
}

/// STCP/XTCP visitor configuration — used by frpc to expose a local port
/// that tunnels traffic to a remote STCP/XTCP proxy through the frps server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisitorConfig {
    /// Name for this visitor (used in logs).
    #[serde(default)]
    pub name: String,
    /// Proxy type: "stcp" or "xtcp".
    #[serde(rename = "type", default)]
    pub visitor_type: String,
    /// The STCP/XTCP proxy name to connect to (maps to proxy_name in NewVisitorConn).
    #[serde(default, alias = "serverName")]
    pub server_name: String,
    /// Shared secret key — must match the STCP proxy's `sk`.
    #[serde(default, alias = "secretKey", alias = "sk")]
    pub secret_key: String,
    /// Protocol for XTCP P2P connections: "quic" (default, matching Go frp
    /// v0.70.1) or "kcp". Both data planes are implemented; "quic" requires
    /// BOTH the `quic` and `kcp` features (the QUIC data plane reuses the
    /// KCP hole-punch machinery). An EXPLICIT empty value normalizes to
    /// "quic" (Go frp: `Protocol = util.EmptyOr(Protocol, "quic")` at
    /// pkg/config/v1/visitor.go:160 — a missing field is covered by the
    /// serde default; the deserializer covers `protocol = ""`).
    #[serde(
        default = "default_xtcp_protocol",
        alias = "protocol",
        deserialize_with = "deserialize_xtcp_protocol"
    )]
    pub protocol: String,
    /// Optional server user for auth matching.
    #[serde(default, alias = "serverUser")]
    pub server_user: String,
    /// Local address to bind for accepting connections.
    #[serde(default = "default_visitor_bind_addr", alias = "bindAddr")]
    pub bind_addr: String,
    /// Local port for the visitor listener. 0 = disabled, -1 = no-bind (do not
    /// listen locally), positive values start a local listener. Go frp uses `int`
    /// and negative values mean "don't bind".
    #[serde(default, alias = "bindPort")]
    pub bind_port: i32,
    /// Optional visitor plugin ([visitors.plugin] section).
    /// Go frp v0.70.1 compat: Plugin.
    #[serde(default)]
    pub plugin: Option<VisitorPluginConfig>,
    /// Fallback timeout in milliseconds before switching from XTCP to STCP.
    /// Go frp compat: fallbackTimeoutMs. Default: 1000 (1 second, Go frp compat)
    #[serde(default = "default_fallback_timeout_ms", alias = "fallbackTimeoutMs")]
    pub fallback_timeout_ms: u64,
    /// Fallback visitor name if this one fails.
    #[serde(default, alias = "fallbackTo")]
    pub fallback_to: String,
    /// Disable NAT traversal assisted address reporting (STUN-discovered
    /// mapped addresses shared between peers during XTCP hole punching).
    /// Go frp compat: natTraversal.disableAssistedAddrs.
    #[serde(default, alias = "disableAssistedAddrs")]
    pub disable_assisted_addrs: bool,
    /// Encrypt the tunnel traffic.
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,
    /// Compress the tunnel traffic.
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,
    /// Keep XTCP tunnel open after connection ends. When true, the
    /// visitor retries NAT hole punching instead of falling back to STCP.
    /// Go frp compat: keepTunnelOpen.
    #[serde(default, alias = "keepTunnelOpen")]
    pub keep_tunnel_open: bool,
    /// Maximum XTCP NAT hole punch retries per hour.
    /// Go frp compat: maxRetriesAnHour. Default: 8.
    #[serde(default = "default_max_retries_an_hour", alias = "maxRetriesAnHour")]
    pub max_retries_an_hour: i32,
    /// Minimum interval in seconds between XTCP retry attempts.
    /// Go frp compat: minRetryInterval. Default: 90 (Go frp compat)
    #[serde(default = "default_min_retry_interval", alias = "minRetryInterval")]
    pub min_retry_interval: i64,
    /// Whether this visitor is enabled. Disabled visitors are not started.
    /// Go frp compat: enabled. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for VisitorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            visitor_type: String::new(),
            server_name: String::new(),
            secret_key: String::new(),
            server_user: String::new(),
            bind_addr: default_visitor_bind_addr(),
            bind_port: 0,
            plugin: None,
            fallback_timeout_ms: default_fallback_timeout_ms(),
            fallback_to: String::new(),
            disable_assisted_addrs: false,
            use_encryption: false,
            use_compression: false,
            keep_tunnel_open: false,
            max_retries_an_hour: default_max_retries_an_hour(),
            min_retry_interval: default_min_retry_interval(),
            protocol: default_xtcp_protocol(),
            enabled: true,
        }
    }
}

/// Visitor plugin configuration ([visitors.plugin] section).
/// Go frp v0.70.1 compat: TypedVisitorPluginOptions.
///
/// Only `type = "virtual_net"` (with `destinationIP`) is supported by frp-rs
/// today. The remaining fields are accepted for the STCP/XTCP `visitor_plugin`
/// extension used by older frp-rs configs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VisitorPluginConfig {
    #[serde(rename = "type", default)]
    pub plugin_type: String,
    #[serde(default, alias = "serverName")]
    pub server_name: String,
    #[serde(default, alias = "sk")]
    pub secret_key: String,
    #[serde(default, alias = "bindAddr")]
    pub bind_addr: String,
    #[serde(default, alias = "bindPort")]
    pub bind_port: i32,
    /// Destination IP advertised as a host route by the virtual_net visitor plugin.
    /// Go frp v0.70.1 compat: destinationIP.
    #[serde(default, alias = "destinationIP")]
    pub destination_ip: String,
}

fn default_max_retries_an_hour() -> i32 {
    8
}
fn default_min_retry_interval() -> i64 {
    90
}
fn default_xtcp_protocol() -> String {
    // Go frp v0.70.1 XTCP visitors default to "quic".
    "quic".into()
}

/// Serde helper for `VisitorConfig.protocol`: Go frp normalizes an EXPLICIT
/// empty value to "quic" (`util.EmptyOr(Protocol, "quic")` in
/// pkg/config/v1/visitor.go:160, applied during config Complete()). The
/// `default = "default_xtcp_protocol"` serde attribute only covers a MISSING
/// field; this covers `protocol = ""` — which would otherwise dispatch to
/// the KCP data plane ("" is not "quic"), diverging from Go where "" is
/// impossible after Complete(). "kcp" and other values pass through
/// unchanged (validation later rejects anything outside kcp/quic).
fn deserialize_xtcp_protocol<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(if s.is_empty() { "quic".into() } else { s })
}
fn default_vnet_netmask() -> String {
    "255.255.255.0".to_string()
}
fn default_vnet_mtu() -> u16 {
    1420
}
