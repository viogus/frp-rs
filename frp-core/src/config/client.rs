use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use super::server::{
    default_authentication_timeout, default_heartbeat_timeout, default_token_auth_timeout,
    default_true, FeatureConfig, LogConfig, ObservabilityConfig, PluginConfig, QuicOptions,
    StoreConfig, ValueSource, WebServerConfig,
};

fn default_udp_packet_size_i64() -> i64 {
    1500
}

/// Maximum UDP payload size (IPv4: 65535 - 8 UDP - 20 IP = 65507). Clamps
/// `udp_packet_size` at config load — a hostile config value (e.g. 2^31)
/// would otherwise allocate a multi-GiB receive buffer per UDP proxy at
/// runtime (work_conn.rs `vec![0u8; udp_packet_size.max(1)]`).
const MAX_UDP_PACKET_SIZE: i64 = 65507;

fn clamp_udp_packet_size<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = i64::deserialize(d)?;
    // Go parity: `UDPPacketSize = util.EmptyOr(UDPPacketSize, 1500)`
    // (pkg/config/v1/client.go:98 Complete(); helper EmptyOr at
    // pkg/util/util/types.go) — an EXPLICIT 0 swaps for the 1500 default
    // at load. A Go-authored config with `udp_packet_size = 0` loads on Go
    // frps and runs at 1500, so it must load here too: the old load-time
    // rejection (audit round 3) failed valid Go configs.
    if v == 0 {
        return Ok(default_udp_packet_size_i64());
    }
    // Negative values keep the load-time rejection — DOCUMENTED Rust-only
    // divergence: Go's int64 is never validated and only breaks later at
    // runtime (the work-conn recv loop would truncate every inbound
    // datagram to 1 byte, `vec![0u8; udp_packet_size.max(1)]`). Fail-fast
    // at load (poolCount precedent) beats the divergent runtime behavior.
    if v < 0 {
        return Err(D::Error::custom(
            "udp_packet_size must not be negative (Go leaves negatives \
             unvalidated and breaks at runtime; frp-rs rejects at load)",
        ));
    }
    Ok(v.min(MAX_UDP_PACKET_SIZE))
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

impl AuthClientConfig {
    /// Go frp v0.71.0 `AuthClientConfig.Complete()`
    /// (`pkg/config/v1/client.go:206-209`): `c.Method = util.EmptyOr(c.Method,
    /// "token")`. The `Result` mirrors Go's `error`-typed signature; the fill
    /// cannot fail.
    ///
    /// See [`crate::config::AuthServerConfig::complete`] for why the empty
    /// value arrives from the serde lane (`#[serde(default)]` on `method` is
    /// `""`, not the `Default` impl's `"token"`).
    pub fn complete(&mut self) -> Result<(), String> {
        crate::auth::complete_auth_method(&mut self.method);
        Ok(())
    }
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
    /// Go frp v0.72.0 `metricsServer`: a separate health/metrics/profiling
    /// listener, disabled unless `port` is set.
    #[serde(default, alias = "metricsServer")]
    pub metrics_server: crate::config::MetricsServerConfig,
    #[serde(default = "default_true")]
    pub tls_enable: bool,
    #[serde(default)]
    pub tls_cert_file: String,
    #[serde(default)]
    pub tls_key_file: String,
    #[serde(default)]
    pub tls_ca_file: String,
    /// Verify the server certificate against the host's system trust store
    /// (Go frp v0.72.0 `transport.tls.useSystemCa`). With `tls_ca_file` also
    /// set, both trust sources are honoured. Requires `tls_enable` unless the
    /// transport protocol is `wss`.
    #[serde(default, alias = "useSystemCa")]
    pub tls_use_system_ca: bool,
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
    /// Tokio worker-thread count for the client runtime. Unset = the
    /// client binary's default (one thread, which measured 1.7x the
    /// throughput of four on a single fat tunnel); `Some(n)` overrides it.
    /// Restart-only: the runtime is built before the config is served.
    #[serde(
        default,
        alias = "workerThreads",
        deserialize_with = "crate::config::deserialize_worker_threads"
    )]
    pub worker_threads: Option<usize>,
    /// TCP mux keepalive interval in seconds. Controls how often yamux
    /// sends keepalive pings to detect dead peers. Default: 30.
    /// Go frp compat: transport.tcpMuxKeepaliveInterval.
    #[serde(default, alias = "tcpMuxKeepaliveInterval")]
    pub tcp_mux_keepalive_interval: i64,
    /// Idle-dead silence bound for the yamux dead-session reaper, in seconds.
    /// `0` = auto (3 × keepalive, floored 30s); `>0` = explicit bound
    /// (floored 30s); `<0` = disable the reaper. Default: 0. Not reloadable
    /// (restart-only, like the keepalive interval).
    #[serde(default, alias = "tcpMuxKeepaliveTimeout")]
    pub tcp_mux_keepalive_timeout: i64,
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
    /// proxy datagrams. Default: 1500 (Go frp compat). An EXPLICIT 0 also
    /// normalizes to 1500 at load — Go `util.EmptyOr` parity
    /// (pkg/config/v1/client.go:98): a Go-authored `udp_packet_size = 0`
    /// runs at 1500 on Go frps. Clamped to ≤ 65507 at load — the max UDP
    /// payload — so a hostile config value cannot force a multi-GiB
    /// per-proxy allocation at runtime (the use-sites in work_conn.rs size
    /// their buffers from this value). Negative values are rejected at load
    /// (documented Rust-only divergence; see `clamp_udp_packet_size`).
    /// Go frp compat: udpPacketSize / UDPPacketSize.
    #[serde(
        default = "default_udp_packet_size_i64",
        alias = "udpPacketSize",
        deserialize_with = "clamp_udp_packet_size"
    )]
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
            metrics_server: crate::config::MetricsServerConfig::default(),
            tls_enable: true,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_use_system_ca: false,
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
            worker_threads: None,
            tcp_mux_keepalive_interval: 30,
            tcp_mux_keepalive_timeout: 0,
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

const AUTO_COMPANION_ANNOTATION: &str = "frp-rs.auto-companion";
const AUTO_COMPANION_PARENT_ANNOTATION: &str = "frp-rs.auto-companion-parent";

/// Format a host and port, bracketing IPv6 literals. Empty hosts fall back to
/// loopback so a config with no `serverAddr` still produces a parseable
/// advertise address.
fn format_host_port(host: &str, port: u16) -> String {
    let host = host.trim();
    let host = if host.is_empty() { "127.0.0.1" } else { host };
    if host.starts_with('[') {
        format!("{host}:{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Split `host:port`, `[v6]:port`, a bare IP, or a bare `[v6]`. A missing or
/// zero port is returned as 0; callers replace it with the SOCKS5 remote port.
fn split_host_port(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(addr) = raw.parse::<std::net::SocketAddr>() {
        return Some((addr.ip().to_string(), addr.port()));
    }
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Some((ip.to_string(), 0));
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if after.is_empty() {
            return Some((format!("[{host}]"), 0));
        }
        let port = after.strip_prefix(':')?.parse().ok()?;
        return Some((format!("[{host}]"), port));
    }
    let (host, port) = raw.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Pick a loopback UDP port for the automatic companion's relay. The socket
/// is dropped immediately, so the plugin can bind it a moment later; a
/// same-process race is not a concern because both sides use this one port.
fn allocate_udp_relay_port(bind_host: &str) -> Result<u16, String> {
    let addr = format_host_port(bind_host, 0);
    let socket = std::net::UdpSocket::bind(&addr)
        .map_err(|e| format!("cannot allocate UDP relay port on {addr}: {e}"))?;
    socket
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("cannot read UDP relay port on {addr}: {e}"))
}

fn unique_companion_name(proxies: &[ProxyConfig], parent: &str) -> String {
    let base = format!("{parent}__udp");
    if !proxies.iter().any(|p| p.name == base) {
        return base;
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base}_{n}");
        if !proxies.iter().any(|p| p.name == candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Return the parent name when `p` is an auto-registered SOCKS5 UDP companion.
pub fn auto_companion_parent(p: &ProxyConfig) -> Option<&str> {
    if p.proxy_type != "udp" {
        return None;
    }
    if p.annotations
        .get(AUTO_COMPANION_ANNOTATION)
        .map(String::as_str)
        != Some("socks5-udp")
    {
        return None;
    }
    p.annotations
        .get(AUTO_COMPANION_PARENT_ANNOTATION)
        .map(String::as_str)
}

impl ClientConfig {
    /// Register the UDP proxy that carries the socks5 UDP relay through frps.
    ///
    /// A SOCKS5 `UDP ASSOCIATE` reply contains a `BND.ADDR:BND.PORT` the client
    /// sends raw datagrams to; those datagrams are not part of the frp TCP
    /// tunnel. When the socks5 proxy has an explicit `remote_port`, frpc can
    /// expose the loopback relay as an ordinary `type = "udp"` proxy on the same
    /// remote port. That is what removes the hand-written companion proxy from
    /// the user's config while remaining compatible with a Go frps (it is a
    /// normal UDP proxy on the wire).
    ///
    /// Idempotent: an existing auto companion is detected by its annotations,
    /// and a user-written UDP proxy targeting the same relay/remote port wins
    /// over auto-registration. Call after `enabled` filtering and before the
    /// `start` allowlist is applied.
    pub fn inject_socks5_udp_companions(&mut self) -> Result<(), String> {
        self.inject_socks5_udp_companions_preserving(&[])
    }

    /// Same as [`Self::inject_socks5_udp_companions`], but reuses the bind port
    /// of an auto companion from `previous`. A reload rebuilds the config from
    /// scratch, so without this an unchanged config would allocate a new
    /// ephemeral port and make the reload diff restart the SOCKS5 plugin (and
    /// drop its live sessions) on every `SIGUSR1`.
    pub fn inject_socks5_udp_companions_preserving(
        &mut self,
        previous: &[ProxyConfig],
    ) -> Result<(), String> {
        struct Addition {
            parent: String,
            bind_addr: Option<String>,
            advertise_addr: Option<String>,
            proxy: ProxyConfig,
        }

        let mut additions = Vec::new();
        for idx in 0..self.proxies.len() {
            let p = &self.proxies[idx];
            let Some(plugin) = p.plugin.as_ref() else {
                continue;
            };
            if plugin.plugin_type != "socks5"
                || !plugin.udp_enable
                || !plugin.udp_auto_companion_enabled()
            {
                continue;
            }
            // Do not create a companion for a parent the `start` allowlist
            // excludes: it would be filtered out anyway, and if a stale
            // `start = ["<name>__udp"]` kept the companion it would target a
            // relay whose plugin never started.
            if !self.start.is_empty() && !self.start.iter().any(|n| n == &p.name) {
                continue;
            }
            let bind_raw = plugin.udp_bind_addr.trim();
            let advertise_raw = plugin.udp_advertise_addr.trim();

            if p.proxy_type != "tcp" {
                tracing::warn!(
                    proxy = %p.name,
                    proxy_type = %p.proxy_type,
                    "socks5 UDP auto companion is only supported on type = \"tcp\"; skipping \
                     (set udp_auto_companion = false for a direct or manual deployment)"
                );
                continue;
            }
            // A direct deployment sets both addresses and advertises a port
            // other than remote_port: there is no companion listening there.
            // That is the pre-existing documented shape, so keep it working
            // instead of refusing startup now that the default is on.
            if !bind_raw.is_empty() && !advertise_raw.is_empty() {
                if let Some((_, advertise_port)) = split_host_port(advertise_raw) {
                    if advertise_port != 0 && advertise_port != p.remote_port {
                        tracing::warn!(
                            proxy = %p.name,
                            remote_port = p.remote_port,
                            advertise = %advertise_raw,
                            "socks5 UDP explicit bind/advertise addresses look like a direct \
                             deployment; skipping the automatic companion (set \
                             udp_auto_companion = false to silence)"
                        );
                        continue;
                    }
                }
            }
            if p.remote_port == 0 {
                tracing::warn!(
                    proxy = %p.name,
                    "socks5 UDP auto companion requires an explicit remote_port; skipping \
                     (set remote_port, or udp_auto_companion = false for direct mode)"
                );
                continue;
            }
            if !p.group.is_empty() {
                tracing::warn!(
                    proxy = %p.name,
                    group = %p.group,
                    "socks5 UDP automatic companion is not added to the group: UDP has a                      single owner per port, so only one group member can serve remote_port;                      the TCP group is unaffected"
                );
            }

            let already = self.proxies.iter().any(|q| {
                q.annotations
                    .get(AUTO_COMPANION_ANNOTATION)
                    .map(String::as_str)
                    == Some("socks5-udp")
                    && q.annotations
                        .get(AUTO_COMPANION_PARENT_ANNOTATION)
                        .map(String::as_str)
                        == Some(p.name.as_str())
            });
            if already {
                continue;
            }

            // A user-written UDP proxy already serving this remote port is the
            // manual setup. Warn when its target cannot match the relay bind:
            // that combination reports UDP ASSOCIATE success but drops every
            // datagram.
            if let Some(manual) = self
                .proxies
                .iter()
                .find(|q| q.proxy_type == "udp" && q.remote_port == p.remote_port)
            {
                let bind_port = split_host_port(bind_raw).map(|(_, port)| port);
                if bind_raw.is_empty() {
                    tracing::warn!(
                        proxy = %p.name,
                        manual_proxy = %manual.name,
                        remote_port = p.remote_port,
                        manual_local_port = manual.local_port,
                        "socks5 UDP has a user-written UDP proxy on the same remote_port but \
                         udp_bind_addr is empty; the relay will bind an ephemeral loopback \
                         port, so that proxy will drop datagrams. Set udp_bind_addr = \
                         \"127.0.0.1:<manual local_port>\" or udp_auto_companion = false"
                    );
                } else if bind_port != Some(manual.local_port) {
                    tracing::warn!(
                        proxy = %p.name,
                        manual_proxy = %manual.name,
                        remote_port = p.remote_port,
                        manual_local_port = manual.local_port,
                        bind = %bind_raw,
                        "socks5 UDP user-written UDP proxy target does not match udp_bind_addr; \
                         the relay will not receive its datagrams (set udp_auto_companion = false \
                         for a manual deployment)"
                    );
                }
                continue;
            }

            let previous_bind = if bind_raw.is_empty()
                && previous
                    .iter()
                    .any(|q| auto_companion_parent(q) == Some(p.name.as_str()))
            {
                previous
                    .iter()
                    .find(|q| q.name == p.name)
                    .and_then(|q| q.plugin.as_ref())
                    .map(|pl| pl.udp_bind_addr.trim())
                    .filter(|s| !s.is_empty())
                    .and_then(split_host_port)
                    .filter(|(_, port)| *port != 0)
            } else {
                None
            };
            let (bind_host, bind_port) = if let Some((host, port)) = previous_bind {
                (host, port)
            } else if bind_raw.is_empty() {
                // A fixed `remote_port` would collide with frps' own UDP
                // listener when frpc and frps share a host (and with any
                // other local service). Let the OS pick a loopback port;
                // the companion targets exactly that port.
                let port = allocate_udp_relay_port("127.0.0.1")
                    .map_err(|e| format!("socks5 proxy '{}': {e}", p.name))?;
                ("127.0.0.1".to_string(), port)
            } else {
                let (host, port) = split_host_port(bind_raw).ok_or_else(|| {
                    format!(
                        "socks5 proxy '{}': invalid udp_bind_addr '{}' for UDP auto companion \
                         (set udp_auto_companion = false for a direct deployment)",
                        p.name, bind_raw
                    )
                })?;
                let port = if port == 0 {
                    allocate_udp_relay_port(&host)
                        .map_err(|e| format!("socks5 proxy '{}': {e}", p.name))?
                } else {
                    port
                };
                (host, port)
            };
            let target_host = match bind_host.as_str() {
                "0.0.0.0" => "127.0.0.1".to_string(),
                "::" | "[::]" => "::1".to_string(),
                other => other.to_string(),
            };
            let is_loopback = bind_host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or_else(|_| bind_host.eq_ignore_ascii_case("localhost"));
            if !is_loopback {
                tracing::warn!(
                    proxy = %p.name,
                    bind = %format_host_port(&bind_host, bind_port),
                    "socks5 UDP relay binds a non-loopback address while the automatic \
                     companion targets loopback; the relay is reachable directly from the \
                     network (set udp_auto_companion = false if that is not intended)"
                );
            }

            let name = unique_companion_name(&self.proxies, &p.name);
            let bind_addr = if bind_raw.is_empty()
                || split_host_port(bind_raw).map(|(_, port)| port) == Some(0)
            {
                Some(format_host_port(&bind_host, bind_port))
            } else {
                None
            };
            let advertise_addr = if plugin.udp_advertise_addr.trim().is_empty() {
                Some(format_host_port(&self.server_addr, p.remote_port))
            } else {
                // With an automatic companion the datagrams must arrive on
                // `remote_port`; a bare IP would otherwise inherit the
                // relay's ephemeral bind port and black-hole.
                match split_host_port(plugin.udp_advertise_addr.trim()) {
                    Some((host, 0)) => Some(format_host_port(&host, p.remote_port)),
                    Some((_, port)) if port != p.remote_port => {
                        tracing::warn!(
                            proxy = %p.name,
                            remote_port = p.remote_port,
                            advertise = %plugin.udp_advertise_addr,
                            "socks5 UDP automatic companion needs udp_advertise_addr to use \
                             remote_port (or no port); skipping the companion (set \
                             udp_bind_addr to a fixed relay port for a direct deployment, or \
                             udp_auto_companion = false)"
                        );
                        continue;
                    }
                    Some(_) => None,
                    None => {
                        return Err(format!(
                            "socks5 proxy '{}': invalid udp_advertise_addr '{}' for UDP auto companion (set udp_auto_companion = false for a direct deployment)",
                            p.name, plugin.udp_advertise_addr
                        ));
                    }
                }
            };
            let mut proxy = ProxyConfig {
                name,
                proxy_type: "udp".to_string(),
                local_ip: target_host,
                local_port: bind_port,
                remote_port: p.remote_port,
                use_encryption: p.use_encryption,
                use_compression: p.use_compression,
                bandwidth_limit: p.bandwidth_limit.clone(),
                bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
                enabled: true,
                ..Default::default()
            };
            proxy.annotations.insert(
                AUTO_COMPANION_ANNOTATION.to_string(),
                "socks5-udp".to_string(),
            );
            proxy
                .annotations
                .insert(AUTO_COMPANION_PARENT_ANNOTATION.to_string(), p.name.clone());
            additions.push(Addition {
                parent: p.name.clone(),
                bind_addr,
                advertise_addr,
                proxy,
            });
        }

        for addition in additions {
            if let Some(parent) = self.proxies.iter_mut().find(|p| p.name == addition.parent) {
                if let Some(plugin) = parent.plugin.as_mut() {
                    if let Some(bind_addr) = addition.bind_addr {
                        plugin.udp_bind_addr = bind_addr;
                    }
                    if let Some(advertise_addr) = addition.advertise_addr {
                        plugin.udp_advertise_addr = advertise_addr;
                    }
                }
            }
            if !self.start.is_empty()
                && self.start.iter().any(|n| n == &addition.parent)
                && !self.start.iter().any(|n| n == &addition.proxy.name)
            {
                self.start.push(addition.proxy.name.clone());
            }
            self.proxies.push(addition.proxy);
        }
        Ok(())
    }

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
        // Go frp: `ClientCommonConfig.Complete()` runs `c.Auth.Complete()`
        // (`pkg/config/v1/client.go:91`, implemented at `:206-209` as
        // `util.EmptyOr(c.Method, "token")`) before `c.Log.Complete()` at `:94`.
        // This is that call. The load path already ran it inside
        // `validate_client_config` (Go's Complete→Validate order), so it is
        // usually a no-op here; it covers a `ClientConfig` built directly and
        // keeps the two entry points from diverging. `[auth]` is optional on the
        // client, so an absent section is left absent (Go's `AuthClientConfig`
        // is a value there, but its `Complete` is the same no-op on a filled
        // `"token"`).
        if let Some(auth) = self.auth.as_mut() {
            let _ = auth.complete();
        }
        // Go frp v0.71.0 `ClientCommonConfig.Complete()` calls
        // `c.WebServer.Complete()` (`pkg/config/v1/client.go:96`), which is
        // `c.Addr = util.EmptyOr(c.Addr, "127.0.0.1")`
        // (`pkg/config/v1/common.go:71-72`). `EmptyOr` fills on the **empty
        // string**, so an explicit `addr = ""` becomes `127.0.0.1` there, and
        // the client has no later step that re-defaults the address.
        //
        // The server has the same Go shape and now mirrors it too:
        // `ServerConfig::complete` (`frp-core/src/config/server.rs`) fills the
        // empty string with `127.0.0.1` first and has **no** `Port > 0 ->
        // "0.0.0.0"` step, because Go's branch for that
        // (`pkg/config/v1/server.go:116-117`) is unreachable once
        // `WebServer.Complete()` has run at `:107`. So an explicit empty server
        // `webServer.addr` binds `127.0.0.1:<port>` on both implementations;
        // it bound `*:<port>` here before, and that server-side divergence is
        // now closed — the bound address is pinned by
        // `dashboard_explicit_empty_addr_binds_loopback_only` and
        // `dashboard_absent_addr_binds_loopback_only` in
        // `frp-server/tests/dashboard_integration.rs`.
        //
        // The serde default on the field (`default_web_server_addr`) only fires
        // when the key is ABSENT, so without this an explicit `addr = ""`
        // survived as the empty string and every admin dial became a lookup of
        // the empty host: measured at `main` @ `c4836b7`,
        // `frpc status -c emptyaddr.toml` (with `[webServer] addr = ""`, `port
        // = 7499`) printed
        // `status query failed: connect :7499: failed to lookup address
        // information: nodename nor servname provided, or not known` (rc 1),
        // where Go v0.71.0 dials `127.0.0.1:7499`. Fixing it here, not in the
        // admin-connection resolver, is what makes the value right wherever the
        // client web server address is consumed — the admin subcommands and the
        // client's own `[webServer]` admin listener alike.
        if self.web_server.addr.is_empty() {
            self.web_server.addr = "127.0.0.1".into();
        }

        // The client is the **sibling slot** of the server's log completion:
        // Go's `ClientCommonConfig.Complete()` calls `c.Log.Complete()` at
        // `pkg/config/v1/client.go:94` — the same call, after `c.Auth.Complete()`
        // at `:91` and **before** `c.Transport.Complete()` (`:95`) and
        // `c.WebServer.Complete()` (`:96`) — and that path runs for EVERY frpc
        // load, `-c` included: `config.LoadClientConfigResult` →
        // `result.Common.Complete()` (`pkg/config/load.go:392`), which is *not*
        // the flags-only exception the server's `-c` path is
        // (`pkg/config/load.go:313-321` completes a fresh struct loaded from the
        // file). frp-rs had no log fill on either config, so the same
        // explicit-empty input (`log.level = ""` / `log.max_days = 0` in the
        // file — the client does not overlay its CLI flags onto the config, so
        // the file is the reachable shape there) silenced frpc's own logging.
        // Fixed here rather than filed: the fix is the one Go call, and
        // `LogConfig::complete` (`frp-core/src/config/server.rs`) is shared, so
        // the sibling cannot drift from the server.
        //
        // **This is the same call Go makes, not the same statement order within
        // the function.** The `web_server.addr` fill above runs before this line,
        // where Go runs `WebServer.Complete()` at `:96` *after* `Log.Complete()`
        // at `:94`. The two completions are independent (neither reads the
        // other's field), so the difference is not observable in a value; the
        // relative order of the *calls* is what is mirrored.
        self.log.complete();

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

        // Go frp: `ServerPort = util.EmptyOr(ServerPort, 7000)`
        // (v1/client.go:87) — an EXPLICIT 0 maps to the default too; serde's
        // default fn only fires when the key is absent. Without this,
        // `server_port = 0` dialed port 0 on the server (connect refused
        // instead of connecting to the default listener).
        if self.server_port == 0 {
            self.server_port = 7000;
        }

        // Go v0.71.0: with tcpMux enabled, application-layer heartbeats are
        // disabled by default (-1) and yamux keepalive covers liveness.
        // util.EmptyOr(v, -1): a zero value — explicit or default — means
        // "use the default" = -1; only positive explicit values survive
        // (round-8 fix 5: the old code preserved an explicit 0, diverging
        // from Go's value-level semantics; runtime-equivalent, but Go frpc
        // shows -1 in status output).
        if self.tcp_mux {
            if !heartbeat_interval_set || self.heartbeat_interval == 0 {
                self.heartbeat_interval = -1;
            }
            if !heartbeat_timeout_set || self.heartbeat_timeout == 0 {
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

        // Go v0.71.0: TcpMuxKeepaliveInterval = EmptyOr(0, 30) — an explicit
        // 0 OR an omitted value (`#[serde(default)]` deserializes to 0, and
        // this struct is the top-level ClientConfig) means "use the default"
        // (30), not "every frame / 1s scan". Without this, an omitted
        // tcpMuxKeepaliveInterval stayed 0 and the runtime `.max(1)` clamped
        // yamux to a 1s scan / 30s dead-detection cadence — diverging from
        // Go's 30s keepalive / 90s dead peer (MED compat deviation).
        if self.tcp_mux_keepalive_interval == 0 {
            self.tcp_mux_keepalive_interval = 30;
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

        // No clamp here — Go frp has none (Go frpc uses 7200; round-8
        // blocker: the old 3600 cap disconnected a Go frpc ↔ Rust frps
        // pair in a reconnect loop). Any positive i64 is honored; the
        // client watchdog arithmetic is overflow-safe by construction:
        // `Duration::from_secs(u64)` never panics, the watchdog sleeps
        // `hb_timeout_dur.saturating_sub(last_pong.elapsed())`
        // (frp-client/src/service.rs), and tokio's sleep/interval saturate
        // to tokio's far-future deadline via `Instant::checked_add` rather
        // than panicking. Values <= 0 (explicit disable) keep their
        // semantics.
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
    // Go frp v1 proxy config carries `groupKey` as a TOP-LEVEL proxy field
    // (ProxyBaseConf.GroupKey) — without this alias the key is silently
    // dropped by the lenient unknown-key tolerance.
    #[serde(default, alias = "groupKey")]
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

#[cfg(test)]
mod tests {
    use super::clamp_udp_packet_size;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Wrapper {
        #[serde(deserialize_with = "clamp_udp_packet_size")]
        v: i64,
    }

    fn parse(s: &str) -> i64 {
        serde_json::from_str::<Wrapper>(s).unwrap().v
    }

    #[test]
    fn udp_packet_size_clamped_at_load() {
        // Above the IPv4 UDP max → clamped down (a hostile 2^31 would
        // allocate a multi-GiB receive buffer per UDP proxy).
        assert_eq!(parse(r#"{"v": 2147483647}"#), 65507);
        assert_eq!(parse(r#"{"v": 999999999}"#), 65507);
        assert_eq!(parse(r#"{"v": 65508}"#), 65507);
        assert_eq!(parse(r#"{"v": 65507}"#), 65507);
        // In-range values pass through untouched.
        assert_eq!(parse(r#"{"v": 2048}"#), 2048);
        assert_eq!(parse(r#"{"v": 1500}"#), 1500);
        // Explicit 0 → Go `util.EmptyOr` swap to the 1500 default
        // (pkg/config/v1/client.go:98): a Go-authored `udp_packet_size = 0`
        // loads on Go frps and runs at 1500 — rejecting it failed valid Go
        // configs at load.
        assert_eq!(
            parse(r#"{"v": 0}"#),
            1500,
            "explicit 0 must normalize to the 1500 default"
        );
        // Negative → rejected at load (documented Rust-only divergence: Go
        // never validates negatives and only breaks later at runtime).
        let err = serde_json::from_str::<Wrapper>(r#"{"v": -5}"#).unwrap_err();
        assert!(
            err.to_string()
                .contains("udp_packet_size must not be negative"),
            "unexpected error: {err}"
        );
        // Non-integer still fails deserialization.
        assert!(serde_json::from_str::<Wrapper>(r#"{"v": "big"}"#).is_err());
    }

    #[test]
    fn udp_packet_size_absent_defaults_to_1500() {
        // Absent key → the serde default fn (1500) — Go's zero value after
        // `util.EmptyOr(0, 1500)`.
        let cfg: super::ClientConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(cfg.udp_packet_size, 1500);
    }
}
