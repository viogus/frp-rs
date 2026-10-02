// ─── Strict config mode ──────────────────────────────────────────────

fn known_set_from(keys: &[&'static str]) -> std::collections::HashSet<&'static str> {
    let mut set = std::collections::HashSet::new();
    set.extend(keys);
    set
}

/// The strict-mode acceptance set for a **server** config.
///
/// One divergence here is deliberate and recorded rather than fixed:
/// `"kcp_bind_port"` / `"quic_bind_port"` / `"websocket_port"` and their camel
/// spellings stay in this set in **every** build shape, while
/// `frp-core/src/config/server.rs` gates the matching serde field on the
/// `kcp`/`quic`/`websocket` feature. `--strict-config` therefore accepts a key a
/// `micro`/`tiny` build cannot honour, and that build then ignores it (the run
/// path warns about it; the key stays accepted). Rejecting it would be the
/// "false 400" direction `docs/deployment.md` rules out, and the repo's own
/// `frps.toml` writes `kcp_bind_port = 17000` + `quic_bind_port = 17001`, so
/// rejection would stop every such build from loading the documented example.
///
/// Both shapes are measured by the test
/// `crate::config::tests::feature_gated_port_keys_are_accepted_while_the_compiled_field_set_follows_the_build`:
/// strict mode accepts the snake and the camel spelling, and
/// `serde_json::to_value(&cfg)` carries the field exactly when the feature is
/// compiled in (a `--no-default-features` load omits the field instead and
/// records the accepted-but-unhonoured key). The same divergence is recorded in
/// `docs/config.md`'s `websocket_port` row. `known_client_keys()` has no
/// counterpart to record: `frp-core/src/config/client.rs` carries no
/// `#[cfg(feature = ...)]` at all.
pub(super) fn known_server_keys() -> std::collections::HashSet<&'static str> {
    known_set_from(&[
        "bind_addr",
        "bind_port",
        "proxy_bind_addr",
        "vhost_http_port",
        "vhost_https_port",
        "kcp_bind_port",
        "quic_bind_port",
        "sudp_port",
        "tcpmux_httpconnect_port",
        "sub_domain_host",
        "websocket_port",
        "tls_enable",
        "tls_cert_file",
        "tls_key_file",
        "tls_ca_file",
        "tls_server_name",
        "tls_skip_verify",
        "tlsSkipVerify",
        "tlsServerName",
        "tls_only",
        "auth",
        "log",
        "web_server",
        "transport",
        "allow_port_start",
        "allow_port_end",
        "allow_ports",
        "max_ports_per_client",
        "max_proxies_per_client",
        "max_custom_domains_per_proxy",
        "vhost_http_timeout",
        "user_conn_timeout",
        "detailed_errors_to_client",
        "tcp_mux_passthrough",
        "udp_packet_size",
        "http_plugins",
        "feature",
        "includes",
        "ssh_tunnel_gateway",
        "nat_hole_analysis_data_reserve_hours",
        "observability",
        // Go compat normalization aliases
        "common",
        "auth_method",
        "authentication_method",
        "auth_token",
        "token",
        "oidc_issuer",
        "oidc_audience",
        "oidc_token_endpoint",
        "oidc_token_endpoint_url",
        "log_file",
        "log_level",
        "log_max_days",
        "log_format",
        // Go legacy INI `log_way` (pkg/config/legacy client.go/server.go
        // LogWay `ini:"log_way"`): accepted by Go and silently dropped —
        // legacy conversion never maps it into the new config (conversion.go
        // copies only LogFile/LogLevel/LogMaxDays). Accept-and-ignore here.
        "log_way",
        "web_server_addr",
        "web_server_port",
        "web_server_user",
        "web_server_password",
        "web_server_enable_prometheus",
        "web_server_tls_cert_file",
        "web_server_tls_key_file",
        "enable_prometheus",
        "tcp_mux",
        "tcp_mux_keepalive_interval",
        "tcpMux",
        "tcpMuxKeepaliveInterval",
        "tcp_mux_keepalive_timeout",
        "tcpMuxKeepaliveTimeout",
        "heartbeatTimeout",
        "maxPoolCount",
        "tcpKeepalive",
        "tcpSendBuffer",
        "tcpRecvBuffer",
        "tcp_send_buffer_size",
        "tcp_recv_buffer_size",
        "max_connections",
        "max_accept_rate",
        "graceful_shutdown_timeout",
        "sshTunnelGateway",
        "bindPort",
        "bindAddr",
        "vhostHTTPPort",
        "vhostHTTPSPort",
        "kcpBindPort",
        "quicBindPort",
        "sudpPort",
        "tcpmuxHTTPConnectPort",
        "proxyBindAddr",
        "websocketPort",
        "maxPortsPerClient",
        "maxProxiesPerClient",
        "maxCustomDomainsPerProxy",
        "userConnTimeout",
        "natholeAnalysisDataReserveHours",
        // Go frp v0.70.1 camelCase aliases accepted by serde that are not
        // renamed away by normalize_server_config (audit task 9 finding 1).
        "detailedErrorsToClient",
        "subDomainHost",
        "udpPacketSize",
        "tcpmuxPassthrough",
        "vhostHTTPTimeout",
        "maxConnections",
        "maxAcceptRate",
        // frp-rs extension fields (strict mode must accept valid frp-rs configs).
        "max_conns_per_proxy",
        "maxConnsPerProxy",
        // frp-rs legacy keys used by the repo's own frps.toml example
        // (subdomain_host maps to sub_domain_host, tls_trusted_ca_file to
        // tls_ca_file — strict mode must not reject the documented config).
        "subdomain_host",
        "tls_trusted_ca_file",
    ])
}

pub(super) fn known_client_keys() -> std::collections::HashSet<&'static str> {
    known_set_from(&[
        "server_addr",
        "server_port",
        "transport_protocol",
        "token",
        "auth",
        "user",
        "client_id",
        "metas",
        "metadatas",
        "proxy_url",
        "proxyURL",
        "nat_hole_stun_server",
        "natHoleStunServer",
        "start",
        "includes",
        "include",
        "store",
        "tls_enable",
        "tls_cert_file",
        "tls_key_file",
        "tls_ca_file",
        "tls_server_name",
        "tls_skip_verify",
        "tlsSkipVerify",
        "tcp_mux_keepalive_interval",
        "tcp_mux_keepalive_timeout",
        "tcpMuxKeepaliveTimeout",
        "tcpSendBuffer",
        "tcpRecvBuffer",
        "disable_custom_tls_first_byte",
        "disableCustomTLSFirstByte",
        "log",
        "login_fail_exit",
        "pool_count",
        "heartbeat_interval",
        "heartbeatInterval",
        "dns_server",
        "dial_server_keepalive",
        "dialServerKeepalive",
        "connect_server_local_ip",
        "connectServerLocalIP",
        "tcp_mux",
        "tcp_mux_keepalive_interval",
        "tcpMuxKeepaliveInterval",
        "tcp_mux_keepalive_timeout",
        "tcpMuxKeepaliveTimeout",
        "tcp_send_buffer_size",
        "tcp_recv_buffer_size",
        "v2",
        "proxies",
        "visitors",
        "web_server",
        "virtual_net",
        "virtualNet",
        "feature",
        "common",
        "protocol",
        "tls_trusted_ca_file",
        "serverAddr",
        "serverPort",
        "transport",
        "log_file",
        "log_level",
        "log_max_days",
        "log_format",
        // Go legacy INI `log_way`: accepted and silently dropped by Go (see
        // the server-side comment) — accept-and-ignore here too.
        "log_way",
        "observability",
        // Go frp v0.70.1 compat — new fields
        "quic",
        "dial_server_timeout",
        "dialServerTimeout",
        "clientID",
        "tlsServerName",
        // Client-side auth flat field normalization aliases
        "auth_method",
        "authentication_method",
        "auth_token",
        "oidc_client_id",
        "oidc_client_secret",
        "oidc_audience",
        "oidc_token_endpoint",
        "oidc_token_endpoint_url",
        "oidc_scope",
        "oidc_issuer",
        "oidc_proxy_url",
        "additional_endpoint_params",
        "oidc_token_source",
        // Go frp v0.70.1 compat (audit task 9 finding 1): keys produced by
        // normalize_client_config (transport.heartbeatTimeout is flattened
        // to top level) plus Go camelCase aliases that serde accepts but
        // normalization does not rename away.
        "heartbeat_timeout",
        "heartbeatTimeout",
        "udp_packet_size",
        "udpPacketSize",
        "loginFailExit",
        "poolCount",
        "tcpMux",
        "webServer",
        "featureGates",
        "dnsServer",
    ])
}

/// Serde-accepted key sets for the **array elements** `check_strict` recurses
/// into, one list per struct (not per proxy/visitor/plugin type: each of these
/// is a single union struct whose serde fields and aliases cover every type).
///
/// `strict_array_element_keys_match_struct_fields` (in `tests.rs`) extracts the
/// field and `alias` names from the struct definitions and fails when a list
/// here drifts from them, in either direction.
///
/// `ProxyConfig` (`frp-core/src/config/client.rs`).
pub(super) const PROXY_KNOWN_KEYS: &[&str] = &[
    "advertiseSubnet",
    "advertise_subnet",
    "allowUsers",
    "allow_users",
    "annotations",
    "bandwidthLimit",
    "bandwidthLimitMode",
    "bandwidth_limit",
    "bandwidth_limit_mode",
    "customDomains",
    "custom_domains",
    "disableAssistedAddrs",
    "disable_assisted_addrs",
    "enabled",
    "group",
    "groupKey",
    "group_key",
    "headers",
    "healthCheckHttpHeaders",
    "health_check_http_headers",
    "health_check_interval_seconds",
    "health_check_max_failed",
    "health_check_timeout_seconds",
    "health_check_type",
    "health_check_url",
    "hostHeaderRewrite",
    "host_header_rewrite",
    "httpPassword",
    "httpPwd",
    "httpUser",
    "http_password",
    "http_pwd",
    "http_user",
    "localIP",
    "localIp",
    "localPort",
    "local_ip",
    "local_port",
    "locations",
    "metadatas",
    "metas",
    "multiplexer",
    "name",
    "plugin",
    "proxyProtocolVersion",
    "proxy_protocol_version",
    "remotePort",
    "remote_port",
    "responseHeaders",
    "response_headers",
    "routeByHTTPUser",
    "route_by_http_user",
    "secretKey",
    "sk",
    "subdomain",
    "type",
    "useCompression",
    "useEncryption",
    "use_compression",
    "use_encryption",
    "virtual_net",
    "vnetIp",
    "vnetMtu",
    "vnetNetmask",
    "vnet_ip",
    "vnet_mtu",
    "vnet_netmask",
];

/// `VisitorConfig` (`frp-core/src/config/client.rs`).
pub(super) const VISITOR_KNOWN_KEYS: &[&str] = &[
    "bindAddr",
    "bindPort",
    "bind_addr",
    "bind_port",
    "disableAssistedAddrs",
    "disable_assisted_addrs",
    "enabled",
    "fallbackTimeoutMs",
    "fallbackTo",
    "fallback_timeout_ms",
    "fallback_to",
    "keepTunnelOpen",
    "keep_tunnel_open",
    "maxRetriesAnHour",
    "max_retries_an_hour",
    "minRetryInterval",
    "min_retry_interval",
    "name",
    "plugin",
    "protocol",
    "secretKey",
    "secret_key",
    "serverName",
    "serverUser",
    "server_name",
    "server_user",
    "sk",
    "type",
    "useCompression",
    "useEncryption",
    "use_compression",
    "use_encryption",
];

/// `PluginConfig` (`frp-core/src/config/server.rs`) — the client plugin table
/// (`[proxies.plugin]`).
pub(super) const CLIENT_PLUGIN_KNOWN_KEYS: &[&str] = &[
    "bindAddr",
    "bindPort",
    "bind_addr",
    "bind_port",
    "crtPath",
    "crt_file",
    "enableHTTP2",
    "enable_http2",
    "hostHeaderRewrite",
    "host_header_rewrite",
    "httpPassword",
    "httpUser",
    "http_password",
    "http_user",
    "keyPath",
    "key_file",
    "localAddr",
    "localPath",
    "local_addr",
    "local_path",
    "passwd",
    "password",
    "pluginCrtPath",
    "pluginKeyPath",
    "plugin_crt_path",
    "plugin_key_path",
    "proxyProtocolVersion",
    "proxy_protocol_version",
    "request_headers",
    "secret_key",
    "serverName",
    "server_name",
    "sk",
    "stripPrefix",
    "strip_prefix",
    "type",
    "unixPath",
    "user",
    "username",
];

/// `VisitorPluginConfig` (`frp-core/src/config/client.rs`) — the visitor plugin
/// table (`[visitors.plugin]`).
pub(super) const VISITOR_PLUGIN_KNOWN_KEYS: &[&str] = &[
    "bindAddr",
    "bindPort",
    "bind_addr",
    "bind_port",
    "destinationIP",
    "destination_ip",
    "secret_key",
    "serverName",
    "server_name",
    "sk",
    "type",
];

/// `HttpPluginConfig` (`frp-core/src/config/server.rs`) — `[[httpPlugins]]`
/// elements (normalized to the `http_plugins` array before the check).
pub(super) const HTTP_PLUGIN_KNOWN_KEYS: &[&str] = &[
    "addr",
    "enable_control",
    "name",
    "ops",
    "path",
    "timeout",
    "tlsVerify",
    "tls_verify",
    "url",
];

/// `HealthCheckHttpHeader` (`frp-core/src/config/client.rs`) — elements of a
/// proxy's `health_check_http_headers` array.
pub(super) const HEALTH_CHECK_HEADER_KNOWN_KEYS: &[&str] = &["name", "value"];

pub(super) fn run_strict_check(
    value: &toml::Value,
    known: &std::collections::HashSet<&str>,
    config_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_strict_check_scoped(value, known, config_path, true)
}

/// The same check, **top level only**: unknown keys of the root table are still
/// refused, unknown keys *inside* a section are not.
///
/// This is the check the legacy `.ini` dialect loads under. Go never applies
/// `strict_config` to that dialect at all: `LoadClientConfigResult`
/// (`pkg/config/load.go`) branches on `DetectLegacyINIFormat` first and hands a
/// legacy file to `legacy.ParseClientConfig` / `legacy.UnmarshalServerConfFromIni`,
/// which read sections by hand (`gopkg.in/ini`) and silently ignore a key their
/// typed struct does not name. So an `.ini` section key can never refuse a file
/// Go loads, and the check that remains is only the one v1-spelled keys still
/// need: a DefaultSection key (`webServer.tls = 1`) deserializes as a real v1
/// field, and Go's legacy reader is the *legacy* branch — it does not reach
/// `RejectUnknownMembers`, but frp-rs's `.ini` reader shares the v1 structs, so a
/// top-level typo there is still a load failure either way. Keeping the top-level
/// half is what preserves the v1 boundary; exempting the section half is what
/// matches Go.
pub(super) fn run_strict_check_top_level(
    value: &toml::Value,
    known: &std::collections::HashSet<&str>,
    config_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_strict_check_scoped(value, known, config_path, false)
}

fn run_strict_check_scoped(
    value: &toml::Value,
    known: &std::collections::HashSet<&str>,
    config_path: &str,
    recurse: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let toml::Value::Table(ref table) = value {
        let errors = if recurse {
            check_strict(table, known, "", config_path)
        } else {
            check_strict_in(table, known, "", config_path, Ctx::Root, false)
        };
        if !errors.is_empty() {
            return Err(errors.join("\n").into());
        }
    }
    Ok(())
}

/// Compute Levenshtein distance between two strings.
/// Used to suggest corrections for unknown config fields.
pub(super) fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = a_chars.len();
    let m = b_chars.len();
    let mut prev = (0..=m).collect::<Vec<_>>();
    let mut curr = vec![0; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

/// Known keys for nested sections, used by `check_strict` recursion.
/// Each entry lists the snake_case fields the frp-rs structs deserialize plus
/// the Go frp v0.71.0 camelCase aliases serde accepts (normalization does not
/// rename keys inside these sections).
fn section_known_keys(section: &str) -> Option<&'static [&'static str]> {
    let keys: &'static [&'static str] = match section {
        // Union of client and server auth flat fields (normalization flattens
        // `[auth.oidc]` into `auth.oidc_*` before strict mode runs).
        "auth" => &[
            "method",
            "token",
            "tokenSource",
            "token_source",
            "authentication_method",
            "auth_method",
            "authMethod",
            "authentication_timeout",
            "authenticationTimeout",
            "token_auth_timeout",
            "tokenAuthTimeout",
            "additional_auth_scopes",
            "additionalScopes",
            "additionalAuthScopes",
            "use_encryption",
            // Server-side OIDC flat fields
            "oidc_issuer",
            "oidc_audience",
            "oidc_token_endpoint",
            "oidc_token_endpoint_url",
            "oidc_skip_expiry",
            "oidcSkipExpiry",
            "oidc_skip_expiry_check",
            "oidcSkipExpiryCheck",
            "oidc_skip_issuer",
            "oidcSkipIssuer",
            "oidc_skip_issuer_check",
            "oidcSkipIssuerCheck",
            "oidc_skip_nbf",
            "oidcSkipNbf",
            "oidc_skip_audience",
            "oidcSkipAudience",
            "oidc_additional_audience",
            "oidcAdditionalAudience",
            "oidc_tls_trusted_ca_file",
            "oidcTLSTrustedCAFile",
            "oidc_proxy_url",
            "oidcProxyURL",
            // Client-side OIDC flat fields
            "oidc_client_id",
            "oidcClientId",
            "oidc_client_secret",
            "oidcClientSecret",
            "oidc_scope",
            "oidcScope",
            "additional_endpoint_params",
            "additionalEndpointParams",
            "oidc_token_source",
            "oidc_tls_insecure_skip_verify",
        ],
        "log" => &[
            "level",
            "file",
            "to",
            "max_days",
            "maxDays",
            "format",
            "disable_print_color",
            "disablePrintColor",
        ],
        "web_server" => &[
            "addr",
            "port",
            "user",
            "password",
            "enable_prometheus",
            "enablePrometheus",
            "assets_dir",
            "assetsDir",
            "pprof_enable",
            "pprofEnable",
            "tls_cert_file",
            "tls_key_file",
            "certFile",
            "keyFile",
            "tls_ca_file",
            "tls_server_name",
            "trustedCaFile",
            "serverName",
            "custom_404_page",
            "custom404Page",
            // The nested table survives normalization only when it holds a key
            // `normalize_web_server_section` does not map (see its doc); the
            // walker descends into it so the diagnostic names the true path.
            "tls",
        ],
        "transport" => &[
            "tcp_mux",
            "tcpMux",
            "tcp_mux_keepalive_interval",
            "tcpMuxKeepaliveInterval",
            "tcp_mux_keepalive_timeout",
            "tcpMuxKeepaliveTimeout",
            "heartbeat_timeout",
            "heartbeatTimeout",
            "max_pool_count",
            "maxPoolCount",
            "tcp_keepalive",
            "tcpKeepalive",
            "tcp_send_buffer_size",
            "tcp_recv_buffer_size",
            "tcpSendBuffer",
            "tcpRecvBuffer",
            "quic",
            // Go frp wireProtocol v2 is expressed as `v2 = true`; the compat
            // suite appends it inside [transport] (audit task 9 fix round 1).
            "v2",
        ],
        "quic" => &[
            "keepalive_period",
            "keepalivePeriod",
            "max_idle_timeout",
            "maxIdleTimeout",
            "max_incoming_streams",
            "maxIncomingStreams",
            // frp-rs extension (no Go equivalent): per-stream receive window.
            "stream_receive_window",
            "streamReceiveWindow",
        ],
        "ssh_tunnel_gateway" => &[
            "bind_port",
            "bindPort",
            "bind_addr",
            "bindAddr",
            "private_key_file",
            "privateKeyFile",
            "auto_gen_private_key_path",
            "autoGenPrivateKeyPath",
            "authorized_keys_file",
            "authorizedKeysFile",
            "ssh_session_idle_timeout",
            "sshSessionIdleTimeout",
            "allow_none_auth",
            "allowNoneAuth",
        ],
        "observability" => &["otlp_endpoint", "service_name"],
        "virtual_net" => &["address"],
        "store" => &["path"],
        _ => return None,
    };
    Some(keys)
}

/// Where the table currently being checked sits in the config tree. Needed
/// because `plugin` means a different struct inside a `[[proxies]]` element
/// (`PluginConfig`) than inside a `[[visitors]]` element
/// (`VisitorPluginConfig`), and because the element positions decide which
/// arrays and nested tables may be descended into.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Top level of a client or server config (and the walked `[section]`
    /// tables, which keep the same per-key dispatch).
    Root,
    /// One `[[proxies]]` element.
    ProxyElement,
    /// One `[[visitors]]` element.
    VisitorElement,
    /// One `[[httpPlugins]]` (normalized `http_plugins`) element.
    HttpPluginElement,
    /// One `[proxies.plugin]` table.
    ProxyPlugin,
    /// One `[visitors.plugin]` table.
    VisitorPlugin,
    /// One `health_check_http_headers` array element.
    HealthCheckHeader,
    /// A `[web_server]` / `[webServer]` section (normalized to `web_server`),
    /// so its nested `tls` table can be walked with the TLS key set.
    WebServer,
    /// The nested `[web_server.tls]` table, which survives normalization only
    /// when it holds a key the hoist does not map.
    WebServerTls,
}

/// `WebServerTlsConfig` (`frp-core/src/config/server.rs`) — the keys
/// `check_strict` accepts inside a surviving `web_server.tls` table.
///
/// The hoist removes every one of them (`normalize_web_server_section`), so in
/// practice this set exists to keep the walk well-defined rather than to accept
/// anything: a key that reaches the walker under `tls` is by construction one
/// the hoist did not map, and every such key is an error.
pub(super) const WEB_SERVER_TLS_KNOWN_KEYS: &[&str] = &[
    "enable",
    "cert_file",
    "certFile",
    "key_file",
    "keyFile",
    "trusted_ca_file",
    "trustedCaFile",
    "server_name",
    "serverName",
];

/// Key set of a nested **table** child, by the kind of table it sits in.
///
/// Deliberately an explicit whitelist. The other nested values inside a proxy
/// element are open maps (`headers`, `response_headers`, `annotations`,
/// `metas`) whose user-chosen keys must not be read as field names; everything
/// else Go nests (`transport`, `healthCheck`, `loadBalancer`, `natTraversal`)
/// is flattened onto the element by `normalize_proxies` before this check runs,
/// so it is checked as an element key instead.
fn child_table_keys(ctx: Ctx, key: &str) -> Option<&'static [&'static str]> {
    match ctx {
        Ctx::Root => section_known_keys(key),
        Ctx::ProxyElement => (key == "plugin").then_some(CLIENT_PLUGIN_KNOWN_KEYS),
        Ctx::VisitorElement => (key == "plugin").then_some(VISITOR_PLUGIN_KNOWN_KEYS),
        Ctx::WebServer => (key == "tls").then_some(WEB_SERVER_TLS_KNOWN_KEYS),
        Ctx::HttpPluginElement
        | Ctx::ProxyPlugin
        | Ctx::VisitorPlugin
        | Ctx::HealthCheckHeader
        | Ctx::WebServerTls => None,
    }
}

/// Key set (and child context) of an **array** child that `check_strict`
/// descends into, one element at a time. Arrays not listed here are left
/// alone: their element type is either a scalar (`ops`, `custom_domains`,
/// `locations`, …) or an open shape (maps of user-chosen keys).
///
/// Both spellings of the health-check header array are listed: serde accepts
/// `health_check_http_headers` and its alias `healthCheckHttpHeaders`, and
/// `normalize_proxies` renames only the nested `healthCheck.httpHeaders` form,
/// so a flat `healthCheckHttpHeaders` alias survives here as its own key.
fn child_array_keys(ctx: Ctx, key: &str) -> Option<(&'static [&'static str], Ctx)> {
    match (ctx, key) {
        (Ctx::Root, "proxies") => Some((PROXY_KNOWN_KEYS, Ctx::ProxyElement)),
        (Ctx::Root, "visitors") => Some((VISITOR_KNOWN_KEYS, Ctx::VisitorElement)),
        (Ctx::Root, "http_plugins") => Some((HTTP_PLUGIN_KNOWN_KEYS, Ctx::HttpPluginElement)),
        (Ctx::ProxyElement, "health_check_http_headers" | "healthCheckHttpHeaders") => {
            Some((HEALTH_CHECK_HEADER_KNOWN_KEYS, Ctx::HealthCheckHeader))
        }
        _ => None,
    }
}

/// Child context of a nested table, so the two walkers cannot disagree about
/// which struct a `plugin` table belongs to.
fn child_ctx(ctx: Ctx, key: &str) -> Ctx {
    match (ctx, key) {
        (Ctx::ProxyElement, "plugin") => Ctx::ProxyPlugin,
        (Ctx::VisitorElement, "plugin") => Ctx::VisitorPlugin,
        (Ctx::Root, "web_server") => Ctx::WebServer,
        (Ctx::WebServer, "tls") => Ctx::WebServerTls,
        _ => Ctx::Root,
    }
}

/// Drop every key `check_strict` would reject, recursing through the same
/// whitelists. Used for elements produced by the **legacy-shaped-section**
/// collector (a top-level mapping carrying a `type`, in any config format):
/// Go's legacy path ignores a key its typed struct does not name
/// (`gopkg.in/ini` `MapTo` and the explicit field reads in
/// `pkg/config/legacy/*.go`) rather than rejecting it, so refusing one there
/// would fail a config Go loads.
///
/// Runs after `normalize_proxies` / `normalize_visitors`, so the keys those
/// folds consume (`transport`, `healthCheck`, `loadBalancer`, `natTraversal`,
/// `requestHeaders`, …) have already been renamed and survive as element keys.
pub(super) fn strip_unknown_legacy_element_keys(element: &mut toml::Value, visitor: bool) {
    let Some(table) = element.as_table_mut() else {
        return;
    };
    let (keys, ctx) = if visitor {
        (VISITOR_KNOWN_KEYS, Ctx::VisitorElement)
    } else {
        (PROXY_KNOWN_KEYS, Ctx::ProxyElement)
    };
    strip_unknown_keys_in(table, &known_set_from(keys), ctx);
}

fn strip_unknown_keys_in(
    table: &mut toml::Table,
    known: &std::collections::HashSet<&str>,
    ctx: Ctx,
) {
    for key in table.keys().cloned().collect::<Vec<_>>() {
        if !known.contains(key.as_str()) {
            table.remove(&key);
            continue;
        }
        match table.get_mut(&key) {
            Some(toml::Value::Table(sub)) => {
                if let Some(sub_keys) = child_table_keys(ctx, &key) {
                    strip_unknown_keys_in(sub, &known_set_from(sub_keys), child_ctx(ctx, &key));
                }
            }
            Some(toml::Value::Array(elements)) => {
                if let Some((element_keys, element_ctx)) = child_array_keys(ctx, &key) {
                    for element in elements.iter_mut() {
                        if let toml::Value::Table(element) = element {
                            strip_unknown_keys_in(
                                element,
                                &known_set_from(element_keys),
                                element_ctx,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

pub(super) fn check_strict(
    table: &toml::Table,
    known: &std::collections::HashSet<&str>,
    path: &str,
    config_path: &str,
) -> Vec<String> {
    check_strict_in(table, known, path, config_path, Ctx::Root, true)
}

/// `recurse == false` checks `table`'s own keys and stops: no descent into a
/// known sub-table or array. Used for the legacy `.ini` dialect (see
/// [`run_strict_check_top_level`]), where Go's own reader is accept-and-ignore
/// inside sections but a v1-spelled top-level key still has to be a real field.
fn check_strict_in(
    table: &toml::Table,
    known: &std::collections::HashSet<&str>,
    path: &str,
    config_path: &str,
    ctx: Ctx,
    recurse: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    // Sections whose keys are wildcards (HashMap via #[serde(flatten)])
    let wildcard_sections: &[&str] = &["feature", "metas"];

    for key in table.keys() {
        let full_key = if path.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", path, key)
        };

        let parent_section = path.rsplit('.').next().unwrap_or("");
        if wildcard_sections.contains(&parent_section) {
            continue;
        }

        if !known.contains(key.as_str()) {
            let mut msg = format!(
                "unknown field \"{}\" in config file {}",
                full_key, config_path
            );
            // Suggest closest known key if within edit distance 3. Skip
            // absurdly long unknown keys (>256 chars): levenshtein() is
            // O(n·m) per known key, so a 10 MB unknown key would cost
            // ~100 × O(400M) char ops on every strict-config load — and no
            // known key (all short) can be within edit distance 3 of a
            // >30-char key anyway, so the suggestion would never match.
            let mut best: Option<(&str, usize)> = None;
            if key.len() <= 256 {
                for known_key in known.iter() {
                    let d = levenshtein(key, known_key);
                    if d <= 3
                        && (best.is_none()
                            || d < best
                                .expect("best set by an earlier iteration of this loop")
                                .1)
                    {
                        best = Some((known_key, d));
                    }
                }
            }
            if let Some((suggestion, _)) = best {
                msg.push_str(&format!(" — did you mean '{}'?", suggestion));
            }
            errors.push(msg);
            continue;
        }

        // Recurse into known sub-tables with per-section known-key sets so
        // nested unknown fields are caught too (Go strict mode checks the
        // whole config tree, not just the top level), and into the
        // array-of-tables elements `[[proxies]]`/`[[visitors]]`/
        // `[[httpPlugins]]` with their per-struct key sets. Go's
        // RejectUnknownMembers (pkg/config/v1/decode.go) rejects an unknown
        // proxy/visitor/plugin field at any depth, including inside these
        // arrays; before this recursion the key set was per *section* and an
        // array value never reached the lookup, so an unknown element key was
        // accepted (the exemption the tests used to pin).
        //
        // Only for the v1 dialects: the legacy `.ini` call site passes
        // `recurse == false` because Go's own reader for that dialect ignores
        // an unknown key inside a section (see `run_strict_check_top_level`).
        if !recurse {
            continue;
        }
        match table.get(key) {
            Some(toml::Value::Table(sub)) => {
                if let Some(sub_keys) = child_table_keys(ctx, key) {
                    errors.extend(check_strict_in(
                        sub,
                        &known_set_from(sub_keys),
                        &full_key,
                        config_path,
                        child_ctx(ctx, key),
                        true,
                    ));
                }
            }
            Some(toml::Value::Array(elements)) => {
                if let Some((element_keys, element_ctx)) = child_array_keys(ctx, key) {
                    for (index, element) in elements.iter().enumerate() {
                        if let toml::Value::Table(element) = element {
                            errors.extend(check_strict_in(
                                element,
                                &known_set_from(element_keys),
                                &format!("{}[{}]", full_key, index),
                                config_path,
                                element_ctx,
                                true,
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    errors
}
