// ─── Strict config mode ──────────────────────────────────────────────

fn known_set_from(keys: &[&'static str]) -> std::collections::HashSet<&'static str> {
    let mut set = std::collections::HashSet::new();
    set.extend(keys);
    set
}

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
        "heartbeatTimeout",
        "maxPoolCount",
        "tcpKeepalive",
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
        "userConnTimeout",
        "natholeAnalysisDataReserveHours",
        // Go frp v0.70.1 camelCase aliases accepted by serde that are not
        // renamed away by normalize_server_config (audit task 9 finding 1).
        "detailedErrorsToClient",
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

pub(super) fn run_strict_check(
    value: &toml::Value,
    known: &std::collections::HashSet<&str>,
    config_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let toml::Value::Table(ref table) = value {
        let errors = check_strict(table, known, "", config_path);
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
/// the Go frp v0.70.1 camelCase aliases serde accepts (normalization does not
/// rename keys inside these sections). Sections not listed are not recursed
/// into (e.g. `proxies`/`visitors` arrays — per-type keys would make the
/// check a maintenance hazard and Go accepts type-specific fields there).
fn section_known_keys(section: &str) -> Option<&'static [&'static str]> {
    let keys: &'static [&'static str] = match section {
        // Union of client and server auth flat fields (normalization flattens
        // `[auth.oidc]` into `auth.oidc_*` before strict mode runs).
        "auth" => &[
            "method",
            "token",
            "tokenSource",
            "method",
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
            "oidc_skip_issuer",
            "oidcSkipIssuer",
            "oidc_skip_issuer_check",
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
        ],
        "transport" => &[
            "tcp_mux",
            "tcpMux",
            "tcp_mux_keepalive_interval",
            "tcpMuxKeepaliveInterval",
            "heartbeat_timeout",
            "heartbeatTimeout",
            "max_pool_count",
            "maxPoolCount",
            "tcp_keepalive",
            "tcpKeepalive",
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

pub(super) fn check_strict(
    table: &toml::Table,
    known: &std::collections::HashSet<&str>,
    path: &str,
    config_path: &str,
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
            // Suggest closest known key if within edit distance 3
            let mut best: Option<(&str, usize)> = None;
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
            if let Some((suggestion, _)) = best {
                msg.push_str(&format!(" — did you mean '{}'?", suggestion));
            }
            errors.push(msg);
            continue;
        }

        // Recurse into known sub-tables with per-section known-key sets so
        // nested unknown fields are caught too (Go strict mode checks the
        // whole config tree, not just the top level).
        if let Some(toml::Value::Table(sub)) = table.get(key) {
            if let Some(sub_keys) = section_known_keys(key) {
                errors.extend(check_strict(
                    sub,
                    &known_set_from(sub_keys),
                    &full_key,
                    config_path,
                ));
            }
        }
    }
    errors
}
