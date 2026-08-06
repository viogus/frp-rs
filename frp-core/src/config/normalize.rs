use std::path::Path;

use super::file::process_includes;
use super::format::{detect_format, parse_to_toml_value};
use super::loader::ConfigPresence;
use super::strict::run_strict_check;

/// Convert a toml::Value to a serde_json::Value for deserialization.
/// This is needed because toml::Value can't be directly deserialized into
/// arbitrary Rust types (the round-trip through toml::to_string produces
/// invalid TOML for inline tables).
pub(super) fn toml_to_json(v: toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::Number(i.into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(f).map_or_else(
            || {
                tracing::warn!(float = %f, "NaN/Inf float value in TOML config replaced with null");
                serde_json::Value::Null
            },
            serde_json::Value::Number,
        ),
        toml::Value::Boolean(b) => serde_json::Value::Bool(b),
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => {
            let map: serde_json::Map<String, serde_json::Value> = table
                .into_iter()
                .map(|(k, v)| (k, toml_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}

/// Move matching top-level keys into a sub-table, optionally stripping known prefixes.
/// e.g. `flatten_to_table(t, &["log_file","log_level"], "log", &["log_"])`
fn flatten_to_table(table: &mut toml::Table, keys: &[&str], target: &str, strip_prefixes: &[&str]) {
    let mut items: Vec<(String, toml::Value)> = Vec::new();
    for &key in keys {
        if let Some(v) = table.remove(key) {
            let sub_key = strip_prefixes
                .iter()
                .find_map(|p| key.strip_prefix(p))
                .unwrap_or(key)
                .to_string();
            items.push((sub_key, v));
        }
    }
    if !items.is_empty() {
        let target_table = table
            .entry(target.to_string())
            .or_insert_with(|| toml::Value::Table(Default::default()));
        if let toml::Value::Table(ref mut t) = target_table {
            for (k, v) in items {
                t.insert(k, v);
            }
        }
    }
}

/// Generic config loader shared by `load_server_config` and `load_client_config`.
pub(super) fn load_config_from_file<C: serde::de::DeserializeOwned>(
    path: &str,
    strict_config: bool,
    known_keys: fn() -> std::collections::HashSet<&'static str>,
    normalize: fn(&mut toml::Value),
    validate: fn(&C) -> Result<(), String>,
) -> Result<(C, ConfigPresence), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: failed to read config file: {e}"))?;
    let format = detect_format(path);
    let mut value: toml::Value =
        parse_to_toml_value(&content, format).map_err(|e| format!("{path}: parse error: {e}"))?;
    let base_dir = Path::new(path).parent().unwrap_or(Path::new("."));
    process_includes(&mut value, base_dir)?;
    normalize(&mut value);
    let presence = ConfigPresence::from_normalized_value(&value);
    if strict_config {
        run_strict_check(&value, &known_keys(), path)?;
    }
    let json_value = toml_to_json(value);
    let cfg: C = serde_json::from_value(json_value)
        .map_err(|e| format!("{path}: config validation error: {e}"))?;
    validate(&cfg).map_err(|e| format!("{path}: {e}"))?;
    Ok((cfg, presence))
}

pub(super) fn normalize_server_config(value: &mut toml::Value) {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Handle [common] section: merge into top level
        if let Some(Value::Table(common_table)) = table.remove("common") {
            for (k, v) in common_table {
                table.entry(k).or_insert(v);
            }
        }

        // Rename canonical Go camelCase section names.
        if let Some(v) = table.remove("webServer") {
            table.entry("web_server").or_insert(v);
        }
        normalize_web_server_section(table);
        if let Some(v) = table.remove("featureGates") {
            table.entry("feature").or_insert(v);
        }

        // Rename canonical Go camelCase section names.
        if let Some(v) = table.remove("webServer") {
            table.entry("web_server").or_insert(v);
        }
        normalize_web_server_section(table);
        if let Some(v) = table.remove("httpPlugins") {
            table.entry("http_plugins").or_insert(v);
        }
        if let Some(v) = table.remove("featureGates") {
            table.entry("feature").or_insert(v);
        }

        // Go allowPorts is an array of {start,end} ranges; normalize to the
        // existing comma-separated "start-end" string form.
        if let Some(Value::Array(ranges)) = table.remove("allowPorts") {
            let mut parts = Vec::new();
            for range in ranges {
                if let Some(t) = range.as_table() {
                    let start = t.get("start").and_then(Value::as_integer).unwrap_or(0);
                    let end = t.get("end").and_then(Value::as_integer).unwrap_or(start);
                    parts.push(format!("{start}-{end}"));
                }
            }
            if !parts.is_empty() {
                table.insert("allow_ports".to_string(), Value::String(parts.join(",")));
            }
        }

        // Move bare `token` into [auth] table as well
        if let Some(v) = table.remove("token") {
            let auth_table = table
                .entry("auth")
                .or_insert_with(|| toml::Value::Table(Default::default()));
            if let toml::Value::Table(ref mut t) = auth_table {
                t.entry("token".to_string()).or_insert(v);
            }
        }

        flatten_to_table(
            table,
            &[
                "auth_method",
                "auth_token",
                "token",
                "oidc_issuer",
                "oidc_audience",
                "oidc_token_endpoint",
            ],
            "auth",
            &["auth_", "oidc_"],
        );
        flatten_to_table(
            table,
            &["log_file", "log_level", "log_max_days"],
            "log",
            &["log_"],
        );
        flatten_to_table(
            table,
            &[
                "web_server_addr",
                "web_server_port",
                "web_server_user",
                "web_server_password",
                "web_server_enable_prometheus",
                "enable_prometheus",
                "enablePrometheus",
                "web_server_tls_cert_file",
                "web_server_tls_key_file",
            ],
            "web_server",
            &["web_server_"],
        );
        flatten_to_table(
            table,
            &[
                "tcp_mux",
                "tcp_mux_keepalive_interval",
                "heartbeat_timeout",
                "max_pool_count",
            ],
            "transport",
            &[],
        );

        // Flatten canonical Go frp [transport.tls] fields to the legacy
        // top-level Rust TLS fields. Explicit top-level values keep precedence.
        let transport_tls = table
            .get_mut("transport")
            .and_then(toml::Value::as_table_mut)
            .and_then(|transport| transport.remove("tls"));
        if let Some(Value::Table(tls_table)) = transport_tls {
            let tls_enable = tls_table.get("force").and_then(Value::as_bool) == Some(true)
                || tls_table.contains_key("certFile")
                || tls_table.contains_key("keyFile");
            for (key, value) in tls_table {
                let flat_key = match key.as_str() {
                    "force" => "tls_only",
                    "certFile" => "tls_cert_file",
                    "keyFile" => "tls_key_file",
                    "trustedCaFile" => "tls_ca_file",
                    "serverName" => "tls_server_name",
                    other => other,
                };
                table.entry(flat_key.to_string()).or_insert(value);
            }
            if tls_enable {
                table
                    .entry("tls_enable".to_string())
                    .or_insert(Value::Boolean(true));
            }
        }

        // MEDIUM-9: Normalize legacy top-level transport fields into [transport]
        flatten_to_table(
            table,
            &[
                "heartbeat_timeout",
                "max_pool_count",
                "heartbeatTimeout",
                "maxPoolCount",
            ],
            "transport",
            &[],
        );

        // Normalize canonical Go frp camelCase keys inside [transport] to
        // snake_case so serde aliases and presence tracking see one shape.
        if let Some(transport) = table.get_mut("transport").and_then(Value::as_table_mut) {
            const RENAMES: &[(&str, &str)] = &[
                ("tcpMux", "tcp_mux"),
                ("tcpMuxKeepaliveInterval", "tcp_mux_keepalive_interval"),
                ("heartbeatTimeout", "heartbeat_timeout"),
                ("maxPoolCount", "max_pool_count"),
                ("tcpKeepalive", "tcp_keepalive"),
            ];
            for (from, to) in RENAMES {
                if let Some(v) = transport.remove(*from) {
                    transport.entry((*to).to_string()).or_insert(v);
                }
            }
        }

        // MEDIUM-5: Normalize [auth.oidc] sub-table → auth.oidc_* flat fields
        if let Some(toml::Value::Table(ref mut auth_table)) = table.get_mut("auth") {
            if let Some(toml::Value::Table(oidc_table)) = auth_table.remove("oidc") {
                for (k, v) in oidc_table {
                    let flat_key = match k.as_str() {
                        "issuer" => "oidc_issuer",
                        "audience" => "oidc_audience",
                        "tokenEndpointUrl" | "tokenEndpointURL" => "oidc_token_endpoint",
                        "skipExpiry" => "oidc_skip_expiry",
                        "skipExpiryCheck" => "oidc_skip_expiry",
                        "skipIssuer" => "oidc_skip_issuer",
                        "skipIssuerCheck" => "oidc_skip_issuer",
                        "skipNbf" => "oidc_skip_nbf",
                        "proxyURL" => "oidc_proxy_url",
                        "additionalAuthScopes" => "additional_auth_scopes",
                        other => other,
                    };
                    auth_table.entry(flat_key.to_string()).or_insert(v);
                }
            }
        }

        // MEDIUM-8: Normalize top-level custom_404_page / custom404Page → web_server.custom_404_page
        if let Some(v) = table
            .remove("custom_404_page")
            .or_else(|| table.remove("custom404Page"))
        {
            let ws_table = table
                .entry("web_server")
                .or_insert_with(|| toml::Value::Table(Default::default()));
            if let toml::Value::Table(ref mut ws) = ws_table {
                ws.entry("custom_404_page".to_string()).or_insert(v);
            }
        }

        // MEDIUM-6: Normalize http_plugins[*].addr + .path → .url
        if let Some(toml::Value::Array(plugins)) = table.get_mut("http_plugins") {
            for plugin_val in plugins.iter_mut() {
                if let Some(ref mut pt) = plugin_val.as_table_mut() {
                    if !pt.contains_key("url") {
                        let addr = pt.get("addr").and_then(|v| v.as_str()).map(String::from);
                        let path = pt.get("path").and_then(|v| v.as_str()).map(String::from);
                        if let Some(addr) = addr {
                            let url = if let Some(p) = path {
                                let p = if p.starts_with('/') {
                                    p
                                } else {
                                    format!("/{}", p)
                                };
                                format!("{}{}", addr.trim_end_matches('/'), p)
                            } else {
                                addr
                            };
                            pt.insert("url".to_string(), toml::Value::String(url));
                        }
                    }
                }
            }
        }

        // Normalize camelCase section names to snake_case
        if let Some(ssh_section) = table.remove("sshTunnelGateway") {
            table.entry("ssh_tunnel_gateway").or_insert(ssh_section);
        }

        // Extract meta_* prefixed keys into metas map (Go frp legacy compat).
        let meta_keys: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("meta_"))
            .cloned()
            .collect();
        if !meta_keys.is_empty() {
            let mut meta_map = toml::Table::new();
            for key in &meta_keys {
                if let Some(v) = table.remove(key) {
                    let sub_key = key.strip_prefix("meta_").unwrap().to_string();
                    meta_map.insert(sub_key, v);
                }
            }
            table
                .entry("metas".to_string())
                .or_insert(toml::Value::Table(meta_map));
        }
    }
}

pub(super) fn normalize_client_config(value: &mut toml::Value) {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Handle [common] section
        if let Some(Value::Table(common_table)) = table.remove("common") {
            for (k, v) in common_table {
                table.entry(k).or_insert(v);
            }
        }

        // Rename protocol → transport_protocol (Go frp uses "protocol")
        if let Some(v) = table.remove("protocol") {
            table.entry("transport_protocol").or_insert(v);
        }

        // Rename tls_trusted_ca_file → tls_ca_file
        if let Some(v) = table.remove("tls_trusted_ca_file") {
            table.entry("tls_ca_file").or_insert(v);
        }

        // Rename serverAddr → server_addr, serverPort → server_port (Go frp uses camelCase)
        if let Some(v) = table.remove("serverAddr") {
            table.entry("server_addr").or_insert(v);
        }
        if let Some(v) = table.remove("serverPort") {
            table.entry("server_port").or_insert(v);
        }

        // Flatten legacy top-level auth_*, oidc_* fields into [auth] table.
        // Go frp uses auth.method, auth.token, auth.oidc_* in client config.
        flatten_to_table(
            table,
            &[
                "auth_method",
                "auth_token",
                "token",
                "oidc_issuer",
                "oidc_audience",
                "oidc_token_endpoint",
                "oidc_client_id",
                "oidc_client_secret",
                "oidc_scope",
                "oidc_proxy_url",
            ],
            "auth",
            &["auth_", "oidc_"],
        );

        // Also copy token from [auth] to top-level for backward compat
        // (ClientConfig has both flat `token` and nested `auth.token`).
        // Extract the token first to avoid mutable borrow conflict with table.
        let auth_token = table
            .get("auth")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("token"))
            .cloned();
        if let Some(token_val) = auth_token {
            table.entry("token").or_insert(token_val);
        }

        // Flatten [transport] section → top-level (ClientConfig has tcp_mux at top level,
        // but Go frp config puts it under [transport])
        if let Some(Value::Table(tr_table)) = table.remove("transport") {
            for (k, v) in tr_table {
                if k == "wireProtocol" {
                    // transport.wireProtocol = "v2" → top-level v2 = true (Go frp compat)
                    if v.as_str() == Some("v2") {
                        table.insert("v2".to_string(), Value::Boolean(true));
                    }
                } else {
                    let flat_key = match k.as_str() {
                        "protocol" => "transport_protocol",
                        "tcpMux" => "tcp_mux",
                        "heartbeatInterval" => "heartbeat_interval",
                        "heartbeatTimeout" => "heartbeat_timeout",
                        "dialServerTimeout" => "dial_server_timeout",
                        "poolCount" => "pool_count",
                        other => other,
                    };
                    table.entry(flat_key.to_string()).or_insert(v);
                }
            }
        }

        // Flatten canonical Go [auth.oidc] sub-table → auth.oidc_* flat fields.
        if let Some(toml::Value::Table(ref mut auth_table)) = table.get_mut("auth") {
            if let Some(toml::Value::Table(oidc_table)) = auth_table.remove("oidc") {
                for (k, v) in oidc_table {
                    let flat_key = match k.as_str() {
                        "clientID" => "oidc_client_id",
                        "clientSecret" => "oidc_client_secret",
                        "audience" => "oidc_audience",
                        "tokenEndpointUrl" | "tokenEndpointURL" => "oidc_token_endpoint",
                        "scope" => "oidc_scope",
                        "issuer" => "oidc_issuer",
                        "additionalEndpointParams" => "additional_endpoint_params",
                        "trustedCaFile" => "oidc_tls_trusted_ca_file",
                        "insecureSkipVerify" => "oidc_tls_insecure_skip_verify",
                        "proxyURL" => "oidc_proxy_url",
                        "tokenSource" => "oidc_token_source",
                        "additionalAuthScopes" => "additional_auth_scopes",
                        other => other,
                    };
                    auth_table.entry(flat_key.to_string()).or_insert(v);
                }
            }
        }

        // Flatten [transport.tls] sub-table → top-level tls_* fields
        // Go frp compat: transport.tls.enable → tls_enable, etc.
        if let Some(Value::Table(tls_table)) = table.remove("tls") {
            for (k, v) in tls_table {
                let flat_key = match k.as_str() {
                    "enable" => "tls_enable",
                    "certFile" => "tls_cert_file",
                    "keyFile" => "tls_key_file",
                    "trustedCaFile" => "tls_ca_file",
                    "serverName" => "tls_server_name",
                    "disableCustomTLSFirstByte" => "disable_custom_tls_first_byte",
                    other => other,
                };
                table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Flatten log_* fields into log table (client side)
        flatten_to_table(
            table,
            &["log_file", "log_level", "log_max_days"],
            "log",
            &["log_"],
        );

        // Normalize Go-format proxy sub-tables into flat fields
        normalize_proxies(table);
        normalize_visitors(table);

        // Extract meta_* prefixed keys into metas map (Go frp legacy compat).
        let meta_keys: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("meta_"))
            .cloned()
            .collect();
        if !meta_keys.is_empty() {
            let mut meta_map = toml::Table::new();
            for key in &meta_keys {
                if let Some(v) = table.remove(key) {
                    let sub_key = key.strip_prefix("meta_").unwrap().to_string();
                    meta_map.insert(sub_key, v);
                }
            }
            table
                .entry("metas".to_string())
                .or_insert(toml::Value::Table(meta_map));
        }
    }
}

/// Normalize canonical Go `[webServer.tls]` (and `[web_server.tls]`) into the
/// existing flat `web_server.tls_cert_file` / `tls_key_file` fields.
fn normalize_web_server_section(table: &mut toml::Table) {
    use toml::Value;

    let Some(Value::Table(ws)) = table.get_mut("web_server") else {
        return;
    };
    if let Some(Value::Table(tls)) = ws.remove("tls") {
        for (k, v) in tls {
            let flat_key = match k.as_str() {
                "certFile" => "tls_cert_file",
                "keyFile" => "tls_key_file",
                "trustedCaFile" => "tls_ca_file",
                "serverName" => "tls_server_name",
                other => other,
            };
            ws.entry(flat_key.to_string()).or_insert(v);
        }
    }
}

/// Normalize Go-format proxy sub-tables into flat fields for each proxy entry.
///
/// Handles:
/// - `[proxies.transport]` → flat fields (useEncryption, bandwidthLimit, ...)
/// - `[proxies.healthCheck]` → flat fields (type, intervalSeconds, ...)
/// - `[proxies.loadBalancer]` → flat fields (group, groupKey)
/// - `[proxies.requestHeaders.set]` → `headers.*`
/// - `[proxies.responseHeaders.set]` → `response_headers.*`
fn normalize_proxies(table: &mut toml::Table) {
    use toml::Value;

    let proxies = match table.get_mut("proxies") {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    for proxy_val in proxies.iter_mut() {
        let proxy_table = match proxy_val.as_table_mut() {
            Some(t) => t,
            _ => continue,
        };

        // Flatten [proxies.transport] sub-table
        if let Some(Value::Table(transport)) = proxy_table.remove("transport") {
            for (k, v) in transport {
                let flat_key = match k.as_str() {
                    "useEncryption" => "use_encryption",
                    "useCompression" => "use_compression",
                    "bandwidthLimit" => "bandwidth_limit",
                    "proxyProtocolVersion" => "proxy_protocol_version",
                    other => other,
                };
                proxy_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Flatten [proxies.healthCheck] sub-table
        if let Some(Value::Table(hc)) = proxy_table.remove("healthCheck") {
            for (k, v) in hc {
                let flat_key = match k.as_str() {
                    "type" => "health_check_type",
                    "url" => "health_check_url",
                    "path" => "health_check_url",
                    "httpHeaders" => "health_check_http_headers",
                    "intervalSeconds" => "health_check_interval_seconds",
                    "timeoutSeconds" => "health_check_timeout_seconds",
                    "maxFailed" => "health_check_max_failed",
                    other => other,
                };
                let value = if k == "httpHeaders" {
                    match v {
                        Value::Array(items) => {
                            let mut map = toml::Table::new();
                            for item in items {
                                if let Some(t) = item.as_table() {
                                    let name =
                                        t.get("name").and_then(Value::as_str).unwrap_or_default();
                                    let value =
                                        t.get("value").and_then(Value::as_str).unwrap_or_default();
                                    map.insert(name.to_string(), Value::String(value.to_string()));
                                }
                            }
                            Value::Table(map)
                        }
                        other => other,
                    }
                } else {
                    v
                };
                proxy_table.entry(flat_key.to_string()).or_insert(value);
            }
        }

        // Flatten [proxies.loadBalancer] sub-table
        if let Some(Value::Table(lb)) = proxy_table.remove("loadBalancer") {
            for (k, v) in lb {
                let flat_key = match k.as_str() {
                    "group" => "group",
                    "groupKey" => "group_key",
                    other => other,
                };
                proxy_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Flatten [proxies.natTraversal] sub-table
        if let Some(Value::Table(nt)) = proxy_table.remove("natTraversal") {
            for (k, v) in nt {
                let flat_key = match k.as_str() {
                    "disableAssistedAddrs" => "disable_assisted_addrs",
                    other => other,
                };
                proxy_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Normalize [proxies.requestHeaders.set] → flat headers map
        if let Some(Value::Table(rh)) = proxy_table.remove("requestHeaders") {
            if let Some(Value::Table(set)) = rh.get("set") {
                if let Some(Value::Table(existing)) = proxy_table.get_mut("headers") {
                    for (k, v) in set.clone() {
                        existing.entry(k).or_insert(v);
                    }
                } else {
                    proxy_table.insert("headers".to_string(), Value::Table(set.clone()));
                }
            }
        }

        // Normalize [proxies.responseHeaders.set] → flat response_headers map
        if let Some(Value::Table(rh)) = proxy_table.remove("responseHeaders") {
            if let Some(Value::Table(set)) = rh.get("set") {
                if let Some(Value::Table(existing)) = proxy_table.get_mut("response_headers") {
                    for (k, v) in set.clone() {
                        existing.entry(k).or_insert(v);
                    }
                } else {
                    proxy_table.insert("response_headers".to_string(), Value::Table(set.clone()));
                }
            }
        }

        // Normalize Go-style flat plugin fields:
        //   plugin = "unix_domain_socket"
        //   plugin_local_addr = "/var/run/docker.sock"
        // into the nested `[proxies.plugin]` shape used by frp-rs.
        if let Some(Value::String(plugin_type)) = proxy_table.get("plugin").cloned() {
            proxy_table.remove("plugin");
            let mut plugin_table = toml::Table::new();
            plugin_table.insert("type".to_string(), Value::String(plugin_type));

            let plugin_keys: Vec<String> = proxy_table
                .keys()
                .filter(|k| k.starts_with("plugin_") || k.starts_with("plugin"))
                .cloned()
                .collect();
            for key in plugin_keys {
                if let Some(v) = proxy_table.remove(&key) {
                    let flat_key = match key.as_str() {
                        "plugin_local_addr" | "pluginLocalAddr" => "local_addr",
                        "plugin_local_path" | "pluginLocalPath" => "local_path",
                        "plugin_unix_path" | "pluginUnixPath" => "local_addr",
                        "plugin_http_user" | "pluginHttpUser" => "http_user",
                        "plugin_http_password"
                        | "pluginHttpPassword"
                        | "plugin_http_passwd"
                        | "pluginHttpPasswd" => "http_password",
                        "plugin_user" | "pluginUser" => "username",
                        "plugin_passwd" | "pluginPasswd" => "password",
                        "plugin_strip_prefix" | "pluginStripPrefix" => "strip_prefix",
                        "plugin_host_header_rewrite" | "pluginHostHeaderRewrite" => {
                            "host_header_rewrite"
                        }
                        "plugin_crt_path" | "pluginCrtPath" => "plugin_crt_path",
                        "plugin_key_path" | "pluginKeyPath" => "plugin_key_path",
                        other => other,
                    };
                    plugin_table.entry(flat_key.to_string()).or_insert(v);
                }
            }

            if let Some(Value::Table(existing)) = proxy_table.get_mut("plugin") {
                for (k, v) in plugin_table {
                    existing.entry(k).or_insert(v);
                }
            } else {
                proxy_table.insert("plugin".to_string(), Value::Table(plugin_table));
            }
        }

        // Normalize [proxies.plugin.requestHeaders.set] → request_headers map,
        // including nested `[proxies.plugin]` tables.
        if let Some(Value::Table(rh)) = proxy_table
            .get_mut("plugin")
            .and_then(Value::as_table_mut)
            .and_then(|t| t.remove("requestHeaders"))
        {
            if let Some(Value::Table(set)) = rh.get("set") {
                if let Some(Value::Table(existing)) = proxy_table
                    .get_mut("plugin")
                    .and_then(Value::as_table_mut)
                    .and_then(|t| t.get_mut("request_headers"))
                {
                    for (k, v) in set.clone() {
                        existing.entry(k).or_insert(v);
                    }
                } else if let Some(plugin) =
                    proxy_table.get_mut("plugin").and_then(Value::as_table_mut)
                {
                    plugin.insert("request_headers".to_string(), Value::Table(set.clone()));
                }
            }
        }
    }
}

/// Normalize Go-format visitor sub-tables into flat fields for each visitor.
///
/// Handles `[visitors.transport]` and `[visitors.natTraversal]`.
fn normalize_visitors(table: &mut toml::Table) {
    use toml::Value;

    let visitors = match table.get_mut("visitors") {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    for visitor_val in visitors.iter_mut() {
        let visitor_table = match visitor_val.as_table_mut() {
            Some(t) => t,
            _ => continue,
        };

        if let Some(Value::Table(transport)) = visitor_table.remove("transport") {
            for (k, v) in transport {
                let flat_key = match k.as_str() {
                    "useEncryption" => "use_encryption",
                    "useCompression" => "use_compression",
                    other => other,
                };
                visitor_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        if let Some(Value::Table(nat)) = visitor_table.remove("natTraversal") {
            for (k, v) in nat {
                let flat_key = match k.as_str() {
                    "disableAssistedAddrs" => "disable_assisted_addrs",
                    other => other,
                };
                visitor_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Normalize Go-style [visitors.plugin] tables into the nested plugin
        // shape used by frp-rs. destinationIP is converted to snake_case; the
        // remaining keys (type, serverName, bindPort, ...) are handled by
        // serde aliases on VisitorPluginConfig.
        if let Some(Value::Table(plugin)) = visitor_table.remove("plugin") {
            let mut plugin_table = toml::Table::new();
            for (k, v) in plugin {
                let flat_key = match k.as_str() {
                    "destinationIP" => "destination_ip",
                    other => other,
                };
                plugin_table.entry(flat_key.to_string()).or_insert(v);
            }
            visitor_table.insert("plugin".to_string(), Value::Table(plugin_table));
        }
    }
}
