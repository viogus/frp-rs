use super::client::{AuthClientConfig, ClientConfig, ProxyConfig, VisitorConfig};
use super::normalize::{normalize_client_config, normalize_server_config, toml_to_json};
use super::server::{PortsRange, ServerConfig, ValueSource};
use crate::feature_gate::VIRTUAL_NET;

/// Parse a bandwidth limit string like "1MB", "500KB", "100KB".
/// Returns bytes per second, or None if unparseable.
/// Go frp compat: only supports "MB" and "KB" suffixes (case-insensitive).
/// Bare numbers, single-letter suffixes ("M", "K"), and "GB" are rejected.
/// Empty string returns Some(0) (no limit, Go compat).
///
/// Note: Empty string returns `Some(0)` (not `None`) so callers using `is_some()`
/// will treat empty as a valid config value. This matches Go frp's behavior where
/// an empty bandwidth limit field means "no limit" (effectively 0). Callers that
/// need to distinguish "not set" from "set to 0" should check `is_empty()` before
/// calling this function.
pub fn parse_bandwidth_limit(s: &str) -> Option<u64> {
    if s.is_empty() {
        return Some(0);
    }
    let s = s.trim();
    let (num_str, mult) = {
        let end = s.len();
        if end > 2 && s[(end - 2)..].eq_ignore_ascii_case("MB") {
            (s[..(end - 2)].trim(), 1_048_576u64)
        } else if end > 2 && s[(end - 2)..].eq_ignore_ascii_case("KB") {
            // Go requires a suffix; bare numbers and single-letter suffixes are invalid.
            // Returns None when "KB" suffix is absent, rejecting bare numbers ("500")
            // and single-letter ("500K").
            (s[..(end - 2)].trim(), 1024u64)
        } else {
            return None;
        }
    };
    let num: f64 = num_str.parse().ok()?;
    if num <= 0.0 {
        return None;
    }
    Some((num * mult as f64) as u64)
}

/// Parse a comma-separated port range string into a list of [`PortsRange`].
///
/// Supports Go frp v0.70.1 syntax: `"10000-20000,30000,{single=40000}"`.
/// Returns an empty vec when the string is empty; **invalid entries are an
/// error** (Go's config validation rejects them rather than silently
/// disabling the restriction).
pub fn parse_allow_ports(s: &str) -> Result<Vec<PortsRange>, String> {
    if s.trim().is_empty() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // {single=N} form.
        if let Some(inner) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
            let single = inner
                .strip_prefix("single=")
                .and_then(|v| v.trim().parse::<u16>().ok())
                .ok_or_else(|| format!("invalid allow_ports entry '{part}'"))?;
            out.push(PortsRange {
                start: single,
                end: single,
                single,
            });
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("invalid allow_ports entry '{part}'"))?;
            let end: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("invalid allow_ports entry '{part}'"))?;
            if start == 0 || end == 0 {
                return Err(format!(
                    "invalid allow_ports entry '{part}': port 0 is not allowed"
                ));
            }
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            out.push(PortsRange {
                start,
                end,
                single: 0,
            });
        } else {
            // Single port: treat as start=end.
            let p: u16 = part
                .parse()
                .map_err(|_| format!("invalid allow_ports entry '{part}'"))?;
            if p == 0 {
                return Err(format!(
                    "invalid allow_ports entry '{part}': port 0 is not allowed"
                ));
            }
            out.push(PortsRange {
                start: p,
                end: p,
                single: 0,
            });
        }
    }
    Ok(out)
}

/// Compute the total number of ports across all ranges.
pub fn count_ports(ranges: &[PortsRange]) -> u16 {
    ranges
        .iter()
        .map(|r| {
            if r.single > 0 {
                1u32
            } else {
                r.end.saturating_sub(r.start) as u32 + 1
            }
        })
        .fold(0u32, |acc, n| acc.saturating_add(n))
        .min(u16::MAX as u32) as u16
}

/// Normalize a parsed TOML value from Go frp format to frp-rs format.
/// Handles:
/// - `[common]` section → flatten to top level
/// - Flat auth_*, log_*, web_server_*, transport_* → nested structs
/// - Field name differences (protocol → transport_protocol, etc.)
pub fn load_server_config_from_str(
    content: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
    normalize_server_config(&mut value);
    let presence = ConfigPresence::from_normalized_value(&value);
    let json_value = toml_to_json(value);
    let mut cfg: ServerConfig =
        serde_json::from_value(json_value).map_err(|e| format!("config validation error: {e}"))?;
    validate_server_config(&cfg)?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

pub fn load_client_config_from_str(
    content: &str,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
    normalize_client_config(&mut value);
    let presence = ConfigPresence::from_normalized_value(&value);
    let mut cfg: ClientConfig = serde_json::from_value(toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    validate_client_config(&cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

/// Presence flags for fields whose Go default depends on whether the user
/// explicitly configured them. Computed from the normalized TOML value so
/// serde defaults cannot be confused with explicit values.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ConfigPresence {
    pub(super) server_heartbeat_timeout_set: bool,
    pub(super) client_heartbeat_interval_set: bool,
    pub(super) client_heartbeat_timeout_set: bool,
}

impl ConfigPresence {
    pub(super) fn from_normalized_value(value: &toml::Value) -> Self {
        let mut presence = Self::default();
        let Some(table) = value.as_table() else {
            return presence;
        };
        presence.client_heartbeat_interval_set =
            table.contains_key("heartbeat_interval") || table.contains_key("heartbeatInterval");
        presence.client_heartbeat_timeout_set =
            table.contains_key("heartbeat_timeout") || table.contains_key("heartbeatTimeout");
        presence.server_heartbeat_timeout_set = presence.client_heartbeat_timeout_set
            || table
                .get("transport")
                .and_then(toml::Value::as_table)
                .is_some_and(|transport| {
                    transport.contains_key("heartbeat_timeout")
                        || transport.contains_key("heartbeatTimeout")
                });
        presence
    }
}

/// Validate proxy configs after deserialization. Catches invalid bandwidth
/// limits, CR/LF in response headers, and other semantic issues that serde
/// cannot express.
fn validate_proxy_configs(proxies: &[ProxyConfig]) -> Result<(), String> {
    const VALID_PROXY_TYPES: &[&str] = &[
        "tcp", "udp", "http", "https", "stcp", "xtcp", "sudp", "tcpmux",
    ];
    for p in proxies {
        // Validate proxy_type
        if !VALID_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
            return Err(format!(
                "proxy '{}': invalid proxy_type '{}'. Valid types: tcp, udp, http, https, stcp, xtcp, sudp, tcpmux",
                p.name, p.proxy_type
            ));
        }

        // Validate response headers: no CR or LF in names or values
        for (name, value) in &p.response_headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': response header name contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': response header value for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate health check HTTP headers too (same CR/LF risk)
        for (name, value) in &p.health_check_http_headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': health check header name contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': health check header value for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate proxy headers field (injected into forwarded requests)
        for (name, value) in &p.headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': header name in 'headers' contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': header value in 'headers' for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate host_header_rewrite (injected into Host header)
        if p.host_header_rewrite.contains('\r') || p.host_header_rewrite.contains('\n') {
            return Err(format!(
                "proxy '{}': host_header_rewrite contains CR/LF",
                p.name
            ));
        }

        // Validate bandwidth_limit: non-empty strings must parse
        if !p.bandwidth_limit.is_empty() && parse_bandwidth_limit(&p.bandwidth_limit).is_none() {
            let hint = if p.bandwidth_limit == "0" || p.bandwidth_limit == "0KB" {
                "value must be positive; use empty string for no limit"
            } else {
                "must be a positive number followed by KB, MB, or GB"
            };
            return Err(format!(
                "proxy '{}': invalid bandwidth_limit: {:?} ({})",
                p.name, p.bandwidth_limit, hint
            ));
        }

        // Validate bandwidth_limit_mode: must be "client" or "server" (Go frp compat).
        if !p.bandwidth_limit_mode.is_empty()
            && p.bandwidth_limit_mode != "client"
            && p.bandwidth_limit_mode != "server"
        {
            return Err(format!(
                "proxy '{}': invalid bandwidth_limit_mode: {:?}, must be \"client\" or \"server\"",
                p.name, p.bandwidth_limit_mode
            ));
        }
    }
    Ok(())
}

/// Validate token/tokenSource mutual exclusivity and source structure.
/// Go frp v0.70.1 compat: validation/auth.go validateAuthTokenSource.
pub fn validate_auth_token_source(
    token: &str,
    token_source: &Option<ValueSource>,
) -> Result<(), String> {
    if !token.is_empty() && token_source.is_some() {
        return Err("cannot specify both auth.token and auth.tokenSource".into());
    }
    if let Some(source) = token_source {
        source
            .validate()
            .map_err(|e| format!("invalid auth.tokenSource: {e}"))?;
    }
    Ok(())
}

/// Go frp v0.70.1 compat: `validation.ValidateOIDCClientCredentialsConfig`
/// (`/tmp/frp-src-0.70.1/pkg/config/v1/validation/oidc.go`) plus the
/// `tokenSource` mutual-exclusivity check from `validateOIDCConfig`
/// (`client.go:84-94`).
fn validate_oidc_client_config(auth: &AuthClientConfig) -> Result<(), String> {
    // auth.oidc.tokenSource is mutually exclusive with every other field
    // of auth.oidc (Go client.go:89-94).
    if let Some(source) = &auth.oidc_token_source {
        if !auth.oidc_client_id.is_empty()
            || !auth.oidc_client_secret.is_empty()
            || !auth.oidc_audience.is_empty()
            || !auth.oidc_scope.is_empty()
            || !auth.oidc_token_endpoint.is_empty()
            || !auth.additional_endpoint_params.is_empty()
            || !auth.oidc_tls_trusted_ca_file.is_empty()
            || auth.oidc_tls_insecure_skip_verify
            || !auth.oidc_proxy_url.is_empty()
        {
            return Err(
                "cannot specify both auth.oidc.tokenSource and any other field of auth.oidc".into(),
            );
        }
        return source
            .validate()
            .map_err(|e| format!("invalid auth.oidc.tokenSource: {e}"));
    }

    // Client-credentials validation only applies to the OIDC method.
    if auth.method != "oidc" {
        return Ok(());
    }

    if auth.oidc_client_id.is_empty() {
        return Err("auth.oidc.clientID is required".into());
    }
    if auth.oidc_token_endpoint.is_empty() && auth.oidc_issuer.is_empty() {
        return Err(
            "auth.oidc.tokenEndpointURL is required (or auth.oidc.issuer for discovery)".into(),
        );
    }
    if !auth.oidc_token_endpoint.is_empty() {
        let ep = &auth.oidc_token_endpoint;
        let rest = if let Some(r) = ep.strip_prefix("https://") {
            r
        } else if let Some(r) = ep.strip_prefix("http://") {
            r
        } else {
            return Err("auth.oidc.tokenEndpointURL must use http or https".into());
        };
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err("auth.oidc.tokenEndpointURL must be an absolute http or https URL".into());
        }
    }
    if auth.additional_endpoint_params.contains_key("scope") {
        return Err(
            "auth.oidc.additionalEndpointParams.scope is not allowed; use auth.oidc.scope instead"
                .into(),
        );
    }
    if !auth.oidc_audience.is_empty() && auth.additional_endpoint_params.contains_key("audience") {
        return Err(
            "cannot specify both auth.oidc.audience and auth.oidc.additionalEndpointParams.audience"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn validate_server_config(cfg: &ServerConfig) -> Result<(), String> {
    validate_auth_token_source(&cfg.auth.token, &cfg.auth.token_source)?;
    // Go frp compat: invalid allow_ports entries are config errors, not a
    // silent disable of the restriction (validation/PortsRange).
    if !cfg.allow_ports.trim().is_empty() {
        parse_allow_ports(&cfg.allow_ports).map_err(|e| format!("server config: {e}"))?;
    }
    // ServerConfig has no inline proxy definitions — proxies are registered
    // by clients at runtime. No proxy-level validation to do here.
    Ok(())
}

pub(super) fn validate_client_config(cfg: &ClientConfig) -> Result<(), String> {
    validate_proxy_configs(&cfg.proxies)?;
    validate_no_duplicate_names(&cfg.proxies, &cfg.visitors)?;
    if let Some(auth) = &cfg.auth {
        let token = if cfg.token.is_empty() {
            auth.token.as_str()
        } else {
            cfg.token.as_str()
        };
        validate_auth_token_source(token, &auth.token_source)?;
        validate_oidc_client_config(auth)?;
    }
    if (!cfg.virtual_net.address.is_empty()
        || cfg.visitors.iter().any(is_virtual_net_visitor)
        || cfg.proxies.iter().any(is_virtual_net_proxy_plugin))
        && !cfg.feature.gates.get(VIRTUAL_NET).copied().unwrap_or(false)
    {
        return Err(format!(
            "VirtualNet feature is not enabled; enable it by setting [featureGates] {VIRTUAL_NET} = true"
        ));
    }
    for p in cfg
        .proxies
        .iter()
        .filter(|p| is_virtual_net_proxy_plugin(p))
    {
        if p.proxy_type != "tcp" {
            return Err(format!(
                "proxy '{}': virtual_net plugin requires proxy type tcp",
                p.name
            ));
        }
        if cfg.virtual_net.address.is_empty() {
            return Err(format!(
                "proxy '{}': virtual_net plugin requires [virtualNet] address",
                p.name
            ));
        }
        if cfg
            .virtual_net
            .address
            .parse::<std::net::Ipv4Addr>()
            .is_err()
        {
            return Err(format!(
                "proxy '{}': invalid [virtualNet] address [{}]",
                p.name, cfg.virtual_net.address
            ));
        }
    }
    for v in cfg.visitors.iter().filter(|v| is_virtual_net_visitor(v)) {
        let Some(plugin) = &v.plugin else {
            continue;
        };
        if plugin.destination_ip.is_empty() {
            return Err(format!(
                "visitor '{}': virtual_net plugin requires destinationIP",
                v.name
            ));
        }
        if plugin.destination_ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "visitor '{}': invalid destination IP address [{}]",
                v.name, plugin.destination_ip
            ));
        }
    }
    Ok(())
}

fn is_virtual_net_visitor(v: &VisitorConfig) -> bool {
    v.plugin
        .as_ref()
        .is_some_and(|p| p.plugin_type == "virtual_net")
}

fn is_virtual_net_proxy_plugin(p: &ProxyConfig) -> bool {
    p.plugin
        .as_ref()
        .is_some_and(|pl| pl.plugin_type == "virtual_net")
}

/// Reject duplicate proxy or visitor names. Go frp v0.70.0 compat:
/// proxies and visitors are keyed by name, and duplicates would otherwise
/// be silently overwritten with no error (Go) or logged as a warning (Rust).
///
/// Cross-type duplicates (same name used for a proxy AND a visitor) are
/// allowed because they live in separate namespaces (Go frp behavior).
pub(super) fn validate_no_duplicate_names(
    proxies: &[ProxyConfig],
    visitors: &[VisitorConfig],
) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(proxies.len());
    for p in proxies {
        if !seen.insert(&p.name) {
            return Err(format!("proxy name [{}] is duplicated", p.name));
        }
    }

    seen.clear();
    for v in visitors {
        if !seen.insert(&v.name) {
            return Err(format!("visitor name [{}] is duplicated", v.name));
        }
    }

    Ok(())
}
