use super::client::{AuthClientConfig, ClientConfig, ProxyConfig, VisitorConfig};
use super::normalize::{
    expand_env_vars, expand_template_functions, normalize_client_config, normalize_server_config,
    toml_to_json,
};
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
/// Parse a bandwidth limit like Go frp `types.BandwidthQuantity`:
/// - case-SENSITIVE "KB"/"MB" suffix ("kb"/"mb" are rejected like Go's
///   "unit not support");
/// - bare numbers and other suffixes are invalid;
/// - an empty string, or a non-positive number, means NO limit
///   (returns Some(0); Go's limiter treats bytes <= 0 as no limiter).
pub fn parse_bandwidth_limit(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    let (num_str, mult) = {
        if let Some(fstr) = s.strip_suffix("MB") {
            (fstr.trim(), 1_048_576u64)
        } else {
            let fstr = s.strip_suffix("KB")?;
            (fstr.trim(), 1024u64)
        }
    };
    let num: f64 = num_str.parse().ok()?;
    if num <= 0.0 {
        // Go: 0 / negative values mean no limit (NewBandwidthLimiter returns
        // nil for bytes <= 0).
        return Some(0);
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
            // Go frp v0.70.1 compat (util.ParseRangeNumbers): a reversed range
            // (max < min) is a config error, not silently swapped (audit task
            // 9 finding 7).
            if end < start {
                return Err(format!(
                    "invalid allow_ports entry '{part}': range number is invalid"
                ));
            }
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
    expand_env_vars(&mut value);
    expand_template_functions(&mut value);
    let web_server_tls_enable_set = ConfigPresence::web_server_tls_enable_set_in(&value);
    normalize_server_config(&mut value);
    let mut presence = ConfigPresence::from_normalized_value(&value);
    presence.web_server_tls_enable_set = web_server_tls_enable_set;
    let json_value = toml_to_json(value);
    let mut cfg: ServerConfig =
        serde_json::from_value(json_value).map_err(|e| format!("config validation error: {e}"))?;
    validate_server_config(&mut cfg)?;
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
    expand_env_vars(&mut value);
    expand_template_functions(&mut value);
    let web_server_tls_enable_set = ConfigPresence::web_server_tls_enable_set_in(&value);
    normalize_client_config(&mut value);
    let mut presence = ConfigPresence::from_normalized_value(&value);
    presence.web_server_tls_enable_set = web_server_tls_enable_set;
    let mut cfg: ClientConfig = serde_json::from_value(toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    validate_client_config(&mut cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

/// Presence flags for fields whose Go default depends on whether the user
/// explicitly configured them. Computed from the normalized TOML value so
/// serde defaults cannot be confused with explicit values.
///
/// One flag is the exception to "from the normalized value": the
/// `[webServer.tls]` / `[web_server.tls]` `enable` key is **removed** by
/// `normalize_web_server_section`, so `ConfigPresence::web_server_tls_enable_set_in`
/// has to read the value *before* normalization. See the flag's own doc.
///
/// Public because the binaries own the diagnostic that the loader can no longer
/// emit: on the `-c` path the config is loaded **before** `init_logging`, so a
/// `tracing::warn` from inside the loader has no subscriber to reach. The
/// binaries re-emit it after `init_logging` via
/// [`ConfigPresence::warn_inert_web_server_tls_enable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigPresence {
    pub(super) server_heartbeat_timeout_set: bool,
    pub(super) client_heartbeat_interval_set: bool,
    pub(super) client_heartbeat_timeout_set: bool,
    /// `[webServer.tls]` / `[web_server.tls]` — top-level or under `[common]`,
    /// in either key case, or in an `includes` file — wrote an `enable` key. The
    /// **value** is deliberately not carried: the loader drops the key before
    /// serde, and the diagnostic is about the key being inert in every
    /// combination (`enable = true` with no pair is the one that silently
    /// serves plaintext HTTP; `enable = false` beside a valid pair is the one
    /// where TLS stays on against the written value). See
    /// [`ConfigPresence::web_server_tls_enable_set_in`] for the four places the
    /// nested table can come from, and why the spellings are checked in that
    /// order.
    pub(super) web_server_tls_enable_set: bool,
}

/// The `[web_server.tls] enable` diagnostic, in one place so `frps` and `frpc`
/// cannot drift. Callers gate it on
/// [`ConfigPresence::web_server_tls_enable_set`]; it is emitted **after**
/// `init_logging`, which is the whole point of the presence flag.
///
/// The sites that call it are the ones with a log sink: `frps`'s two startup
/// paths, `frpc`'s two startup paths plus `frpc verify`, and the two in-process
/// **reloads** (`frp-server`'s `Service::reload`, `frp-client`'s
/// `reload_from_sources`) — one record per load, so a reload adds one rather
/// than replacing the startup record. Loading from the library
/// (`load_*_config_from_str`) is silent by design: the `frpc` admin API's config
/// GET and its validate-before-write both go through it, and `frps verify` never
/// installs a subscriber; the record those paths used to get from the loader is
/// gone (filed in `TODO.md`).
pub const WEB_SERVER_TLS_ENABLE_INERT_WARNING: &str = "web_server.tls.enable has no \
     effect: the dashboard HTTPS server is enabled by a non-empty `cert_file` + `key_file` \
     pair; without that pair the dashboard serves plaintext HTTP";

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

    /// Did the file write `[webServer.tls]` / `[web_server.tls]` `enable`?
    ///
    /// Must be called on the **raw, pre-normalization** value: both normalizers
    /// remove the whole nested `tls` table (`normalize_web_server_section`), so
    /// after normalization the key is unrecoverable.
    ///
    /// The nested table can arrive four ways, and they are checked in the order
    /// the normalizers resolve them — both moves are `or_insert`, so the first
    /// candidate present wins and the later ones are dropped **whole**, nested
    /// `tls` included:
    ///
    /// 1. top-level `web_server`;
    /// 2. `[common] web_server`, flattened to the top level by
    ///    `table.entry(k).or_insert(v)` (`[common]` is a documented spelling —
    ///    `docs/config.md` — and this key reaches the same removal site from
    ///    there, e.g. `[common.web_server.tls] enable`, its inline
    ///    `common = { … }` form, or the same shape in an `includes` file, which
    ///    `process_includes` deep-merges before this runs);
    /// 3. top-level `webServer`, renamed by
    ///    `table.entry("web_server").or_insert(v)`;
    /// 4. `[common] webServer`, flattened then renamed.
    ///
    /// Stopping at the first candidate whose **key is present** (rather than the
    /// first that is a table) is what reproduces the `or_insert` semantics: a
    /// present-but-not-a-table `web_server` stops the normalizers too.
    ///
    /// `.ini` never matches: the INI reader stores `[web_server.tls]` as the
    /// literal top-level key `web_server.tls`, which is not a table in
    /// `web_server` (pre-existing, filed in `TODO.md`).
    pub(super) fn web_server_tls_enable_set_in(value: &toml::Value) -> bool {
        let Some(table) = value.as_table() else {
            return false;
        };
        let common = table.get("common").and_then(toml::Value::as_table);
        let candidates = [
            table.get("web_server"),
            common.and_then(|c| c.get("web_server")),
            table.get("webServer"),
            common.and_then(|c| c.get("webServer")),
        ];
        for candidate in candidates {
            let Some(section) = candidate else {
                continue;
            };
            return section
                .as_table()
                .and_then(|ws| ws.get("tls"))
                .and_then(toml::Value::as_table)
                .is_some_and(|tls| tls.contains_key("enable"));
        }
        false
    }

    /// Whether the loaded file wrote `[webServer.tls]` / `[web_server.tls]`
    /// `enable` — top-level or under `[common]`, in either key case — the
    /// condition for [`Self::warn_inert_web_server_tls_enable`].
    pub fn web_server_tls_enable_set(&self) -> bool {
        self.web_server_tls_enable_set
    }

    /// Emit [`WEB_SERVER_TLS_ENABLE_INERT_WARNING`] when the key was written,
    /// once per load.
    ///
    /// Called by each load site that has a log sink — `frps`'s two startup
    /// paths, `frpc`'s two startup paths, `frpc verify`, and both in-process
    /// reloads — because the loader itself cannot emit it (see the type doc).
    /// The sites without a sink (`frps verify`) and the library loaders
    /// (`load_*_config_from_str`, used by the `frpc` admin API) do not call it;
    /// that gap is filed in `TODO.md`.
    ///
    /// **Warned whenever the key is written, pair or no pair.** The key is inert
    /// in all four combinations, so "does the key do anything" is false in all
    /// four; gating on the pair would silence `enable = false` beside a valid
    /// pair, which is the shape where TLS stays **on** against the written value
    /// (the reason the "wire `enable` to the pair" alternative was rejected) and
    /// where this warning is the only signal. The cost of that choice is one
    /// inert-but-harmless record for `enable = false` with no pair; the message
    /// text is written to be true in every combination. Pinned by
    /// `nested_web_server_tls_enable_warns_once_and_stays_inert`
    /// (`frp-core/tests/web_server_tls_enable_warning.rs`).
    pub fn warn_inert_web_server_tls_enable(&self) {
        if self.web_server_tls_enable_set {
            tracing::warn!("{}", WEB_SERVER_TLS_ENABLE_INERT_WARNING);
        }
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

        // Go frp v0.70.1 compat: validation.ValidateProxyConfigurerForClient
        // (pkg/config/v1/validation/proxy.go), ported per-type checks
        // (audit task 9 finding 8).

        // c.Name == "" → "name should not be empty".
        if p.name.is_empty() {
            return Err("proxy: name should not be empty".into());
        }

        // proxyProtocolVersion must be "", "v1", or "v2".
        if !matches!(p.proxy_protocol_version.as_str(), "" | "v1" | "v2") {
            return Err(format!(
                "proxy '{}': not support proxy protocol version: {}",
                p.name, p.proxy_protocol_version
            ));
        }

        // healthCheck.type must be "", "tcp", or "http"; "http" requires a path.
        if !matches!(p.health_check_type.as_str(), "" | "tcp" | "http") {
            return Err(format!(
                "proxy '{}': not support health check type: {}",
                p.name, p.health_check_type
            ));
        }
        if p.health_check_type == "http" && p.health_check_url.is_empty() {
            return Err(format!(
                "proxy '{}': health check path should not be empty",
                p.name
            ));
        }

        // HTTP/HTTPS/TCPMux proxies need subdomain or custom domains
        // (validateDomainConfigForClient: "subdomain and custom domains
        // should not be both empty").
        if matches!(p.proxy_type.as_str(), "http" | "https" | "tcpmux")
            && p.subdomain.is_empty()
            && p.custom_domains.is_empty()
        {
            return Err(format!(
                "proxy '{}': subdomain and custom domains should not be both empty",
                p.name
            ));
        }

        // '.' and '*' are not supported in subdomain (validateDomainConfigForServer).
        if (p.subdomain.contains('.') || p.subdomain.contains('*'))
            && matches!(p.proxy_type.as_str(), "http" | "https" | "tcpmux")
        {
            return Err(format!(
                "proxy '{}': '.' and '*' are not supported in subdomain",
                p.name
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
        for h in &p.health_check_http_headers {
            let name = &h.name;
            let value = &h.value;
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

    // Client-credentials validation only applies to the OIDC method. The
    // comparison is exact, and that is now the *validated* form of the field:
    // `validate_client_config` has already run the one
    // `crate::auth::complete_auth_method` + `parse_auth_method` policy over
    // it, so `method` here is exactly `"token"` or `"oidc"` (or the field is
    // absent). Before that, `method = "OIDC"` skipped this whole block and the
    // config loaded with no `clientID`.
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

pub(super) fn validate_server_config(cfg: &mut ServerConfig) -> Result<(), String> {
    // `auth.method` first, in Go's order: `ServerConfig.Complete()` runs
    // `Auth.Complete()` — the empty→token fill, `pkg/config/v1/server.go:136-139`
    // — and only then does `ValidateServerConfig` (`validation/server.go:31`)
    // check the value. The load path must fill before it checks, or
    // `method = ""` (Go's "use the default", and the state of every config with
    // no `[auth] method` key at all, since serde's string default is `""`) would
    // be rejected as an unrecognised method.
    cfg.auth.complete()?;
    crate::auth::parse_auth_method(&cfg.auth.method)?;
    validate_auth_token_source(&cfg.auth.token, &cfg.auth.token_source)?;
    // Go frp v0.71.0: unknown feature gates are config errors, not a silent
    // fail-open (featuregate SetFromMap "unrecognized feature gate").
    if !cfg.feature.gates.is_empty() {
        crate::feature_gate::validate_keys(&cfg.feature.gates)
            .map_err(|e| format!("server config: {e}"))?;
    }
    // Go frp v0.71.0: a negative transport.maxPoolCount is invalid.
    if cfg.transport.max_pool_count < 0 {
        return Err(format!(
            "server config: invalid transport.maxPoolCount {}, must be non-negative",
            cfg.transport.max_pool_count
        ));
    }
    // An http_plugins entry with neither addr nor path would produce a
    // malformed "http://?version=..." request at runtime — fail at load time.
    for plugin in &cfg.http_plugins {
        // A path alone would produce the malformed "http:///x" — Go's
        // HTTPPluginOptions.Addr is required. Also reject degenerate addrs
        // like "http://" or "/" that strip to nothing after the scheme.
        let bare = plugin
            .addr
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_matches('/');
        if plugin.addr.is_empty() || bare.is_empty() {
            return Err(format!(
                "server config: http_plugins entry '{}' has no addr",
                plugin.name
            ));
        }
    }
    // Go frp compat: invalid allow_ports entries are config errors, not a
    // silent disable of the restriction (validation/PortsRange).
    if !cfg.allow_ports.trim().is_empty() {
        parse_allow_ports(&cfg.allow_ports).map_err(|e| format!("server config: {e}"))?;
    }
    // ServerConfig has no inline proxy definitions — proxies are registered
    // by clients at runtime. No proxy-level validation to do here.
    Ok(())
}

pub(super) fn validate_client_config(cfg: &mut ClientConfig) -> Result<(), String> {
    validate_proxy_configs(&cfg.proxies)?;
    validate_no_duplicate_names(&cfg.proxies, &cfg.visitors)?;
    // Go frp v0.71.0 validation/visitor.go:42-63 (round 10 MEDIUM): visitors
    // were never validated — an empty name/serverName or bindPort==0 loaded
    // silently and the visitor never connected. Mirror Go's checks exactly:
    // bindPort -1 (no-bind) and positive ports pass; only 0 is rejected.
    for v in &cfg.visitors {
        if v.name.is_empty() {
            return Err("visitor config: name is required".to_string());
        }
        if v.server_name.is_empty() {
            return Err(format!("visitor '{}': server name is required", v.name));
        }
        if v.bind_port == 0 {
            return Err(format!("visitor '{}': bind port is required", v.name));
        }
        // Round-8 blocker: Go v0.71.0 dispatches visitors by a type switch
        // over stcp/sudp/xtcp (validation/visitor.go ValidateVisitorConfigurer)
        // — any other type, including empty, fails with "unknown visitor
        // config type". A `type = "typo"` visitor used to load silently and
        // never connect. Mirrors frp-client/src/store.rs VALID_VISITOR_TYPES.
        if !matches!(v.visitor_type.as_str(), "stcp" | "sudp" | "xtcp") {
            return Err(format!(
                "visitor '{}': unknown visitor type '{}'",
                v.name, v.visitor_type
            ));
        }
        if v.visitor_type == "xtcp" && v.protocol != "kcp" && v.protocol != "quic" {
            return Err(format!(
                "visitor '{}': protocol should be kcp or quic",
                v.name
            ));
        }
    }
    // Negative poolCount: Go frp v0.71.0 has NO client-side check —
    // Go frpc loads the config fine and the SERVER rejects the negative at
    // login (server/control.go:438 "invalid pool count %d, must be
    // non-negative"), which frp-rs already mirrors (control/login.rs
    // "Login rejected: negative pool_count"). This is a deliberate
    // fail-fast divergence: frp-rs frpc refuses the misconfig at load
    // instead of dialing first. 0 keeps its "use the default" semantics
    // (complete_with_heartbeat_set maps 0 → 1, Go util.EmptyOr — pinned by
    // test_explicit_zero_client_pool_count_and_keepalive_use_go_defaults).
    if cfg.pool_count < 0 {
        return Err(format!(
            "client config: invalid poolCount {}, must be non-negative",
            cfg.pool_count
        ));
    }
    // Go frp v0.71.0: unknown feature gates are config errors (featuregate
    // SetFromMap "unrecognized feature gate").
    if !cfg.feature.gates.is_empty() {
        crate::feature_gate::validate_keys(&cfg.feature.gates)
            .map_err(|e| format!("client config: {e}"))?;
    }
    // Split borrows on purpose (`&cfg.token`, `&mut cfg.auth`): the
    // deprecated flat `token` key is read, never copied — the auth token is a
    // secret and this file does not clone it into a local.
    let flat_token = &cfg.token;
    if let Some(auth) = cfg.auth.as_mut() {
        // Go's `ClientCommonConfig.Complete()` runs `Auth.Complete()` — the
        // empty→token fill — at `pkg/config/v1/client.go:91`
        // (`AuthClientConfig.Complete`, `:206-209`) and *then* validation
        // checks the method (`validation/client.go:101`, reached from
        // `ValidateAllClientConfig`). So the fill has to precede the check, and
        // filling `cfg.auth` itself (not a local copy) is what makes
        // `method = ""` both start as token and hand the completed value on to
        // the service. This is the site the old `auth.method != "oidc"`
        // early-return lived at: it skipped client-credentials validation for
        // every non-exact spelling, so `method = "OIDC"` with an empty
        // `clientID` loaded silently. It is now rejected with the same text the
        // other three sites use.
        auth.complete()?;
        crate::auth::parse_auth_method(&auth.method)?;
        // `cfg.token` is the deprecated flat spelling; the nested
        // `[auth] token` wins only when the flat one is empty.
        let token: &str = if flat_token.is_empty() {
            auth.token.as_str()
        } else {
            flat_token.as_str()
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
