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

/// Expand `${ENV_VAR}` references in every string value of a `toml::Value`
/// tree, matching Go frp's Viper-based env expansion (`os.ExpandEnv`):
/// an undefined variable expands to the empty string.
///
/// Pipeline position (see `load_config_from_file`): this runs **after**
/// `process_includes` — so values merged in from include files are expanded
/// too — and **before** `normalize_*_config`, which renames/restructures the
/// tree. Expanding first keeps the canonical shape and lets `ConfigPresence`
/// and the strict key check see the expanded values.
///
/// Deliberately a minimal subset of shell-style expansion, mirroring the
/// `${...}` form Go frp actually honors:
/// - Only `${VAR}` is expanded; a bare `$VAR` is left untouched, so strings
///   that legitimately contain `$` (passwords, shell snippets) are safe.
/// - `${VAR:-default}` is **not** supported — Go's `os.ExpandEnv` has no
///   shell default-value semantics, so neither do we.
/// - `$$` expands to a literal `$` — a frp-rs extension (NOT Go
///   `os.ExpandEnv` semantics: Go has no `$$` escape, it would expand
///   `$${VAR}` to `$` + VAR's value). This is the escape hatch:
///   `$${VAR}` becomes the literal text `${VAR}`.
/// - An unclosed `${` (no closing `}`) is kept verbatim; `${}` (empty
///   name) expands to the empty string.
pub(super) fn expand_env_vars(value: &mut toml::Value) {
    match value {
        toml::Value::String(s) => *s = expand_env_vars_in_str(s),
        toml::Value::Array(arr) => {
            for v in arr.iter_mut() {
                expand_env_vars(v);
            }
        }
        toml::Value::Table(table) => {
            for (_, v) in table.iter_mut() {
                expand_env_vars(v);
            }
        }
        _ => {}
    }
}

/// Expand `${VAR}` / `$$` in a single string. Undefined variables become the
/// empty string. See [`expand_env_vars`] for the exact subset.
fn expand_env_vars_in_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(rest_after) = after.strip_prefix('$') {
            // `$$` → literal `$`.
            out.push('$');
            rest = rest_after;
        } else if let Some(inner) = after.strip_prefix('{') {
            // `${NAME}` → env value (empty string when unset).
            match inner.find('}') {
                Some(end) => {
                    let name = &inner[..end];
                    out.push_str(&std::env::var(name).unwrap_or_default());
                    rest = &inner[end + 1..];
                }
                None => {
                    // Unclosed `${` — keep it verbatim.
                    out.push_str(&rest[pos..]);
                    rest = "";
                }
            }
        } else {
            // Bare `$` not followed by `$` or `{` — keep it verbatim.
            out.push('$');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Expand `{{ parseNumberRange "..." }}` template calls in every string value
/// of a `toml::Value` tree, mirroring the Go frp template function of the
/// same name (`pkg/config/template.go`).
///
/// Go semantics (v0.70.1, confirmed against
/// https://github.com/fatedier/frp/blob/v0.70.1/pkg/config/template.go and
/// `util.ParseRangeNumbers` in pkg/util/util/util.go):
/// - The argument is a comma-separated list of segments; each segment is
///   either a single number `N` or an inclusive range `N-M` (step 1,
///   N <= M). Whitespace around the whole expression and around each
///   component is trimmed.
/// - A segment with more than one `-`, a non-numeric component, or N > M
///   makes the whole call an error (Go then fails the entire template
///   render, which aborts config loading).
/// - Output is a list of numbers; Go's text/template renders the returned
///   `[]int64` in its default `fmt` form, i.e. `[7000 7001 7002]`.
///
/// frp-rs differences (deliberate, see the subset note below): we emit a
/// comma-separated, space-free number string — the form Go frp itself
/// consumes for multi-port settings like `allow_ports` — keep invalid
/// expressions verbatim with a warning instead of failing the whole config,
/// and constrain values to the TCP/UDP port range 0..=65535.
///
/// Pipeline position: this runs **after** `expand_env_vars` so an argument
/// like `{{ parseNumberRange "${PORT_RANGE}" }}` has its env reference
/// expanded first (env first, template second — see `load_config_from_file`).
///
/// Deliberate minimal subset (frp-rs has a zero-new-dependency policy and
/// does not embed a template engine):
/// - Only the exact call form `{{ parseNumberRange "expr" }}` is recognized,
///   with optional ASCII whitespace after `{{`, around the function name and
///   before `}}`. No other template syntax (variables, control flow, other
///   functions) is processed — anything that does not match is left verbatim.
/// - A single string may contain several calls; each is expanded in place
///   and the surrounding text is preserved.
/// - Invalid expressions (non-numeric, N > M, out of 0..=65535) are kept
///   verbatim and a `tracing::warn` is emitted.
pub(super) fn expand_template_functions(value: &mut toml::Value) {
    match value {
        toml::Value::String(s) => *s = expand_template_functions_in_str(s),
        toml::Value::Array(arr) => {
            for v in arr.iter_mut() {
                expand_template_functions(v);
            }
        }
        toml::Value::Table(table) => {
            for (_, v) in table.iter_mut() {
                expand_template_functions(v);
            }
        }
        _ => {}
    }
}

/// Expand `{{ parseNumberRange "..." }}` calls in a single string.
/// See [`expand_template_functions`] for the exact recognized subset.
fn expand_template_functions_in_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("{{") {
        match try_parse_template_call(&rest[pos..]) {
            Some((consumed, replacement)) => {
                out.push_str(&rest[..pos]);
                out.push_str(&replacement);
                rest = &rest[pos + consumed..];
            }
            None => {
                // Not a recognized parseNumberRange call — keep `{{`
                // verbatim and keep scanning for the next call.
                out.push_str(&rest[..pos + 2]);
                rest = &rest[pos + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Try to parse one `{{ parseNumberRange "expr" }}` call at the start of `s`
/// (which must begin with `{{`). On success returns the number of bytes
/// consumed (the whole call) and the replacement text — the expanded list,
/// or the original call verbatim when the expression is invalid (after a
/// warning). Returns `None` when the text is not a well-formed
/// parseNumberRange call at all (kept verbatim by the caller).
fn try_parse_template_call(s: &str) -> Option<(usize, String)> {
    let bytes = s.as_bytes();
    debug_assert!(bytes.starts_with(b"{{"));
    let mut i = skip_ws(bytes, 2);
    if !bytes.get(i..)?.starts_with(b"parseNumberRange") {
        return None;
    }
    i += b"parseNumberRange".len();
    i = skip_ws(bytes, i);
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let expr_start = i;
    let expr_end = bytes[i..].iter().position(|&b| b == b'"').map(|p| i + p)?; // Unclosed quote — not a call.
    let expr = &s[expr_start..expr_end];
    i = expr_end + 1;
    i = skip_ws(bytes, i);
    if !bytes.get(i..)?.starts_with(b"}}") {
        return None;
    }
    i += 2;
    let original = &s[..i];
    match expand_number_range_expr(expr) {
        Some(expansion) => Some((i, expansion)),
        None => {
            tracing::warn!(
                original = %original,
                expr,
                "invalid {{ parseNumberRange ... }} expression in config; leaving it verbatim"
            );
            Some((i, original.to_string()))
        }
    }
}

/// Skip ASCII whitespace (space, tab, CR, LF) starting at byte offset `i`.
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while let Some(&b) = bytes.get(i) {
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Cap on the number of numbers a single range expression may produce.
/// Go's `util.ParseRangeNumbers` expands `0-65535` into 65536 entries; a
/// hostile config could ask for the full port space (or an arbitrarily long
/// comma list), ballooning into ~450 KB of comma-joined text here and up to
/// 65536 per-port proxies in the legacy `[range:...]` INI path. Real configs
/// stay far below this; exceeding it makes the expression invalid (warned
/// and kept verbatim, same as any other invalid segment).
const MAX_RANGE_EXPANSION_NUMBERS: usize = 4096;

/// Expand a Go-style range expression (`"7000-7003"`, `"7000,7005"`) into a
/// comma-separated list of numbers, following `util.ParseRangeNumbers`:
/// split on `,`; each segment is a single number or an inclusive `N-M`
/// range (step 1, N <= M). Returns `None` for any invalid segment or when
/// the expansion would exceed [`MAX_RANGE_EXPANSION_NUMBERS`].
fn expand_number_range_expr(expr: &str) -> Option<String> {
    let mut numbers: Vec<u32> = Vec::new();
    for segment in expr.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            return None;
        }
        let parts: Vec<&str> = segment.split('-').collect();
        match parts.as_slice() {
            [single] => {
                numbers.push(parse_port_num(single)?);
                if numbers.len() > MAX_RANGE_EXPANSION_NUMBERS {
                    return None;
                }
            }
            [start, end] => {
                let start = parse_port_num(start)?;
                let end = parse_port_num(end)?;
                if start > end {
                    return None;
                }
                // `take` caps the materialization BEFORE the range is fully
                // expanded; the over-cap check then rejects the expression.
                let remaining = MAX_RANGE_EXPANSION_NUMBERS - numbers.len();
                numbers.extend((start..=end).take(remaining.saturating_add(1)));
                if numbers.len() > MAX_RANGE_EXPANSION_NUMBERS {
                    return None;
                }
            }
            // More than one `-` in a segment (e.g. "1-2-3") — invalid.
            _ => return None,
        }
    }
    Some(
        numbers
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// Parse a decimal port number in the valid range 0..=65535.
/// Values outside that range (including negatives) are rejected — a frp-rs
/// constraint on top of Go's unbounded int64 arithmetic, since range
/// expansion is only meaningful for ports here.
fn parse_port_num(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok().filter(|&n| n <= 65535)
}

/// Move matching top-level keys into a sub-table, optionally stripping known prefixes.
/// e.g. `flatten_to_table(t, &["log_file","log_level"], "log", &["log_"])`
/// Move legacy top-level keys into the `web_server` sub-table (Go
/// pkg/config/legacy conversion: admin_*/dashboard_* → WebServer.*).
fn legacy_web_server_keys(table: &mut toml::Table, mappings: &[(&str, &str)]) {
    let mut items: Vec<(String, toml::Value)> = Vec::new();
    for (from, to) in mappings {
        if let Some(v) = table.remove(*from) {
            items.push(((*to).to_string(), v));
        }
    }
    if !items.is_empty() {
        let target_table = table
            .entry("web_server".to_string())
            .or_insert_with(|| toml::Value::Table(Default::default()));
        if let toml::Value::Table(ref mut t) = target_table {
            // Existing explicit [web_server] values take precedence.
            for (k, v) in items {
                t.entry(k).or_insert(v);
            }
        }
    }
}

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
    // Expand `${ENV_VAR}` references here, after includes are deep-merged
    // (so include-file values are covered) and before normalization (which
    // renames/restructures keys). See `expand_env_vars` for the exact subset.
    expand_env_vars(&mut value);
    // Expand `{{ parseNumberRange "..." }}` template calls after env expansion
    // (so an argument like "${PORT_RANGE}" is expanded first) and before
    // normalization. See `expand_template_functions` for the exact subset.
    expand_template_functions(&mut value);
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

        // Go legacy INI uses `authentication_method` (not `auth_method`) —
        // map it into [auth].method before the auth flatten pass so OIDC
        // auth does not silently fall back to token.
        if let Some(v) = table.remove("authentication_method") {
            let auth_table = table
                .entry("auth".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(auth) = auth_table {
                auth.entry("method".to_string()).or_insert(v);
            }
        }

        // Go legacy INI server keys authenticate_heartbeats /
        // authenticate_new_work_conns -> [auth] additional_auth_scopes
        // (Go conversion.go AdditionalScopes). Client-side equivalents live
        // in normalize_client_config.
        let mut extra_scopes: Vec<String> = Vec::new();
        if table
            .remove("authenticate_heartbeats")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            extra_scopes.push("HeartBeats".to_string());
        }
        if table
            .remove("authenticate_new_work_conns")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            extra_scopes.push("NewWorkConns".to_string());
        }
        if !extra_scopes.is_empty() {
            let auth_table = table
                .entry("auth".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(auth) = auth_table {
                let mut scopes: Vec<String> = auth
                    .get("additional_auth_scopes")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                scopes.extend(extra_scopes);
                auth.insert(
                    "additional_auth_scopes".to_string(),
                    Value::Array(scopes.into_iter().map(Value::String).collect()),
                );
            }
        }

        // Go legacy INI keys: top-level dashboard_* -> [web_server] (Go
        // pkg/config/legacy conversion.go DashboardAddr/Port/User/Pwd/...).
        // Runs AFTER the [common] merge so keys from [common] migrate too.
        legacy_web_server_keys(
            table,
            &[
                ("dashboard_addr", "addr"),
                ("dashboard_port", "port"),
                ("dashboard_user", "user"),
                ("dashboard_pwd", "password"),
                ("assets_dir", "assets_dir"),
                ("dashboard_assets_dir", "assets_dir"),
                ("dashboard_tls_cert_file", "tls_cert_file"),
                ("dashboard_tls_key_file", "tls_key_file"),
                ("pprof_enable", "pprof_enable"),
            ],
        );

        // Go legacy INI: dashboard_tls_mode (bool) is a TLS enable switch. In
        // frp-rs the dashboard TLS is driven by non-empty cert/key (there is
        // no separate enable flag), so the key is consumed as a no-op —
        // removing it keeps strict mode from rejecting a valid Go key. When
        // dashboard_tls_cert_file/key_file are also set, TLS is enabled by
        // them regardless of this switch (same effective behavior as Go).
        let _ = table.remove("dashboard_tls_mode");

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

        // Go allowPorts is an array of {start,end} ranges (types.PortsRange);
        // normalize to the existing comma-separated string form. A
        // `{single=N}` entry (Go PortsRange.Single) becomes `{single=N}` so
        // parse_allow_ports keeps the single-port semantics (audit task 9
        // finding 6 — previously emitted "0-0", which is rejected).
        if let Some(Value::Array(ranges)) = table.remove("allowPorts") {
            let mut parts = Vec::new();
            for range in ranges {
                if let Some(t) = range.as_table() {
                    if let Some(single) = t.get("single").and_then(Value::as_integer) {
                        parts.push(format!("{{single={single}}}"));
                    } else {
                        let start = t.get("start").and_then(Value::as_integer).unwrap_or(0);
                        let end = t.get("end").and_then(Value::as_integer).unwrap_or(start);
                        parts.push(format!("{start}-{end}"));
                    }
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
                "oidc_token_endpoint_url",
                "oidc_skip_expiry_check",
                "oidc_skip_issuer_check",
            ],
            "auth",
            // Only `auth_` is stripped: the serde fields are oidc_* (they keep
            // their prefix), so stripping "oidc_" produced auth.client_id /
            // auth.issuer which no field matches — silently dropped.
            &["auth_"],
        );
        flatten_to_table(
            table,
            &["log_file", "log_level", "log_max_days", "log_format"],
            "log",
            &["log_"],
        );

        // Go legacy INI: disable_log_color -> [log] disable_print_color (Go
        // pkg/config/legacy conversion.go Log.DisablePrintColor — mirrors the
        // client-side mapping below).
        if let Some(v) = table.remove("disable_log_color") {
            let lg = table
                .entry("log".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(l) = lg {
                l.entry("disable_print_color".to_string()).or_insert(v);
            }
        }

        // Go legacy INI `log_way` (pkg/config/legacy server.go LogWay
        // `ini:"log_way"`): accepted by Go and silently dropped — the legacy
        // conversion never maps it into the new config (conversion.go copies
        // only LogFile/LogLevel/LogMaxDays). Consume it here so strict mode
        // never sees it.
        let _ = table.remove("log_way");

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
                "tcp_keepalive",
                "tcpKeepalive",
                "tcp_send_buffer_size",
                "tcp_recv_buffer_size",
                "tcpSendBuffer",
                "tcpRecvBuffer",
            ],
            "transport",
            &[],
        );

        // Go legacy INI server [plugin.xxx] sections -> [http_plugins] array
        // (Go legacy/server.go loadHTTPPluginOpt).
        let plugin_sections: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("plugin."))
            .cloned()
            .collect();
        if !plugin_sections.is_empty() {
            let mut plugins: Vec<toml::Value> = Vec::new();
            for name in plugin_sections {
                let Some(removed) = table.remove(&name) else {
                    continue;
                };
                let Value::Table(mut st) = removed else {
                    tracing::warn!(
                        "legacy INI [plugin.xxx]: section '{}' is not a table; kept verbatim",
                        name
                    );
                    table.insert(name, removed);
                    continue;
                };
                st.insert(
                    "name".to_string(),
                    Value::String(name.trim_start_matches("plugin.").to_string()),
                );
                plugins.push(Value::Table(st));
            }
            let arr = table
                .entry("http_plugins".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            match arr {
                Value::Array(a) => a.extend(plugins),
                other => {
                    tracing::warn!(
                        "legacy INI [plugin.xxx]: existing 'http_plugins' is not an array                          ({:?}); plugin sections skipped",
                        other
                    );
                }
            }
        }

        // Go legacy INI top-level quic_* keys -> [transport.quic]
        // (Go legacy server.go QUICKeepalivePeriod/QUICMaxIdleTimeout/
        // QUICMaxIncomingStreams). Runs after the transport fold above.
        let quic_keys: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("quic_"))
            .cloned()
            .collect();
        if !quic_keys.is_empty() {
            // Detach the values first so the [transport.quic] borrow below
            // does not overlap a table.remove().
            let mut folded: Vec<(String, toml::Value)> = Vec::new();
            let mut kept: Vec<(String, toml::Value)> = Vec::new();
            for k in quic_keys {
                let Some(v) = table.remove(&k) else { continue };
                // Only the three documented legacy keys are folded; unknown
                // quic_* keys stay top-level so strict mode reports them
                // clearly instead of hiding them.
                let flat_key = match k.as_str() {
                    "quic_keepalive_period" => Some("keepalive_period"),
                    "quic_max_idle_timeout" => Some("max_idle_timeout"),
                    "quic_max_incoming_streams" => Some("max_incoming_streams"),
                    _ => None,
                };
                match flat_key {
                    Some(fk) => folded.push((fk.to_string(), v)),
                    None => kept.push((k, v)),
                }
            }
            if !folded.is_empty() {
                let tr = table
                    .entry("transport".to_string())
                    .or_insert_with(|| Value::Table(Default::default()));
                if let Value::Table(transport) = tr {
                    let quic = transport
                        .entry("quic".to_string())
                        .or_insert_with(|| Value::Table(Default::default()));
                    if let Value::Table(q) = quic {
                        for (k, v) in folded {
                            q.entry(k).or_insert(v);
                        }
                    }
                }
            }
            for (k, v) in kept {
                table.insert(k, v);
            }
        }

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
                        "skipAudience" => "oidc_skip_audience",
                        "additionalAudience" => "oidc_additional_audience",
                        "trustedCaFile" => "oidc_tls_trusted_ca_file",
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

        // (removed MEDIUM-6: http_plugins[*].addr+path → url back-fill. The
        // canonical form is now Go's addr+path; the legacy single `url` field
        // is handled by the `url` serde alias on HttpPluginConfig.addr —
        // emitting a synthesized "url" key alongside addr would duplicate the
        // field.)

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
                    let sub_key = key
                        .strip_prefix("meta_")
                        .expect("key starts_with meta_ — filtered into meta_keys above")
                        .to_string();
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

        // Go legacy INI proxy/visitor sections: [web], [ssh], [range:xxx],
        // [plugin:xxx]. A top-level section table carrying a `type` key is a
        // proxy (or a visitor when role=visitor). [range:xxx] templates are
        // expanded into per-port proxies {prefix}_{i} (Go
        // renderRangeProxyTemplates — local/remote port lists must match in
        // length).
        collect_legacy_ini_proxy_sections(table);

        // Go legacy INI keys: top-level admin_* -> [web_server] (Go
        // pkg/config/legacy conversion.go AdminAddr/Port/User/Pwd/...).
        // Runs AFTER the [common] merge so keys from [common] migrate too.
        legacy_web_server_keys(
            table,
            &[
                ("admin_addr", "addr"),
                ("admin_port", "port"),
                ("admin_user", "user"),
                ("admin_pwd", "password"),
                ("assets_dir", "assets_dir"),
                ("pprof_enable", "pprof_enable"),
            ],
        );

        // Rename canonical Go camelCase section names (mirrors the server
        // path above).
        if let Some(v) = table.remove("webServer") {
            table.entry("web_server").or_insert(v);
        }
        // Normalize canonical Go `[webServer.tls]` (nested certFile/keyFile)
        // into the flat `web_server.tls_cert_file`/`tls_key_file` fields for
        // the client admin server TLS too — without this the nested `tls`
        // table is silently dropped by the ClientConfig deserializer.
        normalize_web_server_section(table);

        // Go legacy INI uses `authentication_method` (not `auth_method`) —
        // map it into [auth].method (mirrors the server-side fix).
        if let Some(v) = table.remove("authentication_method") {
            let auth_table = table
                .entry("auth".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(auth) = auth_table {
                auth.entry("method".to_string()).or_insert(v);
            }
        }

        // Go legacy INI: authenticate_heartbeats / authenticate_new_work_conns
        // -> [auth] additional_scopes (Go conversion.go AdditionalScopes).
        let mut extra_scopes: Vec<String> = Vec::new();
        if table
            .remove("authenticate_heartbeats")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            extra_scopes.push("HeartBeats".to_string());
        }
        if table
            .remove("authenticate_new_work_conns")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            extra_scopes.push("NewWorkConns".to_string());
        }
        if !extra_scopes.is_empty() {
            let auth_table = table
                .entry("auth".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(auth) = auth_table {
                let mut scopes: Vec<String> = auth
                    .get("additional_auth_scopes")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                scopes.extend(extra_scopes);
                auth.insert(
                    "additional_auth_scopes".to_string(),
                    Value::Array(scopes.into_iter().map(Value::String).collect()),
                );
            }
        }

        // Go legacy INI: http_proxy -> [transport] proxy_url.
        if let Some(v) = table.remove("http_proxy") {
            let tr = table
                .entry("transport".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(t) = tr {
                t.entry("proxy_url".to_string()).or_insert(v);
            }
        }

        // Go legacy INI: disable_log_color -> [log] disable_print_color.
        if let Some(v) = table.remove("disable_log_color") {
            let lg = table
                .entry("log".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(l) = lg {
                l.entry("disable_print_color".to_string()).or_insert(v);
            }
        }

        // Go legacy INI: oidc_additional_endpoint_params (flattened map keys
        // prefixed `oidc_additional_`) -> [auth] additional_endpoint_params
        // (top-level, matching the MEDIUM-5 flatten target).
        let oidc_params: Vec<(String, Value)> = table
            .iter()
            .filter(|(k, _)| k.starts_with("oidc_additional_"))
            .map(|(k, v)| {
                (
                    k.trim_start_matches("oidc_additional_").to_string(),
                    v.clone(),
                )
            })
            .collect();
        if !oidc_params.is_empty() {
            for k in oidc_params.iter().map(|(k, _)| k.clone()) {
                let _ = table.remove(&format!("oidc_additional_{k}"));
            }
            let auth_table = table
                .entry("auth".to_string())
                .or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(auth) = auth_table {
                let mut params = auth
                    .get("additional_endpoint_params")
                    .and_then(Value::as_table)
                    .cloned()
                    .unwrap_or_default();
                for (k, v) in oidc_params {
                    params.insert(k, v);
                }
                auth.insert(
                    "additional_endpoint_params".to_string(),
                    Value::Table(params),
                );
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
                "oidc_token_endpoint_url",
                "oidc_client_id",
                "oidc_client_secret",
                "oidc_scope",
                "oidc_proxy_url",
            ],
            "auth",
            // Only `auth_` is stripped (oidc_* fields keep their prefix).
            &["auth_"],
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

        // Go legacy INI top-level quic_* keys -> [transport.quic]
        // (Go legacy client.go QUICKeepalivePeriod/QUICMaxIdleTimeout/
        // QUICMaxIncomingStreams; conversion.go maps them into
        // Transport.QUIC). Runs BEFORE the transport fold below so the
        // folded [transport.quic] table is flattened to the top-level
        // `quic` key together with an explicit [transport.quic].
        let quic_keys: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("quic_"))
            .cloned()
            .collect();
        if !quic_keys.is_empty() {
            // Detach the values first so the [transport.quic] borrow below
            // does not overlap a table.remove().
            let mut folded: Vec<(String, toml::Value)> = Vec::new();
            let mut kept: Vec<(String, toml::Value)> = Vec::new();
            for k in quic_keys {
                let Some(v) = table.remove(&k) else { continue };
                // Only the three documented legacy keys are folded; unknown
                // quic_* keys stay top-level so strict mode reports them
                // clearly instead of hiding them.
                let flat_key = match k.as_str() {
                    "quic_keepalive_period" => Some("keepalive_period"),
                    "quic_max_idle_timeout" => Some("max_idle_timeout"),
                    "quic_max_incoming_streams" => Some("max_incoming_streams"),
                    _ => None,
                };
                match flat_key {
                    Some(fk) => folded.push((fk.to_string(), v)),
                    None => kept.push((k, v)),
                }
            }
            if !folded.is_empty() {
                let tr = table
                    .entry("transport".to_string())
                    .or_insert_with(|| Value::Table(Default::default()));
                if let Value::Table(transport) = tr {
                    let quic = transport
                        .entry("quic".to_string())
                        .or_insert_with(|| Value::Table(Default::default()));
                    if let Value::Table(q) = quic {
                        for (k, v) in folded {
                            q.entry(k).or_insert(v);
                        }
                    }
                }
            }
            for (k, v) in kept {
                table.insert(k, v);
            }
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
            &["log_file", "log_level", "log_max_days", "log_format"],
            "log",
            &["log_"],
        );

        // Go legacy INI `log_way` (pkg/config/legacy client.go LogWay
        // `ini:"log_way"`): accepted by Go and silently dropped (see the
        // server-side comment). Consume it here so strict mode never sees it.
        let _ = table.remove("log_way");

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
                    let sub_key = key
                        .strip_prefix("meta_")
                        .expect("key starts_with meta_ — filtered into meta_keys above")
                        .to_string();
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
///
/// Expand "6000-6006,6007" into the sorted list of individual ports.
/// Matches Go `util.ParseRangeNumbers` semantics; capped at
/// [`MAX_RANGE_EXPANSION_NUMBERS`] per call so a hostile range expression
/// cannot balloon into 65536 per-port proxies.
fn ini_range_numbers(s: &str) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a.trim().parse().ok()?;
            let hi: u16 = b.trim().parse().ok()?;
            if lo > hi {
                return None;
            }
            // `take` caps the materialization BEFORE the range is fully
            // expanded; the over-cap check then rejects the expression.
            let remaining = MAX_RANGE_EXPANSION_NUMBERS - out.len();
            out.extend((lo..=hi).take(remaining.saturating_add(1)));
            if out.len() > MAX_RANGE_EXPANSION_NUMBERS {
                return None;
            }
        } else {
            out.push(part.parse().ok()?);
            if out.len() > MAX_RANGE_EXPANSION_NUMBERS {
                return None;
            }
        }
    }
    Some(out)
}

/// Collect Go legacy INI proxy/visitor sections into `[proxies]`/`[visitors]`.
fn collect_legacy_ini_proxy_sections(table: &mut toml::Table) {
    use toml::Value;

    // Known non-proxy top-level sections are never collected even if they
    // happen to carry a `type` key.
    const KNOWN_SECTIONS: &[&str] = &[
        "common",
        "proxies",
        "visitors",
        "web_server",
        "auth",
        "log",
        "transport",
        "plugins",
        "http_plugins",
        "feature",
        "featureGates",
        "includes",
        "ssh_tunnel_gateway",
        "observability",
        "vnet",
        "store",
    ];
    let sections: Vec<String> = table
        .keys()
        .filter(|k| {
            !KNOWN_SECTIONS.contains(&k.as_str())
                && matches!(table.get(*k), Some(Value::Table(t)) if t.contains_key("type"))
        })
        .cloned()
        .collect();

    for section_name in sections {
        let Value::Table(mut st) = table.remove(&section_name).unwrap() else {
            continue;
        };

        // Go ini.v1 []string fields: a scalar value becomes a one-element
        // array (comma-separated values were already split by ini_to_toml).
        for list_key in ["custom_domains", "locations", "allow_users"] {
            if let Some(Value::String(s)) = st.get(list_key) {
                let items: Vec<Value> = s
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| Value::String(p.to_string()))
                    .collect();
                if !items.is_empty() {
                    st.insert(list_key.to_string(), Value::Array(items));
                }
            }
        }

        if let Some(prefix) = section_name.strip_prefix("range:") {
            // Expand into {prefix}_{i} per-port proxies (Go renderRangeProxyTemplates).
            // local_port/remote_port accept a quoted string ("6000-6002") or
            // an unquoted single port (6000 — ini_to_toml makes it Integer).
            fn ini_port_numbers(v: &Value) -> Option<Vec<u16>> {
                match v {
                    Value::String(s) => ini_range_numbers(s),
                    Value::Integer(i) if *i >= 0 && *i <= i64::from(u16::MAX) => {
                        Some(vec![*i as u16])
                    }
                    _ => None,
                }
            }
            let Some(local_ports) = st.get("local_port").and_then(ini_port_numbers) else {
                tracing::warn!(
                    section = %section_name,
                    "legacy INI [range:...] section: missing or invalid local_port; skipped"
                );
                continue;
            };
            let Some(remote_ports) = st.get("remote_port").and_then(ini_port_numbers) else {
                tracing::warn!(
                    section = %section_name,
                    "legacy INI [range:...] section: missing or invalid remote_port; skipped"
                );
                continue;
            };
            if local_ports.len() != remote_ports.len() {
                tracing::warn!(
                    section = %section_name,
                    local = local_ports.len(),
                    remote = remote_ports.len(),
                    "legacy INI [range:...] section: local/remote port counts differ; skipped"
                );
                continue;
            }
            for (i, (lp, rp)) in local_ports.into_iter().zip(remote_ports).enumerate() {
                let mut t = st.clone();
                t.insert("name".to_string(), Value::String(format!("{prefix}_{i}")));
                t.insert("local_port".to_string(), Value::Integer(i64::from(lp)));
                t.insert("remote_port".to_string(), Value::Integer(i64::from(rp)));
                let proxies = table
                    .entry("proxies".to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(arr) = proxies {
                    arr.push(Value::Table(t));
                }
            }
            continue;
        }

        // Regular section: name = section name (Go keeps the full name,
        // including the "plugin:" prefix).
        st.insert("name".to_string(), Value::String(section_name.clone()));

        let role = st
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("server")
            .to_string();
        st.remove("role");
        let target_key = if role == "visitor" {
            "visitors"
        } else {
            "proxies"
        };
        let arr = table
            .entry(target_key.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(arr) = arr {
            arr.push(Value::Table(st));
        }
    }
}

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
                    // Go legacy INI keys (pkg/config/legacy/proxy.go).
                    "health_check_interval_s" => "health_check_interval_seconds",
                    "health_check_timeout_s" => "health_check_timeout_seconds",
                    other => other,
                };
                let value = if k == "httpHeaders" {
                    // Go frp: healthCheck.httpHeaders is an ARRAY of
                    // {name,value} (HTTPHeader). A legacy frp-rs map form
                    // ({X = "y"}) is converted into the array shape.
                    match v {
                        Value::Array(_) => v,
                        Value::Table(map) => {
                            let items: Vec<Value> = map
                                .into_iter()
                                .map(|(name, value)| {
                                    let mut t = toml::Table::new();
                                    t.insert("name".to_string(), Value::String(name));
                                    t.insert("value".to_string(), value);
                                    Value::Table(t)
                                })
                                .collect();
                            Value::Array(items)
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
