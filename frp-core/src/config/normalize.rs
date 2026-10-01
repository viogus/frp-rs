use std::path::Path;

use super::file::process_includes;
use super::format::{detect_format, parse_to_toml_value, ConfigFormat};
use super::loader::ConfigPresence;
use super::strict::{run_strict_check, run_strict_check_top_level, HTTP_PLUGIN_KNOWN_KEYS};

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
/// - Two action forms are recognized, with optional ASCII whitespace after
///   `{{`, around the function name and before `}}`:
///   - `{{ parseNumberRange "expr" }}` — expanded in place;
///   - `{{ .Envs.NAME }}` — Go frp's environment pattern (data field of
///     `Values`, `load.go`); NAME expands from the process env, unset →
///     Go's literal `<no value>` with a warning (Go text/template runs
///     without a `missingkey` option, so a missing map key prints
///     `<no value>` — `pkg/config/load.go:84`). Byte-parity here also
///     fails closed: `token = "{{ .Envs.FRP_TOKEN }}"` with the env unset
///     yields a token no client can match, where an empty string could
///     silently fall back to unauthenticated. This is what Go configs in
///     the wild use for `token = "{{ .Envs.FRP_TOKEN }}"` — leaving it
///     verbatim shipped the literal text as the value (silent auth
///     failure on migration).
/// - No other template syntax (variables, control flow, other functions,
///   `index` / `range` forms) is processed — anything that does not match
///   one of the two forms is left verbatim.
/// - A single string may contain several actions; each is expanded in place
///   and the surrounding text is preserved.
/// - Invalid range expressions (non-numeric, N > M, out of 0..=65535) are
///   kept verbatim and a `tracing::warn` is emitted.
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

/// Try to parse one `{{ ... }}` action at the start of `s` (which must begin
/// with `{{`). Two forms are recognized, mirroring the Go frp template layer
/// (`pkg/config/load.go` `RenderWithTemplate`, data = `Values{Envs}`):
/// - `{{ parseNumberRange "expr" }}` — expanded list (see
///   [`expand_number_range_expr`]); invalid expressions stay verbatim after
///   a warning.
/// - `{{ .Envs.NAME }}` — Go frp's ONLY environment access (`token = "{{
///   .Envs.FRP_TOKEN }}"` is the documented Go pattern). NAME is looked up
///   in the process env; unset → the literal `<no value>` with a warning.
///   Go frp calls `template.New("frp")` with no `Option("missingkey=...")`,
///   so the text/template default applies: a missing map key prints
///   `<no value>` (Go source `text/template`: `missingkey=default` — "if
///   printed, the result of the index operation is the string `<no value>`";
///   `Envs` is a `map[string]string` populated only from `os.Environ`, so an
///   unset var IS a missing key). frp-rs renders the same literal for
///   byte-parity; the warning is frp-rs-only diagnostics (Go is silent).
///
/// On success returns the number of bytes consumed (the whole action) and
/// the replacement text. Returns `None` when the text is not a well-formed
/// recognized action at all (kept verbatim by the caller) — e.g. `.Envs` in
/// Go `index` syntax (`{{ index .Envs "X-Y" }}`), the bare `{{ .Envs }}`
/// map dump, or `{{ parseNumberRange .Envs.PORT_RANGE }}` argument forms,
/// all of which would need a full template engine.
fn try_parse_template_call(s: &str) -> Option<(usize, String)> {
    let bytes = s.as_bytes();
    debug_assert!(bytes.starts_with(b"{{"));
    let mut i = skip_ws(bytes, 2);
    if bytes.get(i..)?.starts_with(b"parseNumberRange") {
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
    } else if bytes.get(i..)?.starts_with(b".Envs") {
        i += b".Envs".len();
        // The field chain is contiguous in Go templates (`.Envs.NAME` —
        // whitespace between chain elements is a parse error there).
        let name_start = match bytes.get(i) {
            Some(b'.') => i + 1,
            _ => {
                // `.Envs` followed by anything but a dot: `.EnvsX` is a
                // (valid Go syntax) field lookup that ERRORS at exec time
                // (no such field), failing the whole render. frp-rs keeps it
                // verbatim — warn so a migrated config is not silently
                // shipping a literal template.
                tracing::warn!(
                    original = %s,
                    "template action kept verbatim: only '{{ .Envs.NAME }}' (NAME = [A-Za-z0-9_]+) \
                     is expanded; Go would error on any other .Envs field shape"
                );
                return None;
            }
        };
        let name_end = bytes[name_start..]
            .iter()
            .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_'))
            .map(|p| name_start + p)
            .unwrap_or(bytes.len());
        if name_end == name_start {
            // `{{ .Envs }}` alone would render the whole map in Go — out of
            // the zero-dependency subset, kept verbatim (warned, not silent:
            // the map dump in a value is always an operator mistake).
            tracing::warn!(
                original = %s,
                "bare '{{ .Envs }}' kept verbatim: frp-rs expands only '{{ .Envs.NAME }}' \
                 (Go would dump the whole environment map here)"
            );
            return None;
        }
        let name = &s[name_start..name_end];
        i = name_end;
        i = skip_ws(bytes, i);
        if !bytes.get(i..)?.starts_with(b"}}") {
            return None;
        }
        i += 2;
        match std::env::var(name) {
            Ok(v) => Some((i, v)),
            Err(_) => {
                // Go text/template default (no missingkey option in frp's
                // RenderWithTemplate) prints "<no value>" for a missing map
                // key — replicate byte-for-byte. Empty would be a silent
                // divergence AND, for `token = "{{ .Envs.FRP_TOKEN }}"`,
                // could fall back to unauthenticated.
                tracing::warn!(
                    name,
                    "{{ .Envs.{name} }}: environment variable not set; rendering Go's '<no value>' placeholder"
                );
                Some((i, "<no value>".to_string()))
            }
        }
    } else if bytes.get(i..)?.starts_with(b"index") {
        // `{{ index .Envs "K-E-Y" }}` is Go's ONLY legal way to read an env
        // whose name holds non-identifier characters (.Envs.FOO-BAR is a Go
        // parse error). Go renders it to the env value ("<no value>" for a
        // missing key); frp-rs's zero-engine subset keeps the action
        // verbatim — warn so the silent-literal-template failure mode (the
        // template TEXT shipping as the config value) surfaces at load.
        let after = skip_ws(bytes, i + b"index".len());
        if bytes.get(after..).is_some_and(|r| r.starts_with(b".Envs")) {
            tracing::warn!(
                original = %s,
                "{{ index .Envs ... }} kept verbatim: frp-rs expands only '{{ .Envs.NAME }}' \
                 (Go renders the indexed env value here)"
            );
        }
        None
    } else {
        None
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

/// Canonicalize Go's legacy INI boolean keys (`authenticate_heartbeats`,
/// `authenticate_new_work_conns`) for **`.ini` inputs only**.
///
/// Go declares them as `bool` fields with those ini tags
/// (`pkg/auth/legacy/legacy.go:25,28`) and reads them through `MapTo` ->
/// `Key.Bool()` -> `parseBool` (`key.go:194`), whose accepted spellings are
/// wider than `true`/`false`. The lossless INI reader keeps a non-canonical
/// spelling as text (or as the integer `1`/`0`) so a string-typed field can
/// receive it verbatim, so the scope conversion in `conversion.go:31-36,92-97`
/// has to see a real boolean here.
///
/// Deliberately **not** applied to TOML/JSON/YAML: those formats' consumers of
/// these two keys (a frp-rs extension — Go's v1 decoder refuses the keys in
/// them) keep the strict boolean typing they have always had, so a `1` or a
/// `"yes"` there is still ignored rather than silently flipping the
/// heart-beat / new-work-conn scope the server enforces.
pub(super) fn canonicalize_legacy_ini_bools(table: &mut toml::Table) {
    const KEYS: &[&str] = &["authenticate_heartbeats", "authenticate_new_work_conns"];
    for key in KEYS {
        canonicalize_one_legacy_ini_bool(table, key);
    }
    // Go reads both from `[common]` (`legacy/client.go:185-196`,
    // `legacy/server.go:236-247`), and the normalizers merge `[common]` into the
    // root *later* — so the pre-pass has to reach into the section too.
    if let Some(toml::Value::Table(common)) = table.get_mut("common") {
        for key in KEYS {
            canonicalize_one_legacy_ini_bool(common, key);
        }
    }
}

fn canonicalize_one_legacy_ini_bool(table: &mut toml::Table, key: &str) {
    let canonical = match table.get(key) {
        Some(toml::Value::Boolean(b)) => Some(*b),
        Some(toml::Value::Integer(1)) => Some(true),
        Some(toml::Value::Integer(0)) => Some(false),
        Some(toml::Value::String(s)) => super::format::parse_ini_bool(s),
        // An unrecognised spelling is left alone: Go's non-strict `MapTo`
        // swallows the parse error and keeps the field's default, and the
        // `as_bool()` reads then ignore it the same way.
        _ => None,
    };
    if let Some(b) = canonical {
        table.insert(key.to_string(), toml::Value::Boolean(b));
    }
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

/// Merge `from` into `into` **per key**, `into` winning every key it already
/// defines — the whole-table `or_insert` this replaces, at key granularity.
///
/// The whole-table form was the root of this subsystem's six `TODO.md` items: a
/// file that defines both `[webServer]` and `[web_server]` discarded the
/// camelCase table **whole**, so a nested `[webServer.tls]` never reached the
/// hoist and the flat `web_server.tls_*` value won in both loader modes — the
/// one shape where the documented "the nested values take precedence" claim was
/// false (measured before this change: `[webServer.tls] cert_file = "/nested"`
/// beside `[web_server] tls_cert_file = "/flat"` loaded `tls_cert() ==
/// "/flat"` in both loader modes; probe case A1, transcript
/// `/tmp/ws-probe-before.txt`). Merging per key
/// makes the nested table reachable while keeping the *same winner* for a key
/// both sections define: `[web_server]` still wins, because that is the order
/// the old `or_insert` resolved in. Nested tables merge recursively, so
/// `[webServer.tls]` beside `[web_server.tls]` merges per key too — again with
/// the snake_case section winning each key it defines. The order is never
/// inverted.
///
/// A present-but-not-a-table `into` keeps winning and `from` is dropped whole,
/// exactly as `or_insert` did — and
/// [`ConfigPresence::web_server_tls_enable_set_in`] mirrors that.
///
/// The `from` value is **moved whatever its type**, which matters: the pattern
/// that matched `Value::Table` *after* `table.remove(from)` deleted a non-table
/// `webServer` (`webServer = "not a table"`, `= 5`, and their `[common]` forms)
/// instead of carrying it across, so serde never got the type error the base tree
/// produced in both loader modes (measured: base `frps verify` rc 1, `invalid
/// type: string "not a table", expected struct WebServerConfig`; the frozen tree
/// rc 0 "syntax is ok", server and client, top level and `[common]`). Only the
/// `Vacant` arm can insert a non-table; the `Occupied` arm drops it, as
/// `or_insert` did.
fn merge_section_into(table: &mut toml::Table, from: &str, into: &str) {
    use toml::Value;
    let Some(src) = table.remove(from) else {
        return;
    };
    match table.entry(into.to_string()) {
        toml::map::Entry::Vacant(slot) => {
            slot.insert(src);
        }
        toml::map::Entry::Occupied(mut slot) => {
            if let (Value::Table(dst), Value::Table(src)) = (slot.get_mut(), src) {
                or_insert_deep(dst, src);
            }
        }
    }
}

/// `dst.entry(k).or_insert(v)` for every key, recursing into tables that both
/// sides define so nested tables merge instead of one replacing the other.
fn or_insert_deep(dst: &mut toml::Table, src: toml::Table) {
    use toml::Value;
    for (k, v) in src {
        match dst.entry(k) {
            toml::map::Entry::Vacant(slot) => {
                slot.insert(v);
            }
            toml::map::Entry::Occupied(mut slot) => {
                if let (Some(d), Value::Table(s)) = (slot.get_mut().as_table_mut(), v) {
                    or_insert_deep(d, s);
                }
            }
        }
    }
}

/// Which binary's file [`load_config_from_file`] is reading.
///
/// Exactly one legacy-`.ini` rule depends on this: the `[common] includes`
/// include list. Go's **client** legacy reader has the field
/// (`IncludeConfigFiles []string \`ini:"includes"\``,
/// `pkg/config/legacy/client.go:166`; `ParseClientConfig` renders it,
/// `pkg/config/legacy/parse.go:50`). The **server** side has no include handling
/// at all: `LoadServerConfig` (`pkg/config/load.go:295`) unmarshals `[common]`
/// into `legacy.ServerCommonConf` (`pkg/config/legacy/server.go:220`), a struct
/// with no `includes` field, and the only expansion
/// (`LoadAdditionalClientConfigs`, `pkg/config/load.go:381-382`) sits inside
/// `LoadClientConfigResult` (`pkg/config/load.go:346`). Passing the side down to
/// [`process_includes`] is what keeps the server load byte-for-byte what it was
/// before `[common] includes` support existed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ConfigSide {
    Client,
    Server,
}

/// Generic config loader shared by `load_server_config` and `load_client_config`.
pub(super) fn load_config_from_file<C: serde::de::DeserializeOwned>(
    path: &str,
    strict_config: bool,
    // Which side is loading, for the one legacy-`.ini` rule that differs
    // between them (see [`ConfigSide`]).
    side: ConfigSide,
    known_keys: fn() -> std::collections::HashSet<&'static str>,
    // The normalizer must know the dialect: the legacy `.ini` rules for
    // `type`-less sections are **INI-only** (see
    // `collect_legacy_ini_proxy_sections`), so a TOML/JSON/YAML file cannot
    // reuse the client normalizer's `.ini` behaviour.
    //
    // `Result` because the legacy reader is not purely a rewrite: a section the
    // legacy dialect refuses has to fail the load from the normalizer, where the
    // section is still visible, rather than from the v1-shaped validator that
    // runs after it (a typeless `role = "visitor"` section would otherwise be
    // reported with the v1 visitor message — see
    // `collect_legacy_ini_proxy_sections`).
    normalize: fn(&mut toml::Value, ConfigFormat) -> Result<(), String>,
    // `&mut` because a validator may *complete* a field as well as check it —
    // `validate_server_config`/`validate_client_config` run Go's
    // `Auth.Complete()` (the empty `auth.method` → `token` fill,
    // `pkg/config/v1/server.go:136-139`) before Go's validation of the same
    // field, and the completed value has to reach the caller, not just the
    // check. A validator that only checks simply ignores the `mut`.
    validate: fn(&mut C) -> Result<(), String>,
) -> Result<(C, ConfigPresence), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: failed to read config file: {e}"))?;
    let format = detect_format(path);
    let mut value: toml::Value =
        parse_to_toml_value(&content, format).map_err(|e| format!("{path}: parse error: {e}"))?;
    let base_dir = Path::new(path).parent().unwrap_or(Path::new("."));
    process_includes(&mut value, base_dir, format, side)?;
    // Expand `${ENV_VAR}` references here, after includes are deep-merged
    // (so include-file values are covered) and before normalization (which
    // renames/restructures keys). See `expand_env_vars` for the exact subset.
    expand_env_vars(&mut value);
    // Expand `{{ parseNumberRange "..." }}` template calls after env expansion
    // (so an argument like "${PORT_RANGE}" is expanded first) and before
    // normalization. See `expand_template_functions` for the exact subset.
    expand_template_functions(&mut value);
    // Go's legacy INI booleans accept a wider spelling set than the canonical
    // `true`/`false` the lossless reader infers; canonicalize them for `.ini`
    // inputs only, so TOML/JSON/YAML keep the strict boolean behaviour.
    if format == ConfigFormat::Ini {
        if let Some(table) = value.as_table_mut() {
            canonicalize_legacy_ini_bools(table);
        }
    }
    // Read before `normalize`: `normalize_web_server_section` removes the nested
    // `[webServer.tls]`/`[web_server.tls]` table, `enable` included, so this is
    // the last point at which the key is visible. The other flags are read from
    // the normalized value (their keys survive normalization).
    let web_server_tls_enable_set = ConfigPresence::web_server_tls_enable_set_in(&value);
    // Also read before `normalize`: `normalize_server_config` *synthesizes*
    // `tls_enable` from the legacy `[transport.tls]` section (`force`,
    // `certFile`, `keyFile`), so afterwards a user-written key and a synthesized
    // one are indistinguishable.
    let server_tls_enable_set = ConfigPresence::server_tls_enable_set_in(&value);
    // No path prefix: the refusal inside carries Go's own text
    // (`failed to parse visitor v, err: type shouldn't be empty`), and the
    // caller already names the file.
    normalize(&mut value, format)?;
    let mut presence = ConfigPresence::from_normalized_value(&value);
    presence.web_server_tls_enable_set = web_server_tls_enable_set;
    presence.server_tls_enable_set = server_tls_enable_set;
    if strict_config {
        // The legacy `.ini` dialect is exempt from the strict check *inside*
        // sections: Go's legacy reader is accept-and-ignore, so an unknown key in
        // an `.ini` section cannot refuse a file Go loads. The top level is still
        // checked, because that is where a `.ini` DefaultSection's v1 spelling
        // lands (`webServer.tls = 1`) — see `run_strict_check_top_level`.
        if format == ConfigFormat::Ini {
            run_strict_check_top_level(&value, &known_keys(), path)?;
        } else {
            run_strict_check(&value, &known_keys(), path)?;
        }
    }
    let json_value = toml_to_json(value);
    // Go's legacy INI loader reads every value as text and lets the target
    // field's type decide (`gopkg.in/ini.v1` `MapTo`), so `.ini` inputs go
    // through the type-directed reader; TOML/JSON/YAML keep the strict serde
    // typing Go's v1 decoder has.
    let mut cfg: C = if format == ConfigFormat::Ini {
        super::ini_lenient::deserialize_ini(&json_value)
    } else {
        serde_json::from_value(json_value)
    }
    .map_err(|e| format!("{path}: config validation error: {e}"))?;
    validate(&mut cfg).map_err(|e| format!("{path}: {e}"))?;
    Ok((cfg, presence))
}

pub(super) fn normalize_server_config(
    value: &mut toml::Value,
    _format: ConfigFormat,
) -> Result<(), String> {
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

        // `[webServer]` and `[web_server]` are the same section; a file may
        // define both and they merge per key (`[web_server]` wins each key it
        // defines) — see `merge_section_into`. The camelCase table used to be
        // discarded whole here, nested `tls` included.
        merge_section_into(table, "webServer", "web_server");
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
                "tcp_mux_keepalive_timeout",
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
                // Go's `loadHTTPPluginOpt` maps the section onto
                // HTTPPluginOptions with `section.MapTo` and silently ignores a
                // key that struct does not name (pkg/config/legacy/server.go:266-275),
                // and its conversion keeps only name/addr/path/ops/tlsVerify
                // (conversion.go:150-166). Keep the same accept-and-ignore
                // semantics by dropping keys outside HttpPluginConfig's serde
                // surface before the strict walk sees the element; the frp-rs
                // extensions (`url`, `timeout`, `enable_control`) are in that
                // surface and survive.
                // Go's `Ops []string` is filled by `ini`'s comma-splitting
                // `section.MapTo` (`Key.Strings(",")`, key.go:492: trim each
                // element, `\,` is a literal comma, a trailing empty element is
                // dropped), so a single operation (`ops = Login`) is a
                // one-element slice there. `ini_to_toml` only splits a value it
                // can reproduce verbatim, so a value with an escape or a space
                // after the comma arrives as a `String` and would fail
                // `Vec<String>` deserialization — split it the way Go does. The
                // `filter` below drops an empty element on this text path only
                // (pre-existing; an array that reached here is not filtered).
                if let Some(Value::String(s)) = st.get("ops") {
                    let items: Vec<Value> = super::format::split_ini_list(s)
                        .into_iter()
                        .filter(|p| !p.is_empty())
                        .map(Value::String)
                        .collect();
                    st.insert("ops".to_string(), Value::Array(items));
                }
                let unknown_keys: Vec<String> = st
                    .keys()
                    .filter(|k| !HTTP_PLUGIN_KNOWN_KEYS.contains(&k.as_str()))
                    .cloned()
                    .collect();
                for key in unknown_keys {
                    st.remove(&key);
                }
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
                ("tcpMuxKeepaliveTimeout", "tcp_mux_keepalive_timeout"),
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
    Ok(())
}

pub(super) fn normalize_client_config(
    value: &mut toml::Value,
    format: ConfigFormat,
) -> Result<(), String> {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Go detects the legacy `.ini` dialect by the `[common]` section
        // (`DetectLegacyINIFormat`, pkg/config/load.go:65); the hoist below hides
        // it and reads the common config — including `start` — from `[common]`
        // alone (`GetSection("common")` + `MapTo`, legacy/client.go:173-200).
        let is_ini = format == ConfigFormat::Ini;
        let legacy_ini = is_ini && matches!(table.get("common"), Some(Value::Table(_)));
        let common_start = legacy_common_start(table, legacy_ini);
        if let Some(Value::Table(common_table)) = table.remove("common") {
            for (k, v) in common_table {
                table.entry(k).or_insert(v);
            }
        }
        // Go legacy INI proxy/visitor sections ([web], [ssh], [range:xxx],
        // [plugin:xxx]): every non-known top-level section is a proxy (or a
        // visitor when role=visitor) and a missing `type` is Go's `tcp`; the
        // rule is **`.ini`-only** (TOML/JSON/YAML tables stay unknown to v1).
        let (legacy_proxy_indices, legacy_visitor_indices) =
            collect_legacy_ini_proxy_sections(table, is_ini, legacy_ini, common_start.as_ref())?;
        legacy_start_override(table, legacy_ini, common_start);

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

        // `[webServer]` and `[web_server]` are the same section; merge per key
        // (mirrors the server path above) so a nested `[webServer.tls]` is not
        // discarded when `[web_server]` is also present.
        merge_section_into(table, "webServer", "web_server");
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
        normalize_proxies(table, &legacy_proxy_indices);
        normalize_visitors(table);

        // Legacy-collected elements keep Go's INI semantics: a key the typed
        // struct does not name is ignored, not refused. Run after the folds
        // above so every key those folds produce is already in place.
        for (target, indices, visitor) in [
            ("proxies", &legacy_proxy_indices, false),
            ("visitors", &legacy_visitor_indices, true),
        ] {
            let Some(Value::Array(arr)) = table.get_mut(target) else {
                continue;
            };
            for index in indices {
                if let Some(element) = arr.get_mut(*index) {
                    super::strict::strip_unknown_legacy_element_keys(element, visitor);
                }
            }
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
    Ok(())
}

/// Hoist the nested `[webServer.tls]` / `[web_server.tls]` table onto the flat
/// `web_server.tls_*` fields, so both spelling families reach the struct that
/// [`WebServerConfig::tls_cert`]/[`WebServerConfig::tls_key`] read.
///
/// `normalize_server_config` also calls this for the **client** admin server's
/// `[web_server.tls]` (`ClientConfig.web_server` is the same
/// [`WebServerConfig`]), so one mapping serves both crates.
///
/// **What it maps.** Four values, each named by **four** spellings that reach
/// serde as *one* field: the nested canonical snake_case (what
/// [`WebServerTlsConfig`] names the fields), the nested Go camelCase (Go
/// v0.71.0's only spelling — its `TLSConfig` json tags are camelCase,
/// `pkg/config/v1/common.go:76-84`), the parent-level canonical
/// (`web_server.tls_cert_file`, …) and the parent-level camelCase `alias` of
/// that field (`#[serde(alias = "certFile")]`):
///
/// | destination | nested snake | nested camel | parent canonical | parent alias |
/// |---|---|---|---|---|
/// | `tls_cert_file` | `cert_file` | `certFile` | `tls_cert_file` | `certFile` |
/// | `tls_key_file` | `key_file` | `keyFile` | `tls_key_file` | `keyFile` |
/// | `tls_ca_file` | `trusted_ca_file` | `trustedCaFile` | `tls_ca_file` | `trustedCaFile` |
/// | `tls_server_name` | `server_name` | `serverName` | `tls_server_name` | `serverName` |
///
/// **Precedence — the first non-empty spelling wins, nested first.** The
/// resolution order is nested snake → nested camel → parent canonical → parent
/// alias, so a nested entry replaces a flat key that is already set in either
/// key order (the claim the struct's doc comment makes) and snake_case beats
/// camelCase inside one table. Every spelling that loses is **removed**, so the
/// same field can never reach serde twice — the whole group is canonicalized
/// down to `flat_key`. That closes a pre-existing `duplicate field
/// \`tls_cert_file\`` for a parent-level `certFile` beside the parent canonical
/// (measured before this change in both loader modes) *and* the same collision
/// a per-key section merge would otherwise introduce between `[webServer]` and
/// `[web_server]`.
///
/// An explicitly **empty** spelling is *unset* and falls through to the next
/// one. This is a decision, not a mechanical consequence: emptiness is how these
/// fields say *disabled*, so `[web_server.tls] cert_file = ""` beside a
/// configured flat/alias value must not silently drop the certificate and leave
/// the dashboard serving plaintext HTTP (which is what it did — measured
/// `tls_cert() == ""` in both loader modes). If every spelling is empty, the
/// canonical key is written as the empty string, which is the field default.
///
/// **A parent-level snake `cert_file` is not one of the four.** It is not a
/// field at all, and it is deliberately left in place so `check_strict` keeps
/// reporting it.
///
/// **The section merge comes first.** `normalize_server_config` /
/// `normalize_client_config` deep-merge `[webServer]` into `[web_server]`
/// per key before this runs (`merge_section_into`), so a file that defines both
/// sections no longer discards the camelCase one — the nested `[webServer.tls]`
/// table arrives here and merges into `[web_server.tls]` with the snake_case
/// section winning each key it defines. Measured before that fix:
/// `[webServer.tls] cert_file = "/nested"` beside
/// `[web_server] tls_cert_file = "/flat"` loaded `tls_cert() == "/flat"` in both
/// modes; after, `/nested`.
///
/// **`.ini` reaches this function too.** frp-rs treats `.ini` as a config
/// format with the same normalizers as TOML/YAML/JSON, so the INI reader
/// expands a dotted section header whose first segment is a v1 section name into
/// nested tables (`ini_to_toml` / `ini_section_path` in
/// `frp-core/src/config/format.rs`); legacy `[plugin.NAME]` sections are not v1
/// section names and stay flat. Before the expansion the header was stored
/// verbatim as the top-level key `webServer.tls`, so non-strict dropped the
/// section and strict reported `unknown field "webServer.tls"` (measured in both
/// modes; probe case B1). This is an frp-rs extension, not Go parity: Go's
/// `.ini` path is the *legacy* loader (`pkg/config/legacy/server.go` /
/// `client.go`), which reads `[common]` plus the flat `plugin.*` sections from
/// `gopkg.in/ini.v1` and ignores every other section — `[webServer.tls]` in a
/// Go `.ini` is simply never read (probed: the v0.71.0 `frps verify` exits 0 but
/// no value is applied).
///
/// **What it drops, and why.** `enable` is removed and does not reach any
/// field, and the fact that it was written is carried out of the loader on
/// [`ConfigPresence::web_server_tls_enable_set`] so every load site that has a
/// log sink can emit the diagnostic a user needs **after** `init_logging`
/// ([`ConfigPresence::warn_inert_web_server_tls_enable`] — see the code comment
/// at the removal for why the emission is not here). Measured on the v0.71.0
/// binaries, before/after that move (probe `/tmp/enable-warn-probe/`,
/// `run-probe.sh`, stdout and stderr captured separately, occurrence counts):
/// before, the warning was delivered only where the log sink was installed
/// before the load (`frps --config-dir`: 1, `frpc --config-dir`: 1) and
/// **dropped** on the common `-c` path (`frps -c`, `frpc -c`: 0, `RUST_LOG=debug`
/// included), where the load deliberately precedes `init_logging` (the
/// single-config branch of `frps/src/main.rs` and of `frpc/src/main.rs`); after,
/// every one of those four shapes emits exactly **1** on stdout and 0 on stderr.
/// The `-c` ordering itself is untouched — it is Go parity (see the comment on
/// that branch) and the fix moves the **emission**, not the load. Nothing reads
/// [`WebServerTlsConfig::enable`]: `enable` is removed with the table's other
/// mapped keys before serde, so the field is default-`false` in every loaded
/// config (an unmapped key keeps the table alive, but serde ignores it and none
/// of them matches a field) and it has no reader in
/// `frp-server`/`frps`; the dashboard TLS is driven by a non-empty cert/key pair
/// (`Service::run` via `tls_cert()`), which is also what Go does
/// (`pkg/util/http/server.go:77` starts TLS from a non-nil `cfg.TLS`). But Go
/// does **not** accept the key: its `TLSConfig` (`pkg/config/v1/common.go:76-84`)
/// has no `Enable` field, so `frps verify` refuses `enable` with
/// `json: unknown field "enable"` — re-measured on the v0.71.0 binary
/// (`/private/tmp/frp_0.71.0_darwin_arm64/frps`, probe
/// `/tmp/enable-warn-probe/go-probe.sh`: rc 1, 29 B on stdout, 0 B on stderr,
/// while the identical file without `enable` verifies rc 0). Accepting it is
/// therefore a **deliberate divergence**: it
/// keeps a config frp-rs can serve correctly from failing, whose only other
/// cost would be the strict/non-strict split this whole item is about. Do not
/// "wire it up" to the cert/key pair: `enable = false` beside a valid pair would
/// then silently disable the dashboard TLS, and `enable = true` with no pair
/// would promise TLS the pair cannot deliver.
///
/// **What it does not do.** Every unmapped nested key stays **inside** the
/// `tls` table, which is re-inserted under `web_server.tls` when non-empty. It
/// is *not* re-inserted at the parent level: that re-insert existed so
/// `check_strict` could name an unknown nested key, but it let a nested
/// `password` / `user` become the real `web_server.password` / `user`
/// credentials (every `WebServerConfig` field name was reachable this way —
/// measured in both loader modes, probe case C2), and Go refuses those keys
/// outright (probed on the v0.71.0 `frps`: rc 1, `json: unknown field
/// "password"`). Keeping the residue nested makes `check_strict` name the true
/// path — `web_server.tls.user` — pinned by
/// `unknown_nested_web_server_tls_key_names_the_true_nested_path` and
/// `nested_web_server_tls_credentials_do_not_become_the_parent_fields` in
/// `frp-core/src/config/tests.rs`; non-strict drops it like any other unknown
/// key. The nested [`WebServerTlsConfig`] itself is never populated by either
/// loader — only unknown keys can remain in the table — so
/// `WebServerConfig::tls_cert`/`tls_key` always answer from the flat field.
fn normalize_web_server_section(table: &mut toml::Table) {
    use toml::Value;

    let Some(Value::Table(ws)) = table.get_mut("web_server") else {
        return;
    };

    // Pull the nested table out. A `tls` that is not a table is dropped — it
    // could never deserialize as `WebServerTlsConfig` — but the parent-level
    // canonicalization below still runs for it, unlike before.
    let mut tls = match ws.remove("tls") {
        Some(Value::Table(t)) => t,
        _ => toml::Table::new(),
    };

    // One group per destination field. **Four** spellings name each field, and
    // serde fails with `duplicate field` if two of them reach it — so whatever
    // loses is removed and only `flat_key` is written back:
    //
    //   * `nested_snake` — the canonical name inside `[web_server.tls]`
    //   * `go_alias`     — Go's camelCase name: nested **and** the parent-level
    //                      serde `alias` of the flat field
    //                      (`#[serde(alias = "certFile")]`)
    //   * `flat_key`     — the canonical parent-level field
    //
    // The first **non-empty** spelling wins, in the order `nested_snake` →
    // `go_alias` (nested) → `flat_key` → `go_alias` (parent): the nested value
    // beats the flat one in either key order (the claim the struct's doc
    // comment makes), snake_case beats camelCase inside one table, and an
    // explicitly empty string means ***unset***. That last rule is a decision,
    // not an accident: emptiness is how these fields say *disabled*, so
    // `[web_server.tls] cert_file = ""` beside `[web_server] certFile =
    // "/p.pem"` must not silently turn the dashboard HTTPS off and leave it
    // serving plaintext HTTP (measured before this change: `tls_cert() == ""`
    // in both loader modes, probe case F1). An all-empty group still writes the
    // empty canonical key, which is the field default.
    const MAPPED: [(&str, &str, &str); 4] = [
        ("tls_cert_file", "cert_file", "certFile"),
        ("tls_key_file", "key_file", "keyFile"),
        ("tls_ca_file", "trusted_ca_file", "trustedCaFile"),
        ("tls_server_name", "server_name", "serverName"),
    ];
    for (flat_key, nested_snake, go_alias) in MAPPED {
        let mut chosen: Option<Value> = None;
        let mut written = false;
        for spelling in [nested_snake, go_alias] {
            if let Some(v) = tls.remove(spelling) {
                written = true;
                if chosen.is_none() && !is_empty_string(&v) {
                    chosen = Some(v);
                }
            }
        }
        for spelling in [flat_key, go_alias] {
            if let Some(v) = ws.remove(spelling) {
                written = true;
                if chosen.is_none() && !is_empty_string(&v) {
                    chosen = Some(v);
                }
            }
        }
        if written {
            ws.insert(
                flat_key.to_string(),
                chosen.unwrap_or_else(|| Value::String(String::new())),
            );
        }
    }

    // Inert, and silently so **here**. `enable` is accepted (so strict mode does
    // not refuse a file frp-rs can serve correctly) but stored nowhere a reader
    // can see — see the doc comment above. The diagnostic a user needs
    // (`enable = true` with no cert/key pair leaves the dashboard on **plaintext
    // HTTP**) is **not** emitted from this function: on the `-c` path the loader
    // runs before `init_logging` (the single-config branch of `frps/src/main.rs`
    // and of `frpc/src/main.rs` — the load call, then `init_logging`), so a
    // `tracing::warn` here reaches no subscriber and the user sees nothing.
    // The fact is carried out of the loader on
    // `ConfigPresence::web_server_tls_enable_set`, and
    // `ConfigPresence::warn_inert_web_server_tls_enable` is called by every load
    // site that has a sink: `frps`'s two startup paths, `frpc`'s two plus
    // `frpc verify`, and the two in-process **reloads**
    // (`frp-server`/`frp-client`, library crates). One more site — the `frpc`
    // admin API's config **GET** (`frp_client::admin::config_from_file`) — emits
    // on a **state change** rather than per load, because that route is polled:
    // its cell is seeded from the file at admin-server startup, so a GET does not
    // repeat the startup record. One site stays silent on purpose and is named in
    // `docs/config.md`: `frps verify` (its logging is never initialised). Do not
    // re-add an emission here: it would double the record wherever the sink is
    // already installed (`--config-dir`, the reloads) while still being dropped
    // on `-c`.
    tls.remove("enable");

    // Anything left is a key this section does not have. It **stays nested**;
    // the old re-insert at the parent level let a nested `user` / `password`
    // *become* the dashboard Basic Auth credentials. Every `WebServerConfig`
    // field name is dangerous (`addr`, `port`, `user`, `password`,
    // `enable_prometheus` / `enablePrometheus`, `assets_dir` / `assetsDir`,
    // `pprof_enable` / `pprofEnable`, `tls_cert_file` / `certFile`,
    // `tls_key_file` / `keyFile`, `tls_ca_file` / `trustedCaFile`,
    // `tls_server_name` / `serverName`, `custom_404_page` / `custom404Page`),
    // so no name is re-inserted at all. Measured before this change (probe case
    // C2): `[web_server.tls] user = "nested-user"` + `password =
    // "nested-secret"` loaded with `web_server.user == "nested-user"` and
    // `web_server.password == "nested-secret"` in both loader modes. Go refuses
    // both keys — its `TLSConfig` has neither — measured on the v0.71.0 `frps`:
    // rc 1, stdout `json: unknown field "password"`. Keeping the residue inside
    // `tls` makes `check_strict` name the path the user actually wrote
    // (`web_server.tls.user`, via the walker's `web_server` → `tls`
    // recursion); non-strict drops it like any other unknown key.
    if !tls.is_empty() {
        ws.insert("tls".to_string(), Value::Table(tls));
    }
}

/// Is this spelling an explicitly empty string? Used by
/// [`normalize_web_server_section`] to read "empty" as *unset* for the TLS
/// fields, whose emptiness means *disabled*.
fn is_empty_string(v: &toml::Value) -> bool {
    matches!(v, toml::Value::String(s) if s.is_empty())
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

/// Fold `<prefix>*` keys into a map stored under `target` — Go's
/// `GetMapWithoutPrefix` (`pkg/config/legacy/utils.go:21`), which is how the
/// legacy INI layer spells `metadatas` (`meta_*`, `proxy.go:198`) and HTTP
/// request headers (`header_*`, `proxy.go:244`). Merges into an existing map
/// rather than replacing it (`or_insert` per key, like Go's per-key writes).
fn fold_prefixed_keys_into(st: &mut toml::Table, prefix: &str, target: &str) {
    use toml::Value;

    let mut map = toml::Table::new();
    for key in st.keys().cloned().collect::<Vec<_>>() {
        let Some(sub) = key.strip_prefix(prefix) else {
            continue;
        };
        if sub.is_empty() {
            continue;
        }
        if let Some(v) = st.remove(&key) {
            map.insert(sub.to_string(), v);
        }
    }
    if map.is_empty() {
        return;
    }
    match st.get_mut(target) {
        Some(Value::Table(existing)) => {
            for (k, v) in map {
                existing.entry(k).or_insert(v);
            }
        }
        _ => {
            st.insert(target.to_string(), Value::Table(map));
        }
    }
}

/// Collect legacy-shaped proxy/visitor sections into `[proxies]`/`[visitors]`.
///
/// `is_ini` selects the dialect (Go's two loaders disagree about a `type`-less
/// section); `legacy_ini` is Go's `[common]` detector and gates `start`/role:
///
/// * **`.ini`** (`is_ini == true`) — Go uses the legacy loader
///   (`LoadAllProxyConfsFromIni`, `pkg/config/legacy/client.go`), which treats
///   **every** section other than `common`/`range:*`/the default section as a
///   proxy: `role` defaults to `"server"`, and a missing `type` becomes `tcp`
///   (measured on Go v0.71.0: `[myproxy]` with only `local_port`/`remote_port`
///   is registered by frps as `new proxy [myproxy] type [tcp] success` and by
///   frpc as `[myproxy] start proxy success`, and `frpc verify` is rc 0 in both
///   strict modes). frp-rs collects on shape instead, and the shape it accepts
///   is Go's own membership key plus one narrower `.ini` case: a `type` key, or
///   a `type`-less section carrying `local_port`/`remote_port`. The second case
///   is **narrower than Go** on purpose — a `type`-less `.ini` table with
///   neither port key would be a `tcp` proxy with port 0 on Go, while here it
///   stays a v1 section (measured: rc 1 in strict mode with `unknown field
///   "myproxy" in config file …`) — because the same key set is what
///   `format.rs`'s nest gate reads to decide a dotted header is a *flat* name,
///   and it is what keeps a `type`-less camelCase admin block out of the
///   collector. The missing `type` of a collected section is filled with `tcp`
///   here. A `role = "visitor"` section is **not** given the proxy default:
///   measured on Go v0.71.0, such a section is refused (`failed to parse visitor
///   v1, err: type shouldn't be empty`, rc 1), never quietly turned into a tcp
///   proxy. `role` is also authoritative for every other clause here, exactly as
///   it is in Go (which reads it before it looks at the header): a typed
///   `role = "visitor"` section is collected as a visitor whatever its header
///   names — including a reserved settings root — and reaches the visitor
///   bind-port validation instead of being dropped (measured: `[web_server]
///   type = "stcp" local_port = 8080 role = "visitor" server_name = s` is rc 1
///   in both modes on Go v0.71.0 with `visitor web_server: bind port is
///   required`, where frp-rs accepted the file in both modes).
/// * **TOML/JSON/YAML** (`is_ini == false`) — Go's v1 decoder rejects an unknown
///   top-level table (`unknown field "myproxy"`), so the `type` key stays the
///   membership discriminator and an unknown table keeps its current meaning.
///   (frp-rs additionally accepts a *typed* legacy-shaped table in these
///   formats, a pre-existing extension recorded with its measurement in
///   `docs/deployment.md`.)
///
/// Returns the indices of the elements it created, so the caller can run
/// `strip_unknown_legacy_element_keys` over exactly those elements: Go's legacy
/// path ignores an INI key its typed struct does not name (`gopkg.in/ini`
/// `MapTo`), while the strict check on a *v1* `[[proxies]]` element rejects it.
/// Stripping the leftovers keeps the legacy surface at Go's accept-and-ignore
/// semantics without loosening the v1 check.
///
/// # Errors
///
/// One section shape has no representation here and is refused before collection,
/// with Go's own message: a `role = "visitor"` `.ini` section whose
/// `type` is missing or empty. Go's `NewVisitorConfFromIni`
/// (`pkg/config/legacy/visitor.go:168`) starts from `DefaultVisitorConf`, which
/// is `nil` for an empty type, and `LoadAllProxyConfsFromIni` wraps the failure
/// as `failed to parse visitor <name>, err: …` (`pkg/config/legacy/client.go`).
/// The variant name in the message (`v1` above) is the version of the legacy
/// reader; the section name is what Go interpolates. Refusing it *here* rather
/// than letting the section fall through to the v1 visitor validator is what
/// keeps Go's wording: a section that is never collected would be reported as
/// `visitor '<name>': unknown visitor type ''`, the v1 message — a different refusal.
fn collect_legacy_ini_proxy_sections(
    table: &mut toml::Table,
    is_ini: bool,
    legacy_ini: bool,
    start: Option<&toml::Value>,
) -> Result<(Vec<usize>, Vec<usize>), String> {
    use toml::Value;

    let mut proxy_indices = Vec::new();
    let mut visitor_indices = Vec::new();

    /// The v1 **array** roots (`ClientConfig::proxies` / `ClientConfig::visitors`
    /// are `Vec`s): an INI header naming one of these is a legacy section, never the
    /// array. See `format::INI_NESTED_SECTION_ROOTS` for why they are not nested.
    const INI_ARRAY_ROOTS: &[&str] = &["proxies", "visitors"];

    /// Is `name` an array root, or a dotted path *under* one?
    fn names_an_ini_array_root(name: &str) -> bool {
        INI_ARRAY_ROOTS.iter().any(|root| {
            name == *root
                || name
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    }

    /// Go's `ini.Key.String() == ""` test: the key is absent, or present and the
    /// empty string. A non-string `type` is left alone — Go reads it as its
    /// literal text and `DefaultProxyConf` refuses it (`invalid type [..]`).
    fn type_missing_or_empty(t: &toml::Table) -> bool {
        match t.get("type") {
            None => true,
            Some(Value::String(s)) => s.is_empty(),
            Some(_) => false,
        }
    }

    // Go's visitor refusal, before any collection: `role = "visitor"` without a
    // usable `type`; a `type`-less visitor that carries ports is refused the same
    // way, because Go dispatches on `role` before it reads a port. (`[common] role
    // = …` is a merged top-level scalar here, not a table, and Go's
    // `s.MapTo(&common)` ignores the unknown key there too.) The walk below is
    // **recursive**: a dotted header carrying neither a `type` nor a port key is
    // *expanded* by `format::ini_section_path` (`[auth.foo]` becomes the `foo`
    // child of `auth`), while Go's legacy reader reads the section under its raw
    // header (`pkg/config/legacy/client.go:204`, `section.Name()`), so the refusal
    // must see the expanded table under its dotted name. Go's `[common] start`
    // filter (`:259-262`) runs before this refusal, so it is applied here too.
    if is_ini {
        fn find_typeless_visitor(
            prefix: &str,
            table: &toml::Table,
            start: Option<&toml::Value>,
            legacy_ini: bool,
        ) -> Option<String> {
            for (key, value) in table {
                let Some(t) = value.as_table() else {
                    continue;
                };
                let name = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if ini_section_started(start, &name, legacy_ini)
                    && t.get("role").and_then(Value::as_str) == Some("visitor")
                    && type_missing_or_empty(t)
                {
                    return Some(name);
                }
                if let Some(found) = find_typeless_visitor(&name, t, start, legacy_ini) {
                    return Some(found);
                }
            }
            None
        }
        if let Some(name) = find_typeless_visitor("", table, start, legacy_ini) {
            return Err(format!(
                "failed to parse visitor {name}, err: type shouldn't be empty"
            ));
        }
    }

    // Known non-proxy top-level sections are never collected even if they
    // happen to carry a `type` key.
    //
    // Only the **snake_case** spelling of a v1 root is listed. Its camelCase
    // alias is deliberately *not*: Go's legacy loader takes a section by shape,
    // so `[webServer] type = "tcp"` (and `[httpPlugins]` / `[sshTunnelGateway]`)
    // is a proxy *named* after the header there, while a `type`-less
    // `[webServer] port = 7500` is the admin block. Reserving the camelCase name
    // would re-drop the typed proxy; listing it and relying on the filter would
    // repeat the phantom-proxy bug this comment's sibling clause below fixes.
    // The `local_port`/`remote_port` clause of that clause is what separates the
    // two: no admin block carries either key. (Measured on the real v0.71.0
    // binaries: `.ini` files typing all three headers give `frpc verify` rc 0 in
    // both strict modes, and a real run logs `proxy added: [httpPlugins
    // sshTunnelGateway webServer]` on frpc and one `new proxy [<header>] type
    // [tcp] success` per header on frps; base971 gave `Proxies: 1` for each
    // before this PR touched the filter.)
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
            let Some(Value::Table(t)) = table.get(*k) else {
                return false;
            };
            let role_is_visitor = t.get("role").and_then(Value::as_str) == Some("visitor");

            // Go dispatches on `role` **first**: `LoadAllProxyConfsFromIni`
            // (`pkg/config/legacy/client.go:204`) reads `role` (default
            // `server`) before it looks at the header or any other key, so an
            // `.ini` section that says `role = "visitor"` is a visitor even when
            // its header names a v1 settings root and even when it carries proxy
            // port keys. Both spellings are measured on Go v0.71.0, rc 1 in both
            // modes: the reserved-root one is refused by visitor validation for
            // the missing bind port (`[web_server] type = "stcp" local_port =
            // 8080 role = "visitor" server_name = s` → `visitor web_server: bind
            // port is required`, where origin/main strict was also rc 1 with
            // `unknown field "web_server.local_port"` and head accepted it), and
            // so is the flat one (`[auth] remote_port = 7500 role = "visitor"
            // type = "stcp" server_name = s` → `visitor auth: bind port is
            // required`). A typeless visitor never reaches this clause — the
            // guard above has already refused the file with Go's message — so
            // `type` is present here.
            if is_ini && role_is_visitor {
                return t.contains_key("type");
            }

            // A `.ini` header naming a v1 **array** root is the legacy section
            // it looks like, whatever keys it carries and whether or not it is
            // dotted. It cannot be the v1 array — an INI header has no way to
            // build one — and Go never expands it (its legacy loader reads the
            // section under its raw name), so the proxy keeps Go's name and
            // Go's `tcp` default. Without this the portless spelling stayed a
            // map where the deserializer wants a sequence: `frpc verify` on
            // `[visitors.foo] server_name = s` was rc 1 in both modes with
            // `invalid type: map, expected a sequence`, and Go v0.71.0 is rc 0
            // in both. A typed array-root header is collected as a visitor when
            // it says so — the `role` clause above takes it, so this branch only
            // ever sees a proxy.
            if is_ini && names_an_ini_array_root(k) {
                return true;
            }

            if KNOWN_SECTIONS.contains(&k.as_str()) {
                // …unless the reserved name carries a **proxy port**. A v1
                // settings root never does, so a section that names one is the
                // legacy proxy Go registers under that same name — measured:
                // `[web_server] type = tcp local_port = … remote_port = …` and
                // `[transport] local_port = …` are rc 0 with one proxy on Go
                // v0.71.0 in both strict modes, while frp-rs dropped the proxy
                // (non-strict `Proxies: 0`) and refused the file in strict mode
                // (`unknown field "web_server.local_port"`). The clause is
                // deliberately the *port* keys and not `type`: `[log] type =
                // "custom" disable_print_color = true` stays the settings table
                // frp-rs has always read it as (Go refuses that file with
                // `failed to parse proxy log, err: invalid type [custom]`, a
                // disclosed residual pinned by
                // `test_legacy_ini_known_section_with_type_not_collected` and by
                // `legacy_ini_typed_settings_root_with_type_stays_a_settings_table`).
                return is_ini && (t.contains_key("local_port") || t.contains_key("remote_port"));
            }

            if t.contains_key("type") {
                return true;
            }
            // A `type`-less section is a proxy only in the legacy `.ini`
            // dialect and only when it names a port — the same key set the nest
            // gate in `format.rs` uses to declare a dotted header flat, which is
            // what keeps a `type`-less camelCase admin block (`[webServer] port
            // = 7500`, `[webServer]` + `[webServer.tls]`, `[common.webServer]`,
            // the `[webServer]`+`[web_server]` merge, `[webServer]
            // zzz_unknown_key = 1`) out of the collector while
            // `[myproxy]`/`[auth.foo]` with ports stay proxies. A visitor never
            // reaches here (the `role` clause above), which is what Go does
            // instead of defaulting the missing type (`type shouldn't be
            // empty`).
            is_ini && (t.contains_key("local_port") || t.contains_key("remote_port"))
        })
        .cloned()
        .collect();

    // Go applies `[common] start` **before** it reads `role` or parses a section
    // (`LoadAllProxyConfsFromIni`, `pkg/config/legacy/client.go:227-262`): with a
    // non-empty `start`, every named section not in the list is skipped entirely,
    // and the generated `{prefix}_{i}` range sections are filtered by their
    // *generated* names. frp-rs must drop the skipped sections from the table as
    // well, or one Go never parses still reaches proxy validation (`start = p2`
    // with `[p1] type = "custom"` is rc 0 in both Go modes, measured) and the
    // strict checker (`unknown field "p1"`). Only the names Go would dispatch are
    // dropped: the collector's candidate set minus `range:` headers, which keep
    // Go's template validation and are filtered per generated name below. The
    // `start` list itself is the `[common]` value captured above and passed
    // into this collector, not the root key a `[start]` section occupies.
    let sections: Vec<String> = if legacy_ini {
        let (kept, skipped): (Vec<String>, Vec<String>) = sections.into_iter().partition(|name| {
            name.starts_with("range:") || ini_section_started(start, name, legacy_ini)
        });
        for name in skipped {
            table.remove(&name);
        }
        kept
    } else {
        sections
    };

    // Go reads `role` **before** it decides what a section is, and refuses the
    // whole file when it is neither `server`, `visitor` nor empty
    // (`LoadAllProxyConfsFromIni`, `pkg/config/legacy/client.go:255-285`: the
    // missing/empty default is `server`, and the `default:` arm errors with this
    // exact text, using the raw header as the name). The scan covers every
    // top-level section, not just the ones the collector takes: measured on Go
    // v0.71.0, `[proxies]`, `[visitors]`, `[foo]` and `[p]` with `role =
    // "weird"`, `role = "Server"` or `role = 1` are rc 1 in both loader modes
    // (`proxy proxies role should be 'server' or 'visitor'`, …), while those same
    // headers with `role = "server"`, no `role` at all, or `role = ""` are rc 0.
    // A `range:` header is skipped here: Go refuses a bad role there only after
    // expansion, under the generated `{prefix}_{i}` name (see the expansion
    // below), and it reports a missing port before that. The scan is gated on
    // `legacy_ini` (Go's `[common]` detector): a `[common]`-less `.ini` is read
    // by the **v1** decoder, which has no role switch and ignores such a section
    // in non-strict mode (measured: `[foo] role = "weird"` without `[common]` is
    // rc 1 strict with `unknown field "foo"` but rc 0 non-strict, where a role
    // refusal is rc 1 in both modes). Sections the `start` filter skips are not
    // dispatched by Go either, so they are not role-checked here.
    if legacy_ini {
        for name in table.keys() {
            if name.starts_with("range:") || !ini_section_started(start, name, legacy_ini) {
                continue;
            }
            let Some(Value::Table(t)) = table.get(name) else {
                continue;
            };
            if ini_role(t).is_none() {
                return Err(format!("proxy {name} role should be 'server' or 'visitor'"));
            }
        }
    }

    for section_name in sections {
        let Value::Table(mut st) = table.remove(&section_name).unwrap() else {
            continue;
        };

        // Go's legacy proxy default: a section with no `type` — or an **empty**
        // one, which its `ini.Key.String()` cannot tell from a missing key — is a
        // `tcp` proxy (`LoadAllProxyConfsFromIni` → `NewProxyConfFromIni` →
        // `pkg/config/legacy/proxy.go`, which starts from the tcp-variant
        // struct). Written in explicitly so every downstream stage — the strict
        // check, `normalize_proxies`, serde — sees the same concrete type Go
        // does. A typeless `role = "visitor"` section never reaches this point —
        // the guard above refuses the file with Go's message — so this only ever
        // fills a *proxy*'s type.
        if is_ini && type_missing_or_empty(&st) {
            st.insert("type".to_string(), Value::String("tcp".to_string()));
        }

        // Go ini.v1 []string fields: a scalar value becomes a one-element
        // array (a comma list the reader could reproduce verbatim is already an
        // Array here, and is *not* filtered — `a.com,,b.com` keeps its middle
        // empty element on both sides). The splitter is Go's
        // `Key.Strings(",")` (key.go:492), so `a\,b` is one element and a
        // trailing empty element is dropped; the `filter` below then drops an
        // empty element on this **text path only** (pre-existing): measured,
        // `a.com, ,b.com` is `["a.com", "", "b.com"]` on Go and `["a.com",
        // "b.com"]` here, while the verbatim `a.com,,b.com` matches Go.
        for list_key in ["custom_domains", "locations", "allow_users"] {
            if let Some(Value::String(s)) = st.get(list_key) {
                let items: Vec<Value> = super::format::split_ini_list(s)
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .map(Value::String)
                    .collect();
                if !items.is_empty() {
                    st.insert(list_key.to_string(), Value::Array(items));
                }
            }
        }

        // Go legacy INI health-check spellings. The v1 field names are
        // `health_check_interval_seconds` / `health_check_timeout_seconds`, and
        // Go's legacy conversion maps the flat `_s` INI spellings onto
        // `HealthCheck.IntervalSeconds` / `.TimeoutSeconds`
        // (pkg/config/legacy/conversion.go:204-206) — a valid Go legacy INI
        // config uses them and Go honours them. The
        // `[proxies.healthCheck]` flatten in `normalize_proxies` already
        // renames them; the flat INI form needs the same rename, because the
        // element reaches `check_strict` unrenamed otherwise and strict mode
        // walks `proxies`/`visitors` elements (a valid Go legacy config would
        // be refused).
        //
        // `insert`, not `or_insert`: when both spellings are present Go uses
        // the `_s` one. `health_check_interval_s` is the only interval INI tag
        // Go's legacy struct declares (`pkg/config/legacy/proxy.go:130,136`),
        // so `_seconds` is an unknown INI key there; measured on Go v0.71.0
        // (frpc + frps, health-check log gaps): `_s = 2` alone → checks every
        // 2.0 s; `_seconds = 2` alone → one check then the 10 s default
        // (ignored); `_s = 2` + `_seconds = 99` → every 2.0 s, and `_s = 99` +
        // `_seconds = 2` → one check. So `_s` wins in both orders.
        for (from, to) in [
            ("health_check_interval_s", "health_check_interval_seconds"),
            ("health_check_timeout_s", "health_check_timeout_seconds"),
        ] {
            if let Some(v) = st.remove(from) {
                st.insert(to.to_string(), v);
            }
        }

        // Go's prefix mechanisms for a legacy *proxy* section (the visitor
        // struct has neither: `pkg/config/legacy/visitor.go` has no prefix
        // reads, so Go ignores the keys there and the strip pass drops them).
        let is_visitor = st.get("role").and_then(Value::as_str) == Some("visitor");
        if !is_visitor {
            // meta_* -> Metadatas (proxy.go:198, conversion.go:192).
            fold_prefixed_keys_into(&mut st, "meta_", "metadatas");
            // header_* -> HTTP request headers. Go folds these only for
            // `type = "http"` (HTTPProxyConf.UnmarshalFromIni, proxy.go:244);
            // HTTPS/TCP have no Headers field, so Go ignores the keys there and
            // the strip pass drops them.
            if st.get("type").and_then(Value::as_str) == Some("http") {
                fold_prefixed_keys_into(&mut st, "header_", "headers");
            }
        }

        if let Some(prefix) = section_name.strip_prefix("range:") {
            // Expand into {prefix}_{i} per-port proxies (Go renderRangeProxyTemplates,
            // pkg/config/legacy/client.go:289-336). local_port/remote_port accept a
            // comma-separated string ("6000-6002,6010"), an unquoted single port
            // (6000 — ini_to_toml makes it Integer), or an array. The array is the
            // spelling a TOML/JSON/YAML legacy-shaped section carries
            // (`"local_port": [6010, "6011-6012"]`); the INI reader also produces one
            // for a comma list that renders back verbatim (`6010-6012,6020`), and
            // keeps the list as text when it does not (a space, an escape or a
            // trailing comma), which the String arm below handles. Accepting the
            // array only adds cases: before, an array here was `None` and the whole
            // section was dropped with the warning below.
            fn ini_port_numbers(v: &Value) -> Option<Vec<u16>> {
                match v {
                    Value::String(s) => ini_range_numbers(s),
                    Value::Integer(i) if *i >= 0 && *i <= i64::from(u16::MAX) => {
                        Some(vec![*i as u16])
                    }
                    Value::Array(items) => {
                        let mut out = Vec::new();
                        for item in items {
                            match item {
                                Value::String(s) => out.extend(ini_range_numbers(s)?),
                                Value::Integer(i) if *i >= 0 && *i <= i64::from(u16::MAX) => {
                                    out.push(*i as u16);
                                }
                                _ => return None,
                            }
                            if out.len() > MAX_RANGE_EXPANSION_NUMBERS {
                                return None;
                            }
                        }
                        Some(out)
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
            // Go expands the template into {prefix}_{i} sections and only then
            // dispatches on `role` (client.go:252-285), so a `role = visitor`
            // range builds one *visitor* per port, not a proxy. Route the
            // generated element to the same target the rest of the collector
            // uses, and record its index there: the strip pass keeps the
            // visitor-only keys (`bind_addr`, `bind_port`, `server_name`) only
            // when the element is known to be a visitor. The `start` filter is
            // applied to the *generated* names, like Go: `start = p2` with a
            // bad-role `[range:p]` is rc 0 in both Go modes (measured), while
            // `start = p_0` refuses it.
            let started: Vec<usize> = (0..local_ports.len())
                .filter(|i| ini_section_started(start, &format!("{prefix}_{i}"), legacy_ini))
                .collect();
            if started.is_empty() {
                continue;
            }
            let role_is_visitor = match ini_role(&st) {
                Some(IniRole::Visitor) => true,
                Some(IniRole::Server) => false,
                // Go's generated `{prefix}_{i}` sections are dispatched like any
                // other, so a refused role is reported under the first generated
                // name that is actually started: measured, `[range:p] role =
                // "weird" local_port = 8080 remote_port = 18080` is rc 1 in both
                // loader modes with `proxy p_0 role should be 'server' or
                // 'visitor'`.
                None => {
                    let name = format!("{prefix}_{}", started[0]);
                    return Err(format!("proxy {name} role should be 'server' or 'visitor'"));
                }
            };
            for (i, (lp, rp)) in local_ports.into_iter().zip(remote_ports).enumerate() {
                if !started.contains(&i) {
                    continue;
                }
                let mut t = st.clone();
                t.insert("name".to_string(), Value::String(format!("{prefix}_{i}")));
                t.insert("local_port".to_string(), Value::Integer(i64::from(lp)));
                t.insert("remote_port".to_string(), Value::Integer(i64::from(rp)));
                let target_key = if role_is_visitor {
                    "visitors"
                } else {
                    "proxies"
                };
                let arr = table
                    .entry(target_key.to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(arr) = arr {
                    if role_is_visitor {
                        visitor_indices.push(arr.len());
                    } else {
                        proxy_indices.push(arr.len());
                    }
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
            if target_key == "visitors" {
                visitor_indices.push(arr.len());
            } else {
                proxy_indices.push(arr.len());
            }
            arr.push(Value::Table(st));
        }
    }
    Ok((proxy_indices, visitor_indices))
}

/// The two `role` values Go's legacy reader accepts (`server` is also the
/// default for a missing or empty key).
enum IniRole {
    Server,
    Visitor,
}

/// Classify a legacy `.ini` section's `role` key, or `None` when Go refuses the
/// section.
///
/// `pkg/config/legacy/client.go:257-268`: `roleType := section.Key("role")
/// .String()`, `if roleType == "" { roleType = "server" }`, then a switch whose
/// `default:` arm is `proxy %s role should be 'server' or 'visitor'`. The
/// comparison is exact and case-sensitive, and Go sees the *text* of the value,
/// so a non-string spelling (an unquoted `role = 1`) is a refusal too.
fn ini_role(t: &toml::Table) -> Option<IniRole> {
    match t.get("role") {
        None => Some(IniRole::Server),
        Some(toml::Value::String(s)) if s.is_empty() || s == "server" => Some(IniRole::Server),
        Some(toml::Value::String(s)) if s == "visitor" => Some(IniRole::Visitor),
        Some(_) => None,
    }
}

/// Is a legacy `.ini` section dispatched by Go at all?
///
/// Go's `LoadAllProxyConfsFromIni` (`pkg/config/legacy/client.go:227-262`) builds
/// `startProxy` from `[common] start` and skips every named section not in it
/// unless the list is empty; generated range sections are filtered by their
/// generated names. `start` is that captured `[common]` value, never the root
/// key a `[start]` **section** occupies. `legacy_ini` is `false` for a
/// `[common]`-less `.ini` (Go's v1 decoder, where only the runtime `start`
/// filter — `pkg/config/load.go:479-489`, `frp-client/src/service.rs` — applies).
fn ini_section_started(start: Option<&toml::Value>, name: &str, legacy_ini: bool) -> bool {
    if !legacy_ini {
        return true;
    }
    match start.and_then(ini_start_names) {
        None => true,
        Some(names) => names.contains(name),
    }
}

/// The `[common] start` names held by the captured `value`, or `None` when the
/// list is absent or empty (Go's `startAll`), so every section is dispatched.
///
/// Go's `Start []string \`ini:"start"\`` (`pkg/config/legacy/client.go:119`) is
/// filled by `gopkg.in/ini`'s reflection reader, which trims each comma element
/// (`Key.Strings(",")`, key.go:492), so `start = p2, p1` selects both (measured:
/// the `[p1] role = "weird"` refusal names `p1`, not ` p1`). An `Array` here is
/// the reader's lossless spelling of that same text, so its elements are
/// re-rendered; a `String` is split with the same trimming splitter.
pub(super) fn ini_start_names(value: &toml::Value) -> Option<std::collections::HashSet<String>> {
    let names: Vec<String> = match value {
        toml::Value::Array(items) => items.iter().map(super::format::ini_value_text).collect(),
        toml::Value::String(s) => super::format::split_ini_list(s),
        toml::Value::Integer(i) => vec![i.to_string()],
        toml::Value::Float(f) => vec![f.to_string()],
        toml::Value::Boolean(b) => vec![b.to_string()],
        toml::Value::Datetime(d) => vec![d.to_string()],
        toml::Value::Table(_) => return None,
    };
    if names.is_empty() {
        None
    } else {
        Some(names.into_iter().collect())
    }
}

/// Capture Go's legacy `start` list from the `[common]` table, before the hoist
/// removes it.
///
/// Go fills the legacy common config — including `Start []string \`ini:"start"\``
/// (`pkg/config/legacy/client.go:119`) — from the `[common]` section alone
/// (`UnmarshalClientConfFromIni`: `GetSection("common")` + `MapTo`,
/// `pkg/config/legacy/client.go:173-200`), so a `start = …` key in the
/// DefaultSection is ignored there. The hoist's `or_insert` would instead let
/// such a key win, so it is captured here: it drives the dispatch filter
/// (`ini_section_started`) and is written back by [`legacy_start_override`].
fn legacy_common_start(table: &toml::Table, legacy_ini: bool) -> Option<toml::Value> {
    if !legacy_ini {
        return None;
    }
    table
        .get("common")
        .and_then(toml::Value::as_table)
        .and_then(|common| common.get("start"))
        .cloned()
}

/// Write the captured `[common] start` over the root `start` key, **after** the
/// legacy sections are collected, so a `[start]` section — which lives under
/// that same key — is not destroyed before Go's dispatch filter sees it.
///
/// A DefaultSection `start` is dropped when `[common]` has none: Go's list is
/// then empty, i.e. `startAll`. Measured on Go v0.71.0: a DefaultSection
/// `start = p2` before `[common]` still refuses `[p1] role = "weird"`, while
/// `[common] start = p1` plus a DefaultSection `start = p2` dispatches `p2`.
fn legacy_start_override(table: &mut toml::Table, legacy_ini: bool, start: Option<toml::Value>) {
    if !legacy_ini {
        return;
    }
    table.remove("start");
    if let Some(start) = start {
        table.insert("start".to_string(), start);
    }
}

/// Normalize Go-format proxy sub-tables onto each `proxies` element.
///
/// `legacy_indices` are the element indices `collect_legacy_ini_proxy_sections`
/// created. They gate the folds that only Go's legacy INI path justifies (today
/// `plugin_header_*`, which Go's conversion reads only for three plugin types);
/// a `[[proxies]]` element written directly in TOML/YAML/JSON must keep the v1
/// surface's behaviour, where those flat spellings are not Go names.
fn normalize_proxies(table: &mut toml::Table, legacy_indices: &[usize]) {
    use toml::Value;

    let proxies = match table.get_mut("proxies") {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    for (index, proxy_val) in proxies.iter_mut().enumerate() {
        let is_legacy = legacy_indices.contains(&index);
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
            plugin_table.insert("type".to_string(), Value::String(plugin_type.clone()));

            // `plugin_header_*` is Go's spelling for plugin request headers —
            // `transformHeadersFromPluginParams` (pkg/config/legacy/conversion.go:171-181)
            // is called only by the http2https / https2http / https2https arms
            // (conversion.go:217,228,236); every other plugin type drops the
            // parameters, so only those three fold here. A `plugin_header_*` on
            // another type stays a plugin key: the legacy-IN I strip pass drops
            // it (Go ignores it), and a v1 `[[proxies]]` element refuses it.
            // Only for elements the legacy collector produced: Go's legacy
            // conversion reads `plugin_header_*` for these three plugin types,
            // but the flat plugin spelling is not part of the v1 TOML surface —
            // on a `[[proxies]]` element Go rejects `plugin` itself as a string,
            // and folding the headers there would silently *honour* a key that
            // was previously dropped.
            let consumes_plugin_headers = is_legacy
                && matches!(
                    plugin_type.as_str(),
                    "http2https" | "https2http" | "https2https"
                );
            let mut plugin_request_headers = toml::Table::new();

            let plugin_keys: Vec<String> = proxy_table
                .keys()
                .filter(|k| k.starts_with("plugin_") || k.starts_with("plugin"))
                .cloned()
                .collect();
            for key in plugin_keys {
                if let Some(v) = proxy_table.remove(&key) {
                    if let Some(name) = key.strip_prefix("plugin_header_") {
                        if consumes_plugin_headers && !name.is_empty() {
                            plugin_request_headers.insert(name.to_string(), v);
                            continue;
                        }
                    }
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
            if !plugin_request_headers.is_empty() {
                plugin_table.insert(
                    "request_headers".to_string(),
                    Value::Table(plugin_request_headers),
                );
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

        // Go frp compat (client/health/health.go:57-64): the health check
        // interval/timeout/maxFailed fields are Go `int` fields where `<= 0`
        // falls back to the defaults. The ProxyConfig fields are u64/u32, so
        // a bare `-1` (accepted by Go) would fail serde and kill the whole
        // config load on every path — file, --config-dir, reload, and the
        // admin API all funnel through normalize_client_config, and the
        // `[proxies.healthCheck]`/legacy-INI keys were flattened to these
        // names just above. Clamp `<= 0` to the Go defaults pre-
        // deserialization; the runtime `== 0` fallback (frp-client
        // service.rs spawn_health_checks) remains for programmatic configs.
        for (key, default) in [
            ("health_check_interval_seconds", 10i64),
            ("health_check_timeout_seconds", 3i64),
            ("health_check_max_failed", 1i64),
        ] {
            if let Some(Value::Integer(n)) = proxy_table.get(key) {
                if *n <= 0 {
                    proxy_table.insert(key.to_string(), Value::Integer(default));
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
