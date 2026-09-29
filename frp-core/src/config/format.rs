// ─── Format detection ────────────────────────────────────────────────
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum ConfigFormat {
    Toml,
    Ini,
    Json,
    Yaml,
}

pub(super) fn detect_format(path: &str) -> ConfigFormat {
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".ini") {
        ConfigFormat::Ini
    } else if path_lower.ends_with(".json") {
        ConfigFormat::Json
    } else if path_lower.ends_with(".yaml") || path_lower.ends_with(".yml") {
        ConfigFormat::Yaml
    } else {
        ConfigFormat::Toml
    }
}

pub(super) fn parse_to_toml_value(
    content: &str,
    format: ConfigFormat,
) -> Result<toml::Value, Box<dyn std::error::Error>> {
    match format {
        ConfigFormat::Toml => Ok(toml::from_str(content)?),
        ConfigFormat::Ini => ini_to_toml(content),
        ConfigFormat::Json => {
            let json_val: serde_json::Value = serde_json::from_str(content)?;
            Ok(json_to_toml(json_val))
        }
        ConfigFormat::Yaml => yaml_to_toml(content),
    }
}

/// Convert serde_json::Value to toml::Value for normalization pipeline.
fn json_to_toml(v: serde_json::Value) -> toml::Value {
    match v {
        serde_json::Value::Null => toml::Value::String(String::new()),
        serde_json::Value::Bool(b) => toml::Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => toml::Value::String(s),
        serde_json::Value::Array(arr) => {
            toml::Value::Array(arr.into_iter().map(json_to_toml).collect())
        }
        serde_json::Value::Object(map) => {
            let table: toml::Table = map.into_iter().map(|(k, v)| (k, json_to_toml(v))).collect();
            toml::Value::Table(table)
        }
    }
}

// ─── YAML parser (Go Viper-compatible, YAML 1.1 via serde_yaml_ng) ──

/// Parse YAML content into a toml::Value.
///
/// serde_yaml_ng parses into its own `Value` tree first (so YAML 1.1 scalar
/// typing — `yes`/`no`/`on`/`off` booleans, unquoted numbers, anchors — is
/// preserved), then the tree is converted to `serde_json::Value` and fed
/// through the same `json_to_toml` conversion used by the JSON path. This
/// keeps exactly one type-inference pipeline for both formats.
///
/// YAML merge keys (`<<`, <https://yaml.org/type/merge.html>) are *not*
/// applied automatically when deserializing into a `serde_yaml_ng::Value`;
/// the crate exposes `Value::apply_merge` for the YAML 1.1 merge semantics,
/// so we call it explicitly before converting.
fn yaml_to_toml(content: &str) -> Result<toml::Value, Box<dyn std::error::Error>> {
    let mut yaml_value: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(content).map_err(|e| format!("YAML parse error: {e}"))?;
    yaml_value
        .apply_merge()
        .map_err(|e| format!("YAML merge key (`<<`) error: {e}"))?;
    Ok(json_to_toml(yaml_value_to_json(yaml_value)))
}

/// Convert a serde_yaml_ng::Value into a serde_json::Value.
///
/// Mapping keys are converted to their string representation when they are
/// not already strings (YAML allows scalar keys other than strings; JSON and
/// TOML do not).
fn yaml_value_to_json(v: serde_yaml_ng::Value) -> serde_json::Value {
    match v {
        serde_yaml_ng::Value::Null => serde_json::Value::Null,
        serde_yaml_ng::Value::Bool(b) => serde_json::Value::Bool(b),
        serde_yaml_ng::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f).map_or_else(
                    || serde_json::Value::String(n.to_string()),
                    serde_json::Value::Number,
                )
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        serde_yaml_ng::Value::String(s) => serde_json::Value::String(s),
        serde_yaml_ng::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.into_iter().map(yaml_value_to_json).collect())
        }
        serde_yaml_ng::Value::Mapping(map) => {
            let object: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (yaml_key_to_string(&k), yaml_value_to_json(v)))
                .collect();
            serde_json::Value::Object(object)
        }
        // `!Tag` values (e.g. `!Newtype 1`) carry no configuration meaning;
        // unwrap to the tagged value itself (lossy: the tag name is dropped).
        serde_yaml_ng::Value::Tagged(tagged) => {
            debug!(
                "YAML tagged value in config (tag dropped): {:?}",
                tagged.tag
            );
            yaml_value_to_json(tagged.value)
        }
    }
}

/// Render a YAML mapping key as a string for the JSON/TOML path.
fn yaml_key_to_string(k: &serde_yaml_ng::Value) -> String {
    match k {
        serde_yaml_ng::Value::String(s) => s.clone(),
        serde_yaml_ng::Value::Number(n) => n.to_string(),
        serde_yaml_ng::Value::Bool(b) => b.to_string(),
        serde_yaml_ng::Value::Null => String::new(),
        // Complex keys (sequences/mappings/tags) have no JSON/TOML
        // equivalent; fall back to the YAML representation.
        other => serde_yaml_ng::to_string(other).unwrap_or_else(|_| format!("{other:?}")),
    }
}

// ─── INI parser (Go Viper-compatible type inference) ─────────────────

/// Parse INI content into a toml::Value.
///
/// Unlike Go's legacy INI loader (`gopkg.in/ini.v1`, which hands every value
/// to the target field as text and lets the *field's* Go type decide), this
/// reader infers a TOML type. The inference is **lossless**: a value only
/// becomes a TOML integer/float/boolean/array when rendering that value back
/// produces exactly the text the file wrote (`ini_value_text`). `007`, `1.50`,
/// `YES` and `a, b` therefore stay strings here — the type decision moves to
/// the target field, made by `super::ini_lenient` for `.ini` configs.
fn ini_to_toml(content: &str) -> Result<toml::Value, Box<dyn std::error::Error>> {
    let mut root = toml::Table::new();
    // Sections are collected **verbatim** first and expanded/inserted afterwards,
    // because whether a dotted header is a v1 nested table or a legacy proxy
    // section that merely *looks* like one cannot be decided from the header
    // alone: the legacy dialect's discriminator is the section's own `type` key,
    // which is only known once the whole section has been read. Deciding from
    // the header (the first cut of this change) turned `[auth.foo]`,
    // `[store.frontend]` and `[log.svc]` — proxy names that happen to start with
    // a v1 section name — into nested tables, so those proxies silently vanished
    // (measured on the real binaries: base and Go v0.71.0 register them,
    // `proxy added: [auth.foo]`; the frozen tree registered `<none>`).
    let mut sections: Vec<(String, toml::Table)> = Vec::new();
    let mut current: Option<usize> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header: [section]
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim().to_string();
            // A repeated header keeps its first position and merges into the
            // same table, which is what the old `entry(..).or_insert_with(..)`
            // did at header time.
            let index = match sections.iter().position(|(name, _)| *name == section) {
                Some(index) => index,
                None => {
                    sections.push((section, toml::Table::new()));
                    sections.len() - 1
                }
            };
            current = Some(index);
            continue;
        }

        // Key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value_str = line[eq_pos + 1..].trim();

            if key.is_empty() {
                continue;
            }

            let parsed_value = infer_ini_value(value_str);

            match current {
                Some(index) => {
                    sections[index].1.insert(key, parsed_value);
                }
                None => {
                    root.insert(key, parsed_value);
                }
            }
        }
    }

    for (name, table) in sections {
        insert_ini_section(&mut root, &name, table)?;
    }

    Ok(toml::Value::Table(root))
}

/// The v1 section names whose dotted `.ini` headers become nested tables.
///
/// Both spellings of the sections `normalize_*_config` knows, because the
/// `webServer` → `web_server` (and `httpPlugins` → `http_plugins`,
/// `featureGates` → `feature`) renames happen *after* the INI reader.
///
/// A header that is **not** in this set keeps its whole text as its key, which
/// is what the legacy dialect needs (`plugin.user-manager`, `web01`,
/// `my.proxy`), and so does a header in the set that carries a `type` key — see
/// [`ini_section_path`].
const INI_NESTED_SECTION_ROOTS: &[&str] = &[
    "common",
    "web_server",
    "webServer",
    "auth",
    "transport",
    "log",
    "proxies",
    "visitors",
    "http_plugins",
    "httpPlugins",
    "feature",
    "featureGates",
    "ssh_tunnel_gateway",
    "sshTunnelGateway",
    "observability",
    "vnet",
    "store",
];

/// The nesting path of one collected INI section, or `None` to keep its header
/// verbatim as the key.
///
/// Two things hold it back:
///
/// * **A `type` key makes the section a legacy proxy.** In the legacy INI
///   dialect every section other than `[common]` is a proxy whose name is a flat,
///   user-chosen identifier, and `collect_legacy_ini_proxy_sections` decides
///   membership by the presence of `type` — so `[auth.foo]` with `type = tcp` is
///   a proxy *named* `auth.foo`, not the `foo` child of an `auth` table. Go does
///   the same: its legacy loader looks sections up by their raw name
///   (`pkg/config/legacy/server.go`, `section.Name()`), so `[auth.foo]` is one
///   section there too. Expanding it dropped the proxy in both loader modes; the
///   guard keeps it. (The cost, documented in `docs/config.md`: a v1 nested
///   table that itself carries `type` — a `[visitors.plugin]`-style table in an
///   `.ini` — does not expand either, which is also what the base tree did.)
/// * **A non-v1 first segment, quoting, or an empty path segment** keeps the
///   header verbatim, so `[plugin.user-manager]` stays the flat key its
///   `starts_with("plugin.")` handling reads.
fn ini_section_path(section: &str, table: &toml::Table) -> Option<Vec<String>> {
    if table.contains_key("type") {
        return None;
    }
    if !section.contains('.') || section.contains('"') || section.contains('\'') {
        return None;
    }
    let parts: Vec<String> = section.split('.').map(|p| p.trim().to_string()).collect();
    if parts.iter().any(String::is_empty) {
        return None;
    }
    if !INI_NESTED_SECTION_ROOTS.contains(&parts[0].as_str()) {
        return None;
    }
    Some(parts)
}

/// Insert one collected section into the root value, either under its verbatim
/// header text or under the nesting path [`ini_section_path`] returned.
///
/// A path that runs into a value which is not a table is a genuine conflict,
/// reported rather than silently clobbering the value already set. A **verbatim**
/// name that collides with an existing non-table value keeps that value and drops
/// the section's keys, which is the long-standing `or_insert` behaviour.
fn insert_ini_section(
    root: &mut toml::Table,
    section: &str,
    table: toml::Table,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = ini_section_path(section, &table) else {
        let slot = root
            .entry(section.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let Some(dst) = slot.as_table_mut() {
            for (key, value) in table {
                dst.insert(key, value);
            }
        }
        return Ok(());
    };
    let mut cur = root;
    for (depth, part) in path.iter().enumerate() {
        let slot = cur
            .entry(part.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = slot.as_table_mut().ok_or_else(|| {
            let joined = path[..=depth].join(".");
            format!("section [{joined}] conflicts with the value already set at `{joined}`")
        })?;
    }
    for (key, value) in table {
        cur.insert(key, value);
    }
    Ok(())
}

/// Deepest legitimate nesting for infer_ini_value (array literal inside a
/// comma element), ~2 levels. The recursion cap keeps a hostile
/// `[`×k + "x" + `]`×k value from overflowing the stack — each frame
/// trims, lowercases, and re-checks, so 30k brackets SIGSEGV/abort
/// (panic="abort") at startup and on frpc reload paths. Past the cap the
/// remaining value degrades to a plain string literal.
const MAX_INI_NESTING: usize = 16;

/// Go's `ini.v1` boolean spellings — `parseBool` (`key.go:194`). The list is
/// case-sensitive there; `yes`/`no`/`1`/`0` are accepted and are *not* inferred
/// as booleans by the lossless reader, so a bool target reads them through
/// `super::ini_lenient` and the legacy-bool pre-pass below.
pub(super) fn parse_ini_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" | "YES" | "yes" | "Yes" | "y" | "ON" | "on"
        | "On" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" | "NO" | "no" | "No" | "n" | "OFF"
        | "off" | "Off" => Some(false),
        _ => None,
    }
}

/// Split a value the way Go's `Key.Strings(",")` does (`key.go:492`): on `,`,
/// trimming each element; `\,` is a literal comma; an empty value is no
/// elements and a trailing empty element is dropped.
///
/// Both the inference below and `super::ini_lenient` use this, so the array
/// form and the text form of a comma list agree — and agree with Go. Measured
/// on Go v0.71.0 (`custom_domains`, `GET /api/proxy/http`): `a\,b` →
/// `["a,b"]`, `x\,y,z` → `["x,y", "z"]`, `a.example.com,` → `["a.example.com"]`.
pub(super) fn split_ini_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    let mut items = Vec::new();
    let mut buf = String::new();
    let mut escape = false;
    for c in s.chars() {
        if escape {
            escape = false;
            if c != '\\' && c != ',' {
                buf.push('\\');
            }
            buf.push(c);
        } else if c == '\\' {
            escape = true;
        } else if c == ',' {
            items.push(buf.trim().to_string());
            buf.clear();
        } else {
            buf.push(c);
        }
    }
    if !buf.is_empty() {
        items.push(buf.trim().to_string());
    }
    items
}

/// Render a TOML value as the INI text it came from. The inverse of the
/// lossless inference below: for every value `infer_ini_value_depth` returns
/// that is not a `String`, both this and [`ini_value_json_text`] equal the
/// input text — `super::ini_lenient` relies on that when a string-typed field
/// reads an inferred value.
pub(super) fn ini_value_text(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(items) => items
            .iter()
            .map(ini_value_text)
            .collect::<Vec<_>>()
            .join(","),
        // INI never produces these; an empty rendering simply fails the
        // round-trip check below and the text is kept verbatim.
        toml::Value::Datetime(_) | toml::Value::Table(_) => String::new(),
    }
}

/// The text the **JSON projection** renders for a value — what
/// `super::ini_lenient::ini_text` gives a string-typed field, and therefore the
/// rendering that actually has to match the file.
///
/// Rust's `f64` Display and serde_json's `ryu` disagree for extreme
/// magnitudes: `10000000000000000000` is `1e+19` there and `0.0000001` is
/// `1e-7`, while both print as plain decimals here. A value whose two
/// renderings differ is kept as text by the inference, so a string field always
/// receives exactly what the file wrote.
pub(super) fn ini_value_json_text(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(|n| n.to_string())
            .unwrap_or_default(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(items) => items
            .iter()
            .map(ini_value_json_text)
            .collect::<Vec<_>>()
            .join(","),
        toml::Value::Datetime(_) | toml::Value::Table(_) => String::new(),
    }
}

/// Whether an inferred value survives both renderers — the losslessness the
/// inference promises.
fn round_trips(v: &toml::Value, raw: &str) -> bool {
    ini_value_text(v) == raw && ini_value_json_text(v) == raw
}

/// Infer INI value type matching Go Viper behavior — losslessly.
///
/// The result must satisfy both `ini_value_text(&result) == input` and
/// `ini_value_json_text(&result) == input`; otherwise the value stays a
/// `String`. See `ini_to_toml`.
fn infer_ini_value(s: &str) -> toml::Value {
    infer_ini_value_depth(s, 0)
}

fn infer_ini_value_depth(s: &str, depth: usize) -> toml::Value {
    let s = s.trim();

    if s.is_empty() {
        return toml::Value::String(String::new());
    }

    // Quoted string → strip quotes. A value that IS a lone quote character
    // (`"` or `'`, length 1) satisfies both starts_with and ends_with — the
    // old `s[1..s.len() - 1]` became `s[1..0]` and panicked ("slice index
    // starts at 1 but ends at 0"), aborting in release builds (panic=abort);
    // reachable from any `.ini` config at startup and on runtime reload
    // (frpc SIGUSR1 / admin API). Go ini.v1 keeps a lone quote as a
    // one-character literal string, so require len >= 2 and let the
    // one-char value fall through to the string branch below.
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return toml::Value::String(s[1..s.len() - 1].to_string());
    }

    // Boolean — only the canonical spellings, so the text survives the
    // round-trip. `yes`/`no`/`TRUE` stay text and are read as a boolean by
    // `super::ini_lenient` when the target field is a bool (Go's
    // `ini.v1.parseBool` accepts the wider spelling set, `key.go:194`).
    if s == "true" {
        return toml::Value::Boolean(true);
    }
    if s == "false" {
        return toml::Value::Boolean(false);
    }

    // Nested type inference (array literals / comma splits) recurses — cap
    // the depth so hostile nesting degrades to a string literal instead of
    // overflowing the stack (see MAX_INI_NESTING).
    if depth >= MAX_INI_NESTING {
        return toml::Value::String(s.to_string());
    }

    // ["a", "b"] / [] array literal → Array. This is a **frp-rs extension**,
    // not Go syntax: measured on Go v0.71.0, `custom_domains =
    // ["a.example.com","b.example.com"]` reaches frps as
    // `['["a.example.com"', '"b.example.com"]']` (ini.v1 only splits a slice
    // field on `,`; `[]` becomes `["[]"]`). Kept for the slice fields that
    // already accept it; a *string* field reading such a value is rendered by
    // `ini_value_text` as the comma-joined elements, not as the bracket text.
    // Only when the inner content looks like a list: quoted elements or at
    // least one comma. A bare "[::1]" (IPv6 literal) falls through to the
    // string branch instead of becoming the one-element array "["::1"]".
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        if inner.trim().is_empty() {
            return toml::Value::Array(Vec::new());
        }
        let looks_like_list = inner.contains('"') || inner.contains('\'') || inner.contains(',');
        if looks_like_list {
            let parts: Vec<toml::Value> = inner
                .split(',')
                .map(|p| infer_ini_value_depth(p.trim(), depth + 1))
                .collect();
            return toml::Value::Array(parts);
        }
    }

    // Comma-separated → Array (type-infer each element), but only when the
    // split round-trips through *both* renderers: `1,2` becomes an array,
    // `1, 2` keeps its space and `a\,b` keeps its backslash, and both stay
    // text — Go trims each element of a slice field and honours the escape, so
    // the text form and the array form read the same through the target type
    // (see `super::ini_lenient`). The element splitter is Go's own
    // (`Key.Strings(",")`), so `a\,b` is one element here too.
    if s.contains(',') {
        let parts: Vec<toml::Value> = split_ini_list(s)
            .into_iter()
            .map(|p| infer_ini_value_depth(&p, depth + 1))
            .collect();
        let array = toml::Value::Array(parts);
        if round_trips(&array, s) {
            return array;
        }
        return toml::Value::String(s.to_string());
    }

    // Integer / Float — only when the parsed value renders back to exactly
    // this text through **both** renderers: `007`, `+5`, `1.50`, `1e3` stay
    // strings, and are read as a number by `super::ini_lenient` when the target
    // field is numeric. The JSON check matters for extreme magnitudes, where
    // serde_json's `ryu` rendering is exponential and Rust's `f64` Display is
    // not (`1e+19` / `1e-7`): without it a string field would receive
    // `"1e+19"` instead of the `10000000000000000000` the file wrote.
    if let Ok(i) = s.parse::<i64>() {
        let v = toml::Value::Integer(i);
        if round_trips(&v, s) {
            return v;
        }
    }
    if let Ok(f) = s.parse::<f64>() {
        let v = toml::Value::Float(f);
        if round_trips(&v, s) {
            return v;
        }
    }

    // Default: string
    toml::Value::String(s.to_string())
}
