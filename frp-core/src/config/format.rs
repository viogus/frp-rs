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
/// Type inference rules match Go Viper behavior.
fn ini_to_toml(content: &str) -> Result<toml::Value, Box<dyn std::error::Error>> {
    let mut root = toml::Table::new();
    let mut current_section: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header: [section]
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1].trim();
            current_section = Some(section.to_string());
            root.entry(section.to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
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

            if let Some(ref section) = current_section {
                if let Some(toml::Value::Table(ref mut table)) = root.get_mut(section) {
                    table.insert(key, parsed_value);
                }
            } else {
                root.insert(key, parsed_value);
            }
        }
    }

    Ok(toml::Value::Table(root))
}

/// Infer INI value type matching Go Viper behavior.
fn infer_ini_value(s: &str) -> toml::Value {
    let s = s.trim();

    if s.is_empty() {
        return toml::Value::String(String::new());
    }

    // Quoted string → strip quotes
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        return toml::Value::String(s[1..s.len() - 1].to_string());
    }

    // Boolean
    match s.to_lowercase().as_str() {
        "true" | "yes" => return toml::Value::Boolean(true),
        "false" | "no" => return toml::Value::Boolean(false),
        _ => {}
    }

    // ["a", "b"] array literal (Go ini.v1 []string syntax) → Array
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        let parts: Vec<toml::Value> = inner
            .split(',')
            .map(|p| infer_ini_value(p.trim()))
            .collect();
        return toml::Value::Array(parts);
    }

    // Comma-separated → Array (type-infer each element)
    if s.contains(',') {
        let parts: Vec<toml::Value> = s.split(',').map(|p| infer_ini_value(p.trim())).collect();
        return toml::Value::Array(parts);
    }

    // Integer
    if let Ok(i) = s.parse::<i64>() {
        return toml::Value::Integer(i);
    }

    // Float
    if let Ok(f) = s.parse::<f64>() {
        return toml::Value::Float(f);
    }

    // Default: string
    toml::Value::String(s.to_string())
}
