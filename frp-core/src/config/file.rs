use std::path::Path;

use super::client::ClientConfig;
use super::loader::{validate_client_config, validate_server_config};
use super::normalize::{load_config_from_file, normalize_client_config, normalize_server_config};
use super::server::ServerConfig;
use super::{known_client_keys, known_server_keys};

/// Load a server configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
pub fn load_server_config(
    path: &str,
    strict_config: bool,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_config_from_file::<ServerConfig>(
        path,
        strict_config,
        known_server_keys,
        normalize_server_config,
        validate_server_config,
    )?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

/// Load a client configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
pub fn load_client_config(
    path: &str,
    strict_config: bool,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_config_from_file::<ClientConfig>(
        path,
        strict_config,
        known_client_keys,
        normalize_client_config,
        validate_client_config,
    )?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

/// Process `includes` directives in a TOML config: for each glob pattern,
/// find matching files relative to `base_dir`, parse each, and deep-merge
/// into the main config. Removes the `includes` key after processing.
pub(super) fn process_includes(
    value: &mut toml::Value,
    base_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use toml::Value;

    let table = match value.as_table_mut() {
        Some(t) => t,
        None => return Ok(()),
    };

    // Extract includes list (support both "includes" and "include" keys)
    let patterns: Vec<String> = match table.remove("includes").or_else(|| table.remove("include")) {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => vec![s],
        _ => Vec::new(),
    };

    if patterns.is_empty() {
        return Ok(());
    }

    for pattern in &patterns {
        let full_pattern = if Path::new(pattern).is_absolute() {
            pattern.clone()
        } else {
            base_dir.join(pattern).to_string_lossy().to_string()
        };

        let paths = match simple_glob(&full_pattern) {
            Ok(paths) => paths,
            Err(_) => continue,
        };

        for path in &paths {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Include file {}: read error: {}", path.display(), e);
                    continue;
                }
            };
            let inc_value: Value = match toml::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Include file {}: parse error: {}", path.display(), e);
                    continue;
                }
            };

            // Deep-merge included config into main config
            deep_merge_toml(value, &inc_value);
            tracing::debug!(path = %path.display(), "Merged include file: {}", path.display());
        }
    }

    Ok(())
}

/// Simple glob matching that supports a single `*` wildcard per path component.
/// Returns sorted list of matching file paths.
fn simple_glob(pattern: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let pattern_path = Path::new(pattern);

    // Split into: base directory (non-wildcard prefix) + wildcard component
    let parent = pattern_path.parent().unwrap_or(Path::new("."));
    let filename_part = pattern_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("*");

    if !filename_part.contains('*') {
        // No wildcard — check if exact file exists
        let path = Path::new(pattern);
        if path.is_file() {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    if !parent.exists() || !parent.is_dir() {
        return Ok(Vec::new());
    }

    // Build prefix/suffix for matching
    let (prefix, suffix) = if let Some(pos) = filename_part.find('*') {
        (&filename_part[..pos], &filename_part[pos + 1..])
    } else {
        (filename_part, "")
    };

    let ext = pattern_path.extension().and_then(|s| s.to_str());

    let mut results = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Match extension
        if let Some(ext) = ext {
            if path.extension().and_then(|s| s.to_str()) != Some(ext) {
                continue;
            }
        }
        // Match prefix and suffix
        if name.starts_with(prefix) && name.ends_with(suffix) {
            results.push(path);
        }
    }

    results.sort();
    Ok(results)
}

/// Deep-merge two TOML values. `base` is mutated to include all keys from `overlay`.
/// - Scalars: overlay replaces base
/// - Tables: recursively merged
/// - Arrays: concatenated (base + overlay)
fn deep_merge_toml(base: &mut toml::Value, overlay: &toml::Value) {
    use toml::Value;

    match (base, overlay) {
        (Value::Table(ref mut base_table), Value::Table(ref overlay_table)) => {
            for (key, val) in overlay_table {
                match base_table.get_mut(key) {
                    Some(base_val) => {
                        deep_merge_toml(base_val, val);
                    }
                    None => {
                        base_table.insert(key.clone(), val.clone());
                    }
                }
            }
        }
        (Value::Array(ref mut base_arr), Value::Array(ref overlay_arr)) => {
            base_arr.extend(overlay_arr.clone());
        }
        (base_val, _) => {
            *base_val = overlay.clone();
        }
    }
}

/// Collect all non-directory entries from a directory tree (recursive walk).
/// Returns file paths in sorted order. Used for `--config-dir` mode.
pub fn collect_config_files(
    dir: &Path,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_config_files_inner(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_config_files_inner(
    dir: &Path,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !dir.is_dir() {
        return Err(format!("not a directory: {}", dir.display()).into());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_config_files_inner(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|ext| ext == "toml" || ext == "ini" || ext == "json")
        {
            files.push(path);
        }
    }
    Ok(())
}
