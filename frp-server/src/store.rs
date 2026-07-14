//! File-backed persistence for the dashboard proxy config store.
//!
//! The store survives server restarts: configs created via POST /api/store/proxies
//! are written to a JSON file atomically, and reloaded on next startup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use tracing::{error, info, warn};

use frp_core::config::ProxyConfig;

/// Derive the store file path from the server config file path.
///
/// `frps.toml` → `frps_store.json` in the same directory.
/// Falls back to `./frps-store.json` when no config file is provided.
pub fn resolve_store_path(config_file: &Option<String>) -> PathBuf {
    if let Some(ref path_str) = config_file {
        let p = Path::new(path_str);
        if let (Some(parent), Some(stem)) = (p.parent(), p.file_stem()) {
            let mut name = stem.to_os_string();
            name.push("_store.json");
            return parent.join(name);
        }
    }
    PathBuf::from("frps-store.json")
}

/// Load persisted proxy configs from the store file.
///
/// Returns an empty map on any error — a missing or corrupt store file
/// is not a fatal condition (next save will overwrite it).
pub fn load_store(path: &Path) -> HashMap<String, ProxyConfig> {
    let json_str = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(path = %path.display(), "no existing store file, starting fresh");
            return HashMap::new();
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to read store file, starting fresh");
            return HashMap::new();
        }
    };

    match serde_json::from_str::<HashMap<String, ProxyConfig>>(&json_str) {
        Ok(map) => {
            info!(count = map.len(), path = %path.display(), "loaded stored proxy configs");
            map
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "store file is corrupt, starting fresh");
            HashMap::new()
        }
    }
}

/// Atomically persist proxy configs to the store file.
///
/// Writes to a temporary file then renames it in place, so a crash or
/// disk-full error never leaves a partially-written store.
pub fn save_store(path: &Path, configs: &HashMap<String, ProxyConfig>) {
    let json_str = match serde_json::to_string_pretty(configs) {
        Ok(s) => s,
        Err(e) => {
            error!(path = %path.display(), error = %e, "failed to serialize store");
            return;
        }
    };

    // Unique temp file name to avoid races between concurrent dashboard handlers.
    // Includes both a nanosecond timestamp and a random suffix to prevent
    // collisions under concurrent writes from multiple handler invocations.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let random_suffix: u16 = rand::thread_rng().gen();
    let tmp_path = {
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(format!(".{nanos}_{random_suffix:04x}.tmp"));
        PathBuf::from(tmp)
    };

    if let Err(e) = std::fs::write(&tmp_path, &json_str) {
        error!(path = %tmp_path.display(), error = %e, "failed to write store temp file");
        return;
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        error!(from = %tmp_path.display(), to = %path.display(), error = %e,
            "failed to atomically rename store file");
        // Clean up the temp file on failure
        let _ = std::fs::remove_file(&tmp_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_with_valid_config_file() {
        let path = resolve_store_path(&Some("/etc/frps/frps.toml".into()));
        assert_eq!(path, PathBuf::from("/etc/frps/frps_store.json"));
    }

    #[test]
    fn resolve_with_none() {
        let path = resolve_store_path(&None);
        assert_eq!(path, PathBuf::from("frps-store.json"));
    }

    #[test]
    fn resolve_with_relative_path() {
        let path = resolve_store_path(&Some("configs/a.toml".into()));
        assert_eq!(path, PathBuf::from("configs/a_store.json"));
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let map = load_store(Path::new("/nonexistent/frps_store_never_created.json"));
        assert!(map.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("frps_test_store_{}.json", std::process::id()));
        let mut map = HashMap::new();
        map.insert(
            "test-proxy".into(),
            ProxyConfig {
                name: "test-proxy".into(),
                proxy_type: "tcp".into(),
                remote_port: 8080,
                local_ip: "127.0.0.1".into(),
                local_port: 80,
                ..Default::default()
            },
        );

        save_store(&tmp, &map);
        assert!(tmp.exists());

        let loaded = load_store(&tmp);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["test-proxy"].remote_port, 8080);
        assert_eq!(loaded["test-proxy"].local_ip, "127.0.0.1");

        // Clean up
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn save_empty_store() {
        let tmp = std::env::temp_dir().join(format!("frps_test_empty_{}.json", std::process::id()));
        let map: HashMap<String, ProxyConfig> = HashMap::new();

        save_store(&tmp, &map);
        assert!(tmp.exists());

        let loaded = load_store(&tmp);
        assert!(loaded.is_empty());

        let _ = std::fs::remove_file(&tmp);
    }
}
