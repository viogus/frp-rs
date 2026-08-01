//! File-backed runtime config store.
//!
//! Port of Go frp v0.70.1 `pkg/config/source/store.go`. Proxies and visitors
//! managed through the `/api/store/*` admin endpoints are persisted to a JSON
//! file and re-loaded on startup, overlaying the config file as a
//! higher-priority source.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};

const VALID_PROXY_TYPES: &[&str] = &[
    "tcp", "udp", "http", "https", "stcp", "xtcp", "sudp", "tcpmux",
];
const VALID_VISITOR_TYPES: &[&str] = &["stcp", "sudp", "xtcp"];

/// Errors returned by store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("persist failed: {0}")]
    Persist(String),
    #[error("load failed: {0}")]
    Load(String),
}

/// JSON file layout. Entries are typed by their `type` field, matching the
/// Go frp store file (`{"proxies": [...], "visitors": [...]}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoreData {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<ProxyConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visitors: Vec<VisitorConfig>,
}

type StoreMaps = (HashMap<String, ProxyConfig>, HashMap<String, VisitorConfig>);

/// Thread-safe, file-backed proxy/visitor store.
pub struct StoreSource {
    path: PathBuf,
    inner: Mutex<StoreInner>,
}

struct StoreInner {
    proxies: HashMap<String, ProxyConfig>,
    visitors: HashMap<String, VisitorConfig>,
}

impl StoreSource {
    /// Open the store at `path`, loading existing entries if the file exists.
    ///
    /// A missing file starts an empty store (Go frp compat). A corrupt file or
    /// invalid entry is an error so the user is not silently reset at startup.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(StoreError::InvalidArgument("path is required".into()));
        }
        let (proxies, visitors) = if path.exists() {
            load_from_file(&path)?
        } else {
            (HashMap::new(), HashMap::new())
        };
        Ok(Self {
            path,
            inner: Mutex::new(StoreInner { proxies, visitors }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reload entries from disk. Used before merging so external edits made
    /// through another process are reflected in the running service.
    pub fn reload(&self) -> Result<(), StoreError> {
        let (proxies, visitors) = load_from_file(&self.path)?;
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        inner.proxies = proxies;
        inner.visitors = visitors;
        Ok(())
    }

    pub fn get_proxy(&self, name: &str) -> Option<ProxyConfig> {
        self.inner
            .lock()
            .expect("store mutex poisoned")
            .proxies
            .get(name)
            .cloned()
    }

    pub fn get_visitor(&self, name: &str) -> Option<VisitorConfig> {
        self.inner
            .lock()
            .expect("store mutex poisoned")
            .visitors
            .get(name)
            .cloned()
    }

    pub fn all_proxies(&self) -> Vec<ProxyConfig> {
        let inner = self.inner.lock().expect("store mutex poisoned");
        let mut values: Vec<ProxyConfig> = inner.proxies.values().cloned().collect();
        values.sort_by(|a, b| a.name.cmp(&b.name));
        values
    }

    pub fn all_visitors(&self) -> Vec<VisitorConfig> {
        let inner = self.inner.lock().expect("store mutex poisoned");
        let mut values: Vec<VisitorConfig> = inner.visitors.values().cloned().collect();
        values.sort_by(|a, b| a.name.cmp(&b.name));
        values
    }

    pub fn add_proxy(&self, proxy: ProxyConfig) -> Result<ProxyConfig, StoreError> {
        validate_proxy(&proxy)?;
        let name = proxy.name.clone();
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if inner.proxies.contains_key(&name) {
            return Err(StoreError::Conflict(format!(
                "proxy {name:?} already exists"
            )));
        }
        inner.proxies.insert(name.clone(), proxy.clone());
        if let Err(e) = save_to_file(&self.path, &inner.proxies, &inner.visitors) {
            inner.proxies.remove(&name);
            return Err(e);
        }
        Ok(proxy)
    }

    pub fn update_proxy(&self, proxy: ProxyConfig) -> Result<ProxyConfig, StoreError> {
        validate_proxy(&proxy)?;
        let name = proxy.name.clone();
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        let old = inner
            .proxies
            .get(&name)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("proxy {name:?}")))?;
        inner.proxies.insert(name.clone(), proxy.clone());
        if let Err(e) = save_to_file(&self.path, &inner.proxies, &inner.visitors) {
            inner.proxies.insert(name, old);
            return Err(e);
        }
        Ok(proxy)
    }

    pub fn remove_proxy(&self, name: &str) -> Result<(), StoreError> {
        if name.is_empty() {
            return Err(StoreError::InvalidArgument(
                "proxy name cannot be empty".into(),
            ));
        }
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        let old = inner
            .proxies
            .remove(name)
            .ok_or_else(|| StoreError::NotFound(format!("proxy {name:?}")))?;
        if let Err(e) = save_to_file(&self.path, &inner.proxies, &inner.visitors) {
            inner.proxies.insert(name.to_string(), old);
            return Err(e);
        }
        Ok(())
    }

    pub fn add_visitor(&self, visitor: VisitorConfig) -> Result<VisitorConfig, StoreError> {
        validate_visitor(&visitor)?;
        let name = visitor.name.clone();
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if inner.visitors.contains_key(&name) {
            return Err(StoreError::Conflict(format!(
                "visitor {name:?} already exists"
            )));
        }
        inner.visitors.insert(name.clone(), visitor.clone());
        if let Err(e) = save_to_file(&self.path, &inner.proxies, &inner.visitors) {
            inner.visitors.remove(&name);
            return Err(e);
        }
        Ok(visitor)
    }

    pub fn update_visitor(&self, visitor: VisitorConfig) -> Result<VisitorConfig, StoreError> {
        validate_visitor(&visitor)?;
        let name = visitor.name.clone();
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        let old = inner
            .visitors
            .get(&name)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("visitor {name:?}")))?;
        inner.visitors.insert(name.clone(), visitor.clone());
        if let Err(e) = save_to_file(&self.path, &inner.proxies, &inner.visitors) {
            inner.visitors.insert(name, old);
            return Err(e);
        }
        Ok(visitor)
    }

    pub fn remove_visitor(&self, name: &str) -> Result<(), StoreError> {
        if name.is_empty() {
            return Err(StoreError::InvalidArgument(
                "visitor name cannot be empty".into(),
            ));
        }
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        let old = inner
            .visitors
            .remove(name)
            .ok_or_else(|| StoreError::NotFound(format!("visitor {name:?}")))?;
        if let Err(e) = save_to_file(&self.path, &inner.proxies, &inner.visitors) {
            inner.visitors.insert(name.to_string(), old);
            return Err(e);
        }
        Ok(())
    }
}

/// Merge a config with all entries currently held by the store.
///
/// Store entries overlay config-file entries with the same name, matching the
/// Go frp aggregator's higher-priority store source. A disabled store entry is
/// kept in the merged result so the run loop can skip it (and so it suppresses
/// the lower-priority config entry of the same name).
pub fn merge_client_config(cfg: &ClientConfig, store: Option<&StoreSource>) -> ClientConfig {
    // Source-local enabled filtering for the config file as well: disabled
    // entries never participate in the merge (Go frp source.Load() behavior).
    let mut merged = cfg.clone();
    merged.proxies.retain(|p| p.enabled);
    merged.visitors.retain(|v| v.enabled);
    let Some(store) = store else {
        return merged;
    };
    // Go frp source semantics: enabled=false is source-local filtering, not a
    // cross-source tombstone. Disabled store entries are kept on disk but not
    // merged, so a disabled store entry does not suppress a config-file entry.
    let proxies = store
        .all_proxies()
        .into_iter()
        .filter(|p| p.enabled)
        .collect::<Vec<_>>();
    let visitors = store
        .all_visitors()
        .into_iter()
        .filter(|v| v.enabled)
        .collect::<Vec<_>>();
    merged.merge_store_items(proxies, visitors)
}

/// Validate a proxy for storage. The store keeps raw configs (no runtime
/// defaults are applied), matching Go frp's StoreSource.
fn validate_proxy(proxy: &ProxyConfig) -> Result<(), StoreError> {
    if proxy.name.is_empty() {
        return Err(StoreError::InvalidArgument(
            "proxy name cannot be empty".into(),
        ));
    }
    if !VALID_PROXY_TYPES.contains(&proxy.proxy_type.as_str()) {
        return Err(StoreError::InvalidArgument(format!(
            "invalid proxy type: {}",
            proxy.proxy_type
        )));
    }
    Ok(())
}

/// Validate a visitor for storage.
fn validate_visitor(visitor: &VisitorConfig) -> Result<(), StoreError> {
    if visitor.name.is_empty() {
        return Err(StoreError::InvalidArgument(
            "visitor name cannot be empty".into(),
        ));
    }
    if !VALID_VISITOR_TYPES.contains(&visitor.visitor_type.as_str()) {
        return Err(StoreError::InvalidArgument(format!(
            "invalid visitor type: {}",
            visitor.visitor_type
        )));
    }
    Ok(())
}

fn load_from_file(path: &Path) -> Result<StoreMaps, StoreError> {
    let data =
        std::fs::read(path).map_err(|e| StoreError::Load(format!("{}: {e}", path.display())))?;
    let stored: StoreData = serde_json::from_slice(&data)
        .map_err(|e| StoreError::Load(format!("{}: failed to parse JSON: {e}", path.display())))?;

    let mut proxies = HashMap::with_capacity(stored.proxies.len());
    for p in stored.proxies {
        validate_proxy(&p).map_err(|e| StoreError::Load(format!("{}: {e}", path.display())))?;
        proxies.insert(p.name.clone(), p);
    }

    let mut visitors = HashMap::with_capacity(stored.visitors.len());
    for v in stored.visitors {
        validate_visitor(&v).map_err(|e| StoreError::Load(format!("{}: {e}", path.display())))?;
        visitors.insert(v.name.clone(), v);
    }
    Ok((proxies, visitors))
}

fn save_to_file(
    path: &Path,
    proxies: &HashMap<String, ProxyConfig>,
    visitors: &HashMap<String, VisitorConfig>,
) -> Result<(), StoreError> {
    let stored = StoreData {
        proxies: proxies.values().cloned().collect(),
        visitors: visitors.values().cloned().collect(),
    };
    let data = serde_json::to_vec_pretty(&stored)
        .map_err(|e| StoreError::Persist(format!("failed to marshal JSON: {e}")))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::Persist(format!("failed to create directory: {e}")))?;
        }
    }

    let tmp_path = path.with_extension("json.tmp");
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp_path)?;
        f.write_all(&data)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StoreError::Persist(format!(
            "failed to write temp file: {e}"
        )));
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StoreError::Persist(format!(
            "failed to rename temp file: {e}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(name: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 9000,
            ..Default::default()
        }
    }

    fn visitor(name: &str) -> VisitorConfig {
        VisitorConfig {
            name: name.into(),
            visitor_type: "stcp".into(),
            server_name: "server".into(),
            secret_key: "secret".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: 8081,
            ..Default::default()
        }
    }

    #[test]
    fn round_trip_persists_proxies_and_visitors() {
        let path =
            std::env::temp_dir().join(format!("frpc_store_roundtrip_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
        let store = StoreSource::new(&path).unwrap();
        store.add_proxy(proxy("p1")).unwrap();
        store.add_visitor(visitor("v1")).unwrap();

        let reopened = StoreSource::new(&path).unwrap();
        assert_eq!(reopened.get_proxy("p1").unwrap().remote_port, 9000);
        assert_eq!(reopened.get_visitor("v1").unwrap().bind_port, 8081);
        assert_eq!(reopened.all_proxies().len(), 1);
        assert_eq!(reopened.all_visitors().len(), 1);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn round_trip_persists_virtual_net_visitor_plugin() {
        let path = std::env::temp_dir().join(format!(
            "frpc_store_vnet_visitor_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
        let store = StoreSource::new(&path).unwrap();
        store
            .add_visitor(VisitorConfig {
                name: "vnet-visitor".into(),
                visitor_type: "stcp".into(),
                server_name: "vnet-server".into(),
                bind_port: -1,
                plugin: Some(frp_core::config::VisitorPluginConfig {
                    plugin_type: "virtual_net".into(),
                    destination_ip: "100.86.0.1".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();

        let reopened = StoreSource::new(&path).unwrap();
        let visitor = reopened.get_visitor("vnet-visitor").unwrap();
        let plugin = visitor.plugin.expect("visitor plugin persisted");
        assert_eq!(plugin.plugin_type, "virtual_net");
        assert_eq!(plugin.destination_ip, "100.86.0.1");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn load_rejects_hand_edited_invalid_entries() {
        let path =
            std::env::temp_dir().join(format!("frpc_store_invalid_{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"proxies":[{"name":"bad","type":"made_up"}],"visitors":[]}"#,
        )
        .unwrap();

        let err = match StoreSource::new(&path) {
            Ok(_) => panic!("invalid store entry must fail at load"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::Load(_)),
            "invalid store entry must fail at load: {err}"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn add_update_remove_with_rollback_on_conflict() {
        let path =
            std::env::temp_dir().join(format!("frpc_store_crud_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
        let store = StoreSource::new(&path).unwrap();

        store.add_proxy(proxy("p1")).unwrap();
        assert!(matches!(
            store.add_proxy(proxy("p1")),
            Err(StoreError::Conflict(_))
        ));

        let mut updated = proxy("p1");
        updated.remote_port = 9100;
        store.update_proxy(updated).unwrap();
        assert_eq!(store.get_proxy("p1").unwrap().remote_port, 9100);

        store.remove_proxy("p1").unwrap();
        assert!(store.get_proxy("p1").is_none());
        assert!(matches!(
            store.remove_proxy("p1"),
            Err(StoreError::NotFound(_))
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn missing_file_starts_empty() {
        let path =
            std::env::temp_dir().join(format!("frpc_store_missing_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = StoreSource::new(&path).unwrap();
        assert!(store.all_proxies().is_empty());
        assert!(store.all_visitors().is_empty());
    }

    #[test]
    fn merge_respects_enabled_and_start_allowlist() {
        let path =
            std::env::temp_dir().join(format!("frpc_store_merge_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
        let store = StoreSource::new(&path).unwrap();
        store
            .add_proxy(ProxyConfig {
                name: "store-active".into(),
                proxy_type: "tcp".into(),
                remote_port: 7001,
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        store
            .add_proxy(ProxyConfig {
                name: "store-disabled".into(),
                proxy_type: "tcp".into(),
                remote_port: 7002,
                enabled: false,
                ..Default::default()
            })
            .unwrap();

        let base = ClientConfig {
            server_addr: "127.0.0.1".into(),
            start: vec!["store-active".into()],
            proxies: vec![
                ProxyConfig {
                    name: "config-active".into(),
                    proxy_type: "tcp".into(),
                    remote_port: 7003,
                    enabled: true,
                    ..Default::default()
                },
                ProxyConfig {
                    name: "config-disabled".into(),
                    proxy_type: "tcp".into(),
                    remote_port: 7004,
                    enabled: false,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let merged = merge_client_config(&base, Some(&store));
        let merged_names: Vec<String> = merged.proxies.iter().map(|p| p.name.clone()).collect();
        assert!(
            merged_names.contains(&"store-active".to_string()),
            "store proxy should be merged: {:?}",
            merged_names
        );
        // Disabled entries are filtered out by their source before merging.
        assert!(
            merged.proxies.iter().all(|p| p.enabled),
            "merged config should contain only enabled proxies: {:?}",
            merged.proxies
        );
        assert!(
            merged.proxies.iter().any(|p| p.name == "store-active"),
            "store proxy should be merged"
        );
        assert!(
            merged.proxies.iter().any(|p| p.name == "config-active"),
            "config proxy should be merged"
        );
        assert!(
            merged
                .proxies
                .iter()
                .all(|p| p.name != "store-disabled" && p.name != "config-disabled"),
            "disabled proxies should not appear"
        );

        // The start allowlist is honored for the merged set.
        let active = crate::service::filter_active_proxies(&merged, &merged.proxies);
        let names: Vec<&str> = active.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["store-active"]);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.tmp"));
    }
}
