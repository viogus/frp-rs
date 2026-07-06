//! Runtime config store CRUD interface.
//!
//! Port of Go frp v0.69.1 `client/configmgmt/types.go`.
//! Interface only — implementations live in `frp-client`.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

/// Errors for config store operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigStoreError {
    #[error("invalid argument")]
    InvalidArgument,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("store disabled")]
    StoreDisabled,
    #[error("apply config failed: {0}")]
    ApplyConfig(String),
}

/// Interface for runtime proxy/visitor config CRUD.
///
/// Implementations provide file reload, proxy/visitor lifecycle management,
/// and optional persistence.
#[async_trait]
pub trait ConfigManager: Send + Sync {
    /// Reload config from file. If `strict`, unregistered proxies cause errors.
    async fn reload_from_file(&self, strict: bool) -> Result<(), ConfigStoreError>;

    /// Read raw config file content.
    async fn read_config_file(&self) -> Result<String, ConfigStoreError>;
    /// Write raw config file content.
    async fn write_config_file(&self, content: &[u8]) -> Result<(), ConfigStoreError>;

    /// Check whether config store is enabled.
    fn store_enabled(&self) -> bool;
    /// Check whether a specific proxy is managed by the store.
    fn is_store_proxy_enabled(&self, name: &str) -> bool;

    // ── Proxy CRUD ─────────────────────────────────────────────

    /// List all store-managed proxies.
    async fn list_store_proxies(&self) -> Result<Vec<Value>, ConfigStoreError>;
    /// Get a store-managed proxy by name.
    async fn get_store_proxy(&self, name: &str) -> Result<Value, ConfigStoreError>;
    /// Create a store-managed proxy. Returns the created config.
    async fn create_store_proxy(&self, cfg: Value) -> Result<Value, ConfigStoreError>;
    /// Update a store-managed proxy. Returns the updated config.
    async fn update_store_proxy(
        &self,
        name: &str,
        cfg: Value,
    ) -> Result<Value, ConfigStoreError>;
    /// Delete a store-managed proxy.
    async fn delete_store_proxy(&self, name: &str) -> Result<(), ConfigStoreError>;

    // ── Visitor CRUD ───────────────────────────────────────────

    /// List all store-managed visitors.
    async fn list_store_visitors(&self) -> Result<Vec<Value>, ConfigStoreError>;
    /// Get a store-managed visitor by name.
    async fn get_store_visitor(&self, name: &str) -> Result<Value, ConfigStoreError>;
    /// Create a store-managed visitor. Returns the created config.
    async fn create_store_visitor(&self, cfg: Value) -> Result<Value, ConfigStoreError>;
    /// Update a store-managed visitor. Returns the updated config.
    async fn update_store_visitor(
        &self,
        name: &str,
        cfg: Value,
    ) -> Result<Value, ConfigStoreError>;
    /// Delete a store-managed visitor.
    async fn delete_store_visitor(&self, name: &str) -> Result<(), ConfigStoreError>;

    /// Graceful shutdown with the given timeout.
    async fn graceful_close(&self, timeout: Duration);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(ConfigStoreError::InvalidArgument.to_string(), "invalid argument");
        assert_eq!(ConfigStoreError::NotFound.to_string(), "not found");
        assert_eq!(ConfigStoreError::Conflict.to_string(), "conflict");
        assert_eq!(ConfigStoreError::StoreDisabled.to_string(), "store disabled");
        assert_eq!(
            ConfigStoreError::ApplyConfig("bad yaml".into()).to_string(),
            "apply config failed: bad yaml"
        );
    }

    #[test]
    fn test_error_debug() {
        let e = ConfigStoreError::NotFound;
        assert!(format!("{e:?}").contains("NotFound"));
    }

    #[test]
    fn test_trait_object_safe() {
        // Verify ConfigManager can be used as trait object
        fn _accept(_: Box<dyn ConfigManager>) {}
    }
}
