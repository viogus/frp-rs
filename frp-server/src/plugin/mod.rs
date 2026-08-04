#[cfg(feature = "http-proxy")]
mod http;
#[cfg(feature = "http-proxy")]
pub(crate) use http::HttpPluginManager;

#[cfg(not(feature = "http-proxy"))]
/// Stub plugin manager that always allows operations.
pub struct HttpPluginManager;

#[cfg(not(feature = "http-proxy"))]
impl HttpPluginManager {
    pub fn new(_configs: Vec<frp_core::config::HttpPluginConfig>) -> Self {
        Self
    }
    /// Stub: no plugins are ever configured in this build.
    pub fn is_empty(&self) -> bool {
        true
    }
    pub async fn notify(&self, _op: &str, _content: serde_json::Value) -> Result<(), String> {
        Ok(())
    }
}
