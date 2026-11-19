mod server;
pub use metrics_server::{MetricsServerConfig, MetricsServerTlsConfig};
pub use server::*;

mod restart_only;
pub use restart_only::*;

mod client;
mod metrics_server;
pub use client::*;

mod loader;
pub use loader::*;

mod normalize;

mod file;
pub use file::*;

mod format;

mod ini_lenient;

mod strict;

/// Load server configs from a directory, merging all `.toml` files.
#[cfg(test)]
mod tests;

/// Deserializer for `[transport.kcp] deadLink`: reject zero at load time.
///
/// A zero retransmission bound would declare a session dead on its first RTO,
/// which reads as "the transport mysteriously never connects". Fail with a
/// message that names the key instead; unset stays 20 (kcp-go's value).
pub(crate) fn deserialize_kcp_dead_link<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    match u32::deserialize(deserializer)? {
        0 => Err(serde::de::Error::custom(
            "transport.kcp.deadLink must be at least 1 (unset = 20)",
        )),
        other => Ok(other),
    }
}

/// Deserializer for `workerThreads`: reject zero at load time.
///
/// Zero would make tokio's runtime builder panic, so a config that says
/// `workerThreads = 0` fails with a message that names the key instead of
/// dying later with no context. `null`/absent stays `None` (binary default).
pub(crate) fn deserialize_worker_threads<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    match Option::<usize>::deserialize(deserializer)? {
        Some(0) => Err(serde::de::Error::custom(
            "workerThreads must be at least 1 (unset = the binary's default)",
        )),
        other => Ok(other),
    }
}
