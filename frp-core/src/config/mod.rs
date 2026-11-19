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

/// Deserializer for `[transport.kcp] deadLink`: reject the degenerate range at
/// load time.
///
/// The state machine tears a session down once a segment has been transmitted
/// `dead_link` times, so the first transmission already consumes one count: a
/// bound of 1 kills the session on its first write and 2 on the first
/// retransmission (which an ordinary reorder triggers). Both read as "the
/// transport mysteriously never connects", so they are refused with a message
/// that names the key; unset stays 20 (kcp-go's value).
pub(crate) fn deserialize_kcp_dead_link<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    match u32::deserialize(deserializer)? {
        n if n < crate::KCP_DEAD_LINK_MIN => Err(serde::de::Error::custom(
            "transport.kcp.deadLink must be at least 3 (unset = 20); the first transmission counts toward the bound",
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
