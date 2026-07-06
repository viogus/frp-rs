pub mod state;
pub mod store;
pub mod service;
pub mod control;
pub mod proxy;
pub mod vhost;
#[cfg(feature = "dashboard")]
pub mod dashboard;
#[cfg(feature = "dashboard")]
pub mod event;
pub mod nathole;
pub mod tcpmux;
pub mod metrics;
pub mod plugin;
#[cfg(feature = "ssh")]
pub mod ssh_gateway;
pub mod handlers;
pub mod registry;

/// Constant-time string comparison for credential verification.
/// Prevents timing side-channel attacks on HTTP Basic Auth and
/// proxy authorization credentials.
pub(crate) fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}
