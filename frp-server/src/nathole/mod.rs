// XTCP NAT hole punch coordination module.
// Go frp v0.69.1 compat: pkg/nathole/
pub mod classify;
pub mod analysis;
pub mod controller;
pub mod discovery;

/// Timeout waiting for provider's NatHoleClient message (seconds).
/// Go frp v0.69.1 compat: var NatHoleTimeout.
pub static NAT_HOLE_TIMEOUT: i64 = 10;
