// XTCP NAT hole punch coordination module.
// Go frp v0.69.1 compat: pkg/nathole/
pub mod analysis;
pub mod classify;
pub mod controller;

/// Timeout waiting for provider's NatHoleClient message (seconds).
/// Go frp v0.69.1 compat: var NatHoleTimeout.
pub static NAT_HOLE_TIMEOUT: u64 = 10;
