//! VNet message types — Layer 3 VPN routing messages for frp tunnel.
//!
//! Types are defined in frp-core (single source of truth) and re-exported here.

// Re-export VNet message types from frp-core (single source of truth).
pub use frp_core::msg::{VnetPacket, VnetRouteAdvertise, VnetRouteRemove};
