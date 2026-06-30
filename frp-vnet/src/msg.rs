//! VNet message types — Layer 3 VPN routing messages for frp tunnel.

use serde::{Deserialize, Serialize};

/// Client→Server: advertise a subnet this client owns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnetRouteAdvertise {
    pub proxy_name: String,
    /// CIDR subnet, e.g. "10.0.0.0/24"
    pub subnet: String,
    /// Virtual network name for isolation (empty = default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_net: Option<String>,
}

/// Client→Server: remove a previously advertised route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnetRouteRemove {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_net: Option<String>,
}

/// Bidirectional: raw IP packet wrapped for tunnel transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnetPacket {
    /// Target proxy name (routing key for server/client).
    pub proxy_name: String,
    /// Base64-encoded raw IP packet (Layer 3, no Ethernet).
    pub data: String,
}
