use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

// ---------------------------------------------------------------
// V1 message type bytes (matching Go frp v0.71.0 protocol)
// ---------------------------------------------------------------
pub const TYPE_LOGIN: u8 = b'o';
pub const TYPE_LOGIN_RESP: u8 = b'1';
pub const TYPE_NEW_PROXY: u8 = b'p';
pub const TYPE_NEW_PROXY_RESP: u8 = b'2';
pub const TYPE_CLOSE_PROXY: u8 = b'c';
pub const TYPE_NEW_WORK_CONN: u8 = b'w';
pub const TYPE_REQ_WORK_CONN: u8 = b'r';
pub const TYPE_START_WORK_CONN: u8 = b's';
pub const TYPE_NEW_VISITOR_CONN: u8 = b'v';
pub const TYPE_NEW_VISITOR_CONN_RESP: u8 = b'3';
pub const TYPE_PING: u8 = b'h';
pub const TYPE_PONG: u8 = b'4';
pub const TYPE_UDP_PACKET: u8 = b'u';
// NAT hole punching (Go frp v0.71.0 STCP/XTCP)
pub const TYPE_NAT_HOLE_VISITOR: u8 = b'i';
pub const TYPE_NAT_HOLE_CLIENT: u8 = b'n';
pub const TYPE_NAT_HOLE_RESP: u8 = b'm';
pub const TYPE_NAT_HOLE_SID: u8 = b'5';
pub const TYPE_NAT_HOLE_REPORT: u8 = b'6';
/// Rust-only V1 extension — Go frp v0.70.0 does NOT recognize type 7.
pub const TYPE_CLOSE_PROXY_RESP: u8 = b'7';
/// Rust-only V1 extension — Go frp v0.70.0 does NOT recognize type 8.
pub const TYPE_ERROR: u8 = b'8'; // VNet (L3 VPN) message types
#[cfg(feature = "vnet")]
pub const TYPE_VNET_ROUTE_ADVERTISE: u8 = 0x40;
#[cfg(feature = "vnet")]
pub const TYPE_VNET_PACKET: u8 = 0x41;
#[cfg(feature = "vnet")]
pub const TYPE_VNET_ROUTE_REMOVE: u8 = 0x42;

// ---------------------------------------------------------------
// V2 message type IDs (matching Go frp v0.71.0 wire_v2.go)
// ---------------------------------------------------------------
pub const V2_TYPE_LOGIN: u16 = 1;
pub const V2_TYPE_LOGIN_RESP: u16 = 2;
pub const V2_TYPE_NEW_PROXY: u16 = 3;
pub const V2_TYPE_NEW_PROXY_RESP: u16 = 4;
pub const V2_TYPE_CLOSE_PROXY: u16 = 5;
pub const V2_TYPE_NEW_WORK_CONN: u16 = 6;
pub const V2_TYPE_REQ_WORK_CONN: u16 = 7;
pub const V2_TYPE_START_WORK_CONN: u16 = 8;
pub const V2_TYPE_NEW_VISITOR_CONN: u16 = 9;
pub const V2_TYPE_NEW_VISITOR_CONN_RESP: u16 = 10;
pub const V2_TYPE_PING: u16 = 11;
pub const V2_TYPE_PONG: u16 = 12;
pub const V2_TYPE_UDP_PACKET: u16 = 13;
pub const V2_TYPE_NAT_HOLE_VISITOR: u16 = 14;
pub const V2_TYPE_NAT_HOLE_CLIENT: u16 = 15;
pub const V2_TYPE_NAT_HOLE_RESP: u16 = 16;
pub const V2_TYPE_NAT_HOLE_SID: u16 = 17;
pub const V2_TYPE_NAT_HOLE_REPORT: u16 = 18;
/// UDPPacket with a dedicated binary codec, negotiated via the V2 handshake
/// (`udpPacketCodecs` capability). Go frp v0.71.0. V1 stays JSON; V2 falls
/// back to JSON `UDPPacket` (type 13) when the peer did not negotiate the
/// capability. See `frp_core::udp_binary`.
pub const V2_TYPE_UDP_PACKET_BINARY: u16 = 19;
/// Rust-only V2 extension — renumbered to 21 (was 19) because Go frp v0.71.0
/// assigned type 19 to `V2TypeUDPPacketBinary`. Go frp does NOT recognize 21.
pub const V2_TYPE_CLOSE_PROXY_RESP: u16 = 21;
/// Rust-only V2 extension — renumbered to 22 (was 20) to stay clear of Go
/// frp v0.71.0's new type 19. Go frp does NOT recognize 22.
pub const V2_TYPE_ERROR: u16 = 22;
// VNet (L3 VPN) message types
#[cfg(feature = "vnet")]
pub const V2_TYPE_VNET_ROUTE_ADVERTISE: u16 = 42;
#[cfg(feature = "vnet")]
pub const V2_TYPE_VNET_PACKET: u16 = 43;
#[cfg(feature = "vnet")]
pub const V2_TYPE_VNET_ROUTE_REMOVE: u16 = 44;

// ---------------------------------------------------------------
// Base64 helpers for UDPPacket (Go frp encodes []byte as base64)
// ---------------------------------------------------------------

fn b64_ser<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&crate::base64::encode(data))
}

fn b64_de<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    crate::base64::decode(&s).map_err(serde::de::Error::custom)
}

// ---------------------------------------------------------------
// Concrete message structs — all derive Serialize + Deserialize
// Field names match Go frp v0.71.0 JSON keys (snake_case Rust with
// serde renames where Go uses different keys).
// ---------------------------------------------------------------

/// ClientSpec carries client-specific metadata (Go frp compat).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ClientSpec {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub client_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_auth_pass: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Login {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Deliberately `i32`, not Go's int64 (round-8 note): a poolCount above
    /// 2^31-1 fails deserialization (fail-closed) instead of silently
    /// wrapping — Go frp accepts any non-negative int64, but values that
    /// large are nonsensical and the login path rejects negatives anyway
    /// ("invalid pool count, must be non-negative"). Keep this tightening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metas: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_spec: Option<ClientSpec>,
    /// Rust-only extension: Go frp v0.71.0's Login has no `multiplexer` field
    /// (msg.go:76-93) — the per-proxy `NewProxy.multiplexer` is the field Go
    /// consumes. frpc sets this to `Some("yamux")` whenever tcp-mux is
    /// proposed (the default config), so a default Rust frpc → Go frps Login
    /// carries `"multiplexer":"yamux"`; Go ignores the unknown key (benign,
    /// verified by the 86/86 compat matrix). Like the other Rust-only wire
    /// extensions, must NOT be relied on by Go peers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplexer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Server's additional auth scopes (union with client's to decide
    /// which messages need authentication).
    /// NOTE: this is a frp-rs extension — `serverAdditionalAuthScopes`
    /// does NOT exist in Go frp v0.70.1. Go servers never set it, so the
    /// field is absent on the wire (skip_serializing_if) and interop is
    /// unaffected; it only carries extra data between Rust peers.
    #[serde(
        rename = "serverAdditionalAuthScopes",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_additional_auth_scopes: Option<Vec<String>>,
}

pub type LoginResponse = LoginResp;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewProxy {
    pub proxy_name: String,
    pub proxy_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_encryption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_compression: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_str: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
    #[serde(rename = "http_user", skip_serializing_if = "Option::is_none")]
    pub http_user: Option<String>,
    #[serde(rename = "http_pwd", skip_serializing_if = "Option::is_none")]
    pub http_pwd: Option<String>,
    #[serde(
        rename = "host_header_rewrite",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_header_rewrite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "response_headers", skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "route_by_http_user", skip_serializing_if = "Option::is_none")]
    pub route_by_http_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_users: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit: Option<String>,
    #[serde(
        rename = "bandwidth_limit_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub bandwidth_limit_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metas: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplexer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_net: Option<String>,
    #[serde(
        rename = "proxy_protocol_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy_protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_subnet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnet_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnet_netmask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnet_mtu: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewProxyResp {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub type NewProxyResponse = NewProxyResp;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloseProxy {
    pub proxy_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloseProxyResp {
    pub proxy_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg(feature = "vnet")]
pub struct VnetRouteAdvertise {
    pub proxy_name: String,
    pub subnet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_net: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg(feature = "vnet")]
pub struct VnetRouteRemove {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_net: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg(feature = "vnet")]
pub struct VnetPacket {
    pub proxy_name: String,
    /// Base64-encoded raw IP packet
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewWorkConn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
}

/// Request the client to send another work connection.
///
/// `deny_unknown_fields` is intentionally omitted for forward
/// compatibility with Go frp protocol evolution — new fields added
/// by future Go frp versions must not cause deserialization failures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReqWorkConn {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartWorkConn {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether encryption is enabled for the data bridge (Rust frp extension;
    /// not in Go v0.71.0 StartWorkConn — Go ignores unknown JSON fields).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_encryption: Option<bool>,
    /// Whether compression is enabled for the data bridge (Rust frp extension;
    /// not in Go v0.71.0 StartWorkConn — Go ignores unknown JSON fields).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_compression: Option<bool>,
    /// XTCP visitor session ID for hole-punch notification (Rust frp extension).
    /// When set, this work connection is for XTCP notification delivery —
    /// the provider should initiate NAT hole punching with the visitor.
    /// When absent and proxy_type is "xtcp", this is an STCP fallback bridge.
    /// Go frp silently ignores unknown JSON fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat_hole_sid: Option<String>,
    /// XTCP visitor address for hole-punch notification (Rust frp extension).
    /// Go frp silently ignores unknown JSON fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat_hole_visitor_addr: Option<String>,
    /// Secret key for NAT hole-punch detection encryption (Go frp v0.70 compat).
    /// Go frp uses this key to encrypt/decrypt NatHoleSid detect messages
    /// during the MakeHole phase. Without it, Go provider can't decrypt
    /// NatHoleSid from Rust visitor and falls back to passive detection (TCP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ping {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pong {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewVisitorConn {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_encryption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_compression: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewVisitorConnResp {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// UDP address matching Go frp v0.71.0 `net.UDPAddr` JSON representation.
///
/// Go's `net.UDPAddr` has no `omitempty` on `Zone`, so it is ALWAYS emitted
/// on the wire (`"Zone":""` when empty). The `default` keeps deserialization
/// lenient — Go-form JSON without the key still parses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpAddr {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Zone", default)]
    pub zone: String,
}

impl UdpAddr {
    pub fn from_string(s: &str) -> Option<Self> {
        let addr: std::net::SocketAddr = s.parse().ok()?;
        Some(UdpAddr {
            ip: addr.ip().to_string(),
            port: addr.port(),
            zone: String::new(),
        })
    }
}

impl fmt::Display for UdpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UDPPacket {
    // Go frp v0.71.0: Content []byte `json:"c,omitempty"` — an empty datagram
    // OMITS "c"; default lets us deserialize it (missing field 'c' would
    // otherwise fail) and skip_serializing_if keeps Rust->Go byte-identical.
    #[serde(
        rename = "c",
        default,
        serialize_with = "b64_ser",
        deserialize_with = "b64_de",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub content: Vec<u8>,
    #[serde(rename = "l", skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<UdpAddr>,
    #[serde(rename = "r", skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<UdpAddr>,
}

// ---------------------------------------------------------------
// NAT hole punch messages (Go frp v0.71.0 STCP/XTCP)
// ---------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleVisitor {
    pub transaction_id: String,
    pub proxy_name: String,
    // Go frp v0.71.0: PreCheck bool `json:"pre_check,omitempty"` — false is
    // omitted on the wire; both forms still parse (default).
    #[serde(default, skip_serializing_if = "is_false")]
    pub pre_check: bool,
    // Phase 2 fields (pre_check=false, NAT info exchange):
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapped_addrs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_addrs: Option<Vec<String>>,
}

/// Port range for NAT hole punch candidate selection.
/// Go frp v0.71.0 compat.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PortsRange {
    #[serde(default)]
    pub from: i32,
    #[serde(default)]
    pub to: i32,
}

/// Server-recommended hole-punch behavior for a peer.
/// Go frp v0.71.0 compat: DetectBehavior in NatHoleResp.
/// CRITICAL: Go frps uses `json:"...,omitempty"` on ALL fields.
/// When an integer field is 0, Go omits it from the JSON.
/// All i32 fields below MUST have #[serde(default)] to handle this.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleDetectBehavior {
    /// Behavior mode (0-4). Determines role assignment.
    #[serde(default)]
    pub mode: i32,
    /// Role: "sender" or "receiver".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// TTL for hole-punch packets.
    #[serde(default)]
    pub ttl: i32,
    /// Delay before sending (ms).
    #[serde(default)]
    pub send_delay_ms: i32,
    /// Read timeout (ms). JSON key is "read_timeout" (Go frp compat).
    #[serde(default, rename = "read_timeout", alias = "read_timeout_ms")]
    pub read_timeout_ms: i32,
    /// Number of random ports to send from.
    #[serde(default)]
    pub send_random_ports: i32,
    /// Number of random ports to listen on.
    #[serde(default)]
    pub listen_random_ports: i32,
    /// Candidate port ranges derived from address analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_ports: Option<Vec<PortsRange>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleClient {
    pub transaction_id: String,
    pub proxy_name: String,
    /// NAT hole session ID (Go frp v0.71.0 compat: sid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// NAT traversal protocol: "quic" or "tcp" (Rust frp extension; not in
    /// Go v0.71.0 NatHoleClient — Go's NatHoleResp carries `protocol`, which
    /// is the likely confusion source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Provider/visitor addresses discovered via STUN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapped_addrs: Option<Vec<String>>,
    /// Assisted addresses (UPnP, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visitor_addr: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleResp {
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// NAT hole session ID (Go frp v0.71.0 compat: sid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// NAT traversal protocol: "quic" or "tcp" (Go frp v0.71.0 compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Candidate addresses for NAT hole punch (the OTHER side's STUN addresses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_addrs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_addrs: Option<Vec<String>>,
    /// Server-recommended hole-punch behavior (Go frp v0.71.0 compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect_behavior: Option<NatHoleDetectBehavior>,
}

/// Serde helper: skip serializing `false` bool values (match Go omitempty).
fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleSid {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub response: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    // Go frp v0.71.0: Success bool `json:"success,omitempty"` — false is
    // omitted on the wire; both forms still parse (default).
    #[serde(default, skip_serializing_if = "is_false")]
    pub success: bool,
}

// ---------------------------------------------------------------
// FrpMessage — unified enum over all message types
// NOTE: #[serde(untagged)] means ordering matters. Variants with
// more optional/overlapping fields must come after those with
// unique required fields. V1 deserialization uses type-byte dispatch
// (deserialize_v1), so untagged matching is only used for direct
// serde_json::from_value calls (tests, future code paths).
//
// WARNING (latent): CloseProxyResp is deliberately kept FIRST, which
// means it shadows every other variant whose fields it intersects in
// untagged deserialization — most notably CloseProxy, NewVisitorConn,
// NatHoleSid, and VnetRouteAdvertise, which all carry only `proxy_name`
// or overlap it. A bare `{"proxy_name": ...}` JSON value always matches
// CloseProxyResp. This is benign on the wire because V1 dispatch goes
// through the message type byte (deserialize_v1), not untagged matching,
// so no reordering was made; do not rely on untagged matching for any
// proxy_name-only message without handling CloseProxyResp first.
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum FrpMessage {
    CloseProxyResp(CloseProxyResp),
    CloseProxy(CloseProxy),
    ReqWorkConn(ReqWorkConn),
    NewProxyResp(NewProxyResp),
    NewVisitorConnResp(NewVisitorConnResp),
    Pong(Pong),
    NewProxy(Box<NewProxy>),
    UDPPacket(UDPPacket),
    StartWorkConn(Box<StartWorkConn>),
    NewVisitorConn(NewVisitorConn),
    NewWorkConn(NewWorkConn),
    Ping(Ping),
    LoginResp(LoginResp),
    Login(Box<Login>),
    NatHoleVisitor(NatHoleVisitor),
    NatHoleClient(Box<NatHoleClient>),
    NatHoleResp(Box<NatHoleResp>),
    NatHoleSid(NatHoleSid),
    NatHoleReport(NatHoleReport),
    Error(Error),
    #[cfg(feature = "vnet")]
    VnetRouteAdvertise(VnetRouteAdvertise),
    #[cfg(feature = "vnet")]
    VnetPacket(VnetPacket),
    #[cfg(feature = "vnet")]
    VnetRouteRemove(VnetRouteRemove),
}

impl FrpMessage {
    pub fn v1_type_byte(&self) -> u8 {
        match self {
            FrpMessage::Login(_) => TYPE_LOGIN,
            FrpMessage::LoginResp(_) => TYPE_LOGIN_RESP,
            FrpMessage::NewProxy(_) => TYPE_NEW_PROXY,
            FrpMessage::NewProxyResp(_) => TYPE_NEW_PROXY_RESP,
            FrpMessage::CloseProxy(_) => TYPE_CLOSE_PROXY,
            FrpMessage::NewWorkConn(_) => TYPE_NEW_WORK_CONN,
            FrpMessage::ReqWorkConn(_) => TYPE_REQ_WORK_CONN,
            FrpMessage::StartWorkConn(_) => TYPE_START_WORK_CONN,
            FrpMessage::Ping(_) => TYPE_PING,
            FrpMessage::Pong(_) => TYPE_PONG,
            FrpMessage::NewVisitorConn(_) => TYPE_NEW_VISITOR_CONN,
            FrpMessage::NewVisitorConnResp(_) => TYPE_NEW_VISITOR_CONN_RESP,
            FrpMessage::UDPPacket(_) => TYPE_UDP_PACKET,
            FrpMessage::NatHoleVisitor(_) => TYPE_NAT_HOLE_VISITOR,
            FrpMessage::NatHoleClient(_) => TYPE_NAT_HOLE_CLIENT,
            FrpMessage::NatHoleResp(_) => TYPE_NAT_HOLE_RESP,
            FrpMessage::NatHoleSid(_) => TYPE_NAT_HOLE_SID,
            FrpMessage::NatHoleReport(_) => TYPE_NAT_HOLE_REPORT,
            FrpMessage::CloseProxyResp(_) => TYPE_CLOSE_PROXY_RESP,
            FrpMessage::Error(_) => TYPE_ERROR,
            #[cfg(feature = "vnet")]
            FrpMessage::VnetRouteAdvertise(_) => TYPE_VNET_ROUTE_ADVERTISE,
            #[cfg(feature = "vnet")]
            FrpMessage::VnetPacket(_) => TYPE_VNET_PACKET,
            #[cfg(feature = "vnet")]
            FrpMessage::VnetRouteRemove(_) => TYPE_VNET_ROUTE_REMOVE,
        }
    }

    pub fn v2_type_id(&self) -> u16 {
        match self {
            FrpMessage::Login(_) => V2_TYPE_LOGIN,
            FrpMessage::LoginResp(_) => V2_TYPE_LOGIN_RESP,
            FrpMessage::NewProxy(_) => V2_TYPE_NEW_PROXY,
            FrpMessage::NewProxyResp(_) => V2_TYPE_NEW_PROXY_RESP,
            FrpMessage::CloseProxy(_) => V2_TYPE_CLOSE_PROXY,
            FrpMessage::NewWorkConn(_) => V2_TYPE_NEW_WORK_CONN,
            FrpMessage::ReqWorkConn(_) => V2_TYPE_REQ_WORK_CONN,
            FrpMessage::StartWorkConn(_) => V2_TYPE_START_WORK_CONN,
            FrpMessage::NewVisitorConn(_) => V2_TYPE_NEW_VISITOR_CONN,
            FrpMessage::NewVisitorConnResp(_) => V2_TYPE_NEW_VISITOR_CONN_RESP,
            FrpMessage::Ping(_) => V2_TYPE_PING,
            FrpMessage::Pong(_) => V2_TYPE_PONG,
            FrpMessage::UDPPacket(_) => V2_TYPE_UDP_PACKET,
            FrpMessage::NatHoleVisitor(_) => V2_TYPE_NAT_HOLE_VISITOR,
            FrpMessage::NatHoleClient(_) => V2_TYPE_NAT_HOLE_CLIENT,
            FrpMessage::NatHoleResp(_) => V2_TYPE_NAT_HOLE_RESP,
            FrpMessage::NatHoleSid(_) => V2_TYPE_NAT_HOLE_SID,
            FrpMessage::NatHoleReport(_) => V2_TYPE_NAT_HOLE_REPORT,
            FrpMessage::CloseProxyResp(_) => V2_TYPE_CLOSE_PROXY_RESP,
            FrpMessage::Error(_) => V2_TYPE_ERROR,
            #[cfg(feature = "vnet")]
            FrpMessage::VnetRouteAdvertise(_) => V2_TYPE_VNET_ROUTE_ADVERTISE,
            #[cfg(feature = "vnet")]
            FrpMessage::VnetPacket(_) => V2_TYPE_VNET_PACKET,
            #[cfg(feature = "vnet")]
            FrpMessage::VnetRouteRemove(_) => V2_TYPE_VNET_ROUTE_REMOVE,
        }
    }

    // Accessor helpers — return None on variant mismatch instead of panicking
    // (pub API, so wrong-variant calls must not be a footgun).
    pub fn as_login(&self) -> Option<&Login> {
        match self {
            FrpMessage::Login(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_login_resp(&self) -> Option<&LoginResp> {
        match self {
            FrpMessage::LoginResp(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_new_proxy(&self) -> Option<&NewProxy> {
        match self {
            FrpMessage::NewProxy(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_new_proxy_resp(&self) -> Option<&NewProxyResp> {
        match self {
            FrpMessage::NewProxyResp(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_close_proxy(&self) -> Option<&CloseProxy> {
        match self {
            FrpMessage::CloseProxy(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_new_work_conn(&self) -> Option<&NewWorkConn> {
        match self {
            FrpMessage::NewWorkConn(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_start_work_conn(&self) -> Option<&StartWorkConn> {
        match self {
            FrpMessage::StartWorkConn(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_ping(&self) -> Option<&Ping> {
        match self {
            FrpMessage::Ping(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_new_visitor_conn(&self) -> Option<&NewVisitorConn> {
        match self {
            FrpMessage::NewVisitorConn(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_new_visitor_conn_resp(&self) -> Option<&NewVisitorConnResp> {
        match self {
            FrpMessage::NewVisitorConnResp(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_close_proxy_resp(&self) -> Option<&CloseProxyResp> {
        match self {
            FrpMessage::CloseProxyResp(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_pong(&self) -> Option<&Pong> {
        match self {
            FrpMessage::Pong(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_error(&self) -> Option<&Error> {
        match self {
            FrpMessage::Error(v) => Some(v),
            _ => None,
        }
    }

    /// Construct an empty FrpMessage from a V1 type byte (for deserialization).
    pub fn from_v1_type_byte(ty: u8) -> Option<FrpMessage> {
        match ty {
            TYPE_LOGIN => Some(FrpMessage::Login(Box::new(Login {
                version: None,
                hostname: None,
                os: None,
                arch: None,
                user: None,
                run_id: None,
                client_id: None,
                pool_count: None,
                timestamp: None,
                privilege_key: None,
                metas: None,
                client_spec: None,
                multiplexer: None,
            }))),
            TYPE_LOGIN_RESP => Some(FrpMessage::LoginResp(LoginResp {
                version: None,
                run_id: None,
                error: None,
                server_additional_auth_scopes: None,
            })),
            TYPE_NEW_PROXY => Some(FrpMessage::NewProxy(Box::new(NewProxy {
                proxy_name: String::new(),
                proxy_type: String::new(),
                use_encryption: None,
                use_compression: None,
                group: None,
                group_key: None,
                local_str: None,
                remote_port: None,
                sk: None,
                custom_domains: None,
                subdomain: None,
                locations: None,
                http_user: None,
                http_pwd: None,
                host_header_rewrite: None,
                headers: None,
                response_headers: None,
                route_by_http_user: None,
                allow_users: None,
                bandwidth_limit: None,
                bandwidth_limit_mode: None,
                annotations: None,
                metas: None,
                multiplexer: None,
                virtual_net: None,
                proxy_protocol_version: None,
                advertise_subnet: None,
                vnet_ip: None,
                vnet_netmask: None,
                vnet_mtu: None,
            }))),
            TYPE_NEW_PROXY_RESP => Some(FrpMessage::NewProxyResp(NewProxyResp {
                proxy_name: String::new(),
                remote_addr: None,
                error: None,
            })),
            TYPE_CLOSE_PROXY => Some(FrpMessage::CloseProxy(CloseProxy {
                proxy_name: String::new(),
            })),
            TYPE_NEW_WORK_CONN => Some(FrpMessage::NewWorkConn(NewWorkConn {
                run_id: None,
                timestamp: None,
                privilege_key: None,
            })),
            TYPE_REQ_WORK_CONN => Some(FrpMessage::ReqWorkConn(ReqWorkConn {})),
            TYPE_START_WORK_CONN => Some(FrpMessage::StartWorkConn(Box::new(StartWorkConn {
                proxy_name: String::new(),
                src_addr: None,
                src_port: None,
                dst_addr: None,
                dst_port: None,
                error: None,
                use_encryption: None,
                use_compression: None,
                nat_hole_sid: None,
                nat_hole_visitor_addr: None,
                sk: None,
            }))),
            TYPE_PING => Some(FrpMessage::Ping(Ping {
                privilege_key: None,
                timestamp: None,
            })),
            TYPE_PONG => Some(FrpMessage::Pong(Pong { error: None })),
            TYPE_NEW_VISITOR_CONN => Some(FrpMessage::NewVisitorConn(NewVisitorConn {
                proxy_name: String::new(),
                sign_key: None,
                timestamp: None,
                run_id: None,
                use_encryption: None,
                use_compression: None,
            })),
            TYPE_NEW_VISITOR_CONN_RESP => {
                Some(FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
                    proxy_name: String::new(),
                    error: None,
                }))
            }
            TYPE_UDP_PACKET => Some(FrpMessage::UDPPacket(UDPPacket {
                content: vec![],
                local_addr: None,
                remote_addr: None,
            })),
            TYPE_NAT_HOLE_VISITOR => Some(FrpMessage::NatHoleVisitor(NatHoleVisitor::default())),
            TYPE_NAT_HOLE_CLIENT => {
                Some(FrpMessage::NatHoleClient(Box::<NatHoleClient>::default()))
            }
            TYPE_NAT_HOLE_RESP => Some(FrpMessage::NatHoleResp(Box::<NatHoleResp>::default())),
            TYPE_NAT_HOLE_SID => Some(FrpMessage::NatHoleSid(NatHoleSid::default())),
            TYPE_NAT_HOLE_REPORT => Some(FrpMessage::NatHoleReport(NatHoleReport::default())),
            TYPE_CLOSE_PROXY_RESP => Some(FrpMessage::CloseProxyResp(CloseProxyResp {
                proxy_name: String::new(),
            })),
            TYPE_ERROR => Some(FrpMessage::Error(Error {
                error: String::new(),
            })),
            #[cfg(feature = "vnet")]
            TYPE_VNET_ROUTE_ADVERTISE => Some(FrpMessage::VnetRouteAdvertise(VnetRouteAdvertise {
                proxy_name: String::new(),
                subnet: String::new(),
                virtual_net: None,
            })),
            #[cfg(feature = "vnet")]
            TYPE_VNET_PACKET => Some(FrpMessage::VnetPacket(VnetPacket {
                proxy_name: String::new(),
                data: String::new(),
            })),
            #[cfg(feature = "vnet")]
            TYPE_VNET_ROUTE_REMOVE => Some(FrpMessage::VnetRouteRemove(VnetRouteRemove {
                proxy_name: String::new(),
                virtual_net: None,
            })),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq>(
        val: &T,
        expected_json: &str,
    ) {
        let json = serde_json::to_string(val).expect("serialize");
        // Verify JSON matches expected (ignoring field ordering)
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse serialized");
        let expected: serde_json::Value =
            serde_json::from_str(expected_json).expect("parse expected");
        assert_eq!(v, expected, "serialized JSON mismatch");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            &back, val,
            "deserialize must round-trip to the original value"
        );
    }

    #[test]
    fn test_login_roundtrip_minimal() {
        let login = Login {
            version: None,
            hostname: None,
            os: None,
            arch: None,
            user: None,
            run_id: None,
            client_id: None,
            pool_count: None,
            timestamp: None,
            privilege_key: None,
            metas: None,
            client_spec: None,
            multiplexer: None,
        };
        roundtrip(&login, r#"{}"#);
    }

    #[test]
    fn test_login_roundtrip_full() {
        let mut metas = std::collections::HashMap::new();
        metas.insert("k".into(), "v".into());
        let login = Login {
            version: Some("0.69.1".into()),
            hostname: Some("testhost".into()),
            os: Some("linux".into()),
            arch: Some("amd64".into()),
            user: Some("admin".into()),
            run_id: Some("abc123".into()),
            client_id: Some("cid1".into()),
            pool_count: Some(5),
            timestamp: Some(1234567890),
            privilege_key: Some("key123".into()),
            metas: Some(metas),
            client_spec: Some(ClientSpec {
                client_type: Some("frpc".into()),
                always_auth_pass: Some(false),
            }),
            multiplexer: Some("yamux".into()),
        };
        // Golden wire format: client_spec serializes as `type` (Go frp
        // ClientSpec JSON key, msg.rs ClientSpec rename) and must come back
        // on deserialization — the roundtrip helper's equality assert pins
        // both directions.
        roundtrip(
            &login,
            r#"{"version":"0.69.1","hostname":"testhost","os":"linux","arch":"amd64","user":"admin","run_id":"abc123","client_id":"cid1","pool_count":5,"timestamp":1234567890,"privilege_key":"key123","metas":{"k":"v"},"client_spec":{"type":"frpc","always_auth_pass":false},"multiplexer":"yamux"}"#,
        );
    }

    #[test]
    fn test_login_resp_roundtrip() {
        let resp = LoginResp {
            version: Some("0.69.1".into()),
            run_id: Some("rid1".into()),
            error: None,
            server_additional_auth_scopes: None,
        };
        roundtrip(&resp, r#"{"version":"0.69.1","run_id":"rid1"}"#);

        let err_resp = LoginResp {
            version: None,
            run_id: None,
            error: Some("auth failed".into()),
            server_additional_auth_scopes: None,
        };
        roundtrip(&err_resp, r#"{"error":"auth failed"}"#);

        let scoped_resp = LoginResp {
            version: Some("0.69.1".into()),
            run_id: Some("rid2".into()),
            error: None,
            server_additional_auth_scopes: Some(vec!["HeartBeats".into(), "NewWorkConns".into()]),
        };
        roundtrip(
            &scoped_resp,
            r#"{"version":"0.69.1","run_id":"rid2","serverAdditionalAuthScopes":["HeartBeats","NewWorkConns"]}"#,
        );
    }

    #[test]
    fn test_new_proxy_roundtrip() {
        let np = NewProxy {
            proxy_name: "http-proxy".into(),
            proxy_type: "tcp".into(),
            use_encryption: Some(true),
            use_compression: Some(false),
            group: Some("web".into()),
            group_key: Some("hash-key".into()),
            local_str: None,
            remote_port: Some(8080),
            sk: None,
            custom_domains: Some(vec!["example.com".into()]),
            subdomain: None,
            locations: Some(vec!["/api".into(), "/admin".into()]),
            http_user: Some("user".into()),
            http_pwd: Some("pass".into()),
            host_header_rewrite: Some("backend.local".into()),
            headers: None,
            response_headers: None,
            route_by_http_user: None,
            allow_users: None,
            bandwidth_limit: Some("1MB".into()),
            bandwidth_limit_mode: Some("client".into()),
            annotations: None,
            metas: None,
            multiplexer: None,
            virtual_net: None,
            proxy_protocol_version: None,
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        };
        let json = serde_json::to_string(&np).expect("serialize");
        let back: NewProxy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.proxy_name, "http-proxy");
        assert_eq!(back.use_encryption, Some(true));
        assert_eq!(back.locations.as_ref().unwrap().len(), 2);
        assert_eq!(back.http_user.as_deref(), Some("user"));
        assert_eq!(back.http_pwd.as_deref(), Some("pass"));
        assert_eq!(back.host_header_rewrite.as_deref(), Some("backend.local"));
        assert_eq!(back.bandwidth_limit.as_deref(), Some("1MB"));
        assert_eq!(back.group.as_deref(), Some("web"));
        assert_eq!(
            back, np,
            "deserialize must round-trip to the original value"
        );
    }

    /// Every NewProxy field must serialize under its snake_case Go wire key.
    /// Go frp silently ignores unknown keys — a rename typo on ANY field
    /// would break interop without an error, so each key is pinned here.
    #[test]
    fn test_new_proxy_all_fields_wire_keys() {
        let mut response_headers = std::collections::HashMap::new();
        response_headers.insert("X-Custom".into(), "v1".into());
        let mut annotations = std::collections::HashMap::new();
        annotations.insert("env".into(), "prod".into());
        let mut metas = std::collections::HashMap::new();
        metas.insert("region".into(), "us-east".into());

        let np = NewProxy {
            proxy_name: "all-fields".into(),
            proxy_type: "http".into(),
            use_encryption: Some(true),
            use_compression: Some(true),
            group: Some("g1".into()),
            group_key: Some("gk".into()),
            local_str: Some("127.0.0.1:80".into()),
            remote_port: Some(8080),
            sk: Some("sk1".into()),
            custom_domains: Some(vec!["a.example.com".into(), "b.example.com".into()]),
            subdomain: Some("sub".into()),
            locations: Some(vec!["/api".into(), "/admin".into()]),
            http_user: Some("user".into()),
            http_pwd: Some("pass".into()),
            host_header_rewrite: Some("backend.local".into()),
            headers: None,
            response_headers: Some(response_headers),
            route_by_http_user: Some("alice".into()),
            allow_users: Some(vec!["alice".into(), "bob".into()]),
            bandwidth_limit: Some("1MB".into()),
            bandwidth_limit_mode: Some("client".into()),
            annotations: Some(annotations),
            metas: Some(metas),
            multiplexer: Some("yamux".into()),
            virtual_net: Some("vn1".into()),
            proxy_protocol_version: Some("v2".into()),
            advertise_subnet: Some("10.0.0.0/8".into()),
            vnet_ip: Some("10.0.0.1".into()),
            vnet_netmask: Some("255.0.0.0".into()),
            vnet_mtu: Some(1500),
        };
        let json = serde_json::to_string(&np).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");

        assert_eq!(v["proxy_name"], "all-fields", "proxy_name wire key");
        assert_eq!(v["proxy_type"], "http", "proxy_type wire key");
        assert_eq!(v["use_encryption"], true, "use_encryption wire key");
        assert_eq!(v["use_compression"], true, "use_compression wire key");
        assert_eq!(v["group"], "g1", "group wire key");
        assert_eq!(v["group_key"], "gk", "group_key wire key");
        assert_eq!(v["local_str"], "127.0.0.1:80", "local_str wire key");
        assert_eq!(v["remote_port"], 8080, "remote_port wire key");
        assert_eq!(v["sk"], "sk1", "sk wire key");
        assert_eq!(
            v["custom_domains"][0], "a.example.com",
            "custom_domains wire key"
        );
        assert_eq!(
            v["custom_domains"][1], "b.example.com",
            "custom_domains wire key"
        );
        assert_eq!(v["subdomain"], "sub", "subdomain wire key");
        assert_eq!(v["locations"][0], "/api", "locations wire key");
        assert_eq!(v["locations"][1], "/admin", "locations wire key");
        assert_eq!(v["http_user"], "user", "http_user wire key");
        assert_eq!(v["http_pwd"], "pass", "http_pwd wire key");
        assert_eq!(
            v["host_header_rewrite"], "backend.local",
            "host_header_rewrite wire key"
        );
        assert_eq!(
            v["response_headers"]["X-Custom"], "v1",
            "response_headers wire key"
        );
        assert_eq!(
            v["route_by_http_user"], "alice",
            "route_by_http_user wire key"
        );
        assert_eq!(v["allow_users"][0], "alice", "allow_users wire key");
        assert_eq!(v["allow_users"][1], "bob", "allow_users wire key");
        assert_eq!(v["bandwidth_limit"], "1MB", "bandwidth_limit wire key");
        assert_eq!(
            v["bandwidth_limit_mode"], "client",
            "bandwidth_limit_mode wire key"
        );
        assert_eq!(v["annotations"]["env"], "prod", "annotations wire key");
        assert_eq!(v["metas"]["region"], "us-east", "metas wire key");
        assert_eq!(v["multiplexer"], "yamux", "multiplexer wire key");
        assert_eq!(v["virtual_net"], "vn1", "virtual_net wire key");
        assert_eq!(
            v["proxy_protocol_version"], "v2",
            "proxy_protocol_version wire key"
        );
        assert_eq!(
            v["advertise_subnet"], "10.0.0.0/8",
            "advertise_subnet wire key"
        );
        assert_eq!(v["vnet_ip"], "10.0.0.1", "vnet_ip wire key");
        assert_eq!(v["vnet_netmask"], "255.0.0.0", "vnet_netmask wire key");
        assert_eq!(v["vnet_mtu"], 1500, "vnet_mtu wire key");

        // Deserialization must recover the exact value (a rename typo in
        // either direction would surface here as a mismatch).
        let back: NewProxy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, np);
    }

    #[test]
    fn test_new_proxy_resp_roundtrip() {
        let resp = NewProxyResp {
            proxy_name: "p1".into(),
            remote_addr: Some("0.0.0.0:7001".into()),
            error: None,
        };
        roundtrip(&resp, r#"{"proxy_name":"p1","remote_addr":"0.0.0.0:7001"}"#);
    }

    #[test]
    fn test_close_proxy_roundtrip() {
        roundtrip(
            &CloseProxy {
                proxy_name: "p1".into(),
            },
            r#"{"proxy_name":"p1"}"#,
        );
    }

    #[test]
    fn test_close_proxy_resp_roundtrip() {
        roundtrip(
            &CloseProxyResp {
                proxy_name: "p1".into(),
            },
            r#"{"proxy_name":"p1"}"#,
        );
    }

    #[test]
    fn test_error_msg_roundtrip() {
        roundtrip(
            &Error {
                error: "something broke".into(),
            },
            r#"{"error":"something broke"}"#,
        );
    }

    #[test]
    fn test_new_work_conn_roundtrip() {
        let nwc = NewWorkConn {
            run_id: Some("rid1".into()),
            timestamp: Some(9999),
            privilege_key: Some("priv".into()),
        };
        roundtrip(
            &nwc,
            r#"{"run_id":"rid1","timestamp":9999,"privilege_key":"priv"}"#,
        );
    }

    #[test]
    fn test_req_work_conn_roundtrip() {
        roundtrip(&ReqWorkConn {}, r#"{}"#);
    }

    #[test]
    fn test_start_work_conn_roundtrip() {
        let swc = StartWorkConn {
            proxy_name: "p1".into(),
            src_addr: Some("1.2.3.4".into()),
            src_port: Some(12345),
            dst_addr: None,
            dst_port: None,
            error: None,
            use_encryption: None,
            use_compression: None,
            nat_hole_sid: None,
            nat_hole_visitor_addr: None,
            sk: None,
        };
        roundtrip(
            &swc,
            r#"{"proxy_name":"p1","src_addr":"1.2.3.4","src_port":12345}"#,
        );
    }

    #[test]
    fn test_start_work_conn_ports_are_u16() {
        // Round 10 (LOW): Go StartWorkConn ports are uint16 — a hostile frame
        // with -1 or 70000 fails json.Unmarshal in Go. frp-rs used Option<i32>
        // which accepted both; the fields are now Option<u16>, so the same
        // frames fail deserialization here too.
        let bad_neg = r#"{"proxy_name":"p","src_port":-1}"#;
        let bad_big = r#"{"proxy_name":"p","dst_port":70000}"#;
        assert!(serde_json::from_str::<StartWorkConn>(bad_neg).is_err());
        assert!(serde_json::from_str::<StartWorkConn>(bad_big).is_err());
        // In-range values still parse.
        let ok = serde_json::from_str::<StartWorkConn>(
            r#"{"proxy_name":"p","src_port":65535,"dst_port":0}"#,
        )
        .unwrap();
        assert_eq!(ok.src_port, Some(65535));
        assert_eq!(ok.dst_port, Some(0));
    }

    #[test]
    fn test_ping_roundtrip() {
        let ping = Ping {
            privilege_key: Some("pk".into()),
            timestamp: Some(42),
        };
        roundtrip(&ping, r#"{"privilege_key":"pk","timestamp":42}"#);
    }

    #[test]
    fn test_pong_roundtrip() {
        roundtrip(&Pong { error: None }, r#"{}"#);
        roundtrip(
            &Pong {
                error: Some("err".into()),
            },
            r#"{"error":"err"}"#,
        );
    }

    #[test]
    fn test_new_visitor_conn_roundtrip() {
        let nvc = NewVisitorConn {
            proxy_name: "stcp1".into(),
            sign_key: Some("sk".into()),
            timestamp: Some(99),
            run_id: Some("rid".into()),
            use_encryption: Some(true),
            use_compression: Some(false),
        };
        roundtrip(
            &nvc,
            r#"{"proxy_name":"stcp1","sign_key":"sk","timestamp":99,"run_id":"rid","use_encryption":true,"use_compression":false}"#,
        );
    }

    #[test]
    fn test_new_visitor_conn_resp_roundtrip() {
        roundtrip(
            &NewVisitorConnResp {
                proxy_name: "stcp1".into(),
                error: None,
            },
            r#"{"proxy_name":"stcp1"}"#,
        );
        roundtrip(
            &NewVisitorConnResp {
                proxy_name: "stcp1".into(),
                error: Some("denied".into()),
            },
            r#"{"proxy_name":"stcp1","error":"denied"}"#,
        );
    }

    #[test]
    fn test_udp_packet_base64_roundtrip() {
        let data = vec![0, 1, 2, 255, 100];
        let pkt = UDPPacket {
            content: data.clone(),
            local_addr: Some(UdpAddr {
                ip: "127.0.0.1".into(),
                port: 53,
                zone: String::new(),
            }),
            remote_addr: Some(UdpAddr {
                ip: "10.0.0.1".into(),
                port: 9999,
                zone: String::new(),
            }),
        };
        let json = serde_json::to_string(&pkt).expect("serialize");
        // content field should be base64 encoded
        assert!(json.contains(r#""c":"#), "content field present");
        assert!(json.contains(r#""l":"#), "local_addr present");
        assert!(json.contains(r#""r":"#), "remote_addr present");
        let back: UDPPacket = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.content, data);
        assert_eq!(back.local_addr.as_ref().unwrap().ip, "127.0.0.1");
        assert_eq!(back.local_addr.as_ref().unwrap().port, 53);
        assert_eq!(back.remote_addr.as_ref().unwrap().ip, "10.0.0.1");
        assert_eq!(back.remote_addr.as_ref().unwrap().port, 9999);
    }

    #[test]
    fn test_udp_packet_empty_datagram_go_compat() {
        // Go frp omits "c" (json:"c,omitempty") on empty datagrams and may
        // omit "l"/"r" (nil addrs). All three must deserialize cleanly.
        let json = r#"{}"#;
        let pkt: UDPPacket = serde_json::from_str(json).expect("empty packet");
        assert!(pkt.content.is_empty());
        assert!(pkt.local_addr.is_none());
        assert!(pkt.remote_addr.is_none());

        // And Rust->Go stays byte-identical: empty content is NOT serialized.
        let out = serde_json::to_string(&pkt).expect("serialize");
        assert_eq!(out, r#"{}"#);
    }

    #[test]
    fn test_udp_packet_invalid_base64_rejected() {
        // Garbage in the base64 "c" content must make deserialization return
        // Err — never panic and never silently decode to empty (b64_de maps
        // the decode failure through serde::de::Error::custom).
        let json = r#"{"c":"!!!not-base64!!!","l":{"IP":"127.0.0.1","Port":53,"Zone":""},"r":{"IP":"10.0.0.1","Port":9999,"Zone":""}}"#;
        let result = serde_json::from_str::<UDPPacket>(json);
        assert!(
            result.is_err(),
            "garbage base64 content must fail UDPPacket deserialization"
        );

        // Padding violations are also rejected, not silently tolerated.
        let bad_padding =
            r#"{"c":"aGVsbG8=","r":{"IP":"10.0.0.1","Port":9999,"Zone":""},"featureFlags":["x"]}"#;
        // "aGVsbG8=" is valid; corrupt it: drop the padding.
        let corrupt = bad_padding.replace("aGVsbG8=", "aGVsbG8");
        assert!(
            serde_json::from_str::<UDPPacket>(&corrupt).is_err(),
            "invalid base64 length must fail deserialization"
        );
    }

    #[test]
    fn test_nat_hole_report_success_go_compat() {
        // Go frp v0.71.0: Success bool `json:"success,omitempty"` — false is
        // omitted, true is emitted. Rust must serialize byte-identically.
        let ok = NatHoleReport {
            sid: Some("s1".into()),
            success: true,
        };
        assert_eq!(
            serde_json::to_string(&ok).expect("serialize"),
            r#"{"sid":"s1","success":true}"#,
            "success=true must be emitted"
        );

        let fail = NatHoleReport {
            sid: Some("s1".into()),
            success: false,
        };
        assert_eq!(
            serde_json::to_string(&fail).expect("serialize"),
            r#"{"sid":"s1"}"#,
            "success=false must be omitted (Go omitempty parity)"
        );

        // Deserialization accepts both forms.
        let from_true: NatHoleReport =
            serde_json::from_str(r#"{"sid":"s1","success":true}"#).expect("parse");
        assert!(from_true.success);
        let from_false: NatHoleReport =
            serde_json::from_str(r#"{"sid":"s1","success":false}"#).expect("parse");
        assert!(!from_false.success);
        let from_absent: NatHoleReport = serde_json::from_str(r#"{"sid":"s1"}"#).expect("parse");
        assert!(!from_absent.success);
    }

    #[test]
    fn test_nat_hole_visitor_pre_check_go_compat() {
        // Go frp v0.71.0: PreCheck bool `json:"pre_check,omitempty"` — false
        // is omitted, true is emitted.
        let pre = NatHoleVisitor {
            transaction_id: "t1".into(),
            proxy_name: "p1".into(),
            pre_check: true,
            ..NatHoleVisitor::default()
        };
        assert_eq!(
            serde_json::to_string(&pre).expect("serialize"),
            r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":true}"#,
            "pre_check=true must be emitted"
        );

        let full = NatHoleVisitor {
            transaction_id: "t1".into(),
            proxy_name: "p1".into(),
            pre_check: false,
            ..NatHoleVisitor::default()
        };
        assert_eq!(
            serde_json::to_string(&full).expect("serialize"),
            r#"{"transaction_id":"t1","proxy_name":"p1"}"#,
            "pre_check=false must be omitted (Go omitempty parity)"
        );

        // Deserialization accepts both forms.
        let from_true: NatHoleVisitor =
            serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":true}"#)
                .expect("parse");
        assert!(from_true.pre_check);
        let from_false: NatHoleVisitor =
            serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":false}"#)
                .expect("parse");
        assert!(!from_false.pre_check);
        let from_absent: NatHoleVisitor =
            serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1"}"#).expect("parse");
        assert!(!from_absent.pre_check);
    }

    #[test]
    fn test_nat_hole_client_roundtrip() {
        let client = NatHoleClient {
            transaction_id: "t1".into(),
            proxy_name: "xtcp-provider".into(),
            sid: Some("s1".into()),
            protocol: Some("quic".into()),
            mapped_addrs: Some(vec!["1.2.3.4:1000".into(), "5.6.7.8:2000".into()]),
            assisted_addrs: Some(vec!["9.9.9.9:3000".into()]),
            visitor_addr: Some("8.8.8.8:4000".into()),
        };
        roundtrip(
            &client,
            r#"{"transaction_id":"t1","proxy_name":"xtcp-provider","sid":"s1","protocol":"quic","mapped_addrs":["1.2.3.4:1000","5.6.7.8:2000"],"assisted_addrs":["9.9.9.9:3000"],"visitor_addr":"8.8.8.8:4000"}"#,
        );
    }

    #[test]
    fn test_nat_hole_resp_roundtrip() {
        let resp = NatHoleResp {
            transaction_id: "t1".into(),
            error: Some("e1".into()),
            sid: Some("s1".into()),
            protocol: Some("quic".into()),
            candidate_addrs: Some(vec!["1.2.3.4:1000".into()]),
            assisted_addrs: Some(vec!["5.6.7.8:2000".into()]),
            detect_behavior: Some(NatHoleDetectBehavior {
                mode: 3,
                role: Some("sender".into()),
                ttl: 64,
                send_delay_ms: 10,
                // Go wire key is "read_timeout" (rename pins the alias).
                read_timeout_ms: 5000,
                send_random_ports: 4,
                listen_random_ports: 4,
                candidate_ports: Some(vec![PortsRange {
                    from: 1000,
                    to: 2000,
                }]),
            }),
        };
        roundtrip(
            &resp,
            r#"{"transaction_id":"t1","error":"e1","sid":"s1","protocol":"quic","candidate_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"detect_behavior":{"mode":3,"role":"sender","ttl":64,"send_delay_ms":10,"read_timeout":5000,"send_random_ports":4,"listen_random_ports":4,"candidate_ports":[{"from":1000,"to":2000}]}}"#,
        );
    }

    #[test]
    fn test_nat_hole_sid_roundtrip() {
        // response=true is emitted; response=false is omitted (Go omitempty
        // parity) and defaults back to false on deserialization.
        let sid = NatHoleSid {
            transaction_id: Some("t1".into()),
            sid: Some("s1".into()),
            response: true,
            nonce: Some("n1".into()),
        };
        roundtrip(
            &sid,
            r#"{"transaction_id":"t1","sid":"s1","response":true,"nonce":"n1"}"#,
        );
        let quiet = NatHoleSid {
            transaction_id: Some("t1".into()),
            sid: Some("s1".into()),
            response: false,
            nonce: Some("n1".into()),
        };
        roundtrip(&quiet, r#"{"transaction_id":"t1","sid":"s1","nonce":"n1"}"#);
    }

    #[test]
    fn test_frp_message_v1_type_bytes() {
        // Verify every known type byte maps to the correct variant
        let cases: Vec<(u8, &str)> = vec![
            (TYPE_LOGIN, "Login"),
            (TYPE_LOGIN_RESP, "LoginResp"),
            (TYPE_NEW_PROXY, "NewProxy"),
            (TYPE_NEW_PROXY_RESP, "NewProxyResp"),
            (TYPE_CLOSE_PROXY, "CloseProxy"),
            (TYPE_CLOSE_PROXY_RESP, "CloseProxyResp"),
            (TYPE_NEW_WORK_CONN, "NewWorkConn"),
            (TYPE_REQ_WORK_CONN, "ReqWorkConn"),
            (TYPE_START_WORK_CONN, "StartWorkConn"),
            (TYPE_PING, "Ping"),
            (TYPE_PONG, "Pong"),
            (TYPE_NEW_VISITOR_CONN, "NewVisitorConn"),
            (TYPE_NEW_VISITOR_CONN_RESP, "NewVisitorConnResp"),
            (TYPE_UDP_PACKET, "UDPPacket"),
            (TYPE_NAT_HOLE_VISITOR, "NatHoleVisitor"),
            (TYPE_NAT_HOLE_CLIENT, "NatHoleClient"),
            (TYPE_NAT_HOLE_RESP, "NatHoleResp"),
            (TYPE_NAT_HOLE_SID, "NatHoleSid"),
            (TYPE_NAT_HOLE_REPORT, "NatHoleReport"),
            (TYPE_ERROR, "Error"),
        ];
        for (ty, label) in cases {
            let msg = FrpMessage::from_v1_type_byte(ty)
                .unwrap_or_else(|| panic!("from_v1_type_byte({})", ty));
            assert_eq!(
                msg.v1_type_byte(),
                ty,
                "v1_type_byte roundtrip for {}",
                label
            );
        }
    }

    #[test]
    fn test_frp_message_type_byte_dispatch() {
        // Verify type-byte dispatch (the production deserialization path)
        // Login with multiplexer
        let login_json = r#"{"version":"0.1.0","hostname":"h","multiplexer":"yamux"}"#;
        let login: Login = serde_json::from_str(login_json).expect("deserialize Login struct");
        assert_eq!(login.version.as_deref(), Some("0.1.0"));
        assert_eq!(login.multiplexer.as_deref(), Some("yamux"));

        // Error
        let error_json = r#"{"error":"something failed"}"#;
        let err: Error = serde_json::from_str(error_json).expect("deserialize Error struct");
        assert_eq!(err.error, "something failed");

        // CloseProxyResp
        let cpr_json = r#"{"proxy_name":"my-proxy"}"#;
        let cpr: CloseProxyResp =
            serde_json::from_str(cpr_json).expect("deserialize CloseProxyResp struct");
        assert_eq!(cpr.proxy_name, "my-proxy");
    }

    #[test]
    fn test_unknown_type_byte() {
        assert!(FrpMessage::from_v1_type_byte(0x00).is_none());
        assert!(FrpMessage::from_v1_type_byte(0xFF).is_none());
    }

    // ---------------------------------------------------------------
    // UdpAddr tests — serde JSON format matching Go frp v0.71.0
    // ---------------------------------------------------------------

    #[test]
    fn test_udp_addr_serialize_matches_go_format() {
        // Go's net.UDPAddr has no omitempty on Zone: it is ALWAYS emitted,
        // `"Zone":""` when empty (Go frp v0.71.0 byte-identical output).
        let addr = UdpAddr {
            ip: "127.0.0.1".into(),
            port: 8080,
            zone: String::new(),
        };
        let json = serde_json::to_string(&addr).expect("serialize");
        assert_eq!(
            json, r#"{"IP":"127.0.0.1","Port":8080,"Zone":""}"#,
            "Zone must always be emitted, matching Go net.UDPAddr"
        );

        // Round-trip through deserialization.
        let back: UdpAddr = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.ip, "127.0.0.1");
        assert_eq!(back.port, 8080);
        assert_eq!(back.zone, "");

        // Deserialization from Go-form JSON that includes Zone.
        let go_json = r#"{"IP":"127.0.0.1","Port":8080,"Zone":""}"#;
        let from_go: UdpAddr = serde_json::from_str(go_json).expect("deserialize Go format");
        assert_eq!(from_go.ip, "127.0.0.1");
        assert_eq!(from_go.port, 8080);
        assert_eq!(from_go.zone, "");

        // A non-empty zone also round-trips byte-identically.
        let zoned = UdpAddr {
            ip: "fe80::1".into(),
            port: 8080,
            zone: "eth0".into(),
        };
        let zoned_json = serde_json::to_string(&zoned).expect("serialize");
        assert_eq!(zoned_json, r#"{"IP":"fe80::1","Port":8080,"Zone":"eth0"}"#);
        let from_zoned: UdpAddr = serde_json::from_str(&zoned_json).expect("deserialize");
        assert_eq!(from_zoned.zone, "eth0");
    }

    #[test]
    fn test_udp_addr_deserialize_from_go_format() {
        let json = r#"{"IP":"10.0.0.1","Port":53,"Zone":""}"#;
        let addr: UdpAddr = serde_json::from_str(json).expect("deserialize");
        assert_eq!(addr.ip, "10.0.0.1");
        assert_eq!(addr.port, 53);
        assert_eq!(addr.zone, "");
    }

    #[test]
    fn test_udp_addr_zone_defaults_to_empty() {
        // Go's net.UDPAddr always emits Zone, but hand-written JSON may
        // omit it: the `default` on Zone must fill "" (lenient parse).
        let addr: UdpAddr =
            serde_json::from_str(r#"{"IP":"1.2.3.4","Port":53}"#).expect("deserialize");
        assert_eq!(addr.ip, "1.2.3.4");
        assert_eq!(addr.port, 53);
        assert_eq!(addr.zone, "", "missing Zone must default to empty");
    }

    #[test]
    fn test_udp_addr_from_string_ipv4() {
        let addr = UdpAddr::from_string("1.2.3.4:5678").expect("should parse IPv4:port");
        assert_eq!(addr.ip, "1.2.3.4");
        assert_eq!(addr.port, 5678);
        assert_eq!(addr.zone, "");
    }

    #[test]
    fn test_udp_addr_from_string_ipv6() {
        let addr = UdpAddr::from_string("[::1]:9090").expect("should parse IPv6:port");
        assert_eq!(addr.ip, "::1");
        assert_eq!(addr.port, 9090);
        assert_eq!(addr.zone, "");
    }

    #[test]
    fn test_udp_addr_from_string_invalid() {
        assert!(UdpAddr::from_string("not-an-address").is_none());
        assert!(UdpAddr::from_string("").is_none());
    }

    #[test]
    fn test_udp_addr_to_string() {
        let addr = UdpAddr {
            ip: "192.168.1.1".into(),
            port: 3000,
            zone: String::new(),
        };
        assert_eq!(addr.to_string(), "192.168.1.1:3000");
    }

    /// Verify NewProxy fields serialize to Go frp v0.70.0 snake_case wire format.
    /// Go frp ignores camelCase keys; this test guards against regression.
    #[test]
    fn test_new_proxy_wire_format_snake_case() {
        let mut resp_headers = std::collections::HashMap::new();
        resp_headers.insert("X-Custom".into(), "value".into());

        let np = NewProxy {
            proxy_name: "wire-test".into(),
            proxy_type: "http".into(),
            use_encryption: None,
            use_compression: None,
            group: None,
            group_key: None,
            local_str: None,
            remote_port: None,
            sk: None,
            custom_domains: None,
            subdomain: None,
            locations: None,
            http_user: Some("alice".into()),
            http_pwd: Some("secret".into()),
            host_header_rewrite: Some("internal.example.com".into()),
            headers: None,
            response_headers: Some(resp_headers),
            route_by_http_user: Some("alice".into()),
            allow_users: None,
            bandwidth_limit: None,
            bandwidth_limit_mode: Some("server".into()),
            annotations: None,
            metas: None,
            multiplexer: None,
            virtual_net: None,
            proxy_protocol_version: Some("v2".into()),
            advertise_subnet: None,
            vnet_ip: None,
            vnet_netmask: None,
            vnet_mtu: None,
        };
        let json = serde_json::to_string(&np).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");

        // Wire keys MUST be snake_case for Go frp v0.70.0 compat.
        assert_eq!(v["http_user"].as_str(), Some("alice"), "http_user wire key");
        assert_eq!(v["http_pwd"].as_str(), Some("secret"), "http_pwd wire key");
        assert_eq!(
            v["host_header_rewrite"].as_str(),
            Some("internal.example.com"),
            "host_header_rewrite wire key"
        );
        assert_eq!(
            v["response_headers"]["X-Custom"].as_str(),
            Some("value"),
            "response_headers wire key"
        );
        assert_eq!(
            v["route_by_http_user"].as_str(),
            Some("alice"),
            "route_by_http_user wire key"
        );
        assert_eq!(
            v["bandwidth_limit_mode"].as_str(),
            Some("server"),
            "bandwidth_limit_mode wire key"
        );
        assert_eq!(
            v["proxy_protocol_version"].as_str(),
            Some("v2"),
            "proxy_protocol_version wire key"
        );

        // camelCase keys MUST NOT appear on the wire.
        assert!(
            v.get("httpUser").is_none(),
            "camelCase httpUser must NOT appear on wire"
        );
        assert!(
            v.get("httpPwd").is_none(),
            "camelCase httpPwd must NOT appear on wire"
        );
        assert!(
            v.get("hostHeaderRewrite").is_none(),
            "camelCase hostHeaderRewrite must NOT appear"
        );
        assert!(
            v.get("responseHeaders").is_none(),
            "camelCase responseHeaders must NOT appear"
        );
        assert!(
            v.get("routeByHTTPUser").is_none(),
            "camelCase routeByHTTPUser must NOT appear"
        );
        assert!(
            v.get("bandwidthLimitMode").is_none(),
            "camelCase bandwidthLimitMode must NOT appear"
        );
        assert!(
            v.get("proxyProtocolVersion").is_none(),
            "camelCase proxyProtocolVersion must NOT appear"
        );

        // Deserialize from Go-format JSON (snake_case only).
        let go_json = r#"{
            "proxy_name": "go-proxy",
            "proxy_type": "http",
            "http_user": "bob",
            "http_pwd": "bobpass",
            "host_header_rewrite": "go.internal",
            "response_headers": {"X-Go": "1"},
            "route_by_http_user": "bob",
            "bandwidth_limit_mode": "client",
            "proxy_protocol_version": "v1"
        }"#;
        let from_go: NewProxy = serde_json::from_str(go_json).expect("deserialize Go format");
        assert_eq!(from_go.proxy_name, "go-proxy");
        assert_eq!(from_go.http_user.as_deref(), Some("bob"));
        assert_eq!(from_go.http_pwd.as_deref(), Some("bobpass"));
        assert_eq!(from_go.host_header_rewrite.as_deref(), Some("go.internal"));
        assert_eq!(
            from_go
                .response_headers
                .as_ref()
                .and_then(|m| m.get("X-Go"))
                .map(|v| v.as_str()),
            Some("1")
        );
        assert_eq!(from_go.route_by_http_user.as_deref(), Some("bob"));
        assert_eq!(from_go.bandwidth_limit_mode.as_deref(), Some("client"));
        assert_eq!(from_go.proxy_protocol_version.as_deref(), Some("v1"));
    }

    // ---------------------------------------------------------------
    // Forward compatibility: unknown fields must be tolerated
    // ---------------------------------------------------------------

    /// Assert that a JSON literal with an extra unknown key deserializes
    /// into `T`. Future Go frp releases will add fields to wire messages;
    /// serde ignores unknown fields by default and no struct here uses
    /// `deny_unknown_fields` — this pins that property so a refactor
    /// adding it is caught by tests instead of silently breaking every Go
    /// peer on the wire.
    fn accepts<T: serde::de::DeserializeOwned>(json: &str) {
        serde_json::from_str::<T>(json).unwrap_or_else(|e| {
            panic!(
                "expected {} to tolerate unknown fields in {}: {}",
                std::any::type_name::<T>(),
                json,
                e
            )
        });
    }

    #[test]
    fn test_unknown_fields_are_tolerated_go_forward_compat() {
        // Every literal carries a plausible future-Go field
        // ("featureFlags") that no current struct declares, alongside each
        // struct's REAL required fields (Login.client_spec serializes as
        // `client_spec` — verified against the Go v0.71.0 binary).
        accepts::<Login>(
            r#"{"version":"0.71.0","hostname":"h1","os":"linux","arch":"amd64","user":"u1","run_id":"r1","client_id":"c1","pool_count":2,"timestamp":1234567890123,"privilege_key":"pk","metas":{"k":"v"},"client_spec":{"type":"frpc","always_auth_pass":false},"multiplexer":"yamux","featureFlags":["quic-ack"]}"#,
        );
        accepts::<LoginResp>(
            r#"{"version":"0.71.0","run_id":"r1","serverAdditionalAuthScopes":["HeartBeats"],"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NewProxy>(
            r#"{"proxy_name":"p1","proxy_type":"tcp","remote_port":7001,"local_str":"127.0.0.1:80","featureFlags":["quic-ack"]}"#,
        );
        accepts::<NewProxyResp>(
            r#"{"proxy_name":"p1","remote_addr":"0.0.0.0:7001","featureFlags":["quic-ack"]}"#,
        );
        accepts::<CloseProxy>(r#"{"proxy_name":"p1","featureFlags":["quic-ack"]}"#);
        accepts::<CloseProxyResp>(r#"{"proxy_name":"p1","featureFlags":["quic-ack"]}"#);
        #[cfg(feature = "vnet")]
        accepts::<VnetRouteAdvertise>(
            r#"{"proxy_name":"p1","subnet":"10.0.0.0/8","virtual_net":"vn1","featureFlags":["quic-ack"]}"#,
        );
        #[cfg(feature = "vnet")]
        accepts::<VnetPacket>(r#"{"proxy_name":"p1","data":"AQID","featureFlags":["quic-ack"]}"#);
        #[cfg(feature = "vnet")]
        accepts::<VnetRouteRemove>(
            r#"{"proxy_name":"p1","virtual_net":"vn1","featureFlags":["quic-ack"]}"#,
        );
        accepts::<StartWorkConn>(
            r#"{"proxy_name":"p1","src_addr":"1.2.3.4","src_port":12345,"dst_addr":"5.6.7.8","dst_port":80,"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NewWorkConn>(
            r#"{"run_id":"r1","timestamp":123,"privilege_key":"pk","featureFlags":["quic-ack"]}"#,
        );
        accepts::<ReqWorkConn>(r#"{"featureFlags":["quic-ack"]}"#);
        accepts::<Ping>(r#"{"timestamp":123,"privilege_key":"pk","featureFlags":["quic-ack"]}"#);
        accepts::<Pong>(r#"{"error":"ok","featureFlags":["quic-ack"]}"#);
        accepts::<NewVisitorConn>(
            r#"{"proxy_name":"stcp1","sign_key":"sk","timestamp":99,"run_id":"r1","use_encryption":true,"use_compression":false,"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NewVisitorConnResp>(r#"{"proxy_name":"stcp1","featureFlags":["quic-ack"]}"#);
        accepts::<UDPPacket>(
            r#"{"c":"AQID","l":{"IP":"127.0.0.1","Port":53,"Zone":""},"r":{"IP":"10.0.0.1","Port":9999,"Zone":""},"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NatHoleVisitor>(
            r#"{"transaction_id":"t1","proxy_name":"p1","pre_check":true,"protocol":"quic","sign_key":"sk","timestamp":123,"mapped_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NatHoleClient>(
            r#"{"transaction_id":"t1","proxy_name":"p1","sid":"s1","protocol":"quic","mapped_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NatHoleResp>(
            r#"{"transaction_id":"t1","sid":"s1","protocol":"quic","candidate_addrs":["1.2.3.4:1000"],"assisted_addrs":["5.6.7.8:2000"],"featureFlags":["quic-ack"]}"#,
        );
        accepts::<NatHoleSid>(
            r#"{"transaction_id":"t1","sid":"s1","response":true,"nonce":"n1","featureFlags":["quic-ack"]}"#,
        );
        accepts::<NatHoleReport>(r#"{"sid":"s1","success":true,"featureFlags":["quic-ack"]}"#);
        accepts::<Error>(r#"{"error":"boom","featureFlags":["quic-ack"]}"#);
    }

    #[test]
    fn test_missing_optional_fields_default_to_none() {
        // Go peers emit only the fields they set (omitempty). Absent keys must
        // fill Option fields with None and ints/bools with their serde(default)
        // zeros — parse-OK alone would not catch a lost #[serde(default)].
        let nwc: NewWorkConn = serde_json::from_str(r#"{"run_id":"r1"}"#).unwrap();
        assert_eq!(nwc.run_id, Some("r1".to_string()));
        assert_eq!(nwc.timestamp, None);
        assert_eq!(nwc.privilege_key, None);

        let swc: StartWorkConn = serde_json::from_str(r#"{"proxy_name":"p1"}"#).unwrap();
        assert_eq!(swc.proxy_name, "p1");
        assert_eq!(swc.src_addr, None);
        assert_eq!(swc.src_port, None);
        assert_eq!(swc.dst_addr, None);
        assert_eq!(swc.dst_port, None);
        assert_eq!(swc.error, None);
        assert_eq!(swc.use_encryption, None);
        assert_eq!(swc.use_compression, None);
        assert_eq!(swc.nat_hole_sid, None);
        assert_eq!(swc.nat_hole_visitor_addr, None);
        assert_eq!(swc.sk, None);

        let resp: NewProxyResp = serde_json::from_str(r#"{"proxy_name":"p1"}"#).unwrap();
        assert_eq!(resp.remote_addr, None);
        assert_eq!(resp.error, None);

        let ping: Ping = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(ping.privilege_key, None);
        assert_eq!(ping.timestamp, None);

        let nc: NatHoleClient =
            serde_json::from_str(r#"{"transaction_id":"t1","proxy_name":"p1"}"#).unwrap();
        assert_eq!(nc.sid, None);
        assert_eq!(nc.protocol, None);
        assert_eq!(nc.mapped_addrs, None);
        assert_eq!(nc.assisted_addrs, None);
        assert_eq!(nc.visitor_addr, None);

        let sid: NatHoleSid = serde_json::from_str(r#"{"sid":"s1"}"#).unwrap();
        assert_eq!(sid.transaction_id, None);
        assert!(!sid.response);
        assert_eq!(sid.nonce, None);

        // Go omitempty drops zero-valued ints — an empty detect_behavior
        // object must fill every i32 with 0 (field-level #[serde(default)]).
        let nh: NatHoleResp =
            serde_json::from_str(r#"{"transaction_id":"t1","detect_behavior":{}}"#).unwrap();
        let db = nh.detect_behavior.unwrap();
        assert_eq!(
            (
                db.mode,
                db.ttl,
                db.send_delay_ms,
                db.read_timeout_ms,
                db.send_random_ports,
                db.listen_random_ports
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert_eq!(db.role, None);
        assert_eq!(db.candidate_ports, None);
    }
}
