// `Deserialize` is imported for its derive macro as well as the trait.
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

/// Stack-buffer base64 encoder, streamed through `Serializer::collect_str`.
///
/// Byte-identical to `crate::base64::encode` (same standard alphabet, same
/// `=` padding, same empty-input output) but without the intermediate
/// `String` that `serialize_str(&base64::encode(..))` built per packet: each
/// 3-byte block is encoded into a 4-byte ASCII stack buffer and written
/// straight into the serializer. serde_json's `collect_str` escapes and
/// writes the `Display` output with no allocation of its own, and the payload
/// is borrowed, so encoding a packet allocates nothing at all.
struct B64<'a>(&'a [u8]);

impl fmt::Display for B64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        // Every ALPHABET byte is ASCII, so each 4-byte quad is valid UTF-8 by
        // construction. `from_utf8` (not `_unchecked`) keeps this safe; the
        // check compiles down to a cheap 4-byte ASCII test.
        let mut quad = [0u8; 4];
        let (chunks, remainder) = self.0.as_chunks::<3>();
        for chunk in chunks {
            let (b0, b1, b2) = (chunk[0], chunk[1], chunk[2]);
            quad[0] = ALPHABET[(b0 >> 2) as usize];
            quad[1] = ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize];
            quad[2] = ALPHABET[((b1 & 0x0f) << 2 | b2 >> 6) as usize];
            quad[3] = ALPHABET[(b2 & 0x3f) as usize];
            f.write_str(core::str::from_utf8(&quad).map_err(|_| fmt::Error)?)?;
        }
        match remainder {
            [] => {}
            [b0] => {
                quad[0] = ALPHABET[(b0 >> 2) as usize];
                quad[1] = ALPHABET[((b0 & 0x03) << 4) as usize];
                quad[2] = b'=';
                quad[3] = b'=';
                f.write_str(core::str::from_utf8(&quad).map_err(|_| fmt::Error)?)?;
            }
            [b0, b1] => {
                quad[0] = ALPHABET[(b0 >> 2) as usize];
                quad[1] = ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize];
                quad[2] = ALPHABET[((b1 & 0x0f) << 2) as usize];
                quad[3] = b'=';
                f.write_str(core::str::from_utf8(&quad).map_err(|_| fmt::Error)?)?;
            }
            _ => unreachable!("remainder is at most 2 bytes"),
        }
        Ok(())
    }
}

fn b64_ser<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&B64(data))
}

/// Borrowed-str visitor for the base64 `c` field: `deserialize_str` hands the
/// JSON string to us without building an owned `String` when the input has no
/// escapes (serde_json's borrowed path), so the slice goes straight to
/// `base64::decode`. Escaped strings arrive through the default
/// `visit_string` -> `visit_str` forwarding, exactly as before.
struct B64Visitor;

impl<'de> serde::de::Visitor<'de> for B64Visitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a base64-encoded string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        crate::base64::decode(v).map_err(serde::de::Error::custom)
    }
}

fn b64_de<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    d.deserialize_str(B64Visitor)
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
    /// `skip_serializing_if` + `default`: Go's StartWorkConn is all-omitempty
    /// (msg.go:154-161), so a Go REJECT frame carries only `{"error": ...}`
    /// (round-11 F2 built the reject via this same struct — the empty
    /// proxy_name previously leaked onto the wire as an extra key; round-12
    /// B3). Assignment frames always name the proxy, so the omit is
    /// reject-only and inert either way; `default` keeps Go reject frames
    /// (no proxy_name) decodable.
    #[serde(skip_serializing_if = "String::is_empty", default)]
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
mod tests;
