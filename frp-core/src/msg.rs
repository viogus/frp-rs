use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------
// V1 message type bytes (matching Go frp v0.69.1 protocol)
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
// NAT hole punching (Go frp v0.69.1 STCP/XTCP)
pub const TYPE_NAT_HOLE_VISITOR: u8 = b'i';
pub const TYPE_NAT_HOLE_CLIENT: u8 = b'n';
pub const TYPE_NAT_HOLE_RESP: u8 = b'm';
pub const TYPE_NAT_HOLE_SID: u8 = b'5';
pub const TYPE_NAT_HOLE_REPORT: u8 = b'6';
pub const TYPE_CLOSE_PROXY_RESP: u8 = b'7';
pub const TYPE_ERROR: u8 = b'8';

// ---------------------------------------------------------------
// V2 message type IDs (stubs)
// ---------------------------------------------------------------
pub const V2_TYPE_LOGIN: u16 = 1;
pub const V2_TYPE_LOGIN_RESP: u16 = 2;
pub const V2_TYPE_NEW_PROXY: u16 = 3;
pub const V2_TYPE_NEW_PROXY_RESP: u16 = 4;
pub const V2_TYPE_CLOSE_PROXY: u16 = 5;
pub const V2_TYPE_NEW_WORK_CONN: u16 = 6;
pub const V2_TYPE_REQ_WORK_CONN: u16 = 7;
pub const V2_TYPE_START_WORK_CONN: u16 = 8;
pub const V2_TYPE_PING: u16 = 11;
pub const V2_TYPE_PONG: u16 = 12;
pub const V2_TYPE_UDP_PACKET: u16 = 13;
pub const V2_TYPE_NEW_VISITOR_CONN: u16 = 14;
pub const V2_TYPE_NEW_VISITOR_CONN_RESP: u16 = 15;

// ---------------------------------------------------------------
// Base64 helpers for UDPPacket (Go frp encodes []byte as base64)
// ---------------------------------------------------------------

fn b64_ser<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&data_encoding::BASE64.encode(data))
}

fn b64_de<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    data_encoding::BASE64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
}

// ---------------------------------------------------------------
// Concrete message structs — all derive Serialize + Deserialize
// Field names match Go frp v0.69.1 JSON keys (snake_case Rust with
// serde renames where Go uses different keys).
// ---------------------------------------------------------------

/// ClientSpec carries client-specific metadata (Go frp compat).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientSpec {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub client_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_auth_pass: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplexer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub type LoginResponse = LoginResp;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(rename = "httpUser", skip_serializing_if = "Option::is_none")]
    pub http_user: Option<String>,
    #[serde(rename = "httpPwd", skip_serializing_if = "Option::is_none")]
    pub http_pwd: Option<String>,
    #[serde(rename = "hostHeaderRewrite", skip_serializing_if = "Option::is_none")]
    pub host_header_rewrite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "responseHeaders", skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "routeByHTTPUser", skip_serializing_if = "Option::is_none")]
    pub route_by_http_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_users: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit: Option<String>,
    #[serde(rename = "bandwidthLimitMode", skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metas: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplexer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProxyResp {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub type NewProxyResponse = NewProxyResp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseProxy {
    pub proxy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseProxyResp {
    pub proxy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWorkConn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReqWorkConn {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartWorkConn {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewVisitorConnResp {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// UDP address matching Go frp v0.69.1 `net.UDPAddr` JSON representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpAddr {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Zone", skip_serializing_if = "String::is_empty", default)]
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

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UDPPacket {
    #[serde(rename = "c", serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub content: Vec<u8>,
    #[serde(rename = "l", skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<UdpAddr>,
    #[serde(rename = "r", skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<UdpAddr>,
}

// ---------------------------------------------------------------
// NAT hole punch messages (Go frp v0.69.1 STCP/XTCP)
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleVisitor {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleClient {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visitor_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleResp {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleSid {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

// ---------------------------------------------------------------
// FrpMessage — unified enum over all message types
// NOTE: #[serde(untagged)] means ordering matters. Variants with
// more optional/overlapping fields must come after those with
// unique required fields. V1 deserialization uses type-byte dispatch
// (deserialize_v1), so untagged matching is only used for direct
// serde_json::from_value calls (tests, future code paths).
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FrpMessage {
    CloseProxyResp(CloseProxyResp),
    CloseProxy(CloseProxy),
    ReqWorkConn(ReqWorkConn),
    NewProxyResp(NewProxyResp),
    NewVisitorConnResp(NewVisitorConnResp),
    Pong(Pong),
    NewProxy(NewProxy),
    UDPPacket(UDPPacket),
    StartWorkConn(StartWorkConn),
    NewVisitorConn(NewVisitorConn),
    NewWorkConn(NewWorkConn),
    Ping(Ping),
    LoginResp(LoginResp),
    Login(Login),
    NatHoleVisitor(NatHoleVisitor),
    NatHoleClient(NatHoleClient),
    NatHoleResp(NatHoleResp),
    NatHoleSid(NatHoleSid),
    NatHoleReport(NatHoleReport),
    Error(Error),
}

impl FrpMessage {
    pub fn v1_type_byte(&self) -> u8 {
        match self {
            FrpMessage::Login(_)              => TYPE_LOGIN,
            FrpMessage::LoginResp(_)          => TYPE_LOGIN_RESP,
            FrpMessage::NewProxy(_)           => TYPE_NEW_PROXY,
            FrpMessage::NewProxyResp(_)       => TYPE_NEW_PROXY_RESP,
            FrpMessage::CloseProxy(_)         => TYPE_CLOSE_PROXY,
            FrpMessage::NewWorkConn(_)        => TYPE_NEW_WORK_CONN,
            FrpMessage::ReqWorkConn(_)        => TYPE_REQ_WORK_CONN,
            FrpMessage::StartWorkConn(_)      => TYPE_START_WORK_CONN,
            FrpMessage::Ping(_)               => TYPE_PING,
            FrpMessage::Pong(_)               => TYPE_PONG,
            FrpMessage::NewVisitorConn(_)     => TYPE_NEW_VISITOR_CONN,
            FrpMessage::NewVisitorConnResp(_) => TYPE_NEW_VISITOR_CONN_RESP,
            FrpMessage::UDPPacket(_)          => TYPE_UDP_PACKET,
            FrpMessage::NatHoleVisitor(_)     => TYPE_NAT_HOLE_VISITOR,
            FrpMessage::NatHoleClient(_)      => TYPE_NAT_HOLE_CLIENT,
            FrpMessage::NatHoleResp(_)        => TYPE_NAT_HOLE_RESP,
            FrpMessage::NatHoleSid(_)         => TYPE_NAT_HOLE_SID,
            FrpMessage::NatHoleReport(_)      => TYPE_NAT_HOLE_REPORT,
            FrpMessage::CloseProxyResp(_)   => TYPE_CLOSE_PROXY_RESP,
            FrpMessage::Error(_)            => TYPE_ERROR,
        }
    }

    pub fn v2_type_id(&self) -> u16 {
        match self {
            FrpMessage::Login(_)         => V2_TYPE_LOGIN,
            FrpMessage::LoginResp(_)     => V2_TYPE_LOGIN_RESP,
            FrpMessage::NewProxy(_)      => V2_TYPE_NEW_PROXY,
            FrpMessage::NewProxyResp(_)  => V2_TYPE_NEW_PROXY_RESP,
            FrpMessage::CloseProxy(_)    => V2_TYPE_CLOSE_PROXY,
            FrpMessage::NewWorkConn(_)   => V2_TYPE_NEW_WORK_CONN,
            FrpMessage::ReqWorkConn(_)   => V2_TYPE_REQ_WORK_CONN,
            FrpMessage::StartWorkConn(_) => V2_TYPE_START_WORK_CONN,
            FrpMessage::Ping(_)          => V2_TYPE_PING,
            FrpMessage::Pong(_)          => V2_TYPE_PONG,
            FrpMessage::UDPPacket(_)     => V2_TYPE_UDP_PACKET,
            FrpMessage::NewVisitorConn(_) => V2_TYPE_NEW_VISITOR_CONN,
            FrpMessage::NewVisitorConnResp(_) => V2_TYPE_NEW_VISITOR_CONN_RESP,
            _ => 0, // NAT hole types have no V2 equivalent yet
        }
    }

    // Accessor helpers
    pub fn as_login(&self) -> &Login { match self { FrpMessage::Login(v) => v, _ => panic!("not a Login") } }
    pub fn as_login_resp(&self) -> &LoginResp { match self { FrpMessage::LoginResp(v) => v, _ => panic!("not a LoginResp") } }
    pub fn as_new_proxy(&self) -> &NewProxy { match self { FrpMessage::NewProxy(v) => v, _ => panic!("not a NewProxy") } }
    pub fn as_new_proxy_resp(&self) -> &NewProxyResp { match self { FrpMessage::NewProxyResp(v) => v, _ => panic!("not a NewProxyResp") } }
    pub fn as_close_proxy(&self) -> &CloseProxy { match self { FrpMessage::CloseProxy(v) => v, _ => panic!("not a CloseProxy") } }
    pub fn as_new_work_conn(&self) -> &NewWorkConn { match self { FrpMessage::NewWorkConn(v) => v, _ => panic!("not a NewWorkConn") } }
    pub fn as_start_work_conn(&self) -> &StartWorkConn { match self { FrpMessage::StartWorkConn(v) => v, _ => panic!("not a StartWorkConn") } }
    pub fn as_ping(&self) -> &Ping { match self { FrpMessage::Ping(v) => v, _ => panic!("not a Ping") } }
    pub fn as_new_visitor_conn(&self) -> &NewVisitorConn { match self { FrpMessage::NewVisitorConn(v) => v, _ => panic!("not a NewVisitorConn") } }
    pub fn as_new_visitor_conn_resp(&self) -> &NewVisitorConnResp { match self { FrpMessage::NewVisitorConnResp(v) => v, _ => panic!("not a NewVisitorConnResp") } }
    pub fn as_close_proxy_resp(&self) -> &CloseProxyResp { match self { FrpMessage::CloseProxyResp(v) => v, _ => panic!("not a CloseProxyResp") } }
    pub fn as_pong(&self) -> &Pong { match self { FrpMessage::Pong(v) => v, _ => panic!("not a Pong") } }
    pub fn as_error(&self) -> &Error { match self { FrpMessage::Error(v) => v, _ => panic!("not an Error") } }

    /// Construct an empty FrpMessage from a V1 type byte (for deserialization).
    pub fn from_v1_type_byte(ty: u8) -> Option<FrpMessage> {
        match ty {
            TYPE_LOGIN         => Some(FrpMessage::Login(Login {
                version: None, hostname: None, os: None, arch: None,
                user: None, run_id: None, client_id: None, pool_count: None,
                timestamp: None, privilege_key: None, metas: None, client_spec: None,
                multiplexer: None,
            })),
            TYPE_LOGIN_RESP    => Some(FrpMessage::LoginResp(LoginResp {
                version: None, run_id: None, error: None,
            })),
            TYPE_NEW_PROXY     => Some(FrpMessage::NewProxy(NewProxy {
                proxy_name: String::new(), proxy_type: String::new(),
                use_encryption: None, use_compression: None,
                group: None, group_key: None, local_str: None,
                remote_port: None, sk: None, custom_domains: None,
                subdomain: None, locations: None, http_user: None,
                http_pwd: None, host_header_rewrite: None, headers: None,
                response_headers: None, route_by_http_user: None,
                allow_users: None, bandwidth_limit: None,
                bandwidth_limit_mode: None, annotations: None,
                metas: None, multiplexer: None,
            })),
            TYPE_NEW_PROXY_RESP => Some(FrpMessage::NewProxyResp(NewProxyResp {
                proxy_name: String::new(), remote_addr: None, error: None,
            })),
            TYPE_CLOSE_PROXY   => Some(FrpMessage::CloseProxy(CloseProxy {
                proxy_name: String::new(),
            })),
            TYPE_NEW_WORK_CONN => Some(FrpMessage::NewWorkConn(NewWorkConn {
                run_id: None, timestamp: None, privilege_key: None,
            })),
            TYPE_REQ_WORK_CONN => Some(FrpMessage::ReqWorkConn(ReqWorkConn {})),
            TYPE_START_WORK_CONN => Some(FrpMessage::StartWorkConn(StartWorkConn {
                proxy_name: String::new(), src_addr: None, src_port: None,
                dst_addr: None, dst_port: None, error: None,
            })),
            TYPE_PING          => Some(FrpMessage::Ping(Ping { privilege_key: None, timestamp: None })),
            TYPE_PONG          => Some(FrpMessage::Pong(Pong { error: None })),
            TYPE_NEW_VISITOR_CONN => Some(FrpMessage::NewVisitorConn(NewVisitorConn {
                proxy_name: String::new(), sign_key: None, timestamp: None,
                run_id: None, use_encryption: None, use_compression: None,
            })),
            TYPE_NEW_VISITOR_CONN_RESP => Some(FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
                proxy_name: String::new(), error: None,
            })),
            TYPE_UDP_PACKET    => Some(FrpMessage::UDPPacket(UDPPacket {
                content: vec![], local_addr: None, remote_addr: None,
            })),
            TYPE_NAT_HOLE_VISITOR => Some(FrpMessage::NatHoleVisitor(NatHoleVisitor {
                proxy_name: String::new(), sign_key: None, timestamp: None,
                run_id: None, use_encryption: None, use_compression: None,
            })),
            TYPE_NAT_HOLE_CLIENT => Some(FrpMessage::NatHoleClient(NatHoleClient {
                proxy_name: String::new(), sign_key: None, run_id: None,
                sid: None, visitor_addr: None,
            })),
            TYPE_NAT_HOLE_RESP => Some(FrpMessage::NatHoleResp(NatHoleResp {
                proxy_name: String::new(), error: None,
            })),
            TYPE_NAT_HOLE_SID => Some(FrpMessage::NatHoleSid(NatHoleSid {
                sid: None,
                provider_addr: None,
            })),
            TYPE_NAT_HOLE_REPORT => Some(FrpMessage::NatHoleReport(NatHoleReport {
                sid: None,
            })),
            TYPE_CLOSE_PROXY_RESP => Some(FrpMessage::CloseProxyResp(CloseProxyResp {
                proxy_name: String::new(),
            })),
            TYPE_ERROR => Some(FrpMessage::Error(Error {
                error: String::new(),
            })),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Serialize + serde::de::DeserializeOwned + std::fmt::Debug>(
        val: &T,
        expected_json: &str,
    ) {
        let json = serde_json::to_string(val).expect("serialize");
        // Verify JSON matches expected (ignoring field ordering)
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse serialized");
        let expected: serde_json::Value = serde_json::from_str(expected_json).expect("parse expected");
        assert_eq!(v, expected, "serialized JSON mismatch");
        let _back: T = serde_json::from_str(&json).expect("deserialize");
    }

    #[test]
    fn test_login_roundtrip_minimal() {
        let login = Login {
            version: None, hostname: None, os: None, arch: None,
            user: None, run_id: None, client_id: None, pool_count: None,
            timestamp: None, privilege_key: None, metas: None, client_spec: None,
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
        let json = serde_json::to_string(&login).expect("serialize");
        let back: Login = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.version.as_deref(), Some("0.69.1"));
        assert_eq!(back.hostname.as_deref(), Some("testhost"));
        assert_eq!(back.pool_count, Some(5));
        assert_eq!(back.multiplexer.as_deref(), Some("yamux"));
        assert!(back.metas.as_ref().unwrap().contains_key("k"));
    }

    #[test]
    fn test_login_resp_roundtrip() {
        let resp = LoginResp {
            version: Some("0.69.1".into()),
            run_id: Some("rid1".into()),
            error: None,
        };
        roundtrip(&resp, r#"{"version":"0.69.1","run_id":"rid1"}"#);

        let err_resp = LoginResp {
            version: None,
            run_id: None,
            error: Some("auth failed".into()),
        };
        roundtrip(&err_resp, r#"{"error":"auth failed"}"#);
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
        roundtrip(&CloseProxy { proxy_name: "p1".into() }, r#"{"proxy_name":"p1"}"#);
    }

    #[test]
    fn test_close_proxy_resp_roundtrip() {
        roundtrip(&CloseProxyResp { proxy_name: "p1".into() }, r#"{"proxy_name":"p1"}"#);
    }

    #[test]
    fn test_error_msg_roundtrip() {
        roundtrip(&Error { error: "something broke".into() }, r#"{"error":"something broke"}"#);
    }

    #[test]
    fn test_new_work_conn_roundtrip() {
        let nwc = NewWorkConn {
            run_id: Some("rid1".into()),
            timestamp: Some(9999),
            privilege_key: Some("priv".into()),
        };
        roundtrip(&nwc, r#"{"run_id":"rid1","timestamp":9999,"privilege_key":"priv"}"#);
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
        };
        roundtrip(&swc, r#"{"proxy_name":"p1","src_addr":"1.2.3.4","src_port":12345}"#);
    }

    #[test]
    fn test_ping_roundtrip() {
        let ping = Ping { privilege_key: Some("pk".into()), timestamp: Some(42) };
        roundtrip(&ping, r#"{"privilege_key":"pk","timestamp":42}"#);
    }

    #[test]
    fn test_pong_roundtrip() {
        roundtrip(&Pong { error: None }, r#"{}"#);
        roundtrip(&Pong { error: Some("err".into()) }, r#"{"error":"err"}"#);
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
        roundtrip(&nvc, r#"{"proxy_name":"stcp1","sign_key":"sk","timestamp":99,"run_id":"rid","use_encryption":true,"use_compression":false}"#);
    }

    #[test]
    fn test_udp_packet_base64_roundtrip() {
        let data = vec![0, 1, 2, 255, 100];
        let pkt = UDPPacket {
            content: data.clone(),
            local_addr: Some(UdpAddr { ip: "127.0.0.1".into(), port: 53, zone: String::new() }),
            remote_addr: Some(UdpAddr { ip: "10.0.0.1".into(), port: 9999, zone: String::new() }),
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
            let msg = FrpMessage::from_v1_type_byte(ty).expect(&format!("from_v1_type_byte({})", ty));
            assert_eq!(msg.v1_type_byte(), ty, "v1_type_byte roundtrip for {}", label);
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
        let cpr: CloseProxyResp = serde_json::from_str(cpr_json).expect("deserialize CloseProxyResp struct");
        assert_eq!(cpr.proxy_name, "my-proxy");
    }

    #[test]
    fn test_unknown_type_byte() {
        assert!(FrpMessage::from_v1_type_byte(0x00).is_none());
        assert!(FrpMessage::from_v1_type_byte(0xFF).is_none());
    }
}
