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
pub struct NewWorkConn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UDPPacket {
    #[serde(rename = "c", serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub content: Vec<u8>,
    #[serde(rename = "l")]
    pub local_addr: String,
    #[serde(rename = "r")]
    pub remote_addr: String,
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
    pub fn as_pong(&self) -> &Pong { match self { FrpMessage::Pong(v) => v, _ => panic!("not a Pong") } }

    /// Construct an empty FrpMessage from a V1 type byte (for deserialization).
    pub fn from_v1_type_byte(ty: u8) -> Option<FrpMessage> {
        match ty {
            TYPE_LOGIN         => Some(FrpMessage::Login(Login {
                version: None, hostname: None, os: None, arch: None,
                user: None, run_id: None, client_id: None, pool_count: None,
                timestamp: None, privilege_key: None, metas: None, client_spec: None,
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
                content: vec![], local_addr: String::new(), remote_addr: String::new(),
            })),
            TYPE_NAT_HOLE_VISITOR => Some(FrpMessage::NatHoleVisitor(NatHoleVisitor {
                proxy_name: String::new(), sign_key: None, timestamp: None,
                run_id: None, use_encryption: None, use_compression: None,
            })),
            TYPE_NAT_HOLE_CLIENT => Some(FrpMessage::NatHoleClient(NatHoleClient {
                proxy_name: String::new(), sign_key: None, run_id: None,
            })),
            TYPE_NAT_HOLE_RESP => Some(FrpMessage::NatHoleResp(NatHoleResp {
                proxy_name: String::new(), error: None,
            })),
            TYPE_NAT_HOLE_SID => Some(FrpMessage::NatHoleSid(NatHoleSid {
                sid: None,
            })),
            TYPE_NAT_HOLE_REPORT => Some(FrpMessage::NatHoleReport(NatHoleReport {
                sid: None,
            })),
            _ => None,
        }
    }
}
