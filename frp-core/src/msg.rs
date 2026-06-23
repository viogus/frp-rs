use serde::{Deserialize, Serialize};

// V1 message type bytes (matching the Go frp protocol)
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

// V2 message type IDs
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

// ---------------------------------------------------------------
// Concrete message structs – all derive Serialize + Deserialize
// ---------------------------------------------------------------

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
    pub pool_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadatas: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_udp_port: Option<i32>,
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
    pub metadatas: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProxyResp {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<i32>,
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
pub struct Pong {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UDPPacket {
    pub content: Vec<u8>,
    pub local_addr: String,
    pub remote_addr: String,
}

// ---------------------------------------------------------------
// FrpMessage – unified enum over all message types
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FrpMessage {
    Login(Login),
    LoginResp(LoginResp),
    NewProxy(NewProxy),
    NewProxyResp(NewProxyResp),
    CloseProxy(CloseProxy),
    NewWorkConn(NewWorkConn),
    ReqWorkConn(ReqWorkConn),
    StartWorkConn(StartWorkConn),
    Ping(Ping),
    Pong(Pong),
    UDPPacket(UDPPacket),
}

impl FrpMessage {
    pub fn v1_type_byte(&self) -> u8 {
        match self {
            FrpMessage::Login(_)         => TYPE_LOGIN,
            FrpMessage::LoginResp(_)     => TYPE_LOGIN_RESP,
            FrpMessage::NewProxy(_)      => TYPE_NEW_PROXY,
            FrpMessage::NewProxyResp(_)  => TYPE_NEW_PROXY_RESP,
            FrpMessage::CloseProxy(_)    => TYPE_CLOSE_PROXY,
            FrpMessage::NewWorkConn(_)   => TYPE_NEW_WORK_CONN,
            FrpMessage::ReqWorkConn(_)   => TYPE_REQ_WORK_CONN,
            FrpMessage::StartWorkConn(_) => TYPE_START_WORK_CONN,
            FrpMessage::Ping(_)          => TYPE_PING,
            FrpMessage::Pong(_)          => TYPE_PONG,
            FrpMessage::UDPPacket(_)     => TYPE_UDP_PACKET,
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
        }
    }

    /// Return a reference to the inner message as a concrete type.
    /// Panics if the variant doesn't match.
    pub fn as_login(&self) -> &Login {
        match self { FrpMessage::Login(v) => v, _ => panic!("not a Login") }
    }
    pub fn as_login_resp(&self) -> &LoginResp {
        match self { FrpMessage::LoginResp(v) => v, _ => panic!("not a LoginResp") }
    }
    pub fn as_new_proxy(&self) -> &NewProxy {
        match self { FrpMessage::NewProxy(v) => v, _ => panic!("not a NewProxy") }
    }
    pub fn as_new_proxy_resp(&self) -> &NewProxyResp {
        match self { FrpMessage::NewProxyResp(v) => v, _ => panic!("not a NewProxyResp") }
    }
    pub fn as_close_proxy(&self) -> &CloseProxy {
        match self { FrpMessage::CloseProxy(v) => v, _ => panic!("not a CloseProxy") }
    }
    pub fn as_new_work_conn(&self) -> &NewWorkConn {
        match self { FrpMessage::NewWorkConn(v) => v, _ => panic!("not a NewWorkConn") }
    }
    pub fn as_start_work_conn(&self) -> &StartWorkConn {
        match self { FrpMessage::StartWorkConn(v) => v, _ => panic!("not a StartWorkConn") }
    }
    pub fn as_ping(&self) -> &Ping {
        match self { FrpMessage::Ping(v) => v, _ => panic!("not a Ping") }
    }
    pub fn as_pong(&self) -> &Pong {
        match self { FrpMessage::Pong(v) => v, _ => panic!("not a Pong") }
    }

    /// Construct an empty FrpMessage from a V1 type byte (for deserialization).
    pub fn from_v1_type_byte(ty: u8) -> Option<FrpMessage> {
        match ty {
            TYPE_LOGIN         => Some(FrpMessage::Login(Login {
                version: None, hostname: None, os: None, arch: None,
                user: None, run_id: None, pool_count: None,
                timestamp: None, privilege_key: None, metadatas: None,
            })),
            TYPE_LOGIN_RESP    => Some(FrpMessage::LoginResp(LoginResp {
                version: None, run_id: None, server_udp_port: None, error: None,
            })),
            TYPE_NEW_PROXY     => Some(FrpMessage::NewProxy(NewProxy {
                proxy_name: String::new(), proxy_type: String::new(),
                use_encryption: None, use_compression: None,
                group: None, group_key: None, local_str: None,
                remote_port: None, sk: None, custom_domains: None, metadatas: None,
            })),
            TYPE_NEW_PROXY_RESP => Some(FrpMessage::NewProxyResp(NewProxyResp {
                proxy_name: String::new(), remote_port: None, error: None,
            })),
            TYPE_CLOSE_PROXY   => Some(FrpMessage::CloseProxy(CloseProxy {
                proxy_name: String::new(),
            })),
            TYPE_NEW_WORK_CONN => Some(FrpMessage::NewWorkConn(NewWorkConn {
                run_id: None, timestamp: None, privilege_key: None,
            })),
            TYPE_REQ_WORK_CONN => Some(FrpMessage::ReqWorkConn(ReqWorkConn {})),
            TYPE_START_WORK_CONN => Some(FrpMessage::StartWorkConn(StartWorkConn {
                proxy_name: String::new(), dst_addr: None, dst_port: None, error: None,
            })),
            TYPE_PING          => Some(FrpMessage::Ping(Ping { privilege_key: None, timestamp: None })),
            TYPE_PONG          => Some(FrpMessage::Pong(Pong {})),
            TYPE_UDP_PACKET    => Some(FrpMessage::UDPPacket(UDPPacket {
                content: vec![], local_addr: String::new(), remote_addr: String::new(),
            })),
            _ => None,
        }
    }
}
