use serde::Serialize;

/// Events emitted to WebSocket clients via the admin event stream.
/// Uses `#[serde(tag = "type")]` for type-discriminated JSON so clients
/// can match on `event.type`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    /// A new proxy was registered by a client.
    ProxyUp {
        proxy_name: String,
        proxy_type: String,
        run_id: String,
        remote_port: Option<u16>,
    },
    /// A proxy was explicitly closed or its client disconnected.
    ProxyDown { proxy_name: String, run_id: String },
    /// A frpc client connected and authenticated successfully.
    ClientConnected {
        run_id: String,
        client_addr: Option<String>,
    },
    /// A frpc client disconnected (control channel closed).
    ClientDisconnected { run_id: String },
    /// Periodic traffic snapshot for a proxy (emitted every ~1s, only when changed).
    Traffic {
        proxy_name: String,
        bytes_in: u64,
        bytes_out: u64,
        current_conns: i64,
    },
    /// An error condition (auth failure, bind failure, plugin rejection, etc.).
    Error {
        message: String,
        context: Option<String>,
    },
}
