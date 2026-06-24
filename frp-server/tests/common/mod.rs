use std::net::SocketAddr;
use tokio::net::TcpSocket;
use tokio::task::JoinHandle;

use frp_core::config::ServerConfig;
use frp_core::msg::{FrpMessage, Login, LoginResp};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_server::service::Service;

/// Bind to a random port, return the port number, then drop the socket.
/// Small race window between drop and reuse, but negligible on localhost.
pub fn allocate_port() -> u16 {
    let socket = TcpSocket::new_v4().expect("create socket");
    socket.bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    socket.local_addr().unwrap().port()
}

/// Start the frp server on the given config, returning the join handle.
/// The server is ready to accept connections after a short sleep.
pub async fn start_test_server(cfg: ServerConfig) -> (JoinHandle<()>, u16) {
    let port = cfg.bind_port;
    let service = Service::new(cfg);
    let handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    // Give the server time to bind and start accepting
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    (handle, port)
}

/// Connect to the server and send a Login message. Returns the LoginResp.
/// Keeps the connection open (caller holds the stream for further messages).
pub async fn raw_login(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
) -> Result<(tokio::net::TcpStream, LoginResp), frp_core::Error> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
        frp_core::Error::Transport(format!("connect to {}: {}", addr, e))
    })?;

    let login = FrpMessage::Login(Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp,
        privilege_key,
        metas: None,
        client_spec: None,
    });

    write_msg_v1(&mut stream, &login).await?;

    match read_msg_v1(&mut stream).await? {
        FrpMessage::LoginResp(resp) => Ok((stream, resp)),
        other => Err(frp_core::Error::Protocol(format!(
            "expected LoginResp, got type byte {:?}",
            other.v1_type_byte()
        ))),
    }
}

/// Like raw_login but discards the stream, returning only the LoginResp.
pub async fn raw_login_resp(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
) -> Result<LoginResp, frp_core::Error> {
    let (_, resp) = raw_login(addr, privilege_key, timestamp).await?;
    Ok(resp)
}
