//! Plugin support — local servers that handle application-level protocols.
//!
//! When a proxy config includes a `[proxies.plugin]` section, the client
//! starts a local server instead of connecting to an existing local port.
//! The tunneled connections are forwarded to this local server.
//!
//! Supported plugin types:
//! - `http_proxy`: HTTP/HTTPS forward proxy with optional basic auth.
//! - `socks5`: SOCKS5 proxy (CONNECT only) with optional username/password auth.
//! - `static_file`: Serve static files from a local directory with optional basic auth.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

/// A running plugin server. Drop to shut down.
pub struct PluginHandle {
    pub local_addr: SocketAddr,
    /// Abort handle for the server task.
    _task: tokio::task::JoinHandle<()>,
    /// Signal to shut down (None after drop).
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for PluginHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Start an HTTP proxy plugin server.
///
/// Returns a handle with the bound address. The server handles:
/// - CONNECT tunneling (HTTPS)
/// - Plain HTTP forwarding
/// - Optional basic auth via `http_user` / `http_password`
pub async fn start_http_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("http_proxy plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("http_proxy plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let auth = HttpProxyAuth::from_config(cfg);

    let task = tokio::spawn(async move {
        debug!("http_proxy plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let auth = auth.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_http_proxy_conn(stream, auth).await {
                                    debug!("http_proxy: {peer} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("http_proxy plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("http_proxy plugin shutting down");
                    break;
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}

#[derive(Clone)]
struct HttpProxyAuth {
    user: Option<String>,
    password: Option<String>,
}

impl HttpProxyAuth {
    fn from_config(cfg: &PluginConfig) -> Self {
        let user = if cfg.http_user.is_empty() {
            None
        } else {
            Some(cfg.http_user.clone())
        };
        let password = if cfg.http_password.is_empty() {
            None
        } else {
            Some(cfg.http_password.clone())
        };
        Self { user, password }
    }

    fn check(&self, header: &str) -> bool {
        if self.user.is_none() && self.password.is_none() {
            return true;
        }
        // Parse "Basic base64(user:pass)"
        if let Some(credentials) = header.strip_prefix("Basic ") {
            if let Ok(decoded) = base64_decode(credentials) {
                if let Some((user, pass)) = decoded.split_once(':') {
                    let user_ok = self.user.as_deref().map_or(true, |u| u == user);
                    let pass_ok = self.password.as_deref().map_or(true, |p| p == pass);
                    return user_ok && pass_ok;
                }
            }
        }
        false
    }
}

/// Simple base64 decode (no external dep needed for this).
fn base64_decode(input: &str) -> Result<String, ()> {
    let input = input.trim();
    let mut buf = Vec::new();
    let mut accum = 0u32;
    let mut bits = 0u32;
    for &b in input.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                // padding — finish
                if bits >= 2 {
                    buf.push((accum >> (bits - 2)) as u8);
                }
                break;
            }
            _ => continue, // skip whitespace
        };
        accum = (accum << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }
    Ok(String::from_utf8(buf).map_err(|_| ())?)
}

async fn handle_http_proxy_conn(mut client: TcpStream, auth: HttpProxyAuth) -> Result<(), String> {
    // Read the first line (request line)
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client.read_exact(&mut byte).await.map_err(|e| format!("read: {e}"))?;
        buf.push(byte[0]);
        if buf.len() > 3
            && buf[buf.len() - 4] == b'\r'
            && buf[buf.len() - 3] == b'\n'
            && buf[buf.len() - 2] == b'\r'
            && buf[buf.len() - 1] == b'\n'
        {
            break;
        }
        if buf.len() > 65536 {
            return Err("request headers too large".into());
        }
    }

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line: METHOD URL HTTP/1.1
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let url = parts[1];

    // Parse headers
    let mut proxy_auth = String::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().to_lowercase() == "proxy-authorization" {
                proxy_auth = value.trim().to_string();
            }
        }
    }

    // Check auth
    if !auth.check(&proxy_auth) {
        let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                       Proxy-Authenticate: Basic realm=\"frp\"\r\n\
                       Content-Length: 0\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err("auth failed".into());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, url).await
    } else {
        handle_http_forward(client, &buf, method, url).await
    }
}

async fn handle_connect(mut client: TcpStream, target: &str) -> Result<(), String> {
    // Connect to the target host:port
    let target = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:443")
    };

    let mut remote = TcpStream::connect(&target)
        .await
        .map_err(|e| format!("connect to {target}: {e}"))?;

    // Tell client connection established
    let resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client.write_all(resp).await.map_err(|e| format!("write: {e}"))?;

    // Bidirectional copy
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    Ok(())
}

async fn handle_http_forward(
    mut client: TcpStream,
    raw_headers: &[u8],
    method: &str,
    url: &str,
) -> Result<(), String> {
    // Parse host:port from URL
    let (host, port, path) = parse_http_url(url)?;

    let mut remote = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;

    // Build forwarded request: rewrite request line, strip Proxy-Auth, add Connection: close
    let headers_str = String::from_utf8_lossy(raw_headers);
    let mut header_lines: Vec<&str> = headers_str.lines().skip(1).collect();
    header_lines.retain(|line| {
        !line.to_lowercase().starts_with("proxy-authorization:")
    });

    let mut fwd_headers = format!("{method} {path} HTTP/1.0\r\n");
    for line in &header_lines {
        fwd_headers.push_str(line);
        fwd_headers.push_str("\r\n");
    }
    fwd_headers.push_str("Connection: close\r\n\r\n");

    remote
        .write_all(fwd_headers.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    let _ = tokio::io::copy(&mut remote, &mut client).await;
    Ok(())
}

/// Parse an HTTP URL into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    // Handle absolute URLs: http://host:port/path
    if let Some(rest) = url.strip_prefix("http://") {
        let (host_port, path) = rest.split_once('/').unwrap_or((rest, "/"));
        let path = format!("/{path}");
        let (host, port) = split_host_port(host_port);
        return Ok((host.to_string(), port, path));
    }
    // Handle relative URLs — assume they have Host header (parsed elsewhere)
    // For now, default to port 80
    Err("only absolute HTTP URLs supported".into())
}

fn split_host_port(s: &str) -> (&str, u16) {
    if let Some((host, port_str)) = s.rsplit_once(':') {
        // Check if the port part is numeric (not IPv6 address)
        if port_str.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = port_str.parse().unwrap_or(80);
            return (host, port);
        }
    }
    (s, 80)
}

// ---------------------------------------------------------------
// SOCKS5 plugin (RFC 1928)
// ---------------------------------------------------------------

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;
const USERPASS_VERSION: u8 = 0x01;
const USERPASS_OK: u8 = 0x00;
const USERPASS_FAIL: u8 = 0x01;

/// Start a SOCKS5 proxy plugin server.
///
/// Supports CONNECT command only (TCP tunnel).
/// Optional username/password auth via PluginConfig `username` / `password`.
pub async fn start_socks5_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("socks5 plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("socks5 plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let user = if cfg.username.is_empty() { None } else { Some(cfg.username.clone()) };
    let pass = if cfg.password.is_empty() { None } else { Some(cfg.password.clone()) };

    let task = tokio::spawn(async move {
        debug!("socks5 plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let u = user.clone();
                            let p = pass.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_socks5_conn(stream, u, p).await {
                                    debug!("socks5: {peer} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("socks5 plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("socks5 plugin shutting down");
                    break;
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}

async fn handle_socks5_conn(
    mut client: TcpStream,
    user: Option<String>,
    pass: Option<String>,
) -> Result<(), String> {
    let mut buf = [0u8; 512];

    // Step 1: Auth method negotiation
    client.read_exact(&mut buf[..2]).await.map_err(|e| format!("read greeting: {e}"))?;
    let ver = buf[0];
    let nmethods = buf[1] as usize;
    if ver != SOCKS5_VERSION {
        return Err(format!("bad socks version: {ver}"));
    }
    if nmethods == 0 {
        return Err("no auth methods offered".into());
    }
    client.read_exact(&mut buf[..nmethods]).await.map_err(|e| format!("read methods: {e}"))?;
    let methods = &buf[..nmethods];

    let use_auth = user.is_some() && pass.is_some();

    let chosen_method = if use_auth && methods.contains(&AUTH_USER_PASS) {
        AUTH_USER_PASS
    } else if methods.contains(&AUTH_NO_AUTH) {
        AUTH_NO_AUTH
    } else {
        client.write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]).await
            .map_err(|e| format!("write auth reject: {e}"))?;
        return Err("no acceptable auth method".into());
    };

    client.write_all(&[SOCKS5_VERSION, chosen_method]).await
        .map_err(|e| format!("write auth reply: {e}"))?;

    // Step 2: Username/password auth (if selected)
    if chosen_method == AUTH_USER_PASS {
        let u = user.as_deref().unwrap();
        let p = pass.as_deref().unwrap();

        client.read_exact(&mut buf[..2]).await.map_err(|e| format!("read user/pass ver: {e}"))?;
        if buf[0] != USERPASS_VERSION {
            client.write_all(&[USERPASS_VERSION, USERPASS_FAIL]).await
                .map_err(|e| format!("write auth fail: {e}"))?;
            return Err(format!("bad user/pass version: {}", buf[0]));
        }
        let ulen = buf[1] as usize;
        if ulen > 255 {
            return Err("username too long".into());
        }
        client.read_exact(&mut buf[..ulen]).await.map_err(|e| format!("read username: {e}"))?;
        let client_user = std::str::from_utf8(&buf[..ulen])
            .map_err(|e| format!("username utf8: {e}"))?
            .to_string();

        client.read_exact(&mut buf[..1]).await.map_err(|e| format!("read plen: {e}"))?;
        let plen = buf[0] as usize;
        if plen > 255 {
            return Err("password too long".into());
        }
        client.read_exact(&mut buf[..plen]).await.map_err(|e| format!("read password: {e}"))?;
        let client_pass = std::str::from_utf8(&buf[..plen])
            .map_err(|e| format!("password utf8: {e}"))?
            .to_string();

        if client_user == u && client_pass == p {
            client.write_all(&[USERPASS_VERSION, USERPASS_OK]).await
                .map_err(|e| format!("write auth ok: {e}"))?;
        } else {
            client.write_all(&[USERPASS_VERSION, USERPASS_FAIL]).await
                .map_err(|e| format!("write auth fail: {e}"))?;
            return Err("auth failed".into());
        }
    }

    // Step 3: Read request
    client.read_exact(&mut buf[..4]).await.map_err(|e| format!("read request hdr: {e}"))?;
    if buf[0] != SOCKS5_VERSION {
        return Err(format!("bad request version: {}", buf[0]));
    }
    let cmd = buf[1];
    let atyp = buf[3];

    if cmd != CMD_CONNECT {
        let reply = make_socks5_reply(REP_CMD_NOT_SUPPORTED, ATYP_IPV4, &[0, 0, 0, 0], 0);
        client.write_all(&reply).await.map_err(|e| format!("write reply: {e}"))?;
        return Err(format!("unsupported cmd: {cmd}"));
    }

    // Parse target address
    let (host, port) = parse_socks5_target(&mut client, atyp, &mut buf).await?;

    // Step 4: Connect to target
    let target = format!("{host}:{port}");
    let mut remote = match TcpStream::connect(&target).await {
        Ok(remote) => remote,
        Err(_) => {
            let reply = make_socks5_reply(REP_HOST_UNREACHABLE, ATYP_IPV4, &[0, 0, 0, 0], 0);
            let _ = client.write_all(&reply).await;
            return Err(format!("connect to {target}: failed"));
        }
    };

    // Send success reply
    let reply = make_socks5_reply(REP_SUCCEEDED, ATYP_IPV4, &[0, 0, 0, 0], 0);
    client.write_all(&reply).await.map_err(|e| format!("write reply: {e}"))?;

    // Step 5: Bidirectional relay
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    Ok(())
}

/// Pure parser: decode a SOCKS5 address (ATYP + addr + port) from bytes.
/// Returns (host_string, port, bytes_consumed).
#[allow(dead_code)]
fn parse_socks5_addr(buf: &[u8]) -> Result<(String, u16, usize), String> {
    if buf.is_empty() {
        return Err("empty buffer".into());
    }
    let atyp = buf[0];
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 7 {
                return Err("buffer too short for IPv4".into());
            }
            let host = format!("{}.{}.{}.{}", buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((host, port, 7))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Err("buffer too short for domain length".into());
            }
            let dlen = buf[1] as usize;
            if dlen > 255 {
                return Err("domain name too long".into());
            }
            if buf.len() < 2 + dlen + 2 {
                return Err("buffer too short for domain+port".into());
            }
            let domain = std::str::from_utf8(&buf[2..2 + dlen])
                .map_err(|e| format!("domain utf8: {e}"))?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
            Ok((domain, port, 2 + dlen + 2))
        }
        ATYP_IPV6 => {
            if buf.len() < 19 {
                return Err("buffer too short for IPv6".into());
            }
            let host = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([buf[1], buf[2]]),
                u16::from_be_bytes([buf[3], buf[4]]),
                u16::from_be_bytes([buf[5], buf[6]]),
                u16::from_be_bytes([buf[7], buf[8]]),
                u16::from_be_bytes([buf[9], buf[10]]),
                u16::from_be_bytes([buf[11], buf[12]]),
                u16::from_be_bytes([buf[13], buf[14]]),
                u16::from_be_bytes([buf[15], buf[16]]),
            );
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((host, port, 19))
        }
        _ => Err(format!("unsupported atyp: {atyp}")),
    }
}

/// Parse target address from SOCKS5 request (ATYP + addr + port) over TCP.
async fn parse_socks5_target(
    client: &mut TcpStream,
    atyp: u8,
    buf: &mut [u8; 512],
) -> Result<(String, u16), String> {
    match atyp {
        ATYP_IPV4 => {
            client.read_exact(&mut buf[..6]).await.map_err(|e| format!("read ipv4: {e}"))?;
            let host = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((host, port))
        }
        ATYP_DOMAIN => {
            client.read_exact(&mut buf[..1]).await.map_err(|e| format!("read domain len: {e}"))?;
            let dlen = buf[0] as usize;
            if dlen > 255 {
                return Err("domain name too long".into());
            }
            client.read_exact(&mut buf[..dlen]).await.map_err(|e| format!("read domain: {e}"))?;
            let domain = std::str::from_utf8(&buf[..dlen])
                .map_err(|e| format!("domain utf8: {e}"))?
                .to_string();
            client.read_exact(&mut buf[..2]).await.map_err(|e| format!("read port: {e}"))?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            Ok((domain, port))
        }
        ATYP_IPV6 => {
            client.read_exact(&mut buf[..18]).await.map_err(|e| format!("read ipv6: {e}"))?;
            let host = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
            );
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((host, port))
        }
        _ => {
            let reply = make_socks5_reply(REP_ADDR_NOT_SUPPORTED, ATYP_IPV4, &[0, 0, 0, 0], 0);
            client.write_all(&reply).await.map_err(|e| format!("write reply: {e}"))?;
            Err(format!("unsupported atyp: {atyp}"))
        }
    }
}

/// Build a SOCKS5 reply packet.
fn make_socks5_reply(rep: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut reply = Vec::with_capacity(6 + addr.len());
    reply.push(SOCKS5_VERSION);
    reply.push(rep);
    reply.push(0x00); // RSV
    reply.push(atyp);
    reply.extend_from_slice(addr);
    reply.extend_from_slice(&port.to_be_bytes());
    reply
}

// ---------------------------------------------------------------
// static_file plugin
// ---------------------------------------------------------------

/// Start a static file serving plugin.
///
/// Serves files from `local_path` directory over HTTP.
/// Supports optional basic auth (`http_user` / `http_password`)
/// and URL prefix stripping (`strip_prefix`).
pub async fn start_static_file_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    if cfg.local_path.is_empty() {
        return Err(frp_core::Error::Config(
            "static_file plugin requires local_path".into()
        ));
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("static_file plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("static_file plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let auth = HttpProxyAuth::from_config(cfg);
    let local_path = cfg.local_path.clone();
    let strip_prefix: Option<String> = if cfg.strip_prefix.is_empty() {
        None
    } else {
        Some(cfg.strip_prefix.trim_matches('/').to_string())
    };

    let task = tokio::spawn(async move {
        debug!("static_file plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let a = auth.clone();
                            let lp = local_path.clone();
                            let sp = strip_prefix.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_static_file_conn(stream, a, &lp, sp.as_deref()).await
                                {
                                    debug!("static_file: {peer} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("static_file plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("static_file plugin shutting down");
                    break;
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}

async fn handle_static_file_conn(
    mut client: TcpStream,
    auth: HttpProxyAuth,
    local_path: &str,
    strip_prefix: Option<&str>,
) -> Result<(), String> {
    // Read HTTP request headers (reuse pattern from http_proxy)
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client.read_exact(&mut byte).await.map_err(|e| format!("read: {e}"))?;
        buf.push(byte[0]);
        if buf.len() > 3
            && buf[buf.len() - 4] == b'\r'
            && buf[buf.len() - 3] == b'\n'
            && buf[buf.len() - 2] == b'\r'
            && buf[buf.len() - 1] == b'\n'
        {
            break;
        }
        if buf.len() > 65536 {
            return Err("request too large".into());
        }
    }

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let url_path = parts[1];

    if method != "GET" {
        let resp = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err(format!("method not allowed: {method}"));
    }

    // Check auth (Authorization header with Basic scheme)
    let mut authorization = String::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("authorization") {
                authorization = value.trim().to_string();
            }
        }
    }

    if !auth.check(&authorization) {
        let resp = b"HTTP/1.1 401 Unauthorized\r\n\
                       WWW-Authenticate: Basic realm=\"frp\"\r\n\
                       Content-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err("auth failed".into());
    }

    // Decode URL and strip prefix to get relative filesystem path
    let rel_path = resolve_static_path(url_path, strip_prefix)?;

    // Sanitize: reject path traversal
    if rel_path.contains("..") {
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err("path traversal rejected".into());
    }

    // Build full filesystem path
    let mut full_path = std::path::PathBuf::from(local_path);
    if !rel_path.is_empty() {
        full_path = full_path.join(&rel_path);
    }

    // If directory, try index.html
    if full_path.is_dir() {
        full_path = full_path.join("index.html");
    }

    // Read and serve file
    let content = match std::fs::read(&full_path) {
        Ok(data) => data,
        Err(_) => {
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = client.write_all(resp).await;
            return Err(format!("file not found: {}", full_path.display()));
        }
    };

    let mime = mime_from_path(&full_path);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    );
    client.write_all(resp.as_bytes()).await.map_err(|e| format!("write headers: {e}"))?;
    client.write_all(&content).await.map_err(|e| format!("write body: {e}"))?;

    Ok(())
}

/// Resolve a URL path to a relative filesystem path, with optional prefix stripping.
/// Returns a relative path (no leading `/`) or empty string for root.
fn resolve_static_path(url_path: &str, strip_prefix: Option<&str>) -> Result<String, String> {
    // URL-decode
    let decoded = urlencoding_decode(url_path);

    let stripped = if let Some(prefix) = strip_prefix {
        let prefix_slash = format!("/{prefix}");
        match decoded.strip_prefix(&prefix_slash) {
            Some(rest) => rest,
            None => {
                return Err(format!("prefix '{}' not found in path '{}'", prefix, decoded));
            }
        }
    } else {
        &decoded
    };

    // Convert to relative path: strip leading /, empty string for root
    let trimmed = stripped.trim_start_matches('/');
    Ok(trimmed.to_string())
}

/// Simple percent-decode (application/x-www-form-urlencoded style).
fn urlencoding_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4 | lo) as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Detect MIME type from file extension.
fn mime_from_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("wasm") => "application/wasm",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        // "test:pass" = dGVzdDpwYXNz
        let result = base64_decode("dGVzdDpwYXNz").unwrap();
        assert_eq!(result, "test:pass");
    }

    #[test]
    fn test_parse_http_url() {
        let (host, port, path) = parse_http_url("http://example.com:8080/foo/bar").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo/bar");

        let (host, port, path) = parse_http_url("http://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_split_host_port() {
        assert_eq!(split_host_port("host:443"), ("host", 443));
        assert_eq!(split_host_port("host"), ("host", 80));
        assert_eq!(split_host_port("1.2.3.4:8080"), ("1.2.3.4", 8080));
    }

    // --- SOCKS5 tests ---

    #[test]
    fn test_socks5_make_reply_success() {
        let reply = make_socks5_reply(REP_SUCCEEDED, ATYP_IPV4, &[127, 0, 0, 1], 8080);
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(reply[2], 0x00); // RSV
        assert_eq!(reply[3], ATYP_IPV4);
        assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), 8080);
    }

    #[test]
    fn test_socks5_make_reply_host_unreachable() {
        let reply = make_socks5_reply(REP_HOST_UNREACHABLE, ATYP_IPV4, &[0, 0, 0, 0], 0);
        assert_eq!(reply[1], REP_HOST_UNREACHABLE);
    }

    #[test]
    fn test_socks5_make_reply_ipv6() {
        let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let reply = make_socks5_reply(REP_SUCCEEDED, ATYP_IPV6, &addr, 443);
        assert_eq!(reply[3], ATYP_IPV6);
        assert_eq!(reply.len(), 22); // 4 + 16 + 2
        assert_eq!(&reply[4..20], &addr);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 443);
    }

    #[test]
    fn test_socks5_parse_ipv4_addr() {
        // ATYP_IPV4 + 4 bytes + 2 bytes port
        let buf: [u8; 7] = [ATYP_IPV4, 192, 168, 1, 100, 0x1f, 0x90]; // 192.168.1.100:8080
        let (host, port, consumed) = parse_socks5_addr(&buf).unwrap();
        assert_eq!(host, "192.168.1.100");
        assert_eq!(port, 8080);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_socks5_parse_domain_addr() {
        // ATYP_DOMAIN + len(11) + "example.com" + port(443)
        let domain = b"example.com";
        let mut buf = vec![ATYP_DOMAIN, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let (host, port, consumed) = parse_socks5_addr(&buf).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(consumed, 1 + 1 + 11 + 2); // atyp + len + domain + port
    }

    #[tokio::test]
    async fn test_socks5_auth_negotiation_no_auth() {
        // Start a mini socks5 handler, connect as client, verify no-auth negotiation
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // No username/password → no-auth only
            let _ = handle_socks5_conn(stream, None, None).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send greeting: version=5, 1 method, method=NO_AUTH
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH]).await.unwrap();

        // Read auth reply
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], AUTH_NO_AUTH, "expected no-auth method");

        // Close to let server finish
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_auth_negotiation_user_pass() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_socks5_conn(stream, Some("alice".into()), Some("s3cret".into())).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send greeting: version=5, 2 methods: USER_PASS, NO_AUTH
        client.write_all(&[SOCKS5_VERSION, 2, AUTH_USER_PASS, AUTH_NO_AUTH]).await.unwrap();

        // Server should pick USER_PASS
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], AUTH_USER_PASS);

        // Send user/pass auth: VER=1, ULEN=5, "alice", PLEN=6, "s3cret"
        client.write_all(&[USERPASS_VERSION, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"s3cret").await.unwrap();

        // Read auth result
        let mut auth_result = [0u8; 2];
        client.read_exact(&mut auth_result).await.unwrap();
        assert_eq!(auth_result[0], USERPASS_VERSION);
        assert_eq!(auth_result[1], USERPASS_OK, "expected auth success");

        drop(client);
        server.await.unwrap();
    }

    // --- static_file tests ---

    #[test]
    fn test_resolve_static_path_no_prefix() {
        assert_eq!(resolve_static_path("/", None).unwrap(), "");
        assert_eq!(resolve_static_path("/index.html", None).unwrap(), "index.html");
        assert_eq!(resolve_static_path("/css/style.css", None).unwrap(), "css/style.css");
        assert_eq!(resolve_static_path("/a/b/c.html", None).unwrap(), "a/b/c.html");
    }

    #[test]
    fn test_resolve_static_path_with_prefix() {
        let sp = Some("static");
        assert_eq!(resolve_static_path("/static/", sp).unwrap(), "");
        assert_eq!(resolve_static_path("/static/index.html", sp).unwrap(), "index.html");
        assert_eq!(resolve_static_path("/static/css/style.css", sp).unwrap(), "css/style.css");
    }

    #[test]
    fn test_resolve_static_path_prefix_mismatch() {
        assert!(resolve_static_path("/other/file.html", Some("static")).is_err());
        assert!(resolve_static_path("/", Some("static")).is_err());
    }

    #[test]
    fn test_urlencoding_decode() {
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("%2Fetc%2Fpasswd"), "/etc/passwd");
        assert_eq!(urlencoding_decode("noencoding"), "noencoding");
        assert_eq!(urlencoding_decode("a+b"), "a b");
        assert_eq!(urlencoding_decode("%gg"), "%gg"); // invalid hex
    }

    #[test]
    fn test_mime_from_path() {
        use std::path::Path;
        assert_eq!(mime_from_path(Path::new("index.html")), "text/html; charset=utf-8");
        assert_eq!(mime_from_path(Path::new("style.css")), "text/css; charset=utf-8");
        assert_eq!(mime_from_path(Path::new("app.js")), "application/javascript; charset=utf-8");
        assert_eq!(mime_from_path(Path::new("image.png")), "image/png");
        assert_eq!(mime_from_path(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(mime_from_path(Path::new("unknown.xyz")), "application/octet-stream");
    }

    #[test]
    fn test_resolve_static_path_rejects_traversal() {
        // resolve_static_path itself doesn't reject .. — caller does.
        // Verify that .. passes through (caller's responsibility to check).
        assert_eq!(resolve_static_path("/../etc/passwd", None).unwrap(), "../etc/passwd");
    }
}
