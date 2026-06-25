//! Plugin support — local servers that handle application-level protocols.
//!
//! When a proxy config includes a `[proxies.plugin]` section, the client
//! starts a local server instead of connecting to an existing local port.
//! The tunneled connections are forwarded to this local server.
//!
//! Supported plugin types:
//! - `http_proxy`: HTTP/HTTPS forward proxy with optional basic auth.

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
}
