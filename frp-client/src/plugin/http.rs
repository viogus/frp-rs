use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::debug;

use frp_core::config::PluginConfig;

use super::{base64_decode, serve_plugin, split_host_port, PluginHandle};

/// Start an HTTP proxy plugin server.
///
/// Returns a handle with the bound address. The server handles:
/// - CONNECT tunneling (HTTPS)
/// - Plain HTTP forwarding
/// - Optional basic auth via `http_user` / `http_password`
pub async fn start_http_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let auth = HttpProxyAuth::from_config(cfg);
    serve_plugin("http_proxy", auth, |stream, peer, auth| async move {
        if let Err(e) = handle_http_proxy_conn(stream, auth).await {
            debug!(%peer, error = %e, "http_proxy: {peer} error: {e}");
        }
    })
    .await
}

#[derive(Clone)]
pub struct HttpProxyAuth {
    user: Option<String>,
    password: Option<String>,
}

impl HttpProxyAuth {
    pub fn from_config(cfg: &PluginConfig) -> Self {
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

    pub fn check(&self, header: &str) -> bool {
        match (self.user.as_deref(), self.password.as_deref()) {
            // No auth configured — accept all connections
            (None, None) => true,
            // Both configured — require both to match
            (Some(expected_user), Some(expected_pass)) => {
                if let Some(credentials) = header.strip_prefix("Basic ") {
                    if let Ok(decoded) = base64_decode(credentials) {
                        if let Some((user, pass)) = decoded.split_once(':') {
                            // Constant-time comparison (parity with
                            // control/admin/SSH auth): the short-circuit `==`
                            // above leaks whether the username matched via
                            // timing. Both comparisons must run — bitwise `&`
                            // (not `&&`) so a mismatched username cannot skip
                            // the password comparison.
                            let user_ok = frp_core::auth::constant_time_eq_str(user, expected_user);
                            let pass_ok = frp_core::auth::constant_time_eq_str(pass, expected_pass);
                            return user_ok & pass_ok;
                        }
                    }
                }
                false
            }
            // Partially configured (only user or only password) — reject all.
            // This is a config error; logging happens once at config load.
            (Some(_), None) | (None, Some(_)) => false,
        }
    }
}

async fn handle_http_proxy_conn(mut client: TcpStream, auth: HttpProxyAuth) -> Result<(), String> {
    // Read headers in chunks until \r\n\r\n
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = client
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
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
        // Go frp compat: 200ms delay to slow brute-force attacks.
        sleep(Duration::from_millis(200)).await;
        let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                       Proxy-Authenticate: Basic realm=\"frp\"\r\n\
                       Content-Length: 0\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
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
    frp_core::transport::set_nodelay(&remote);

    // Tell client connection established
    let resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client
        .write_all(resp)
        .await
        .map_err(|e| format!("write: {e}"))?;

    // Bidirectional copy
    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut remote,
        *frp_core::buffer_pool::BUFFER_SIZE,
        *frp_core::buffer_pool::BUFFER_SIZE,
    )
    .await
    {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
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
    frp_core::transport::set_nodelay(&remote);

    // Split buffer on first \r\n\r\n to separate headers from any pre-read body data.
    let header_end = raw_headers
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw_headers.len());
    let header_bytes = &raw_headers[..header_end];
    let body_bytes = &raw_headers[header_end..];

    // Build forwarded request: rewrite request line, strip Proxy-Auth, add Connection: close
    let headers_str = String::from_utf8_lossy(header_bytes);
    let mut header_lines: Vec<&str> = headers_str.lines().skip(1).collect();
    header_lines.retain(|line| !line.to_lowercase().starts_with("proxy-authorization:"));

    let mut fwd = Vec::new();
    fwd.extend_from_slice(format!("{method} {path} HTTP/1.0\r\n").as_bytes());
    for line in &header_lines {
        fwd.extend_from_slice(line.as_bytes());
        fwd.extend_from_slice(b"\r\n");
    }
    fwd.extend_from_slice(b"Connection: close\r\n\r\n");
    // Append any pre-read body data after the headers
    if !body_bytes.is_empty() {
        fwd.extend_from_slice(body_bytes);
    }

    remote
        .write_all(&fwd)
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    if let Err(e) = tokio::io::copy(&mut remote, &mut client).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
