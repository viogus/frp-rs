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
//! - `visitor_plugin`: Placeholder for STCP/XTCP visitor connection hooks.

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;


mod http;
mod http2http;
mod http2https;
mod https2http;
mod https2https;
mod socks5;
mod static_file;
mod unix_socket;
mod tls2raw;
mod visitor;
mod context;

pub(crate) use http::start_http_proxy;
pub(crate) use http2http::start_http2http_plugin;
pub(crate) use http2https::start_http2https_plugin;
pub(crate) use https2http::start_https2http_plugin;
pub(crate) use https2https::start_https2https_plugin;
pub(crate) use socks5::start_socks5_proxy;
pub(crate) use context::PluginContext;
pub(crate) use static_file::start_static_file_proxy;
pub(crate) use unix_socket::start_unix_socket_plugin;
pub(crate) use tls2raw::start_tls2raw_plugin;
pub(crate) use visitor::start_visitor_plugin;

/// A running plugin server. Drop to shut down.
#[derive(Debug)]
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

/// Shared plugin server skeleton — handles bind, shutdown channel, accept
/// loop, and `PluginHandle` construction. All 8 plugin `start_*` functions
/// delegate to this.
///
/// `handler` receives the accepted `TcpStream`, peer address, and a clone of
/// `state`. It is spawned as a fresh `tokio::task` per connection.
pub(crate) async fn serve_plugin<S, H, Fut>(
    plugin_name: &'static str,
    state: S,
    handler: H,
) -> Result<PluginHandle, frp_core::Error>
where
    S: Clone + Send + Sync + 'static,
    H: Fn(TcpStream, std::net::SocketAddr, S) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    use tokio::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("{plugin_name} plugin: bind: {e}").into())
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("{plugin_name} plugin: local_addr: {e}").into())
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        tracing::debug!(%local_addr, "{plugin_name} plugin listening on {local_addr}");
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            // Forwarded interactive data path — disable Nagle.
                            frp_core::transport::set_nodelay(&stream);
                            let s = state.clone();
                            tokio::spawn(handler(stream, peer, s));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "{plugin_name} plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::debug!("{plugin_name} plugin shutting down");
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

/// Simple base64 decode (no external dep needed for this).
pub(super) fn base64_decode(input: &str) -> Result<String, ()> {
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
    String::from_utf8(buf).map_err(|_| ())
}

pub(super) fn split_host_port(s: &str) -> (&str, u16) {
    // IPv6 bracket notation: [::1]:8080 or [fe80::1%eth0]:443
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, port_str)) = rest.split_once(']') {
            // Port follows the closing bracket, e.g. "]:8080"
            if let Some(port_str) = port_str.strip_prefix(':') {
                if port_str.chars().all(|c| c.is_ascii_digit()) {
                    let port: u16 = port_str.parse().unwrap_or(80);
                    return (host, port);
                }
            }
            // No port after bracket, use default
            return (host, 80);
        }
        // Malformed bracket — fall through
    }
    if let Some((host, port_str)) = s.rsplit_once(':') {
        // Check if the port part is numeric (not IPv6 address)
        if port_str.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = port_str.parse().unwrap_or(80);
            return (host, port);
        }
    }
    (s, 80)
}

/// Read an HTTP request head from `stream` (chunked until CRLFCRLF, 64 KiB cap),
/// parse the request line, and build the forwarded HTTP/1.0 request string with
/// optional Host rewrite. Shared by the http2http/http2https/https2http/https2https
/// plugins; each then connects its own backend and writes the returned string.
pub(super) async fn read_request_and_build_forward<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    host_rewrite: &str,
) -> Result<String, String> {
    // Read HTTP headers in chunks until \r\n\r\n
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
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

    // Split buffer on first \r\n\r\n to separate headers from any pre-read body data.
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(buf.len());
    let headers_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = headers_str.lines();

    // Parse request line: METHOD URL HTTP/1.x
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let path = parts[1];

    // Build forwarded request with optional Host rewrite
    let mut fwd = format!("{method} {path} HTTP/1.0\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if !host_rewrite.is_empty() && line.to_lowercase().starts_with("host:") {
            fwd.push_str(&format!("Host: {host_rewrite}\r\n"));
        } else {
            fwd.push_str(line);
            fwd.push_str("\r\n");
        }
    }
    fwd.push_str("Connection: close\r\n\r\n");

    Ok(fwd)
}

/// Simple percent-decode (application/x-www-form-urlencoded style).
pub(super) fn urlencoding_decode(input: &str) -> String {
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
    fn test_split_host_port() {
        assert_eq!(split_host_port("host:443"), ("host", 443));
        assert_eq!(split_host_port("host"), ("host", 80));
        assert_eq!(split_host_port("1.2.3.4:8080"), ("1.2.3.4", 8080));
    }

    #[test]
    fn test_urlencoding_decode() {
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("%2Fetc%2Fpasswd"), "/etc/passwd");
        assert_eq!(urlencoding_decode("noencoding"), "noencoding");
        assert_eq!(urlencoding_decode("a+b"), "a b");
        assert_eq!(urlencoding_decode("%gg"), "%gg"); // invalid hex
    }
}
