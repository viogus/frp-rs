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
//! - `virtual_net`: Hand work connections to the vnet controller (no listener).
//! - `visitor_plugin`: STATUS: Placeholder for STCP/XTCP visitor connection
//!   hooks. This is a frp-rs extension (not present in Go frp). Planned for
//!   post-v0.7.0 release.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::service::Service;
use crate::util::opt_if_empty;

mod context;
#[cfg(feature = "http2http")]
mod h2;
mod http;
mod http2http;
mod http2https;
mod https2http;
mod https2https;
mod socks5;
mod static_file;
mod tls2raw;
mod unix_socket;
mod visitor;

pub(crate) use context::PluginContext;
pub use http::start_http_proxy;
pub use http2http::start_http2http_plugin;
pub use http2https::start_http2https_plugin;
pub use https2http::start_https2http_plugin;
pub use https2https::start_https2https_plugin;
pub use socks5::start_socks5_proxy;
pub use static_file::start_static_file_proxy;
pub(crate) use tls2raw::start_tls2raw_plugin;
pub use unix_socket::start_unix_socket_plugin;
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

/// Dispatch to the correct plugin start function based on plugin_type.
/// For `visitor_plugin`, `plugin_ctx` must be `Some`; for all other types,
/// `plugin_ctx` is ignored.
pub(crate) async fn dispatch_plugin_start(
    plugin_cfg: &frp_core::config::PluginConfig,
    plugin_ctx: Option<PluginContext>,
) -> Result<PluginHandle, frp_core::Error> {
    match plugin_cfg.plugin_type.as_str() {
        "http_proxy" => start_http_proxy(plugin_cfg).await,
        "socks5" => start_socks5_proxy(plugin_cfg).await,
        "static_file" => start_static_file_proxy(plugin_cfg).await,
        "unix_domain_socket" => start_unix_socket_plugin(plugin_cfg).await,
        "tls2raw" => start_tls2raw_plugin(plugin_cfg).await,
        "http2http" => start_http2http_plugin(plugin_cfg).await,
        "http2https" => start_http2https_plugin(plugin_cfg).await,
        "https2http" => start_https2http_plugin(plugin_cfg).await,
        "https2https" => start_https2https_plugin(plugin_cfg).await,
        "visitor_plugin" => {
            let ctx = plugin_ctx.ok_or_else(|| {
                frp_core::Error::Config("visitor_plugin requires PluginContext".into())
            })?;
            start_visitor_plugin(plugin_cfg, ctx).await
        }
        other => Err(frp_core::Error::Config(
            format!("unknown plugin type: {other}").into(),
        )),
    }
}

/// Copy one direction of a plugin tunnel with a large, configurable buffer.
///
/// `tokio::io::copy` defaults to an 8 KiB internal buffer; wrapping the
/// reader in a `BufReader` lets the plugin HTTP/HTTPS data planes honor
/// `FRP_BRIDGE_BUF_KB` (32 KiB default) without changing flush semantics.
pub(super) async fn copy_stream_large<R, W>(reader: R, writer: &mut W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut reader =
        tokio::io::BufReader::with_capacity(*frp_core::buffer_pool::BUFFER_SIZE, reader);
    tokio::io::copy_buf(&mut reader, writer).await
}

impl Service {
    /// Start a single plugin and return its handle with resolved bound address.
    /// Used during reload to restart plugins with updated config.
    /// Returns None if plugin_type is unknown or start fails (logged internally).
    pub(crate) async fn start_plugin(
        &self,
        proxy_name: &str,
        plugin_cfg: &frp_core::config::PluginConfig,
    ) -> Option<PluginHandle> {
        if plugin_cfg.plugin_type == "virtual_net" {
            return None;
        }
        let result = if plugin_cfg.plugin_type == "visitor_plugin" {
            let current_cfg = self.cfg.read().await.clone();
            let ctx = PluginContext {
                server_addr: current_cfg.server_addr.clone(),
                server_port: current_cfg.server_port,
                transport_protocol: current_cfg.transport_protocol.clone(),
                tls_enable: current_cfg.tls_enable,
                tls_server_name: current_cfg.tls_server_name.clone(),
                tls_ca_file: opt_if_empty!(current_cfg.tls_ca_file),
                use_encryption: true,
                use_compression: false,
                token: self.auth_cfg.token.clone(),
                oidc_client: self.oidc_client.clone(),
                tcp_mux: current_cfg.tcp_mux,
                tcp_mux_keepalive_interval: current_cfg.tcp_mux_keepalive_interval,
                proxy_url: opt_if_empty!(current_cfg.proxy_url.clone()),
                dns_server: opt_if_empty!(current_cfg.dns_server.clone()),
                dial_timeout_secs: current_cfg.dial_server_timeout.max(1) as u64,
                keepalive_secs: current_cfg.dial_server_keepalive.max(0) as u64,
                connect_bind_addr: opt_if_empty!(current_cfg.connect_server_local_ip.clone()),
                disable_custom_tls_first_byte: current_cfg.disable_custom_tls_first_byte,
                tls_cert_file: opt_if_empty!(current_cfg.tls_cert_file.clone()),
                tls_key_file: opt_if_empty!(current_cfg.tls_key_file.clone()),
                v2: current_cfg.v2,
            };
            dispatch_plugin_start(plugin_cfg, Some(ctx)).await
        } else {
            dispatch_plugin_start(plugin_cfg, None).await
        };

        match result {
            Ok(handle) => {
                info!(
                    plugin_type = %plugin_cfg.plugin_type,
                    proxy_name = %proxy_name,
                    addr = %handle.local_addr,
                    "{} plugin for '{}' restarted on {}",
                    plugin_cfg.plugin_type, proxy_name, handle.local_addr
                );
                Some(handle)
            }
            Err(e) => {
                warn!(
                    plugin_type = %plugin_cfg.plugin_type,
                    proxy_name = %proxy_name,
                    error = %e,
                    "Failed to restart {} plugin for '{}': {}",
                    plugin_cfg.plugin_type, proxy_name, e
                );
                None
            }
        }
    }
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

/// A parsed HTTP request ready to be forwarded: the rewritten head, the
/// request-body framing, and any body bytes that arrived in the same read
/// as the head.
pub(super) struct ForwardedRequest {
    /// Rewritten HTTP/1.0 request head, ending in `\r\n\r\n`.
    pub head: String,
    /// Request body bytes that arrived together with the head. Forward these
    /// verbatim before draining the rest of the body with
    /// [`forward_request_body`].
    pub body_prefix: Vec<u8>,
    /// Framing of the request body; `None` when the request has no body.
    pub body: Option<BodyFraming>,
}

/// How a request body is framed on the wire (RFC 7230 §3.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyFraming {
    /// `Content-Length: N` — forward exactly N raw bytes.
    Length(usize),
    /// `Transfer-Encoding: chunked` — forward the client's framing verbatim.
    Chunked,
}

/// Determine the request body framing from raw header lines. Chunked
/// transfer-encoding wins over Content-Length (RFC 7230 §3.3.3); neither
/// header means the request has no body.
pub(super) fn parse_request_body_framing<'a>(
    headers: impl Iterator<Item = &'a str>,
) -> Option<BodyFraming> {
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in headers {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            if value.trim().to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        } else if name.trim().eq_ignore_ascii_case("content-length") {
            // First parseable value wins; a conflicting second value makes
            // the request malformed (Go's http.Server rejects it outright).
            if content_length.is_none() {
                content_length = value
                    .split(',')
                    .next()
                    .and_then(|v| v.trim().parse::<usize>().ok());
            }
        }
    }
    if chunked {
        Some(BodyFraming::Chunked)
    } else {
        content_length.map(BodyFraming::Length)
    }
}

/// Read an HTTP request head from `stream` (chunked until CRLFCRLF, 64 KiB cap),
/// parse the request line, and build the forwarded HTTP/1.0 request head with
/// optional Host rewrite and injected request headers. Shared by the
/// http2http/http2https/https2http/https2https plugins; each then connects its
/// own backend, writes the returned head, and streams the request body with
/// [`forward_request_body`].
///
/// `request_headers` are injected via Set semantics (Go `req.Header.Set`:
/// an existing header with the same name is replaced), matching Go
/// `pkg/plugin/client/http_common.go rewriteHTTPPluginRequest`.
///
/// Only the head is read here. Body bytes that happen to arrive in the same
/// TCP read as the head are returned in [`ForwardedRequest::body_prefix`] so
/// nothing is lost — Go's http.Server streams request bodies, and discarding
/// pre-read bytes made backends hang forever on POST/PUT.
pub(super) async fn read_request_and_build_forward<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    host_rewrite: &str,
    request_headers: &std::collections::HashMap<String, String>,
) -> Result<ForwardedRequest, String> {
    // Read HTTP headers in chunks until \r\n\r\n. Stop at the FIRST
    // \r\n\r\n anywhere in the buffer (not only at its end): with a request
    // body the head terminator is followed by body bytes, and reading past
    // it would swallow the body into the "headers" until the 64 KiB cap.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
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

    // Body framing is parsed from the original headers — Transfer-Encoding
    // is stripped below as hop-by-hop and re-added only when the request is
    // chunked (the forwarded body bytes keep the client's own framing).
    let framing = parse_request_body_framing(lines.clone());

    // Build forwarded request with optional Host rewrite.
    // Strip hop-by-hop headers per RFC 2616 Section 13.5.1.
    let hop_by_hop: &[&str] = &[
        "transfer-encoding:",
        "proxy-authorization:",
        "proxy-authenticate:",
        "te:",
        "trailer:",
        "upgrade:",
        "connection:",
    ];
    let mut fwd = format!("{method} {path} HTTP/1.0\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_lowercase();
        if hop_by_hop.iter().any(|h| lower.starts_with(h)) {
            continue;
        }
        // Drop Content-Length when the body is chunked (RFC 7230 §3.3.3):
        // Go's http.Server deletes CL when Transfer-Encoding is chunked,
        // and forwarding the ambiguous pair is request-smuggling shaped.
        if framing == Some(BodyFraming::Chunked) && lower.starts_with("content-length:") {
            continue;
        }
        // Skip headers that request_headers will override (Go Header.Set).
        if let Some((name, _)) = line.split_once(':') {
            if request_headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case(name.trim()))
            {
                continue;
            }
        }
        if !host_rewrite.is_empty() && lower.starts_with("host:") {
            let safe_host: String = host_rewrite
                .chars()
                .filter(|&c| c != '\r' && c != '\n')
                .collect();
            fwd.push_str(&format!("Host: {safe_host}\r\n"));
        } else {
            // Strip CR/LF from forwarded header lines: header injection /
            // request-smuggling defense (the h2 plugin path rejects CR/LF
            // outright — mirror that policy here for the HTTP/1.0 path).
            let safe_line: String = line.chars().filter(|&c| c != '\r' && c != '\n').collect();
            fwd.push_str(&safe_line);
            fwd.push_str("\r\n");
        }
    }
    // Inject configured request headers (Go rewriteHTTPPluginRequest).
    // "host" is skipped: Go's req.Header.Set cannot set Host — it is
    // controlled by hostHeaderRewrite (or the original request).
    // Names/values are sanitized against CR/LF like every other header.
    for (k, v) in request_headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        let safe_k: String = k.chars().filter(|&c| c != '\r' && c != '\n').collect();
        let safe_v: String = v.chars().filter(|&c| c != '\r' && c != '\n').collect();
        if safe_k.is_empty() {
            continue;
        }
        fwd.push_str(&format!("{safe_k}: {safe_v}\r\n"));
    }
    if framing == Some(BodyFraming::Chunked) {
        fwd.push_str("Transfer-Encoding: chunked\r\n");
    }
    fwd.push_str("Connection: close\r\n\r\n");

    Ok(ForwardedRequest {
        head: fwd,
        body_prefix: buf[header_end..].to_vec(),
        body: framing,
    })
}

/// Max length of a chunk-size / trailer line in a chunked request body
/// (matches the 64 KiB request-head cap).
const CHUNK_LINE_MAX: usize = 64 * 1024;

/// Stream a request body to `writer`: first the bytes that arrived together
/// with the request head (`body_prefix`), then the rest of the body per its
/// wire framing (Content-Length or chunked Transfer-Encoding). Mirrors the
/// h2 plugin path (`plugin/h2.rs`): Go's http.Server/Transport stream
/// request bodies, and a backend that waits for the full request would hang
/// forever if only the bytes from the first read were forwarded.
///
/// The client's chunked framing is forwarded verbatim (it is already valid
/// HTTP/1.1); the parser only tracks chunk boundaries to know where the body
/// ends so the response relay can start without waiting for the client to
/// close the connection.
pub(super) async fn forward_request_body<S, W>(
    stream: &mut S,
    writer: &mut W,
    body_prefix: &[u8],
    framing: Option<BodyFraming>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(framing) = framing else {
        return Ok(());
    };
    let mut reader = BodyReader::new(stream, body_prefix);
    match framing {
        BodyFraming::Length(total) => {
            let mut remaining = total;
            let mut buf = [0u8; 8192];
            while remaining > 0 {
                let max = remaining.min(buf.len());
                let n = reader
                    .read(&mut buf[..max])
                    .await
                    .map_err(|e| format!("read body: {e}"))?;
                if n == 0 {
                    return Err("connection closed before full body".into());
                }
                writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("write forward body: {e}"))?;
                remaining -= n;
            }
        }
        BodyFraming::Chunked => loop {
            let line = reader
                .read_line(CHUNK_LINE_MAX)
                .await
                .map_err(|e| format!("read chunk line: {e}"))?;
            writer
                .write_all(&line)
                .await
                .map_err(|e| format!("write forward body: {e}"))?;
            // Strip the line terminator, then any chunk extension
            // ("size;ext=val"), to isolate the chunk size.
            let mut size_line = line.as_slice();
            if size_line.ends_with(b"\n") {
                size_line = &size_line[..size_line.len() - 1];
            }
            if size_line.ends_with(b"\r") {
                size_line = &size_line[..size_line.len() - 1];
            }
            let size_part =
                trim_ascii_ws(size_line.split(|&b| b == b';').next().unwrap_or(size_line));
            if size_part.is_empty() {
                continue; // tolerate stray blank lines between chunks
            }
            let size_str = std::str::from_utf8(size_part)
                .map_err(|_| "invalid chunk size in request body".to_string())?;
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| format!("invalid chunk size in request body: {size_str}"))?;
            if size == 0 {
                // Trailer section up to the final blank line (RFC 7230 §4.1.2).
                loop {
                    let trailer = reader
                        .read_line(CHUNK_LINE_MAX)
                        .await
                        .map_err(|e| format!("read chunk trailer: {e}"))?;
                    writer
                        .write_all(&trailer)
                        .await
                        .map_err(|e| format!("write forward body: {e}"))?;
                    if is_blank_line(&trailer) {
                        break;
                    }
                }
                break;
            }
            let mut buf = [0u8; 8192];
            let mut remaining = size;
            while remaining > 0 {
                let max = remaining.min(buf.len());
                let n = reader
                    .read(&mut buf[..max])
                    .await
                    .map_err(|e| format!("read chunk data: {e}"))?;
                if n == 0 {
                    return Err("connection closed mid-chunk".into());
                }
                writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("write forward body: {e}"))?;
                remaining -= n;
            }
            // Chunk data is followed by CRLF (RFC 7230 §4.1).
            let mut crlf = [0u8; 2];
            reader
                .read_exact(&mut crlf)
                .await
                .map_err(|e| format!("read chunk terminator: {e}"))?;
            writer
                .write_all(&crlf)
                .await
                .map_err(|e| format!("write forward body: {e}"))?;
        },
    }
    Ok(())
}

/// Reader over a request body that serves the bytes which arrived together
/// with the request head first, then falls through to the stream. Mirrors
/// the h2-plugin `BodyReader` (`plugin/h2.rs`), which handles the same
/// "body bytes may precede the head split" situation for responses.
struct BodyReader<'a, S: tokio::io::AsyncRead + Unpin> {
    stream: &'a mut S,
    /// Remaining unconsumed bytes that arrived with the head.
    pending: Vec<u8>,
    /// Bytes of `pending` already consumed.
    pos: usize,
}

impl<'a, S: tokio::io::AsyncRead + Unpin> BodyReader<'a, S> {
    fn new(stream: &'a mut S, prefix: &[u8]) -> Self {
        Self {
            stream,
            pending: prefix.to_vec(),
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.pending[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    /// Read into `out`, draining the pending prefix before the stream.
    async fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.available().is_empty() {
            if self.pos > 0 {
                self.pending.clear();
                self.pos = 0;
            }
            return self.stream.read(out).await;
        }
        let n = self.available().len().min(out.len());
        out[..n].copy_from_slice(&self.available()[..n]);
        self.consume(n);
        Ok(n)
    }

    /// Read exactly `out.len()` bytes (UnexpectedEof on early close).
    async fn read_exact(&mut self, out: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            let n = self.read(&mut out[filled..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                ));
            }
            filled += n;
        }
        Ok(())
    }

    /// Read one line (LF or CRLF terminated, terminator included).
    async fn read_line(&mut self, max: usize) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let avail = self.available();
            if let Some(rel) = avail.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&avail[..rel + 1]);
                self.consume(rel + 1);
                return Ok(line);
            }
            line.extend_from_slice(avail);
            self.consume(avail.len());
            if line.len() > max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line too long",
                ));
            }
            if self.pos > 0 {
                self.pending.clear();
                self.pos = 0;
            }
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in line",
                ));
            }
            line.extend_from_slice(&tmp[..n]);
        }
    }
}

/// Trim leading/trailing spaces and tabs from a byte slice (header values
/// and chunk-size lines may carry them).
fn trim_ascii_ws(mut b: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = b.split_first() {
        if first == b' ' || first == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = b.split_last() {
        if last == b' ' || last == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// True when a chunked-body trailer line is blank (only CR/LF/space/tab).
fn is_blank_line(b: &[u8]) -> bool {
    b.iter().all(|&c| matches!(c, b'\r' | b'\n' | b' ' | b'\t'))
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

    #[test]
    fn test_parse_request_body_framing() {
        // No body framing headers → no body.
        assert_eq!(parse_request_body_framing("".lines()), None);
        assert_eq!(
            parse_request_body_framing("Host: example.com".lines()),
            None
        );
        // Content-Length framing.
        assert_eq!(
            parse_request_body_framing("Content-Length: 42".lines()),
            Some(BodyFraming::Length(42))
        );
        assert_eq!(
            parse_request_body_framing("Content-Length: 0".lines()),
            Some(BodyFraming::Length(0))
        );
        // Chunked transfer-encoding.
        assert_eq!(
            parse_request_body_framing("Transfer-Encoding: chunked".lines()),
            Some(BodyFraming::Chunked)
        );
        assert_eq!(
            parse_request_body_framing("Transfer-Encoding: Chunked".lines()),
            Some(BodyFraming::Chunked)
        );
        // Chunked wins over Content-Length (RFC 7230 §3.3.3).
        assert_eq!(
            parse_request_body_framing("Content-Length: 42\r\nTransfer-Encoding: chunked".lines()),
            Some(BodyFraming::Chunked)
        );
        // Unparseable Content-Length is ignored (Go's server rejects the
        // request outright, but a body cannot be inferred from it).
        assert_eq!(
            parse_request_body_framing("Content-Length: abc".lines()),
            None
        );
    }
}
