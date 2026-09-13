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

/// Real tunnel-peer registry for the http-family plugins (Go parity:
/// `http_common.go:116-117` — `SetRemoteAddr(connInfo.SrcAddr)` when
/// `useSourceRemoteAddr`, which only the https2http/https2https variants set).
///
/// `serve_plugin` binds 127.0.0.1:0, so every plugin accept sees the frpc
/// work-conn dialer — `peer.ip()` is always 127.0.0.1 and an X-Forwarded-For
/// appended from it would lie about the tunnel peer (audit finding M9). The
/// real address lives only in StartWorkConn (`src_addr`/`src_port`), parsed by
/// the work-conn side; it registers it here keyed by its local ephemeral
/// port, and the plugin accept handler for that conn takes it once.
/// http2http/http2https never register or consult this — Go does not call
/// SetXForwarded there. Lookup miss (health-check or stray dial) falls back
/// to the loopback peer, which is today's behavior.
static REAL_TUNNEL_PEER: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u16, SocketAddr>>,
> = std::sync::OnceLock::new();

fn real_tunnel_peer_map() -> &'static std::sync::Mutex<std::collections::HashMap<u16, SocketAddr>> {
    REAL_TUNNEL_PEER.get_or_init(Default::default)
}

/// RAII handle for a REAL_TUNNEL_PEER entry (audit F5). The work-conn task
/// holds it for as long as its bridged connection could still be consumed
/// by the plugin's accept handler; the `Drop` removes the entry on EVERY
/// exit path — normal bridge end, early return, and tokio abort (aborting
/// the task drops its future, which drops the guard). Without it, entries
/// survived their connection: a leaked registry entry keyed by an ephemeral
/// port is stale forever, and when the OS later recycles that port for an
/// UNRELATED dial the stale entry misattributes that connection's
/// X-Forwarded-For (the take-once consume would fire on the wrong conn).
pub(crate) struct PluginPeerGuard {
    dialer_port: u16,
    real_peer: SocketAddr,
}

impl Drop for PluginPeerGuard {
    fn drop(&mut self) {
        // Remove only when the entry is still the one THIS guard registered
        // (newest-registration-wins): a guard from a superseded registration
        // must not delete its successor's live entry.
        let mut map = real_tunnel_peer_map()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map.get(&self.dialer_port) == Some(&self.real_peer) {
            map.remove(&self.dialer_port);
        }
    }
}

/// Register the real tunnel peer for one plugin connection, keyed by the
/// work-conn dialer's local ephemeral port (kernel-assigned, unique per
/// concurrent dial). Called right after the dial succeeds; the accept
/// handler for that connection consumes the entry. Returns a guard whose
/// Drop removes the entry (see PluginPeerGuard).
pub(crate) fn register_plugin_peer(dialer_port: u16, real_peer: SocketAddr) -> PluginPeerGuard {
    real_tunnel_peer_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(dialer_port, real_peer);
    PluginPeerGuard {
        dialer_port,
        real_peer,
    }
}

/// Wholesale clear of every registry entry. Called by serve_plugin teardown
/// (audit F5): the listener has just aborted and drained every handler that
/// could consume entries, so any survivors are leaks from connections whose
/// work-conn task ended abnormally WITHOUT its guard running (defense in
/// depth — the guard covers the normal paths). Clearing is safe even if a
/// handler is somehow still mid-flight: an entry cleared under it degrades
/// that one connection to the loopback peer fallback, the status quo
/// before the registry existed.
pub(crate) fn clear_plugin_peers() {
    real_tunnel_peer_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// Resolve the real tunnel peer for an accepted plugin connection. The
/// dialer registers a few microseconds after `connect()` returns, so an
/// accept handler that wins the scheduling race retries briefly before
/// falling back to the loopback peer (status quo behavior).
fn take_plugin_peer(dialer_port: u16) -> Option<SocketAddr> {
    real_tunnel_peer_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&dialer_port)
}

pub(crate) async fn plugin_peer_ip(peer: SocketAddr) -> std::net::IpAddr {
    for _ in 0..8 {
        if let Some(real) = take_plugin_peer(peer.port()) {
            return real.ip();
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    peer.ip()
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
        // Throttle accept-error warnings: under persistent EMFILE the loop
        // fails ~10/s (100ms pause below), which would flood the logs.
        let mut last_accept_warn: Option<std::time::Instant> = None;
        // In-flight connection handlers, so shutdown can abort them — Go's
        // http.Server.Close() closes active connections; a dropped
        // PluginHandle previously left handler tasks running until the
        // client disconnected.
        let mut handlers: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            // Forwarded interactive data path — disable Nagle.
                            frp_core::transport::set_nodelay(&stream);
                            let s = state.clone();
                            handlers.spawn(handler(stream, peer, s));
                        }
                        Err(e) => {
                            // Warn at most once per second while the accept
                            // failure persists (the first failure warns too).
                            if last_accept_warn
                                .map(|t| t.elapsed() >= std::time::Duration::from_secs(1))
                                .unwrap_or(true)
                            {
                                tracing::warn!(error = %e, "{plugin_name} plugin accept error: {e}");
                                last_accept_warn = Some(std::time::Instant::now());
                            }
                            // Transient accept errors (EMFILE/ENFILE fd
                            // exhaustion, etc.) must not kill the listener:
                            // Go's Accept loop retries. Pause briefly to
                            // avoid hot-spinning while the condition
                            // persists; only the shutdown signal breaks the
                            // loop.
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::debug!("{plugin_name} plugin shutting down");
                    break;
                }
            }
        }
        // Abort in-flight handlers (Go http.Server.Close() semantics) and
        // wait until every task has actually stopped, so the plugin's local
        // port is never left half-served after the handle is dropped.
        handlers.abort_all();
        while handlers.join_next().await.is_some() {}
        // Audit F5: every handler that could consume a REAL_TUNNEL_PEER
        // entry is now gone, so sweep whatever the guards left behind
        // (connections whose work-conn task died without dropping its
        // guard). Entries are keyed by ephemeral ports that outlive this
        // listener, so a survivor would misattribute X-Forwarded-For on
        // port recycling. Benign worst case: an in-flight entry cleared
        // here degrades that conn to the loopback peer fallback.
        clear_plugin_peers();
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
    ///
    /// `use_encryption`/`use_compression` come from the owning proxy's config:
    /// PluginConfig has no such fields, and the visitor plugin's NewVisitorConn
    /// wire declaration plus its P2P bridge wrappers (visitor.rs) must match
    /// what the proxy declares, not a hardcoded value.
    pub(crate) async fn start_plugin(
        &self,
        proxy_name: &str,
        plugin_cfg: &frp_core::config::PluginConfig,
        use_encryption: bool,
        use_compression: bool,
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
                use_encryption,
                use_compression,
                token: self.auth_cfg.token.clone(),
                oidc_client: self.oidc_client.clone(),
                tcp_mux: current_cfg.tcp_mux,
                tcp_mux_keepalive_interval: current_cfg.tcp_mux_keepalive_interval,
                tcp_mux_keepalive_timeout: current_cfg.tcp_mux_keepalive_timeout,
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
/// Strict base64 → UTF-8, Go `base64.StdEncoding` semantics (length % 4,
/// padding placement, no whitespace/unknown-char tolerance).
///
/// The old hand-rolled decoder TRIMMED its input and skipped unknown bytes:
/// "Basic  dTE6cDE=" decoded where Go's DecodeString rejects the leading
/// space (delay-classification divergence), and its padding flush emitted a
/// spurious trailing NUL byte whenever the payload length was not a
/// multiple of 3 ("u1:p1" decoded to "u1:p1\0", so every valid credential
/// of that shape failed the compare).
pub(super) fn base64_decode(input: &str) -> Result<String, ()> {
    let bytes = frp_core::base64::decode(input).map_err(|_| ())?;
    String::from_utf8(bytes).map_err(|_| ())
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
    /// Rewritten HTTP/1.1 request head, ending in `\r\n\r\n`.
    pub head: String,
    /// Request body bytes that arrived together with the head. Forward these
    /// verbatim before draining the rest of the body with
    /// [`forward_request_body`].
    pub body_prefix: Vec<u8>,
    /// Framing of the request body; `None` when the request has no body.
    pub body: Option<BodyFraming>,
    /// Request method (e.g. `HEAD`) — the body forward skips it when the
    /// method can never carry a body.
    pub method: String,
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
/// Case-insensitive `starts_with` on ASCII header-name prefixes. The
/// forward builders scan every header line against hop-by-hop /
/// content-length / host / x-forwarded-for prefixes; allocating a lowercase
/// String per line was a per-request alloc cluster (round-17 audit E). The
/// prefix constants are ASCII, so byte-slice comparison is equivalent and
/// zero-alloc. `s.len() >= p.len()` mirrors `str::starts_with`'s short-length
/// short-circuit.
pub(super) fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    let s = s.as_bytes();
    let p = prefix.as_bytes();
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

/// header means the request has no body.
///
/// Content-Length is resolved by [`resolve_content_length`]: duplicate
/// identical values collapse to one length; list-form values ("5, 5") and
/// every non-decimal value are rejected (Go `parseContentLength` —
/// `strconv.ParseUint` takes no commas, so net/http answers 400). On error
/// no framing is inferred here — the head builders reject the request on
/// that error before any body is forwarded.
pub(super) fn parse_request_body_framing<'a>(
    headers: impl Iterator<Item = &'a str>,
) -> Option<BodyFraming> {
    // Collect so the Content-Length resolution below can re-scan the full
    // header set — a single-pass "first value wins" scan would miss
    // duplicate/conflicting lines.
    let lines: Vec<&str> = headers.collect();
    let mut chunked = false;
    for line in &lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding")
            && transfer_encoding_is_chunked(value)
        {
            chunked = true;
        }
    }
    if chunked {
        Some(BodyFraming::Chunked)
    } else {
        resolve_content_length(lines.into_iter())
            .ok()
            .flatten()
            .map(BodyFraming::Length)
    }
}

/// Whether the Transfer-Encoding header group of a parsed head is
/// acceptable to Go readTransfer's protoAtLeast(1,1) arm (transfer.go
/// parseTransferEncoding): a head with NO Transfer-Encoding line is
/// always fine (`len(raw) == 0` returns nil, no error), a single line
/// EqualFold-"chunked" is fine, while more than one TE header line is
/// "too many transfer-encoding values" and a single line that is not
/// ASCII-case-insensitive "chunked" is "unsupported transfer encoding" —
/// both readRequest errors (Go http.Server faces render 501; the
/// Err-to-bare-close policy of the operator-local http2http-family
/// listeners applies instead). Callers gate on the request version first
/// — an HTTP/1.0 request ignores its Transfer-Encoding entirely (Issue
/// 12785) and must not reach this check. Round-17 audit finding E; line
/// semantics match [`parse_request_body_framing`] (the value is the raw
/// text after the first ':', trimmed — obs-fold merging is not applied
/// at this face).
fn transfer_encoding_group_ok<'a>(headers: impl Iterator<Item = &'a str>) -> bool {
    let mut values: Vec<&str> = Vec::new();
    for line in headers {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            values.push(value.trim());
        }
    }
    values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("chunked"))
}

/// True when a Transfer-Encoding value applies the chunked coding. Per RFC
/// 7230 §3.3.3, chunked must be the FINAL coding of a comma-separated list
/// ("gzip, chunked" is chunked; "chunkedfoo" or any coding after chunked is
/// not) — a substring check would mis-detect `chunkedfoo`.
fn transfer_encoding_is_chunked(value: &str) -> bool {
    value
        .split(',')
        .next_back()
        .map(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
}

/// Resolve the Content-Length header(s) of a request head to one canonical
/// value per RFC 7230 §3.3.2 ("reject or replace with a single value"),
/// mirroring Go's net/http `fixLength` + `parseContentLength`
/// (transfer.go — probed against the Go frp v0.71.0 binary, go1.25.12).
/// Go stores each header line value trimmed of ASCII space/tab only —
/// textproto's `isASCIISpace` is exactly {' ', '\t', '\n', '\r'} with the
/// newline bytes unreachable in a value, and every OTHER control byte
/// (<0x21 except tab, plus 0x7f) is rejected by `validHeaderValueByte`
/// while the head is read (reader.go — 400 "malformed MIME header line").
/// The trim below therefore strips only space/tab: a value carrying any
/// other control byte survives to the digit parse and fails it, matching
/// Go's rejection. Go never splits on commas, so:
///
/// - no Content-Length → `Ok(None)`;
/// - duplicate identical values (`Content-Length: 5` twice — identical on
///   the trimmed raw text, so `05` + `5` differ and are rejected) →
///   `Ok(Some(5))`, forwarded as a single line;
/// - a list-form value (`Content-Length: 5, 5`) → `Err` — Go's
///   `strconv.ParseUint` accepts no comma, so net/http answers 400 (audit
///   round-8 F9: the old code summed the parts);
/// - an empty value → `Err("invalid empty Content-Length")` (Go's text);
/// - a non-decimal value (letters, any sign — ParseUint accepts no sign,
///   not even `+`) → `Err("bad Content-Length")` (Go's text);
/// - a value above 2^63-1 → `Err("bad Content-Length")` (Go's bitSize=63);
/// - conflicting values (`Content-Length: 5` + `Content-Length: 100`) →
///   `Err`: the request framing is invalid and the request must be rejected
///   (the connection closes — no 400 is sent, like the other parser
///   failures).
pub(super) fn resolve_content_length<'a>(
    headers: impl Iterator<Item = &'a str>,
) -> Result<Option<usize>, String> {
    // Trimmed raw text of every Content-Length line, in header order
    // (Go readMIMEHeader trims each stored value; fixLength compares the
    // trimmed texts byte-for-byte).
    let mut values: Vec<&str> = Vec::new();
    for line in headers {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        // trim_matches of ASCII space/tab only (round-3 review, audit
        // round 8): textproto.isASCIISpace has no \x0b/\x0c, and Go rejects
        // control bytes in values while reading the head — accepting a
        // \x0b-wrapped "5" here would be accept-where-Go-rejects.
        values.push(value.trim_matches(|c| c == ' ' || c == '\t'));
    }
    match values.len() {
        0 => Ok(None),
        1 => parse_content_length_value(values[0]),
        _ => {
            // Multiple Content-Length lines: Go fixLength accepts them only
            // when every trimmed raw text is byte-identical (RFC 7230
            // §3.3.2) — any difference invalidates the framing, including
            // one that parses to the same number ("05" vs "5").
            if values.iter().any(|v| *v != values[0]) {
                return Err("conflicting Content-Length headers".into());
            }
            parse_content_length_value(values[0])
        }
    }
}

/// One Content-Length value under Go `parseContentLength` semantics
/// (transfer.go): empty → error; otherwise `strconv.ParseUint(value, 10,
/// 63)` — unsigned decimal digits only, no sign, no commas, no whitespace,
/// capped at 2^63-1. `usize` truncation past 64-bit would already have
/// failed the 63-bit cap on every supported target.
fn parse_content_length_value(value: &str) -> Result<Option<usize>, String> {
    if value.is_empty() {
        return Err("invalid empty Content-Length".into());
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad Content-Length".into());
    }
    let n: u64 = value
        .parse()
        .map_err(|_| "bad Content-Length".to_string())?;
    if n > i64::MAX as u64 {
        return Err("bad Content-Length".into());
    }
    Ok(Some(n as usize))
}

/// Go `ParseHTTPVersion` (net/http/request.go, go1.25) restricted to
/// major 1. ParseHTTPVersion is NOT an exact-match switch: HTTP/1.0 and
/// HTTP/1.1 short-circuit, but every other version parses when it is
/// exactly 8 chars "HTTP/X.Y" with single ASCII digits (HTTP/1.2 ..
/// HTTP/9.9 all parse — verified against the go1.25.0 stdlib). The major-1
/// restriction mirrors where the frpc plugins sit in the stack: the frps
/// vhost front 505s every request whose version token is not HTTP/1.x (Go
/// conn.readRequest's http1ServerSupportsRequest), and Go's plugin arms
/// serve/tunnel every parseable 1.x (non-CONNECT: `ProtoMajor == 1` passes
/// the supports-request gate; CONNECT: `http.ReadRequest` accepts the token
/// and the tunnel ignores the minor). Rejecting HTTP/1.2..1.9 closed conns
/// that Go forwards; malformed shapes and major != 1 tokens still reject.
/// (Moved here from plugin/http.rs when the request-line parser became
/// shared — audit round: strict request-line parse across the h1 plugins.)
pub(super) fn go_parse_http_version_ok(version: &str) -> bool {
    match version {
        "HTTP/1.0" | "HTTP/1.1" => true,
        _ => {
            let b = version.as_bytes();
            b.len() == 8
                && b.starts_with(b"HTTP/")
                && b[5] == b'1'
                && b[6] == b'.'
                && b[7].is_ascii_digit()
        }
    }
}

/// Go conn.readRequest `validMethod` gate (net/http/request.go, go1.25):
/// the method token must be non-empty and made of RFC 7230 tchar bytes
/// only — alphanumerics plus `!#$%&'*+-.^_`|~`. No case rule: lowercase
/// "get" is a legal token here (gorilla mux's `Method("GET")` mismatch 405s
/// it later in Go, at the router). Applied after the line parse, matching
/// Go's order — readRequest parses the request line, then rejects a
/// non-tchar method with a badRequestError (http.Server renders 400)
/// BEFORE routing, so a "G@T" request never reaches the handler.
pub(super) fn go_valid_method_ok(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Strict HTTP request-line parse shared by every HTTP/1.1 plugin inbound
/// path. Go net/http parseRequestLine splits on literal SPACE only (two
/// `Cut(line, " ")`), so every other whitespace run — a tab-separated
/// "GET\tURL\tHTTP/1.1" in particular — never yields the required second
/// space and the whole line is malformed (ReadRequest error). Returns
/// (method, request-target, version) when the line has exactly three
/// non-empty space-separated parts, the method token passes Go's
/// [`go_valid_method_ok`] gate (readRequest rejects non-tchar methods with
/// a 400 before routing), the request-target's PRE-'?' portion carries no
/// invalid %-escape (audit round-16 FIX 13 + post-fix round: Go url.Parse
/// errors "invalid URL escape" — net/url unescape — inside ReadRequest,
/// before any routing/auth; probe vs go1.25.12 http.Server: /x%zz, /x%
/// and /x%2 in the PATH all answer 400. The check stops at the first '?':
/// url.Parse cuts the query RAW and never unescape-validates it, so
/// query-only escapes like ?q=%zz serve — see [`target_has_invalid_escape`].
/// Review round: a CONNECT authority-form target is additionally
/// host-mode-gated — a well-formed escape decoding to an ASCII byte is
/// an error there unless it is the literal "%25" — see
/// [`request_target_has_invalid_escape`]), and the
/// version token passes [`go_parse_http_version_ok`] (request-side Go
/// ParseHTTPVersion semantics). The old split_whitespace collapsed every
/// whitespace run, so tab-joined tokens parsed and multi-space request
/// lines were forwarded — accept-where-Go-rejects.
pub(super) fn parse_request_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if target.is_empty()
        || request_target_has_invalid_escape(method, target)
        || !go_parse_http_version_ok(version)
        || !go_valid_method_ok(method)
    {
        return None;
    }
    Some((method, target, version))
}

/// Mode-aware %-escape gate over a request-target (shared by
/// [`parse_request_line`] and the http.rs h1 conn classifier). Go parses
/// request targets with url.ParseRequestURI (net/url/url.go parse,
/// viaRequest=true) before routing. The CTL sweep happens FIRST over the
/// WHOLE raw target (`for i := range rawURL`: any byte < 0x20 or == 0x7f
/// errors "invalid control character in URL" — url.go parse, round-17
/// audit finding A — a query carrying a CTL byte errors the whole target
/// even though a query carrying an invalid escape is kept raw and
/// served); only then comes the '?' query cut
/// (`rest, RawQuery = strings.Cut(rest, "?")` — the query is kept RAW and
/// never unescape-validated). An authority-form target — "CONNECT
/// host[:port]" lines, which Go's readRequest justAuthority rewrites to
/// "http://" + target (request.go): the fixed scheme makes the authority
/// run from the target's start to its FIRST '/', and the remainder (from
/// that '/' on) is the path — is split into a host region
/// (parseHost → unescape in encodeHost mode) and a path region (setPath
/// → path mode). Non-CONNECT targets — origin-form "/x" and
/// absolute-form "http://h/x" — are pure paths and stay in path mode
/// throughout (the absolute-form HOST is a documented divergence: Go
/// host-modes it too — probe vs go1.25 http.Server: GET
/// http://h%41st/x answers 400 — but the fix-list scope for the host
/// gate is the CONNECT authority; see target_has_invalid_escape).
pub(super) fn request_target_has_invalid_escape(method: &str, target: &str) -> bool {
    // Round-17 audit finding A: the CTL sweep covers the WHOLE raw target
    // — query included — before the '?' cut (Go url.go parse, go1.25:
    // `if c := rawURL[i]; c < 0x20 || c == 0x7f`).
    if target.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return true;
    }
    let pre = target.split_once('?').map_or(target, |(p, _q)| p);
    if method == "CONNECT" && !pre.starts_with('/') {
        // justAuthority applies only to non-'/'-prefixed CONNECT targets;
        // "CONNECT //x/y" is path-form in Go (HasPrefix check fails).
        match pre.find('/') {
            // Authority region: host-mode. Path region (the '/' and
            // everything after): path-mode (setPath over the remainder).
            Some(fs) => {
                authority_has_invalid_escape(&pre[..fs]) || target_has_invalid_escape(&pre[fs..])
            }
            None => authority_has_invalid_escape(pre),
        }
    } else {
        target_has_invalid_escape(pre)
    }
}

/// Whether a CONNECT authority region fails Go's net/url authority
/// validation (url.go parseAuthority / parseHost / validOptionalPort /
/// validUserinfo, go1.25 — verified against the stdlib source; round-17
/// audit finding C). The region splits happen on the RAW bytes exactly
/// where Go cuts them:
///
///   - userinfo — up to the LAST literal '@' (parseAuthority
///     `LastIndex(authority, "@")`): every byte must be in Go's
///     validUserinfo set (unreserved + sub-delims + ':' + '%' + '@' — an
///     inner '@' is legal because the split takes the last one), and
///     every '%' must begin a well-formed two-hex-digit escape: the
///     unescape then runs in encodeUserPassword mode, which accepts ANY
///     well-formed escape (no host-mode ASCII rejection). The old
///     whole-string host-mode scan rejected "user%41@host", which Go
///     serves (userinfo is not the host).
///
///   - host region — encodeHost-mode escape gate: a well-formed escape
///     decoding to an ASCII byte (first hex digit < 8) is an error
///     unless it is the literal "%25" (case-invariant — 2 and 5 are
///     digits); a malformed escape is an error. Raw ASCII bytes are
///     swept with the same charset rule as the decoded escapes (Go's
///     unescape default arm: `s[i] < 0x80 && shouldEscape(s[i],
///     encodeHost)` → InvalidHostError — a raw '^', '|', DEL or any
///     other byte outside the host-legal set rejects in ReadRequest
///     before the dial; see [`should_escape_encode_host`]). Raw
///     obs-text (>= 0x80) is legal in the host region, exactly like Go
///     (the < 0x80 gate).
///
///   - port region — Go validOptionalPort over the RAW text: bracketed
///     hosts split after the last ']', unbracketed hosts at the LAST ':'
///     (the colon is included in the checked text); the port must be
///     empty or ':' followed only by ASCII digits. A '%' in the port
///     fails this raw-digit gate even when it would parse as a legal
///     escape ("h:8%C3%A9" escapes a host-mode escape scan but not this
///     gate — Go rejects it in ReadRequest, silent close on the CONNECT
///     arm, while the old code dialed and rendered 400).
///
///   - bracketed hosts additionally get Go's RFC 6874 zone split: when
///     the inside-brackets text contains "%25", the region from the
///     FIRST "%25" to the ']' is checked in encodeZone mode — an escape
///     there is legal when it decodes to a space or to a byte that would
///     not need escaping in encodeHost mode ("%41" inside a zone passes)
///     — and the rest of the string in encodeHost mode.
fn authority_has_invalid_escape(authority: &str) -> bool {
    let bytes = authority.as_bytes();
    // Userinfo: split at the LAST literal '@' (Go parseAuthority).
    let hostport = match authority.rfind('@') {
        Some(at) => {
            if !valid_userinfo_bytes(&bytes[..at]) || !escape_well_formed(&bytes[..at]) {
                return true;
            }
            &bytes[at + 1..]
        }
        None => bytes,
    };
    if hostport.first() == Some(&b'[') {
        // Bracketed host: Go parseHost splits after the LAST ']' and
        // validOptionalPort-checks the raw text after it; a missing ']'
        // is an error.
        let Some(close) = hostport.iter().rposition(|&c| c == b']') else {
            return true;
        };
        if !valid_optional_port(&hostport[close + 1..]) {
            return true;
        }
        // RFC 6874 zone split at the FIRST "%25" inside the brackets.
        match hostport[..close].windows(3).position(|w| w == b"%25") {
            Some(zone) => {
                encode_host_escape_invalid(&hostport[..zone])
                    || encode_zone_escape_invalid(&hostport[zone..close])
                    || encode_host_escape_invalid(&hostport[close..])
            }
            None => encode_host_escape_invalid(hostport),
        }
    } else {
        // Unbracketed: the port region is everything from the LAST ':'
        // (colon included); no colon means the whole text is the host
        // region. validOptionalPort ran on the RAW text, then the escape
        // gate covers the whole string (the port cannot carry a '%' past
        // the raw-digit gate, so region vs whole-string is identical).
        if let Some(i) = hostport.iter().rposition(|&c| c == b':') {
            if !valid_optional_port(&hostport[i..]) {
                return true;
            }
        }
        encode_host_escape_invalid(hostport)
    }
}

/// Go validUserinfo charset (url.go): unreserved + sub-delims + ':' +
/// '%' + '@' — an inner '@' is legal (the split takes the LAST '@', and
/// validUserinfo itself permits more '@'s — issue 3439/22655).
fn valid_userinfo_bytes(s: &[u8]) -> bool {
    s.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'%'
                    | b'@'
            )
    })
}

/// Every '%' begins a valid two-hex-digit escape (the only escape shape
/// any unescape mode accepts).
fn escape_well_formed(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if i + 2 >= s.len() || hex_val(s[i + 1]).is_none() || hex_val(s[i + 2]).is_none() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// Go validOptionalPort (url.go): the port text is legal when empty or
/// when it starts with ':' followed only by ASCII digits. The text is
/// RAW — a '%' or any non-digit fails even when it would parse as a
/// legal escape (round-17 audit finding C).
fn valid_optional_port(port: &[u8]) -> bool {
    if port.is_empty() {
        return true;
    }
    if port[0] != b':' {
        return false;
    }
    port[1..].iter().all(|b| b.is_ascii_digit())
}

/// encodeHost-mode escape gate over a host-region slice: a well-formed
/// escape is an error when it decodes to an ASCII byte (first hex digit
/// < 8) unless it is the literal "%25" (RFC 6874 zone exemption —
/// case-invariant, since 2 and 5 are digits); a malformed escape is an
/// error. Raw ASCII bytes are swept with the same charset rule (the
/// `s[i] < 0x80 && shouldEscape(s[i], encodeHost)` default arm of Go's
/// unescape — audit round-17 finding F6: a raw '^' in a CONNECT
/// authority previously passed the gate and rendered a dial 400 where
/// Go rejects the head in ReadRequest, silent close on the http_proxy
/// CONNECT arm). Mirrors Go unescape's encodeHost arms (url.go).
fn encode_host_escape_invalid(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if i + 2 >= s.len() || hex_val(s[i + 1]).is_none() || hex_val(s[i + 2]).is_none() {
                return true;
            }
            let first_hex = hex_val(s[i + 1]).unwrap();
            if first_hex < 8 && s[i..i + 3] != *b"%25" {
                return true;
            }
            i += 3;
        } else {
            // Go's default arm: only sub-0x80 bytes are swept; raw
            // obs-text is legal in the host region.
            if s[i] < 0x80 && should_escape_encode_host(s[i]) {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// encodeZone-mode escape gate (Go unescape's encodeZone arm, url.go —
/// the RFC 6874 zone part of a bracketed host): a malformed escape is an
/// error; a well-formed one is an error only when it is not the literal
/// "%25" and its decoded byte is not a space and would need escaping in
/// encodeHost mode ("%41" inside a zone is legal — redundant escaping of
/// a host-legal byte; "%2D" is legal too — '-', '_', '.' and '~' are
/// exempt from shouldEscape under the unreserved-marks switch, so their
/// redundant escapes decode to host-legal bytes — probe: CONNECT
/// [fe80::1%25en%2D0]:80 parses in go1.25). Raw ASCII bytes are swept
/// like the host region (Go's default arm gates both encodeHost and
/// encodeZone modes).
fn encode_zone_escape_invalid(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if i + 2 >= s.len() || hex_val(s[i + 1]).is_none() || hex_val(s[i + 2]).is_none() {
                return true;
            }
            let v = hex_val(s[i + 1]).unwrap() * 16 + hex_val(s[i + 2]).unwrap();
            if s[i..i + 3] != *b"%25" && v != b' ' && should_escape_encode_host(v) {
                return true;
            }
            i += 3;
        } else {
            if s[i] < 0x80 && should_escape_encode_host(s[i]) {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// Go shouldEscape(c, encodeHost|encodeZone) (net/url/url.go, go1.25):
/// alphanumerics never escape; the host/zone-mode switch exempts the
/// sub-delims plus ':', '[', ']', '<', '>', '"'; the UNCONDITIONAL
/// second switch (reserved-character switch §2.3 "mark" — runs for
/// host/zone modes too) exempts the unreserved marks '-', '_', '.', '~'
/// (audit round-17 finding F5: the pre-fix set lacked the four marks, so
/// a raw '~' or a zone escape like "%2D" was rejected where Go accepts
/// it). Every other byte needs escaping.
fn should_escape_encode_host(c: u8) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    !matches!(
        c,
        b'-' | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'"'
    )
}

/// Whether the pre-'?' portion of a request-target contains a '%' that
/// does not begin a valid two-hex-digit escape (PATH mode — the mode
/// for every region that is not a CONNECT authority, see
/// [`request_target_has_invalid_escape`]). Go url.Parse splits the
/// target at the FIRST '?' BEFORE any unescape validation — `rest,
/// RawQuery = Cut(rest, "?")` (net/url/url.go parse) — and the query is
/// kept RAW: nothing downstream ever unescape-decodes it server-side, so
/// an invalid escape in the query is never an error (probe vs go1.25.12
/// http.Server: /x?q=%zz, /x?q=%2 and /x?q=%zz%2 all answer 200 while
/// /x%zz?q=1 answers 400). Only the pre-'?' portion is unescape-validated
/// (as path via setPath/encodePath, or as authority/host via
/// parseHost/encodeHost). '#' is NOT a fragment separator in request URIs
/// (url.ParseRequestURI never splits on it — http.Request has no fragment
/// concept), so an escape after a '#' is still path-validated and errors
/// like any other path escape. Go rejects the whole target on such an
/// escape ("invalid URL escape", net/url/url.go unescape) before the
/// request is routed, so the http.Server error switch answers the generic
/// 400 — every plugin caller maps a parse failure onto its established
/// malformed-request render (400 on the plain HTTP faces, silent close on
/// the http_proxy CONNECT arm — the Go http_proxy.go Handle path closes
/// on any ReadRequest error). Note the round-13-era comment claiming Go's
/// path decoder is "lax" about invalid escapes was wrong: the laxness
/// concerns escape DECODING (encodePath mode keeps '+' literal and valid
/// escapes byte-clean) — an invalid escape never reaches the decoder,
/// url.Parse has already rejected the target. (Post-fix round: the scan
/// covers only the pre-'?' slice — the round-16 wave scanned the WHOLE
/// target and rejected query-only escapes like ?q=%zz that Go serves.
/// Review round: path-mode still applies to the whole pre-'?' slice of
/// CONNECT targets whose FIRST '/' begins the path region, so "%41" in
/// an origin-form path and in an absolute-form host both stay accepted
/// — the host-mode gate above covers only the CONNECT authority.)
fn target_has_invalid_escape(target: &str) -> bool {
    let path = target.split_once('?').map_or(target, |(p, _q)| p);
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || hex_val(b[i + 1]).is_none() || hex_val(b[i + 2]).is_none() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// Read an HTTP request head from `stream` (chunked until the first empty
/// line — Go textproto semantics, LF-only and mixed-EOL heads legal — with
/// the 64 KiB cap), parse the request line, and build the forwarded HTTP/1.1
/// request head with
/// optional Host rewrite and injected request headers. Shared by the
/// http2http/http2https/https2http/https2https plugins; each then connects its
/// own backend, writes the returned head, and streams the request body with
/// [`forward_request_body`].
///
/// `request_headers` are injected via Set semantics (Go `req.Header.Set`:
/// an existing header with the same name is replaced), matching Go
/// `pkg/plugin/client/http_common.go rewriteHTTPPluginRequest`.
///
/// `x_forwarded_for` is the peer address to append as `X-Forwarded-For`
/// (Go `httputil.ReverseProxy`'s `SetXForwarded`: the inbound chain is
/// preserved and the peer appended — `https2http`/`https2https` pass the
/// connection peer; `http2http`/`http2https` pass `None`, matching Go,
/// which does not set X-Forwarded-For there).
///
/// Only the head is read here. Body bytes that happen to arrive in the same
/// TCP read as the head are returned in [`ForwardedRequest::body_prefix`] so
/// nothing is lost — Go's http.Server streams request bodies, and discarding
/// pre-read bytes made backends hang forever on POST/PUT.
pub(super) async fn read_request_and_build_forward<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    stream: &mut S,
    host_rewrite: &str,
    request_headers: &std::collections::HashMap<String, String>,
    x_forwarded_for: Option<std::net::IpAddr>,
) -> Result<ForwardedRequest, String> {
    // Read the request head in chunks. Head end follows Go textproto
    // semantics (the engine behind http.ReadRequest): each line ends at the
    // next '\n' with ONE trailing '\r' stripped, and the first empty line
    // ends the head — so LF-only and mixed-EOL heads are legal, not just
    // \r\n\r\n. Stop at the first empty line anywhere in the buffer (not
    // only at its end): with a request body the head terminator is followed
    // by body bytes, and reading past it would swallow the body into the
    // "headers" until the 64 KiB cap.
    // Read the whole head under ONE absolute deadline armed at the first
    // read attempt (audit round-8 F8). A per-read deadline re-arms on
    // every byte, so a peer dripping 1 B/59 s could hold the handler task
    // + fd forever without ever parking on a single read. The single
    // window bounds the ENTIRE head — mirrors Go http.Server's
    // ReadHeaderTimeout (60 s inside Go frp's http_proxy plugin,
    // plugin/http.rs), which a fresh byte does not extend. Body reads
    // downstream stay unbounded (Go parity: a body may stream for the
    // life of the connection).
    let buf = tokio::time::timeout(PLUGIN_HEADER_READ_TIMEOUT, async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        // Round-17 audit D: the carried scanner replaces the per-chunk
        // full-buffer `head_end` rescan (O(n²) over the chunks of one
        // head) with a resume-from-line-start scan; byte-identical
        // results for this feed-until-terminator loop.
        let mut scanner = frp_core::textproto::HeadEndScanner::new();
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed".into());
            }
            buf.extend_from_slice(&chunk[..n]);
            if scanner.feed(&buf).is_some() {
                break;
            }
            // Deliberate divergence from the Go http.Server faces of the
            // sibling plugins (http.rs / static_file.rs aligned Go's
            // readLimit = 1 MiB + 4096 slack this round): these four
            // http2http/https2http-family listeners bind the operator's
            // OWN 127.0.0.1 port and see only local traffic, so the h2.rs
            // 16 MiB precedent applies — a Go-legal head in the
            // (64 KiB, ~1 MiB] band fails here instead of serving. The
            // terminator-first ordering above IS shared with Go: only an
            // unterminated head breaches the cap, never a terminated one.
            if buf.len() > 65536 {
                return Err("request headers too large".into());
            }
        }
        Ok::<Vec<u8>, String>(buf)
    })
    .await
    .map_err(|_elapsed| "timed out reading request headers".to_string())??;

    // Split the head from any pre-read body bytes at the first empty line
    // (Go textproto semantics — the same rule the read loop above applied
    // through the scanner, so the split lands exactly where the loop
    // stopped; for CRLF input the index is byte-identical to the old
    // \r\n\r\n scan).
    let header_end = frp_core::textproto::head_end(&buf).unwrap_or(buf.len());
    let headers_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = headers_str.lines().peekable();

    // Parse request line: METHOD URL HTTP/1.x — strict Go parseRequestLine
    // semantics via the shared helper (literal-space splitn(3), every part
    // non-empty, version token a parseable request-side HTTP/1.x). A
    // malformed line fails the read here — this arm's failure handling
    // (silent close) is unchanged: Go's http.Server face renders a 400
    // (GO_400_RENDER, see plugin/http.rs) before closing; the bare close
    // is the acknowledged divergence for this operator-local listener
    // class, same rationale as the 64 KiB cap above.
    let request_line = lines.next().ok_or("empty request")?;
    // Round-17 audit F7: parse_request_line's gate admits only HTTP/1.x
    // version tokens, but a token Go's ParseHTTPVersion parses with ANY
    // single-digit major (HTTP/2.0, HTTP/0.9, HTTP/9.9 — request.go
    // lenient 8-char shape) is not a malformed line here: such a head may
    // clear every read gate below and then answer Go's detailed 505 render,
    // or — the h2c-preface "PRI * HTTP/2.0" — be SERVED through the version
    // gate. Re-run the same line-shape checks minus the 1.x restriction so
    // the classification sees those tokens; every other failure stays on
    // the bare-close Err arm (acknowledged divergence for this
    // operator-local listener class, see the doc at parse_request_line).
    let (method, path, version) = match parse_request_line(request_line) {
        Some(ok) => ok,
        None => {
            let mut parts = request_line.splitn(3, ' ');
            let (m, t, v) = (parts.next(), parts.next(), parts.next());
            match (m, t, v) {
                (Some(m), Some(t), Some(v))
                    if !t.is_empty()
                        && !request_target_has_invalid_escape(m, t)
                        && go_valid_method_ok(m)
                        && http::parseable_version(v).is_some_and(|(maj, _)| maj != 1) =>
                {
                    (m, t, v)
                }
                _ => return Err(format!("bad request line: {request_line}")),
            }
        }
    };
    // Every head that reaches the gates below has a ParseHTTPVersion-able
    // token (both admission paths above guarantee it), so the re-parse can
    // only fail on invariant drift. Round-18 audit L4: the old `expect`
    // was an abort under `panic=abort` on that drift; a guarded arm now
    // falls to the same bare-close Err the lenient path takes for an
    // unparseable version — no behavior change for any reachable head.
    let Some((v_maj, v_min)) = http::parseable_version(version) else {
        return Err(format!("bad request line: {request_line}"));
    };

    // Round-17 audit F7: the Go conn.readRequest ladder (server.go
    // c.readRequest + package readRequest, go1.25.12) — walk the terminated
    // header block in textproto readMIMEHeader shape FIRST. Any read-time
    // shape error is a ProtocolError-ish failure whose render Go's
    // http.Server face answers with the no-detail 400 (GO_400_RENDER).
    let walk = match walk_leg_head(&headers_str) {
        Ok(w) => w,
        Err(why) => return reject_head(stream, GO_400_RENDER, why).await,
    };
    // dup-Host fires INSIDE package readRequest, before readTransfer
    // (request.go: two canonical-Host records — "too many Host headers"):
    // a plain error, hence the no-detail render. (Read-time walk errors
    // likewise precede the TE/CL gates below, matching Go's order.)
    if walk.host_groups > 1 {
        return reject_head(stream, GO_400_RENDER, "too many Host headers").await;
    }

    // Round-17 audit E: Go readTransfer gates the whole Transfer-Encoding
    // read on protoAtLeast(1, 1) (transfer.go, Issue 12785) — an
    // HTTP/1.0 request IGNORES its Transfer-Encoding (the header is
    // dropped silently, never chunked-framed). The TE group must be
    // exactly one header line whose value is EqualFold-"chunked" — a
    // different count ("too many transfer-encoding values") or a
    // different value ("unsupported transfer encoding") is a readRequest
    // error: 501 on the Go http.Server faces of the sibling plugins, the
    // established Err-to-bare-close policy of this operator-local
    // listener class here (deliberate divergence, unchanged by F7). The
    // old code forwarded such heads (the TE line was stripped hop-by-hop
    // and the body CL-framed) where Go rejects. F7 widened the gate to
    // the parsed (major, minor) pair: parseable non-1.x heads (HTTP/2.0
    // class) also clear readTransfer before the 505 gate below.
    let te_checked = (v_maj, v_min) >= (1, 1);
    if te_checked && !transfer_encoding_group_ok(lines.clone()) {
        return Err("unsupported transfer encoding".into());
    }

    // Body framing is parsed from the original headers — Transfer-Encoding
    // is stripped below as hop-by-hop and re-added only when the request is
    // chunked (the forwarded body bytes keep the client's own framing).
    // The protoAtLeast(1,1) gate above carries into the framing: an
    // HTTP/1.0 head (whose TE was ignored, not rejected) resolves
    // Content-Length alone.
    let framing = if te_checked {
        parse_request_body_framing(lines.clone())
    } else {
        resolve_content_length(lines.clone())
            .ok()
            .flatten()
            .map(BodyFraming::Length)
    };
    // Content-Length is resolved per RFC 7230 §3.3.2 ("reject or replace
    // with a single value") under Go fixLength/parseContentLength
    // semantics: duplicate identical values collapse to one line, while
    // list-form values ("5, 5"), non-decimal values, and conflicting
    // values make the request framing invalid — reject (the connection
    // closes, matching the other parser failures; no 400 is sent).
    // Resolution runs UNCONDITIONALLY, chunked requests included: Go
    // probes the CL values even when chunked wins the framing — probed
    // against the Go frp v0.71.0-era stdlib (go1.25.12): chunked + "5, 5",
    // chunked + "5x", and chunked + conflicting values all 400, while a
    // chunked + valid "5" is accepted and the header deleted. The retain
    // gate below drops every Content-Length line on chunked requests and
    // the canonical-line append keys on `framing != Chunked`, so a valid
    // resolution is never forwarded under chunked — matching Go's delete.
    let content_length = resolve_content_length(lines.clone())?;

    // Round-17 audit F7: the Go conn.readRequest tail (server.go
    // c.readRequest — runs AFTER package readRequest cleared the
    // line/MIME/dup/transfer gates above): the http1ServerSupportsRequest
    // 505 gate first, then the conn gates. These heads are NOT malformed —
    // they are complete, well-shaped requests whose version or Host shape
    // Go's http.Server face answers with a DETAILED render; unlike the
    // bare-close Err arms above, each writes Go's own byte-exact response
    // before the caller's Err handling closes the connection.
    let is_pri_upgrade = method == "PRI" && path == "*" && (v_maj, v_min) == (2, 0);
    if v_maj != 1 && !is_pri_upgrade {
        // http1ServerSupportsRequest false: statusError{505} — the
        // detailed 193B render (probe-verified, plugin/http.rs GO_505).
        return reject_head(stream, http::GO_505_RENDER, "unsupported protocol version").await;
    }
    // isH2Upgrade (request.go:529-531): PRI + "*" + HTTP/2.0 AND a
    // zero-header map. Only the missing-Host gate exempts it; the
    // malformed-Host and invalid-name gates below it have no exemption.
    let h2_upgrade_zero_headers = is_pri_upgrade && walk.header_groups == 0;
    if (v_maj, v_min) >= (1, 1)
        && walk.host_groups == 0
        && !h2_upgrade_zero_headers
        && method != "CONNECT"
    {
        // missing-Host badRequestError: detailed 163B render.
        return reject_head(
            stream,
            GO_400_MISSING_HOST_RENDER,
            "missing required Host header",
        )
        .await;
    }
    if walk.host_groups == 1 && !http::valid_host_header(walk.host_value.as_deref().unwrap_or("")) {
        // malformed-Host badRequestError (no version gate in Go): detailed
        // 149B render.
        return reject_head(
            stream,
            GO_400_MALFORMED_HOST_RENDER,
            "malformed Host header",
        )
        .await;
    }
    if walk.name_has_space {
        // invalid-header-name badRequestError (issue 34540: a SPACE is the
        // one bad key byte textproto lets through uncanonicalized):
        // detailed 145B render.
        return reject_head(
            stream,
            GO_400_INVALID_HEADER_NAME_RENDER,
            "invalid header name",
        )
        .await;
    }
    // Go also runs an invalid-header-VALUE gate here — it is UNREACHABLE:
    // textproto kills every CTL value byte at read time, so such a head
    // already answered the generic GO_400_RENDER above (probe-verified
    // against go1.25.12; the F7 value gate therefore has no detailed arm,
    // deviation reported to the round-17 audit).

    // Build forwarded request with optional Host rewrite.
    // Strip hop-by-hop headers per RFC 2616 Section 13.5.1 (matches Go's
    // removeProxyHeaders / ReverseProxy hopHeaders: Connection,
    // Proxy-Connection, Keep-Alive, Proxy-Authorization, Proxy-Authenticate,
    // TE, Trailer(s), Transfer-Encoding, Upgrade). Expect is stripped too:
    // the plugin cannot relay the interim 100-continue response, and a
    // strict client that gates its body-send on it would deadlock against
    // the body read (RFC 7231 §5.1.1: without the header the client sends
    // the body at once).
    let hop_by_hop: &[&str] = &[
        "transfer-encoding:",
        "proxy-authorization:",
        "proxy-connection:",
        "proxy-authenticate:",
        "te:",
        "trailer:",
        "upgrade:",
        "connection:",
        "keep-alive:",
        "expect:",
    ];
    // A configured X-Forwarded-For replaces the chain (Go Header.Set runs
    // after SetXForwarded) — computed before the loop because both the
    // replace-mode and the peer-append mode must suppress the inbound line
    // (R5: pre-fix the no-peer plugins emitted the configured value twice,
    // once in the request_headers loop and once below, plus the inbound
    // line).
    let configured_xff = request_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, v)| v.clone());
    // Inbound X-Forwarded-For chain, preserved by the https plugins (Go
    // SetXForwarded appends the peer to the existing chain).
    let mut prior_xff: Vec<String> = Vec::new();
    // The outbound request line speaks HTTP/1.1 — Go's
    // http.DefaultTransport (the ReverseProxy backend of http2http/
    // http2https/https2http/https2https, http2http.go:34-44) never writes
    // HTTP/1.0 requests. Chunked bodies are the canary: chunked
    // Transfer-Encoding is HTTP/1.1-only, so under the old HTTP/1.0
    // request line an origin saw neither TE nor CL and silently dropped
    // the upload body (audit round-9 B1, twin of the http.rs fix). The
    // `Connection: close` terminator below is kept: each tunnel conn
    // serves one request and closes after the response (Go sends close
    // whenever the connection closes after the response).
    let mut fwd = format!("{method} {path} HTTP/1.1\r\n");
    // Round-18 audit L2: Go textproto folds obs-continuation lines
    // (leading SP/HTAB) into the PRECEDING record's value (reader.go
    // readContinuedLineSlice); this raw per-line re-emission must therefore
    // route each fold by the previous line's disposition. A fold whose
    // record was dropped or replaced above would otherwise be emitted as a
    // bare line and obs-fold onto the preceding EMITTED record at the
    // backend — worst case appended to the "Host:" line, which sits
    // directly below the stripped hop headers in the canonical head shape.
    // Folds of KEPT records stay raw and contiguous with their head line
    // (byte-preserving round trip) and skip the record-head arms below (a
    // folded value piece may contain a colon — the request_headers
    // override arm must not misread it as its own record).
    let mut prev_record_dropped = false;
    while let Some(line) = lines.next() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if prev_record_dropped {
                // The fold belongs to a dropped/replaced record — swallow
                // it (and any following folds; the flag stays set until a
                // fresh record head arrives).
                continue;
            }
            if line.contains(['\r', '\n']) {
                let safe_line: String = line.chars().filter(|&c| c != '\r' && c != '\n').collect();
                fwd.push_str(&safe_line);
            } else {
                fwd.push_str(line);
            }
            fwd.push_str("\r\n");
            continue;
        }
        // A fresh record head — folds following it route by the disposition
        // this iteration sets.
        prev_record_dropped = false;
        // When appending the peer IP (https plugins) OR replacing the chain
        // with a configured value, the inbound X-Forwarded-For record is
        // collected here and re-emitted canonically after the loop — the
        // original line must not pass through as well, or the backend sees
        // two X-Forwarded-For headers.
        if (x_forwarded_for.is_some() || configured_xff.is_some())
            && starts_with_ignore_ascii_case(line, "x-forwarded-for:")
        {
            // Round-18 audit L3: the prior chain is Go's per-ROW stored
            // value joined by ", " (reverseproxy.go setXForwarded —
            // `strings.Join(prior, ", ")`; mirrored server-side by the
            // round-13 vhost injector), so an EMPTY-value row contributes
            // an empty element, never a dropped row: a sole empty row
            // emits ", {peer}", byte-identical to Go. Stored shape
            // reconstructed from the raw line — readMIMEHeader stores the
            // after-colon value of the OWS-trimmed first physical line,
            // TrimLeft'd once, with each obs-fold appended as ' ' + its
            // OWS-trimmed piece, unconditionally (an all-whitespace fold
            // included). The old ASCII `trim()` + non-empty gate dropped
            // empty rows and trimmed Unicode whitespace Go keeps.
            let mut value = line
                .split_once(':')
                .map(|(_, v)| v.trim_matches([' ', '\t']).to_string())
                .unwrap_or_default();
            // The record's folds are part of the row value — consume them
            // here so they neither leak as bare lines nor route to the
            // record-head arms below.
            while let Some(fold) = lines.next_if(|l| l.starts_with([' ', '\t'])) {
                value.push(' ');
                value.push_str(fold.trim_matches([' ', '\t']));
            }
            prior_xff.push(value);
            continue;
        }
        if hop_by_hop
            .iter()
            .any(|h| starts_with_ignore_ascii_case(line, h))
        {
            prev_record_dropped = true;
            continue;
        }
        // Drop every original Content-Length line: when the body is chunked
        // (RFC 7230 §3.3.3 — Go's http.Server deletes CL when
        // Transfer-Encoding is chunked, and forwarding the ambiguous pair
        // is request-smuggling shaped), or when a usable Content-Length was
        // resolved — all CL lines are then replaced by a single canonical
        // line appended after the loop (RFC 7230 §3.3.2; forwarding
        // duplicate/conflicting values would desync the backend).
        if starts_with_ignore_ascii_case(line, "content-length:")
            && (framing == Some(BodyFraming::Chunked) || content_length.is_some())
        {
            prev_record_dropped = true;
            continue;
        }
        // Skip headers that request_headers will override — Go Header.Set
        // replaces the WHOLE record, folded value included.
        if let Some((name, _)) = line.split_once(':') {
            if request_headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case(name.trim()))
            {
                prev_record_dropped = true;
                continue;
            }
        }
        if !host_rewrite.is_empty() && starts_with_ignore_ascii_case(line, "host:") {
            let safe_host: String = host_rewrite
                .chars()
                .filter(|&c| c != '\r' && c != '\n')
                .collect();
            fwd.push_str(&format!("Host: {safe_host}\r\n"));
            // The rewrite REPLACES the original record — its folds must
            // not obs-fold onto the rewritten line (Go never re-emits
            // them; req.Host is written from the rewrite alone).
            prev_record_dropped = true;
        } else {
            // Strip CR/LF from forwarded header lines: header injection /
            // request-smuggling defense (the h2 plugin path rejects CR/LF
            // outright — mirror that policy here for the HTTP/1.1 path).
            // `lines()` already strips the trailing CRLF, so a lone `\r` can
            // only be mid-line (malformed client) — the common path appends
            // the line slice directly, no per-line String (round-17 audit E).
            if line.contains(['\r', '\n']) {
                let safe_line: String = line.chars().filter(|&c| c != '\r' && c != '\n').collect();
                fwd.push_str(&safe_line);
            } else {
                fwd.push_str(line);
            }
            fwd.push_str("\r\n");
        }
    }
    // Inject configured request headers (Go rewriteHTTPPluginRequest).
    // "host" is skipped: Go's req.Header.Set cannot set Host — it is
    // controlled by hostHeaderRewrite (or the original request).
    // Names/values are sanitized against CR/LF like every other header.
    // X-Forwarded-For is skipped here whenever a canonical tail line will
    // be emitted (peer-append mode OR a configured value): it is emitted
    // canonically below — Go's Header.Set runs AFTER SetXForwarded, so a
    // configured value replaces the appended chain (emitting both would
    // give the backend two X-Forwarded-For lines).
    for (k, v) in request_headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        if (x_forwarded_for.is_some() || configured_xff.is_some())
            && k.eq_ignore_ascii_case("x-forwarded-for")
        {
            continue;
        }
        let safe_k: String = k.chars().filter(|&c| c != '\r' && c != '\n').collect();
        let safe_v: String = v.chars().filter(|&c| c != '\r' && c != '\n').collect();
        if safe_k.is_empty() {
            continue;
        }
        fwd.push_str(&format!("{safe_k}: {safe_v}\r\n"));
    }
    if let Some(cfg_xff) = configured_xff {
        fwd.push_str(&format!("X-Forwarded-For: {cfg_xff}\r\n"));
    } else if let Some(ip) = x_forwarded_for {
        if prior_xff.is_empty() {
            fwd.push_str(&format!("X-Forwarded-For: {ip}\r\n"));
        } else {
            fwd.push_str(&format!(
                "X-Forwarded-For: {}, {ip}\r\n",
                prior_xff.join(", ")
            ));
        }
    }
    if framing == Some(BodyFraming::Chunked) {
        fwd.push_str("Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = content_length {
        // Exactly one Content-Length line (RFC 7230 §3.3.2), matching the
        // byte count the body forward will stream.
        fwd.push_str(&format!("Content-Length: {n}\r\n"));
    }
    fwd.push_str("Connection: close\r\n\r\n");

    Ok(ForwardedRequest {
        head: fwd,
        body_prefix: buf[header_end..].to_vec(),
        body: framing,
        method: method.to_string(),
    })
}

/// Round-17 audit F7: write a Go render for a head the caller then rejects.
/// `read_request_and_build_forward` returns Err for the connection close;
/// the render itself must be flushed before the close, so every F7 gate
/// writes its byte-exact Go response through this helper and THEN returns
/// the Err (the four http2http-family legs treat any Err as a bare close —
/// the render is the only bytes the client sees, matching what Go's
/// http.Server face would have answered on the same head).
async fn reject_head<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    render: &str,
    why: &str,
) -> Result<ForwardedRequest, String> {
    let _ = stream.write_all(render.as_bytes()).await;
    Err(format!("{why}: rejected after writing Go render"))
}

/// Round-17 audit F7: header-block facts from the terminated head of the
/// four http2http-family plugin legs, computed in Go textproto
/// readMIMEHeader shape (reader.go) so the conn gates in
/// [`read_request_and_build_forward`] mirror server.go exactly.
#[derive(Debug, Default)]
struct LegHeadWalk {
    /// Header records (non-empty, non-continuation lines with a colon) —
    /// Go's header-map size, used by the isH2Upgrade zero-header test
    /// (request.go:529-531: the exemption applies only to a head with NO
    /// headers at all).
    header_groups: usize,
    /// Records whose key canonicalizes to "Host": an all-token key with
    /// no SPACE, case-insensitive. Go's dup-Host test is
    /// `len(req.Header["Host"]) > 1` — textproto merges duplicates into
    /// one canonical key, so two Host LINES are two entries but
    /// "Host" + "HOST" are two lines merged under one key too (request.go
    /// counts the merged slice, and merge happens at read: the key is
    /// lowercased for storage, so both land in the same slice — two
    /// records, one canonical key, dup-Host fires).
    host_groups: usize,
    /// Stored value of the FIRST Host record in Go stored-value shape:
    /// each physical line is SP/HTAB-trimmed at BOTH ends before the colon
    /// cut (readContinuedLineSlice `trim(line)`, reader.go), the stored
    /// value is TrimLeft'd once more after the cut, and continuation folds
    /// join with a single space.
    host_value: Option<String>,
    /// Any record key holding SPACE — issue 34540: of all the bytes that
    /// are not valid header-field bytes, only SPACE survives
    /// ReadMIMEHeader (every other bad key byte errors at read); Go's conn
    /// invalid-header-name gate is the sole catcher of the surviving
    /// noCanon key, and it answers the DETAILED 400.
    name_has_space: bool,
}

/// Round-17 audit F7: walk one terminated header block (request line
/// already consumed) in Go textproto readMIMEHeader shape. `Err(why)`
/// mirrors the read-time failures Go's conn.serve face answers with the
/// no-detail GO_400_RENDER: colonless records, empty or invalid key bytes
/// (CTL, HTAB, obs-text — SPACE is NOT an error, it sets
/// `name_has_space`), CTL bytes anywhere in a record value (HTAB legal),
/// and a leading-SP/HTAB first header line ("malformed MIME header initial
/// line"). Continuation folds (following lines starting with SP/HTAB) join
/// the current record's value with a single space after both-end trimming.
fn walk_leg_head<'a>(headers: &'a str) -> Result<LegHeadWalk, &'static str> {
    let mut walk = LegHeadWalk::default();
    let mut cur_is_host = false;
    let mut cur_value: Option<std::borrow::Cow<'a, str>> = None; // None = no record open
    let mut saw_record = false;
    for line in headers.lines().skip(1) {
        // The head terminator never produces a record (it is the empty
        // line the read loop stopped at). A space-only line is NOT a
        // terminator — it is an obs-fold continuation of the open record
        // and joins it below; only a zero-length line ends the block.
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            // readContinuedLineSlice continuation of the current record.
            // A fold before any record is the readMIMEHeader
            // initial-line error.
            if !saw_record {
                return Err("malformed MIME header initial line");
            }
            if let Some(v) = cur_value.as_mut() {
                // Go joins each continuation with an UNCONDITIONAL ' '
                // appended before the trimmed piece — even when the fold
                // line is all whitespace and trims to "" (reader.go:
                // "r.buf = append(r.buf, ' ')" then trim(line)). The
                // first physical line's trailing WS is trimmed, but
                // fold-created trailing WS is not: ReadMIMEHeader stores
                // TrimLeft(v), never a right trim — so "Host: b" + " "
                // folds to stored "b ", which httpguts ValidHostHeader
                // rejects (conn: 149B "malformed Host header").
                let piece = line.trim_matches([' ', '\t']);
                if value_has_ctl(piece) {
                    return Err("malformed MIME header: CTL byte in folded value");
                }
                // Round-18 audit L6: a fold-free record holds a Borrowed
                // slice of the head (zero alloc); to_mut upgrades to an
                // owned String only here, on the first fold (clones once,
                // later folds push in place).
                let v = v.to_mut();
                v.push(' ');
                v.push_str(piece);
            }
            continue;
        }
        // Close the previous record into the walk before opening the next.
        if let Some(v) = cur_value.take() {
            if cur_is_host {
                walk.host_groups += 1;
                if walk.host_value.is_none() {
                    // into_owned: the first Host record's fold-free
                    // Borrowed slice becomes the owned field value here —
                    // one alloc, the same as the pre-Cow String (a folded
                    // record's Owned moves out with no copy).
                    walk.host_value = Some(v.into_owned());
                }
            }
        }
        // ReadContinuedLineSlice trimmed each physical line at BOTH ends
        // before the colon cut; a trimmed-away line never reaches a
        // record.
        let trimmed = line.trim_matches([' ', '\t']);
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            return Err("malformed MIME header line: missing colon");
        };
        if key.is_empty() {
            // canonicalMIMEHeaderKey on an empty key errors.
            return Err("malformed MIME header line: empty key");
        }
        if key
            .bytes()
            .any(|b| b != b' ' && !header_field_name_byte_ok(b))
        {
            // canonicalMIMEHeaderKey: any invalid byte other than SPACE
            // (CTL, HTAB, obs-text, ...) errors the whole read.
            return Err("malformed MIME header line: invalid key byte");
        }
        if value_has_ctl(value) {
            // Go validates the value over the RAW post-colon bytes before
            // the TrimLeft storage — a leading CTL errors too.
            return Err("malformed MIME header line: CTL byte in value");
        }
        let stored = value.trim_start_matches([' ', '\t']);
        let key_has_space = key.contains(' ');
        let is_host = !key_has_space && key.eq_ignore_ascii_case("host");
        walk.header_groups += 1;
        walk.name_has_space |= key_has_space;
        cur_is_host = is_host;
        // Cow::Borrowed of the head slice — zero alloc for fold-free
        // records (upgraded at the first fold above, into_owned at the
        // closes below).
        cur_value = Some(std::borrow::Cow::Borrowed(stored));
        saw_record = true;
    }
    if let Some(v) = cur_value.take() {
        if cur_is_host {
            walk.host_groups += 1;
            if walk.host_value.is_none() {
                // Same into_owned as the mid-loop close above.
                walk.host_value = Some(v.into_owned());
            }
        }
    }
    Ok(walk)
}

/// textproto value CTL scan (validHeaderFieldByte): every byte below
/// SPACE except HTAB is illegal in a header value, plus DEL.
fn value_has_ctl(v: &str) -> bool {
    v.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// textproto validHeaderFieldByte for record KEYS (the token set of
/// RFC 7230 §3.2.6); SPACE is handled by the caller, not here.
fn header_field_name_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Max length of a chunk-size / trailer line in a chunked request body
/// (matches the 64 KiB request-head cap). Shared with the h2 plugin's
/// response-side chunked reader (plugin/h2.rs), which enforces the same
/// bound on chunk-size / trailer lines read from the backend.
pub(super) const CHUNK_LINE_MAX: usize = 64 * 1024;

/// Bound on the whole HTTP request-head read in the plugins (audit round-8
/// F8). The head must be read within ONE absolute window armed at the first
/// read — NOT re-armed per read: a per-read deadline lets a peer dripping
/// 1 B/59 s hold the handler task + fd forever without ever parking on a
/// single read. Mirrors Go http.Server's ReadHeaderTimeout, which a fresh
/// byte does not extend. Request-body reads downstream are deliberately
/// unbounded (Go parity: a body may stream for the life of the connection).
pub(super) const PLUGIN_HEADER_READ_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Go http.Server generic error render — probe-captured byte-exact from
/// go1.25.12 (net/http server.go: the fixed errorHeaders CT text/plain +
/// Connection: close, status-text body, NO Content-Length, no trailing CRLF
/// after the body). Used where the plugins render what Go's http.Server
/// would for a malformed request head (audit: 400/431 arms).
pub(super) const GO_400_RENDER: &str = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request";
/// Go conn.serve `badRequestError` render for the missing-Host conn gate
/// (server.go — "missing required Host header"; wire shape probe-verified
/// against go1.25.12, 163 bytes): a DETAILED statusError render (reason
/// echoed in the status line AND the body), same shape family as
/// [`GO_505_RENDER`] (round-17 audit F1: the conn gates fire after the
/// version gate on the plain http.Server face).
pub(super) const GO_400_MISSING_HOST_RENDER: &str =
    "HTTP/1.1 400 Bad Request: missing required Host header\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Connection: close\r\n\
    \r\n\
    400 Bad Request: missing required Host header";
/// Same shape family, for the malformed-Host conn gate (server.go
/// ValidHostHeader on the stored Host value; probe-verified, 149 bytes).
pub(super) const GO_400_MALFORMED_HOST_RENDER: &str =
    "HTTP/1.1 400 Bad Request: malformed Host header\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Connection: close\r\n\
    \r\n\
    400 Bad Request: malformed Host header";
/// Same shape family, for the invalid-header-name conn gate (issue 34540:
/// a header name containing SPACE survives the textproto read and fires
/// this detailed 400 at the conn; probe-verified, 145 bytes).
pub(super) const GO_400_INVALID_HEADER_NAME_RENDER: &str =
    "HTTP/1.1 400 Bad Request: invalid header name\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Connection: close\r\n\
    \r\n\
    400 Bad Request: invalid header name";
/// Same shape as [`GO_400_RENDER`], for request-header-block overflow (Go
/// MaxHeaderBytes breach).
pub(super) const GO_431_RENDER: &str = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large";
/// ReverseProxy-style 502 render for backend dial/TLS failures. NOT
/// byte-exact Go parity: go1.25's `httputil.ReverseProxy` defaultErrorHandler
/// (reverseproxy.go:319-322) only logs and calls `WriteHeader(502)` when no
/// ErrorHandler is set — net/http then adds a Date header on the wire and
/// KEEPS the client connection alive. frp-rs deliberately diverges: the bare
/// head below (no Content-Type, no body, no Date — every frp-rs manual
/// response writer omits Date by convention), followed by a close.
pub(super) const GO_502_RENDER: &str = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
/// Go `http.NotFound` render — probe-captured from go1.25.12 (CL-first
/// repo order, Date omitted by convention; body is exactly
/// "404 page not found\n").
pub(super) const GO_404_NOT_FOUND_RENDER: &str = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 19\r\nConnection: close\r\n\r\n404 page not found\n";

/// Write the ReverseProxy-style 502 render ([`GO_502_RENDER`]) to a peer,
/// then return `Err(e)` — the 502 is the final byte frp-rs writes before the
/// caller drops the connection. Deliberate divergence: Go's ReverseProxy
/// does NOT close — its defaultErrorHandler only WriteHeaders the 502 and
/// the client connection keep-alives on.
pub(super) async fn write_go_502<W>(peer: &mut W, err: String) -> Result<(), String>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    peer.write_all(GO_502_RENDER.as_bytes())
        .await
        .map_err(|e| format!("write 502: {e}"))?;
    Err(err)
}

/// Whether a raw head buffer starts with an ASCII-case-insensitive
/// "CONNECT" — mirrors Go http_proxy.go's arm split, which reads the FIRST
/// 7 stream bytes via `io.ReadFull` and `strings.EqualFold`s them against
/// "CONNECT" before any head parsing. Used to pick the CONNECT arm's
/// failure behavior (silent close) when the head parse itself failed, and to
/// classify a head read that breached the cap (http.rs; static_file.rs never
/// sees CONNECT — Go gorilla's method gate for the FileServer route is
/// GET-only).
pub(super) fn head_starts_connect(buf: &[u8]) -> bool {
    buf.len() >= 7 && buf[..7].eq_ignore_ascii_case(b"CONNECT")
}

/// Bound on a TLS listener handshake in the TLS-terminating plugins
/// (tls2raw/https2http/https2https; audit round-8 F6). A peer that sends a
/// partial ClientHello (rustls waits for the record body) must be released
/// — the accept cannot park the handler task + fd + plugin listener slot
/// forever. One absolute window per handshake (no per-record re-arm). Go
/// frp's plugins have no equivalent bound (net/http's ReadHeaderTimeout
/// applies after TLS); this is Rust-only hardening, shared with tls2raw's
/// original per-site deadline.
#[cfg(feature = "tls")]
pub(super) const PLUGIN_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Accept one TLS handshake under the shared [`PLUGIN_HANDSHAKE_TIMEOUT`]
/// window. The bare `acceptor.accept` in https2http/https2https had no
/// bound at all; tls2raw already bounded its accept with the same 60 s.
/// Error strings are debug-log only (both sites log and drop the
/// connection — no 4xx is possible before the request is read).
#[cfg(feature = "tls")]
pub(super) async fn accept_tls_bounded(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, String> {
    tokio::time::timeout(PLUGIN_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_elapsed| {
            format!(
                "TLS handshake timed out after {:?}",
                PLUGIN_HANDSHAKE_TIMEOUT
            )
        })?
        .map_err(|e| e.to_string())
}

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
///
/// A HEAD request carries no body at all — the forward is skipped even when
/// the head declares a Content-Length (RFC 7230 §3.3.2: neither side sends
/// a body with HEAD).
pub(super) async fn forward_request_body<S, W>(
    stream: &mut S,
    writer: &mut W,
    body_prefix: &[u8],
    framing: Option<BodyFraming>,
    method: &str,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // HEAD requests never carry a body, even when the head declares a
    // Content-Length (RFC 7230 §3.3.2). Blocking on a body that will never
    // arrive would stall the response relay until the client closes — skip
    // the read and keep the Content-Length header in the forwarded head so
    // the backend still knows the response framing.
    if method.eq_ignore_ascii_case("HEAD") {
        return Ok(());
    }
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
    ///
    /// The cap is enforced after EVERY buffer extension (pending prefix and
    /// each stream chunk): a line errors as soon as its accumulated length
    /// exceeds `max` and is never returned over-length.
    async fn read_line(&mut self, max: usize) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            // Serve the pending prefix first (body bytes that arrived with
            // the head), scanning it for the terminator.
            let avail = self.available();
            if let Some(rel) = avail.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&avail[..rel + 1]);
                self.consume(rel + 1);
                if line.len() > max {
                    return Err(line_too_long());
                }
                return Ok(line);
            }
            line.extend_from_slice(avail);
            self.consume(avail.len());
            if line.len() > max {
                return Err(line_too_long());
            }
            if self.pos > 0 {
                self.pending.clear();
                self.pos = 0;
            }
            // Refill from the stream, then scan the NEW bytes for the
            // terminator: `line` accumulates across reads and the `\n` can
            // only arrive inside a chunk.
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in line",
                ));
            }
            if let Some(rel) = tmp[..n].iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&tmp[..rel + 1]);
                // Bytes past the terminator belong to the next line: stage
                // them back into `pending` so the next read/read_line call
                // serves them before touching the stream.
                self.pending.extend_from_slice(&tmp[rel + 1..n]);
                if line.len() > max {
                    return Err(line_too_long());
                }
                return Ok(line);
            }
            line.extend_from_slice(&tmp[..n]);
            // Cap check after every extension: without it the overflow was
            // only noticed at the next loop iteration, one full read past
            // the cap boundary.
            if line.len() > max {
                return Err(line_too_long());
            }
        }
    }
}

/// Error for a chunk-size/trailer line that exceeds the cap.
fn line_too_long() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long")
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

/// Percent-decode of a URL PATH (audit round: '+' stays LITERAL). Go's
/// URL decoding happens in url.Parse, where PlusToSpace is a query-only
/// rule (net/url: `parseQuery` applies it, path decoding never does) — a
/// request-target "/a+b" decodes to "/a+b", exactly like the raw bytes.
/// The old x-www-form-urlencoded-style '+' → ' ' translation served "a b"
/// when the client asked for the file "a+b".
///
/// Decoding is BYTE-level (audit round-16 FIX 2): each valid escape
/// contributes one raw byte — a %C3%AF sequence yields the UTF-8 bytes
/// C3 AF, where the old `(hi << 4 | lo) as char` Latin-1 cast produced ï
/// = C3 and mojibake'd every non-ASCII name on re-encode ("naïve" served
/// as "naÃ¯ve"). The result is NOT guaranteed UTF-8 (a lone %FF decodes
/// to a byte with no encoding) — callers that need text or a PathBuf must
/// convert explicitly (OsStringExt::from_vec on unix, from_utf8_lossy
/// elsewhere); only bytes are safe to move around raw. Invalid escapes
/// cannot reach this helper through a request-target — url.Parse rejects
/// them first (see [`parse_request_line`]'s [`target_has_invalid_escape`]
/// gate) — but the pass-through leniency below is kept for the helper's
/// own robustness (defense in depth; the gate is the parity surface).
pub(super) fn urlencoding_decode(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push(hi << 4 | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
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

    /// M9 pin: the real-tunnel-peer registry is take-once per dialer port,
    /// newest registration wins on port reuse (a stale entry from an earlier
    /// conn must not shadow the current dial), and unknown ports miss.
    #[test]
    fn real_tunnel_peer_registry_take_once() {
        let dialer = SocketAddr::from(([127, 0, 0, 1], 44444));
        // The guard keeps the entry alive for its registration's lifetime
        // (F5). Take-once: the accept handler consumes the entry.
        let _g1 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 7], 5555)));
        assert_eq!(
            plugin_peer_ip_now(dialer),
            std::net::IpAddr::V4("203.0.113.7".parse().unwrap())
        );
        assert_eq!(take_plugin_peer(dialer.port()), None);
        // Overwrite on dialer-port reuse (kernel ephemeral recycle).
        let _g2 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 8], 5556)));
        let _g3 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 9], 5557)));
        assert_eq!(
            plugin_peer_ip_now(dialer),
            std::net::IpAddr::V4("203.0.113.9".parse().unwrap())
        );
        // Unknown port → miss (health-check/stray dials fall back to peer.ip()).
        assert_eq!(take_plugin_peer(1), None);
    }

    /// F5 pin: a dropped guard removes its own registry entry, so every
    /// work-conn exit path (normal end, early return, abort) cleans up.
    #[test]
    fn plugin_peer_guard_drop_removes_entry() {
        let dialer = SocketAddr::from(([127, 0, 0, 1], 44445));
        let real = SocketAddr::from(([203, 0, 113, 7], 5555));
        let guard = register_plugin_peer(dialer.port(), real);
        assert_eq!(take_plugin_peer(dialer.port()), Some(real));
        // Consumed entries are gone; dropping the guard is a no-op.
        drop(guard);
        assert_eq!(take_plugin_peer(dialer.port()), None);

        // Un-consumed entry: the guard drop removes it (the work-conn task
        // ended before the accept handler ran).
        let guard = register_plugin_peer(dialer.port(), real);
        drop(guard);
        assert_eq!(take_plugin_peer(dialer.port()), None);
    }

    /// F5 pin: a guard from a SUPERSEDED registration must not delete its
    /// successor's live entry (newest-registration-wins on port recycle).
    #[test]
    fn plugin_peer_guard_drop_keeps_newer_entry() {
        let dialer = SocketAddr::from(([127, 0, 0, 1], 44446));
        let g2 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 8], 5556)));
        let _g3 = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 9], 5557)));
        // g2's registration was overwritten: dropping g2 must NOT remove the
        // live g3 entry.
        drop(g2);
        assert_eq!(
            take_plugin_peer(dialer.port()),
            Some(SocketAddr::from(([203, 0, 113, 9], 5557)))
        );
    }

    /// F5 pin: serve_plugin teardown's wholesale clear empties the registry
    /// (defense in depth for connections whose guard never ran).
    #[test]
    fn clear_plugin_peers_empties_registry() {
        let dialer = SocketAddr::from(([127, 0, 0, 1], 44447));
        let _g = register_plugin_peer(dialer.port(), SocketAddr::from(([203, 0, 113, 7], 5555)));
        let _g2 = register_plugin_peer(44448, SocketAddr::from(([203, 0, 113, 7], 5556)));
        clear_plugin_peers();
        assert_eq!(take_plugin_peer(dialer.port()), None);
        assert_eq!(take_plugin_peer(44448), None);
        assert_eq!(
            real_tunnel_peer_map()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
    }

    /// Sync resolution for the test above (plugin_peer_ip's retry loop would
    /// add 8 ms per miss; here the entry always exists on the first attempt).
    fn plugin_peer_ip_now(peer: SocketAddr) -> std::net::IpAddr {
        take_plugin_peer(peer.port())
            .map(|a| a.ip())
            .unwrap_or(peer.ip())
    }

    /// Fake AsyncRead for BodyReader tests: serves a fixed byte blob in
    /// fixed-size chunks, counting the bytes handed out in a shared counter
    /// (readable while the reader still borrows the stream).
    struct FakeStream {
        data: Vec<u8>,
        chunk: usize,
        pos: usize,
        served: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FakeStream {
        fn new(
            data: Vec<u8>,
            chunk: usize,
        ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    data,
                    chunk,
                    pos: 0,
                    served: served.clone(),
                },
                served,
            )
        }
    }

    impl tokio::io::AsyncRead for FakeStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.pos >= self.data.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let n = (self.data.len() - self.pos)
                .min(self.chunk)
                .min(buf.remaining());
            buf.put_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            self.served
                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Property guard, not a placement-regression catch: the bytes consumed
    /// for an over-long stream-delivered line stay bounded near the cap —
    /// at most one 4096-byte chunk past the boundary, never the whole
    /// over-long line. This also held on the pre-fix code (its cap check
    /// ran one iteration later and errored at the same byte count with the
    /// same kind/message); the genuinely new cap enforcement on the
    /// terminator-found paths is covered by
    /// `read_line_caps_over_long_pending_line` (pending branch) and
    /// `read_line_terminates_on_stream_line` (stream-terminator scanning).
    #[tokio::test]
    async fn read_line_caps_over_long_stream_line() {
        let mut data = vec![b'x'; CHUNK_LINE_MAX + 8192];
        data.push(b'\n');
        let total = data.len();
        let (stream, served) = FakeStream::new(data, 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &[]);
        let err = reader.read_line(CHUNK_LINE_MAX).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let served = served.load(std::sync::atomic::Ordering::Relaxed);
        assert!(served > CHUNK_LINE_MAX, "the cap must have been crossed");
        assert!(
            served <= CHUNK_LINE_MAX + 4096,
            "read {served} bytes past a {CHUNK_LINE_MAX} cap"
        );
        assert!(
            served < total,
            "the whole over-long line must not be consumed"
        );
    }

    /// Regression: a line delivered via the stream (not coalesced with the
    /// head) must still terminate. Previously only the pending prefix was
    /// scanned for `\n`, so a stream-delivered line ran to EOF ("eof in
    /// line") and the chunked forward failed. Bytes past the terminator
    /// must stay staged for the next reads (chunk data, CRLF, next line).
    #[tokio::test]
    async fn read_line_terminates_on_stream_line() {
        let (stream, _served) = FakeStream::new(b"5\r\nhello\r\n0\r\n\r\n".to_vec(), 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &[]);
        let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
        assert_eq!(line, b"5\r\n");
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
        assert_eq!(reader.read_line(CHUNK_LINE_MAX).await.unwrap(), b"0\r\n");
        assert_eq!(reader.read_line(CHUNK_LINE_MAX).await.unwrap(), b"\r\n");
    }

    /// The `\r` of a CRLF at the end of one stream chunk with the `\n`
    /// opening the next must still terminate the line (only `\n` is
    /// scanned for), and the bytes past the terminator must be staged.
    #[tokio::test]
    async fn read_line_crlf_split_across_stream_chunks() {
        // Stream reads are 4096 bytes: 4095 x's plus `\r` fill the first
        // read, `\n` opens the second — the worst-case split.
        let mut data = vec![b'x'; 4095];
        data.extend_from_slice(b"\r\nhello\r\n");
        let (stream, _served) = FakeStream::new(data, 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &[]);
        let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
        assert_eq!(line.len(), 4097);
        assert!(line[..4095].iter().all(|&b| b == b'x'));
        assert!(line.ends_with(b"\r\n"));
        // The next line ("hello\r\n") was staged, not lost.
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
    }

    /// A partial line followed by EOF must error ("eof in line"), never
    /// return the truncated line.
    #[tokio::test]
    async fn read_line_eof_mid_line_errors() {
        let (stream, _served) = FakeStream::new(b"hello".to_vec(), 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &[]);
        let err = reader.read_line(CHUNK_LINE_MAX).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "eof in line");
    }

    /// A line delivered entirely with the head is served from the pending
    /// prefix without touching the stream (existing behavior preserved).
    #[tokio::test]
    async fn read_line_serves_pending_prefix_line() {
        let (stream, served) = FakeStream::new(Vec::new(), 4096);
        let mut boxed = Box::new(stream);
        let prefix = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
        let mut reader = BodyReader::new(&mut boxed, &prefix);
        assert_eq!(reader.read_line(CHUNK_LINE_MAX).await.unwrap(), b"5\r\n");
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the stream must not be read"
        );
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    /// A line exactly `max` bytes long (terminator included) is accepted;
    /// only EXCEEDING the cap errors.
    #[tokio::test]
    async fn read_line_accepts_line_at_cap() {
        let mut data = vec![b'x'; CHUNK_LINE_MAX - 1];
        data.push(b'\n');
        let (stream, _served) = FakeStream::new(data, 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &[]);
        let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
        assert_eq!(line.len(), CHUNK_LINE_MAX);
        assert!(line.ends_with(b"\n"));
    }

    /// A line exactly `max` bytes long delivered via the pending prefix is
    /// accepted (boundary is `>` not `>=`); the stream-path boundary is
    /// covered by `read_line_accepts_line_at_cap`.
    #[tokio::test]
    async fn read_line_accepts_at_cap_pending_prefix_line() {
        let mut prefix = vec![b'x'; CHUNK_LINE_MAX - 1];
        prefix.push(b'\n');
        let (stream, served) = FakeStream::new(Vec::new(), 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &prefix);
        let line = reader.read_line(CHUNK_LINE_MAX).await.unwrap();
        assert_eq!(line.len(), CHUNK_LINE_MAX);
        assert!(line.ends_with(b"\n"));
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the stream must not be read"
        );
    }

    /// An over-long line arriving entirely with the head errors from the
    /// prefix alone — the stream is never read.
    #[tokio::test]
    async fn read_line_caps_over_long_pending_line() {
        let mut prefix = vec![b'x'; CHUNK_LINE_MAX + 1];
        prefix.push(b'\n');
        let (stream, served) = FakeStream::new(Vec::new(), 4096);
        let mut boxed = Box::new(stream);
        let mut reader = BodyReader::new(&mut boxed, &prefix);
        let err = reader.read_line(CHUNK_LINE_MAX).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the stream must not be read"
        );
    }

    #[test]
    fn test_base64_decode() {
        // "test:pass" = dGVzdDpwYXNz (payload length a multiple of 3)
        let result = base64_decode("dGVzdDpwYXNz").unwrap();
        assert_eq!(result, "test:pass");
        // Padded payload whose length is NOT a multiple of 3: the leftover
        // bits before '=' are zero-fill. The old decoder emitted them as a
        // spurious trailing NUL byte ("u1:p1\0") — the auth compare then
        // rejected every valid credential of that shape. RED on the old
        // `bits >= 2` flush at padding.
        let result = base64_decode("dTE6cDE=").unwrap();
        assert_eq!(result, "u1:p1");
    }

    #[test]
    fn test_split_host_port() {
        assert_eq!(split_host_port("host:443"), ("host", 443));
        assert_eq!(split_host_port("host"), ("host", 80));
        assert_eq!(split_host_port("1.2.3.4:8080"), ("1.2.3.4", 8080));
    }

    #[test]
    fn test_urlencoding_decode() {
        // Byte-level decode (audit round-16 FIX 2): results are raw bytes,
        // not chars.
        assert_eq!(urlencoding_decode("hello%20world"), b"hello world".to_vec());
        assert_eq!(
            urlencoding_decode("%2Fetc%2Fpasswd"),
            b"/etc/passwd".to_vec()
        );
        assert_eq!(urlencoding_decode("noencoding"), b"noencoding".to_vec());
        // '+' is LITERAL in path decoding — Go's PlusToSpace is query-only
        // (url.Parse decodes paths without it). Flip: the old x-www-form
        // behavior served "a b" for "/a+b".
        assert_eq!(urlencoding_decode("a+b"), b"a+b".to_vec());
        // Invalid hex stays literal on decode (Go url.Parse leaves bad
        // escapes untouched) — parse_request_line's gate rejects such
        // targets before decode anyway.
        assert_eq!(urlencoding_decode("%gg"), b"%gg".to_vec());
        // FIX 2 mojibake pin: %C3%AF decodes to the UTF-8 bytes C3 AF, NOT
        // the Latin-1 cast ï = C3 (which re-encoded as C3 83 C2 AF and
        // served "naÃ¯ve.txt" for "naïve.txt").
        assert_eq!(urlencoding_decode("na%C3%AFve.txt"), b"na\xc3\xafve.txt");
        assert_eq!(urlencoding_decode("%FF"), b"\xff".to_vec());
    }

    /// Matrix for the shared request-side version gate — moved from
    /// plugin/http.rs when the request-line parser became shared. Request
    /// side: ParseHTTPVersion accepts every 8-char "HTTP/X.Y" with a single
    /// ASCII digit (go1.25 request.go:817-838; "HTTP/1.0"/"HTTP/1.1"
    /// short-circuit), and the plugin gate additionally requires major 1
    /// (the frps vhost front 505s everything else — HTTP/2.0 tokens never
    /// reach the plugin legs in either ecosystem).
    #[test]
    fn test_go_parse_http_version_ok_matrix() {
        // Lenient-but-parseable: single-digit minor, majors 2..9 parse in
        // Go ParseHTTPVersion but the major-1 gate rejects them.
        assert!(go_parse_http_version_ok("HTTP/1.0"));
        assert!(go_parse_http_version_ok("HTTP/1.1"));
        assert!(go_parse_http_version_ok("HTTP/1.2"));
        assert!(go_parse_http_version_ok("HTTP/1.9"));
        assert!(!go_parse_http_version_ok("HTTP/2.0"));
        assert!(!go_parse_http_version_ok("HTTP/3.0"));
        assert!(!go_parse_http_version_ok("HTTP/9.9"));
        // Malformed tokens.
        assert!(!go_parse_http_version_ok("HTTP/1.10")); // 9 bytes
        assert!(!go_parse_http_version_ok("HTTP/1.1 "));
        assert!(!go_parse_http_version_ok("HTTP/.1"));
        assert!(!go_parse_http_version_ok("http/1.1"));
        assert!(!go_parse_http_version_ok(""));
        assert!(!go_parse_http_version_ok("HTTP/1\t1"));
        assert!(!go_parse_http_version_ok("HTTP/10.1"));
        assert!(!go_parse_http_version_ok("HTTP/1.1."));
    }

    #[test]
    fn test_parse_request_line() {
        // Well-formed three-part lines.
        assert_eq!(
            parse_request_line("GET /path HTTP/1.1"),
            Some(("GET", "/path", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT host:443 HTTP/1.1"),
            Some(("CONNECT", "host:443", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("GET /x HTTP/1.2"),
            Some(("GET", "/x", "HTTP/1.2"))
        );
        // Go parseRequestLine: literal-space cuts only, so a 2-token line
        // ("GET /x", HTTP/0.9-style — Go dropped the 0.9 fallback), a
        // tab-joined "GET\t/x\tHTTP/1.1" (no literal second space), an empty
        // version slot ("GET /x " — splitn finds nothing after the last
        // space), and an empty target ("GET  HTTP/1.1") all malformed.
        assert_eq!(parse_request_line("GET /x"), None);
        assert_eq!(parse_request_line("GET\t/x\tHTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /x "), None);
        assert_eq!(parse_request_line("GET  HTTP/1.1"), None);
        assert_eq!(parse_request_line(" HTTP/1.1"), None);
        // The two-Cut parse leaves the SECOND space as an empty slot:
        // "GET  /x HTTP/1.1" → requestURI "" (Go: url.ParseRequestURI("")
        // fails "empty url"), "GET /x  HTTP/1.1" → proto " HTTP/1.1"
        // (leading space — ParseHTTPVersion fails). Both malformed in Go.
        assert_eq!(parse_request_line("GET  /x HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /x  HTTP/1.1"), None);
        // Version gate.
        assert_eq!(parse_request_line("GET /x HTTP/2.0"), None);
        assert_eq!(parse_request_line("GET /x garbage"), None);
        assert_eq!(parse_request_line("GET /x HTTP/1.1 trailing"), None);
        assert_eq!(parse_request_line(""), None);
        // Go conn.readRequest validMethod gate: the method token must be
        // non-empty and made of RFC 7230 tchar bytes only. Lowercase "get"
        // is a LEGAL token (validMethod has no case rule — gorilla mux
        // Method("GET") 405s it later in Go); "G@T" is a 400 before
        // routing. A tab EMBEDDED in the method ("GE\tT /x") splits on the
        // literal space into a parseable line whose token then fails the
        // gate — accept-where-Go-rejects before the gate, now rejected.
        assert_eq!(
            parse_request_line("get /x HTTP/1.1"),
            Some(("get", "/x", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("M-SEARCH /x HTTP/1.1"),
            Some(("M-SEARCH", "/x", "HTTP/1.1"))
        );
        assert_eq!(parse_request_line("G@T /x HTTP/1.1"), None);
        assert_eq!(parse_request_line("GE(T /x HTTP/1.1"), None);
        assert_eq!(parse_request_line("GE\tT /x HTTP/1.1"), None);
        // Non-ASCII byte in the method token.
        assert_eq!(parse_request_line("GÉT /x HTTP/1.1"), None);
        // Empty method token.
        assert_eq!(parse_request_line(" /x HTTP/1.1"), None);
        // Audit round-16 FIX 13: invalid %-escapes in the request-target's
        // pre-'?' portion — Go url.Parse "invalid URL escape" inside
        // ReadRequest → 400 before routing/auth (probe vs go1.25.12:
        // /x%zz, /x%, /x%2 all 400). A '%' must be followed by two hex
        // digits, anywhere before the query (path and absolute-form
        // authority alike — Go parses one URL). The post-fix round then
        // proved the scan must STOP at the first '?': url.Parse Cuts the
        // query RAW before any unescape, so a garbage escape in the query
        // is never decoded, never validated, and never an error (probe:
        // /x?q=%zz, /x?q=%2, /x?q=%zz%2 all answer 200). '#' is not a
        // fragment separator under ParseRequestURI, so escapes after it
        // stay path-validated and 400 like any other path escape.
        assert_eq!(parse_request_line("GET /x%zz HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /x%2 HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /x% HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET %zz HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT host%zz:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET http://h/x%zz HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /x%zz?q=1 HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /x%zz#f%zz HTTP/1.1"), None);
        // Query-only escapes parse (the query stays raw — Go never
        // unescape-validates it).
        assert_eq!(
            parse_request_line("GET /x?q=%zz HTTP/1.1"),
            Some(("GET", "/x?q=%zz", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("GET /x?q=%zz%2 HTTP/1.1"),
            Some(("GET", "/x?q=%zz%2", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT host:443?a=%zz HTTP/1.1"),
            Some(("CONNECT", "host:443?a=%zz", "HTTP/1.1"))
        );
        // Valid escapes and literal '%'-free targets pass.
        assert_eq!(
            parse_request_line("GET /x%20y%2Fz HTTP/1.1"),
            Some(("GET", "/x%20y%2Fz", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("GET /100%25done HTTP/1.1"),
            Some(("GET", "/100%25done", "HTTP/1.1"))
        );
        // Absolute-form target (non-CONNECT): path mode over the whole
        // pre-'?' slice. A WELL-FORMED ASCII escape in the absolute-form
        // HOST parses here — documented divergence, kept per the review
        // scope (the host-mode gate below covers the CONNECT authority
        // only): Go host-modes that region too (probe vs go1.25
        // http.Server: "GET http://h%41st/x HTTP/1.1" answers 400), and
        // frp-rs dials absolute-form hosts verbatim, so a %41 host fails
        // the dial anyway. Malformed escapes in the absolute-form host
        // reject here exactly like Go ("GET http://h%zzst/x" → 400 —
        // url.Parse errors before routing, both modes).
        assert_eq!(
            parse_request_line("GET http://h%41st/x HTTP/1.1"),
            Some(("GET", "http://h%41st/x", "HTTP/1.1"))
        );
        assert_eq!(parse_request_line("GET http://h%zzst/x HTTP/1.1"), None);
    }

    /// Review-round fix: a CONNECT authority-form target is validated
    /// with Go's HOST-mode unescape (net/url/url.go:226 — parseHost over
    /// the authority of readRequest justAuthority's "http://" + target
    /// rewrite): a well-formed escape that decodes to an ASCII byte
    /// (first hex digit < 8) is an error UNLESS it is the literal "%25"
    /// (the RFC 6874 zone exemption — "%25" decodes to '%'), while
    /// escapes decoding to obs-text (first hex digit >= 8, "%C3%A9") and
    /// the "%25" literal pass. Malformed escapes reject in every mode.
    /// The region split mirrors Go's parse: the authority runs to the
    /// target's FIRST '/', the remainder (from the '/' on) is the path
    /// (path mode), the query stays raw. Probe vs go1.25 http.Server:
    /// "CONNECT h%41st:443" / h%2Fst / h%zzst → 400; h%25st / h%C3%A9st
    /// → 200 (the "h:4%31" port shape rejects earlier in Go — parseHost's
    /// validOptionalPort digits-only gate — but same ReadRequest-error
    /// class). RED on pre-fix code: the escape scan was path-mode over
    /// the whole target, so the well-formed ASCII escapes (%41/%2F/%40)
    /// parsed and reached the CONNECT dial — only malformed %zz
    /// rejected.
    #[test]
    fn test_parse_request_line_connect_host_mode_escapes() {
        // ASCII-decoding escapes in the authority: host-mode rejects
        // (Go: "invalid URL escape", ReadRequest → 400 → silent close
        // on the http_proxy CONNECT arm).
        assert_eq!(parse_request_line("CONNECT h%41st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h%2Fst:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h%5Bst:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h%40st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h%7Fst:443 HTTP/1.1"), None);
        // Port-region escape: same rejection class (Go's validOptionalPort
        // digit gate fires first there — either way a ReadRequest error).
        assert_eq!(parse_request_line("CONNECT h:4%31 HTTP/1.1"), None);
        // Malformed escapes reject (both modes agree).
        assert_eq!(parse_request_line("CONNECT h%zzst:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h%2:443 HTTP/1.1"), None);
        // "%25" (the exemption — decodes to '%') and obs-text decodes
        // ("%C3%A9" → 'é') pass.
        assert_eq!(
            parse_request_line("CONNECT h%25st:443 HTTP/1.1"),
            Some(("CONNECT", "h%25st:443", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT h%C3%A9st:443 HTTP/1.1"),
            Some(("CONNECT", "h%C3%A9st:443", "HTTP/1.1"))
        );
        // Region split at the first '/': authority host-mode, path (from
        // the '/') path-mode, query raw.
        assert_eq!(
            parse_request_line("CONNECT h%25st:443/a%41?q=%zz HTTP/1.1"),
            Some(("CONNECT", "h%25st:443/a%41?q=%zz", "HTTP/1.1"))
        );
        assert_eq!(parse_request_line("CONNECT h%25st:443/a%zz HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h%41st:443/a HTTP/1.1"), None);
        // '/'-prefixed CONNECT targets are path-form in Go (justAuthority
        // only applies when the target does NOT start with '/') — path
        // mode throughout.
        assert_eq!(
            parse_request_line("CONNECT /rpc%41 HTTP/1.1"),
            Some(("CONNECT", "/rpc%41", "HTTP/1.1"))
        );
    }

    /// Round-17 audit finding F6: the raw-ASCII sweep. Go's unescape
    /// default arm rejects `s[i] < 0x80 && shouldEscape(s[i], mode)` in
    /// host and zone modes (InvalidHostError — ReadRequest → silent close
    /// on the http_proxy CONNECT arm). The pre-fix gate charset-validated
    /// only %-escaped bytes, so raw '^'/'|'/'{' authorities passed and
    /// died at the dial with a 400 render where Go closes silently.
    #[test]
    fn test_parse_request_line_connect_host_raw_ascii_sweep() {
        // Raw non-legal ASCII in the authority host region → reject
        // (Go InvalidHostError; probe vs go1.25: "CONNECT h^st:80" /
        // "h|st" answer 0 bytes on the http_proxy CONNECT arm).
        assert_eq!(parse_request_line("CONNECT h^st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h|st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h{st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h`st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h\\st:443 HTTP/1.1"), None);
        assert_eq!(parse_request_line("CONNECT h#st:443 HTTP/1.1"), None);
        // Raw DEL is swept by the CTL pass (b == 0x7f) even before F6.
        assert_eq!(parse_request_line("CONNECT h\u{7f}st:443 HTTP/1.1"), None);
        // A raw space in the authority never survives the 3-part
        // request-line split — the second space makes "st:443" the
        // version token, which fails the version shape (Go: the line
        // parses to a 2-part request line → malformed 400; same class).
        assert_eq!(parse_request_line("CONNECT h st:443 HTTP/1.1"), None);
        // Raw obs-text is LEGAL (the sweep gates on < 0x80) — Go parses
        // it and dies at the dial.
        assert_eq!(
            parse_request_line("CONNECT h\u{ff}st:443 HTTP/1.1"),
            Some(("CONNECT", "h\u{ff}st:443", "HTTP/1.1"))
        );
    }

    /// Round-17 audit finding F5: the unreserved-marks switch. Go's
    /// shouldEscape has an UNCONDITIONAL second switch exempting '-', '_',
    /// '.' and '~' that runs for host/zone modes too — the pre-fix set
    /// lacked the four marks, so a raw '~' host passed only by accident
    /// (no raw sweep existed) but a zone escape like "%2D" was rejected
    /// where Go accepts it (probe: CONNECT [fe80::1%25en%2D0]:80 parses in
    /// go1.25 — redundant escaping of a zone-legal byte).
    #[test]
    fn test_parse_request_line_connect_host_unreserved_marks() {
        // Raw marks in the authority host region stay legal under the F6
        // sweep (they must — the sweep calls should_escape_encode_host).
        assert_eq!(
            parse_request_line("CONNECT h-st:443 HTTP/1.1"),
            Some(("CONNECT", "h-st:443", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT h_st:443 HTTP/1.1"),
            Some(("CONNECT", "h_st:443", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT h.st:443 HTTP/1.1"),
            Some(("CONNECT", "h.st:443", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT h~st:443 HTTP/1.1"),
            Some(("CONNECT", "h~st:443", "HTTP/1.1"))
        );
        // Zone redundant escapes of the marks decode to host-legal bytes:
        // %2D / %7E inside a zone pass (Go probe row above); the host-mode
        // %2D (outside any zone) stays rejected (escapes of host-legal
        // bytes are still invalid under the ASCII-escape rule).
        assert_eq!(
            parse_request_line("CONNECT [fe80::1%25en%2D0]:80 HTTP/1.1"),
            Some(("CONNECT", "[fe80::1%25en%2D0]:80", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT [fe80::1%25en-0]:80 HTTP/1.1"),
            Some(("CONNECT", "[fe80::1%25en-0]:80", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("CONNECT [fe80::1%25en%7E0]:80 HTTP/1.1"),
            Some(("CONNECT", "[fe80::1%25en%7E0]:80", "HTTP/1.1"))
        );
        assert_eq!(parse_request_line("CONNECT h%2Dst:443 HTTP/1.1"), None);
        // Zone raw-ASCII sweep (F6 in zone mode): a raw '^' inside the
        // zone region rejects like the host region.
        assert_eq!(
            parse_request_line("CONNECT [fe80::1%25en^0]:80 HTTP/1.1"),
            None
        );
    }

    /// Go conn.readRequest `validMethod` (request.go go1.25): non-empty +
    /// tchar-only (alnum and `!#$%&'*+-.^_`|~`). No case rule — lowercase
    /// "get" passes, exactly like Go (gorilla's Method("GET") route check
    /// is where lowercase 405s later).
    #[test]
    fn test_go_valid_method_ok() {
        assert!(go_valid_method_ok("GET"));
        assert!(go_valid_method_ok("get"), "lowercase is a legal token");
        assert!(go_valid_method_ok("CONNECT"));
        assert!(go_valid_method_ok("PATCH"));
        assert!(go_valid_method_ok("M-SEARCH"));
        assert!(go_valid_method_ok("_foo"));
        assert!(go_valid_method_ok("!#$%&'*+-.^_`|~0123456789"));
        assert!(go_valid_method_ok(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        ));
        assert!(!go_valid_method_ok(""));
        assert!(!go_valid_method_ok("G@T"));
        assert!(!go_valid_method_ok("GE(T"));
        assert!(!go_valid_method_ok("GET:FOO")); // colon is not tchar
        assert!(!go_valid_method_ok("/GET")); // slash is not tchar
        assert!(!go_valid_method_ok("GET\u{7f}"));
        assert!(!go_valid_method_ok("GÉT")); // non-ASCII bytes are not tchar
        assert!(!go_valid_method_ok("GE T")); // space is not tchar
    }

    #[test]
    fn test_go_render_shapes() {
        // Exact Go probe captures — any future edit to these renders changes
        // the bytes peers see.
        assert_eq!(
            GO_502_RENDER,
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(GO_502_RENDER.len(), 47);
        assert!(!GO_400_RENDER.contains("Content-Length"));
        assert!(GO_400_RENDER.ends_with("400 Bad Request"));
        assert!(!GO_431_RENDER.contains("Content-Length"));
        assert!(GO_431_RENDER.starts_with("HTTP/1.1 431 Request Header Fields Too Large"));
        assert!(GO_404_NOT_FOUND_RENDER.ends_with("404 page not found\n"));
        assert!(GO_404_NOT_FOUND_RENDER.contains("Content-Length: 19"));
        assert!(!head_starts_connect(GO_400_RENDER.as_bytes()));
        assert!(head_starts_connect(b"CONNECT host:443 HTTP/1.1"));
        assert!(head_starts_connect(b"connect"));
        assert!(head_starts_connect(b"Connect"));
        assert!(!head_starts_connect(b"GET / HTTP/1.1"));
        assert!(!head_starts_connect(b"CONNEC")); // 6 bytes: short of the 7-byte read
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
        // Chunked must be the FINAL coding of the list (RFC 7230 §3.3.3);
        // "gzip, chunked" is chunked, "chunkedfoo" or a coding after chunked
        // is not.
        assert_eq!(
            parse_request_body_framing("Transfer-Encoding: gzip, chunked".lines()),
            Some(BodyFraming::Chunked)
        );
        assert_eq!(
            parse_request_body_framing("Transfer-Encoding: chunkedfoo".lines()),
            None
        );
        assert_eq!(
            parse_request_body_framing("Transfer-Encoding: chunked, gzip".lines()),
            None
        );
        // Chunked wins over Content-Length (RFC 7230 §3.3.3).
        assert_eq!(
            parse_request_body_framing("Content-Length: 42\r\nTransfer-Encoding: chunked".lines()),
            Some(BodyFraming::Chunked)
        );
        // List-form Content-Length ("5, 5") is malformed: Go's
        // strconv.ParseUint takes no commas, so net/http (the server
        // inside Go frp's http_proxy plugin) answers 400. resolve_
        // content_length errors, and the head builders reject the request
        // on that error — no framing is inferred here.
        assert_eq!(
            parse_request_body_framing("Content-Length: 5, 5".lines()),
            None
        );
        // Duplicate identical Content-Length lines collapse to one value.
        assert_eq!(
            parse_request_body_framing("Content-Length: 5\r\nContent-Length: 5".lines()),
            Some(BodyFraming::Length(5))
        );
        // Unparseable Content-Length is malformed — Go's server rejects
        // the request outright (400 "bad Content-Length"). resolve_
        // content_length errors, and the head builders reject the request
        // on that error.
        assert_eq!(
            parse_request_body_framing("Content-Length: abc".lines()),
            None
        );
    }

    /// Go parity (probed against the Go frp v0.71.0-era stdlib, go1.25.12):
    /// Go validates Content-Length values even when Transfer-Encoding:
    /// chunked wins the framing — chunked + "5, 5" is still 400 "bad
    /// Content-Length". The F9 resolve gate in the head builders therefore
    /// runs UNCONDITIONALLY: the old chunked-skip accepted garbage CL
    /// under chunked and forwarded the request (round-8 F9). A chunked
    /// request carrying a VALID Content-Length still forwards with the CL
    /// line dropped (Go deletes the header once chunked wins) and the
    /// Transfer-Encoding preserved.
    #[tokio::test]
    async fn chunked_request_resolves_content_length() {
        use tokio::io::AsyncWriteExt;
        // Malformed (list-form) Content-Length under chunked fails the
        // forward build, mirroring Go's 400.
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io
            .write_all(
                b"POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nContent-Length: 5, 5\r\n\r\n",
            )
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        let err =
            read_request_and_build_forward(&mut server_io, "", &Default::default(), None).await;
        let err = match err {
            Ok(_) => panic!(
                "chunked + list-form Content-Length must reject the forward build (regression)"
            ),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("Content-Length"),
            "rejection must name the header, got: {err}"
        );

        // A VALID Content-Length under chunked is accepted; the retain
        // gate drops the CL line and the Transfer-Encoding survives.
        let head = build_forward(
            b"POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert!(
            !head
                .lines()
                .any(|l| starts_with_ignore_ascii_case(l, "content-length:")),
            "Content-Length must be dropped under chunked, got: {head}"
        );
        assert!(
            head.contains("Transfer-Encoding: chunked"),
            "chunked framing must survive, got: {head}"
        );
    }

    #[test]
    fn test_resolve_content_length() {
        // No Content-Length header → no length.
        assert_eq!(
            resolve_content_length("Host: example.com".lines()).unwrap(),
            None
        );
        // Single value.
        assert_eq!(
            resolve_content_length("Content-Length: 42".lines()).unwrap(),
            Some(42)
        );
        // Zero is a legal body length.
        assert_eq!(
            resolve_content_length("Content-Length: 0".lines()).unwrap(),
            Some(0)
        );
        // Leading zeros and trailing ASCII OWS are accepted (Go
        // textproto.TrimString + strconv.ParseUint).
        assert_eq!(
            resolve_content_length("Content-Length: 05".lines()).unwrap(),
            Some(5)
        );
        assert_eq!(
            resolve_content_length("Content-Length: 5   ".lines()).unwrap(),
            Some(5)
        );
        // Duplicate identical lines collapse to one copy (Go fixLength
        // dedupes — the comparison is on the ASCII-OWS-trimmed raw text).
        assert_eq!(
            resolve_content_length("Content-Length: 5\r\nContent-Length: 5".lines()).unwrap(),
            Some(5)
        );
        assert_eq!(
            resolve_content_length("Content-Length: 5 \r\nContent-Length: 5".lines()).unwrap(),
            Some(5)
        );
        // Conflicting values invalidate the request framing (Go answers
        // 400 "message cannot contain multiple Content-Length headers").
        assert!(
            resolve_content_length("Content-Length: 5\r\nContent-Length: 100".lines()).is_err()
        );
        // ... including raw-text differences that parse to the same number
        // ("05" == 5 numerically, but the trimmed texts differ).
        assert!(resolve_content_length("Content-Length: 05\r\nContent-Length: 5".lines()).is_err());
        // List forms are NOT legal. Go strconv.ParseUint rejects any
        // non-digit, so a comma list ("5, 5", RFC 7230 §3.3.2's legal form
        // notwithstanding) is a 400. Probed against the Go frp v0.71.0
        // binary (built with go1.25.12): every list shape below is answered
        // "HTTP/1.1 400 Bad Request".
        assert!(resolve_content_length("Content-Length: 5, 5".lines()).is_err());
        assert!(resolve_content_length("Content-Length: 5, 7".lines()).is_err());
        assert!(resolve_content_length("Content-Length:  5 , 5 ".lines()).is_err());
        assert!(resolve_content_length("Content-Length: 5,5,5".lines()).is_err());
        // ... and identical list lines do not rescue the form.
        assert!(
            resolve_content_length("Content-Length: 5, 5\r\nContent-Length: 5, 5".lines()).is_err()
        );
        // Control bytes other than space/tab in the value are NOT trimmed
        // (textproto.isASCIISpace has no \x0b/\x0c; Go rejects them while
        // reading the head — round-3 review, audit round 8): a \x0b-wrapped
        // "5" survives to the digit parse and fails it.
        assert!(resolve_content_length("Content-Length: \x0b5".lines()).is_err());
        assert!(resolve_content_length("Content-Length: 5\x0c".lines()).is_err());
        // Non-numeric values are errors (Go 400 "bad Content-Length") —
        // including empty values (Go "invalid empty Content-Length") and
        // any sign (strconv.ParseUint accepts no sign, not even '+').
        assert!(resolve_content_length("Content-Length: abc".lines()).is_err());
        assert!(resolve_content_length("Content-Length:".lines()).is_err());
        assert!(resolve_content_length("Content-Length:   ".lines()).is_err());
        assert!(resolve_content_length("Content-Length: -5".lines()).is_err());
        assert!(resolve_content_length("Content-Length: +5".lines()).is_err());
        // 63-bit cap (Go ParseUint bitSize=63): 2^63-1 is the largest
        // accepted value; anything larger is an error even when it fits u64.
        assert_eq!(
            resolve_content_length("Content-Length: 9223372036854775807".lines()).unwrap(),
            Some(i64::MAX as usize)
        );
        assert!(resolve_content_length("Content-Length: 9223372036854775808".lines()).is_err());
        assert!(resolve_content_length("Content-Length: 9999999999999999999".lines()).is_err());
    }

    /// Drive `read_request_and_build_forward` over a duplex stream and
    /// return the forwarded head.
    async fn build_forward(
        raw_head: &[u8],
        request_headers: &std::collections::HashMap<String, String>,
        x_forwarded_for: Option<std::net::IpAddr>,
    ) -> String {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io.write_all(raw_head).await.unwrap();
        client_io.flush().await.unwrap();
        let fwd =
            read_request_and_build_forward(&mut server_io, "", request_headers, x_forwarded_for)
                .await
                .expect("forward build");
        fwd.head
    }

    fn xff_lines(head: &str) -> Vec<&str> {
        head.lines()
            .filter(|l| starts_with_ignore_ascii_case(l, "x-forwarded-for:"))
            .collect()
    }

    /// Audit round-9 B1 twin (http.rs `build_forward_head_chunked_post_is_
    /// http11`): the shared forward builder speaks HTTP/1.1 on the outbound
    /// leg — Go's http.DefaultTransport (the ReverseProxy backend of the
    /// http2http/http2https/https2http/https2https plugins, http2http.go)
    /// never writes HTTP/1.0 requests. Chunked bodies are the canary:
    /// chunked Transfer-Encoding is HTTP/1.1-only, so under the old
    /// HTTP/1.0 request line an origin saw neither TE nor CL and silently
    /// dropped the upload body. Pins the exact head bytes: request line,
    /// re-added chunked framing, `Connection: close` terminator. RED on the
    /// HTTP/1.0 request line (byte-exact compare fails).
    #[tokio::test]
    async fn build_forward_chunked_post_head_is_http11() {
        let head = build_forward(
            b"POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert_eq!(
            head,
            "POST /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            "byte-exact outbound head (chunked POST)"
        );

        // A Content-Length-framed request keeps its canonical CL line and
        // stays HTTP/1.1.
        let cl_head = build_forward(
            b"POST /p HTTP/1.1\r\nHost: b\r\nContent-Length: 3\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert_eq!(
            cl_head,
            "POST /p HTTP/1.1\r\nHost: b\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",
            "byte-exact outbound head (CL POST)"
        );
    }

    /// R5 pin: the https plugins (peer-present) append the tunnel peer to
    /// the INBOUND X-Forwarded-For chain — one canonical line, the chain
    /// preserved and extended (Go SetXForwarded semantics).
    #[tokio::test]
    async fn forward_xff_appends_peer_to_inbound_chain() {
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 1.2.3.4, 5.6.7.8\r\nUser-Agent: t\r\n\r\n",
            &Default::default(),
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        let lines = xff_lines(&head);
        assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
        assert_eq!(
            lines[0].trim(),
            "X-Forwarded-For: 1.2.3.4, 5.6.7.8, 203.0.113.9",
            "inbound chain preserved and peer appended"
        );
    }

    /// R5 pin: a configured X-Forwarded-For REPLACES the appended chain
    /// (peer + inbound) — one canonical line with the configured value only
    /// (Go Header.Set runs after SetXForwarded).
    #[tokio::test]
    async fn forward_configured_xff_replaces_chain() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Forwarded-For".to_string(), "cfg-value".to_string());
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 1.2.3.4, 5.6.7.8\r\n\r\n",
            &headers,
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        let lines = xff_lines(&head);
        assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
        assert_eq!(
            lines[0].trim(),
            "X-Forwarded-For: cfg-value",
            "configured value replaces the chain (no chain, no peer)"
        );
        assert!(
            !head.contains("1.2.3.4") && !head.contains("203.0.113.9"),
            "chain and peer must not leak alongside the configured value"
        );
    }

    /// R5 pin: the http2http/http2https plugins (peer absent) pass an
    /// inbound X-Forwarded-For through untouched — single line, verbatim.
    #[tokio::test]
    async fn forward_xff_passthrough_when_no_peer() {
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        let lines = xff_lines(&head);
        assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
        assert_eq!(
            lines[0].trim(),
            "X-Forwarded-For: 9.9.9.9",
            "inbound XFF passes through verbatim when no peer appends"
        );
    }

    /// R5 pin (divergence regression): a configured X-Forwarded-For in the
    /// no-peer plugins must STILL be exactly one header — Go Header.Set
    /// replaces the inbound value whether or not ReverseProxy later appends
    /// a peer. Pre-fix this emitted the configured value twice (once in the
    /// request_headers loop, once in the canonical tail) plus the inbound
    /// chain.
    #[tokio::test]
    async fn forward_configured_xff_single_line_without_peer() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Forwarded-For".to_string(), "cfg-value".to_string());
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: b\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
            &headers,
            None,
        )
        .await;
        let lines = xff_lines(&head);
        assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
        assert_eq!(
            lines[0].trim(),
            "X-Forwarded-For: cfg-value",
            "configured value is the only XFF line even without a peer"
        );
        assert!(
            !head.contains("1.2.3.4"),
            "inbound chain must not leak alongside the configured value"
        );
    }

    /// Audit round-7 S1 pin: an LF-only request head (request line + one
    /// header + LF blank line) terminates the read loop and builds the
    /// forward — Go http.ReadRequest/textproto semantics. RED pre-fix: the
    /// \r\n\r\n scan never matched, the loop read on and hit EOF once the
    /// writer half dropped ("connection closed"); the dropped writer makes
    /// the RED arm fail fast instead of stalling the 60 s per-read timeout.
    #[tokio::test]
    async fn forward_lf_only_head_terminates() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io
            .write_all(b"GET /p HTTP/1.1\nHost: b\nX-A: 1\n\n")
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        drop(client_io); // EOF after the buffered head drains
        let fwd = read_request_and_build_forward(&mut server_io, "", &Default::default(), None)
            .await
            .expect("LF-only head must end the head read, not EOF-error");
        assert!(
            fwd.head.starts_with("GET /p HTTP/1.1\r\n"),
            "forwarded head: {}",
            fwd.head
        );
        assert!(
            fwd.head.contains("X-A: 1\r\n"),
            "LF header line must be forwarded: {}",
            fwd.head
        );
        assert!(fwd.body_prefix.is_empty(), "no body bytes were pre-read");
    }

    /// Round-17 audit E pins (mod.rs sibling legs): Go parseTransferEncoding
    /// gates its whole read on protoAtLeast(1, 1) (transfer.go, Issue
    /// 12785) — the 1.0 ignore-arm and the >=1.1 reject-arm of this
    /// operator-local listener class. RED on pre-fix code: a garbage-TE
    /// 1.1 head was forwarded (TE stripped hop-by-hop, body CL-framed)
    /// where Go's http.Server faces answer their 501; a garbage-TE 1.0
    /// head reached the chunked-framing resolution where Go drops the
    /// header and reads a body-less request.
    #[tokio::test]
    async fn transfer_encoding_garbage_rejects_11_ignores_10() {
        use tokio::io::AsyncWriteExt;
        // HTTP/1.1 + non-chunked TE → Err (the sibling-face 501 class).
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io
            .write_all(b"GET /p HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: gzip\r\n\r\n")
            .await
            .unwrap();
        match read_request_and_build_forward(&mut server_io, "", &Default::default(), None).await {
            Err(e) => assert_eq!(e, "unsupported transfer encoding"),
            Ok(fwd) => panic!(
                "1.1 garbage TE must reject the read, forwarded: {}",
                fwd.head
            ),
        }
        // HTTP/1.0 + garbage TE → the header is ignored (Issue 12785):
        // the head forwards with the TE line dropped and no chunked
        // framing (CL resolution only — no CL header, no body expected).
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io
            .write_all(b"GET /p HTTP/1.0\r\nTransfer-Encoding: gzip\r\n\r\n")
            .await
            .unwrap();
        let fwd = read_request_and_build_forward(&mut server_io, "", &Default::default(), None)
            .await
            .expect("1.0 garbage Transfer-Encoding must be ignored, not rejected");
        assert!(
            !fwd.head.contains("Transfer-Encoding"),
            "the ignored TE header must be dropped from the forward: {}",
            fwd.head
        );
        assert!(
            !fwd.head.contains("chunked"),
            "1.0 framing must not resolve chunked: {}",
            fwd.head
        );
        assert!(fwd.body_prefix.is_empty(), "no body bytes were pre-read");
    }

    /// Audit round-8 F8 pin: a slowloris peer that drips ONE byte per 59 s
    /// never trips a per-read re-armed deadline (every byte resets the
    /// clock), but MUST be released by one absolute window over the whole
    /// head read (Go http.Server ReadHeaderTimeout = 60 s inside Go frp's
    /// http_proxy plugin). Paused time keeps the 300 s outer bound
    /// deterministic: RED (per-read re-arm) trips the OUTER timeout instead
    /// of the 60 s window; GREEN (single absolute window) returns
    /// "timed out reading request headers" at virtual t=60 s.
    #[tokio::test(start_paused = true)]
    async fn header_read_single_absolute_window_beats_trickle() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        // One byte per 59 s forever — the head never completes (no blank
        // line) and each byte would re-arm a per-read deadline.
        let trickle = tokio::spawn(async move {
            loop {
                if client_io.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(59)).await;
            }
        });
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            read_request_and_build_forward(&mut server_io, "", &Default::default(), None),
        )
        .await;
        drop(trickle);
        match res {
            Ok(Ok(_)) => panic!("a trickled, unterminated head must not build a forward"),
            Ok(Err(e)) => {
                assert_eq!(
                    e, "timed out reading request headers",
                    "the single absolute window must trip at 60 s"
                );
            }
            Err(_elapsed) => panic!(
                "per-read deadline re-arms on every byte: 1 B/59 s trickle beat the 60 s bound"
            ),
        }
    }

    /// Drive `read_request_and_build_forward` over a duplex stream and
    /// return the bytes the REJECTING side wrote before its Err (the F7
    /// render) plus the Err text. Reading the render back requires the
    /// writer half to drop first (duplex EOF), so the caller's Err borrow
    /// must be released before the read — the helper owns that order.
    async fn reject_bytes(raw_head: &[u8]) -> (Vec<u8>, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io.write_all(raw_head).await.unwrap();
        client_io.flush().await.unwrap();
        let err =
            match read_request_and_build_forward(&mut server_io, "", &Default::default(), None)
                .await
            {
                Ok(fwd) => panic!("head must be rejected, built forward: {}", fwd.head),
                Err(e) => e,
            };
        drop(server_io);
        let mut render = Vec::new();
        client_io.read_to_end(&mut render).await.unwrap();
        (render, err)
    }

    /// Round-17 audit F7: Go conn.readRequest gates on the http2http-family
    /// legs — every rejected class answers the byte-exact render Go's
    /// http.Server face writes on the same head (probe-verified against
    /// go1.25.12), instead of the old bare close.
    #[tokio::test]
    async fn f7_conn_gates_render_go_byte_exact_shapes() {
        // dup-Host fires inside package readRequest (before readTransfer):
        // plain error, no-detail 400.
        let (render, err) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_RENDER.as_bytes(),
            "dup-Host render must be the generic 400"
        );
        assert!(
            err.contains("too many Host headers"),
            "dup-Host Err must name the class, got: {err}"
        );
        // Same class through case-folded duplicate keys (canonical merge).
        let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: a\r\nHOST: b\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_RENDER.as_bytes(),
            "case-folded dup Host keys merge under one canonical key in Go"
        );
        // Missing Host on >=1.1 non-CONNECT, non-PRI heads: detailed 400
        // ("missing required Host header").
        let (render, err) = reject_bytes(b"GET /x HTTP/1.1\r\nUser-Agent: t\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_MISSING_HOST_RENDER.as_bytes(),
            "missing-Host must render the detailed 163B 400"
        );
        assert!(err.contains("missing required Host header"), "got: {err}");
        // Malformed Host value: detailed 149B (no version gate in Go).
        let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h/x\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_MALFORMED_HOST_RENDER.as_bytes(),
            "malformed-Host must render the detailed 149B 400"
        );
        // SPACE in a header NAME (issue 34540 noCanon survivor): detailed
        // 145B.
        let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h\r\nBad Name: y\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_INVALID_HEADER_NAME_RENDER.as_bytes(),
            "space-in-name must render the detailed 145B 400"
        );
        // CTL in a header VALUE: Go's detailed invalid-value conn gate is
        // UNREACHABLE (textproto errors at read) — the generic 400 answers.
        let (render, err) =
            reject_bytes(b"GET /x HTTP/1.1\r\nHost: h\r\nX-A: ok\x01bad\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_RENDER.as_bytes(),
            "CTL value byte dies at textproto read: generic 400, NOT the detailed arm"
        );
        assert!(err.contains("CTL byte in value"), "got: {err}");
        // Colonless header line: textproto missing-colon read error →
        // generic 400.
        let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\nHost: h\r\nNoColonHere\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_RENDER.as_bytes(),
            "colonless record renders the generic 400"
        );
        // Leading-SP first header line: "malformed MIME header initial
        // line" → generic 400.
        let (render, _) = reject_bytes(b"GET /x HTTP/1.1\r\n Bad\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_RENDER.as_bytes(),
            "initial-line leading whitespace renders the generic 400"
        );
        // Parseable non-1.x version (HTTP/2.0) past every read gate:
        // detailed 505 (http1ServerSupportsRequest).
        let (render, err) = reject_bytes(b"GET /x HTTP/2.0\r\nHost: h\r\n\r\n").await;
        assert_eq!(
            render,
            http::GO_505_RENDER.as_bytes(),
            "HTTP/2.0 head must render the detailed 505"
        );
        assert!(err.contains("unsupported protocol version"), "got: {err}");
        // PRI * HTTP/2.0 WITH headers and no Host is NOT the h2-upgrade
        // zero-header exemption: missing-Host fires.
        let (render, _) = reject_bytes(b"PRI * HTTP/2.0\r\nX-A: b\r\n\r\n").await;
        assert_eq!(
            render,
            GO_400_MISSING_HOST_RENDER.as_bytes(),
            "PRI-with-headers has no missing-Host exemption"
        );
    }

    /// Round-17 audit F7 rows that must still FORWARD (Go serves them):
    /// HTTP/1.0 has no Host requirement, CONNECT is exempt from the
    /// missing-Host gate, and the h2c-preface "PRI * HTTP/2.0" zero-header
    /// head clears every gate (its scheme-500 fate is decided later, at
    /// the handler — as in Go, where the request is served to the handler
    /// and the plugin's RoundTrip errors on the empty scheme).
    #[tokio::test]
    async fn f7_gates_spare_served_classes() {
        // HTTP/1.0 without Host: protoAtLeast(1,1) false — no gate.
        let head = build_forward(b"GET /x HTTP/1.0\r\n\r\n", &Default::default(), None).await;
        assert!(
            head.starts_with("GET /x HTTP/1.1"),
            "1.0 head forwards: {head}"
        );
        // HTTP/1.0 ignores Transfer-Encoding (Issue 12785).
        let head = build_forward(
            b"GET /x HTTP/1.0\r\nTransfer-Encoding: gzip\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert!(
            head.starts_with("GET /x HTTP/1.1"),
            "1.0 TE head forwards: {head}"
        );
        // CONNECT heads are exempt from the missing-Host gate.
        let head = build_forward(b"CONNECT h:80 HTTP/1.1\r\n\r\n", &Default::default(), None).await;
        assert!(
            head.starts_with("CONNECT h:80 HTTP/1.1"),
            "CONNECT no-Host forwards: {head}"
        );
        // The h2c preface: zero headers → isH2Upgrade → the missing-Host
        // gate skips it (only the malformed/name gates could catch it).
        let head = build_forward(b"PRI * HTTP/2.0\r\n\r\n", &Default::default(), None).await;
        assert!(
            head.starts_with("PRI * HTTP/1.1"),
            "zero-header PRI * HTTP/2.0 clears the conn gates (outbound line always 1.1): {head}"
        );
        // An empty Host VALUE passes Go's ValidHostHeader (empty is legal)
        // — forwarded, not 400'd.
        let head = build_forward(
            b"GET /x HTTP/1.1\r\nHost: \r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert!(
            head.starts_with("GET /x HTTP/1.1"),
            "empty Host value forwards: {head}"
        );
        // HTAB inside a header value is legal (only CTL < 0x20 minus HTAB
        // dies at read).
        let head = build_forward(
            b"GET /x HTTP/1.1\r\nHost: h\r\nX-A: y \tz\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert!(
            head.starts_with("GET /x HTTP/1.1"),
            "HTAB in value forwards: {head}"
        );
    }

    /// Round-17 audit F7: `walk_leg_head` textproto-shape facts feeding
    /// the gates — Host record counting (incl. fold continuation joining
    /// and case-folded keys), value shape, and every read-time error
    /// class the generic 400 render answers.
    #[test]
    fn f7_walk_leg_head_textproto_shapes() {
        // Host line + a folded header: the fold joins X-A's value with one
        // space; Host counts once with the TrimLeft'd value.
        let w = walk_leg_head("GET / HTTP/1.1\r\nX-A: b\r\n \t c\r\nHost:  h\r\n\r\n").unwrap();
        assert_eq!(w.header_groups, 2, "two records, got: {w:?}");
        assert_eq!(w.host_groups, 1, "one Host record, got: {w:?}");
        assert_eq!(
            w.host_value.as_deref(),
            Some("h"),
            "Host value TrimLeft'd, got: {w:?}"
        );
        // Case-folded keys are one canonical Host (Go lowercases at read).
        let w = walk_leg_head("GET / HTTP/1.1\r\nHOST: a\r\nhost: b\r\n\r\n").unwrap();
        assert_eq!(w.host_groups, 2, "two canonical-Host records, got: {w:?}");
        assert_eq!(
            w.host_value.as_deref(),
            Some("a"),
            "first Host value wins, got: {w:?}"
        );
        // SPACE in a key sets the flag but is not a read error.
        let w = walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nBad Name: y\r\n\r\n").unwrap();
        assert!(w.name_has_space, "space key survives the read, got: {w:?}");
        assert_eq!(w.host_groups, 1);
        // "Host " (trailing space) is NOT the Host key — canonical merge
        // keeps it separate.
        let w = walk_leg_head("GET / HTTP/1.1\r\nHost : h\r\n\r\n").unwrap();
        assert_eq!(w.host_groups, 0, "'Host ' never canonicalizes to Host");
        assert!(w.name_has_space);
        // A space-only line between records is an obs-fold continuation
        // of the OPEN record — it never starts a record, and it joins
        // with a ' ' that survives (reader.go appends the join space
        // before trimming the piece): Host "h" + " \t " folds to stored
        // "h ", which the consumer's ValidHostHeader gate rejects (the
        // 149B malformed-Host render). The round-17 code skipped
        // empty-piece folds and stored "h" (served/forwarded).
        let w = walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\n \t \r\nX-A: b\r\n\r\n").unwrap();
        assert_eq!(w.header_groups, 2);
        assert_eq!(
            w.host_value.as_deref(),
            Some("h "),
            "all-WS fold appends the join space, got: {w:?}"
        );
        // PR-review R1 pin: "Host: b" + a single all-whitespace fold
        // (" ") — stored "b " (space join unconditional, not "b").
        let w = walk_leg_head("GET / HTTP/1.1\r\nHost: b\r\n \r\n\r\n").unwrap();
        assert_eq!(
            w.host_value.as_deref(),
            Some("b "),
            "single-space fold appends the join space, got: {w:?}"
        );
        // Read-time error classes (each answers the generic 400 e2e).
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\n Bad\r\n\r\n").is_err(),
            "initial-line fold"
        );
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\nNoColon\r\n\r\n").is_err(),
            "colonless"
        );
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\n: v\r\n\r\n").is_err(),
            "empty key"
        );
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\nX-B\x01d: v\r\n\r\n").is_err(),
            "CTL in key"
        );
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: ok\x01bad\r\n\r\n").is_err(),
            "CTL in value"
        );
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: v\x7fz\r\n\r\n").is_err(),
            "DEL in value"
        );
        // Leading CTL in a value errors too (Go validates the raw
        // post-colon bytes before TrimLeft).
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: \x01v\r\n\r\n").is_err(),
            "leading CTL in value"
        );
        // Folded content is CTL-scanned.
        assert!(
            walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: b\r\n \x01c\r\n\r\n").is_err(),
            "CTL in folded piece"
        );
        // HTAB is legal in values; the head-terminator "" and whitespace
        // lines never count as records.
        let w = walk_leg_head("GET / HTTP/1.1\r\nHost: h\r\nX-A: y \tz\r\n\r\n").unwrap();
        assert_eq!(w.header_groups, 2);
        assert_eq!(w.host_groups, 1);
    }

    /// Round-18 audit L2 pin: an obs-fold under a STRIPPED hop-by-hop
    /// record must be swallowed with it — never emitted as a bare line
    /// that obs-folds onto the preceding EMITTED record at the backend
    /// (worst case appending " folded" to the "Host:" line that follows
    /// the stripped Proxy-Authorization in Go's canonical head order).
    /// RED on the pre-fix loop: the fold re-emitted raw, byte-exact
    /// compare fails with "Host: a folded".
    #[tokio::test]
    async fn l2_hop_stripped_record_fold_swallowed() {
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: a\r\nProxy-Authorization: secret\r\n \tfolded\r\nUser-Agent: t\r\n\r\n",
            &Default::default(),
            None,
        )
        .await;
        assert_eq!(
            head, "GET /p HTTP/1.1\r\nHost: a\r\nUser-Agent: t\r\nConnection: close\r\n\r\n",
            "stripped hop record AND its fold must vanish from the forwarded head"
        );
    }

    /// Round-18 audit L2 pin, request_headers-override arm: a fold under a
    /// record that request_headers will REPLACE (Go Header.Set replaces
    /// the whole record, folded value included) must be swallowed too —
    /// the pre-fix loop emitted it as an orphan line that obs-folded onto
    /// whatever the override re-injection emitted above it.
    #[tokio::test]
    async fn l2_overridden_record_fold_swallowed() {
        let mut request_headers = std::collections::HashMap::new();
        request_headers.insert("x-a".to_string(), "2".to_string());
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: a\r\nX-A: 1\r\n folded\r\n\r\n",
            &request_headers,
            None,
        )
        .await;
        assert_eq!(
            head, "GET /p HTTP/1.1\r\nHost: a\r\nx-a: 2\r\nConnection: close\r\n\r\n",
            "overridden record's fold must vanish; only the injected value reaches the backend"
        );
    }

    /// Round-18 audit L3 pin (server-side vhost mirror: vhost.rs round-13
    /// empty-XFF pin): an EMPTY-value X-Forwarded-For row is a real chain
    /// element — Go `strings.Join(prior, ", ")` (reverseproxy.go
    /// setXForwarded) keeps empty elements, so a sole empty row emits
    /// ", {peer}" with the leading comma. The old ASCII-trim +
    /// non-empty gate dropped the row and emitted a bare peer line.
    #[tokio::test]
    async fn l3_empty_xff_row_kept_in_chain() {
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: \r\nUser-Agent: t\r\n\r\n",
            &Default::default(),
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        let lines = xff_lines(&head);
        assert_eq!(lines.len(), 1, "exactly one XFF line, got: {lines:?}");
        assert_eq!(
            lines[0], "X-Forwarded-For: , 203.0.113.9",
            "empty row contributes an empty chain element (leading comma)"
        );
    }

    /// Round-18 audit L3 pin: obs-fold continuations are part of their
    /// row's STORED value (Go textproto joins ' ' + trimmed piece), so an
    /// inbound folded XFF row must merge into one chain element, then join
    /// the following rows — `1.2.3.4 5.6.7.8, 9.9.9.9, {peer}`.
    #[tokio::test]
    async fn l3_xff_fold_merges_into_row_value() {
        let head = build_forward(
            b"GET /p HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.4\r\n 5.6.7.8\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
            &Default::default(),
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        let lines = xff_lines(&head);
        assert_eq!(
            lines.len(),
            1,
            "exactly one canonical XFF line, got: {lines:?}"
        );
        assert_eq!(
            lines[0], "X-Forwarded-For: 1.2.3.4 5.6.7.8, 9.9.9.9, 203.0.113.9",
            "fold merges into its row's value with a single space; rows join with ', '"
        );
    }
}
