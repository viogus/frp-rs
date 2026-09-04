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

/// Result of the http_proxy basic-auth check.
///
/// Go frp http_proxy.go `Auth()` semantics: a header that fails to parse
/// into a user:pass pair rejects instantly; only a decoded pair that fails
/// the constant-time compare triggers the 200 ms anti-brute-force delay (the
/// sleep sits inside `Auth()` at the compare, below the shape failures).
pub enum AuthVerdict {
    Accept,
    RejectInstant,
    RejectDelayed,
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

    /// static_file (Go `NewHTTPAuthMiddleware` → net/http `r.BasicAuth()`):
    /// case-insensitive `Basic ` prefix gate (Go Issue 22736 does
    /// ascii.EqualFold on the prefix), then decode + compare. The middleware
    /// sleeps on EVERY reject when credentials are configured, so this bool
    /// shape (used by static_file.rs, which owns its delay) is enough.
    pub fn check(&self, header: &str) -> bool {
        match (self.user.as_deref(), self.password.as_deref()) {
            // No auth configured — accept all connections
            (None, None) => true,
            // Both configured — require both to match
            (Some(expected_user), Some(expected_pass)) => {
                let b = header.as_bytes();
                if b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"basic ") {
                    if let Ok(decoded) = base64_decode(&header[6..]) {
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

    /// http_proxy plugin (`http_proxy.go` `Auth()`): Go splits the header on
    /// the FIRST space and decodes the payload WITHOUT checking the scheme
    /// token — `SplitN(header, " ", 2)` never compares `s[0]` against
    /// "Basic". Shape failures (no space, undecodable payload, no `:` in the
    /// pair) return `RejectInstant`; a compare failure returns
    /// `RejectDelayed` (Go sleeps 200 ms exactly there).
    pub fn classify_proxy_auth(&self, header: &str) -> AuthVerdict {
        match (self.user.as_deref(), self.password.as_deref()) {
            (None, None) => AuthVerdict::Accept,
            (Some(expected_user), Some(expected_pass)) => {
                let Some((_scheme, payload)) = header.split_once(' ') else {
                    return AuthVerdict::RejectInstant;
                };
                let Ok(decoded) = base64_decode(payload) else {
                    return AuthVerdict::RejectInstant;
                };
                let Some((user, pass)) = decoded.split_once(':') else {
                    return AuthVerdict::RejectInstant;
                };
                let user_ok = frp_core::auth::constant_time_eq_str(user, expected_user);
                let pass_ok = frp_core::auth::constant_time_eq_str(pass, expected_pass);
                if user_ok & pass_ok {
                    AuthVerdict::Accept
                } else {
                    AuthVerdict::RejectDelayed
                }
            }
            // Partially configured — config error at load; reject instantly.
            (Some(_), None) | (None, Some(_)) => AuthVerdict::RejectInstant,
        }
    }
}

async fn handle_http_proxy_conn(mut client: TcpStream, auth: HttpProxyAuth) -> Result<(), String> {
    // Read headers in chunks until \r\n\r\n. Stop at the FIRST \r\n\r\n
    // anywhere in the buffer (not only at its end): with a request body the
    // head terminator is followed by body bytes, and reading past it would
    // swallow the body into the "headers" until the 64 KiB cap.
    // Go parity: http.Server ReadHeaderTimeout (60s) — one absolute deadline
    // over the whole header read, so a slowloris "trickle" cannot park the
    // task + fd + plugin listener slot indefinitely.
    let buf = tokio::time::timeout(Duration::from_secs(60), async {
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
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 65536 {
                return Err("request headers too large".into());
            }
        }
        Ok::<Vec<u8>, String>(buf)
    })
    .await
    .map_err(|_| "read headers timed out".to_string())??;

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
            if key.trim().eq_ignore_ascii_case("proxy-authorization") {
                proxy_auth = value.trim().to_string();
            }
        }
    }

    // Check auth. Response arms verified byte-for-byte against Go v0.71.0
    // (probe): CONNECT failures go through handleConnectReq →
    // getBadResponse — status TEXT "Not authorized" (Go's custom Status
    // field, not the standard reason) + `Connection: close`; plain-request
    // failures go through net/http ServeHTTP — standard status text, no
    // Connection header (Go keeps the conn reusable; frp-rs serves one
    // request per tunnel conn and closes after — response bytes identical).
    // Both arms send `Proxy-Authenticate: Basic` with no realm. Go's `Date`
    // header comes from net/http and is omitted here like every other
    // frp-rs manual response writer.
    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    match auth.classify_proxy_auth(&proxy_auth) {
        AuthVerdict::Accept => {}
        verdict => {
            if matches!(verdict, AuthVerdict::RejectDelayed) {
                // Go frp http_proxy.go Auth(): 200ms delay only when a
                // decoded user:pass pair fails the compare (shape failures
                // answer instantly — no sleep below the early returns).
                sleep(Duration::from_millis(200)).await;
            }
            let resp: &'static [u8] = if is_connect {
                b"HTTP/1.1 407 Not authorized\r\nConnection: close\r\n\
                  Proxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
            } else {
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
            };
            if let Err(e) = client.write_all(resp).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err("auth failed".into());
        }
    }

    // Case-insensitive CONNECT match: Go frp http_proxy.go uses
    // strings.EqualFold(string(firstBytes), http.MethodConnect) — a
    // lowercase "connect" is accepted.
    if is_connect {
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

    let mut remote = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            // Go frp http_proxy.go CONNECT arm: dial failure answers the
            // client with HTTP/1.1 400 + Connection: close (the proxy is
            // about to drop the connection), instead of closing silently.
            let resp =
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            if let Err(we) = client.write_all(resp).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("connect to {target}: {e}"));
        }
    };
    frp_core::transport::set_nodelay(&remote);

    // Tell client connection established. Phrase parity: Go frp writes
    // "HTTP/1.1 200 OK" on CONNECT success (pkg/plugin/client/http_proxy.go
    // httpProxy.go:188 `resp.Status = "200 OK"`) — not the conventional
    // "200 Connection Established".
    let resp = b"HTTP/1.1 200 OK\r\n\r\n";
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

    // Build forwarded request: rewrite request line, strip hop-by-hop and
    // proxy headers (Go removeProxyHeaders: Connection, Proxy-Connection,
    // Keep-Alive, Proxy-Authorization, Proxy-Authenticate, TE, Trailer(s),
    // Transfer-Encoding, Upgrade; Expect is stripped too — the plugin
    // cannot relay the interim 100-continue response, and a strict client
    // that gates its body-send on it would deadlock against the body read,
    // RFC 7231 §5.1.1), add Connection: close.
    let headers_str = String::from_utf8_lossy(header_bytes);
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
    let mut header_lines: Vec<&str> = headers_str.lines().skip(1).collect();
    // Body framing is parsed from the original headers — Transfer-Encoding
    // is stripped below as hop-by-hop and re-added only when chunked.
    let framing = super::parse_request_body_framing(headers_str.lines().skip(1));
    // Content-Length is resolved per RFC 7230 §3.3.2 ("reject or replace
    // with a single value"): duplicate identical values collapse to one
    // line, list-form values ("5, 5") sum, and conflicting values make the
    // request framing invalid — reject (the connection closes).
    let content_length = super::resolve_content_length(headers_str.lines().skip(1))?;
    header_lines.retain(|line| {
        // Skip the head's trailing blank line(s) too: lines() yields "" for
        // the \r\n\r\n terminator, and forwarding it would terminate the
        // head early, pushing `Connection: close` into the body.
        // Round-17 audit E: zero-alloc ASCII case-insensitive prefix scan
        // (was a per-line lowercase String).
        if line.is_empty()
            || hop_by_hop
                .iter()
                .any(|h| super::starts_with_ignore_ascii_case(line, h))
        {
            return false;
        }
        // Drop every original Content-Length line: when chunked per RFC
        // 7230 §3.3.3, or when a usable Content-Length was resolved — all
        // CL lines are then replaced by a single canonical line appended
        // after the loop (RFC 7230 §3.3.2; forwarding duplicate/conflicting
        // values would desync the backend).
        if super::starts_with_ignore_ascii_case(line, "content-length:")
            && (framing == Some(super::BodyFraming::Chunked) || content_length.is_some())
        {
            return false;
        }
        true
    });

    let mut fwd = Vec::new();
    fwd.extend_from_slice(format!("{method} {path} HTTP/1.0\r\n").as_bytes());
    for line in &header_lines {
        // Strip CR/LF from forwarded header lines: `lines()` splits only on
        // `\n`, so a lone `\r` inside a header line (malformed client) would
        // otherwise survive into the forwarded request as an injected line
        // (request-smuggling shape). Same policy as read_request_and_build_
        // forward and the h2 path, which reject CR/LF outright. Round-17
        // audit E: `lines()` already strips the trailing CRLF, so the common
        // path (no mid-line `\r`) appends the slice directly, no String.
        if line.contains(['\r', '\n']) {
            let safe_line: String = line.chars().filter(|&c| c != '\r' && c != '\n').collect();
            fwd.extend_from_slice(safe_line.as_bytes());
        } else {
            fwd.extend_from_slice(line.as_bytes());
        }
        fwd.extend_from_slice(b"\r\n");
    }
    if framing == Some(super::BodyFraming::Chunked) {
        fwd.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = content_length {
        // Exactly one Content-Length line (RFC 7230 §3.3.2), matching the
        // byte count the body forward will stream.
        fwd.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    fwd.extend_from_slice(b"Connection: close\r\n\r\n");

    remote
        .write_all(&fwd)
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Stream the request body (pre-read bytes plus the rest per its framing)
    // before relaying the response — Go's http.DefaultTransport streams it,
    // and a backend that waits for the full request would stall otherwise.
    // A body-forward error must NOT drop the connection: backends reply early
    // without reading the full request (e.g. nginx's 413 client_max_body_size),
    // and Go's Transport still delivers those responses.
    if let Err(e) =
        super::forward_request_body(&mut client, &mut remote, body_bytes, framing, method).await
    {
        tracing::debug!(error = %e, "request body forward failed, relaying response anyway: {}", e);
    }

    // Copy response back to client
    if let Err(e) = super::copy_stream_large(remote, &mut client).await {
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

    fn auth(user: &str, pass: &str) -> HttpProxyAuth {
        HttpProxyAuth {
            user: Some(user.into()),
            password: Some(pass.into()),
        }
    }

    fn b64(s: &str) -> String {
        frp_core::base64::encode(s.as_bytes())
    }

    fn basic(u: &str, p: &str) -> String {
        format!("Basic {}", b64(&format!("{u}:{p}")))
    }

    /// Go http_proxy.go `Auth()` verdict matrix (source + probe-verified):
    /// shape failures reject INSTANTLY; only a decoded pair failing the
    /// compare delays 200 ms; the scheme token is never inspected (SplitN
    /// decodes `s[1]` unconditionally — "Bearer <b64>" with valid creds is
    /// ACCEPTED by Go frp).
    #[test]
    fn test_classify_proxy_auth_go_verdict_matrix() {
        let a = auth("u1", "p1");
        // Valid creds — accepted with the canonical Basic scheme.
        assert!(matches!(
            a.classify_proxy_auth(&basic("u1", "p1")),
            AuthVerdict::Accept
        ));
        // Go ignores the scheme token entirely: a Bearer-spelled header with
        // valid creds passes (http_proxy.go Auth() never checks s[0]).
        assert!(matches!(
            a.classify_proxy_auth(&format!("Bearer {}", b64("u1:p1"))),
            AuthVerdict::Accept
        ));
        // Wrong creds — the only DELAYED verdict (Go's 200ms sleep sits in
        // Auth() after the shape gates, at the compare).
        assert!(matches!(
            a.classify_proxy_auth(&basic("u1", "zz")),
            AuthVerdict::RejectDelayed
        ));
        // Shape failures — instant (Go returns before the sleep line).
        assert!(matches!(
            a.classify_proxy_auth(""),
            AuthVerdict::RejectInstant
        )); // no header
        assert!(matches!(
            a.classify_proxy_auth("Basic"),
            AuthVerdict::RejectInstant
        )); // no space -> SplitN len 1
        assert!(matches!(
            a.classify_proxy_auth(&format!("Basic {}", b64("no-colon"))),
            AuthVerdict::RejectInstant // decoded pair has no colon
        ));
        assert!(matches!(
            a.classify_proxy_auth("Basic notbase64!!!"),
            AuthVerdict::RejectInstant // undecodable payload
        ));
        assert!(matches!(
            a.classify_proxy_auth("Basic  dTE6cDE="),
            AuthVerdict::RejectInstant // double space -> payload has a leading space, decode fails
        ));
        // Unconfigured accepts everything; partial config is a load-time
        // error -> reject.
        assert!(matches!(
            HttpProxyAuth {
                user: None,
                password: None
            }
            .classify_proxy_auth(""),
            AuthVerdict::Accept
        ));
        assert!(matches!(
            HttpProxyAuth {
                user: Some("u".into()),
                password: None
            }
            .classify_proxy_auth(""),
            AuthVerdict::RejectInstant
        ));
    }

    /// static_file middleware parity: the `Basic ` prefix gate is
    /// case-insensitive (Go net/http parseBasicAuth, Issue 22736:
    /// ascii.EqualFold on the prefix) — lowercase "basic " must pass the
    /// shape check and reach the credential compare.
    #[test]
    fn test_check_static_file_basic_prefix_case_insensitive() {
        let a = auth("admin", "s3cret");
        let lower = format!("basic {}", b64("admin:s3cret"));
        assert!(
            a.check(&lower),
            "Go EqualFold prefix: lowercase basic accepted"
        );
        assert!(
            a.check(&basic("admin", "s3cret")),
            "canonical form accepted"
        );
        assert!(!a.check(&basic("admin", "wrong")), "wrong creds rejected");
        // No prefix at all -> reject (std BasicAuth requires the scheme).
        assert!(
            !a.check(&b64("admin:s3cret")),
            "scheme-less header rejected"
        );
    }
}
