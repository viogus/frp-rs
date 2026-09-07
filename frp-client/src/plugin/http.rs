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
    // Read the request head in chunks. Head end follows Go textproto
    // semantics (the engine behind http.ReadRequest): each line ends at the
    // next '\n' with ONE trailing '\r' stripped, and the first empty line
    // ends the head — so LF-only and mixed-EOL heads are legal, not just
    // \r\n\r\n. Stop at the first empty line anywhere in the buffer (not
    // only at its end): with a request body the head terminator is followed
    // by body bytes, and reading past it would swallow the body into the
    // "headers" until the cap.
    // Go parity: http.Server ReadHeaderTimeout (60s) — one absolute deadline
    // over the whole header read, so a slowloris "trickle" cannot park the
    // task + fd + plugin listener slot indefinitely (audit round-8 F8; the
    // shared const PLUGIN_HEADER_READ_TIMEOUT has the same absolute-window
    // semantics).
    // The 1 MiB cap below is Go's http.Server MaxHeaderBytes DEFAULT on the
    // PLAIN arm (audit: the old 64 KiB cap rejected request heads Go serves
    // — 100+ KiB Cookie or Authorization headers are legal HTTP). On the
    // CONNECT arm it is a fail-closed Rust-only divergence: frp http_proxy
    // sniffs the method prefix and then calls http.ReadRequest directly,
    // which has NO size cap (bounded only by the ReadHeaderTimeout window).
    // The sniff runs after this read loop, so the cap cannot know the arm
    // yet — a breach is not a read error: the buffer is carried back so the
    // arm classification below can answer 431 on the plain arm the way Go's
    // server would (it errors the read itself and writes the render BEFORE
    // the handler — http_proxy.go's plain arm never sees the giant head at
    // all), while the CONNECT arm closes silently (see the arm notes below).
    enum HeadRead {
        Done(Vec<u8>),
        TooLarge(Vec<u8>),
    }
    let head = tokio::time::timeout(super::PLUGIN_HEADER_READ_TIMEOUT, async {
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
            if frp_core::textproto::head_end(&buf).is_some() {
                break;
            }
            if buf.len() > 1024 * 1024 {
                return Ok(HeadRead::TooLarge(buf));
            }
        }
        Ok::<HeadRead, String>(HeadRead::Done(buf))
    })
    .await
    .map_err(|_| "read headers timed out".to_string())??;
    let (buf, head_too_large) = match head {
        HeadRead::Done(buf) => (buf, false),
        HeadRead::TooLarge(buf) => (buf, true),
    };

    // Arm classification: Go frp http_proxy.go reads the FIRST 7 stream
    // bytes (io.ReadFull) and EqualFolds them against "CONNECT" BEFORE any
    // head parsing — the sniff, not the parse outcome, picks the failure
    // behavior of everything downstream:
    //   - CONNECT arm (sniff true): http.ReadRequest errors close silently
    //     — the handler has no response writer for a head it never parsed.
    //     Go-parity for EOF / deadline / malformed heads. For the 1 MiB cap
    //     this arm is NOT Go parity (Go's ReadRequest is uncapped): the
    //     silent close on a too-large CONNECT head is deliberate fail-closed
    //     hardening on this operator-local 127.0.0.1 listener surface — Go
    //     would read on until the 60s window or a body-less head end.
    //   - Plain arm (sniff false): the head goes through PutConn into the
    //     http.Server, which renders its own error (400 malformed request,
    //     431 header block over the cap) before ServeHTTP ever runs.
    //   - Fewer than 7 bytes at the head read: ReadFull fails (EOF or the
    //     60s deadline) → silent close, both arms.
    let is_connect = super::head_starts_connect(&buf);
    let head_short = buf.len() < 7;

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line: METHOD URL HTTP/1.x. Strict Go parseRequestLine
    // semantics via the shared helper (literal-space splitn(3), every part
    // non-empty, request-side Go ParseHTTPVersion semantics restricted to
    // major 1 — see plugin/mod.rs `parse_request_line`; the version gate is
    // the request-side form because the frps vhost front has already
    // 505-gated every request it forwards, so only HTTP/1.x tokens can
    // reach this plugin, and Go serves/tunnels every parseable 1.x
    // (HTTP/1.2..1.9 included). The old split_whitespace collapsed every
    // whitespace run, so tab-joined tokens parsed and the request was
    // dialed/forwarded — accept-where-Go-rejects.
    // A failed head (malformed line, or a too-large block whose line never
    // gets validated — Go's server trips the cap before reading further)
    // renders Go's server error on the plain arm, then closes. Silent arms
    // (CONNECT sniff / fewer than 7 bytes, mirroring ReadFull) close
    // without a byte. TooLarge heads skip the parse entirely (the line may
    // even be valid — the CAP is the error, 431 either way).
    let mut parsed_line = None;
    if !head_too_large {
        parsed_line = lines.next().and_then(super::parse_request_line);
    }
    let (method, url) = match parsed_line {
        Some((m, u, _)) => (m, u),
        None => {
            if !is_connect && !head_short {
                let render = if head_too_large {
                    super::GO_431_RENDER
                } else {
                    super::GO_400_RENDER
                };
                if let Err(e) = client.write_all(render.as_bytes()).await {
                    tracing::debug!(error = %e, "plugin relay error: {}", e);
                }
            }
            return Err("bad request line".into());
        }
    };

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
    let remote = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            // Go frp http_proxy.go handleConnectReq dial-failure arm: it
            // writes a bare http.Response{StatusCode: 400}.Write — probed
            // against Go frp v0.71.0: byte-exactly "HTTP/1.1 400 Bad
            // Request\r\nContent-Length: 0\r\n\r\n". NO Connection header
            // (Connection: close belongs to the 407 getBadResponse arm
            // only), no body. The round-13-era writer here added a
            // spurious "Connection: close" the Go raw response does not
            // carry.
            // Audit: the ":443" default-append is GONE — Go dials
            // `req.URL.Host` as-is (http_proxy.go handleConnectReq
            // net.Dial("tcp", r.Host)) and a port-less host is a DIAL
            // failure ("missing port in address"), so the request lands in
            // this same 400 arm. Appending :443 made "CONNECT example.com"
            // dial example.com:443 where Go answers 400.
            let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
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

    // Bidirectional relay through pooled buffers (audit round-8 P1: the
    // copy_bidirectional_with_sizes pair of fresh buffers per conn is gone;
    // relay_plain_pooled has identical FIN-propagation semantics).
    if let Err(e) = frp_core::bridge::relay_plain_pooled(client, remote).await {
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

    let mut remote = match TcpStream::connect(format!("{host}:{port}")).await {
        Ok(s) => s,
        Err(e) => {
            // Go frp http_proxy.go HTTPHandler dial-failure arm:
            // http.Error(rw, err.Error(), http.StatusInternalServerError)
            // — probed against Go frp v0.71.0 (backend = refused port):
            // "HTTP/1.1 500 Internal Server Error\r\nContent-Type:
            // text/plain; charset=utf-8\r\nX-Content-Type-Options:
            // nosniff\r\nDate: ...\r\nContent-Length: N\r\nConnection:
            // close\r\n\r\n<dial error text>\n". Go adds Connection: close
            // whenever the connection closes after the response; frp-rs
            // serves exactly one request per tunnel conn and closes after
            // every response, so the header is always truthful and written
            // unconditionally. Date is omitted like every other frp-rs
            // manual response writer; the body is the std dial error
            // Display text + '\n' (Go fmt.Fprintln), with the real
            // Content-Length. The old code closed the conn with ZERO
            // bytes — a refused backend was indistinguishable from a
            // vanished proxy.
            let body = format!("{e}\n");
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(we) = client.write_all(resp.as_bytes()).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("connect to {host}:{port}: {e}"));
        }
    };
    frp_core::transport::set_nodelay(&remote);

    // Split the head from any pre-read body data at the first empty line
    // (Go textproto semantics — the same helper the read loop above used,
    // so the split lands exactly where the loop stopped; for CRLF input the
    // index is byte-identical to the old \r\n\r\n scan).
    let header_end = frp_core::textproto::head_end(raw_headers).unwrap_or(raw_headers.len());
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
    // with a single value") under Go fixLength/parseContentLength
    // semantics: duplicate identical values collapse to one line, while
    // list-form values ("5, 5"), non-decimal values, and conflicting
    // values make the request framing invalid — reject (the connection
    // closes). Resolution runs UNCONDITIONALLY, chunked requests included:
    // Go probes the CL values even when chunked wins the framing — probed
    // against the Go frp v0.71.0-era stdlib (go1.25.12): chunked + "5, 5",
    // chunked + "5x", and chunked + conflicting values all 400, while a
    // chunked + valid "5" is accepted and the header deleted. The retain
    // gate below drops every Content-Length line on chunked requests and
    // the canonical-line append keys on `framing != Chunked`, so a valid
    // resolution is never forwarded under chunked — matching Go's delete.
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

    let fwd = build_forward_head(method, &path, &header_lines, framing, content_length);

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

/// Build the outbound request head for the forward path. The request line is
/// HTTP/1.1 — Go's http.DefaultTransport (http_proxy.go HTTPHandler path)
/// never writes HTTP/1.0 requests. The old HTTP/1.0 line silently dropped
/// chunked upload bodies: chunked Transfer-Encoding is HTTP/1.1-only, so an
/// origin that parses the request as 1.0 sees neither Transfer-Encoding nor
/// Content-Length and treats the body as empty. `Connection: close` is kept
/// (Go sends close whenever the connection closes after the response; this
/// plugin serves one request per tunnel conn and closes — the origin then
/// answers without keep-alive framing). Header lines arrive pre-filtered
/// (hop-by-hop stripped, Content-Length lines dropped when chunked or a
/// usable resolution exists); body framing is appended as one canonical line
/// per RFC 7230 §3.3.2/§3.3.3. Extracted from handle_http_forward for a
/// byte-exact unit pin (chunked POST head starts `POST <path> HTTP/1.1`,
/// carries the chunked framing line, ends `Connection: close\r\n\r\n`).
fn build_forward_head(
    method: &str,
    path: &str,
    header_lines: &[&str],
    framing: Option<super::BodyFraming>,
    content_length: Option<usize>,
) -> Vec<u8> {
    let mut fwd = Vec::new();
    fwd.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for line in header_lines {
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
    fwd
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

    /// The version-gate matrix moved to plugin/mod.rs with the shared
    /// `parse_request_line` helper (test_go_parse_http_version_ok_matrix
    /// lives next to it there).

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

    /// B1: the outbound forward head speaks HTTP/1.1 — Go's
    /// http.DefaultTransport (http_proxy.go HTTPHandler) never writes
    /// HTTP/1.0 requests. Chunked bodies are the canary: chunked
    /// Transfer-Encoding is HTTP/1.1-only, so under the old HTTP/1.0
    /// request line an origin saw neither TE nor CL and silently dropped
    /// the upload body. Pins the exact head bytes.
    #[test]
    fn build_forward_head_chunked_post_is_http11() {
        let lines = [
            "Host: 127.0.0.1:8080",
            "Content-Type: application/octet-stream",
        ];
        let head = build_forward_head(
            "POST",
            "/up",
            &lines,
            Some(crate::plugin::BodyFraming::Chunked),
            None,
        );
        let head = String::from_utf8(head).unwrap();
        assert!(
            head.starts_with("POST /up HTTP/1.1\r\n"),
            "outbound request line must be HTTP/1.1: {head:?}"
        );
        assert!(!head.contains("HTTP/1.0"), "HTTP/1.0 leaks: {head:?}");
        assert!(
            head.contains("Host: 127.0.0.1:8080\r\n"),
            "host line kept: {head:?}"
        );
        assert!(
            head.contains("Content-Type: application/octet-stream\r\n"),
            "header lines kept: {head:?}"
        );
        assert!(
            head.contains("Transfer-Encoding: chunked\r\n"),
            "chunked framing re-added after the hop-by-hop strip: {head:?}"
        );
        assert!(
            head.ends_with("Connection: close\r\n\r\n"),
            "head ends with the close terminator: {head:?}"
        );

        // Content-Length framing: exactly one canonical CL line, no
        // Transfer-Encoding, still HTTP/1.1.
        let cl_head = build_forward_head("POST", "/up", &lines, None, Some(5));
        let cl_head = String::from_utf8(cl_head).unwrap();
        assert!(cl_head.starts_with("POST /up HTTP/1.1\r\n"), "{cl_head:?}");
        assert!(cl_head.contains("Content-Length: 5\r\n"), "{cl_head:?}");
        assert!(!cl_head.contains("Transfer-Encoding:"), "{cl_head:?}");
        assert!(
            cl_head.ends_with("Connection: close\r\n\r\n"),
            "{cl_head:?}"
        );
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

    /// B6: audit round-8 F8 pin through the REAL http_proxy listener — the
    /// head-read loop here in http.rs (a verbatim twin of the loop in
    /// plugin/mod.rs, which has its own copy of this pin). A slowloris peer
    /// that drips ONE byte per 59 s never trips a per-read re-armed deadline
    /// (every byte resets the clock) but MUST be released by the single
    /// absolute PLUGIN_HEADER_READ_TIMEOUT window over the whole head read
    /// (Go http.Server ReadHeaderTimeout = 60 s): the handler errors out at
    /// virtual t=60 s and drops the conn, and the client observes EOF.
    /// Paused time keeps the 300 s outer bound deterministic. RED (per-read
    /// re-arm): the outer bound trips and the test panics.
    #[tokio::test(start_paused = true)]
    async fn http_proxy_head_read_absolute_window_releases_trickler() {
        use tokio::io::AsyncWriteExt;
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let (mut reader, mut trickle_io) = tokio::io::split(client);
        // One byte per 59 s forever — the head never completes (no blank
        // line, no EOF), and each byte would re-arm a per-read deadline.
        let trickle = tokio::spawn(async move {
            loop {
                if trickle_io.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(59)).await;
            }
        });
        let mut buf = [0u8; 1];
        let res = tokio::time::timeout(Duration::from_secs(300), reader.read(&mut buf)).await;
        drop(trickle);
        match res {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a trickled head read"),
            Ok(Err(e)) => panic!("read error from a trickled head read: {e}"),
            Err(_elapsed) => panic!(
                "trickled head read was not released: the 60 s absolute window never fired \
                 (per-read re-arm lets 1 B/59 s beat it)"
            ),
        }
    }

    /// Audit FIX 4 pin: Go frp dials CONNECT targets verbatim
    /// (http_proxy.go handleConnectReq `net.Dial("tcp", r.Host)`) — a
    /// port-less authority is a DIAL failure ("missing port in address"),
    /// so "CONNECT example.com HTTP/1.1" answers Go's bare-400 render,
    /// never a tunnel to :443 (the deleted default-append used to dial
    /// example.com:443 and CONNECT-succeed). Wire = probe capture.
    #[tokio::test]
    async fn http_proxy_connect_without_port_answers_go_400() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let _ = client
            .write_all(b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
            "port-less CONNECT must answer Go's bare 400, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Audit FIX 5 pin: a malformed head on the PLAIN arm renders Go's
    /// http.Server 400 (in Go the head went through PutConn — the server
    /// errors the read and writes errorHeaders + the status-text body
    /// before ServeHTTP ever runs; http_proxy.go's plain arm only ever
    /// serves parseable heads). Probe-captured from go1.25.12 with the same
    /// tab-joined garbage line. EOF/timeout and the CONNECT arm stay silent
    /// (ReadRequest error — no writer), pinned by the trickler above and
    /// http_proxy_oversized_connect_head_closes_silently below.
    #[tokio::test]
    async fn http_proxy_malformed_plain_head_answers_go_400() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let _ = client.write_all(b"GARBAGE\tLINE\r\n\r\n").await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            super::super::GO_400_RENDER.as_bytes(),
            "malformed plain head must render Go's 400, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Audit FIX 5 pin: a plain-arm head over the 1 MiB cap (Go
    /// http.Server MaxHeaderBytes default; the old 64 KiB cap rejected
    /// legal heads) renders Go's 431 before the connection closes. The
    /// send has no blank line so the head can only end by breaching the
    /// cap — the client write may error (server closes mid-send) and is
    /// ignored.
    #[tokio::test]
    async fn http_proxy_oversized_plain_head_answers_go_431() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let mut head = Vec::with_capacity(1024 * 1024 + 64);
        head.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ");
        head.resize(1024 * 1024 + 32, b'A');
        let _ = client.write_all(&head).await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            super::super::GO_431_RENDER.as_bytes(),
            "oversized plain head must render Go's 431, got {} bytes",
            resp.len()
        );
    }

    /// Audit FIX 5 pin: the CONNECT arm of an oversized head closes
    /// SILENTLY. Note the divergence carefully: Go's http_proxy.go sniffs
    /// CONNECT and then hands the stream to http.ReadRequest, which has NO
    /// size cap (only the ReadHeaderTimeout window) — a giant CONNECT head
    /// never fails in Go. The 1 MiB cap here is fail-closed Rust-only
    /// hardening on the operator-local 127.0.0.1 surface; the silent close
    /// (no 431 exists on this arm — no parsed head, no writer) mirrors the
    /// ReadFull-short EOF behavior.
    #[tokio::test]
    async fn http_proxy_oversized_connect_head_closes_silently() {
        let cfg = PluginConfig::default();
        let handle = match start_http_proxy(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        let mut head = Vec::with_capacity(1024 * 1024 + 64);
        head.extend_from_slice(b"CONNECT example.com HTTP/1.1\r\nHost: x\r\nX-Big: ");
        head.resize(1024 * 1024 + 32, b'A');
        let _ = client.write_all(&head).await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert!(
            resp.is_empty(),
            "oversized CONNECT head must close silently, got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(200)])
        );
    }
}
