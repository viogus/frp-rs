use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::service::HealthEvent;

// NOTE: Go frp does NOT support group-level health checks. Go frp's validation
// (pkg/config/v1/validation/proxy.go) only accepts "", "tcp", and "http" for
// health check types. The proxy Group field is used solely for server-side load
// balancing, not health checking. Per-proxy health checks are fully supported.
// If group-level health checking is desired as a frp-rs extension, implement:
//   1. GroupHealthState struct: name->healthy mapping per group, group->proxy_names mapping.
//   2. Shared Arc<Mutex<HashMap<group_name, GroupHealthState>>> across health check tasks.
//   3. HealthCheckConfig::group_name + group_state fields.
//   4. Modified failure/recovery logic in run_health_check.
//   5. service.rs: accept "group" check_type, pass group state, handle multi-proxy CloseProxy.

/// Configuration for a health check task.
pub(crate) struct HealthCheckConfig {
    pub proxy_name: String,
    pub local_addr: String,
    pub check_type: String,
    pub check_url: String,
    pub hc_headers: Vec<frp_core::config::HealthCheckHttpHeader>,
    pub interval: Duration,
    pub timeout: Duration,
    pub max_failed: u32,
    pub health_tx: mpsc::Sender<HealthEvent>,
    pub cancel: Arc<AtomicBool>,
    /// Monotonic session-generation counter, bumped once per successful
    /// control login. A monitor re-arms itself (fresh "unregistered" state)
    /// whenever the value changes, so the proxy re-registers on the new
    /// session's first healthy probe — Go frp parity: each control.Run()
    /// builds a fresh health.Monitor with statusOK=false (H2).
    pub session_gen: Arc<AtomicU64>,
}

/// Run a health check for a proxy.
/// Supports "tcp" (connect only) and "http" (GET + check 2xx status).
///
/// Go frp compat: the monitor keeps running after max_failed and sends
/// recovery events when the service comes back. Matches Go frp's health.Monitor:
///   - On max_failed: calls statusFailedFn (sends Close event), keeps running
///   - On recovery after failure: calls statusNormalFn (sends Recover event)
///   - Only stops when `cancel` is set (proxy removed, not on health failure).
pub(crate) async fn run_health_check(config: HealthCheckConfig) {
    let HealthCheckConfig {
        proxy_name,
        local_addr,
        check_type,
        check_url,
        hc_headers,
        interval,
        timeout,
        max_failed,
        health_tx,
        cancel,
        session_gen,
    } = config;
    info!(check_type = %check_type, proxy_name = %proxy_name, local_addr = %local_addr, interval = ?interval, timeout = ?timeout, "Health check ({}) started for '{}' -> {} (interval: {:?}, timeout: {:?})",
        check_type, proxy_name, local_addr, interval, timeout);

    // Go frp compat: failedTimes resets on a successful check (#5502, dev).
    // State transitions are tracked by was_failed/statusOK; the counter
    // counts only the CURRENT failure streak.
    let mut state = HealthState::new();

    // Monitors are long-lived across control sessions; the service bumps
    // `session_gen` after every successful login. On a change the session
    // started afresh — the server holds NO registrations for this proxy yet
    // (register_proxies skips health-checked proxies by design) — so the
    // monitor returns to the pristine "never registered, never failed"
    // state. Its next successful probe then emits Recover and the proxy is
    // re-registered on the new session (Go parity: a fresh control.Run()
    // builds a fresh Monitor with statusOK=false). Without this, a proxy
    // that stayed healthy across a reconnect was never re-registered and
    // stayed dead until a real failure+recovery cycle (H2).
    let mut seen_gen = session_gen.load(Ordering::Relaxed);

    // Go frp v0.70.1 compat: add 500ms startup delay before the first check.
    // This prevents a thundering herd of health checks when many proxies
    // register simultaneously at client startup.
    tokio::time::sleep(Duration::from_millis(500)).await;

    loop {
        // Check cancellation before each check cycle.
        if cancel.load(Ordering::Relaxed) {
            info!(proxy_name = %proxy_name, "Health check cancelled for '{}'", proxy_name);
            return;
        }

        // Re-arm on a control-session boundary (see `seen_gen` above). The
        // new state keeps `was_healthy=false`, so Close cannot fire before
        // this session's first successful probe — exactly a fresh Go Monitor.
        let gen = session_gen.load(Ordering::Relaxed);
        if gen != seen_gen {
            debug!(proxy_name = %proxy_name, session_gen = gen, "Health check: control session changed, re-arming registration state for '{}'", proxy_name);
            state = HealthState::new();
            seen_gen = gen;
        }

        // Run check first, then sleep (Go frp compat: check happens immediately on start,
        // then sleep for interval duration before the next check).
        let result = if check_type == "http" {
            run_http_check(&local_addr, &check_url, timeout, &hc_headers).await
        } else {
            run_tcp_check(&local_addr, timeout).await
        };

        // Close is only ever fired from a FAILURE tick (Go frp: statusFailedFn
        // runs in the error branch). The old guard ran on every tick, so the
        // first success after a failure sent Recover AND re-fired Close in the
        // same tick (failures was monotonic and was_failed had just been cleared)
        // — flapping CloseProxy/NewProxy every health interval.
        match state.on_check(result.is_ok(), max_failed) {
            HealthAction::Recover => {
                // Service recovered. Notify control loop to re-register.
                info!(proxy_name = %proxy_name, "Health check recovered for '{}', sending Recover event", proxy_name);
                // try_send: during a reconnect the control-loop consumer
                // is gone and the bounded channel may be full — blocking
                // here would pause health probing. On failure keep
                // was_failed=true so the next successful check retries.
                if health_tx
                    .try_send(HealthEvent::Recover(proxy_name.clone()))
                    .is_ok()
                {
                    state.confirm_recover();
                }
            }
            HealthAction::Close => {
                warn!(proxy_name = %proxy_name, max_failed = %max_failed, "Health check: proxy '{}' exceeded max failures ({}), sending Close event",
                    proxy_name, max_failed);
                // try_send: during a reconnect the consumer may be gone and the
                // channel full — never block probing. On failure keep
                // was_failed=false; the next failed check retries the Close.
                if health_tx
                    .try_send(HealthEvent::Close(proxy_name.clone()))
                    .is_ok()
                {
                    state.confirm_close();
                }
                // Keep running -- monitor for recovery (Go frp compat).
            }
            HealthAction::None => {}
        }

        if let Err(e) = result {
            warn!(proxy_name = %proxy_name, failures = %state.failures, error = %e, "Health check FAIL for '{}' ({}): {}", proxy_name, state.failures, e);
        } else {
            debug!(proxy_name = %proxy_name, "Health check OK for '{}'", proxy_name);
        }

        tokio::time::sleep(interval).await;
    }
}

/// Action a health-check monitor should take after one probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthAction {
    /// No event; the check was healthy (or a failure below the threshold).
    None,
    /// The proxy exceeded `max_failed` failures and must be closed.
    Close,
    /// The proxy recovered and must be re-registered.
    Recover,
}

/// Health-check state machine mirroring Go frp's `health.Monitor`
/// (`statusOK`/`failedTimes` transitions). Pure and unit-testable.
struct HealthState {
    /// Consecutive failure count since the last successful check. Go frp
    /// v0.71.0 released with a monotonic counter that never reset (a failure
    /// streak could accumulate across recovery and misfire Close); fatedier
    /// fixed it in #5502 (dev) by resetting on success — mirrored here.
    failures: u64,
    /// A Close event was emitted and no Recover has been delivered yet.
    was_failed: bool,
    /// The proxy was observed healthy at least once (Go frp: statusOK).
    /// Close is only fired after the proxy was healthy at least once.
    was_healthy: bool,
}

impl HealthState {
    fn new() -> Self {
        HealthState {
            failures: 0,
            // Go frp v0.71.0 proxy_wrapper: a health-checked proxy starts with
            // health=1 ("failed") and is NOT registered until the FIRST
            // successful probe flips it healthy. Initial was_failed=true makes
            // that first success emit a Recover event, which registers the
            // proxy (mirroring Go's statusOKFn clearing pw.health).
            was_failed: true,
            was_healthy: false,
        }
    }

    /// Process one probe result and return the event the monitor should emit.
    ///
    /// Transitions are NOT committed here: the caller confirms them via
    /// [`confirm_recover`]/[`confirm_close`] only after the corresponding
    /// event was actually delivered (`try_send` can fail during a reconnect,
    /// in which case the transition is retried on the next matching tick).
    fn on_check(&mut self, ok: bool, max_failed: u32) -> HealthAction {
        if ok {
            // Go frp compat (fatedier/frp #5502, dev): failedTimes is reset
            // on a successful check, so a failure streak never accumulates
            // across recovery — a proxy that recovers must fail max_failed
            // times in a row again before Close fires.
            self.failures = 0;
            self.was_healthy = true;
            if self.was_failed {
                HealthAction::Recover
            } else {
                HealthAction::None
            }
        } else {
            self.failures += 1;
            // Go frp compat: only fire Close after the proxy was ever healthy
            // (statusOK must be true before transitioning to false triggers the
            // callback). Evaluated ONLY on failure ticks.
            if self.was_healthy && self.failures >= max_failed as u64 && !self.was_failed {
                HealthAction::Close
            } else {
                HealthAction::None
            }
        }
    }

    /// Commit a delivered Recover event (was_failed=false).
    fn confirm_recover(&mut self) {
        self.was_failed = false;
    }

    /// Commit a delivered Close event (was_failed=true).
    fn confirm_close(&mut self) {
        self.was_failed = true;
    }
}

/// Go http.Client redirect cap (http.Client.checkRedirect: "stopped after 10
/// redirects"). A chain longer than this fails the check like Go's
/// `http.DefaultClient.Do` error.
const MAX_HEALTH_CHECK_REDIRECTS: usize = 10;

/// Cap on the response-head bytes read per probe hop. Only the status line +
/// headers are inspected (the Location header for redirects); the body is
/// never drained, so the head is all we ever need. 16 KiB bounds a hostile
/// header flood that would otherwise consume the whole check deadline.
const MAX_HEALTH_RESPONSE_HEAD: usize = 16 * 1024;

/// TCP health check: connect to addr, then close. Success = connection established.
pub(crate) async fn run_tcp_check(addr: &str, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Go parity: health checks dial with net/http (NoDelay=true
            // default). Cosmetic for a connect+close probe, but keeps the
            // "every raw TcpStream" nodelay invariant uniform.
            frp_core::transport::set_nodelay(&stream);
            Ok(())
        }
        Ok(Err(e)) => Err(format!("TCP connect: {e}")),
        Err(_) => Err("timeout".into()),
    }
}

/// HTTP health check: send GET, verify a 2xx status code.
///
/// Hand-rolled on raw TCP (no HTTP client dependency). Wire-shape parity with
/// Go's `doHTTPCheck` (client/health/health.go:167-183 — `http.NewRequest`
/// + `http.DefaultClient.Do`):
///   * ORIGIN-form request target (`GET /path?query HTTP/1.1` — never the
///     absolute URL; the old probe sent `GET http://host/path HTTP/1.1`,
///     which Go never sends and some servers reject);
///   * redirects are followed (301/302/303/307/308 with a Location header,
///     up to 10 hops — the http.Client default policy), each hop on a fresh
///     connection, Location resolved RFC-3986-style against the current URL;
///   * the WHOLE check — every hop's DNS/dial/write/read — runs under ONE
///     `timeout` deadline (Go checkWorker wraps doCheck in a single
///     WithDeadline(monitor.timeout), health.go:108), so a slow redirect
///     chain cannot exceed the configured per-check budget;
///   * the status-line gate accepts any `HTTP/x.y` version token with a
///     3-digit numeric code (`HTTP/2.0 200 OK` is valid for Go's ReadResponse
///     and was rejected by the old `HTTP/1.`-only prefix check).
///
/// The response BODY is deliberately not drained (Go `io.Copy(io.Discard,
/// resp.Body)`): Go drains only so its keep-alive transport can reuse the
/// connection. This probe opens a fresh connection per hop and sends
/// `Connection: close`, so there is nothing to reuse — a bounded head read
/// costs the same and skips the drain. Wire-invisible given close-per-probe.
///
/// `_addr` (the local-addr config string) is unused on the HTTP path — the
/// dial target is the checked URL's authority, exactly like Go, where the
/// monitor stores only the URL and addr is used solely to build it.
pub(crate) async fn run_http_check(
    _addr: &str,
    url: &str,
    timeout: Duration,
    headers: &[frp_core::config::HealthCheckHttpHeader],
) -> Result<(), String> {
    tokio::time::timeout(timeout, http_check_chain(url, headers))
        .await
        .map_err(|_| "timeout".to_string())?
}

/// Drive the redirect chain until a verdict. `hop` counts requests: the
/// initial probe plus up to `MAX_HEALTH_CHECK_REDIRECTS` follow-ups; an
/// 11th redirect fails like Go's "stopped after 10 redirects".
async fn http_check_chain(
    url: &str,
    headers: &[frp_core::config::HealthCheckHttpHeader],
) -> Result<(), String> {
    let mut current = url.to_string();
    for _hop in 0..=MAX_HEALTH_CHECK_REDIRECTS {
        let response = probe_http_hop(&current, headers).await?;
        if (200..300).contains(&response.status) {
            return Ok(());
        }
        // Only Go's isRedirect codes with a Location header are followed
        // (net/http/client.go isRedirect: 301, 302, 303, 307, 308).
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(location) = response.location {
                current = resolve_redirect_url(&current, &location)?;
                continue;
            }
        }
        // Final response (no Location, non-redirect code, or unsupported
        // redirect target): the verdict is on THIS response.
        return Err(format!("non-2xx status: {}", response.status_line));
    }
    Err("stopped after 10 redirects".to_string())
}

/// One probe hop on a fresh connection: dial the URL authority, send an
/// origin-form GET, and read the response head.
async fn probe_http_hop(
    url: &str,
    headers: &[frp_core::config::HealthCheckHttpHeader],
) -> Result<HttpProbeResponse, String> {
    let parsed = parse_health_url(url)?;
    let mut stream = tokio::net::TcpStream::connect((parsed.host.as_str(), parsed.port))
        .await
        .map_err(|e| format!("TCP connect: {e}"))?;
    // Go's health checks dial with net/http (NoDelay=true by default); the
    // small GET must not sit in Nagle's buffer waiting for the ACK. This
    // probe is not a relay, so no buffer-size setup is needed — just nodelay.
    frp_core::transport::set_nodelay(&stream);

    // Host header: a user-configured "Host" header overrides everything (Go:
    // monitor.header is applied wholesale, req.Host = header.Get("Host"));
    // otherwise the URL authority's hostname, port-stripped and de-bracketed
    // (Go URL.Hostname() semantics — HTTP/1.1 Host without a port is
    // equivalent on the default port; the pre-fix probe derived the same
    // value from `addr`, which for every auto-built URL equals the URL host).
    let custom_host = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| h.value.as_str());
    let host = custom_host.unwrap_or(parsed.host.as_str());
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close",
        parsed.target, host
    );
    for h in headers {
        // Skip Host header — already included above with the resolved host value.
        if h.name.eq_ignore_ascii_case("host") {
            continue;
        }
        req.push_str(&format!("\r\n{}: {}", h.name, h.value));
    }
    req.push_str("\r\n\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let head = read_http_response_head(&mut stream).await?;
    parse_http_response_head(&head)
}

/// Read the response head (status line + headers) into a bounded buffer.
///
/// Verdict-shape parity with Go's `http.ReadResponse` (which health.go's
/// `DefaultClient.Do` uses): a head only yields a verdict once its blank
/// line has been read under textproto.ReadLine semantics — any mix of
/// `\r\n` and bare-`\n` line endings is legal, and the first line empty
/// after stripping one trailing `\r` ends the head (see
/// `frp_core::textproto::head_end`). EOF before the blank line is a
/// truncated head (Go net/textproto maps it to `io.ErrUnexpectedEOF`), and
/// a head that fills `MAX_HEALTH_RESPONSE_HEAD` without a blank line is a
/// cap hit — both FAIL the check. ("Connection: close" servers still send
/// the blank line; only peers that die mid-head omit it.) Never reads past
/// the head — the body is not drained (see run_http_check).
async fn read_http_response_head(stream: &mut tokio::net::TcpStream) -> Result<String, String> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            if head.is_empty() {
                return Err("empty response".into());
            }
            return Err("head truncated: EOF before blank line".into());
        }
        head.extend_from_slice(&buf[..n]);
        // Terminate at the FIRST blank line under Go textproto.ReadLine
        // semantics (frp_core::textproto::head_end): each line ends at the
        // next `\n` with ONE trailing `\r` stripped, so bare-LF header
        // lines and CRLF lines may mix freely, and the head ends at the
        // first line empty under that rule (a CRLF blank after LF lines —
        // `...\n\r\n` — terminates just like `\r\n\r\n` or `\n\n`). Body
        // bytes sharing the read window are truncated away. Go
        // http.ReadResponse likewise stops at the blank line with the body
        // unread, so head+body in one segment is UP in Go and must be here.
        if let Some(end) = frp_core::textproto::head_end(&head) {
            head.truncate(end);
            break;
        }
        if head.len() >= MAX_HEALTH_RESPONSE_HEAD {
            // Hardening bound with no Go counterpart (Go reads the head
            // without a cap): a >16 KiB response head is pathological for a
            // health endpoint, and the fail-closed verdict matches Go's on
            // every shape Go can see (Go DOWNs an unterminated head by
            // deadline). Documented divergence for the legit-oversized
            // case: Go UP, frp-rs DOWN.
            return Err(format!(
                "head exceeds {} B cap without terminator",
                MAX_HEALTH_RESPONSE_HEAD
            ));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

struct HttpProbeResponse {
    status: u16,
    status_line: String,
    location: Option<String>,
}

/// Parse the response head. The version gate mirrors Go's ReadResponse:
/// any `HTTP/<major>.<minor>` version token is accepted ("HTTP/2.0 200 OK"
/// passes), the status code must be a numeric token, and a non-numeric code
/// is a failure (Go Atoi parity), never a non-2xx verdict.
fn parse_http_response_head(head: &str) -> Result<HttpProbeResponse, String> {
    if head.is_empty() {
        return Err("empty response".into());
    }
    let status_line = head.split('\n').next().unwrap_or("").trim_end_matches('\r');
    let status = parse_status_code(status_line)
        .ok_or_else(|| format!("malformed status line: {status_line}"))?;
    let location = response_header_location(head);
    Ok(HttpProbeResponse {
        status,
        status_line: status_line.to_string(),
        location,
    })
}

/// Parse the status code out of a status line: `HTTP/<digits>.<digits> SP
/// <code>...`. The version token must be exactly HTTP/major.minor (Go
/// ParseHTTPVersion), the code token all digits (Go Atoi — leading zeros
/// like "0200" are accepted, exactly like Atoi returning 200).
fn parse_status_code(line: &str) -> Option<u16> {
    let line = line.trim_end_matches('\r');
    let rest = line.strip_prefix("HTTP/")?;
    let (version, tail) = rest.split_once(' ')?;
    let (major, minor) = version.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|b| b.is_ascii_digit())
        || !minor.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let code_token = tail.trim_start().split(' ').next().unwrap_or("");
    if code_token.is_empty() || !code_token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code_token.parse::<u16>().ok()
}

/// First `Location` header value (case-insensitive name), if any.
fn response_header_location(head: &str) -> Option<String> {
    for line in head.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break; // end of head
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("location") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// A parsed health-check URL: dial target + origin-form request target.
struct ProbeUrl {
    host: String,
    port: u16,
    /// Path + query (the origin-form request target); never empty.
    target: String,
}

/// Parse an `http://host[:port]/path?query` health URL. https:// is
/// rejected — the hand-rolled probe has no TLS stack (Go would follow an
/// https redirect via net/http); see resolve_redirect_url.
fn parse_health_url(url: &str) -> Result<ProbeUrl, String> {
    let scheme_end = url
        .find("://")
        .ok_or_else(|| format!("invalid health URL '{url}': no scheme"))?;
    if !url[..scheme_end].eq_ignore_ascii_case("http") {
        return Err(format!(
            "invalid health URL '{url}': only http:// is supported by the probe"
        ));
    }
    let rest = &url[scheme_end + 3..];
    // Authority ends at the first '/', '?' or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // Request target: path + query (fragment is never sent — Go strips it
    // from RequestURI too). A bare authority ("http://h:p") targets "/".
    let mut target = if authority_end < rest.len() {
        rest[authority_end..]
            .split('#')
            .next()
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };
    if target.is_empty() || target.starts_with('?') {
        target = format!("/{target}");
    }
    let (host, port) = split_url_authority(authority)
        .ok_or_else(|| format!("invalid health URL '{url}': bad authority '{authority}'"))?;
    Ok(ProbeUrl { host, port, target })
}

/// Split `host[:port]`, handling bracketed IPv6 (`[::1]:8080`, `[::1]`),
/// unbracketed IPv6 (`::1:8080` — from the last-colon split) and hostnames.
/// Default port is 80 (Go URL.Port() semantics). `[::1]x]:80`-style garbage
/// fails closed (None).
fn split_url_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = if tail.is_empty() {
            80
        } else {
            tail.strip_prefix(':')?.parse::<u16>().ok()?
        };
        Some((host.to_string(), port))
    } else if authority.contains(':') {
        // Unbracketed IPv6 or a host:port pair: split the numeric port off
        // the LAST colon so IPv6 segments stay in the host.
        let (host, port) = authority.rsplit_once(':')?;
        if host.is_empty() {
            return None;
        }
        let port = port.parse::<u16>().ok()?;
        // The host half of a ':'-bearing authority must itself be a valid
        // IPv6 literal ("::1" splits into host ":" — malformed → None).
        if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        Some((host.to_string(), port))
    } else {
        Some((authority.to_string(), 80))
    }
}

/// Resolve a Location header against the current health URL (RFC 3986 merge
/// — Go req.URL.Parse(loc) in http.Client redirect handling).
fn resolve_redirect_url(current: &str, location: &str) -> Result<String, String> {
    let loc = location.trim();
    // Empty Location: an empty reference resolves to the current URL
    // (Go ResolveReference) — the next hop re-probes it and the redirect
    // counter terminates a loop.
    if loc.is_empty() {
        return Ok(current.to_string());
    }
    let loc_no_frag = loc.split('#').next().unwrap_or(loc);
    if loc_no_frag.is_empty() {
        return Ok(current.to_string());
    }
    if let Some(end) = loc_no_frag.find("://") {
        let scheme = &loc_no_frag[..end];
        if scheme.eq_ignore_ascii_case("http") {
            return Ok(loc_no_frag.to_string());
        }
        // https (or any other scheme): the hand-rolled probe has no TLS
        // stack. Go follows via net/http; here the redirect is not
        // followed and the non-2xx verdict lands on the redirecting
        // response (documented divergence — an http health endpoint
        // redirecting to https is not a supported config).
        return Err(format!(
            "redirect to '{loc_no_frag}' is not supported (probe has no TLS stack)"
        ));
    }
    // Scheme-relative ("//host/path") → current scheme + value.
    let loc_resolved = if loc_no_frag.starts_with("//") {
        format!("http:{loc_no_frag}")
    } else {
        // Split the current URL into "http://authority" + path.
        let scheme_end = current.find("://").map(|i| i + 3).unwrap_or(0);
        let (base_authority, base_path) = match current[scheme_end..].find('/') {
            Some(i) => (
                current[..scheme_end + i].to_string(),
                &current[scheme_end + i..],
            ),
            None => (current.to_string(), "/"),
        };
        if loc_no_frag.starts_with('/') {
            // Absolute-path reference: replace the whole path.
            format!("{base_authority}{loc_no_frag}")
        } else {
            // Relative reference: merge against the base path's directory
            // (RFC 3986 §5.3: strip the last segment). "/a/b?q" + "ok" →
            // "/a/ok".
            let base_path = base_path.split('?').next().unwrap_or(base_path);
            let dir = match base_path.rsplit_once('/') {
                Some((head, _tail)) if !head.is_empty() => format!("{head}/"),
                _ => "/".to_string(),
            };
            format!("{base_authority}{dir}{loc_no_frag}")
        }
    };
    Ok(loc_resolved)
}

/// Robust host/port split of a `host:port` local-addr string (config
/// `local_ip` is a bare string, so IPv6 literals arrive UNBRACKETED —
/// `"::1:8080"`; plugin addresses arrive as `"127.0.0.1:port"`). Tries a
/// full SocketAddr parse first (bracketed v6, v4), then a last-colon split
/// with a numeric-port gate (keeps unbracketed IPv6 segments in the host).
/// Returns None for garbage (no port, empty host, non-numeric port).
fn local_addr_host_port(hostport: &str) -> Option<(String, u16)> {
    if let Ok(sa) = hostport.parse::<std::net::SocketAddr>() {
        return Some((sa.ip().to_string(), sa.port()));
    }
    let (host, port) = hostport.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // The host half of a ':'-bearing string must itself be a valid IPv6
    // literal: bare "::1" (no port) splits into host ":" → None.
    if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return None;
    }
    Some((host.to_string(), port.parse::<u16>().ok()?))
}

/// Build the auto health-check URL `http://{host}:{port}/{path}` from a
/// `host:port` local-addr string (Go parity: proxy_wrapper.go JoinHostPort
/// plus health.go:68-76 `"http://" + addr` construction). Literal IPv6 is
/// bracketed here because the addr string is not (an unbracketed
/// "::1:8080" must become `http://[::1]:8080/...`). Garbage input falls
/// back to 127.0.0.1:0 so the caller never emits a malformed URL.
pub(crate) fn build_health_check_url(local_addr: &str, path_or_url: &str) -> String {
    let (host, port) = local_addr_host_port(local_addr)
        .map(|(h, p)| (h, p.to_string()))
        .unwrap_or_else(|| ("127.0.0.1".to_string(), "0".to_string()));
    let path = if path_or_url.starts_with('/') {
        path_or_url.to_string()
    } else {
        format!("/{path_or_url}")
    };
    // A parsed SocketAddr ip string is never bracketed; a raw hostname may
    // carry brackets only if the caller passed "[::1]:8080" through the
    // non-parse path (impossible — that parses). Bracket any ':'-bearing
    // host so the URL authority is unambiguous.
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    format!("http://{host}:{port}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the Close guard must only ever run on FAILURE ticks. The
    /// old guard (`was_healthy && failures >= max_failed && !was_failed`) ran
    /// after every tick including successes, so the first success after a
    /// recovery sent Recover AND re-fired Close in the same tick (failures was
    /// monotonic and was_failed had just been cleared) — flapping
    /// CloseProxy/NewProxy every health interval.
    #[test]
    fn success_tick_after_recovery_emits_recover_but_not_close() {
        let mut st = HealthState::new();
        // Go v0.71.0: a health-checked proxy starts "failed" (health=1), so
        // the FIRST success emits Recover and registers the proxy.
        assert_eq!(st.on_check(true, 2), HealthAction::Recover);
        st.confirm_recover();
        // Healthy baseline: no events.
        assert_eq!(st.on_check(true, 2), HealthAction::None);
        // Failure 1: below max_failed, no event.
        assert_eq!(st.on_check(false, 2), HealthAction::None);
        // Failure 2: reaches max_failed -> Close.
        assert_eq!(st.on_check(false, 2), HealthAction::Close);
        st.confirm_close();
        // Further failures while closed: no re-fire.
        assert_eq!(st.on_check(false, 2), HealthAction::None);
        // Success after a failure streak: Recover only.
        assert_eq!(st.on_check(true, 2), HealthAction::Recover);
        st.confirm_recover();
        // Success right after recovery: NO event. Regression: the old guard
        // fired Close here because `failures` was monotonic and was_failed
        // had just been cleared by the Recover above.
        assert_eq!(st.on_check(true, 2), HealthAction::None);
        // A later failure does NOT re-close immediately: the successful check
        // reset the counter (Go #5502), so the streak restarts from zero.
        assert_eq!(st.on_check(false, 2), HealthAction::None);
        // One more failure reaches max_failed again -> Close.
        assert_eq!(st.on_check(false, 2), HealthAction::Close);
        // The first success after Close recovers (was_failed=true)...
        st.confirm_close();
        assert_eq!(st.on_check(true, 2), HealthAction::Recover);
        st.confirm_recover();
        // ...and the following success tick is silent.
        assert_eq!(st.on_check(true, 2), HealthAction::None);
    }

    /// Go #5502 regression: failures must not accumulate across a recovery.
    /// Old behavior closed a proxy that failed max_failed times over SEPARATE
    /// outages (e.g. 2 failures, 10 min healthy, 1 failure with max_failed=3)
    /// because the monotonic counter never reset.
    #[test]
    fn failure_streak_does_not_accumulate_across_recovery() {
        let mut st = HealthState::new();
        // First success registers (health=1 -> 0).
        assert_eq!(st.on_check(true, 3), HealthAction::Recover);
        st.confirm_recover();
        // Outage 1: 2 failures, below max_failed=3, no Close.
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        // Recovery.
        assert_eq!(st.on_check(true, 3), HealthAction::None);
        // Outage 2: 1 failure — must NOT Close (streak restarted at 0).
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        // Outage 2 continues: 2 more failures reach max_failed in one streak.
        assert_eq!(st.on_check(false, 3), HealthAction::None);
        assert_eq!(st.on_check(false, 3), HealthAction::Close);
    }

    /// Close is only emitted on failure ticks; success ticks can only emit
    /// Recover (or nothing).
    #[test]
    fn close_never_emitted_on_success_ticks() {
        let mut st = HealthState::new();
        // Force the closed state, then feed success ticks: never Close.
        st.on_check(false, 1);
        st.confirm_close();
        assert_eq!(st.on_check(true, 1), HealthAction::Recover);
        st.confirm_recover();
        assert_eq!(st.on_check(true, 1), HealthAction::None);
        assert_eq!(st.on_check(true, 1), HealthAction::None);
    }

    /// A proxy that was never healthy is never closed (Go frp statusOK gate).
    #[test]
    fn never_healthy_proxy_is_not_closed() {
        let mut st = HealthState::new();
        // A never-healthy proxy is never closed (Go frp statusOK gate).
        assert_eq!(st.on_check(false, 1), HealthAction::None);
        assert_eq!(st.on_check(false, 1), HealthAction::None);
        assert_eq!(st.on_check(false, 1), HealthAction::None);
        // First ever success registers the proxy (Recover; Go health=1 → 0).
        assert_eq!(st.on_check(true, 1), HealthAction::Recover);
        st.confirm_recover();
        // Healthy afterwards: no events.
        assert_eq!(st.on_check(true, 1), HealthAction::None);
    }

    // --- F3/F4: probe wire-shape + URL-builder pins ---

    /// Spawn a scripted responder: each accepted connection reads the request
    /// head, records it (full head string, so tests can assert request-line
    /// and header shape), and answers with the next queued (status line,
    /// headers) pair. Connections beyond the queue are closed unanswered.
    async fn spawn_scripted_server(
        responses: Vec<(String, Vec<(String, String)>)>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let idx = Arc::new(AtomicUsize::new(0));
        let seen_task = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let i = idx.fetch_add(1, Ordering::Relaxed);
                let Some((status_line, headers)) = responses.get(i) else {
                    continue; // extra connection: close unanswered
                };
                let mut buf = [0u8; 4096];
                let n = match sock.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                seen_task.lock().unwrap().push(head);
                let mut resp = format!("{status_line}\r\n");
                for (k, v) in headers {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("Content-Length: 0\r\n\r\n");
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        (addr, seen)
    }

    /// Wait until `n` request heads have been captured (the probe returns as
    /// soon as it read its response; the server's capture happens just
    /// before the response write, so by response-read time the push has
    /// happened — this poll is a belt-and-braces cross-thread sync).
    async fn wait_seen(
        seen: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        n: usize,
    ) -> Vec<String> {
        for _ in 0..200 {
            {
                let g = seen.lock().unwrap();
                if g.len() >= n {
                    return g.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "only {} of {n} requests observed",
            seen.lock().unwrap().len()
        );
    }

    #[tokio::test]
    async fn http_probe_uses_origin_form_request_line() {
        let (addr, seen) =
            spawn_scripted_server(vec![("HTTP/1.1 200 OK".to_string(), vec![])]).await;
        let url = format!("http://{addr}/healthz?x=1");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
        let heads = wait_seen(&seen, 1).await;
        // Origin-form request target, never the absolute URL (Go
        // http.NewRequest + RequestURI semantics). The old probe sent
        // "GET http://{addr}/healthz?x=1 HTTP/1.1".
        assert!(
            heads[0].starts_with("GET /healthz?x=1 HTTP/1.1\r\n"),
            "request line was not origin-form: {:?}",
            heads[0].lines().next()
        );
        assert!(
            heads[0].contains("\r\nHost: 127.0.0.1\r\n"),
            "{:?}",
            heads[0]
        );
    }

    #[tokio::test]
    async fn http_probe_accepts_2xx_and_rejects_non_2xx() {
        let (addr, _seen) = spawn_scripted_server(vec![
            ("HTTP/1.1 200 OK".to_string(), vec![]),
            ("HTTP/1.1 500 Internal Server Error".to_string(), vec![]),
        ])
        .await;
        let url = format!("http://{addr}/");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(err.contains("non-2xx status"), "{err}");
        assert!(err.contains("500"), "{err}");
    }

    #[tokio::test]
    async fn http_probe_connect_refusal_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener); // nothing listens on the port any more
        let url = format!("http://{addr}/");
        let err = run_http_check(&addr, &url, Duration::from_secs(2), &[])
            .await
            .unwrap_err();
        assert!(err.contains("TCP connect"), "{err}");
    }

    #[tokio::test]
    async fn http_probe_follows_redirect_to_ok() {
        let (addr, seen) = spawn_scripted_server(vec![
            (
                "HTTP/1.1 302 Found".to_string(),
                vec![("Location".to_string(), "/ok".to_string())],
            ),
            ("HTTP/1.1 200 OK".to_string(), vec![]),
        ])
        .await;
        let url = format!("http://{addr}/start");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
        let heads = wait_seen(&seen, 2).await;
        assert!(heads[0].starts_with("GET /start HTTP/1.1\r\n"));
        assert!(heads[1].starts_with("GET /ok HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn http_probe_resolves_relative_redirect_against_base_directory() {
        let (addr, seen) = spawn_scripted_server(vec![
            (
                "HTTP/1.1 302 Found".to_string(),
                vec![("Location".to_string(), "c".to_string())],
            ),
            ("HTTP/1.1 200 OK".to_string(), vec![]),
        ])
        .await;
        let url = format!("http://{addr}/a/b");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
        let heads = wait_seen(&seen, 2).await;
        assert!(
            heads[1].starts_with("GET /a/c HTTP/1.1\r\n"),
            "{:?}",
            heads[1]
        );
    }

    #[tokio::test]
    async fn http_probe_redirect_without_location_fails() {
        let (addr, seen) =
            spawn_scripted_server(vec![("HTTP/1.1 302 Found".to_string(), vec![])]).await;
        let url = format!("http://{addr}/");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        // Verdict lands on the redirecting response: 302 is not 2xx.
        assert!(err.contains("non-2xx status"), "{err}");
        assert!(err.contains("302"), "{err}");
        // Exactly one hop — no Location, no follow.
        assert_eq!(wait_seen(&seen, 1).await.len(), 1);
    }

    #[tokio::test]
    async fn http_probe_follows_only_go_is_redirect_codes() {
        let (addr, seen) = spawn_scripted_server(vec![
            (
                "HTTP/1.1 301 Moved Permanently".to_string(),
                vec![("Location".to_string(), "/a".to_string())],
            ),
            (
                "HTTP/1.1 303 See Other".to_string(),
                vec![("Location".to_string(), "/b".to_string())],
            ),
            (
                "HTTP/1.1 304 Not Modified".to_string(),
                vec![("Location".to_string(), "/c".to_string())],
            ),
        ])
        .await;
        let url = format!("http://{addr}/");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        // 304 is NOT in Go isRedirect (301/302/303/307/308): the chain stops
        // on the 304 and the check fails on it.
        assert!(err.contains("304"), "{err}");
        let heads = wait_seen(&seen, 3).await;
        assert!(
            heads[1].starts_with("GET /a HTTP/1.1\r\n"),
            "{:?}",
            heads[1]
        );
        assert!(
            heads[2].starts_with("GET /b HTTP/1.1\r\n"),
            "{:?}",
            heads[2]
        );
        assert_eq!(heads.len(), 3); // no /c hop
    }

    #[tokio::test]
    async fn http_probe_redirect_chain_over_10_fails() {
        let mut responses = Vec::new();
        for i in 0..11 {
            responses.push((
                "HTTP/1.1 302 Found".to_string(),
                vec![("Location".to_string(), format!("/{i}"))],
            ));
        }
        let (addr, seen) = spawn_scripted_server(responses).await;
        let url = format!("http://{addr}/");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        // Go http.Client: "stopped after 10 redirects".
        assert!(err.contains("stopped after 10 redirects"), "{err}");
        assert_eq!(wait_seen(&seen, 11).await.len(), 11);
    }

    #[tokio::test]
    async fn http_probe_https_redirect_is_not_followed() {
        let (addr, seen) = spawn_scripted_server(vec![(
            "HTTP/1.1 302 Found".to_string(),
            vec![("Location".to_string(), "https://example.com/x".to_string())],
        )])
        .await;
        let url = format!("http://{addr}/");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(err.contains("not supported"), "{err}");
        assert_eq!(wait_seen(&seen, 1).await.len(), 1);
    }

    #[tokio::test]
    async fn http_probe_accepts_any_http_version_token() {
        // Go ReadResponse accepts any HTTP/x.y version token; the old probe's
        // "HTTP/1." prefix gate wrongly failed an "HTTP/2.0 200" response.
        let (addr, _seen) =
            spawn_scripted_server(vec![("HTTP/2.0 200 OK".to_string(), vec![])]).await;
        let url = format!("http://{addr}/");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());

        let (addr, _seen) =
            spawn_scripted_server(vec![("HTTP/9.9 204 No Content".to_string(), vec![])]).await;
        let url = format!("http://{addr}/");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());

        // Malformed version token → failure, not a silent non-2xx verdict.
        let (addr, _seen) = spawn_scripted_server(vec![("FOO 200 OK".to_string(), vec![])]).await;
        let url = format!("http://{addr}/");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(err.contains("malformed status line"), "{err}");
    }

    #[tokio::test]
    async fn http_probe_sends_custom_headers_and_host_override() {
        let (addr, seen) =
            spawn_scripted_server(vec![("HTTP/1.1 200 OK".to_string(), vec![])]).await;
        let headers = vec![
            frp_core::config::HealthCheckHttpHeader {
                name: "Host".to_string(),
                value: "example.test".to_string(),
            },
            frp_core::config::HealthCheckHttpHeader {
                name: "X-Check".to_string(),
                value: "1".to_string(),
            },
        ];
        let url = format!("http://{addr}/");
        assert!(
            run_http_check(&addr, &url, Duration::from_secs(5), &headers)
                .await
                .is_ok()
        );
        let heads = wait_seen(&seen, 1).await;
        // User Host header replaces the derived one (Go monitor.header
        // semantics); other headers pass through verbatim.
        assert!(
            heads[0].contains("\r\nHost: example.test\r\n"),
            "{:?}",
            heads[0]
        );
        assert!(heads[0].contains("\r\nX-Check: 1\r\n"), "{:?}", heads[0]);
        // No duplicate Host header (the derived Host is skipped when a
        // custom one is configured).
        assert_eq!(heads[0].matches("\r\nHost:").count(), 1);
    }

    #[test]
    fn local_addr_host_port_shapes() {
        assert_eq!(
            local_addr_host_port("127.0.0.1:8080"),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            local_addr_host_port("[::1]:8080"),
            Some(("::1".to_string(), 8080))
        );
        // Unbracketed IPv6: the last-colon split keeps the v6 segments.
        assert_eq!(
            local_addr_host_port("::1:8080"),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(
            local_addr_host_port("localhost:8080"),
            Some(("localhost".to_string(), 8080))
        );
        // Garbage: no port, empty host, non-numeric port, bare v6 without a
        // port (indistinguishable from a bad split) → None.
        assert_eq!(local_addr_host_port(":8080"), None);
        assert_eq!(local_addr_host_port("127.0.0.1"), None);
        assert_eq!(local_addr_host_port("127.0.0.1:abc"), None);
        assert_eq!(local_addr_host_port("::1"), None);
        assert_eq!(local_addr_host_port(""), None);
    }

    #[test]
    fn build_health_check_url_shapes() {
        // The four finding-spec shapes. Literal IPv6 is bracketed exactly
        // once; a path without a leading '/' gains one.
        assert_eq!(
            build_health_check_url("127.0.0.1:8080", ""),
            "http://127.0.0.1:8080/"
        );
        assert_eq!(
            build_health_check_url("[::1]:8080", "/x"),
            "http://[::1]:8080/x"
        );
        // F4: the old split(':') produced "http://:/x" here.
        assert_eq!(
            build_health_check_url("::1:8080", "/x"),
            "http://[::1]:8080/x"
        );
        assert_eq!(
            build_health_check_url("localhost:8080", "ok"),
            "http://localhost:8080/ok"
        );
        // Garbage falls back to 127.0.0.1:0 (never a malformed URL).
        assert_eq!(
            build_health_check_url("garbage", "/x"),
            "http://127.0.0.1:0/x"
        );
        assert_eq!(build_health_check_url("::1", "/x"), "http://127.0.0.1:0/x");
    }

    // ---- GAP2 (round-6 audit): run_tcp_check arms never pinned ----

    #[tokio::test]
    async fn tcp_check_success_and_refused_arms() {
        // Success: a real listener accepts the probe connect.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(run_tcp_check(&addr, Duration::from_secs(5)).await.is_ok());
        drop(listener);
        // Refused: the port is closed — deterministic on loopback.
        let err = run_tcp_check(&addr, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.contains("TCP connect"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn tcp_check_timeout_arm_fires() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737 — never routed, never answered),
        // so the probe's own 100ms budget is what reaps the dial — except on
        // hosts without a default route, where connect(2) fails
        // synchronously with EHOSTUNREACH before any timer can run. Loopback
        // cannot pin this arm at all (a closed 127/8 port answers
        // ECONNREFUSED on the kernel's first connect() call). Both outcomes
        // are accepted: routed hosts (CI) exercise the timeout arm, unrouted
        // hosts (offline sandboxes) exercise the dial-error arm that
        // tcp_check_success_and_refused_arms pins via ECONNREFUSED.
        let started = tokio::time::Instant::now();
        let err = run_tcp_check("192.0.2.1:9", Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(
            err == "timeout" || err.contains("TCP connect:"),
            "unexpected error: {err}"
        );
        // The named property is that the probe's OWN 100ms budget reaps the
        // dial. Without the tokio::time::timeout in run_tcp_check the routed
        // branch would drift into the OS connect timeout (~130s) and report
        // "TCP connect: Connection timed out" — accepted by the OR above —
        // so the elapsed bound is what actually pins the timeout arm.
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout arm breached: check took {elapsed:?}"
        );
    }

    // ---- GAP3 (round-6 audit): http probe whole-chain deadline + head
    // EOF/cap/empty edges ----

    /// Server that answers each connection with `raw` bytes verbatim (no
    /// added framing), or stays silent when `raw` is None. The probe's own
    /// read shapes decide the outcome — these pins script what a real
    /// (misbehaving or terse) server can send.
    async fn spawn_raw_server(raw: Option<Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                match raw.as_ref() {
                    Some(bytes) => {
                        let mut buf = [0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock.write_all(bytes).await;
                    }
                    None => {
                        // Stalling server: read the request, then hold the
                        // connection open without answering (dropping the
                        // socket would surface as EOF, not a stall).
                        let mut buf = [0u8; 4096];
                        let _ = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf))
                            .await;
                        let _ = tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn http_probe_stalling_server_hits_single_deadline() {
        // The WHOLE chain runs under one timeout: a first-hop server that
        // accepts and never responds must release the check within (a small
        // multiple of) the budget — not hang the health task.
        let (addr, _handle) = spawn_raw_server(None).await;
        let url = format!("http://{addr}/healthz");
        let started = tokio::time::Instant::now();
        let err = run_http_check(&addr, &url, Duration::from_millis(200), &[])
            .await
            .unwrap_err();
        assert_eq!(err, "timeout");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "single-deadline breach: check took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn http_probe_truncated_head_fails_closed() {
        // Peer dies mid-head: status line + one header line, then EOF
        // without the CRLFCRLF terminator. Go net/textproto maps this to
        // io.ErrUnexpectedEOF inside http.ReadResponse, so Go frp's check
        // verdicts DOWN — frp-rs must too, not "parse what arrived".
        let (addr, _handle) =
            spawn_raw_server(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".to_vec())).await;
        let url = format!("http://{addr}/healthz");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(err.contains("truncated"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn http_probe_empty_response_fails() {
        // Peer closes without a single byte: empty head → parse error, a
        // fail-closed verdict (Go: io.ReadAll gets EOF → error).
        let (addr, _handle) = spawn_raw_server(Some(Vec::new())).await;
        let url = format!("http://{addr}/healthz");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(err.contains("empty response"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn http_probe_oversized_head_fails_closed() {
        // >16 KiB of header junk with no blank line: the head reader stops
        // at its cap and the cap-hit verdict fails the probe (bounded
        // memory, fail-closed). Go has no head cap — its verdict on this
        // input is DOWN via deadline — so fail-closed here matches Go on
        // every shape Go can see.
        let junk = vec![b'a'; MAX_HEALTH_RESPONSE_HEAD + 1024];
        let (addr, _handle) = spawn_raw_server(Some(junk)).await;
        let url = format!("http://{addr}/healthz");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(
            err.contains("cap without terminator"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn http_probe_unterminated_oversized_head_with_valid_status_line_fails() {
        // A valid status line does NOT rescue an unterminated head: the
        // reader only yields a verdict at the CRLFCRLF terminator (Go
        // ReadResponse parity), so hitting the 16 KiB cap with no blank
        // line in sight fails the check even though "HTTP/1.1 200 OK\r\n"
        // arrived first. Divergence vs Go (which has no cap): a legit
        // >16 KiB response head that completes would be UP in Go and is
        // DOWN here — a documented hardening bound, pathological for a
        // health endpoint.
        let mut head = b"HTTP/1.1 200 OK\r\n".to_vec();
        head.extend(std::iter::repeat_n(b'x', MAX_HEALTH_RESPONSE_HEAD));
        let (addr, _handle) = spawn_raw_server(Some(head)).await;
        let url = format!("http://{addr}/healthz");
        let err = run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .unwrap_err();
        assert!(
            err.contains("cap without terminator"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn http_probe_head_and_body_in_one_segment_succeeds() {
        // Real backends flush head + body in one segment (Go net/http,
        // nginx, hyper single writev). The reader must stop at the FIRST
        // blank line — Go http.ReadResponse reads the head only, body
        // unread — and never require the stream to end at the terminator
        // (body bytes after it would otherwise read to EOF and DOWN a
        // healthy 2xx). Regression pin for the round-3 review BLOCKER.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let (addr, _handle) = spawn_raw_server(Some(raw)).await;
        let url = format!("http://{addr}/healthz");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn http_probe_lf_only_head_succeeds() {
        // Minimal/embedded HTTP/1.0-era servers may end lines with a lone
        // \n. Go net/textproto ReadLine accepts it (strips only a preceding
        // \r), so the blank line terminates the head there too — UP, not
        // "truncated".
        let raw = b"HTTP/1.1 200 OK\nContent-Length: 5\n\n".to_vec();
        let (addr, _handle) = spawn_raw_server(Some(raw)).await;
        let url = format!("http://{addr}/healthz");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn http_probe_mixed_eol_head_succeeds() {
        // Audit round 7 (S1): Go textproto.ReadLine strips ONE trailing \r
        // per line and accepts a lone \n, so a head whose header lines end
        // in bare \n may still terminate with a CRLF blank line — the mixed
        // shape `...\n\r\n` contains neither the \r\n\r\n nor the \n\n
        // window the old terminator scan matched. A server sending this
        // shape therefore never yielded a verdict: the head read ran on
        // until EOF ("head truncated") and DOWNed a healthy 2xx that Go
        // verdicts UP. Regression pin for the round-7 head_end fix.
        let raw = b"HTTP/1.1 200 OK\nContent-Length: 5\n\r\n".to_vec();
        let (addr, _handle) = spawn_raw_server(Some(raw)).await;
        let url = format!("http://{addr}/healthz");
        assert!(run_http_check(&addr, &url, Duration::from_secs(5), &[])
            .await
            .is_ok());
    }

    #[test]
    fn mixed_eol_head_ends_at_blank_line() {
        // The local head_terminator (round-7 S1 replacement) is gone — the
        // read path now uses frp_core::textproto::head_end (unit-tested in
        // frp-core). This pin keeps the health-specific shapes at the
        // helper level: mixed LF/CRLF lines terminate at the blank line,
        // and bytes past it are not part of the head.
        let cases: &[(&[u8], Option<usize>)] = &[
            (b"HTTP/1.1 200 OK\r\n\r\n", Some(19)),
            (b"OK\n\n", Some(4)),
            // The round-7 missed shape: LF header lines + CRLF blank.
            (b"HTTP/1.1 200 OK\nContent-Length: 5\n\r\n", Some(36)),
            (b"OK\r\n\r\nbody", Some(6)),
            (b"a\r\nb\r\n\r\n", Some(8)),
            (b"HTTP/1.1 200 OK\r\nx", None), // no blank line yet
        ];
        for (head, want) in cases {
            assert_eq!(
                frp_core::textproto::head_end(head),
                *want,
                "head: {:?}",
                String::from_utf8_lossy(head)
            );
        }
    }

    // ---- GAP8 (round-6 audit): URL/authority parse helpers had zero
    // direct pins (only e2e-shaped indirect coverage) ----

    #[test]
    fn parse_health_url_shapes() {
        let u = parse_health_url("http://example.com:8080/healthz?x=1").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 8080);
        assert_eq!(u.target, "/healthz?x=1");
        // Bare authority targets "/"; a leading '?' target gains '/'.
        assert_eq!(parse_health_url("http://h").unwrap().target, "/");
        assert_eq!(parse_health_url("http://h?q").unwrap().target, "/?q");
        // Bracketed IPv6 authority is de-bracketed into the dial host.
        let u = parse_health_url("http://[::1]:8080/x").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 8080);
        // Fragments never enter the request target.
        assert_eq!(parse_health_url("http://h/p#frag").unwrap().target, "/p");
        // Fail-closed shapes.
        assert!(parse_health_url("https://h/p").is_err());
        assert!(parse_health_url("nonsense").is_err());
        assert!(parse_health_url("http://h:abc/x").is_err());
        // Empty authority parses with an empty host + default port (Go
        // url.Parse parity — "http:///path" has Host ""; the probe then
        // fails at the dial).
        let u = parse_health_url("http:///path").unwrap();
        assert!(u.host.is_empty());
        assert_eq!(u.port, 80);
    }

    #[test]
    fn split_url_authority_shapes() {
        // host:port, default port, bracketed v6 with/without port,
        // unbracketed v6 from a last-colon split.
        assert_eq!(split_url_authority("h:80"), Some(("h".into(), 80)));
        assert_eq!(split_url_authority("h"), Some(("h".into(), 80)));
        assert_eq!(
            split_url_authority("[::1]:8080"),
            Some(("::1".into(), 8080))
        );
        assert_eq!(split_url_authority("[::1]"), Some(("::1".into(), 80)));
        assert_eq!(split_url_authority("::1:8080"), Some(("::1".into(), 8080)));
        // Fail-closed: empty host, non-numeric port, bracket garbage
        // ("[::1]x]:80" — Go tooManyColons/missingPort parity), malformed
        // IPv6 split.
        assert_eq!(split_url_authority(":80"), None);
        assert_eq!(split_url_authority("h:abc"), None);
        assert_eq!(split_url_authority("[::1]x]:80"), None);
        assert_eq!(split_url_authority("[]:80"), None);
        assert_eq!(split_url_authority("::1"), None);
    }

    #[test]
    fn resolve_redirect_url_shapes() {
        // Relative reference merges against the base directory (RFC 3986).
        assert_eq!(
            resolve_redirect_url("http://h/a/b?q", "ok").unwrap(),
            "http://h/a/ok"
        );
        // Absolute-path reference replaces the whole path.
        assert_eq!(
            resolve_redirect_url("http://h/a/b?q", "/new").unwrap(),
            "http://h/new"
        );
        // Scheme-relative reference takes the current scheme.
        assert_eq!(
            resolve_redirect_url("http://h/a", "//other/p").unwrap(),
            "http://other/p"
        );
        // Fragment-only Location strips to nothing (no-fragment re-probe).
        assert_eq!(
            resolve_redirect_url("http://h/a", "#frag").unwrap(),
            "http://h/a"
        );
        // Empty Location resolves to the current URL (redirect loop is
        // bounded by the hop counter).
        assert_eq!(
            resolve_redirect_url("http://h/a", "").unwrap(),
            "http://h/a"
        );
        // https (or any non-http scheme) is refused — the probe has no TLS
        // stack; the verdict lands on the redirecting response.
        assert!(resolve_redirect_url("http://h/a", "https://t/x").is_err());
    }

    #[test]
    fn parse_status_line_gates() {
        // Go ReadResponse/Atoi parity: any HTTP/x.y version, all-digit
        // codes (leading zeros accepted, Atoi-style), non-numeric codes
        // and malformed versions fail.
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/2.0 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 0200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 200"), Some(200));
        assert_eq!(parse_status_code("HTTP/1 200 OK"), None);
        assert_eq!(parse_status_code("HTTP/1.1 20A OK"), None);
        assert_eq!(parse_status_code("FOO 200 OK"), None);
        assert_eq!(parse_status_code(""), None);
    }
}
