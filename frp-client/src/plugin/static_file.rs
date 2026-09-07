use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::debug;

use frp_core::config::PluginConfig;

use super::http::HttpProxyAuth;
use super::{serve_plugin, urlencoding_decode, PluginHandle};

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
            "static_file plugin requires local_path".into(),
        ));
    }
    let auth = HttpProxyAuth::from_config(cfg);
    let local_path = cfg.local_path.clone();
    let strip_prefix: Option<String> = if cfg.strip_prefix.is_empty() {
        None
    } else {
        Some(cfg.strip_prefix.trim_matches('/').to_string())
    };
    // The base directory is canonicalized PER REQUEST inside
    // `handle_static_file_conn` (see the audit-F comment there) — a startup
    // cache went stale when a base-dir symlink retargeted after startup
    // (versioned deploys like /var/www/current), 403ing every file
    // (round-17 review LOW).
    let state = (auth, local_path, strip_prefix);
    serve_plugin(
        "static_file",
        state,
        |stream, peer, (a, lp, sp)| async move {
            if let Err(e) = handle_static_file_conn(stream, a, &lp, sp.as_deref()).await {
                debug!(%peer, error = %e, "static_file: {peer} error: {e}");
            }
        },
    )
    .await
}

async fn handle_static_file_conn(
    mut client: TcpStream,
    auth: HttpProxyAuth,
    local_path: &str,
    strip_prefix: Option<&str>,
) -> Result<(), String> {
    // Read the request head in chunks. Head end follows Go textproto
    // semantics (the engine behind http.ReadRequest): each line ends at the
    // next '\n' with ONE trailing '\r' stripped, and the first empty line
    // ends the head — so LF-only and mixed-EOL heads are legal, not just
    // \r\n\r\n. Stop at the first empty line anywhere in the buffer (not
    // only at its end): a pipelined or body-carrying request may follow the
    // head terminator with more bytes, and the tail-only check would read
    // past it into the next request until the 64 KiB cap.
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
            if frp_core::textproto::head_end(&buf).is_some() {
                break;
            }
            if buf.len() > 65536 {
                return Err("request too large".into());
            }
        }
        Ok::<Vec<u8>, String>(buf)
    })
    .await
    .map_err(|_| "read headers timed out".to_string())??;

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Audit FIX 7: request line via the shared Go-parity parser
    // (plugin/mod.rs `parse_request_line` — splitn(3, ' ') with every part
    // non-empty + request-side Go ParseHTTPVersion semantics; the frps vhost
    // front has already 505-gated 1.x-only, mirroring http.rs). The old
    // split_whitespace collapsed tab-joined lines into parseable tokens —
    // accept-where-Go-rejects. A malformed line renders Go's generic server
    // 400 (same byte shape as http.rs's plain arm), never a silent close.
    let request_line = lines.next().ok_or("empty request")?;
    let Some((method, target, _version)) = super::parse_request_line(request_line) else {
        if let Err(e) = client.write_all(super::GO_400_RENDER.as_bytes()).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err(format!("bad request line: {request_line}"));
    };

    // Go url.Parse parity (audit round-7 finding): the request target
    // splits at the FIRST '?'. The path is decoded and resolved below;
    // the query stays RAW — never decoded into the path, never part of
    // file resolution — and survives verbatim into a 301 Location (Go
    // fs.go localRedirect appends RawQuery). The old code let the query
    // ride along into file resolution, so every ?-request looked up a
    // "name?query"-shaped filename and 404'd.
    let (url_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };

    // Check auth (Authorization header with Basic scheme). Audit FIX 10:
    // the same single header pass collects If-Modified-Since for the 304
    // precondition (Go's http.FileServer would read it via Header.Get after
    // auth — one pass, one trim, same result).
    let mut authorization = String::new();
    let mut if_modified_since = None;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("authorization") {
                authorization = value.to_string();
            } else if key.eq_ignore_ascii_case("if-modified-since") {
                if_modified_since = Some(value.to_string());
            }
        }
    }

    if !auth.check(&authorization) {
        // Go frp compat: 200ms delay to slow brute-force attacks.
        sleep(Duration::from_millis(200)).await;
        // Go frp static_file.go wraps NewHTTPAuthMiddleware
        // (pkg/util/net/http.go:45-59): realm "Restricted" + http.Error →
        // text/plain body "Unauthorized\n", nosniff, no Connection header.
        // (Probe-verified against Go v0.71.0; Go also adds net/http's Date.)
        let resp = b"HTTP/1.1 401 Unauthorized\r\n\
                       Content-Length: 13\r\n\
                       Content-Type: text/plain; charset=utf-8\r\n\
                       WWW-Authenticate: Basic realm=\"Restricted\"\r\n\
                       X-Content-Type-Options: nosniff\r\n\
                       \r\n\
                       Unauthorized\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("auth failed".into());
    }

    // Decode URL and strip prefix to get relative filesystem path.
    // Audit FIX 6: a URL outside the route (Go: gorilla PathPrefix route
    // miss → http.NotFound) renders Go's 404 page — byte-exact — then
    // closes. Never a silent close, and never the old code's
    // prefix-passthrough that served "/staticx/y" as "x/y".
    let (rel_path, url_remainder) = match resolve_static_path(url_path, strip_prefix) {
        Ok(parts) => parts,
        Err(e) => {
            if let Err(we) = client
                .write_all(super::GO_404_NOT_FOUND_RENDER.as_bytes())
                .await
            {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(e);
        }
    };

    // Sanitize: reject path traversal (component-level check). Audit FIX 9:
    // resolve_static_path now cleans root-anchored (Go path.Clean), so no
    // ".."/empty/"." component can survive — this is unreachable defense
    // kept for depth (Go needs no equivalent: the cleaned name cannot
    // escape http.Dir either).
    if !validate_rel_path(&rel_path) {
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("path traversal rejected".into());
    }

    // Build full filesystem path
    let mut full_path = std::path::PathBuf::from(local_path);
    if !rel_path.is_empty() {
        full_path = full_path.join(&rel_path);
    }

    // Go http.FileServer localRedirect parity (audit round-7 finding): a
    // directory URL that does not end in '/' answers 301 Moved Permanently
    // with Location = path.Base(stripped URL path) + "/" — RELATIVE, so it
    // stays correct under the strip prefix (Go fs.go:709-712, "./" for
    // .../index.html and dirList included) — plus "?" + RawQuery when the
    // request has a query (fs.go localRedirect appends it verbatim). Go
    // redirects BEFORE index.html is served: the relative links inside a
    // served index.html would otherwise resolve against the slash-less
    // URL. The redirect is also method-agnostic — http.FileServer serves
    // every method, and gorilla's GET gate is what limits Go frp to
    // GET/HEAD — so it fires for any method that reaches this point (the
    // 405 gate below is deliberately after it). Auth still precedes it
    // (Go frp's middleware wraps the whole FileServer handler: 401 first,
    // then the redirect). Render is frp-rs-shaped: Go's wire adds a Date
    // header and keep-alives the conn, this plugin closes after every
    // response (repo convention, no Date anywhere).
    let slash_terminated = url_remainder.is_empty() || url_remainder.ends_with('/');
    if full_path.is_dir() && !slash_terminated {
        // Go path.Base of the stripped URL path: last non-empty segment
        // ("." for a bare trailing "/." — path.Base("") is unreachable:
        // an empty remainder only follows an exact-boundary request like
        // "/static/", which is slash-terminated).
        let base = url_remainder
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(".");
        let mut location = format!("{base}/");
        if let Some(q) = raw_query {
            location.push('?');
            location.push_str(q);
        }
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        if let Err(e) = client.write_all(resp.as_bytes()).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err(format!("directory without trailing slash: {url_path}"));
    }

    // Method gate. gorilla Methods("GET") matches HEAD requests too (mux.go
    // rewrites HEAD onto a GET-only route), so HEAD serves below (Audit
    // FIX 10: same 200 head — Content-Length included — no body). Other
    // methods are gorilla route misses (Go would 404); the pre-existing 405
    // divergence is kept. The gate sits BELOW the directory redirect and
    // the auth check: Go FileServer's localRedirect answers the
    // slash-less-dir 301 for any method (audit round-7 finding), and Go
    // frp's auth middleware wraps the handler — so a wrong-creds
    // non-GET/HEAD request now answers 401 where the old pre-auth gate
    // answered 405 (both diverge from Go's 404 route miss; 401 matches
    // Go's auth-before-handler ordering).
    if method != "GET" && method != "HEAD" {
        let resp =
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err(format!("method not allowed: {method}"));
    }

    // If directory (slash-terminated, or just redirected above), try index.html
    if full_path.is_dir() {
        full_path = full_path.join("index.html");
    }

    // Defense-in-depth: canonicalize the base directory, then open the file
    // and verify via the ALREADY-OPENED handle that it stays within the base.
    // The verification must resolve the open fd's inode, not re-resolve the
    // path: re-canonicalizing the path after open() lets a symlink swap
    // between the two make the check disagree with the opened inode (TOCTOU).
    // Round-17 audit F: the base is canonicalized per request — a startup
    // cache went stale when a base-dir symlink retargeted (versioned deploys)
    // and 403'd every file (round-17 review LOW). Go's http.FileServer
    // canonicalizes per request too; the cost is a short path walk per
    // request, not per byte.
    let base = std::fs::canonicalize(local_path)
        .map_err(|e| format!("failed to resolve base directory '{}': {e}", local_path))?;

    // Open the file first, then check the canonical path on the open handle.
    let file = match std::fs::File::open(&full_path) {
        Ok(f) => f,
        Err(_) => {
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            if let Err(e) = client.write_all(resp).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err(format!("file not found: {}", full_path.display()));
        }
    };

    // Linux: canonicalize via /proc/self/fd/<fd> — the fd symlink resolves to
    // the inode the handle is pinned to, closing the TOCTOU window (a symlink
    // swap after open() cannot change what the fd points at).
    #[cfg(target_os = "linux")]
    let resolved = {
        use std::os::unix::io::AsRawFd;
        std::fs::canonicalize(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|e| format!("failed to resolve path: {e}"))?
    };
    // Non-Linux: no /proc/self/fd — re-canonicalize the path. The residual
    // race (a symlink swap between open() and canonicalize() making the
    // check disagree with the opened inode) is accepted here; the check
    // remains defense-in-depth on top of the component-level path validation.
    #[cfg(not(target_os = "linux"))]
    let resolved =
        std::fs::canonicalize(&full_path).map_err(|e| format!("failed to resolve path: {e}"))?;
    if !resolved.starts_with(&base) {
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("path traversal rejected".into());
    }

    // Stream the file body in bounded chunks instead of buffering it whole:
    // the old path blocked the async task on std::fs::read_to_end and
    // truncated at 64 MiB (Content-Length then lied). Go's http.FileServer
    // streams the file — so do we, from the already-open, inode-verified
    // handle (tokio::fs::File wraps the same fd; position is still 0).
    let mut file = tokio::fs::File::from_std(file);
    let meta = file
        .metadata()
        .await
        .map_err(|e| format!("failed to stat file: {e}"))?;
    let size = meta.len();
    let mtime = mtime_secs(&meta);
    let mime = mime_from_path(&full_path);

    // Audit FIX 10: If-Modified-Since precondition — Go serveContent
    // checkPreconditions. The mtime is truncated to whole seconds (the
    // header has 1 s resolution); mtime <= IMS → 304, rendered BEFORE the
    // entity headers and with NO body, NO Content-Length, NO Last-Modified
    // (the frp-rs render prescribed by the audit; Go's writeNotModified
    // drops Last-Modified only when an ETag is set — FileServer never sets
    // one). An unparsable IMS is condNone → serve 200 (Go http.ParseTime
    // error). A None mtime (platform cannot report it, pre-epoch clock)
    // disables both Last-Modified and the precondition — Go's zero modtime
    // behaves the same.
    if let Some(ims) = if_modified_since
        .as_deref()
        .and_then(parse_if_modified_since)
    {
        if let Some(mt) = mtime {
            if mt <= ims {
                let resp = b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
                client
                    .write_all(resp)
                    .await
                    .map_err(|e| format!("write 304: {e}"))?;
                return Ok(());
            }
        }
    }

    // Audit FIX 10: the 200 arm gains Last-Modified: <mtime as RFC 1123 GMT>
    // (Go serveContent setLastModified). HEAD — gorilla GET-method matches
    // HEAD — serves the identical head (Content-Length included) with no
    // body (Go serveContent: `if r.Method == "HEAD" { return }`).
    let mut head = format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\n");
    if let Some(mt) = mtime {
        head.push_str(&format!("Last-Modified: {}\r\n", format_http_date(mt)));
    }
    head.push_str(&format!(
        "Content-Length: {size}\r\nConnection: close\r\n\r\n"
    ));
    client
        .write_all(head.as_bytes())
        .await
        .map_err(|e| format!("write headers: {e}"))?;
    if method == "HEAD" {
        return Ok(());
    }

    // (Documented gaps vs Go FileServer: no gzip compression of served
    // files, no Range/206 handling, no If-None-Match — the audit scoped
    // Last-Modified/304 only.)
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut chunk)
            .await
            .map_err(|e| format!("failed to read file: {e}"))?;
        if n == 0 {
            break;
        }
        client
            .write_all(&chunk[..n])
            .await
            .map_err(|e| format!("write body: {e}"))?;
    }

    Ok(())
}

/// Resolve a URL path to a relative filesystem path, with optional prefix
/// stripping. Returns a relative path (no leading `/`), "" for the root, or
/// Err for a route miss.
///
/// Go frp static_file.go (gorilla router + http.FileServer) semantics:
/// - The URL path is URL-DECODED first — url.Parse decodes URL.Path before
///   the gorilla PathPrefix regexp matches and StripPrefix runs, so "%2F"
///   acts as a real "/" (audit round-8 FIX 8 keeps "+" literal — PlusToSpace
///   is query-only).
/// - The strip_prefix route matches ONLY at a component boundary: gorilla
///   registers PathPrefix("/{prefix}/"), so "/static", "/staticx/y" and
///   "/staticx" are route misses (Audit FIX 6) while "/static/..." strips
///   everything after the boundary.
/// - The remainder is cleaned ANCHORED AT THE URL ROOT — Go path.Clean over
///   the root-joined name (serveFile: `path.Clean(upath)`): "//" and "/./"
///   collapse, "/a/../b" is "b", and ".." clamps at the root — "/../x"
///   cleans to "/x" and can never escape (Audit FIX 9). The old code
///   returned ".." components for the caller to reject (403); Go serves the
///   anchored result (200).
fn resolve_static_path(url_path: &str, strip_prefix: Option<&str>) -> Result<String, String> {
    Ok(resolve_static_parts(url_path, strip_prefix)?.0)
}

/// Shared resolver body: returns (cleaned relative path, decoded remainder
/// of the URL path after the strip boundary). The remainder is the UNcleaned
/// path Go's serveFile/localRedirect reason over (audit round-7 finding):
/// fs.go uses url = r.URL.Path — after StripPrefix, i.e. the decoded path
/// minus the prefix — for both the trailing-slash test and the
/// path.Base(url) redirect target, never the cleaned name.
fn resolve_static_parts(
    url_path: &str,
    strip_prefix: Option<&str>,
) -> Result<(String, String), String> {
    // URL-decode
    let decoded = urlencoding_decode(url_path);

    let stripped: &str = match strip_prefix {
        Some(prefix) => {
            let boundary = format!("/{prefix}/");
            match decoded.strip_prefix(&boundary) {
                Some(rest) => rest,
                None => {
                    return Err(format!(
                        "prefix '/{prefix}/' not at a path boundary in '{decoded}'"
                    ));
                }
            }
        }
        None => decoded.as_str(),
    };

    // Root-anchored clean (Go path.Clean): empty and "." components vanish,
    // ".." pops the previous component and clamps at the root.
    let mut components: Vec<&str> = Vec::new();
    for part in stripped.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }
    Ok((components.join("/"), stripped.to_string()))
}

/// Detect MIME type from file extension.
///
/// Audit FIX 9: .js/.xml match Go's mime package BUILTIN table
/// (mime/type.go builtinTypesLower: ".js" = text/javascript; charset=utf-8,
/// ".xml" = text/xml; charset=utf-8) — the old application/javascript /
/// application/xml rows were the /etc/mime.types OS-table answers on many
/// Linux distros (Go consults the builtin first, then the OS table, so a
/// system whose mime.types overrides gets the OS value — frp-rs pins the
/// Go builtin; documented divergence).
fn mime_from_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "text/xml; charset=utf-8",
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

/// Validate a relative path for path traversal attempts.
/// Returns true if the path is safe to use (no empty components, no `.`, no `..`).
fn validate_rel_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    !path
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
}

/// Whole-second unix mtime of a file metadata, or None when the platform
/// cannot report one (Go: a zero modtime disables Last-Modified and the 304
/// precondition — same outcome).
fn mtime_secs(meta: &std::fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

const HTTP_WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HTTP_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 for a civil date (Howard Hinnant's days_from_civil).
/// Only used for dates ≥ 1970-01-01 (all inputs non-negative).
fn civil_to_days(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = (month + 9) % 12; // March = 0 of the shifted year
    let doy = (153 * mp as i64 + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date (year, month, day) for days since 1970-01-01 (Hinnant's
/// inverse — the civil_from_days algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Render a unix timestamp as the HTTP-date form Go's http.TimeFormat
/// emits — IMF-fixdate / RFC 1123: "Mon, 02 Jan 2006 15:04:05 GMT".
/// Table-driven; no chrono (dependency policy).
fn format_http_date(unix_secs: u64) -> String {
    let days = (unix_secs / 86400) as i64;
    let secs_of_day = unix_secs % 86400;
    // 1970-01-01 was a Thursday → weekday index (Sunday = 0) is (days + 4) % 7.
    let wd = ((days + 4).rem_euclid(7)) as usize;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        HTTP_WEEKDAYS[wd],
        day,
        HTTP_MONTHS[(month - 1) as usize],
        year,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Parse an If-Modified-Since value — the IMF-fixdate / RFC 1123 shape
/// ("Mon, 02 Jan 2006 15:04:05 GMT") — into whole unix seconds.
///
/// Mirrors Go's checkIfModifiedSince path: a value that fails to parse is
/// condNone (serve 200, no 400/403). The weekday token must be one of the
/// seven abbreviated names — Go time.Parse looks it up case-insensitively
/// but NEVER cross-checks it against the date ("ignore weekday except for
/// error checking", format.go): "Fri, 01 Jan 2000 00:00:00 GMT" parses
/// clean in Go though 2000-01-01 was a Saturday, and Go answers 304
/// (probe-verified against go1.25.12). The zone must be the literal "GMT"
/// (RFC 1123 mandates GMT; Go's layout would also tolerate any other
/// 3-letter abbreviation at zero offset — accepting GMT only is
/// byte-identical for every client echoing a server-emitted date), and the
/// calendar date must exist (Feb 30 normalizes → rejected — Go time.Parse
/// errors the same way). One documented leniency: a space-padded
/// single-digit day is accepted ("Mon,  2 Jan 2006 ...") — Go's RFC1123
/// layout element is '02', which requires TWO digits, so that shape errors
/// in Go and Go re-serves 200 where frp-rs answers 304. The divergence is
/// RFC 7232-safe (a 304 only ever revalidates a copy the client holds) and
/// answers stale only for clients that never see Go servers.
fn parse_if_modified_since(value: &str) -> Option<u64> {
    let v = value.trim();
    // "Weekday, day month year clock GMT" — the weekday must be one of the
    // seven abbreviated names (Go's layout needs a real name: time.Parse
    // does a case-insensitive lookup and fails the whole parse otherwise),
    // but it is never cross-checked against the date (see the fn doc — Go
    // answers 304 for a wrong-but-valid weekday). Anything without the
    // comma shape fails (Go's layout needs the comma too).
    let (weekday, rest) = v.split_once(',')?;
    if !HTTP_WEEKDAYS
        .iter()
        .any(|&w| w.eq_ignore_ascii_case(weekday))
    {
        return None;
    }
    let mut parts = rest.split_whitespace();
    let day: u32 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    let zone = parts.next()?;
    if parts.next().is_some() || zone != "GMT" {
        return None;
    }
    let month = HTTP_MONTHS.iter().position(|&m| m == month_name)? as u32 + 1;
    if !(1970..=9999).contains(&year) || day == 0 || day > 31 {
        return None;
    }
    let mut clock_parts = clock.split(':');
    let hour: u64 = clock_parts.next()?.parse().ok()?;
    let minute: u64 = clock_parts.next()?.parse().ok()?;
    let second: u64 = clock_parts.next()?.parse().ok()?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = civil_to_days(year, month, day);
    // Calendar validity: the civil date must round-trip (Feb 30 rolls to
    // Mar 1 → rejected; Go time.Parse errors on an out-of-range
    // day-of-month the same way). No weekday-vs-date consistency check
    // here — Go never validates that (audit round-7 finding, probe: "Fri,
    // 01 Jan 2000" parses and answers 304 though 2000-01-01 was a
    // Saturday).
    let (y2, m2, d2) = civil_from_days(days);
    if y2 != year || m2 != month || d2 != day {
        return None;
    }
    Some(days as u64 * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_static_path_no_prefix() {
        assert_eq!(resolve_static_path("/", None).unwrap(), "");
        assert_eq!(
            resolve_static_path("/index.html", None).unwrap(),
            "index.html"
        );
        assert_eq!(
            resolve_static_path("/css/style.css", None).unwrap(),
            "css/style.css"
        );
        assert_eq!(
            resolve_static_path("/a/b/c.html", None).unwrap(),
            "a/b/c.html"
        );
    }

    #[test]
    fn test_resolve_static_path_with_prefix() {
        let sp = Some("static");
        assert_eq!(resolve_static_path("/static/", sp).unwrap(), "");
        assert_eq!(
            resolve_static_path("/static/index.html", sp).unwrap(),
            "index.html"
        );
        assert_eq!(
            resolve_static_path("/static/css/style.css", sp).unwrap(),
            "css/style.css"
        );
        // "%2F" decodes to a real "/" BEFORE the boundary check (Go: url.Parse
        // decodes URL.Path, gorilla matches the decoded path) — this strips.
        assert_eq!(resolve_static_path("/static%2Fx", sp).unwrap(), "x");
    }

    #[test]
    fn test_resolve_static_path_prefix_mismatch() {
        assert!(resolve_static_path("/other/file.html", Some("static")).is_err());
        assert!(resolve_static_path("/", Some("static")).is_err());
        // Audit FIX 6: the route is gorilla PathPrefix("/static/") — a
        // component boundary is required. "/static" (no trailing component)
        // and "/staticx/..." are route misses → 404, never a strip.
        assert!(resolve_static_path("/static", Some("static")).is_err());
        assert!(resolve_static_path("/staticx/y", Some("static")).is_err());
        assert!(resolve_static_path("/static.x", Some("static")).is_err());
    }

    #[test]
    fn test_mime_from_path() {
        use std::path::Path;
        assert_eq!(
            mime_from_path(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            mime_from_path(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
        // Audit FIX 9: Go mime builtin table (mime/type.go) — the old rows
        // were the /etc/mime.types answers on many distros.
        assert_eq!(
            mime_from_path(Path::new("app.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            mime_from_path(Path::new("data.xml")),
            "text/xml; charset=utf-8"
        );
        assert_eq!(mime_from_path(Path::new("image.png")), "image/png");
        assert_eq!(mime_from_path(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(
            mime_from_path(Path::new("unknown.xyz")),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_resolve_static_path_anchors_dotdot() {
        // Audit FIX 9: the remainder is cleaned anchored at the URL root
        // (Go path.Clean("/"+name)) — ".." clamps at the root and can never
        // escape; it never reaches validate_rel_path. The old code returned
        // "../etc/passwd" for the caller to reject (403); Go serves the
        // anchored result (200).
        assert_eq!(
            resolve_static_path("/../etc/passwd", None).unwrap(),
            "etc/passwd"
        );
        assert_eq!(resolve_static_path("/../x", None).unwrap(), "x");
        assert_eq!(resolve_static_path("/a/../b.txt", None).unwrap(), "b.txt");
        assert_eq!(resolve_static_path("/a/b/../../c", None).unwrap(), "c");
        // Repeated slashes collapse (Go Clean), and the strip-prefix
        // boundary holds on the collapsed form for the no-prefix arm too.
        assert_eq!(resolve_static_path("//x//y", None).unwrap(), "x/y");
        assert_eq!(resolve_static_path("/a//b", None).unwrap(), "a/b");
        assert_eq!(
            resolve_static_path("/css//style.css", None).unwrap(),
            "css/style.css"
        );
        // "." components vanish.
        assert_eq!(resolve_static_path("/a/./b", None).unwrap(), "a/b");
        assert_eq!(
            resolve_static_path("/./index.html", None).unwrap(),
            "index.html"
        );
    }

    #[test]
    fn test_format_http_date() {
        // Oracle strings verified against GNU date (UTC).
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            format_http_date(1136239445),
            "Mon, 02 Jan 2006 22:04:05 GMT"
        );
        assert_eq!(format_http_date(946684800), "Sat, 01 Jan 2000 00:00:00 GMT");
        assert_eq!(
            format_http_date(1667456321),
            "Thu, 03 Nov 2022 06:18:41 GMT"
        );
    }

    #[test]
    fn test_parse_if_modified_since() {
        // Round-trip: every emitted Last-Modified parses back to the same
        // whole second (the comparison is mtime_secs <= ims_secs).
        for secs in [0u64, 946684800, 1136239445, 1667456321] {
            let s = format_http_date(secs);
            assert_eq!(parse_if_modified_since(&s), Some(secs), "round trip {s}");
        }
        // Whole-second parse of a boundary value (the e2e test drives the
        // mtime <= IMS comparison: ims 946684798 < mtime 946684800 →
        // conditional false → 200; ims >= 946684800 → 304).
        assert_eq!(
            parse_if_modified_since("Sat, 01 Jan 2000 00:00:00 GMT"),
            Some(946684800)
        );
        // Space-padded single-digit day. Documented leniency divergence:
        // Go's RFC1123 layout element is '02' (two digits), so Go
        // time.Parse errors on this shape → condNone → Go re-serves 200;
        // frp-rs answers 304 (RFC 7232-safe — a 304 only revalidates).
        assert_eq!(
            parse_if_modified_since("Sat,  1 Jan 2000 00:00:00 GMT"),
            Some(946684800)
        );
        // Wrong-but-valid weekday → accepted: Go time.Parse validates the
        // weekday NAME only ("ignore weekday except for error checking")
        // and never cross-checks it against the date — "Fri, 01 Jan 2000"
        // parses clean in Go (2000-01-01 was a Saturday) and answers 304.
        assert_eq!(
            parse_if_modified_since("Fri, 01 Jan 2000 00:00:00 GMT"),
            Some(946684800)
        );
        // Same date, different wrong weekday — 2000-02-29 was a Tuesday
        // (see test_feb_29_2000_oracle below) yet "Wed" parses (Go parity).
        assert_eq!(
            parse_if_modified_since("Wed, 29 Feb 2000 00:00:00 GMT"),
            Some(951782400)
        );
        // Not a weekday NAME at all → parse fail → condNone → 200 (Go's
        // layout lookup rejects; unlike a wrong-but-valid name).
        assert_eq!(
            parse_if_modified_since("Xyz, 01 Jan 2000 00:00:00 GMT"),
            None
        );
        // Case-insensitive weekday lookup (Go's match() folds ASCII case).
        assert_eq!(
            parse_if_modified_since("sat, 01 Jan 2000 00:00:00 GMT"),
            Some(946684800)
        );
        // Nonexistent calendar date (Feb 30 normalizes to Mar 1) → None.
        assert_eq!(
            parse_if_modified_since("Wed, 30 Feb 2000 00:00:00 GMT"),
            None
        );
        // Garbage / wrong zone / extra tokens → None (200).
        assert_eq!(parse_if_modified_since("garbage"), None);
        assert_eq!(parse_if_modified_since(""), None);
        assert_eq!(
            parse_if_modified_since("Sat, 01 Jan 2000 00:00:00 UTC"),
            None
        );
        assert_eq!(
            parse_if_modified_since("Sat, 01 Jan 2000 00:00:00 GMT extra"),
            None
        );
        assert_eq!(
            parse_if_modified_since("Sat, 01 Jan 2000 25:00:00 GMT"),
            None
        );
        assert_eq!(
            parse_if_modified_since("Sat, 01 Jan 2000 00:61:00 GMT"),
            None
        );
    }

    /// Whole-second validation of the Feb 29 2000 pin above: 2000 was a leap
    /// year, 951782400 = the 2000-02-29 00:00:00 UTC oracle (GNU date).
    #[test]
    fn test_feb_29_2000_oracle() {
        assert_eq!(format_http_date(951782400), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn test_validate_rel_path_rejects_traversal() {
        assert!(!validate_rel_path(".."));
        assert!(!validate_rel_path("../etc/passwd"));
        assert!(!validate_rel_path("foo/../../bar"));
        assert!(!validate_rel_path("."));
        assert!(!validate_rel_path("./config"));
        assert!(!validate_rel_path("foo/./bar"));
        assert!(!validate_rel_path("foo//bar"));
        assert!(!validate_rel_path("foo///bar"));
        // urlencoding_decode would decode %2F to /, which would produce
        // an empty component and be rejected
        assert!(!validate_rel_path("foo//bar"));
    }

    #[test]
    fn test_validate_rel_path_allows_normal() {
        assert!(validate_rel_path(""));
        assert!(validate_rel_path("index.html"));
        assert!(validate_rel_path("css/style.css"));
        assert!(validate_rel_path("a/b/c.html"));
        assert!(validate_rel_path("file.with..dots"));
        assert!(validate_rel_path("something..test"));
    }

    // ---- Audit FIX 6-10 e2e pins (real plugin listener + temp dir) ----

    async fn start_static(dir: &std::path::Path, strip: Option<&str>) -> Option<PluginHandle> {
        let cfg = PluginConfig {
            plugin_type: "static_file".into(),
            local_path: dir.to_str().unwrap_or("").into(),
            strip_prefix: strip.unwrap_or("").into(),
            ..Default::default()
        };
        match start_static_file_proxy(&cfg).await {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("Skipping test: cannot start static_file plugin (sandboxed?): {e}");
                None
            }
        }
    }

    /// One raw request over a fresh conn; full response until the server
    /// closes (every static_file response is Connection: close).
    async fn raw_get(addr: std::net::SocketAddr, req: &[u8]) -> Vec<u8> {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(req).await.unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        resp
    }

    fn write_file(dir: &std::path::Path, name: &str, body: &[u8]) {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, body).unwrap();
    }

    /// Audit FIX 6 + 8 e2e: prefix routing needs a component boundary
    /// (gorilla PathPrefix("/static/")) — "/staticx/y" and bare "/static"
    /// are route misses rendering Go's 404 page byte-exact, "/static/x"
    /// serves. And "+" in the URL path stays literal (PlusToSpace is
    /// query-only): /a+b must serve the "a+b" file, never "a b" (pre-fix
    /// decode turned "+" into a space and served the wrong file).
    #[tokio::test]
    async fn test_static_file_e2e_prefix_boundary_and_plus() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "x", b"boundary-content");
        write_file(dir.path(), "a+b", b"plus-body");
        write_file(dir.path(), "a b", b"space-body");
        let Some(handle) = start_static(dir.path(), Some("static")).await else {
            return;
        };
        let addr = handle.local_addr;

        assert_eq!(
            raw_get(addr, b"GET /staticx/y HTTP/1.1\r\nHost: t\r\n\r\n").await,
            super::super::GO_404_NOT_FOUND_RENDER.as_bytes(),
        );
        assert_eq!(
            raw_get(addr, b"GET /static HTTP/1.1\r\nHost: t\r\n\r\n").await,
            super::super::GO_404_NOT_FOUND_RENDER.as_bytes(),
        );
        let ok = raw_get(addr, b"GET /static/x HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            ok.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&ok)
        );
        assert!(ok.ends_with(b"boundary-content"));

        let plus = raw_get(addr, b"GET /static/a+b HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            plus.ends_with(b"plus-body"),
            "a+b must serve the 'a+b' file, got: {}",
            String::from_utf8_lossy(&plus)
        );
    }

    /// Audit FIX 9 e2e: rooted clean — "//" collapse and "/../" anchored
    /// inside the base (Go path.Clean semantics; Go serves all of these
    /// 200 — the pre-fix code 403'd the ".." shapes).
    #[tokio::test]
    async fn test_static_file_e2e_rooted_clean() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "plain.txt", b"plain-body");
        write_file(dir.path(), "sub/inner.txt", b"inner-body");
        let Some(handle) = start_static(dir.path(), None).await else {
            return;
        };
        let addr = handle.local_addr;

        let doubled = raw_get(addr, b"GET /sub//inner.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            doubled.ends_with(b"inner-body"),
            "got: {}",
            String::from_utf8_lossy(&doubled)
        );
        let anchored = raw_get(addr, b"GET /../plain.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            anchored.ends_with(b"plain-body"),
            "got: {}",
            String::from_utf8_lossy(&anchored)
        );
        let mid = raw_get(addr, b"GET /sub/../plain.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            mid.ends_with(b"plain-body"),
            "got: {}",
            String::from_utf8_lossy(&mid)
        );
        // A second ".." over the root clamps (still plain.txt — never 403).
        let clamped = raw_get(
            addr,
            b"GET /sub/../../plain.txt HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert!(
            clamped.ends_with(b"plain-body"),
            "got: {}",
            String::from_utf8_lossy(&clamped)
        );
    }

    /// Audit FIX 7 e2e: malformed request lines render Go's generic server
    /// 400 (byte-exact), never a silent close — the old split_whitespace
    /// parsed the tab-joined line as a legal request.
    #[tokio::test]
    async fn test_static_file_e2e_malformed_line_400() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "x", b"x");
        let Some(handle) = start_static(dir.path(), None).await else {
            return;
        };
        let addr = handle.local_addr;

        assert_eq!(
            raw_get(addr, b"GET\t/x\tHTTP/1.1\r\n\r\n").await,
            super::super::GO_400_RENDER.as_bytes(),
        );
        assert_eq!(
            raw_get(addr, b"GET /x\r\n\r\n").await,
            super::super::GO_400_RENDER.as_bytes(),
        );
    }

    /// Audit FIX 10 e2e: Last-Modified on 200, If-Modified-Since → 304
    /// (mtime <= IMS, whole-second truncation), unparsable IMS → 200, and
    /// HEAD serving the identical head with no body.
    #[tokio::test]
    async fn test_static_file_e2e_last_modified_and_304() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("doc.txt");
        std::fs::write(&p, b"hello-static").unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946684800);
        std::fs::File::open(&p)
            .unwrap()
            .set_modified(mtime)
            .expect("set_modified on temp file");
        let Some(handle) = start_static(dir.path(), None).await else {
            return;
        };
        let addr = handle.local_addr;

        // 200 head carries Last-Modified: <mtime as RFC 1123 GMT>.
        let ok = raw_get(addr, b"GET /doc.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let ok_s = String::from_utf8_lossy(&ok);
        assert!(
            ok_s.starts_with(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
                 Content-Length: 12\r\nConnection: close\r\n\r\n"
            ),
            "got: {ok_s}"
        );
        assert!(ok.ends_with(b"hello-static"));

        // IMS == mtime → 304: status + Connection only — no body, no
        // Content-Length, no Last-Modified.
        let eq = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                  If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT\r\n\r\n";
        assert_eq!(
            raw_get(addr, eq.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n"
        );

        // IMS one second AFTER the mtime → 304 as well (mtime <= IMS).
        let later = format_http_date(946684801);
        let after =
            format!("GET /doc.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {later}\r\n\r\n");
        assert_eq!(
            raw_get(addr, after.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n"
        );

        // IMS BEFORE the mtime (truncated whole seconds: 946684798) → 200
        // with the full body.
        let earlier = format_http_date(946684798);
        let before =
            format!("GET /doc.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {earlier}\r\n\r\n");
        let mod_resp = raw_get(addr, before.as_bytes()).await;
        assert!(
            mod_resp.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&mod_resp)
        );
        assert!(mod_resp.ends_with(b"hello-static"));

        // Unparsable IMS → condNone → 200 (Go http.ParseTime error path).
        let garbage = b"GET /doc.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: not-a-date\r\n\r\n";
        let g_resp = raw_get(addr, garbage).await;
        assert!(
            g_resp.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&g_resp)
        );

        // HEAD: identical head (Content-Length included), zero body bytes.
        let head = raw_get(addr, b"HEAD /doc.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(
            String::from_utf8_lossy(&head),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
             Content-Length: 12\r\nConnection: close\r\n\r\n"
        );
    }

    /// Audit round-7 e2e: Go http.FileServer localRedirect parity — a
    /// directory URL without the trailing slash answers 301 with the
    /// RELATIVE Location path.Base(stripped URL path) + "/" (RawQuery
    /// appended verbatim), for ANY method (FileServer's redirect precedes
    /// any method handling; frp-rs's 405 gate sits below it). The
    /// slash-terminated form serves index.html directly, and a query never
    /// reaches file resolution (Go url.Parse: Path vs RawQuery).
    #[tokio::test]
    async fn test_static_file_e2e_dir_redirect_and_index() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "sub/index.html", b"index-body");
        write_file(dir.path(), "sub/deep/inner.html", b"inner-body");
        write_file(dir.path(), "plain.txt", b"plain-body");
        let Some(handle) = start_static(dir.path(), None).await else {
            return;
        };
        let addr = handle.local_addr;

        // Slash-less dir → 301, relative Location = last path segment + "/".
        assert_eq!(
            raw_get(addr, b"GET /sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Deeper dir: base of the FULL stripped path, not just the request.
        assert_eq!(
            raw_get(addr, b"GET /sub/deep HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: deep/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // RawQuery survives into the Location (Go localRedirect appends it).
        assert_eq!(
            raw_get(addr, b"GET /sub?x=1 HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/?x=1\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // HEAD and POST redirect too (FileServer redirects any method; the
        // 405 gate below never sees a slash-less directory URL).
        assert!(raw_get(addr, b"HEAD /sub HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .starts_with(b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n"));
        assert_eq!(
            raw_get(addr, b"POST /sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Non-directory target keeps the method gate (405 divergence vs
        // Go frp's gorilla route miss → 404).
        assert_eq!(
            raw_get(addr, b"POST /plain.txt HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\
              Connection: close\r\n\r\n",
        );
        // Slash-terminated dir → 200 index.html, no redirect.
        let ok = raw_get(addr, b"GET /sub/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            ok.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&ok)
        );
        assert!(ok.ends_with(b"index-body"));
        // "%2F" decodes to a real slash (url.Parse decodes Path) → 200 too.
        let enc = raw_get(addr, b"GET /sub%2F HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            enc.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&enc)
        );
        // A query never reaches file resolution: /plain.txt?x=1 serves the
        // file (Go url.Parse splits RawQuery off Path — the old code
        // looked up a "plain.txt?x=1" filename and 404'd).
        let q = raw_get(addr, b"GET /plain.txt?x=1 HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            q.starts_with(b"HTTP/1.1 200 OK\r\n") && q.ends_with(b"plain-body"),
            "got: {}",
            String::from_utf8_lossy(&q)
        );

        // Prefix mode: Location stays relative to the STRIPPED path — the
        // browser resolves "sub/" against /static/ itself.
        let Some(pref) = start_static(dir.path(), Some("static")).await else {
            return;
        };
        let addr = pref.local_addr;
        assert_eq!(
            raw_get(addr, b"GET /static/sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let ok = raw_get(addr, b"GET /static/sub/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            ok.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&ok)
        );
        assert!(ok.ends_with(b"index-body"));
        // The exact-boundary "/static/" is slash-terminated (remainder is
        // empty) → root dir serves, never redirected.
        let root = raw_get(addr, b"GET /static/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            root.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&root)
        );
    }
}
