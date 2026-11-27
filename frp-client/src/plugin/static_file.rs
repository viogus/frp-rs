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
    // Round-16 FIX 14 (comment only): Go frp's router registers the strip
    // route as `PathPrefix("/" + StripPrefix + "/")` VERBATIM
    // (pkg/plugin/client/static_file.go): a config value carrying its own
    // slashes — "static/", "/static", "/static/" — produces the prefix
    // "/static//" or "//static/" in Go, and every real request then 404s.
    // frp-rs TRIMS the slashes and serves "static/" configs exactly like
    // "static" — a documented, deliberate divergence (friendlier; the byte
    // difference exists only for configs Go cannot serve at all).
    let strip_prefix: Option<String> = if cfg.strip_prefix.is_empty() {
        None
    } else {
        Some(cfg.strip_prefix.trim_matches('/').to_string())
    };
    // The base directory is canonicalized PER REQUEST inside
    // `handle_static_file_conn` (see the audit finding D4 comment there) —
    // a startup cache went stale when a base-dir symlink retargeted after
    // startup (versioned deploys like /var/www/current), 403ing every file
    // (round-17 review LOW). Audit finding D4 reviewed hoisting the walk
    // to plugin start / reload and refused (mutable filesystem state,
    // false-ACCEPT direction) — the per-request cost is deliberate.
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
    // Deliberate divergence — gorilla's router-level cleanPath 301 is NOT
    // replicated in full. Go frp's router (gorilla mux ServeHTTP,
    // mux.go:175-200) rewrites dot-segment / duplicate-slash request paths
    // with a canonical 301 BEFORE route matching, auth, and the method gate:
    // "/static/../x" answers 301 -> "/x" (probe-verified vs gorilla v1.8.1:
    // Location is the cleaned absolute path with the query preserved). frp-rs
    // instead resolves dot-segments and duplicate slashes internally via the
    // root-anchored clean in `resolve_static_parts` and serves the canonical
    // FILE directly — no redirect round-trip: same final content, different
    // wire (200 where Go sends 301). The DIRECTORY redirect arms below must
    // then redirect from a canonical Location (round-16 FIX 11): when the
    // decoded path is non-canonical (gorilla would have cleanPath-301'd at
    // the router), they emit the single-hop ABSOLUTE Location of the cleaned
    // path + "/" (Go's two-hop chain folded into one — the second hop lands
    // on the same canonical listing); canonical paths keep Go FileServer's
    // relative path.Base + "/" Location. The method/auth gates here still
    // run in the gorilla order on the RAW path.
    //
    // Read the request head in chunks. Head end follows Go textproto
    // semantics (the engine behind http.ReadRequest): each line ends at the
    // next '\n' with ONE trailing '\r' stripped, and the first empty line
    // ends the head — so LF-only and mixed-EOL heads are legal, not just
    // \r\n\r\n. Stop at the first empty line anywhere in the buffer (not
    // only at its end): a pipelined or body-carrying request may follow the
    // head terminator with more bytes, and the tail-only check would read
    // past it into the next request.
    // Go parity: http.Server ReadHeaderTimeout (60s) — one absolute deadline
    // over the whole header read, so a slowloris "trickle" cannot park the
    // task + fd + plugin listener slot indefinitely.
    // The 1 MiB cap below is Go's http.Server MaxHeaderBytes DEFAULT on
    // this gorilla-mux/http.Server face (Go frp static_file.go serves
    // through gorilla on a stock http.Server) — the same default the
    // http.rs plugin plain arm uses. The old 64 KiB cap rejected request
    // heads Go serves: 100+ KiB Cookie or Authorization headers are legal
    // HTTP. Go enforces the cap as a READ LIMIT, not a size gate:
    // conn.readRequest sets c.r.setReadLimit(initialReadLimitSize) =
    // maxHeaderBytes + 4096 bufio slop (server.go), and the parser only
    // errors when the limit is consumed with the head still INCOMPLETE — a
    // head whose empty-line terminator arrived within the limit parses and
    // serves (the http.rs mirror loop documents the probe: a terminated
    // ~1 MiB+64 head answers 200 in go1.25). The loop below mirrors that
    // model exactly like http.rs: the terminator scan runs BEFORE the cap
    // check, so a completed head serves no matter how large the buffer
    // grew, and the 4096-byte reads reproduce Go's bufio slack — the
    // buffer can overshoot the cap by one chunk, and a terminator inside
    // that overshoot still serves (boundary parity with Go: served
    // <= ~1 MiB+4096, 431 above). Unlike http.rs there is no CONNECT arm
    // to classify — every static_file face is the plain http.Server one —
    // so a breach renders Go's 431 page (Go errTooLarge writes the render
    // before the handler runs) and errors. A truncated render is possible
    // only when the 60 s drip deadline fires mid-write — accepted: the
    // peer that overflows the cap is by definition misbehaving.
    // History (why the loop reads the way it does): before this round the
    // 64 KiB cap check sat AFTER the terminator break — a TERMINATED head
    // of any size broke out on the head_end scan and served (the cap never
    // ran on the terminator path; the old comment's claim that such heads
    // "grew unbounded" was wrong — they broke out and were served), while
    // an UNTERMINATED head hit the cap only on the loop iteration after
    // crossing 64 KiB and errored silently. The round-16-wave intermediate
    // then moved the cap check BEFORE the terminator scan and 431'd every
    // terminated head past 64 KiB — the divergence this read-limit model
    // fixes: a 70 KiB terminated head is Go-served and must serve here
    // (pin test_static_file_e2e_oversize_head_431 was flipped to prove
    // it). The old loop also re-scanned the whole buffer per 512 B chunk
    // (quadratic); round-17 finding D replaced the full-buffer rescan with
    // the incremental `HeadEndScanner` — byte-identical result, carries
    // the line offset across feeds, so the loop's per-iteration `head_end`
    // cost over the accumulated bytes is gone (the 4 KiB chunk size
    // survives for the Go bufio-slack parity it exists for).
    let buf = tokio::time::timeout(Duration::from_secs(60), async {
        let mut buf = Vec::new();
        // 4 KiB chunks: the cap check runs after the terminator scan, so
        // the buffer can overshoot 1 MiB by up to one chunk before the
        // breach is detected — Go's bufio slack is the same 4096
        // (initialReadLimitSize = MaxHeaderBytes + 4096), keeping the
        // served/431 boundary byte-aligned with Go.
        let mut chunk = [0u8; 4096];
        let mut head_scan = frp_core::textproto::HeadEndScanner::new();
        loop {
            // Terminator scan FIRST: Go's read limit only errors when the
            // limit is consumed with the head still incomplete — a head
            // whose empty line is already in the buffer was completed in
            // time and parses. Only an overshoot that contains NO
            // terminator is a breach (431 — Go errTooLarge renders before
            // the handler runs).
            if head_scan.feed(&buf).is_some() {
                break;
            }
            if buf.len() > 1024 * 1024 {
                if let Err(we) = client.write_all(super::GO_431_RENDER.as_bytes()).await {
                    tracing::debug!(error = %we, "plugin relay error: {}", we);
                }
                return Err("request head too large".into());
            }
            let n = client
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed".into());
            }
            buf.extend_from_slice(&chunk[..n]);
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

    // Gorilla route-gate order — Go frp static_file.go router wiring
    // (verified against gorilla mux v1.8.1 source + live probes). The route
    // carries PathPrefix("/<prefix>/") + Methods("GET"), and the router
    // runs its auth middleware chain ONLY when a route fully matches
    // (mux.go Router.Match: chain built iff match.MatchErr == nil). The
    // gates therefore fire in this order, each short-circuiting the rest:
    //   1. PathPrefix miss → http.NotFound 404 page (auth NOT run)
    //   2. method != "GET" → bare 405 (methodNotAllowedHandler; auth NOT
    //      run). The match is on the raw request token: HEAD is NOT
    //      rewritten onto the GET route (round-13-era claim, false —
    //      route.go methodMatcher does an exact matchInArray on r.Method;
    //      mux_test.go:2643 pins HEAD against GET-only routes → no match),
    //      and a lowercase "get" is a 405 too (no canonicalization).
    //   3. auth middleware → 401 page (Go frp router.Use wraps the
    //      handler): wrong-creds GET answers 401, wrong-creds non-GET
    //      already stopped at the bare 405 above.
    //   4. http.FileServer → 301 localRedirect / index.html / dirList /
    //      file serve.
    // Decode the URL path to BYTES (round-16 FIX 2 — byte-level decode, see
    // urlencoding_decode; non-ASCII names must survive as bytes, not as
    // Latin-1 chars) and compute the gorilla cleanPath canonical form of the
    // FULL decoded path (prefix included — gorilla cleans at the router,
    // before StripPrefix). The dir-301 arm uses both below.
    let decoded_path = urlencoding_decode(url_path);
    let canonical_full = clean_path_canonical(&decoded_path);
    let (rel_components, url_remainder) = match resolve_static_parts(&decoded_path, strip_prefix) {
        Ok(parts) => parts,
        Err(e) => {
            // Audit FIX 6: a URL outside the route (Go: gorilla PathPrefix
            // route miss → http.NotFound) renders Go's 404 page — byte-exact —
            // then closes. Never a silent close, and never the old code's
            // prefix-passthrough that served "/staticx/y" as "x/y". Precedes
            // auth and the method gate (route gate, not middleware).
            if let Err(we) = client
                .write_all(super::GO_404_NOT_FOUND_RENDER.as_bytes())
                .await
            {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(e);
        }
    };

    // Method gate — gorilla Methods("GET") exact-string match, on the ROUTE
    // ahead of the auth middleware, so it fires before auth: an
    // unauthenticated non-GET with a valid prefix path answers bare 405,
    // not 401 (probe-verified vs gorilla v1.8.1: HEAD and POST on a valid
    // path → 405, no auth in the chain). It also precedes the
    // FileServer-internal directory redirect below — a non-GET
    // slash-less-dir URL is a 405, never the 301 (probe: POST /static/sub
    // → 405 while GET /static/sub → 301). HEAD is not a route match (no
    // HEAD→GET rewrite — the round-13-era claim was false), so it answers
    // the same bare 405. Render mirrors Go's methodNotAllowedHandler (a
    // bare status write; Go's wire adds Date and — for non-HEAD — an auto
    // Content-Length: 0; frp-rs's fixed CL:0 + Connection: close head is
    // the repo's established bodyless render, also for HEAD where Go omits
    // the CL).
    if method != "GET" {
        let resp =
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err(format!("method not allowed: {method}"));
    }

    // Check auth (Authorization header with Basic scheme). Audit FIX 10:
    // the same single header pass collects If-Modified-Since for the 304
    // precondition (Go's http.FileServer would read it via Header.Get after
    // auth — one pass, one trim, same result). Runs after the route and
    // method gates (Go: the middleware wraps only fully-matched routes) and
    // before every FileServer-internal response below.
    // Audit round-18 L6: the header pass runs in Go textproto
    // readMIMEHeader stored-value shape. An obs-fold continuation line
    // (leading SP/HTAB) is part of the PRECEDING record — "Authorization:
    // Basic\n  <payload>" IS one credential in Go — where the old walker
    // re-split fold lines into bogus records (a fold after the captured
    // record simply vanished from its value) and trimmed with Unicode
    // whitespace where Go strips SP/HTAB only (textproto `trim`). Stored
    // value per record: the after-colon slice of the OWS-trimmed first
    // physical line, TrimLeft'd once, with each fold appended as ' ' + its
    // OWS-trimmed piece — unconditionally, an all-whitespace fold included.
    // The scan also stops at the head's blank line (round-17 F4 mirror):
    // the read chunk can carry PIPELINED bytes past the terminator, and
    // those bytes belong to the next request, never to this head. The
    // missing Host/TE/CL/505 conn gates are deliberately NOT rebuilt here —
    // documented defense-in-depth: the frps vhost front fully validates
    // every head before the tunnel hands it to this operator-local
    // 127.0.0.1 listener, and the gorilla route + method gates above
    // already narrowed the request class.
    let mut authorization: Option<String> = None;
    let mut if_modified_since: Option<String> = None;
    // The record currently open for fold merging: exactly one of these is
    // true for the last-seen record, and only when that record was the
    // FIRST of its key (Go Header.Get FIRST-value semantics — net/
    // textproto duplicate rows accumulate into a slice; Get returns v[0],
    // an empty-value first row included (round-16 FIX 7). A later
    // duplicate's folds belong to THAT row and must not bleed into the
    // captured first row.
    let mut cur_is_auth = false;
    let mut cur_is_ims = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if cur_is_auth {
                if let Some(v) = authorization.as_mut() {
                    v.push(' ');
                    v.push_str(line.trim_matches([' ', '\t']));
                }
            } else if cur_is_ims {
                if let Some(v) = if_modified_since.as_mut() {
                    v.push(' ');
                    v.push_str(line.trim_matches([' ', '\t']));
                }
            }
            continue;
        }
        // A fresh record: textproto trims the physical line at BOTH ends
        // (SP/HTAB) before the colon cut (readContinuedLineSlice
        // `trim(line)`).
        let trimmed = line.trim_matches([' ', '\t']);
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        // Stored value = TrimLeft once after the cut (reader.go
        // ReadMIMEHeader); the line trim above already removed the first
        // line's trailing OWS, but fold-created trailing OWS survives.
        let stored = value.trim_start_matches([' ', '\t']);
        // Keys holding SPACE never canonicalize (noCanon) and cannot match
        // (mirrors the `name_has_space` gate of the sibling walkers).
        let key_has_space = key.contains(' ');
        let is_auth = !key_has_space && key.eq_ignore_ascii_case("authorization");
        let is_ims = !key_has_space && key.eq_ignore_ascii_case("if-modified-since");
        if is_auth && authorization.is_none() {
            authorization = Some(stored.to_string());
            cur_is_auth = true;
            cur_is_ims = false;
        } else if is_ims && if_modified_since.is_none() {
            if_modified_since = Some(stored.to_string());
            cur_is_ims = true;
            cur_is_auth = false;
        } else {
            cur_is_auth = false;
            cur_is_ims = false;
        }
    }

    if !auth.check(authorization.as_deref().unwrap_or("")) {
        // Go frp compat: 200ms delay to slow brute-force attacks.
        sleep(Duration::from_millis(200)).await;
        // Go frp static_file.go wraps NewHTTPAuthMiddleware
        // (pkg/util/net/http.go:45-59): realm "Restricted" + http.Error →
        // text/plain body "Unauthorized\n", nosniff, no Connection header.
        // (Probe-verified against Go v0.71.0; Go also adds net/http's Date.)
        // Round-16 FIX 12: the header name on the wire is Go-canonicalized
        // — net/http writes "Www-Authenticate:", never the registry casing
        // "WWW-Authenticate:" (probe vs go1.25.12 and Go frp v0.71.0 both
        // emit Www-Authenticate). The old pin at the integration test
        // frp-client/tests/plugin_static_file.rs:153 asserted the uncased
        // spelling and must flip with it (out of scope here — reported).
        let resp = b"HTTP/1.1 401 Unauthorized\r\n\
                       Content-Length: 13\r\n\
                       Content-Type: text/plain; charset=utf-8\r\n\
                       Www-Authenticate: Basic realm=\"Restricted\"\r\n\
                       X-Content-Type-Options: nosniff\r\n\
                       \r\n\
                       Unauthorized\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("auth failed".into());
    }

    // Build the full filesystem path from the CLEANED relative components.
    // join_components is cfg(unix) byte-capable (OsStringExt), so non-UTF-8
    // names survive all the way to the open (round-16 FIX 2). Path traversal
    // needs no runtime check: the components come from the root-anchored
    // clean below, which admits no empty / "." / ".." member, and the
    // open-handle guard that follows is the real defense.
    let full_path = join_components(local_path, &rel_components);

    // ----------------------------------------------------------------
    // Go http.FileServer-equivalent arms (serveFile, fs.go:679-762),
    // preceded by the Rust-only guard — round-16 FIX 6: the guard runs
    // BEFORE every FileServer arm. The old order ran the directory arms
    // (dir-301, index swap, dirList) ahead of the canonicalize + fd check,
    // so a symlink-to-outside-directory 301'd and then dirListed outside
    // `local_path`. The one arm the guard does not precede is the
    // index.html-suffix redirect below — it does no file I/O and leaks
    // nothing (its refetch of the directory is itself guarded). The open
    // itself also precedes the guard (audit finding D4) — an open that
    // fails answers a serveError page and an open that succeeds is
    // verified via its fd before any arm can serve from it.
    // ----------------------------------------------------------------

    // Round-16 FIX 3 + round-17 finding I: Go serveFile's FIRST arm
    // (fs.go:682-688) — a URL path ending in "/index.html" answers 301
    // Location: ./ REGARDLESS of existence, before fs.Open (probe vs
    // go1.25.12: served AND deleted index.html both redirect; ?query
    // preserved). The redirect keeps the relative links inside a served
    // index.html resolvable against the directory. Finding I: the probe
    // runs on the CLEANED path — gorilla's router cleans URL.Path (path.
    // Clean + trailing-slash restore, mux.go:175-195/280-301) BEFORE the
    // route match and StripPrefix, so a path whose "/index.html" suffix is
    // only there after the clean ("/sub/index.html/." — the trailing "/."
    // is cleaned away) reaches serveFile as "/sub/index.html" and
    // redirects, while the uncleaned probe missed it and fell through to
    // serve the file. The router hop is folded away here (round-16 FIX 11
    // precedent), so the probe cleans the slash-reattached remainder —
    // component-boundary equivalent to stripping the prefix from the
    // cleaned full path (the prefix ends at a component boundary, so the
    // clean does not move it). Location stays "./" for cleaned and folded
    // shapes alike: the mandated pin is "/a/./b/index.html must 301 like
    // its clean form", and the browser resolves "./" from the original URL
    // onto the canonical directory either way. The reattached "/" mirrors
    // Go's StripPrefix handing FileServer "/index.html" (leading slash
    // kept); the prefix-stripped remainder lacks it, so the "/" is
    // re-attached only for the probe.
    let mut suffix_probe: Vec<u8> = Vec::with_capacity(url_remainder.len() + 1);
    if url_remainder.starts_with(b"/") {
        suffix_probe.extend_from_slice(&url_remainder);
    } else {
        suffix_probe.push(b'/');
        suffix_probe.extend_from_slice(&url_remainder);
    }
    let suffix_probe = clean_path_canonical(&suffix_probe);
    if suffix_probe.ends_with(b"/index.html") {
        // Go localRedirect(w, r, "./") — query appended only when non-empty
        // (fs.go:785-791; round-16 FIX 10).
        let mut location = Vec::with_capacity(3);
        location.extend_from_slice(b"./");
        append_raw_query(&mut location, raw_query);
        let resp = render_301(&location);
        if let Err(e) = client.write_all(&resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err(format!("index.html suffix redirect: {url_path}"));
    }

    enum StaticFsResolution {
        OpenFailed(std::io::Error),
        BaseResolveFailed(std::io::Error),
        HandleResolveFailed(String),
        PathTraversal,
        StatFailed(std::io::Error),
        DirNeedsTrailingSlash,
        DirNotModified304,
        DirListing {
            mtime: Option<u64>,
            body: String,
        },
        DirListFailed {
            canon: std::path::PathBuf,
            err: String,
        },
        FileNeedsSlashRedirect,
        FileNotModified304 {
            mt: u64,
        },
        SmallFile {
            buf: frp_core::buffer_pool::PoolGuard,
            len: usize,
            mtime: Option<u64>,
            canon: std::path::PathBuf,
        },
        SmallFileReadFailed(std::io::Error),
        LargeFile {
            file: std::fs::File,
            size: u64,
            mtime: Option<u64>,
            canon: std::path::PathBuf,
        },
    }

    fn resolve_open_file_in_blocking(
        mut file: std::fs::File,
        meta: std::fs::Metadata,
        canon: std::path::PathBuf,
        from_index: bool,
        slash_terminated: bool,
        ims_parsed: Option<u64>,
    ) -> StaticFsResolution {
        use std::io::{Read, Seek, SeekFrom};

        if !from_index && slash_terminated {
            return StaticFsResolution::FileNeedsSlashRedirect;
        }
        let mtime = mtime_secs(&meta);
        if let (Some(ims), Some(mt)) = (ims_parsed, mtime) {
            if mt <= ims {
                return StaticFsResolution::FileNotModified304 { mt };
            }
        }
        let size = meta.len();
        // Fast-path small regular files (<= 64 KiB) right inside this single
        // `spawn_blocking` hop using a pooled 64 KiB buffer, avoiding both
        // `tokio::fs::File`'s extra `spawn_blocking` read/drop hops and its
        // internal staging-buffer allocation.
        const SMALL_FILE_MAX: u64 = 64 * 1024;
        if meta.is_file() && size <= SMALL_FILE_MAX {
            let mut buf = frp_core::buffer_pool::PoolGuard::acquire();
            let cap = buf.as_mut_slice().len();
            if size <= cap as u64 {
                let mut filled = 0usize;
                loop {
                    match file.read(&mut buf.as_mut_slice()[filled..]) {
                        Ok(0) => {
                            if filled as u64 == size {
                                return StaticFsResolution::SmallFile {
                                    buf,
                                    len: filled,
                                    mtime,
                                    canon,
                                };
                            }
                            // File size changed concurrently; rewind and stream.
                            break;
                        }
                        Ok(n) => {
                            filled += n;
                            if filled == cap {
                                // Probe 1 byte to confirm EOF vs concurrent growth.
                                let mut probe = [0u8; 1];
                                match file.read(&mut probe) {
                                    Ok(0) if filled as u64 == size => {
                                        return StaticFsResolution::SmallFile {
                                            buf,
                                            len: filled,
                                            mtime,
                                            canon,
                                        };
                                    }
                                    Ok(_) => break,
                                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                                    Err(e) => return StaticFsResolution::SmallFileReadFailed(e),
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return StaticFsResolution::SmallFileReadFailed(e),
                    }
                }
                if let Err(e) = file.seek(SeekFrom::Start(0)) {
                    return StaticFsResolution::SmallFileReadFailed(e);
                }
                let refreshed_size = file.metadata().map(|m| m.len()).unwrap_or(size);
                return StaticFsResolution::LargeFile {
                    file,
                    size: refreshed_size,
                    mtime,
                    canon,
                };
            }
        }

        StaticFsResolution::LargeFile {
            file,
            size,
            mtime,
            canon,
        }
    }

    let slash_terminated = url_remainder.is_empty() || url_remainder.ends_with(b"/");
    let ims_parsed = if_modified_since
        .as_deref()
        .and_then(parse_if_modified_since);

    // Run all synchronous filesystem syscalls (open, canonicalize, fd realpath
    // containment check, stat, index.html probe, small-file read, and directory
    // listing) on Tokio's blocking pool in a single hop so slow/network
    // filesystems never stall async worker threads.
    let fs_full_path = full_path.clone();
    let fs_local_path = local_path.to_string();
    let resolution = tokio::task::spawn_blocking(move || {
        // Audit finding D4 (base canonicalize below open): open-failure arms
        // answer Go's serveError → toHTTPError pages without paying the
        // base-directory walk.
        let file = match std::fs::File::open(&fs_full_path) {
            Ok(f) => f,
            Err(e) => return StaticFsResolution::OpenFailed(e),
        };

        // Rust-only hardening: canonicalize base per request and verify via
        // the already-open handle (eliminates stale base cache and TOCTOU).
        let base = match std::fs::canonicalize(&fs_local_path) {
            Ok(b) => b,
            Err(e) => return StaticFsResolution::BaseResolveFailed(e),
        };

        let resolved = match open_handle_canonical(&file, &fs_full_path) {
            Ok(p) => p,
            Err(e) => return StaticFsResolution::HandleResolveFailed(e),
        };
        if !resolved.starts_with(&base) {
            return StaticFsResolution::PathTraversal;
        }
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) => return StaticFsResolution::StatFailed(e),
        };

        let mut f = file;
        let mut f_meta = meta;
        let mut f_canon = resolved;

        if f_meta.is_dir() {
            if !slash_terminated {
                return StaticFsResolution::DirNeedsTrailingSlash;
            }
            // Go serveFile index.html swap (fs.go:735-745): OPEN-based.
            let index_path = f_canon.join("index.html");
            if let Ok(ix) = std::fs::File::open(&index_path) {
                let ix_canon = match open_handle_canonical(&ix, &index_path) {
                    Ok(p) => p,
                    Err(e) => return StaticFsResolution::HandleResolveFailed(e),
                };
                if !ix_canon.starts_with(&base) {
                    return StaticFsResolution::PathTraversal;
                }
                if let Ok(im) = ix.metadata() {
                    f = ix;
                    f_meta = im;
                    f_canon = ix_canon;
                }
            }
            if !f_meta.is_dir() {
                return resolve_open_file_in_blocking(
                    f,
                    f_meta,
                    f_canon,
                    true,
                    slash_terminated,
                    ims_parsed,
                );
            }

            let mtime = mtime_secs(&f_meta);
            if let (Some(ims), Some(mt)) = (ims_parsed, mtime) {
                if mt <= ims {
                    return StaticFsResolution::DirNotModified304;
                }
            }
            match render_dir_listing(&f_canon) {
                Ok(body) => StaticFsResolution::DirListing { mtime, body },
                Err(err) => StaticFsResolution::DirListFailed {
                    canon: f_canon,
                    err,
                },
            }
        } else {
            resolve_open_file_in_blocking(f, f_meta, f_canon, false, slash_terminated, ims_parsed)
        }
    })
    .await
    .map_err(|e| format!("static_file blocking task failed: {e}"))?;

    match resolution {
        StaticFsResolution::OpenFailed(e) => {
            // Round-17 finding F: Go serveError → toHTTPError (fs.go:
            // 680-696) maps IsNotExist → 404 page, IsPermission → 403
            // page, anything else → 500 — every arm via http.Error.
            let resp = match e.kind() {
                std::io::ErrorKind::NotFound => super::GO_404_NOT_FOUND_RENDER.to_string(),
                std::io::ErrorKind::PermissionDenied => {
                    http_error_render("403 Forbidden", "403 Forbidden\n")
                }
                _ => http_error_render("500 Internal Server Error", "500 Internal Server Error\n"),
            };
            if let Err(we) = client.write_all(resp.as_bytes()).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("failed to open {}: {e}", full_path.display()));
        }
        StaticFsResolution::BaseResolveFailed(e) => {
            // Round-17 finding G — reachable only as a post-open race now.
            if let Err(we) = client
                .write_all(super::GO_404_NOT_FOUND_RENDER.as_bytes())
                .await
            {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!(
                "failed to resolve base directory '{}': {e}",
                local_path
            ));
        }
        StaticFsResolution::HandleResolveFailed(e) => return Err(e),
        StaticFsResolution::PathTraversal => {
            let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            if let Err(e) = client.write_all(resp).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err("path traversal rejected".into());
        }
        StaticFsResolution::StatFailed(e) => {
            return Err(format!("failed to stat {}: {e}", full_path.display()));
        }
        StaticFsResolution::DirNeedsTrailingSlash => {
            let mut location: Vec<u8>;
            if canonical_full != decoded_path {
                location = Vec::with_capacity(canonical_full.len() + 8);
                location.extend_from_slice(url_escape_bytes(&canonical_full).as_bytes());
                if canonical_full.len() > 1 {
                    location.push(b'/');
                }
            } else {
                location = Vec::with_capacity(8);
                match rel_components.last() {
                    Some(base) => location.extend_from_slice(base),
                    None => location.extend_from_slice(b"."),
                }
                location.push(b'/');
            }
            append_raw_query(&mut location, raw_query);
            let resp = render_301(&location);
            if let Err(e) = client.write_all(&resp).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err(format!("directory without trailing slash: {url_path}"));
        }
        StaticFsResolution::DirNotModified304 => {
            let resp = b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
            client
                .write_all(resp)
                .await
                .map_err(|e| format!("write 304: {e}"))?;
            return Ok(());
        }
        StaticFsResolution::DirListFailed { canon, err } => {
            tracing::debug!(error = %err, "static_file: dirList read error: {err}");
            let err_body = "Error reading directory\n";
            let head = format!(
                "HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                err_body.len()
            );
            if let Err(we) = client.write_all(head.as_bytes()).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            if let Err(we) = client.write_all(err_body.as_bytes()).await {
                tracing::debug!(error = %we, "plugin relay error: {}", we);
            }
            return Err(format!("dirList failed for {}: {err}", canon.display()));
        }
        StaticFsResolution::DirListing { mtime, body } => {
            let mut head =
                String::from("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n");
            if let Some(mt) = mtime {
                head.push_str(&format!("Last-Modified: {}\r\n", format_http_date(mt)));
            }
            head.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            ));
            client
                .write_all(head.as_bytes())
                .await
                .map_err(|e| format!("write headers: {e}"))?;
            client
                .write_all(body.as_bytes())
                .await
                .map_err(|e| format!("write body: {e}"))?;
            return Ok(());
        }
        StaticFsResolution::FileNeedsSlashRedirect => {
            // Handled below using `rel_components` / `raw_query`.
        }
        StaticFsResolution::FileNotModified304 { mt } => {
            let resp = format!(
                "HTTP/1.1 304 Not Modified\r\nLast-Modified: {}\r\nConnection: close\r\n\r\n",
                format_http_date(mt)
            );
            client
                .write_all(resp.as_bytes())
                .await
                .map_err(|e| format!("write 304: {e}"))?;
            return Ok(());
        }
        StaticFsResolution::SmallFile {
            buf,
            len,
            mtime,
            canon,
        } => {
            return write_small_file_response(&mut client, &buf.raw_buf()[..len], mtime, &canon)
                .await;
        }
        StaticFsResolution::SmallFileReadFailed(e) => {
            // Preserve pre-optimization error behavior if reading at offset 0
            // fails before any headers were sent: respond 500 via Go's
            // serveError shape rather than silently dropping an unwritten conn.
            let resp =
                http_error_render("500 Internal Server Error", "500 Internal Server Error\n");
            let _ = client.write_all(resp.as_bytes()).await;
            return Err(format!("failed to read file: {e}"));
        }
        StaticFsResolution::LargeFile {
            file,
            size,
            mtime,
            canon,
        } => {
            return serve_open_file(&mut client, file, size, mtime, &canon).await;
        }
    }

    if slash_terminated {
        // Round-16 FIX 4: Go serveFile's file-with-trailing-slash redirect
        // (fs.go:714-724) — a FILE URL ending in '/' answers 301 Location:
        // "../" + path.Base(url) (the base resolves one directory UP out of
        // the slash-suffixed URL; probe vs go1.25.12: GET /plain.txt/ →
        // 301 Location: ../plain.txt). Degenerate: the URL's last path
        // element is "/" or "." — the root path itself maps to a file —
        // which Go answers with a 500 "http: attempting to traverse a
        // non-directory" (fs.go:716-721: `base := path.Base(url); if base
        // == "/" || base == "."`), rendered here in the repo shape
        // (http.Error for 5xx: text/plain + nosniff + CL + msg "\n" body).
        // Round-16 post-fix note (gate equivalence, no code change): Go
        // gates on the RAW path.Base(url) while this arm gates on
        // cleaned-components-empty (`rel_components.last()` == None), and
        // the two are PROVABLY equal on every shape reachable here. The
        // arm is reachable only when local_path points at a FILE (a
        // misconfiguration — a directory target with a trailing slash
        // took the listing/index arms above) and the URL ends in '/'. Go's
        // FileServer re-slash-prefixes every stripped path and cleans it
        // (path.Clean) before serveFile, so its url is always "/"-leading:
        // path.Base(url) == "/" exactly when Clean(url) == "/" — the same
        // root condition as an empty component list — and the "."-base
        // shape (path.Base("") == ".") is unreachable because the
        // request-target "" never reaches this arm (parse_request_line
        // rejects empty targets; the resolve below strips the prefix, it
        // never empties a non-empty target). The gate shape is therefore
        // Go-equivalent on every input; only the misconfig probe e2e
        // (GET / against a file local_path) exercises it.
        let Some(base) = rel_components.last() else {
            const BODY: &str = "http: attempting to traverse a non-directory\n";
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                BODY.len(),
                BODY
            );
            if let Err(e) = client.write_all(resp.as_bytes()).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err(format!("file root target: {url_path}"));
        };
        let mut location = Vec::with_capacity(base.len() + 4);
        location.extend_from_slice(b"../");
        location.extend_from_slice(base);
        append_raw_query(&mut location, raw_query);
        let resp = render_301(&location);
        if let Err(e) = client.write_all(&resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err(format!("file target with trailing slash: {url_path}"));
    }

    unreachable!("all non-slash-redirect resolutions returned above")
}

/// Write a pre-read small file (`<= 64 KiB`) in a single vectored write pass
/// (`writev` of HTTP response headers + body slice), avoiding both a second
/// `write` syscall and any heap copy of the body.
async fn write_small_file_response(
    client: &mut TcpStream,
    body: &[u8],
    mtime: Option<u64>,
    mime_path: &std::path::Path,
) -> Result<(), String> {
    let mime = mime_from_path(mime_path);
    let mut head = String::with_capacity(192);
    head.push_str("HTTP/1.1 200 OK\r\nContent-Type: ");
    head.push_str(mime);
    head.push_str("\r\n");
    if let Some(mt) = mtime {
        head.push_str("Last-Modified: ");
        head.push_str(&format_http_date(mt));
        head.push_str("\r\n");
    }
    use std::fmt::Write as _;
    let _ = write!(
        head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let head_bytes = head.as_bytes();
    let mut head_pos = 0usize;
    let mut body_pos = 0usize;
    while head_pos < head_bytes.len() || body_pos < body.len() {
        let n = if head_pos < head_bytes.len() && body_pos < body.len() {
            let slices = [
                std::io::IoSlice::new(&head_bytes[head_pos..]),
                std::io::IoSlice::new(&body[body_pos..]),
            ];
            client
                .write_vectored(&slices)
                .await
                .map_err(|e| format!("write response: {e}"))?
        } else if head_pos < head_bytes.len() {
            client
                .write(&head_bytes[head_pos..])
                .await
                .map_err(|e| format!("write headers: {e}"))?
        } else {
            client
                .write(&body[body_pos..])
                .await
                .map_err(|e| format!("write body: {e}"))?
        };
        if n == 0 {
            return Err("write response: write zero".into());
        }
        let head_rem = head_bytes.len() - head_pos;
        if n <= head_rem {
            head_pos += n;
        } else {
            head_pos = head_bytes.len();
            body_pos += n - head_rem;
        }
    }
    Ok(())
}

/// Go serveContent tail (fs.go:759-761): bounded-chunk body stream for an
/// already-open, inode-verified large file handle (`> 64 KiB`, after IMS check
/// in `resolve_open_file_in_blocking`). Streams the
/// body instead of buffering it whole: the old path blocked the async task
/// on std::fs::read_to_end and truncated at 64 MiB (Content-Length then
/// lied). Go's http.FileServer streams the file — so do we, from the
/// already-open handle (tokio::fs::File wraps the same fd; position is
/// still 0). `mime_path` is the served FILE's path (the swapped index.html
/// for the dir-request case — Go names serveContent after the file).
async fn serve_open_file(
    client: &mut TcpStream,
    file: std::fs::File,
    size: u64,
    mtime: Option<u64>,
    mime_path: &std::path::Path,
) -> Result<(), String> {
    use tokio::io::AsyncBufReadExt;

    let mime = mime_from_path(mime_path);

    // The 200 arm gains Last-Modified: <mtime as RFC 1123 GMT> (Go
    // serveContent setLastModified). Method is exactly "GET" when this arm
    // runs — the gorilla route gate above (Methods("GET") exact-string
    // match, NO HEAD rewrite) already answered every other method with a
    // bare 405, so no HEAD body-skip is needed here. Go's own
    // `if r.Method == "HEAD" { return }` arm in serveContent is likewise
    // unreachable under Go frp's router (gorilla never routes HEAD to the
    // FileServer) and exists only for direct http.FileServer users.
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

    // Documented gaps vs Go frp's handler stack (audit finding D3; each
    // pinned e2e in frp-client/tests/plugin_static_file.rs):
    // * gzip — Go frp wraps the FileServer in
    //   netpkg.MakeHTTPGzipHandler (pkg/plugin/client/static_file.go,
    //   pkg/util/net/http.go:62-91): when Accept-Encoding contains "gzip"
    //   (no q=0 or type/size gate) EVERY response is compressed with
    //   Content-Encoding: gzip. net/http's FileServer itself never gzips
    //   and serves no precompressed ".gz" variants. frp-rs serves raw
    //   bytes — deliberate divergence, the wrapper is not replicated.
    // * Range — Go serveContent honors Range with a 206 + Content-Range
    //   and stamps every response "Accept-Ranges: bytes" (fs.go
    //   serveContent). frp-rs ignores Range and serves the full 200 —
    //   deliberate divergence, no partial content, no Accept-Ranges.
    // * If-None-Match — FileServer sets no ETag, so Go's checkIfNoneMatch
    //   (fs.go:519-544) only 304s on "*"; a non-matching token is condTrue
    //   and skips the If-Modified-Since gate (fs.go:649-665), so a stale
    //   IMS under a non-matching INM answers 200 in Go where frp-rs (no
    //   INM handling) answers 304. Token-less requests are parity; "*" is
    //   Go-304 / frp-rs-200. The audit scoped Last-Modified/304 only.
    let buf_cap = size.clamp(64 * 1024, 256 * 1024) as usize;
    let mut reader = tokio::io::BufReader::with_capacity(buf_cap, tokio::fs::File::from_std(file));
    loop {
        let chunk = reader
            .fill_buf()
            .await
            .map_err(|e| format!("failed to read file: {e}"))?;
        if chunk.is_empty() {
            break;
        }
        let n = chunk.len();
        client
            .write_all(chunk)
            .await
            .map_err(|e| format!("write body: {e}"))?;
        reader.consume(n);
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
///   is query-only). Round-16 FIX 2: the decode is byte-level — "%C3%AF" is
///   the two bytes C3 AF (a UTF-8 "ï"), never two Latin-1 characters; a
///   decoded path is raw BYTES, not necessarily UTF-8, and every consumer
///   converts explicitly (OsStringExt on unix, lossy elsewhere).
/// - The strip_prefix route matches ONLY at a component boundary: gorilla
///   registers PathPrefix("/{prefix}/"), so "/static", "/staticx/y" and
///   "/staticx" are route misses (Audit FIX 6) while "/static/..." strips
///   everything after the boundary.
/// - The remainder is cleaned ANCHORED AT THE URL ROOT — Go path.Clean over
///   the root-joined name (serveFile: `path.Clean(upath)`): "//" and "/./"
///   collapse, "/a/../b" is "b", and ".." clamps at the root — "/../x"
///   cleans to "/x" and can never escape (Audit FIX 9). Go serves the
///   anchored result (200).
#[cfg(test)]
fn resolve_static_path(url_path: &str, strip_prefix: Option<&str>) -> Result<String, String> {
    let decoded = urlencoding_decode(url_path);
    let (components, _remainder) = resolve_static_parts(&decoded, strip_prefix)?;
    let mut out = String::new();
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&String::from_utf8_lossy(c));
    }
    Ok(out)
}

/// Shared resolver body over DECODED BYTES (round-16 FIX 2): returns
/// (cleaned relative components, decoded remainder of the URL path after the
/// strip boundary). A component is a raw byte slice — empty / "." / ".."
/// never survive the clean. The remainder is the UNcleaned path Go's
/// serveFile/localRedirect reason over (audit round-7 finding): fs.go uses
/// url = r.URL.Path — after StripPrefix, i.e. the decoded path minus the
/// prefix — for both the trailing-slash test and the path.Base(url)
/// redirect target, never the cleaned name.
fn resolve_static_parts(
    decoded: &[u8],
    strip_prefix: Option<&str>,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    let stripped: &[u8] = match strip_prefix {
        Some(prefix) => {
            let boundary = format!("/{prefix}/");
            match decoded.strip_prefix(boundary.as_bytes()) {
                Some(rest) => rest,
                None => {
                    return Err(format!(
                        "prefix '/{prefix}/' not at a path boundary in '{}'",
                        String::from_utf8_lossy(decoded)
                    ));
                }
            }
        }
        None => decoded,
    };

    // Root-anchored clean (Go path.Clean): empty and "." components vanish,
    // ".." pops the previous component and clamps at the root.
    let mut components: Vec<Vec<u8>> = Vec::new();
    for part in stripped.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                components.pop();
            }
            c => components.push(c.to_vec()),
        }
    }
    Ok((components, stripped.to_vec()))
}

/// gorilla cleanPath (mux.go:280-301) over the decoded path: path.Clean,
/// then a trailing '/' restored when the original had one — operating on
/// BYTES (round-16 FIX 2: decoded paths are raw bytes; "/" is the only
/// byte class that matters to the clean). Used to detect router-level
/// non-canonical paths: `canonical != decoded` means gorilla would have
/// 301'd at the router and the FileServer arms must redirect from the
/// canonical form (round-16 FIX 11).
fn clean_path_canonical(p: &[u8]) -> Vec<u8> {
    // gorilla cleanPath identity cases: "" maps to "/", Clean("/") == "/".
    if p.is_empty() || p == b"/" {
        return vec![b'/'];
    }
    let trailing = p.last() == Some(&b'/');
    // Root-anchored clean (Go path.Clean over a rooted path — URL paths are
    // always rooted): empty and "." components vanish, ".." pops the
    // previous component and clamps at the root.
    let mut components: Vec<&[u8]> = Vec::new();
    for part in p.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(p.len());
    out.push(b'/');
    for c in components {
        if out.len() > 1 {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    if trailing && out.len() > 1 {
        out.push(b'/');
    }
    out
}

/// Build the target filesystem path from the configured base and the
/// cleaned relative BYTE components. cfg(unix): components join via
/// OsString, so non-UTF-8 names survive to the open (round-16 FIX 2);
/// elsewhere names decode lossily (the lossy path is compile-time only —
/// Windows/macOS filesystem names are not guaranteed UTF-8 either, but
/// unix byte-exactness is where the audit found the mojibake).
#[cfg(unix)]
fn join_components(base: &str, components: &[Vec<u8>]) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let mut joined = std::ffi::OsString::from(base);
    for c in components {
        joined.push("/");
        joined.push(std::ffi::OsString::from_vec(c.clone()));
    }
    std::path::PathBuf::from(joined)
}

#[cfg(not(unix))]
fn join_components(base: &str, components: &[Vec<u8>]) -> std::path::PathBuf {
    let mut joined = std::path::PathBuf::from(base);
    for c in components {
        joined.push(String::from_utf8_lossy(c).as_ref());
    }
    joined
}

/// Go 301 render in the repo shape (Location row first, fixed CL:0 +
/// Connection: close; Go's wire adds Date and keep-alives — documented
/// divergence, no Date anywhere in this plugin).
fn render_301(location: &[u8]) -> Vec<u8> {
    let mut head = Vec::with_capacity(location.len() + 64);
    head.extend_from_slice(b"HTTP/1.1 301 Moved Permanently\r\nLocation: ");
    head.extend_from_slice(location);
    head.extend_from_slice(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    head
}

/// Go localRedirect query append (fs.go:785-791): "?" + RawQuery is
/// appended only when RawQuery is NON-EMPTY — a bare "?" (Some("")) must
/// not leave a stray '?' dangling in the Location (round-16 FIX 10; probe
/// vs go1.25.12: GET /sub? → Location: sub/ with no '?').
fn append_raw_query(location: &mut Vec<u8>, raw_query: Option<&str>) {
    if let Some(q) = raw_query {
        if !q.is_empty() {
            location.push(b'?');
            location.extend_from_slice(q.as_bytes());
        }
    }
}

/// Go `http.Error` render (net/http server.go errorResponse shape) for the
/// toHTTPError status arms (round-17 finding F): text/plain body of the
/// status text + "\n", nosniff, exact Content-Length of that body. The
/// repo shape adds Connection: close and no Date (documented divergence —
/// Go's wire adds Date and keep-alives).
fn http_error_render(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         X-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Canonical path of an open handle's inode. Linux: /proc/self/fd/<fd> —
/// the fd symlink resolves to the inode the handle is pinned to, closing
/// the TOCTOU window (a symlink swap after open() cannot change what the
/// fd points at). Elsewhere: canonicalize of `path` — the residual race (a
/// swap between open() and canonicalize() making the check disagree with
/// the opened inode) is accepted; the check remains defense-in-depth on
/// top of the component-level clean.
///
/// The /proc/self/fd walk is PER-OPEN on purpose (audit finding D4): it
/// verifies the inode that open() actually pinned, so no path-based cache
/// can replace it without reopening the race it closes. This syscall cost
/// on every served request is the accepted price of the guard (the
/// per-request base walk in `handle_static_file_conn` is the other half;
/// both deliberately uncached — see the round-17 stale-base note there).
fn open_handle_canonical(
    file: &std::fs::File,
    _path: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        std::fs::canonicalize(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|e| format!("failed to resolve path: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // `file` is only consulted on Linux (the /proc/self/fd walk above), so on
        // other platforms it is genuinely unused here. Without this, `cargo build`
        // warns on macOS/Windows while Linux CI stays clean — the warning is real,
        // it is just platform-specific.
        let _ = file;
        std::fs::canonicalize(_path).map_err(|e| format!("failed to resolve path: {e}"))
    }
}

/// Render a directory listing matching Go's dirList (go1.25
/// net/http/fs.go:139-172), which http.FileServer answers for a directory
/// whose index.html is absent (or itself a directory — the swapped index
/// dir then gets listed). Wire shape, probe-verified against go1.25.0:
///
/// ```text
/// <!doctype html>
/// <meta name="viewport" content="width=device-width">
/// <pre>
/// <a href="{escaped}">{html-escaped}</a>   (one line per entry, byte-wise
///                                           ascending over the raw names —
///                                           dirList sort.Slice's them
///                                           itself, fs.go:156)
/// </pre>
/// ```
///
/// The modern format: no sizes, no dates, no title/h1/hr/ul (those belong
/// to the pre-Go-1.7 dirList). A directory's trailing "/" is appended to
/// the name BEFORE escaping — in both the href and the link text; a
/// symlink-to-directory does NOT get it (DirEntry.file_type reports the
/// link, mirroring the d_type the Go side reads). href escaping =
/// url.URL{Path: name}.String() encodePath mode: alnum + "-_.~$&+,/:;=@"
/// stay literal (only '?' is additionally escaped beyond the unreserved
/// set), everything else — space, '#', '%', non-ASCII — is
/// percent-encoded byte-wise with uppercase hex. Link-text escaping =
/// htmlReplacer (net/http server.go): & < > " ' -> &amp; &lt; &gt; &#34;
/// &#39;. Entries are sorted byte-wise over the RAW names — Go dirList runs
/// sort.Slice itself (fs.go:160 in go1.25.12 — the line drifts between Go
/// releases; :156 was stale), with the same byte comparison over
/// Name() strings, so this sort matches Go's and lossy-string sorting
/// would misorder invalid UTF-8 names. Round-16 FIX 2: the href escapes
/// the RAW name bytes, so a
/// non-UTF-8 name lists as a fetchable %XX href exactly like Go; only the
/// link TEXT is rendered lossily (documented divergence — Go writes the
/// raw bytes into the HTML body; the body is a UTF-8 String here).
fn render_dir_listing(dir: &std::path::Path) -> Result<String, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    let mut entries: Vec<(std::ffi::OsString, bool)> = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| format!("read_dir entry in {}: {e}", dir.display()))?;
        let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
        // The name stays an OsString here: the raw-bytes hop lives in the
        // pure `render_listing` below, where it is unit-testable with a name
        // the host filesystem may refuse to store at all (APFS/EILSEQ — see
        // the e2e test's runtime-capability skip).
        entries.push((ent.file_name(), is_dir));
    }
    Ok(render_listing(&entries))
}

/// Pure half of `render_dir_listing`: takes the already-collected
/// `(name, is_dir)` entries, converts each name to bytes, sorts byte-wise and
/// renders the Go dirList body. No filesystem access, so it runs — and can be
/// asserted byte-exactly — on a host whose filesystem cannot store the
/// non-UTF-8 name at all: restoring the pre-round-16 lossy hop
/// (`to_string_lossy()`) HERE turns `raw%FF.txt` into `raw%EF%BF%BD.txt` and
/// moves the byte-wise sort order with it — both pinned by
/// `test_render_listing_non_utf8_name_escapes_byte_exact`, whose lossy-sort-key
/// mutation the first three entries alone cannot catch. The `#[cfg(unix)]` e2e
/// half cannot observe any of this on APFS because the write of the 0xFF name
/// itself fails there (EILSEQ). The name→bytes hop deliberately lives in this
/// pure half for that reason.
fn render_listing(entries: &[(std::ffi::OsString, bool)]) -> String {
    let mut entries: Vec<(Vec<u8>, bool)> = entries
        .iter()
        .map(|(name, is_dir)| {
            // Raw name BYTES — cfg(unix) without any lossy hop (OsStringExt);
            // elsewhere names decode lossily at the platform boundary
            // (compile-time-only path — same rule as join_components).
            #[cfg(unix)]
            let name_bytes = {
                use std::os::unix::ffi::OsStringExt;
                name.clone().into_vec()
            };
            #[cfg(not(unix))]
            let name_bytes = name.to_string_lossy().as_bytes().to_vec();
            (name_bytes, *is_dir)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::from(
        "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n",
    );
    for (name, is_dir) in entries {
        let mut display = name;
        if is_dir {
            display.push(b'/');
        }
        out.push_str("<a href=\"");
        out.push_str(&url_escape_bytes(&display));
        out.push_str("\">");
        out.push_str(&html_escape_text(&String::from_utf8_lossy(&display)));
        out.push_str("</a>\n");
    }
    out.push_str("</pre>\n");
    out
}

/// Percent-encode a URL path exactly like Go's url.URL{Path: p}.String()
/// encodePath mode (net/url/url.go shouldEscape): the path is escaped as a
/// whole, so the RFC 2396 reserved set that is meaningful per-segment but
/// harmless whole-path ($ & + , / : ; = @ plus the unreserved - _ . ~ and
/// alnum) stays literal, and only '?' is additionally escaped. Everything
/// else is %XX with uppercase hex, one byte at a time. Byte-level
/// (round-16 FIX 2): decoded paths are raw bytes, so the escape operates on
/// BYTES — the gorilla-canonical 301 Location arm and the dirList href arm
/// escape possibly non-UTF-8 paths this way (Go hexEscapeNonASCII over
/// url.String() lands on the same encodePath for >= 0x80). Operates on
/// bytes, so any caller passing a Rust &str slices its UTF-8 bytes first
/// (s.as_bytes()) — byte-exact for every valid-UTF-8 input.
fn url_escape_bytes(s: &[u8]) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'$'
            | b'&'
            | b'+'
            | b','
            | b'/'
            | b':'
            | b';'
            | b'='
            | b'@' => {
                out.push(b as char);
            }
            // Audit round-18 L7: manual nibble write into the existing
            // String — the old per-byte `format!("%{b:02X}")` allocation
            // is gone (a 200-entry directory listing escaped a fresh
            // String per non-literal byte).
            _ => {
                out.push('%');
                out.push(HEX_UPPER[(b >> 4) as usize] as char);
                out.push(HEX_UPPER[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Escape text for an HTML body context exactly like Go's htmlReplacer
/// (net/http server.go): & < > " ' -> &amp; &lt; &gt; &#34; &#39;.
fn html_escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
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
///
/// Audit finding D2: the extension lookup is ASCII case-insensitive — Go
/// mime.TypeByExtension checks the case-sensitive table first, then folds
/// the extension to lowercase for the mimeTypesLower table (mime/type.go:
/// 104-133; probe vs go1.25.12: ".JPG" and ".Jpg" answer image/jpeg). The
/// rows cover the whole Go builtin set — .avif/.mjs/.webp were missing
/// and are added with the builtin values; the extra non-Go rows
/// (ico/txt/zip/woff/woff2/ttf/mp3/mp4/webm) are a deliberate superset.
/// Fallback: Go returns "" for an unknown extension and http.FileServer
/// then SNIFFS the first 512 bytes (DetectContentType, fs.go serveContent)
/// — frp-rs deliberately does NOT sniff, serving
/// "application/octet-stream" instead (documented divergence).
fn mime_from_path(path: &std::path::Path) -> &'static str {
    // Cow: the all-lowercase common case borrows; only an extension
    // containing an ASCII uppercase byte allocates the folded copy (a
    // match over `extension()` cannot fold in place).
    let ext: std::borrow::Cow<'_, str> = match path.extension().and_then(|e| e.to_str()) {
        Some(e) if e.bytes().any(|b| b.is_ascii_uppercase()) => {
            std::borrow::Cow::Owned(e.to_ascii_lowercase())
        }
        Some(e) => std::borrow::Cow::Borrowed(e),
        None => return "application/octet-stream",
    };
    match ext.as_ref() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "avif" => "image/avif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "text/xml; charset=utf-8",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

/// Whole-second unix mtime of a file metadata, or None when the platform
/// cannot report one OR the mtime is the zero time. Go isZeroTime
/// (fs.go:606-609) treats BOTH time.Time zero and time.Unix(0, 0) as zero:
/// no Last-Modified is emitted and any If-Modified-Since is condNone
/// (always 200). Round-16 FIX 9: Some(0) is exactly time.Unix(0,0) — an
/// mtime pinned to the epoch (`touch -d @0`, std's
/// set_modified(UNIX_EPOCH)) must not emit "Last-Modified: Thu, 01 Jan 1970
/// 00:00:00 GMT" nor ever answer 304. (The pre-FIX code treated Some(0) as
/// a real mtime; its doc's claim that "Go's zero modtime behaves the same"
/// was wrong for the epoch value.)
fn mtime_secs(meta: &std::fs::Metadata) -> Option<u64> {
    let secs = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())?;
    (secs != 0).then_some(secs)
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

/// Parse an If-Modified-Since value into whole unix seconds, mirroring Go's
/// checkIfModifiedSince path: a value that fails to parse is condNone (serve
/// 200, no 400/403).
///
/// Go http.ParseTime tries THREE layouts in order (net/http parseTime.go):
/// TimeFormat / IMF-fixdate / RFC 1123 ("Mon, 02 Jan 2006 15:04:05 GMT" —
/// the shape Last-Modified is emitted in), time.RFC850 ("Sunday, 06-Jan-02
/// 15:04:05 MST") and time.ANSIC ("Mon Jan _2 15:04:05 2006"). Round-16
/// FIX 8: the old parser knew only the IMF shape, so an RFC 850 or ANSIC
/// If-Modified-Since — which Go parses and can answer 304 against — fell
/// through to a plain 200 here.
///
/// Common rules (all three layouts): the weekday token must be a valid name
/// for the layout — Go time.Parse looks the word up in the layout's day-name
/// list, case-insensitively, but NEVER cross-checks it against the date
/// ("ignore weekday except for error checking", format.go): "Fri, 01 Jan
/// 2000 00:00:00 GMT" parses clean in Go though 2000-01-01 was a Saturday,
/// and Go answers 304 (probe-verified against go1.25.12). The calendar date
/// must exist (Feb 30 normalizes → rejected — Go time.Parse errors the same
/// way). Numeric tokens are ASCII-only (Go atoi accepts no Unicode digits,
/// no sign). Dates before 1970 parse in Go too, but an IMS older than any
/// real file's mtime answers condTrue — byte-identical to a parse failure
/// here — so rejecting pre-1970 years is behaviorally Go-identical (the IMF
/// parser has always done it). Zones: every accepted zone parses at ZERO
/// offset — time.Parse knows no zone database, and probe-verified even the
/// "GMT+5"-style names never shift the instant — so a zone is a
/// recognition gate, not a correction (IMF gate: the strict literal
/// "GMT"; RFC 850 gate: Go parseTimeZone, [`rfc850_zone_ok`]; ANSIC: no
/// zone element at all). The IMF strictness is byte-identical for every
/// client echoing a server-emitted date — the established, documented
/// divergence.
fn parse_if_modified_since(value: &str) -> Option<u64> {
    // Audit round-18 L5: the value arrives in textproto stored shape from
    // the head walker (physical-line OWS stripped at read time), and Go's
    // http.ParseTime parses the stored value VERBATIM — the old Unicode
    // `trim()` here stripped whitespace Go keeps: an obs-fold-created
    // trailing space fails Go's layout match (condNone → 200), and a
    // leading one can never survive readMIMEHeader's TrimLeft anyway.
    parse_imf_fixdate(value)
        .or_else(|| parse_rfc850(value))
        .or_else(|| parse_ansic(value))
}

/// IMF-fixdate / RFC 1123 — "Weekday, day month year clock GMT": comma
/// after the (short) weekday, space-separated day / 3-letter month /
/// 4-digit year / clock / zone. The 3-letter month lookup is
/// case-insensitive (Go). The day token must be EXACTLY two digits —
/// Go's RFC1123 layout element is '02' (stdZeroDay), which time.Parse's
/// getnum parses with fixed=true, i.e. exactly two digits (time/format.go:
/// 923-938): a single-digit day ("Sat, 2 Jan 2006 ...") and a three-digit
/// day ("Sat, 007 Jan 2006 ...") both error in Go (probe vs go1.25.12) →
/// condNone → Go re-serves 200. (Audit finding D1: the pre-fix code
/// accepted the space-padded single-digit shape as a "documented
/// leniency" — probe-verified false parity; the shape now fails like Go.)
fn parse_imf_fixdate(v: &str) -> Option<u64> {
    // The weekday must be one of the seven abbreviated names (Go's layout
    // needs a real name: time.Parse does a case-insensitive lookup and
    // fails the whole parse otherwise), but it is never cross-checked
    // against the date (see the fn doc — Go answers 304 for a
    // wrong-but-valid weekday). Anything without the comma shape fails
    // (Go's layout needs the comma too).
    let (weekday, rest) = v.split_once(',')?;
    if !HTTP_WEEKDAYS
        .iter()
        .any(|&w| w.eq_ignore_ascii_case(weekday))
    {
        return None;
    }
    let mut parts = rest.split_whitespace();
    let day_tok = parts.next()?;
    let month_name = parts.next()?;
    let year_tok = parts.next()?;
    let clock = parts.next()?;
    let zone = parts.next()?;
    if parts.next().is_some() || zone != "GMT" {
        return None;
    }
    // Go layout "2006": exactly four ASCII digits. The layout element
    // "02" (stdZeroDay) is getnum(value, fixed=true) — exactly TWO
    // digits (time/format.go:923-938); a 1- or 3-digit day token errors
    // in Go (probe vs go1.25.12: "Sat, 1 Jan 2000 ..." and
    // "Sat, 007 Jan 2000 ..." both ERR → condNone → 200; audit
    // finding D1).
    if year_tok.len() != 4
        || !ascii_digits(year_tok)
        || day_tok.len() != 2
        || !ascii_digits(day_tok)
    {
        return None;
    }
    let year: i64 = year_tok.parse().ok()?;
    let day: u32 = day_tok.parse().ok()?;
    let month = HTTP_MONTHS
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(month_name))? as u32
        + 1;
    parse_clock_date(year, month, day, clock)
}

/// Round-17 finding H: Go `time.parseTimeZone` (format.go:1443-1488) +
/// the stdTZ "UTC" special (format.go:1288-1291) over the WHOLE zone token
/// of the RFC 850 layout — probe-verified against go1.25.12. Go's layout
/// consumes the zone by parseTimeZone's returned length, and anything the
/// zone parser leaves over is "extra text" → parse error; the `n == len`
/// gate below reproduces that whole-token rule. An accepted zone parses at
/// ZERO offset (probe: every OK row below yields unix 946684800 — the
/// "GMT+5" style offsets name the zone but time.Parse never applies them
/// to the instant), so no offset math follows acceptance.
fn rfc850_zone_ok(zone: &str) -> bool {
    // stdTZ special case first: an exact "UTC" is consumed before
    // parseTimeZone ever runs, so "UTCX"/"UTCT" leave the tail as extra
    // text (error) instead of falling into the 3-letter-uppercase rule.
    if zone == "UTC" {
        return true;
    }
    if zone.starts_with("UTC") {
        return false;
    }
    match parse_time_zone_len(zone) {
        Some(n) => n == zone.len(),
        None => false,
    }
}

/// Go `time.parseTimeZone` — consumed length of a legal zone prefix, or
/// `None`:
/// * fewer than 3 bytes → error;
/// * `ChST`/`MeST` — the only zones with a lower-case letter — match
///   their 4 bytes exactly (a longer token leaves the tail as extra
///   text, handled by the caller's whole-token gate);
/// * `GMT` is special and may carry a signed hour offset (`GMT`,
///   `GMT+02`, `GMT-5`, `GMT+0` all legal; the offset must be 0-23 —
///   `GMT+24` fails — and must consume the remainder or the tail is
///   extra text; `GMTX` consumes only the 3 "GMT" bytes → tail error);
/// * a leading `+`/`-` names a bare signed offset (`+03`, `-23`; digits
///   0-23, at least one; a sign with no digits, or > 23, fails);
/// * otherwise an upper-case run: 3 letters OK, 4 OK only ending in `T`
///   (or the `WITA` special), 5 OK only ending in `T`, 0/1/2/6+ fail —
///   a lower-case letter or other byte anywhere in the first 6 ends the
///   run and rules by the count so far (`aBC`/`ABc` → 0/2 → fail).
fn parse_time_zone_len(zone: &str) -> Option<usize> {
    let b = zone.as_bytes();
    if b.len() < 3 {
        return None;
    }
    // Special case 1: ChST and MeST are the only zones with a lower-case
    // letter (matched before the upper-case-run count, which would see
    // only 1 upper-case letter and fail).
    if b.len() >= 4 && (zone.starts_with("ChST") || zone.starts_with("MeST")) {
        return Some(4);
    }
    // Special case 2: GMT may carry an hour offset (parseGMT: 3 bytes,
    // then a signed 0-23 offset when present — an absent offset or a
    // failed offset parse still consumes the 3 "GMT" bytes).
    if let Some(rest) = zone.strip_prefix("GMT") {
        if rest.is_empty() {
            return Some(3);
        }
        let signed = parse_signed_offset_len(rest);
        return Some(signed.map_or(3, |n| 3 + n));
    }
    // Special case 3: unnamed zones with a +/-00 shape.
    if b[0] == b'+' || b[0] == b'-' {
        return parse_signed_offset_len(zone);
    }
    // Upper-case run — need at least three, at most five.
    let upper = b.iter().take_while(|c| c.is_ascii_uppercase()).count();
    match upper {
        3 => Some(3),
        4 if b[3] == b'T' || zone.starts_with("WITA") => Some(4),
        5 if b[4] == b'T' => Some(5),
        _ => None,
    }
}

/// Go `parseSignedOffset` (format.go:1514-1530) over the bytes AFTER the
/// sign: a leadingInt digit run in 0-23 — at least one digit, more than
/// 23 fails, and only the consumed digits count toward the length (a
/// colon or other tail is extra text for the caller's whole-token gate).
fn parse_signed_offset_len(after_sign: &str) -> Option<usize> {
    let b = after_sign.as_bytes();
    if !matches!(b.first(), Some(b'+') | Some(b'-')) {
        return None;
    }
    let digits = b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let x: u64 = after_sign[1..1 + digits].parse().ok()?;
    if x > 23 {
        return None;
    }
    Some(1 + digits)
}

/// RFC 850 / RFC 1036 — "FullWeekday, dd-Mon-yy HH:MM:SS Zone": comma after
/// the FULL weekday name (Go layout element "Monday"), dash-separated
/// 2-digit day / 3-letter month / 2-digit year, clock, zone.
/// Go's 2-digit-year pivot (format.go): 69-99 → 1969-1999, 00-68 →
/// 2000-2068. The zone word parses under Go's `parseTimeZone` rules
/// ([`rfc850_zone_ok`] — round-17 finding H): names are NOT restricted to
/// the alphabetic set the pre-fix gate demanded — the full token must be
/// a legal time-zone shape (uppercase-run names, ChST/MeST, GMT±n,
/// ±nn) and the token must be consumed WHOLE (a leftover is Go's
/// "extra text" error). Any accepted zone parses at ZERO offset —
/// `time.Parse` applies no offset for a layout-zone word (probe: every
/// accepted zone yields the same instant as a UTC clock) — so no offset
/// arithmetic happens here.
fn parse_rfc850(v: &str) -> Option<u64> {
    const RFC850_WEEKDAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    let (weekday, rest) = v.split_once(',')?;
    if !RFC850_WEEKDAYS
        .iter()
        .any(|&w| w.eq_ignore_ascii_case(weekday))
    {
        return None;
    }
    let mut parts = rest.split_whitespace();
    let date_tok = parts.next()?;
    let clock = parts.next()?;
    let zone = parts.next()?;
    if parts.next().is_some() || !rfc850_zone_ok(zone) {
        return None;
    }
    // The date token is dash-separated exactly — Go layout
    // "02-Jan-06": literal '-' delimiters (time.Parse matches
    // delimiters exactly), so "02 Jan 06" fails in Go and must fail
    // here (split_whitespace alone would erase the dash/space
    // distinction). Go layouts "02" (zero-padded two digits) and "06".
    let mut date = date_tok.split('-');
    let day_tok = date.next()?;
    let month_name = date.next()?;
    let year_tok = date.next()?;
    if date.next().is_some() {
        return None;
    }
    if day_tok.len() != 2
        || year_tok.len() != 2
        || !ascii_digits(day_tok)
        || !ascii_digits(year_tok)
    {
        return None;
    }
    let day: u32 = day_tok.parse().ok()?;
    let year2: i64 = year_tok.parse().ok()?;
    let year: i64 = if year2 >= 69 {
        1900 + year2
    } else {
        2000 + year2
    };
    let month = HTTP_MONTHS
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(month_name))? as u32
        + 1;
    parse_clock_date(year, month, day, clock)
}

/// ANSIC / asctime() — "Wkd Mmm _d HH:MM:SS YYYY": abbreviated weekday,
/// abbreviated month, SPACE-PADDED day (1-2 digits), clock, 4-digit year,
/// NO zone — the layout carries no zone element, so any trailing token
/// fails the parse in Go (matches are delimiter-exact) and the result is
/// UTC.
fn parse_ansic(v: &str) -> Option<u64> {
    let mut parts = v.split_whitespace();
    let weekday = parts.next()?;
    let month_name = parts.next()?;
    let day_tok = parts.next()?;
    let clock = parts.next()?;
    let year_tok = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !HTTP_WEEKDAYS
        .iter()
        .any(|&w| w.eq_ignore_ascii_case(weekday))
    {
        return None;
    }
    // Go layout "2006": exactly four ASCII digits. The layout element
    // "_2" (stdUnderDay) is a space-padded day: time.Parse runs cutspace
    // then getnum(value, fixed=false) (time/format.go:923-938), so ONE or
    // TWO digits are legal but a 3-digit token errors (probe vs go1.25.12:
    // "Sat Jan 007 00:00:00 2000" ERR → condNone → 200 — the ANSIC
    // sibling of audit finding D1).
    if year_tok.len() != 4 || !ascii_digits(year_tok) || day_tok.len() > 2 || !ascii_digits(day_tok)
    {
        return None;
    }
    let year: i64 = year_tok.parse().ok()?;
    let day: u32 = day_tok.parse().ok()?;
    let month = HTTP_MONTHS
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(month_name))? as u32
        + 1;
    parse_clock_date(year, month, day, clock)
}

/// ASCII-only digit token check (Go atoi parity — no Unicode digits, no
/// sign, no empty).
fn ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Clock + calendar validation shared by all three layouts: "HH:MM:SS"
/// with ASCII digits and in-range fields, then the civil-date round-trip
/// (Feb 30 etc. rejected — Go time.Parse errors the same way). No
/// weekday-vs-date consistency check — Go never validates that (audit
/// round-7 finding, probe: "Fri, 01 Jan 2000" parses and answers 304
/// though 2000-01-01 was a Saturday). Returns whole unix seconds.
fn parse_clock_date(year: i64, month: u32, day: u32, clock: &str) -> Option<u64> {
    if !(1970..=9999).contains(&year) || day == 0 || day > 31 {
        return None;
    }
    let mut clock_parts = clock.split(':');
    let hour_tok = clock_parts.next()?;
    let minute_tok = clock_parts.next()?;
    let second_tok = clock_parts.next()?;
    if clock_parts.next().is_some()
        || !ascii_digits(hour_tok)
        || !ascii_digits(minute_tok)
        || !ascii_digits(second_tok)
    {
        return None;
    }
    let hour: u64 = hour_tok.parse().ok()?;
    let minute: u64 = minute_tok.parse().ok()?;
    let second: u64 = second_tok.parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = civil_to_days(year, month, day);
    // Calendar validity: the civil date must round-trip (Feb 30 rolls to
    // Mar 1 → rejected; Go time.Parse errors on an out-of-range
    // day-of-month the same way).
    let (y2, m2, d2) = civil_from_days(days);
    if y2 != year || m2 != month || d2 != day {
        return None;
    }
    Some(days as u64 * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests;
