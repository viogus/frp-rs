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
    let mut authorization: Option<String> = None;
    let mut if_modified_since = None;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            // Go Header.Get FIRST-value semantics (net/textproto: duplicate
            // rows accumulate into a slice; Header.Get returns v[0]) — the
            // first row wins, an empty-value row included (round-16 FIX 7;
            // the old last-wins assignment mirrored nothing in Go).
            if key.eq_ignore_ascii_case("authorization") && authorization.is_none() {
                authorization = Some(value.to_string());
            } else if key.eq_ignore_ascii_case("if-modified-since") && if_modified_since.is_none() {
                if_modified_since = Some(value.to_string());
            }
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
        // frp-client/tests/plugin_static_file.rs:133 asserted the uncased
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

    // Audit finding D4 (the base canonicalize moved BELOW the open): the
    // open-failure arms answer Go's serveError → toHTTPError pages without
    // paying the base-directory walk (~4-8 syscalls saved per
    // open-failure request — the walk exists only to verify an open that
    // never happened). A base that vanished under the plugin now answers
    // 404 through Go's own ENOENT arm below (fs.go:680-696), and an
    // unreadable base answers 403 like Go's IsPermission arm — the old
    // pre-open walk collapsed both to a blanket 404. The Rust-only
    // containment guard still precedes every content-serve arm; it needs
    // the base only once the open SUCCEEDED (next block).
    let file = match std::fs::File::open(&full_path) {
        Ok(f) => f,
        Err(e) => {
            // Round-17 finding F: Go serveError → toHTTPError (fs.go:
            // 680-696) maps IsNotExist → 404 page, IsPermission → 403
            // page, anything else → 500 — every arm via http.Error
            // (text/plain body of the status text + "\n", nosniff). The
            // pre-fix arm collapsed all three to the shared 404 page; now
            // the io::ErrorKind decides, mirroring os.IsNotExist /
            // os.IsPermission (a Kind-carrying error maps on kind; a
            // kind-less error falls to the default 500, like Go's
            // syscall.Errno-less error).
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
    };

    // Rust-only hardening (Go's http.Dir cleans the joined name — path.Clean
    // clamps "..", so traversal cannot escape — then deliberately FOLLOWS
    // symlinks wherever they point; escaping the root is a documented Go
    // footgun this plugin declines to copy): canonicalize the base directory
    // PER REQUEST and verify via the ALREADY-OPEN handle above that the
    // target stays within the base. A startup cache of the base realpath
    // went stale when a base-dir symlink retargeted (versioned deploys like
    // /var/www/current) and 403'd every file (round-17 review LOW) — audit
    // finding D4 reviewed hoisting the walk to plugin start / reload and
    // refused: the realpath is mutable filesystem state with a
    // false-ACCEPT direction too (a retargeted base would sail the stale
    // starts_with check and serve OUTSIDE the new root), so the walk stays
    // per-request — the deliberate cost that replaces the staleable cache.
    // The verification must resolve the open fd's inode, not re-resolve the
    // path: re-canonicalizing the path after open() lets a symlink swap
    // between the two make the check disagree with the opened inode
    // (TOCTOU). Cost: a short path walk per request, not per byte.
    let base = match std::fs::canonicalize(local_path) {
        Ok(b) => b,
        Err(e) => {
            // Round-17 finding G — reachable only as a post-open race now
            // (audit finding D4 moved the walk below the open): the open
            // above succeeded, so the base existed moments ago; a concurrent
            // rename/retarget between the open and this walk fails here.
            // Go's serveError/toHTTPError maps the same condition (its own
            // open of the joined name ENOENTs) to the 404 page — render the
            // same page before closing.
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
    };

    let resolved = open_handle_canonical(&file, &full_path)?;
    if !resolved.starts_with(&base) {
        // Escaping target — 403, redirects and listings included
        // (round-16 FIX 6). Content-Length: 0 head, repo shape.
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("path traversal rejected".into());
    }
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat {}: {e}", full_path.display()))?;

    // Go serveFile keeps (f, d) as a mutable pair and swaps BOTH on an
    // index.html hit (fs.go:742-744) — the metadata a later arm reads must
    // describe the SWAPPED target. frp-rs mirrors with a triple (handle,
    // metadata, canonical path); `resolved` doubles as the symlink-free
    // path the listing arms read from (an escaping target already 403'd,
    // so reading `resolved` never leaves the base).
    let mut f = file;
    let mut f_meta = meta;
    let mut f_canon = resolved;

    // Directory handling — serveFile's redirect block (fs.go:705-725) runs
    // inside http.FileServer: after Go frp's auth middleware (401 first,
    // then the redirect) and unreachable for non-GET (the route method gate
    // above already answered 405 — gorilla never hands another method to
    // FileServer; probe: POST on a slash-less dir is 405, never this 301).
    // Round-16 FIX 11: the arm fires only for in-base targets (guard-first).
    let slash_terminated = url_remainder.is_empty() || url_remainder.ends_with(b"/");
    if f_meta.is_dir() {
        // A directory URL that does not end in '/' answers 301 with a
        // Location derived from the CLEANED path:
        //   * canonical request path → Go FileServer localRedirect:
        //     RELATIVE Location = path.Base(stripped URL path) + "/"
        //     (fs.go:705-713) — relative stays correct under the strip
        //     prefix. Query appended verbatim.
        //   * non-canonical path (dot-segments / duplicate slashes —
        //     gorilla cleanPath would have 301'd at the ROUTER, pre-auth
        //     and pre-strip) → ABSOLUTE single-hop Location: escaped
        //     cleaned FULL path + "/" (Go's chain is two hops — router 301
        //     to the canonical path, then the FileServer redirect above;
        //     the fold redirects once to the canonical slash-terminated
        //     URL). A relative Location from the UNCLEANED remainder would
        //     send the client back to the non-canonical URL (handler-head
        //     note; round-16 FIX 11 — the old code derived every Location
        //     from the uncleaned remainder, so "/static//sub" 301'd back to
        //     "/static//sub/" and never converged).
        if !slash_terminated {
            let mut location: Vec<u8>;
            if canonical_full != decoded_path {
                location = Vec::with_capacity(canonical_full.len() + 8);
                location.extend_from_slice(url_escape_bytes(&canonical_full).as_bytes());
                if canonical_full.len() > 1 {
                    location.push(b'/');
                }
            } else {
                // Canonical: Go path.Base of the stripped URL path — last
                // non-empty cleaned component. (A bare trailing "/."
                // cleaning to the root is non-canonical and took the arm
                // above; "." is unreachable here but mirrors Go's
                // path.Base("") fallback shape.)
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

        // Go serveFile index.html swap (fs.go:735-745): OPEN-based — when
        // the index entry opens and stats cleanly, the target swaps to it,
        // even when the index entry is ITSELF a directory (Go then lists
        // ITS contents below). Round-16 FIX 7: the old code probed with
        // std::fs::metadata — a mode-000 index.html stats cleanly but fails
        // to OPEN, so Go skips the swap and dirLists the directory (200);
        // the metadata probe swapped, and the later open 404'd. A missing
        // index leaves the directory as the target.
        let index_path = f_canon.join("index.html");
        if let Ok(ix) = std::fs::File::open(&index_path) {
            // Rust-only: an index.html symlink escaping the base is denied
            // (Go would serve the outside file).
            let ix_canon = open_handle_canonical(&ix, &index_path)?;
            if !ix_canon.starts_with(&base) {
                let resp =
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                if let Err(e) = client.write_all(resp).await {
                    tracing::debug!(error = %e, "plugin relay error: {}", e);
                }
                return Err("path traversal rejected".into());
            }
            if let Ok(im) = ix.metadata() {
                f = ix;
                f_meta = im;
                f_canon = ix_canon;
            }
            // Stat error (raced deletion): keep the directory — Go's
            // `ff, err := fs.Open(index); if err != nil { return }` arm
            // likewise leaves d/f untouched.
        }
        // Swapped target may now be a FILE — Go re-tests `d.IsDir()` after
        // the swap and serves the swapped file via serveContent when it is;
        // the listing arm below is the still-a-directory case (an index
        // entry that is itself a directory, or no openable index at all).
        if !f_meta.is_dir() {
            return serve_open_file(
                &mut client,
                f,
                &f_meta,
                &f_canon,
                if_modified_since.as_deref(),
            )
            .await;
        }

        // Go serveFile "still a directory" arm (fs.go:748-756): no
        // openable index.html (or the index entry was itself a directory —
        // see the swap above), so answer Go's dirList page. Precondition
        // order mirrors Go: If-Modified-Since is evaluated against the
        // CURRENT target's mtime first (possibly the swapped index-dir) — a
        // hit answers 304 with no Last-Modified, no Content-Type, no CL.
        // Round-16 FIX 15 (citation): Go's setLastModified for the listing
        // runs only after the IMS gate passes (probe-verified go1.25: dir
        // 304 wire = status + Date) — the frp-rs no-LM 304 head is the same
        // header SET minus Go's Date plus the repo's Connection: close.
        // "Exact parity" was previously claimed here — overstated: Go
        // stamps Date and keep-alives the connection; frp-rs closes after
        // every response, no Date anywhere (repo convention). Then the 200
        // listing carries Last-Modified of the current target.
        let mtime = mtime_secs(&f_meta);
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
        let body = match render_dir_listing(&f_canon) {
            Ok(b) => b,
            Err(e) => {
                // Go dirList read error (fs.go:158-161): log +
                // http.Error(w, "Error reading directory", 500) — the
                // frp-rs shape (no Date, close after).
                tracing::debug!(error = %e, "static_file: dirList read error: {e}");
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
                return Err(format!("dirList failed for {}: {e}", f_canon.display()));
            }
        };
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
    } else if slash_terminated {
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

    // File arm — Go serveContent (fs.go:759-761). The body lives in
    // `serve_open_file` below, shared with the index-swap-to-file path
    // inside the directory block above (Go re-tests `d.IsDir()` after the
    // swap and serves a swapped index FILE here; the listing arm there is
    // the still-a-directory case).
    serve_open_file(
        &mut client,
        f,
        &f_meta,
        &f_canon,
        if_modified_since.as_deref(),
    )
    .await
}

/// Go serveContent tail (fs.go:759-761): IMS precondition + bounded-chunk
/// body stream for an already-open, inode-verified file handle. Streams the
/// body instead of buffering it whole: the old path blocked the async task
/// on std::fs::read_to_end and truncated at 64 MiB (Content-Length then
/// lied). Go's http.FileServer streams the file — so do we, from the
/// already-open handle (tokio::fs::File wraps the same fd; position is
/// still 0). `mime_path` is the served FILE's path (the swapped index.html
/// for the dir-request case — Go names serveContent after the file).
async fn serve_open_file(
    client: &mut TcpStream,
    file: std::fs::File,
    meta: &std::fs::Metadata,
    mime_path: &std::path::Path,
    if_modified_since: Option<&str>,
) -> Result<(), String> {
    let size = meta.len();
    let mtime = mtime_secs(meta);
    let mime = mime_from_path(mime_path);

    // If-Modified-Since precondition — Go serveContent checkPreconditions.
    // The mtime is truncated to whole seconds (the header has 1 s
    // resolution); mtime <= IMS → 304. Round-16 FIX 5: the FILE 304 keeps
    // its Last-Modified — Go runs setLastModified BEFORE
    // checkPreconditions, and writeNotModified deletes Last-Modified only
    // when an ETag is set; FileServer never sets one (probe vs go1.25.12:
    // file 304 carries Last-Modified). The dir arm above differs: its
    // setLastModified runs after the IMS gate, hence the no-LM dir 304.
    // Round-16 FIX 9: a zero-time (epoch) mtime is None here — no
    // Last-Modified is emitted and the precondition never fires (Go
    // isZeroTime → condNone → always 200). An unparsable IMS is condNone →
    // serve 200 (Go http.ParseTime error). A None mtime (platform cannot
    // report it, pre-epoch clock, zero time) disables both Last-Modified
    // and the precondition.
    if let Some(ims) = if_modified_since.and_then(parse_if_modified_since) {
        if let Some(mt) = mtime {
            if mt <= ims {
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
        }
    }

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
    let mut file = tokio::fs::File::from_std(file);
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
/// sort.Slice itself (fs.go:156), with the same byte comparison over
/// Name() strings, so this sort matches Go's and lossy-string sorting
/// would misorder invalid UTF-8 names. Round-16 FIX 2: the href escapes
/// the RAW name bytes, so a
/// non-UTF-8 name lists as a fetchable %XX href exactly like Go; only the
/// link TEXT is rendered lossily (documented divergence — Go writes the
/// raw bytes into the HTML body; the body is a UTF-8 String here).
fn render_dir_listing(dir: &std::path::Path) -> Result<String, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    let mut entries: Vec<(Vec<u8>, bool)> = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| format!("read_dir entry in {}: {e}", dir.display()))?;
        let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
        // Raw name BYTES — cfg(unix) without any lossy hop (OsStringExt);
        // elsewhere names decode lossily at the platform boundary
        // (compile-time-only path — same rule as join_components).
        #[cfg(unix)]
        let name_bytes = {
            use std::os::unix::ffi::OsStringExt;
            ent.file_name().into_vec()
        };
        #[cfg(not(unix))]
        let name_bytes = ent.file_name().to_string_lossy().as_bytes().to_vec();
        entries.push((name_bytes, is_dir));
    }
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
    Ok(out)
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
            _ => out.push_str(&format!("%{b:02X}")),
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
    let v = value.trim();
    parse_imf_fixdate(v)
        .or_else(|| parse_rfc850(v))
        .or_else(|| parse_ansic(v))
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
        // Audit finding D2: TypeByExtension folds the extension to
        // lowercase before the mimeTypesLower lookup (mime/type.go:
        // 104-133) — probe vs go1.25.12: ".JPG"/".Jpg" answer image/jpeg.
        assert_eq!(mime_from_path(Path::new("photo.JPG")), "image/jpeg");
        assert_eq!(mime_from_path(Path::new("photo.Jpg")), "image/jpeg");
        assert_eq!(mime_from_path(Path::new("IMAGE.PNG")), "image/png");
        assert_eq!(
            mime_from_path(Path::new("INDEX.HTML")),
            "text/html; charset=utf-8"
        );
        // The remaining Go builtin rows (mime/type.go builtinTypesLower) —
        // .avif/.mjs/.webp were missing from the pre-fix table.
        assert_eq!(mime_from_path(Path::new("pic.avif")), "image/avif");
        assert_eq!(
            mime_from_path(Path::new("app.mjs")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(mime_from_path(Path::new("pic.webp")), "image/webp");
        // Unknown extension → octet-stream, no content sniffing (D2
        // fallback comment — Go would DetectContentType-sniff here).
        assert_eq!(
            mime_from_path(Path::new("unknown.xyz")),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_resolve_static_path_anchors_dotdot() {
        // Audit FIX 9: the remainder is cleaned anchored at the URL root
        // (Go path.Clean("/"+name)) — ".." clamps at the root and can never
        // escape; the old code returned "../etc/passwd" for the caller to
        // reject (403); Go serves the anchored result (200). (The
        // component-level validate_rel_path that once backed the 403 was
        // removed in the round-16 rework — the clean is constructive and
        // the open-handle guard is the real defense.)
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
        // Audit finding D1: the IMF day token must be exactly two digits —
        // Go's RFC1123 element '02' is getnum(fixed=true) (time/format.go:
        // 923-938), so single- AND three-digit days error in Go (probe vs
        // go1.25.12) → condNone → 200. The pre-fix code accepted the
        // space-padded single-digit shape as a "documented leniency" and
        // answered 304 where Go re-serves 200 — wrong, flipped here.
        assert_eq!(
            parse_if_modified_since("Sat,  1 Jan 2000 00:00:00 GMT"),
            None
        );
        assert_eq!(
            parse_if_modified_since("Sat, 007 Jan 2000 00:00:00 GMT"),
            None
        );
        // Exactly two digits parses (2000-01-07 = 946684800 + 6 days).
        assert_eq!(
            parse_if_modified_since("Sat, 07 Jan 2000 00:00:00 GMT"),
            Some(947203200)
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

        // Round-16 FIX 8: the other two layouts Go http.ParseTime tries —
        // RFC 850 (full weekday, dd-Mon-yy, Go parseTimeZone zone — the
        // round-16-era "any alphabetic zone" claim was broad: the full
        // parseTimeZone grammar applies, see the zone matrix test below)
        // and ANSIC (abbreviated weekday + month, space-padded day, no
        // zone). Oracle: 1136239445 = 2006-01-02 22:04:05 UTC (Monday).
        assert_eq!(
            parse_if_modified_since("Monday, 02-Jan-06 22:04:05 GMT"),
            Some(1136239445)
        );
        // Zone word "UTC": the stdTZ exact-3 special (format.go:1288-1291)
        // parses before parseTimeZone runs — "UTC" alone is legal even
        // though the generic 3-uppercase rule would not see it.
        assert_eq!(
            parse_if_modified_since("Monday, 02-Jan-06 22:04:05 UTC"),
            Some(1136239445)
        );
        // 2-digit-year pivot (Go format.go): 69-99 → 19xx, 00-68 → 20xx.
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 GMT"),
            Some(946684800)
        );
        // 2068-01-01 00:00:00 UTC = 35794 days after the epoch (98 years,
        // 24 leaps) = 3092601600; 2068-01-01 was a Sunday — "Monday" here
        // is a wrong-but-valid weekday name, which Go never cross-checks
        // (same as the IMF pins above).
        assert_eq!(
            parse_if_modified_since("Monday, 01-Jan-68 00:00:00 GMT"),
            Some(3092601600)
        );
        // ...68 is the LAST in-range year of the 20xx arm; 69 pivots to
        // 1969 which this parser rejects (pre-1970 — behaviorally
        // Go-identical: an IMS before every real mtime answers 200 either
        // way, see the fn doc).
        assert_eq!(
            parse_if_modified_since("Sunday, 01-Jan-69 00:00:00 GMT"),
            None
        );
        // Full weekday NAME is required by the RFC 850 layout — the
        // abbreviated shape belongs to the IMF layout above.
        assert_eq!(parse_if_modified_since("Sun, 02-Jan-06 22:04:05 GMT"), None);
        assert_eq!(
            parse_if_modified_since("Monday, 02 Jan 06 22:04:05 GMT"),
            None
        );
        // ANSIC — "Wkd Mmm _d HH:MM:SS YYYY", no zone, trailing token or
        // zone word fails (Go delimiters are exact). Oracle: the same
        // Monday instant with the layout's double-space day padding.
        assert_eq!(
            parse_if_modified_since("Mon Jan  2 22:04:05 2006"),
            Some(1136239445)
        );
        assert_eq!(
            parse_if_modified_since("Sat Jan  1 00:00:00 2000"),
            Some(946684800)
        );
        // Audit finding D1 (ANSIC sibling): layout "_2" is
        // getnum(fixed=false) — a 1- OR 2-digit day is legal, a 3-digit
        // day errors in Go (probe vs go1.25.12: "Sat Jan 007 ..." ERR).
        assert_eq!(
            parse_if_modified_since("Sat Jan  7 00:00:00 2000"),
            Some(947203200)
        );
        assert_eq!(parse_if_modified_since("Sat Jan 007 00:00:00 2000"), None);
        assert_eq!(
            parse_if_modified_since("Mon Jan  2 22:04:05 2006 GMT"),
            None
        );
        assert_eq!(parse_if_modified_since("Mon Jan  2 22:04:05"), None);
        assert_eq!(parse_if_modified_since("Mon 02 Jan 22:04:05 2006"), None);
        // Wrong-but-valid weekday accepted here too (Go never cross-checks).
        assert_eq!(
            parse_if_modified_since("Sun Jan  1 00:00:00 2000"),
            Some(946684800)
        );
    }

    /// Round-17 finding H: the RFC 850 zone word mirrors Go's
    /// `parseTimeZone` + stdTZ-UTC special over the WHOLE token — probe
    /// matrix re-verified against go1.25.12 (/tmp/go, time.Parse with the
    /// RFC 850 layout, 2026-09-08). Every OK row parses at ZERO offset
    /// (unix 946684800 — the layout-zone word never shifts the instant),
    /// which is why the parser gates on shape alone.
    #[test]
    fn rfc850_zone_go_parse_time_zone_matrix() {
        // Rows that time.Parse(time.RFC850, ...) accepts (probe: all OK,
        // unix 946684800 — zero offset).
        for ok in [
            "GMT",    // parseGMT, no offset
            "GMT+02", // signed offset 0-23, whole token consumed
            "GMT+5",  // single-digit offset
            "GMT+23", // 23 is in range
            "GMT+0",  // zero offset is legal despite the doc comment
            "GMT-5",  // negative sign
            "UTC",    // stdTZ exact-3 special, before parseTimeZone
            "XYZ",    // 3-uppercase run
            "ABC",    // 3-uppercase run
            "WITA",   // the 4-letter special (upper run would need a T)
            "ChST",   // lower-case-letter special
            "MeST",   // lower-case-letter special
            "CEST",   // 4-uppercase ending in T
            "XYZT",   // 4-uppercase ending in T
            "ABCDT",  // 5-uppercase ending in T
            "+03",    // bare signed offset
            "+23",    // 23 is in range
            "UTX",    // 3-uppercase (rule-derived: not probed)
        ] {
            assert!(
                rfc850_zone_ok(ok),
                "{ok} must parse (probe: OK at zero offset)"
            );
        }
        // Rows time.Parse rejects — every shape errors ("extra text" or
        // errBad). Probed except where noted.
        for bad in [
            "GMT+02:00", // offset consumed, ":00" is extra text (probe: ERR)
            "GMT+2:00",  // same, single digit (probe: ERR)
            "GMT+24:00", // 24 > 23 → offset fails → "GMT" only → extra text
            "GMT+24",    // rule-derived: x > 23 fails
            "GMT+024",   // leading zeros parse to 24 → out of range
            "GMT+",      // sign without digits (probe: ERR)
            "GMTX",      // "GMT" consumed, "X" extra text (probe: ERR)
            "GMTX+02",   // same (probe: ERR)
            "utc",       // lowercase: upper run is 0 (probe: ERR)
            "UTCX",      // stdTZ consumes "UTC", "X" is extra text
            "UTCT",      // same — parseTimeZone never runs on a "UTC" head
            "U",         // < 3 bytes (probe: ERR)
            "ABCDEF",    // 6-uppercase run (probe: ERR)
            "ABCDEFG",   // 7-uppercase (probe: ERR)
            "chst",      // upper run 0 (probe: ERR)
            "chST",      // upper run 2 (probe: ERR)
            "ABCD",      // 4-upper not ending in T, not WITA (probe: ERR)
            "ABCDE",     // 5-upper not ending in T (probe: ERR)
            "aBC",       // upper run 0 (probe: ERR)
            "ABCdE",     // upper run 3 OK, "dE" extra text (probe: ERR)
            "+5",        // < 3 bytes (probe: ERR)
            "+24",       // rule-derived: x > 23 fails
        ] {
            assert!(!rfc850_zone_ok(bad), "{bad} must fail (probe: ERR)");
        }
        // Whole-date rows through the IMS parser: the accepted zone shapes
        // land on the same zero-offset instant as GMT.
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 GMT+5"),
            Some(946684800)
        );
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 XYZ"),
            Some(946684800)
        );
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 WITA"),
            Some(946684800)
        );
        // The probe-ERR shapes fail the IMS parse too (condNone → 200).
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 GMT+02:00"),
            None
        );
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 ABCDEF"),
            None
        );
        assert_eq!(
            parse_if_modified_since("Saturday, 01-Jan-00 00:00:00 +5"),
            None
        );
    }

    /// gorilla cleanPath oracles (mux.go:280-301 — path.Clean plus the
    /// trailing-slash restore) over DECODED bytes (round-16 FIX 11): the
    /// canonical form the dir-301 arms redirect from when the request path
    /// is non-canonical.
    #[test]
    fn test_clean_path_canonical_go_oracles() {
        let c = |s: &str| {
            String::from_utf8_lossy(clean_path_canonical(s.as_bytes()).as_slice()).into_owned()
        };
        assert_eq!(c("/"), "/");
        assert_eq!(c(""), "/");
        assert_eq!(c("/sub"), "/sub");
        assert_eq!(c("/sub/"), "/sub/");
        assert_eq!(c("/sub/deep"), "/sub/deep");
        assert_eq!(c("/sub/deep/"), "/sub/deep/");
        // "." components vanish; ".." pops and clamps at the root.
        assert_eq!(c("/./sub"), "/sub");
        assert_eq!(c("/sub/../sub"), "/sub");
        assert_eq!(c("/a/.."), "/");
        assert_eq!(c("/a/../sub/"), "/sub/");
        assert_eq!(c("/.."), "/");
        assert_eq!(c("/../x"), "/x");
        // Repeated slashes collapse; the trailing slash is restored when the
        // cleaned result lost one the original had (gorilla cleanPath).
        assert_eq!(c("/static//sub"), "/static/sub");
        assert_eq!(c("//static"), "/static");
        assert_eq!(c("/static///sub/"), "/static/sub/");
        assert_eq!(c("/sub/./"), "/sub/");
        assert_eq!(c("/."), "/");
        assert_eq!(c("/sub/.."), "/");
    }

    /// Whole-second validation of the Feb 29 2000 pin above: 2000 was a leap
    /// year, 951782400 = the 2000-02-29 00:00:00 UTC oracle (GNU date).
    #[test]
    fn test_feb_29_2000_oracle() {
        assert_eq!(format_http_date(951782400), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    // ---- Audit FIX 6-10 e2e pins (real plugin listener + temp dir) ----

    async fn start_static(
        dir: &std::path::Path,
        strip: Option<&str>,
        auth: Option<(&str, &str)>,
    ) -> Option<PluginHandle> {
        let cfg = PluginConfig {
            plugin_type: "static_file".into(),
            local_path: dir.to_str().unwrap_or("").into(),
            strip_prefix: strip.unwrap_or("").into(),
            http_user: auth.map(|a| a.0.to_string()).unwrap_or_default(),
            http_password: auth.map(|a| a.1.to_string()).unwrap_or_default(),
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
        // A cap-close (431/400) can RST the conn while unrequested-overflow
        // bytes still sit in the server's receive buffer — the server closes
        // without draining. Bytes already sent are delivered; a reset on the
        // write or on a later read is the response end, not a failure.
        if let Err(e) = c.write_all(req).await {
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ),
                "write: {e}"
            );
        }
        let mut resp = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match c.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    break;
                }
                Err(e) => panic!("read: {e}"),
            }
        }
        resp
    }

    /// Basic Authorization header value for (user, pass) — Go StdEncoding,
    /// "Basic " + base64("user:pass") (the shape Go's BasicAuth / frp-rs's
    /// HttpProxyAuth::check both accept).
    fn basic_auth(user: &str, pass: &str) -> String {
        let mut h = String::from("Basic ");
        h.push_str(&frp_core::base64::encode(
            format!("{user}:{pass}").as_bytes(),
        ));
        h
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
        let Some(handle) = start_static(dir.path(), Some("static"), None).await else {
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
        let Some(handle) = start_static(dir.path(), None, None).await else {
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
        let Some(handle) = start_static(dir.path(), None, None).await else {
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

        // Round-16 FIX 13 (shared parse_request_line validation): an
        // invalid %-escape in the request target's PRE-'?' portion is a
        // 400 — Go url.Parse errors "invalid URL escape" inside
        // ReadRequest, before routing (probe vs go1.25.12: GET /x%zz →
        // 400). Incomplete escapes and escapes inside CONNECT authorities
        // are equally rejected; a literal "%25" is fine (it is the
        // encoded '%'). Query-only escapes parse and serve (post-fix
        // round): url.Parse Cuts the query RAW at the first '?' and never
        // unescape-validates it (probe vs go1.25.12: GET /x?q=%zz → 200).
        for bad in ["/x%zz", "/x%2", "/x%", "/sub/%zq", "/%GG", "http://h/x%zz"] {
            let req = format!("GET {bad} HTTP/1.1\r\nHost: t\r\n\r\n");
            assert_eq!(
                raw_get(addr, req.as_bytes()).await,
                super::super::GO_400_RENDER.as_bytes(),
                "invalid escape target {bad}"
            );
        }
        let ok_esc = raw_get(addr, b"GET /x%25zz HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            ok_esc.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
            "a valid escape clears the parse gate and reaches the open miss, got: {}",
            String::from_utf8_lossy(&ok_esc)
        );
        // A garbage escape in the QUERY never reaches the escape gate — the
        // file serves byte-identically to the same request without the
        // query (Go keeps the query raw end to end).
        let base = raw_get(addr, b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(base.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let qresp = raw_get(addr, b"GET /x?q=%zz HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(
            qresp,
            base,
            "a query-only invalid escape must serve the file like the baseline, \
             got: {}",
            String::from_utf8_lossy(&qresp[..qresp.len().min(80)])
        );
    }

    /// Audit FIX 10 e2e: Last-Modified on 200, If-Modified-Since → 304
    /// (mtime <= IMS, whole-second truncation), unparsable IMS → 200, and
    /// HEAD answering the gorilla route method gate: Methods("GET") matches
    /// GET only (no HEAD rewrite), so HEAD on a served file is a bare 405 —
    /// never a head-without-body 200.
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
        let Some(handle) = start_static(dir.path(), None, None).await else {
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

        // IMS == mtime → 304 — carries Last-Modified (round-16 FIX 5: Go
        // serveContent runs setLastModified BEFORE checkPreconditions, and
        // writeNotModified deletes Last-Modified only when an ETag is set —
        // FileServer never sets one, so the file 304 keeps it; probe vs
        // go1.25.12). No body, no Content-Length.
        let eq = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                  If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT\r\n\r\n";
        assert_eq!(
            raw_get(addr, eq.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\n\
              Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
              Connection: close\r\n\r\n"
        );

        // IMS one second AFTER the mtime → 304 as well (mtime <= IMS).
        let later = format_http_date(946684801);
        let after =
            format!("GET /doc.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {later}\r\n\r\n");
        assert_eq!(
            raw_get(addr, after.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\n\
              Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
              Connection: close\r\n\r\n"
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

        // HEAD: not a gorilla route match (Methods("GET") exact, no HEAD
        // rewrite — round-13-era claim was false) → bare 405 gate render,
        // zero body bytes, and no file I/O happened.
        let head = raw_get(addr, b"HEAD /doc.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(
            String::from_utf8_lossy(&head),
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
    }

    /// Audit round-7 e2e: Go http.FileServer localRedirect parity — a
    /// directory URL without the trailing slash answers 301 with the
    /// RELATIVE Location path.Base(stripped URL path) + "/" (RawQuery
    /// appended verbatim). The redirect sits INSIDE http.FileServer, and
    /// gorilla's route method gate runs ahead of the handler, so only GET
    /// ever reaches it: HEAD and POST on a slash-less dir answer the bare
    /// 405 gate render instead of the 301 (probe-verified vs gorilla
    /// v1.8.1 — POST /dir → 405 with CL:0, HEAD → 405 without CL). The
    /// slash-terminated form serves index.html directly, and a query never
    /// reaches file resolution (Go url.Parse: Path vs RawQuery).
    #[tokio::test]
    async fn test_static_file_e2e_dir_redirect_and_index() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "index.html", b"root-body");
        write_file(dir.path(), "sub/index.html", b"index-body");
        write_file(dir.path(), "sub/deep/inner.html", b"inner-body");
        write_file(dir.path(), "plain.txt", b"plain-body");
        let Some(handle) = start_static(dir.path(), None, None).await else {
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
        // A BARE '?' (empty RawQuery) appends nothing — Go localRedirect
        // gates on `if r.URL.RawQuery != ""`, so the Location carries no
        // stray '?' (round-16 FIX 10; probe vs go1.25.12: GET /sub? →
        // Location: sub/).
        assert_eq!(
            raw_get(addr, b"GET /sub? HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // HEAD and POST never reach FileServer's redirect: gorilla's
        // Methods("GET") route gate answers a bare 405 first (no auth chain
        // either — this listener configures no credentials).
        assert_eq!(
            raw_get(addr, b"HEAD /sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\
              Connection: close\r\n\r\n",
        );
        assert_eq!(
            raw_get(addr, b"POST /sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\
              Connection: close\r\n\r\n",
        );
        // Non-directory target: the same bare-405 route gate — now exact Go
        // parity (gorilla methodNotAllowedHandler on a Methods("GET") miss;
        // probe-verified: POST on a valid file path → 405; frp-rs renders
        // one fixed CL:0 head for every non-GET method, where Go omits the
        // CL on HEAD only).
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
        let Some(pref) = start_static(dir.path(), Some("static"), None).await else {
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

    /// dirList parity e2e: GET on a directory without a usable index.html
    /// answers 200 with Go's modern dirList page (go1.25 fs.go:139-172) —
    /// byte-wise-sorted <a> anchors inside <pre>, hrefs url-escaped, link
    /// text html-escaped, directories "/"-suffixed, no sizes/dates — and
    /// the surrounding Go serveFile order holds: the slash-less dir 301
    /// fires BEFORE the listing, a directory If-Modified-Since == dir mtime
    /// answers 304 with no LM/CT/CL (Go's setLastModified runs only after
    /// the IMS gate), the listing 200 carries Last-Modified, an open miss
    /// on a file path renders the Go 404 page, and the %-escaped hrefs are
    /// fetchable URLs.
    #[tokio::test]
    async fn test_static_file_e2e_dir_listing() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["alpha.txt", "b.txt", "plain.txt", "q?r.txt", "x\"&'<>.txt"] {
            write_file(dir.path(), name, b"x");
        }
        write_file(dir.path(), "sub/inner.txt", b"inner");
        write_file(dir.path(), "sub/deep/inner.html", b"deep");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        let expected = "<!doctype html>\n\
             <meta name=\"viewport\" content=\"width=device-width\">\n\
             <pre>\n\
             <a href=\"alpha.txt\">alpha.txt</a>\n\
             <a href=\"b.txt\">b.txt</a>\n\
             <a href=\"plain.txt\">plain.txt</a>\n\
             <a href=\"q%3Fr.txt\">q?r.txt</a>\n\
             <a href=\"sub/\">sub/</a>\n\
             <a href=\"x%22&%27%3C%3E.txt\">x&#34;&amp;&#39;&lt;&gt;.txt</a>\n\
             </pre>\n";
        let body = expected.as_bytes();

        // GET / → 200 listing: byte-exact body, text/html CT, exact CL.
        let resp = raw_get(addr, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let sep = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head terminator");
        let (head, resp_body) = resp.split_at(sep + 4);
        let head_s = String::from_utf8_lossy(head);
        assert!(head_s.starts_with("HTTP/1.1 200 OK\r\n"), "got: {head_s}");
        assert!(
            head_s.contains("Content-Type: text/html; charset=utf-8\r\n"),
            "got: {head_s}"
        );
        assert!(
            head_s.contains(&format!("Content-Length: {}\r\n", body.len())),
            "got: {head_s}"
        );
        assert!(head_s.contains("Last-Modified: "), "got: {head_s}");
        assert_eq!(resp_body, body);

        // The ASCII hrefs are fetchable: /q%3Fr.txt decodes to the q?r.txt
        // FILE (a raw '?' in the URL would split the query — Go parity).
        // (Round-16 FIX 2: this "hrefs fetchable" claim was false for
        // non-ASCII names under the old Latin-1 `as char` decode — the
        // non-ASCII round-trip is pinned separately below in
        // test_static_file_e2e_non_ascii_round_trip.)
        let q = raw_get(addr, b"GET /q%3Fr.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            q.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&q)
        );

        // Subdir listing: slash-terminated GET lists its own sorted entries.
        let sub = raw_get(addr, b"GET /sub/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let sub_s = String::from_utf8_lossy(&sub);
        assert!(sub_s.starts_with("HTTP/1.1 200 OK\r\n"), "got: {sub_s}");
        assert!(
            sub_s.contains("<a href=\"deep/\">deep/</a>\n<a href=\"inner.txt\">inner.txt</a>"),
            "got: {sub_s}"
        );

        // Slash-less dir → the FileServer 301 fires BEFORE the listing.
        assert_eq!(
            raw_get(addr, b"GET /sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );

        // dir IMS == dir mtime → 304 exact (no LM/CT/CL — Go parity on the
        // still-dir arm; probe-verified go1.25 dir 304 has no entity
        // headers at all).
        let mt = mtime_secs(&std::fs::metadata(dir.path()).unwrap()).unwrap();
        let eq = format!(
            "GET / HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {}\r\n\r\n",
            format_http_date(mt)
        );
        assert_eq!(
            raw_get(addr, eq.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n"
        );
        // IMS clearly before the dir mtime → 200 listing again.
        let before = format!(
            "GET / HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {}\r\n\r\n",
            format_http_date(mt - 3600)
        );
        let again = raw_get(addr, before.as_bytes()).await;
        assert!(
            again.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&again)
        );

        // Open miss on a file path → the Go 404 page (old bare CL:0 head
        // gone; Go's toHTTPError maps this to the same http.Error shape).
        assert_eq!(
            raw_get(addr, b"GET /nope.txt HTTP/1.1\r\nHost: t\r\n\r\n").await,
            super::super::GO_404_NOT_FOUND_RENDER.as_bytes(),
        );

        // Prefix mode: GET /static/ lists the same root page (strip-prefix
        // listing parity).
        let Some(pref) = start_static(dir.path(), Some("static"), None).await else {
            return;
        };
        let pa = pref.local_addr;
        let presp = raw_get(pa, b"GET /static/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            presp.ends_with(body),
            "got: {}",
            String::from_utf8_lossy(&presp)
        );
    }

    /// Round-16 post-fix e2e (the flip): a terminated request head that
    /// exceeds 64 KiB is SERVED byte-identically to the same request
    /// without the big header — Go's cap is a READ LIMIT
    /// (MaxHeaderBytes 1 MiB + 4096 bufio slop) that errors only when the
    /// limit is consumed with the head still INCOMPLETE, so a head whose
    /// empty-line terminator arrived parses and serves at ANY size up to
    /// ~1 MiB+4096 (probe vs go1.25.12: a terminated ~1 MiB+64 head
    /// answers 200). RED on the old code twice over: the round-15 order
    /// (cap check after the terminator break) served this head only
    /// because the 64 KiB cap never ran on the terminator path — the
    /// round-16-wave order (cap check before the terminator scan) 431'd
    /// it. The baseline-equality assert proves the parse + file-serve
    /// path ran end to end (the big header was consumed, the request line
    /// parsed, the file opened and served) — not just "not 431".
    #[tokio::test]
    async fn test_static_file_e2e_oversize_head_is_served() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "x", b"x");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        let base = raw_get(addr, b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            base.starts_with(b"HTTP/1.1 200 OK"),
            "baseline must serve the file, got: {:?}",
            String::from_utf8_lossy(&base[..base.len().min(80)])
        );
        let mut req = Vec::from(b"GET /x HTTP/1.1\r\nHost: t\r\nX-Big: ".as_slice());
        req.resize(req.len() + 70000, b'a');
        req.extend_from_slice(b"\r\n\r\n");
        assert!(
            req.len() > 65536,
            "fixture must exceed the old 64 KiB cap (len {})",
            req.len()
        );
        let resp = raw_get(addr, &req).await;
        assert_eq!(
            resp,
            base,
            "a TERMINATED head past 64 KiB must be served byte-identically to the \
             baseline (Go read-limit model), got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }

    /// Round-16 post-fix e2e (arm b): a terminated head whose terminator
    /// lies PAST the serve boundary — total ~1 MiB + 8226, terminator far
    /// beyond the 1 MiB + 4096 slack — still renders Go's 431 page
    /// byte-exact. Go's errTooLarge fires when the limit is consumed
    /// mid-head; a terminator that far out never completes the head in
    /// time (probe: same class as the http.rs plain-arm 431). RED on the
    /// round-15 order (the 64 KiB cap sat after the terminator break and
    /// this head served): the fixture breaches the read limit only at
    /// ~1 MiB, which the 64 KiB era never enforced on unterminated
    /// buffers beyond a silent error. The breach fires as soon as the
    /// buffer passes 1 MiB without an empty line, so the client-side
    /// write outruns the read: the payload is written from a spawned
    /// task (it errors when the server closes mid-send — expected,
    /// ignored) while this task reads the render, bounded by a 10 s
    /// deadline.
    #[tokio::test]
    async fn test_static_file_e2e_terminated_past_slack_head_answers_go_431() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "x", b"x");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let client = TcpStream::connect(handle.local_addr).await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(client);
        let mut head = Vec::with_capacity(1024 * 1024 + 16 * 1024);
        head.extend_from_slice(b"GET /x HTTP/1.1\r\nHost: t\r\nX-Big: ");
        head.resize(1024 * 1024 + 8192, b'A');
        head.extend_from_slice(b"\r\n\r\n");
        tokio::spawn(async move {
            // The server breaches at ~1 MiB + one chunk and closes; the
            // rest of the payload is never consumed. The write errors —
            // that is the expected outcome, ignored here.
            let _ = wr.write_all(&head).await;
        });
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            rd.read_to_end(&mut resp),
        )
        .await
        .expect("timed out waiting for the 431 render — regression?");
        assert_eq!(
            resp,
            super::super::GO_431_RENDER.as_bytes(),
            "a terminated head past the serve boundary must render Go's 431, \
             got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }

    /// Round-16 post-fix e2e (arm c): an UNTERMINATED head past the cap —
    /// ~1 MiB + 32 of header bytes, no empty line ever sent — renders Go's
    /// 431 page byte-exact. No terminator is ever in the buffer, so the
    /// read limit is the only way the read can end; an unfinished head is
    /// errTooLarge in Go (the render fires before the handler runs).
    /// Go's limit carries 4096 bufio slop on top of MaxHeaderBytes, so Go
    /// would only breach after ~1 MiB+4096 consumed; frp-rs fires up to
    /// one 4096 chunk earlier (same 431 class, slack margin as documented
    /// on the read loop). The head size keeps the whole client payload
    /// consumed before the breach fires, so the close is clean and the
    /// render always arrives. RED on the old code: the round-15 order
    /// errored this shape SILENTLY at 64 KiB (no render) and the
    /// round-16-wave order 431'd it at 64 KiB with a different cap.
    #[tokio::test]
    async fn test_static_file_e2e_unterminated_oversized_head_answers_go_431() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "x", b"x");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
        let mut head = Vec::with_capacity(1024 * 1024 + 64);
        head.extend_from_slice(b"GET /x HTTP/1.1\r\nHost: t\r\nX-Big: ");
        head.resize(1024 * 1024 + 32, b'A');
        // No terminator: the head stays unterminated past the cap.
        let _ = client.write_all(&head).await;
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        assert_eq!(
            resp,
            super::super::GO_431_RENDER.as_bytes(),
            "an unterminated head past the cap must render Go's 431, \
             got {} bytes: {:?}",
            resp.len(),
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }

    /// Round-16 FIX 3 e2e: Go serveFile's FIRST arm — a URL path ending in
    /// "/index.html" answers 301 Location: ./ BEFORE any file I/O, so it
    /// fires for a deleted index.html too, and the query survives
    /// (fs.go:682-688 + localRedirect; probe vs go1.25.12: served AND
    /// deleted index.html both redirect). The relative "./" resolves against
    /// the requesting directory, so links inside a served index.html stay
    /// resolvable under a strip prefix as well.
    #[tokio::test]
    async fn test_static_file_e2e_index_suffix_redirect() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "sub/index.html", b"index-body");
        // sub2 has NO index.html — the suffix redirect fires anyway.
        std::fs::create_dir_all(dir.path().join("sub2")).unwrap();
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        // Exists → 301 ./; missing → same 301 ./ (no 404 — the arm runs
        // before fs.Open).
        assert_eq!(
            raw_get(addr, b"GET /sub/index.html HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(
            raw_get(addr, b"GET /sub2/index.html HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Query preserved (localRedirect appends RawQuery when non-empty).
        assert_eq!(
            raw_get(addr, b"GET /sub/index.html?x=1 HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./?x=1\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Root-level /index.html (no such file here) → same arm, same 301.
        assert_eq!(
            raw_get(addr, b"GET /index.html HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // A trailing slash kills the suffix match ("/index.html/" ends in
        // "/", not "/index.html") → normal file handling: an open miss on
        // the nonexistent root index.html renders the 404 page.
        assert_eq!(
            raw_get(addr, b"GET /index.html/ HTTP/1.1\r\nHost: t\r\n\r\n").await,
            super::super::GO_404_NOT_FOUND_RENDER.as_bytes(),
        );

        // Prefix mode: same relative "./" — the browser resolves it against
        // /static/sub/, which serves the very index.html that was requested.
        let Some(pref) = start_static(dir.path(), Some("static"), None).await else {
            return;
        };
        let pa = pref.local_addr;
        assert_eq!(
            raw_get(
                pa,
                b"GET /static/sub/index.html HTTP/1.1\r\nHost: t\r\n\r\n"
            )
            .await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }

    /// Round-17 finding I e2e: the "/index.html" suffix probe runs on the
    /// CLEANED path. Gorilla's router path.Cleans URL.Path (and 301s the
    /// absolute cleaned form) BEFORE StripPrefix hands the path to
    /// FileServer, so the probe serveFile sees is always clean. frp-rs
    /// folds the router hop away (round-16 FIX 11 precedent) — Location
    /// "./" answers in one hop where Go needs two (router 301, then the
    /// fs.go suffix redirect on the refetch) — but the CLEANED probe is
    /// mandatory: "/a/b/index.html/." reaches Go's serveFile as
    /// "/a/b/index.html" (the trailing "/." cleaned away) and redirects,
    /// while a raw-suffix probe fell through and served the file.
    #[tokio::test]
    async fn test_static_file_e2e_suffix_probe_on_cleaned_path() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "a/b/index.html", b"index-body");
        // b2 has NO index.html — the suffix redirect fires anyway (the arm
        // runs before fs.Open, round-16 FIX 3).
        std::fs::create_dir_all(dir.path().join("a/b2")).unwrap();
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;
        let expect_301 = b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./\r\n\
                           Content-Length: 0\r\nConnection: close\r\n\r\n";

        // The mandated shape: a mid-path "/./" must 301 like its clean
        // form ("/a/./b/index.html" ≡ "/a/b/index.html" — gorilla cleans
        // both to the same path before the probe).
        assert_eq!(
            raw_get(addr, b"GET /a/./b/index.html HTTP/1.1\r\nHost: t\r\n\r\n").await,
            expect_301,
        );
        // The divergence shape: the "/index.html" suffix exists only after
        // the clean. Pre-fix this answered 200 with the file body (raw
        // probe missed); Go cleans "/a/b/index.html/." → router 301 → the
        // refetch's probe redirects "./" — the single-hop fold must land
        // on the same 301.
        assert_eq!(
            raw_get(addr, b"GET /a/b/index.html/. HTTP/1.1\r\nHost: t\r\n\r\n").await,
            expect_301,
        );
        // Same hidden-dot shape over a MISSING index.html → still 301
        // (no existence check in the arm).
        assert_eq!(
            raw_get(addr, b"GET /a/b2/index.html/. HTTP/1.1\r\nHost: t\r\n\r\n").await,
            expect_301,
        );
        // Query survives the cleaned probe (RawQuery append after the
        // split — the dot suffix is in the path, not the query).
        assert_eq!(
            raw_get(
                addr,
                b"GET /a/b/index.html/.?q=1 HTTP/1.1\r\nHost: t\r\n\r\n"
            )
            .await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ./?q=1\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // A mid-path dot that the RAW probe already caught stays caught
        // (clean and raw agree on "/a/b/./index.html").
        assert_eq!(
            raw_get(addr, b"GET /a/b/./index.html HTTP/1.1\r\nHost: t\r\n\r\n").await,
            expect_301,
        );
        // A trailing slash still kills the suffix match — the cleaned
        // probe of "/a/b/index.html/" keeps the trailing '/', so it never
        // ends in "/index.html". The FILE here exists, so Go's fs.go
        // redirect arm (a non-directory whose URL ends in '/' → 301
        // "../" + path.Base, fs.go:714-724) answers first — the file body
        // is never served.
        assert_eq!(
            raw_get(addr, b"GET /a/b/index.html/ HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ../index.html\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );

        // Prefix mode: the fold cleans the reattached remainder only —
        // component-boundary equivalent to stripping the prefix from the
        // cleaned full path.
        let Some(pref) = start_static(dir.path(), Some("static"), None).await else {
            return;
        };
        let pa = pref.local_addr;
        assert_eq!(
            raw_get(
                pa,
                b"GET /static/a/b/index.html/. HTTP/1.1\r\nHost: t\r\n\r\n"
            )
            .await,
            expect_301,
        );
    }

    /// Round-16 FIX 4 e2e: Go serveFile's file-with-trailing-slash redirect
    /// (fs.go:714-724) — a FILE URL ending in '/' answers 301 Location:
    /// "../" + path.Base(url), the base resolving one directory UP out of
    /// the slash-suffixed URL (probe vs go1.25.12: GET /plain.txt/ → 301
    /// Location: ../plain.txt). Degenerate: local_path pointing AT a file —
    /// the root URL then maps to the file with an empty base, which Go
    /// answers with the 500 "http: attempting to traverse a non-directory"
    /// (fs.go:716-721).
    #[tokio::test]
    async fn test_static_file_e2e_file_with_slash_301() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "plain.txt", b"plain-body");
        write_file(dir.path(), "sub/deep/inner.html", b"inner-body");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        assert_eq!(
            raw_get(addr, b"GET /plain.txt/ HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ../plain.txt\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Query preserved into the "../"-Location.
        assert_eq!(
            raw_get(addr, b"GET /plain.txt/?x=1 HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ../plain.txt?x=1\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Deep file: base = path.Base of the FULL slash-suffixed URL.
        assert_eq!(
            raw_get(
                addr,
                b"GET /sub/deep/inner.html/ HTTP/1.1\r\nHost: t\r\n\r\n"
            )
            .await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ../inner.html\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Prefix mode: "../plain.txt" resolves against /static/ — the
        // slash-less URL that serves the file.
        let Some(pref) = start_static(dir.path(), Some("static"), None).await else {
            return;
        };
        let pa = pref.local_addr;
        assert_eq!(
            raw_get(pa, b"GET /static/plain.txt/ HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: ../plain.txt\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );

        // Degenerate 500: local_path IS a file → GET / maps the root URL to
        // the file with an empty base (Go path.Base("/") == "/" → the
        // traverse-a-non-directory http.Error).
        let file_path = {
            let p = dir.path().join("standalone.txt");
            std::fs::write(&p, b"file-as-root").unwrap();
            p
        };
        let Some(fh) = start_static(&file_path, None, None).await else {
            return;
        };
        let resp = raw_get(fh.local_addr, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(
            String::from_utf8_lossy(&resp),
            "HTTP/1.1 500 Internal Server Error\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             X-Content-Type-Options: nosniff\r\n\
             Content-Length: 45\r\nConnection: close\r\n\r\n\
             http: attempting to traverse a non-directory\n",
        );
    }

    /// Round-16 FIX 9 e2e: an epoch (zero) mtime is Go's isZeroTime — no
    /// Last-Modified is emitted on the 200 and the If-Modified-Since
    /// precondition never fires (Go condNone → always 200). The old code
    /// treated Some(0) as a real mtime: it emitted "Thu, 01 Jan 1970" and
    /// answered 304 against any IMS.
    #[tokio::test]
    async fn test_static_file_e2e_epoch_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.txt");
        std::fs::write(&p, b"epoch-body").unwrap();
        std::fs::File::open(&p)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .expect("set_modified(UNIX_EPOCH) on temp file");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        let ok = raw_get(addr, b"GET /epoch.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let ok_s = String::from_utf8_lossy(&ok);
        assert!(
            ok_s.starts_with(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: 10\r\nConnection: close\r\n\r\n"
            ),
            "no Last-Modified for an epoch mtime, got: {ok_s}"
        );
        assert!(!ok_s.contains("Last-Modified"), "got: {ok_s}");
        assert!(ok.ends_with(b"epoch-body"));

        // IMS any date → 200, never 304 (epoch mtime is None → the
        // precondition arm is skipped entirely).
        let ims = "GET /epoch.txt HTTP/1.1\r\nHost: t\r\n\
                   If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n";
        let ims_resp = raw_get(addr, ims.as_bytes()).await;
        assert!(
            ims_resp.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "epoch mtime must never 304, got: {}",
            String::from_utf8_lossy(&ims_resp)
        );
    }

    /// Round-16 FIX 8 e2e: If-Modified-Since in Go's two ALTERNATE accepted
    /// layouts — RFC 850 and ANSIC — parses (Go http.ParseTime tries all
    /// three; the old parser knew only IMF-fixdate, so both fell through to
    /// a 200). File mtime pinned at 946684800 (2000-01-01 00:00:00 UTC).
    #[tokio::test]
    async fn test_static_file_e2e_ims_alternate_layouts() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("doc.txt");
        std::fs::write(&p, b"alternate").unwrap();
        std::fs::File::open(&p)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(946684800))
            .expect("set_modified on temp file");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        // RFC 850 (full weekday, dd-Mon-yy): "Saturday, 01-Jan-00" ==
        // 2000-01-01 == the mtime → 304. The file 304 keeps Last-Modified
        // (round-16 FIX 5 shape).
        let rfc850 = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                      If-Modified-Since: Saturday, 01-Jan-00 00:00:00 GMT\r\n\r\n";
        assert_eq!(
            raw_get(addr, rfc850.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\n\
              Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
              Connection: close\r\n\r\n"
        );

        // ANSIC (abbreviated weekday + month, space-padded day, no zone):
        // "Sat Jan  1 00:00:00 2000" → same 304.
        let ansic = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                     If-Modified-Since: Sat Jan  1 00:00:00 2000\r\n\r\n";
        assert_eq!(
            raw_get(addr, ansic.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\n\
              Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
              Connection: close\r\n\r\n"
        );

        // An RFC 850 IMS one second AFTER the mtime → 304 too (mtime <=
        // IMS; 2-digit year "00" pivots to 2000).
        let later = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                     If-Modified-Since: Saturday, 01-Jan-00 00:00:01 GMT\r\n\r\n";
        assert_eq!(
            raw_get(addr, later.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\n\
              Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
              Connection: close\r\n\r\n"
        );

        // A trailing zone word after an ANSIC date fails the ANSIC layout
        // (no zone element — Go delimiters exact) → condNone → 200.
        let bad = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                   If-Modified-Since: Sat Jan  1 00:00:00 2000 GMT\r\n\r\n";
        let resp = raw_get(addr, bad.as_bytes()).await;
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Round-16 FIX 7 e2e: duplicate headers use Go Header.Get FIRST-value
    /// semantics — the first If-Modified-Since row decides the precondition
    /// (an empty-value row included), and the first Authorization row is the
    /// one the auth middleware checks. The old last-wins assignment
    /// mirrored nothing in Go (textproto appends; Get returns v[0]).
    #[tokio::test]
    async fn test_static_file_e2e_dup_header_first_wins() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("doc.txt");
        std::fs::write(&p, b"dup-header-body").unwrap();
        std::fs::File::open(&p)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(946684800))
            .expect("set_modified on temp file");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        // IMS rows: the mtime (== 304 candidate) first, an EARLIER date
        // (== 200 candidate) second → the FIRST row wins → 304. (Last-wins
        // would answer 200.)
        let a = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                 If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
                 If-Modified-Since: Fri, 31 Dec 1999 23:00:00 GMT\r\n\r\n";
        assert_eq!(
            raw_get(addr, a.as_bytes()).await,
            b"HTTP/1.1 304 Not Modified\r\n\
              Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\
              Connection: close\r\n\r\n"
        );
        // Reversed: the earlier (200-candidate) row first, the mtime row
        // second → the first row wins → 200. (Last-wins would answer 304.)
        let b = "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
                 If-Modified-Since: Fri, 31 Dec 1999 23:00:00 GMT\r\n\
                 If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT\r\n\r\n";
        let resp_b = raw_get(addr, b.as_bytes()).await;
        assert!(
            resp_b.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "got: {}",
            String::from_utf8_lossy(&resp_b)
        );

        // Authorization rows (creds u/p): good-then-bad → the FIRST row
        // wins → 200.
        let Some(authd) = start_static(dir.path(), None, Some(("u", "p"))).await else {
            return;
        };
        let aa = authd.local_addr;
        let good = basic_auth("u", "p");
        let bad = basic_auth("u", "wrong");
        let c = format!(
            "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
             Authorization: {good}\r\nAuthorization: {bad}\r\n\r\n"
        );
        let resp_c = raw_get(aa, c.as_bytes()).await;
        assert!(
            resp_c.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "first Authorization row wins, got: {}",
            String::from_utf8_lossy(&resp_c)
        );
        // Bad-then-good → 401 (first row is what auth checks).
        let d = format!(
            "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
             Authorization: {bad}\r\nAuthorization: {good}\r\n\r\n"
        );
        let resp_d = raw_get(aa, d.as_bytes()).await;
        assert!(
            resp_d.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"),
            "first row bad → 401, got: {}",
            String::from_utf8_lossy(&resp_d)
        );
        // Empty-value row first shadows a later valid row (Header.Get
        // returns v[0] even when empty) → 401.
        let e = format!(
            "GET /doc.txt HTTP/1.1\r\nHost: t\r\n\
             Authorization:\r\nAuthorization: {good}\r\n\r\n"
        );
        let resp_e = raw_get(aa, e.as_bytes()).await;
        assert!(
            resp_e.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"),
            "empty first row shadows the valid one, got: {}",
            String::from_utf8_lossy(&resp_e)
        );
    }

    /// Round-16 FIX 11 e2e: a non-canonical request path resolving to a
    /// DIRECTORY redirects from the gorilla-cleanPath canonical form with an
    /// ABSOLUTE Location (single-hop fold of Go's router-301 +
    /// FileServer-301 chain) — the old relative Location derived from the
    /// UNCLEANED remainder sent "/static//sub" back to "/static//sub/",
    /// which never converged. Canonical paths keep the relative
    /// path.Base + "/" Location (pinned above). Follow-ups land on the
    /// canonical slash-terminated URL and serve.
    #[tokio::test]
    async fn test_static_file_e2e_dir_noncanonical_absolute_301() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "sub/index.html", b"index-body");
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        let redirects = [
            ("GET /./sub HTTP/1.1\r\nHost: t\r\n\r\n", "/sub/"),
            ("GET /sub/../sub HTTP/1.1\r\nHost: t\r\n\r\n", "/sub/"),
            ("GET /nope/../sub HTTP/1.1\r\nHost: t\r\n\r\n", "/sub/"),
        ];
        for (req, location) in redirects {
            let want = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            assert_eq!(
                raw_get(addr, req.as_bytes()).await,
                want.as_bytes(),
                "request {req}"
            );
        }
        // The absolute Location is directly fetchable → canonical listing.
        let follow = raw_get(addr, b"GET /sub/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            follow.starts_with(b"HTTP/1.1 200 OK\r\n") && follow.ends_with(b"index-body"),
            "got: {}",
            String::from_utf8_lossy(&follow)
        );

        // Prefix mode: the doubled-slash shape that never converged before —
        // "/static//sub" → absolute "/static/sub/" (canonical-full includes
        // the prefix; gorilla cleans at the router, pre-strip).
        let Some(pref) = start_static(dir.path(), Some("static"), None).await else {
            return;
        };
        let pa = pref.local_addr;
        assert_eq!(
            raw_get(pa, b"GET /static//sub HTTP/1.1\r\nHost: t\r\n\r\n").await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /static/sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let pfollow = raw_get(pa, b"GET /static/sub/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            pfollow.starts_with(b"HTTP/1.1 200 OK\r\n") && pfollow.ends_with(b"index-body"),
            "got: {}",
            String::from_utf8_lossy(&pfollow)
        );
        // The slash-terminated non-canonical form serves DIRECTLY (no
        // redirect — only slash-less dirs redirect).
        let term = raw_get(pa, b"GET /static//sub/ HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            term.starts_with(b"HTTP/1.1 200 OK\r\n") && term.ends_with(b"index-body"),
            "got: {}",
            String::from_utf8_lossy(&term)
        );
    }

    /// Round-16 FIX 2 e2e: non-ASCII file names round-trip through the
    /// listing and the file arms — the dirList href percent-encodes the
    /// UTF-8 bytes ("na%C3%AFve.txt"), the href is fetchable, and a raw
    /// UTF-8 request path serves the same file. (The old Latin-1 `as char`
    /// decode re-encoded %C3%AF as C3 83 C2 AF — a mojibake name that
    /// 404'd. cfg(unix): names that are not valid UTF-8 at all round-trip
    /// byte-exactly too.)
    #[tokio::test]
    async fn test_static_file_e2e_non_ascii_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "naïve.txt", "naïve-content".as_bytes());
        let Some(handle) = start_static(dir.path(), None, None).await else {
            return;
        };
        let addr = handle.local_addr;

        // The listing href escapes the UTF-8 bytes; the anchor text shows
        // the raw name.
        let listing = raw_get(addr, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let ls = String::from_utf8_lossy(&listing);
        assert!(
            ls.contains("<a href=\"na%C3%AFve.txt\">naïve.txt</a>"),
            "listing must escape href but keep the text, got: {ls}"
        );

        // Fetching the escaped href → 200, byte-exact body.
        let via_href = raw_get(addr, b"GET /na%C3%AFve.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert!(
            via_href.starts_with(b"HTTP/1.1 200 OK\r\n")
                && via_href.ends_with(b"na\xc3\xafve-content"),
            "got: {}",
            String::from_utf8_lossy(&via_href)
        );
        // A raw UTF-8 request path decodes to the same bytes → same file.
        let via_raw = raw_get(
            addr,
            "GET /naïve.txt HTTP/1.1\r\nHost: t\r\n\r\n".as_bytes(),
        )
        .await;
        assert_eq!(
            via_raw, via_href,
            "raw UTF-8 and %-escaped paths must agree"
        );

        // cfg(unix): a name that is NOT valid UTF-8 — %FF — escapes as
        // "%FF", fetches, and serves byte-exactly (OsStringExt join; the
        // lossy path is compile-time-only elsewhere).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let raw_name = std::ffi::OsString::from_vec(b"raw\xff.txt".to_vec());
            std::fs::write(dir.path().join(&raw_name), b"raw-ff-body").unwrap();
            let listing2 = raw_get(addr, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
            let ls2 = String::from_utf8_lossy(&listing2);
            assert!(
                ls2.contains("<a href=\"raw%FF.txt\">"),
                "non-UTF-8 name must list byte-escaped, got: {ls2}"
            );
            let via = raw_get(addr, b"GET /raw%FF.txt HTTP/1.1\r\nHost: t\r\n\r\n").await;
            assert!(
                via.starts_with(b"HTTP/1.1 200 OK\r\n") && via.ends_with(b"raw-ff-body"),
                "got: {}",
                String::from_utf8_lossy(&via)
            );
        }
    }

    /// Route-gate order e2e: with a credentials-configured listener,
    /// gorilla's route gates precede the auth middleware — prefix miss →
    /// 404 page (auth never runs, with OR without valid credentials),
    /// valid-prefix non-GET → bare 405 (again auth-independent), and only a
    /// fully-matched GET reaches the auth chain (wrong creds → 401 page)
    /// and then http.FileServer (valid creds → 200 file / 301 slash-less
    /// dir; wrong creds on the slash-less dir → 401, auth before the
    /// FileServer-internal redirect).
    #[tokio::test]
    async fn test_static_file_e2e_method_and_route_gates_before_auth() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "plain.txt", b"plain-body");
        write_file(dir.path(), "sub/index.html", b"index-body");
        let Some(handle) = start_static(dir.path(), Some("static"), Some(("u", "p"))).await else {
            return;
        };
        let addr = handle.local_addr;
        let good = basic_auth("u", "p");
        let bad = basic_auth("u", "wrong");

        // 1. Prefix miss → 404 page. No credentials and valid credentials
        // both: gorilla builds the middleware chain only for fully-matched
        // routes, so the 401 arm never runs.
        assert_eq!(
            raw_get(addr, b"GET /staticx/y HTTP/1.1\r\nHost: t\r\n\r\n").await,
            super::super::GO_404_NOT_FOUND_RENDER.as_bytes(),
        );
        let miss_auth =
            format!("GET /staticx/y HTTP/1.1\r\nHost: t\r\nAuthorization: {good}\r\n\r\n");
        assert_eq!(
            raw_get(addr, miss_auth.as_bytes()).await,
            super::super::GO_404_NOT_FOUND_RENDER.as_bytes(),
        );

        // 2. Method gate → bare 405 before auth: no credentials, valid
        // credentials, and wrong credentials all answer 405 on a
        // valid-prefix path (route gate, not middleware).
        let auth_lines = [
            String::new(),
            format!("\r\nAuthorization: {good}"),
            format!("\r\nAuthorization: {bad}"),
        ];
        for auth_line in &auth_lines {
            for method in ["HEAD", "POST"] {
                let req =
                    format!("{method} /static/plain.txt HTTP/1.1\r\nHost: t{auth_line}\r\n\r\n");
                assert_eq!(
                    raw_get(addr, req.as_bytes()).await,
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                    "method {method} with auth {auth_line:?}"
                );
            }
        }

        // 3. Matched GET with wrong creds → the Go frp 401 page (the
        // 200ms anti-brute-force delay is inside the handler, already
        // covered by the auth unit tests elsewhere). Header name is
        // Go-canonicalized on the wire (round-16 FIX 12: net/http writes
        // "Www-Authenticate:", probe vs go1.25.12 + Go frp v0.71.0).
        let unauth =
            format!("GET /static/plain.txt HTTP/1.1\r\nHost: t\r\nAuthorization: {bad}\r\n\r\n");
        assert_eq!(
            raw_get(addr, unauth.as_bytes()).await,
            b"HTTP/1.1 401 Unauthorized\r\n\
              Content-Length: 13\r\n\
              Content-Type: text/plain; charset=utf-8\r\n\
              Www-Authenticate: Basic realm=\"Restricted\"\r\n\
              X-Content-Type-Options: nosniff\r\n\
              \r\n\
              Unauthorized\n",
        );

        // 4. Matched GET with valid creds → 200 file.
        let ok_req =
            format!("GET /static/plain.txt HTTP/1.1\r\nHost: t\r\nAuthorization: {good}\r\n\r\n");
        let ok = raw_get(addr, ok_req.as_bytes()).await;
        assert!(
            ok.starts_with(b"HTTP/1.1 200 OK\r\n") && ok.ends_with(b"plain-body"),
            "got: {}",
            String::from_utf8_lossy(&ok)
        );

        // 5. Valid-creds slash-less dir → the FileServer 301 (auth passed).
        let redir_req =
            format!("GET /static/sub HTTP/1.1\r\nHost: t\r\nAuthorization: {good}\r\n\r\n");
        assert_eq!(
            raw_get(addr, redir_req.as_bytes()).await,
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: sub/\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        // Wrong-creds slash-less dir → 401 page: auth wraps the whole
        // FileServer, so the redirect never runs for an unauthenticated
        // caller.
        let unauth_redir =
            format!("GET /static/sub HTTP/1.1\r\nHost: t\r\nAuthorization: {bad}\r\n\r\n");
        assert!(raw_get(addr, unauth_redir.as_bytes())
            .await
            .starts_with(b"HTTP/1.1 401 Unauthorized\r\n"),);
    }

    #[test]
    fn test_url_escape_and_html_escape_go_parity() {
        // url.URL{Path}.String() encodePath mode: the unreserved set plus
        // $&+,/:;=@ stay literal — ONLY '?' is additionally escaped — and
        // everything else percent-encodes byte-wise with uppercase hex
        // (href oracles probe-verified against go1.25.0 dirList). The fn
        // operates on BYTES (round-16 FIX 2) — non-ASCII inputs are their
        // UTF-8 bytes, and arbitrary bytes escape identically.
        assert_eq!(
            url_escape_bytes(b"a b?c#d%&e:f/g"),
            "a%20b%3Fc%23d%25&e:f/g"
        );
        assert_eq!(url_escape_bytes(b"plain.txt"), "plain.txt");
        assert_eq!(url_escape_bytes(b"sub/"), "sub/");
        assert_eq!(url_escape_bytes(b"q?r.txt"), "q%3Fr.txt");
        assert_eq!(url_escape_bytes(b"x\"&'<>.txt"), "x%22&%27%3C%3E.txt");
        // Non-ASCII percent-encodes byte-wise (ï = C3 AF) — and so does a
        // byte that is NOT valid UTF-8 at all (%FF), like Go hexEscapeNon-
        // ASCII over a raw name.
        assert_eq!(url_escape_bytes("naïve.txt".as_bytes()), "na%C3%AFve.txt");
        assert_eq!(url_escape_bytes(b"raw\xff.txt"), "raw%FF.txt");
        assert_eq!(url_escape_bytes(b"\xff"), "%FF");
        // htmlReplacer (net/http server.go): & < > " '.
        assert_eq!(
            html_escape_text("x\"&'<>.txt"),
            "x&#34;&amp;&#39;&lt;&gt;.txt"
        );
        assert_eq!(html_escape_text("plain & simple"), "plain &amp; simple");
        assert_eq!(html_escape_text("no escapes"), "no escapes");
    }

    #[test]
    fn test_render_dir_listing_go_shape() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["alpha.txt", "b.txt", "q?r.txt", "x\"&'<>.txt"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/inner.txt"), b"x").unwrap();
        let listing = render_dir_listing(dir.path()).unwrap();
        assert_eq!(
            listing,
            "<!doctype html>\n\
             <meta name=\"viewport\" content=\"width=device-width\">\n\
             <pre>\n\
             <a href=\"alpha.txt\">alpha.txt</a>\n\
             <a href=\"b.txt\">b.txt</a>\n\
             <a href=\"q%3Fr.txt\">q?r.txt</a>\n\
             <a href=\"sub/\">sub/</a>\n\
             <a href=\"x%22&%27%3C%3E.txt\">x&#34;&amp;&#39;&lt;&gt;.txt</a>\n\
             </pre>\n"
        );
        // Byte-wise sort (Go fs.ReadDir pre-sorts on raw names): uppercase
        // sorts before lowercase.
        std::fs::write(dir.path().join("A.txt"), b"x").unwrap();
        let l2 = render_dir_listing(dir.path()).unwrap();
        assert!(
            l2.find("<a href=\"A.txt\">A.txt</a>").unwrap()
                < l2.find("<a href=\"alpha.txt\">alpha.txt</a>").unwrap(),
            "A.txt must sort before alpha.txt: {l2}"
        );
        // A symlink-to-directory lists WITHOUT the trailing "/" (d_type
        // parity — Go appends "/" only to entries whose IsDir() is true).
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join("sub"), dir.path().join("linkdir")).unwrap();
            let l3 = render_dir_listing(dir.path()).unwrap();
            assert!(
                l3.contains("<a href=\"linkdir\">linkdir</a>"),
                "symlink-to-dir must not get '/': {l3}"
            );
        }
    }
}
