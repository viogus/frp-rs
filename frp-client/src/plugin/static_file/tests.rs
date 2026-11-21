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
    let after = format!("GET /doc.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {later}\r\n\r\n");
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
/// byte-exactly too — except that the `#[cfg(unix)]` half skips itself at
/// runtime on a filesystem that cannot store a 0xFF name (APFS/EILSEQ;
/// see the skip block below). The pure `render_listing` and
/// `join_components` unit tests cover those two hops unconditionally,
/// including on such a filesystem.)
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
        via_href.starts_with(b"HTTP/1.1 200 OK\r\n") && via_href.ends_with(b"na\xc3\xafve-content"),
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
        // Runtime-capability skip: not every filesystem can represent a
        // non-UTF-8 name at all. APFS rejects byte 0xFF with EILSEQ —
        // measured on macOS arm64 as `Os { code: 92, kind: Uncategorized,
        // message: "Illegal byte sequence" }`.
        //
        // The match is on `raw_os_error` because NO stable `ErrorKind`
        // matches: the measured kind is `Uncategorized`, and
        // `ErrorKind::Uncategorized` is `#[unstable]`/`#[doc(hidden)]`, so
        // it cannot be named on stable — there is no viable kind match to
        // reject here, `raw_os_error` was the only option.
        //
        // EILSEQ is not one value: 92 on macOS, 86 on FreeBSD, 85 on
        // NetBSD, 84 on Linux and OpenBSD (88 on MIPS, 122 on SPARC, per
        // libc's constants). The two arms matched below cover the
        // platforms this repo runs on. They collide with unrelated errnos
        // — 84 is EOVERFLOW on macOS and 92 is ENOPROTOOPT on Linux — but
        // neither is reachable from `std::fs::write` on a regular path, so
        // the collision cannot mask a real failure.
        //
        // Failure direction is fail-loud: only EILSEQ returns early; every
        // other error still panics. The property under test is frp-rs's
        // byte-exact escaping and round-trip, not the host filesystem's
        // capability.
        if let Err(e) = std::fs::write(dir.path().join(&raw_name), b"raw-ff-body") {
            if matches!(e.raw_os_error(), Some(92) | Some(84)) {
                eprintln!(
                    "skipping the non-UTF-8 filename half: this filesystem cannot \
                     store such a name ({e})"
                );
                return;
            }
            panic!("writing the non-UTF-8 name failed unexpectedly: {e}");
        }
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
    let miss_auth = format!("GET /staticx/y HTTP/1.1\r\nHost: t\r\nAuthorization: {good}\r\n\r\n");
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
            let req = format!("{method} /static/plain.txt HTTP/1.1\r\nHost: t{auth_line}\r\n\r\n");
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
    let redir_req = format!("GET /static/sub HTTP/1.1\r\nHost: t\r\nAuthorization: {good}\r\n\r\n");
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

/// Round-16 FIX 2, pure half: the name→bytes hop must keep a name that is
/// NOT valid UTF-8 byte-exact, so the dirList href is `%FF`, and the
/// byte-wise sort key must be the RAW bytes. Synthetic entries only — no
/// filesystem, so this runs on APFS, where the `#[cfg(unix)]` half of
/// `test_static_file_e2e_non_ascii_round_trip` skips because a 0xFF name
/// cannot be created at all (EILSEQ).
///
/// Two mutations this pins, each checked by mutation:
/// * the pre-round-16 lossy hop (`into_vec()` →
///   `to_string_lossy().as_bytes().to_vec()`) renders `raw%EF%BF%BD.txt`
///   instead of `raw%FF.txt`. Before this test nothing in the suite
///   observed that on macOS.
/// * a lossy SORT key (`from_utf8_lossy` in the comparator) is invisible
///   to the first three entries, whose raw and lossy orders agree — hence
///   `a\xff` and `a\xf0\x90\x80\x80` (U+10000): raw sorts `F0 90 80 80`
///   before `FF`, while a lossy key collapses `a\xff` to `61 EF BF BD` and
///   moves it *ahead*. The two keys stay distinct, so the flip does **not**
///   depend on sort stability. Go compares Go strings, i.e. raw bytes
///   (`net/http/fs.go` `dirList` sorts `Name()` with `sort.Slice`), so the
///   raw key is the faithful one — and for a genuinely tied key Go's
///   *unstable* `sort.Slice` (sort/slice.go:15-17) has no fixed expectation
///   to match, which is why the pair here is chosen to be tie-free.
///   The input array is deliberately NOT in rendered order, so the order
///   in the expected body also proves a sort happened at all.
#[cfg(unix)]
#[test]
fn test_render_listing_non_utf8_name_escapes_byte_exact() {
    use std::os::unix::ffi::OsStringExt;
    let name = |b: &[u8]| std::ffi::OsString::from_vec(b.to_vec());
    let entries = [
        (name(b"sub\xff"), true),
        (name(b"plain.txt"), false),
        (name(b"a\xff"), false),
        (name(b"raw\xff.txt"), false),
        (name(b"a\xf0\x90\x80\x80"), false),
    ];
    assert_eq!(
        render_listing(&entries),
        "<!doctype html>\n\
         <meta name=\"viewport\" content=\"width=device-width\">\n\
         <pre>\n\
         <a href=\"a%F0%90%80%80\">a\u{10000}</a>\n\
         <a href=\"a%FF\">a\u{fffd}</a>\n\
         <a href=\"plain.txt\">plain.txt</a>\n\
         <a href=\"raw%FF.txt\">raw\u{fffd}.txt</a>\n\
         <a href=\"sub%FF/\">sub\u{fffd}/</a>\n\
         </pre>\n"
    );
}

/// `join_components` (unix) must carry a non-UTF-8 component byte-exactly
/// to the open; a lossy hop (`String::from_utf8_lossy`) would replace the
/// 0xFF with EF BF BD and 404. This is the only test of the unix arm —
/// the e2e arm that exercises it cannot create such a name on APFS.
#[cfg(unix)]
#[test]
fn test_join_components_non_utf8_component_byte_exact() {
    use std::os::unix::ffi::OsStrExt;
    // The byte-exact assertion already rules out the exact mojibake a lossy
    // hop would produce (`/base/raw` + bytes `EF BF BD` + `.txt`). A
    // separate `assert_ne!` against that string would be dead code — this
    // assertion fails first, so the negative one could never be the
    // detector.
    let one = join_components("/base", &[b"raw\xff.txt".to_vec()]);
    assert_eq!(one.as_os_str().as_bytes(), b"/base/raw\xff.txt");
    let two = join_components("/base", &[b"sub".to_vec(), b"raw\xff.txt".to_vec()]);
    assert_eq!(two.as_os_str().as_bytes(), b"/base/sub/raw\xff.txt");
}
