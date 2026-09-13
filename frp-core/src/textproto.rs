//! Go `net/textproto` header-block parity.
//!
//! Go's `textproto.Reader.ReadLine` (the engine behind `http.ReadRequest`
//! and `http.ReadResponse` header parsing) reads to the next `\n` and strips
//! ONE trailing `\r` from the line. Consequences frp-rs must mirror:
//!
//! * A header block may mix line endings — `\r\n` and bare `\n` lines are
//!   both legal, and the head ends at the FIRST empty line under the same
//!   rule. The strict `\r\n\r\n` scan (and the `\n\n` fallback) missed
//!   legal mixed-EOL heads such as LF-terminated header lines followed by a
//!   CRLF blank line (`...\n\r\n` — contains neither window).
//! * Exactly one trailing `\r` is stripped, so a line ending `\r\r\n`
//!   keeps its second `\r` and is not blank.
//!
//! Audit round 7 (S1 family): the pre-helper scans at the vhost HTTP/1.1
//! request-head loop, tcpmux CONNECT head, client health response-head,
//! vhost h2c backend response-head, the vhost ResponseHeaderInjector backend
//! head, the frp-core WS upgrade accept, and five frp-client plugin head
//! sites matched only `\r\n\r\n` (or `\n\n`) windows, so a legal mixed-EOL
//! head either never terminated (vhost read to the 4096 cap → 431, tcpmux to
//! the cap → silent close, health read on until EOF → false DOWN, injector
//! skipped injection) or truncated at the wrong byte. All sites now share
//! this helper.

/// End index (exclusive — past the terminating `\n`) of the first blank
/// line in `head` under Go `textproto.ReadLine` semantics.
///
/// A line is `head[line_start..nl]` where `nl` is the next `\n`; one
/// trailing `\r` is stripped; an empty result ends the head. Returns `None`
/// when `head` ends inside a line (no blank line yet). O(n) single pass.
pub fn head_end(head: &[u8]) -> Option<usize> {
    let mut line_start = 0;
    while line_start < head.len() {
        let nl = head[line_start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|i| line_start + i)?; // no \n yet: head ends inside a line
        let mut line = &head[line_start..nl];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            return Some(nl + 1);
        }
        line_start = nl + 1;
    }
    None
}

/// Incremental [`head_end`] for read loops that grow a buffer per chunk
/// and re-check for the terminating blank line each iteration.
///
/// A read loop that calls [`head_end`] on the whole accumulated buffer
/// per chunk re-scans every byte of every earlier chunk per iteration —
/// O(n²) total for a head of n chunks (audit round-17 finding D: the
/// three chunked h1 plugin head loops — frp-client plugin/http.rs,
/// plugin/static_file.rs and plugin/mod.rs `read_request_and_build_
/// forward`). This scanner carries the line-start offset across feeds.
/// A `feed` that finds no blank line ends either mid-line or exactly at
/// a line boundary (buffer ending at a '\n'); the lines before the
/// carried offset were already judged non-blank and their bytes never
/// change, so resuming there is byte-identical to the full rescan of the
/// accumulated buffer — provided the caller stops feeding at the first
/// `Some`, which is the pattern every read loop uses ([`head_end`] always
/// reports the FIRST blank line, and the loops break there).
#[derive(Default)]
pub struct HeadEndScanner {
    /// Byte offset where the current (possibly empty) line starts — the
    /// byte right after the previous line's `\n`.
    line_start: usize,
    /// Watermark for the mid-line case (audit round-18 finding C1): when a
    /// `feed` ends inside a line (no `\n` after `line_start`), everything
    /// from `line_start` to the old end of the buffer was just scanned and
    /// found `\n`-free. `scanned` records that end so the next `feed` —
    /// which sees the same bytes plus appended ones, since the buffer only
    /// grows between feeds — resumes the `\n` hunt past them instead of
    /// re-scanning the whole unterminated line. Without the watermark a
    /// 1-byte drip feed was O(n²): every feed re-scanned the full
    /// accumulated buffer. `scanned` never exceeds `line_start` except
    /// transiently in this mid-line state, so `max(line_start, scanned)`
    /// is the resume point.
    scanned: usize,
}

impl HeadEndScanner {
    pub fn new() -> Self {
        Self {
            line_start: 0,
            scanned: 0,
        }
    }

    /// Check `buf` (the accumulated buffer; must only ever grow between
    /// feeds) for the terminating blank line, resuming where the previous
    /// feed stopped. Same result as [`head_end`] on the accumulated
    /// buffer for the feed-until-`Some` pattern.
    ///
    /// Amortized O(1) per drip byte: the `\n` hunt restarts at
    /// `max(line_start, scanned)` — everything before it was either
    /// already judged part of non-blank lines or, in the mid-line case,
    /// scanned `\n`-free by the previous feed. When the hunt finds the
    /// next `\n` at `nl >= scanned` the line under test still starts at
    /// `line_start` (the mid-line state never has a `\n` between
    /// `line_start` and `scanned`, so the whole line is
    /// `buf[line_start..nl]` — non-blank in that state since
    /// `line_start < scanned <= nl`), so blankness and the single
    /// trailing-`\r` strip are judged exactly as [`head_end`] judges
    /// them.
    pub fn feed(&mut self, buf: &[u8]) -> Option<usize> {
        while self.line_start < buf.len() {
            let from = self.line_start.max(self.scanned);
            let nl = buf[from..]
                .iter()
                .position(|b| *b == b'\n')
                .map(|i| from + i);
            let Some(nl) = nl else {
                // Still mid-line: no '\n' from line_start to the end of
                // the buffer. Remember where the scan stopped so the next
                // feed (extended buffer) resumes past these bytes instead
                // of re-scanning them; line_start stays put because the
                // current line is still unterminated.
                self.scanned = buf.len();
                return None;
            };
            let mut line = &buf[self.line_start..nl];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            self.line_start = nl + 1;
            if line.is_empty() {
                return Some(nl + 1);
            }
        }
        None
    }
}

/// Re-encode a parsed request/response head with CRLF line endings — Go
/// `net/http` `Request.Write` / `Response.Write` parity
/// (net/http/request.go: Go re-serializes the parsed head, and every line
/// goes out `\r\n`-terminated regardless of how it arrived).
///
/// `head` must be exactly the head region (up to and including its
/// terminating blank line, i.e. the `head_end` slice); bytes past it are
/// entity body and the caller forwards them verbatim. A head that already
/// uses CRLF throughout maps byte-identically. An unterminated partial
/// head (no blank line) re-emits each line `\r\n`-terminated.
pub fn canonicalize_eol_crlf(head: &[u8]) -> Vec<u8> {
    // split_inclusive keeps each line's terminator attached so no line-start
    // bookkeeping is needed. A terminated line strips its \n then ONE
    // trailing \r — the CRLF terminator — the same rule textproto.ReadLine
    // applies (a \r\r\n line keeps one \r, so it is not blank and its
    // payload \r survives the re-encode). A trailing fragment with no \n
    // (an unterminated partial head) keeps its bytes verbatim — a \r there
    // is payload, not a terminator — and is CRLF-terminated like every
    // other line.
    let mut out = Vec::with_capacity(head.len());
    for line in head.split_inclusive(|&b| b == b'\n') {
        if line.last() == Some(&b'\n') {
            let mut content = &line[..line.len() - 1];
            if content.last() == Some(&b'\r') {
                content = &content[..content.len() - 1];
            }
            out.extend_from_slice(content);
        } else {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Canonicalize the head region of a caller-owned pre-read buffer (bytes up
/// to and including the first blank line under `head_end` semantics) to CRLF
/// line endings, forwarding everything past the head verbatim — entity body
/// and pipelined requests are never re-encoded (Go writes the parsed head
/// with CRLF and copies the body separately).
///
/// Wire sites: vhost HTTP/1.1 raw forward (CONNECT and the rewrite/inject
/// path) and the tcpmux CONNECT passthrough. The read loop already accepted
/// a bare-LF/mixed-EOL head (textproto legal); Go net/http would re-serialize
/// that same head with CRLF on write, so the backend must not see the
/// client's EOL convention.
///
/// A head that is already CRLF throughout maps byte-identically and the
/// input is returned unchanged — no copy on the common path. A buffer with
/// no blank line yet (truncated head, EOF mid-head) is also returned
/// unchanged: no parsed head exists to re-encode, and the caller already
/// decided to forward the read bytes.
pub fn canonicalize_head_crlf(pre_read: Vec<u8>) -> Vec<u8> {
    let Some(head_end) = head_end(&pre_read) else {
        return pre_read;
    };
    let head = &pre_read[..head_end];
    // A bare-LF line ending is a '\n' whose previous byte is not '\r'.
    // CRLF-only heads skip the re-encode (identity, no allocation).
    let mut prev_cr = false;
    let has_bare_lf = head.iter().any(|&b| {
        let bare = b == b'\n' && !prev_cr;
        prev_cr = b == b'\r';
        bare
    });
    if !has_bare_lf {
        return pre_read;
    }
    let mut out = canonicalize_eol_crlf(head);
    out.extend_from_slice(&pre_read[head_end..]);
    out
}

/// Go net/http `ParseHTTPVersion` (net/http/request.go) — LENIENT, not an
/// exact-match switch: `HTTP/1.0` and `HTTP/1.1` are exact rows, and every
/// other parseable token is exactly 8 chars, `HTTP/`-prefixed, with `.` at
/// [6] and single ASCII digits at [5] and [7]. So `HTTP/0.0`-`HTTP/9.9`
/// parse on both sides of the dot (`HTTP/9.9`, `HTTP/1.2`, `HTTP/0.9`,
/// `HTTP/4.0` all pass) and `http.ReadResponse` accepts every parseable
/// proto. Failing shapes: any length other than 8 (`HTTP/1.10`,
/// `HTTP/10.0`, `HTTP/1`), no `.` at [6] (`HTTP/01.1`), non-digit minor
/// (`HTTP/1.x`), non-`HTTP/` prefix (`http/1.1`, `FOO`) and trailing bytes
/// (`HTTP/1.1 `). (Audit round 7 pinned the reverse — an exact switch
/// rejecting `HTTP/9.9` as "digit lookalikes" — a misreading of the Go
/// source; the pre-round-7 single-digit approximation was correct, and
/// round 18 restores it with the 8-char shape check added. Request faces
/// keep their own major-1 gates on top when they need
/// `http1ServerSupportsRequest` semantics.) Callers (all RESPONSE faces,
/// where ReadResponse's gate is exactly this): the CONNECT proxy status
/// gate, the health response-head parse, and both h2 backend-head parses
/// (server h2c + the client https2http plugin).
pub fn is_valid_http_version(vers: &str) -> bool {
    match vers {
        "HTTP/1.0" | "HTTP/1.1" => return true,
        _ => {}
    }
    let b = vers.as_bytes();
    b.len() == 8
        && b.starts_with(b"HTTP/")
        && b[5].is_ascii_digit()
        && b[6] == b'.'
        && b[7].is_ascii_digit()
}

/// RFC 7230 `tchar` — the byte class Go's `validHeaderFieldByte`
/// (net/textproto) tests: ALPHA / DIGIT / `!#$%&'*+-.^_`|~`.
fn is_token_byte(b: u8) -> bool {
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

/// RFC 7230 `token = 1*tchar`: non-empty and every byte a `tchar`.
///
/// This is the injection guard for any header key/value frp-rs SYNTHESIZES
/// from untrusted input — a CR, LF, space, colon or obs-text byte fails the
/// test, so a line built only from `is_token`-passing pieces can never carry
/// a smuggled CRLF.
pub fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_byte)
}

/// Go `net/textproto.CanonicalMIMEHeaderKey` — the canonical spelling
/// `textproto.MIMEHeader`/`http.Header` store names under, applied
/// empirically per the Go rule (`canonicalMIMEHeaderKey`): walk the bytes
/// with an `upper` flag that starts true and is set to "the previous byte
/// was a dash" after every byte, uppercasing an ASCII letter while `upper`
/// is set and lowercasing one while it is not.
///
/// Consequences the rule pins (all verified against the Go function):
/// only `-` re-arms the uppercase state, so a non-dash separator does NOT
/// reset it (`x_underscore` → `X_underscore`, not `X_Underscore`); a token
/// that STARTS with a non-letter keeps its leading bytes and never
/// uppercases them (`9digit` → `9digit`); a `-` after a letter lowercases
/// the glyph that follows (`X-Low` → `X-Low`, `X-lOW` → `X-Low`).
///
/// Go's quick check returns the input UNCHANGED when any byte is outside
/// the RFC 7230 token class (`validHeaderFieldByte` == `tchar`); that branch
/// is mirrored here, so a hostile name is echoed rather than rewritten.
pub fn go_canonical_header_key(name: &str) -> String {
    if name.bytes().any(|b| !is_token_byte(b)) {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for &b in name.as_bytes() {
        // Every byte of a token is ASCII, so the cast is lossless and the
        // push can never panic.
        let b = if upper {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        };
        out.push(b as char);
        upper = b == b'-';
    }
    out
}

/// The `Trailer:` announcement Go's `http.Transport` re-emits on the
/// chunked egress leg — `transferWriter.writeHeader`'s "Write Trailer
/// header" block (net/http/transfer.go:310-332): the outbound trailer keys
/// are canonicalized, sorted, joined with `,` (NO space) and written as one
/// `Trailer: <keys>` line right after `Transfer-Encoding: chunked`.
///
/// `values` are the raw inbound `trailer` declaration rows (Go's h2 server
/// turns the `trailer` header into `req.Trailer` keys; the comma list is
/// this project's stand-in for that map). Each row is split on `,`, each
/// element trimmed of ASCII SP/HTAB, and an element is skipped when it is:
///
/// * empty — Go fails the whole request there (`net/http: invalid trailer
///   field name ""`, the parsed key failing `ValidHeaderFieldName`);
/// * not an RFC 7230 token — Go fails the request too (transfer.go:315-318
///   `badStringError("invalid Trailer key", k)` for a name it cannot
///   canonicalize, and its own name validation otherwise).
///
/// Both skips are deliberate FAIL-CLOSED stand-ins for Go's request error:
/// the announcement is built only from vetted token bytes, so no CR/LF or
/// other hostile octet can reach the emitted line, and the request is
/// served rather than refused. `Transfer-Encoding`, `Trailer` and
/// `Content-Length` are dropped (Go errors on them as trailer keys — a
/// trailer may not describe the framing). Returns `None` when nothing
/// survives, which is the "no Trailer line at all" case (Go writes the
/// line only when `len(keys) > 0`).
pub fn go_trailer_announcement<'a>(values: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut keys: Vec<String> = Vec::new();
    for value in values {
        for piece in value.split(',') {
            let key = piece.trim_matches([' ', '\t']);
            if key.is_empty() {
                continue;
            }
            if !is_token(key) {
                continue;
            }
            let canonical = go_canonical_header_key(key);
            if matches!(
                canonical.as_str(),
                "Transfer-Encoding" | "Trailer" | "Content-Length"
            ) {
                continue;
            }
            if !keys.contains(&canonical) {
                keys.push(canonical);
            }
        }
    }
    if keys.is_empty() {
        return None;
    }
    keys.sort_unstable();
    Some(keys.join(","))
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_eol_crlf, go_canonical_header_key, go_trailer_announcement, head_end,
        is_token, is_valid_http_version,
    };

    /// Build a head from header lines (each gets one `\n`) plus a blank
    /// line (the `\r\n`/`\n` terminator) and optional body bytes past it;
    /// the expected end is derived from the construction, so no
    /// hand-counted byte offsets can go stale.
    fn head_case(lines: &[&str], blank: &str, tail: &str) -> (Vec<u8>, usize) {
        let mut head = Vec::new();
        for l in lines {
            head.extend_from_slice(l.as_bytes());
            head.push(b'\n');
        }
        let end = head.len() + blank.len();
        head.extend_from_slice(blank.as_bytes());
        head.extend_from_slice(tail.as_bytes());
        (head, end)
    }

    #[test]
    fn terminates_on_first_blank_line_any_eol_mix() {
        let cases: Vec<(&[&str], &str, &str, &str)> = vec![
            // Canonical CRLFCRLF.
            (
                &["HTTP/1.1 200 OK\r", "Content-Length: 5\r"],
                "\r\n",
                "",
                "CRLF head + CRLF blank",
            ),
            // LF-only head.
            (
                &["GET / HTTP/1.1", "Host: a"],
                "\n",
                "",
                "LF head + LF blank",
            ),
            // The missed shape: LF-terminated header lines + CRLF blank
            // line — contains neither \r\n\r\n nor \n\n.
            (
                &["GET / HTTP/1.1", "Host: a"],
                "\r\n",
                "",
                "LF head + CRLF blank",
            ),
            // CRLF-terminated header lines + LF-only blank line.
            (
                &["GET / HTTP/1.1\r", "Host: a\r"],
                "\n",
                "",
                "CRLF head + LF blank",
            ),
            // Both conventions in one head.
            (
                &["A: b", "C: d\r", "E: f"],
                "\r\n",
                "",
                "mixed head + CRLF blank",
            ),
            // \r\r\n keeps one \r → not blank; the \r\n after it is.
            (&["X: y\r\r"], "\r\n", "", "bare \\r before line end"),
            // Empty first line ends the head immediately.
            (&[], "\r\n", "", "blank first line CRLF"),
            (&[], "\n", "", "blank first line LF"),
            // Bytes past the terminator are not part of the head.
            (&["H: v\r"], "\r\n", "body\r\n", "body after terminator"),
        ];
        for (lines, blank, tail, label) in cases {
            let (head, want) = head_case(lines, blank, tail);
            assert_eq!(
                head_end(&head),
                Some(want),
                "{label}: {:?}",
                String::from_utf8_lossy(&head)
            );
        }
    }

    #[test]
    fn no_terminator_within_slice() {
        for head in [
            b"GET / HTTP/1.1\r\nHost: a".as_slice(), // no \n at all after
            b"GET / HTTP/1.1\nHost: a\n",            // ends after a non-blank line
            b"",                                     // empty
            b"\r",                                   // bare \r, no newline
        ] {
            assert_eq!(
                head_end(head),
                None,
                "head: {:?}",
                String::from_utf8_lossy(head)
            );
        }
    }

    /// Round-17 finding D: `HeadEndScanner::feed` under the
    /// feed-until-`Some` pattern the chunked h1 plugin head loops use must
    /// agree with `head_end` on the full accumulated buffer — for every
    /// chunk split of every head shape, since the incremental scanner
    /// never re-scans already-judged lines and a divergence there would
    /// mis-terminate a real head.
    #[test]
    fn head_end_scanner_matches_full_rescan_under_any_chunking() {
        use super::HeadEndScanner;
        let heads: Vec<Vec<u8>> = vec![
            // Terminated heads, mixed EOL conventions (head_case builds the
            // expected end itself; only the buffer is needed here).
            head_case(&["GET / HTTP/1.1\r", "Host: a\r"], "\r\n", "body").0,
            head_case(&["A: b", "C: d\r", "E: f"], "\r\n", "").0,
            head_case(&["X: y\r\r"], "\r\n", "tail").0,
            head_case(&[], "\n", "BODY").0,
            head_case(&["H: v\r"], "\r\n", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").0,
            // Blank first line.
            b"\r\n".to_vec(),
            // Unterminated shapes: scanner must stay None on every prefix.
            b"GET / HTTP/1.1\nHost: a\n".to_vec(),
            b"\r".to_vec(),
            b"".to_vec(),
        ];
        for head in heads {
            let full = head_end(&head);
            for split in 1..=head.len().max(1) {
                let mut scan = HeadEndScanner::new();
                let mut got = None;
                let mut fed = 0;
                while fed < head.len() {
                    let end = (fed + split).min(head.len());
                    if let Some(nl) = scan.feed(&head[..end]) {
                        got = Some(nl);
                        break;
                    }
                    fed = end;
                }
                assert_eq!(
                    got,
                    full,
                    "chunk {split} of {:?}",
                    String::from_utf8_lossy(&head)
                );
            }
        }
    }

    /// Round-18 finding C1: `feed` was O(n²) under a 1-byte drip — the
    /// mid-line early return left `line_start` unmoved, so each feed
    /// re-scanned the whole accumulated buffer hunting a '\n' that the
    /// previous feed had already proven absent. This test drips one
    /// enormous single-line head (the worst case: no blank line until the
    /// very end, so every pre-fix feed scanned from byte 0) one byte at a
    /// time. Pre-fix that was ~n²/2 byte comparisons (~2e9 at 64 KiB,
    /// multiple seconds; ~3e10 at 256 KiB, tens of seconds); the
    /// watermark makes each drip O(1), so the test now runs in
    /// milliseconds and a regression to the full-rescan shape stalls it
    /// well past any sane test timeout.
    #[test]
    fn head_end_scanner_drip_feed_is_incremental() {
        use super::HeadEndScanner;
        let mut head = Vec::with_capacity(256 * 1024);
        head.extend_from_slice(b"GET / HTTP/1.1\r\n");
        head.resize(head.len() + 256 * 1024, b'a');
        head.extend_from_slice(b"\r\n\r\n");
        let expected_end = head.len(); // past the terminating blank line

        let mut scan = HeadEndScanner::new();
        let mut got = None;
        let mut fed = 0;
        while fed < head.len() {
            fed += 1; // 1-byte drip
            if let Some(nl) = scan.feed(&head[..fed]) {
                got = Some(nl);
                break;
            }
        }
        assert_eq!(got, Some(expected_end), "drip must terminate the head");
        // The drip consumed the whole buffer byte-by-byte; a partial feed
        // (the read loop may also hand a fresh scanner a pre-read seed)
        // must agree with head_end on the same bytes.
        assert_eq!(head_end(&head), Some(expected_end));
    }

    /// `canonicalize_eol_crlf` input is the head region only (what
    /// `head_end` delimited); every case pairs the EOL mix with its expected
    /// canonical CRLF re-encode.
    #[test]
    fn canonicalize_eol_crlf_all_line_endings() {
        let cases: Vec<(&[u8], &[u8], &str)> = vec![
            // CRLF throughout → byte-identical (canonicalization identity).
            (
                b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                "CRLF head",
            ),
            // LF-only head + LF blank.
            (
                b"GET / HTTP/1.1\nHost: a\n\n",
                b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                "LF head",
            ),
            // Mixed head + CRLF blank (the audit round-7 missed shape).
            (
                b"GET / HTTP/1.1\nHost: a\r\nX: y\n\r\n",
                b"GET / HTTP/1.1\r\nHost: a\r\nX: y\r\n\r\n",
                "mixed + CRLF blank",
            ),
            // CRLF lines + LF-only blank.
            (
                b"A: b\r\nC: d\r\n\n",
                b"A: b\r\nC: d\r\n\r\n",
                "CRLF lines + LF blank",
            ),
            // \r\r\n keeps one \r in the payload — the line is not blank and
            // its literal \r must survive the re-encode.
            (
                b"X: y\r\r\n\r\n",
                b"X: y\r\r\n\r\n",
                "bare \\r before line end",
            ),
            // Blank first line.
            (b"\r\n", b"\r\n", "CRLF blank only"),
            (b"\n", b"\r\n", "LF blank only"),
        ];
        for (input, want, label) in cases {
            assert_eq!(
                canonicalize_eol_crlf(input),
                want,
                "{label}: {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn canonicalize_head_crlf_region_tail_verbatim() {
        use super::canonicalize_head_crlf;
        // CRLF head + tail: unchanged (canonicalization identity, no copy).
        let input = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nbody\r\n\r\n".to_vec();
        assert_eq!(canonicalize_head_crlf(input.clone()), input);
        // Bare-LF head: head region re-encoded, tail byte-verbatim even when
        // the tail itself contains blank lines and a second bare-LF head.
        let input = b"GET / HTTP/1.1\nHost: a\n\n\nGET / HTTP/1.1\nHost: b\n\n".to_vec();
        assert_eq!(
            canonicalize_head_crlf(input.clone()),
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n\nGET / HTTP/1.1\nHost: b\n\n".to_vec()
        );
        // The audit round-7 missed shape (LF header lines + CRLF blank):
        // head re-encoded, pipelined tail preserved.
        let input = b"GET / HTTP/1.1\nHost: a\r\n\r\nGET / HTTP/1.1\r\n".to_vec();
        assert_eq!(
            canonicalize_head_crlf(input.clone()),
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\n".to_vec()
        );
        // Truncated head (no blank line): returned unchanged, no re-encode.
        let input = b"GET / HTTP/1.1\nHost: a\n".to_vec();
        assert_eq!(canonicalize_head_crlf(input.clone()), input);
        // \r\r\n line keeps its payload \r; CRLF head stays identity.
        let input = b"X: y\r\r\n\r\n".to_vec();
        assert_eq!(canonicalize_head_crlf(input.clone()), input);
    }

    #[test]
    fn is_valid_http_version_go_parse_http_version_lenient() {
        // Go ParseHTTPVersion: exact rows 1.0/1.1, else exactly-8-char
        // `HTTP/X.Y` with single ASCII digits and '.' at [6]. The exact
        // rows parse, and every 8-char single-digit shape parses too —
        // HTTP/9.9 and HTTP/0.0 are legal (ReadResponse accepts any
        // parseable proto). The round-7 exact-switch pin was a misreading
        // of the Go source; corrected in round 18.
        for ok in [
            "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "HTTP/9.9", "HTTP/0.0", "HTTP/1.2",
            "HTTP/0.9",
        ] {
            assert!(is_valid_http_version(ok), "{ok} must pass");
        }
        // Shape violations: wrong length, no '.' at [6], non-digit minor,
        // wrong prefix, trailing bytes.
        for bad in [
            "HTTP/1.10",
            "HTTP/10.0",
            "HTTP/9.10",
            "HTTP/1",
            "HTTP/1.",
            "HTTP/1.x",
            "FOO",
            "HTTP",
            "http/1.1",
            "HTTP/1.1 ",
            "HTTP/01.1",
            "XXXXX9.9",
        ] {
            assert!(!is_valid_http_version(bad), "{bad} must fail");
        }
    }

    #[test]
    fn canonicalize_eol_crlf_unterminated_partial_head() {
        // No blank line: every line is re-emitted CRLF-terminated (the
        // callers' head_end fallback is the whole buffer).
        assert_eq!(
            canonicalize_eol_crlf(b"GET / HTTP/1.1\r\nHost: a"),
            b"GET / HTTP/1.1\r\nHost: a\r\n"
        );
        assert_eq!(
            canonicalize_eol_crlf(b"GET / HTTP/1.1\nHost: a"),
            b"GET / HTTP/1.1\r\nHost: a\r\n"
        );
        assert_eq!(canonicalize_eol_crlf(b""), b"");
        // A lone \r with no \n is payload, not a line terminator.
        assert_eq!(canonicalize_eol_crlf(b"X: y\r"), b"X: y\r\r\n");
    }

    /// Round 18: the canonical spelling rule is `upper` starts true and
    /// becomes "previous byte was a dash" — so only `-` re-arms it.
    #[test]
    fn go_canonical_header_key_matches_go_rule() {
        for (input, want) in [
            ("content-length", "Content-Length"),
            ("X-Checksum", "X-Checksum"),
            ("x-cHECKSUM", "X-Checksum"),
            // Non-dash separators do NOT reset the uppercase state.
            ("x_underscore", "X_underscore"),
            ("x.y", "X.y"),
            // A leading non-letter consumes the `upper` state.
            ("9digit", "9digit"),
            ("9-digit", "9-Digit"),
            // Trailing dash arms nothing after it.
            ("x-", "X-"),
            ("", ""),
            // Go's quick check: a byte outside the token class echoes the
            // input unchanged (canonicalization is not even attempted).
            ("x y", "x y"),
            ("x:y", "x:y"),
            ("x\ty", "x\ty"),
        ] {
            assert_eq!(go_canonical_header_key(input), want, "input {input:?}");
        }
    }

    /// RFC 7230 `token = 1*tchar` — the injection guard for synthesized
    /// header lines.
    #[test]
    fn is_token_is_exactly_rfc7230_tchar() {
        for ok in ["x", "X-T", "b-key", "9", "!#$%&'*+-.^_`|~", "a1"] {
            assert!(is_token(ok), "{ok:?} must be a token");
        }
        for bad in [
            "", " ", "a b", "a\tb", "a\r\nb", "a:b", "a,b", "a;b", "a\"b", "a(b)", "é", "\u{7f}",
            "a\n", "\r",
        ] {
            assert!(!is_token(bad), "{bad:?} must not be a token");
        }
    }

    /// The `Trailer:` announcement (Go transferWriter.writeHeader): split on
    /// `,`, trim, drop empties and non-tokens, canonicalize, drop the three
    /// framing names, dedup, sort, join WITHOUT a space.
    #[test]
    fn go_trailer_announcement_transfer_writer_parity() {
        // Sorted + canonicalized, no space after the comma.
        assert_eq!(
            go_trailer_announcement(["X-T, b-key"].into_iter()),
            Some("B-Key,X-T".to_string())
        );
        // Whitespace-separated list, duplicates collapse after
        // canonicalization (Go's map keys are already unique).
        assert_eq!(
            go_trailer_announcement(["x-t , X-T ,\tx-t\t"].into_iter()),
            Some("X-T".to_string())
        );
        // Repeated declaration rows accumulate into one line.
        assert_eq!(
            go_trailer_announcement(["X-T", "Zed"].into_iter()),
            Some("X-T,Zed".to_string())
        );
        // The framing names never get announced (Go errors on them).
        assert_eq!(
            go_trailer_announcement(["Content-Length, Trailer, Transfer-Encoding"].into_iter()),
            None
        );
        assert_eq!(
            go_trailer_announcement(["content-length"].into_iter()),
            None,
            "the skip is on the CANONICAL spelling"
        );
        // Nothing to announce: no rows, empty rows, empty elements only.
        assert_eq!(go_trailer_announcement(std::iter::empty::<&str>()), None);
        assert_eq!(go_trailer_announcement([""].into_iter()), None);
        assert_eq!(go_trailer_announcement([" , , "].into_iter()), None);
        // Hostile / malformed keys are dropped, never echoed (the fail-closed
        // stand-in for Go's request error — the emitted line stays clean).
        assert_eq!(
            go_trailer_announcement(["X-T, a b, a:b, a\r\nX: y, é"].into_iter()),
            Some("X-T".to_string())
        );
    }
}
