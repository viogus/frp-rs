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
//! request-head loop, tcpmux CONNECT head, and client health response-head
//! matched only `\r\n\r\n` (or `\n\n`) windows, so a legal mixed-EOL head
//! either never terminated (vhost read to the 4096 cap → 431, tcpmux to the
//! cap → silent close, health read on until EOF → false DOWN) or truncated
//! at the wrong byte. All four sites now share this helper.

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

#[cfg(test)]
mod tests {
    use super::{canonicalize_eol_crlf, head_end};

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
}
