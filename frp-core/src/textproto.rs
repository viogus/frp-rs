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

#[cfg(test)]
mod tests {
    use super::head_end;

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
            (&["HTTP/1.1 200 OK\r", "Content-Length: 5\r"], "\r\n", "", "CRLF head + CRLF blank"),
            // LF-only head.
            (&["GET / HTTP/1.1", "Host: a"], "\n", "", "LF head + LF blank"),
            // The missed shape: LF-terminated header lines + CRLF blank
            // line — contains neither \r\n\r\n nor \n\n.
            (&["GET / HTTP/1.1", "Host: a"], "\r\n", "", "LF head + CRLF blank"),
            // CRLF-terminated header lines + LF-only blank line.
            (&["GET / HTTP/1.1\r", "Host: a\r"], "\n", "", "CRLF head + LF blank"),
            // Both conventions in one head.
            (&["A: b", "C: d\r", "E: f"], "\r\n", "", "mixed head + CRLF blank"),
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
            assert_eq!(head_end(&head), Some(want), "{label}: {:?}", String::from_utf8_lossy(&head));
        }
    }

    #[test]
    fn no_terminator_within_slice() {
        for head in [
            b"GET / HTTP/1.1\r\nHost: a".as_slice(), // no \n at all after
            b"GET / HTTP/1.1\nHost: a\n",             // ends after a non-blank line
            b"",                                      // empty
            b"\r",                                    // bare \r, no newline
        ] {
            assert_eq!(head_end(head), None, "head: {:?}", String::from_utf8_lossy(head));
        }
    }
}
