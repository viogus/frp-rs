//! Self-contained HTTP response-header injector.

use super::*;

/// Wraps an AsyncRead, buffering HTTP response headers on first read
/// and injecting configured headers before passing through.
///
/// Go parity model (go1.25 httputil.ReverseProxy + v0.71.0 vhost
/// ModifyResponse): the injector must fire on the FIRST final response
/// head (status >= 200) and on a 101 Switching Protocols (Go runs
/// modifyResponse on 101 before handleUpgradeResponse), but NEVER on an
/// interim 1xx head other than 101 — Go's Transport consumes those heads
/// internally and modifyResponse never sees them — nor on a MALFORMED
/// first line (unparseable version token or code: Go errors the whole
/// response and the reverse proxy answers 502, see head_status_code).
/// Interim heads are still
/// real bytes on this raw pipe (an `Expect: 100-continue` backend waits
/// for its 100 head to reach the client before sending the body), so they
/// are served through UNINJECTED and promptly, not withheld until a final
/// head shows up (withholding would deadlock the Expect handshake).
/// Malformed heads pass through uninjected too — never manufacture
/// configured headers into a head Go would reject outright.
pub(super) struct ResponseHeaderInjector<R> {
    inner: R,
    headers: std::collections::HashMap<String, String>,
    /// Emission content: the injected final/101 head (spliced headers,
    /// trailing body bytes attached), a raw interim 1xx head, or the
    /// truncated post-EOF tail. Never emitted before its boundary is in
    /// the buffer (M3: a head spanning several internal reads must not
    /// leak fragment-first).
    buffer: Vec<u8>,
    buffer_offset: usize,
    /// The emission content carries the injected configured headers (final
    /// head or 101). Once drained, the rest of the response passes through
    /// raw (`complete`).
    injected: bool,
    /// The emission content is exactly one complete interim 1xx head
    /// (status 100..=199, NOT 101) served raw — Go's Transport consumes
    /// these and modifyResponse never runs, and Expect:100-continue
    /// deadlocks if they are withheld. Once drained, head accumulation
    /// resumes from `tail`.
    raw_head: bool,
    /// Bytes read past an interim head's blank line (the next head's
    /// start, possibly already complete) while the interim head is being
    /// emitted. Taken back into `buffer` when the emission drains. For an
    /// injected 204/304 whose backend declared a body (round-18 C3b) it
    /// instead holds the split-off body bytes — the discard input — until
    /// the emission drains.
    tail: Option<Vec<u8>>,
    /// The last head served raw was MALFORMED (unparseable first line)
    /// rather than a legal interim 1xx. Round-13 serves malformed heads raw
    /// — Go would 404 before relaying anything — so once one is out it IS
    /// the response: no configured headers are ever spliced into it, and
    /// nothing after it is relayed. Round-15: draining it is TERMINAL
    /// (pipelined bytes after an unparseable head must not re-enter the
    /// gather loop as a second injectable response) — `complete` plus this
    /// flag serves permanent EOF. Cleared whenever a legal interim is
    /// served.
    pub(super) malformed_raw: bool,
    /// True once every buffered byte is served and no further buffering is
    /// possible — the rest of the response passes through raw. With
    /// `malformed_raw` set it instead means the malformed raw head was the
    /// response and the stream ends at EOF (the `complete` arm never
    /// polls the inner reader in that state).
    complete: bool,
    /// Carried head-boundary scan (round-18 C2c): `head_end` is re-run
    /// against the WHOLE accumulated buffer at the top of the gather loop
    /// after every internal read — a head arriving in a 1-byte drip
    /// rescanned the accumulated bytes per drip, O(n²). The scanner
    /// resumes the blank-line hunt where the previous feed stopped
    /// (amortized O(1) per drip byte; the `buffer` only grows between
    /// feeds). MUST be reset wherever `buffer` is REPLACED rather than
    /// grown — the scanner's `line_start`/`scanned` watermarks belong to
    /// the old content. Replacement sites: `raw_head_fully_served` (tail
    /// handback), the C3b discard handoff in `emission_drained`, the
    /// inject branch (`buffer = injected`), and the discard
    /// done-branch (`buffer = mem::take(&mut skip.pending)` — served
    /// via `raw_pass` or `complete`, never rescanned, so the scanner
    /// stays dormant there; listed for any edit that adds a scan
    /// after a discard).
    head_scanner: frp_core::textproto::HeadEndScanner,
    /// Persistent read buffer to avoid per-poll_read allocation.
    read_buf: [u8; 4096],
    /// Absolute deadline for the FIRST injectable head (Go
    /// ResponseHeaderTimeout analog, A2). Armed once at construction; an
    /// interim 1xx raw serve does NOT extend it. When it fires while a head
    /// is still being gathered, poll_read errors with TimedOut. (It does
    /// NOT bound the round-18 C3b discard — that phase never reads the
    /// inner reader, so no park exists to bound.) Boxed-pinned Sleep
    /// registered once (no per-poll wheel churn); `Pin<Box<T>>` is Unpin
    /// regardless of `T`, so the manual Unpin impl above stays valid.
    deadline_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// A declared entity body behind an injected 204/304 head, being
    /// consumed so the shared stream lands at the next-response boundary
    /// (round-18 C3b; full model in the inject branch). While armed, the
    /// emission drain hands the split-off body bytes back to `buffer` and
    /// the discard section consumes them — in-hand bytes only; the inner
    /// reader is never touched (a legal 304 + Content-Length cannot be
    /// told apart from a lying backend's split junk once the in-hand
    /// bytes are spent, and consuming wire bytes would eat a pipelined
    /// next response or park a keep-alive bridge to the A2 deadline).
    /// Only in-hand bytes are ever consumed as the declared body. What
    /// the single in-hand pass does not reach — a lying backend's later
    /// junk, or the stream's real continuation — passes through raw below
    /// (deliberate fail-open window: a clean wire-eat is
    /// byte-indistinguishable from eating a legal pipelined response).
    /// Once the declared framing is fully consumed from in-hand bytes the
    /// stream resumes raw: `complete` when the boundary was exact,
    /// `raw_pass` when bytes past it are already in hand. In-hand bytes
    /// spent before the framing completed → `complete` immediately,
    /// silently. Chunked framing errors end the stream permanently
    /// (`abort_after_discard_failure`).
    discard: Option<Discard>,
    /// Pass-through content already in hand when a discard completed —
    /// the bytes a lying backend wrote past its declared framing, or a
    /// pipelined next response. Served like an emission (the gate below);
    /// once drained, `complete` is raised. Unlike the interim-head `tail`,
    /// this content follows a response that was ALREADY served and must
    /// never re-enter head classification.
    raw_pass: bool,
}

// SAFETY: All fields of ResponseHeaderInjector are Unpin when R: Unpin.
// HashMap, Vec, Option<Vec>, Option<Discard> (Vec/u64/enum — Unpin),
// usize, bool, [u8; 4096], and Option<Pin<Box<tokio::time::Sleep>>>
// (Pin<Box<T>> is Unpin for any T) are all Unpin.
impl<R: Unpin> Unpin for ResponseHeaderInjector<R> {}

impl<R: AsyncRead + Unpin> ResponseHeaderInjector<R> {
    /// A raw-served head (interim 1xx, or a MALFORMED first line — neither
    /// is injected) has been fully emitted. An interim 1xx head hands the
    /// accumulation back to its split-off tail, which may already hold the
    /// pipelined final head (100 + 200 in one backend segment) — the
    /// caller's next poll re-resolves it and re-enters classification.
    ///
    /// A MALFORMED head (status None — version/code garbage Go's
    /// ReadResponse errors) is the TERMINAL response: Go errors the whole
    /// response and the reverse proxy closes the backend connection, so
    /// bytes after it are never a legal continuation. Round-15 security
    /// review: the pre-fix drain resumed the gather loop on the tail, and
    /// whatever the backend wrote next became a SECOND response on one
    /// user connection — a pipelined valid-looking final head (a hostile
    /// or buggy backend writing `HTTP/1.1 200 OK` after its unparseable
    /// head) was INJECTED and served as a second spliced response
    /// (double-response, smuggling-adjacent shape, through the injector),
    /// while endless blank-line-terminated garbage went out raw, streamed
    /// as repeated "responses" after a head the client already rejected
    /// (the `complete` arm below). Drop the tail and mark complete: the
    /// `complete` arm with `malformed_raw` set serves permanent EOF, never
    /// pass-through reads.
    fn raw_head_fully_served(&mut self) {
        if self.malformed_raw {
            self.tail = None;
            self.buffer.clear();
            self.buffer_offset = 0;
            self.head_scanner = frp_core::textproto::HeadEndScanner::new();
            self.complete = true;
            return;
        }
        // The tail is fresh content (the next head's start) — the carried
        // boundary scanner's watermarks describe the OLD buffer.
        self.head_scanner = frp_core::textproto::HeadEndScanner::new();
        self.buffer = self.tail.take().unwrap_or_default();
        self.buffer_offset = 0;
    }

    /// The emission buffer was fully served by this poll — transition the
    /// per-kind post-drain state (shared by the flag gate and the
    /// post-boundary serve below):
    /// - `raw_pass` — pass-through content left over from a completed C3b
    ///   discard (bytes a lying backend wrote past its declared 204/304
    ///   body) fully served: the stream is raw forever → `complete`.
    /// - `raw_head` — interim 1xx (or malformed) head fully served:
    ///   hand the accumulation back to the split-off tail, or terminate
    ///   for a malformed head (see `raw_head_fully_served`).
    /// - `injected` + armed `discard` — the injected 204/304 head is out
    ///   and its backend DECLARED a body that HTTP forbids the status from
    ///   carrying (round-18 C3b): the split-off `tail` holds the discard
    ///   input. NOT complete — hand it to `buffer` so the discard section
    ///   consumes exactly the declared framing instead of relaying it.
    ///   Always the NEXT poll (round-18 M1): the drain's own poll filled
    ///   the caller's ReadBuf and must return Ready — falling through to
    ///   the discard's inner poll could end that poll in Pending, and a
    ///   Pending return with a filled buffer silently drops the drain's
    ///   bytes (tokio's `Read` future builds a fresh ReadBuf per poll).
    /// - `injected` alone — the head is out; the rest of the response
    ///   passes through raw.
    fn emission_drained(&mut self) {
        if self.raw_pass {
            self.raw_pass = false;
            self.complete = true;
        } else if self.raw_head {
            self.raw_head = false;
            self.raw_head_fully_served();
        } else if self.injected && self.discard.is_some() {
            self.injected = false;
            self.buffer = self.tail.take().unwrap_or_default();
            self.buffer_offset = 0;
            self.head_scanner = frp_core::textproto::HeadEndScanner::new();
        } else {
            self.complete = true;
        }
    }

    pub(super) fn new(
        inner: R,
        headers: std::collections::HashMap<String, String>,
        header_timeout: Option<std::time::Duration>,
    ) -> Self {
        Self {
            inner,
            headers,
            buffer: Vec::new(),
            buffer_offset: 0,
            injected: false,
            raw_head: false,
            tail: None,
            malformed_raw: false,
            complete: false,
            head_scanner: frp_core::textproto::HeadEndScanner::new(),
            read_buf: [0u8; 4096],
            deadline_sleep: header_timeout.map(|d| Box::pin(tokio::time::sleep(d))),
            discard: None,
            raw_pass: false,
        }
    }

    /// True when the version token parses like Go `http.ParseHTTPVersion`
    /// (go1.25 request.go:819-838): `HTTP/1.1`/`HTTP/1.0` exact, otherwise
    /// `HTTP/` + exactly ONE digit + `.` + exactly ONE digit — the generic
    /// arm length-checks `len(vers) != len("HTTP/X.Y")` and parses single
    /// bytes at [5:6]/[7:8]. "HTTP/1.10" and "HTTP/01.1" fail the length
    /// check, "HTTP/9.9" passes. (ReadResponse validates the status code
    /// BEFORE the version — response.go:173-186 — but either failure errors
    /// the whole response, so the order does not change the outcome.)
    pub(super) fn is_http_version(v: &[u8]) -> bool {
        let Some(rest) = v.strip_prefix(b"HTTP/") else {
            return false;
        };
        rest.len() == 3 && rest[1] == b'.' && rest[0].is_ascii_digit() && rest[2].is_ascii_digit()
    }

    /// Status code of the head's first line, or None when the line is not
    /// a parseable `HTTP/x.y <status-code>` status line. Round-13 review
    /// (3 independent reviewers): the version token must parse (Go
    /// ParseHTTPVersion) and the remainder is trimmed of ASCII SPACES only
    /// (Go TrimLeft(" ", ...) — a TAB before the code keeps the token
    /// `\t100`, 4 chars, malformed, exactly like Go; trimming TAB was
    /// classifying `HTTP/1.1 \t100 Continue` as interim when Go 502s it).
    /// The code token is 3 bytes with Go Atoi semantics (see below) —
    /// there is no 100..=199 membership check here; classification happens
    /// at the call site.
    pub(super) fn head_status_code(head: &[u8]) -> Option<u16> {
        let line_end = head.iter().position(|&b| b == b'\n')?;
        let line = &head[..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // Go ReadResponse parseStatusLine parity: the version token is cut
        // at the FIRST literal space, the remainder is TrimLeft'd of spaces
        // only (extra spaces legal — "HTTP/1.1  100 Continue"), then the
        // code is the next space-delimited token. Go validates the code
        // BEFORE the version (response.go:173-186), but the outcome is
        // order-independent — either failure rejects the whole response.
        let mut sp = line.splitn(2, |&b| b == b' ');
        let version = sp.next()?;
        let rest = sp.next()?;
        if !Self::is_http_version(version) {
            return None;
        }
        let mut rest = rest;
        while let Some(stripped) = rest.strip_prefix(b" ") {
            rest = stripped;
        }
        let code = rest.split(|&b| b == b' ').next()?;
        // Go strconv.Atoi parity (response.go:173-186): the code token is
        // length-gated at 3 BYTES ("0200" is a 4-byte token → malformed),
        // then parsed as a SIGNED decimal — "+20" and "-00" are legal
        // status codes (Atoi gives 20 / 0) and only `err || value < 0`
        // rejects: "-01" fails, "-00" passes with 0. No 100..=199
        // membership check here — the caller classifies interim vs final.
        if code.len() != 3 {
            return None;
        }
        let (has_sign, negative, digits) = match code[0] {
            b'+' => (true, false, &code[1..]),
            b'-' => (true, true, &code[1..]),
            _ => (false, false, code),
        };
        if digits.len() != 3 - usize::from(has_sign) || digits.iter().any(|&b| !b.is_ascii_digit())
        {
            return None;
        }
        let mut value: i64 = 0;
        for &b in digits {
            value = value * 10 + i64::from(b - b'0');
        }
        if negative {
            value = -value;
        }
        if value < 0 {
            return None;
        }
        Some(value as u16)
    }

    /// Copy the status + header lines of a backend response head
    /// (`head_region` EXCLUDES the terminating blank line) into `out`,
    /// dropping any header whose name matches a configured response header
    /// (case-insensitive, Go canonicalization), folded obs-fold
    /// continuation lines included — Go `Header.Set` semantics: the
    /// configured value replaces the backend value; both never reach the
    /// wire. A continuation AFTER a kept line stays with its parent (bytes
    /// preserved verbatim).
    ///
    /// `suppress` additionally drops backend lines (folded continuations
    /// included) whose name is in the table — the round-16 Go write-layer
    /// parity for a final head whose status forbids a body (204/304; the
    /// table is `suppressed_headers_for_status`, citation there). The
    /// caller filters its OWN configured emission of the same names the
    /// same way: Go's `Header.Set` (ModifyResponse) runs BEFORE the write
    /// layer's delHeader sweep, so a configured Content-Length /
    /// Transfer-Encoding / Content-Type is suppressed on a 204/304 exactly
    /// like a backend one.
    fn splice_head_deduplicated(
        head_region: &[u8],
        headers: &std::collections::HashMap<String, String>,
        suppress: &'static [&'static str],
        out: &mut Vec<u8>,
    ) {
        let mut pos = 0;
        while pos < head_region.len() {
            let (line, next) = match head_region[pos..].iter().position(|&b| b == b'\n') {
                Some(p) => (&head_region[pos..pos + p + 1], pos + p + 1),
                None => (&head_region[pos..], head_region.len()),
            };
            let body = line.strip_suffix(b"\n").unwrap_or(line);
            let body = body.strip_suffix(b"\r").unwrap_or(body);
            let is_continuation = matches!(body.first(), Some(b' ' | b'\t'));
            if !is_continuation {
                if let Some(colon) = body.iter().position(|&b| b == b':') {
                    let name = &body[..colon];
                    if headers
                        .keys()
                        .any(|k| k.as_bytes().eq_ignore_ascii_case(name))
                        || suppress
                            .iter()
                            .any(|s| name.eq_ignore_ascii_case(s.as_bytes()))
                    {
                        // Drop this header AND its folded continuation
                        // lines (they belong to it — a leftover fold tail
                        // would obs-fold onto the PRECEDING kept header at
                        // the client).
                        let mut after = next;
                        while after < head_region.len() {
                            let (c_line, c_next) =
                                match head_region[after..].iter().position(|&b| b == b'\n') {
                                    Some(p) => (&head_region[after..after + p + 1], after + p + 1),
                                    None => (&head_region[after..], head_region.len()),
                                };
                            let c_body = c_line.strip_suffix(b"\n").unwrap_or(c_line);
                            let c_body = c_body.strip_suffix(b"\r").unwrap_or(c_body);
                            if matches!(c_body.first(), Some(b' ' | b'\t')) {
                                after = c_next;
                            } else {
                                break;
                            }
                        }
                        pos = after;
                        continue;
                    }
                }
            }
            out.extend_from_slice(line);
            pos = next;
        }
    }

    /// The write-layer suppression table for a head about to be injected —
    /// Go's `chunkWriter.writeHeader` DELETES `suppressedHeaders(code)`
    /// from the header map at serialization (go1.25 server.go:1483-1497,
    /// `for _, k := range suppressedHeaders(code) { delHeader(k) }`), after
    /// ModifyResponse's `Header.Set` ran — so every response through the
    /// Go frp http vhost carries neither the backend's nor the configured
    /// framing headers on a status that forbids a body. The tables
    /// (transfer.go:474-477, 480-486): `bodyAllowedForStatus`
    /// (transfer.go:461-470 — false for 1xx, 204, 304) selects
    /// suppressedHeadersNoBody = {Content-Length, Transfer-Encoding} for
    /// every no-body status; 304 gets suppressedHeaders304 =
    /// {Content-Type, Content-Length, Transfer-Encoding} (RFC 7232 §4.1).
    ///
    /// Only 204 and 304 reach this branch: interim 1xx heads are served
    /// raw elsewhere and never reach the strip, and a 101 IS injected but
    /// suppressed by nothing — Go's ReverseProxy answers an upgraded (101)
    /// response through handleUpgradeResponse (reverseproxy.go:632+), which
    /// hijacks the conn and writes the head via `Response.Write`; the
    /// chunkWriter delHeader sweep never runs on that path.
    fn suppressed_headers_for_status(status: Option<u16>) -> &'static [&'static str] {
        match status {
            Some(304) => &["content-type", "content-length", "transfer-encoding"],
            Some(204) => &["content-length", "transfer-encoding"],
            _ => &[],
        }
    }

    /// Walk the head's header lines (raw; obs-fold continuation lines
    /// intact) collecting the `Transfer-Encoding` and `Content-Length`
    /// values Go's textproto unfold would have produced, OWS-trimmed.
    /// `ok` goes false when a folded continuation belongs to a TE/CL
    /// header — Go's unfold would have mangled such a value into a parse
    /// error (parseTransferEncoding / parseContentLength, transfer.go:
    /// 630-655 / 705-722) — mirror by refusing to classify.
    fn head_te_cl(head_region: &[u8]) -> (Vec<&[u8]>, Vec<&[u8]>, bool) {
        let mut te: Vec<&[u8]> = Vec::new();
        let mut cl: Vec<&[u8]> = Vec::new();
        let mut ok = true;
        let mut last_te_cl = false;
        let mut pos = 0;
        while pos < head_region.len() {
            let (line, next) = match head_region[pos..].iter().position(|&b| b == b'\n') {
                Some(p) => (&head_region[pos..pos + p + 1], pos + p + 1),
                None => (&head_region[pos..], head_region.len()),
            };
            pos = next;
            let mut body = line.strip_suffix(b"\n").unwrap_or(line);
            body = body.strip_suffix(b"\r").unwrap_or(body);
            if matches!(body.first(), Some(b' ' | b'\t')) {
                if last_te_cl {
                    ok = false;
                }
                continue;
            }
            last_te_cl = false;
            let Some(colon) = body.iter().position(|&b| b == b':') else {
                continue;
            };
            let name = &body[..colon];
            let mut value = &body[colon + 1..];
            while matches!(value.first(), Some(b' ' | b'\t')) {
                value = &value[1..];
            }
            while matches!(value.last(), Some(b' ' | b'\t')) {
                value = &value[..value.len() - 1];
            }
            if name.eq_ignore_ascii_case(b"transfer-encoding") {
                te.push(value);
                last_te_cl = true;
            } else if name.eq_ignore_ascii_case(b"content-length") {
                cl.push(value);
                last_te_cl = true;
            }
        }
        (te, cl, ok)
    }

    /// The framing the backend DECLARED for a no-body-class head
    /// (204/304) — consulted only to decide how much junk a lying backend
    /// wrote after the head must be consumed (round-18 C3b; model in the
    /// inject branch). Mirrors the response side of Go's transfer.go
    /// framing resolution on the parts that matter for the discard:
    ///
    /// - `Transfer-Encoding: chunked` wins over Content-Length (RFC 9112
    ///   §6.1; Go fixLength transfer.go:716-722 deletes the CL when
    ///   chunked). Any other TE shape (several values, or a non-chunked
    ///   token) errors the response in Go (parseTransferEncoding
    ///   transfer.go:630-655) — no framing to discard against, relay as
    ///   today (Go discards the conn there, frp-rs's raw relay is the
    ///   established divergence for unvalidated heads).
    /// - else a Content-Length whose values all TrimString-match (Go
    ///   Issue 16490 dedupe) and parse as ParseUint base-10 < 2^63
    ///   (parseContentLength), with N > 0.
    /// - absent CL, CL: 0, or an unparseable value → nothing to consume
    ///   (Go errors the whole response on a garbage CL — this relay does
    ///   not validate heads, audit carve-out: relay as today).
    fn declared_body_framing(head_region: &[u8]) -> DeclaredFraming {
        let (te, cl, ok) = Self::head_te_cl(head_region);
        if !ok {
            return DeclaredFraming::None;
        }
        if !te.is_empty() {
            if te.len() == 1 && te[0].eq_ignore_ascii_case(b"chunked") {
                return DeclaredFraming::Chunked;
            }
            return DeclaredFraming::None;
        }
        let Some(first) = cl.first() else {
            return DeclaredFraming::None;
        };
        if cl.iter().any(|v| *v != *first) {
            return DeclaredFraming::None;
        }
        match Self::parse_content_length_value(first) {
            Some(0) | None => DeclaredFraming::None,
            Some(n) => DeclaredFraming::ContentLength(n),
        }
    }

    /// Go parseContentLength value mirror (transfer.go:705-722): digits
    /// only (no sign, no interior whitespace — the caller OWS-trimmed),
    /// ParseUint base 10 with 63-bit precision (`< 2^63`).
    fn parse_content_length_value(v: &[u8]) -> Option<u64> {
        if v.is_empty() {
            return None;
        }
        let mut n: u64 = 0;
        for &b in v {
            if !b.is_ascii_digit() {
                return None;
            }
            n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        }
        (n < 1 << 63).then_some(n)
    }

    /// Round-18 C3b: in-hand junk behind an injected 204/304 head failed
    /// the declared chunked framing (the only failing arm left — the
    /// discard never reads the inner reader, so truncation and deadline
    /// arms are unreachable by construction). The head is already out, so
    /// frp-core must never answer a gateway head, and the stream position
    /// is unknowable mid-junk — end the pair with PERMANENT clean EOF
    /// (the `complete` + `malformed_raw` state never polls the inner
    /// reader again). Go abandons no-body bodies without reading them
    /// (chunked-on-204/304 and CL:0 → Body = NoBody, transfer.go:570-574;
    /// the pooled conn is then closed at the next reuse with the junk
    /// still in its buffer — persistConn readLoop) and for a declared
    /// CL > 0 it reads exactly N junk bytes (LimitReader) then errors the
    /// next ReadResponse on whatever follows — either way the response
    /// stream ends, as it does here. The WARN is rate-limited — a hostile
    /// backend fleet must not flood the log.
    fn abort_after_discard_failure(this: &mut Self, why: &'static str) {
        this.discard = None;
        this.tail = None;
        this.buffer.clear();
        this.buffer_offset = 0;
        this.complete = true;
        // Reuse the malformed-raw terminal state (see that field): the
        // `complete` arm serves permanent EOF without touching the inner
        // reader.
        this.malformed_raw = true;
        Self::warn_discard_failure(why);
    }

    /// Rate-limited discard-failure WARN: at most one line per 5 s across
    /// all bridges (the 5s cadence mirrors the UDP session-table warn
    /// throttle; a hostile backend fleet must not flood the log).
    fn warn_discard_failure(why: &'static str) {
        const WINDOW_MS: u64 = 5000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let last = DISCARD_WARN_THROTTLE.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= WINDOW_MS
            && DISCARD_WARN_THROTTLE
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                reason = why,
                "response injector: cannot consume the declared body after a served 204/304 head — ending the stream"
            );
        }
    }
}

/// Round-18 C3b throttle for `ResponseHeaderInjector::warn_discard_failure`
/// (5s window — see there).
static DISCARD_WARN_THROTTLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A declared entity body a backend wrote after a 204/304 head that HTTP
/// forbids from carrying one (RFC 9112 §3.3.3; Go readTransfer answers
/// Body = NoBody on these statuses — but ONLY when the framing is chunked,
/// CL: 0, or absent: a `Content-Length: N` with N > 0 still arms a body
/// (transfer.go:565-578 realLength arm), so Go READS exactly N junk bytes
/// before its pooled conn is reusable). The injected head the user saw was
/// stripped of the framing headers (see `suppressed_headers_for_status`)
/// — the junk below is real bytes on the shared stream; the in-hand ones
/// are consumed, never relayed, and what the single in-hand pass does not
/// reach passes through raw as the stream's real continuation (round-18
/// C3b fail-open window — documented at the `discard` field). The
/// consumption is IN-HAND ONLY — see the
/// discard section in `poll_read` for why the inner reader is never
/// touched (a legal 304 whose Content-Length declared the would-be-200
/// length is byte-indistinguishable from a lying backend's split junk).
enum Discard {
    /// `Content-Length: N`, N > 0 — consume N junk bytes. Bytes are
    /// counted, never inspected.
    Length { left: u64 },
    /// `Transfer-Encoding: chunked` — the junk is chunk-framed and must be
    /// parsed to find where the body ends.
    Chunked(ChunkedSkip),
}

/// What a no-body-class head declared as the response framing — the
/// round-18 C3b discard decision (see `declared_body_framing`).
enum DeclaredFraming {
    /// Nothing to consume (absent CL, CL: 0, or an unparseable value) —
    /// trailing bytes relay as today.
    None,
    /// `Content-Length: N` with N > 0.
    ContentLength(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// Incremental chunked-framing skipper mirroring Go's wire acceptance
/// (net/http/internal/chunked.go): chunk-size lines end in CRLF exactly — a
/// bare LF is rejected (RFC 9112 erratum eid7633) and any CR before the
/// final position is an invalid CR (readChunkLine) — trailing OWS is
/// trimmed, the chunk extension is cut at ';' (removeChunkExtension), and
/// the size is parsed as hex (parseHexUint); each chunk-data run is
/// followed by a two-byte "\r\n" footer (checkEnd ReadFull(2), anything
/// else is "malformed chunked encoding"); the 0-chunk line ends the body
/// (beginChunk err = io.EOF) and the optional trailers block runs to the
/// first blank line — textproto semantics, the same block shape as a
/// response head's terminator (Go body.readTrailer transfer.go:843-870:
/// an immediate "\r\n" ends with no fields, otherwise MIME-header fields
/// to the blank line). Line lengths are bounded as in Go: size lines by
/// bufio's 4096 window / maxLineLength, the trailers block by the same
/// 4096 ("suspiciously long trailer" there). Go additionally caps chunk
/// overhead (16 KiB of "excess"); this discard is bounded by the
/// response-head deadline instead (see the discard section).
struct ChunkedSkip {
    state: ChunkedState,
    /// Bytes fed but not yet classified — a partial size line or data-run
    /// head, a split footer, or the trailer block. On completion this is
    /// drained to the caller: whatever remains past the body end is the
    /// stream's real continuation.
    pending: Vec<u8>,
    /// Remaining bytes of the current chunk's data run.
    left: u64,
    /// Trailers-block scan offset within `pending` (L6 NIT, round 18): the
    /// block is never drained line-by-line (a partial last line must wait
    /// for more bytes), so a feed that ends mid-trailer re-scanned every
    /// complete trailer line from 0 on the next call — O(lines × feeds)
    /// under a drip. Persisted so re-entry resumes past the lines already
    /// scanned; reset when the block completes. Bounded by the same 4096
    /// cap as before (the `pos > 4096` check runs per line).
    trailer_scanned: usize,
}

enum ChunkedState {
    /// A chunk-size line is being read.
    Size,
    /// The current chunk's data run is being skipped.
    Data,
    /// The current chunk's data run is fully skipped; its "\r\n" footer is
    /// being read.
    DataEnd,
    /// The 0-chunk line was read; the trailers block runs to the first
    /// blank line.
    Trailers,
}

impl ChunkedSkip {
    fn new() -> Self {
        Self {
            state: ChunkedState::Size,
            pending: Vec::new(),
            left: 0,
            trailer_scanned: 0,
        }
    }

    /// Feed raw stream bytes (the machine copies what it cannot classify
    /// into its own `pending`, so the caller's slice is spent either way).
    /// Returns `Ok(true)` once the chunked body end — the trailer block's
    /// blank line — is consumed: `pending` then holds any bytes past it,
    /// which the caller relays raw. `Ok(false)` while more bytes are
    /// needed. `Err(reason)` mirrors a Go grammar rejection (the caller
    /// fails the discard closed).
    fn feed(&mut self, data: &[u8]) -> Result<bool, &'static str> {
        self.pending.extend_from_slice(data);
        loop {
            match self.state {
                ChunkedState::Size => {
                    let Some(nl) = self.pending.iter().position(|&b| b == b'\n') else {
                        // No terminator in hand: bufio's 4096 window (the
                        // line + CRLF) bounds the wait.
                        if self.pending.len() > 4096 + 2 {
                            return Err("chunked size line exceeds 4096 bytes");
                        }
                        return Ok(false);
                    };
                    // readChunkLine: the line must end "\r\n" — a bare LF
                    // and any earlier CR both reject.
                    if nl < 1 || self.pending[nl - 1] != b'\r' {
                        return Err("chunked line ends with bare LF");
                    }
                    if self.pending[..nl - 1].contains(&b'\r') {
                        return Err("invalid CR in chunked line");
                    }
                    let mut content = &self.pending[..nl - 1];
                    // maxLineLength (4096) gates the line CONTENT (Go
                    // checks after the CRLF trim).
                    if content.len() >= 4096 {
                        return Err("chunked size line too long");
                    }
                    // trimTrailingWhitespace (OWS), removeChunkExtension
                    // (cut at ';'), parseHexUint.
                    while matches!(content.last(), Some(b' ' | b'\t')) {
                        content = &content[..content.len() - 1];
                    }
                    if let Some(semi) = content.iter().position(|&b| b == b';') {
                        content = &content[..semi];
                    }
                    let size = Self::parse_hex(content)?;
                    self.pending.drain(..=nl);
                    if size == 0 {
                        // beginChunk: the 0-chunk ends the body (io.EOF);
                        // the optional trailers follow.
                        self.state = ChunkedState::Trailers;
                    } else {
                        self.left = size;
                        self.state = ChunkedState::Data;
                    }
                }
                ChunkedState::Data => {
                    if self.pending.is_empty() {
                        return Ok(false);
                    }
                    let take = (self.pending.len() as u64).min(self.left) as usize;
                    self.pending.drain(..take);
                    self.left -= take as u64;
                    if self.left == 0 {
                        self.state = ChunkedState::DataEnd;
                    }
                }
                ChunkedState::DataEnd => {
                    // checkEnd: the footer is exactly "\r\n" (ReadFull(2));
                    // anything else is malformed.
                    if self.pending.len() < 2 {
                        return Ok(false);
                    }
                    if &self.pending[..2] != b"\r\n" {
                        return Err("malformed chunked encoding");
                    }
                    self.pending.drain(..2);
                    self.state = ChunkedState::Size;
                }
                ChunkedState::Trailers => {
                    // Trailer fields to the first blank line. Go reads the
                    // block with textproto (lenient EOL, one trailing "\r"
                    // stripped) and bounds it to the bufio window
                    // (seeUpcomingDoubleCRLF + Peek(2) single-CRLF fast
                    // path, transfer.go:843-870) — mirror: scan lines to
                    // the first empty one, cap the BLOCK at 4096 bytes.
                    // Resume from the persisted offset so previously
                    // scanned complete lines are not re-scanned on a
                    // partial-last-line feed (see `trailer_scanned`).
                    let mut pos = self.trailer_scanned;
                    loop {
                        if pos > 4096 {
                            return Err("suspiciously long trailer after chunked body");
                        }
                        let Some(rel) = self.pending[pos..].iter().position(|&b| b == b'\n') else {
                            // Partial last line — more bytes needed. Bound
                            // the pending block here too: an unterminated
                            // trickle must not grow past the 4096 window
                            // Go's bufio-based trailer read would error
                            // on. Persist the progress made this call
                            // (lines scanned before the partial one).
                            if self.pending.len() > 4096 + 2 {
                                return Err("suspiciously long trailer after chunked body");
                            }
                            self.trailer_scanned = pos;
                            return Ok(false);
                        };
                        let mut line = &self.pending[pos..pos + rel];
                        if line.last() == Some(&b'\r') {
                            line = &line[..line.len() - 1];
                        }
                        pos += rel + 1;
                        if line.is_empty() {
                            self.pending.drain(..pos);
                            self.trailer_scanned = 0;
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    /// Go parseHexUint mirror (internal/chunked.go:278-298): hex digits
    /// only, at most 16 (the 17th digit errors; 16 digits are exactly
    /// u64::MAX, so no overflow is possible). An empty token errors too.
    fn parse_hex(v: &[u8]) -> Result<u64, &'static str> {
        if v.is_empty() {
            return Err("empty hex number for chunk length");
        }
        let mut n: u64 = 0;
        for (i, &b) in v.iter().enumerate() {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err("invalid byte in chunk length"),
            };
            if i == 16 {
                return Err("http chunk length too large");
            }
            n = n << 4 | u64::from(d);
        }
        Ok(n)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ResponseHeaderInjector<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        // Everything buffered has been served and the head phase is over:
        // a final/101 head was injected (the rest passes through
        // untouched), or a malformed head was served raw — which is
        // TERMINAL, never pass-through (see `raw_head_fully_served`).
        if this.complete {
            if this.malformed_raw {
                // Round-15 security review: the raw-served MALFORMED head
                // (status-None first line) was the response. Go errors the
                // whole response at ReadResponse and the reverse proxy
                // closes the backend connection, so no further backend
                // bytes are a legal continuation. Pre-fix, this drain
                // resumed the gather loop on the split-off tail and the
                // backend's next bytes became a SECOND response on one
                // user connection: a pipelined valid-looking final head
                // (see `raw_head_fully_served`) went through the INJECTOR
                // as a spliced second response, and endless
                // blank-line-terminated garbage was streamed raw. Either
                // shape is a double-response the client already rejected.
                // Permanent EOF; the consumer ends the bridge.
                return Poll::Ready(Ok(()));
            }
            // Round-14 review fix: a mid-body read failure AFTER the final
            // head went out must never surface as an error kind frp-core
            // answers with a gateway head — Go's ErrorHandler never runs
            // once the head is out (RoundTrip returned; the transport copy
            // merely aborts) while frp-core maps InvalidData to a 404.
            // Producer: SnappyStreamReader decode failure under the
            // injector on a compressed arm. Swallow it as clean EOF (the
            // stream framing is lost either way) and own the log here.
            return match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                    tracing::debug!(
                        error = %e,
                        "response injector: mid-body decode failure after head served, ending stream"
                    );
                    Poll::Ready(Ok(()))
                }
                other => other,
            };
        }

        // Serve buffered emission content. Shapes, all emitted only
        // post-boundary: the injected final/101 head, a raw interim 1xx
        // head (a malformed head is served raw the same way — Go would
        // reject it, frp-rs forwards it uninjected for the browser's own
        // parser to reject; round-13 review), or — round-18 C3b — the raw
        // pass-through leftovers of a completed body discard. M3: nothing
        // pre-boundary is ever served — a header spanning several internal
        // reads (e.g. a big Set-Cookie set over 4 KiB) must not leak
        // fragment-first, and a head cut short by EOF is dropped whole,
        // never relayed partial (Go relays nothing until a head parses).
        //
        // The flag gate: a drained interim head hands accumulation back to
        // its split-off tail, which may already hold the pipelined final
        // head (100 + 200 in one backend segment). That swapped-in tail is
        // flagless; it must NOT be served raw (which would skip injection)
        // and must not trip the debug_assert below — a flagless non-empty
        // buffer falls through to the gather loop, which re-resolves the
        // head boundary and re-enters classification. A drained injected
        // 204/304 whose backend declared a body (discard armed) hands the
        // split-off junk to `buffer` the same way, and the drain poll
        // RETURNS like every other drain (see below — a poll that filled
        // the caller's buffer must never end in Pending); the NEXT poll
        // runs the discard section — never the gather loop (the junk is
        // post-response bytes and must not be re-classified as a head).
        if (this.injected || this.raw_head || this.raw_pass)
            && this.buffer_offset < this.buffer.len()
        {
            debug_assert!(this.injected || this.raw_head || this.raw_pass);
            let remaining = this.buffer.len() - this.buffer_offset;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
            this.buffer_offset += to_copy;
            let fully_drained = this.buffer_offset >= this.buffer.len();
            if fully_drained {
                this.emission_drained();
            }
            // Every drain returns here having served >= 1 byte (the gate
            // above only runs while `buffer_offset < buffer.len()`), and
            // it must ALWAYS return — ReadBuf contract: a poll that filled
            // the caller's buffer must never go on to return
            // Poll::Pending, because tokio's `Read` future builds a FRESH
            // ReadBuf per poll and bytes filled by a Pending poll are
            // never reported to the caller (silently dropped from the
            // user-facing wire). The C3b discard handoff — a fully
            // drained injected 204/304 whose backend declared a body
            // (round-18 M1) — must therefore NOT fall through into the
            // discard section on this poll: when the in-hand tail is
            // empty the discard instant-completes and polls the inner
            // reader below, which returns Pending for a keep-alive
            // backend that has not yet sent its next response — that
            // Pending would discard this drain's final chunk (the tail of
            // an injected head larger than the caller's buffer, up to the
            // ~64 KiB gather cap under frp-core's 32 KiB PoolGuard). The
            // discard section runs on the NEXT poll, whose caller ReadBuf
            // starts unfilled; the post-boundary serve below already
            // returns the same way.
            return Poll::Ready(Ok(()));
        }

        // Round-18 C3b: the injected 204/304 head is fully out (drained
        // above, or by the post-boundary serve of the poll that injected
        // it) and the backend DECLARED a body that HTTP forbids the status
        // from carrying — the emission never relayed the framing headers,
        // and the declared body must not be relayed either (model in the
        // inject branch). Consume exactly the declared framing from the
        // bytes already IN HAND (the split-off tail from the drain); the
        // discard never reads the inner reader (see the section below for
        // why). The section leaves the injector in one of two states:
        // `complete` (exact boundary, in-hand bytes spent before the
        // framing completed, or an abort — see
        // `abort_after_discard_failure`) or `raw_pass` + buffered
        // leftovers (bytes past the declared framing — served raw below).
        if this.discard.is_some() {
            // Single pass only: every arm below aborts or completes the
            // discard, so no iteration is reachable. Consume the in-hand
            // buffer. A Length discard drains only up to its remaining
            // count (bytes past it are leftovers, not junk); a Chunked
            // discard feeds the WHOLE buffer into its machine, which
            // keeps what it cannot classify. A LEGAL 304 whose
            // Content-Length declared the would-be-200 length sends no
            // body, so post-head in-hand bytes behind it are the next
            // response — the Length arm's first <=left in-hand bytes eat
            // that coalesced-pipelined shape too (byte-indistinguishable
            // from junk; deliberate R2 model, same as the not-in-hand
            // pass-through below).
            let mut done = false;
            if !this.buffer.is_empty() {
                match this.discard.as_mut().unwrap() {
                    Discard::Length { left } => {
                        let take = (this.buffer.len() as u64).min(*left) as usize;
                        this.buffer.drain(..take);
                        *left -= take as u64;
                        done = *left == 0;
                    }
                    Discard::Chunked(skip) => {
                        // The machine copies everything it cannot classify
                        // into its own pending buffer, so the fed bytes
                        // are spent either way — clear them here or the
                        // same bytes would re-feed forever.
                        match skip.feed(&this.buffer) {
                            Ok(d) => {
                                this.buffer.clear();
                                done = d;
                            }
                            Err(why) => {
                                this.buffer.clear();
                                Self::abort_after_discard_failure(this, why);
                            }
                        }
                    }
                }
            }
            if this.discard.is_none() {
                // Abort path — the stream ended permanently (clean EOF
                // state raised by the abort helper). Nothing further to
                // do here: fall through to the EOF gate below.
            } else if done {
                // Declared framing fully consumed. Bytes in hand past
                // the boundary are the stream's real continuation
                // (Length leftovers stay in `buffer`; the chunked
                // machine held them in its pending buffer).
                let finished = this.discard.take().unwrap();
                if let Discard::Chunked(mut skip) = finished {
                    this.buffer = std::mem::take(&mut skip.pending);
                }
                this.buffer_offset = 0;
                if this.buffer.is_empty() {
                    // Exact boundary: the shared stream sits on the next
                    // response. The response (204/304) is fully out —
                    // clean EOF; `complete` pass-through covers whatever
                    // the backend sends later.
                    this.complete = true;
                } else {
                    this.raw_pass = true;
                }
            } else {
                // Not done and the in-hand bytes are spent (a Length
                // discard drains the buffer to zero when it is not done; a
                // chunked feed consumed the whole fed buffer into its
                // machine). READ NO FURTHER JUNK. From here the stream is
                // byte-indistinguishable between a LEGAL 304 whose
                // Content-Length declared the would-be-200 entity length
                // (RFC 9110 §15.4.5 — the backend never sends a body) and
                // a lying backend's junk split across writes; whatever
                // arrives next is the shared stream's real continuation
                // and must not be consumed as a phantom body (a pipelined
                // second response would lose its first N bytes, and a
                // keep-alive legal 304 would park the bridge to the A2
                // deadline). Go reads nothing only on the chunked /
                // CL-absent / CL:0 arms (Body = NoBody); a declared
                // CL:N > 0 arms io.LimitReader(N) and Go READS exactly N
                // wire bytes (transfer.go:565-578) — a junk-eat for the
                // hostile shape, a stall for the legal keep-alive 304
                // (its body never comes), first-N-bytes-eaten for the
                // pipelined one. No clean Go parity exists for the CL>0
                // arm; the fail-open below is a deliberate frp-rs
                // divergence — INSTANT clean completion with no further
                // wire read FOR THE DISCARD (the in-hand bytes were the
                // whole consumption; the inner poll a few lines below
                // only serves the real continuation if it is already in
                // hand, or parks the caller on that read's registered
                // waker — never a phantom body read), no WARN (nothing
                // failed — this is the legal shape as often as the
                // hostile one). Any partial junk the machine held is
                // dropped with it; whatever the backend sends later
                // passes through raw as the stream's real continuation.
                this.buffer.clear();
                this.discard = None;
                this.complete = true;
            }
            // Discard ended (any state). Serve leftovers in hand now —
            // returning Ready without serving would read as premature EOF
            // to the caller while `raw_pass` bytes sit in `buffer`.
            if this.raw_pass && this.buffer_offset < this.buffer.len() {
                let remaining = this.buffer.len() - this.buffer_offset;
                let to_copy = remaining.min(buf.remaining());
                buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
                this.buffer_offset += to_copy;
                if this.buffer_offset >= this.buffer.len() {
                    this.raw_pass = false;
                    this.complete = true;
                }
                return Poll::Ready(Ok(()));
            }
            // Exact-boundary or instant-complete: the 204/304 response is
            // over and the shared stream sits at its real continuation.
            // NOT an EOF — a Ready with nothing filled reads as
            // end-of-stream and the bridge caller ends the connection,
            // which would kill a legal keep-alive 304 whose
            // Content-Length declared the would-be-200 entity length
            // (RFC 9110 §15.4.5 — such a backend sends no body, and its
            // next bytes ARE the next response; the emission already
            // stripped the CL, so the user-facing wire expects exactly
            // that). Round-18 pin: 304 + declared CL + zero in-hand junk
            // → response 2 must arrive byte-exact, no stall. The
            // `complete` arm at the top of the next poll passes the
            // continuation through raw; poll the inner reader HERE so
            // this poll either serves it or parks on the inner read's
            // registered waker (a bare return would leave the caller with
            // no waker). Only the abort path — `malformed_raw`, raised by
            // `abort_after_discard_failure` — is terminal: permanent EOF,
            // never pass-through (a discard-grammar failure means the
            // stream position is unknowable and every later byte would be
            // served as a phantom second response).
            if this.malformed_raw {
                return Poll::Ready(Ok(()));
            }
            return match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                    tracing::debug!(
                        error = %e,
                        "response injector: mid-body decode failure after 204/304 head served, ending stream"
                    );
                    Poll::Ready(Ok(()))
                }
                other => other,
            };
        }

        // Buffer empty and the injectable head has not ended yet — gather
        // more of the response from the backend. Bytes are held (never
        // served) until a blank line ends a head (Go `textproto.ReadLine`
        // semantics: CRLF, bare-LF, or mixed line endings all legal) or the
        // backend closes.
        loop {
            // A split-off tail may already hold a complete head (the
            // backend pipelined interim + final heads in one segment) —
            // resolve it before reading more. Round-18 C2c: the boundary
            // hunt is carried in `head_scanner` across reads and polls —
            // a head arriving in a 1-byte drip is O(n) total, not O(n²)
            // (the scanner resumes where the previous feed stopped; the
            // buffer only grows between feeds, and every buffer
            // REPLACEMENT site resets the scanner).
            if !this.buffer.is_empty() {
                if let Some(end) = this.head_scanner.feed(&this.buffer) {
                    let blank_start = if end >= 2 && this.buffer[end - 2] == b'\r' {
                        end - 2
                    } else {
                        end - 1
                    };
                    // Go http.ReadResponse rejects a head whose FIRST line
                    // is empty (the head starting with its own blank line
                    // means no status line exists) — such a backend answer
                    // is malformed, and splicing configured headers in
                    // front of it would manufacture a plausible response
                    // out of garbage. Fail the read like Go's reverse
                    // proxy would (round-3 review finding).
                    if blank_start == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "backend response head has no status line",
                        )));
                    }
                    // Go ReadResponse parity: an interim 1xx head (not
                    // 101) is consumed internally by Go's Transport and
                    // modifyResponse never runs on it, and a MALFORMED
                    // first line (unparseable version token or code — Go
                    // errors the response, the reverse proxy answers 502)
                    // never reaches modifyResponse either. Both are served
                    // through this raw pipe UNINJECTED — never manufacture
                    // configured headers into a head Go would swallow or
                    // reject (round-13 review, 3 independent reviewers).
                    let status = Self::head_status_code(&this.buffer[..end]);
                    let served_raw = match status {
                        Some(c) if (100..=199).contains(&c) && c != 101 => true,
                        None => true,
                        Some(_) => false,
                    };
                    if served_raw {
                        // Serve the head raw NOW (an Expect:100-continue
                        // backend waits for its 100 head to reach the
                        // client before sending the body); bytes past the
                        // blank line are the next head's start and go back
                        // into `buffer` once the emission drains.
                        this.tail = Some(this.buffer.split_off(end));
                        this.buffer_offset = 0;
                        this.raw_head = true;
                        this.malformed_raw = status.is_none();
                        break;
                    }
                    // Final head (>= 200) or 101 — the one head Go's
                    // modifyResponse runs on: inject configured headers
                    // before the blank line. `end` is past the terminating
                    // blank line, which is exactly "\n" or "\r\n" (a line
                    // textproto deemed empty keeps at most one trailing
                    // "\r") and stays attached to the head: the configured
                    // headers must go out BEFORE it — bytes after the
                    // blank line are the backend's entity body and pass
                    // verbatim.
                    let mut injected = Vec::with_capacity(this.buffer.len() + 512);
                    // Go ModifyResponse `Header.Set(k, v)` REPLACES a
                    // backend-sent value for a configured name — the wire
                    // must never carry both lines (round-13 review finding:
                    // a backend `X-Custom: a` + configured `X-Custom: b`
                    // previously shipped both, backend's first, breaking a
                    // first-value-wins security header). Backend lines whose
                    // name matches a configured key are dropped,
                    // case-insensitively, folded continuations included.
                    //
                    // Round-16/18 (Go write-layer parity): a FINAL 204/304
                    // must not carry framing headers — nor, for a 304,
                    // Content-Type — on the user-facing wire. Go's
                    // net/http serialization deletes suppressed headers in
                    // chunkWriter.writeHeader (go1.25 server.go:1483-1497:
                    // `for _, k := range suppressedHeaders(code) {
                    // delHeader(k) }`, run after ModifyResponse's Header.Set);
                    // `bodyAllowedForStatus` (transfer.go:461-470 — false
                    // for 1xx, 204, 304) selects suppressedHeadersNoBody =
                    // {Content-Length, Transfer-Encoding}
                    // (transfer.go:474-477) and a 304 additionally loses
                    // Content-Type via suppressedHeaders304
                    // (transfer.go:480-486) — every response through the Go
                    // frp http vhost ReverseProxy passes that layer. 101 is
                    // injected but suppressed by NOTHING: Go's ReverseProxy
                    // answers an upgraded (101) response through
                    // handleUpgradeResponse (reverseproxy.go:632+), which
                    // hijacks the conn and writes via `Response.Write` —
                    // the chunkWriter sweep never runs on that path.
                    // Interim 1xx heads never reach this branch (raw serve
                    // above). Only 204 and 304 are therefore stripped here.
                    let suppress = Self::suppressed_headers_for_status(status);
                    Self::splice_head_deduplicated(
                        &this.buffer[..blank_start],
                        &this.headers,
                        suppress,
                        &mut injected,
                    );
                    // A6 (round-13 review): Go frp applies the configured
                    // headers with Header.Set (vhost http.go modifyResponse)
                    // — keys canonicalize, so "X-Custom" + "x-custom" in the
                    // config are ONE header and the wire carries ONE line
                    // (which value wins is Go map-iteration luck). Emit
                    // deterministically: original keys sorted, a
                    // case-insensitive collision resolves to the LAST key in
                    // sorted order (one of Go's possible outcomes) — never
                    // both lines, which would read as two headers to the
                    // client and break first-value-wins security headers.
                    //
                    // Round-16/18: the write-layer suppression also hits a
                    // CONFIGURED Content-Length / Transfer-Encoding /
                    // Content-Type on a 204/304 — Go's ModifyResponse
                    // `Header.Set` runs BEFORE chunkWriter.writeHeader's
                    // delHeader sweep, so a configured suppressed name is
                    // filtered from the emission exactly like the splice
                    // dropped backend lines above.
                    let mut sorted: Vec<(&String, &String)> = this
                        .headers
                        .iter()
                        .filter(|(k, _)| {
                            !suppress
                                .iter()
                                .any(|s| k.as_bytes().eq_ignore_ascii_case(s.as_bytes()))
                        })
                        .collect();
                    sorted.sort_by(|a, b| a.0.cmp(b.0));
                    let mut prev_key: Option<&[u8]> = None;
                    let mut prev_start = 0usize;
                    for (k, v) in sorted {
                        if prev_key.is_some_and(|pk| pk.eq_ignore_ascii_case(k.as_bytes())) {
                            // Same canonical header as the previous (sorted)
                            // key — rewind the whole previous emitted line
                            // and let this entry replace it.
                            injected.truncate(prev_start);
                        }
                        // Sanitize header names/values to prevent HTTP
                        // header injection.
                        let safe_k: String =
                            k.chars().filter(|&c| c != '\r' && c != '\n').collect();
                        let safe_v: String =
                            v.chars().filter(|&c| c != '\r' && c != '\n').collect();
                        // Configured headers always go out CRLF (Go
                        // net/http renders every response header CRLF,
                        // whatever the backend wrote) — a backend LF-only
                        // head intentionally ends up mixed-EOL; the
                        // injected lines remain parseable and the trailing
                        // blank keeps the backend's own EOL.
                        prev_start = injected.len();
                        injected
                            .extend_from_slice(format!("{}: {}\r\n", safe_k, safe_v).as_bytes());
                        prev_key = Some(k.as_bytes());
                    }
                    if matches!(status, Some(204) | Some(304)) {
                        // Round-18 C3b: bytes a backend writes after a
                        // 204/304 head. Go's Transport abandons them per
                        // framing (transfer.go:565-578: chunked +
                        // !bodyAllowedForStatus and CL:0/absent → Body =
                        // NoBody, nothing read, pooled conn closed at the
                        // next reuse with the junk still buffered; a
                        // declared CL: N > 0 → Body = LimitReader(N), so
                        // Go READS exactly N junk bytes before the conn is
                        // reusable). frp-rs's 204/304 head is already out,
                        // so the stream position is what it is; the
                        // user-facing wire stays parseable by never
                        // relaying the junk either. When the backend
                        // DECLARED a bounded body (Content-Length: N > 0,
                        // or chunked — the framing survives in the head
                        // region above even though the emission
                        // suppressed its header lines), consume exactly
                        // that much so the shared stream lands clean on
                        // whatever follows (a pipelined next response, or
                        // the backend close): the split-off tail is the
                        // discard input and `discard` arms the
                        // consumption phase. The consumption never reads
                        // the inner reader (see the discard section): once
                        // the in-hand bytes are spent the stream is
                        // byte-indistinguishable between a legal 304 whose
                        // CL declared the would-be-200 length and a lying
                        // backend's split junk, and a wire read would eat
                        // a pipelined next response or park the bridge —
                        // both mirror Go's abandon-and-close with an
                        // instant clean completion instead. With no
                        // declared framing (absent CL, CL: 0, or an
                        // unparseable value — no head validation is added
                        // here, audit carve-out) the tail relays raw as
                        // before: no body parser runs on a no-body status
                        // in Go either, and the emission's suppressed CL
                        // is what keeps the user-facing wire parseable.
                        match Self::declared_body_framing(&this.buffer[..blank_start]) {
                            DeclaredFraming::None => {
                                injected.extend_from_slice(&this.buffer[blank_start..]);
                            }
                            DeclaredFraming::ContentLength(n) => {
                                injected.extend_from_slice(&this.buffer[blank_start..end]);
                                this.tail = Some(this.buffer.split_off(end));
                                this.discard = Some(Discard::Length { left: n });
                            }
                            DeclaredFraming::Chunked => {
                                injected.extend_from_slice(&this.buffer[blank_start..end]);
                                this.tail = Some(this.buffer.split_off(end));
                                this.discard = Some(Discard::Chunked(ChunkedSkip::new()));
                            }
                        }
                    } else {
                        // Body-bearing status (or 101): the blank line and
                        // every byte past it belong to the response body —
                        // attach them to the emission.
                        injected.extend_from_slice(&this.buffer[blank_start..]);
                    }
                    this.buffer = injected;
                    this.buffer_offset = 0;
                    // The buffer was replaced by the spliced emission — the
                    // carried boundary scanner describes the old content.
                    this.head_scanner = frp_core::textproto::HeadEndScanner::new();
                    this.injected = true;
                    break;
                }
            }
            // A2 (round-13 review): Go ResponseHeaderTimeout is ONE
            // absolute deadline — armed once, never extended by interim 1xx
            // heads (go1.25 transport.go:2842-2853: the timer starts when
            // the request body is fully written; the respHeaderTimer case
            // is never re-armed). An Expect:100-continue backend that
            // answers 100 and then stalls must not park this bridge
            // unbounded — the frp-core one-shot timeout was consumed by the
            // raw interim serve above. Poll a sleep to the absolute
            // deadline before each inner read: Pending registers the timer
            // waker alongside the inner read's; a fire errors the read
            // (TimedOut), which frp-core maps to a Go-shaped 504. The
            // deadline is anchored at construction (bridge spawn, head
            // already forwarded) — Go arms at request-body-complete, which
            // this read layer cannot observe; a slow Expect upload counts
            // against the budget where Go's timer would not (same anchor as
            // the pre-existing first-read timeout).
            if let Some(deadline_sleep) = this.deadline_sleep.as_mut() {
                if deadline_sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out waiting for response headers",
                    )));
                }
            }
            let mut temp_buf = ReadBuf::new(&mut this.read_buf);
            match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = temp_buf.filled().len();
                    if n == 0 {
                        // EOF before a head terminator. The backend
                        // closed without completing a usable head (nothing
                        // relayed; interim 1xx heads may have been). Go
                        // readResponse errors on an unterminated head
                        // (partial bytes included — the reverse proxy
                        // relays nothing until a head parses) and the vhost
                        // ErrorHandler answers 404; surface
                        // Err(UnexpectedEof) so frp-core's 404 arm fires.
                        // A bare Ok(0) here would read as clean
                        // end-of-stream (round-14 review fix), and the old
                        // partial-byte relay put half a head on the wire.
                        //
                        // A `malformed_raw` stream is UNREACHABLE here:
                        // both raise sites also set `complete` —
                        // `abort_after_discard_failure` (the discard
                        // section returns the permanent EOF in that same
                        // poll) and the raw serve of a malformed head
                        // (whose emission drains only through the flag
                        // gate into `raw_head_fully_served`, which raises
                        // `complete` before the gather loop can run
                        // again) — and the top-of-poll `complete` gate
                        // serves that EOF first. Round-18 4c: the old
                        // guard answered a bare Ok(()) for this shape (a
                        // fail-OPEN clean end-of-stream) while its comment
                        // claimed fail-closed. Removed — fail-closed now
                        // holds unconditionally, so a future raise site
                        // cannot turn an unterminated head into a "clean"
                        // end-of-stream. Go parity: an EOF before the
                        // head terminator is an unterminated response
                        // head; http.Transport ReadResponse errors on it
                        // and the vhost ErrorHandler answers 404
                        // (frp-core/src/bridge.rs:506-532 renders that
                        // page from this Err arm).
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "backend closed before completing response head",
                        )));
                    }
                    // Guard against memory exhaustion from backends that
                    // never terminate the head with a blank line (the cap
                    // still bounds a backend that sends no blank line at
                    // all, whatever EOL convention it uses). The head end
                    // may span internal reads — the carried `head_scanner`
                    // re-checks at the loop top without rescanning (C2c).
                    //
                    // Cap values across the response-head surfaces are
                    // NOT uniform (round-18 C5); each bounds the same
                    // hostile-backend trickle, at a different point:
                    // - this injector (vhost h1 http legs, backend
                    //   response heads): 64 KiB, fail-closed — a larger
                    //   head is answered 404 via the InvalidData
                    //   Err-arm. The 64 KiB predates the readLimit model
                    //   and is plain Rust hardening: the backend here is
                    //   the operator's own upstream on a one-user-conn
                    //   bridge, and a legit > 64 KiB response head is
                    //   pathological. Go forwards heads up to 10 MiB
                    //   (`maxHeaderResponseSize` default,
                    //   transport.go:2106-2112), so heads between 64 KiB
                    //   and 10 MiB are a documented narrow divergence
                    //   (fail-closed; Go ErrorHandler parity on the 404
                    //   shape).
                    // - the h2c CONNECT/backend legs (vhost_h2c.rs
                    //   `read_until_head_from` and the client plugin h2
                    //   `read_until_head`): 1 MiB per head with Go
                    //   ReadRequest-style terminator-first semantics — a
                    //   TERMINATED head up to ~1 MiB + 4096 serves, only
                    //   an unterminated/terminator-past-one errors (Go
                    //   `MaxHeaderBytes` request model; see those files).
                    // - Go's Transport response side: one cumulative
                    //   10 MiB `maxHeaderResponseSize` budget per
                    //   RoundTrip (transport.go:2106-2112, 2274).
                    // The spread is deliberate hardening, not an
                    // oversight: any of the three bounds stops the
                    // trickle, and each surface kept its historical cap
                    // rather than churning pins for a NIT.
                    if this.buffer.len() + n > 65536 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "response header exceeds 64KB limit",
                        )));
                    }
                    this.buffer.extend_from_slice(&this.read_buf[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Data will arrive later; that inner poll registered
                    // the waker — park until then. Returning Pending
                    // straight after a Ready inner read would park the
                    // caller with no registered waker (a Ready poll does
                    // not register one) — deadlock; the loop only returns
                    // Pending once the inner poll itself went Pending, so
                    // its waker is set.
                    return Poll::Pending;
                }
            }
        }

        // A head boundary was found in this poll (interim → raw serve,
        // final/101 → injected serve): emit what fits; the tail goes out
        // on subsequent polls. `complete` is raised only once the buffer
        // is fully drained; a drained interim head hands the accumulation
        // back to the split-off tail, and a drained injected 204/304 head
        // whose backend declared a body arms the C3b discard (see
        // `emission_drained`) — that poll ends here and the next one runs
        // the discard section.
        let remaining = this.buffer.len() - this.buffer_offset;
        let to_copy = remaining.min(buf.remaining());
        buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
        this.buffer_offset += to_copy;
        if this.buffer_offset >= this.buffer.len() {
            this.emission_drained();
        }

        Poll::Ready(Ok(()))
    }
}
