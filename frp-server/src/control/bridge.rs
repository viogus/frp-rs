use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use futures_util::FutureExt;

use frp_core::cipher_stream::{CipherReader, CipherWriter};
use frp_core::encryption::derive_key;
use frp_core::metrics::ConnGuard;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{
    read_msg_v1, read_msg_v2_udp_binary_socket, read_msg_v2_with_udp_codec, write_msg_v1,
    write_msg_v2_with_udp_codec, write_v2_frame_raw, UdpBinaryRead, V2_FRAME_TYPE_MESSAGE,
};
use frp_core::snappy_stream::{SnappyStreamReader, SnappyStreamWriter};
use frp_core::transport::{split_work_conn_halves, IoStream};

use crate::service::AppState;

use super::pool::PendingRequest;

/// Build a StartWorkConn message from request and address info.
/// Pure data construction — no `.await` calls. Extracted from the
/// async state machine in `assign_work_to_proxy`.
#[inline(never)]
fn build_start_work_conn(
    req: &PendingRequest,
    src_addr: &str,
    src_port: u16,
    dst_addr: &str,
    dst_port: u16,
) -> FrpMessage {
    FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        src_addr: if !src_addr.is_empty() {
            Some(src_addr.to_string())
        } else {
            None
        },
        src_port: if src_port != 0 { Some(src_port) } else { None },
        dst_addr: if !dst_addr.is_empty() {
            Some(dst_addr.to_string())
        } else {
            None
        },
        dst_port: if dst_port != 0 { Some(dst_port) } else { None },
        error: None,
        // use_encryption/use_compression: propagate proxy config settings.
        // Go frpc v0.69.1 ignores these fields (not in its StartWorkConn struct)
        // and uses its own proxy config. The server must match whatever the
        // provider does, so the bridge type (plain vs encrypted) is determined
        // below based on req.use_encryption/compression, NOT forced to false.
        // Rust frpc (work_conn.rs) respects swc.use_encryption over its own config.
        // CipherWriter now eagerly flushes IV on first poll_flush, preventing the
        // dual-CipherWriter deadlock that previously forced plain bridge for XTCP.
        use_encryption: if req.use_encryption { Some(true) } else { None },
        use_compression: if req.use_compression {
            Some(true)
        } else {
            None
        },
        // For XTCP STCP fallback: set empty nat_hole_sid marker so Rust frpc
        // knows this work conn is for STCP bridging, not XTCP notification.
        // When `proxy_info` is None the proxy was already unregistered in the
        // enqueue→bridge window, so this path is already broken (the bridge
        // fails or the peer rejects the StartWorkConn); omitting the marker
        // there is acceptable because the proxy type is unknown anyway.
        nat_hole_sid: if req
            .proxy_info
            .as_ref()
            .is_some_and(|p| p.proxy_type == "xtcp")
        {
            Some(String::new())
        } else {
            None
        },
        nat_hole_visitor_addr: None,
        sk: None,
    }))
}

/// RAII guard that tracks an active bridge connection for graceful shutdown drain.
struct ActiveGuard(std::sync::Arc<AppState>);
impl ActiveGuard {
    fn new(state: &std::sync::Arc<AppState>) -> Self {
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(state.clone())
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

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
struct ResponseHeaderInjector<R> {
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
    /// emitted. Taken back into `buffer` when the emission drains.
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
    malformed_raw: bool,
    /// True once every buffered byte is served and no further buffering is
    /// possible — the rest of the response passes through raw. With
    /// `malformed_raw` set it instead means the malformed raw head was the
    /// response and the stream ends at EOF (the `complete` arm never
    /// polls the inner reader in that state).
    complete: bool,
    /// Persistent read buffer to avoid per-poll_read allocation.
    read_buf: [u8; 4096],
    /// Absolute deadline for the FIRST injectable head (Go
    /// ResponseHeaderTimeout analog, A2). Armed once at construction; an
    /// interim 1xx raw serve does NOT extend it. When it fires while a head
    /// is still being gathered, poll_read errors with TimedOut. Boxed-pinned
    /// Sleep registered once (no per-poll wheel churn); `Pin<Box<T>>` is
    /// Unpin regardless of `T`, so the manual Unpin impl above stays valid.
    deadline_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

// SAFETY: All fields of ResponseHeaderInjector are Unpin when R: Unpin.
// HashMap, Vec, Option<Vec>, usize, bool, [u8; 4096], and
// Option<Pin<Box<tokio::time::Sleep>>> (Pin<Box<T>> is Unpin for any T) are
// all Unpin.
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
            self.complete = true;
            return;
        }
        self.buffer = self.tail.take().unwrap_or_default();
        self.buffer_offset = 0;
    }

    fn new(
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
            read_buf: [0u8; 4096],
            deadline_sleep: header_timeout.map(|d| Box::pin(tokio::time::sleep(d))),
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
    fn is_http_version(v: &[u8]) -> bool {
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
    fn head_status_code(head: &[u8]) -> Option<u16> {
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
    /// `strip_content_length` additionally drops backend `Content-Length`
    /// lines (folded continuations included) — the round-16 Go write-layer
    /// parity for a final head whose status forbids a body (204/304; see
    /// the inject branch below for the suppression-table citation). The
    /// caller filters its OWN configured Content-Length emission the same
    /// way when the flag is set: Go's `Header.Set` (ModifyResponse) runs
    /// BEFORE the write layer's suppression, so a configured Content-Length
    /// is suppressed on a 204/304 exactly like a backend one.
    fn splice_head_deduplicated(
        head_region: &[u8],
        headers: &std::collections::HashMap<String, String>,
        strip_content_length: bool,
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
                        || (strip_content_length && name.eq_ignore_ascii_case(b"content-length"))
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

        // Serve buffered emission content. Two shapes, all emitted only
        // post-boundary: the injected final/101 head, or a raw interim 1xx
        // head (a malformed head is served raw the same way — Go would
        // reject it, frp-rs forwards it uninjected for the browser's own
        // parser to reject; round-13 review). M3: nothing pre-boundary is
        // ever served — a header spanning several internal reads (e.g. a
        // big Set-Cookie set over 4 KiB) must not leak fragment-first, and
        // a head cut short by EOF is dropped whole, never relayed partial
        // (Go relays nothing until a head parses).
        //
        // The flag gate: a drained interim head hands accumulation back to
        // its split-off tail, which may already hold the pipelined final
        // head (100 + 200 in one backend segment). That swapped-in tail is
        // flagless; it must NOT be served raw (which would skip injection)
        // and must not trip the debug_assert below — a flagless non-empty
        // buffer falls through to the gather loop, which re-resolves the
        // head boundary and re-enters classification.
        if (this.injected || this.raw_head) && this.buffer_offset < this.buffer.len() {
            debug_assert!(this.injected || this.raw_head);
            let remaining = this.buffer.len() - this.buffer_offset;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
            this.buffer_offset += to_copy;
            if this.buffer_offset >= this.buffer.len() {
                if this.raw_head {
                    // Raw head (interim 1xx, or malformed — neither is
                    // injected) fully served — an interim head resumes
                    // accumulating the next head from the split-off tail;
                    // a MALFORMED head is terminal (Go errors the whole
                    // response; nothing after it is relayed).
                    this.raw_head = false;
                    this.raw_head_fully_served();
                } else {
                    // Injected head is fully out; the remainder of the
                    // response is raw pass-through.
                    this.complete = true;
                }
            }
            return Poll::Ready(Ok(()));
        }

        // Buffer empty and the injectable head has not ended yet — gather
        // more of the response from the backend. Bytes are held (never
        // served) until a blank line ends a head (Go `textproto.ReadLine`
        // semantics: CRLF, bare-LF, or mixed line endings all legal) or the
        // backend closes.
        loop {
            // A split-off tail may already hold a complete head (the
            // backend pipelined interim + final heads in one segment) —
            // resolve it before reading more.
            if !this.buffer.is_empty() {
                if let Some(end) = frp_core::textproto::head_end(&this.buffer) {
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
                    // Round-16 (Go write-layer parity): a FINAL 204/304
                    // must not carry Content-Length on the user-facing wire.
                    // Go's net/http serialization deletes suppressed headers
                    // in chunkWriter.writeHeader (go1.25 server.go:1483-1497:
                    // `for _, k := range suppressedHeaders(code) {
                    // delHeader(k) }`); `bodyAllowedForStatus` forbids a
                    // body for both statuses and the suppression tables in
                    // transfer.go:459-485 are suppressedHeadersNoBody =
                    // {Content-Length, Transfer-Encoding} (204) and
                    // suppressedHeaders304 = {Content-Type,
                    // Content-Length, Transfer-Encoding} (304) — every
                    // response through the Go frp http vhost ReverseProxy
                    // passes that layer, so Go never sends CL with a
                    // 204/304. Narrow divergence kept deliberate: frp-rs
                    // strips Content-Length ONLY — Transfer-Encoding on a
                    // no-body status is dropped by Go but relayed here (a
                    // backend that chunked a 204 is broken; no body parser
                    // runs on a no-body status), and a 304 keeps its
                    // Content-Type where Go suppresses it (informational,
                    // no semantic effect). Trailing bytes a lying backend
                    // writes after the 204/304 head: Go's proxy body copy
                    // stops (ErrBodyNotAllowed) while frp-rs raw-relays
                    // them — the head no longer declares a length, so no
                    // client frames them as this response's body (pre-fix,
                    // the relayed CL:16 + body made the client wait for a
                    // body RFC 9110 §8.6 says a 204 never has; stripping
                    // the CL is what keeps the user-facing wire
                    // parseable).
                    let strip_content_length = matches!(status, Some(204) | Some(304));
                    Self::splice_head_deduplicated(
                        &this.buffer[..blank_start],
                        &this.headers,
                        strip_content_length,
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
                    // Round-16: on a 204/304 the write-layer suppression
                    // also hits a CONFIGURED Content-Length (Go's
                    // ModifyResponse Header.Set runs before
                    // chunkWriter.writeHeader's delHeader sweep) — filter
                    // it from the emission just like the splice dropped
                    // backend lines above.
                    let mut sorted: Vec<(&String, &String)> = this
                        .headers
                        .iter()
                        .filter(|(k, _)| {
                            !(strip_content_length && k.eq_ignore_ascii_case("content-length"))
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
                    injected.extend_from_slice(&this.buffer[blank_start..]);
                    this.buffer = injected;
                    this.buffer_offset = 0;
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
                        // EOF before a head terminator. If the last unit
                        // served raw was a MALFORMED head, that relayed
                        // unit is the response and the stream ends cleanly
                        // (see `malformed_raw`). Otherwise the backend
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
                        if this.malformed_raw {
                            this.complete = true;
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "backend closed before completing response head",
                        )));
                    }
                    // Guard against memory exhaustion from backends that
                    // never terminate the head with a blank line (the cap
                    // still bounds a backend that sends no blank line at
                    // all, whatever EOL convention it uses). Documented
                    // Rust hardening divergence: Go's cap is the 10 MiB
                    // `maxHeaderResponseSize` default
                    // (transport.go:2106-2112) — a backend head between
                    // 64 KiB and 10 MiB is answered 404 by frp-rs (bridge
                    // Err-arm InvalidData → NotFoundResponse, Go
                    // ErrorHandler parity) where Go would forward it.
                    if this.buffer.len() + n > 65536 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "response header exceeds 64KB limit",
                        )));
                    }
                    this.buffer.extend_from_slice(&this.read_buf[..n]);
                    // The head end may span internal reads — the search
                    // covers the whole buffer; the loop re-checks at the
                    // top.
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
        // is fully drained, and a drained interim head hands the
        // accumulation back to the split-off tail.
        let remaining = this.buffer.len() - this.buffer_offset;
        let to_copy = remaining.min(buf.remaining());
        buf.put_slice(&this.buffer[this.buffer_offset..this.buffer_offset + to_copy]);
        this.buffer_offset += to_copy;
        if this.buffer_offset >= this.buffer.len() {
            if this.raw_head {
                this.raw_head = false;
                this.raw_head_fully_served();
            } else {
                this.complete = true;
            }
        }

        Poll::Ready(Ok(()))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_work_conn(
    work_conn: IoStream,
    sock: Arc<tokio::net::UdpSocket>,
    proxy_name: String,
    local_addr: Option<msg::UdpAddr>,
    use_enc: bool,
    enc_key: [u8; 16],
    v2: bool,
    udp_packet_size: usize,
    bw_limiter: Option<frp_core::bandwidth::SharedBandwidthLimiter>,
    cancel: tokio_util::sync::CancellationToken,
    // Negotiated UDPPacket codec (`"binary-v1"` or empty). When set, UDP
    // packets on this V2 work conn use the binary codec (Go frp v0.71.0).
    udp_packet_codec: String,
    // M1 (audit round 3): read deadline for this work conn, mirroring Go
    // server/proxy/udp.go `workConnReaderFn` SetReadDeadline(60s). The
    // client pings at a FIXED 30s (audit F1 — Go client/proxy/udp.go
    // heartbeatFn hardcodes 30s; frp-rs used to wire dial_server_keepalive
    // here, whose 7200s default let this 60s deadline kill idle conns), so
    // 60s of frame silence means the peer is dead or the conn is
    // half-open — the bridge must end so the assign supervisor re-requests
    // a replacement (Go udpWorker loop parity). Without it a silent
    // half-open peer parked the reader forever, leaving the UDP proxy dead
    // until control reconnect. The deadline applies per read (each
    // completed frame — a Ping included — starts a fresh 60s), so an
    // active conn is never reaped.
    read_timeout: std::time::Duration,
) {
    // write_msg_v2_nof skips the flush syscall. That is only safe for a raw
    // TcpStream: TLS/mux/WS-wrapped streams buffer internally and would leave
    // frames in flight without flush — and a CipherWriter must flush to emit
    // its IV.
    let no_flush = work_conn.try_tcp().is_some() && !use_enc;
    let udp_codec_opt = if udp_packet_codec.is_empty() {
        None
    } else {
        Some(udp_packet_codec.as_str())
    };
    let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
        return;
    };
    // Provider-segment encryption (Go parity): when the UDP proxy configures
    // use_encryption, the work conn carries a CipherStream (AES-128-CFB,
    // derive_key(token)) with the V1/V2 frame protocol inside it — matching
    // the client side (frp-client work_conn.rs) and Go's
    // libio.WithEncryption(rwc, token) on the UDP proxy work conn.
    let w_r: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if use_enc {
        Box::new(CipherReader::new(w_r, enc_key))
    } else {
        w_r
    };
    let mut w_w: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = if use_enc {
        // Audit B2: OS-RNG failure (IV generation) ends this work conn
        // instead of aborting the process.
        match CipherWriter::new(w_w, enc_key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::warn!(error = %e, "udp work conn: IV generation failed");
                return;
            }
        }
    } else {
        w_w
    };
    // Buffer the frame reads: read_msg_v1/v2 issue two read_exact calls per
    // packet (header + payload), so BufReader amortizes them into one
    // syscall per packet — and one syscall for several small packets. The
    // write half is untouched (separate object), so no flush semantics
    // change.
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    let sock_reader = sock.clone();
    let reader_name = proxy_name.clone();
    let mut reader_cancel = cancel_rx.clone();
    let cancel_reader = cancel.clone();
    // UDP bandwidth limiting (frp-rs extension; Go frp v0.70.1 has no UDP
    // limiter). Go v0.71.0 parity for the model: ONE per-proxy shared
    // limiter created at registration (mode == "server"/"both"), wrapping
    // BOTH directions with the same bucket (proxy.go single-`rate.Limiter`
    // semantics). Both bridge tasks clone the Arc; empty/unset rate (0)
    // stays unlimited (limiter is None).
    let reader_lim = bw_limiter.clone();
    let reader = async move {
        debug!(proxy_name = %reader_name, "UDP work conn reader task started for '{}'", reader_name);
        // Reusable payload buffer for the V2 UDP read path (avoids a heap
        // alloc per UDP packet).
        let mut scratch: Vec<u8> = Vec::new();
        loop {
            let result = tokio::select! {
                biased;
                _ = cancel_reader.cancelled() => break,
                changed = reader_cancel.changed() => {
                    if changed.is_err() || *reader_cancel.borrow() { break; }
                    continue;
                }
                result = async {
                    match tokio::time::timeout(read_timeout, async {
                        if v2 {
                            if udp_codec_opt.is_some() {
                                // Binary UDP codec negotiated (Go v0.71.0):
                                // type-19 frames decode to native SocketAddr
                                // form, skipping the per-packet String alloc +
                                // reparse that the message path performs
                                // (audit LOW: decode formats then re-parses).
                                read_msg_v2_udp_binary_socket(&mut w_r, &mut scratch).await
                            } else {
                                read_msg_v2_with_udp_codec(&mut w_r, udp_codec_opt, &mut scratch)
                                    .await
                                    .map(UdpBinaryRead::Message)
                            }
                        } else {
                            read_msg_v1(&mut w_r).await.map(UdpBinaryRead::Message)
                        }
                    })
                    .await
                    {
                        Ok(r) => r,
                        // M1: 60s of frame silence (Go udp.go read-deadline
                        // parity) = dead/half-open peer. Folds into the Err
                        // arm below: log + break, and the supervisor
                        // re-requests a replacement work conn.
                        Err(_) => Err(frp_core::Error::Protocol(
                            format!(
                                "UDP work conn read deadline ({read_timeout:?}) expired with no frame from the client"
                            )
                            .into(),
                        )),
                    }
                } => result,
            };
            match result {
                // Native-address form (binary codec): the destination is
                // already a SocketAddr — send directly, no text round trip.
                Ok(UdpBinaryRead::Socket(pkt)) => {
                    if let Some(lim) = reader_lim.as_ref() {
                        frp_core::bandwidth::BandwidthLimiter::consume_shared(
                            lim,
                            pkt.content.len(),
                        )
                        .await;
                    }
                    if let Err(e) = sock_reader.send_to(&pkt.content, pkt.remote_addr).await {
                        debug!(proxy_name = %reader_name, error = %e,
                            "UDP send_to failed for '{}': {}", reader_name, e);
                    }
                }
                Ok(UdpBinaryRead::Message(FrpMessage::UDPPacket(up))) => {
                    // Rate-limit only bytes actually forwarded. Counting a
                    // dropped (malformed, no remote_addr) packet against the
                    // budget without delivering it would silently bill the
                    // user for nothing — refund=true by consuming only here,
                    // and log the drop for diagnosability.
                    if let Some(ref remote) = up.remote_addr {
                        if let Some(lim) = reader_lim.as_ref() {
                            frp_core::bandwidth::BandwidthLimiter::consume_shared(
                                lim,
                                up.content.len(),
                            )
                            .await;
                        }
                        // Prefer a direct `SocketAddr` (no per-packet String
                        // alloc + reparse of the destination, audit #14a); fall
                        // back to the string form when the address carries an
                        // IPv6 zone that `SocketAddr` cannot express.
                        if let Some(dest) = udp_dest_socket_addr(remote) {
                            if let Err(e) = sock_reader.send_to(&up.content, dest).await {
                                debug!(proxy_name = %reader_name, error = %e,
                                    "UDP send_to failed for '{}': {}", reader_name, e);
                            }
                        } else if let Err(e) =
                            sock_reader.send_to(&up.content, remote.to_string()).await
                        {
                            debug!(proxy_name = %reader_name, error = %e,
                                "UDP send_to failed for '{}': {}", reader_name, e);
                        }
                    } else {
                        debug!(
                            proxy_name = %reader_name,
                            bytes = up.content.len(),
                            "UDP work conn for '{}': dropped datagram with no remote_addr (malformed)",
                            reader_name
                        );
                    }
                }
                Ok(UdpBinaryRead::Message(FrpMessage::Ping(_)))
                | Ok(UdpBinaryRead::Message(FrpMessage::Pong(_))) => continue,
                Ok(UdpBinaryRead::Message(other)) => {
                    debug!(proxy_name = %reader_name, msg_type = %other.v1_type_byte(),
                        "UDP work conn for '{}': unexpected msg 0x{:02x}", reader_name, other.v1_type_byte());
                }
                Err(e) => {
                    debug!(proxy_name = %reader_name, error = %e,
                        "UDP work conn for '{}' read closed: {}", reader_name, e);
                    break;
                }
            }
        }
    };

    let writer_name = proxy_name.clone();
    let mut writer_cancel = cancel_rx;
    let cancel_writer = cancel;
    let writer_lim = bw_limiter.clone();
    let writer = async move {
        debug!(proxy_name = %writer_name, "UDP work conn writer task started for '{}'", writer_name);
        let mut buf = vec![0u8; udp_packet_size];
        // local_addr is loop-invariant (comes from proxy config). Move the
        // owned value into each packet and back out afterwards, so the
        // Option<UdpAddr> String heap allocs happen once per bridge instead
        // of once per packet. Single-task writer: no concurrency risk.
        let mut local_addr = local_addr;
        // Spare Vec for the packet content: the wire format base64-encodes
        // UDPPacket.content, and the memcpy of `buf[..n]` is inherent — but
        // the per-packet Vec *allocation* is not. take/return keeps the
        // capacity across packets (audit D1-4).
        let mut spare: Vec<u8> = Vec::with_capacity(udp_packet_size);
        // Reused binary-codec wire buffer: type ID + encoded packet.
        let mut wire_scratch: Vec<u8> = Vec::with_capacity(udp_packet_size + 48);
        loop {
            let received = tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => break,
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                    continue;
                }
                result = sock.recv_from(&mut buf) => result,
            };
            match received {
                Ok((n, src)) => {
                    spare.clear();
                    spare.extend_from_slice(&buf[..n]);
                    let content = std::mem::take(&mut spare);
                    if let Some(lim) = writer_lim.as_ref() {
                        frp_core::bandwidth::BandwidthLimiter::consume_shared(lim, n).await;
                    }
                    let result = if v2 && udp_codec_opt.is_some() {
                        // V2 binary codec path: encode the remote `SocketAddr`
                        // straight into the wire body — the per-packet
                        // `ip.to_string()` String alloc + reparse is only
                        // needed for the V1 JSON path, where the address is
                        // serialized as text (audit: LOW). Output bytes are
                        // identical to the string round trip
                        // (`encode_udp_packet_binary_socket_addr`). `content`
                        // is borrowed here and returned to `spare` below;
                        // `local_addr` is loop-invariant and only borrowed.
                        let encode = async {
                            wire_scratch.clear();
                            wire_scratch
                                .extend_from_slice(&msg::V2_TYPE_UDP_PACKET_BINARY.to_be_bytes());
                            frp_core::udp_binary::encode_udp_packet_binary_socket_addr(
                                &content,
                                local_addr.as_ref(),
                                &src,
                                &mut wire_scratch,
                            )
                            .map_err(|e| {
                                frp_core::Error::Protocol(
                                    format!("encode binary UDP packet: {e}").into(),
                                )
                            })?;
                            write_v2_frame_raw(&mut w_w, V2_FRAME_TYPE_MESSAGE, 0, &wire_scratch)
                                .await?;
                            if !no_flush {
                                w_w.flush().await.map_err(|e| {
                                    frp_core::Error::Protocol(
                                        format!("flush after binary UDP packet: {e}").into(),
                                    )
                                })?;
                            }
                            Ok(())
                        };
                        let r = encode.await;
                        spare = content;
                        r
                    } else {
                        let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                            content,
                            local_addr: local_addr.take(),
                            remote_addr: Some(msg::UdpAddr {
                                // Go net.IP.String() collapses IPv4-mapped
                                // IPv6 to the dotted-quad form; mirror that
                                // on the V1 JSON path too (same normalization
                                // as the V2 binary codec, review finding C1).
                                ip: match src.ip() {
                                    std::net::IpAddr::V6(v6) => v6
                                        .to_ipv4_mapped()
                                        .map(|v4| v4.to_string())
                                        .unwrap_or_else(|| src.ip().to_string()),
                                    _ => src.ip().to_string(),
                                },
                                port: src.port(),
                                zone: String::new(),
                            }),
                        });
                        let r = if v2 {
                            write_msg_v2_with_udp_codec(
                                &mut w_w,
                                &pkt,
                                udp_codec_opt,
                                no_flush,
                                &mut wire_scratch,
                            )
                            .await
                        } else {
                            write_msg_v1(&mut w_w, &pkt).await
                        };
                        // Return the invariant values to their locals for the
                        // next packet before checking the write result.
                        if let FrpMessage::UDPPacket(p) = pkt {
                            local_addr = p.local_addr;
                            spare = p.content;
                        }
                        r
                    };
                    if let Err(e) = result {
                        debug!(proxy_name = %writer_name, error = %e,
                            "UDP work conn write failed for '{}': {}", writer_name, e);
                        break;
                    }
                }
                Err(e) => {
                    debug!(proxy_name = %writer_name, error = %e,
                        "UDP recv_from error for '{}': {}", writer_name, e);
                    break;
                }
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            debug!(proxy_name = %proxy_name, "UDP reader exited; draining then cancelling writer");
            // Best-effort signal to the writer; a closed watch channel is fine.
            let _ = cancel_tx.send(true);
            // Give the writer a bounded window to drain before we drop it.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut writer,
            )
            .await;
        }
        _ = &mut writer => {
            debug!(proxy_name = %proxy_name, "UDP writer exited; draining then cancelling reader");
            // Best-effort signal to the reader; a closed watch channel is fine.
            let _ = cancel_tx.send(true);
            // Give the reader a bounded window to drain before we drop it.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut reader,
            )
            .await;
        }
    }
}

/// Log a bridge-task panic. Bridge tasks are spawned fire-and-forget and
/// their JoinHandles deliberately dropped, so a panic used to be silently
/// swallowed by Tokio (audit round 5, MEDIUM). The RAII `ConnGuard` still
/// releases the connection slot during unwind, but the panic cause was lost
/// — `catch_unwind` at the spawn sites preserves the diagnostic.
fn log_bridge_panic(proxy_name: &str, what: &str, p: Box<dyn std::any::Any + Send>) {
    let msg = p
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("(unknown)");
    tracing::error!(
        proxy_name = %proxy_name,
        panic = %msg,
        "Bridge task panicked: {what} (proxy '{}', panic: {})",
        proxy_name,
        msg
    );
}

/// Server-side UDP work-conn read deadline (Go server/proxy/udp.go
/// `workConnReaderFn` SetReadDeadline(60s) parity, M1 audit round 3). The
/// client pings at a FIXED 30s (audit F1 — Go client/proxy/udp.go
/// heartbeatFn hardcodes 30s, no config knob; frp-rs matches), so 60s
/// without ANY frame — a Ping included — means the peer is gone or the
/// conn is half-open.
const UDP_WORK_CONN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Re-request a UDP work conn after the previous one died (M1, audit
/// round 3). Mirrors Go's udpWorker replacement loop
/// (server/proxy/udp.go:184-243): a UDP proxy needs one live work conn
/// for its lifetime, and work-conn death must not strand it until control
/// reconnect. The cancel guard lives at the call site — a proxy close or
/// control teardown must not re-request. The existence guard in
/// `handle_udp_work_conn` closes the remaining cancel-vs-send race (a
/// close that lands between the guard check here and the internal send).
async fn request_udp_work_conn_replacement(
    internal_tx: &tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
    proxy_name: &str,
    reason: &str,
) {
    if let Err(e) = internal_tx
        .send(crate::state::InternalMsg::UdpNeedsWorkConn {
            proxy_name: proxy_name.to_string(),
        })
        .await
    {
        debug!(
            proxy_name = %proxy_name,
            error = %e,
            "UDP work-conn re-request after {reason} failed for '{}': {}",
            proxy_name,
            e
        );
    }
}

/// Assign a work connection to a UDP proxy for bidirectional data forwarding.
/// Matches Go frp v0.69.1 behavior: sends StartWorkConn, then bridges
/// UDP socket ↔ work connection via UDPPacket messages.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn assign_udp_work_conn(
    work_conn: IoStream,
    proxy_name: &str,
    udp_sockets: &std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    local_addr: Option<msg::UdpAddr>,
    use_enc: bool,
    enc_key: [u8; 16],
    v2: bool,
    udp_packet_size: usize,
    bw_limiter: Option<frp_core::bandwidth::SharedBandwidthLimiter>,
    cancel: tokio_util::sync::CancellationToken,
    udp_packet_codec: String,
    // M1 (audit round 3): internal channel back to the control loop — used
    // to re-request a replacement work conn when this one dies.
    internal_tx: tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
) {
    let mut work_conn = work_conn;
    let sock = match udp_sockets.get(proxy_name) {
        Some(s) => s.clone(),
        None => {
            // Proxy closed between the pending_udp enqueue and this work
            // conn's arrival (CloseProxy removed the socket) — nothing to
            // assign to, and no re-request: the proxy is gone.
            warn!(proxy_name = %proxy_name, "UDP socket not found for proxy '{}'", proxy_name);
            return;
        }
    };
    let proxy_name = proxy_name.to_string();

    // Control is shutting down (supersession / disconnect) — do not start a
    // bridge that would immediately be cancelled anyway.
    if cancel.is_cancelled() {
        debug!(proxy_name = %proxy_name, "Control is shutting down, not starting UDP bridge for '{}'", proxy_name);
        return;
    }

    // Send StartWorkConn to tell the client which proxy to associate
    let swc = FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: proxy_name.clone(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        error: None,
        use_encryption: if use_enc { Some(true) } else { None },
        use_compression: None,
        nat_hole_sid: None,
        nat_hole_visitor_addr: None,
        sk: None,
    }));
    if v2 {
        if let Err(e) = work_conn.write_v2_frame(&swc).await {
            warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn (V2) for UDP '{}': {}", proxy_name, e);
            // M1: the fresh work conn died before the bridge could start
            // and the pending_udp entry was already consumed — re-request
            // so the proxy is not stranded.
            request_udp_work_conn_replacement(
                &internal_tx,
                &proxy_name,
                "StartWorkConn (V2) write failure",
            )
            .await;
            return;
        }
    } else if let Err(e) = work_conn.write_v1_frame(&swc).await {
        warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn for UDP '{}': {}", proxy_name, e);
        // M1: same as the V2 branch above.
        request_udp_work_conn_replacement(&internal_tx, &proxy_name, "StartWorkConn write failure")
            .await;
        return;
    }
    debug!(proxy_name = %proxy_name, "UDP work conn assigned to '{}', starting bridge supervisor", proxy_name);

    let log_proxy_name = proxy_name.clone();
    let bridge_cancel = cancel.clone();
    let req_tx = internal_tx;
    tokio::spawn(async move {
        // Await the bridge's JoinHandle instead of dropping it: if the task
        // panics, JoinError carries the panic payload (audit round 5, MEDIUM).
        // The RAII ConnGuard still releases the slot during unwind; this just
        // preserves the panic cause in the logs.
        let handle = tokio::spawn(run_udp_work_conn(
            work_conn,
            sock,
            proxy_name,
            local_addr,
            use_enc,
            enc_key,
            v2,
            udp_packet_size,
            bw_limiter,
            bridge_cancel,
            udp_packet_codec,
            UDP_WORK_CONN_READ_TIMEOUT,
        ));
        if let Err(e) = handle.await {
            if e.is_panic() {
                log_bridge_panic(&log_proxy_name, "UDP bridge", e.into_panic());
            }
        }
        // M1 (audit round 3): work-conn death (EOF / read error / 60s
        // frame silence) must not strand the UDP proxy until control
        // reconnect — Go's udpWorker loop replaces the conn
        // (server/proxy/udp.go:184-243). Re-request a replacement unless
        // the exit was a cancellation (proxy closed or control teardown:
        // the socket entry is gone, and a ReqWorkConn would dial a work
        // conn into nothing). The existence guard in handle_udp_work_conn
        // closes the remaining cancel-vs-send race.
        if !cancel.is_cancelled() {
            request_udp_work_conn_replacement(&req_tx, &log_proxy_name, "work-conn death").await;
        }
    });
}

/// Relay plain traffic between two IoStreams, preferring zero-copy splice
/// on Linux when both sides are raw TCP.
async fn relay_plain_fast(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    relay_plain_fast_inner(user_conn, work_conn, metrics).await
}

/// Linux: try splice(2) zero-copy relay when both sides are raw TCP.
#[cfg(target_os = "linux")]
async fn relay_plain_fast_inner(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    // Two-arm dispatch so the Tcp arm consumes the streams while the other
    // arm binds new mutable variables for the copy_bidirectional fallthrough.
    // try_tcp() (borrow check) then into_tcp() (owned) — no await between,
    // so the transport cannot change.
    if user_conn.try_tcp().is_some() && work_conn.try_tcp().is_some() {
        let user = user_conn
            .into_tcp()
            .expect("try_tcp confirmed raw TCP above");
        let work = work_conn
            .into_tcp()
            .expect("try_tcp confirmed raw TCP above");
        match frp_core::splice::bridge_splice(user, work).await {
            Ok((a, b)) => {
                metrics.record_traffic(a, b);
            }
            Err(e) => {
                tracing::warn!(error = %e, "splice bridge closed with error: {}", e);
            }
        }
    } else {
        // Pooled-buffer relay (P3): copy_bidirectional_with_sizes allocated
        // two fresh 32 KiB buffers per bridge call; PoolGuard recycles them
        // across connections (FRP_BRIDGE_BUF_KB still governs the size).
        match frp_core::bridge::relay_plain_pooled(user_conn, work_conn).await {
            Ok((a, b)) => {
                metrics.record_traffic(a, b);
            }
            Err(e) => {
                tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
            }
        }
    }
}

/// Non-Linux: pooled-buffer bidirectional relay (splice(2) unavailable).
#[cfg(not(target_os = "linux"))]
async fn relay_plain_fast_inner(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    match frp_core::bridge::relay_plain_pooled(user_conn, work_conn).await {
        Ok((a, b)) => {
            metrics.record_traffic(a, b);
        }
        Err(e) => {
            tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
        }
    }
}

/// Type-erased user-side bridge halves: erasing the per-transport types lets
/// `bridge_encrypted` & friends share one monomorphization, and lets the
/// visitor-segment Cipher wrapper (`CipherReader`/`CipherWriter`) and the
/// plain boxed halves be handled uniformly.
type UserBridgeHalves = (
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
);

/// Split the visitor (user) conn into bridge halves, wrapping them in
/// `CipherReader`/`CipherWriter` with `derive_key(sk)` when visitor-segment
/// encryption is enabled (`visitor_enc_key = Some(key)`) and in
/// `SnappyStreamReader`/`SnappyStreamWriter` when visitor-segment compression
/// is enabled (`visitor_comp`).
///
/// Wire order matches Go frp's `VisitorManager.NewConn` (`WithEncryption`
/// outer, `WithCompression` inner): write plaintext → snappy → CFB → socket,
/// so the enc+comp wrapper is `SnappyStreamReader::new(CipherReader::new(...))`
/// / `SnappyStreamWriter::new(CipherWriter::new(...))`. A compression-only
/// visitor wraps the raw halves in Snappy directly.
///
/// When the `compression` feature is disabled, `SnappyStream*` degrades to a
/// transparent passthrough, so a compression-only visitor bridges plaintext
/// (same behavior as the provider-segment `compress_chunk_into` passthrough).
///
/// Returns `Err` (with a warn-worthy message) only when the underlying
/// transport cannot be split (same guard as `split_work_conn_halves`).
fn split_user_side(
    visitor_enc_key: Option<[u8; 16]>,
    visitor_comp: bool,
    user_conn: IoStream,
) -> Result<UserBridgeHalves, &'static str> {
    let (u_r, u_w) = split_work_conn_halves(user_conn)?;
    let (u_r, u_w): UserBridgeHalves = if let Some(key) = visitor_enc_key {
        (
            Box::new(CipherReader::new(u_r, key)),
            // Audit B2: IV-generation failure is an error, not an abort.
            Box::new(CipherWriter::new(u_w, key).map_err(|_| "OS random generator failed")?),
        )
    } else {
        (u_r, u_w)
    };
    if visitor_comp {
        Ok((
            Box::new(SnappyStreamReader::new(u_r)),
            Box::new(SnappyStreamWriter::new(u_w)),
        ))
    } else {
        Ok((u_r, u_w))
    }
}

/// Compute the visitor-segment encryption key from the proxy's `sk`
/// (`derive_key(sk)`), when the visitor declared `use_encryption`. Empty sk is
/// treated as "no key": we warn and bridge plaintext (robustness over exact
/// Go parity — Go would PBKDF2 an empty string into a weak key). Shared by the
/// byte-stream and SUDP message bridges so the logic (and its warn) cannot
/// drift apart (audit #12).
fn visitor_encryption_key(
    proxy_info: Option<&std::sync::Arc<crate::proxy::ProxyInfo>>,
    proxy_name: &str,
    use_encryption: bool,
) -> Option<[u8; 16]> {
    if !use_encryption {
        return None;
    }
    match proxy_info
        .and_then(|p| p.sk.as_deref())
        .filter(|s| !s.is_empty())
    {
        Some(sk) => Some(derive_key(sk)),
        None => {
            warn!(
                proxy_name = %proxy_name,
                "visitor declared use_encryption but proxy '{}' has no secret_key; \
                 bridging visitor segment in plaintext",
                proxy_name
            );
            None
        }
    }
}

/// Build a `SocketAddr` for `remote` without allocating, when the address is a
/// plain IPv4/IPv6 (no zone). Returns `None` when the ip does not parse or the
/// address carries an IPv6 scope zone — the caller falls back to the string
/// form in that case. Hot-path helper for the UDP reader (audit #14a): avoids
/// a `String` alloc + reparse per datagram in the common case.
fn udp_dest_socket_addr(remote: &msg::UdpAddr) -> Option<std::net::SocketAddr> {
    if !remote.zone.is_empty() {
        return None;
    }
    let ip: std::net::IpAddr = remote.ip.parse().ok()?;
    Some(std::net::SocketAddr::new(ip, remote.port))
}

/// Checked split of the user-side (visitor-segment) conn: calls `split_user_side`
/// and turns the `Err(&'static str)` into a `warn!`-and-None, so call sites use
/// `let Some((u_r, u_w)) = try_split_user_side(...) else { return };` instead of
/// repeating the five-line warn-return match (audit #12 — the pattern drifted
/// across SUDP and byte-stream bridges).
fn try_split_user_side(
    visitor_enc_key: Option<[u8; 16]>,
    visitor_comp: bool,
    user_conn: IoStream,
) -> Option<UserBridgeHalves> {
    match split_user_side(visitor_enc_key, visitor_comp, user_conn) {
        Ok(pair) => Some(pair),
        Err(msg) => {
            warn!("{msg}");
            None
        }
    }
}

/// Checked split of the work-conn halves: turns the `Err(&'static str)` into a
/// `warn!`-and-None (audit #12, dedup of the repeated warn-return match).
fn try_split_work_halves(
    work_conn: IoStream,
) -> Option<(
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
)> {
    match split_work_conn_halves(work_conn) {
        Ok(pair) => Some(pair),
        Err(msg) => {
            warn!("{msg}");
            None
        }
    }
}

/// Holds split user-side halves as one `AsyncRead`+`AsyncWrite` object so the
/// XTCP STCP fallback can keep its `copy_bidirectional` semantics via the
/// pooled relay `relay_plain_pooled` (both directions run to completion; the
/// work side is only shut down after the full bidirectional copy — avoids
/// the premature-FIN race that a join-of-two-halves bridge would
/// reintroduce).
struct UserSide<R, W> {
    r: R,
    w: W,
}

impl<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> AsyncRead for UserSide<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for UserSide<R, W>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.w).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

/// Bridge a user connection to a work connection for one proxy.
///
/// Runs inside the spawned bridge task. Extracted from `assign_work_to_proxy`
/// so the spawn site is a plain call and the bridge logic lives in its own
/// state machine instead of a 54 KiB inline closure.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
async fn run_work_bridge(
    work_conn: IoStream,
    req: PendingRequest,
    proxy_info: Option<Arc<crate::proxy::ProxyInfo>>,
    encryption_key: [u8; 16],
    metrics: Arc<frp_core::metrics::ProxyMetrics>,
    header_timeout: Option<std::time::Duration>,
    state: Arc<AppState>,
    v2: bool,
) {
    let _guard = ConnGuard::new(metrics.clone());
    let _drain = ActiveGuard::new(&state);

    // --- Encryption decisions (Go frp three-stage model) ---
    // Provider segment (work conn): token-based encryption from the proxy
    // config (`req.use_encryption`). SUDP previously forced plaintext here —
    // the per-packet transform model is now aligned with Go's stream
    // encryption, so SUDP honors the provider-segment encryption too.
    // (SUDP compression stays off — see `comp_key` below.)
    let is_sudp = proxy_info.as_ref().is_some_and(|p| p.proxy_type == "sudp");
    let use_enc = req.use_encryption;

    // SUDP data plane: when the visitor and provider segments use the same
    // wire protocol + packet codec, the byte-stream bridge below is
    // correct (Go `libio.Join`); when they differ, Go frp v0.71.0 routes
    // the pair through `joinSUDPMessageBridge`, which decodes and re-encodes
    // every packet on each side. The mismatch happens during upgrades —
    // e.g. a V1/JSON visitor talking to a V2/binary provider — and a plain
    // byte-stream relay would make the provider misparse the visitor's
    // frames ("unexpected V2 frame type"). Route mismatches to the
    // message-level bridge; identical encodings keep the zero-copy path.
    if is_sudp {
        let provider_codec = proxy_info
            .as_ref()
            .map(|p| p.udp_packet_codec.clone())
            .unwrap_or_default();
        let visitor_codec = req.visitor_udp_packet_codec.as_str();
        let mixed = normalize_wire_protocol(v2) != normalize_wire_protocol(req.visitor_v2)
            || provider_codec != visitor_codec;
        if mixed {
            tracing::info!(
                proxy_name = %req.proxy_name,
                provider_wire = %normalize_wire_protocol(v2),
                provider_codec = %provider_codec,
                visitor_wire = %normalize_wire_protocol(req.visitor_v2),
                visitor_codec = %visitor_codec,
                "bridging mixed SUDP packet encodings (message-level bridge)"
            );
            return run_sudp_message_bridge(
                work_conn,
                req,
                proxy_info,
                encryption_key,
                metrics,
                state,
                v2,
                &provider_codec,
            )
            .await;
        }
    }

    // Visitor segment (user conn): sk-based encryption when the visitor
    // declared `use_encryption` in NewVisitorConn (Go three-stage model,
    // stage 1). The visitor conn is wrapped in CipherReader/CipherWriter with
    // `derive_key(sk)` and only then joined to the provider segment
    // (token encryption or plaintext) — two nested layers, mirroring Go's
    // three-stage model.
    //
    // Empty sk: Go frp would still PBKDF2 an empty string and encrypt (the
    // key is just weak); we warn and bridge plaintext to keep the tunnel
    // usable (robustness over exact parity).
    let visitor_enc_key = visitor_encryption_key(
        proxy_info.as_ref(),
        &req.proxy_name,
        req.visitor_use_encryption,
    );

    // Whether visitor-segment encryption/compression is on. The user conn is
    // NOT split here — each bridge branch below calls
    // `split_user_side(visitor_enc_key, visitor_comp, req.user_conn)`, which
    // wraps the halves in CipherReader/CipherWriter (when the key is present)
    // and SnappyStreamReader/SnappyStreamWriter (when compression is on),
    // keeping the plain IoStream available for the relay_plain_fast splice
    // path (only taken when neither wrapping applies). CipherWriter::poll_flush
    // already sends the IV eagerly, and the first write to the user side
    // carries it, so no manual IV flush is needed.
    let visitor_encrypted = visitor_enc_key.is_some();
    if visitor_encrypted {
        debug!(
            proxy_name = %req.proxy_name,
            "Visitor-segment encryption on for proxy '{}' (derive_key(sk))", req.proxy_name
        );
    }

    // Visitor-segment compression: from the visitor's NewVisitorConn
    // use_compression declaration (`[[visitors]] transport.useCompression`),
    // Go 三段式第 1 段. Applied in `split_user_side` below — Snappy stream
    // inside the CFB layer when visitor-segment encryption is also on.
    let visitor_comp = req.visitor_use_compression;
    if visitor_comp {
        debug!(
            proxy_name = %req.proxy_name,
            "Visitor-segment compression on for proxy '{}'", req.proxy_name
        );
    }

    // The per-proxy SHARED bandwidth limiter (F1/F2): created once at proxy
    // registration (build_proxy_info) when mode == "server"/"both" and a
    // rate is set; one bucket covers BOTH directions and all concurrent
    // connections (Go frp v0.71.0 single-`rate.Limiter` parity — the mode
    // gate lives at registration, not per bridge call). "client"/empty mode
    // is the client's responsibility (Go: server creates a limiter only in
    // "server" mode).
    let bw_limiter = proxy_info
        .as_ref()
        .and_then(|p| p.bandwidth_limiter.clone());

    // The response-header injector runs for EVERY plain-HTTP non-CONNECT
    // leg (`proxy_type == "http"`, NOT `starts_with("http")`); clone the
    // HashMap at bridge time instead of deep-cloning it into every pending
    // request at enqueue time. Uses the resolved metadata (bridge-time
    // re-fetch when the enqueue-time snapshot was None).
    //
    // The empty-map case is deliberate: when
    // `response_headers` is not configured the injector carries NO headers
    // and is a pure deadline-only pass-through — splice no-ops over the
    // empty map and the response bytes are byte-identical to the
    // injector-less bridge, with ONE deliberate wire mutation (round-16):
    // a final 204/304 head has its Content-Length lines dropped at the
    // splice (Go's write-layer suppression — see the inject branch above),
    // so exactly those two statuses differ from the raw bridge by design.
    // But the leg still gets Go
    // ResponseHeaderTimeout parity: the injector's absolute deadline
    // (armed at construction, never extended by interim 1xx) must run for
    // http non-CONNECT legs even with no headers configured — Go's
    // ReverseProxy arms ResponseHeaderTimeoutS from the transport config,
    // independent of any ModifyResponse. Routing these legs through the
    // injector also removes the duplicate one-shot first-read timeout in
    // the frp-core bridge (see the injector arms below).
    //
    // The two exclusions mirror Go v0.71.0 exactly:
    //   * https tunnels: HTTPSProxyConfig (pkg/config/v1/proxy.go:369) has
    //     no ResponseHeaders field — a wire-declared response_headers on an
    //     https proxy is silently dropped by Go, and the bridge here sees
    //     raw TLS bytes anyway (injecting would corrupt the ciphertext).
    //   * CONNECT tunnels on an http proxy: Go's connectHandler joins raw
    //     (http.go:282-285) — no host rewrite, no ModifyResponse, no
    //     ResponseHeaderTimeout — so the injector must not splice into the
    //     tunnel stream nor arm a head deadline on it. `request_is_connect`
    //     is set by the two vhost HTTP send sites (h1 + h2c) and rides the
    //     PendingRequest, including across run_id group forwarders.
    let injector_headers = proxy_info
        .as_ref()
        .filter(|p| p.proxy_type == "http" && !req.request_is_connect)
        .map(|p| p.response_headers.clone());

    // For encrypted bridges, pre_read bytes are passed into bridge_encrypted
    // which writes them through the CipherWriter (matching Go frp streaming CFB).
    if use_enc {
        let key = encryption_key;
        let Some((u_r, u_w)) = try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
        else {
            return;
        };
        // One boxed split for every IoStream variant — a single
        // monomorphization of bridge_encrypted instead of one per variant.
        let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
            return;
        };
        // SUDP provider-segment compression stays off in BOTH bridge modes:
        // bridge_encrypted's Snappy stream would be misread by the provider's
        // frame reader as a V1 header (sNaPpY magic → "invalid V1 msg length").
        // Go's streaming compression model for the per-packet SUDP plane is
        // not unified here yet — this change is encryption-focused.
        let comp_key = req.use_compression && !is_sudp;
        if let Some(headers) = injector_headers {
            // Response-header injection MUST observe plaintext: the work
            // conn carries AES-128-CFB ciphertext, so decrypt FIRST via
            // CipherReader, THEN wrap in the injector. Audit round-14 A1:
            // with use_compression the decrypted stream is STILL
            // Snappy-encoded — the bridge's own decompressor runs below any
            // reader passed as work_r — so a `SnappyStreamReader` goes
            // between the CipherReader and the injector, and the
            // `_decompressed_read` bridge variant skips its read-side decode
            // (the user→work write side keeps compressing). Go parity: frp's
            // vhost ReverseProxy/ModifyResponse sits ABOVE the transport's
            // snappy layer and always injects into plaintext. Without this a
            // compressed http proxy + response_headers would splice into
            // Snappy bytes (corrupt stream) or silently never inject.
            let decrypted: Box<dyn AsyncRead + Unpin + Send> =
                Box::new(CipherReader::new(w_r, key));
            let injector_r: Box<dyn AsyncRead + Unpin + Send> = if comp_key {
                Box::new(frp_core::snappy_stream::SnappyStreamReader::new(decrypted))
            } else {
                decrypted
            };
            let injector = ResponseHeaderInjector::new(injector_r, headers, header_timeout);
            // The injector owns the absolute response-head deadline (armed
            // at construction above); the frp-core bridge gets NO one-shot
            // header_timeout here — a duplicate would consume on the first
            // read (an interim 100 already served raw would burn it, and a
            // backend stalling after interim bytes would park the bridge
            // task + conns forever). The injector's TimedOut errors through
            // the bridge Err arm into the Go-shaped 504.
            frp_core::bridge::bridge_encrypted_decompressed_read(
                u_r,
                u_w,
                injector,
                w_w,
                &key,
                comp_key,
                req.pre_read,
                bw_limiter.as_ref(),
                Some(metrics.clone()),
            )
            .await;
            // Matches the original inline closure: the injector path skips
            // the "bridge completed" debug below.
            return;
        }
        frp_core::bridge::bridge_encrypted(
            u_r,
            u_w,
            w_r,
            w_w,
            &key,
            comp_key,
            req.pre_read,
            bw_limiter.as_ref(),
            Some(metrics.clone()),
            false,
        )
        .await;
    } else {
        // Pass VHost pre-read bytes through bridge_plain so the bridge
        // can coordinate: write pre_read first, then skip work_w shutdown
        // to let the backend response flow back to the user.
        let bridge_pre_read = req.pre_read;
        // SUDP: compression stays forced off — bridge_plain wraps the stream
        // in Snappy when comp_key is set, which the provider's plaintext
        // read_msg_v1 would misread as a V1 frame header (sNaPpY magic →
        // "invalid V1 msg length"). Go's streaming compression model for the
        // per-packet SUDP plane is not unified here yet; this change is
        // encryption-focused, so SUDP compression remains off (only the
        // provider-segment encryption restriction was lifted above).
        let comp_key = req.use_compression && !is_sudp;

        // XTCP STCP fallback: keep copy_bidirectional semantics for both
        // directions — bridge_plain's join! pattern drops the work writer
        // (sending FIN) as soon as the user reader reaches EOF. For STCP
        // fallback the visitor's test client half-closes after sending data,
        // so the server sees EOF on the user side ~60ms before the provider
        // starts its bridge. The premature FIN on the work connection races
        // with the provider's copy_bidirectional startup and produces
        // ECONNRESET on VPS. relay_plain_pooled avoids this exactly like
        // copy_bidirectional: both directions run to completion within the
        // same function, and the work side is only shut down after the full
        // bidirectional copy finishes (pooled buffers — audit round-8 P1).
        //
        // Visitor-segment encryption/compression (if on) split the user conn
        // into wrapped halves (via `split_user_side`), re-combined via
        // `UserSide` for the same relay call.
        if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            // Pooled-buffer relay (audit round-8 P1): relay_plain_pooled has
            // EXACTLY the copy_bidirectional semantics this arm's comment
            // above requires — both directions run to completion and the
            // work side is only shut down after the full bidirectional copy
            // (FIN-propagation, no premature-FIN race), without the
            // per-conn buffer pair. Buffer size stays FRP_BRIDGE_BUF_KB
            // (the pool's BUFFER_SIZE governs the XTCP STCP fallback path).
            let user_side = UserSide { r: u_r, w: u_w };
            match frp_core::bridge::relay_plain_pooled(user_side, work_conn).await {
                Ok((a, b)) => {
                    metrics.record_traffic(a, b);
                }
                Err(e) => {
                    debug!(error = %e, "XTCP STCP fallback bridge closed: {}", e);
                }
            }
        } else if bw_limiter.is_some() {
            // Bandwidth limiting active: use rate-limited plain bridge.
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
                return;
            };
            if let Some(headers) = injector_headers {
                // A1: decompress the work stream before the injector when the
                // proxy uses compression (see the encrypted arm above).
                let injector_r: Box<dyn AsyncRead + Unpin + Send> = if comp_key {
                    Box::new(frp_core::snappy_stream::SnappyStreamReader::new(w_r))
                } else {
                    w_r
                };
                let injector = ResponseHeaderInjector::new(injector_r, headers, header_timeout);
                // No one-shot header_timeout to the bridge: the injector
                // owns the absolute response-head deadline (see the
                // encrypted arm above).
                frp_core::bridge::bridge_plain_rate_limited_decompressed_read(
                    u_r,
                    u_w,
                    injector,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    bw_limiter.as_ref(),
                    Some(metrics.clone()),
                )
                .await;
            } else {
                frp_core::bridge::bridge_plain_rate_limited(
                    u_r,
                    u_w,
                    w_r,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    bw_limiter.as_ref(),
                    Some(metrics.clone()),
                )
                .await;
            }
        } else if !comp_key
            && bridge_pre_read.is_empty()
            && injector_headers.is_none()
            && !visitor_encrypted
            && !visitor_comp
        {
            // Fast path: pure plain relay with no compression, no VHost
            // pre-read, no header injection, and no visitor-segment
            // encryption/compression (splice needs the raw IoStream; visitor
            // wrapping already split it into wrapped halves). On Linux, try
            // zero-copy splice for Tcp-to-Tcp; otherwise use
            // copy_bidirectional.
            relay_plain_fast(req.user_conn, work_conn, &metrics).await;
        } else {
            // Slow path: compression, VHost pre-read, header injection, or
            // visitor-segment encryption.
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
                return;
            };
            if let Some(headers) = injector_headers {
                // A1: decompress the work stream before the injector when the
                // proxy uses compression (see the encrypted arm above).
                let injector_r: Box<dyn AsyncRead + Unpin + Send> = if comp_key {
                    Box::new(frp_core::snappy_stream::SnappyStreamReader::new(w_r))
                } else {
                    w_r
                };
                let injector = ResponseHeaderInjector::new(injector_r, headers, header_timeout);
                // No one-shot header_timeout to the bridge: the injector
                // owns the absolute response-head deadline (see the
                // encrypted arm above).
                frp_core::bridge::bridge_plain_decompressed_read(
                    u_r,
                    u_w,
                    injector,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    Some(metrics.clone()),
                )
                .await;
            } else {
                frp_core::bridge::bridge_plain(
                    u_r,
                    u_w,
                    w_r,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    Some(metrics.clone()),
                )
                .await;
            }
        }
    }
    debug!(proxy_name = %req.proxy_name, "Proxy '{}' bridge completed", req.proxy_name);
}

/// Go frp v0.71.0 `normalizeWireProtocol`: "" and "v1" both normalize to
/// "v1"; only "v2" stays "v2".
fn normalize_wire_protocol(v2: bool) -> &'static str {
    if v2 {
        "v2"
    } else {
        "v1"
    }
}

/// Message-level SUDP bridge (Go frp v0.71.0 `joinSUDPMessageBridge`).
///
/// Used when the visitor segment and the provider segment negotiate
/// different packet encodings (e.g. a V1/JSON visitor talking to a
/// V2/binary provider during an upgrade). A plain byte-stream relay would
/// make the provider misparse the visitor's frames as its own protocol
/// ("unexpected V2 frame type"), so every `UDPPacket` is decoded on the
/// source side and re-encoded on the destination side.
///
/// Direction semantics match Go:
/// - visitor → provider: `UDPPacket` forwarded, `Ping` dropped
///   (`bridgeSUDPVisitorToProxy`);
/// - provider → visitor: `UDPPacket` forwarded, `Ping` forwarded
///   (`bridgeSUDPProxyToVisitor`).
///
/// `Pong` is ignored on both sides (frp-rs UDP data planes treat
/// Ping/Pong as keepalive and never forward them); any other message type
/// is a protocol violation and closes the pair.
#[allow(clippy::too_many_arguments)]
async fn run_sudp_message_bridge(
    work_conn: IoStream,
    req: PendingRequest,
    proxy_info: Option<Arc<crate::proxy::ProxyInfo>>,
    encryption_key: [u8; 16],
    metrics: Arc<frp_core::metrics::ProxyMetrics>,
    state: Arc<AppState>,
    provider_v2: bool,
    provider_codec: &str,
) {
    let _guard = ConnGuard::new(metrics.clone());
    let _drain = ActiveGuard::new(&state);
    let visitor_v2 = req.visitor_v2;
    let visitor_codec = req.visitor_udp_packet_codec.as_str();

    // Visitor-segment encryption/compression (Go 三段式第 1 段): identical
    // decision to the byte-stream bridge — sk-derived key when the visitor
    let visitor_enc_key = visitor_encryption_key(
        proxy_info.as_ref(),
        &req.proxy_name,
        req.visitor_use_encryption,
    );
    let Some((v_r, mut v_w)) =
        try_split_user_side(visitor_enc_key, req.visitor_use_compression, req.user_conn)
    else {
        return;
    };
    // Provider-segment encryption (token-derived key) wraps the work halves
    // before the message loop, matching the byte-stream bridge.
    let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
        return;
    };
    let w_r: frp_core::transport::BoxedReadHalf = if req.use_encryption {
        Box::new(CipherReader::new(w_r, encryption_key))
    } else {
        w_r
    };
    let mut w_w: frp_core::transport::BoxedWriteHalf = if req.use_encryption {
        // Audit B2: OS-RNG failure (IV generation) ends this bridge instead
        // of aborting the process.
        match CipherWriter::new(w_w, encryption_key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::warn!(error = %e, "udp bridge: IV generation failed");
                return;
            }
        }
    } else {
        w_w
    };
    // Frame reads issue two read_exact calls per message; buffer them.
    let mut v_r = tokio::io::BufReader::with_capacity(16 * 1024, v_r);
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);

    let visitor_codec_opt = if visitor_codec.is_empty() {
        None
    } else {
        Some(visitor_codec)
    };
    let provider_codec_opt = if provider_codec.is_empty() {
        None
    } else {
        Some(provider_codec)
    };
    let proxy_name = req.proxy_name.clone();

    // Direction 1: visitor → provider. Ping is dropped (Go
    // bridgeSUDPVisitorToProxy). Traffic is accumulated locally and flushed
    // to metrics periodically so the live dashboard/otel counters are not
    // frozen at 0 for the whole (possibly long-lived) bridge — and so an
    // aborted/joined-interrupted task does not lose the session's bytes or
    // dump them wholesale into the teardown day's bucket (#4).
    const SUDP_TRAFFIC_REPORT_EVERY: u32 = 64;
    let visitor_to_provider = async {
        // Reusable payload buffer for the V2 UDP read path.
        let mut scratch: Vec<u8> = Vec::new();
        // Reusable binary-codec wire buffer (write side; `scratch` above is
        // the read side).
        let mut wire_scratch: Vec<u8> = Vec::new();
        let mut fwd_in: u64 = 0;
        let mut report = 0u32;
        loop {
            let read = if visitor_v2 {
                read_msg_v2_with_udp_codec(&mut v_r, visitor_codec_opt, &mut scratch).await
            } else {
                read_msg_v1(&mut v_r).await
            };
            let msg = match read {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        proxy_name = %proxy_name,
                        error = %e,
                        "SUDP message bridge: visitor read closed: {}",
                        e
                    );
                    break;
                }
            };
            match &msg {
                FrpMessage::UDPPacket(pkt) => {
                    fwd_in += pkt.content.len() as u64;
                }
                FrpMessage::Ping(_) | FrpMessage::Pong(_) => {
                    // Go drops SUDP pings on the visitor→proxy leg.
                    continue;
                }
                other => {
                    warn!(
                        proxy_name = %proxy_name,
                        type_byte = %other.v1_type_byte(),
                        "SUDP message bridge: unexpected visitor message 0x{:02x}",
                        other.v1_type_byte()
                    );
                    break;
                }
            }
            let write = if provider_v2 {
                write_msg_v2_with_udp_codec(
                    &mut w_w,
                    &msg,
                    provider_codec_opt,
                    false,
                    &mut wire_scratch,
                )
                .await
            } else {
                write_msg_v1(&mut w_w, &msg).await
            };
            if let Err(e) = write {
                debug!(
                    proxy_name = %proxy_name,
                    error = %e,
                    "SUDP message bridge: provider write failed: {}",
                    e
                );
                break;
            }
            report += 1;
            if report >= SUDP_TRAFFIC_REPORT_EVERY {
                metrics.record_traffic(fwd_in, 0);
                fwd_in = 0;
                report = 0;
            }
        }
        metrics.record_traffic(fwd_in, 0);
    };

    // Direction 2: provider → visitor. Ping is forwarded (Go
    // bridgeSUDPProxyToVisitor). Traffic is accumulated locally and flushed
    // periodically (see direction 1's rationale: live counters, no loss on
    // abort, no single-day dump).
    let provider_to_visitor = async {
        // Reusable payload buffer for the V2 UDP read path (own buffer; the
        // two directions run concurrently via tokio::join!).
        let mut scratch: Vec<u8> = Vec::new();
        // Reusable binary-codec wire buffer (write side; `scratch` above is
        // the read side).
        let mut wire_scratch: Vec<u8> = Vec::new();
        let mut fwd_out: u64 = 0;
        let mut report = 0u32;
        loop {
            let read = if provider_v2 {
                read_msg_v2_with_udp_codec(&mut w_r, provider_codec_opt, &mut scratch).await
            } else {
                read_msg_v1(&mut w_r).await
            };
            let msg = match read {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        proxy_name = %proxy_name,
                        error = %e,
                        "SUDP message bridge: provider read closed: {}",
                        e
                    );
                    break;
                }
            };
            match &msg {
                FrpMessage::UDPPacket(pkt) => {
                    fwd_out += pkt.content.len() as u64;
                }
                FrpMessage::Ping(_) => {
                    // Go forwards SUDP pings provider→visitor
                    // (bridgeSUDPProxyToVisitor).
                }
                FrpMessage::Pong(_) => {
                    // Pong is never forwarded (Go has no Pong in this
                    // direction; frp-rs data planes treat Ping/Pong as
                    // keepalive and ignore them).
                    continue;
                }
                other => {
                    warn!(
                        proxy_name = %proxy_name,
                        type_byte = %other.v1_type_byte(),
                        "SUDP message bridge: unexpected provider message 0x{:02x}",
                        other.v1_type_byte()
                    );
                    break;
                }
            }
            let write = if visitor_v2 {
                write_msg_v2_with_udp_codec(
                    &mut v_w,
                    &msg,
                    visitor_codec_opt,
                    false,
                    &mut wire_scratch,
                )
                .await
            } else {
                write_msg_v1(&mut v_w, &msg).await
            };
            if let Err(e) = write {
                debug!(
                    proxy_name = %proxy_name,
                    error = %e,
                    "SUDP message bridge: visitor write failed: {}",
                    e
                );
                break;
            }
            report += 1;
            if report >= SUDP_TRAFFIC_REPORT_EVERY {
                metrics.record_traffic(0, fwd_out);
                fwd_out = 0;
                report = 0;
            }
        }
        metrics.record_traffic(0, fwd_out);
    };

    tokio::join!(visitor_to_provider, provider_to_visitor);
    debug!(proxy_name = %proxy_name, "SUDP message bridge completed");
}

/// The backend response-head deadline (seconds) for a `proxy_type == "http"`
/// non-CONNECT leg — Go frp v0.71.0 `VhostHTTPTimeout` →
/// `httputil.ReverseProxy.ResponseHeaderTimeoutS`. Pure wrapper over
/// [`crate::vhost::clamp_vhost_timeout`] so the floor/cap semantics have a
/// unit pin without spawning a bridge: a `<= 0` config floors to 60s — Go's
/// own `NewHTTPReverseProxy` does this floor (pkg/util/vhost/http.go:50-52:
/// `if option.ResponseHeaderTimeoutS <= 0 { option.ResponseHeaderTimeoutS =
/// 60 }`), so an unset value is 60s, never "no deadline" — and positive
/// values cap at 24h (Rust-only hardening against hostile huge configs; Go
/// has no cap).
fn http_leg_head_deadline(vhost_http_timeout_secs: u64) -> u64 {
    crate::vhost::clamp_vhost_timeout(vhost_http_timeout_secs)
}

/// Assign `req` to `work_conn`, starting the bridge.
///
/// Returns `Ok(())` once the bridge task is spawned (work_conn and req are
/// consumed), or `Err(req)` if the StartWorkConn write failed — the work
/// conn is dead and the request (with its user conn) is returned so the
/// caller can retry it against a fresh work conn instead of dropping the
/// user connection (audit fix: dead pooled work conns used to fail the user
/// conn with no retry). Boxed: the request is large and this error is cold
/// (one alloc on the retry path; keeps `result_large_err` quiet).
pub(crate) async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
    state: Arc<AppState>,
    v2: bool,
    bridge_cancel: tokio_util::sync::CancellationToken,
) -> Result<(), Box<PendingRequest>> {
    // Extract peer address from user connection for PROXY protocol support
    let (src_addr, src_port) = req
        .user_conn
        .try_tcp()
        .and_then(|s| s.peer_addr().ok())
        .map(|a| (a.ip().to_string(), a.port()))
        .unwrap_or_default();

    // Proxy metadata is carried in the request (fetched once by the
    // dispatcher). When the snapshot is None — the STCP/XTCP
    // visitor-before-provider-registration race, where the request was
    // enqueued before the proxy was visible to the dispatcher — re-fetch
    // from the proxy map at bridge time (the old behavior), so the bridge
    // uses the now-registered proxy's metadata instead of empty
    // local_addr/dst_port. Clone the Arc (cheap refcount bump) so the
    // borrow does not block moving `req` into the spawned bridge task
    // below.
    let proxy_info = match req.proxy_info.clone() {
        Some(info) => Some(info),
        None => state.proxy_manager.get(&req.proxy_name).await,
    };
    // DstAddr/DstPort family semantics (Go v0.71.0): only the HTTP
    // reverse-proxy family sends NONE. Go wires its vhost http CreateConnFn
    // to `GetRealConn(rAddr, nil)` (server/proxy/http.go:64/114-122) — the
    // conn's remote address survives as src, the local endpoint is dropped,
    // and Go frpc falls back to 127.0.0.1:0 for the PROXY-protocol
    // destination pair (client/proxy/proxy.go:179-211:
    // `if m.DstAddr == "" { m.DstAddr = "127.0.0.1" }` — round-12 audit
    // B1: the pre-round-12 code reported the real vhost accept addr here,
    // shape-differing from Go on every http-type leg). Every OTHER raw
    // user-conn leg (tcp + https + tcpmux + stcp) reports the server-side
    // endpoint the user actually dialed (Go `handleUserTCPConnection` →
    // `GetWorkConnFromPool(userConn.RemoteAddr(), userConn.LocalAddr())`,
    // server/proxy/proxy.go:288, dst fields at 178-186), NOT the
    // client-declared local service (round-11 audit F1: local_str is never
    // set by Go frpc and is the wrong semantic even when set — the
    // frpc-side local service is not the address the user's connection
    // targeted on frps). HTTPS vhost legs reach here as raw passthrough
    // conns (`run_vhost_https_listener` enqueues the un-wrapped
    // `IoStream::Tcp` — frps only peeks the ClientHello SNI, vhost.rs), so
    // they report their real local addr exactly like Go's https handler.
    // The `local_addr` fallback below stays as the STCP/XTCP
    // visitor-before-registration safety net and for any future wrapped
    // conn; it is NOT a Go-parity path.
    let user_local = req.user_conn.try_tcp().and_then(|s| s.local_addr().ok());
    let http_reverse_proxy_leg = proxy_info.as_ref().is_some_and(|p| p.proxy_type == "http");
    let dst_addr = if http_reverse_proxy_leg {
        String::new()
    } else {
        user_local
            .map(|a| a.ip().to_string())
            .or_else(|| proxy_info.as_ref().and_then(|p| p.local_addr.clone()))
            .unwrap_or_default()
    };
    let dst_port = if http_reverse_proxy_leg {
        0
    } else {
        user_local
            .map(|a| a.port())
            .or_else(|| proxy_info.as_ref().and_then(|p| p.remote_port))
            .unwrap_or(0)
    };

    let swc = build_start_work_conn(&req, &src_addr, src_port, &dst_addr, dst_port);

    let write_result = if v2 {
        work_conn.write_v2_frame(&swc).await
    } else {
        work_conn.write_v1_frame(&swc).await
    };

    if let Err(e) = write_result {
        warn!(error = %e, "Failed to send StartWorkConn: {}", e);
        // The work conn is dead (e.g. the client closed it while pooled).
        // Return the request so the caller can re-enqueue it against a
        // fresh work conn instead of failing the user connection.
        return Err(Box::new(req));
    }

    // Flush StartWorkConn to wire before bridge data. KcpStream::poll_flush
    // now triggers immediate force_flush (update + drain + FEC encode + UDP send)
    // in the KCP driver, so Go frpc receives StartWorkConn as a separate KCP
    // output before bridge data arrives.
    if let Err(e) = work_conn.flush().await {
        warn!(error = %e, "Failed to flush StartWorkConn: {}", e);
    }

    // For XTCP STCP fallback: send a dummy NatHoleSid frame with
    // empty sid after StartWorkConn for Go frpc compatibility.
    // Go frpc's InWorkConn expects either an embedded nat_hole_sid in
    // StartWorkConn JSON (newer frp) or a separate NatHoleSid frame
    // immediately after StartWorkConn (Go frp v0.69.1). Our Rust frpc
    // provider's byte-peek (V1) / V2 frame read handles both formats.
    // The copy_bidirectional-semantics relay (used for XTCP STCP fallback
    // below) doesn't send a premature FIN, so the provider can safely
    // consume this frame without the old ECONNRESET race.
    // V2-aware: use V2 or V1 framing based on protocol version.
    if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
        let dummy = FrpMessage::NatHoleSid(msg::NatHoleSid::default());
        let write_result = if v2 {
            work_conn.write_v2_frame(&dummy).await
        } else {
            work_conn.write_v1_frame(&dummy).await
        };
        // A failure to deliver the empty NatHoleSid marker means the Go frpc
        // provider may not start its XTCP STCP fallback bridge; log it (unlike
        // the StartWorkConn write above, this one didn't name the failing frame).
        if let Err(e) = write_result {
            debug!(
                proxy_name = %req.proxy_name,
                error = %e,
                "failed to write dummy NatHoleSid frame to work conn: {e}"
            );
        }
    }

    debug!(proxy_name = %req.proxy_name, proxy_type = %proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""), "Bridging user conn to work conn for proxy '{}' (type={})", req.proxy_name, proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""));

    let proxy_name = req.proxy_name.clone();
    let metrics = state.proxy_metrics.get_or_create(&proxy_name).await;

    // HTTP vhost backend response-header timeout (Go frp compat:
    // VhostHTTPTimeout drives httputil.ReverseProxy.ResponseHeaderTimeoutS).
    // Exactly `proxy_type == "http"` on a NON-CONNECT request — the two
    // gates mirror Go v0.71.0's vhost architecture:
    //   * CONNECT: http.go:229-234 + 282-285 route CONNECT to
    //     connectHandler, which hijacks the conn and joins raw — the
    //     ReverseProxy transport (and with it ResponseHeaderTimeout) never
    //     arms, and the server never answers 504 on a silent backend.
    //   * https tunnels: the HTTPS Muxer's registryRouter serves raw TLS
    //     bytes (SNI routing only) — no ReverseProxy, no header deadline.
    // TCP/STCP/XTCP bridges have no such semantic either. The deadline
    // VALUE goes through the shared vhost clamp (`http_leg_head_deadline`
    // below, wrapping crate::vhost::clamp_vhost_timeout): a `<= 0` config
    // FLOORS to 60s and everything caps at 24h. The floor is not frp-rs
    // hardening — Go frp v0.71.0's NewHTTPReverseProxy floors
    // `ResponseHeaderTimeoutS <= 0` to 60s itself
    // (pkg/util/vhost/http.go:50-51), so an unset `vhost_http_timeout`
    // (config default 60) and an explicit 0 both arm the same 60s deadline;
    // there is no "0 disables the timeout" in Go (the old `> 0` gate —
    // arming nothing for a 0 config — carried a false Go citation; round-16
    // finding).
    let header_timeout = if proxy_info
        .as_ref()
        .is_some_and(|p| p.proxy_type == "http" && !req.request_is_connect)
    {
        Some(std::time::Duration::from_secs(http_leg_head_deadline(
            state.vhost_http_timeout,
        )))
    } else {
        None
    };

    // Spawn the bridge; select against the server shutdown token so a
    // graceful shutdown can interrupt half-open idle bridges instead of
    // waiting on TCP keepalive (2h) or yamux keepalive (90s) — audit D2-4 —
    // AND against the per-control `bridge_cancel` token so control teardown
    // (disconnect / supersession) stops the bridge: the work conn is owned
    // by this control, and a half-open client-side conn would otherwise
    // copy forever, leaking 1 task + 2 fds per reconnect with active
    // tunnels (HIGH finding). ONE task per bridged connection instead of
    // the old nested spawn whose JoinHandle was awaited only to extract the
    // panic payload (audit round 5, MEDIUM): the select is polled in-place
    // and panics are surfaced via catch_unwind, halving the task
    // allocations and wakeup registrations. The task is fire-and-forget
    // (bridges are connection-bounded and self-terminate; shutdown just
    // accelerates teardown). Note: in the release panic=abort profile the
    // panic aborts before catch_unwind fires — exactly as the old
    // JoinHandle-await also never fired there; in unwinding builds (tests)
    // the payload still reaches log_bridge_panic and the RAII ConnGuard
    // still releases the slot during unwind.
    let shutdown = state.shutdown_token.clone();
    let state_for_bridge = state.clone();
    let log_proxy_name = req.proxy_name.clone();
    tokio::spawn(async move {
        let fut = async {
            tokio::select! {
                _ = run_work_bridge(
                    work_conn,
                    req,
                    proxy_info,
                    encryption_key,
                    metrics,
                    header_timeout,
                    state_for_bridge,
                    v2,
                ) => {}
                _ = shutdown.cancelled() => {}
                _ = bridge_cancel.cancelled() => {}
            }
        };
        if let Err(p) = AssertUnwindSafe(fut).catch_unwind().await {
            log_bridge_panic(&log_proxy_name, "bridge", p);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Work stream whose reads block forever and whose writes fail
    /// deterministically, independent of platform TCP shutdown/RST timing.
    struct FailingWorkStream;

    impl AsyncRead for FailingWorkStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for FailingWorkStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected writer failure",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn udp_work_reader_eof_cancels_blocked_socket_writer() {
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_addr = socket.local_addr().unwrap();
        let retained_socket = socket.clone();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            // M1: keep the 60s production read deadline; these tests end
            // the bridge via EOF/cancel, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));
        drop(peer);

        tokio::time::timeout(std::time::Duration::from_millis(200), bridge)
            .await
            .expect("reader EOF must cancel the sibling blocked on UDP recv_from")
            .unwrap();

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"after-stop", socket_addr).await.unwrap();
        let mut buf = [0; 32];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            retained_socket.recv_from(&mut buf),
        )
        .await
        .expect("stopped writer must not consume a later datagram")
        .unwrap();
        assert_eq!(&buf[..n], b"after-stop");
    }

    #[tokio::test]
    async fn udp_work_writer_error_cancels_blocked_work_reader() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_addr = socket.local_addr().unwrap();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::SshChannel(Box::new(FailingWorkStream)),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            // M1: keep the 60s production read deadline; these tests end
            // the bridge via EOF/cancel, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));
        sender.send_to(b"force-write", socket_addr).await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
            .await
            .expect("writer error must cancel the sibling blocked on work read")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_forwards_packets_and_addresses_bidirectionally() {
        let (work, peer) = tcp_pair().await;
        let mut peer = IoStream::Tcp(peer);
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();
        let local_addr = msg::UdpAddr {
            ip: "192.0.2.8".to_string(),
            port: 7000,
            zone: String::new(),
        };
        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket.clone(),
            "udp-test".to_string(),
            Some(local_addr.clone()),
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            // M1: keep the 60s production read deadline; these tests end
            // the bridge via EOF/cancel, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));

        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"request".to_vec(),
            local_addr: None,
            remote_addr: Some(msg::UdpAddr {
                ip: remote_addr.ip().to_string(),
                port: remote_addr.port(),
                zone: String::new(),
            }),
        }))
        .await
        .unwrap();
        let mut buf = [0u8; 32];
        let (n, _) = remote.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        remote
            .send_to(b"response", socket.local_addr().unwrap())
            .await
            .unwrap();
        let response = peer.read_v1_frame().await.unwrap();
        match response {
            FrpMessage::UDPPacket(packet) => {
                assert_eq!(packet.content, b"response");
                assert_eq!(
                    packet.local_addr.unwrap().to_string(),
                    local_addr.to_string()
                );
                assert_eq!(
                    packet.remote_addr.unwrap().to_string(),
                    remote_addr.to_string()
                );
            }
            other => panic!("expected UDPPacket, got type {}", other.v1_type_byte()),
        }

        drop(peer);
        tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn udp_bridge_cancel_terminates_half_open_work_conn() {
        // Half-open work conn: keep the peer side open but never send, so the
        // reader blocks on read_msg_v1 (no EOF) and the writer blocks on
        // recv_from. Before the cancellation fix this bridge task hung
        // forever, leaking the work conn fd + socket + task memory after
        // control supersession/disconnect (Go frp v0.70.1 fix parity).
        let (work, _peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cancel = tokio_util::sync::CancellationToken::new();
        let bridge_cancel = cancel.clone();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            bridge_cancel,
            String::new(),
            // M1: keep the 60s production read deadline; the cancel arm
            // below ends this bridge, not frame silence.
            UDP_WORK_CONN_READ_TIMEOUT,
        ));

        // Let both bridge tasks reach their blocking points.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
            .await
            .expect("cancel must terminate the half-open UDP bridge task")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_reader_silence_reaps_half_open_conn() {
        // M1: Go server/proxy/udp.go read-deadline parity. A peer that
        // stays open but silent (no frames at all — a Ping included) must
        // be reaped after the read deadline; before the fix the reader was
        // parked on read_msg forever (dead UDP proxy until control
        // reconnect). Short deadline (150ms) pins the reap path without a
        // 60s test.
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let retained_socket = socket.clone();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            std::time::Duration::from_millis(150),
        ));
        // Keep `peer` alive and silent: no EOF, no frames.
        std::mem::forget(peer);

        tokio::time::timeout(std::time::Duration::from_secs(2), bridge)
            .await
            .expect("frame silence must end the UDP bridge after the read deadline")
            .unwrap();

        // The reaped bridge must not consume a later datagram (writer was
        // cancelled, not left draining).
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"after-stop", retained_socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0; 32];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            retained_socket.recv_from(&mut buf),
        )
        .await
        .expect("stopped writer must not consume a later datagram")
        .unwrap();
        assert_eq!(&buf[..n], b"after-stop");
    }

    #[tokio::test]
    async fn udp_work_conn_death_requests_replacement() {
        // M1: a UDP work-conn death (EOF here; read error / 60s silence
        // follow the same break path) must re-request a replacement
        // through the control loop — Go udpWorker replacement-loop parity.
        // Before the fix UdpNeedsWorkConn was sent exactly once at
        // registration and a dead work conn stranded the UDP proxy until
        // control reconnect.
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut udp_sockets = std::collections::HashMap::new();
        udp_sockets.insert("udp-test".to_string(), socket.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::InternalMsg>(16);

        let assign = tokio::spawn(async move {
            assign_udp_work_conn(
                IoStream::Tcp(work),
                "udp-test",
                &udp_sockets,
                None,
                false,
                [0u8; 16],
                false,
                1500,
                None,
                tokio_util::sync::CancellationToken::new(),
                String::new(),
                tx,
            )
            .await
        });
        // Let assign write StartWorkConn and spawn the bridge, then kill the
        // peer so the bridge read sees EOF.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(peer);
        assign.await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("work-conn death must re-request a replacement")
            .expect("channel closed");
        match msg {
            crate::state::InternalMsg::UdpNeedsWorkConn { proxy_name } => {
                assert_eq!(proxy_name, "udp-test");
            }
            other => panic!("expected UdpNeedsWorkConn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_work_conn_cancel_suppresses_replacement_request() {
        // M1: an exit caused by cancellation (proxy closed / control
        // teardown) must NOT re-request — the udp_sockets entry is gone and
        // a ReqWorkConn would dial a work conn into nothing. Half-open
        // bridge cancelled mid-flight; the channel must stay empty.
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut udp_sockets = std::collections::HashMap::new();
        udp_sockets.insert("udp-test".to_string(), socket.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::InternalMsg>(16);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_in = cancel.clone();

        let assign = tokio::spawn(async move {
            assign_udp_work_conn(
                IoStream::Tcp(work),
                "udp-test",
                &udp_sockets,
                None,
                false,
                [0u8; 16],
                false,
                1500,
                None,
                cancel_in,
                String::new(),
                tx,
            )
            .await
        });
        // Let the bridge park on the half-open read, then cancel it (the
        // 60s production read deadline keeps the natural-death path out of
        // this test's window). Keep `peer` alive so no EOF races the cancel.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        assign.await.unwrap();
        std::mem::forget(peer);

        match tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await {
            // Supervisors finished (tx dropped) without sending — correct.
            Ok(None) => {}
            Ok(Some(other)) => {
                panic!("cancel-based bridge exit must not re-request a replacement, got {other:?}")
            }
            Err(_elapsed) => panic!("supervisor still alive 300ms after cancel"),
        }
    }

    #[tokio::test]
    async fn bridge_cancel_terminates_half_open_tcp_bridge() {
        // Half-open TCP bridge: work conn + user conn both open, neither
        // side sending, so the copy blocks forever. Before the fix the
        // bridge task selected only on the server-global shutdown token, so
        // control teardown (disconnect / supersession) left it copying — the
        // half-open work conn (client side gone) + user conn + task leaked
        // per reconnect with active tunnels (HIGH finding). The bridge must
        // exit when the per-control token is cancelled, which is exactly
        // what control cleanup does with `bridge_cancel`.
        let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
        let (work, mut work_peer) = tcp_pair().await;
        let (user, _user_peer) = tcp_pair().await;
        let cancel = tokio_util::sync::CancellationToken::new();

        let req = PendingRequest {
            proxy_name: "t1".to_string(),
            user_conn: IoStream::Tcp(user),
            pre_read: Vec::new(),
            use_encryption: false,
            use_compression: false,
            visitor_use_encryption: false,
            visitor_use_compression: false,
            visitor_v2: false,
            visitor_udp_packet_codec: String::new(),
            created_at: tokio::time::Instant::now(),
            user_conn_permit: None,
            proxy_info: Some(Arc::new(
                crate::control::proxy_ops::unregister_generation_tests::proxy_info(
                    "t1",
                    "tcp",
                    "run-1",
                    Some(24000),
                    1,
                ),
            )),
            request_is_connect: false,
        };
        let spawn_res = assign_work_to_proxy(
            IoStream::Tcp(work),
            req,
            [0u8; 16],
            state,
            false,
            cancel.clone(),
        )
        .await;
        assert!(spawn_res.is_ok(), "bridge spawn must succeed");

        // Let the bridge reach its blocking copy point on the half-open pair.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Control teardown: cancel the per-control bridge token.
        cancel.cancel();

        // The bridge task must exit, dropping the work conn (and user conn).
        // The work-conn peer observes EOF — but first drains the
        // StartWorkConn frame written on spawn. Without the fix the final
        // read hangs forever and the timeout fires.
        let mut out = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                work_peer.read(&mut chunk),
            )
            .await
            .expect("cancel must terminate the half-open TCP bridge (work conn peer must see EOF)")
            .expect("read from work conn peer must succeed");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        assert!(
            !out.is_empty(),
            "StartWorkConn frame must have been delivered before EOF"
        );
    }

    // ---------------------------------------------------------------------
    // ResponseHeaderInjector unit tests (regressions for #3a / #3b).
    // ---------------------------------------------------------------------

    async fn injector_read_all(
        injector: &mut ResponseHeaderInjector<tokio::io::DuplexStream>,
    ) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        let mut chunk = [0u8; 7];
        loop {
            let n = injector.read(&mut chunk).await.expect("injector read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            // A deliberately small caller buffer exercises the "injected tail
            // must survive a partial serve" path (#3b).
        }
        out
    }

    /// #3a: a response header longer than one internal 4 KiB buffer, whose
    /// `\r\n\r\n` terminator spans two inner reads, must still be injected.
    #[tokio::test]
    async fn injector_headers_hspanning_reads_are_injected() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        // Build a response whose header block is larger than the injector's
        // 4096-byte read buffer, so the boundary lands in the second read.
        let mut big_cookie = String::from("Set-Cookie: a=");
        for _ in 0..900 {
            big_cookie.push('x');
        }
        big_cookie.push_str(";\r\n");
        let response = format!("HTTP/1.1 200 OK\r\n{big_cookie}\r\nbody-data");
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("X-Injected: yes"),
            "injected header must be present, got: {s:?}"
        );
        assert!(s.ends_with("body-data"), "body must survive, got: {s:?}");
        assert!(
            s.starts_with("HTTP/1.1 200 OK\r\n"),
            "leading status line must be preserved"
        );
    }

    /// #3b: the injected buffer is larger than the caller's `ReadBuf`, so the
    /// injected header tail spans multiple polls — none of it may be dropped.
    #[tokio::test]
    async fn injector_injected_tail_not_dropped_across_small_reads() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        for i in 0..20 {
            headers.insert(format!("X-{i}"), String::from("value-value-value-value"));
        }
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        let response = "HTTP/1.1 200 OK\r\n\r\nhello-body";
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        for i in 0..20 {
            assert!(
                s.contains(&format!("X-{i}: value-value-value-value\r\n")),
                "injected header {i} missing (tail dropped?): {s:?}"
            );
        }
        assert!(s.ends_with("hello-body"), "body must be intact");
    }

    /// Round-14 review: a backend that closes without any head terminator
    /// (garbage, or a head cut short) must ERROR — nothing is relayed. Go
    /// readResponse relays nothing until a head parses and errors on the
    /// unterminated head; the vhost ErrorHandler answers 404 and frp-core
    /// maps this UnexpectedEof to it. The old code relayed the partial
    /// bytes raw and ended "clean" (half a head on the wire, no 404).
    #[tokio::test]
    async fn injector_unterminated_bytes_then_eof_errors_not_relayed() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        inner_w
            .write_all(b"no-header-terminator-here")
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let mut buf = [0u8; 64];
        let err = injector
            .read(&mut buf)
            .await
            .expect_err("unterminated head + EOF must error, never relay partial bytes");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// Audit round 7 (S1 family): a backend response head with bare-LF line
    /// endings is legal under Go textproto.ReadLine semantics (each line
    /// ends at the next `\n`, ONE trailing `\r` is stripped, the head ends
    /// at the first empty line) but contains no `\r\n\r\n` window. The old
    /// strict-CRLF scan never found a boundary: injection was skipped and
    /// the head read on until EOF. RED on the old scan — the fix must
    /// terminate the gather at the LF blank line, emit the configured
    /// header as a REAL header line BEFORE the head/body blank line (bytes
    /// past it are the backend's body and pass verbatim), and keep the
    /// body intact after it.
    #[tokio::test]
    async fn injector_lf_only_head_injects_at_blank_line() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        let response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhello";
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        // Byte-exact pin: head lines verbatim (LF kept), the injected
        // header line CRLF-terminated BEFORE the backend's blank line, the
        // blank line itself and the body verbatim after it.
        let expected = b"HTTP/1.1 200 OK\nContent-Type: text/plain\nX-Injected: yes\r\n\nhello";
        assert_eq!(
            &out[..],
            expected,
            "LF-only head must terminate at the blank line with the header injected"
        );
    }

    #[tokio::test]
    async fn injector_empty_first_line_is_rejected_not_prepended() {
        // Go http.ReadResponse rejects a head with no status line (the head
        // starting with its own blank line) — the old splice prepended the
        // configured headers to the garbage and forwarded it as a plausible
        // 200-ish response (round-3 review finding).
        use tokio::io::AsyncWriteExt;
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));

        for garbage in [
            "\r\nHTTP/1.1 200 OK\r\n\r\nbody",
            "\nHTTP/1.1 200 OK\n\nbody",
        ] {
            let (mut w, r) = tokio::io::duplex(64 * 1024);
            let mut injector = ResponseHeaderInjector::new(r, headers.clone(), None);
            w.write_all(garbage.as_bytes()).await.expect("write");
            w.shutdown().await.expect("shutdown");
            drop(w);
            let mut buf = Vec::new();
            let res = tokio::io::AsyncReadExt::read_to_end(&mut injector, &mut buf).await;
            assert!(
                res.is_err(),
                "an empty first line must error, not forward: {garbage:?}"
            );
        }
    }

    /// Round-13 (F1#2): a backend head of status 1xx (NOT 101) must be
    /// served RAW, promptly, with no injection — Go's Transport consumes
    /// interim responses and ModifyResponse never runs on them, and an
    /// Expect:100-continue backend deadlocks if its 100 head is withheld
    /// while the injector keeps gathering the (never-arriving) final head.
    /// A final head pipelined in the SAME backend segment as the 100 must
    /// still get the injection (the split-off tail is re-accumulated once
    /// the raw emission drains).
    #[tokio::test]
    async fn injector_interim_1xx_served_raw_final_pipelined_injected() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        // One backend segment: interim 100 head + final 200 head + body.
        let response =
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
        inner_w.write_all(response.as_bytes()).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        // Byte-exact: the 100 head verbatim, then the 200 head WITH the
        // configured header injected before its blank line, body intact.
        let expected = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Injected: yes\r\n\r\nhello";
        assert_eq!(
            &out[..],
            expected,
            "interim head must pass raw, final head must be injected"
        );
    }

    /// Round-13 (F1#2): interim head arriving on a SEPARATE write (the
    /// Expect:100-continue shape — backend waits for the 100 to reach the
    /// client before sending the final head) must be emitted before the
    /// final head exists, not withheld while the injector waits for a
    /// second head it cannot see.
    #[tokio::test]
    async fn injector_interim_1xx_emitted_before_final_arrives() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        // Phase 1: only the 100 head. A single read must return it in full.
        inner_w
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .expect("write 100");
        let mut first = [0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut injector, &mut first)
            .await
            .expect("read 100 head");
        assert_eq!(
            &first[..n],
            b"HTTP/1.1 100 Continue\r\n\r\n",
            "the interim head must be served raw before the final head exists"
        );

        // Phase 2: final head + body, then EOF.
        inner_w
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
            .await
            .expect("write final");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut injector, &mut rest)
            .await
            .expect("read rest");
        assert_eq!(
            &rest[..],
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Injected: yes\r\n\r\nhello",
            "the final head must still get the injection"
        );
    }

    /// Round-13 (F1#2): 101 is NOT interim — Go runs modifyResponse on a
    /// 101, so the configured headers are injected into the 101 head, and
    /// the raw upgrade bytes after it pass through verbatim.
    #[tokio::test]
    async fn injector_101_switching_protocols_gets_injection() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        let response =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\xfeRAW-UPGRADE-BYTES";
        inner_w.write_all(response).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        let expected = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nX-Injected: yes\r\n\r\n\x81\xfeRAW-UPGRADE-BYTES";
        assert_eq!(
            &out[..],
            expected,
            "101 must be injected, upgrade bytes must pass verbatim"
        );
    }

    /// Round-13 (F1#2) + round-14 review: 100 head then backend EOF with
    /// no final head ever arriving — the raw 100 passes through, then the
    /// stream errors. Go readResponse consumes the interim and errors on
    /// the EOF-before-final-head; the vhost ErrorHandler answers 404, and
    /// frp-core maps this UnexpectedEof to that 404 (a 100 already on the
    /// wire is a legal interim prefix to a late final head).
    #[tokio::test]
    async fn injector_100_only_then_eof_errors_after_interim() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        inner_w
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .expect("write 100");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let mut buf = [0u8; 4096];
        let n = injector.read(&mut buf).await.expect("interim read");
        assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
        let err = injector
            .read(&mut buf)
            .await
            .expect_err("EOF before the final head must error, not end cleanly");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// Round-13 review (3 independent reviewers): a head whose first line
    /// does not parse as `HTTP/x.y <3-digit-code>` is malformed — Go errors
    /// the whole response and the reverse proxy answers 502, ModifyResponse
    /// never runs. The injector must serve such heads raw and NEVER
    /// manufacture configured headers into them. Pins the strict status
    /// line: tab separator, unparseable version token, and a 4-digit code
    /// are all malformed (space-TrimLeft is spaces-only, "0200" rejected
    /// before Atoi), while extra SPACES stay legal and DO inject.
    #[tokio::test]
    async fn injector_malformed_first_line_served_raw_never_injected() {
        use tokio::io::AsyncWriteExt;
        let headers = || {
            let mut h = std::collections::HashMap::new();
            h.insert("X-Injected".to_string(), String::from("yes"));
            h
        };
        for (name, head) in [
            ("tab separator", &b"HTTP/1.1\t100 Continue\r\n\r\n"[..]),
            ("bad version token", &b"HTTP/1.x 200 OK\r\n\r\n"[..]),
            ("4-digit code", &b"HTTP/1.1 0200 OK\r\n\r\n"[..]),
            ("no code", &b"HTTP/1.1 \r\n\r\n"[..]),
        ] {
            let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
            let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
            inner_w.write_all(head).await.expect("write head");
            inner_w.shutdown().await.expect("shutdown");
            drop(inner_w);
            // The malformed head (blank line included) is served raw in one
            // read; the EOF after it ends the stream CLEANLY — the relayed
            // malformed unit IS the response (round-13: served uninjected
            // for the browser's own parser to reject), so a following EOF
            // must not signal a "missing final head" 404 on top of it.
            let out = injector_read_all(&mut injector).await;
            assert_eq!(
                &out[..],
                head,
                "[{name}] malformed first line must pass through byte-exact, uninjected"
            );
        }
        // Extra spaces between version and code are legal (Go TrimLeft): the
        // head IS final (200) and MUST be injected.
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
        inner_w
            .write_all(b"HTTP/1.1   200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
            .await
            .expect("write 200");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("X-Injected: yes"),
            "multi-space first line is a valid final head and must inject, got: {s:?}"
        );
        assert!(s.ends_with("hello"), "body must survive, got: {s:?}");
    }

    /// Round-16 gap-fill pin: a MALFORMED head followed IN THE SAME
    /// BACKEND SEGMENT by a valid-looking `HTTP/1.1 200 OK` head must
    /// serve exactly ONE response — the garbage, raw and byte-exact — and
    /// drop the pipelined valid head (never injected, never relayed), then
    /// go permanent EOF. Round-15's terminal-drain fix (malformed_raw
    /// drain: tail cleared, `complete` set, subsequent polls Ready(0))
    /// already covers this shape; the sibling test above pins only the
    /// malformed-head-then-EOF arm, so this pin closes the same-segment
    /// coverage gap. Without the round-15 drain the gather loop resumed on
    /// the split-off tail and the 200 head was INJECTED and served as a
    /// second spliced response on one user connection (double-response,
    /// smuggling-adjacent shape).
    #[tokio::test]
    async fn injector_malformed_then_pipelined_valid_head_same_segment_single_raw_serve() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        // One write, one segment: malformed first line (bad version token →
        // status None → raw-served, malformed_raw) immediately followed by
        // a valid-looking final head + body.
        let segment = b"HTTP/1.x 200 OOPS\r\nServer: bogus\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        inner_w.write_all(segment).await.expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        assert_eq!(
            &out[..],
            &b"HTTP/1.x 200 OOPS\r\nServer: bogus\r\n\r\n"[..],
            "only the malformed head may be served — the pipelined valid head must be \
             dropped with the tail (double-response regression)"
        );
        // Permanent EOF after the single raw serve: the drain discarded the
        // tail and the complete+malformed_raw arm never polls the backend
        // again (a follow-up read must not surface the 200 head).
        let mut probe = [0u8; 8];
        assert_eq!(
            injector.read(&mut probe).await.expect("read after drain"),
            0,
            "stream must be permanently at EOF after the malformed raw serve"
        );
    }

    /// Round-16: Go's net/http write layer suppresses Content-Length on
    /// no-body statuses at user-facing serialization (chunkWriter.writeHeader
    /// delHeader sweep, go1.25 server.go:1483-1497; suppressedHeadersNoBody =
    /// {Content-Length, Transfer-Encoding} for 204, transfer.go:459-485) —
    /// every response through Go frp's h1 http vhost loses its CL. The
    /// injector owns every http non-CONNECT leg, EMPTY headers map included
    /// (the deadline-only pass-through), so the strip must run there too: a
    /// 204 with `Content-Length: 16` goes out without CL. Byte-exact pin:
    /// kept header lines, the terminating blank line, and any trailing bytes
    /// the (lying) backend wrote after the head all survive verbatim — only
    /// the CL line is dropped.
    #[tokio::test]
    async fn injector_204_strips_content_length_empty_map_deadline_only_leg() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        // NO configured response_headers: this is the pure deadline-only
        // pass-through leg — the 204/304 strip must still run.
        let mut injector = ResponseHeaderInjector::<tokio::io::DuplexStream>::new(
            inner_r,
            Default::default(),
            None,
        );

        inner_w
            .write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 16\r\nX-Keep: yes\r\n\r\n0123456789abcdef",
            )
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        assert_eq!(
            &out[..],
            &b"HTTP/1.1 204 No Content\r\nX-Keep: yes\r\n\r\n0123456789abcdef"[..],
            "204 head must lose its Content-Length line; every other byte (kept header, \
             blank line, trailing body bytes) is verbatim"
        );
    }

    /// Round-16: 304 mirrors the 204 strip (Go suppressedHeaders304 =
    /// {Content-Type, Content-Length, Transfer-Encoding}) but KEEPS its
    /// Content-Type — frp-rs strips Content-Length only, on both statuses;
    /// the 304 Content-Type suppression is a documented narrow divergence
    /// (informational header, no semantic effect).
    #[tokio::test]
    async fn injector_304_strips_content_length_keeps_content_type() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        inner_w
            .write_all(
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 16\r\nContent-Type: text/plain\r\nETag: \"v1\"\r\n\r\n",
            )
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.starts_with("HTTP/1.1 304 Not Modified\r\n"),
            "status line preserved, got: {s:?}"
        );
        assert!(
            !s.to_ascii_lowercase().contains("content-length"),
            "304 head must not carry Content-Length, got: {s:?}"
        );
        assert!(
            s.contains("Content-Type: text/plain\r\n"),
            "304 keeps Content-Type (documented narrow divergence), got: {s:?}"
        );
        assert!(
            s.contains("X-Injected: yes"),
            "configured headers must still inject on a 304, got: {s:?}"
        );
        assert!(
            s.contains("ETag: \"v1\""),
            "other backend headers preserved, got: {s:?}"
        );
    }

    /// Round-16: a body-bearing final status (200) is untouched — its
    /// Content-Length survives byte-exact, statuses Go's write layer does
    /// not suppress.
    #[tokio::test]
    async fn injector_200_keeps_content_length() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::<tokio::io::DuplexStream>::new(
            inner_r,
            Default::default(),
            None,
        );

        inner_w
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        assert_eq!(
            &out[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..],
            "200 head must keep its Content-Length verbatim"
        );
    }

    /// Round-16: the suppression hits a CONFIGURED Content-Length too — Go's
    /// ModifyResponse Header.Set runs BEFORE chunkWriter.writeHeader's
    /// delHeader sweep, so a response_headers entry naming content-length is
    /// suppressed on a 204 exactly like a backend line, while other
    /// configured headers still inject.
    #[tokio::test]
    async fn injector_204_suppresses_configured_content_length_too() {
        use tokio::io::AsyncWriteExt;
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Length".to_string(), String::from("99"));
        headers.insert("X-Injected".to_string(), String::from("yes"));
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

        inner_w
            .write_all(b"HTTP/1.1 204 No Content\r\nServer: b\r\n\r\n")
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        let out = injector_read_all(&mut injector).await;
        assert_eq!(
            &out[..],
            &b"HTTP/1.1 204 No Content\r\nServer: b\r\nX-Injected: yes\r\n\r\n"[..],
            "configured Content-Length must be suppressed on a 204 like a backend line"
        );
    }

    // A4 (round-13 review): the version token must be exactly `HTTP/X.Y`
    // single-digit — Go ParseHTTPVersion length-checks to 8 bytes and
    // parses single bytes (request.go:819-838).
    #[test]
    fn head_status_go_version_token_matrix() {
        let v = ResponseHeaderInjector::<tokio::io::DuplexStream>::is_http_version;
        for ok in [
            "HTTP/1.1", "HTTP/1.0", "HTTP/0.9", "HTTP/1.9", "HTTP/2.0", "HTTP/9.9",
        ] {
            assert!(v(ok.as_bytes()), "{ok} must parse (Go ParseHTTPVersion)");
        }
        for bad in [
            "HTTP/1.10",
            "HTTP/01.1",
            "HTTP/10.0",
            "HTTP/1.x",
            "HTTP/x.1",
            "HTTP/1",
            "HTTP/1.",
            "HTTP//1.1",
            "HTTP/1.1 ",
            "1.1",
            "FOO",
        ] {
            assert!(!v(bad.as_bytes()), "{bad} must NOT parse");
        }
    }

    // A7 (round-13 review): the code token is 3 BYTES with Go strconv.Atoi
    // semantics — a leading sign is legal ("+20" → 20, "-00" → 0) and only
    // a parse error or negative VALUE rejects ("-01") — and there is no
    // 100..=199 membership check here (response.go:173-186).
    #[test]
    fn head_status_go_code_atoi_matrix() {
        let code =
            |head: &[u8]| ResponseHeaderInjector::<tokio::io::DuplexStream>::head_status_code(head);
        let ok = [
            (&b"HTTP/1.1 200 OK\r\n\r\n"[..], 200u16),
            (&b"HTTP/1.1 +20 Weird\r\n\r\n"[..], 20u16),
            (&b"HTTP/1.1 -00 Weird\r\n\r\n"[..], 0u16),
            (&b"HTTP/1.1 000 Weird\r\n\r\n"[..], 0u16),
            (&b"HTTP/1.1 099 X\r\n\r\n"[..], 99u16),
            (&b"HTTP/1.1 599 X\r\n\r\n"[..], 599u16),
            (&b"HTTP/1.1 600 X\r\n\r\n"[..], 600u16),
            (&b"HTTP/1.1 999 X\r\n\r\n"[..], 999u16),
            (&b"HTTP/1.1 100 Continue\r\n\r\n"[..], 100u16),
            (&b"HTTP/1.0 101 Switching Protocols\r\n\r\n"[..], 101u16),
        ];
        for (head, want) in ok {
            assert_eq!(
                code(head),
                Some(want),
                "head: {}",
                String::from_utf8_lossy(head)
            );
        }
        let bad: &[&[u8]] = &[
            b"HTTP/1.1 -01 X\r\n\r\n",   // Atoi(-1) < 0 → malformed
            b"HTTP/1.1 +2a X\r\n\r\n",   // Atoi error
            b"HTTP/1.1 20a X\r\n\r\n",   // Atoi error
            b"HTTP/1.1 0200 X\r\n\r\n",  // 4-byte token
            b"HTTP/1.1 20 X\r\n\r\n",    // 2-byte token
            b"HTTP/1.1 + X\r\n\r\n",     // sign with no digits
            b"HTTP/1.10 200 OK\r\n\r\n", // A4: multi-digit minor
            b"HTTP/01.1 200 OK\r\n\r\n", // A4: multi-digit major
            b"FOO 200 OK\r\n\r\n",       // no HTTP/ prefix
        ];
        for head in bad {
            assert_eq!(code(head), None, "head: {}", String::from_utf8_lossy(head));
        }
    }

    /// Round-16 (false-Go-citation fix): the http-leg response-head
    /// deadline takes the shared vhost clamp — a `<= 0` `vhost_http_timeout`
    /// FLOORS to 60s, exactly like Go frp v0.71.0's NewHTTPReverseProxy
    /// (pkg/util/vhost/http.go:50-51: `if option.ResponseHeaderTimeoutS <= 0
    /// { option.ResponseHeaderTimeoutS = 60 }`), and everything caps at 24h
    /// (Rust-only hardening; Go has no cap). The old `> 0` gate armed NO
    /// deadline for a 0/unset config — a false "0 disables the timeout"
    /// citation: in Go an unset VhostHTTPTimeout (config default 60) and an
    /// explicit 0 both arm the same 60s deadline.
    #[test]
    fn http_leg_head_deadline_floors_zero_and_caps() {
        assert_eq!(http_leg_head_deadline(0), 60, "0 must floor to Go's 60s");
        assert_eq!(http_leg_head_deadline(1), 1);
        assert_eq!(http_leg_head_deadline(59), 59);
        assert_eq!(http_leg_head_deadline(60), 60);
        assert_eq!(http_leg_head_deadline(61), 61);
        let cap = 24 * 60 * 60;
        assert_eq!(http_leg_head_deadline(cap), cap);
        assert_eq!(
            http_leg_head_deadline(cap + 1),
            cap,
            "positive values cap at 24h"
        );
        assert_eq!(
            http_leg_head_deadline(u64::MAX),
            cap,
            "hostile huge config must not overflow Instant arithmetic"
        );
    }

    // A7 end-to-end shape: a "+20"-coded head is FINAL (not interim) in Go
    // — modifyResponse runs and the injector must inject.
    #[tokio::test]
    async fn injector_signed_code_heads_are_final_and_injected() {
        use tokio::io::AsyncWriteExt;
        let headers = || {
            let mut h = std::collections::HashMap::new();
            h.insert("X-Injected".to_string(), String::from("yes"));
            h
        };
        for head in [
            &b"HTTP/1.1 +20 Whimsy\r\n\r\nok"[..],
            &b"HTTP/1.1 -00 Whimsy\r\n\r\nok"[..],
        ] {
            let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
            let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
            inner_w.write_all(head).await.expect("write head");
            inner_w.shutdown().await.expect("shutdown");
            drop(inner_w);
            let out = injector_read_all(&mut injector).await;
            let s = String::from_utf8_lossy(&out);
            assert!(
                s.contains("X-Injected: yes"),
                "signed code is a legal final head and must inject, got: {s:?}"
            );
            assert!(s.ends_with("ok"), "body must survive, got: {s:?}");
        }
        // The multi-digit version head, by contrast, is malformed in Go —
        // served raw, byte-exact, uninjected.
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
        let raw = b"HTTP/1.10 200 OK\r\n\r\n";
        inner_w.write_all(raw).await.expect("write head");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let out = injector_read_all(&mut injector).await;
        assert_eq!(&out[..], raw, "HTTP/1.10 must pass through raw, uninjected");
    }

    // A2 (round-13 review): the response-head deadline is ONE absolute
    // deadline — an interim 1xx raw serve does NOT extend it. A backend
    // that answers 100 then stalls errors TimedOut instead of parking the
    // bridge forever.
    #[tokio::test(start_paused = true)]
    async fn injector_interim_1xx_does_not_extend_the_head_deadline() {
        use tokio::io::AsyncWriteExt;
        let headers = std::collections::HashMap::new();
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector =
            ResponseHeaderInjector::new(inner_r, headers, Some(std::time::Duration::from_secs(5)));
        inner_w
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .expect("write 100");
        let mut buf = [0u8; 4096];
        // The interim head is served raw...
        let n = injector.read(&mut buf).await.expect("interim read");
        assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
        // ...then the final head never arrives: the absolute deadline fires
        // (the paused clock auto-advances while the read parks).
        let err = injector
            .read(&mut buf)
            .await
            .expect_err("deadline must fire");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    // A2 companion: a final head that ARRIVES within the deadline injects
    // normally (the deadline must not cut healthy responses short).
    #[tokio::test(start_paused = true)]
    async fn injector_head_within_deadline_injects_normally() {
        use tokio::io::AsyncWriteExt;
        let headers = || {
            let mut h = std::collections::HashMap::new();
            h.insert("X-Injected".to_string(), String::from("yes"));
            h
        };
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(
            inner_r,
            headers(),
            Some(std::time::Duration::from_secs(60)),
        );
        inner_w
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .expect("write 200");
        let mut buf = [0u8; 4096];
        let n = injector.read(&mut buf).await.expect("read");
        let out = String::from_utf8_lossy(&buf[..n]);
        assert!(out.contains("X-Injected: yes"), "injected, got: {out:?}");
        // Deadline NOT armed on the body path: the drain below is bounded by
        // the inner EOF, and nothing after `complete` consults the timer.
        assert!(out.ends_with("ok"), "body attached, got: {out:?}");
    }

    // A6 (round-13 review): case-insensitive duplicate config keys are ONE
    // canonical header on the wire — keys sorted, the LAST same-name key
    // wins (deterministic stand-in for Go's random map-iteration winner);
    // never two lines. Backend-sent lines under either spelling are dropped
    // with their folded continuations.
    #[tokio::test]
    async fn injector_config_case_duplicate_keys_emit_single_line() {
        use tokio::io::AsyncWriteExt;
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Custom".to_string(), "first".to_string());
        headers.insert("x-custom".to_string(), "second".to_string());
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);
        inner_w
            .write_all(
                b"HTTP/1.1 200 OK\r\nX-Custom: backend\r\n  backend-fold\r\nContent-Length: 2\r\n\r\nok",
            )
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        let custom_lines: Vec<&str> = s
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("x-custom:"))
            .collect();
        assert_eq!(
            custom_lines.len(),
            1,
            "exactly one X-Custom line on the wire, got: {s:?}"
        );
        // Sorted ascending, "X-Custom" < "x-custom" (uppercase first) — the
        // later key wins deterministically.
        assert_eq!(custom_lines[0], "x-custom: second", "got: {s:?}");
        assert!(
            !s.contains("backend"),
            "backend value must be dropped: {s:?}"
        );
        assert!(
            !s.contains("backend-fold"),
            "fold must go with its parent: {s:?}"
        );
        assert!(s.ends_with("ok"), "body must survive: {s:?}");
    }

    // B1 (round-13 review): a backend header whose lowercase spelling
    // matches a configured key is dropped WITH its obs-fold tail; the
    // configured value goes out alone.
    #[tokio::test]
    async fn injector_drops_lowercase_backend_header_under_config_key() {
        use tokio::io::AsyncWriteExt;
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);
        inner_w
            .write_all(
                b"HTTP/1.1 200 OK\r\nx-frame-options: SAMEORIGIN\r\n  folded-tail\r\nContent-Length: 2\r\n\r\nok",
            )
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("X-Frame-Options: DENY\r\n"),
            "configured value must be injected, got: {s:?}"
        );
        assert!(
            !s.contains("SAMEORIGIN"),
            "backend value must be dropped: {s:?}"
        );
        assert!(
            !s.contains("folded-tail"),
            "fold tail must go with its parent: {s:?}"
        );
        assert!(s.ends_with("ok"), "body must survive: {s:?}");
    }

    // B6 (round-13 review) + round-14 rework: a raw interim head, then a
    // TRUNCATED second head ("HTTP/1.1 20" cut mid-code) followed by EOF.
    // The interim goes out raw; nothing of the unterminated final head is
    // ever relayed (Go readResponse errors on an unterminated head before
    // the reverse proxy writes anything) — the partial is dropped and the
    // next read reports Err(UnexpectedEof) so the bridge's 404 arm answers
    // after the legal interim prefix.
    #[tokio::test]
    async fn injector_truncated_second_head_after_interim_not_relayed() {
        use tokio::io::AsyncWriteExt;
        let headers = || {
            let mut h = std::collections::HashMap::new();
            h.insert("X-Injected".to_string(), String::from("yes"));
            h
        };
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
        inner_w
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 20")
            .await
            .expect("write");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let mut buf = [0u8; 4096];
        let n = injector.read(&mut buf).await.expect("interim read");
        assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
        let err = injector
            .read(&mut buf)
            .await
            .expect_err("truncated final head must not be relayed");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    // B7 (round-13 review): a head whose FIRST line is blank (no status
    // line) after an interim raw serve fails the read like Go's reverse
    // proxy — it must not be spliced into a plausible response.
    #[tokio::test]
    async fn injector_blank_line_head_after_interim_is_invalid() {
        use tokio::io::AsyncWriteExt;
        let headers = || {
            let mut h = std::collections::HashMap::new();
            h.insert("X-Injected".to_string(), String::from("yes"));
            h
        };
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
        inner_w
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n\r\n200 OK\r\n\r\n")
            .await
            .expect("write");
        let mut buf = [0u8; 4096];
        let n = injector.read(&mut buf).await.expect("interim read");
        assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
        let err = injector
            .read(&mut buf)
            .await
            .expect_err("blank-first-line head must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Audit round-15 gap pin: a mid-body decode failure AFTER a legal final
    /// response head was already served must be swallowed as a CLEAN EOF —
    /// the `complete` arm (:394-403) turns a post-head inner read error of
    /// kind InvalidData into `Ok(())`, because frp-core would answer a
    /// gateway head (404/502) for bytes the client already accepted as the
    /// response (Go's ErrorHandler never runs once RoundTrip returned).
    /// Producer shape pinned here is the real compressed-arm wiring
    /// (`comp_key` → the work reader is wrapped in `SnappyStreamReader`
    /// before the injector): a valid Snappy stream for the head + body,
    /// then a garbage frame mid-body (a "compressed data" chunk header
    /// declaring 0xFFFFFF bytes — far past the decoder's per-chunk cap, so
    /// it errors the moment it is processed, never buffered as a partial
    /// tail). Regression shape: without the swallow arm the read after the
    /// body surfaces Err(InvalidData) instead of a clean EOF.
    #[tokio::test]
    async fn injector_mid_body_snappy_decode_failure_after_head_is_clean_eof() {
        use frp_core::encryption::SnappyCompressor;
        use tokio::io::AsyncWriteExt;

        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Injected".to_string(), String::from("yes"));

        // Compress the whole backend response (head + body) into one
        // Snappy stream chunk, then append the corrupt frame.
        let mut comp = SnappyCompressor::new();
        let mut wire = Vec::new();
        comp.compress(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            &mut wire,
        )
        .expect("compress backend response");
        wire.extend_from_slice(&[0x00, 0xFF, 0xFF, 0xFF]);
        assert!(
            wire.len() < 32 * 1024,
            "payload must fit one SnappyStreamReader read chunk"
        );

        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        // The compressed-arm wiring (bridge.rs comp_key → injector inner is
        // a SnappyStreamReader over the work stream).
        let mut injector = ResponseHeaderInjector::new(
            frp_core::snappy_stream::SnappyStreamReader::new(inner_r),
            headers,
            None,
        );
        inner_w.write_all(&wire).await.expect("write wire");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);

        // Every read must succeed — the corruption may only shorten the
        // stream to a clean EOF, never surface as an error kind frp-core
        // would answer with a gateway head.
        let mut out = Vec::new();
        let mut chunk = [0u8; 7]; // small caller buffer (injector tail path)
        let saw_eof = loop {
            match injector.read(&mut chunk).await {
                Ok(0) => break true,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(e) => panic!(
                    "mid-body decode failure after head served must be swallowed as clean EOF, got Err({e})"
                ),
            }
        };
        assert!(
            saw_eof,
            "the corruption must end the stream with a clean EOF"
        );

        let s = String::from_utf8_lossy(&out);
        // The head was relayed/injected EXACTLY once, before the corruption.
        assert_eq!(
            s.matches("HTTP/1.1 200 OK").count(),
            1,
            "exactly one response head on the wire, got: {s:?}"
        );
        assert_eq!(
            s.matches("X-Injected: yes").count(),
            1,
            "injected header present exactly once, got: {s:?}"
        );
        assert!(
            s.starts_with("HTTP/1.1 200 OK\r\n"),
            "status line first, got: {s:?}"
        );
        // The legal body survived up to the corruption point...
        assert!(s.ends_with("hello"), "body must survive, got: {s:?}");
        // ...and the corrupt tail was never relayed (no second response /
        // garbage bytes after the body).
        assert!(
            !out.windows(4).any(|w| w == [0x00, 0xFF, 0xFF, 0xFF]),
            "corrupt frame bytes must never reach the wire: {out:?}"
        );
    }
}
