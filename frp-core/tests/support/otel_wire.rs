//! The pure half of the OTLP/HTTP test sinks: enough protobuf framing to prove
//! that a span name went over the wire as a span name.
//!
//! Kept separate from the sinks because it has no I/O and no runtime: the
//! async sink in `otel_sink.rs` and the blocking one in `otel_sink_std.rs` (used
//! by the daemon tests that spawn a binary) both `#[path]`-include it, so there
//! is exactly one decoder in the tree.

#![allow(dead_code)]

/// `Content-Length` of an HTTP/1.x request head, case-insensitively.
pub fn content_length(head: &str) -> Option<usize> {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then_some(value)
        })
        .and_then(|v| v.trim().parse().ok())
}

/// Byte offset of `needle` in `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Encode a protobuf length-delimited field. `tag` is the already-composed
/// field-number/wire-type byte; only one-byte lengths are needed here (the
/// span names are short), which keeps the helper allocation-free and obvious.
pub fn length_delimited_field(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(
        value.len() < 0x80,
        "test helper only handles one-byte field lengths, got {}",
        value.len()
    );
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}
