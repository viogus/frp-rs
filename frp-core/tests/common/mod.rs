//! Shared record-shape pin for the two `tls_enable` diagnostic captures:
//! `frp-core/tests/server_tls_enable_warning.rs` and
//! `frp-core/tests/web_server_tls_enable_warning.rs`.
//!
//! Both emit sites live in `frp-core/src/config/loader.rs` and both are
//! `tracing::warn!("{}", <message>)`, so both render as one
//! `tracing_subscriber::fmt` line: the prefix, the message, and an optional
//! trailing newline. `contains(NEEDLE)` — the assertion class this replaced —
//! cannot see an appended clause, and a guard that only required the prefix to
//! hold `WARN` and no newline could not see a literal injected *between* the
//! target and the message. Both mutants were measured green against those older
//! shapes; this pins the whole record instead.
//!
//! The prefix must not be pinned on shell state. `tracing_subscriber::fmt`'s
//! default layer enables ANSI whenever the `ansi` feature is on and `NO_COLOR`
//! is unset or empty (`tracing-subscriber-0.3.23/src/fmt/fmt_layer.rs:739-743`),
//! so a CI runner without `NO_COLOR` renders the level and target as SGR
//! sequences — `"\x1b[33m WARN\x1b[0m \x1b[2mfrp_core::config::loader\x1b[0m\x1b[2m:\x1b[0m "`
//! — and a contiguous `" frp_core::config::loader: "` anchor then matches zero
//! times. That is exactly how the pin reddened CI on `c3ce6caa` while a
//! `NO_COLOR=1` dev shell stayed green. Every capture here adds
//! `.with_ansi(false)`, and the assertions below strip SGR anyway, so neither
//! the accepted bytes nor the failure messages depend on the environment.

/// The `tracing` target of both emit sites — the module path `tracing::warn!`
/// records when it is invoked from `frp-core/src/config/loader.rs`.
///
/// Measured with the captures' own subscriber
/// (`tracing_subscriber::fmt().with_max_level(WARN).without_time().with_ansi(false)`):
/// the prefix is exactly `" WARN frp_core::config::loader: "`, in both the
/// default-feature and `--no-default-features` lanes. `.with_ansi(false)` is
/// what makes that literal true; `strip_sgr` below makes the pin hold even if
/// a capture forgets it.
pub const WARNING_TARGET: &str = "frp_core::config::loader";

/// Drop well-formed ANSI SGR sequences (`ESC [ <digits and ';'> m`) from a
/// captured record, copying every other byte through unchanged.
///
/// Hand-rolled because the repo forbids new dependencies (`CLAUDE.md`); it is
/// deliberately narrow — it removes a sequence only when the bracket is
/// terminated by `m`, so unrelated bytes (including a lone `ESC`) survive and
/// a diagnostic still shows what the capture really held.
fn strip_sgr(record: &str) -> String {
    let bytes = record.as_bytes();
    let mut out = String::with_capacity(record.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'[') {
            let mut j = i + 2;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b';') {
                j += 1;
            }
            if bytes.get(j) == Some(&b'm') {
                i = j + 1;
                continue;
            }
        }
        let ch = record[i..]
            .chars()
            .next()
            .expect("i stays on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The emitted record must be the one-line `tracing` prefix followed by `want`
/// and **nothing else** but an optional trailing newline.
///
/// Four rejections, each measured against a mutant:
///
/// * the message appears zero or twice, or is a different message — `contains`
///   + `match_indices`;
/// * bytes appended after the message — `warn!("{} (see docs/tls.md)", …)`
///   fails the `tail` assertion;
/// * a literal injected between the target and the message —
///   `warn!("EXTRA {}", …)` fails the `anchor` assertions, because the prefix
///   then ends in `"EXTRA "` rather than `" <target>: "` (and the anchor must
///   occur exactly once, so a literal that itself ends in the target does not
///   sneak through);
/// * the target **rewritten** to a longer key that ends in the expected one —
///   `warn!(target: "x <target>", …)` used to pass: the anchor still occurred
///   exactly once and still ended the prefix, so the extra `x` merely widened
///   the bytes before the anchor. The level is therefore pinned to exactly
///   `WARN`, which is the whole of that prefix field.
///
/// The level is compared **trimmed and after `strip_sgr`**: that is the one
/// `<target>:` field's own text, so pinning it to `WARN` is what rejects the
/// rewritten-target mutant, while `tracing_subscriber`'s fmt format stays free
/// to pad or colour the level. Every failure message quotes the **raw** record
/// so a coloured capture is still diagnosable.
pub fn assert_record_is_exactly_the_message(tag: &str, record: &str, want: &str, target: &str) {
    let clean = strip_sgr(record);
    assert!(
        clean.contains(want),
        "{tag}: the record must carry the message; got raw record: {record:?}"
    );
    assert_eq!(
        clean.match_indices(want).count(),
        1,
        "{tag}: the message must appear exactly once in the record; got raw record: {record:?}"
    );
    let at = clean.find(want).expect("checked just above");
    let prefix = &clean[..at];
    let tail = &clean[at + want.len()..];
    assert!(
        tail.is_empty() || tail == "\n",
        "{tag}: the emit site appended bytes after the message (only a trailing newline is \
         allowed); got tail: {tail:?} from raw record: {record:?}"
    );
    let anchor = format!(" {target}: ");
    assert_eq!(
        prefix.matches(&anchor).count(),
        1,
        "{tag}: the tracing prefix must carry the target `{target}: ` exactly once (SGR stripped); \
         got prefix: {prefix:?} from raw record: {record:?}"
    );
    assert!(
        prefix.ends_with(&anchor),
        "{tag}: the emit site inserted bytes between the tracing prefix and the message; the \
         prefix must end with {anchor:?} (SGR stripped), got prefix: {prefix:?} from raw record: \
         {record:?}"
    );
    let level = &prefix[..prefix.len() - anchor.len()];
    assert_eq!(
        level.trim(),
        "WARN",
        "{tag}: only the tracing level may precede the target, and it must be exactly `WARN`. An \
         emit site that rewrites the target to a longer key ending in `{target}` (e.g. \
         `x {target}`) leaves extra text here and must not pass; got level: {level:?} from raw \
         record: {record:?}"
    );
}
