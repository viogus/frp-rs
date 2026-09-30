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

/// The `tracing` target of both emit sites — the module path `tracing::warn!`
/// records when it is invoked from `frp-core/src/config/loader.rs`.
///
/// Measured with the captures' own subscriber
/// (`tracing_subscriber::fmt().with_max_level(WARN).without_time()`): the prefix
/// is exactly `" WARN frp_core::config::loader: "`, in both the default-feature
/// and `--no-default-features` lanes (no ANSI in either).
pub const WARNING_TARGET: &str = "frp_core::config::loader";

/// The emitted record must be the one-line `tracing` prefix followed by `want`
/// and **nothing else** but an optional trailing newline.
///
/// Three rejections, each measured against a mutant:
///
/// * the message appears zero or twice, or is a different message — `contains`
///   + `match_indices`;
/// * bytes appended after the message — `warn!("{} (see docs/tls.md)", …)`
///   fails the `tail` assertion;
/// * a literal injected between the target and the message —
///   `warn!("EXTRA {}", …)` fails the `anchor` assertions, because the prefix
///   then ends in `"EXTRA "` rather than `" <target>: "` (and the anchor must
///   occur exactly once, so a literal that itself ends in the target does not
///   sneak through).
///
/// The level itself is not pinned byte for byte: `tracing_subscriber`'s fmt
/// format owns it (and may colour it), so only its one-line shape is required.
pub fn assert_record_is_exactly_the_message(tag: &str, record: &str, want: &str, target: &str) {
    assert!(
        record.contains(want),
        "{tag}: the record must carry the message; got: {record:?}"
    );
    assert_eq!(
        record.match_indices(want).count(),
        1,
        "{tag}: the message must appear exactly once in the record; got: {record:?}"
    );
    let at = record.find(want).expect("checked just above");
    let prefix = &record[..at];
    let tail = &record[at + want.len()..];
    assert!(
        tail.is_empty() || tail == "\n",
        "{tag}: the emit site appended bytes after the message (only a trailing newline is \
         allowed); got tail: {tail:?} from record: {record:?}"
    );
    let anchor = format!(" {target}: ");
    assert_eq!(
        prefix.matches(&anchor).count(),
        1,
        "{tag}: the tracing prefix must carry the target `{target}: ` exactly once; got prefix: \
         {prefix:?} from record: {record:?}"
    );
    assert!(
        prefix.ends_with(&anchor),
        "{tag}: the emit site inserted bytes between the tracing prefix and the message; the \
         prefix must end with {anchor:?}, got prefix: {prefix:?} from record: {record:?}"
    );
    let level = &prefix[..prefix.len() - anchor.len()];
    assert!(
        level.contains("WARN") && !level.contains('\n'),
        "{tag}: only the one-line tracing level may precede the target; got level: {level:?} \
         from record: {record:?}"
    );
}
