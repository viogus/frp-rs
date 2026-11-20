use std::time::Duration;

use bpaf::Parser;
use bpaf::*;

/// Default of `--api-timeout`: Go frp v0.71.0's
/// `var adminAPITimeout = 30 * time.Second` (`cmd/frpc/sub/admin.go:32`).
pub const DEFAULT_ADMIN_API_TIMEOUT: Duration = Duration::from_secs(30);

/// Consume Go's `leadingInt` from `time.ParseDuration`: digits into a `u64`,
/// failing on the same overflow Go fails on.
pub(crate) fn leading_int(s: &[u8]) -> Result<(u64, usize), ()> {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if x > (1u64 << 63) / 10 {
            return Err(());
        }
        x = x * 10 + u64::from(s[i] - b'0');
        if x > 1u64 << 63 {
            return Err(());
        }
        i += 1;
    }
    Ok((x, i))
}

/// Consume Go's `leadingFraction`: the digits after a decimal point as a
/// `u64` plus the matching power-of-ten scale. On overflow Go stops updating
/// the value but keeps consuming digits; the scale stops growing too.
pub(crate) fn leading_fraction(s: &[u8]) -> (u64, f64, usize) {
    let mut x: u64 = 0;
    let mut scale = 1f64;
    let mut overflow = false;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if !overflow {
            if x > ((1u64 << 63) - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + u64::from(s[i] - b'0');
                if y > 1u64 << 63 {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, i)
}

/// Parse a duration with Go `time.ParseDuration`'s grammar, hand-written.
///
/// Needed because `Duration` does not implement `FromStr` on the pinned
/// toolchain and the dependency policy forbids adding a crate for it. Grammar
/// (Go's `ParseDuration`): one or more `number unit` groups, each number a
/// decimal integer with an optional fractional part, each unit one of
/// `ns us µs μs ms s m h` (lowercase only), behind an optional leading `+`/`-`.
/// A bare `0` is the only unit-less form; a number with no unit is
/// `time: missing unit in duration "…"`, an unknown unit is
/// `time: unknown unit "d" in duration "1d"`, and everything else malformed is
/// `time: invalid duration "…"` — Go's wording, measured through
/// `frpc stop --api-timeout=<value>` on the v0.71.0 binary. Overflow past
/// `2562047h47m16.854775807s` (`i64::MAX` ns) is rejected, never panicked.
///
/// A negative value parses (Go accepts `-1s`) but a [`Duration`] cannot be
/// negative and the only consumer is a deadline, where "negative" means
/// "already elapsed" — so it is represented as [`Duration::ZERO`], exactly like
/// a parsed `0`. Go distinguishes them only in the sign it later applies to an
/// already-expired context, which behaves the same.
///
/// One divergence, recorded rather than copied: Go accumulates the group total
/// in a `uint64` (`d += v`) and only checks `d > 1<<63`, so two groups that sum
/// past `2^64` wrap. Measured on the v0.71.0 binary,
/// `frpc stop --api-timeout=9223372036854775808ns9223372036854775808ns` is
/// accepted and reports `context deadline exceeded` (the wrapped total is 0 ns),
/// while this parser rejects it with `time: invalid duration`. frp-rs is
/// therefore **stricter** on that input and never panics: it uses checked
/// arithmetic instead of wrapping.
pub(crate) fn parse_go_duration(text: String) -> Result<Duration, String> {
    let orig = text.as_str();
    let invalid = || format!("time: invalid duration \"{orig}\"");
    let mut rest = text.as_bytes();
    let mut neg = false;
    if let Some((&c, tail)) = rest.split_first() {
        match c {
            b'-' => {
                neg = true;
                rest = tail;
            }
            b'+' => rest = tail,
            _ => {}
        }
    }
    // Go special-cases a bare "0" after the sign.
    if rest == b"0" {
        return Ok(Duration::ZERO);
    }
    if rest.is_empty() {
        return Err(invalid());
    }
    // Total nanoseconds, tracked in Go's unsigned domain so the overflow checks
    // match (`d > 1<<63` fails, `d == 1<<63` is still representable as -2^63).
    let mut total: u64 = 0;
    while !rest.is_empty() {
        if !(rest[0] == b'.' || rest[0].is_ascii_digit()) {
            return Err(invalid());
        }
        let (v, used) = leading_int(rest).map_err(|()| invalid())?;
        let pre = used != 0;
        rest = &rest[used..];
        let mut f: u64 = 0;
        let mut scale = 1f64;
        let mut post = false;
        if !rest.is_empty() && rest[0] == b'.' {
            rest = &rest[1..];
            let (ff, ss, used) = leading_fraction(rest);
            f = ff;
            scale = ss;
            rest = &rest[used..];
            post = used != 0;
        }
        if !pre && !post {
            return Err(invalid());
        }
        // The unit is the run of bytes that are neither a digit nor a point.
        let unit_len = rest
            .iter()
            .take_while(|c| **c != b'.' && !c.is_ascii_digit())
            .count();
        if unit_len == 0 {
            return Err(format!("time: missing unit in duration \"{orig}\""));
        }
        let unit_name = &rest[..unit_len];
        rest = &rest[unit_len..];
        let unit: u64 = match unit_name {
            b"ns" => 1,
            // U+00B5 MICRO SIGN and U+03BC GREEK SMALL LETTER MU, Go's two µs
            // spellings (UTF-8: C2 B5 and CE BC).
            b"us" | b"\xc2\xb5s" | b"\xce\xbcs" => 1_000,
            b"ms" => 1_000_000,
            b"s" => 1_000_000_000,
            b"m" => 60 * 1_000_000_000,
            b"h" => 3_600 * 1_000_000_000,
            _ => {
                return Err(format!(
                    "time: unknown unit \"{}\" in duration \"{orig}\"",
                    String::from_utf8_lossy(unit_name)
                ))
            }
        };
        if v > (1u64 << 63) / unit {
            return Err(invalid());
        }
        let mut v = v * unit;
        if f > 0 {
            // Go: `v += uint64(float64(f) * (float64(unit) / scale))`.
            let fraction = (f as f64) * (unit as f64 / scale);
            if !fraction.is_finite() || fraction < 0.0 {
                return Err(invalid());
            }
            v = v.checked_add(fraction as u64).ok_or_else(invalid)?;
            if v > 1u64 << 63 {
                return Err(invalid());
            }
        }
        total = total.checked_add(v).ok_or_else(invalid)?;
        if total > 1u64 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok(Duration::ZERO);
    }
    if total > (1u64 << 63) - 1 {
        return Err(invalid());
    }
    Ok(Duration::from_nanos(total))
}

/// `--api-timeout` for the frpc admin subcommands.
///
/// Go frp v0.71.0 registers this flag **per subcommand**:
/// `init()`'s loop over `reload`/`status`/`stop` (`cmd/frpc/sub/admin.go:45-49`)
/// runs `cmd.Flags().DurationVar(&adminAPITimeout, "api-timeout",
/// adminAPITimeout, "Timeout for admin API calls")` at `:47`.
/// `NewAdminCommand` (`:52-73`) only builds the command and registers no flag.
/// It is not a root persistent flag; measured, `frpc verify --api-timeout=1s` is
/// `Error: unknown flag: --api-timeout`, exit 1. The underscore spelling
/// `--api_timeout` is registered as well, like every other flag in this file;
/// `docs/deployment.md` records the measured Go behaviour for both spellings.
pub(crate) fn api_timeout_parser() -> impl Parser<Duration> {
    long("api-timeout")
        .long("api_timeout")
        .argument::<String>("DURATION")
        .help("Timeout for admin API calls")
        .parse(parse_go_duration)
        .fallback(DEFAULT_ADMIN_API_TIMEOUT)
}
